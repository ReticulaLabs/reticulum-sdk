pub mod lr1121;
pub mod sx1262;
pub mod sx1276;

use std::collections::VecDeque;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::{Interface, InterfaceContext, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

const LORA_HW_MTU: usize = 508;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_COMMAND_DELAY: Duration = Duration::from_millis(2);
const DEFAULT_RX_POLL_INTERVAL: Duration = Duration::from_millis(50);

const FREQ_MIN: u64 = 137_000_000;
const FREQ_MAX: u64 = 3_000_000_000;
const TXPOWER_MIN: i8 = -9;
const TXPOWER_MAX: i8 = 22;
const SF_MIN: u8 = 5;
const SF_MAX: u8 = 12;
const CR_MIN: u8 = 5;
const CR_MAX: u8 = 8;

pub const DEFAULT_SYNC_WORD: u16 = 0x1424;

const SPI_IOC_MESSAGE_1: u64 = 0x40206B00;
const SPI_IOC_WR_MODE: u64 = 0x40016B01;
const SPI_IOC_WR_MAX_SPEED_HZ: u64 = 0x40046B04;
const SPI_IOC_WR_BITS_PER_WORD: u64 = 0x40016B03;

/// SPI bus abstraction over a Linux spidev device using raw ioctls.
pub struct SpiBus {
    fd: std::fs::File,
}

impl SpiBus {
    pub fn open(path: &str, speed_hz: u32) -> Result<Self, LoRaError> {
        use std::os::fd::AsRawFd;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| LoRaError::Spi(format!("cannot open {}: {}", path, e)))?;

        let fd = file.as_raw_fd();

        // Set SPI mode 0
        let mode: u8 = 0x00;
        let ret = unsafe { libc::ioctl(fd, SPI_IOC_WR_MODE as _, &mode) };
        if ret < 0 {
            return Err(LoRaError::Spi(format!("cannot set SPI mode: {}", std::io::Error::last_os_error())));
        }

        // Set speed
        let ret = unsafe { libc::ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ as _, &speed_hz) };
        if ret < 0 {
            return Err(LoRaError::Spi(format!("cannot set SPI speed: {}", std::io::Error::last_os_error())));
        }

        // Set bits per word
        let bits: u8 = 8;
        let ret = unsafe { libc::ioctl(fd, SPI_IOC_WR_BITS_PER_WORD as _, &bits) };
        if ret < 0 {
            return Err(LoRaError::Spi(format!("cannot set SPI bits: {}", std::io::Error::last_os_error())));
        }

        Ok(Self { fd: file })
    }

    /// Full-duplex transfer. Sends `tx_buf` bytes and receives into `rx_buf`.
    pub fn xfer(&mut self, tx_buf: &[u8], rx_buf: &mut [u8]) -> Result<(), LoRaError> {
        use std::os::fd::AsRawFd;

        #[repr(C)]
        struct SpiIocTransfer {
            tx_buf: u64,
            rx_buf: u64,
            len: u32,
            speed_hz: u32,
            delay_usecs: u16,
            bits_per_word: u8,
            cs_change: u8,
            tx_nbits: u8,
            rx_nbits: u8,
            pad: u8,
        }

        let transfer = SpiIocTransfer {
            tx_buf: tx_buf.as_ptr() as u64,
            rx_buf: rx_buf.as_mut_ptr() as u64,
            len: tx_buf.len() as u32,
            speed_hz: 0,
            delay_usecs: 0,
            bits_per_word: 0,
            cs_change: 0,
            tx_nbits: 0,
            rx_nbits: 0,
            pad: 0,
        };

        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), SPI_IOC_MESSAGE_1 as _, &transfer) };
        if ret < 0 {
            return Err(LoRaError::Spi(format!("SPI xfer failed: {}", std::io::Error::last_os_error())));
        }
        Ok(())
    }

    /// Half-duplex write.
    pub fn write(&mut self, buf: &[u8]) -> Result<(), LoRaError> {
        use std::io::Write;
        self.fd.write_all(buf).map_err(|e| {
            LoRaError::Spi(format!("write failed: {}", e))
        })
    }
}

// ---------------------------------------------------------------------------
// Minimal GPIO abstraction using the Linux GPIO character-device v1 ioctl API
// ---------------------------------------------------------------------------
mod gpio {
    use std::fs::{File, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    const GPIOHANDLE_GET_LINE_IOCTL: u64 = 0xC228B440;
    const GPIOHANDLE_GET_LINE_VALUES_IOCTL: u64 = 0xC080B441;
    const GPIOHANDLE_SET_LINE_VALUES_IOCTL: u64 = 0xC080B442;

    #[repr(C)]
    struct GpioHandleRequest {
        lineoffsets: [u32; 64],
        flags: u32,
        default_values: [u32; 64],
        consumer_label: [u8; 32],
        fd: i32,
    }

    #[repr(C)]
    struct GpioHandleData {
        values: [u16; 64],
    }

    pub struct GpioLine {
        fd: File,
        offset: u32,
    }

    impl GpioLine {
        pub fn new_output(chip_path: &str, line: u32) -> io::Result<Self> {
            Self::request_line(chip_path, line, 2)
        }

        pub fn new_input(chip_path: &str, line: u32) -> io::Result<Self> {
            Self::request_line(chip_path, line, 1)
        }

        fn request_line(chip_path: &str, line: u32, flags: u32) -> io::Result<Self> {
            let chip = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(chip_path)?;

            let mut label = [0u8; 32];
            let label_bytes = b"rs-reticulum";
            label[..label_bytes.len()].copy_from_slice(label_bytes);

            let mut req = GpioHandleRequest {
                lineoffsets: [0; 64],
                flags,
                default_values: [0; 64],
                consumer_label: label,
                fd: 0,
            };
            req.lineoffsets[0] = line;

            let ret = unsafe {
                libc::ioctl(
                    chip.as_raw_fd(),
                    GPIOHANDLE_GET_LINE_IOCTL as _,
                    &mut req,
                )
            };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            if req.fd < 0 {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    "GPIO: invalid handle fd returned",
                ));
            }

            let handle_fd = unsafe { File::from_raw_fd(req.fd) };

            Ok(GpioLine {
                fd: handle_fd,
                offset: 0,
            })
        }

        pub fn set_value(&self, value: bool) -> io::Result<()> {
            let mut data = GpioHandleData { values: [0; 64] };
            data.values[self.offset as usize] = if value { 1 } else { 0 };
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    GPIOHANDLE_SET_LINE_VALUES_IOCTL as _,
                    &data,
                )
            };
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        pub fn get_value(&self) -> io::Result<bool> {
            let mut data = GpioHandleData { values: [0; 64] };
            let ret = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    GPIOHANDLE_GET_LINE_VALUES_IOCTL as _,
                    &mut data,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(data.values[self.offset as usize] != 0)
        }
    }
}

use gpio::GpioLine;

pub struct GpioPins {
    pub busy: Option<GpioLine>,
    pub reset: Option<GpioLine>,
    pub dio1: Option<GpioLine>,
}

impl GpioPins {
    pub fn open(config: &LoRaConfig) -> Result<Self, LoRaError> {
        let chip_path = match &config.gpio_chip {
            Some(p) => p.as_str(),
            None => return Ok(Self { busy: None, reset: None, dio1: None }),
        };

        let busy = match config.busy_line {
            Some(line) => Some(
                GpioLine::new_input(chip_path, line)
                    .map_err(|e| LoRaError::Gpio(format!("busy pin: {}", e)))?,
            ),
            None => None,
        };

        let reset = match config.reset_line {
            Some(line) => Some(
                GpioLine::new_output(chip_path, line)
                    .map_err(|e| LoRaError::Gpio(format!("reset pin: {}", e)))?,
            ),
            None => None,
        };

        let dio1 = match config.dio1_line {
            Some(line) => Some(
                GpioLine::new_input(chip_path, line)
                    .map_err(|e| LoRaError::Gpio(format!("dio1 pin: {}", e)))?,
            ),
            None => None,
        };

        Ok(Self { busy, reset, dio1 })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum LoRaError {
    Spi(String),
    Gpio(String),
    Config(String),
    Timeout,
    Io(std::io::Error),
    CrcMismatch,
    HeaderError,
    Chipset(String),
}

impl fmt::Display for LoRaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoRaError::Spi(msg) => write!(f, "SPI error: {msg}"),
            LoRaError::Gpio(msg) => write!(f, "GPIO error: {msg}"),
            LoRaError::Config(msg) => write!(f, "configuration error: {msg}"),
            LoRaError::Timeout => write!(f, "operation timed out"),
            LoRaError::Io(err) => write!(f, "I/O error: {err}"),
            LoRaError::CrcMismatch => write!(f, "CRC mismatch"),
            LoRaError::HeaderError => write!(f, "packet header error"),
            LoRaError::Chipset(msg) => write!(f, "chipset error: {msg}"),
        }
    }
}

impl std::error::Error for LoRaError {}

impl From<std::io::Error> for LoRaError {
    fn from(err: std::io::Error) -> Self {
        LoRaError::Io(err)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LoRaConfig {
    pub spi_path: String,
    pub gpio_chip: Option<String>,
    pub busy_line: Option<u32>,
    pub reset_line: Option<u32>,
    pub dio1_line: Option<u32>,
    pub frequency: u64,
    pub bandwidth: f64,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: i8,
    pub sync_word: u16,
    pub preamble_length: u16,
    pub crc_enabled: bool,
    pub implicit_header: bool,
    pub iq_inverted: bool,
    pub dio2_rf_switch: bool,
    pub tcxo_voltage: Option<f64>,
    pub spi_speed: u32,
    pub command_delay: Duration,
    pub rx_poll_interval: Duration,
    pub flow_control: bool,
}

impl LoRaConfig {
    pub fn new<T: Into<String>>(
        spi_path: T,
        frequency: u64,
        bandwidth: f64,
        tx_power: i8,
        spreading_factor: u8,
        coding_rate: u8,
    ) -> Self {
        Self {
            spi_path: spi_path.into(),
            gpio_chip: None,
            busy_line: None,
            reset_line: None,
            dio1_line: None,
            frequency,
            bandwidth,
            spreading_factor,
            coding_rate,
            tx_power,
            sync_word: DEFAULT_SYNC_WORD,
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            iq_inverted: false,
            dio2_rf_switch: false,
            tcxo_voltage: None,
            spi_speed: 4_000_000,
            command_delay: DEFAULT_COMMAND_DELAY,
            rx_poll_interval: DEFAULT_RX_POLL_INTERVAL,
            flow_control: false,
        }
    }

    pub fn with_gpio(mut self, chip: &str, busy: u32, reset: u32, dio1: u32) -> Self {
        self.gpio_chip = Some(chip.to_string());
        self.busy_line = Some(busy);
        self.reset_line = Some(reset);
        self.dio1_line = Some(dio1);
        self
    }

    pub fn with_sync_word(mut self, word: u16) -> Self {
        self.sync_word = word;
        self
    }

    pub fn with_crc(mut self, enabled: bool) -> Self {
        self.crc_enabled = enabled;
        self
    }

    pub fn with_implicit_header(mut self, enabled: bool) -> Self {
        self.implicit_header = enabled;
        self
    }

    pub fn with_iq_inverted(mut self, inverted: bool) -> Self {
        self.iq_inverted = inverted;
        self
    }

    pub fn with_dio2_rf_switch(mut self, enabled: bool) -> Self {
        self.dio2_rf_switch = enabled;
        self
    }

    pub fn with_tcxo_voltage(mut self, voltage: f64) -> Self {
        self.tcxo_voltage = Some(voltage);
        self
    }

    pub fn with_spi_speed(mut self, speed: u32) -> Self {
        self.spi_speed = speed;
        self
    }

    pub fn with_rx_poll_interval(mut self, interval: Duration) -> Self {
        self.rx_poll_interval = interval;
        self
    }

    pub fn with_flow_control(mut self, fc: bool) -> Self {
        self.flow_control = fc;
        self
    }

    pub fn validate(&self) -> Result<(), LoRaError> {
        if !(FREQ_MIN..=FREQ_MAX).contains(&self.frequency) {
            return Err(LoRaError::Config(format!(
                "frequency {} Hz out of range [{}, {}]",
                self.frequency, FREQ_MIN, FREQ_MAX
            )));
        }
        if !(SF_MIN..=SF_MAX).contains(&self.spreading_factor) {
            return Err(LoRaError::Config(format!(
                "spreading factor {} out of range [{}, {}]",
                self.spreading_factor, SF_MIN, SF_MAX
            )));
        }
        if !(CR_MIN..=CR_MAX).contains(&self.coding_rate) {
            return Err(LoRaError::Config(format!(
                "coding rate {} out of range [{}, {}]",
                self.coding_rate, CR_MIN, CR_MAX
            )));
        }
        if !(TXPOWER_MIN..=TXPOWER_MAX).contains(&self.tx_power) {
            return Err(LoRaError::Config(format!(
                "TX power {} dBm out of range [{}, {}]",
                self.tx_power, TXPOWER_MIN, TXPOWER_MAX
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Received packet from the radio chipset
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    pub payload: Vec<u8>,
    pub rssi: f32,
    pub snr: f32,
}

// ---------------------------------------------------------------------------
// LoRa chipset abstraction trait
// ---------------------------------------------------------------------------

pub trait LoRaChipset: Send {
    fn new(spi: SpiBus, gpio: GpioPins) -> Self;
    fn init(&mut self, config: &LoRaConfig) -> Result<(), LoRaError>;
    fn transmit(&mut self, payload: &[u8]) -> Result<(), LoRaError>;
    fn start_receive(&mut self) -> Result<(), LoRaError>;
    fn process_irq(&mut self) -> Result<Vec<ReceivedPacket>, LoRaError>;
    fn reset(&mut self) -> Result<(), LoRaError>;
    fn current_rssi(&mut self) -> Result<f32, LoRaError>;
}

// ---------------------------------------------------------------------------
// LoRaInterface — the Reticulum Interface wrapper
// ---------------------------------------------------------------------------

pub struct LoRaInterface<C: LoRaChipset> {
    config: LoRaConfig,
    _chipset: PhantomData<C>,
}

impl<C: LoRaChipset + 'static> LoRaInterface<C> {
    pub fn new(config: LoRaConfig) -> Self {
        Self {
            config,
            _chipset: PhantomData,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let iface_address = context.channel.address;
        let config = { context.inner.lock().unwrap().config.clone() };

        if let Err(error) = config.validate() {
            log::error!("lora_interface: invalid configuration: {}", error);
            iface_stop.cancel();
            return;
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let chipset = match Self::open_chipset(&config).await {
                Ok(c) => Arc::new(std::sync::Mutex::new(c)),
                Err(error) => {
                    log::error!(
                        "lora_interface: could not open LoRa chipset: {}",
                        error
                    );
                    tokio::select! {
                        _ = context.cancel.cancelled() => break,
                        _ = tokio::time::sleep(RECONNECT_DELAY) => {},
                    }
                    continue;
                }
            };

            log::info!("lora_interface: LoRa chipset initialised");

            let stop = CancellationToken::new();
            let (rx_packet_tx, mut rx_packet_rx) = mpsc::channel::<ReceivedPacket>(64);

            let rx_forward_handle = {
                let cancel = context.cancel.clone();
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            Some(pkt) = rx_packet_rx.recv() => {
                                if pkt.payload.len() > LORA_HW_MTU {
                                    log::warn!(
                                        "lora_interface: dropping oversized packet len={}",
                                        pkt.payload.len()
                                    );
                                    continue;
                                }
                                match Packet::deserialize(&mut InputBuffer::new(&pkt.payload)) {
                                    Ok(packet) => {
                                        let _ = rx_channel
                                            .send(RxMessage {
                                                address: iface_address,
                                                snr: Some(pkt.snr),
                                                rssi: Some(pkt.rssi as i16),
                                                packet,
                                            })
                                            .await;
                                    }
                                    Err(_) => {
                                        log::warn!(
                                            "lora_interface: couldn't decode received packet len={}",
                                            pkt.payload.len()
                                        );
                                    }
                                }
                            }
                        }
                    }
                })
            };

            let rx_poll_handle = {
                let chipset = chipset.clone();
                let cancel = context.cancel.clone();
                let stop = stop.clone();
                let rx_packet_tx = rx_packet_tx.clone();
                let poll_interval = config.rx_poll_interval;

                tokio::task::spawn_blocking(move || {
                    while !stop.is_cancelled() && !cancel.is_cancelled() {
                        std::thread::sleep(poll_interval);

                        let result = {
                            let mut cs = chipset.lock().unwrap();
                            cs.process_irq()
                        };

                        match result {
                            Ok(packets) => {
                                for pkt in packets {
                                    if rx_packet_tx.blocking_send(pkt).is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(error) => {
                                log::error!(
                                    "lora_interface: IRQ processing error: {}",
                                    error
                                );
                                stop.cancel();
                                return;
                            }
                        }
                    }
                })
            };

            let tx_handle = {
                let chipset = chipset.clone();
                let cancel = context.cancel.clone();
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();
                let config = config.clone();

                tokio::spawn(async move {
                    let mut packet_queue: VecDeque<Packet> = VecDeque::new();

                    loop {
                        if stop.is_cancelled() {
                            break;
                        }

                        if !packet_queue.is_empty() {
                            let packet = packet_queue.pop_front().unwrap();
                            if !Self::do_transmit(&chipset, packet, iface_address).await {
                                stop.cancel();
                                break;
                            }
                            continue;
                        }

                        let mut tx_channel = tx_channel.lock().await;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            Some(message) = tx_channel.recv() => {
                                if config.flow_control {
                                    packet_queue.push_back(message.packet);
                                    continue;
                                }
                                if !Self::do_transmit(&chipset, message.packet, iface_address).await {
                                    stop.cancel();
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            tokio::select! {
                _ = rx_forward_handle => {
                    stop.cancel();
                }
                _ = rx_poll_handle => {
                    stop.cancel();
                }
                _ = tx_handle => {
                    stop.cancel();
                }
                _ = context.cancel.cancelled() => {
                    stop.cancel();
                }
            }

            log::warn!("lora_interface: disconnected, reconnecting in {}s", RECONNECT_DELAY.as_secs());
            tokio::time::sleep(RECONNECT_DELAY).await;
        }

        iface_stop.cancel();
    }

    async fn open_chipset(config: &LoRaConfig) -> Result<C, LoRaError> {
        let config = config.clone();
        tokio::task::spawn_blocking(move || -> Result<C, LoRaError> {
            let spi = SpiBus::open(&config.spi_path, config.spi_speed)?;
            let gpio = GpioPins::open(&config)?;
            let mut chipset = C::new(spi, gpio);
            chipset.init(&config)?;
            chipset.start_receive()?;
            Ok(chipset)
        })
        .await
        .map_err(|e| LoRaError::Chipset(format!("spawn_blocking join: {}", e)))?
    }

    async fn do_transmit(
        chipset: &Arc<std::sync::Mutex<C>>,
        packet: Packet,
        _iface_address: crate::hash::AddressHash,
    ) -> bool {
        let mut tx_buffer = [0u8; LORA_HW_MTU];
        let mut output = OutputBuffer::new(&mut tx_buffer);
        if let Err(error) = packet.serialize(&mut output) {
            log::warn!("lora_interface: couldn't serialize outbound packet: {error}");
            return true;
        }

        let payload = output.as_slice().to_vec();
        let chipset = chipset.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut cs = chipset.lock().unwrap();
            cs.transmit(&payload)
        })
        .await;

        match result {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                log::error!("lora_interface: transmit error: {}", error);
                false
            }
            Err(e) => {
                log::error!("lora_interface: spawn_blocking join error: {}", e);
                false
            }
        }
    }
}

impl<C: LoRaChipset> Interface for LoRaInterface<C> {
    fn hw_mtu(&self) -> usize {
        LORA_HW_MTU
    }

    fn supports_discovery(&self) -> bool {
        true
    }

    fn bitrate(&self) -> Option<f64> {
        let bw = self.config.bandwidth;
        let sf = self.config.spreading_factor as f64;
        let cr = self.config.coding_rate as f64;

        if sf <= 0.0 || cr <= 0.0 || bw <= 0.0 {
            return None;
        }

        Some(sf * ((4.0 / cr) / (2.0_f64.powf(sf) / (bw / 1000.0))) * 1000.0)
    }
}
