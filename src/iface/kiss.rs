use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::{Interface, InterfaceContext, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

const FEND: u8 = 0xc0;
const FESC: u8 = 0xdb;
const TFEND: u8 = 0xdc;
const TFESC: u8 = 0xdd;

const CMD_UNKNOWN: u8 = 0xfe;
const CMD_DATA: u8 = 0x00;
const CMD_TXDELAY: u8 = 0x01;
const CMD_P: u8 = 0x02;
const CMD_SLOTTIME: u8 = 0x03;
const CMD_TXTAIL: u8 = 0x04;
const CMD_READY: u8 = 0x0f;

const MAX_CHUNK: usize = 32_768;
const HW_MTU: usize = 564;
const DEFAULT_PREAMBLE_MS: u16 = 350;
const DEFAULT_TXTAIL_MS: u16 = 20;
const DEFAULT_PERSISTENCE: u8 = 64;
const DEFAULT_SLOTTIME_MS: u16 = 20;
const DEFAULT_SPEED: u32 = 9_600;
const READ_TIMEOUT: Duration = Duration::from_millis(100);
const FLOW_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const STARTUP_DELAY: Duration = Duration::from_secs(2);

// TODO: Configure via features
const PACKET_TRACE: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KissParity {
    None,
    Even,
    Odd,
}

#[derive(Debug, Clone)]
pub struct KissInterface {
    port: String,
    speed: u32,
    databits: u8,
    parity: KissParity,
    stopbits: u8,
    preamble: u16,
    txtail: u16,
    persistence: u8,
    slottime: u16,
    flow_control: bool,
}

impl KissInterface {
    pub fn new<T: Into<String>>(port: T) -> Self {
        Self {
            port: port.into(),
            speed: DEFAULT_SPEED,
            databits: 8,
            parity: KissParity::None,
            stopbits: 1,
            preamble: DEFAULT_PREAMBLE_MS,
            txtail: DEFAULT_TXTAIL_MS,
            persistence: DEFAULT_PERSISTENCE,
            slottime: DEFAULT_SLOTTIME_MS,
            flow_control: false,
        }
    }

    pub fn with_serial_params(
        mut self,
        speed: u32,
        databits: u8,
        parity: KissParity,
        stopbits: u8,
    ) -> Self {
        self.speed = speed;
        self.databits = databits;
        self.parity = parity;
        self.stopbits = stopbits;
        self
    }

    pub fn with_kiss_params(
        mut self,
        preamble: u16,
        txtail: u16,
        persistence: u8,
        slottime: u16,
    ) -> Self {
        self.preamble = preamble;
        self.txtail = txtail;
        self.persistence = persistence;
        self.slottime = slottime;
        self
    }

    pub fn with_flow_control(mut self, flow_control: bool) -> Self {
        self.flow_control = flow_control;
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let iface_address = context.channel.address;
        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let config = { context.inner.lock().unwrap().clone() };
            let mut serial = match config.open_port() {
                Ok(serial) => tokio::fs::File::from_std(serial),
                Err(e) => {
                    log::info!(
                        "kiss_interface: couldn't open serial port <{}>: {}, retrying in {}s",
                        config.port,
                        e,
                        RECONNECT_DELAY.as_secs()
                    );
                    tokio::select! {
                        _ = context.cancel.cancelled() => break,
                        _ = tokio::time::sleep(RECONNECT_DELAY) => continue,
                    }
                }
            };

            tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = tokio::time::sleep(STARTUP_DELAY) => {}
            }

            if let Err(e) = configure_device(&mut serial, &config).await {
                log::warn!(
                    "kiss_interface: couldn't configure serial port <{}>: {}",
                    config.port,
                    e
                );
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }

            log::info!("kiss_interface: serial port <{}> is open", config.port);

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();
            let (read_serial, write_serial) = tokio::io::split(serial);
            let (ready_send, ready_recv) = mpsc::channel(8);

            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();

                tokio::spawn(async move {
                    read_loop(
                        read_serial,
                        iface_address,
                        rx_channel,
                        ready_send,
                        cancel,
                        stop,
                    )
                    .await;
                })
            };

            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let stop = stop.clone();

                tokio::spawn(async move {
                    write_loop(
                        write_serial,
                        iface_address,
                        tx_channel,
                        ready_recv,
                        config.flow_control,
                        cancel,
                        stop,
                    )
                    .await;
                })
            };

            let _ = tx_task.await;
            let _ = rx_task.await;

            log::info!("kiss_interface: serial port <{}> closed", config.port);
        }

        iface_stop.cancel();
    }

    fn open_port(&self) -> io::Result<File> {
        #[cfg(unix)]
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
                .open(&self.port)?;
            configure_serial_fd(
                file.as_raw_fd(),
                self.speed,
                self.databits,
                self.parity,
                self.stopbits,
            )?;
            Ok(file)
        }

        #[cfg(not(unix))]
        {
            let _ = self;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KISSInterface serial support is only implemented on Unix",
            ))
        }
    }
}

impl Interface for KissInterface {
    fn hw_mtu(&self) -> usize {
        HW_MTU
    }

    fn bitrate(&self) -> Option<f64> {
        if self.speed > 0 {
            Some(self.speed as f64)
        } else {
            None
        }
    }
}

async fn configure_device<W>(serial: &mut W, config: &KissInterface) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    write_command(serial, CMD_TXDELAY, &[scale_10ms(config.preamble)]).await?;
    write_command(serial, CMD_TXTAIL, &[scale_10ms(config.txtail)]).await?;
    write_command(serial, CMD_P, &[config.persistence]).await?;
    write_command(serial, CMD_SLOTTIME, &[scale_10ms(config.slottime)]).await?;
    write_command(serial, CMD_READY, &[0x01]).await?;
    serial.flush().await
}

async fn write_command<W>(serial: &mut W, command: u8, data: &[u8]) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut frame = Vec::with_capacity(data.len() + 3);
    frame.push(FEND);
    frame.push(command);
    frame.extend_from_slice(data);
    frame.push(FEND);
    serial.write_all(&frame).await
}

async fn read_loop<R>(
    mut serial: R,
    iface_address: crate::hash::AddressHash,
    rx_channel: crate::iface::InterfaceRxSender,
    ready_send: mpsc::Sender<()>,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    R: AsyncReadExt + Unpin,
{
    let mut decoder = KissDecoder::new();
    let mut chunk = [0u8; MAX_CHUNK];
    let mut idle = tokio::time::interval(READ_TIMEOUT);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = idle.tick() => {
                decoder.reset_timed_out();
            }
            result = serial.read(&mut chunk) => {
                match result {
                    Ok(0) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Ok(n) => {
                        for &byte in &chunk[..n] {
                            match decoder.push(byte) {
                                Some(KissEvent::Data(data)) => {
                                    if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&data)) {
                                        if PACKET_TRACE {
                                            log::trace!("kiss_interface: rx << ({}) {}", iface_address, packet);
                                        }
                                        let _ = rx_channel.send(RxMessage { address: iface_address, snr: None, rssi: None, packet }).await;
                                    } else {
                                        log::warn!("kiss_interface: couldn't decode packet");
                                    }
                                }
                                Some(KissEvent::Ready) => {
                                    let _ = ready_send.send(()).await;
                                }
                                None => {}
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => {
                        log::warn!("kiss_interface: serial read error {}", e);
                        stop.cancel();
                        break;
                    }
                }
            }
        }
    }
}

async fn write_loop<W>(
    mut serial: W,
    iface_address: crate::hash::AddressHash,
    tx_channel: Arc<tokio::sync::Mutex<crate::iface::InterfaceTxReceiver>>,
    mut ready_recv: mpsc::Receiver<()>,
    flow_control: bool,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    W: AsyncWriteExt + Unpin,
{
    let mut queue = VecDeque::<Vec<u8>>::new();
    let mut interface_ready = true;
    let mut locked_at: Option<tokio::time::Instant> = None;

    loop {
        if stop.is_cancelled() {
            break;
        }

        if interface_ready {
            if let Some(data) = queue.pop_front() {
                if send_payload(&mut serial, iface_address, &data)
                    .await
                    .is_err()
                {
                    stop.cancel();
                    break;
                }
                if flow_control {
                    interface_ready = false;
                    locked_at = Some(tokio::time::Instant::now());
                }
                continue;
            }
        }

        let mut tx_channel = tx_channel.lock().await;
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            Some(_) = ready_recv.recv() => {
                interface_ready = true;
                locked_at = None;
            }
            _ = tokio::time::sleep_until(locked_at.unwrap_or_else(tokio::time::Instant::now) + FLOW_CONTROL_TIMEOUT), if flow_control && !interface_ready => {
                log::warn!("kiss_interface: unlocking flow control due to READY timeout");
                interface_ready = true;
                locked_at = None;
            }
            Some(message) = tx_channel.recv() => {
                let mut tx_buffer = [0u8; HW_MTU];
                let mut output = OutputBuffer::new(&mut tx_buffer);
                if message.packet.serialize(&mut output).is_ok() {
                    queue.push_back(output.as_slice().to_vec());
                } else {
                    log::warn!("kiss_interface: couldn't encode packet");
                }
            }
        }
    }
}

async fn send_payload<W>(
    serial: &mut W,
    iface_address: crate::hash::AddressHash,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    if PACKET_TRACE {
        log::trace!(
            "kiss_interface: tx >> ({}) {} bytes",
            iface_address,
            payload.len()
        );
    }

    let frame = encode_data_frame(payload);
    serial.write_all(&frame).await?;
    serial.flush().await
}

fn encode_data_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(data.len() + 4);
    frame.push(FEND);
    frame.push(CMD_DATA);
    escape_into(data, &mut frame);
    frame.push(FEND);
    frame
}

fn escape_into(data: &[u8], frame: &mut Vec<u8>) {
    for &byte in data {
        match byte {
            FEND => frame.extend_from_slice(&[FESC, TFEND]),
            FESC => frame.extend_from_slice(&[FESC, TFESC]),
            _ => frame.push(byte),
        }
    }
}

fn scale_10ms(value_ms: u16) -> u8 {
    (value_ms / 10).min(u8::MAX as u16) as u8
}

#[derive(Debug, PartialEq, Eq)]
enum KissEvent {
    Data(Vec<u8>),
    Ready,
}

#[derive(Debug)]
struct KissDecoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    data: Vec<u8>,
}

impl KissDecoder {
    fn new() -> Self {
        Self {
            in_frame: false,
            escape: false,
            command: CMD_UNKNOWN,
            data: Vec::with_capacity(HW_MTU),
        }
    }

    fn push(&mut self, mut byte: u8) -> Option<KissEvent> {
        if self.in_frame && byte == FEND && self.command == CMD_DATA {
            self.in_frame = false;
            self.escape = false;
            self.command = CMD_UNKNOWN;
            return Some(KissEvent::Data(std::mem::take(&mut self.data)));
        }

        if byte == FEND {
            self.in_frame = true;
            self.escape = false;
            self.command = CMD_UNKNOWN;
            self.data.clear();
            return None;
        }

        if !self.in_frame || self.data.len() >= HW_MTU {
            return None;
        }

        if self.data.is_empty() && self.command == CMD_UNKNOWN {
            self.command = byte & 0x0f;
            return None;
        }

        match self.command {
            CMD_DATA => {
                if byte == FESC {
                    self.escape = true;
                    return None;
                }

                if self.escape {
                    if byte == TFEND {
                        byte = FEND;
                    } else if byte == TFESC {
                        byte = FESC;
                    }
                    self.escape = false;
                }
                self.data.push(byte);
                None
            }
            CMD_READY => Some(KissEvent::Ready),
            _ => None,
        }
    }

    fn reset_timed_out(&mut self) {
        if !self.data.is_empty() {
            self.in_frame = false;
            self.escape = false;
            self.command = CMD_UNKNOWN;
            self.data.clear();
        }
    }
}

#[cfg(unix)]
fn configure_serial_fd(
    fd: std::os::fd::RawFd,
    speed: u32,
    databits: u8,
    parity: KissParity,
    stopbits: u8,
) -> io::Result<()> {
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut termios = unsafe { termios.assume_init() };

    unsafe {
        libc::cfmakeraw(&mut termios);
    }

    termios.c_cflag |= libc::CREAD | libc::CLOCAL;
    termios.c_cflag &= !libc::CSIZE;
    termios.c_cflag |= match databits {
        5 => libc::CS5,
        6 => libc::CS6,
        7 => libc::CS7,
        _ => libc::CS8,
    };

    match parity {
        KissParity::None => {
            termios.c_cflag &= !libc::PARENB;
        }
        KissParity::Even => {
            termios.c_cflag |= libc::PARENB;
            termios.c_cflag &= !libc::PARODD;
        }
        KissParity::Odd => {
            termios.c_cflag |= libc::PARENB;
            termios.c_cflag |= libc::PARODD;
        }
    }

    if stopbits == 2 {
        termios.c_cflag |= libc::CSTOPB;
    } else {
        termios.c_cflag &= !libc::CSTOPB;
    }

    let baud = baud_constant(speed)?;
    if unsafe { libc::cfsetispeed(&mut termios, baud) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::cfsetospeed(&mut termios, baud) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
fn baud_constant(speed: u32) -> io::Result<libc::speed_t> {
    let baud = match speed {
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1_200 => libc::B1200,
        1_800 => libc::B1800,
        2_400 => libc::B2400,
        4_800 => libc::B4800,
        9_600 => libc::B9600,
        19_200 => libc::B19200,
        38_400 => libc::B38400,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        57_600 => libc::B57600,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        115_200 => libc::B115200,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        230_400 => libc::B230400,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        460_800 => libc::B460800,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        500_000 => libc::B500000,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        576_000 => libc::B576000,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        921_600 => libc::B921600,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported serial baud rate {speed}"),
            ));
        }
    };

    Ok(baud)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_data_frame_with_kiss_escaping() {
        let encoded = encode_data_frame(&[0x01, FEND, 0x02, FESC, 0x03]);
        assert_eq!(
            encoded,
            vec![
                FEND, CMD_DATA, 0x01, FESC, TFEND, 0x02, FESC, TFESC, 0x03, FEND
            ]
        );
    }

    #[test]
    fn decodes_data_frame_with_kiss_escaping() {
        let mut decoder = KissDecoder::new();
        let frame = [FEND, CMD_DATA, 0x01, FESC, TFEND, FESC, TFESC, FEND];
        let mut event = None;
        for byte in frame {
            event = decoder.push(byte).or(event);
        }

        assert_eq!(event, Some(KissEvent::Data(vec![0x01, FEND, FESC])));
    }

    #[test]
    fn strips_kiss_port_nibble_from_command() {
        let mut decoder = KissDecoder::new();
        let frame = [FEND, 0x30, 0x01, FEND];
        let mut event = None;
        for byte in frame {
            event = decoder.push(byte).or(event);
        }

        assert_eq!(event, Some(KissEvent::Data(vec![0x01])));
    }

    #[test]
    fn emits_ready_command() {
        let mut decoder = KissDecoder::new();
        let frame = [FEND, CMD_READY, 0x01, FEND];
        let mut event = None;
        for byte in frame {
            event = decoder.push(byte).or(event);
        }

        assert_eq!(event, Some(KissEvent::Ready));
    }

    #[test]
    fn clamps_ten_millisecond_config_values() {
        assert_eq!(scale_10ms(350), 35);
        assert_eq!(scale_10ms(3_000), 255);
    }

    #[test]
    fn reports_serial_speed_as_bitrate() {
        assert_eq!(KissInterface::new("/dev/null").bitrate(), Some(9_600.0));
        assert_eq!(
            KissInterface::new("/dev/null")
                .with_serial_params(38_400, 8, KissParity::None, 1)
                .bitrate(),
            Some(38_400.0)
        );
    }

    #[test]
    fn zero_serial_speed_is_not_reported_as_bitrate() {
        assert_eq!(
            KissInterface::new("/dev/null")
                .with_serial_params(0, 8, KissParity::None, 1)
                .bitrate(),
            None
        );
    }
}
