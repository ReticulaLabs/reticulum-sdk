use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_serial::{DataBits, SerialPortBuilderExt, SerialStream, StopBits};
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::{Interface, InterfaceContext, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

const RNODE_HW_MTU: usize = 508;
const SERIAL_SPEED: u32 = 115_200;
const RECONNECT_WAIT: Duration = Duration::from_secs(5);
const DETECT_TIMEOUT: Duration = Duration::from_secs(5);
const VALIDATE_TIMEOUT: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_millis(100);
const REQUIRED_FW_VER_MAJ: u8 = 1;
const REQUIRED_FW_VER_MIN: u8 = 52;
const FREQ_MIN: u64 = 137_000_000;
const FREQ_MAX: u64 = 3_000_000_000;
const BANDWIDTH_MIN: u32 = 7_800;
const BANDWIDTH_MAX: u32 = 1_625_000;
const TXPOWER_MAX: u8 = 37;
const SF_MIN: u8 = 5;
const SF_MAX: u8 = 12;
const CR_MIN: u8 = 5;
const CR_MAX: u8 = 8;
const RSSI_OFFSET: i16 = 157;

mod kiss {
    pub const FEND: u8 = 0xC0;
    pub const FESC: u8 = 0xDB;
    pub const TFEND: u8 = 0xDC;
    pub const TFESC: u8 = 0xDD;

    pub const CMD_UNKNOWN: u8 = 0xFE;
    pub const CMD_DATA: u8 = 0x00;
    pub const CMD_FREQUENCY: u8 = 0x01;
    pub const CMD_BANDWIDTH: u8 = 0x02;
    pub const CMD_TXPOWER: u8 = 0x03;
    pub const CMD_SF: u8 = 0x04;
    pub const CMD_CR: u8 = 0x05;
    pub const CMD_RADIO_STATE: u8 = 0x06;
    pub const CMD_RADIO_LOCK: u8 = 0x07;
    pub const CMD_DETECT: u8 = 0x08;
    pub const CMD_LEAVE: u8 = 0x0A;
    pub const CMD_ST_ALOCK: u8 = 0x0B;
    pub const CMD_LT_ALOCK: u8 = 0x0C;
    pub const CMD_READY: u8 = 0x0F;
    pub const CMD_STAT_RX: u8 = 0x21;
    pub const CMD_STAT_TX: u8 = 0x22;
    pub const CMD_STAT_RSSI: u8 = 0x23;
    pub const CMD_STAT_SNR: u8 = 0x24;
    pub const CMD_STAT_CHTM: u8 = 0x25;
    pub const CMD_STAT_PHYPRM: u8 = 0x26;
    pub const CMD_STAT_BAT: u8 = 0x27;
    pub const CMD_STAT_CSMA: u8 = 0x28;
    pub const CMD_STAT_TEMP: u8 = 0x29;
    pub const CMD_RANDOM: u8 = 0x40;
    pub const CMD_PLATFORM: u8 = 0x48;
    pub const CMD_MCU: u8 = 0x49;
    pub const CMD_FW_VERSION: u8 = 0x50;
    pub const CMD_RESET: u8 = 0x55;
    pub const CMD_ERROR: u8 = 0x90;

    pub const DETECT_REQ: u8 = 0x73;
    pub const DETECT_RESP: u8 = 0x46;

    pub const RADIO_STATE_OFF: u8 = 0x00;
    pub const RADIO_STATE_ON: u8 = 0x01;

    pub const ERROR_INITRADIO: u8 = 0x01;
    pub const ERROR_TXFAILED: u8 = 0x02;
    pub const ERROR_MEMORY_LOW: u8 = 0x05;
    pub const ERROR_MODEM_TIMEOUT: u8 = 0x06;

    pub const PLATFORM_ESP32: u8 = 0x80;
}

#[derive(Debug, Clone)]
pub struct RNodeConfig {
    pub port: String,
    pub frequency: u64,
    pub bandwidth: u32,
    pub txpower: u8,
    pub spreadingfactor: u8,
    pub codingrate: u8,
    pub flow_control: bool,
    pub airtime_limit_short: Option<f32>,
    pub airtime_limit_long: Option<f32>,
}

impl RNodeConfig {
    pub fn new<T: Into<String>>(
        port: T,
        frequency: u64,
        bandwidth: u32,
        txpower: u8,
        spreadingfactor: u8,
        codingrate: u8,
    ) -> Self {
        Self {
            port: port.into(),
            frequency,
            bandwidth,
            txpower,
            spreadingfactor,
            codingrate,
            flow_control: false,
            airtime_limit_short: None,
            airtime_limit_long: None,
        }
    }

    pub fn with_flow_control(mut self, flow_control: bool) -> Self {
        self.flow_control = flow_control;
        self
    }

    pub fn with_airtime_limits(mut self, short: Option<f32>, long: Option<f32>) -> Self {
        self.airtime_limit_short = short;
        self.airtime_limit_long = long;
        self
    }

    pub fn validate(&self) -> Result<(), RNodeConfigError> {
        if !(FREQ_MIN..=FREQ_MAX).contains(&self.frequency) {
            return Err(RNodeConfigError::Frequency(self.frequency));
        }
        if !(BANDWIDTH_MIN..=BANDWIDTH_MAX).contains(&self.bandwidth) {
            return Err(RNodeConfigError::Bandwidth(self.bandwidth));
        }
        if self.txpower > TXPOWER_MAX {
            return Err(RNodeConfigError::TxPower(self.txpower));
        }
        if !(SF_MIN..=SF_MAX).contains(&self.spreadingfactor) {
            return Err(RNodeConfigError::SpreadingFactor(self.spreadingfactor));
        }
        if !(CR_MIN..=CR_MAX).contains(&self.codingrate) {
            return Err(RNodeConfigError::CodingRate(self.codingrate));
        }
        if let Some(limit) = self.airtime_limit_short {
            validate_airtime_limit(limit, "short-term")?;
        }
        if let Some(limit) = self.airtime_limit_long {
            validate_airtime_limit(limit, "long-term")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RNodeConfigError {
    Frequency(u64),
    Bandwidth(u32),
    TxPower(u8),
    SpreadingFactor(u8),
    CodingRate(u8),
    AirtimeLimit { name: &'static str, value: f32 },
}

impl fmt::Display for RNodeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frequency(value) => write!(f, "invalid frequency {value}"),
            Self::Bandwidth(value) => write!(f, "invalid bandwidth {value}"),
            Self::TxPower(value) => write!(f, "invalid TX power {value}"),
            Self::SpreadingFactor(value) => write!(f, "invalid spreading factor {value}"),
            Self::CodingRate(value) => write!(f, "invalid coding rate {value}"),
            Self::AirtimeLimit { name, value } => {
                write!(f, "invalid {name} airtime limit {value}")
            }
        }
    }
}

impl std::error::Error for RNodeConfigError {}

fn validate_airtime_limit(limit: f32, name: &'static str) -> Result<(), RNodeConfigError> {
    if (0.0..=100.0).contains(&limit) {
        Ok(())
    } else {
        Err(RNodeConfigError::AirtimeLimit { name, value: limit })
    }
}

pub struct RNodeInterface {
    config: RNodeConfig,
}

impl RNodeInterface {
    pub fn new(config: RNodeConfig) -> Self {
        Self { config }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let iface_address = context.channel.address;
        let config = { context.inner.lock().unwrap().config.clone() };

        if let Err(error) = config.validate() {
            log::error!("rnode_interface: invalid configuration: {}", error);
            iface_stop.cancel();
            return;
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let stream = match open_serial(&config).await {
                Ok(stream) => stream,
                Err(error) => {
                    log::error!(
                        "rnode_interface: could not open serial port {}: {}",
                        config.port,
                        error
                    );
                    tokio::time::sleep(RECONNECT_WAIT).await;
                    continue;
                }
            };

            log::info!("rnode_interface: serial port {} is now open", config.port);

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();
            let state = Arc::new(tokio::sync::Mutex::new(RNodeState::new()));
            let ready = Arc::new(Notify::new());
            let (read_stream, write_stream) = tokio::io::split(stream);
            let write_stream = Arc::new(tokio::sync::Mutex::new(write_stream));

            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();
                let state = state.clone();
                let ready = ready.clone();

                tokio::spawn(async move {
                    read_loop(
                        read_stream,
                        iface_address,
                        rx_channel,
                        state,
                        ready,
                        cancel,
                        stop,
                    )
                    .await;
                })
            };

            let configured = configure_device(&config, &state, &ready, &write_stream).await;
            if !configured {
                stop.cancel();
                let _ = rx_task.await;
                tokio::time::sleep(RECONNECT_WAIT).await;
                continue;
            }

            log::info!(
                "rnode_interface: RNode on {} is configured and powered up",
                config.port
            );

            let tx_task = {
                let cancel = context.cancel.clone();
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();
                let state = state.clone();
                let ready = ready.clone();
                let write_stream = write_stream.clone();
                let config = config.clone();

                tokio::spawn(async move {
                    tx_loop(
                        tx_channel,
                        write_stream,
                        state,
                        ready,
                        config,
                        iface_address,
                        cancel,
                        stop,
                    )
                    .await;
                })
            };

            tokio::select! {
                _ = rx_task => {}
                _ = tx_task => {}
                _ = context.cancel.cancelled() => {
                    stop.cancel();
                }
            }

            let _ = detach(&write_stream).await;
            log::warn!("rnode_interface: disconnected from {}", config.port);
            tokio::time::sleep(RECONNECT_WAIT).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for RNodeInterface {
    fn hw_mtu(&self) -> usize {
        RNODE_HW_MTU
    }

    fn supports_discovery(&self) -> bool {
        true
    }

    fn bitrate(&self) -> Option<f64> {
        let sf = self.config.spreadingfactor as f64;
        let cr = self.config.codingrate as f64;
        let bandwidth = self.config.bandwidth as f64;

        if sf <= 0.0 || cr <= 0.0 || bandwidth <= 0.0 {
            return None;
        }

        Some(sf * ((4.0 / cr) / (2.0_f64.powf(sf) / (bandwidth / 1000.0))) * 1000.0)
    }
}

#[derive(Debug)]
struct RNodeState {
    detected: bool,
    firmware_ok: bool,
    maj_version: u8,
    min_version: u8,
    platform: Option<u8>,
    mcu: Option<u8>,
    r_frequency: Option<u64>,
    r_bandwidth: Option<u32>,
    r_txpower: Option<u8>,
    r_sf: Option<u8>,
    r_cr: Option<u8>,
    r_state: Option<u8>,
    r_lock: Option<u8>,
    r_stat_rx: Option<u32>,
    r_stat_tx: Option<u32>,
    r_stat_rssi: Option<i16>,
    r_stat_snr: Option<f32>,
    r_st_alock: Option<f32>,
    r_lt_alock: Option<f32>,
    r_airtime_short: f32,
    r_airtime_long: f32,
    r_channel_load_short: f32,
    r_channel_load_long: f32,
    r_symbol_time_ms: Option<f32>,
    r_symbol_rate: Option<u16>,
    r_preamble_symbols: Option<u16>,
    r_preamble_time_ms: Option<u16>,
    r_csma_slot_time_ms: Option<u16>,
    r_csma_difs_ms: Option<u16>,
    r_csma_cw_band: Option<u8>,
    r_csma_cw_min: Option<u8>,
    r_csma_cw_max: Option<u8>,
    r_current_rssi: Option<i16>,
    r_noise_floor: Option<i16>,
    r_interference: Option<i16>,
    r_battery_state: u8,
    r_battery_percent: u8,
    r_temperature: Option<i16>,
    r_random: Option<u8>,
    hw_errors: Vec<RNodeHardwareError>,
    interface_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RNodeHardwareError {
    code: u8,
    description: &'static str,
}

impl RNodeState {
    fn new() -> Self {
        Self {
            detected: false,
            firmware_ok: false,
            maj_version: 0,
            min_version: 0,
            platform: None,
            mcu: None,
            r_frequency: None,
            r_bandwidth: None,
            r_txpower: None,
            r_sf: None,
            r_cr: None,
            r_state: None,
            r_lock: None,
            r_stat_rx: None,
            r_stat_tx: None,
            r_stat_rssi: None,
            r_stat_snr: None,
            r_st_alock: None,
            r_lt_alock: None,
            r_airtime_short: 0.0,
            r_airtime_long: 0.0,
            r_channel_load_short: 0.0,
            r_channel_load_long: 0.0,
            r_symbol_time_ms: None,
            r_symbol_rate: None,
            r_preamble_symbols: None,
            r_preamble_time_ms: None,
            r_csma_slot_time_ms: None,
            r_csma_difs_ms: None,
            r_csma_cw_band: None,
            r_csma_cw_min: None,
            r_csma_cw_max: None,
            r_current_rssi: None,
            r_noise_floor: None,
            r_interference: None,
            r_battery_state: 0,
            r_battery_percent: 0,
            r_temperature: None,
            r_random: None,
            hw_errors: Vec::new(),
            interface_ready: false,
        }
    }

    fn radio_matches(&self, config: &RNodeConfig) -> bool {
        self.r_frequency
            .is_some_and(|frequency| config.frequency.abs_diff(frequency) <= 100)
            && self.r_bandwidth == Some(config.bandwidth)
            && self.r_txpower == Some(config.txpower)
            && self.r_sf == Some(config.spreadingfactor)
            && self.r_cr == Some(config.codingrate)
            && self.r_state == Some(kiss::RADIO_STATE_ON)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KissFrame {
    command: u8,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct KissDecoder {
    in_frame: bool,
    escape: bool,
    command: u8,
    payload: Vec<u8>,
}

impl KissDecoder {
    fn new() -> Self {
        Self {
            in_frame: false,
            escape: false,
            command: kiss::CMD_UNKNOWN,
            payload: Vec::with_capacity(RNODE_HW_MTU),
        }
    }

    fn push(&mut self, byte: u8) -> Option<KissFrame> {
        if byte == kiss::FEND {
            let frame = if self.in_frame && self.command != kiss::CMD_UNKNOWN {
                Some(KissFrame {
                    command: self.command,
                    payload: std::mem::take(&mut self.payload),
                })
            } else {
                None
            };

            self.in_frame = true;
            self.escape = false;
            self.command = kiss::CMD_UNKNOWN;
            self.payload.clear();
            return frame;
        }

        if !self.in_frame {
            return None;
        }

        if self.command == kiss::CMD_UNKNOWN {
            self.command = byte;
            return None;
        }

        let byte = if self.escape {
            self.escape = false;
            match byte {
                kiss::TFEND => kiss::FEND,
                kiss::TFESC => kiss::FESC,
                other => other,
            }
        } else if byte == kiss::FESC {
            self.escape = true;
            return None;
        } else {
            byte
        };

        if self.payload.len() >= RNODE_HW_MTU {
            self.in_frame = false;
            self.escape = false;
            self.command = kiss::CMD_UNKNOWN;
            self.payload.clear();
            return None;
        }

        self.payload.push(byte);
        None
    }
}

async fn open_serial(config: &RNodeConfig) -> Result<SerialStream, tokio_serial::Error> {
    tokio_serial::new(&config.port, SERIAL_SPEED)
        .data_bits(DataBits::Eight)
        .stop_bits(StopBits::One)
        .flow_control(tokio_serial::FlowControl::None)
        .open_native_async()
}

async fn configure_device<W>(
    config: &RNodeConfig,
    state: &Arc<tokio::sync::Mutex<RNodeState>>,
    ready: &Arc<Notify>,
    writer: &Arc<tokio::sync::Mutex<W>>,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    {
        let mut state = state.lock().await;
        *state = RNodeState::new();
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    if let Err(error) = detect(writer).await {
        log::error!(
            "rnode_interface: hardware detection write failed: {}",
            error
        );
        return false;
    }

    if !wait_for(state, DETECT_TIMEOUT, |state| state.detected).await {
        log::error!("rnode_interface: RNode detect timed out");
        return false;
    }

    {
        let state = state.lock().await;
        if !state.firmware_ok {
            log::error!(
                "rnode_interface: RNode firmware {}.{} is below required {}.{}",
                state.maj_version,
                state.min_version,
                REQUIRED_FW_VER_MAJ,
                REQUIRED_FW_VER_MIN
            );
            return false;
        }
    }

    if let Err(error) = init_radio(config, writer).await {
        log::error!(
            "rnode_interface: radio configuration write failed: {}",
            error
        );
        return false;
    }

    if !wait_for(state, VALIDATE_TIMEOUT, |state| state.radio_matches(config)).await {
        let state = state.lock().await;
        log::error!(
            "rnode_interface: radio validation failed: freq={:?}, bw={:?}, txp={:?}, sf={:?}, cr={:?}, state={:?}",
            state.r_frequency,
            state.r_bandwidth,
            state.r_txpower,
            state.r_sf,
            state.r_cr,
            state.r_state,
        );
        return false;
    }

    {
        let mut state = state.lock().await;
        state.interface_ready = true;
    }
    ready.notify_waiters();

    true
}

async fn wait_for<F>(
    state: &Arc<tokio::sync::Mutex<RNodeState>>,
    timeout: Duration,
    predicate: F,
) -> bool
where
    F: Fn(&RNodeState) -> bool,
{
    let start = tokio::time::Instant::now();
    loop {
        {
            let state = state.lock().await;
            if predicate(&state) {
                return true;
            }
        }

        if start.elapsed() >= timeout {
            return false;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn init_radio<W>(
    config: &RNodeConfig,
    writer: &Arc<tokio::sync::Mutex<W>>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_command(writer, kiss::CMD_RADIO_STATE, &[kiss::RADIO_STATE_OFF]).await?;

    write_command(
        writer,
        kiss::CMD_FREQUENCY,
        &(config.frequency as u32).to_be_bytes(),
    )
    .await?;
    write_command(writer, kiss::CMD_BANDWIDTH, &config.bandwidth.to_be_bytes()).await?;
    write_command(writer, kiss::CMD_TXPOWER, &[config.txpower]).await?;
    write_command(writer, kiss::CMD_SF, &[config.spreadingfactor]).await?;
    write_command(writer, kiss::CMD_CR, &[config.codingrate]).await?;

    if let Some(limit) = config.airtime_limit_short {
        write_airtime_limit(writer, kiss::CMD_ST_ALOCK, limit).await?;
    }
    if let Some(limit) = config.airtime_limit_long {
        write_airtime_limit(writer, kiss::CMD_LT_ALOCK, limit).await?;
    }

    log::info!(
        "rnode: configured freq={} Hz bw={} kHz sf={} cr={} power={} dBm",
        config.frequency,
        config.bandwidth / 1000,
        config.spreadingfactor,
        config.codingrate,
        config.txpower,
    );
    write_command(writer, kiss::CMD_RADIO_STATE, &[kiss::RADIO_STATE_ON]).await
}

async fn write_airtime_limit<W>(
    writer: &Arc<tokio::sync::Mutex<W>>,
    command: u8,
    limit: f32,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let value = (limit * 100.0).round().clamp(0.0, u16::MAX as f32) as u16;
    write_command(writer, command, &value.to_be_bytes()).await
}

async fn detect<W>(writer: &Arc<tokio::sync::Mutex<W>>) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = writer.lock().await;
    write_frame(&mut *writer, kiss::CMD_DETECT, &[kiss::DETECT_REQ]).await?;
    write_frame(&mut *writer, kiss::CMD_FW_VERSION, &[0x00]).await?;
    write_frame(&mut *writer, kiss::CMD_PLATFORM, &[0x00]).await?;
    write_frame(&mut *writer, kiss::CMD_MCU, &[0x00]).await?;
    writer.flush().await
}

async fn detach<W>(writer: &Arc<tokio::sync::Mutex<W>>) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_command(writer, kiss::CMD_RADIO_STATE, &[kiss::RADIO_STATE_OFF]).await?;
    write_command(writer, kiss::CMD_LEAVE, &[0xFF]).await
}

async fn write_command<W>(
    writer: &Arc<tokio::sync::Mutex<W>>,
    command: u8,
    payload: &[u8],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = writer.lock().await;
    write_frame(&mut *writer, command, payload).await?;
    writer.flush().await
}

async fn write_frame<W>(writer: &mut W, command: u8, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_frame(command, payload);
    writer.write_all(&frame).await
}

fn encode_frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 3);
    frame.push(kiss::FEND);
    frame.push(command);
    for &byte in payload {
        match byte {
            kiss::FEND => frame.extend_from_slice(&[kiss::FESC, kiss::TFEND]),
            kiss::FESC => frame.extend_from_slice(&[kiss::FESC, kiss::TFESC]),
            other => frame.push(other),
        }
    }
    frame.push(kiss::FEND);
    frame
}

async fn read_loop<R>(
    mut reader: R,
    iface_address: crate::hash::AddressHash,
    rx_channel: crate::iface::InterfaceRxSender,
    state: Arc<tokio::sync::Mutex<RNodeState>>,
    ready: Arc<Notify>,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    R: AsyncRead + Unpin,
{
    let mut decoder = KissDecoder::new();
    let mut buffer = [0u8; 256];
    let mut last_read = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            result = reader.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        log::warn!("rnode_interface: serial port closed");
                        stop.cancel();
                        break;
                    }
                    Ok(n) => {
                        last_read = tokio::time::Instant::now();
                        for &byte in &buffer[..n] {
                            if let Some(frame) = decoder.push(byte) {
                                if !handle_frame(frame, iface_address, &rx_channel, &state, &ready).await {
                                    stop.cancel();
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        log::warn!("rnode_interface: serial read error: {}", error);
                        stop.cancel();
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(last_read + READ_TIMEOUT) => {
                decoder = KissDecoder::new();
                last_read = tokio::time::Instant::now();
            }
        }
    }
}

async fn handle_frame(
    frame: KissFrame,
    iface_address: crate::hash::AddressHash,
    rx_channel: &crate::iface::InterfaceRxSender,
    state: &Arc<tokio::sync::Mutex<RNodeState>>,
    ready: &Arc<Notify>,
) -> bool {
    match frame.command {
        kiss::CMD_DATA => {
            if frame.payload.len() > RNODE_HW_MTU {
                log::warn!(
                    "rnode_interface: dropping oversized RNode frame len={}",
                    frame.payload.len()
                );
                return true;
            }

            match Packet::deserialize(&mut InputBuffer::new(&frame.payload)) {
                Ok(packet) => {
                    log::trace!("rnode_interface: rx << ({}) {} bytes", iface_address, frame.payload.len());
                    let rstate = state.lock().await;
                    let snr = rstate.r_stat_snr;
                    let rssi = rstate.r_stat_rssi;
                    drop(rstate);
                    let _ = rx_channel
                        .send(RxMessage {
                            address: iface_address,
                            snr,
                            rssi,
                            packet,
                        })
                        .await;
                }
                Err(_) => {
                    log::warn!(
                        "rnode_interface: couldn't decode packet len={}",
                        frame.payload.len()
                    );
                }
            }
            true
        }
        kiss::CMD_READY => {
            let mut state = state.lock().await;
            state.interface_ready = true;
            ready.notify_waiters();
            true
        }
        _ => update_command_state(frame, state, ready).await,
    }
}

async fn update_command_state(
    frame: KissFrame,
    state: &Arc<tokio::sync::Mutex<RNodeState>>,
    ready: &Arc<Notify>,
) -> bool {
    let mut state = state.lock().await;
    let keep_running = match frame.command {
        kiss::CMD_DETECT => {
            state.detected = frame.payload.first() == Some(&kiss::DETECT_RESP);
            true
        }
        kiss::CMD_FW_VERSION if frame.payload.len() >= 2 => {
            state.maj_version = frame.payload[0];
            state.min_version = frame.payload[1];
            state.firmware_ok = state.maj_version > REQUIRED_FW_VER_MAJ
                || (state.maj_version == REQUIRED_FW_VER_MAJ
                    && state.min_version >= REQUIRED_FW_VER_MIN);
            true
        }
        kiss::CMD_FREQUENCY if frame.payload.len() >= 4 => {
            state.r_frequency =
                Some(u32::from_be_bytes(frame.payload[..4].try_into().unwrap()) as u64);
            true
        }
        kiss::CMD_BANDWIDTH if frame.payload.len() >= 4 => {
            state.r_bandwidth = Some(u32::from_be_bytes(frame.payload[..4].try_into().unwrap()));
            true
        }
        kiss::CMD_TXPOWER => {
            state.r_txpower = frame.payload.first().copied();
            true
        }
        kiss::CMD_SF => {
            state.r_sf = frame.payload.first().copied();
            true
        }
        kiss::CMD_CR => {
            state.r_cr = frame.payload.first().copied();
            true
        }
        kiss::CMD_RADIO_STATE => {
            state.r_state = frame.payload.first().copied();
            if state.r_state == Some(kiss::RADIO_STATE_ON) {
                state.interface_ready = true;
                ready.notify_waiters();
            }
            true
        }
        kiss::CMD_RADIO_LOCK => {
            state.r_lock = frame.payload.first().copied();
            true
        }
        kiss::CMD_STAT_RX if frame.payload.len() >= 4 => {
            state.r_stat_rx = Some(read_u32(&frame.payload));
            true
        }
        kiss::CMD_STAT_TX if frame.payload.len() >= 4 => {
            state.r_stat_tx = Some(read_u32(&frame.payload));
            true
        }
        kiss::CMD_STAT_RSSI => {
            state.r_stat_rssi = frame.payload.first().map(|rssi| *rssi as i16 - RSSI_OFFSET);
            true
        }
        kiss::CMD_STAT_SNR => {
            state.r_stat_snr = frame
                .payload
                .first()
                .map(|snr| i8::from_be_bytes([*snr]) as f32 * 0.25);
            true
        }
        kiss::CMD_ST_ALOCK if frame.payload.len() >= 2 => {
            state.r_st_alock = Some(read_u16(&frame.payload) as f32 / 100.0);
            true
        }
        kiss::CMD_LT_ALOCK if frame.payload.len() >= 2 => {
            state.r_lt_alock = Some(read_u16(&frame.payload) as f32 / 100.0);
            true
        }
        kiss::CMD_STAT_CHTM if frame.payload.len() >= 11 => {
            state.r_airtime_short = read_u16(&frame.payload[0..2]) as f32 / 100.0;
            state.r_airtime_long = read_u16(&frame.payload[2..4]) as f32 / 100.0;
            state.r_channel_load_short = read_u16(&frame.payload[4..6]) as f32 / 100.0;
            state.r_channel_load_long = read_u16(&frame.payload[6..8]) as f32 / 100.0;
            state.r_current_rssi = Some(frame.payload[8] as i16 - RSSI_OFFSET);
            state.r_noise_floor = Some(frame.payload[9] as i16 - RSSI_OFFSET);
            state.r_interference = if frame.payload[10] == 0xff {
                None
            } else {
                Some(frame.payload[10] as i16 - RSSI_OFFSET)
            };
            true
        }
        kiss::CMD_STAT_PHYPRM if frame.payload.len() >= 12 => {
            state.r_symbol_time_ms = Some(read_u16(&frame.payload[0..2]) as f32 / 1000.0);
            state.r_symbol_rate = Some(read_u16(&frame.payload[2..4]));
            state.r_preamble_symbols = Some(read_u16(&frame.payload[4..6]));
            state.r_preamble_time_ms = Some(read_u16(&frame.payload[6..8]));
            state.r_csma_slot_time_ms = Some(read_u16(&frame.payload[8..10]));
            state.r_csma_difs_ms = Some(read_u16(&frame.payload[10..12]));
            true
        }
        kiss::CMD_STAT_CSMA if frame.payload.len() >= 3 => {
            state.r_csma_cw_band = Some(frame.payload[0]);
            state.r_csma_cw_min = Some(frame.payload[1]);
            state.r_csma_cw_max = Some(frame.payload[2]);
            true
        }
        kiss::CMD_STAT_BAT if frame.payload.len() >= 2 => {
            state.r_battery_state = frame.payload[0];
            state.r_battery_percent = frame.payload[1].min(100);
            true
        }
        kiss::CMD_STAT_TEMP => {
            state.r_temperature = frame.payload.first().and_then(|temp| {
                let temp = *temp as i16 - 120;
                (-30..=90).contains(&temp).then_some(temp)
            });
            true
        }
        kiss::CMD_RANDOM => {
            state.r_random = frame.payload.first().copied();
            true
        }
        kiss::CMD_PLATFORM => {
            state.platform = frame.payload.first().copied();
            log::debug!(
                "rnode_interface: platform report {:?}",
                frame.payload.first().copied()
            );
            true
        }
        kiss::CMD_MCU => {
            state.mcu = frame.payload.first().copied();
            log::debug!(
                "rnode_interface: mcu report {:?}",
                frame.payload.first().copied()
            );
            true
        }
        kiss::CMD_ERROR => {
            let Some(code) = frame.payload.first().copied() else {
                return true;
            };

            match code {
                kiss::ERROR_INITRADIO => {
                    log::error!("rnode_interface: hardware initialisation error");
                    false
                }
                kiss::ERROR_TXFAILED => {
                    log::error!("rnode_interface: hardware TX error");
                    false
                }
                kiss::ERROR_MEMORY_LOW => {
                    state.hw_errors.push(RNodeHardwareError {
                        code,
                        description: "Memory exhausted on connected device",
                    });
                    log::error!("rnode_interface: hardware memory exhausted");
                    true
                }
                kiss::ERROR_MODEM_TIMEOUT => {
                    state.hw_errors.push(RNodeHardwareError {
                        code,
                        description: "Modem communication timed out on connected device",
                    });
                    log::error!("rnode_interface: hardware modem timeout");
                    true
                }
                _ => {
                    log::error!("rnode_interface: unknown hardware error code {}", code);
                    false
                }
            }
        }
        kiss::CMD_RESET => {
            log::warn!("rnode_interface: device reset report {:?}", frame.payload);
            !(state.platform == Some(kiss::PLATFORM_ESP32) && frame.payload.first() == Some(&0xf8))
        }
        _ => true,
    };

    keep_running
}

fn read_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes(data[..2].try_into().unwrap())
}

fn read_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().unwrap())
}

async fn tx_loop<W>(
    tx_channel: Arc<tokio::sync::Mutex<crate::iface::InterfaceTxReceiver>>,
    writer: Arc<tokio::sync::Mutex<W>>,
    state: Arc<tokio::sync::Mutex<RNodeState>>,
    ready: Arc<Notify>,
    config: RNodeConfig,
    iface_address: crate::hash::AddressHash,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    W: AsyncWrite + Unpin,
{
    let mut packet_queue = VecDeque::new();

    loop {
        if stop.is_cancelled() {
            break;
        }

        if config.flow_control && !packet_queue.is_empty() && is_interface_ready(&state).await {
            if let Some(packet) = packet_queue.pop_front() {
                if let Err(error) =
                    send_packet(&writer, &state, &config, packet, iface_address).await
                {
                    log::warn!("rnode_interface: serial write error: {}", error);
                    stop.cancel();
                    break;
                }
                continue;
            }
        }

        let mut tx_channel = tx_channel.lock().await;
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = ready.notified(), if config.flow_control && !packet_queue.is_empty() => {}
            Some(message) = tx_channel.recv() => {
                let packet = message.packet;
                if config.flow_control && !is_interface_ready(&state).await {
                    packet_queue.push_back(packet);
                    continue;
                }

                if let Err(error) = send_packet(&writer, &state, &config, packet, iface_address).await {
                    log::warn!("rnode_interface: serial write error: {}", error);
                    stop.cancel();
                    break;
                }
            }
        };
    }
}

async fn is_interface_ready(state: &Arc<tokio::sync::Mutex<RNodeState>>) -> bool {
    state.lock().await.interface_ready
}

async fn send_packet<W>(
    writer: &Arc<tokio::sync::Mutex<W>>,
    state: &Arc<tokio::sync::Mutex<RNodeState>>,
    config: &RNodeConfig,
    packet: Packet,
    iface_address: crate::hash::AddressHash,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut tx_buffer = [0u8; core::mem::size_of::<Packet>() * 2];
    let mut output = OutputBuffer::new(&mut tx_buffer);
    if packet.serialize(&mut output).is_err() {
        log::warn!("rnode_interface: couldn't serialize outbound packet");
        return Ok(());
    }

    if output.offset() > RNODE_HW_MTU {
        log::warn!(
            "rnode_interface: dropping oversized outbound packet len={} mtu={}",
            output.offset(),
            RNODE_HW_MTU
        );
        return Ok(());
    }

    log::trace!("rnode_interface: tx >> ({}) {} bytes", iface_address, output.offset());

    if config.flow_control {
        let mut state = state.lock().await;
        state.interface_ready = false;
    }

    write_command(writer, kiss::CMD_DATA, output.as_slice()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kiss_frame_escapes_fend_and_fesc() {
        let encoded = encode_frame(kiss::CMD_DATA, &[0x01, kiss::FEND, kiss::FESC, 0x02]);
        assert_eq!(
            encoded,
            vec![
                kiss::FEND,
                kiss::CMD_DATA,
                0x01,
                kiss::FESC,
                kiss::TFEND,
                kiss::FESC,
                kiss::TFESC,
                0x02,
                kiss::FEND,
            ]
        );

        let mut decoder = KissDecoder::new();
        let frame = encoded.into_iter().find_map(|byte| decoder.push(byte));
        assert_eq!(
            frame,
            Some(KissFrame {
                command: kiss::CMD_DATA,
                payload: vec![0x01, kiss::FEND, kiss::FESC, 0x02],
            })
        );
    }

    #[test]
    fn kiss_decoder_ignores_bytes_before_frame() {
        let mut decoder = KissDecoder::new();
        assert_eq!(decoder.push(0x01), None);
        assert_eq!(decoder.push(0x02), None);

        let encoded = encode_frame(kiss::CMD_READY, &[]);
        let frame = encoded.into_iter().find_map(|byte| decoder.push(byte));
        assert_eq!(
            frame,
            Some(KissFrame {
                command: kiss::CMD_READY,
                payload: vec![],
            })
        );
    }

    #[test]
    fn config_validation_matches_python_bounds() {
        assert!(
            RNodeConfig::new("/dev/ttyUSB0", 915_000_000, 125_000, 22, 7, 5)
                .with_airtime_limits(Some(50.0), Some(75.5))
                .validate()
                .is_ok()
        );

        assert_eq!(
            RNodeConfig::new("/dev/ttyUSB0", 136_999_999, 125_000, 22, 7, 5).validate(),
            Err(RNodeConfigError::Frequency(136_999_999))
        );
        assert_eq!(
            RNodeConfig::new("/dev/ttyUSB0", 915_000_000, 7_799, 22, 7, 5).validate(),
            Err(RNodeConfigError::Bandwidth(7_799))
        );
        assert_eq!(
            RNodeConfig::new("/dev/ttyUSB0", 915_000_000, 125_000, 38, 7, 5).validate(),
            Err(RNodeConfigError::TxPower(38))
        );
        assert_eq!(
            RNodeConfig::new("/dev/ttyUSB0", 915_000_000, 125_000, 22, 4, 5).validate(),
            Err(RNodeConfigError::SpreadingFactor(4))
        );
        assert_eq!(
            RNodeConfig::new("/dev/ttyUSB0", 915_000_000, 125_000, 22, 7, 9).validate(),
            Err(RNodeConfigError::CodingRate(9))
        );
        assert_eq!(
            RNodeConfig::new("/dev/ttyUSB0", 915_000_000, 125_000, 22, 7, 5)
                .with_airtime_limits(Some(101.0), None)
                .validate(),
            Err(RNodeConfigError::AirtimeLimit {
                name: "short-term",
                value: 101.0
            })
        );
    }

    #[tokio::test]
    async fn command_state_tracks_python_status_reports() {
        let state = Arc::new(tokio::sync::Mutex::new(RNodeState::new()));
        let ready = Arc::new(Notify::new());

        assert!(
            update_command_state(
                KissFrame {
                    command: kiss::CMD_STAT_RSSI,
                    payload: vec![200],
                },
                &state,
                &ready,
            )
            .await
        );
        assert!(
            update_command_state(
                KissFrame {
                    command: kiss::CMD_STAT_SNR,
                    payload: vec![0xf8],
                },
                &state,
                &ready,
            )
            .await
        );
        assert!(
            update_command_state(
                KissFrame {
                    command: kiss::CMD_STAT_CHTM,
                    payload: vec![
                        0x04, 0xd2, 0x09, 0xc4, 0x00, 0x64, 0x00, 0xc8, 180, 120, 0xff
                    ],
                },
                &state,
                &ready,
            )
            .await
        );
        assert!(
            update_command_state(
                KissFrame {
                    command: kiss::CMD_STAT_BAT,
                    payload: vec![0x02, 150],
                },
                &state,
                &ready,
            )
            .await
        );
        assert!(
            update_command_state(
                KissFrame {
                    command: kiss::CMD_STAT_TEMP,
                    payload: vec![145],
                },
                &state,
                &ready,
            )
            .await
        );

        let state = state.lock().await;
        assert_eq!(state.r_stat_rssi, Some(43));
        assert_eq!(state.r_stat_snr, Some(-2.0));
        assert_eq!(state.r_airtime_short, 12.34);
        assert_eq!(state.r_airtime_long, 25.0);
        assert_eq!(state.r_channel_load_short, 1.0);
        assert_eq!(state.r_channel_load_long, 2.0);
        assert_eq!(state.r_current_rssi, Some(23));
        assert_eq!(state.r_noise_floor, Some(-37));
        assert_eq!(state.r_interference, None);
        assert_eq!(state.r_battery_state, 0x02);
        assert_eq!(state.r_battery_percent, 100);
        assert_eq!(state.r_temperature, Some(25));
    }

    #[tokio::test]
    async fn hardware_error_reports_nonfatal_and_fatal_errors() {
        let state = Arc::new(tokio::sync::Mutex::new(RNodeState::new()));
        let ready = Arc::new(Notify::new());

        assert!(
            update_command_state(
                KissFrame {
                    command: kiss::CMD_ERROR,
                    payload: vec![kiss::ERROR_MEMORY_LOW],
                },
                &state,
                &ready,
            )
            .await
        );
        assert!(
            !update_command_state(
                KissFrame {
                    command: kiss::CMD_ERROR,
                    payload: vec![kiss::ERROR_TXFAILED],
                },
                &state,
                &ready,
            )
            .await
        );

        let state = state.lock().await;
        assert_eq!(state.hw_errors.len(), 1);
        assert_eq!(state.hw_errors[0].code, kiss::ERROR_MEMORY_LOW);
    }
}
