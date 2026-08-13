use std::cmp;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio_util::sync::CancellationToken;

use crate::iface::{
    decode_rx, encode_tx, IfacConfig, DEFAULT_HW_MTU, INITIAL_RECONNECT_BACKOFF, Interface,
    InterfaceContext, InterfaceMode, MAX_AUTOCONFIGURED_HW_MTU, MAX_RECONNECT_BACKOFF, RxMessage,
    configured_bitrate,
};

const FEND: u8 = 0xc0;
const FESC: u8 = 0xdb;
const TFEND: u8 = 0xdc;
const TFESC: u8 = 0xdd;

const CMD_UNKNOWN: u8 = 0xfe;
const CMD_DATA: u8 = 0x00;

const DEFAULT_KISS_ADDR: &str = "127.0.0.1:8001";
const DEFAULT_CONTROL_ADDR: &str = "127.0.0.1:8073";
const DEFAULT_MTU_OVERHEAD: usize = 15;
const DEFAULT_BITRATE: f64 = 600.0;
const RETICULUM_BASE_MTU: usize = 500;
const CONTROL_RECONNECT_WAIT: Duration = Duration::from_secs(5);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_READ_BUFFER_SIZE: usize = 16 * 1024;
const MAX_CONTROL_MESSAGE_SIZE: usize = 1024 * 1024;

// Modem types reported in `get_config`.
const MODEM_OFDM: i64 = 0;
const MODEM_MFSK: i64 = 1;
const MODEM_ROBUST: i64 = 2;

// Physical bitrate (bps) per `robust_mode`, matching the reference
// `Modem73Interface.ROBUST_BPS` and the modem73 `CONTROL_PORT.md`
// documentation. Modes 10/11 (RDM-800 / RDM-800S) were added in modem73 2.x.
const ROBUST_BPS: &[f64] = &[
    1150.0, 585.0, 296.0, 296.0, 149.0, 732.0, 378.0, 194.0, 197.0, 99.0, 780.0, 510.0,
];

// On-air frame time in seconds per OFDM modulation: (short, normal, long).
// Matches the reference `Modem73Interface.OFDM_AIRTIME`.
const OFDM_AIRTIME: &[(&str, (f64, f64, f64))] = &[
    ("BPSK", (1.64, 2.73, 4.92)),
    ("QPSK", (1.09, 2.73, 4.92)),
    ("8PSK", (2.05, 3.55, 6.56)),
    ("QAM16", (1.09, 2.73, 4.92)),
    ("QAM64", (2.05, 3.55, 6.56)),
    ("QAM256", (1.64, 2.73, 4.92)),
    ("QAM1024", (2.32, 4.10, 4.10)),
    ("QAM4096", (2.05, 3.55, 3.55)),
];

// TODO: Configure via features
const PACKET_TRACE: bool = false;

#[derive(Debug, Clone)]
pub struct Modem73Interface {
    kiss_addr: String,
    control_addr: String,
    mtu_overhead: usize,
    /// Live bitrate in bps (stored as `f64` bits), derived from the TNC
    /// `get_config` response. Shared with the interface manager so data
    /// pacing tracks the current modem configuration.
    bitrate: Arc<AtomicU64>,
    auto_fragmentation: bool,
    current_mtu: Arc<AtomicUsize>,
    fragmentation_target: Arc<AtomicBool>,
    mode: InterfaceMode,
}

impl Default for Modem73Interface {
    fn default() -> Self {
        Self::new(DEFAULT_KISS_ADDR, DEFAULT_CONTROL_ADDR)
    }
}

impl Modem73Interface {
    pub fn new<T: Into<String>, U: Into<String>>(kiss_addr: T, control_addr: U) -> Self {
        Self {
            kiss_addr: kiss_addr.into(),
            control_addr: control_addr.into(),
            mtu_overhead: DEFAULT_MTU_OVERHEAD,
            bitrate: Arc::new(AtomicU64::new(f64::to_bits(DEFAULT_BITRATE))),
            auto_fragmentation: true,
            current_mtu: Arc::new(AtomicUsize::new(RETICULUM_BASE_MTU)),
            fragmentation_target: Arc::new(AtomicBool::new(false)),
            mode: InterfaceMode::Full,
        }
    }

    pub fn new_with_defaults() -> Self {
        Self::default()
    }

    pub fn with_mtu_overhead(mut self, mtu_overhead: usize) -> Self {
        self.mtu_overhead = mtu_overhead;
        self
    }

    pub fn with_bitrate(self, bitrate: f64) -> Self {
        self.bitrate.store(f64::to_bits(bitrate), Ordering::Relaxed);
        self
    }

    pub fn with_auto_fragmentation(mut self, auto_fragmentation: bool) -> Self {
        self.auto_fragmentation = auto_fragmentation;
        self
    }

    pub fn with_interface_mode(mut self, mode: InterfaceMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn current_mtu(&self) -> usize {
        self.current_mtu.load(Ordering::Relaxed)
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let iface_address = context.channel.address;
        let config = { context.inner.lock().unwrap().clone() };
        let ifac_config = context.channel.ifac_config();
        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let initial_mtu = query_initial_mtu(&config).await.unwrap_or_else(|| {
            let fallback = RETICULUM_BASE_MTU;
            log::warn!(
                "modem73_interface: could not reach control port at <{}>, starting with MTU {}",
                config.control_addr,
                fallback
            );
            fallback
        });
        config.current_mtu.store(initial_mtu, Ordering::Relaxed);

        let control_task = {
            let config = config.clone();
            let cancel = context.cancel.clone();
            tokio::spawn(async move {
                control_loop(config, cancel).await;
            })
        };

        let mut reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
        'outer: loop {
            if context.cancel.is_cancelled() {
                break;
            }

            // Connect to completion without draining the transmit channel.
            // Previously, outbound traffic arriving while the connect was
            // in flight would fire a `tx_channel.recv()` branch, aborting
            // the connect and restarting it from scratch (and dropping the
            // message).  Messages now simply queue in the bounded tx
            // channel and are drained by the transmit task once the
            // connection is established.
            let stream = tokio::select! {
                biased;
                _ = context.cancel.cancelled() => break,
                result = TcpStream::connect(config.kiss_addr.clone()) => result,
            };

            let stream = match stream {
                Ok(stream) => stream,
                Err(error) => {
                    log::info!(
                        "modem73_interface: couldn't connect to KISS data port <{}>: {}, retrying in {}s",
                        config.kiss_addr,
                        error,
                        reconnect_backoff.as_secs()
                    );
                    let retry_at =
                        tokio::time::Instant::now() + super::jitter_reconnect_delay(reconnect_backoff);
                    reconnect_backoff =
                        cmp::min(reconnect_backoff.saturating_mul(2), MAX_RECONNECT_BACKOFF);

                    if super::await_reconnect_delay(&context.cancel, &tx_channel, retry_at).await
                    {
                        break 'outer;
                    }
                    continue;
                }
            };

            let connected_at = tokio::time::Instant::now();
            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();
            let (read_stream, write_stream) = stream.into_split();

            log::info!(
                "modem73_interface: KISS data port connected <{}>",
                config.kiss_addr
            );

            let rx_task = {
                let rx_channel = rx_channel.clone();
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mtu = config.current_mtu.clone();
                let ifac_config = ifac_config.clone();

                tokio::spawn(async move {
                    read_loop(read_stream, iface_address, rx_channel, mtu, cancel, stop, ifac_config)
                        .await;
                })
            };

            let tx_task = {
                let tx_channel = tx_channel.clone();
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mtu = config.current_mtu.clone();
                let ifac_config = ifac_config.clone();

                tokio::spawn(async move {
                    write_loop(
                        write_stream,
                        iface_address,
                        tx_channel,
                        mtu,
                        cancel,
                        stop,
                        ifac_config,
                    )
                    .await;
                })
            };

            let _ = tx_task.await;
            let _ = rx_task.await;

            log::info!(
                "modem73_interface: KISS data port disconnected <{}>",
                config.kiss_addr
            );

            // Reconnecting immediately after a dropped connection can turn
            // accept-then-drop peers into a reconnect storm.  Apply the
            // same 1s→30s exponential backoff used for failed connections,
            // resetting it after a connection that stayed up long enough to
            // be considered stable.
            let delay = super::jitter_reconnect_delay(super::reconnect_backoff_after_drop(
                connected_at,
                &mut reconnect_backoff,
                INITIAL_RECONNECT_BACKOFF,
                MAX_RECONNECT_BACKOFF,
            ));
            let retry_at = tokio::time::Instant::now() + delay;

            if super::await_reconnect_delay(&context.cancel, &tx_channel, retry_at).await {
                break 'outer;
            }
        }

        let _ = control_task.await;
        iface_stop.cancel();
    }
}

impl Interface for Modem73Interface {
    fn hw_mtu(&self) -> usize {
        self.current_mtu.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn bitrate(&self) -> Option<f64> {
        configured_bitrate(f64::from_bits(self.bitrate.load(Ordering::Relaxed)))
    }

    fn bitrate_source(&self) -> Option<Arc<AtomicU64>> {
        Some(self.bitrate.clone())
    }

    fn autoconfigure_mtu(&self) -> bool {
        true
    }

    fn hw_mtu_source(&self) -> Option<Arc<AtomicUsize>> {
        Some(self.current_mtu.clone())
    }

    fn interface_mode(&self) -> InterfaceMode {
        self.mode
    }
}

async fn query_initial_mtu(config: &Modem73Interface) -> Option<usize> {
    let stream = match tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        TcpStream::connect(config.control_addr.clone()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            log::warn!(
                "modem73_interface: initial control-port query failed: {}",
                error
            );
            return None;
        }
        Err(_) => {
            log::warn!("modem73_interface: initial control-port query timed out");
            return None;
        }
    };

    let (mut read, mut write) = stream.into_split();
    if let Err(error) = send_control_command(&mut write, &json!({ "cmd": "get_config" })).await {
        log::warn!(
            "modem73_interface: initial get_config command failed: {}",
            error
        );
        return None;
    }

    match recv_control_message(&mut read).await {
        Ok(Some(message)) => {
            if let Some(bitrate) = derive_bitrate(&message) {
                config.bitrate.store(f64::to_bits(bitrate), Ordering::Relaxed);
                log::info!(
                    "modem73_interface: derived bitrate {} bps from TNC configuration",
                    bitrate as u64
                );
            }
            payload_size(&message).map(|payload_size| compute_mtu(config, payload_size))
        }
        Ok(None) => None,
        Err(error) => {
            log::warn!(
                "modem73_interface: initial control response failed: {}",
                error
            );
            None
        }
    }
}

async fn control_loop(config: Modem73Interface, cancel: CancellationToken) {
    loop {
        if cancel.is_cancelled() {
            break;
        }

        let stream = match tokio::time::timeout(
            CONTROL_CONNECT_TIMEOUT,
            TcpStream::connect(config.control_addr.clone()),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                log::warn!(
                    "modem73_interface: control port <{}> error: {}",
                    config.control_addr,
                    error
                );
                wait_control_retry(&cancel).await;
                continue;
            }
            Err(_) => {
                log::warn!(
                    "modem73_interface: control port <{}> connect timed out",
                    config.control_addr
                );
                wait_control_retry(&cancel).await;
                continue;
            }
        };

        log::debug!(
            "modem73_interface: control port connected <{}>",
            config.control_addr
        );

        let (mut read, mut write) = stream.into_split();
        if let Err(error) = send_control_command(&mut write, &json!({ "cmd": "get_config" })).await
        {
            log::warn!("modem73_interface: control get_config failed: {}", error);
            wait_control_retry(&cancel).await;
            continue;
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                message = recv_control_message(&mut read) => {
                    match message {
                        Ok(Some(message)) => {
                            handle_control_message(&config, &mut write, message).await;
                        }
                        Ok(None) => break,
                        Err(error) => {
                            log::warn!("modem73_interface: control receive error: {}", error);
                            break;
                        }
                    }
                }
            }
        }

        wait_control_retry(&cancel).await;
    }
}

async fn wait_control_retry(cancel: &CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(CONTROL_RECONNECT_WAIT) => {}
    }
}

async fn handle_control_message(
    config: &Modem73Interface,
    write: &mut OwnedWriteHalf,
    message: Value,
) {
    // `config_changed` events carry the configuration in a nested "config"
    // object; `get_config` replies carry it at the top level.
    let cfg = if message.get("event").and_then(Value::as_str) == Some("config_changed") {
        message.get("config")
    } else {
        Some(&message)
    };
    let Some(cfg) = cfg else {
        return;
    };

    if let Some(bitrate) = derive_bitrate(cfg) {
        let old_bitrate = config.bitrate.swap(f64::to_bits(bitrate), Ordering::Relaxed);
        if f64::from_bits(old_bitrate) != bitrate {
            log::info!(
                "modem73_interface: bitrate {} -> {} bps (TNC configuration change)",
                f64::from_bits(old_bitrate) as u64,
                bitrate as u64
            );
        }
    }

    let Some(payload_size) = payload_size(cfg) else {
        return;
    };

    let new_mtu = compute_mtu(config, payload_size);
    let old_mtu = config.current_mtu.swap(new_mtu, Ordering::Relaxed);
    if old_mtu != new_mtu {
        log::info!(
            "modem73_interface: payload_size={}, HW_MTU {} -> {}",
            payload_size,
            old_mtu,
            new_mtu
        );
    }

    if config.auto_fragmentation {
        let want_fragmentation = needs_fragmentation(config, payload_size);
        if config.fragmentation_target.load(Ordering::Relaxed) != want_fragmentation
            && set_fragmentation(write, want_fragmentation).await
        {
            config
                .fragmentation_target
                .store(want_fragmentation, Ordering::Relaxed);
            log::info!(
                "modem73_interface: fragmentation {} (payload_size={}, threshold={})",
                if want_fragmentation {
                    "enabled"
                } else {
                    "disabled"
                },
                payload_size,
                RETICULUM_BASE_MTU + config.mtu_overhead
            );
        }
    }
}

async fn set_fragmentation(write: &mut OwnedWriteHalf, enabled: bool) -> bool {
    let command = json!({
        "cmd": "set_config",
        "fragmentation_enabled": enabled,
    });

    match send_control_command(write, &command).await {
        Ok(()) => true,
        Err(error) => {
            log::warn!(
                "modem73_interface: failed to set fragmentation_enabled={}: {}",
                enabled,
                error
            );
            false
        }
    }
}

fn compute_mtu(config: &Modem73Interface, payload_size: usize) -> usize {
    payload_size
        .saturating_sub(config.mtu_overhead)
        .max(RETICULUM_BASE_MTU)
}

fn needs_fragmentation(config: &Modem73Interface, payload_size: usize) -> bool {
    payload_size.saturating_sub(config.mtu_overhead) < RETICULUM_BASE_MTU
}

fn payload_size(message: &Value) -> Option<usize> {
    message
        .get("payload_size")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

/// Derive the physical bitrate (bps) from a modem73 `get_config` response,
/// mirroring the reference `Modem73Interface._phy_profile`. Returns `None`
/// for modes with no known rate (e.g. MFSK), in which case the caller keeps
/// the currently configured bitrate.
fn derive_bitrate(cfg: &Value) -> Option<f64> {
    match cfg.get("modem_type").and_then(Value::as_i64) {
        Some(MODEM_ROBUST) => {
            let robust_mode = cfg.get("robust_mode").and_then(Value::as_i64)?;
            if robust_mode < 0 || robust_mode as usize >= ROBUST_BPS.len() {
                return None;
            }
            Some(ROBUST_BPS[robust_mode as usize])
        }
        Some(MODEM_OFDM) => {
            let modulation = cfg.get("modulation").and_then(Value::as_str)?;
            let airs = OFDM_AIRTIME
                .iter()
                .find(|(name, _)| *name == modulation)?
                .1;
            let frame_size = cfg.get("frame_size").and_then(Value::as_i64)?;
            let payload = cfg.get("payload_size").and_then(Value::as_i64)?;
            if payload <= 0 {
                return None;
            }
            let (short, normal, long) = airs;
            let airtime = [short, normal, long][frame_size.clamp(0, 2) as usize];
            Some(payload as f64 * 8.0 / airtime)
        }
        // MFSK has no published rate in the config; keep the configured value.
        Some(MODEM_MFSK) => None,
        _ => None,
    }
}

async fn send_control_command(write: &mut OwnedWriteHalf, value: &Value) -> io::Result<()> {
    let data = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let length = u32::try_from(data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "control command is too large for modem73 length prefix",
        )
    })?;

    write.write_all(&length.to_be_bytes()).await?;
    write.write_all(&data).await?;
    write.flush().await
}

async fn recv_control_message(read: &mut OwnedReadHalf) -> io::Result<Option<Value>> {
    let mut header = [0u8; 4];
    if let Err(error) = read.read_exact(&mut header).await {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(error)
        };
    }

    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Ok(Some(json!({})));
    }
    if length > MAX_CONTROL_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized modem73 control message",
        ));
    }

    let mut body = vec![0u8; length];
    read.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

async fn read_loop(
    mut stream: OwnedReadHalf,
    iface_address: crate::hash::AddressHash,
    rx_channel: crate::iface::InterfaceRxSender,
    mtu: Arc<AtomicUsize>,
    cancel: CancellationToken,
    stop: CancellationToken,
    ifac_config: Option<IfacConfig>,
) {
    let mut decoder = KissDecoder::new();
    let mut tcp_buffer = [0u8; TCP_READ_BUFFER_SIZE];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            result = stream.read(&mut tcp_buffer) => {
                match result {
                    Ok(0) => {
                        log::warn!("modem73_interface: KISS data connection closed");
                        stop.cancel();
                        break;
                    }
                    Ok(n) => {
                        let max_frame_len = mtu.load(Ordering::Relaxed).min(MAX_AUTOCONFIGURED_HW_MTU);
                        for &byte in &tcp_buffer[..n] {
                            if let Some(data) = decoder.push(byte, max_frame_len) {
                                match decode_rx(ifac_config.as_ref(), &data) {
                                    Ok(packet) => {
                                        if PACKET_TRACE {
                                            log::trace!("modem73_interface: rx << ({}) {}", iface_address, packet);
                                        }
                                        let _ = rx_channel.send(RxMessage { address: iface_address, snr: None, rssi: None, packet }).await;
                                    }
                                    Err(_) => log::warn!("modem73_interface: couldn't decode packet"),
                                }
                            }
                        }
                    }
                    Err(error) => {
                        log::warn!("modem73_interface: KISS data read error: {}", error);
                        stop.cancel();
                        break;
                    }
                }
            }
        }
    }
}

async fn write_loop(
    mut stream: OwnedWriteHalf,
    iface_address: crate::hash::AddressHash,
    tx_channel: Arc<tokio::sync::Mutex<crate::iface::InterfaceTxReceiver>>,
    mtu: Arc<AtomicUsize>,
    cancel: CancellationToken,
    stop: CancellationToken,
    ifac_config: Option<IfacConfig>,
) {
    loop {
        if stop.is_cancelled() {
            break;
        }

        let mut tx_channel = tx_channel.lock().await;
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            Some(message) = tx_channel.recv() => {
                let max_payload_len = mtu.load(Ordering::Relaxed).min(MAX_AUTOCONFIGURED_HW_MTU);
                let mut tx_buffer = vec![0u8; max_payload_len];
                let tx_len = match encode_tx(ifac_config.as_ref(), &message.packet, &mut tx_buffer) {
                    Ok(len) => len,
                    Err(_) => {
                        log::warn!("modem73_interface: couldn't encode packet");
                        continue;
                    }
                };

                if PACKET_TRACE {
                    log::trace!(
                        "modem73_interface: tx >> ({}) {} bytes",
                        iface_address,
                        tx_len
                    );
                }

                let frame = encode_data_frame(&tx_buffer[..tx_len]);
                if let Err(error) = stream.write_all(&frame).await {
                    log::warn!("modem73_interface: KISS data write error: {}", error);
                    stop.cancel();
                    break;
                }
                if let Err(error) = stream.flush().await {
                    log::warn!("modem73_interface: KISS data flush error: {}", error);
                    stop.cancel();
                    break;
                }
            }
        };
    }
}

fn encode_data_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(data.len() + 4);
    frame.push(FEND);
    frame.push(CMD_DATA);
    for &byte in data {
        match byte {
            FEND => frame.extend_from_slice(&[FESC, TFEND]),
            FESC => frame.extend_from_slice(&[FESC, TFESC]),
            _ => frame.push(byte),
        }
    }
    frame.push(FEND);
    frame
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
            data: Vec::with_capacity(DEFAULT_HW_MTU),
        }
    }

    fn push(&mut self, mut byte: u8, max_frame_len: usize) -> Option<Vec<u8>> {
        if self.in_frame && byte == FEND && self.command == CMD_DATA {
            self.in_frame = false;
            self.escape = false;
            self.command = CMD_UNKNOWN;
            return Some(std::mem::take(&mut self.data));
        }

        if byte == FEND {
            self.in_frame = true;
            self.escape = false;
            self.command = CMD_UNKNOWN;
            self.data.clear();
            return None;
        }

        if !self.in_frame || self.data.len() >= max_frame_len {
            return None;
        }

        if self.data.is_empty() && self.command == CMD_UNKNOWN {
            self.command = byte & 0x0f;
            return None;
        }

        if self.command != CMD_DATA {
            return None;
        }

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
            event = decoder.push(byte, DEFAULT_HW_MTU).or(event);
        }

        assert_eq!(event, Some(vec![0x01, FEND, FESC]));
    }

    #[test]
    fn computes_mtu_with_overhead_and_base_floor() {
        let iface = Modem73Interface::new_with_defaults();
        assert_eq!(compute_mtu(&iface, 700), 685);
        assert_eq!(compute_mtu(&iface, 400), RETICULUM_BASE_MTU);
    }

    #[test]
    fn detects_fragmentation_requirement() {
        let iface = Modem73Interface::new_with_defaults();
        assert!(!needs_fragmentation(
            &iface,
            RETICULUM_BASE_MTU + DEFAULT_MTU_OVERHEAD
        ));
        assert!(needs_fragmentation(
            &iface,
            RETICULUM_BASE_MTU + DEFAULT_MTU_OVERHEAD - 1
        ));
    }

    #[test]
    fn reports_default_bitrate() {
        assert_eq!(Modem73Interface::new_with_defaults().bitrate(), Some(600.0));
    }

    #[test]
    fn invalid_bitrate_is_not_reported() {
        assert_eq!(
            Modem73Interface::new_with_defaults()
                .with_bitrate(f64::INFINITY)
                .bitrate(),
            None
        );
    }

    #[test]
    fn derives_bitrate_from_robust_mode() {
        let config = json!({ "modem_type": MODEM_ROBUST, "robust_mode": 0 });
        assert_eq!(derive_bitrate(&config), Some(1150.0));

        let config = json!({ "modem_type": MODEM_ROBUST, "robust_mode": 5 });
        assert_eq!(derive_bitrate(&config), Some(732.0));

        let config = json!({ "modem_type": MODEM_ROBUST, "robust_mode": 10 });
        assert_eq!(derive_bitrate(&config), Some(780.0));
    }

    #[test]
    fn derives_bitrate_from_ofdm_modulation_and_payload() {
        // BPSK normal frame: payload 500 bytes in 2.73 s.
        let config = json!({
            "modem_type": MODEM_OFDM,
            "modulation": "BPSK",
            "frame_size": 1,
            "payload_size": 500,
        });
        assert_eq!(derive_bitrate(&config), Some(500.0 * 8.0 / 2.73));

        // frame_size clamps to the (short, normal, long) table.
        let config = json!({
            "modem_type": MODEM_OFDM,
            "modulation": "QAM16",
            "frame_size": 5,
            "payload_size": 500,
        });
        assert_eq!(derive_bitrate(&config), Some(500.0 * 8.0 / 4.92));
    }

    #[test]
    fn derive_bitrate_falls_back_on_unknown_modes() {
        // MFSK has no published rate in the config.
        let config = json!({ "modem_type": MODEM_MFSK, "mfsk_mode": 0 });
        assert_eq!(derive_bitrate(&config), None);

        // Unknown OFDM modulation.
        let config = json!({
            "modem_type": MODEM_OFDM,
            "modulation": "UNKNOWN",
            "frame_size": 1,
            "payload_size": 500,
        });
        assert_eq!(derive_bitrate(&config), None);

        // Out-of-range robust mode.
        let config = json!({ "modem_type": MODEM_ROBUST, "robust_mode": 99 });
        assert_eq!(derive_bitrate(&config), None);
    }
}
