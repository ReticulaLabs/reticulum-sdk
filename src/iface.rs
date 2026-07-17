pub mod backbone;
pub mod hdlc;
pub mod ifac;
pub mod kiss;
pub mod lora;
pub mod modem73;
pub mod rnode;
pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task;
use tokio::time::{self, Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::buffer::InputBuffer;
use crate::hash::ADDRESS_HASH_SIZE;
use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::iface::ifac::IfacConfig;
use crate::packet::{HeaderType, Packet, PacketType};

pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

// Python Reticulum keeps hardware/interface MTU distinct from the fixed
// interoperable Reticulum packet MTU. Fast interfaces can negotiate higher
// effective transfer sizes later, but the base packet wire format remains 500
// bytes. These constants model interface capacity rather than packet format.
//
// TODO: some of these (such as INTERFACE_TX_QUEUE_CAP could become
// configuration items as reticulum grows. The unlimited max of the Python
// implementation isn't great from a security standpoint.
pub const DEFAULT_HW_MTU: usize = 2048;
pub const MAX_AUTOCONFIGURED_HW_MTU: usize = 524_288;
const DEFAULT_ANNOUNCE_CAP: f64 = 0.02;
const DEFAULT_INTERFACE_TX_QUEUE_CAP: usize = 16_384;
const MAX_QUEUED_ANNOUNCES: usize = 16_384;
const INTERFACE_SEND_TIMEOUT: Duration = Duration::from_millis(100);

// --- Ingress burst limiting (ported from Python Reticulum) ---
/// How many timestamps to keep for frequency calculation.
const INGRESS_FREQ_SAMPLES: usize = 48;
/// Minimum frequency floor for rate decay (Hz).
const INGRESS_MIN_FREQ_HZ: f64 = 0.1;
/// Announce burst threshold for interfaces < 2 hours old (Hz).
const INGRESS_BURST_FREQ_NEW: f64 = 3.0;
/// Announce burst threshold for established interfaces (Hz).
const INGRESS_BURST_FREQ: f64 = 10.0;
/// Path request burst threshold for new interfaces (Hz).
const INGRESS_PR_BURST_FREQ_NEW: f64 = 3.0;
/// Path request burst threshold for established interfaces (Hz).
const INGRESS_PR_BURST_FREQ: f64 = 8.0;
/// How long burst mode remains active after rate drops below threshold (s).
const INGRESS_BURST_HOLD_S: u64 = 15;
/// Penalty time before held announces can be released (s).
const INGRESS_BURST_PENALTY_S: u64 = 15;
/// Min samples before frequency can be computed.
const INGRESS_DEQUE_MIN_SAMPLE: usize = 2;
/// Min samples before burst can be deactivated.
const INGRESS_BURST_MIN_SAMPLES: usize = 6;
/// Maximum held announces per interface.
const INGRESS_MAX_HELD: usize = 256;
/// Egress path-request frequency threshold (Hz). When an interface's
/// outgoing PR rate exceeds this, a warning is logged.
const EGRESS_PR_FREQ: f64 = 5.0;
/// How old an interface must be to be considered "established" (s).
const INGRESS_NEW_TIME_S: u64 = 2 * 60 * 60; // 2 hours
const SATURATED_QUEUE_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TxMessageType {
    Broadcast(Option<AddressHash>),
    Direct(AddressHash),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxMessage {
    pub tx_type: TxMessageType,
    pub packet: Packet,
}

#[derive(Debug, Clone)]
pub struct RxMessage {
    pub address: AddressHash, // Address of source interface
    pub snr: Option<f32>,     // Signal-to-noise ratio (RNode only)
    pub rssi: Option<i16>,    // Received signal strength (RNode only)
    pub packet: Packet,       // Received packet
}

/// Queue length snapshot for a single interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceQueueLength {
    /// Interface address the queue lengths belong to.
    pub address: AddressHash,
    /// Number of outbound packets currently queued for the interface worker.
    pub tx: usize,
    /// Number of forwarded announces waiting in the interface announce pacer.
    pub announce: usize,
    /// Cumulative number of data packets sent through this interface.
    pub packets_tx: u64,
    /// Cumulative microseconds spent in pacing waits for this interface.
    pub pacing_wait_us: u64,
    /// Last computed pacing interval in microseconds (0 if not pacing).
    pub last_pacing_interval_us: u64,
}

/// Queue length snapshot for the interface manager.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct InterfaceQueueLengths {
    /// Number of inbound packets queued from interface workers to transport.
    pub rx: usize,
    /// Per-interface outbound queue lengths.
    pub interfaces: Vec<InterfaceQueueLength>,
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
    pub ifac_config: Option<IfacConfig>,
}

impl InterfaceChannel {
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    pub fn new(
        rx_channel: InterfaceRxSender,
        tx_channel: InterfaceTxReceiver,
        address: AddressHash,
        stop: CancellationToken,
    ) -> Self {
        Self {
            address,
            rx_channel,
            tx_channel,
            stop,
            ifac_config: None,
        }
    }

    /// Deserialize a received packet buffer and verify the IFAC if this
    /// channel has IFAC configured.
    ///
    /// Returns the parsed `Packet` with the IFAC field still attached
    /// (the transport layer does not inspect the IFAC, so it can be
    /// forwarded as-is).
    pub fn receive(&self, data: &[u8]) -> Result<Packet, crate::error::RnsError> {
        match &self.ifac_config {
            Some(config) => {
                let packet = Packet::deserialize_with_ifac_len(
                    &mut InputBuffer::new(data),
                    config.ifac_len(),
                )?;
                config.verify_packet(&packet)?;
                Ok(packet)
            }
            None => Packet::deserialize(&mut InputBuffer::new(data)),
        }
    }

    pub fn set_ifac_config(&mut self, config: Option<IfacConfig>) {
        self.ifac_config = config;
    }

    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

/// Interface modes control how Reticulum handles announce propagation,
/// path discovery and path expiry for a given interface.  These match
/// the modes defined in the Python Reticulum reference implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    /// Default mode.  All discovery, meshing and transport functionality
    /// is available.  Paths have the standard expiry time (1 week).
    Full = 0x01,
    /// Intended for interfaces with exactly one reachable peer.
    PointToPoint = 0x02,
    /// Network access point.  Announces are not automatically broadcast
    /// on this interface, and paths have a shorter expiry time (1 day).
    AccessPoint = 0x03,
    /// Roaming (physically mobile) interface.  Paths have a shorter
    /// expiry time (6 hours).
    Roaming = 0x04,
    /// Connects to network segments that are significantly different
    /// from the local one (e.g. a high-speed Internet link from a
    /// LoRa-based network).  Affects announce propagation rules.
    Boundary = 0x05,
    /// Gateway interface that actively discovers unknown paths on
    /// behalf of nodes connected via this interface.
    Gateway = 0x06,
    /// Internal interface – part of a network distinct from any
    /// `Boundary` interface.  Affects announce propagation rules.
    Internal = 0x07,
}

impl InterfaceMode {
    /// Which interface modes a transport node should actively discover
    /// paths for (matching Python's `DISCOVER_PATHS_FOR`).
    pub const DISCOVER_PATHS_FOR: &'static [InterfaceMode] = &[
        InterfaceMode::AccessPoint,
        InterfaceMode::Gateway,
        InterfaceMode::Roaming,
        InterfaceMode::Internal,
    ];
}

pub trait Interface {
    fn hw_mtu(&self) -> usize;

    /// Whether this interface type supports the interface discovery
    /// protocol. When `true`, the interface can be registered with
    /// `Transport::register_discoverable_interface()` to announce its
    /// presence to the network.
    fn supports_discovery(&self) -> bool {
        false
    }

    fn bitrate(&self) -> Option<f64> {
        None
    }

    /// The interface mode, which controls announce propagation,
    /// path expiry and discovery behaviour.
    fn interface_mode(&self) -> InterfaceMode {
        InterfaceMode::Full
    }

    fn announce_cap(&self) -> f64 {
        DEFAULT_ANNOUNCE_CAP
    }

    /// Whether this interface should auto-size its HW_MTU from the bitrate
    /// and participate in link MTU discovery / upgrades.
    fn autoconfigure_mtu(&self) -> bool {
        false
    }

    /// Whether this interface has a user-configured fixed MTU and should
    /// participate in link MTU discovery / upgrades.
    fn fixed_mtu(&self) -> bool {
        false
    }

    /// Returns a shared MTU atomic for live updates. If the interface
    /// updates its HW_MTU at runtime (e.g. Modem73), it should return
    /// `Some(arc)` pointing to the same `Arc<AtomicUsize>` used by
    /// `hw_mtu()`. The default returns `None`, causing the registration
    /// path to snapshot the value returned by `hw_mtu()`.
    fn hw_mtu_source(&self) -> Option<Arc<AtomicUsize>> {
        None
    }
}

pub(crate) fn configured_bitrate(bitrate: f64) -> Option<f64> {
    if bitrate.is_finite() && bitrate > 0.0 {
        Some(bitrate)
    } else {
        None
    }
}

/// Compute the frequency (Hz) of events from a deque of timestamps.
fn ingress_freq(deque: &VecDeque<Instant>, now: Instant) -> f64 {
    let n = deque.len();
    if n < INGRESS_DEQUE_MIN_SAMPLE {
        return 0.0;
    }
    let oldest = deque.front().copied().unwrap_or(now);
    let span = now.duration_since(oldest);
    let span_s = span.as_secs_f64();
    if span_s <= 0.0 {
        return 0.0;
    }
    n as f64 / span_s
}

struct LocalInterface {
    address: AddressHash,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    announce_pacer: Option<AnnouncePacer>,
    saturated_queue_logger: SaturatedQueueLogger,
    shared_instance_client: bool,
    /// Hardware MTU atomic, shared with the interface for live updates.
    /// `None` means the interface does not participate in link MTU
    /// discovery / upgrades.
    hw_mtu: Option<Arc<AtomicUsize>>,
    /// Interface Access Code configuration. When set, outbound packets
    /// will have an Ed25519 IFAC signature attached before transmission.
    ifac_config: Option<IfacConfig>,
    /// Interface bitrate in bps, used for data pacing on slow links.
    bitrate: Option<f64>,
    /// Interface mode controlling announce propagation, path expiry
    /// and discovery behaviour.
    mode: InterfaceMode,
    /// Timestamp of the last data packet send, used for inter-packet pacing.
    last_data_send: std::sync::Mutex<Instant>,
    /// Cumulative number of data packets sent through this interface.
    packets_tx: AtomicU64,
    /// Cumulative microseconds spent in pacing waits for this interface.
    pacing_wait_us: AtomicU64,
    /// Last computed pacing interval in microseconds.
    last_pacing_interval_us: AtomicU64,

    // --- Ingress burst limiting state ---
    /// Timestamps of recently received announces for frequency tracking.
    ia_freq_deque: std::sync::Mutex<VecDeque<Instant>>,
    /// Timestamps of recently received path requests for frequency tracking.
    ip_freq_deque: std::sync::Mutex<VecDeque<Instant>>,
    /// Whether announce burst limiting is currently active.
    ingress_burst_active: std::sync::Mutex<bool>,
    /// When the current announce burst was activated.
    ingress_burst_activated: std::sync::Mutex<Instant>,
    /// Whether path-request burst limiting is currently active.
    ingress_pr_burst_active: std::sync::Mutex<bool>,
    /// When the current PR burst was activated.
    ingress_pr_burst_activated: std::sync::Mutex<Instant>,

    // --- Egress path-request tracking ---
    /// Timestamps of recently sent path requests for frequency tracking.
    op_freq_deque: std::sync::Mutex<VecDeque<Instant>>,
}

#[derive(Clone)]
struct SaturatedQueueLogger {
    iface: AddressHash,
    state: Arc<tokio::sync::Mutex<SaturatedQueueLogState>>,
}

struct SaturatedQueueLogState {
    next_log_at: Instant,
    suppressed: usize,
}

impl SaturatedQueueLogger {
    fn new(iface: AddressHash) -> Self {
        Self {
            iface,
            state: Arc::new(tokio::sync::Mutex::new(SaturatedQueueLogState {
                next_log_at: Instant::now(),
                suppressed: 0,
            })),
        }
    }

    async fn warn_drop(&self, tx_type: TxMessageType) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if now < state.next_log_at {
            state.suppressed += 1;
            return;
        }

        let suppressed = state.suppressed;
        state.suppressed = 0;
        state.next_log_at = now + SATURATED_QUEUE_LOG_INTERVAL;
        drop(state);

        if suppressed > 0 {
            log::warn!(
                "iface: dropping outbound packet for saturated interface queue iface={} tx_type={:?} suppressed_drops={}",
                self.iface,
                tx_type,
                suppressed
            );
        } else {
            log::warn!(
                "iface: dropping outbound packet for saturated interface queue iface={} tx_type={:?}",
                self.iface,
                tx_type
            );
        }
    }
}

#[derive(Clone)]
struct AnnouncePacer {
    bitrate: f64,
    announce_cap: f64,
    state: Arc<tokio::sync::Mutex<AnnouncePacerState>>,
}

struct AnnouncePacerState {
    announce_allowed_at: Instant,
    announce_queue: VecDeque<AddressHash>,
    announce_data: HashMap<AddressHash, TxMessage>,
    timer_active: bool,
}

impl AnnouncePacer {
    fn new(bitrate: f64, announce_cap: f64) -> Self {
        Self {
            bitrate,
            announce_cap,
            state: Arc::new(tokio::sync::Mutex::new(AnnouncePacerState {
                announce_allowed_at: Instant::now(),
                announce_queue: VecDeque::new(),
                announce_data: HashMap::new(),
                timer_active: false,
            })),
        }
    }

    fn wait_time(&self, packet: &Packet) -> Option<Duration> {
        if self.bitrate <= 0.0 || self.announce_cap <= 0.0 {
            return None;
        }

        let transport_len = match packet.header.header_type {
            HeaderType::Type1 => 0,
            HeaderType::Type2 => {
                packet.transport.as_ref()?;
                ADDRESS_HASH_SIZE
            }
        };
        let packet_len = 2 + transport_len + ADDRESS_HASH_SIZE + 1 + packet.data.len();
        let tx_time = (packet_len as f64 * 8.0) / self.bitrate;

        Some(Duration::from_secs_f64(tx_time / self.announce_cap))
    }

    fn should_pace(message: &TxMessage) -> bool {
        message.packet.header.packet_type == PacketType::Announce && message.packet.header.hops > 0
    }

    async fn queue_len(&self) -> usize {
        self.state.lock().await.announce_data.len()
    }

    async fn send(
        &self,
        tx_send: InterfaceTxSender,
        stop: CancellationToken,
        saturated_queue_logger: SaturatedQueueLogger,
        message: TxMessage,
    ) {
        let Some(wait_time) = self.wait_time(&message.packet) else {
            send_or_drop(&tx_send, message, Some(&saturated_queue_logger)).await;
            return;
        };

        let mut state = self.state.lock().await;
        let now = Instant::now();
        if state.announce_queue.is_empty() && now >= state.announce_allowed_at {
            state.announce_allowed_at = now + wait_time;
            drop(state);

            send_or_drop(&tx_send, message, Some(&saturated_queue_logger)).await;
            return;
        }

        let dest = message.packet.destination;
        if state.announce_data.contains_key(&dest) {
            state.announce_data.insert(dest, message);
        } else if state.announce_queue.len() < MAX_QUEUED_ANNOUNCES {
            state.announce_queue.push_back(dest);
            state.announce_data.insert(dest, message);
        }

        if !state.timer_active {
            state.timer_active = true;
            task::spawn(process_announce_queue(
                self.clone(),
                tx_send,
                stop,
                saturated_queue_logger,
            ));
        }
    }
}

async fn process_announce_queue(
    pacer: AnnouncePacer,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    saturated_queue_logger: SaturatedQueueLogger,
) {
    loop {
        if stop.is_cancelled() {
            let mut state = pacer.state.lock().await;
            state.timer_active = false;
            return;
        }

        let next_message = {
            let mut state = pacer.state.lock().await;
            let now = Instant::now();
            if now < state.announce_allowed_at {
                let wait_time = state.announce_allowed_at - now;
                drop(state);
                time::sleep(wait_time).await;
                continue;
            }

            match state.announce_queue.pop_front() {
                Some(dest) => {
                    if let Some(message) = state.announce_data.remove(&dest) {
                        if let Some(wait_time) = pacer.wait_time(&message.packet) {
                            state.announce_allowed_at = now + wait_time;
                        }
                        Some(message)
                    } else {
                        state.timer_active = false;
                        None
                    }
                }
                None => {
                    state.timer_active = false;
                    None
                }
            }
        };

        let Some(message) = next_message else {
            return;
        };

        send_or_drop(&tx_send, message, Some(&saturated_queue_logger)).await;
    }
}

async fn send_or_drop(
    tx_send: &InterfaceTxSender,
    message: TxMessage,
    saturated_queue_logger: Option<&SaturatedQueueLogger>,
) {
    match tx_send.try_send(message) {
        Ok(()) => {}
        Err(TrySendError::Full(message)) => {
            let tx_type = message.tx_type;
            if time::timeout(INTERFACE_SEND_TIMEOUT, tx_send.send(message))
                .await
                .is_err()
            {
                if let Some(logger) = saturated_queue_logger {
                    logger.warn_drop(tx_type).await;
                } else {
                    log::warn!(
                        "iface: dropping outbound packet for saturated interface queue tx_type={:?}",
                        tx_type
                    );
                }
            }
        }
        Err(TrySendError::Closed(_)) => {
            log::trace!("iface: dropping outbound packet for closed interface queue");
        }
    }
}

pub struct InterfaceContext<T: Interface> {
    pub inner: Arc<Mutex<T>>,
    pub channel: InterfaceChannel,
    pub cancel: CancellationToken,
}

pub struct InterfaceManager {
    counter: usize,
    rx_recv: Arc<tokio::sync::Mutex<InterfaceRxReceiver>>,
    rx_send: InterfaceRxSender,
    cancel: CancellationToken,
    ifaces: Vec<LocalInterface>,
}

impl InterfaceManager {
    pub fn new(rx_cap: usize) -> Self {
        let (rx_send, rx_recv) = InterfaceChannel::make_rx_channel(rx_cap);
        let rx_recv = Arc::new(tokio::sync::Mutex::new(rx_recv));

        Self {
            counter: 0,
            rx_recv,
            rx_send,
            cancel: CancellationToken::new(),
            ifaces: Vec::new(),
        }
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_with_pacer(tx_cap, None, false, None, None, None, InterfaceMode::Full)
    }

    fn new_channel_with_pacer(
        &mut self,
        tx_cap: usize,
        announce_pacer: Option<AnnouncePacer>,
        shared_instance_client: bool,
        hw_mtu: Option<Arc<AtomicUsize>>,
        ifac_config: Option<IfacConfig>,
        bitrate: Option<f64>,
        mode: InterfaceMode,
    ) -> InterfaceChannel {
        self.counter += 1;

        let counter_bytes = self.counter.to_le_bytes();
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&counter_bytes[..]));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!(
            "iface: create channel {} hw_mtu={:?}",
            address,
            hw_mtu.as_ref().map(|m| m.load(Ordering::Relaxed))
        );

        let stop = CancellationToken::new();

        self.ifaces.push(LocalInterface {
            address,
            tx_send,
            stop: stop.clone(),
            announce_pacer,
            saturated_queue_logger: SaturatedQueueLogger::new(address),
            shared_instance_client,
            hw_mtu,
            ifac_config: ifac_config.clone(),
            bitrate,
            mode,
            last_data_send: std::sync::Mutex::new(Instant::now()),
            packets_tx: AtomicU64::new(0),
            pacing_wait_us: AtomicU64::new(0),
            last_pacing_interval_us: AtomicU64::new(0),
            ia_freq_deque: std::sync::Mutex::new(VecDeque::with_capacity(INGRESS_FREQ_SAMPLES)),
            ip_freq_deque: std::sync::Mutex::new(VecDeque::with_capacity(INGRESS_FREQ_SAMPLES)),
            ingress_burst_active: std::sync::Mutex::new(false),
            ingress_burst_activated: std::sync::Mutex::new(Instant::now()),
            ingress_pr_burst_active: std::sync::Mutex::new(false),
            ingress_pr_burst_activated: std::sync::Mutex::new(Instant::now()),
            op_freq_deque: std::sync::Mutex::new(VecDeque::with_capacity(INGRESS_FREQ_SAMPLES)),
        });

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
            ifac_config,
        }
    }

    pub fn new_context<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        self.new_context_with_options(inner, false)
    }

    fn new_context_with_options<T: Interface>(
        &mut self,
        inner: T,
        shared_instance_client: bool,
    ) -> InterfaceContext<T> {
        let bitrate = inner.bitrate();
        let announce_cap = inner.announce_cap();
        let announce_pacer = bitrate
            .filter(|bitrate| *bitrate > 0.0 && announce_cap > 0.0)
            .map(|bitrate| AnnouncePacer::new(bitrate, announce_cap));
        let hw_mtu = if inner.autoconfigure_mtu() || inner.fixed_mtu() {
            Some(
                inner
                    .hw_mtu_source()
                    .unwrap_or_else(|| Arc::new(AtomicUsize::new(inner.hw_mtu()))),
            )
        } else {
            None
        };
        let mode = inner.interface_mode();
        let channel = self.new_channel_with_pacer(
            DEFAULT_INTERFACE_TX_QUEUE_CAP,
            announce_pacer,
            shared_instance_client,
            hw_mtu,
            None,
            configured_bitrate(bitrate.unwrap_or(0.0)),
            mode,
        );

        let inner = Arc::new(Mutex::new(inner));

        let context = InterfaceContext::<T> {
            inner: inner.clone(),
            channel,
            cancel: self.cancel.clone(),
        };

        context
    }

    pub fn spawn<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context(inner);
        let address = context.channel.address().clone();

        task::spawn(worker(context));

        address
    }

    pub fn spawn_shared_instance_client<T: Interface, F, R>(
        &mut self,
        inner: T,
        worker: F,
    ) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context_with_options(inner, true);
        let address = context.channel.address().clone();

        task::spawn(worker(context));

        address
    }

    pub fn receiver(&self) -> Arc<tokio::sync::Mutex<InterfaceRxReceiver>> {
        self.rx_recv.clone()
    }

    /// Returns current interface queue lengths for metrics collection.
    pub async fn queue_lengths(&self) -> InterfaceQueueLengths {
        let mut interfaces = Vec::with_capacity(self.ifaces.len());

        for iface in &self.ifaces {
            if iface.stop.is_cancelled() {
                continue;
            }

            interfaces.push(InterfaceQueueLength {
                address: iface.address,
                tx: channel_queue_len(&iface.tx_send),
                announce: match &iface.announce_pacer {
                    Some(pacer) => pacer.queue_len().await,
                    None => 0,
                },
                packets_tx: iface.packets_tx.load(Ordering::Relaxed),
                pacing_wait_us: iface.pacing_wait_us.load(Ordering::Relaxed),
                last_pacing_interval_us: iface.last_pacing_interval_us.load(Ordering::Relaxed),
            });
        }

        InterfaceQueueLengths {
            rx: channel_queue_len(&self.rx_send),
            interfaces,
        }
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    /// Record an incoming announce on an interface and return `true` if the
    /// announce should be dropped due to ingress burst limiting.
    /// Only applied to interfaces with a known bitrate (slow links).
    pub fn ingress_record_announce(&self, address: &AddressHash) -> bool {
        let Some(iface) = self.ifaces.iter().find(|i| i.address == *address) else {
            return false;
        };
        if iface.stop.is_cancelled() || iface.bitrate.is_none() {
            return false;
        }

        // Track the timestamp
        let now = Instant::now();
        let mut deque = iface.ia_freq_deque.lock().unwrap();
        deque.push_back(now);
        if deque.len() > INGRESS_FREQ_SAMPLES {
            deque.pop_front();
        }

        // Compute frequency
        let freq = ingress_freq(&deque, now);

        // Evaluate burst state
        let mut burst_active = iface.ingress_burst_active.lock().unwrap();
        let mut burst_activated = iface.ingress_burst_activated.lock().unwrap();

        if *burst_active {
            // Already limiting: check if we can deactivate
            let freq_threshold = INGRESS_BURST_FREQ; // conservative: always use established threshold
            if freq < freq_threshold
                && now.duration_since(*burst_activated) > Duration::from_secs(INGRESS_BURST_HOLD_S)
                && deque.len() >= INGRESS_BURST_MIN_SAMPLES
            {
                *burst_active = false;
                return false;
            }
            return true; // actively limiting
        } else {
            // Not limiting yet: check if threshold is crossed
            let freq_threshold = INGRESS_BURST_FREQ;
            if freq > freq_threshold {
                *burst_active = true;
                *burst_activated = now;
                return true; // start limiting
            }
            return false;
        }
    }

    /// Record an incoming path request on an interface and return `true`
    /// if it should be dropped due to ingress burst limiting.
    /// Only applied to interfaces with a known bitrate (slow links).
    pub fn ingress_record_pr(&self, address: &AddressHash) -> bool {
        let Some(iface) = self.ifaces.iter().find(|i| i.address == *address) else {
            return false;
        };
        if iface.stop.is_cancelled() || iface.bitrate.is_none() {
            return false;
        }

        let now = Instant::now();
        let mut deque = iface.ip_freq_deque.lock().unwrap();
        deque.push_back(now);
        if deque.len() > INGRESS_FREQ_SAMPLES {
            deque.pop_front();
        }

        let freq = ingress_freq(&deque, now);

        let mut burst_active = iface.ingress_pr_burst_active.lock().unwrap();
        let mut burst_activated = iface.ingress_pr_burst_activated.lock().unwrap();

        if *burst_active {
            let freq_threshold = INGRESS_PR_BURST_FREQ;
            if freq < freq_threshold
                && now.duration_since(*burst_activated) > Duration::from_secs(INGRESS_BURST_HOLD_S)
                && deque.len() >= INGRESS_BURST_MIN_SAMPLES
            {
                *burst_active = false;
                return false;
            }
            return true;
        } else {
            let freq_threshold = INGRESS_PR_BURST_FREQ;
            if freq > freq_threshold {
                *burst_active = true;
                *burst_activated = now;
                return true;
            }
            return false;
        }
    }

    /// Evaluate and update ingress burst state for all interfaces.
    /// Should be called periodically (e.g. every ~10 seconds).
    pub fn ingress_evaluate_all(&self) {
        let now = Instant::now();
        for iface in &self.ifaces {
            if iface.stop.is_cancelled() || iface.bitrate.is_none() {
                continue;
            }

            // Announce burst
            {
                let deque = iface.ia_freq_deque.lock().unwrap();
                let freq = ingress_freq(&deque, now);
                let mut burst_active = iface.ingress_burst_active.lock().unwrap();
                let mut burst_activated = iface.ingress_burst_activated.lock().unwrap();
                let freq_threshold = INGRESS_BURST_FREQ;

                if *burst_active {
                    if freq < freq_threshold
                        && now.duration_since(*burst_activated) > Duration::from_secs(INGRESS_BURST_HOLD_S)
                        && deque.len() >= INGRESS_BURST_MIN_SAMPLES
                    {
                        *burst_active = false;
                    }
                } else {
                    if freq > freq_threshold {
                        *burst_active = true;
                        *burst_activated = now;
                    }
                }
            }

            // PR burst
            {
                let deque = iface.ip_freq_deque.lock().unwrap();
                let freq = ingress_freq(&deque, now);
                let mut burst_active = iface.ingress_pr_burst_active.lock().unwrap();
                let mut burst_activated = iface.ingress_pr_burst_activated.lock().unwrap();
                let freq_threshold = INGRESS_PR_BURST_FREQ;

                if *burst_active {
                    if freq < freq_threshold
                        && now.duration_since(*burst_activated) > Duration::from_secs(INGRESS_BURST_HOLD_S)
                        && deque.len() >= INGRESS_BURST_MIN_SAMPLES
                    {
                        *burst_active = false;
                    }
                } else {
                    if freq > freq_threshold {
                        *burst_active = true;
                        *burst_activated = now;
                    }
                }
            }
        }
    }

    /// Record an outgoing path request on this interface and return
    /// `true` if the egress PR frequency exceeds `EGRESS_PR_FREQ` (5
    /// Hz), indicating excessive outgoing PR activity.
    pub fn egress_record_pr(&self, address: &AddressHash) -> bool {
        let Some(iface) = self.ifaces.iter().find(|i| i.address == *address) else {
            return false;
        };
        if iface.stop.is_cancelled() {
            return false;
        }

        let now = Instant::now();

        // Prune entries older than the decay window
        {
            let mut deque = iface.op_freq_deque.lock().unwrap();
            deque.push_back(now);
            if deque.len() > INGRESS_FREQ_SAMPLES {
                deque.pop_front();
            }
        }

        let freq = {
            let deque = iface.op_freq_deque.lock().unwrap();
            ingress_freq(&deque, now)
        };

        freq > EGRESS_PR_FREQ
    }

    /// Sweep stale outgoing PR timestamps for all interfaces.
    pub fn egress_evaluate_all(&self) {
        let now = Instant::now();
        for iface in &self.ifaces {
            if iface.stop.is_cancelled() {
                continue;
            }
            let mut deque = iface.op_freq_deque.lock().unwrap();
            // Remove entries older than the decay window (10 seconds).
            while let Some(&t) = deque.front() {
                if now.duration_since(t).as_secs_f64() > 10.0 {
                    deque.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    /// Return the interface mode for the given interface address, or
    /// `InterfaceMode::Full` if the interface is not found or cancelled.
    pub fn interface_mode(&self, address: &AddressHash) -> InterfaceMode {
        self.ifaces
            .iter()
            .find(|i| i.address == *address && !i.stop.is_cancelled())
            .map(|i| i.mode)
            .unwrap_or(InterfaceMode::Full)
    }

    /// Return the path expiry duration appropriate for the interface
    /// mode at `address`.  AccessPoint → 1 day, Roaming → 6 hours,
    /// everything else → 7 days.
    pub fn path_expiry_for_iface(&self, address: &AddressHash) -> Duration {
        match self.interface_mode(address) {
            InterfaceMode::AccessPoint => Duration::from_secs(60 * 60 * 24),
            InterfaceMode::Roaming => Duration::from_secs(60 * 60 * 6),
            _ => Duration::from_secs(60 * 60 * 24 * 7),
        }
    }

    /// Returns `true` if the interface at `address` has a mode that
    /// a Transport Node should actively discover paths for (matching
    /// Python's `DISCOVER_PATHS_FOR`).
    pub fn should_discover_paths_for(&self, address: &AddressHash) -> bool {
        InterfaceMode::DISCOVER_PATHS_FOR.contains(&self.interface_mode(address))
    }

    pub fn active_interface_addresses(&self) -> Vec<AddressHash> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| iface.address)
            .collect()
    }

    pub fn shared_instance_clients_except(&self, address: AddressHash) -> Vec<AddressHash> {
        self.ifaces
            .iter()
            .filter(|iface| iface.shared_instance_client && !iface.stop.is_cancelled())
            .filter(|iface| iface.address != address)
            .map(|iface| iface.address)
            .collect()
    }

    /// Return the hardware MTU registered for the interface at `address`,
    /// or `None` if the interface does not participate in MTU upgrades or
    /// is no longer active.
    pub fn hw_mtu(&self, address: &AddressHash) -> Option<usize> {
        self.ifaces
            .iter()
            .find(|iface| iface.address == *address && !iface.stop.is_cancelled())
            .and_then(|iface| iface.hw_mtu.as_ref().map(|mtu| mtu.load(Ordering::Relaxed)))
    }

    /// Convenience wrapper: computes pacing delay, sleeps, then flushes.
    /// This is equivalent to calling `send_pacing_delay` + `send_flush`
    /// and is provided for backward compatibility.
    pub async fn send(&self, message: TxMessage) {
        let wait = self.send_pacing_delay(&message).await;
        if wait > Duration::ZERO {
            time::sleep(wait).await;
        }
        self.send_flush(message).await;
    }

    /// Compute the pacing delay for this message across all matching
    /// interfaces and update the per-interface `last_data_send` timestamps.
    /// The caller should sleep for the returned duration (if non-zero)
    /// *before* calling `send_flush`, so that the pacing sleep does not
    /// hold the `InterfaceManager` lock and block other interfaces.
    pub async fn send_pacing_delay(&self, message: &TxMessage) -> Duration {
        let mut max_wait = Duration::ZERO;
        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }
                    should_send
                }
                TxMessageType::Direct(address) => address == iface.address,
            };

            if !should_send || iface.stop.is_cancelled() {
                continue;
            }

            // Announces have their own dedicated pacer.
            if AnnouncePacer::should_pace(message) {
                continue;
            }

            let Some(bitrate) = iface.bitrate else { continue };
            if bitrate <= 0.0 { continue; }

            let transport_size = if message.packet.header.header_type == HeaderType::Type2 {
                ADDRESS_HASH_SIZE
            } else {
                0
            };
            let packet_len = 2 + transport_size + ADDRESS_HASH_SIZE + 1
                + message.packet.data.len();
            let tx_time = (packet_len as f64 * 8.0) / bitrate;
            let min_interval = Duration::from_secs_f64(tx_time * 2.0);

            iface.last_pacing_interval_us
                .store(min_interval.as_micros() as u64, Ordering::Relaxed);

            let wait = {
                let mut last_send = iface.last_data_send.lock().unwrap();
                let now = Instant::now();
                let deadline = *last_send + min_interval;
                if now >= deadline {
                    *last_send = now;
                    Duration::ZERO
                } else {
                    let remaining = deadline - now;
                    *last_send = deadline;
                    remaining
                }
            };

            if wait > max_wait {
                max_wait = wait;
            }
        }
        max_wait
    }

    /// Send a message without any pacing sleep.  The caller is responsible
    /// for having called `send_pacing_delay` beforehand and slept for the
    /// returned duration so that the `InterfaceManager` lock is not held
    /// during the sleep.  Pacing delay computation is NOT repeated here.
    pub async fn send_flush(&self, message: TxMessage) {
        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }
                    should_send
                }
                TxMessageType::Direct(address) => address == iface.address,
            };

            if !should_send || iface.stop.is_cancelled() {
                continue;
            }

            // Interface mode filtering: Access Point interfaces do not
            // rebroadcast announces (they only originate their own).
            if iface.mode == InterfaceMode::AccessPoint
                && AnnouncePacer::should_pace(&message)
            {
                continue;
            }

            let mut message = message.clone();

            if let Some(ifac_config) = &iface.ifac_config {
                if let Err(err) = ifac_config.attach(&mut message.packet) {
                    log::warn!(
                        "iface: failed to attach IFAC for iface={} err={:?}",
                        iface.address,
                        err,
                    );
                    continue;
                }
            }

            if let Some(pacer) = iface
                .announce_pacer
                .as_ref()
                .filter(|_| AnnouncePacer::should_pace(&message))
            {
                pacer
                    .send(
                        iface.tx_send.clone(),
                        iface.stop.clone(),
                        iface.saturated_queue_logger.clone(),
                        message,
                    )
                    .await;
            } else {
                send_or_drop(&iface.tx_send, message, Some(&iface.saturated_queue_logger))
                    .await;

                iface.packets_tx.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Set or clear the IFAC configuration for a specific interface.
    ///
    /// When set, outbound packets sent through this interface will have an
    /// Ed25519 signature attached as an Interface Access Code.
    pub fn set_ifac_config(&mut self, address: &AddressHash, config: Option<IfacConfig>) {
        for iface in &mut self.ifaces {
            if iface.address == *address {
                iface.ifac_config = config;
                return;
            }
        }
    }

    /// Return the IFAC configuration for a specific interface, if set.
    pub fn get_ifac_config(&self, address: &AddressHash) -> Option<&IfacConfig> {
        self.ifaces
            .iter()
            .find(|iface| iface.address == *address)
            .and_then(|iface| iface.ifac_config.as_ref())
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn channel_queue_len<T>(sender: &mpsc::Sender<T>) -> usize {
    sender.max_capacity().saturating_sub(sender.capacity())
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;
    use crate::packet::{
        ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PacketContext,
        PacketDataBuffer, PropagationType,
    };

    fn announce(destination: u8, hops: u8, data: &[u8]) -> TxMessage {
        TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet: Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type1,
                    context_flag: ContextFlag::Unset,
                    propagation_type: PropagationType::Broadcast,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                    hops,
                },
                ifac: None,
                destination: AddressHash::new([destination; 16]),
                transport: None,
                context: PacketContext::None,
                data: PacketDataBuffer::new_from_slice(data),
            },
        }
    }

    /// Create a Type2 data packet directed at a specific interface.
    /// The header includes a transport address (as Type2 requires) and
    /// the payload has `data_len` zeroed bytes.
    fn data_tx(iface: AddressHash, data_len: usize) -> TxMessage {
        TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet: Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type2,
                    context_flag: ContextFlag::Unset,
                    propagation_type: PropagationType::Broadcast,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Data,
                    hops: 0,
                },
                ifac: None,
                destination: AddressHash::new([1; 16]),
                transport: Some(AddressHash::new([2; 16])),
                context: PacketContext::None,
                data: PacketDataBuffer::new_from_slice(&vec![0u8; data_len]),
            },
        }
    }

    /// Helper: expected min_interval for a data packet sent over a link
    /// with the given `bitrate` and `data_len` payload bytes.
    fn expected_data_interval(bitrate: f64, data_len: usize) -> Duration {
        let packet_len = 2 + ADDRESS_HASH_SIZE + ADDRESS_HASH_SIZE + 1 + data_len;
        let tx_time = (packet_len as f64 * 8.0) / bitrate;
        Duration::from_secs_f64(tx_time * 2.0)
    }

    #[tokio::test(start_paused = true)]
    async fn data_pacing_delays_packets_on_low_bandwidth_link() {
        let mut manager = InterfaceManager::new(4);
        // 1 kbps link – realistic for LoRa at SF11/BW250
        let bitrate = 1_000.0;
        let channel = manager.new_channel_with_pacer(
            4, None, false, None, None, Some(bitrate), InterfaceMode::Full,
        );
        let iface = channel.address;
        let mut receiver = channel.tx_channel;

        let data_len = 100;
        let interval = expected_data_interval(bitrate, data_len);

        // Advance well past the initial last_data_send so the first
        // packet is not mistakenly delayed.
        time::advance(Duration::from_secs(10)).await;
        task::yield_now().await;

        // --- first packet: should go through immediately ---
        let msg1 = data_tx(iface, data_len);
        let wait1 = manager.send_pacing_delay(&msg1).await;
        assert_eq!(wait1, Duration::ZERO);
        manager.send_flush(msg1).await;
        assert!(receiver.try_recv().is_ok(), "first packet should arrive immediately");

        // --- second packet sent right away: must be paced ---
        let msg2 = data_tx(iface, data_len);
        let wait2 = manager.send_pacing_delay(&msg2).await;
        let tolerance = Duration::from_millis(50);
        assert!(
            wait2 >= interval.saturating_sub(tolerance) && wait2 <= interval + tolerance,
            "expected wait ≈ {interval:?}, got {wait2:?}",
        );
        // Without advancing time the tx channel stays empty.
        assert!(
            receiver.try_recv().is_err(),
            "second packet should be delayed by pacing",
        );

        // Advance by the computed wait and flush.
        time::advance(wait2).await;
        task::yield_now().await;
        manager.send_flush(msg2).await;
        assert!(receiver.try_recv().is_ok(), "second packet should arrive after the pacing delay");
    }

    #[tokio::test(start_paused = true)]
    async fn data_pacing_does_not_delay_on_high_bandwidth_link() {
        let mut manager = InterfaceManager::new(4);
        // 10 Mbps – typical fast link, no meaningful pacing needed.
        let bitrate = 10_000_000.0;
        let channel = manager.new_channel_with_pacer(
            4, None, false, None, None, Some(bitrate), InterfaceMode::Full,
        );
        let iface = channel.address;
        let mut receiver = channel.tx_channel;

        time::advance(Duration::from_secs(10)).await;
        task::yield_now().await;

        for i in 0..5 {
            let msg = data_tx(iface, 100);
            let wait = manager.send_pacing_delay(&msg).await;
            // For 10 Mbps, the computed interval is ~200 µs – well below
            // any meaningful threshold.  We accept anything < 1 ms.
            assert!(
                wait < Duration::from_millis(1),
                "high-bandwidth link should produce negligible pacing delay, got {wait:?} for packet {i}",
            );
            manager.send_flush(msg).await;
            assert!(receiver.try_recv().is_ok(), "packet {i} should arrive immediately on fast link");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn data_pacing_interval_scales_with_packet_size() {
        let mut manager = InterfaceManager::new(4);
        let bitrate = 1_000.0;
        let channel = manager.new_channel_with_pacer(
            4, None, false, None, None, Some(bitrate), InterfaceMode::Full,
        );
        let iface = channel.address;

        time::advance(Duration::from_secs(10)).await;
        task::yield_now().await;

        // First packet (small) after advancing time: no delay.
        let msg_small = data_tx(iface, 10);
        let wait_small = manager.send_pacing_delay(&msg_small).await;
        assert_eq!(wait_small, Duration::ZERO, "first packet after idle should not be delayed");

        // Flush the small packet, then immediately send a large one.
        manager.send_flush(msg_small).await;

        let msg_large = data_tx(iface, 500);
        let wait_large = manager.send_pacing_delay(&msg_large).await;
        let interval_large = expected_data_interval(bitrate, 500);
        let tolerance = Duration::from_millis(50);
        assert!(
            wait_large >= interval_large.saturating_sub(tolerance)
                && wait_large <= interval_large + tolerance,
            "large packet wait {wait_large:?} should be ≈ {interval_large:?}",
        );
        assert!(
            wait_large > wait_small,
            "larger payload should produce a longer pacing interval ({} > {})",
            wait_large.as_micros(),
            wait_small.as_micros(),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn data_pacing_skipped_when_bitrate_is_not_set() {
        let mut manager = InterfaceManager::new(4);
        // No bitrate → no data pacing.
        let channel = manager.new_channel(4);
        let iface = channel.address;
        let mut receiver = channel.tx_channel;

        time::advance(Duration::from_secs(10)).await;
        task::yield_now().await;

        for i in 0..5 {
            let msg = data_tx(iface, 100);
            let wait = manager.send_pacing_delay(&msg).await;
            assert_eq!(
                wait,
                Duration::ZERO,
                "no pacing when bitrate is absent (packet {i})",
            );
            manager.send_flush(msg).await;
            assert!(receiver.try_recv().is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn local_announces_bypass_announce_pacer() {
        let mut manager = InterfaceManager::new(1);
        let pacer = AnnouncePacer::new(10_000.0, DEFAULT_ANNOUNCE_CAP);
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None, None, InterfaceMode::Full);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 0, &[1])).await;
        manager.send(announce(2, 0, &[2])).await;

        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([1; 16])
        );
        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([2; 16])
        );
    }

    #[tokio::test]
    async fn saturated_interface_queue_drops_instead_of_blocking() {
        let mut manager = InterfaceManager::new(1);
        let channel = manager.new_channel(1);
        let iface = channel.address;
        let _receiver = channel.tx_channel;

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            })
            .await;

        time::timeout(
            Duration::from_millis(500),
            manager.send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            }),
        )
        .await
        .expect("send blocked behind a saturated interface queue");
    }

    #[tokio::test]
    async fn queue_lengths_report_rx_and_per_interface_tx_depths() {
        let mut manager = InterfaceManager::new(4);
        let channel = manager.new_channel(4);
        let iface = channel.address;
        let rx_channel = channel.rx_channel.clone();
        let _receiver = channel.tx_channel;

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            })
            .await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Packet::default(),
            })
            .await;
        rx_channel
            .send(RxMessage {
                address: iface,
                snr: None,
                rssi: None,
                packet: Packet::default(),
            })
            .await
            .expect("queued rx message");

        let lengths = manager.queue_lengths().await;

        assert_eq!(lengths.rx, 1);
        assert_eq!(lengths.interfaces.len(), 1);
        assert_eq!(lengths.interfaces[0].address, iface);
        assert_eq!(lengths.interfaces[0].tx, 2);
        assert_eq!(lengths.interfaces[0].announce, 0);
    }

    #[tokio::test]
    async fn spawned_interface_tx_queue_handles_short_bursts() {
        struct TestInterface;

        impl Interface for TestInterface {
            fn hw_mtu(&self) -> usize {
                DEFAULT_HW_MTU
            }
        }

        let mut manager = InterfaceManager::new(1);
        let context = manager.new_context(TestInterface);
        let mut receiver = context.channel.tx_channel;

        for _ in 0..DEFAULT_INTERFACE_TX_QUEUE_CAP {
            manager
                .send(TxMessage {
                    tx_type: TxMessageType::Broadcast(None),
                    packet: Packet::default(),
                })
                .await;
        }

        for _ in 0..DEFAULT_INTERFACE_TX_QUEUE_CAP {
            assert!(receiver.try_recv().is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn forwarded_announces_are_paced_on_bitrate_limited_interfaces() {
        let mut manager = InterfaceManager::new(1);
        let pacer = AnnouncePacer::new(10_000.0, DEFAULT_ANNOUNCE_CAP);
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None, None, InterfaceMode::Full);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 1, &[1])).await;
        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([1; 16])
        );

        manager.send(announce(2, 1, &[2])).await;
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        time::advance(Duration::from_secs(1)).await;
        task::yield_now().await;

        assert_eq!(
            receiver.try_recv().unwrap().packet.destination,
            AddressHash::new([2; 16])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_announces_keep_only_latest_packet_for_destination() {
        let mut manager = InterfaceManager::new(1);
        let pacer = AnnouncePacer::new(10_000.0, DEFAULT_ANNOUNCE_CAP);
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None, None, InterfaceMode::Full);
        let mut receiver = channel.tx_channel;

        manager.send(announce(1, 1, &[0])).await;
        assert_eq!(receiver.try_recv().unwrap().packet.data.as_slice(), &[0]);

        manager.send(announce(2, 1, &[1])).await;
        manager.send(announce(2, 1, &[2])).await;

        let lengths = manager.queue_lengths().await;
        assert_eq!(lengths.interfaces[0].announce, 1);

        time::advance(Duration::from_secs(1)).await;
        task::yield_now().await;

        assert_eq!(receiver.try_recv().unwrap().packet.data.as_slice(), &[2]);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }
}
