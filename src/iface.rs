pub mod backbone;
pub mod hdlc;
pub mod ifac;
pub mod kiss;
pub mod lora;
pub mod modem73;
pub mod rnode;
pub mod tcp_client;
pub mod tcp_server;
pub mod serial;
pub mod udp;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use std::collections::{HashMap, HashSet, VecDeque};
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
use crate::packet::{HeaderType, Packet, PacketContext, PacketType};

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
pub(crate) const DEFAULT_ANNOUNCE_CAP: f64 = 0.06;
const DEFAULT_INTERFACE_TX_QUEUE_CAP: usize = 16_384;
const MAX_QUEUED_ANNOUNCES: usize = 16_384;
const INTERFACE_SEND_TIMEOUT: Duration = Duration::from_millis(100);

// Channel load thresholds to reduce non-essential traffic such as announcements.
// Low == "announce at announce_cap"
// High == "reduce/queue things like announcements to clear space for data"
pub(crate) const CHANNEL_LOAD_LOW_THRESHOLD: f64 = 30.0;
pub(crate) const CHANNEL_LOAD_HIGH_THRESHOLD: f64 = 50.0;

const QUEUE_WARN_THRESHOLD: usize = 1000;
const QUEUE_WARN_INTERVAL: Duration = Duration::from_secs(300);

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

/// Compute the on-wire size of a packet, matching the formula used by
/// both the data pacer and the announce pacer.
fn packet_wire_len(packet: &Packet) -> usize {
    let transport_size = if packet.header.header_type == HeaderType::Type2 {
        ADDRESS_HASH_SIZE
    } else {
        0
    };
    2 + transport_size + ADDRESS_HASH_SIZE + 1 + packet.data.len()
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
    /// Cumulative number of packets sent through this interface.
    pub packets_tx: u64,
    /// Cumulative microseconds spent in pacing waits for this interface.
    pub pacing_wait_us: u64,
    /// Last computed pacing interval in microseconds (0 if not pacing).
    pub last_pacing_interval_us: u64,
    /// Current channel load as a percentage × 1000 (e.g. 6.9% → 6900).
    pub channel_load: u64,
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
    pub channel_load: Option<Arc<Mutex<f64>>>,
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
            channel_load: None,
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

    /// Whether announces received on an Internal-mode interface should be
    /// forwarded through this interface.  When `false`, announces originating
    /// from an Internal-mode interface are blocked.  Defaults to `true`.
    /// Matches Python's `Interface.announces_from_internal`.
    fn announces_from_internal(&self) -> bool {
        true
    }

    /// Whether path requests received on this interface should be
    /// recursively forwarded to other interfaces when the destination
    /// is unknown.  When `false`, the transport only forwards recursive
    /// path requests if the interface mode is in `DISCOVER_PATHS_FOR`.
    /// Defaults to `false`.  Matches Python's `Interface.recursive_prs`.
    fn recursive_prs(&self) -> bool {
        false
    }

    /// Whether this interface provides its own channel-load measurement
    /// from hardware (e.g. RNode's CCA / CMD_STAT_CHTM).  When `true`,
    /// the interface manager will skip spawning the theoretical channel
    /// load background task that would otherwise overwrite the hardware
    /// measurement.
    fn has_hardware_channel_load(&self) -> bool {
        false
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

/// Select the ingress frequency threshold based on the interface age.
/// New interfaces (age < INGRESS_NEW_TIME_S) get a lower threshold.
fn ingress_threshold(created_at: Instant, new_threshold: f64, mature_threshold: f64) -> f64 {
    if Instant::now().duration_since(created_at) < Duration::from_secs(INGRESS_NEW_TIME_S) {
        new_threshold
    } else {
        mature_threshold
    }
}

/// Shared ingress burst recording logic for both announces and path requests.
/// Records a timestamp, computes frequency, evaluates burst state, and returns
/// `true` if the packet should be dropped.
#[allow(clippy::too_many_arguments)]
fn ingress_record_impl(
    freq_deque: &std::sync::Mutex<VecDeque<Instant>>,
    burst_active: &AtomicBool,
    burst_activated: &std::sync::Mutex<Instant>,
    created_at: Instant,
    new_threshold: f64,
    mature_threshold: f64,
) -> bool {
    let now = Instant::now();

    let mut deque = freq_deque.lock().unwrap();
    deque.push_back(now);
    if deque.len() > INGRESS_FREQ_SAMPLES {
        deque.pop_front();
    }

    let freq = ingress_freq(&deque, now);
    let threshold = ingress_threshold(created_at, new_threshold, mature_threshold);
    let deque_len = deque.len();
    drop(deque);

    let mut burst_activated = burst_activated.lock().unwrap();

    if burst_active.load(Ordering::Relaxed) {
        if freq < threshold
            && now.duration_since(*burst_activated) > Duration::from_secs(INGRESS_BURST_HOLD_S)
            && deque_len >= INGRESS_BURST_MIN_SAMPLES
        {
            burst_active.store(false, Ordering::Relaxed);
            return false;
        }
        true
    } else {
        if freq > threshold {
            burst_active.store(true, Ordering::Relaxed);
            *burst_activated = now;
            return true;
        }
        false
    }
}

/// Shared ingress burst evaluation for periodic cleanup.
fn ingress_evaluate_impl(
    freq_deque: &std::sync::Mutex<VecDeque<Instant>>,
    burst_active: &AtomicBool,
    burst_activated: &std::sync::Mutex<Instant>,
    created_at: Instant,
    new_threshold: f64,
    mature_threshold: f64,
) {
    let now = Instant::now();
    let deque = freq_deque.lock().unwrap();
    let freq = ingress_freq(&deque, now);
    let threshold = ingress_threshold(created_at, new_threshold, mature_threshold);
    let deque_len = deque.len();
    drop(deque);

    let mut burst_activated = burst_activated.lock().unwrap();

    if burst_active.load(Ordering::Relaxed) {
        if freq < threshold
            && now.duration_since(*burst_activated) > Duration::from_secs(INGRESS_BURST_HOLD_S)
            && deque_len >= INGRESS_BURST_MIN_SAMPLES
        {
            burst_active.store(false, Ordering::Relaxed);
        }
    } else {
        if freq > threshold {
            burst_active.store(true, Ordering::Relaxed);
            *burst_activated = now;
        }
    }
}

struct LocalInterface {
    address: AddressHash,
    /// If this interface was spawned by a parent (e.g. BackboneClient by
    /// BackboneServer), this field holds the parent's interface address.
    /// Matches Python's `Interface.parent_interface`.  Used for aggregated
    /// ingress burst control and traffic accounting.
    parent_interface: Option<AddressHash>,
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
    /// Whether announces from Internal-mode interfaces are forwarded
    /// through this interface.  Matches Python's `announces_from_internal`.
    announces_from_internal: bool,
    /// Whether path requests received on this interface should be
    /// recursively forwarded.  Matches Python's `recursive_prs`.
    recursive_prs: bool,
    /// Timestamp of the last data packet send, used for inter-packet pacing.
    last_data_send: std::sync::Mutex<Instant>,
    /// Cumulative number of packets sent through this interface.
    packets_tx: AtomicU64,
    /// Cumulative number of data bytes sent through this interface.
    bytes_tx: Arc<AtomicU64>,
    /// Cumulative microseconds spent in pacing waits for this interface.
    pacing_wait_us: AtomicU64,
    /// Last computed pacing interval in microseconds.
    last_pacing_interval_us: AtomicU64,

    // --- Ingress burst limiting state ---
    /// When this interface was created, used to distinguish new vs established
    /// interfaces for ingress burst threshold selection.
    ingress_created_at: Instant,
    /// Timestamps of recently received announces for frequency tracking.
    ia_freq_deque: std::sync::Mutex<VecDeque<Instant>>,
    /// Timestamps of recently received path requests for frequency tracking.
    ip_freq_deque: std::sync::Mutex<VecDeque<Instant>>,
    /// Whether announce burst limiting is currently active.
    ingress_burst_active: AtomicBool,
    /// When the current announce burst was activated.
    ingress_burst_activated: std::sync::Mutex<Instant>,
    /// Whether path-request burst limiting is currently active.
    ingress_pr_burst_active: AtomicBool,
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
    channel_load: Option<Arc<Mutex<f64>>>,
    iface: Option<AddressHash>,
    state: Arc<tokio::sync::Mutex<AnnouncePacerState>>,
}

struct AnnouncePacerState {
    announce_allowed_at: Instant,
    announce_queue: VecDeque<AddressHash>,
    /// Queued announce messages alongside the pacing interval computed
    /// at enqueue time, so the dequeue path can read it without re-
    /// acquiring the channel_load mutex inside wait_time().
    announce_data: HashMap<AddressHash, (TxMessage, Duration)>,
    timer_active: bool,
    next_queue_warn_at: Instant,
    last_queue_warn_len: usize,
}

impl AnnouncePacer {
    fn new(bitrate: f64, announce_cap: f64) -> Self {
        Self {
            bitrate,
            announce_cap,
            channel_load: None,
            iface: None,
            state: Arc::new(tokio::sync::Mutex::new(AnnouncePacerState {
                announce_allowed_at: Instant::now(),
                announce_queue: VecDeque::new(),
                announce_data: HashMap::new(),
                timer_active: false,
                next_queue_warn_at: Instant::now(),
                last_queue_warn_len: 0,
            })),
        }
    }

    fn set_iface(&mut self, addr: AddressHash) {
        self.iface = Some(addr);
    }

    fn with_channel_load(mut self, load: Arc<Mutex<f64>>) -> Self {
        self.channel_load = Some(load);
        self
    }

    fn effective_announce_cap(&self) -> f64 {
        match &self.channel_load {
            Some(load) => {
                let load = *load.lock().unwrap();
                if load < CHANNEL_LOAD_LOW_THRESHOLD {
                    self.announce_cap
                } else if load < CHANNEL_LOAD_HIGH_THRESHOLD {
                    let factor = 1.0
                        - (0.9 * (load - CHANNEL_LOAD_LOW_THRESHOLD)
                            / (CHANNEL_LOAD_HIGH_THRESHOLD - CHANNEL_LOAD_LOW_THRESHOLD));
                    self.announce_cap * factor
                } else {
                    self.announce_cap * 0.1
                }
            }
            None => self.announce_cap,
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

        Some(Duration::from_secs_f64(tx_time / self.effective_announce_cap()))
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
            state.announce_data.insert(dest, (message, wait_time));
        } else if state.announce_queue.len() < MAX_QUEUED_ANNOUNCES {
            state.announce_queue.push_back(dest);
            state.announce_data.insert(dest, (message, wait_time));
        }

        let qlen = state.announce_queue.len();
        if qlen >= QUEUE_WARN_THRESHOLD
            && qlen > state.last_queue_warn_len
            && now >= state.next_queue_warn_at
        {
            state.next_queue_warn_at = now + QUEUE_WARN_INTERVAL;
            state.last_queue_warn_len = qlen;
            let iface = self.iface.map(|a| a.to_string()).unwrap_or_default();
            let pkt_time = (44.0_f64 * 8.0) / self.bitrate;
            let drain = self.effective_announce_cap() / pkt_time;
            log::warn!(
                "iface {}: announce backlog {} entries, cap={:.0}% ({:.0}% effective), drain={:.1}/s",
                iface, qlen,
                self.announce_cap * 100.0,
                self.effective_announce_cap() * 100.0,
                drain,
            );
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

            // Pop the queued announce with the lowest hop count,
            // matching Python's hop-prioritized announce queue.
            let min_idx = state.announce_queue.iter().enumerate().filter_map(|(i, dest)| {
                state.announce_data.get(dest).map(|(msg, _)| (i, msg.packet.header.hops))
            }).min_by_key(|&(_, hops)| hops);

            match min_idx {
                Some((idx, _)) => {
                    if let Some(dest) = state.announce_queue.remove(idx) {
                        if let Some((message, wait_time)) = state.announce_data.remove(&dest) {
                            state.announce_allowed_at = now + wait_time;
                            Some(message)
                        } else {
                            state.timer_active = false;
                            None
                        }
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

/// Background task that periodically computes a theoretical channel load
/// for interfaces with a known bitrate but no hardware channel-load
/// measurement.  The load is derived from recent TX activity:
///
///   airtime = (bytes_sent * 8) / bitrate
///   load_pct = airtime / sample_interval * 100
///
/// The result is written to the shared `channel_load` mutex so that both
/// the announce pacer and metrics collection see a non-zero value.
async fn theoretical_channel_load_task(
    channel_load: Arc<Mutex<f64>>,
    bytes_tx: Arc<AtomicU64>,
    bitrate: f64,
    stop: CancellationToken,
) {
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(15);
    let mut last_bytes = bytes_tx.load(Ordering::Relaxed);
    let mut timer = time::interval(SAMPLE_INTERVAL);

    // Skip the immediate first tick so we have a real delta.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = timer.tick() => {},
        }

        let current_bytes = bytes_tx.load(Ordering::Relaxed);
        let delta_bytes = current_bytes - last_bytes;
        last_bytes = current_bytes;

        if delta_bytes == 0 {
            *channel_load.lock().unwrap() = 0.0;
        } else {
            let airtime_s = (delta_bytes as f64 * 8.0) / bitrate;
            let load_pct = (airtime_s / SAMPLE_INTERVAL.as_secs_f64()) * 100.0;
            *channel_load.lock().unwrap() = load_pct.clamp(0.0, 100.0);
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
    /// Maps interface address → index into `ifaces` for O(1) lookups.
    /// Rebuilt after any removal that shifts indices.
    iface_index: HashMap<AddressHash, usize>,
    /// Set of destination hashes that are registered locally on this node.
    /// Used to exempt local destinations from interface-mode filtering.
    local_destinations: HashSet<AddressHash>,
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
            iface_index: HashMap::new(),
            local_destinations: HashSet::new(),
        }
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_with_pacer(tx_cap, None, false, None, None, None, InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)))
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
        announces_from_internal: bool,
        recursive_prs: bool,
        channel_load: Arc<Mutex<f64>>,
        bytes_tx: Arc<AtomicU64>,
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

        let announce_pacer = announce_pacer.map(|mut p| { p.set_iface(address); p });

        let stop = CancellationToken::new();

        self.ifaces.push(LocalInterface {
            address,
            parent_interface: None,
            tx_send,
            stop: stop.clone(),
            announce_pacer,
            saturated_queue_logger: SaturatedQueueLogger::new(address),
            shared_instance_client,
            hw_mtu,
            ifac_config: ifac_config.clone(),
            bitrate,
            mode,
            announces_from_internal,
            recursive_prs,
            ingress_created_at: Instant::now(),
            last_data_send: std::sync::Mutex::new(Instant::now()),
            packets_tx: AtomicU64::new(0),
            bytes_tx,
            pacing_wait_us: AtomicU64::new(0),
            last_pacing_interval_us: AtomicU64::new(0),
            ia_freq_deque: std::sync::Mutex::new(VecDeque::with_capacity(INGRESS_FREQ_SAMPLES)),
            ip_freq_deque: std::sync::Mutex::new(VecDeque::with_capacity(INGRESS_FREQ_SAMPLES)),
            ingress_burst_active: AtomicBool::new(false),
            ingress_burst_activated: std::sync::Mutex::new(Instant::now()),
            ingress_pr_burst_active: AtomicBool::new(false),
            ingress_pr_burst_activated: std::sync::Mutex::new(Instant::now()),
            op_freq_deque: std::sync::Mutex::new(VecDeque::with_capacity(INGRESS_FREQ_SAMPLES)),
        });

        self.iface_index.insert(address, self.ifaces.len() - 1);

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
            ifac_config,
            channel_load: Some(channel_load),
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
        let channel_load = Arc::new(Mutex::new(0.0));
        let announce_pacer = bitrate
            .filter(|bitrate| *bitrate > 0.0 && announce_cap > 0.0)
            .map(|bitrate| AnnouncePacer::new(bitrate, announce_cap).with_channel_load(channel_load.clone()));
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
        let announces_from_internal = inner.announces_from_internal();
        let recursive_prs = inner.recursive_prs();
        let bytes_tx = Arc::new(AtomicU64::new(0));
        let channel = self.new_channel_with_pacer(
            DEFAULT_INTERFACE_TX_QUEUE_CAP,
            announce_pacer,
            shared_instance_client,
            hw_mtu,
            None,
            configured_bitrate(bitrate.unwrap_or(0.0)),
            mode,
            announces_from_internal,
            recursive_prs,
            channel_load.clone(),
            bytes_tx.clone(),
        );

        // Spawn a background task that periodically calculates theoretical
        // channel load from recent TX activity for interfaces with a known
        // bitrate but no hardware channel-load measurement (e.g. RNode's
        // CCA provides its own).  The result is written to the shared
        // channel_load mutex so that both the announce pacer and metrics
        // collection see a non-zero value.
        if let Some(bitrate) = bitrate.filter(|b| *b > 0.0) {
            if !inner.has_hardware_channel_load() {
                let stop = channel.stop.clone();
                task::spawn(theoretical_channel_load_task(
                    channel_load,
                    bytes_tx,
                    bitrate,
                    stop,
                ));
            }
        }

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

            let channel_load = match &iface.announce_pacer {
                Some(pacer) => pacer.channel_load.as_ref().map(|cl| {
                    (*cl.lock().unwrap() * 1000.0) as u64
                }).unwrap_or(0),
                None => 0,
            };
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
                channel_load,
            });
        }

        InterfaceQueueLengths {
            rx: channel_queue_len(&self.rx_send),
            interfaces,
        }
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
        self.iface_index.clear();
        for (idx, iface) in self.ifaces.iter().enumerate() {
            self.iface_index.insert(iface.address, idx);
        }
    }

    /// Record an incoming announce on an interface and return `true` if the
    /// announce should be dropped due to ingress burst limiting.
    /// Only applied to interfaces with a known bitrate (slow links).
    /// Matches Python's aggregated ingress control: if the interface has a
    /// parent, and any sibling (same parent) is in burst state, the burst
    /// is considered active across the group (BackboneInterface.py:165).
    pub fn ingress_record_announce(&self, address: &AddressHash) -> bool {
        let Some(iface) = self.iface_by_address(address) else {
            return false;
        };
        if iface.bitrate.is_none() {
            return false;
        }

        let dropped = ingress_record_impl(
            &iface.ia_freq_deque,
            &iface.ingress_burst_active,
            &iface.ingress_burst_activated,
            iface.ingress_created_at,
            INGRESS_BURST_FREQ_NEW,
            INGRESS_BURST_FREQ,
        );

        // Aggregated ingress burst control: if any sibling (same parent)
        // is in burst state, treat this interface as burst-active too.
        // Uses AtomicBool::load to avoid per-sibling lock acquisitions.
        if !dropped {
            if let Some(parent) = iface.parent_interface {
                for sibling in &self.ifaces {
                    if sibling.address != *address
                        && sibling.parent_interface == Some(parent)
                        && sibling.ingress_burst_active.load(Ordering::Relaxed)
                    {
                        return true;
                    }
                }
            }
        }

        dropped
    }

    /// Record an incoming path request on an interface and return `true`
    /// if it should be dropped due to ingress burst limiting.
    /// Only applied to interfaces with a known bitrate (slow links).
    /// Uses the same sibling-aggregation pattern as `ingress_record_announce`.
    pub fn ingress_record_pr(&self, address: &AddressHash) -> bool {
        let Some(iface) = self.iface_by_address(address) else {
            return false;
        };
        if iface.bitrate.is_none() {
            return false;
        }

        let dropped = ingress_record_impl(
            &iface.ip_freq_deque,
            &iface.ingress_pr_burst_active,
            &iface.ingress_pr_burst_activated,
            iface.ingress_created_at,
            INGRESS_PR_BURST_FREQ_NEW,
            INGRESS_PR_BURST_FREQ,
        );

        if !dropped {
            if let Some(parent) = iface.parent_interface {
                for sibling in &self.ifaces {
                    if sibling.address != *address
                        && sibling.parent_interface == Some(parent)
                        && sibling.ingress_pr_burst_active.load(Ordering::Relaxed)
                    {
                        return true;
                    }
                }
            }
        }

        dropped
    }

    /// Evaluate and update ingress burst state for all interfaces.
    /// Should be called periodically (e.g. every ~10 seconds).
    pub fn ingress_evaluate_all(&self) {
        for iface in &self.ifaces {
            if iface.stop.is_cancelled() || iface.bitrate.is_none() {
                continue;
            }

            ingress_evaluate_impl(
                &iface.ia_freq_deque,
                &iface.ingress_burst_active,
                &iface.ingress_burst_activated,
                iface.ingress_created_at,
                INGRESS_BURST_FREQ_NEW,
                INGRESS_BURST_FREQ,
            );

            ingress_evaluate_impl(
                &iface.ip_freq_deque,
                &iface.ingress_pr_burst_active,
                &iface.ingress_pr_burst_activated,
                iface.ingress_created_at,
                INGRESS_PR_BURST_FREQ_NEW,
                INGRESS_PR_BURST_FREQ,
            );
        }
    }

    /// Record an outgoing path request on this interface and return
    /// `true` if the egress PR frequency exceeds `EGRESS_PR_FREQ` (5
    /// Hz), indicating excessive outgoing PR activity.
    pub fn egress_record_pr(&self, address: &AddressHash) -> bool {
        let Some(iface) = self.iface_by_address(address) else {
            return false;
        };

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

    /// Register a destination hash as locally owned.  Local destinations
    /// are exempt from certain interface-mode announce filtering rules
    /// (matching Python's `local_destination` check in `Transport.outbound()`).
    pub fn add_local_destination(&mut self, hash: AddressHash) {
        self.local_destinations.insert(hash);
    }

    /// Unregister a previously registered local destination hash.
    pub fn remove_local_destination(&mut self, hash: &AddressHash) {
        self.local_destinations.remove(hash);
    }

    /// Returns `true` if the given destination hash is registered as a
    /// local destination on this node.
    pub fn is_local_destination(&self, hash: &AddressHash) -> bool {
        self.local_destinations.contains(hash)
    }

    /// Look up an interface by address without scanning the entire Vec.
    /// Returns `None` if the address is not found or the interface was
    /// cancelled (but not yet removed by `cleanup`).
    fn iface_by_address(&self, address: &AddressHash) -> Option<&LocalInterface> {
        let idx = *self.iface_index.get(address)?;
        let iface = &self.ifaces[idx];
        if iface.stop.is_cancelled() {
            return None;
        }
        Some(iface)
    }

    /// Mutable variant of `iface_by_address`.
    fn iface_by_address_mut(&mut self, address: &AddressHash) -> Option<&mut LocalInterface> {
        let idx = *self.iface_index.get(address)?;
        let iface = &mut self.ifaces[idx];
        if iface.stop.is_cancelled() {
            return None;
        }
        Some(iface)
    }

    /// Return whether the interface at `address` has recursive path
    /// requests enabled.  Returns `false` if the interface is not found
    /// or cancelled.  Matches Python's `Interface.recursive_prs`.
    pub fn recursive_prs_for_iface(&self, address: &AddressHash) -> bool {
        self.iface_by_address(address)
            .map(|i| i.recursive_prs)
            .unwrap_or(false)
    }

    /// Return the interface mode for the given interface address, or
    /// `InterfaceMode::Full` if the interface is not found or cancelled.
    pub fn interface_mode(&self, address: &AddressHash) -> InterfaceMode {
        self.iface_by_address(address)
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
        self.iface_by_address(address)
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

            let packet_len = packet_wire_len(&message.packet);
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
        // Hoist invariant values out of the per-interface loop.
        // source_mode and is_local depend only on the message, not on the
        // destination interface, so computing them once avoids O(n²) behaviour
        // from the linear scan inside self.interface_mode().
        let source_mode = match &message.tx_type {
            TxMessageType::Broadcast(Some(addr)) => Some(self.interface_mode(addr)),
            _ => None,
        };
        let is_local = self.is_local_destination(&message.packet.destination);

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

            // Interface mode-based announce propagation filtering.
            // Matches Python RNS/Transport.py outbound() lines 1207-1264.
            let is_paced_announce = AnnouncePacer::should_pace(&message);
            if is_paced_announce {
                // Path responses are solicited replies to client path
                // requests.  They must cross all interface mode boundaries
                // regardless of normal announce propagation rules,
                // otherwise clients cannot resolve paths across modes
                // such as Boundary ↔ Internal.
                if message.packet.context == PacketContext::PathResponse {
                    // fall through — no mode restrictions
                } else {

                    // Python: "elif not local_destination and interface.announces_from_internal == False
                    //          and from_interface.mode == MODE_INTERNAL: block"
                    // This filter applies on ANY outgoing interface (regardless of its own mode)
                    // when the announce originated on an Internal-mode interface.
                    if !is_local
                        && !iface.announces_from_internal
                        && source_mode == Some(InterfaceMode::Internal)
                    {
                        log::trace!(
                            "iface: blocking announce on {} from internal-mode iface",
                            iface.address,
                        );
                        continue;
                    }

                    // Python: "elif interface.mode == MODE_ACCESS_POINT: block"
                    if iface.mode == InterfaceMode::AccessPoint {
                        log::trace!("iface: blocking announce on AP iface {}", iface.address);
                        continue;
                    }

                    // Python: "elif not local_destination and interface.mode == MODE_INTERNAL:"
                    if !is_local && iface.mode == InterfaceMode::Internal {
                        // Block if source interface mode is Boundary (Python line 1233:
                        // "if from_interface.mode == MODE_BOUNDARY: should_transmit = False")
                        // In the Rust code, Broadcast(None) always means a locally-originated
                        // announce (hops == 0) so it never reaches this path.
                        if source_mode == Some(InterfaceMode::Boundary) {
                            log::trace!(
                                "iface: blocking announce on internal iface {} from boundary-mode iface",
                                iface.address,
                            );
                            continue;
                        }
                    }

                    // Python: "elif interface.mode == MODE_ROAMING:"
                    if iface.mode == InterfaceMode::Roaming {
                        if is_local {
                            // Python: "if local_destination != None: pass" → allow
                        } else {
                            // Python: block if source is Roaming or Boundary
                            let blocked = matches!(
                                source_mode,
                                Some(InterfaceMode::Roaming) | Some(InterfaceMode::Boundary)
                            );
                            if blocked {
                                log::trace!(
                                    "iface: blocking announce on roaming iface {} from {:?}",
                                    iface.address,
                                    source_mode,
                                );
                                continue;
                            }
                        }
                    }

                    // Python: "elif interface.mode == MODE_BOUNDARY:"
                    if iface.mode == InterfaceMode::Boundary {
                        if is_local {
                            // Python: "if local_destination != None: pass" → allow
                        } else {
                            // Python: block if source is Roaming
                            if source_mode == Some(InterfaceMode::Roaming) {
                                log::trace!(
                                    "iface: blocking announce on boundary iface {} from roaming-mode iface",
                                    iface.address,
                                );
                                continue;
                            }
                        }
                    }

                    // Full / PointToPoint / Gateway fall through to normal
                    // announce pacing and cap-based queuing below.
                    }
            }

            // Path responses are solicited replies to client path requests
            // and must cross all interface mode boundaries freely, even
            // though they technically carry a Broadcast tx_type.
            if message.packet.context != PacketContext::PathResponse {
                // For AccessPoint interfaces, block non-announce broadcasts
                // that originated from other interfaces.  This prevents the
                // AP from relaying unrelated network noise to its clients.
                if iface.mode == InterfaceMode::AccessPoint {
                    let from_other_iface = match &message.tx_type {
                        TxMessageType::Broadcast(Some(addr)) => *addr != iface.address,
                        _ => false,
                    };
                    if from_other_iface {
                        log::trace!(
                            "iface: blocking non-announce broadcast on AP iface {}",
                            iface.address,
                        );
                        continue;
                    }
                }

                // For Internal interfaces, block non-announce broadcasts
                // that originated from a Boundary interface.  This protects
                // the internal (typically low-bandwidth) side from being
                // flooded by traffic from the boundary (typically high-speed)
                // side, matching the intent described in the Reticulum docs.
                if iface.mode == InterfaceMode::Internal {
                    if source_mode == Some(InterfaceMode::Boundary) {
                        log::trace!(
                            "iface: blocking non-announce broadcast on internal iface {} from boundary",
                            iface.address,
                        );
                        continue;
                    }
                }
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

            let packet_len = packet_wire_len(&message.packet) as u64;

            if let Some(pacer) = iface
                .announce_pacer
                .as_ref()
                .filter(|_| is_paced_announce)
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
            }

            iface.packets_tx.fetch_add(1, Ordering::Relaxed);
            iface.bytes_tx.fetch_add(packet_len, Ordering::Relaxed);
        }
    }

    /// Set or clear the IFAC configuration for a specific interface.
    ///
    /// When set, outbound packets sent through this interface will have an
    /// Ed25519 signature attached as an Interface Access Code.
    pub fn set_ifac_config(&mut self, address: &AddressHash, config: Option<IfacConfig>) {
        if let Some(idx) = self.iface_index.get(address).copied() {
            self.ifaces[idx].ifac_config = config;
        }
    }

    /// Return the IFAC configuration for a specific interface, if set.
    pub fn get_ifac_config(&self, address: &AddressHash) -> Option<&IfacConfig> {
        let idx = *self.iface_index.get(address)?;
        self.ifaces[idx].ifac_config.as_ref()
    }

    /// Set the parent interface for an interface.
    /// Matches Python's `Interface.parent_interface` used by
    /// `BackboneInterface` and `I2PInterface` for their spawned children.
    pub fn set_parent_interface(&mut self, address: &AddressHash, parent: &AddressHash) {
        if let Some(idx) = self.iface_index.get(address).copied() {
            self.ifaces[idx].parent_interface = Some(*parent);
        }
    }

    /// Return the parent_interface for a given interface, if any.
    pub fn parent_interface_of(&self, address: &AddressHash) -> Option<AddressHash> {
        let idx = *self.iface_index.get(address)?;
        self.ifaces[idx].parent_interface
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
            4, None, false, None, None, Some(bitrate), InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)),
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
            4, None, false, None, None, Some(bitrate), InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)),
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
            4, None, false, None, None, Some(bitrate), InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)),
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
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None, None, InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)));
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
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None, None, InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)));
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
        let channel = manager.new_channel_with_pacer(4, Some(pacer), false, None, None, None, InterfaceMode::Full, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)));
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

    // ------------------------------------------------------------------
    // Interface mode broadcast filter tests
    // ------------------------------------------------------------------

    /// Create a non-announce (Data) broadcast message, optionally
    /// specifying the source interface address.
    fn data_broadcast(source: Option<AddressHash>, data: &[u8]) -> TxMessage {
        TxMessage {
            tx_type: match source {
                Some(addr) => TxMessageType::Broadcast(Some(addr)),
                None => TxMessageType::Broadcast(None),
            },
            packet: Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type1,
                    context_flag: ContextFlag::Unset,
                    propagation_type: PropagationType::Broadcast,
                    destination_type: DestinationType::Plain,
                    packet_type: PacketType::Data,
                    hops: 0,
                },
                ifac: None,
                destination: AddressHash::new([0xdd; 16]),
                transport: None,
                context: PacketContext::None,
                data: PacketDataBuffer::new_from_slice(data),
            },
        }
    }

    /// Create a forwarded (hops > 0) announce message.
    fn forwarded_announce(destination: u8) -> TxMessage {
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
                    hops: 1, // forwarded
                },
                ifac: None,
                destination: AddressHash::new([destination; 16]),
                transport: None,
                context: PacketContext::None,
                data: PacketDataBuffer::new_from_slice(&[]),
            },
        }
    }

    /// Create a four-interface harness (Full, Boundary, Internal, AP)
    /// with a high dummy bitrate so pacing never interferes.
    struct ModeTestHarness {
        mgr: InterfaceManager,
        ifaces: Vec<(&'static str, AddressHash, mpsc::Receiver<TxMessage>)>,
    }

    impl ModeTestHarness {
        fn new() -> Self {
            let mut mgr = InterfaceManager::new(4);
            let mut ifaces = Vec::new();

            for (label, mode) in &[
                ("full", InterfaceMode::Full),
                ("boundary", InterfaceMode::Boundary),
                ("internal", InterfaceMode::Internal),
                ("ap", InterfaceMode::AccessPoint),
            ] {
                let ch = mgr.new_channel_with_pacer(
                    4, None, false, None, None, Some(1_000_000.0),
                    *mode, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)),
                );
                ifaces.push((*label, ch.address, ch.tx_channel));
            }

            Self { mgr, ifaces }
        }
    }

    #[tokio::test]
    async fn non_announce_broadcast_from_full_reaches_boundary_and_internal() {
        let mut h = ModeTestHarness::new();
        let full_addr = h.ifaces.iter().find(|(l, _, _)| *l == "full").unwrap().1;

        h.mgr
            .send_flush(data_broadcast(Some(full_addr), &[1]))
            .await;

        // Full (source) excluded by should_send.
        // AP blocked by AccessPoint non-announce filter.
        // Boundary and Internal are not filtered → receive.
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "boundary" || *lbl == "internal";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn non_announce_broadcast_from_boundary_blocked_on_internal_and_ap() {
        let mut h = ModeTestHarness::new();
        let boundary_addr = h.ifaces.iter().find(|(l, _, _)| *l == "boundary").unwrap().1;

        h.mgr
            .send_flush(data_broadcast(Some(boundary_addr), &[1]))
            .await;

        // Boundary (source) excluded by should_send.
        // Internal blocked by Internal filter (broadcast from Boundary).
        // AP blocked by AP filter (broadcast from other interface).
        // Full receives (no filter).
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "full";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn non_announce_broadcast_from_internal_blocked_on_ap() {
        let mut h = ModeTestHarness::new();
        let internal_addr = h.ifaces.iter().find(|(l, _, _)| *l == "internal").unwrap().1;

        h.mgr
            .send_flush(data_broadcast(Some(internal_addr), &[1]))
            .await;

        // Internal (source) excluded by should_send.
        // AP blocked by AP filter (broadcast from other interface).
        // Full and Boundary receive (no filter).
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "full" || *lbl == "boundary";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn non_announce_broadcast_from_ap_excluded_by_should_send() {
        let mut h = ModeTestHarness::new();
        let ap_addr = h.ifaces.iter().find(|(l, _, _)| *l == "ap").unwrap().1;

        h.mgr
            .send_flush(data_broadcast(Some(ap_addr), &[1]))
            .await;

        // AP (source) excluded by should_send.
        // AP filter doesn't matter (message never reaches it).
        // All other interfaces receive it.
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl != "ap";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn direct_message_always_reaches_target_interface() {
        let mut h = ModeTestHarness::new();
        let ap_addr = h.ifaces.iter().find(|(l, _, _)| *l == "ap").unwrap().1;

        h.mgr
            .send_flush(TxMessage {
                tx_type: TxMessageType::Direct(ap_addr),
                packet: Packet {
                    header: Header {
                        ifac_flag: IfacFlag::Open,
                        header_type: HeaderType::Type1,
                        context_flag: ContextFlag::Unset,
                        propagation_type: PropagationType::Broadcast,
                        destination_type: DestinationType::Plain,
                        packet_type: PacketType::Data,
                        hops: 0,
                    },
                    ifac: None,
                    destination: AddressHash::new([0xdd; 16]),
                    transport: None,
                    context: PacketContext::None,
                    data: PacketDataBuffer::new_from_slice(&[1]),
                },
            })
            .await;

        // Only the AP interface should receive a Direct message
        for (lbl, _addr, rx) in &mut h.ifaces {
            assert_eq!(
                rx.try_recv().is_ok(),
                *lbl == "ap",
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn forwarded_announce_blocked_on_ap() {
        let mut h = ModeTestHarness::new();
        let full_addr = h.ifaces.iter().find(|(l, _, _)| *l == "full").unwrap().1;

        let mut msg = forwarded_announce(0xaa);
        msg.tx_type = TxMessageType::Broadcast(Some(full_addr));
        h.mgr.send_flush(msg).await;

        // Full (source) excluded by should_send.
        // AP blocked by announce filter (AP blocks all announces).
        // Boundary and Internal receive (no restriction on Full→* announces).
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "boundary" || *lbl == "internal";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn forwarded_announce_from_boundary_blocked_on_internal_and_ap() {
        let mut h = ModeTestHarness::new();
        let boundary_addr = h.ifaces.iter().find(|(l, _, _)| *l == "boundary").unwrap().1;

        let mut msg = forwarded_announce(0xbb);
        msg.tx_type = TxMessageType::Broadcast(Some(boundary_addr));
        h.mgr.send_flush(msg).await;

        // Boundary (source) excluded by should_send.
        // Internal blocked by announce filter: Internal blocks announces from Boundary.
        // AP blocked by announce filter: AP blocks all announces.
        // Full receives (no restriction).
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "full";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn forwarded_announce_from_internal_blocked_on_ap() {
        let mut h = ModeTestHarness::new();
        let internal_addr = h.ifaces.iter().find(|(l, _, _)| *l == "internal").unwrap().1;

        let mut msg = forwarded_announce(0xcc);
        msg.tx_type = TxMessageType::Broadcast(Some(internal_addr));
        h.mgr.send_flush(msg).await;

        // Internal (source) excluded by should_send.
        // AP blocked by announce filter (AP blocks all announces).
        // Full and Boundary receive (no restriction on Internal→* announces).
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "full" || *lbl == "boundary";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn forwarded_announce_from_roaming_blocked_on_boundary_and_ap() {
        let mut h = ModeTestHarness::new();
        let roaming_ch = h.mgr.new_channel_with_pacer(
            4, None, false, None, None, Some(1_000_000.0),
            InterfaceMode::Roaming, true, false, Arc::new(Mutex::new(0.0)), Arc::new(AtomicU64::new(0)),
        );

        let mut msg = forwarded_announce(0xee);
        msg.tx_type = TxMessageType::Broadcast(Some(roaming_ch.address));
        h.mgr.send_flush(msg).await;

        // Roaming (source) excluded by should_send.
        // Boundary blocked by announce filter: Boundary blocks announces from Roaming.
        // AP blocked by announce filter: AP blocks all announces.
        // Full receives (no restriction).
        // Internal receives (no restriction: Internal only blocks from Boundary).
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl == "full" || *lbl == "internal";
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }

    #[tokio::test]
    async fn path_response_crosses_boundary_to_internal() {
        let mut h = ModeTestHarness::new();
        let boundary_addr = h.ifaces.iter().find(|(l, _, _)| *l == "boundary").unwrap().1;

        // Create a PathResponse packet from Boundary source.
        let mut msg = forwarded_announce(0xab);
        msg.packet.context = PacketContext::PathResponse;
        msg.tx_type = TxMessageType::Broadcast(Some(boundary_addr));

        h.mgr.send_flush(msg).await;

        // PathResponse must be delivered to Internal even though it
        // originated from Boundary — it is a solicited reply.
        for (lbl, _addr, rx) in &mut h.ifaces {
            let should = *lbl != "boundary"; // source excluded; all others receive
            assert_eq!(
                rx.try_recv().is_ok(),
                should,
                "{lbl}",
            );
        }
    }
}
