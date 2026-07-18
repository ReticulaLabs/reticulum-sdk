use alloc::sync::Arc;
use announce_limits::AnnounceLimits;
use announce_table::AnnounceTable;
use discovery::DISCOVERY_JOB_INTERVAL;
use discovery::RegisteredDiscoveryInterface;
use discovery::create_discovery_destination;
use discovery::is_discovery_destination;
use hmac::{Hmac, Mac};
use link_table::LinkTable;
use packet_cache::PacketCache;
use path_requests::PathRequests;
use path_requests::TagBytes;
use path_requests::create_path_request_destination;
use path_table::PathTable;
use rand_core::OsRng;
use rand_core::RngCore;
use reverse_table::ReverseTable;
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::net::TcpListener as StdTcpListener;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use tokio_util::sync::CancellationToken;

use tokio::sync::Mutex;
use tokio::sync::broadcast;

use crate::destination::DestinationAnnounce;
use crate::destination::DestinationDesc;
use crate::destination::DestinationHandleStatus;
use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::destination::SingleOutputDestination;
use crate::destination::link::LINK_MTU_SIZE;
use crate::destination::link::Link;
use crate::destination::link::LinkEvent;
use crate::destination::link::LinkEventData;
use crate::destination::link::LinkHandleResult;
use crate::destination::link::LinkId;
use crate::destination::link::LinkStatus;
use crate::destination::link::link_signalling_bytes;
use crate::destination::link::mtu_from_signalling_bytes;

use crate::error::RnsError;

use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::identity::{PUBLIC_KEY_LENGTH, PrivateIdentity};

use crate::iface::InterfaceManager;
use crate::iface::InterfaceMode;

use crate::iface::InterfaceQueueLengths;
use crate::iface::InterfaceRxReceiver;
use crate::iface::RxMessage;
use crate::iface::TxMessage;
use crate::iface::TxMessageType;
use crate::iface::tcp_client::TcpClient;
use blackhole::BlackholeTable;

use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::HeaderType;
use crate::packet::IfacFlag;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::packet::PropagationType;

mod announce_limits;
mod announce_table;
mod blackhole;
mod discovery;
mod link_table;
mod packet_cache;
mod path_requests;
mod path_table;
mod reverse_table;

pub use discovery::DiscoveredInterface;
pub use discovery::DiscoveryInterfaceConfig;
pub use discovery::DiscoveryInterfaceKind;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

const INTERVAL_LINKS_CHECK: Duration = Duration::from_secs(1);
const INTERVAL_PENDING_PROOF_TIMEOUT: Duration = Duration::from_secs(60);
const INTERVAL_INPUT_LINK_STALE: Duration = Duration::from_secs(720);
const INTERVAL_INPUT_LINK_CLOSE: Duration = Duration::from_secs(5);
const INTERVAL_OUTPUT_LINK_RESTART: Duration = Duration::from_secs(60);
const INTERVAL_OUTPUT_LINK_STALE: Duration = Duration::from_secs(720);
const INTERVAL_OUTPUT_LINK_CLOSE: Duration = Duration::from_secs(5);
const INTERVAL_OUTPUT_LINK_REPEAT: Duration = Duration::from_secs(6);
const INTERVAL_OUTPUT_LINK_TRIED: Duration = Duration::from_secs(30);
const INTERVAL_OUTPUT_LINK_KEEP: Duration = Duration::from_secs(5);
const INTERVAL_IFACE_CLEANUP: Duration = Duration::from_secs(10);
const INTERVAL_ANNOUNCES_RETRANSMIT: Duration = Duration::from_secs(1);
const INTERVAL_OLD_ANNOUNCES_RETRANSMIT: Duration = Duration::from_secs(60);
const INTERVAL_KEEP_PACKET_CACHED: Duration = Duration::from_secs(180);
const INTERVAL_PACKET_CACHE_CLEANUP: Duration = Duration::from_secs(90);
const INTERVAL_LINK_TABLE_STALE: Duration = Duration::from_secs(720);
const INTERVAL_KEEP_REVERSE_PATH: Duration = Duration::from_secs(8 * 60);
const INTERVAL_PATH_TABLE_CULL: Duration = Duration::from_secs(30);

const PATH_REQUEST_MI: Duration = Duration::from_secs(20);
const PATH_REQUEST_GRACE: Duration = Duration::from_millis(400);
const PATH_REQUEST_RG: Duration = Duration::from_millis(1500);

// Interface mode path expiry times (matching Python Reticulum):
// Full / Gateway / Boundary / Internal / PointToPoint → 1 week
const PATH_EXPIRY_FULL: Duration = Duration::from_secs(60 * 60 * 24 * 7);
// Access Point → 1 day
const PATH_EXPIRY_AP: Duration = Duration::from_secs(60 * 60 * 24);
// Roaming → 6 hours
const PATH_EXPIRY_ROAMING: Duration = Duration::from_secs(60 * 60 * 6);

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;

/// Default capacity for internal tokio broadcast channels used to deliver
/// transport events (announces, link events, received data, receipts, etc.)
/// to the application layer.
///
/// Each broadcast channel pre-allocates a fixed ring buffer of this size.
/// Memory usage per channel = capacity × size of the message slot.
///
/// Can be overridden on a per-transport basis via
/// [`TransportConfig::set_event_channel_capacity`]. High-throughput
/// deployments (e.g., backbone links) should use a larger capacity
/// (up to 32768), while resource-constrained or low-speed links (LoRa,
/// serial) can use a smaller one (e.g., 512–1024).
pub(crate) const EVENT_CHANNEL_CAPACITY: usize = 16384;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;
pub const DEFAULT_SHARED_INSTANCE_PORT: u16 = 37428;
pub const DEFAULT_INSTANCE_CONTROL_PORT: u16 = 37429;
pub const DEFAULT_INSTANCE_NAME: &str = "default";
const DEFAULT_PER_HOP_TIMEOUT_SECS: u64 = 6;
const PY_CONN_CHALLENGE: &[u8] = b"#CHALLENGE#";
const PY_CONN_WELCOME: &[u8] = b"#WELCOME#";
const PY_CONN_FAILURE: &[u8] = b"#FAILURE#";
const PY_CONN_AUTH_MAX_FRAME: usize = 256;
const PY_CONN_MUTUAL_AUTH_TIMEOUT: Duration = Duration::from_millis(500);

/// Log a warning if a broadcast sender is at or above capacity.
fn warn_if_event_channel_full<T>(sender: &tokio::sync::broadcast::Sender<T>, capacity: usize, label: &str, name: &str) {
    let len = sender.len();
    if len >= capacity {
        log::warn!(
            "tp({}): {} event channel is full ({} of {} slots used), messages will be dropped",
            name,
            label,
            len,
            capacity,
        );
    }
}

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
}

pub struct TransportConfig {
    name: String,
    identity: PrivateIdentity,
    broadcast: bool,
    retransmit: bool,

    /// If `false`, `Transport` will replace known routes to distant destinations
    /// only if they are shorter (fewer hops) than the new one.
    /// If `true`, routes will also be replaced if the new route is equally long.
    /// So newer routes are preferred over older ones.
    reroute_eager: bool,

    /// Attempt to reopen lost links once they have been closed.
    restart_outlinks: bool,

    /// Resend announces of remote destinations at a slower pace once
    /// the initial round of announces is over.
    announce_forever: bool,

    /// Create a local `rnstransport.probe` destination that returns
    /// packet proofs for incoming probe packets.
    respond_to_probes: bool,

    /// Whether to publish blackhole list via a `rnstransport.info.blackhole`
    /// request handler (protocol-compatible with Python Reticulum).
    publish_blackhole: bool,

    /// Remote transport identity hashes from which blackhole lists
    /// are fetched (protocol-compatible with Python Reticulum
    /// `blackhole_sources` config option).
    blackhole_sources: Vec<AddressHash>,

    /// Interval at which remote blackhole sources are polled for
    /// updates. Defaults to 1 hour.
    blackhole_update_interval: Duration,

    /// Whether to participate in link MTU discovery and upgrades.
    /// When enabled, the initiator queries the next-hop interface HW_MTU and
    /// signals it in the link request; intermediate transport nodes clamp the
    /// value to the minimum of all interfaces along the path.
    link_mtu_discovery: bool,

    /// Capacity of the internal tokio broadcast channels that deliver
    /// transport events (announces, link events, received data, receipts,
    /// raw interface messages) to the application layer.
    ///
    /// Each channel pre-allocates a fixed ring buffer of this size.
    /// High-throughput deployments (e.g. backbone links aggregating many
    /// peers) can increase this to reduce the chance of dropped messages;
    /// resource-constrained or low-speed setups (LoRa, serial) can lower
    /// it to save memory.
    event_channel_capacity: usize,

    /// Python-compatible shared instance mode. When enabled, this transport
    /// tries to become the local shared instance and falls back to connecting
    /// to an existing one.
    share_instance: bool,
    require_shared_instance: bool,
    shared_instance_type: SharedInstanceType,
    shared_instance_port: u16,
    instance_control_port: u16,
    instance_name: String,
    rpc_key: Option<Vec<u8>>,
    is_shared_instance: bool,
    is_connected_to_shared_instance: bool,
    is_standalone_instance: bool,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub hops: u8,
    pub snr: Option<f32>,
    pub rssi: Option<i16>,
    pub app_data: PacketDataBuffer,
}

/// Proof-of-delivery receipt with per-packet radio metadata.
/// Created when a proof packet arrives for a tracked pending proof.
#[derive(Clone)]
pub struct PacketReceipt {
    /// Hash of the original data packet that was proven.
    pub packet_hash: Hash,
    /// Destination address the original packet was sent to.
    pub destination: AddressHash,
    /// Signal-to-noise ratio of the received proof packet (RNode only).
    pub snr: Option<f32>,
    /// Received signal strength of the received proof packet (RNode only).
    pub rssi: Option<i16>,
}

struct PendingProof {
    original_packet_hash: Hash,
    destination_address: AddressHash,
    created_at: time::Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedInstanceType {
    Tcp,
    Unix,
}

/// Per-type counters for received packets.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct PacketTypeCounters {
    pub announce: u64,
    pub link_request: u64,
    pub proof: u64,
    pub data: u64,
}

/// Snapshot of transport metrics intended for external collection.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TransportMetrics {
    /// Interface queue depth metrics.
    pub interface_queues: InterfaceQueueLengths,
    /// Number of entries currently known in the path table.
    pub path_table_entries: usize,
    /// Count of received packets by type since transport creation.
    pub packets_received_by_type: PacketTypeCounters,
    /// Number of duplicate inbound packets dropped.
    pub packets_dropped_duplicate: u64,
    /// Number of announces blocked by the rate limiter.
    pub announces_rate_limited: u64,
    /// Number of packets that failed decryption.
    pub decryption_failures: u64,
    /// Number of entries in the announce retransmit table.
    pub announce_table_entries: usize,
    /// Number of entries in the link forwarding table.
    pub link_table_entries: usize,
    /// Number of entries in the reverse path table.
    pub reverse_table_entries: usize,
    /// Number of entries in the duplicate packet cache.
    pub packet_cache_entries: usize,
    /// Number of outbound links currently in Active state.
    pub active_out_links: usize,
    /// Number of inbound links currently in Active state.
    pub active_in_links: usize,
    /// Total number of outbound link entries.
    pub total_out_links: usize,
    /// Total number of inbound link entries.
    pub total_in_links: usize,
    /// Number of non-cancelled interfaces registered with the manager.
    pub active_interfaces: usize,
    /// Number of pending discovery path requests.
    pub pending_path_requests: usize,
    /// Number of entries in the blackhole table.
    pub blackhole_entries: usize,
    /// Total data packets sent across all interfaces.
    pub total_packets_tx: u64,
    /// Total microseconds spent in pacing waits across all interfaces.
    pub total_pacing_wait_us: u64,
}

/// Shared sending context: independently-locked resources used for
/// outbound packet processing.  By factoring these out of
/// `TransportHandler` we allow `Transport::send_packet` and friends to
/// operate without ever acquiring the handler lock.
struct SendCtx {
    path_table: std::sync::RwLock<PathTable>,
    packet_cache: std::sync::Mutex<PacketCache>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
}

impl SendCtx {
    async fn send_packet(&self, name: &str, packet: Packet) {
        let message = {
            let destination = packet.destination;
            let pt = self.path_table.read().unwrap();
            let (packet, maybe_iface) = pt.handle_packet(packet);
            let tx_type = if let Some(iface) = maybe_iface {
                drop(pt);
                self.path_table.write().unwrap().refresh(&destination);
                log::trace!(
                    "tp({name}): outbound packet dst={} ctx={:?} over iface={}",
                    packet.destination,
                    packet.context,
                    iface,
                );
                TxMessageType::Direct(iface)
            } else {
                log::trace!(
                    "tp({name}): outbound broadcast dst={} ctx={:?} type={:?}",
                    packet.destination,
                    packet.context,
                    packet.header.packet_type,
                );
                TxMessageType::Broadcast(None)
            };
            let message = TxMessage { tx_type, packet };
            self.packet_cache.lock().unwrap().update(&message.packet);
            message
        };

        // Compute pacing delay before locking so the sleep does not
        // block the InterfaceManager for other interfaces.
        let wait = {
            let mgr = self.iface_manager.lock().await;
            mgr.send_pacing_delay(&message).await
        };
        if wait > Duration::ZERO {
            time::sleep(wait).await;
        }
        self.iface_manager.lock().await.send_flush(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().unwrap().update(&message.packet);

        let wait = {
            let mgr = self.iface_manager.lock().await;
            mgr.send_pacing_delay(&message).await
        };
        if wait > Duration::ZERO {
            time::sleep(wait).await;
        }
        self.iface_manager.lock().await.send_flush(message).await;
    }

    fn prepare_send_packet(&self, packet: Packet) -> TxMessage {
        let destination = packet.destination;
        let pt = self.path_table.read().unwrap();
        let (packet, maybe_iface) = pt.handle_packet(packet);
        let tx_type = if let Some(iface) = maybe_iface {
            drop(pt);
            self.path_table.write().unwrap().refresh(&destination);
            TxMessageType::Direct(iface)
        } else {
            TxMessageType::Broadcast(None)
        };
        let message = TxMessage { tx_type, packet };
        self.packet_cache.lock().unwrap().update(&message.packet);
        message
    }
}

/// Accumulates outbound messages during packet processing so they can be
/// flushed after the `TransportHandler` lock is released.
struct PendingSends {
    messages: Vec<TxMessage>,
}

impl PendingSends {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    fn push(&mut self, msg: TxMessage) {
        self.messages.push(msg);
    }

    async fn flush(self, send_ctx: &SendCtx) {
        for msg in self.messages {
            send_ctx.send(msg).await;
        }
    }
}

struct TransportHandler {
    config: TransportConfig,
    send_ctx: Arc<SendCtx>,
    announce_tx: broadcast::Sender<AnnounceEvent>,
    discovery_tx: broadcast::Sender<DiscoveredInterface>,

    announce_table: AnnounceTable,
    link_table: LinkTable,
    reverse_table: ReverseTable,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,
    probe_destination: Option<Arc<Mutex<SingleInputDestination>>>,
    discovery_destination: Arc<Mutex<SingleInputDestination>>,
    discoverable_ifaces: HashMap<AddressHash, RegisteredDiscoveryInterface>,

    announce_limits: AnnounceLimits,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,

    path_requests: PathRequests,
    last_path_requests: HashMap<AddressHash, time::Instant>,

    link_in_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,
    receipt_tx: broadcast::Sender<PacketReceipt>,

    pending_proofs: HashMap<AddressHash, PendingProof>,

    fixed_dest_path_requests: AddressHash,

    cancel: CancellationToken,

    /// Packet type counters incremented during inbound processing.
    packets_received_by_type: PacketTypeCounters,
    /// Number of duplicate inbound packets dropped.
    packets_dropped_duplicate: u64,
    /// Number of announces blocked by the rate limiter.
    announces_rate_limited: u64,
    /// Number of packets that failed decryption.
    decryption_failures: u64,

    /// Last received packet SNR/RSSI, updated per-packet from any interface.
    /// Used by the shared-instance RPC to expose radio metrics to peers.
    last_snr: Option<f32>,
    last_rssi: Option<i16>,

    /// Blackholed identity table (protocol-compatible with Python
    /// Reticulum `RNS.Transport.blackholed_identities`).
    blackhole_table: BlackholeTable,
}

#[derive(Clone)]
pub struct Transport {
    name: String,
    discovery_tx: broadcast::Sender<DiscoveredInterface>,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_out_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,
    receipt_tx: broadcast::Sender<PacketReceipt>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    send_ctx: Arc<SendCtx>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity, broadcast: bool) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            broadcast,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            respond_to_probes: false,
            publish_blackhole: false,
            blackhole_sources: vec![],
            blackhole_update_interval: Duration::from_secs(60 * 60),
            link_mtu_discovery: true,
            share_instance: false,
            require_shared_instance: false,
            shared_instance_type: SharedInstanceType::Tcp,
            shared_instance_port: DEFAULT_SHARED_INSTANCE_PORT,
            instance_control_port: DEFAULT_INSTANCE_CONTROL_PORT,
            instance_name: DEFAULT_INSTANCE_NAME.into(),
            rpc_key: None,
            is_shared_instance: false,
            is_connected_to_shared_instance: false,
            is_standalone_instance: true,
            event_channel_capacity: EVENT_CHANNEL_CAPACITY,
        }
    }

    pub fn set_retransmit(&mut self, retransmit: bool) {
        self.retransmit = retransmit;
    }

    pub fn set_broadcast(&mut self, broadcast: bool) {
        self.broadcast = broadcast;
    }

    pub fn set_reroute_eager(&mut self, reroute_eager: bool) {
        self.reroute_eager = reroute_eager;
    }

    pub fn set_restart_outlinks(&mut self, restart_outlinks: bool) {
        self.restart_outlinks = restart_outlinks;
    }

    pub fn set_announce_forever(&mut self, announce_forever: bool) {
        self.announce_forever = announce_forever;
    }

    pub fn set_respond_to_probes(&mut self, respond_to_probes: bool) {
        self.respond_to_probes = respond_to_probes;
    }

    pub fn set_publish_blackhole(&mut self, publish: bool) {
        self.publish_blackhole = publish;
    }

    pub fn publish_blackhole(&self) -> bool {
        self.publish_blackhole
    }

    pub fn set_blackhole_sources(&mut self, sources: Vec<AddressHash>) {
        self.blackhole_sources = sources;
    }

    pub fn blackhole_sources(&self) -> &[AddressHash] {
        &self.blackhole_sources
    }

    pub fn set_blackhole_update_interval(&mut self, interval: Duration) {
        self.blackhole_update_interval = interval;
    }

    pub fn set_link_mtu_discovery(&mut self, link_mtu_discovery: bool) {
        self.link_mtu_discovery = link_mtu_discovery;
    }

    /// Set the capacity of internal broadcast event channels.
    ///
    /// Each event channel (announces, link events, received data, receipts,
    /// raw interface messages) pre-allocates a fixed ring buffer of this
    /// capacity.  Larger values reduce the chance of dropped messages when
    /// application-layer consumers are slow, at the cost of more memory.
    ///
    /// Recommended ranges:
    /// - High-throughput backbone / TCP: 16384–32768
    /// - Moderate-rate WiFi / Ethernet:  4096–8192
    /// - Low-rate LoRa / serial / KISS:  512–1024
    pub fn set_event_channel_capacity(&mut self, capacity: usize) {
        self.event_channel_capacity = capacity;
    }

    pub fn set_share_instance(&mut self, share_instance: bool) {
        self.share_instance = share_instance;
    }

    pub fn share_instance(&self) -> bool {
        self.share_instance
    }

    pub fn set_require_shared_instance(&mut self, require_shared_instance: bool) {
        self.require_shared_instance = require_shared_instance;
    }

    pub fn require_shared_instance(&self) -> bool {
        self.require_shared_instance
    }

    pub fn set_shared_instance_type(&mut self, shared_instance_type: SharedInstanceType) {
        self.shared_instance_type = shared_instance_type;
    }

    pub fn shared_instance_type(&self) -> SharedInstanceType {
        self.shared_instance_type
    }

    pub fn set_shared_instance_port(&mut self, port: u16) {
        self.shared_instance_port = port;
    }

    pub fn shared_instance_port(&self) -> u16 {
        self.shared_instance_port
    }

    pub fn set_instance_control_port(&mut self, port: u16) {
        self.instance_control_port = port;
    }

    pub fn instance_control_port(&self) -> u16 {
        self.instance_control_port
    }

    pub fn set_instance_name<T: Into<String>>(&mut self, name: T) {
        self.instance_name = name.into();
    }

    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }

    pub fn set_rpc_key<T: Into<Vec<u8>>>(&mut self, rpc_key: T) {
        self.rpc_key = Some(rpc_key.into());
    }

    pub fn set_rpc_key_hex(&mut self, rpc_key: &str) -> Result<(), RnsError> {
        self.rpc_key = Some(Self::parse_rpc_key_hex(rpc_key)?);
        Ok(())
    }

    pub fn rpc_key(&self) -> Option<&[u8]> {
        self.rpc_key.as_deref()
    }

    fn parse_rpc_key_hex(rpc_key: &str) -> Result<Vec<u8>, RnsError> {
        let hex = rpc_key
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();

        if hex.len() % 2 != 0 {
            return Err(RnsError::InvalidArgument);
        }

        hex.chunks_exact(2)
            .map(|chunk| {
                let high = Self::hex_nibble(chunk[0])?;
                let low = Self::hex_nibble(chunk[1])?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    fn hex_nibble(byte: u8) -> Result<u8, RnsError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(RnsError::InvalidArgument),
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            broadcast: false,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            respond_to_probes: false,
            publish_blackhole: false,
            blackhole_sources: vec![],
            blackhole_update_interval: Duration::from_secs(60 * 60),
            link_mtu_discovery: true,
            share_instance: false,
            require_shared_instance: false,
            shared_instance_type: SharedInstanceType::Tcp,
            shared_instance_port: DEFAULT_SHARED_INSTANCE_PORT,
            instance_control_port: DEFAULT_INSTANCE_CONTROL_PORT,
            instance_name: DEFAULT_INSTANCE_NAME.into(),
            rpc_key: None,
            is_shared_instance: false,
            is_connected_to_shared_instance: false,
            is_standalone_instance: true,
            event_channel_capacity: EVENT_CHANNEL_CAPACITY,
        }
    }
}

impl Transport {
    pub fn new(mut config: TransportConfig) -> Self {
        let cap = config.event_channel_capacity;
        let (announce_tx, _) = tokio::sync::broadcast::channel(cap);
        let (discovery_tx, _) = tokio::sync::broadcast::channel(cap);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(cap);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(cap);
        let (received_data_tx, _) = tokio::sync::broadcast::channel(cap);
        let (receipt_tx, _) = tokio::sync::broadcast::channel(cap);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(cap);

        let iface_manager = InterfaceManager::new(config.event_channel_capacity / 2);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));
        let cancel = CancellationToken::new();
        start_shared_instance(&mut config, iface_manager.clone(), cancel.clone());

        let start_shared_rpc = config.is_shared_instance
            && matches!(config.shared_instance_type, SharedInstanceType::Tcp);
        let rpc_name = config.name.clone();
        let rpc_port = config.instance_control_port;
        let rpc_key = config.rpc_key.clone();

        let transport_id = if config.retransmit {
            Some(config.identity.address_hash().clone())
        } else {
            None
        };
        let path_requests = PathRequests::new(config.name.as_str(), transport_id);

        let path_request_dest = create_path_request_destination().desc.address_hash;
        let discovery_destination = Arc::new(Mutex::new(create_discovery_destination(
            config.identity.clone(),
        )));
        let probe_destination = if config.respond_to_probes {
            let mut destination = SingleInputDestination::new(
                config.identity.clone(),
                DestinationName::new("rnstransport", "probe"),
            );
            destination.set_accept_link_requests(false);
            destination.set_prove_packets(true);
            let address_hash = destination.desc.address_hash;

            let destination = Arc::new(Mutex::new(destination));
            log::info!(
                "tp({}): enabled probe responder at {}",
                config.name,
                address_hash
            );
            Some((address_hash, destination))
        } else {
            None
        };
        let mut single_in_destinations = HashMap::new();
        let probe_destination = probe_destination.map(|(address_hash, destination)| {
            single_in_destinations.insert(address_hash, destination.clone());
            // Register local destination so interface-mode filtering
            // exempts it (matching Python's local_destination check).
            let cloned = iface_manager.clone();
            let hash = address_hash;
            tokio::task::spawn(async move {
                cloned.lock().await.add_local_destination(hash);
            });
            address_hash
        });
        let probe_destination = probe_destination
            .and_then(|address_hash| single_in_destinations.get(&address_hash).cloned());

        let name = config.name.clone();
        let has_blackhole_sources = !config.blackhole_sources.is_empty();
        let blackhole_sources = config.blackhole_sources.clone();
        let blackhole_update_interval = config.blackhole_update_interval;
        let send_ctx = Arc::new(SendCtx {
            path_table: std::sync::RwLock::new(PathTable::new(config.reroute_eager)),
            packet_cache: std::sync::Mutex::new(PacketCache::new()),
            iface_manager: iface_manager.clone(),
        });
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            send_ctx: send_ctx.clone(),
            announce_table: AnnounceTable::new(),
            link_table: LinkTable::new(),
            reverse_table: ReverseTable::new(),
            single_in_destinations,
            single_out_destinations: HashMap::new(),
            probe_destination,
            discovery_destination,
            discoverable_ifaces: HashMap::new(),
            announce_limits: AnnounceLimits::new(),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            path_requests,
            last_path_requests: HashMap::new(),
            announce_tx,
            discovery_tx: discovery_tx.clone(),
            link_in_event_tx: link_in_event_tx.clone(),
            received_data_tx: received_data_tx.clone(),
            receipt_tx: receipt_tx.clone(),
            pending_proofs: HashMap::new(),
            last_snr: None,
            last_rssi: None,
            fixed_dest_path_requests: path_request_dest,
            cancel: cancel.clone(),
            packets_received_by_type: PacketTypeCounters::default(),
            packets_dropped_duplicate: 0,
            announces_rate_limited: 0,
            decryption_failures: 0,
            blackhole_table: BlackholeTable::new(),
        }));

        {
            let handler = handler.clone();
            let send_ctx = send_ctx.clone();
            tokio::spawn(manage_transport(
                handler,
                send_ctx,
                rx_receiver,
                iface_messages_tx.clone(),
            ))
        };

        if start_shared_rpc {
            start_tcp_shared_rpc(rpc_name, rpc_port, rpc_key, handler.clone(), cancel.clone());
        }

        if has_blackhole_sources {
            log::info!(
                "tp({name}): starting blackhole updater with {} source(s)",
                blackhole_sources.len(),
            );
            let updater_handler = handler.clone();
            let updater_send_ctx = send_ctx.clone();
            let updater_iface_manager = iface_manager.clone();
            let updater_event_tx = link_out_event_tx.clone();
            let updater_name = name.clone();
            let updater_cancel = cancel.clone();
            tokio::spawn(blackhole_updater_job(
                updater_handler,
                updater_send_ctx,
                updater_iface_manager,
                updater_event_tx,
                updater_name,
                blackhole_update_interval,
                updater_cancel,
            ));
        }

        Self {
            name,
            discovery_tx,
            iface_manager,
            link_in_event_tx,
            link_out_event_tx,
            received_data_tx,
            receipt_tx,
            iface_messages_tx,
            handler,
            send_ctx,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        self.send_ctx.send_packet(&self.name, packet.clone()).await;
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    pub async fn interface_queue_lengths(&self) -> InterfaceQueueLengths {
        self.iface_manager.lock().await.queue_lengths().await
    }

    /// Returns the current number of path table entries.
    pub async fn path_table_len(&self) -> usize {
        self.send_ctx.path_table.read().unwrap().len()
    }

    /// Blackhole an identity.  Once blackholed, all announces from this
    /// identity will be ignored and any existing paths to its destinations
    /// will be removed.
    ///
    /// Protocol-compatible with Python `RNS.Transport.blackhole_identity()`.
    pub async fn blackhole_identity(
        &self,
        identity_hash: &AddressHash,
        until: Option<time::Instant>,
        reason: Option<String>,
    ) -> bool {
        let mut handler = self.handler.lock().await;
        let source = *handler.config.identity.address_hash();
        let added = handler
            .blackhole_table
            .add(*identity_hash, source, until, reason);
        let removed = handler.remove_blackholed_paths();
        log::info!(
            "tp({}): blackholed identity {}, removed {} path{}",
            handler.config.name,
            identity_hash,
            removed,
            if removed == 1 { "" } else { "s" },
        );
        added
    }

    /// Lift the blackhole for an identity.
    ///
    /// Protocol-compatible with Python `RNS.Transport.unblackhole_identity()`.
    pub async fn unblackhole_identity(&self, identity_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let removed = handler.blackhole_table.remove(identity_hash);
        if removed {
            log::info!(
                "tp({}): lifted blackhole for identity {}",
                handler.config.name,
                identity_hash,
            );
        }
        removed
    }

    /// Reload blackhole entries (persistence not yet implemented;
    /// this is a no-op stub for API compatibility).
    pub async fn reload_blackhole(&self) {
        log::warn!(
            "tp({}): blackhole persistence not yet implemented",
            self.name,
        );
    }

    /// Returns a metrics snapshot for transport-level collectors.
    pub async fn metrics(&self) -> TransportMetrics {
        let path_table_entries = self.path_table_len().await;
        let interface_queues = self.interface_queue_lengths().await;
        let packet_cache_entries = self.send_ctx.packet_cache.lock().unwrap().len();

        let handler = self.handler.lock().await;

        let mut active_out_links: usize = 0;
        let mut active_in_links: usize = 0;
        for link in handler.out_links.values() {
            if link.lock().await.status() == LinkStatus::Active {
                active_out_links += 1;
            }
        }
        for link in handler.in_links.values() {
            if link.lock().await.status() == LinkStatus::Active {
                active_in_links += 1;
            }
        }

        let active_interfaces = self
            .iface_manager
            .lock()
            .await
            .active_interface_addresses()
            .len();

        let total_packets_tx = interface_queues.interfaces.iter().map(|i| i.packets_tx).sum();
        let total_pacing_wait_us = interface_queues.interfaces.iter().map(|i| i.pacing_wait_us).sum();

        TransportMetrics {
            interface_queues,
            path_table_entries,
            packets_received_by_type: handler.packets_received_by_type,
            packets_dropped_duplicate: handler.packets_dropped_duplicate,
            announces_rate_limited: handler.announces_rate_limited,
            decryption_failures: handler.decryption_failures,
            announce_table_entries: handler.announce_table.entries_len(),
            link_table_entries: handler.link_table.len(),
            reverse_table_entries: handler.reverse_table.len(),
            packet_cache_entries,
            active_out_links,
            active_in_links,
            total_out_links: handler.out_links.len(),
            total_in_links: handler.in_links.len(),
            active_interfaces,
            pending_path_requests: handler.path_requests.pending_discovery_len(),
            blackhole_entries: handler.blackhole_table.len(),
            total_packets_tx,
            total_pacing_wait_us,
        }
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    pub fn recv_receipts(&self) -> broadcast::Receiver<PacketReceipt> {
        self.receipt_tx.subscribe()
    }

    pub fn recv_discovery(&self) -> broadcast::Receiver<DiscoveredInterface> {
        self.discovery_tx.subscribe()
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.send_ctx.send_packet(&self.name, packet).await;
    }

    /// Track a pending proof for a sent data packet.
    /// When the corresponding proof packet arrives, a `PacketReceipt`
    /// (with RSSI/SNR if available) will be sent on the receipt channel.
    ///
    /// For link data packets sent via `send_to_out_links`, this is called
    /// automatically. For direct data packets, call this manually after sending.
    pub async fn track_pending_proof(&self, packet_hash: Hash, destination: AddressHash) {
        let proof_dest = AddressHash::new_from_hash(&packet_hash);
        let mut handler = self.handler.lock().await;
        handler.pending_proofs.insert(
            proof_dest,
            PendingProof {
                original_packet_hash: packet_hash,
                destination_address: destination,
                created_at: time::Instant::now(),
            },
        );
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.send_ctx
            .send_packet(
                &self.name,
                destination
                    .lock()
                    .await
                    .announce(OsRng, app_data)
                    .expect("valid announce packet"),
            )
            .await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.send_ctx
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet,
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.send_ctx
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet,
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let links = {
            let handler = self.handler.lock().await;
            handler.out_links.values().cloned().collect::<Vec<_>>()
        };
        for link in links {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    drop(link);
                    self.send_ctx.send_packet(&self.name, packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) -> Vec<Hash> {
        let mut sent_packets = vec![];
        let links = {
            let handler = self.handler.lock().await;
            handler.out_links.values().cloned().collect::<Vec<_>>()
        };
        for link in links {
            let link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    let packet_hash = packet.hash();
                    let link_id = link.id().clone();
                    drop(link);
                    self.send_ctx.send_packet(&self.name, packet).await;
                    // Track as pending proof (proof destination = link id)
                    let mut handler = self.handler.lock().await;
                    handler.pending_proofs.insert(
                        link_id,
                        PendingProof {
                            original_packet_hash: packet_hash,
                            destination_address: *destination,
                            created_at: time::Instant::now(),
                        },
                    );
                    sent_packets.push(packet_hash);
                }
            }
        }

        if sent_packets.len() == 0 {
            log::trace!(
                "tp({}): no output links for {} destination",
                self.name,
                destination
            );
        }

        sent_packets
    }

    pub async fn send_to_in_links(&self, destination: &AddressHash, payload: &[u8]) {
        let links = {
            let handler = self.handler.lock().await;
            handler.in_links.values().cloned().collect::<Vec<_>>()
        };
        let mut count = 0usize;
        for link in links {
            let link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    drop(link);
                    self.send_ctx.send_packet(&self.name, packet).await;
                    count += 1;
                }
            }
        }

        if count == 0 {
            log::trace!(
                "tp({}): no input links for {} destination",
                self.name,
                destination
            );
        }
    }

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        let links = {
            let handler = self.handler.lock().await;
            handler.out_links.values().cloned().collect::<Vec<_>>()
        };

        for link in links {
            if *link.lock().await.id() == *link_id {
                return Some(link);
            }
        }

        None
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.in_links.get(link_id).cloned()
    }

    pub async fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        let link = self
            .handler
            .lock()
            .await
            .out_links
            .get(&destination.address_hash)
            .cloned();

        if let Some(link) = link {
            if link.lock().await.status() != LinkStatus::Closed {
                return link;
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        // Query the path table for the next-hop interface, then look up its
        // HW_MTU so the link initiator can signal the path capacity.
        let path_mtu = {
            if self.handler.lock().await.config.link_mtu_discovery {
                let iface_addr = self
                    .send_ctx
                    .path_table
                    .read()
                    .unwrap()
                    .next_hop_iface(&destination.address_hash);
                if let Some(iface) = iface_addr {
                    self.iface_manager.lock().await.hw_mtu(&iface)
                } else {
                    None
                }
            } else {
                None
            }
        };

        let mut link = Link::new(destination, self.link_out_event_tx.clone());

        let packet = link.request(path_mtu);

        log::debug!(
            "tp({}): create new link {} for destination {} path_mtu={:?}",
            self.name,
            link.id(),
            destination,
            path_mtu
        );

        let link = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        self.handler
            .lock()
            .await
            .out_links
            .insert(destination.address_hash, link.clone());

        link
    }

    pub async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        let link = if let Some(link) = self.find_in_link(&link_id).await {
            Some(link)
        } else {
            self.find_out_link(&link_id).await
        };
        if let Some(link) = link {
            let mut link = link.lock().await;
            if let Some(packet) = link.teardown()? {
                drop(link);
                self.send_packet(packet).await
            }
        } else {
            log::warn!("tp({}): close link {link_id} not found", self.name)
        }
        Ok(())
    }

    pub async fn link_identify(
        &self,
        link_id: LinkId,
        identity: &PrivateIdentity,
    ) -> Result<(), RnsError> {
        let link = self
            .find_link(&link_id)
            .await
            .ok_or(RnsError::InvalidArgument)?;
        let packet = link.lock().await.identify_packet(identity)?;
        self.send_packet(packet).await;
        Ok(())
    }

    pub async fn link_request(
        &self,
        link_id: LinkId,
        path: &str,
        data: Value,
    ) -> Result<AddressHash, RnsError> {
        let link = self
            .find_link(&link_id)
            .await
            .ok_or(RnsError::InvalidArgument)?;
        let packet = link.lock().await.request_packet(path, data)?;
        let request_id = AddressHash::new_from_hash(&packet.hash());
        self.send_packet(packet).await;
        Ok(request_id)
    }

    pub async fn link_response(
        &self,
        link_id: LinkId,
        request_id: AddressHash,
        data: Value,
    ) -> Result<(), RnsError> {
        let link = self
            .find_link(&link_id)
            .await
            .ok_or(RnsError::InvalidArgument)?;
        let packet = link.lock().await.response_packet(request_id, data)?;
        self.send_packet(packet).await;
        Ok(())
    }

    async fn find_link(&self, link_id: &LinkId) -> Option<Arc<Mutex<Link>>> {
        if let Some(link) = self.find_in_link(link_id).await {
            Some(link)
        } else {
            self.find_out_link(link_id).await
        }
    }

    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        let mut pending = PendingSends::new();
        {
            let mut h = self.handler.lock().await;
            h.request_path(destination, &mut pending, on_iface, tag).await;
        }
        pending.flush(&self.send_ctx).await;
    }

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.subscribe()
    }

    pub fn received_data_events(&self) -> broadcast::Receiver<ReceivedData> {
        self.received_data_tx.subscribe()
    }

    pub async fn add_destination(
        &mut self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        let destination = SingleInputDestination::new(identity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    pub async fn get_in_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.handler
            .lock()
            .await
            .single_in_destinations
            .get(address)
            .cloned()
    }

    pub async fn probe_destination(&self) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.handler.lock().await.probe_destination.clone()
    }

    pub async fn is_shared_instance(&self) -> bool {
        self.handler.lock().await.config.is_shared_instance
    }

    pub async fn is_connected_to_shared_instance(&self) -> bool {
        self.handler
            .lock()
            .await
            .config
            .is_connected_to_shared_instance
    }

    pub async fn is_standalone_instance(&self) -> bool {
        self.handler.lock().await.config.is_standalone_instance
    }

    pub async fn register_discoverable_interface(
        &self,
        iface: AddressHash,
        config: DiscoveryInterfaceConfig,
    ) {
        self.handler
            .lock()
            .await
            .discoverable_ifaces
            .insert(iface, RegisteredDiscoveryInterface::new(config));
    }

    pub async fn unregister_discoverable_interface(&self, iface: &AddressHash) {
        self.handler.lock().await.discoverable_ifaces.remove(iface);
    }

    pub async fn send_discovery_announce(&self, iface: &AddressHash) -> Result<(), RnsError> {
        let packet = {
            let mut handler = self.handler.lock().await;
            handler.build_discovery_packet(iface).await?
        };

        self.send_ctx.send_packet(&self.name, packet).await;
        Ok(())
    }

    pub async fn get_out_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleOutputDestination>>> {
        self.handler
            .lock()
            .await
            .single_out_destinations
            .get(address)
            .cloned()
    }

    pub async fn has_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.has_destination(address)
    }

    pub async fn knows_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.knows_destination(address)
    }

    pub fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
        // direct access to handler for testing purposes
        self.handler.clone()
    }
}

fn start_shared_instance(
    config: &mut TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
) {
    config.is_shared_instance = false;
    config.is_connected_to_shared_instance = false;
    config.is_standalone_instance = false;

    if !config.share_instance {
        config.is_standalone_instance = true;
        return;
    }

    if config.rpc_key.is_none() {
        config.rpc_key = Some(config.identity.shared_instance_rpc_key());
    }

    match config.shared_instance_type {
        SharedInstanceType::Tcp => start_tcp_shared_instance(config, iface_manager, cancel),
        SharedInstanceType::Unix => {
            log::warn!(
                "tp({}): shared_instance_type=unix is not implemented; running standalone",
                config.name
            );
            config.is_standalone_instance = true;
        }
    }
}

fn start_tcp_shared_instance(
    config: &mut TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
) {
    let addr = format!("127.0.0.1:{}", config.shared_instance_port);

    match StdTcpListener::bind(&addr) {
        Ok(listener) => {
            if config.require_shared_instance {
                panic!("No shared instance available, but application required it");
            }

            config.is_shared_instance = true;
            start_tcp_shared_data_listener(
                config.name.clone(),
                addr.clone(),
                listener,
                iface_manager,
                cancel.clone(),
            );
            log::debug!("tp({}): started shared instance on {}", config.name, addr);
        }
        Err(error) => {
            log::trace!(
                "share_instance: tp({}) connecting local client to <{}>",
                config.name,
                addr
            );
            let iface_manager_for_task = iface_manager.clone();
            let client = TcpClient::new(addr.clone());
            tokio::spawn(async move {
                iface_manager_for_task
                    .lock()
                    .await
                    .spawn(client, TcpClient::spawn);
            });

            config.is_connected_to_shared_instance = true;
            config.retransmit = false;
            config.respond_to_probes = false;
            log::debug!(
                "tp({}): connected to shared instance on {} after bind failed: {}",
                config.name,
                addr,
                error
            );
        }
    }
}

fn start_tcp_shared_data_listener(
    name: String,
    addr: String,
    listener: StdTcpListener,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let listener = match listener
            .set_nonblocking(true)
            .map(|_| listener)
            .map_err(|error| error.to_string())
            .and_then(|listener| TcpListener::from_std(listener).map_err(|error| error.to_string()))
        {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    "share_instance: tp({}) could not start data listener <{}>: {}",
                    name,
                    addr,
                    error
                );
                return;
            }
        };

        log::debug!(
            "share_instance: tp({}) listening for data clients on <{}>",
            name,
            addr
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    break;
                }
                client = listener.accept() => {
                    match client {
                        Ok((stream, remote)) => {
                            log::trace!(
                                "share_instance: client <{}> connected to <{}>",
                                remote,
                                addr
                            );
                            let iface_manager = iface_manager.clone();
                            tokio::spawn(async move {
                                handle_shared_data_client(stream, remote.to_string(), iface_manager).await;
                            });
                        }
                        Err(error) => {
                            log::warn!(
                                "share_instance: error accepting data client on <{}>: {}",
                                addr,
                                error
                            );
                        }
                    }
                }
            }
        }
    });
}

async fn handle_shared_data_client(
    stream: TcpStream,
    remote: String,
    iface_manager: Arc<Mutex<InterfaceManager>>,
) {
    iface_manager
        .lock()
        .await
        .spawn_shared_instance_client(TcpClient::new_from_stream(remote, stream), TcpClient::spawn);
}

fn start_tcp_shared_rpc(
    name: String,
    port: u16,
    auth_key: Option<Vec<u8>>,
    handler: Arc<Mutex<TransportHandler>>,
    cancel: CancellationToken,
) {
    let addr = format!("127.0.0.1:{}", port);
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    "share_instance: tp({}) could not bind RPC control listener <{}>: {}",
                    name,
                    addr,
                    error
                );
                return;
            }
        };

        log::debug!(
            "share_instance: tp({}) listening for RPC control clients on <{}>",
            name,
            addr
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    break;
                }
                client = listener.accept() => {
                    match client {
                        Ok((stream, remote)) => {
                            log::trace!(
                                "share_instance: RPC client <{}> connected to <{}>",
                                remote,
                                addr
                            );
                            let auth_key = auth_key.clone();
                            let handler = handler.clone();
                            tokio::spawn(async move {
                                if let Err(error) =
                                    handle_shared_rpc_client(stream, auth_key.as_deref(), handler)
                                        .await
                                {
                                    log::warn!(
                                        "share_instance: RPC client <{}> failed: {}",
                                        remote,
                                        error
                                    );
                                }
                            });
                        }
                        Err(error) => {
                            log::warn!(
                                "share_instance: error accepting RPC control client on <{}>: {}",
                                addr,
                                error
                            );
                        }
                    }
                }
            }
        }
    });
}

async fn handle_shared_rpc_client(
    mut stream: TcpStream,
    auth_key: Option<&[u8]>,
    handler: Arc<Mutex<TransportHandler>>,
) -> Result<(), String> {
    shared_rpc_authenticate(&mut stream, auth_key).await?;

    let request = read_py_connection_frame(&mut stream, 64 * 1024).await?;
    let request = read_shared_rpc_value(&request)?;

    let response = if let Some(map) = request.as_map() {
        if shared_rpc_map_str(map, "get") == Some("request_path") {
            handle_shared_rpc_request_path(map, handler).await
        } else {
            let mut h = handler.lock().await;
            handle_shared_rpc_request(&request, Some(&mut h))
        }
    } else {
        let mut h = handler.lock().await;
        handle_shared_rpc_request(&request, Some(&mut h))
    };

    let encoded = write_shared_rpc_value(&response)?;
    write_py_connection_frame(&mut stream, &encoded).await
}

async fn handle_shared_rpc_request_path(
    map: &[(Value, Value)],
    handler: Arc<Mutex<TransportHandler>>,
) -> Value {
    let Some(dest_bytes) = shared_rpc_map_value(map, "destination_hash").and_then(|v| v.as_slice())
    else {
        return Value::Boolean(false);
    };
    if dest_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return Value::Boolean(false);
    }

    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(&dest_bytes[..crate::hash::ADDRESS_HASH_SIZE]);
    let address_hash = AddressHash::new(hash);

    log::trace!(
        "tp(shared_instance): RPC request_path destination_hash={:02x?}",
        hash,
    );

    {
        // RPC handlers are called infrequently; send directly.
        let mut h = handler.lock().await;
        let packet = h.path_requests.generate(&address_hash, None);
        h.send_ctx
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet,
            })
            .await;
        h.last_path_requests.insert(address_hash, time::Instant::now());
    }

    let timeout = Duration::from_secs(DEFAULT_PER_HOP_TIMEOUT_SECS * 3);
    let start = time::Instant::now();

    loop {
        if time::Instant::now().duration_since(start) >= timeout {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let h = handler.lock().await;
        let path_table = h.send_ctx.path_table.read().unwrap();
        if let Some(entry) = path_table.get(&address_hash) {
            return Value::Map(vec![
                (Value::from("found"), Value::from(true)),
                (Value::from("hops"), Value::from(entry.hops as u64)),
                (
                    Value::from("next_hop"),
                    Value::Binary(entry.received_from.as_slice().to_vec()),
                ),
                (
                    Value::from("interface"),
                    Value::Binary(entry.iface.as_slice().to_vec()),
                ),
            ]);
        }
    }

    Value::Map(vec![(Value::from("found"), Value::from(false))])
}

async fn shared_rpc_authenticate(
    stream: &mut TcpStream,
    auth_key: Option<&[u8]>,
) -> Result<(), String> {
    let challenge = shared_rpc_challenge();
    write_py_connection_frame(stream, &challenge).await?;

    let response = read_py_connection_frame(stream, 256).await?;
    let authenticated = shared_rpc_response_is_authenticated(&challenge, &response, auth_key)?;

    if authenticated {
        write_py_connection_frame(stream, PY_CONN_WELCOME).await?;
        shared_rpc_answer_peer_challenge(stream, auth_key).await
    } else {
        let _ = write_py_connection_frame(stream, PY_CONN_FAILURE).await;
        Err("authentication failed".into())
    }
}

fn shared_rpc_challenge() -> Vec<u8> {
    let mut random = [0u8; 40];
    OsRng.fill_bytes(&mut random);

    let mut challenge = Vec::with_capacity(PY_CONN_CHALLENGE.len() + 8 + random.len());
    challenge.extend_from_slice(PY_CONN_CHALLENGE);
    challenge.extend_from_slice(b"{sha256}");
    challenge.extend_from_slice(&random);
    challenge
}

fn shared_rpc_response_is_authenticated(
    challenge: &[u8],
    response: &[u8],
    auth_key: Option<&[u8]>,
) -> Result<bool, String> {
    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    if let Some(auth_key) = auth_key {
        let expected = shared_rpc_hmac_response(auth_key, message)?;
        let expected_raw = &expected[b"{sha256}".len()..];
        Ok(response == expected.as_slice() || response == expected_raw)
    } else {
        Ok(true)
    }
}

async fn shared_rpc_answer_peer_challenge(
    stream: &mut TcpStream,
    auth_key: Option<&[u8]>,
) -> Result<(), String> {
    let Some(peer_challenge) = read_py_connection_frame_if_ready(
        stream,
        PY_CONN_AUTH_MAX_FRAME,
        PY_CONN_MUTUAL_AUTH_TIMEOUT,
    )
    .await?
    else {
        return Ok(());
    };

    if !peer_challenge.starts_with(PY_CONN_CHALLENGE) {
        return Err(format!(
            "expected peer challenge, got {} bytes starting with {:02x}",
            peer_challenge.len(),
            peer_challenge.first().copied().unwrap_or_default()
        ));
    }

    let auth_key = auth_key.ok_or_else(|| {
        "peer requested mutual authentication, but no shared_instance rpc_key is configured"
            .to_string()
    })?;
    let response = shared_rpc_hmac_response(auth_key, &peer_challenge[PY_CONN_CHALLENGE.len()..])?;
    write_py_connection_frame(stream, &response).await?;

    let welcome = read_py_connection_frame(stream, PY_CONN_AUTH_MAX_FRAME).await?;
    if welcome == PY_CONN_WELCOME {
        Ok(())
    } else if welcome == PY_CONN_FAILURE {
        Err("peer rejected mutual authentication digest".into())
    } else {
        Err(format!(
            "expected mutual authentication welcome, got {} bytes",
            welcome.len()
        ))
    }
}

fn shared_rpc_hmac_response(auth_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).map_err(|error| error.to_string())?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    let mut response = Vec::with_capacity(b"{sha256}".len() + digest.len());
    response.extend_from_slice(b"{sha256}");
    response.extend_from_slice(&digest);
    Ok(response)
}

fn handle_shared_rpc_request(request: &Value, mut handler: Option<&mut TransportHandler>) -> Value {
    let Some(map) = request.as_map() else {
        return Value::Boolean(false);
    };

    if let Some(operation) = shared_rpc_map_str(map, "get") {
        return match operation {
            "path_table" => shared_rpc_path_table(handler.as_deref_mut()),
            "rate_table" => shared_rpc_rate_table(handler.as_deref_mut()),
            "interface_stats" => shared_rpc_interface_stats(),
            "next_hop_if_name" => shared_rpc_next_hop_if_name(map, handler.as_deref()),
            "next_hop" => shared_rpc_next_hop(map, handler.as_deref()),
            "packet_snr" => handler
                .and_then(|h| h.last_snr)
                .map(Value::from)
                .unwrap_or(Value::Nil),
            "packet_rssi" => handler
                .and_then(|h| h.last_rssi)
                .map(|v| Value::from(v as i64))
                .unwrap_or(Value::Nil),
            "packet_q" => Value::Nil,
            "first_hop_timeout" => Value::from(DEFAULT_PER_HOP_TIMEOUT_SECS),
            "link_count" => Value::from(0),
            "blackholed_identities" => shared_rpc_blackholed_identities(handler.as_deref_mut()),
            "is_blackholed" => shared_rpc_is_blackholed(map, handler.as_deref_mut()),
            _ => {
                log::warn!(
                    "share_instance: unsupported RPC get operation <{}>",
                    operation
                );
                Value::Boolean(false)
            }
        };
    }

    if let Some(operation) = shared_rpc_map_str(map, "drop") {
        return match operation {
            "path" => shared_rpc_drop_path(map, handler.as_deref_mut()),
            "all_via" => shared_rpc_drop_all_via(map, handler.as_deref_mut()),
            "announce_queues" => shared_rpc_drop_announce_queues(handler.as_deref_mut()),
            _ => {
                log::warn!(
                    "share_instance: unsupported RPC drop operation <{}>",
                    operation
                );
                Value::Boolean(false)
            }
        };
    }

    if let Some(identity_bytes) =
        shared_rpc_map_value(map, "blackhole_identity").and_then(|v| v.as_slice())
    {
        return shared_rpc_blackhole_identity(identity_bytes, map, handler.as_deref_mut());
    }

    if let Some(identity_bytes) =
        shared_rpc_map_value(map, "unblackhole_identity").and_then(|v| v.as_slice())
    {
        return shared_rpc_unblackhole_identity(identity_bytes, handler.as_deref_mut());
    }

    if shared_rpc_map_value(map, "destination_data").is_some()
        || shared_rpc_map_value(map, "identity_data").is_some()
    {
        return Value::Boolean(false);
    }

    log::warn!("share_instance: unsupported RPC request {:?}", request);
    Value::Boolean(false)
}

fn shared_rpc_path_table(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Array(vec![]);
    };
    let path_table = handler.send_ctx.path_table.read().unwrap();
    let now = std::time::Instant::now();
    let entries: Vec<Value> = path_table
        .entries()
        .map(|(hash, entry)| {
            let expires_secs = if entry.expires > now {
                (entry.expires - now).as_secs_f64()
            } else {
                0.0
            };
            Value::Map(vec![
                (Value::from("hash"), Value::Binary(hash.as_slice().to_vec())),
                (Value::from("hops"), Value::from(entry.hops as u64)),
                (
                    Value::from("via"),
                    Value::Binary(entry.received_from.as_slice().to_vec()),
                ),
                (
                    Value::from("interface"),
                    Value::Binary(entry.iface.as_slice().to_vec()),
                ),
                (Value::from("expires"), Value::from(expires_secs)),
            ])
        })
        .collect();
    Value::Array(entries)
}

fn shared_rpc_rate_table(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Array(vec![]);
    };
    let tok_now = time::Instant::now();
    let entries: Vec<Value> = handler
        .announce_limits
        .entries()
        .map(|(hash, entry)| {
            let last_secs = if tok_now > entry.last_announce {
                (tok_now - entry.last_announce).as_secs_f64()
            } else {
                0.0
            };
            let blocked_secs = if entry.blocked_until > tok_now {
                (entry.blocked_until - tok_now).as_secs_f64()
            } else {
                0.0
            };
            Value::Map(vec![
                (Value::from("hash"), Value::Binary(hash.as_slice().to_vec())),
                (Value::from("last"), Value::from(last_secs)),
                (
                    Value::from("rate_violations"),
                    Value::from(entry.violations as u64),
                ),
                (Value::from("blocked_until"), Value::from(blocked_secs)),
            ])
        })
        .collect();
    Value::Array(entries)
}

fn shared_rpc_blackholed_identities(handler: Option<&mut TransportHandler>) -> Value {
    match handler {
        Some(handler) => handler.blackhole_table.to_msgpack(),
        None => Value::Map(vec![]),
    }
}

fn shared_rpc_is_blackholed(
    map: &[(Value, Value)],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    if let Some(identity_bytes) =
        shared_rpc_map_value(map, "identity_hash").and_then(|v| v.as_slice())
    {
        let identity_hash = AddressHash::new_from_slice(identity_bytes);
        Value::Boolean(handler.blackhole_table.contains(&identity_hash))
    } else {
        Value::Boolean(false)
    }
}

fn shared_rpc_drop_path(map: &[(Value, Value)], handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    let Some(destination) = shared_rpc_destination_hash(map) else {
        return Value::Boolean(false);
    };
    let removed = handler
        .send_ctx
        .path_table
        .write()
        .unwrap()
        .remove(&destination);
    Value::Boolean(removed)
}

fn shared_rpc_drop_all_via(
    map: &[(Value, Value)],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::from(0);
    };
    let Some(via) = shared_rpc_destination_hash(map) else {
        return Value::from(0);
    };
    let count = handler
        .send_ctx
        .path_table
        .write()
        .unwrap()
        .drop_all_via(&via);
    Value::from(count as u64)
}

fn shared_rpc_drop_announce_queues(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::from(0);
    };
    handler.announce_table.clear();
    Value::from(0)
}

fn shared_rpc_blackhole_identity(
    identity_bytes: &[u8],
    map: &[(Value, Value)],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    if identity_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return Value::Boolean(false);
    }
    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(identity_bytes);
    let identity_hash = AddressHash::new(hash);

    let until = shared_rpc_map_value(map, "duration")
        .and_then(|v| v.as_f64())
        .map(|secs| time::Instant::now() + time::Duration::from_secs_f64(secs));
    let reason = shared_rpc_map_value(map, "reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    let source = *handler.config.identity.address_hash();
    let added = handler
        .blackhole_table
        .add(identity_hash, source, until, reason);
    let removed = handler.remove_blackholed_paths();
    log::info!(
        "share_instance: blackholed identity {}, removed {} path{}",
        identity_hash,
        removed,
        if removed == 1 { "" } else { "s" },
    );
    Value::Boolean(added)
}

fn shared_rpc_unblackhole_identity(
    identity_bytes: &[u8],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    if identity_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return Value::Boolean(false);
    }
    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(identity_bytes);
    let identity_hash = AddressHash::new(hash);
    let removed = handler.blackhole_table.remove(&identity_hash);
    if removed {
        log::info!(
            "share_instance: lifted blackhole for identity {}",
            identity_hash,
        );
    }
    Value::Boolean(removed)
}

fn shared_rpc_next_hop(map: &[(Value, Value)], handler: Option<&TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Nil;
    };
    let Some(destination) = shared_rpc_destination_hash(map) else {
        return Value::Nil;
    };

    handler
        .send_ctx
        .path_table
        .read()
        .unwrap()
        .next_hop(&destination)
        .map(|next_hop| Value::Binary(next_hop.as_slice().to_vec()))
        .unwrap_or(Value::Nil)
}

fn shared_rpc_next_hop_if_name(
    map: &[(Value, Value)],
    handler: Option<&TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::from("None");
    };
    let Some(destination) = shared_rpc_destination_hash(map) else {
        return Value::from("None");
    };

    handler
        .send_ctx
        .path_table
        .read()
        .unwrap()
        .next_hop_iface(&destination)
        .map(|iface| iface.to_string())
        .map(Value::from)
        .unwrap_or_else(|| Value::from("None"))
}

fn shared_rpc_destination_hash(map: &[(Value, Value)]) -> Option<AddressHash> {
    let value = shared_rpc_map_value(map, "destination_hash")?;
    let bytes = value.as_slice()?;
    if bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return None;
    }

    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(bytes);
    Some(AddressHash::new(hash))
}

fn shared_rpc_interface_stats() -> Value {
    Value::Map(vec![
        (Value::from("interfaces"), Value::Array(vec![])),
        (Value::from("rxb"), Value::from(0)),
        (Value::from("txb"), Value::from(0)),
        (Value::from("rxs"), Value::from(0)),
        (Value::from("txs"), Value::from(0)),
        (Value::from("rss"), Value::Nil),
    ])
}

fn shared_rpc_map_str<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a str> {
    shared_rpc_map_value(map, name).and_then(Value::as_str)
}

fn shared_rpc_map_value<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

fn read_shared_rpc_value(data: &[u8]) -> Result<Value, String> {
    read_msgpack_value(data).or_else(|msgpack_error| {
        read_python_pickle_value(data).map_err(|pickle_error| {
            format!(
                "unsupported RPC payload: MessagePack decode failed: {msgpack_error}; pickle decode failed: {pickle_error}"
            )
        })
    })
}

fn read_msgpack_value(data: &[u8]) -> Result<Value, String> {
    let mut cursor = std::io::Cursor::new(data);
    let value = read_value(&mut cursor).map_err(|error| error.to_string())?;
    if cursor.position() as usize != data.len() {
        return Err("MessagePack payload has trailing bytes".into());
    }
    Ok(value)
}

fn write_shared_rpc_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    write_value(&mut encoded, value).map_err(|error| error.to_string())?;
    Ok(encoded)
}

enum PickleStackItem {
    Mark,
    Value(Value),
}

fn read_python_pickle_value(data: &[u8]) -> Result<Value, String> {
    let mut index = 0usize;
    let mut stack = Vec::<PickleStackItem>::new();

    while index < data.len() {
        let opcode = data[index];
        index += 1;

        match opcode {
            0x80 => {
                index = index
                    .checked_add(1)
                    .filter(|index| *index <= data.len())
                    .ok_or_else(|| "pickle protocol opcode is truncated".to_string())?;
            }
            0x95 => {
                index = index
                    .checked_add(8)
                    .filter(|index| *index <= data.len())
                    .ok_or_else(|| "pickle frame opcode is truncated".to_string())?;
            }
            b'}' => stack.push(PickleStackItem::Value(Value::Map(vec![]))),
            b'(' => stack.push(PickleStackItem::Mark),
            0x94 => {}
            0x8c => {
                let len = read_pickle_u8(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|error| error.to_string())
                    .map(Value::from)?;
                stack.push(PickleStackItem::Value(value));
            }
            b'X' => {
                let len = read_pickle_u32_le(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|error| error.to_string())
                    .map(Value::from)?;
                stack.push(PickleStackItem::Value(value));
            }
            b'C' => {
                let len = read_pickle_u8(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                stack.push(PickleStackItem::Value(Value::Binary(bytes.to_vec())));
            }
            b'B' => {
                let len = read_pickle_u32_le(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                stack.push(PickleStackItem::Value(Value::Binary(bytes.to_vec())));
            }
            b'N' => stack.push(PickleStackItem::Value(Value::Nil)),
            0x88 => stack.push(PickleStackItem::Value(Value::Boolean(true))),
            0x89 => stack.push(PickleStackItem::Value(Value::Boolean(false))),
            b']' => stack.push(PickleStackItem::Value(Value::Array(vec![]))),
            b'K' => stack.push(PickleStackItem::Value(Value::from(read_pickle_u8(
                data, &mut index,
            )?))),
            b'M' => stack.push(PickleStackItem::Value(Value::from(read_pickle_u16_le(
                data, &mut index,
            )?))),
            b'J' => stack.push(PickleStackItem::Value(Value::from(read_pickle_i32_le(
                data, &mut index,
            )?))),
            b'u' => pickle_set_items(&mut stack)?,
            b's' => pickle_set_item(&mut stack)?,
            b'.' => {
                let Some(PickleStackItem::Value(value)) = stack.pop() else {
                    return Err("pickle did not end with a value".into());
                };
                return Ok(value);
            }
            opcode => {
                return Err(format!("unsupported pickle opcode 0x{opcode:02x}"));
            }
        }
    }

    Err("pickle ended without STOP opcode".into())
}

fn write_python_pickle_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut encoded = vec![0x80, 0x05];
    write_python_pickle_payload(&mut encoded, value)?;
    encoded.push(b'.');
    Ok(encoded)
}

fn write_python_pickle_payload(encoded: &mut Vec<u8>, value: &Value) -> Result<(), String> {
    match value {
        Value::Nil => encoded.push(b'N'),
        Value::Boolean(false) => encoded.push(0x89),
        Value::Boolean(true) => encoded.push(0x88),
        Value::Integer(integer) => {
            if let Some(value) = integer.as_u64() {
                if value <= u8::MAX as u64 {
                    encoded.push(b'K');
                    encoded.push(value as u8);
                } else if value <= u16::MAX as u64 {
                    encoded.push(b'M');
                    encoded.extend_from_slice(&(value as u16).to_le_bytes());
                } else if value <= i32::MAX as u64 {
                    encoded.push(b'J');
                    encoded.extend_from_slice(&(value as i32).to_le_bytes());
                } else {
                    return Err("integer response is too large for pickle encoder".into());
                }
            } else if let Some(value) = integer.as_i64() {
                if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
                    encoded.push(b'J');
                    encoded.extend_from_slice(&(value as i32).to_le_bytes());
                } else {
                    return Err("integer response is too large for pickle encoder".into());
                }
            }
        }
        Value::String(string) => {
            let Some(string) = string.as_str() else {
                return Err("invalid string response".into());
            };
            let bytes = string.as_bytes();
            if bytes.len() <= u8::MAX as usize {
                encoded.push(0x8c);
                encoded.push(bytes.len() as u8);
            } else {
                encoded.push(b'X');
                encoded.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
            encoded.extend_from_slice(bytes);
            encoded.push(0x94);
        }
        Value::Binary(bytes) => {
            if bytes.len() <= u8::MAX as usize {
                encoded.push(b'C');
                encoded.push(bytes.len() as u8);
            } else {
                encoded.push(b'B');
                encoded.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
            encoded.extend_from_slice(bytes);
            encoded.push(0x94);
        }
        Value::Array(values) => {
            encoded.push(b']');
            encoded.push(0x94);
            if !values.is_empty() {
                encoded.push(b'(');
                for value in values {
                    write_python_pickle_payload(encoded, value)?;
                }
                encoded.push(b'e');
            }
        }
        Value::Map(values) => {
            encoded.push(b'}');
            encoded.push(0x94);
            if !values.is_empty() {
                encoded.push(b'(');
                for (key, value) in values {
                    write_python_pickle_payload(encoded, key)?;
                    write_python_pickle_payload(encoded, value)?;
                }
                encoded.push(b'u');
            }
        }
        _ => return Err("unsupported RPC response type".into()),
    }

    Ok(())
}

fn pickle_set_items(stack: &mut Vec<PickleStackItem>) -> Result<(), String> {
    let mark_index = stack
        .iter()
        .rposition(|item| matches!(item, PickleStackItem::Mark))
        .ok_or_else(|| "pickle SETITEMS without MARK".to_string())?;
    let values = stack.split_off(mark_index + 1);
    stack.pop();

    let Some(PickleStackItem::Value(Value::Map(map))) = stack.last_mut() else {
        return Err("pickle SETITEMS target is not a dict".into());
    };
    let mut values = values.into_iter();
    while let Some(key) = values.next() {
        let Some(value) = values.next() else {
            return Err("pickle SETITEMS has odd item count".into());
        };
        let PickleStackItem::Value(key) = key else {
            return Err("pickle SETITEMS key is MARK".into());
        };
        let PickleStackItem::Value(value) = value else {
            return Err("pickle SETITEMS value is MARK".into());
        };
        map.push((key, value));
    }

    Ok(())
}

fn pickle_set_item(stack: &mut Vec<PickleStackItem>) -> Result<(), String> {
    let Some(PickleStackItem::Value(value)) = stack.pop() else {
        return Err("pickle SETITEM missing value".into());
    };
    let Some(PickleStackItem::Value(key)) = stack.pop() else {
        return Err("pickle SETITEM missing key".into());
    };
    let Some(PickleStackItem::Value(Value::Map(map))) = stack.last_mut() else {
        return Err("pickle SETITEM target is not a dict".into());
    };
    map.push((key, value));
    Ok(())
}

fn read_pickle_bytes<'a>(
    data: &'a [u8],
    index: &mut usize,
    len: usize,
) -> Result<&'a [u8], String> {
    let end = index
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| "pickle byte payload is truncated".to_string())?;
    let bytes = &data[*index..end];
    *index = end;
    Ok(bytes)
}

fn read_pickle_u8(data: &[u8], index: &mut usize) -> Result<u8, String> {
    let bytes = read_pickle_bytes(data, index, 1)?;
    Ok(bytes[0])
}

fn read_pickle_u16_le(data: &[u8], index: &mut usize) -> Result<u16, String> {
    let bytes = read_pickle_bytes(data, index, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_pickle_u32_le(data: &[u8], index: &mut usize) -> Result<u32, String> {
    let bytes = read_pickle_bytes(data, index, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_pickle_i32_le(data: &[u8], index: &mut usize) -> Result<i32, String> {
    let bytes = read_pickle_bytes(data, index, 4)?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

async fn read_py_connection_frame_if_ready(
    stream: &mut TcpStream,
    max_size: usize,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    match time::timeout(timeout, stream.readable()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    }

    let mut header = [0u8; 4];
    let peeked = stream
        .peek(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    if peeked < header.len() {
        return Ok(None);
    }

    let size = i32::from_be_bytes(header);
    if !(0..=max_size as i32).contains(&size) {
        return Ok(None);
    }

    read_py_connection_frame(stream, max_size).await.map(Some)
}

async fn read_py_connection_frame(
    stream: &mut TcpStream,
    max_size: usize,
) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;

    let size = i32::from_be_bytes(header);
    let size = if size == -1 {
        let mut long_header = [0u8; 8];
        stream
            .read_exact(&mut long_header)
            .await
            .map_err(|error| error.to_string())?;
        u64::from_be_bytes(long_header)
            .try_into()
            .map_err(|_| "frame is too large".to_string())?
    } else if size >= 0 {
        size as usize
    } else {
        return Err("invalid frame length".into());
    };

    if size > max_size {
        return Err(format!("frame length {size} exceeds maximum {max_size}"));
    }

    let mut data = vec![0u8; size];
    stream
        .read_exact(&mut data)
        .await
        .map_err(|error| error.to_string())?;
    Ok(data)
}

async fn write_py_connection_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = i32::try_from(data.len()).map_err(|_| "frame is too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(data)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    fn knows_destination(&self, address: &AddressHash) -> bool {
        self.single_out_destinations.contains_key(address)
    }

    /// Remove path table entries whose associated identity is blackholed.
    /// Protocol-compatible with Python `Transport.remove_blackholed_paths()`.
    pub fn remove_blackholed_paths(&mut self) -> usize {
        let blackholed: HashSet<AddressHash> =
            self.blackhole_table.identity_hashes().into_iter().collect();

        if blackholed.is_empty() {
            return 0;
        }

        let mut drop_destinations = Vec::new();
        for (dest_hash, dest) in &self.single_out_destinations {
            if let Ok(handler) = dest.try_lock() {
                if blackholed.contains(&handler.identity.address_hash) {
                    drop_destinations.push(*dest_hash);
                }
            }
        }

        let count = drop_destinations.len();
        for dest_hash in &drop_destinations {
            self.single_out_destinations.remove(dest_hash);
            self.send_ctx.path_table.write().unwrap().remove(dest_hash);
        }

        if count > 0 {
            log::info!(
                "tp({}): removed {} destination{} associated with blackholed identities",
                self.config.name,
                count,
                if count == 1 { "" } else { "s" },
            );
        }

        count
    }

    fn accepts_transport_packet(&self, packet: &Packet) -> bool {
        if packet.header.packet_type == PacketType::Announce {
            return true;
        }

        match packet.transport {
            Some(transport_id) => transport_id == *self.config.identity.address_hash(),
            None => true,
        }
    }

    async fn filter_duplicate_packets(&mut self, packet: &Packet) -> bool {
        let mut allow_duplicate = false;

        match packet.header.packet_type {
            PacketType::Announce => {}
            PacketType::LinkRequest => {
                allow_duplicate = true;
            }
            PacketType::Data => {
                allow_duplicate = packet.context == PacketContext::KeepAlive;
            }
            PacketType::Proof => {
                if packet.context == PacketContext::LinkRequestProof {
                    if let Some(link) = self.in_links.get(&packet.destination) {
                        if link.lock().await.status().not_yet_active() {
                            allow_duplicate = true;
                        }
                    }
                }
            }
        }

        let is_new = self.send_ctx.packet_cache.lock().unwrap().update(packet);

        if !is_new && !allow_duplicate {
            self.packets_dropped_duplicate += 1;
        }

        is_new || allow_duplicate
    }

    async fn request_path(
        &mut self,
        address: &AddressHash,
        pending: &mut PendingSends,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        // Per-destination rate limit: at most one path request per
        // destination every PATH_REQUEST_MI (20s).
        if let Some(last) = self.last_path_requests.get(address) {
            if last.elapsed() <= PATH_REQUEST_MI {
                return;
            }
        }
        self.last_path_requests
            .insert(*address, time::Instant::now());

        let packet = self.path_requests.generate(address, tag);

        // Per-interface egress path-request limiting: only send to
        // interfaces whose outgoing PR rate is below the threshold
        // (EGRESS_PR_FREQ, default 5 Hz).
        let ifaces = {
            let mgr = self.send_ctx.iface_manager.lock().await;
            mgr.active_interface_addresses()
        };

        let mut sent_any = false;
        for iface_addr in &ifaces {
            if let Some(ref on) = on_iface {
                if iface_addr == on {
                    continue;
                }
            }

            let is_hot = {
                let mgr = self.send_ctx.iface_manager.lock().await;
                mgr.egress_record_pr(iface_addr)
            };

            if is_hot {
                log::trace!(
                    "tp({}): egress PR limit hit on iface {}, dropping path request to {}",
                    self.config.name,
                    iface_addr,
                    address,
                );
                continue;
            }

            pending.push(TxMessage {
                tx_type: TxMessageType::Direct(*iface_addr),
                packet: packet.clone(),
            });
            sent_any = true;
        }

        // Fallback: if no interface accepted the PR (e.g. all were hot
        // or only the originating interface existed), send a normal
        // broadcast so the request doesn't get completely lost.
        if !sent_any {
            pending.push(TxMessage {
                tx_type: TxMessageType::Broadcast(on_iface),
                packet,
            });
        }
    }

    async fn build_discovery_packet(&mut self, iface: &AddressHash) -> Result<Packet, RnsError> {
        let config = self
            .discoverable_ifaces
            .get_mut(iface)
            .ok_or(RnsError::InvalidArgument)?;

        config.last_announce = time::Instant::now();

        let app_data = config
            .config
            .build_app_data(self.config.retransmit, self.config.identity.address_hash())?;

        self.discovery_destination
            .lock()
            .await
            .announce(OsRng, Some(app_data.as_slice()))
    }
}

async fn handle_proof(
    packet: &Packet,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
    snr: Option<f32>,
    rssi: Option<i16>,
) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        match link.handle_packet(packet, true) {
            LinkHandleResult::Activated => {
                log::debug!(
                    "tp({}): out-link {} activated by proof, sending RTT",
                    handler.config.name,
                    link.id(),
                );
                let rtt_packet = link.create_rtt();
                pending.push(handler.send_ctx.prepare_send_packet(rtt_packet));
            }
            _ => {}
        }
    }

    // Check pending proofs for both link and direct packet proofs
    if let Some(pending_proof) = handler.pending_proofs.remove(&packet.destination) {
        let receipt = PacketReceipt {
            packet_hash: pending_proof.original_packet_hash,
            destination: pending_proof.destination_address,
            snr,
            rssi,
        };
        warn_if_event_channel_full(&handler.receipt_tx, handler.config.event_channel_capacity, "receipt", &handler.config.name);
        let _ = handler.receipt_tx.send(receipt);
    }

    let maybe_packet = handler.link_table.handle_proof(packet);

    if let Some((packet, iface)) = maybe_packet {
        pending.push(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        });
    }

    let maybe_packet = handler.reverse_table.handle_proof(packet);

    if let Some((packet, iface)) = maybe_packet {
        pending.push(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        });
    }
}

async fn send_to_next_hop(
    packet: &Packet,
    handler: &TransportHandler,
    pending: &mut PendingSends,
    lookup: Option<AddressHash>,
) -> bool {
    let dst = packet.destination;
    let (packet, maybe_iface) = {
        let pt = handler.send_ctx.path_table.read().unwrap();
        pt.handle_inbound_packet(packet, lookup)
    };

    if let Some(iface) = maybe_iface {
        handler
            .send_ctx
            .path_table
            .write()
            .unwrap()
            .refresh(&dst);
        pending.push(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        });
    } else {
        log::trace!(
            "tp({}): no next-hop for dst={}, dropping forwarded packet",
            handler.config.name,
            packet.destination,
        );
    }

    maybe_iface.is_some()
}

/// Returns `(true, Some(...))` if the keepalive was handled and needs
/// forwarding, `(true, None)` if handled without forwarding,
/// `(false, None)` if not a keepalive packet at all.
async fn handle_keepalive_response(
    packet: &Packet,
    handler: &mut TransportHandler,
) -> (bool, Option<TxMessage>) {
    if packet.context == PacketContext::KeepAlive {
        if packet.data.len() == 0 {
            log::trace!(
                "tp({}): keepalive with empty data for link {}, ignoring",
                handler.config.name,
                packet.destination,
            );
            return (true, None);
        }
        if packet.data.as_slice()[0] == KEEP_ALIVE_RESPONSE {
            log::trace!(
                "tp({}): keepalive response for link {}",
                handler.config.name,
                packet.destination,
            );

            let forwarded = handler.link_table.handle_keepalive(packet);

            if let Some((propagated, iface)) = forwarded {
                return (
                    true,
                    Some(TxMessage {
                        tx_type: TxMessageType::Direct(iface),
                        packet: propagated,
                    }),
                );
            }

            return (true, None);
        }
    }

    (false, None)
}

async fn handle_data(
    packet: &Packet,
    iface: AddressHash,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
) {
    let mut data_handled = false;

    if packet.header.destination_type == DestinationType::Link {
        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().await;
            let result = link.handle_packet(packet, false);
            match result {
                LinkHandleResult::KeepAlive => {
                    log::trace!(
                        "tp({}): received keepalive on in-link {}, sending response",
                        handler.config.name,
                        link.id(),
                    );
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    pending.push(handler.send_ctx.prepare_send_packet(packet));
                }
                LinkHandleResult::MessageReceived(Some(proof)) => {
                    log::trace!(
                        "tp({}): received data on in-link {}, sending proof",
                        handler.config.name,
                        link.id(),
                    );
                    pending.push(handler.send_ctx.prepare_send_packet(proof));
                }
                LinkHandleResult::MessageReceived(None) => {
                    log::trace!(
                        "tp({}): received data on in-link {} (no proof)",
                        handler.config.name,
                        link.id(),
                    );
                }
                LinkHandleResult::None => {
                    log::trace!(
                        "tp({}): received packet on in-link {} (no action)",
                        handler.config.name,
                        link.id(),
                    );
                }
                LinkHandleResult::Activated => {
                    log::trace!(
                        "tp({}): in-link {} activated",
                        handler.config.name,
                        link.id(),
                    );
                }
            }
        }

        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            let result = link.handle_packet(packet, true);
            if matches!(result, LinkHandleResult::KeepAlive) {
                log::trace!(
                    "tp({}): received keepalive response on out-link {}",
                    handler.config.name,
                    link.id(),
                );
            }
            data_handled = true;
        }

        {
            let (keepalive, fwd) = handle_keepalive_response(packet, handler).await;
            if let Some(fwd) = fwd {
                pending.push(fwd);
            }
            if keepalive {
                return;
            }
        }

        if let Some((packet, iface)) = handler.link_table.handle_packet(packet, iface) {
            let destination = packet.destination;
            pending.push(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            });

            log::trace!(
                "tp({}): forwarded packet for remote link {} via iface {}",
                handler.config.name,
                destination,
                iface,
            );

            return;
        }

        let lookup = handler.link_table.original_destination(&packet.destination);
        if lookup.is_some() {
            let sent = send_to_next_hop(packet, handler, pending, lookup).await;

            log::trace!(
                "tp({}): {} packet to remote link {}",
                handler.config.name,
                if sent {
                    "forwarded"
                } else {
                    "could not forward"
                },
                packet.destination
            );
        }
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            let mut plain_data = PacketDataBuffer::new();
            let mut proof = None;
            let decrypted_len = {
                let destination = destination.lock().await;
                match destination.decrypt(
                    packet.data.as_slice(),
                    plain_data.accuire_buf(packet.data.len()),
                ) {
                    Ok(data) => {
                        if destination.prove_packets() {
                            proof = Some(destination.proof_packet(&packet.hash()));
                        }
                        Some(data.len())
                    }
                    Err(err) => {
                        handler.decryption_failures += 1;
                        log::warn!(
                            "tp({}): failed to decrypt packet for {}: {err:?}",
                            handler.config.name,
                            packet.destination,
                        );
                        None
                    }
                }
            };

            if let Some(decrypted_len) = decrypted_len {
                data_handled = true;
                plain_data.resize(decrypted_len);

                warn_if_event_channel_full(&handler.received_data_tx, handler.config.event_channel_capacity, "received_data", &handler.config.name);
                handler
                    .received_data_tx
                    .send(ReceivedData {
                        destination: packet.destination.clone(),
                        data: plain_data,
                    })
                    .ok();
            }

            if let Some(proof) = proof {
                log::trace!(
                    "tp({}): send packet proof for {}",
                    handler.config.name,
                    packet.destination
                );

                pending.push(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: proof,
                });
            }
        } else {
            let has_next_hop = handler
                .send_ctx
                .path_table
                .read()
                .unwrap()
                .next_hop_full(&packet.destination)
                .is_some();
            if has_next_hop {
                handler.reverse_table.add(packet, iface);
            } else {
                let enough_time_passed = handler
                    .last_path_requests
                    .get(&packet.destination)
                    .map(|last| last.elapsed() > PATH_REQUEST_MI)
                    .unwrap_or(true);

                if enough_time_passed {
                    handler
                        .request_path(&packet.destination, pending, Some(iface), None)
                        .await;
                }
            }

            data_handled = send_to_next_hop(packet, handler, pending, None).await;
        }
    }

    if data_handled {
        log::trace!(
            "tp({}): handle data request for {} dst={:2x} ctx={:2x}",
            handler.config.name,
            packet.destination,
            packet.header.destination_type as u8,
            packet.context as u8,
        );
    }
}

async fn handle_announce(
    packet: &Packet,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
    iface: AddressHash,
    snr: Option<f32>,
    rssi: Option<i16>,
) {
    if handler.has_destination(&packet.destination) {
        // destination is local
        return;
    }

    if packet.context != PacketContext::PathResponse {
        if let Some(blocked_until) = handler.announce_limits.check(&packet.destination) {
            handler.announces_rate_limited += 1;
            log::info!(
                "tp({}): too many announces from {}, blocked for {} seconds",
                handler.config.name,
                &packet.destination,
                blocked_until.as_secs(),
            );
            return;
        }

        // Ingress burst limiting: drop announces that arrive faster than
        // the interface can reasonably process (default threshold ~10 Hz).
        if handler.send_ctx.iface_manager.lock().await.ingress_record_announce(&iface) {
            log::trace!(
                "tp({}): dropping announce from {} due to ingress burst limiting",
                handler.config.name,
                packet.destination,
            );
            return;
        }
    }

    if log::log_enabled!(log::Level::Trace) {
        let hash = packet.hash();
        log::trace!(
            "tp({}): rx announce dst={} iface={} header={:?} context_flag={:?} propagation={:?} \
dest_type={:?} ctx={:?} packet_hops={} transport={} transport_matches_destination={} hash={}",
            handler.config.name,
            packet.destination,
            iface,
            packet.header.header_type,
            packet.header.context_flag,
            packet.header.propagation_type,
            packet.header.destination_type,
            packet.context,
            packet.header.hops,
            packet
                .transport
                .map(|transport| transport.to_string())
                .unwrap_or_else(|| "None".to_owned()),
            packet.transport == Some(packet.destination),
            hash,
        );
    }

    if let Ok(result) = DestinationAnnounce::validate(packet) {
        let destination = result.0;
        let app_data = result.1;
        let identity_hash = destination.identity.address_hash;
        let dest_desc = destination.desc;

        // Protocol-compatible blackhole check: reject announces from
        // identities that have been blackholed.  Equivalent to the check
        // in Python `RNS.Identity.validate_announce()`.
        if handler.blackhole_table.contains(&identity_hash) {
            log::info!(
                "tp({}): dropped announce from blackholed identity {}",
                handler.config.name,
                identity_hash,
            );
            return;
        }

        let destination = Arc::new(Mutex::new(destination));

        log::trace!(
            "tp({}): validated announce destination_hash={} identity_hash={} iface={} \
is_path_response={}",
            handler.config.name,
            packet.destination,
            identity_hash,
            iface,
            packet.context == PacketContext::PathResponse,
        );

        if !handler
            .single_out_destinations
            .contains_key(&packet.destination)
        {
            log::trace!(
                "tp({}): new announce for {}",
                handler.config.name,
                packet.destination
            );

            handler
                .single_out_destinations
                .insert(packet.destination, destination.clone());
        }

        // Echo detection: if this destination is already in the announce
        // table and we've previously retransmitted it, a peer is relaying
        // our announce back to us.  Count the echo and stop retransmitting
        // once LOCAL_REBROADCASTS_MAX is reached (matches Python behaviour).
        let is_echo = handler.config.retransmit
            && handler.announce_table.contains_key(&packet.destination);

        if is_echo {
            let completed = handler
                .announce_table
                .echo_received(&packet.destination, packet.header.hops);
            if completed {
                log::trace!(
                    "tp({}): announce for {} completed by echo",
                    handler.config.name,
                    packet.destination,
                );
            }
        } else {
            handler
                .announce_table
                .add(packet, packet.destination, iface);
        }

        let path_expiry = handler
            .send_ctx
            .iface_manager
            .lock()
            .await
            .path_expiry_for_iface(&iface);
        handler
            .send_ctx
            .path_table
            .write()
            .unwrap()
            .handle_announce(packet, packet.transport, iface, path_expiry);

        if let Some(response_iface) = handler.path_requests.take_discovery(&packet.destination) {
            let transport_id = handler.config.identity.address_hash().clone();
            let response = Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type2,
                    context_flag: packet.header.context_flag,
                    propagation_type: PropagationType::Transport,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                    hops: packet.header.hops,
                },
                ifac: None,
                destination: packet.destination,
                transport: Some(transport_id),
                context: PacketContext::PathResponse,
                data: packet.data.clone(),
            };

            pending.push(TxMessage {
                tx_type: TxMessageType::Direct(response_iface),
                packet: response,
            });

            log::trace!(
                "tp({}): answered waiting discovery path request for {} over {}",
                handler.config.name,
                packet.destination,
                response_iface
            );
        }

        // Only trigger a new retransmit for the first announce, not echoes
        if !is_echo && handler.config.retransmit {
            let transport_id = handler.config.identity.address_hash().clone();
            if let Some(message) = handler
                .announce_table
                .new_packet(&packet.destination, &transport_id)
            {
                pending.push(message);
            }
        }

        warn_if_event_channel_full(&handler.announce_tx, handler.config.event_channel_capacity, "announce", &handler.config.name);
        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            hops: packet.header.hops,
            snr,
            rssi,
            app_data: PacketDataBuffer::new_from_slice(&app_data),
        });

        if is_discovery_destination(&dest_desc) {
            if let Ok(discovered) = DiscoveredInterface::from_announce(
                dest_desc,
                packet.header.hops,
                app_data,
            ) {
                warn_if_event_channel_full(&handler.discovery_tx, handler.config.event_channel_capacity, "discovery", &handler.config.name);
                let _ = handler.discovery_tx.send(discovered);
            }
        }
    } else {
        log::debug!(
            "tp({}): dropped invalid announce for dst={}",
            handler.config.name,
            packet.destination,
        );
    }
}

async fn handle_path_request(
    packet: &Packet,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
    iface: AddressHash,
) {
    // Ingress burst limiting for path requests
    if handler.send_ctx.iface_manager.lock().await.ingress_record_pr(&iface) {
        log::trace!(
            "tp({}): dropping path request from {} due to ingress PR burst limiting",
            handler.config.name,
            packet.destination,
        );
        return;
    }

    if let Some(request) = handler.path_requests.decode(packet.data.as_slice()) {
        if let Some(dest) = handler.single_in_destinations.get(&request.destination) {
            let response = dest
                .lock()
                .await
                .path_response(OsRng, None)
                .expect("valid path response");

            pending.push(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: response,
            });

            log::trace!(
                "tp({}): send direct path response over {}",
                handler.config.name,
                iface
            );

            return;
        }

        if handler.config.retransmit {
            let (received_from, hops) = {
                let pt = handler.send_ctx.path_table.read().unwrap();
                pt.get(&request.destination)
                    .map(|e| (e.received_from, e.hops))
                    .unzip()
            };
            if let (Some(received_from), Some(hops)) = (received_from, hops) {
                if let Some(requestor_id) = request.requesting_transport {
                    if requestor_id == received_from {
                        log::trace!(
                            "tp({}): dropping circular path request from {}",
                            handler.config.name,
                            request.destination
                        );
                        return;
                    }
                }

                let mut grace = PATH_REQUEST_GRACE;
                if handler.send_ctx.iface_manager.lock().await.interface_mode(&iface)
                    == crate::iface::InterfaceMode::Roaming
                {
                    grace += PATH_REQUEST_RG;
                }

                if handler
                    .announce_table
                    .add_response(request.destination, iface, hops, grace)
                {
                    log::trace!(
                        "tp({}): scheduled remote path response to {} ({} hops) over {} with {}ms grace",
                        handler.config.name,
                        request.destination,
                        hops,
                        iface,
                        grace.as_millis(),
                    );

                    return;
                }

                log::trace!(
                    "tp({}): announce for {} not cached, falling back to recursive forwarding",
                    handler.config.name,
                    request.destination,
                );
            }

            // Python: only forward recursive path requests when the
            // requesting interface has `recursive_prs` enabled, or its
            // mode is in DISCOVER_PATHS_FOR (AccessPoint, Gateway,
            // Roaming, Internal).
            let should_search = {
                let mgr = handler.send_ctx.iface_manager.lock().await;
                mgr.recursive_prs_for_iface(&iface)
                    || InterfaceMode::DISCOVER_PATHS_FOR.contains(&mgr.interface_mode(&iface))
            };

            if should_search {
                if let Some(packet) = handler.path_requests.generate_recursive(
                &request.destination,
                iface,
                Some(request.tag_bytes.clone()),
            ) {
                // Apply egress PR limiting: only forward to non-hot
                // interfaces, excluding the originating interface.
                let ifaces = {
                    let mgr = handler.send_ctx.iface_manager.lock().await;
                    mgr.active_interface_addresses()
                };
                let mut sent_any = false;
                for iface_addr in &ifaces {
                    if *iface_addr == iface {
                        continue;
                    }
                    let is_hot = {
                        let mgr = handler.send_ctx.iface_manager.lock().await;
                        mgr.egress_record_pr(iface_addr)
                    };
                    if is_hot {
                        log::trace!(
                            "tp({}): egress PR limit hit on iface {}, dropping recursive PR to {}",
                            handler.config.name,
                            iface_addr,
                            request.destination,
                        );
                        continue;
                    }
                    pending.push(TxMessage {
                        tx_type: TxMessageType::Direct(*iface_addr),
                        packet: packet.clone(),
                    });
                    sent_any = true;
                }
                if !sent_any {
                    pending.push(TxMessage {
                        tx_type: TxMessageType::Broadcast(Some(iface)),
                        packet,
                    });
                }
            }
            }
        }
    }
}

async fn handle_fixed_destinations(
    packet: &Packet,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
    iface: AddressHash,
) -> bool {
    if packet.destination == handler.fixed_dest_path_requests {
        handle_path_request(packet, handler, pending, iface).await;
        true
    } else {
        false
    }
}

fn should_rebroadcast_inbound_packet(packet: &Packet) -> bool {
    packet.header.header_type == HeaderType::Type1
        && packet.header.propagation_type == PropagationType::Broadcast
        && packet.header.packet_type == PacketType::Data
        && packet.header.destination_type == DestinationType::Plain
        && packet.header.hops == 1
}

async fn handle_link_request_as_destination(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
    iface: AddressHash,
) {
    let packet = if handler.config.link_mtu_discovery {
        clamp_link_request_mtu(packet, handler, Some(iface), None).await
    } else {
        packet.clone()
    };

    let mut destination = destination.lock().await;
    match destination.handle_packet(&packet) {
        DestinationHandleStatus::LinkProof => {
            let link_id = LinkId::from(&packet);
            if !handler.in_links.contains_key(&link_id) {
                log::trace!(
                    "tp({}): send proof to {}",
                    handler.config.name,
                    packet.destination
                );

                let link = Link::new_from_request(
                    &packet,
                    destination.sign_key().clone(),
                    destination.desc,
                    handler.link_in_event_tx.clone(),
                );

                if let Ok(mut link) = link {
                    let prove_packet = link.prove();
                    pending.push(handler.send_ctx.prepare_send_packet(prove_packet));

                    log::debug!(
                        "tp({}): save input link {} for destination {}",
                        handler.config.name,
                        link.id(),
                        link.destination().address_hash
                    );

                    handler
                        .in_links
                        .insert(*link.id(), Arc::new(Mutex::new(link)));
                }
            }
        }
        DestinationHandleStatus::None => {}
    }
}

async fn handle_link_request_as_intermediate(
    received_from: AddressHash,
    next_hop_iface: AddressHash,
    remaining_hops: u8,
    packet: &Packet,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
) {
    log::trace!(
        "tp({}): forward link request dst={} from={} to_iface={} ({} hops remaining)",
        handler.config.name,
        packet.destination,
        received_from,
        next_hop_iface,
        remaining_hops,
    );

    handler.link_table.add(
        packet,
        packet.destination,
        received_from,
        next_hop_iface,
        remaining_hops,
    );

    let forwarded = if handler.config.link_mtu_discovery {
        clamp_link_request_mtu(packet, handler, Some(received_from), Some(next_hop_iface)).await
    } else {
        packet.clone()
    };

    let sent = send_to_next_hop(&forwarded, handler, pending, None).await;
    if !sent {
        log::warn!(
            "tp({}): failed to forward link request dst={} to_iface={}",
            handler.config.name,
            packet.destination,
            next_hop_iface,
        );
    }
}

async fn clamp_link_request_mtu(
    packet: &Packet,
    handler: &TransportHandler,
    inbound_iface: Option<AddressHash>,
    outbound_iface: Option<AddressHash>,
) -> Packet {
    if packet.data.len() != PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE {
        return packet.clone();
    }

    let signalling =
        &packet.data.as_slice()[PUBLIC_KEY_LENGTH * 2..PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE];
    let path_mtu = mtu_from_signalling_bytes(signalling);
    let iface_manager = handler.send_ctx.iface_manager.lock().await;
    let inbound_mtu = inbound_iface.and_then(|iface| iface_manager.hw_mtu(&iface));
    let outbound_mtu = outbound_iface.and_then(|iface| iface_manager.hw_mtu(&iface));
    drop(iface_manager);

    let mut clamped = path_mtu;
    if let Some(mtu) = inbound_mtu {
        clamped = clamped.min(mtu);
    }

    match outbound_iface {
        Some(_) => match outbound_mtu {
            Some(mtu) => clamped = clamped.min(mtu),
            None => return strip_link_mtu_signalling(packet),
        },
        None => {
            if let Some(mtu) = inbound_mtu {
                clamped = clamped.min(mtu);
            } else {
                return strip_link_mtu_signalling(packet);
            }
        }
    }

    if clamped < path_mtu {
        let mut data = packet.data.clone();
        let offset = data.len() - LINK_MTU_SIZE;
        data.as_mut_slice()[offset..].copy_from_slice(&link_signalling_bytes(clamped));
        Packet {
            data,
            ..packet.clone()
        }
    } else {
        packet.clone()
    }
}

fn strip_link_mtu_signalling(packet: &Packet) -> Packet {
    let mut data = packet.data.clone();
    data.resize(PUBLIC_KEY_LENGTH * 2);
    Packet {
        data,
        ..packet.clone()
    }
}

async fn handle_link_request(
    packet: &Packet,
    iface: AddressHash,
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
) {
    // Ingress burst limiting for link requests (which carry path requests)
    if handler.send_ctx.iface_manager.lock().await.ingress_record_pr(&iface) {
        log::trace!(
            "tp({}): dropping link request from {} due to ingress PR burst limiting",
            handler.config.name,
            packet.destination,
        );
        return;
    }

    if let Some(destination) = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned()
    {
        log::trace!(
            "tp({}): handle link request for {}",
            handler.config.name,
            packet.destination
        );

        handle_link_request_as_destination(destination, packet, handler, pending, iface).await;
    } else {
        let route = {
            let pt = handler.send_ctx.path_table.read().unwrap();
            pt.next_hop_route(&packet.destination)
        };
        if let Some((_, next_iface, path_hops)) = route {
            log::trace!(
                "tp({}): handle link request for remote destination {}",
                handler.config.name,
                packet.destination
            );

            let remaining_hops = path_hops.saturating_sub(1);
            handle_link_request_as_intermediate(iface, next_iface, remaining_hops, packet, handler, pending)
                .await;
        } else {
            log::trace!(
                "tp({}): dropping link request to unknown destination {}",
                handler.config.name,
                packet.destination
            );
        }
    }
}

async fn handle_check_links(
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        match link.status() {
            LinkStatus::Active => {
                if link.elapsed() > INTERVAL_INPUT_LINK_STALE {
                    log::debug!(
                        "tp({}): in-link {} stale after {}s",
                        handler.config.name,
                        link.id(),
                        link.elapsed().as_secs(),
                    );
                    link.stale();
                }
            }
            LinkStatus::Stale => {
                if link.elapsed() > INTERVAL_INPUT_LINK_STALE + INTERVAL_INPUT_LINK_CLOSE {
                    log::debug!(
                        "tp({}): teardown stale in-link {} after {}s",
                        handler.config.name,
                        link.id(),
                        link.elapsed().as_secs(),
                    );
                    if let Some(packet) = link.teardown().unwrap_or_else(|err| {
                        log::error!(
                            "tp({}): teardown stale in-link error: {err:?}",
                            handler.config.name
                        );
                        None
                    }) {
                        pending.push(handler.send_ctx.prepare_send_packet(packet));
                    }
                    links_to_remove.push(*link_entry.0);
                }
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(&addr);
    }

    links_to_remove.clear();

    let mut rediscover_destinations: Vec<(AddressHash, Option<AddressHash>)> = Vec::new();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        match link.status() {
            LinkStatus::Active => {
                if link.elapsed() > INTERVAL_OUTPUT_LINK_STALE {
                    log::debug!(
                        "tp({}): out-link {} stale after {}s",
                        handler.config.name,
                        link.id(),
                        link.elapsed().as_secs(),
                    );
                    link.stale();
                }
            }
            LinkStatus::Stale => {
                if handler.config.restart_outlinks {
                    if link.elapsed() > INTERVAL_OUTPUT_LINK_RESTART {
                        log::debug!(
                            "tp({}): restart out-link {} after {}s",
                            handler.config.name,
                            link.id(),
                            link.elapsed().as_secs(),
                        );
                        link.restart();
                    }
                } else {
                    if link.elapsed() > INTERVAL_OUTPUT_LINK_STALE + INTERVAL_OUTPUT_LINK_CLOSE {
                        log::debug!(
                            "tp({}): teardown out-link {} after {}s",
                            handler.config.name,
                            link.id(),
                            link.elapsed().as_secs(),
                        );
                        if let Some(packet) = link.teardown().unwrap_or_else(|err| {
                            log::error!(
                                "tp({}): teardown stale out-link error: {err:?}",
                                handler.config.name
                            );
                            None
                        }) {
                            pending.push(handler.send_ctx.prepare_send_packet(packet));
                        }
                        links_to_remove.push(*link_entry.0);
                    }
                }
            }
            LinkStatus::Pending => {
                if link.elapsed() > INTERVAL_OUTPUT_LINK_REPEAT {
                    log::warn!(
                        "tp({}): repeat link request {}",
                        handler.config.name,
                        link.id()
                    );
                    let current_mtu = link.mtu();
                    pending.push(handler.send_ctx.prepare_send_packet(link.request(Some(current_mtu))));
                }

                if link.elapsed() > INTERVAL_OUTPUT_LINK_TRIED {
                    let already_unresponsive = handler
                        .send_ctx
                        .path_table
                        .read()
                        .unwrap()
                        .is_unresponsive(link_entry.0);

                    if !already_unresponsive {
                        let enough_time_passed = handler
                            .last_path_requests
                            .get(link_entry.0)
                            .map(|last| last.elapsed() > PATH_REQUEST_MI)
                            .unwrap_or(true);

                        if enough_time_passed {
                            log::warn!(
                                "tp({}): link {} pending for >{}s, marking path unresponsive \
                                 and rediscovering",
                                handler.config.name,
                                link.id(),
                                INTERVAL_OUTPUT_LINK_TRIED.as_secs(),
                            );

                            let blocked_if = handler
                                .send_ctx
                                .path_table
                                .read()
                                .unwrap()
                                .next_hop_iface(link_entry.0);

                            handler
                                .send_ctx
                                .path_table
                                .write()
                                .unwrap()
                                .mark_unresponsive(link_entry.0);

                            // If we are not a transport instance, drop the current
                            // path to allow using higher-hop count paths.
                            if !handler.config.retransmit {
                                handler
                                    .send_ctx
                                    .path_table
                                    .write()
                                    .unwrap()
                                    .remove(link_entry.0);
                            }

                            rediscover_destinations.push((*link_entry.0, blocked_if));
                        }
                    }
                }
            }
            LinkStatus::Closed => {
                link.close();
                links_to_remove.push(*link_entry.0);
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(&addr);
    }

    for (dest, blocked_if) in &rediscover_destinations {
        if let Some(blocked_if) = blocked_if {
            let ifaces = handler
                .send_ctx
                .iface_manager
                .lock()
                .await
                .active_interface_addresses();
            for iface in ifaces {
                if iface != *blocked_if {
                    handler.request_path(dest, pending, Some(iface), None).await;
                }
            }
        } else {
            handler.request_path(dest, pending, None, None).await;
        }
    }
}

async fn handle_keep_links(
    handler: &TransportHandler,
    pending: &mut PendingSends,
) {
    for link in handler.out_links.values() {
        let mut link = link.lock().await;

        if link.status() == LinkStatus::Active {
            log::trace!(
                "tp({}): send keepalive for link {}",
                handler.config.name,
                link.id(),
            );

            pending.push(handler.send_ctx.prepare_send_packet(link.keep_alive_packet(KEEP_ALIVE_REQUEST)));
            link.mark_activity();
        }
    }
}

async fn handle_cleanup(
    handler: &TransportHandler,
) {
    let mut mgr = handler.send_ctx.iface_manager.lock().await;
    mgr.cleanup();
    mgr.ingress_evaluate_all();
    mgr.egress_evaluate_all();
}

async fn handle_discovery(
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
) {
    let now = time::Instant::now();
    let mut selected_iface = None;
    let mut selected_elapsed = Duration::ZERO;

    for (iface, discovery) in &handler.discoverable_ifaces {
        if !discovery.is_due(now) {
            continue;
        }

        let elapsed = now.duration_since(discovery.last_announce);
        if selected_iface.is_none() || elapsed > selected_elapsed {
            selected_iface = Some(*iface);
            selected_elapsed = elapsed;
        }
    }

    let Some(iface) = selected_iface else {
        return;
    };

    let packet = match handler.build_discovery_packet(&iface).await {
        Ok(packet) => packet,
        Err(err) => {
            log::warn!(
                "tp({}): failed to build discovery announce on {}: {err:?}",
                handler.config.name,
                iface
            );
            return;
        }
    };

    pending.push(handler.send_ctx.prepare_send_packet(packet));
}

async fn retransmit_announces(
    handler: &mut TransportHandler,
    pending: &mut PendingSends,
    retransmit_old: bool,
) {
    let transport_id = handler.config.identity.address_hash().clone();
    let messages = handler.announce_table.to_retransmit(&transport_id);

    for message in messages {
        pending.push(message);
    }

    if retransmit_old {
        let messages = handler.announce_table.to_retransmit_old(&transport_id);

        for message in messages {
            pending.push(message);
        }
    }
}

fn create_retransmit_packet(packet: &Packet) -> Packet {
    Packet {
        header: Header {
            ifac_flag: packet.header.ifac_flag,
            header_type: packet.header.header_type,
            context_flag: packet.header.context_flag,
            propagation_type: packet.header.propagation_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops,
        },
        ifac: packet.ifac,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data.clone(),
    }
}

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    send_ctx: Arc<SendCtx>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let (cancel, retransmit, announce_forever, tp_name, event_channel_capacity) = {
        let h = handler.lock().await;
        (
            h.cancel.clone(),
            h.config.retransmit,
            h.config.announce_forever,
            h.config.name.clone(),
            h.config.event_channel_capacity,
        )
    };
    let mut last_retransmit_old = if announce_forever {
        Some(time::Instant::now() - INTERVAL_OLD_ANNOUNCES_RETRANSMIT)
    } else {
        None
    };

    let packet_send_ctx = send_ctx.clone();
    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();

        log::trace!("tp({}): start packet task", tp_name);

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                let message = {
                    let mut rx_receiver = rx_receiver.lock().await;
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            break;
                        },
                        message = rx_receiver.recv() => message,
                    }
                };

                let Some(message) = message else {
                    break;
                };

                warn_if_event_channel_full(&iface_messages_tx, event_channel_capacity, "iface_messages", &tp_name);
                let _ = iface_messages_tx.send(message.clone());

                let mut packet = message.packet;
                packet.header.hops = packet.header.hops.saturating_add(1);

                if PACKET_TRACE {
                    log::debug!(
                        "tp: << rx({}) = {} {}",
                        message.address,
                        packet,
                        packet.hash()
                    );
                }

                // Hold the handler lock only for synchronous operations.
                // Outbound sends are accumulated and flushed after the lock is released.
                let mut pending = PendingSends::new();
                let transport_id;
                {
                    let mut handler = handler.lock().await;
                    transport_id = *handler.config.identity.address_hash();

                    if handle_fixed_destinations(&packet, &mut *handler, &mut pending, message.address).await {
                        drop(handler);
                        pending.flush(&packet_send_ctx).await;
                        continue;
                    }

                    if !handler.accepts_transport_packet(&packet) {
                        log::trace!(
                            "tp({}): dropping packet for other transport: dst={}, transport={}",
                            tp_name,
                            packet.destination,
                            packet
                                .transport
                                .map(|transport| transport.to_string())
                                .unwrap_or_else(|| "None".to_owned()),
                        );
                        continue;
                    }

                    if !handler.filter_duplicate_packets(&packet).await {
                        log::debug!(
                            "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
                            tp_name,
                            packet.destination,
                            packet.context,
                            packet.header.packet_type
                        );
                        continue;
                    }

                    if handler.config.broadcast && should_rebroadcast_inbound_packet(&packet) {
                        // Plain first-hop broadcasts are not inserted into transport. Repeat
                        // them locally, and leave routed traffic to the path/link tables.
                        pending.push(TxMessage {
                            tx_type: TxMessageType::Broadcast(Some(message.address)),
                            packet: packet.clone(),
                        });
                    }

                    let snr = message.snr;
                    let rssi = message.rssi;
                    handler.last_snr = snr;
                    handler.last_rssi = rssi;
                    match packet.header.packet_type {
                        PacketType::Announce => {
                            handler.packets_received_by_type.announce += 1;
                            handle_announce(&packet, &mut *handler, &mut pending, message.address, snr, rssi).await
                        }
                        PacketType::LinkRequest => {
                            handler.packets_received_by_type.link_request += 1;
                            handle_link_request(&packet, message.address, &mut *handler, &mut pending).await
                        }
                        PacketType::Proof => {
                            handler.packets_received_by_type.proof += 1;
                            handle_proof(&packet, &mut *handler, &mut pending, snr, rssi).await
                        }
                        PacketType::Data => {
                            handler.packets_received_by_type.data += 1;
                            handle_data(&packet, message.address, &mut *handler, &mut pending).await
                        }
                    }
                }

                // Forward announces to shared-instance clients without holding
                // either the handler or iface_manager lock.
                if packet.header.packet_type == PacketType::Announce {
                    let clients = packet_send_ctx
                        .iface_manager
                        .lock()
                        .await
                        .shared_instance_clients_except(message.address);
                    for local_iface in clients {
                        let local_announce = Packet {
                            header: Header {
                                ifac_flag: IfacFlag::Open,
                                header_type: HeaderType::Type2,
                                context_flag: packet.header.context_flag,
                                propagation_type: PropagationType::Transport,
                                destination_type: DestinationType::Single,
                                packet_type: PacketType::Announce,
                                hops: packet.header.hops,
                            },
                            ifac: None,
                            destination: packet.destination,
                            transport: Some(transport_id),
                            context: PacketContext::None,
                            data: packet.data.clone(),
                        };

                        pending.push(TxMessage {
                            tx_type: TxMessageType::Direct(local_iface),
                            packet: local_announce,
                        });
                    }
                }

                // handler lock released — flush pending sends without contention
                pending.flush(&packet_send_ctx).await;
            }
        })
    };

    {
        let handler = handler.clone();
        let send_ctx = send_ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_LINKS_CHECK) => {
                        let mut pending = PendingSends::new();
                        {
                            let mut h = handler.lock().await;
                            handle_check_links(&mut *h, &mut pending).await;
                        }
                        pending.flush(&send_ctx).await;

                        // Expire stale pending proofs
                        let cutoff = time::Instant::now() - INTERVAL_PENDING_PROOF_TIMEOUT;
                        let mut h = handler.lock().await;
                        h.pending_proofs.retain(|_, v| v.created_at > cutoff);
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let send_ctx = send_ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(DISCOVERY_JOB_INTERVAL) => {
                        let mut pending = PendingSends::new();
                        {
                            let mut h = handler.lock().await;
                            handle_discovery(&mut *h, &mut pending).await;
                        }
                        pending.flush(&send_ctx).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let send_ctx = send_ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_OUTPUT_LINK_KEEP) => {
                        let mut pending = PendingSends::new();
                        {
                            let h = handler.lock().await;
                            handle_keep_links(&*h, &mut pending).await;
                        }
                        pending.flush(&send_ctx).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_IFACE_CLEANUP) => {
                        handle_cleanup(&*handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let send_ctx = send_ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_PACKET_CACHE_CLEANUP) => {
                        send_ctx.packet_cache.lock().unwrap().release(INTERVAL_KEEP_PACKET_CACHED);

                        let mut handler = handler.lock().await;
                        handler.link_table.remove_stale(INTERVAL_LINK_TABLE_STALE);
                        handler.reverse_table.remove_stale(INTERVAL_KEEP_REVERSE_PATH);

                        // Periodically remove expired blackhole entries
                        // (rate-limited internally to 60-second intervals).
                        if let Some(removed) = handler.blackhole_table.check_expired() {
                            if removed > 0 {
                                log::debug!(
                                    "tp({}): removed {} expired blackhole entr{}",
                                    handler.config.name,
                                    removed,
                                    if removed == 1 { "y" } else { "ies" },
                                );
                            }
                        }

                        let transport_name = handler.config.name.clone();
                        let link_fwd_max = handler.link_table.forward_stats();
                        let active_ifaces: HashSet<AddressHash> = handler
                            .send_ctx
                            .iface_manager
                            .lock()
                            .await
                            .active_interface_addresses()
                            .into_iter()
                            .collect();
                        drop(handler);

                        // Log interface pacing metrics at trace level
                        // for troubleshooting packet flow.
                        let queues = send_ctx
                            .iface_manager
                            .lock()
                            .await
                            .queue_lengths()
                            .await;
                        for iface_q in &queues.interfaces {
                            if iface_q.packets_tx > 0 || iface_q.last_pacing_interval_us > 0 {
                                log::trace!(
                                    "tp({}): iface {} tx={} pacing_wait={}us interval={}us",
                                    transport_name,
                                    iface_q.address,
                                    iface_q.packets_tx,
                                    iface_q.pacing_wait_us,
                                    iface_q.last_pacing_interval_us,
                                );
                            }
                        }
                        if link_fwd_max.0 > 0 {
                            log::trace!(
                                "tp({}): link_table forwards total={} max_per_link={}",
                                transport_name,
                                link_fwd_max.1,
                                link_fwd_max.0,
                            );
                        }

                        send_ctx
                            .path_table
                            .write()
                            .unwrap()
                            .remove_stale(|iface| active_ifaces.contains(iface));
                    },
                }
            }
        });
    }

    {
        let send_ctx = send_ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_PATH_TABLE_CULL) => {
                        let active_ifaces: HashSet<AddressHash> = send_ctx
                            .iface_manager
                            .lock()
                            .await
                            .active_interface_addresses()
                            .into_iter()
                            .collect();

                        send_ctx
                            .path_table
                            .write()
                            .unwrap()
                            .remove_stale(|iface| active_ifaces.contains(iface));
                    },
                }
            }
        });
    }

    if retransmit {
        let handler = handler.clone();
        let send_ctx = send_ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(INTERVAL_ANNOUNCES_RETRANSMIT) => {
                        let mut pending = PendingSends::new();

                        {
                            let mut h = handler.lock().await;
                            let mut retransmit_old = false;

                            if let Some(instant) = last_retransmit_old {
                                let now = time::Instant::now();
                                if now - instant > INTERVAL_OLD_ANNOUNCES_RETRANSMIT {
                                    retransmit_old = true;
                                    last_retransmit_old = Some(now);
                                }
                            }

                            retransmit_announces(&mut *h, &mut pending, retransmit_old).await;
                        }

                        pending.flush(&send_ctx).await;
                    }
                }
            }
        });
    }
}

/// How long to wait before the first blackhole update cycle.
const BLACKHOLE_INITIAL_WAIT: Duration = Duration::from_secs(20);

/// The maximum time to wait for a link to activate.
const BLACKHOLE_LINK_TIMEOUT: Duration = Duration::from_secs(25);

/// The maximum time to wait for a blackhole list response.
const BLACKHOLE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Background task that periodically fetches blackhole lists from remote
/// sources.  Spawned by [`Transport::new`] when `blackhole_sources` is
/// non-empty.  Protocol-compatible with the Python `BlackholeUpdater`.
async fn blackhole_updater_job(
    handler: Arc<Mutex<TransportHandler>>,
    send_ctx: Arc<SendCtx>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    event_tx: broadcast::Sender<LinkEventData>,
    name: String,
    update_interval: Duration,
    cancel: CancellationToken,
) {
    tokio::time::sleep(BLACKHOLE_INITIAL_WAIT).await;

    let mut last_updates: HashMap<AddressHash, time::Instant> = HashMap::new();
    let mut iteration: u64 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                log::debug!("tp({name}): blackhole updater cancelled");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }

        iteration += 1;
        log::trace!("tp({name}): blackhole updater iteration {iteration}");

        let sources: Vec<AddressHash> = {
            let handler = handler.lock().await;
            handler.config.blackhole_sources.clone()
        };

        let now = time::Instant::now();

        for source_hash in &sources {
            let should_update = match last_updates.get(source_hash) {
                Some(last) => {
                    let elapsed = now.saturating_duration_since(*last);
                    let due = elapsed >= update_interval;
                    log::trace!(
                        "tp({name}): blackhole source {source_hash} last update {:.0}s ago, {}",
                        elapsed.as_secs_f64(),
                        if due { "due" } else { "skipping" },
                    );
                    due
                }
                None => {
                    log::trace!("tp({name}): blackhole source {source_hash} never updated, due",);
                    true
                }
            };
            if !should_update {
                continue;
            }

            log::trace!(
                "tp({name}): computing destination hash for blackhole source {source_hash}",
            );
            let dest_hash = blackhole::blackhole_destination_hash(source_hash);
            log::trace!(
                "tp({name}): blackhole destination hash {dest_hash} for source {source_hash}",
            );

            let has_path = send_ctx
                .path_table
                .read()
                .unwrap()
                .get(&dest_hash)
                .is_some();
            if !has_path {
                log::debug!(
                    "tp({name}): no path to blackhole source {source_hash} (dest {dest_hash}), skipping"
                );
                continue;
            }
            log::trace!("tp({name}): found path to blackhole destination {dest_hash}",);

            let dest_desc = {
                let handler = handler.lock().await;
                handler.single_out_destinations.get(&dest_hash).cloned()
            };
            let dest_desc = if let Some(d) = dest_desc {
                Some(d.lock().await.desc.clone())
            } else {
                None
            };

            let desc = match dest_desc {
                Some(desc) => {
                    log::trace!(
                        "tp({name}): resolved blackhole destination {dest_hash} to identity {}",
                        desc.identity.address_hash,
                    );
                    desc
                }
                None => {
                    log::warn!(
                        "tp({name}): blackhole source {source_hash} (dest {dest_hash}) has path but no destination desc",
                    );
                    continue;
                }
            };

            log::info!("tp({name}): updating blackhole list from {source_hash} (dest {dest_hash})");

            match update_blackhole_from_source(
                &handler,
                &send_ctx,
                &iface_manager,
                &event_tx,
                &name,
                desc,
                *source_hash,
                dest_hash,
            )
            .await
            {
                Ok(count) => {
                    last_updates.insert(*source_hash, now);
                    log::info!(
                        "tp({name}): blackhole update from {source_hash} complete, {count} new entries"
                    );
                }
                Err(e) => {
                    log::warn!("tp({name}): blackhole update from {source_hash} failed: {e}");
                }
            }
        }

        if sources.is_empty() {
            log::trace!(
                "tp({name}): blackhole updater iteration {iteration}: no sources configured"
            );
        }
    }
}

/// Establish a link to a blackhole source, send a `/list` request, and merge
/// the response into the local [`BlackholeTable`].
///
/// Returns `Ok(inserted_count)` on success (even if the response contained no
/// new entries or was in an unexpected format), or `Err(reason)` on connection
/// / protocol failure.
async fn update_blackhole_from_source(
    handler: &Arc<Mutex<TransportHandler>>,
    send_ctx: &Arc<SendCtx>,
    iface_manager: &Arc<Mutex<InterfaceManager>>,
    event_tx: &broadcast::Sender<LinkEventData>,
    name: &str,
    dest_desc: DestinationDesc,
    source_hash: AddressHash,
    dest_hash: AddressHash,
) -> Result<usize, String> {
    log::trace!("tp({name}): starting blackhole fetch from {source_hash} (dest {dest_hash})",);
    let mut rx = event_tx.subscribe();

    let path_mtu = {
        let handler_locked = handler.lock().await;
        if handler_locked.config.link_mtu_discovery {
            let iface_addr = send_ctx
                .path_table
                .read()
                .unwrap()
                .next_hop_iface(&dest_hash);
            if let Some(iface) = iface_addr {
                let mtu = iface_manager.lock().await.hw_mtu(&iface);
                log::trace!("tp({name}): blackhole link path_mtu={mtu:?} via iface {iface}",);
                mtu
            } else {
                log::trace!("tp({name}): blackhole link no next-hop iface found");
                None
            }
        } else {
            None
        }
    };

    let mut link = Link::new(dest_desc, event_tx.clone());
    let link_id = {
        let packet = link.request(path_mtu);
        let link_id = *link.id();
        log::debug!("tp({name}): blackhole updater created link {link_id} to {dest_hash}",);
        send_ctx.send_packet(name, packet).await;
        link_id
    };

    let link_arc = Arc::new(Mutex::new(link));
    handler
        .lock()
        .await
        .out_links
        .insert(dest_hash, link_arc.clone());

    log::trace!(
        "tp({name}): waiting for blackhole link {link_id} to activate (timeout {:.0}s)",
        BLACKHOLE_LINK_TIMEOUT.as_secs_f64(),
    );
    let activated = async {
        loop {
            match rx.recv().await {
                Ok(data) => {
                    if data.id == link_id && matches!(data.event, LinkEvent::Activated) {
                        return true;
                    }
                    if data.id == link_id && matches!(data.event, LinkEvent::Closed) {
                        log::trace!(
                            "tp({name}): blackhole link {link_id} closed while waiting for activation",
                        );
                        return false;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::trace!(
                        "tp({name}): blackhole link event receiver lagged by {n} messages, retrying",
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    log::trace!("tp({name}): blackhole link event channel closed",);
                    return false;
                }
            }
        }
    };

    if !tokio::time::timeout(BLACKHOLE_LINK_TIMEOUT, activated)
        .await
        .map_err(|_| "link activation timeout".to_string())?
    {
        return Err("link closed before activation".to_string());
    }

    log::debug!("tp({name}): blackhole link {link_id} activated");

    let request_packet = {
        let link_locked = link_arc.lock().await;
        link_locked
            .request_packet("/list", Value::Map(vec![]))
            .map_err(|e| format!("request packet error: {e}"))?
    };
    let request_id = AddressHash::new_from_hash(&request_packet.hash());
    log::trace!(
        "tp({name}): sending /list request {request_id} ({}) on link {link_id}",
        request_packet.data.len(),
    );
    send_ctx.send_packet(name, request_packet).await;

    log::debug!("tp({name}): sent /list request {request_id} on link {link_id}");

    let response_received = async {
        loop {
            match rx.recv().await {
                Ok(data) => {
                    if data.id == link_id {
                        match data.event {
                            LinkEvent::Response(resp) if resp.request_id == request_id => {
                                return Some(resp.data);
                            }
                            LinkEvent::Closed => {
                                log::trace!(
                                    "tp({name}): blackhole link {link_id} closed while waiting for response",
                                );
                                return None;
                            }
                            LinkEvent::Response(resp) => {
                                log::trace!(
                                    "tp({name}): blackhole link {link_id} got response for different request {resp_request_id}, ignoring",
                                    resp_request_id = resp.request_id,
                                );
                            }
                            _ => {}
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::trace!("tp({name}): blackhole response receiver lagged by {n}, retrying",);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    log::trace!("tp({name}): blackhole response channel closed",);
                    return None;
                }
            }
        }
    };

    let response = tokio::time::timeout(BLACKHOLE_RESPONSE_TIMEOUT, response_received)
        .await
        .map_err(|_| "response timeout".to_string())?
        .ok_or("link closed before response".to_string())?;

    log::debug!("tp({name}): received blackhole list on link {link_id}");

    let inserted = if let Value::Map(entries) = &response {
        log::trace!(
            "tp({name}): blackhole response contains {} entry(ies)",
            entries.len(),
        );
        let mut inserted = 0usize;
        let mut skipped_bad_key = 0usize;
        let mut skipped_existing = 0usize;
        {
            let mut handler_locked = handler.lock().await;
            for (k, v) in entries {
                if let Some(identity_bytes) = k.as_slice() {
                    if identity_bytes.len() != AddressHash::new_empty().as_slice().len() {
                        skipped_bad_key += 1;
                        continue;
                    }
                    let mut identity_hash = AddressHash::new_empty();
                    identity_hash.as_mut_slice().copy_from_slice(identity_bytes);
                    if let Some(entry) = blackhole::BlackholeEntry::from_msgpack(v, source_hash) {
                        if handler_locked
                            .blackhole_table
                            .insert_remote_entry(identity_hash, entry)
                        {
                            inserted += 1;
                        } else {
                            skipped_existing += 1;
                        }
                    }
                }
            }
        }
        log::trace!(
            "tp({name}): blackhole response summary: {inserted} new, {skipped_existing} existing, {skipped_bad_key} bad keys",
        );
        inserted
    } else {
        log::warn!(
            "tp({name}): unexpected blackhole response format from {source_hash}: expected Map, got {:?}",
            response
        );
        0
    };

    log::trace!("tp({name}): tearing down blackhole link {link_id} to {dest_hash}",);
    handler.lock().await.out_links.remove(&dest_hash);

    log::trace!("tp({name}): blackhole fetch from {source_hash} complete, {inserted} new entries",);

    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
    use crate::packet::{HeaderType, PACKET_MDU};
    use std::net::TcpListener as StdTcpListener;

    fn free_local_ports(count: usize) -> Option<Vec<u16>> {
        let listeners = (0..count)
            .map(|_| StdTcpListener::bind("127.0.0.1:0").ok())
            .collect::<Option<Vec<_>>>()?;

        listeners
            .iter()
            .map(|listener| listener.local_addr().ok().map(|addr| addr.port()))
            .collect()
    }

    #[test]
    fn shared_instance_config_matches_python_names() {
        let mut config = TransportConfig::default();

        assert!(!config.share_instance());
        assert_eq!(config.shared_instance_type(), SharedInstanceType::Tcp);
        assert_eq!(config.shared_instance_port(), DEFAULT_SHARED_INSTANCE_PORT);
        assert_eq!(
            config.instance_control_port(),
            DEFAULT_INSTANCE_CONTROL_PORT
        );
        assert_eq!(config.instance_name(), DEFAULT_INSTANCE_NAME);
        assert!(!config.require_shared_instance());
        assert!(config.rpc_key().is_none());

        config.set_share_instance(true);
        config.set_require_shared_instance(true);
        config.set_shared_instance_type(SharedInstanceType::Unix);
        config.set_shared_instance_port(40000);
        config.set_instance_control_port(40001);
        config.set_instance_name("mesh-a");
        config.set_rpc_key(vec![0x42; 24]);

        assert!(config.share_instance());
        assert!(config.require_shared_instance());
        assert_eq!(config.shared_instance_type(), SharedInstanceType::Unix);
        assert_eq!(config.shared_instance_port(), 40000);
        assert_eq!(config.instance_control_port(), 40001);
        assert_eq!(config.instance_name(), "mesh-a");
        assert_eq!(config.rpc_key(), Some(vec![0x42; 24].as_slice()));
    }

    #[test]
    fn shared_instance_rpc_key_hex_matches_python_config_parsing() {
        let mut config = TransportConfig::default();

        config
            .set_rpc_key_hex("e5 c032D3")
            .expect("valid Python-style hex key");

        assert_eq!(config.rpc_key(), Some([0xe5, 0xc0, 0x32, 0xd3].as_slice()));
        assert!(config.set_rpc_key_hex("not hex").is_err());
        assert!(config.set_rpc_key_hex("abc").is_err());
    }

    fn inbound_packet_for_rebroadcast() -> Packet {
        let mut packet: Packet = Default::default();
        packet.header.header_type = HeaderType::Type1;
        packet.header.propagation_type = PropagationType::Broadcast;
        packet.header.destination_type = DestinationType::Plain;
        packet.header.packet_type = PacketType::Data;
        packet.header.hops = 1;
        packet
    }

    #[test]
    fn repeats_only_first_hop_plain_broadcast_packets() {
        let packet = inbound_packet_for_rebroadcast();
        assert!(should_rebroadcast_inbound_packet(&packet));

        let mut already_forwarded = packet.clone();
        already_forwarded.header.hops = 2;
        assert!(!should_rebroadcast_inbound_packet(&already_forwarded));

        let mut transported = packet.clone();
        transported.header.header_type = HeaderType::Type2;
        transported.header.propagation_type = PropagationType::Transport;
        transported.transport = Some(AddressHash::new_from_slice(b"next-hop"));
        assert!(!should_rebroadcast_inbound_packet(&transported));
    }

    #[test]
    fn routed_packet_types_are_not_blindly_rebroadcast() {
        let mut packet = inbound_packet_for_rebroadcast();

        packet.header.destination_type = DestinationType::Single;
        assert!(!should_rebroadcast_inbound_packet(&packet));

        packet.header.destination_type = DestinationType::Link;
        assert!(!should_rebroadcast_inbound_packet(&packet));

        packet.header.destination_type = DestinationType::Plain;
        packet.header.packet_type = PacketType::Proof;
        assert!(!should_rebroadcast_inbound_packet(&packet));

        packet.header.packet_type = PacketType::LinkRequest;
        assert!(!should_rebroadcast_inbound_packet(&packet));

        packet.header.packet_type = PacketType::Announce;
        assert!(!should_rebroadcast_inbound_packet(&packet));
    }

    #[tokio::test]
    async fn tcp_share_instance_first_server_second_client() {
        let Some(ports) = free_local_ports(1) else {
            eprintln!("skipping local shared instance test; TCP bind unavailable");
            return;
        };
        let port = ports[0];

        let mut first_config = TransportConfig::default();
        first_config.set_share_instance(true);
        first_config.set_shared_instance_port(port);
        let first = Transport::new(first_config);

        assert!(first.is_shared_instance().await);
        assert!(!first.is_connected_to_shared_instance().await);
        assert!(!first.is_standalone_instance().await);

        let mut second_config = TransportConfig::default();
        second_config.set_share_instance(true);
        second_config.set_shared_instance_port(port);
        let second = Transport::new(second_config);

        assert!(!second.is_shared_instance().await);
        assert!(second.is_connected_to_shared_instance().await);
        assert!(!second.is_standalone_instance().await);
    }

    #[tokio::test]
    async fn shared_rpc_returns_first_hop_timeout() {
        let Some(ports) = free_local_ports(2) else {
            eprintln!("skipping shared RPC test; TCP bind unavailable");
            return;
        };

        let rpc_key = b"test-rpc-key".to_vec();
        let mut config = TransportConfig::default();
        config.set_share_instance(true);
        config.set_shared_instance_port(ports[0]);
        config.set_instance_control_port(ports[1]);
        config.set_rpc_key(rpc_key.clone());
        let _transport = Transport::new(config);

        let addr = format!("127.0.0.1:{}", ports[1]);
        let mut stream = None;
        for _ in 0..20 {
            match TcpStream::connect(&addr).await {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(_) => time::sleep(Duration::from_millis(25)).await,
            }
        }
        let mut stream = stream.expect("RPC listener accepts connection");

        let challenge = read_py_connection_frame(&mut stream, 256)
            .await
            .expect("challenge frame");
        assert!(challenge.starts_with(PY_CONN_CHALLENGE));
        let response = shared_rpc_hmac_response(&rpc_key, &challenge[PY_CONN_CHALLENGE.len()..])
            .expect("hmac response");
        write_py_connection_frame(&mut stream, &response)
            .await
            .expect("response frame");
        let welcome = read_py_connection_frame(&mut stream, 256)
            .await
            .expect("welcome frame");
        assert_eq!(welcome.as_slice(), PY_CONN_WELCOME);
        complete_client_side_mutual_auth(&mut stream, &rpc_key).await;

        let request = Value::Map(vec![
            (Value::from("get"), Value::from("first_hop_timeout")),
            (
                Value::from("destination_hash"),
                Value::Binary(vec![0u8; crate::hash::ADDRESS_HASH_SIZE]),
            ),
        ]);
        let encoded = write_python_pickle_value(&request).expect("encoded request");
        write_py_connection_frame(&mut stream, &encoded)
            .await
            .expect("request frame");

        let response = read_py_connection_frame(&mut stream, 256)
            .await
            .expect("response frame");
        let response = read_shared_rpc_value(&response).expect("decoded response");
        assert_eq!(response.as_u64(), Some(DEFAULT_PER_HOP_TIMEOUT_SECS));
    }

    #[tokio::test]
    async fn shared_data_port_does_not_write_rpc_auth_probe_to_hdlc_clients() {
        let Some(ports) = free_local_ports(2) else {
            eprintln!("skipping shared data-port silence test; TCP bind unavailable");
            return;
        };

        let mut config = TransportConfig::default();
        config.set_share_instance(true);
        config.set_shared_instance_port(ports[0]);
        config.set_instance_control_port(ports[1]);
        let _transport = Transport::new(config);

        let addr = format!("127.0.0.1:{}", ports[0]);
        let mut stream = None;
        for _ in 0..20 {
            match TcpStream::connect(&addr).await {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(_) => time::sleep(Duration::from_millis(25)).await,
            }
        }
        let mut stream = stream.expect("shared data listener accepts connection");

        let mut buffer = [0u8; 1];
        let read = time::timeout(Duration::from_millis(250), stream.read(&mut buffer)).await;
        assert!(read.is_err(), "shared data port wrote non-HDLC bytes");
    }

    #[tokio::test]
    async fn shared_rpc_derives_default_key_from_transport_identity() {
        let Some(ports) = free_local_ports(2) else {
            eprintln!("skipping shared RPC auth test; TCP bind unavailable");
            return;
        };

        let identity = PrivateIdentity::new_from_name("shared-rpc-default-key-test");
        let rpc_key = identity.shared_instance_rpc_key();
        let mut config = TransportConfig::new("shared-rpc-default-key-test", &identity, false);
        config.set_share_instance(true);
        config.set_shared_instance_port(ports[0]);
        config.set_instance_control_port(ports[1]);
        let _transport = Transport::new(config);

        let addr = format!("127.0.0.1:{}", ports[1]);
        let mut stream = None;
        for _ in 0..20 {
            match TcpStream::connect(&addr).await {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(_) => time::sleep(Duration::from_millis(25)).await,
            }
        }
        let mut stream = stream.expect("RPC listener accepts connection");

        let challenge = read_py_connection_frame(&mut stream, 256)
            .await
            .expect("challenge frame");
        let response = shared_rpc_hmac_response(&rpc_key, &challenge[PY_CONN_CHALLENGE.len()..])
            .expect("hmac response");
        write_py_connection_frame(&mut stream, &response)
            .await
            .expect("response frame");

        let welcome = read_py_connection_frame(&mut stream, 256)
            .await
            .expect("welcome frame");
        assert_eq!(welcome.as_slice(), PY_CONN_WELCOME);
        complete_client_side_mutual_auth(&mut stream, &rpc_key).await;
    }

    async fn complete_client_side_mutual_auth(stream: &mut TcpStream, rpc_key: &[u8]) {
        let peer_challenge = shared_rpc_challenge();
        write_py_connection_frame(stream, &peer_challenge)
            .await
            .expect("peer challenge frame");

        let response = read_py_connection_frame(stream, PY_CONN_AUTH_MAX_FRAME)
            .await
            .expect("peer response frame");
        assert!(
            shared_rpc_response_is_authenticated(&peer_challenge, &response, Some(rpc_key))
                .expect("peer response verification")
        );

        write_py_connection_frame(stream, PY_CONN_WELCOME)
            .await
            .expect("peer welcome frame");
    }

    #[test]
    fn shared_rpc_handles_python_client_requests() {
        let expected = [
            ("path_table", Value::Array(vec![])),
            ("rate_table", Value::Array(vec![])),
            ("next_hop_if_name", Value::from("None")),
            ("next_hop", Value::Nil),
            (
                "first_hop_timeout",
                Value::from(DEFAULT_PER_HOP_TIMEOUT_SECS),
            ),
            ("link_count", Value::from(0)),
            ("packet_rssi", Value::Nil),
            ("packet_snr", Value::Nil),
            ("packet_q", Value::Nil),
            ("blackholed_identities", Value::Map(vec![])),
            ("is_blackholed", Value::Boolean(false)),
        ];

        for (operation, response) in expected {
            let request = Value::Map(vec![(Value::from("get"), Value::from(operation))]);
            let actual = handle_shared_rpc_request(&request, None);
            assert_eq!(actual, response);

            let encoded = write_shared_rpc_value(&actual).expect("encoded response");
            let decoded = read_msgpack_value(&encoded).expect("decoded response");
            assert_eq!(decoded, response);
        }

        let request = Value::Map(vec![(Value::from("get"), Value::from("interface_stats"))]);
        let response = handle_shared_rpc_request(&request, None);
        let stats = response.as_map().expect("interface stats dict");
        assert_eq!(
            shared_rpc_map_value(stats, "interfaces"),
            Some(&Value::Array(vec![]))
        );
        assert_eq!(
            shared_rpc_map_value(stats, "rxb").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            shared_rpc_map_value(stats, "txb").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            shared_rpc_map_value(stats, "rxs").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            shared_rpc_map_value(stats, "txs").and_then(Value::as_u64),
            Some(0)
        );

        let encoded = write_shared_rpc_value(&response).expect("encoded stats response");
        let decoded = read_msgpack_value(&encoded).expect("decoded stats response");
        assert_eq!(decoded, response);

        let request = Value::Map(vec![(
            Value::from("destination_data"),
            Value::from("retain"),
        )]);
        let response = handle_shared_rpc_request(&request, None);
        assert_eq!(response, Value::Boolean(false));

        let request = Value::Map(vec![(Value::from("identity_data"), Value::from("retain"))]);
        let response = handle_shared_rpc_request(&request, None);
        assert_eq!(response, Value::Boolean(false));

        let unsupported = Value::Map(vec![(Value::from("get"), Value::from("unsupported"))]);
        let response = handle_shared_rpc_request(&unsupported, None);
        assert_eq!(response, Value::Boolean(false));

        let encoded = write_shared_rpc_value(&response).expect("encoded response");
        assert_eq!(encoded.first(), Some(&0xc2));
    }

    #[tokio::test]
    async fn shared_rpc_returns_known_next_hop_path_data() {
        let transport = Transport::new(Default::default());
        let handler = transport.get_handler();
        let iface = {
            let iface_manager = transport.iface_manager();
            let mut iface_manager = iface_manager.lock().await;
            *iface_manager.new_channel(4).address()
        };

        let remote_destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("example_utilities", "shared.rpc.path"),
        );
        let mut announce = remote_destination
            .announce(OsRng, None)
            .expect("valid announce");
        let destination = announce.destination;
        let next_hop = AddressHash::new_from_slice(b"next-hop-transport");

        announce.header.header_type = HeaderType::Type2;
        announce.header.propagation_type = PropagationType::Transport;
        announce.header.hops = 1;
        announce.transport = Some(next_hop);

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&announce, &mut *h, &mut pending, iface, None, None).await;
        }

        let request = Value::Map(vec![
            (Value::from("get"), Value::from("next_hop")),
            (
                Value::from("destination_hash"),
                Value::Binary(destination.as_slice().to_vec()),
            ),
        ]);
        let mut guard = handler.lock().await;
        let response = handle_shared_rpc_request(&request, Some(&mut *guard));
        assert_eq!(response, Value::Binary(next_hop.as_slice().to_vec()));

        let request = Value::Map(vec![
            (Value::from("get"), Value::from("next_hop_if_name")),
            (
                Value::from("destination_hash"),
                Value::Binary(destination.as_slice().to_vec()),
            ),
        ]);
        let response = handle_shared_rpc_request(&request, Some(&mut *guard));
        assert_eq!(response, Value::from(iface.to_string()));
    }

    #[test]
    fn shared_rpc_decodes_python_pickled_request() {
        let request = read_shared_rpc_value(&[
            0x80, 0x05, 0x95, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7d, 0x94, 0x28,
            0x8c, 0x03, b'g', b'e', b't', 0x94, 0x8c, 0x11, b'f', b'i', b'r', b's', b't', b'_',
            b'h', b'o', b'p', b'_', b't', b'i', b'm', b'e', b'o', b'u', b't', 0x94, 0x8c, 0x10,
            b'd', b'e', b's', b't', b'i', b'n', b'a', b't', b'i', b'o', b'n', b'_', b'h', b'a',
            b's', b'h', 0x94, b'C', 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, b'u', b'.',
        ])
        .expect("Python pickle request");

        let response = handle_shared_rpc_request(&request, None);
        assert_eq!(response.as_u64(), Some(DEFAULT_PER_HOP_TIMEOUT_SECS));

        let encoded = write_python_pickle_value(&response).expect("pickle response");
        assert_eq!(encoded, vec![0x80, 0x05, b'K', 0x06, b'.']);
    }

    #[test]
    fn shared_rpc_decodes_python_msgpack_request() {
        let request = read_shared_rpc_value(&[
            0x82, 0xa3, b'g', b'e', b't', 0xb1, b'f', b'i', b'r', b's', b't', b'_', b'h', b'o',
            b'p', b'_', b't', b'i', b'm', b'e', b'o', b'u', b't', 0xb0, b'd', b'e', b's', b't',
            b'i', b'n', b'a', b't', b'i', b'o', b'n', b'_', b'h', b'a', b's', b'h', 0xc4, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ])
        .expect("Python MessagePack request");

        let response = handle_shared_rpc_request(&request, None);
        assert_eq!(response.as_u64(), Some(DEFAULT_PER_HOP_TIMEOUT_SECS));

        let encoded = write_shared_rpc_value(&response).expect("MessagePack response");
        assert_eq!(encoded, vec![0x06]);
    }

    #[tokio::test]
    async fn drop_duplicates() {
        let mut config: TransportConfig = Default::default();
        config.set_retransmit(true);

        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let next_hop_iface = AddressHash::new_from_slice(&[3u8; 32]);
        let destination = AddressHash::new_from_slice(&[4u8; 32]);

        let mut announce: Packet = Default::default();
        announce.header.header_type = HeaderType::Type2;
        announce.header.packet_type = PacketType::Announce;
        announce.header.hops = 3;
        announce.transport = Some(destination);

        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&announce)
                .await
        );
        assert!(
            !handler
                .lock()
                .await
                .filter_duplicate_packets(&announce)
                .await
        );

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&announce, &mut *h, &mut pending, next_hop_iface, None, None).await;
        }

        let mut data_packet: Packet = Default::default();
        data_packet.data = PacketDataBuffer::new_from_slice(b"foo");
        data_packet.destination = destination;
        let duplicate: Packet = data_packet.clone();

        let mut different_packet = data_packet.clone();
        different_packet.data = PacketDataBuffer::new_from_slice(b"bar");

        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&data_packet)
                .await
        );
        assert!(
            !handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
        );
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&different_packet)
                .await
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        handler
            .lock()
            .await
            .send_ctx
            .packet_cache
            .lock()
            .unwrap()
            .release(Duration::from_secs(1));

        // Packet should have been removed from cache (stale)
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
        );
    }

    #[tokio::test]
    async fn rejects_packets_for_other_transport_instances() {
        let local_identity = PrivateIdentity::new_from_name("local transport");
        let local_transport_id = *local_identity.address_hash();
        let mut config = TransportConfig::new("transport-filter", &local_identity, true);
        config.set_retransmit(true);

        let transport = Transport::new(config);
        let handler = transport.get_handler();
        let other_transport_id = AddressHash::new_from_slice(b"other transport instance");

        let mut packet: Packet = Default::default();
        packet.header.header_type = HeaderType::Type2;
        packet.header.packet_type = PacketType::Data;
        packet.header.propagation_type = PropagationType::Transport;
        packet.transport = Some(other_transport_id);

        assert!(!handler.lock().await.accepts_transport_packet(&packet));

        packet.transport = Some(local_transport_id);
        assert!(handler.lock().await.accepts_transport_packet(&packet));

        packet.transport = Some(other_transport_id);
        packet.header.packet_type = PacketType::Announce;
        assert!(handler.lock().await.accepts_transport_packet(&packet));
    }

    #[tokio::test]
    async fn decrypts_single_destination_packets_before_emitting() {
        let mut transport = Transport::new(Default::default());
        let destination = transport
            .add_destination(
                PrivateIdentity::new_from_rand(OsRng),
                DestinationName::new("example_utilities", "single.decrypt"),
            )
            .await;

        let destination_desc = destination.lock().await.desc;
        let output_destination = SingleOutputDestination::new_from_desc(destination_desc);
        let packet = output_destination
            .data_packet(b"plaintext payload")
            .expect("encrypted packet");

        let iface = AddressHash::new_from_rand(OsRng);
        let handler = transport.get_handler();
        let mut events = transport.received_data_events();

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_data(&packet, iface, &mut *h, &mut pending).await;
        }

        let received = events.recv().await.expect("received data event");
        assert_eq!(received.destination, destination_desc.address_hash);
        assert_eq!(received.data.as_slice(), b"plaintext payload");
    }

    #[tokio::test]
    async fn invalid_single_destination_ciphertext_is_not_proved() {
        let mut transport = Transport::new(Default::default());
        let destination = transport
            .add_destination(
                PrivateIdentity::new_from_rand(OsRng),
                DestinationName::new("example_utilities", "single.proof"),
            )
            .await;
        destination.lock().await.set_prove_packets(true);

        let destination_desc = destination.lock().await.desc;
        let output_destination = SingleOutputDestination::new_from_desc(destination_desc);
        let mut packet = output_destination
            .data_packet(b"plaintext payload")
            .expect("encrypted packet");
        let last = packet.data.len() - 1;
        packet.data.as_mut_slice()[last] ^= 0x01;

        let handler = transport.get_handler();
        let (iface, mut tx) = {
            let iface_manager = transport.iface_manager();
            let mut iface_manager = iface_manager.lock().await;
            let channel = iface_manager.new_channel(4);
            (*channel.address(), channel.tx_channel)
        };

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_data(&packet, iface, &mut *h, &mut pending).await;
        }

        assert!(
            time::timeout(Duration::from_millis(100), tx.recv())
                .await
                .is_err(),
            "invalid ciphertext must not receive a packet proof"
        );
    }

    #[tokio::test]
    async fn send_packet_uses_known_multihop_path() {
        let transport = Transport::new(Default::default());
        let handler = transport.get_handler();
        let (iface, mut tx) = {
            let iface_manager = transport.iface_manager();
            let mut iface_manager = iface_manager.lock().await;
            let channel = iface_manager.new_channel(4);
            (*channel.address(), channel.tx_channel)
        };

        let remote_destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("example_utilities", "known.path"),
        );
        let mut announce = remote_destination
            .announce(OsRng, None)
            .expect("valid announce");
        let destination = announce.destination;
        let next_hop = AddressHash::new_from_slice(b"next-hop-transport");

        announce.header.header_type = HeaderType::Type2;
        announce.header.propagation_type = PropagationType::Transport;
        announce.header.hops = 2;
        announce.transport = Some(next_hop);

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&announce, &mut *h, &mut pending, iface, None, None).await;
        }

        let mut packet: Packet = Default::default();
        packet.header.destination_type = DestinationType::Single;
        packet.header.packet_type = PacketType::Data;
        packet.destination = destination;
        packet.data = PacketDataBuffer::new_from_slice(b"payload");

        transport.send_packet(packet).await;

        let sent = time::timeout(Duration::from_secs(1), tx.recv())
            .await
            .expect("routed packet")
            .expect("routed packet message");

        assert_eq!(sent.tx_type, TxMessageType::Direct(iface));
        assert_eq!(sent.packet.header.header_type, HeaderType::Type2);
        assert_eq!(
            sent.packet.header.propagation_type,
            PropagationType::Transport
        );
        assert_eq!(sent.packet.destination, destination);
        assert_eq!(sent.packet.transport, Some(next_hop));
    }

    #[tokio::test]
    async fn path_response_bypasses_announce_rate_limits() {
        let transport = Transport::new(Default::default());
        let handler = transport.get_handler();
        let remote_destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("example_utilities", "path.response"),
        );
        let path_response = remote_destination
            .path_response(OsRng, None)
            .expect("valid path response");
        let iface = AddressHash::new_from_rand(OsRng);

        {
            let mut guard = handler.lock().await;
            guard
                .announce_limits
                .force_block(path_response.destination, Duration::from_secs(60));
        }

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&path_response, &mut *h, &mut pending, iface, None, None).await;
        }

        assert!(
            handler
                .lock()
                .await
                .send_ctx
                .path_table
                .read()
                .unwrap()
                .get(&path_response.destination)
                .is_some(),
            "path response should still populate the path table",
        );
    }

    #[tokio::test]
    async fn metrics_snapshot_reflects_transport_state() {
        let transport = Transport::new(Default::default());
        let handler = transport.get_handler();
        let remote_destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("example_utilities", "metrics.path"),
        );
        let announce = remote_destination
            .announce(OsRng, None)
            .expect("valid announce");
        let iface = AddressHash::new_from_rand(OsRng);

        // Before any traffic
        let m = transport.metrics().await;
        assert_eq!(m.path_table_entries, 0);
        assert_eq!(m.announce_table_entries, 0);
        assert_eq!(m.packets_dropped_duplicate, 0);
        assert_eq!(m.announces_rate_limited, 0);
        assert_eq!(m.decryption_failures, 0);
        assert_eq!(m.link_table_entries, 0);
        assert_eq!(m.reverse_table_entries, 0);
        assert_eq!(m.active_out_links, 0);
        assert_eq!(m.active_in_links, 0);
        assert_eq!(m.total_out_links, 0);
        assert_eq!(m.total_in_links, 0);
        assert_eq!(m.pending_path_requests, 0);
        assert_eq!(m.active_interfaces, 0);

        // Process an announce
        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&announce, &mut *h, &mut pending, iface, None, None).await;
        }

        let m = transport.metrics().await;
        assert_eq!(m.path_table_entries, 1);
        // announce_table should have one entry after handle_announce
        assert_eq!(m.announce_table_entries, 1);
        // packet cache is updated in the main processing loop, not inside handle_announce,
        // so we don't check it here
    }

    #[tokio::test]
    async fn metrics_track_rate_limited_announces() {
        let transport = Transport::new(Default::default());
        let handler = transport.get_handler();
        let remote_destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("example_utilities", "metrics.limit"),
        );
        let announce = remote_destination
            .announce(OsRng, None)
            .expect("valid announce");
        let iface = AddressHash::new_from_rand(OsRng);

        // Force-block the destination so the next announce is rate-limited
        {
            let mut guard = handler.lock().await;
            guard
                .announce_limits
                .force_block(announce.destination, Duration::from_secs(60));
        }

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&announce, &mut *h, &mut pending, iface, None, None).await;
        }

        let m = transport.metrics().await;
        assert_eq!(m.announces_rate_limited, 1);
        // The announnce should NOT have populated the path table
        assert_eq!(m.path_table_entries, 0);
    }

    #[tokio::test]
    async fn retransmit_keeps_multiple_aspects_for_same_identity() {
        let identity = PrivateIdentity::new_from_name("lxst-test-identity");
        let first_destination = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("lxst", "telephony"),
        );
        let second_destination =
            SingleInputDestination::new(identity, DestinationName::new("lxst", "messaging"));
        let first_announce = first_destination
            .announce(OsRng, None)
            .expect("valid first announce");
        let second_announce = second_destination
            .announce(OsRng, None)
            .expect("valid second announce");

        let mut config = TransportConfig::default();
        config.set_retransmit(true);
        let transport_id = config.identity.address_hash().clone();
        let transport = Transport::new(config);
        let handler = transport.get_handler();
        let iface = AddressHash::new_from_rand(OsRng);

        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&first_announce, &mut *h, &mut pending, iface, None, None).await;
        }
        let mut pending = PendingSends::new();
        {
            let mut h = handler.lock().await;
            handle_announce(&second_announce, &mut *h, &mut pending, iface, None, None).await;
        }

        let mut guard = handler.lock().await;
        guard.announce_table.reset_retransmit_timers();
        let retransmitted = guard.announce_table.to_retransmit(&transport_id);
        let destinations: Vec<_> = retransmitted
            .iter()
            .map(|message| message.packet.destination)
            .collect();

        assert!(destinations.contains(&first_announce.destination));
        assert!(destinations.contains(&second_announce.destination));
    }

    #[tokio::test]
    async fn retransmit_sends_multiple_aspects_between_interfaces() {
        let identity = PrivateIdentity::new_from_name("lxst-interface-identity");
        let first_destination = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new("lxst", "telephony"),
        );
        let second_destination =
            SingleInputDestination::new(identity, DestinationName::new("lxst", "messaging"));
        let first_announce = first_destination
            .announce(OsRng, None)
            .expect("valid first announce");
        let large_agent_data = [0x42u8; PACKET_MDU + 1];
        let second_announce = second_destination
            .announce(OsRng, Some(&large_agent_data))
            .expect("valid second announce");

        let mut config = TransportConfig::default();
        config.set_retransmit(true);
        let transport = Transport::new(config);
        let (in_address, in_rx, mut out_tx) = {
            let iface_manager = transport.iface_manager();
            let mut iface_manager = iface_manager.lock().await;
            let in_channel = iface_manager.new_channel(4);
            let out_channel = iface_manager.new_channel(4);
            (
                *in_channel.address(),
                in_channel.rx_channel.clone(),
                out_channel.tx_channel,
            )
        };

        in_rx
            .send(RxMessage {
                address: in_address,
                snr: None,
                rssi: None,
                packet: first_announce,
            })
            .await
            .expect("queued first announce");
        in_rx
            .send(RxMessage {
                address: in_address,
                snr: None,
                rssi: None,
                packet: second_announce,
            })
            .await
            .expect("queued second announce");

        let first_retransmit = time::timeout(Duration::from_secs(2), out_tx.recv())
            .await
            .expect("first retransmit")
            .expect("first retransmit message");
        let second_retransmit = time::timeout(Duration::from_secs(2), out_tx.recv())
            .await
            .expect("second retransmit")
            .expect("second retransmit message");
        let destinations = [
            first_retransmit.packet.destination,
            second_retransmit.packet.destination,
        ];

        assert!(destinations.contains(&first_destination.desc.address_hash));
        assert!(destinations.contains(&second_destination.desc.address_hash));
    }
}
