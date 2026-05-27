use alloc::sync::Arc;
use announce_limits::AnnounceLimits;
use announce_table::AnnounceTable;
use discovery::create_discovery_destination;
use discovery::is_discovery_destination;
use discovery::RegisteredDiscoveryInterface;
use discovery::DISCOVERY_JOB_INTERVAL;
use link_table::LinkTable;
use packet_cache::PacketCache;
use path_requests::create_path_request_destination;
use path_requests::PathRequests;
use path_requests::TagBytes;
use path_table::PathTable;
use rand_core::OsRng;
use reverse_table::ReverseTable;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time;
use tokio_util::sync::CancellationToken;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use crate::destination::link::Link;
use crate::destination::link::LinkEventData;
use crate::destination::link::LinkHandleResult;
use crate::destination::link::LinkId;
use crate::destination::link::LinkStatus;
use crate::destination::DestinationAnnounce;
use crate::destination::DestinationDesc;
use crate::destination::DestinationHandleStatus;
use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::destination::SingleOutputDestination;

use crate::error::RnsError;

use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::identity::PrivateIdentity;

use crate::iface::InterfaceManager;
use crate::iface::InterfaceRxReceiver;
use crate::iface::RxMessage;
use crate::iface::TxMessage;
use crate::iface::TxMessageType;

use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;

mod announce_limits;
mod announce_table;
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
const INTERVAL_INPUT_LINK_STALE: Duration = Duration::from_secs(10);
const INTERVAL_INPUT_LINK_CLOSE: Duration = Duration::from_secs(5);
const INTERVAL_OUTPUT_LINK_RESTART: Duration = Duration::from_secs(60);
const INTERVAL_OUTPUT_LINK_STALE: Duration = Duration::from_secs(10);
const INTERVAL_OUTPUT_LINK_CLOSE: Duration = Duration::from_secs(5);
const INTERVAL_OUTPUT_LINK_REPEAT: Duration = Duration::from_secs(6);
const INTERVAL_OUTPUT_LINK_KEEP: Duration = Duration::from_secs(5);
const INTERVAL_IFACE_CLEANUP: Duration = Duration::from_secs(10);
const INTERVAL_ANNOUNCES_RETRANSMIT: Duration = Duration::from_secs(1);
const INTERVAL_OLD_ANNOUNCES_RETRANSMIT: Duration = Duration::from_secs(60);
const INTERVAL_KEEP_PACKET_CACHED: Duration = Duration::from_secs(180);
const INTERVAL_PACKET_CACHE_CLEANUP: Duration = Duration::from_secs(90);
const INTERVAL_KEEP_REVERSE_PATH: Duration = Duration::from_secs(8 * 60);

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

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
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub app_data: PacketDataBuffer,
}

struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    announce_tx: broadcast::Sender<AnnounceEvent>,
    discovery_tx: broadcast::Sender<DiscoveredInterface>,

    path_table: PathTable,
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

    packet_cache: Mutex<PacketCache>,

    path_requests: PathRequests,

    link_in_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,

    fixed_dest_path_requests: AddressHash,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    discovery_tx: broadcast::Sender<DiscoveredInterface>,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_out_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
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
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let (announce_tx, _) = tokio::sync::broadcast::channel(16);
        let (discovery_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (received_data_tx, _) = tokio::sync::broadcast::channel(16);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(16);

        let iface_manager = InterfaceManager::new(16);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let transport_id = if config.retransmit {
            Some(config.identity.address_hash().clone())
        } else {
            None
        };
        let path_requests = PathRequests::new(config.name.as_str(), transport_id);

        let path_request_dest = create_path_request_destination().desc.address_hash;
        let discovery_destination =
            Arc::new(Mutex::new(create_discovery_destination(config.identity.clone())));
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
            single_in_destinations.insert(address_hash, destination);
            address_hash
        });
        let probe_destination = probe_destination
            .and_then(|address_hash| single_in_destinations.get(&address_hash).cloned());

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let reroute_eager = config.reroute_eager;
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            announce_table: AnnounceTable::new(),
            link_table: LinkTable::new(),
            path_table: PathTable::new(reroute_eager),
            reverse_table: ReverseTable::new(),
            single_in_destinations,
            single_out_destinations: HashMap::new(),
            probe_destination,
            discovery_destination,
            discoverable_ifaces: HashMap::new(),
            announce_limits: AnnounceLimits::new(),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            path_requests,
            announce_tx,
            discovery_tx: discovery_tx.clone(),
            link_in_event_tx: link_in_event_tx.clone(),
            received_data_tx: received_data_tx.clone(),
            fixed_dest_path_requests: path_request_dest,
            cancel: cancel.clone(),
        }));

        {
            let handler = handler.clone();
            tokio::spawn(manage_transport(
                handler,
                rx_receiver,
                iface_messages_tx.clone(),
            ))
        };

        Self {
            name,
            discovery_tx,
            iface_manager,
            link_in_event_tx,
            link_out_event_tx,
            received_data_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        let (packet, maybe_iface) = self
            .handler
            .lock()
            .await
            .path_table
            .handle_packet(packet);

        if let Some(iface) = maybe_iface {
            self.send_direct(iface, packet.clone()).await;
            log::trace!("Sent outbound packet to {}", iface);
        }

        // TODO handle other cases
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    pub fn recv_discovery(&self) -> broadcast::Receiver<DiscoveredInterface> {
        self.discovery_tx.subscribe()
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.handler
            .lock()
            .await
            .send_packet(
                destination
                    .lock()
                    .await
                    .announce(OsRng, app_data)
                    .expect("valid announce packet"),
            )
            .await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet,
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet,
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(
        &self,
        destination: &AddressHash,
        payload: &[u8]
    ) -> Vec<Hash> {
        let mut sent_packets = vec![];
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    sent_packets.push(packet.hash());
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
        let handler = self.handler.lock().await;
        let mut count = 0usize;
        for link in handler.in_links.values() {
            let link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
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
        self.handler.lock().await.out_links.get(link_id).cloned()
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

        let mut link = Link::new(destination, self.link_out_event_tx.clone());

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
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

    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        self.handler.lock().await.request_path(destination, on_iface, tag).await
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

    pub async fn get_in_destination(&self, address: &AddressHash)
        -> Option<Arc<Mutex<SingleInputDestination>>>
    {
        self.handler.lock().await.single_in_destinations.get(address).cloned()
    }

    pub async fn probe_destination(&self) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.handler.lock().await.probe_destination.clone()
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

        self.handler.lock().await.send_packet(packet).await;
        Ok(())
    }

    pub async fn get_out_destination(&self, address: &AddressHash)
        -> Option<Arc<Mutex<SingleOutputDestination>>>
    {
        self.handler.lock().await.single_out_destinations.get(address).cloned()
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

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    async fn send_packet(&self, packet: Packet) {
        let message = TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet,
        };

        self.send(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }

    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    fn knows_destination(&self, address: &AddressHash) -> bool {
        self.single_out_destinations.contains_key(address)
    }

    async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
        let mut allow_duplicate = false;

        match packet.header.packet_type {
            PacketType::Announce => {
                return true;
            },
            PacketType::LinkRequest => {
                allow_duplicate = true;
            },
            PacketType::Data => {
                allow_duplicate = packet.context == PacketContext::KeepAlive;
            },
            PacketType::Proof => {
                if packet.context == PacketContext::LinkRequestProof {
                    if let Some(link) = self.in_links.get(&packet.destination) {
                        if link.lock().await.status().not_yet_active() {
                            allow_duplicate = true;
                        }
                    }
                }
            },
            _ => {}
        }

        let is_new = self.packet_cache.lock().await.update(packet);

        is_new || allow_duplicate
    }

    async fn request_path(
        &mut self,
        address: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>
    ) {
        let packet = self.path_requests.generate(address, tag);

        self.send(TxMessage {
            tx_type: TxMessageType::Broadcast(on_iface),
            packet,
        }).await;
    }

    async fn build_discovery_packet(&mut self, iface: &AddressHash) -> Result<Packet, RnsError> {
        let config = self
            .discoverable_ifaces
            .get_mut(iface)
            .ok_or(RnsError::InvalidArgument)?;

        config.last_announce = time::Instant::now();

        let app_data = config.config.build_app_data(
            self.config.retransmit,
            self.config.identity.address_hash(),
        )?;

        self.discovery_destination
            .lock()
            .await
            .announce(OsRng, Some(app_data.as_slice()))
    }
}

async fn handle_proof<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        match link.handle_packet(packet, true) {
            LinkHandleResult::Activated => {
                let rtt_packet = link.create_rtt();
                handler.send_packet(rtt_packet).await;
            },
            _ => {}
        }
    }

    let maybe_packet = handler.link_table.handle_proof(packet);

    if let Some((packet, iface)) = maybe_packet {
        handler.send(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet
        })
        .await;
    }

    let maybe_packet = handler.reverse_table.handle_proof(packet);

    if let Some((packet, iface)) = maybe_packet {
        handler.send(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        })
        .await;
    }
}

async fn send_to_next_hop<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
    lookup: Option<AddressHash>
) -> bool {
    let (packet, maybe_iface) = handler.path_table.handle_inbound_packet(
        packet,
        lookup
    );

    if let Some(iface) = maybe_iface {
        handler.send(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        })
        .await;
    }

    maybe_iface.is_some()
}

async fn handle_keepalive_response<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>
) -> bool {
    if packet.context == PacketContext::KeepAlive {
        if packet.data.as_slice()[0] == KEEP_ALIVE_RESPONSE {
            let lookup = handler.link_table.handle_keepalive(packet);

            if let Some((propagated, iface)) = lookup {
                handler.send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: propagated,
                })
                .await;
            }

            return true;
        }
    }

    false
}

async fn handle_data<'a>(
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut data_handled = false;

    if packet.header.destination_type == DestinationType::Link {
        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().await;
            let result = link.handle_packet(packet, false);
            match result {
                LinkHandleResult::KeepAlive => {
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    handler.send_packet(packet).await;
                },
                LinkHandleResult::MessageReceived(Some(proof)) => {
                    handler.send_packet(proof).await;
                },
                _ => {}
            }
        }

        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            let _ = link.handle_packet(packet, true);
            data_handled = true;
        }

        if handle_keepalive_response(packet, &handler).await {
            return;
        }

        let lookup = handler.link_table.original_destination(&packet.destination);
        if lookup.is_some() {
            let sent = send_to_next_hop(packet, &handler, lookup).await;

            log::trace!(
                "tp({}): {} packet to remote link {}",
                handler.config.name,
                if sent { "forwarded" } else { "could not forward" },
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
                if destination.prove_packets() {
                    proof = Some(destination.proof_packet(&packet.hash()));
                }

                match destination.decrypt(packet.data.as_slice(), plain_data.accuire_buf_max()) {
                    Ok(data) => Some(data.len()),
                    Err(err) => {
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

                handler
                    .send(TxMessage {
                        tx_type: TxMessageType::Direct(iface),
                        packet: proof,
                    })
                    .await;
            }
        } else {
            if let Some((next_hop, _)) = handler.path_table.next_hop_full(&packet.destination) {
                handler.reverse_table.add(packet, iface, next_hop);
            }

            data_handled = send_to_next_hop(packet, &handler, None).await;
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

async fn handle_announce<'a>(
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
    iface: AddressHash
) {
    if handler.has_destination(&packet.destination) {
        // destination is local
        return
    }

    if packet.context != PacketContext::PathResponse {
        if let Some(blocked_until) = handler.announce_limits.check(&packet.destination) {
            log::info!(
                "tp({}): too many announces from {}, blocked for {} seconds",
                handler.config.name,
                &packet.destination,
                blocked_until.as_secs(),
            );
            return;
        }
    }

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
        packet.hash(),
    );

    if let Ok(result) = DestinationAnnounce::validate(packet) {
        let destination = result.0;
        let app_data = result.1;
        let identity_hash = destination.identity.address_hash;
        let dest_desc = destination.desc;
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

        handler.announce_table.add(packet, packet.destination, iface);

        handler.path_table.handle_announce(
            packet,
            packet.transport,
            iface,
        );

        let retransmit = handler.config.retransmit;
        if retransmit {
            let transport_id = handler.config.identity.address_hash().clone();
            if let Some(message) = handler
                .announce_table
                .new_packet(&packet.destination, &transport_id)
            {
                handler.send(message).await;
            }
        }

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(&app_data),
        });

        if is_discovery_destination(&dest_desc) {
            if let Ok(discovered) =
                DiscoveredInterface::from_announce(dest_desc, packet.header.hops + 1, app_data)
            {
                let _ = handler.discovery_tx.send(discovered);
            }
        }
    }
}

async fn handle_path_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if let Some(request) = handler.path_requests.decode(packet.data.as_slice()) {
        if let Some(dest) = handler.single_in_destinations.get(&request.destination) {
            let response = dest
                .lock()
                .await
                .path_response(OsRng, None)
                .expect("valid path response");

            handler.send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: response,
            }).await;

            log::trace!(
                "tp({}): send direct path response over {}",
                handler.config.name,
                iface
            );

            return;
        }

        if handler.config.retransmit {
            if let Some(entry) = handler.path_table.get(&request.destination) {
                if let Some(requestor_id) = request.requesting_transport {
                    if requestor_id == entry.received_from {
                        log::trace!(
                            "tp({}): dropping circular path request from {}",
                            handler.config.name,
                            request.destination
                        );
                        return;
                    }
                }

                let hops = entry.hops;

                handler.announce_table.add_response(request.destination, iface, hops);

                log::trace!(
                    "tp({}): scheduled remote path response to {} ({} hops) over {}",
                    handler.config.name,
                    request.destination,
                    hops,
                    iface
                );

                return;
            }
        }

        if let Some(packet) = handler.path_requests.generate_recursive(
            &request.destination,
            Some(iface),
            None
        ) {
            handler.send(TxMessage {
                tx_type: TxMessageType::Broadcast(Some(iface)),
                packet
            }).await;
        }
    }
}

async fn handle_fixed_destinations<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash
) -> bool {
    if packet.destination == handler.fixed_dest_path_requests {
        handle_path_request(packet, handler, iface).await;
        true
    } else {
        false
    }
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>
) {
    let mut destination = destination.lock().await;
    match destination.handle_packet(packet) {
        DestinationHandleStatus::LinkProof => {
            let link_id = LinkId::from(packet);
            if !handler.in_links.contains_key(&link_id) {
                log::trace!(
                    "tp({}): send proof to {}",
                    handler.config.name,
                    packet.destination
                );

                let link = Link::new_from_request(
                    packet,
                    destination.sign_key().clone(),
                    destination.desc,
                    handler.link_in_event_tx.clone(),
                );

                if let Ok(mut link) = link {
                    handler.send_packet(link.prove()).await;

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

async fn handle_link_request_as_intermediate<'a>(
    received_from: AddressHash,
    next_hop: AddressHash,
    next_hop_iface: AddressHash,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>
) {
    handler.link_table.add(
        packet,
        packet.destination,
        received_from,
        next_hop,
        next_hop_iface
    );

    send_to_next_hop(packet, &handler, None).await;
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>
) {
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

        handle_link_request_as_destination(destination, packet, handler).await;
    } else if let Some(entry) = handler.path_table.next_hop_full(&packet.destination) {
        log::trace!(
            "tp({}): handle link request for remote destination {}",
            handler.config.name,
            packet.destination
        );

        let (next_hop, next_iface) = entry;
        handle_link_request_as_intermediate(
            iface,
            next_hop,
            next_iface,
            packet,
            handler
        ).await;
    } else {
        log::trace!(
            "tp({}): dropping link request to unknown destination {}",
            handler.config.name,
            packet.destination
        );
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        match link.status() {
            LinkStatus::Active => if link.elapsed() > INTERVAL_INPUT_LINK_STALE {
                link.stale();
            }
            LinkStatus::Stale => if link.elapsed() > INTERVAL_INPUT_LINK_STALE + INTERVAL_INPUT_LINK_CLOSE {
                if let Some(packet) = link.teardown().unwrap_or_else(|err| {
                    log::error!("tp({}): teardown stale in-link error: {err:?}", handler.config.name);
                    None
                }) {
                    handler.send_packet(packet).await
                }
                links_to_remove.push(*link_entry.0);
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(&addr);
    }

    links_to_remove.clear();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        match link.status() {
            LinkStatus::Active => if link.elapsed() > INTERVAL_OUTPUT_LINK_STALE {
                link.stale();
            }
            LinkStatus::Stale => {
                if handler.config.restart_outlinks {
                    if link.elapsed() > INTERVAL_OUTPUT_LINK_RESTART {
                        link.restart();
                    }
                } else {
                    if link.elapsed() > INTERVAL_OUTPUT_LINK_STALE + INTERVAL_OUTPUT_LINK_CLOSE {
                        if let Some(packet) = link.teardown().unwrap_or_else(|err| {
                            log::error!("tp({}): teardown stale out-link error: {err:?}", handler.config.name);
                            None
                        }) {
                            handler.send_packet(packet).await
                        }
                        links_to_remove.push(*link_entry.0);
                    }
                }
            }
            LinkStatus::Pending => if link.elapsed() > INTERVAL_OUTPUT_LINK_REPEAT {
                log::warn!(
                    "tp({}): repeat link request {}",
                    handler.config.name,
                    link.id()
                );
                handler.send_packet(link.request()).await;
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
}

async fn handle_keep_links<'a>(handler: MutexGuard<'a, TransportHandler>) {
    for link in handler.out_links.values() {
        let link = link.lock().await;

        if link.status() == LinkStatus::Active {
            handler.send_packet(link.keep_alive_packet(KEEP_ALIVE_REQUEST)).await;
        }
    }
}

async fn handle_cleanup<'a>(handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();
}

async fn handle_discovery<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
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

    handler.send_packet(packet).await;
}

async fn retransmit_announces<'a>(
    mut handler: MutexGuard<'a, TransportHandler>,
    retransmit_old: bool
) {
    let transport_id = handler.config.identity.address_hash().clone();
    let messages = handler.announce_table.to_retransmit(&transport_id);

    for message in messages {
        handler.send(message).await;
    }

    if retransmit_old {
        let messages = handler.announce_table.to_retransmit_old(&transport_id);

        for message in messages {
            handler.send(message).await;
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
            hops: packet.header.hops + 1,
        },
        ifac: packet.ifac,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data,
    }
}

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;
    let mut last_retransmit_old = if handler.lock().await.config.announce_forever {
        Some(time::Instant::now() - INTERVAL_OLD_ANNOUNCES_RETRANSMIT)
    } else {
        None
    };

    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();

        log::trace!(
            "tp({}): start packet task",
            handler.lock().await.config.name
        );

        tokio::spawn(async move {
            loop {
                let mut rx_receiver = rx_receiver.lock().await;

                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    Some(message) = rx_receiver.recv() => {
                        let _ = iface_messages_tx.send(message);

                        let packet = message.packet;

                        let mut handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::debug!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        if handle_fixed_destinations(
                            &packet,
                            &mut handler,
                            message.address
                        ).await {
                            continue;
                        }

                        if !handler.filter_duplicate_packets(&packet).await {
                            log::debug!(
                                "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
                                handler.config.name,
                                packet.destination,
                                packet.context,
                                packet.header.packet_type
                            );
                            continue;
                        }

                        if handler.config.broadcast && packet.header.packet_type != PacketType::Announce {
                            // TODO: remove seperate handling for announces in handle_announce.
                            // Send broadcast message expect current iface address
                            handler.send(TxMessage { tx_type: TxMessageType::Broadcast(Some(message.address)), packet }).await;
                        }

                        match packet.header.packet_type {
                            PacketType::Announce => handle_announce(
                                &packet,
                                handler,
                                message.address
                            ).await,
                            PacketType::LinkRequest => handle_link_request(
                                &packet,
                                message.address,
                                handler
                            ).await,
                            PacketType::Proof => handle_proof(&packet, handler).await,
                            PacketType::Data => handle_data(&packet, message.address, handler).await,
                        }
                    }
                };
            }
        })
    };

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
                    _ = time::sleep(INTERVAL_LINKS_CHECK) => {
                        handle_check_links(handler.lock().await).await;
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
                    _ = time::sleep(DISCOVERY_JOB_INTERVAL) => {
                        handle_discovery(handler.lock().await).await;
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
                    _ = time::sleep(INTERVAL_OUTPUT_LINK_KEEP) => {
                        handle_keep_links(handler.lock().await).await;
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
                        handle_cleanup(handler.lock().await).await;
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
                    _ = time::sleep(INTERVAL_PACKET_CACHE_CLEANUP) => {
                        let mut handler = handler.lock().await;

                        handler
                            .packet_cache
                            .lock()
                            .await
                            .release(INTERVAL_KEEP_PACKET_CACHED);

                        handler.link_table.remove_stale();
                        handler.reverse_table.remove_stale(INTERVAL_KEEP_REVERSE_PATH);
                    },
                }
            }
        });
    }

    if retransmit {
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
                    _ = time::sleep(INTERVAL_ANNOUNCES_RETRANSMIT) => {
                        let mut retransmit_old = false;

                        if let Some(instant) = last_retransmit_old {
                            let now = time::Instant::now();
                            if now - instant > INTERVAL_OLD_ANNOUNCES_RETRANSMIT {
                                retransmit_old = true;
                                last_retransmit_old = Some(now);
                            }
                        }

                        retransmit_announces(handler.lock().await, retransmit_old).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
    use crate::packet::{HeaderType, PACKET_MDU};

    #[tokio::test]
    async fn drop_duplicates() {
        let mut config: TransportConfig = Default::default();
        config.set_retransmit(true);

        let transport = Transport::new(config);
        let handler = transport.get_handler();

        let source1 = AddressHash::new_from_slice(&[1u8; 32]);
        let source2 = AddressHash::new_from_slice(&[2u8; 32]);
        let next_hop_iface = AddressHash::new_from_slice(&[3u8; 32]);
        let destination = AddressHash::new_from_slice(&[4u8; 32]);

        let mut announce: Packet = Default::default();
        announce.header.header_type = HeaderType::Type2;
        announce.header.packet_type = PacketType::Announce;
        announce.header.hops = 3;
        announce.transport = Some(destination);

        assert!(handler.lock().await.filter_duplicate_packets(&announce).await);

        handle_announce(&announce, handler.lock().await, next_hop_iface).await;

        let mut data_packet: Packet = Default::default();
        data_packet.data = PacketDataBuffer::new_from_slice(b"foo");
        data_packet.destination = destination;
        let mut duplicate: Packet = data_packet.clone();

        let mut different_packet = data_packet.clone();
        different_packet.data = PacketDataBuffer::new_from_slice(b"bar");

        assert!(handler.lock().await.filter_duplicate_packets(&data_packet).await);
        assert!(!handler.lock().await.filter_duplicate_packets(&duplicate).await);
        assert!(handler.lock().await.filter_duplicate_packets(&different_packet).await);

        tokio::time::sleep(Duration::from_secs(2)).await;
        handler.lock().await.packet_cache.lock().await.release(Duration::from_secs(1));

        // Packet should have been removed from cache (stale)
        assert!(handler.lock().await.filter_duplicate_packets(&duplicate).await);
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

        handle_data(&packet, iface, handler.lock().await).await;

        let received = events.recv().await.expect("received data event");
        assert_eq!(received.destination, destination_desc.address_hash);
        assert_eq!(received.data.as_slice(), b"plaintext payload");
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

        handle_announce(&path_response, handler.lock().await, iface).await;

        assert!(
            handler.lock().await.path_table.get(&path_response.destination).is_some(),
            "path response should still populate the path table",
        );
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

        handle_announce(&first_announce, handler.lock().await, iface).await;
        handle_announce(&second_announce, handler.lock().await, iface).await;

        let mut guard = handler.lock().await;
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
                packet: first_announce,
            })
            .await
            .expect("queued first announce");
        in_rx
            .send(RxMessage {
                address: in_address,
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
