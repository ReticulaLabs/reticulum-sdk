use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, SigningKey};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::{ADDRESS_HASH_SIZE, AddressHash, HASH_SIZE, Hash},
    identity::{DecryptIdentity, DerivedKey, EncryptIdentity, Identity, PrivateIdentity},
    packet::{
        DestinationType, Header, PACKET_MDU, Packet, PacketContext, PacketDataBuffer, PacketType,
        RETICULUM_AES_BLOCK_SIZE, RETICULUM_MTU, RETICULUM_TOKEN_OVERHEAD, compute_link_mdu,
    },
};

use super::DestinationDesc;

pub(crate) const LINK_MTU_SIZE: usize = 3;
pub(crate) const LINK_MODE_AES256_CBC: u8 = 0x01;
const CHANNEL_HEADER_SIZE: usize = 6;
const CHANNEL_SEQUENCE_MAX: u16 = u16::MAX;
const CHANNEL_SEQUENCE_MODULUS: u32 = CHANNEL_SEQUENCE_MAX as u32 + 1;
/// Maximum number of channel sequences the receiver will buffer while
/// waiting for an out-of-order head. Sized to absorb the burst and queue
/// reordering that high-throughput links (up to 5-10 Gbps) can produce:
/// at ~500-byte packets this covers ~8 MiB of reordered data. Must stay
/// well below half the 16-bit sequence modulus (32768) so that forward
/// and backward sequence distances remain unambiguous.
const CHANNEL_WINDOW_MAX: u16 = 16384;

/// How long the channel receiver will wait for a missing sequence while
/// holding buffered packets before concluding the packet was lost and
/// flushing the reorder buffer so the stream keeps making progress.
/// Without this, a single lost packet stalls delivery of every subsequent
/// channel message indefinitely.
const CHANNEL_REORDER_TIMEOUT: Duration = Duration::from_millis(500);

/// Keepalive interval for active links. Matches Python's `Link.KEEPALIVE`
/// (360 seconds): a keepalive is only sent when the link has been quiet
/// (no inbound traffic) for this long, and at most once per interval.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(360);

/// Default establishment budget for a pending out-link before it is
/// failed. `Transport::link` overrides this with a hop-count-based value
/// (matching Python's `Link.establishment_timeout`).
const DEFAULT_ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a pending out-link request is retransmitted while waiting
/// for its proof. This is a *cadence* timer: it is independent of the
/// establishment anchor (`request_time`), so repeated retransmissions do
/// not push the pending-link rediscovery logic (`INTERVAL_OUTPUT_LINK_TRIED`)
/// forever into the future.
const LINK_REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(6);

pub(crate) fn link_signalling_bytes(mtu: usize) -> [u8; LINK_MTU_SIZE] {
    let mode_bits = ((LINK_MODE_AES256_CBC << 5) & 0xE0) as u32;
    let signalling_value = (mtu as u32 & 0x1F_FFFF) + (mode_bits << 16);
    let bytes = signalling_value.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

/// Extract the signalled MTU from link request or proof signalling bytes.
pub(crate) fn mtu_from_signalling_bytes(bytes: &[u8]) -> usize {
    if bytes.len() < LINK_MTU_SIZE {
        return RETICULUM_MTU;
    }
    let mut raw = [0u8; 4];
    raw[1..4].copy_from_slice(&bytes[..LINK_MTU_SIZE]);
    (u32::from_be_bytes(raw) & 0x1F_FFFF) as usize
}

pub(crate) fn mode_from_signalling_bytes(bytes: &[u8]) -> u8 {
    if bytes.len() < LINK_MTU_SIZE {
        return LINK_MODE_AES256_CBC;
    }
    (bytes[0] & 0xE0) >> 5
}

fn channel_sequence_distance(base: u16, sequence: u16) -> u32 {
    (sequence as u32 + CHANNEL_SEQUENCE_MODULUS - base as u32) % CHANNEL_SEQUENCE_MODULUS
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LinkStatus {
    Pending = 0x00,
    Handshake = 0x01,
    Active = 0x02,
    Stale = 0x03,
    Closed = 0x04,
}

impl LinkStatus {
    pub fn not_yet_active(&self) -> bool {
        *self == LinkStatus::Pending || *self == LinkStatus::Handshake
    }
}

pub type LinkId = AddressHash;

#[derive(Clone)]
pub struct LinkPayload {
    buffer: Vec<u8>,
}

impl LinkPayload {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        Self {
            buffer: data.to_vec(),
        }
    }

    pub fn new_from_vec(data: &Vec<u8>) -> Self {
        Self {
            buffer: data.clone(),
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

impl From<&Packet> for LinkId {
    fn from(packet: &Packet) -> Self {
        let data = packet.data.as_slice();
        let data_diff = if data.len() > PUBLIC_KEY_LENGTH * 2 {
            data.len() - PUBLIC_KEY_LENGTH * 2
        } else {
            0
        };

        let hashable_data = &data[..data.len() - data_diff];

        AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update(&[packet.header.to_meta() & 0b00001111])
                .chain_update(packet.destination.as_slice())
                .chain_update(&[packet.context as u8])
                .chain_update(hashable_data)
                .finalize()
                .into(),
        ))
    }
}

pub enum LinkHandleResult {
    None,
    Activated,
    KeepAlive,
    MessageReceived(Option<Packet>),
}

#[derive(Clone)]
pub enum LinkEvent {
    Activated,
    Data(Box<LinkPayload>),
    RemoteIdentified(Identity),
    Request(LinkRequest),
    Response(LinkResponse),
    Channel(ChannelEnvelope),
    Proof(Hash),
    /// A decrypted resource-context packet received over this link.
    ///
    /// Carries the plaintext payload (the raw resource protocol data,
    /// e.g. advertisement/request/hashmap-update/proof blobs or a single
    /// encrypted resource part) and the packet context that identifies
    /// which part of the resource protocol it belongs to.
    Resource(LinkResourcePacket),
    Closed,
}

/// Decrypted payload of a resource-context packet received over a link.
#[derive(Clone)]
pub struct LinkResourcePacket {
    pub context: PacketContext,
    pub data: Vec<u8>,
    /// Full hash of the received packet, used for request deduplication.
    pub packet_hash: Hash,
}

#[derive(Clone)]
pub struct LinkRequest {
    /// Request id using this SDK's convention: the first 16 bytes of
    /// SHA-256 over (header flags | destination | context | plaintext).
    /// Both SDK peers derive the same value, so it is safe to echo back
    /// with `response_packet` when talking to another SDK client.
    pub request_id: AddressHash,
    /// Request id using the Python reference convention. For inline
    /// requests this is the first 16 bytes of SHA-256 over
    /// (header flags | context | ciphertext); for resource-based requests
    /// it is the first 16 bytes of SHA-256 over the packed msgpack request.
    /// The Python client correlates responses against this value, so
    /// applications serving Python clients must echo these exact bytes
    /// (e.g. via `response_packet_raw`).
    pub request_id_raw: Vec<u8>,
    pub path_hash: AddressHash,
    /// Raw path hash bytes as received on the wire, left-aligned. The
    /// Python reference hashes the request path into a 16-byte truncated
    /// hash, which is what applications should match against.
    pub path_hash_raw: Vec<u8>,
    pub requested_at: f64,
    pub data: Value,
}

#[derive(Clone)]
pub struct LinkResponse {
    pub request_id: AddressHash,
    pub data: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelEnvelope {
    pub msg_type: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl ChannelEnvelope {
    pub fn new(msg_type: u16, sequence: u16, payload: &[u8]) -> Result<Self, RnsError> {
        if payload.len() > u16::MAX as usize {
            return Err(RnsError::OutOfMemory);
        }

        Ok(Self {
            msg_type,
            sequence,
            payload: payload.to_vec(),
        })
    }

    pub fn pack(&self) -> Result<Vec<u8>, RnsError> {
        if self.payload.len() > u16::MAX as usize {
            return Err(RnsError::OutOfMemory);
        }

        let mut raw = Vec::with_capacity(CHANNEL_HEADER_SIZE + self.payload.len());
        raw.extend_from_slice(&self.msg_type.to_be_bytes());
        raw.extend_from_slice(&self.sequence.to_be_bytes());
        raw.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(&self.payload);
        Ok(raw)
    }

    pub fn unpack(raw: &[u8]) -> Result<Self, RnsError> {
        if raw.len() < CHANNEL_HEADER_SIZE {
            return Err(RnsError::PacketError);
        }

        let msg_type = u16::from_be_bytes([raw[0], raw[1]]);
        let sequence = u16::from_be_bytes([raw[2], raw[3]]);
        let payload_len = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        let payload = &raw[CHANNEL_HEADER_SIZE..];
        if payload.len() != payload_len {
            return Err(RnsError::PacketError);
        }

        Ok(Self {
            msg_type,
            sequence,
            payload: payload.to_vec(),
        })
    }
}

pub trait ChannelMessage: Sized {
    const MSG_TYPE: u16;

    fn pack(&self) -> Result<Vec<u8>, RnsError>;
    fn unpack(payload: &[u8]) -> Result<Self, RnsError>;
}

#[derive(Clone)]
pub struct LinkEventData {
    pub id: LinkId,
    pub address_hash: AddressHash,
    pub event: LinkEvent,
}

pub struct Link {
    id: LinkId,
    destination: DestinationDesc,
    priv_identity: PrivateIdentity,
    peer_identity: Identity,
    derived_key: DerivedKey,
    status: LinkStatus,
    mtu: usize,
    request_time: Instant,
    /// Absolute deadline by which an initiator out-link must be
    /// established. Set once when the link request is first sent and
    /// *not* extended by request retransmissions; if the link is still
    /// Pending past this point it is failed and removed. Matches Python's
    /// `Link.establishment_timeout`.
    establishment_deadline: Instant,
    /// When the next link-request retransmission may be sent. Advanced
    /// by `request()` on each retransmission; deliberately *not* tied to
    /// `request_time`, so a pending link still trips the rediscovery
    /// logic once its establishment anchor has aged past
    /// `INTERVAL_OUTPUT_LINK_TRIED` instead of retransmitting forever.
    next_retry_time: Instant,
    rtt: Duration,
    /// Last time a keepalive request was sent on this link. Used to gate
    /// keepalive cadence (matches Python's `Link.last_keepalive`).
    last_keepalive: Instant,
    /// Keepalive interval for this link (matches Python's `Link.keepalive`).
    keepalive: Duration,
    event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    proves_messages: bool,
    next_channel_sequence: u16,
    next_rx_channel_sequence: u16,
    channel_rx_ring: Vec<ChannelEnvelope>,
    /// When the receiver started waiting for a missing sequence while
    /// holding buffered packets. Set when a gap is first observed and
    /// reset whenever delivery makes progress or the buffer empties. Used
    /// to trigger loss recovery via `CHANNEL_REORDER_TIMEOUT`.
    channel_rx_stall_since: Option<Instant>,
    channel_tx: Option<tokio::sync::broadcast::Sender<Vec<u8>>>,
    /// Reusable plaintext scratch buffer for decrypting received link
    /// packets. Sized to the negotiated MDU once and reused so the receive
    /// path does not perform a fresh zeroed heap allocation (up to the MDU)
    /// on every packet, which dominates throughput on high-speed links.
    decrypt_buffer: Vec<u8>,
}

impl Link {
    pub fn new(
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Self {
        let mut rng = UnwrapErr(SysRng);
        Self {
            id: AddressHash::new_empty(),
            destination,
            priv_identity: PrivateIdentity::new_from_rand(&mut rng),
            peer_identity: Identity::default(),
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            mtu: RETICULUM_MTU,
            request_time: Instant::now(),
            establishment_deadline: Instant::now() + DEFAULT_ESTABLISHMENT_TIMEOUT,
            next_retry_time: Instant::now(),
            rtt: Duration::from_secs(0),
            last_keepalive: Instant::now(),
            keepalive: KEEPALIVE_INTERVAL,
            event_tx,
            proves_messages: false,
            next_channel_sequence: 0,
            next_rx_channel_sequence: 0,
            channel_rx_ring: Vec::new(),
            channel_rx_stall_since: None,
            channel_tx: None,
            decrypt_buffer: Vec::new(),
        }
    }

    pub fn prove_messages(&mut self, setting: bool) {
        self.proves_messages = setting;
    }

    pub fn new_from_request(
        packet: &Packet,
        signing_key: SigningKey,
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Result<Self, RnsError> {
        if packet.data.len() != PUBLIC_KEY_LENGTH * 2
            && packet.data.len() != PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE
        {
            return Err(RnsError::InvalidArgument);
        }

        let peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        )?;

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {}", link_id);

        // Extract signalled MTU from the link request if present
        let mtu = if packet.data.len() >= PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE {
            let signalling = &packet.data.as_slice()
                [PUBLIC_KEY_LENGTH * 2..PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE];
            if mode_from_signalling_bytes(signalling) != LINK_MODE_AES256_CBC {
                return Err(RnsError::InvalidArgument);
            }
            mtu_from_signalling_bytes(signalling)
        } else {
            RETICULUM_MTU
        };

        let mut rng = UnwrapErr(SysRng);
        let mut link = Self {
            id: link_id,
            destination,
            priv_identity: PrivateIdentity::new(StaticSecret::random_from_rng(&mut rng), signing_key),
            peer_identity,
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            mtu,
            request_time: Instant::now(),
            establishment_deadline: Instant::now() + DEFAULT_ESTABLISHMENT_TIMEOUT,
            next_retry_time: Instant::now(),
            rtt: Duration::from_secs(0),
            last_keepalive: Instant::now(),
            keepalive: KEEPALIVE_INTERVAL,
            event_tx,
            proves_messages: false,
            next_channel_sequence: 0,
            next_rx_channel_sequence: 0,
            channel_rx_ring: Vec::new(),
            channel_rx_stall_since: None,
            channel_tx: None,
            decrypt_buffer: Vec::new(),
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub fn request(&mut self, path_mtu: Option<usize>) -> Packet {
        let mtu = path_mtu.unwrap_or(RETICULUM_MTU);
        let mut packet_data = PacketDataBuffer::new();
        let signalling = link_signalling_bytes(mtu);

        packet_data.write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.write(self.priv_identity.as_identity().verifying_key.as_bytes());
        packet_data.write(&signalling);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::LinkRequest,
                ..Default::default()
            },
            ifac: None,
            destination: self.destination.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        self.status = LinkStatus::Pending;
        self.id = LinkId::from(&packet);
        self.mtu = mtu;
        // Only the *retry cadence* advances on a (re)transmission. The
        // establishment anchor `request_time` is set once at creation and
        // deliberately left untouched here: resetting it on every
        // retransmission would keep `elapsed()` below
        // `INTERVAL_OUTPUT_LINK_TRIED` forever and make the pending-link
        // rediscovery branch dead code (finding 1.1).
        self.next_retry_time = Instant::now() + LINK_REQUEST_RETRY_INTERVAL;

        log::debug!(
            "link({}): link request created dst={} mtu={}",
            self.id,
            self.destination.address_hash,
            mtu,
        );

        packet
    }

    pub fn prove(&mut self) -> Packet {
        log::debug!("link({}): prove", self.id);

        if self.status != LinkStatus::Active {
            self.status = LinkStatus::Active;
            self.post_event(LinkEvent::Activated);
        }

        let mut packet_data = PacketDataBuffer::new();
        let signalling = link_signalling_bytes(self.mtu);

        packet_data.write(self.id.as_slice());
        packet_data.write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.write(self.priv_identity.as_identity().verifying_key.as_bytes());
        packet_data.write(&signalling);

        let signature = self.priv_identity.sign(packet_data.as_slice());

        packet_data.reset();
        packet_data.write(&signature.to_bytes()[..]);
        packet_data.write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.write(&signalling);

        let packet = Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRequestProof,
            data: packet_data,
        };

        packet
    }

    fn handle_data_packet(&mut self, packet: &Packet, out_link: bool) -> LinkHandleResult {
        if self.status != LinkStatus::Active {
            log::warn!("link({}): handling data packet in inactive state", self.id);
        }

        match packet.context {
            PacketContext::None => {
                if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                    log::trace!("link({}): data {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Data(Box::new(LinkPayload::new_from_vec(
                        &plain_text,
                    ))));

                    let proof = if self.proves_messages {
                        Some(self.message_proof(packet.hash()))
                    } else {
                        None
                    };

                    return LinkHandleResult::MessageReceived(proof);
                } else {
                    log::error!("link({}): can't decrypt packet", self.id);
                }
            }
            PacketContext::LinkIdentify => {
                if !out_link {
                    if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                        match self.validate_link_identify(&plain_text) {
                            Ok(identity) => {
                                self.request_time = Instant::now();
                                self.post_event(LinkEvent::RemoteIdentified(identity));
                            }
                            Err(err) => {
                                log::warn!(
                                    "link({}): invalid link identify packet: {err:?}",
                                    self.id
                                );
                            }
                        }
                    } else {
                        log::error!("link({}): can't decrypt link identify packet", self.id);
                    }
                }
            }
            PacketContext::Request => {
                if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                    let request_id = AddressHash::new_from_hash(&packet.hash());
                    let request_id_raw = python_request_id(packet);
                    match decode_link_request(&plain_text, request_id, request_id_raw) {
                        Ok(request) => {
                            self.request_time = Instant::now();
                            self.post_event(LinkEvent::Request(request));
                        }
                        Err(err) => {
                            log::warn!("link({}): invalid request packet: {err:?}", self.id);
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt request packet", self.id);
                }
            }
            PacketContext::Response => {
                if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                    match decode_link_response(&plain_text) {
                        Ok(response) => {
                            self.request_time = Instant::now();
                            self.post_event(LinkEvent::Response(response));
                        }
                        Err(err) => {
                            log::warn!("link({}): invalid response packet: {err:?}", self.id);
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt response packet", self.id);
                }
            }
            PacketContext::Channel => {
                if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                    // Channel messages are only proven when the link opts in
                    // via `prove_messages`, mirroring Python's
                    // `Destination.proof_strategy` gating. Per-packet proofs
                    // double the link's packet rate and add an Ed25519
                    // signature per message, which dominates the receive
                    // path cost on high-throughput links.
                    let proof = if self.proves_messages {
                        Some(self.message_proof(packet.hash()))
                    } else {
                        None
                    };
                    if let Some(ref tx) = self.channel_tx {
                        let _ = tx.send(plain_text.clone());
                        self.request_time = Instant::now();
                        return LinkHandleResult::MessageReceived(proof);
                    }
                    match ChannelEnvelope::unpack(&plain_text) {
                        Ok(envelope) => {
                            self.request_time = Instant::now();
                            self.handle_channel_envelope(envelope);
                            return LinkHandleResult::MessageReceived(proof);
                        }
                        Err(err) => {
                            log::warn!("link({}): invalid channel packet: {err:?}", self.id);
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt channel packet", self.id);
                }
            }
            PacketContext::Resource
            | PacketContext::ResourceProof
            | PacketContext::ResourceAdvertisement
            | PacketContext::ResourceRequest
            | PacketContext::ResourceHashUpdate
            | PacketContext::ResourceInitiatorCancel
            | PacketContext::ResourceReceiverCancel => {
                return self.handle_resource_packet(packet);
            }
            PacketContext::KeepAlive => {
                if packet.data.len() >= 1 && packet.data.as_slice()[0] == 0xFF {
                    self.request_time = Instant::now();
                    log::trace!("link({}): keep-alive request", self.id);
                    return LinkHandleResult::KeepAlive;
                }
                if packet.data.len() >= 1 && packet.data.as_slice()[0] == 0xFE {
                    log::trace!("link({}): keep-alive response", self.id);
                    self.request_time = Instant::now();
                    return LinkHandleResult::None;
                }
            }
            PacketContext::LinkRTT => {
                if !out_link {
                    if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                        if let Ok(rtt) = rmp::decode::read_f64(&mut &plain_text[..]) {
                            self.rtt = Duration::from_secs_f64(rtt);
                        } else {
                            log::error!("link({}): failed to decode rtt", self.id);
                        }
                    } else {
                        log::error!("link({}): can't decrypt rtt packet", self.id);
                    }
                }
            }
            PacketContext::LinkClose => {
                if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                    match plain_text[..].try_into() {
                        Err(err) => {
                            log::error!(
                                "link({}): invalid decode link close payload: {err}",
                                self.id
                            )
                        }
                        Ok(dest_bytes) => {
                            let link_id = LinkId::new(dest_bytes);
                            if self.id == link_id {
                                let _ = self.close();
                            }
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt link close packet", self.id);
                }
            }
            _ => {}
        }

        LinkHandleResult::None
    }

    pub fn handle_packet(&mut self, packet: &Packet, out_link: bool) -> LinkHandleResult {
        if packet.destination != self.id {
            return LinkHandleResult::None;
        }

        match packet.header.packet_type {
            PacketType::Data => return self.handle_data_packet(packet, out_link),
            PacketType::Proof => {
                // Resource proofs are PROOF packets with a RESOURCE_PRF context
                // (matching the Python reference). Route them to the resource
                // handler; link-request and message proofs stay in
                // handle_proof_packet.
                if packet.context == PacketContext::ResourceProof {
                    return self.handle_resource_packet(packet);
                }
                return self.handle_proof_packet(packet);
            }
            _ => return LinkHandleResult::None,
        }
    }

    fn handle_resource_packet(&mut self, packet: &Packet) -> LinkHandleResult {
        match packet.context {
            PacketContext::Resource | PacketContext::ResourceProof => {
                // Resource parts and proofs are never encrypted at the packet
                // layer (matching the Python reference): the resource takes
                // care of its own encryption on the whole stream, and each
                // part packet carries a raw slice of that encrypted stream.
                // Resource proofs are likewise sent unencrypted. Advancing
                // the link ratchet is handled by the other encrypted contexts.
                log::trace!(
                    "link({}): resource packet ctx={:?} {}B",
                    self.id,
                    packet.context,
                    packet.data.len(),
                );
                self.request_time = Instant::now();
                self.post_event(LinkEvent::Resource(LinkResourcePacket {
                    context: packet.context,
                    data: packet.data.as_slice().to_vec(),
                    packet_hash: packet.hash(),
                }));
            }
            PacketContext::ResourceAdvertisement
            | PacketContext::ResourceRequest
            | PacketContext::ResourceHashUpdate
            | PacketContext::ResourceInitiatorCancel
            | PacketContext::ResourceReceiverCancel => {
                if let Ok(plain_text) = self.decrypt_into_owned(packet.data.as_slice()) {
                    log::trace!(
                        "link({}): resource packet ctx={:?} {}B",
                        self.id,
                        packet.context,
                        plain_text.len(),
                    );
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Resource(LinkResourcePacket {
                        context: packet.context,
                        data: plain_text,
                        packet_hash: packet.hash(),
                    }));
                } else {
                    log::error!("link({}): can't decrypt resource packet", self.id);
                }
            }
            _ => {}
        }

        LinkHandleResult::None
    }

    fn handle_proof_packet(&mut self, packet: &Packet) -> LinkHandleResult {
        if self.status == LinkStatus::Pending && packet.context == PacketContext::LinkRequestProof {
            match validate_proof_packet(&self.destination, &self.id, packet) {
                Ok((identity, confirmed_mtu)) => {
                    log::debug!("link({}): has been proved mtu={}", self.id, confirmed_mtu);

                    self.mtu = confirmed_mtu;
                    self.handshake(identity);

                    self.status = LinkStatus::Active;
                    self.rtt = self.request_time.elapsed();
                    self.mark_activity();

                    log::debug!("link({}): activated", self.id);

                    self.post_event(LinkEvent::Activated);

                    return LinkHandleResult::Activated;
                }
                Err(_) => {
                    log::warn!("link({}): proof is not valid", self.id);
                }
            }
        }

        if self.status == LinkStatus::Active && packet.context == PacketContext::None {
            if let Ok(hash) =
                validate_message_proof(&self.peer_identity, packet.data.as_slice(), None)
            {
                self.post_event(LinkEvent::Proof(hash));
            }
        }

        return LinkHandleResult::None;
    }

    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        self.encrypted_data_packet(data, PacketContext::None)
    }

    /// Build a resource-context packet (e.g. a resource part, advertisement,
    /// request, hashmap update or proof blob) encrypted and addressed to this
    /// link's peer. The payload must fit within the link MDU.
    pub fn resource_packet(
        &self,
        context: PacketContext,
        data: &[u8],
    ) -> Result<Packet, RnsError> {
        self.encrypted_data_packet(data, context)
    }

    /// Build a raw resource part packet (matching the Python reference).
    ///
    /// Resource part packets are never encrypted at the packet layer: the
    /// resource takes care of its own encryption on the whole stream and
    /// each part carries a slice of that encrypted stream. The payload must
    /// fit within the link MDU.
    pub fn resource_part_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        self.raw_data_packet(data, PacketContext::Resource, PacketType::Data)
    }

    /// Build a raw resource proof packet (matching the Python reference).
    ///
    /// Resource proofs are sent unencrypted over the link as PROOF packets
    /// with a RESOURCE_PRF context. The payload must fit within the link MDU.
    pub fn resource_proof_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        self.raw_data_packet(data, PacketContext::ResourceProof, PacketType::Proof)
    }

    /// Build an unencrypted packet addressed to this link's peer.
    /// Used for resource parts and proofs, which are never encrypted at the
    /// packet layer. The payload must fit within the link MDU.
    fn raw_data_packet(
        &self,
        data: &[u8],
        context: PacketContext,
        packet_type: PacketType,
    ) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active && self.status != LinkStatus::Stale {
            log::warn!("link: can't create data packet for closed link");
            return Err(RnsError::LinkClosed);
        }
        if data.len() > self.mdu() {
            return Err(RnsError::OutOfMemory);
        }

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context,
            data: PacketDataBuffer::new_from_slice(data),
        })
    }

    /// Maximum Data Unit for this link, computed from the negotiated path MTU.
    /// This is the largest plaintext payload that can be encrypted into a single
    /// link packet. Uses AES-block-aligned arithmetic like the Python reference.
    pub fn mdu(&self) -> usize {
        compute_link_mdu(self.mtu)
    }

    pub fn channel_mdu(&self) -> usize {
        self.mdu().saturating_sub(CHANNEL_HEADER_SIZE)
    }

    /// Bind this link to a channel consumer. Returns a receiver for raw decrypted
    /// payloads of packets sent with `PacketContext::Channel`. Only one binding
    /// is allowed per link; returns `Err(ChannelError)` if already bound.
    pub fn bind_to_channel(
        &mut self,
    ) -> Result<tokio::sync::broadcast::Receiver<Vec<u8>>, RnsError> {
        if self.channel_tx.is_some() {
            return Err(RnsError::ChannelError);
        }
        let (tx, rx) = tokio::sync::broadcast::channel(64);
        self.channel_tx = Some(tx);
        Ok(rx)
    }

    pub fn channel_packet<M: ChannelMessage>(&mut self, message: &M) -> Result<Packet, RnsError> {
        let payload = message.pack()?;
        self.channel_raw_packet(M::MSG_TYPE, &payload)
    }

    pub fn channel_raw_packet(
        &mut self,
        msg_type: u16,
        payload: &[u8],
    ) -> Result<Packet, RnsError> {
        if payload.len() > self.channel_mdu() {
            return Err(RnsError::OutOfMemory);
        }

        let sequence = self.next_channel_sequence;
        self.next_channel_sequence = self.next_channel_sequence.wrapping_add(1);
        let envelope = ChannelEnvelope::new(msg_type, sequence, payload)?;
        let raw = envelope.pack()?;
        self.encrypted_data_packet(&raw, PacketContext::Channel)
    }

    fn encrypted_data_packet(
        &self,
        data: &[u8],
        context: PacketContext,
    ) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active && self.status != LinkStatus::Stale {
            log::warn!("link: can't create data packet for closed link");
            return Err(RnsError::LinkClosed);
        }
        if data.len() > self.mdu() {
            return Err(RnsError::OutOfMemory);
        }

        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.encrypt(
                data,
                packet_data
                    .acquire_buf(data.len() + RETICULUM_TOKEN_OVERHEAD + RETICULUM_AES_BLOCK_SIZE),
            )?;
            cipher_text.len()
        };

        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context,
            data: packet_data,
        })
    }

    fn handle_channel_envelope(&mut self, envelope: ChannelEnvelope) {
        let mut distance =
            channel_sequence_distance(self.next_rx_channel_sequence, envelope.sequence);

        // Stale or very late packets behind the expected position can never
        // be delivered in order; drop them rather than feeding them back
        // into the reorder logic (or worse, into the loss-recovery flush).
        if distance >= CHANNEL_SEQUENCE_MODULUS / 2 {
            log::trace!(
                "link({}): late channel sequence {} (expected {})",
                self.id,
                envelope.sequence,
                self.next_rx_channel_sequence
            );
            return;
        }

        let stall_expired = self
            .channel_rx_stall_since
            .is_some_and(|since| since.elapsed() >= CHANNEL_REORDER_TIMEOUT);

        // Loss recovery for a stalled reorder buffer. Fires when there is
        // buffered data waiting on a missing head AND either:
        //   * the head has been missing for longer than
        //     CHANNEL_REORDER_TIMEOUT (slow trickle / genuine loss), or
        //   * the incoming packet falls outside the reorder window (the
        //     buffer filled up in milliseconds under a high-rate burst).
        // In both cases the missing head is treated as lost: the buffered
        // packets are delivered (in order, gaps skipped) so the stream
        // keeps making progress instead of stalling forever.
        if !self.channel_rx_ring.is_empty()
            && (stall_expired || distance >= CHANNEL_WINDOW_MAX as u32)
        {
            log::debug!(
                "link({}): channel reorder recovery (expected sequence {}, {} buffered, \
                 stall={}ms, gap={}) flushing to recover from loss",
                self.id,
                self.next_rx_channel_sequence,
                self.channel_rx_ring.len(),
                self.channel_rx_stall_since
                    .map_or(0, |since| since.elapsed().as_millis()),
                distance,
            );
            self.flush_channel_rx_ring();
            distance = channel_sequence_distance(self.next_rx_channel_sequence, envelope.sequence);
            // After the flush the incoming packet may be a duplicate of an
            // already-delivered sequence; drop it if it is now behind.
            if distance >= CHANNEL_SEQUENCE_MODULUS / 2 {
                log::trace!(
                    "link({}): late channel sequence {} after recovery",
                    self.id,
                    envelope.sequence
                );
                return;
            }
        }

        if distance >= CHANNEL_WINDOW_MAX as u32 {
            if self.channel_rx_ring.is_empty() {
                // The expected position is stale and nothing is buffered:
                // the stream jumped far ahead (e.g. after a long outage or
                // heavy loss). Resynchronise to the incoming sequence so
                // the channel does not discard every subsequent packet.
                log::debug!(
                    "link({}): channel stream resynchronised at sequence {}",
                    self.id,
                    envelope.sequence
                );
                self.next_rx_channel_sequence = envelope.sequence.wrapping_add(1);
                self.post_event(LinkEvent::Channel(envelope));
            } else {
                log::trace!(
                    "link({}): invalid channel sequence {}",
                    self.id,
                    envelope.sequence
                );
            }
            return;
        }

        // Binary-search the insertion point to keep the buffer ordered by
        // sequence distance from the expected position. This stays correct
        // as `next_rx_channel_sequence` advances: every buffered sequence
        // shares the same offset, so their relative order is invariant.
        let pos = self.channel_rx_ring.partition_point(|existing| {
            channel_sequence_distance(self.next_rx_channel_sequence, existing.sequence) < distance
        });
        if pos < self.channel_rx_ring.len()
            && self.channel_rx_ring[pos].sequence == envelope.sequence
        {
            log::trace!(
                "link({}): duplicate channel sequence {}",
                self.id,
                envelope.sequence
            );
            return;
        }

        self.channel_rx_ring.insert(pos, envelope);

        let delivered = self.deliver_contiguous_channel_rx();
        if self.channel_rx_ring.is_empty() {
            self.channel_rx_stall_since = None;
        } else if delivered || self.channel_rx_stall_since.is_none() {
            // Delivery advanced the expected sequence (a new head is now
            // missing) or we started buffering behind a gap. Restart the
            // stall clock so loss recovery stays bounded.
            self.channel_rx_stall_since = Some(Instant::now());
        }
    }

    /// Deliver every buffered envelope in sequence order, advancing the
    /// expected sequence past any gaps. Used to recover from lost packets
    /// after the reorder stall has been exceeded.
    fn flush_channel_rx_ring(&mut self) {
        let envelopes: Vec<_> = self.channel_rx_ring.drain(..).collect();
        for envelope in envelopes {
            self.next_rx_channel_sequence = envelope.sequence.wrapping_add(1);
            self.post_event(LinkEvent::Channel(envelope));
        }
        self.channel_rx_stall_since = None;
    }

    /// Deliver the contiguous run of buffered envelopes starting at the
    /// expected sequence, returning whether any were delivered.
    fn deliver_contiguous_channel_rx(&mut self) -> bool {
        let mut count = 0;
        while count < self.channel_rx_ring.len()
            && self.channel_rx_ring[count].sequence == self.next_rx_channel_sequence
        {
            self.next_rx_channel_sequence = self.next_rx_channel_sequence.wrapping_add(1);
            count += 1;
        }
        if count == 0 {
            return false;
        }
        let envelopes: Vec<_> = self.channel_rx_ring.drain(0..count).collect();
        for envelope in envelopes {
            self.post_event(LinkEvent::Channel(envelope));
        }
        true
    }

    pub fn identify_packet(&self, identity: &PrivateIdentity) -> Result<Packet, RnsError> {
        let mut signed_data = [0u8; ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2];
        let signed_data_len = {
            let mut output = OutputBuffer::new(&mut signed_data);
            output.write(self.id.as_slice())?;
            output.write(identity.as_identity().public_key.as_bytes())?;
            output.write(identity.as_identity().verifying_key.as_bytes())?;
            output.offset()
        };

        let signature = identity.sign(&signed_data[..signed_data_len]);

        let mut plaintext = [0u8; PUBLIC_KEY_LENGTH * 2 + SIGNATURE_LENGTH];
        let plaintext_len = {
            let mut output = OutputBuffer::new(&mut plaintext);
            output.write(identity.as_identity().public_key.as_bytes())?;
            output.write(identity.as_identity().verifying_key.as_bytes())?;
            output.write(&signature.to_bytes())?;
            output.offset()
        };

        self.encrypted_data_packet(&plaintext[..plaintext_len], PacketContext::LinkIdentify)
    }

    pub fn request_packet(&self, path: &str, data: Value) -> Result<Packet, RnsError> {
        let request = Value::Array(vec![
            Value::F64(now_seconds()),
            Value::Binary(
                AddressHash::new_from_slice(path.as_bytes())
                    .as_slice()
                    .to_vec(),
            ),
            data,
        ]);
        let packed_request = encode_msgpack(&request)?;
        if packed_request.len() > self.mdu() {
            return Err(RnsError::OutOfMemory);
        }

        self.encrypted_data_packet(&packed_request, PacketContext::Request)
    }

    pub fn response_packet(
        &self,
        request_id: AddressHash,
        data: Value,
    ) -> Result<Packet, RnsError> {
        self.response_packet_raw(request_id.as_slice(), data)
    }

    /// Build a response packet using raw request-id bytes as-is.
    ///
    /// The Python reference correlates responses against the request id it
    /// derives from the request (either from the transmitted packet or from
    /// the packed request payload), which may differ from this SDK's own
    /// request id convention. Passing the raw bytes here allows applications
    /// to interoperate with both implementations.
    pub fn response_packet_raw(
        &self,
        request_id: &[u8],
        data: Value,
    ) -> Result<Packet, RnsError> {
        let response = Value::Array(vec![Value::Binary(request_id.to_vec()), data]);
        let packed_response = encode_msgpack(&response)?;
        if packed_response.len() > self.mdu() {
            return Err(RnsError::OutOfMemory);
        }

        self.encrypted_data_packet(&packed_response, PacketContext::Response)
    }

    pub fn keep_alive_packet(&self, data: u8) -> Packet {
        log::trace!("link({}): create keep alive {}", self.id, data);

        let mut packet_data = PacketDataBuffer::new();
        packet_data.write(&[data]);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::KeepAlive,
            data: packet_data,
        }
    }

    pub fn message_proof(&self, hash: Hash) -> Packet {
        log::trace!(
            "link({}): creating proof for message hash {}",
            self.id,
            hash
        );

        let signature = self.priv_identity.sign(hash.as_slice());

        let mut packet_data = PacketDataBuffer::new();
        packet_data.write(hash.as_slice());
        packet_data.write(&signature.to_bytes()[..]);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        }
    }

    pub fn encrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        let mut rng = UnwrapErr(SysRng);
        self.priv_identity
            .encrypt(&mut rng, text, &self.derived_key, out_buf)
    }

    pub fn decrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        let mut rng = UnwrapErr(SysRng);
        self.priv_identity
            .decrypt(&mut rng, text, &self.derived_key, out_buf)
    }

    /// Decrypt `text` into a reusable scratch buffer and return an owned
    /// copy of the plaintext. Reusing a single buffer avoids a fresh
    /// zeroed heap allocation (up to the negotiated MDU) on every received
    /// packet, which is the dominant receive-path cost on high-throughput
    /// links. Field-level borrowing keeps `priv_identity`/`derived_key`
    /// (read) disjoint from the mutable scratch buffer so `decrypt` can be
    /// called without aliasing `self`.
    fn decrypt_into_owned(&mut self, text: &[u8]) -> Result<Vec<u8>, RnsError> {
        let decrypt_buf_len = self.mdu().max(PACKET_MDU);
        if self.decrypt_buffer.len() < decrypt_buf_len {
            self.decrypt_buffer.resize(decrypt_buf_len, 0);
        }
        let mut rng = UnwrapErr(SysRng);
        let priv_identity = &self.priv_identity;
        let derived_key = &self.derived_key;
        let buffer = &mut self.decrypt_buffer;
        let plain = priv_identity.decrypt(&mut rng, text, derived_key, buffer)?;
        Ok(plain.to_vec())
    }

    pub fn destination(&self) -> &DestinationDesc {
        &self.destination
    }

    /// Record inbound activity on the link. This is the only event that
    /// resets the staleness timer: it must never be called when *sending*
    /// traffic (e.g. keepalives), or a link whose peer has stopped
    /// responding would never be marked stale and closed.
    pub fn mark_activity(&mut self) {
        self.request_time = Instant::now();
    }

    /// Whether a keepalive request should be sent on this initiator link.
    ///
    /// Keepalives are only sent when the link has been quiet (no inbound
    /// traffic, i.e. `mark_activity`/received packets have not reset the
    /// timer) for at least the keepalive interval, and at most once per
    /// interval. This matches Python's `Link` watchdog: keepalives are sent
    /// at most every `keepalive` seconds and only when the link is idle
    /// (`Link.py:749-751`).
    pub(crate) fn keepalive_due(&self) -> bool {
        let now = Instant::now();
        now.saturating_duration_since(self.request_time) >= self.keepalive
            && now.saturating_duration_since(self.last_keepalive) >= self.keepalive
    }

    /// Record that a keepalive request was sent. This updates only the
    /// keepalive cadence timer and deliberately does *not* reset the
    /// staleness timer (see `mark_activity`).
    pub(crate) fn mark_keepalive_sent(&mut self) {
        self.last_keepalive = Instant::now();
    }

    pub fn create_rtt(&self) -> Packet {
        let rtt = self.rtt.as_secs_f64();
        let mut buf = Vec::new();
        {
            buf.reserve(9);
            rmp::encode::write_f64(&mut buf, rtt).unwrap();
        }

        let mut packet_data = PacketDataBuffer::new();

        let token_len = {
            let token = self
                .encrypt(
                    buf.as_slice(),
                    packet_data.acquire_buf(
                        buf.len() + RETICULUM_TOKEN_OVERHEAD + RETICULUM_AES_BLOCK_SIZE,
                    ),
                )
                .expect("encrypted data");
            token.len()
        };

        packet_data.resize(token_len);

        log::trace!("link: {} create rtt packet = {} sec", self.id, rtt);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRTT,
            data: packet_data,
        }
    }

    fn handshake(&mut self, peer_identity: Identity) {
        log::debug!("link({}): handshake", self.id);

        self.status = LinkStatus::Handshake;
        self.peer_identity = peer_identity;

        self.derived_key = self
            .priv_identity
            .derive_key(&self.peer_identity.public_key, Some(&self.id.as_slice()));
    }

    fn post_event(&self, event: LinkEvent) {
        let len = self.event_tx.len();
        if len >= crate::transport::EVENT_CHANNEL_CAPACITY {
            log::warn!(
                "link({}): event channel full ({} of {} slots used), events will be dropped.",
                self.id,
                len,
                crate::transport::EVENT_CHANNEL_CAPACITY,
            );
        }
        let _ = self.event_tx.send(LinkEventData {
            id: self.id,
            address_hash: self.destination.address_hash,
            event,
        });
    }

    fn validate_link_identify(&self, plaintext: &[u8]) -> Result<Identity, RnsError> {
        const PUBLIC_IDENTITY_LEN: usize = PUBLIC_KEY_LENGTH * 2;
        const IDENTIFY_LEN: usize = PUBLIC_IDENTITY_LEN + SIGNATURE_LENGTH;

        if plaintext.len() != IDENTIFY_LEN {
            return Err(RnsError::PacketError);
        }

        let identity = Identity::new_from_slices(
            &plaintext[..PUBLIC_KEY_LENGTH],
            &plaintext[PUBLIC_KEY_LENGTH..PUBLIC_IDENTITY_LEN],
        )?;
        let signature = Signature::from_slice(&plaintext[PUBLIC_IDENTITY_LEN..IDENTIFY_LEN])
            .map_err(|_| RnsError::PacketError)?;

        let mut signed_data = [0u8; ADDRESS_HASH_SIZE + PUBLIC_IDENTITY_LEN];
        let signed_data_len = {
            let mut output = OutputBuffer::new(&mut signed_data);
            output.write(self.id.as_slice())?;
            output.write(&plaintext[..PUBLIC_IDENTITY_LEN])?;
            output.offset()
        };

        identity.verify(&signed_data[..signed_data_len], &signature)?;
        Ok(identity)
    }

    pub(crate) fn teardown(&mut self) -> Result<Option<Packet>, RnsError> {
        let packet = if self.status != LinkStatus::Pending && self.status != LinkStatus::Closed {
            let mut packet = self.data_packet(self.id.as_slice())?;
            packet.context = PacketContext::LinkClose;
            Some(packet)
        } else {
            None
        };
        self.close();
        Ok(packet)
    }

    pub(crate) fn close(&mut self) {
        self.status = LinkStatus::Closed;
        self.post_event(LinkEvent::Closed);
        log::warn!("link: close {}", self.id);
    }

    pub fn stale(&mut self) {
        self.status = LinkStatus::Stale;

        log::warn!("link: stale {}", self.id);
    }

    pub fn restart(&mut self) {
        log::warn!(
            "link({}): restart after {}s",
            self.id,
            self.request_time.elapsed().as_secs()
        );

        self.status = LinkStatus::Pending;

        // A restart begins a fresh establishment attempt: re-anchor the
        // establishment timers so the pending-link watchdog and
        // rediscovery logic apply to this new attempt instead of failing
        // the link immediately on the budget from the previous one.
        self.request_time = Instant::now();
        self.next_retry_time = Instant::now();
        self.establishment_deadline = Instant::now() + DEFAULT_ESTABLISHMENT_TIMEOUT;
    }

    pub fn elapsed(&self) -> Duration {
        self.request_time.elapsed()
    }

    /// Whether the pending out-link request should be retransmitted. The
    /// cadence is tracked independently of the establishment anchor
    /// (`request_time`), so retransmissions cannot keep pushing the
    /// `INTERVAL_OUTPUT_LINK_TRIED` rediscovery logic into the future.
    pub(crate) fn request_retry_due(&self) -> bool {
        Instant::now() >= self.next_retry_time
    }

    /// Set the establishment deadline for this out-link. Called once when
    /// the link request is created; request retransmissions must not
    /// re-arm it or a pending link would never fail.
    pub fn set_establishment_deadline(&mut self, timeout: Duration) {
        self.establishment_deadline = Instant::now() + timeout;
    }

    /// Whether this out-link is still Pending past its establishment
    /// deadline and should be failed and removed.
    pub fn establishment_expired(&self) -> bool {
        self.status == LinkStatus::Pending && Instant::now() >= self.establishment_deadline
    }

    /// Test-only: age the establishment anchor so the pending-link
    /// rediscovery logic can be exercised without sleeping.
    #[cfg(test)]
    pub(crate) fn set_establishment_elapsed_for_test(&mut self, elapsed: Duration) {
        self.request_time = Instant::now() - elapsed;
    }

    pub fn status(&self) -> LinkStatus {
        self.status
    }

    pub fn id(&self) -> &LinkId {
        &self.id
    }

    /// The negotiated path MTU for this link.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn rtt(&self) -> &Duration {
        &self.rtt
    }
}

pub(crate) fn validate_proof_packet(
    destination: &DestinationDesc,
    id: &LinkId,
    packet: &Packet,
) -> Result<(Identity, usize), RnsError> {
    const MIN_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;
    const MTU_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + LINK_MTU_SIZE;
    const SIGN_DATA_LEN: usize = ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE;

    if packet.data.len() != MIN_PROOF_LEN && packet.data.len() != MTU_PROOF_LEN {
        return Err(RnsError::PacketError);
    }

    let mut proof_data = [0u8; SIGN_DATA_LEN];

    let verifying_key = destination.identity.verifying_key.as_bytes();
    let sign_data_len = {
        let mut output = OutputBuffer::new(&mut proof_data[..]);

        output.write(id.as_slice())?;
        output.write(
            &packet.data.as_slice()[SIGNATURE_LENGTH..SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH],
        )?;
        output.write(verifying_key)?;

        if packet.data.len() >= MTU_PROOF_LEN {
            let mtu_bytes = &packet.data.as_slice()[SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH..];
            if mode_from_signalling_bytes(mtu_bytes) != LINK_MODE_AES256_CBC {
                return Err(RnsError::InvalidArgument);
            }
            output.write(mtu_bytes)?;
        }

        output.offset()
    };

    let identity = Identity::new_from_slices(
        &proof_data[ADDRESS_HASH_SIZE..ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH],
        verifying_key,
    )?;

    let signature = Signature::from_slice(&packet.data.as_slice()[..SIGNATURE_LENGTH])
        .map_err(|_| RnsError::CryptoError)?;

    identity
        .verify(&proof_data[..sign_data_len], &signature)
        .map_err(|_| RnsError::IncorrectSignature)?;

    let mtu = if packet.data.len() >= MTU_PROOF_LEN {
        mtu_from_signalling_bytes(&packet.data.as_slice()[SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH..])
    } else {
        RETICULUM_MTU
    };

    Ok((identity, mtu))
}

fn validate_message_proof(
    peer_identity: &Identity,
    data: &[u8],
    expected_hash: Option<&Hash>,
) -> Result<Hash, RnsError> {
    if data.len() == HASH_SIZE + SIGNATURE_LENGTH {
        // Explicit proof: first HASH_SIZE bytes are the hash, rest is the signature
        let hash_slice = &data[..HASH_SIZE];
        let signature =
            Signature::from_slice(&data[HASH_SIZE..]).map_err(|_| RnsError::PacketError)?;
        peer_identity
            .verify(hash_slice, &signature)
            .map_err(|_| RnsError::IncorrectSignature)?;
        Ok(Hash::new(hash_slice.try_into().unwrap()))
    } else if data.len() == SIGNATURE_LENGTH {
        // Implicit proof: entire data is the signature, hash must be provided externally
        let hash = expected_hash.ok_or(RnsError::PacketError)?;
        let signature = Signature::from_slice(data).map_err(|_| RnsError::PacketError)?;
        peer_identity
            .verify(hash.as_slice(), &signature)
            .map_err(|_| RnsError::IncorrectSignature)?;
        Ok(*hash)
    } else {
        Err(RnsError::PacketError)
    }
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs_f64()
}

fn encode_msgpack(value: &Value) -> Result<Vec<u8>, RnsError> {
    let mut out = Vec::new();
    write_value(&mut out, value).map_err(|_| RnsError::InvalidArgument)?;
    Ok(out)
}

fn decode_link_request(
    data: &[u8],
    request_id: AddressHash,
    request_id_raw: Vec<u8>,
) -> Result<LinkRequest, RnsError> {
    let value = read_value(&mut &data[..]).map_err(|_| RnsError::PacketError)?;
    let values = value.as_array().ok_or(RnsError::PacketError)?;
    if values.len() != 3 {
        return Err(RnsError::PacketError);
    }

    let requested_at = values[0].as_f64().ok_or(RnsError::PacketError)?;
    let path_hash_raw = values[1].as_slice().ok_or(RnsError::PacketError)?.to_vec();
    let path_hash = address_hash_from_raw(&path_hash_raw);

    Ok(LinkRequest {
        request_id,
        request_id_raw,
        path_hash,
        path_hash_raw,
        requested_at,
        data: values[2].clone(),
    })
}

/// Compute the request id the way the Python reference does for inline
/// requests: the first 16 bytes of SHA-256 over the packet's hashable part
/// (header flags | destination | context | ciphertext), matching
/// `Packet.getTruncatedHash()`. Python sends requests either inline in a
/// packet (in which case the request id is derived from the transmitted
/// packet hashable part) or as a resource (in which case it is derived
/// from the packed request payload, computed by the caller from the
/// reassembled data).
fn python_request_id(packet: &Packet) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([packet.header.to_meta() & 0b0000_1111]);
    hasher.update(packet.destination.as_slice());
    hasher.update([packet.context as u8]);
    hasher.update(packet.data.as_slice());
    let digest = hasher.finalize();
    digest[..ADDRESS_HASH_SIZE].to_vec()
}

/// Convert raw request path-hash bytes into an address hash.
///
/// The Python reference sends the full 16-byte truncated hash of the
/// request path. The value is copied as-is when it matches the address
/// size; anything shorter is left-aligned and zero-padded so the leading
/// bytes remain comparable.
fn address_hash_from_raw(raw: &[u8]) -> AddressHash {
    let mut hash = [0u8; ADDRESS_HASH_SIZE];
    let n = core::cmp::min(raw.len(), ADDRESS_HASH_SIZE);
    hash[..n].copy_from_slice(&raw[..n]);
    AddressHash::new(hash)
}

fn decode_link_response(data: &[u8]) -> Result<LinkResponse, RnsError> {
    let value = read_value(&mut &data[..]).map_err(|_| RnsError::PacketError)?;
    let values = value.as_array().ok_or(RnsError::PacketError)?;
    if values.len() != 2 {
        return Err(RnsError::PacketError);
    }

    Ok(LinkResponse {
        request_id: read_address_hash(&values[0])?,
        data: values[1].clone(),
    })
}

fn read_address_hash(value: &Value) -> Result<AddressHash, RnsError> {
    let bytes = value.as_slice().ok_or(RnsError::PacketError)?;
    if bytes.len() != ADDRESS_HASH_SIZE {
        return Err(RnsError::PacketError);
    }

    let mut hash = [0u8; ADDRESS_HASH_SIZE];
    hash.copy_from_slice(bytes);
    Ok(AddressHash::new(hash))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rmpv::Value;
    use x25519_dalek::StaticSecret;

    use crate::destination::{DestinationName, SingleInputDestination};
    use crate::error::RnsError;
    use crate::hash::{AddressHash, ADDRESS_HASH_SIZE};
    use crate::identity::PrivateIdentity;
    use crate::packet::{DestinationType, LINK_PACKET_MDU, PacketContext, PacketType};
    use crate::serde::Serialize;
    use crate::test_vectors;
    use sha2::{Digest, Sha256};

    use super::{
        ChannelEnvelope, ChannelMessage, KEEPALIVE_INTERVAL, LINK_MTU_SIZE, Link, LinkEvent,
        LinkHandleResult, LinkStatus,
    };
    use std::time::{Duration, Instant};

    struct TestChannelMessage(Vec<u8>);

    impl ChannelMessage for TestChannelMessage {
        const MSG_TYPE: u16 = 0x1234;

        fn pack(&self) -> Result<Vec<u8>, RnsError> {
            Ok(self.0.clone())
        }

        fn unpack(payload: &[u8]) -> Result<Self, RnsError> {
            Ok(Self(payload.to_vec()))
        }
    }

    #[test]
    fn prove_emits_lrproof_with_link_destination_type() {
        let identity = PrivateIdentity::new(
            StaticSecret::from(test_vectors::FIXED_LINK_OWNER_PRIVATE_KEY),
            SigningKey::from_bytes(&test_vectors::FIXED_LINK_OWNER_SIGNING_KEY),
        );
        let destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "link.prove"),
        );
        let (event_tx, _) = tokio::sync::broadcast::channel(1);
        let mut link = Link::new(destination.desc, event_tx);
        link.id = AddressHash::new(test_vectors::FIXED_LRPROOF_LINK_ID);
        link.priv_identity = PrivateIdentity::new(
            StaticSecret::from(test_vectors::FIXED_LRPROOF_X25519_PRIVATE_KEY),
            SigningKey::from_bytes(&test_vectors::FIXED_LINK_OWNER_SIGNING_KEY),
        );

        let proof = link.prove();

        assert_eq!(proof.header.destination_type, DestinationType::Link);
        assert_eq!(proof.header.packet_type, PacketType::Proof);
        assert_eq!(proof.context, PacketContext::LinkRequestProof);
        assert_eq!(proof.destination, link.id);
        let mut proof_data = [0u8; 4096];
        let mut proof_buffer = crate::buffer::OutputBuffer::new(&mut proof_data);
        proof.serialize(&mut proof_buffer).expect("proof");
        assert_eq!(
            proof_buffer.as_slice(),
            test_vectors::decode_hex(test_vectors::LRPROOF_PACKET_HEX).as_slice()
        );
    }

    fn create_active_link_pair() -> (
        Link,
        Link,
        tokio::sync::broadcast::Receiver<super::LinkEventData>,
        tokio::sync::broadcast::Receiver<super::LinkEventData>,
    ) {
        create_active_link_pair_with_capacity(8)
    }

    fn create_active_link_pair_with_capacity(
        capacity: usize,
    ) -> (
        Link,
        Link,
        tokio::sync::broadcast::Receiver<super::LinkEventData>,
        tokio::sync::broadcast::Receiver<super::LinkEventData>,
    ) {
        let identity = PrivateIdentity::new_from_name("link owner");
        let destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "link.requests"),
        );
        let (out_event_tx, mut out_event_rx) = tokio::sync::broadcast::channel(capacity);
        let (in_event_tx, mut in_event_rx) = tokio::sync::broadcast::channel(capacity);

        let mut out_link = Link::new(destination.desc, out_event_tx);
        let link_request = out_link.request(None);
        let mut in_link = Link::new_from_request(
            &link_request,
            destination.sign_key().clone(),
            destination.desc,
            in_event_tx,
        )
        .expect("input link");
        let proof = in_link.prove();
        match out_link.handle_packet(&proof, true) {
            super::LinkHandleResult::Activated => {}
            _ => unreachable!("link proof should activate output link"),
        }
        let _ = in_event_rx.try_recv();
        let _ = out_event_rx.try_recv();

        (out_link, in_link, out_event_rx, in_event_rx)
    }

    #[test]
    fn link_request_rejects_python_incompatible_payload_lengths() {
        let identity = PrivateIdentity::new_from_name("invalid request owner");
        let destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "link.invalid_request"),
        );
        let (event_tx, _) = tokio::sync::broadcast::channel(1);
        let mut out_link = Link::new(destination.desc, event_tx.clone());
        let mut request = out_link.request(None);
        request.data.write(&[0x00]);

        let result = Link::new_from_request(
            &request,
            destination.sign_key().clone(),
            destination.desc,
            event_tx,
        );

        assert!(matches!(result, Err(RnsError::InvalidArgument)));
    }

    #[test]
    fn link_request_rejects_unsupported_signalled_mode() {
        let identity = PrivateIdentity::new_from_name("invalid mode owner");
        let destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "link.invalid_mode"),
        );
        let (event_tx, _) = tokio::sync::broadcast::channel(1);
        let mut out_link = Link::new(destination.desc, event_tx.clone());
        let mut request = out_link.request(None);
        let offset = request.data.len() - LINK_MTU_SIZE;
        request.data.as_mut_slice()[offset] = 0x40;

        let result = Link::new_from_request(
            &request,
            destination.sign_key().clone(),
            destination.desc,
            event_tx,
        );

        assert!(matches!(result, Err(RnsError::InvalidArgument)));
    }

    #[test]
    fn link_identify_emits_remote_identity() {
        let (out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        let remote_identity = PrivateIdentity::new_from_name("lxmf propagation peer");
        let identify = out_link
            .identify_packet(&remote_identity)
            .expect("identify packet");

        in_link.handle_packet(&identify, false);

        let event = in_events.try_recv().expect("identity event");
        match event.event {
            LinkEvent::RemoteIdentified(identity) => {
                assert_eq!(identity.address_hash, *remote_identity.address_hash());
            }
            _ => unreachable!("unexpected link event"),
        }
    }

    #[test]
    fn link_request_and_response_emit_events() {
        let (mut out_link, mut in_link, mut out_events, mut in_events) = create_active_link_pair();
        let request = out_link
            .request_packet(
                "/offer",
                Value::Array(vec![Value::from(1), Value::from("abc")]),
            )
            .expect("request packet");
        let request_id = AddressHash::new_from_hash(&request.hash());
        let mut python_hasher = Sha256::new();
        python_hasher.update([request.header.to_meta() & 0b0000_1111]);
        python_hasher.update(request.destination.as_slice());
        python_hasher.update([PacketContext::Request as u8]);
        python_hasher.update(request.data.as_slice());
        let python_request_id = python_hasher.finalize()[..ADDRESS_HASH_SIZE].to_vec();

        in_link.handle_packet(&request, false);

        let event = in_events.try_recv().expect("request event");
        match event.event {
            LinkEvent::Request(request) => {
                assert_eq!(request.request_id, request_id);
                assert_eq!(request.request_id_raw, python_request_id);
                assert_eq!(request.path_hash, AddressHash::new_from_slice(b"/offer"));
                assert_eq!(
                    request.data,
                    Value::Array(vec![Value::from(1), Value::from("abc")])
                );
            }
            _ => unreachable!("unexpected link event"),
        }

        let response = in_link
            .response_packet(request_id, Value::from(true))
            .expect("response packet");
        out_link.handle_packet(&response, true);

        let event = out_events.try_recv().expect("response event");
        match event.event {
            LinkEvent::Response(response) => {
                assert_eq!(response.request_id, request_id);
                assert_eq!(response.data, Value::from(true));
            }
            _ => unreachable!("unexpected link event"),
        }
    }

    #[test]
    fn channel_envelope_matches_python_wire_format() {
        let envelope = ChannelEnvelope::new(0x1234, 0x0002, b"hello").expect("envelope");
        let raw = envelope.pack().expect("packed envelope");

        assert_eq!(
            raw,
            vec![
                0x12, 0x34, 0x00, 0x02, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'
            ]
        );
        assert_eq!(ChannelEnvelope::unpack(&raw).expect("unpacked"), envelope);
        assert!(ChannelEnvelope::unpack(&raw[..raw.len() - 1]).is_err());
    }

    #[test]
    fn channel_packet_uses_channel_context_and_sequence() {
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        // Opt in to per-message proofs so the proof header is verified.
        in_link.prove_messages(true);
        let message = TestChannelMessage(b"hello".to_vec());
        let packet = out_link.channel_packet(&message).expect("channel packet");

        assert_eq!(packet.header.destination_type, DestinationType::Link);
        assert_eq!(packet.header.packet_type, PacketType::Data);
        assert_eq!(packet.context, PacketContext::Channel);

        match in_link.handle_packet(&packet, false) {
            LinkHandleResult::MessageReceived(Some(proof)) => {
                assert_eq!(proof.header.destination_type, DestinationType::Link);
                assert_eq!(proof.header.packet_type, PacketType::Proof);
            }
            _ => unreachable!("channel packet should request a proof"),
        }

        let event = in_events.try_recv().expect("channel event");
        match event.event {
            LinkEvent::Channel(envelope) => {
                assert_eq!(envelope.msg_type, TestChannelMessage::MSG_TYPE);
                assert_eq!(envelope.sequence, 0);
                assert_eq!(envelope.payload, b"hello");
                let decoded =
                    TestChannelMessage::unpack(&envelope.payload).expect("decoded channel message");
                assert_eq!(decoded.0, b"hello");
            }
            _ => unreachable!("unexpected link event"),
        }
    }

    #[test]
    fn link_packets_reject_payloads_over_link_mdu() {
        let (out_link, _in_link, _out_events, _in_events) = create_active_link_pair();
        let payload = vec![0x42u8; LINK_PACKET_MDU + 1];

        assert!(matches!(
            out_link.data_packet(&payload),
            Err(RnsError::OutOfMemory)
        ));
    }

    #[test]
    fn destination_side_validates_initiator_signed_message_proofs() {
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        out_link.prove_messages(true);

        let packet = in_link
            .data_packet(b"message from destination")
            .expect("link packet");
        let expected_hash = packet.hash();
        let proof = match out_link.handle_packet(&packet, true) {
            LinkHandleResult::MessageReceived(Some(proof)) => proof,
            _ => unreachable!("initiator should prove received message"),
        };

        assert!(matches!(
            in_link.handle_packet(&proof, false),
            LinkHandleResult::None
        ));
        let event = in_events.try_recv().expect("proof event");
        match event.event {
            LinkEvent::Proof(hash) => assert_eq!(hash, expected_hash),
            _ => unreachable!("unexpected link event"),
        }
    }

    #[test]
    fn channel_mdu_reserves_channel_header_from_link_mdu() {
        let (out_link, _in_link, _out_events, _in_events) = create_active_link_pair();

        assert_eq!(
            out_link.channel_mdu(),
            LINK_PACKET_MDU - super::CHANNEL_HEADER_SIZE
        );
    }

    #[test]
    fn channel_receive_delivers_contiguous_messages_in_order() {
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        let first = out_link
            .channel_raw_packet(0x1234, b"first")
            .expect("first channel packet");
        let second = out_link
            .channel_raw_packet(0x1234, b"second")
            .expect("second channel packet");

        assert!(matches!(
            in_link.handle_packet(&second, false),
            LinkHandleResult::MessageReceived(_)
        ));
        assert!(in_events.try_recv().is_err());

        assert!(matches!(
            in_link.handle_packet(&first, false),
            LinkHandleResult::MessageReceived(_)
        ));

        let event = in_events.try_recv().expect("first channel event");
        match event.event {
            LinkEvent::Channel(envelope) => {
                assert_eq!(envelope.sequence, 0);
                assert_eq!(envelope.payload, b"first");
            }
            _ => unreachable!("unexpected link event"),
        }

        let event = in_events.try_recv().expect("second channel event");
        match event.event {
            LinkEvent::Channel(envelope) => {
                assert_eq!(envelope.sequence, 1);
                assert_eq!(envelope.payload, b"second");
            }
            _ => unreachable!("unexpected link event"),
        }
    }

    #[test]
    fn channel_packet_accepts_system_message_types() {
        let (mut out_link, _in_link, _out_events, _in_events) = create_active_link_pair();
        let packet = out_link
            .channel_raw_packet(0xff00, b"")
            .expect("system channel packet");

        assert_eq!(packet.context, PacketContext::Channel);
    }

    #[test]
    fn channel_receive_buffers_large_out_of_order_burst_and_delivers_in_order() {
        // A burst larger than the old 48-packet window must be buffered and
        // then delivered in sequence order once the heads arrive.
        let (mut out_link, mut in_link, _out_events, mut in_events) =
            create_active_link_pair_with_capacity(super::CHANNEL_WINDOW_MAX as usize + 8);
        // A modest burst that still exceeds the old 48-packet window by a
        // wide margin, but completes quickly enough that the 500 ms stall
        // recovery does not interfere.
        let count: usize = 512;
        let packets: Vec<_> = (0..count)
            .map(|i| {
                out_link
                    .channel_raw_packet(0x1234, &i.to_be_bytes())
                    .expect("channel packet")
            })
            .collect();

        // Deliver all but the first in reverse order; nothing may be emitted.
        for packet in packets[1..].iter().rev() {
            assert!(matches!(
                in_link.handle_packet(packet, false),
                LinkHandleResult::MessageReceived(_)
            ));
        }
        assert!(in_events.try_recv().is_err());

        // The head (sequence 0) fills the gap and the whole burst flushes.
        assert!(matches!(
            in_link.handle_packet(&packets[0], false),
            LinkHandleResult::MessageReceived(_)
        ));
        let mut seen = Vec::new();
        while let Ok(ev) = in_events.try_recv() {
            match ev.event {
                LinkEvent::Channel(envelope) => seen.push(envelope.sequence),
                _ => unreachable!("unexpected link event"),
            }
        }
        assert_eq!(seen, (0..count as u16).collect::<Vec<_>>());
    }

    #[test]
    fn channel_receive_recovers_from_lost_sequence_after_stall_timeout() {
        // Sequence 0 is lost. Everything after it is buffered, and once the
        // stall exceeds CHANNEL_REORDER_TIMEOUT the buffer is flushed (gaps
        // skipped) so the stream keeps making progress.
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        let packets: Vec<_> = (0..7)
            .map(|i| {
                out_link
                    .channel_raw_packet(0x1234, &[i])
                    .expect("channel packet")
            })
            .collect();

        // Feed 1..=5; sequence 0 is missing.
        for packet in &packets[1..6] {
            assert!(matches!(
                in_link.handle_packet(packet, false),
                LinkHandleResult::MessageReceived(_)
            ));
        }
        assert!(in_events.try_recv().is_err());
        assert!(in_link.channel_rx_stall_since.is_some());

        // Force the stall to have expired, then a subsequent arrival
        // triggers recovery and flushes the buffered packets.
        in_link.channel_rx_stall_since = Some(
            Instant::now() - super::CHANNEL_REORDER_TIMEOUT - Duration::from_secs(1),
        );
        assert!(matches!(
            in_link.handle_packet(&packets[6], false),
            LinkHandleResult::MessageReceived(_)
        ));

        let mut seen = Vec::new();
        while let Ok(ev) = in_events.try_recv() {
            match ev.event {
                LinkEvent::Channel(envelope) => seen.push(envelope.sequence),
                _ => unreachable!("unexpected link event"),
            }
        }
        // 0 was lost; 1..=6 are delivered in order and the stream advances.
        assert_eq!(seen, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(in_link.next_rx_channel_sequence, 7);
        assert!(in_link.channel_rx_stall_since.is_none());
    }

    #[test]
    fn channel_receive_resynchronises_when_stream_jumps_ahead() {
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        out_link.next_channel_sequence = 20000;
        let packet = out_link
            .channel_raw_packet(0x1234, b"jump")
            .expect("channel packet");

        // Nothing buffered and the sequence is far outside the window: the
        // link resynchronises instead of discarding the stream.
        assert!(matches!(
            in_link.handle_packet(&packet, false),
            LinkHandleResult::MessageReceived(_)
        ));
        let event = in_events.try_recv().expect("resync channel event");
        match event.event {
            LinkEvent::Channel(envelope) => {
                assert_eq!(envelope.sequence, 20000);
                assert_eq!(envelope.payload, b"jump");
            }
            _ => unreachable!("unexpected link event"),
        }
        assert_eq!(in_link.next_rx_channel_sequence, 20001);
    }

    #[test]
    fn channel_receive_handles_sequence_wraparound() {
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
        in_link.next_rx_channel_sequence = u16::MAX - 1;
        out_link.next_channel_sequence = u16::MAX - 1;

        for expected in [u16::MAX - 1, u16::MAX, 0, 1] {
            let packet = out_link
                .channel_raw_packet(0x1234, &expected.to_be_bytes())
                .expect("channel packet");
            assert!(matches!(
                in_link.handle_packet(&packet, false),
                LinkHandleResult::MessageReceived(_)
            ));
            let event = in_events.try_recv().expect("channel event");
            match event.event {
                LinkEvent::Channel(envelope) => assert_eq!(envelope.sequence, expected),
                _ => unreachable!("unexpected link event"),
            }
        }
        assert_eq!(in_link.next_rx_channel_sequence, 2);
    }

    fn keepalive_test_link() -> Link {
        let (event_tx, _) = tokio::sync::broadcast::channel(1);
        let destination = SingleInputDestination::new(
            PrivateIdentity::new_from_name("keepalive"),
            DestinationName::new("example_utilities", "keepalive.test"),
        );
        Link::new(destination.desc, event_tx)
    }

    #[test]
    fn fresh_link_keepalive_is_not_due() {
        let link = keepalive_test_link();
        assert!(
            !link.keepalive_due(),
            "a freshly created link must not send a keepalive"
        );
    }

    #[test]
    fn idle_link_keepalive_due_after_interval() {
        let mut link = keepalive_test_link();
        // The peer has been silent for longer than the keepalive interval
        // and no keepalive has been sent in that time.
        let past = Instant::now() - KEEPALIVE_INTERVAL - Duration::from_secs(1);
        link.request_time = past;
        link.last_keepalive = past;
        assert!(
            link.keepalive_due(),
            "an idle link must send a keepalive once the interval elapses"
        );
    }

    #[test]
    fn keepalive_send_is_gated_by_cadence() {
        let mut link = keepalive_test_link();
        let past = Instant::now() - KEEPALIVE_INTERVAL - Duration::from_secs(1);
        link.request_time = past;
        link.last_keepalive = past;
        assert!(link.keepalive_due());

        link.mark_keepalive_sent();
        assert!(
            !link.keepalive_due(),
            "a second keepalive must not be sent before the interval elapses again"
        );
    }

    #[test]
    fn active_traffic_suppresses_keepalive() {
        let mut link = keepalive_test_link();
        link.last_keepalive = Instant::now() - KEEPALIVE_INTERVAL - Duration::from_secs(1);
        // Inbound traffic keeps the activity timer fresh.
        link.mark_activity();
        assert!(
            !link.keepalive_due(),
            "recent inbound traffic must suppress keepalives"
        );
    }

    #[test]
    fn keepalive_send_does_not_reset_staleness() {
        let mut link = keepalive_test_link();
        let past = Instant::now() - Duration::from_secs(2);
        link.request_time = past;

        link.mark_keepalive_sent();

        assert_eq!(
            link.request_time, past,
            "sending a keepalive must not reset the staleness timer"
        );
    }

    #[test]
    fn pending_link_expires_after_establishment_deadline() {
        let mut link = keepalive_test_link();
        link.status = LinkStatus::Pending;

        // A pending link inside its establishment budget has not expired.
        link.set_establishment_deadline(Duration::from_secs(60));
        assert!(!link.establishment_expired());

        // Once the deadline passes, a still-pending link has expired.
        link.set_establishment_deadline(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(link.establishment_expired());

        // An established link is never considered establishment-expired,
        // even if the deadline has long since passed.
        link.status = LinkStatus::Active;
        assert!(!link.establishment_expired());
    }

    #[test]
    fn request_retransmission_does_not_reset_establishment_anchor() {
        let mut link = keepalive_test_link();
        link.status = LinkStatus::Pending;
        let anchor = link.request_time;

        // A (re)transmission must advance the retry cadence but leave the
        // establishment anchor untouched, otherwise `elapsed()` could
        // never reach the "tried" threshold and the pending-link
        // rediscovery logic would be dead code.
        link.request(None);
        assert_eq!(
            link.request_time, anchor,
            "retransmitting a link request must not reset request_time"
        );
        assert!(
            link.request_time.elapsed() < Duration::from_secs(1),
            "the establishment anchor must stay fresh after creation"
        );
    }

    #[test]
    fn request_retry_is_not_due_until_interval_elapses() {
        let mut link = keepalive_test_link();
        link.status = LinkStatus::Pending;

        // Right after a request is sent the retry is not yet due...
        link.request(None);
        assert!(
            !link.request_retry_due(),
            "a freshly sent request must not be immediately due for retransmission"
        );

        // ...but once the cadence interval has elapsed it is.
        link.next_retry_time = Instant::now() - Duration::from_millis(1);
        assert!(link.request_retry_due());
    }

    #[test]
    fn pending_elapsed_keeps_aging_across_retransmissions() {
        let mut link = keepalive_test_link();
        link.status = LinkStatus::Pending;

        // Age the link past the "tried" threshold, then retransmit several
        // times: each retransmission must not reset the establishment
        // anchor, so the link stays past the threshold where the
        // rediscovery logic fires.
        link.request_time = Instant::now() - Duration::from_secs(31);
        for _ in 0..10 {
            link.next_retry_time = Instant::now() - Duration::from_millis(1);
            link.request(None);
        }

        assert!(
            link.elapsed() > Duration::from_secs(30),
            "retransmissions must not reset the establishment anchor"
        );
    }

    #[test]
    fn restart_reanchors_establishment_timers() {
        let mut link = keepalive_test_link();
        link.status = LinkStatus::Active;

        // Age the link far past both the tried threshold and the
        // establishment deadline from its original attempt.
        let past = Instant::now() - Duration::from_secs(3600);
        link.request_time = past;
        link.next_retry_time = past;
        link.set_establishment_deadline(Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(5));

        // A restart begins a fresh establishment attempt, so every
        // establishment timer must be re-anchored.
        link.restart();

        assert_eq!(link.status, LinkStatus::Pending);
        assert!(
            link.request_time.elapsed() < Duration::from_secs(1),
            "restart must reset the establishment anchor"
        );
        assert!(
            !link.establishment_expired(),
            "restart must re-arm the establishment deadline"
        );
        assert!(
            link.request_retry_due(),
            "a restarted link should send a fresh request promptly"
        );
    }

    #[test]
    fn resource_proof_is_proof_packet_and_routed_to_resource_handler() {
        let (out_link, mut in_link, _, mut in_event_rx) = create_active_link_pair();

        let proof_data = b"proof-blob".to_vec();
        let proof = out_link
            .resource_proof_packet(&proof_data)
            .expect("resource proof packet");

        // Matching the Python reference, resource proofs are PROOF packets
        // with a RESOURCE_PRF context, sent unencrypted over the link.
        assert_eq!(proof.header.packet_type, PacketType::Proof);
        assert_eq!(proof.context, PacketContext::ResourceProof);
        assert_eq!(proof.destination, out_link.id);
        assert_eq!(proof.data.as_slice(), proof_data.as_slice());

        let result = in_link.handle_packet(&proof, false);
        assert!(matches!(result, LinkHandleResult::None));

        let event_data = in_event_rx
            .try_recv()
            .expect("expected a resource event on the link");
        match event_data.event {
            LinkEvent::Resource(resource) => {
                assert_eq!(resource.context, PacketContext::ResourceProof);
                assert_eq!(resource.data, proof_data);
                assert_eq!(resource.packet_hash, proof.hash());
            }
            _ => panic!("expected resource event, got other event"),
        }
    }
}
