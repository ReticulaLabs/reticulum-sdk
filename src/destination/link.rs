use std::{
    cmp::min,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, SigningKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand_core::OsRng;
use rmpv::{decode::read_value, encode::write_value, Value};
use sha2::Digest;
use x25519_dalek::StaticSecret;

use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::{AddressHash, Hash, ADDRESS_HASH_SIZE, HASH_SIZE},
    identity::{DecryptIdentity, DerivedKey, EncryptIdentity, Identity, PrivateIdentity},
    packet::{
        DestinationType, Header, Packet, PacketContext, PacketDataBuffer, PacketType,
        LINK_PACKET_MDU, PACKET_MDU, RETICULUM_MTU,
    },
};

use super::DestinationDesc;

const LINK_MTU_SIZE: usize = 3;
const LINK_MODE_AES256_CBC: u8 = 0x01;
const CHANNEL_HEADER_SIZE: usize = 6;
const CHANNEL_SEQUENCE_MAX: u16 = u16::MAX;
const CHANNEL_SEQUENCE_MODULUS: u32 = CHANNEL_SEQUENCE_MAX as u32 + 1;
const CHANNEL_WINDOW_MAX: u16 = 48;

fn link_signalling_bytes() -> [u8; LINK_MTU_SIZE] {
    let mode_bits = ((LINK_MODE_AES256_CBC << 5) & 0xE0) as u32;
    let signalling_value = (RETICULUM_MTU as u32 & 0x1F_FFFF) + (mode_bits << 16);
    let bytes = signalling_value.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
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
    buffer: [u8; PACKET_MDU],
    len: usize,
}

impl LinkPayload {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; PACKET_MDU],
            len: 0,
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut buffer = [0u8; PACKET_MDU];

        let len = min(data.len(), buffer.len());

        buffer[..len].copy_from_slice(&data[..len]);

        Self { buffer, len }
    }

    pub fn new_from_vec(data: &Vec<u8>) -> Self {
        let mut buffer = [0u8; PACKET_MDU];
        let len = min(buffer.len(), data.len());

        for i in 0..len {
            buffer[i] = data[i];
        }

        Self { buffer, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
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
    Data(LinkPayload),
    RemoteIdentified(Identity),
    Request(LinkRequest),
    Response(LinkResponse),
    Channel(ChannelEnvelope),
    Proof(Hash),
    Closed,
}

#[derive(Clone)]
pub struct LinkRequest {
    pub request_id: AddressHash,
    pub path_hash: AddressHash,
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
    request_time: Instant,
    rtt: Duration,
    event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    proves_messages: bool,
    next_channel_sequence: u16,
    next_rx_channel_sequence: u16,
    channel_rx_ring: Vec<ChannelEnvelope>,
}

impl Link {
    pub fn new(
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Self {
        Self {
            id: AddressHash::new_empty(),
            destination,
            priv_identity: PrivateIdentity::new_from_rand(OsRng),
            peer_identity: Identity::default(),
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            proves_messages: false,
            next_channel_sequence: 0,
            next_rx_channel_sequence: 0,
            channel_rx_ring: Vec::new(),
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
        if packet.data.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::InvalidArgument);
        }

        let peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        );

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {}", link_id);

        let mut link = Self {
            id: link_id,
            destination,
            priv_identity: PrivateIdentity::new(StaticSecret::random_from_rng(OsRng), signing_key),
            peer_identity,
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            proves_messages: false,
            next_channel_sequence: 0,
            next_rx_channel_sequence: 0,
            channel_rx_ring: Vec::new(),
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub fn request(&mut self) -> Packet {
        let mut packet_data = PacketDataBuffer::new();
        let signalling = link_signalling_bytes();

        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());
        packet_data.safe_write(&signalling);

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
        self.request_time = Instant::now();

        packet
    }

    pub fn prove(&mut self) -> Packet {
        log::debug!("link({}): prove", self.id);

        if self.status != LinkStatus::Active {
            self.status = LinkStatus::Active;
            self.post_event(LinkEvent::Activated);
        }

        let mut packet_data = PacketDataBuffer::new();
        let signalling = link_signalling_bytes();

        packet_data.safe_write(self.id.as_slice());
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());
        packet_data.safe_write(&signalling);

        let signature = self.priv_identity.sign(packet_data.as_slice());

        packet_data.reset();
        packet_data.safe_write(&signature.to_bytes()[..]);
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(&signalling);

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
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): data {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Data(LinkPayload::new_from_slice(plain_text)));

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
                    let mut buffer = [0u8; PACKET_MDU];
                    if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                        match self.validate_link_identify(plain_text) {
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
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    let request_id = AddressHash::new_from_hash(&packet.hash());
                    match decode_link_request(plain_text, request_id) {
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
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    match decode_link_response(plain_text) {
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
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    match ChannelEnvelope::unpack(plain_text) {
                        Ok(envelope) => {
                            self.request_time = Instant::now();
                            self.handle_channel_envelope(envelope);
                            return LinkHandleResult::MessageReceived(Some(
                                self.message_proof(packet.hash()),
                            ));
                        }
                        Err(err) => {
                            log::warn!("link({}): invalid channel packet: {err:?}", self.id);
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt channel packet", self.id);
                }
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
                    let mut buffer = [0u8; PACKET_MDU];
                    if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                        if let Ok(rtt) = rmp::decode::read_f32(&mut &plain_text[..]) {
                            self.rtt = Duration::from_secs_f32(rtt);
                        } else {
                            log::error!("link({}): failed to decode rtt", self.id);
                        }
                    } else {
                        log::error!("link({}): can't decrypt rtt packet", self.id);
                    }
                }
            }
            PacketContext::LinkClose => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
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
            PacketType::Proof => return self.handle_proof_packet(packet),
            _ => return LinkHandleResult::None,
        }
    }

    fn handle_proof_packet(&mut self, packet: &Packet) -> LinkHandleResult {
        if self.status == LinkStatus::Pending && packet.context == PacketContext::LinkRequestProof {
            if let Ok(identity) = validate_proof_packet(&self.destination, &self.id, packet) {
                log::debug!("link({}): has been proved", self.id);

                self.handshake(identity);

                self.status = LinkStatus::Active;
                self.rtt = self.request_time.elapsed();

                log::debug!("link({}): activated", self.id);

                self.post_event(LinkEvent::Activated);

                return LinkHandleResult::Activated;
            } else {
                log::warn!("link({}): proof is not valid", self.id);
            }
        }

        if self.status == LinkStatus::Active && packet.context == PacketContext::None {
            if let Ok(hash) = validate_message_proof(&self.peer_identity, packet.data.as_slice()) {
                self.post_event(LinkEvent::Proof(hash));
            }
        }

        return LinkHandleResult::None;
    }

    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        self.encrypted_data_packet(data, PacketContext::None)
    }

    pub fn channel_mdu(&self) -> usize {
        LINK_PACKET_MDU.saturating_sub(CHANNEL_HEADER_SIZE)
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
        if data.len() > LINK_PACKET_MDU {
            return Err(RnsError::OutOfMemory);
        }

        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.encrypt(data, packet_data.accuire_buf_max())?;
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
        if !self.channel_sequence_in_window(envelope.sequence) {
            log::trace!(
                "link({}): invalid channel sequence {}",
                self.id,
                envelope.sequence
            );
            return;
        }

        if self
            .channel_rx_ring
            .iter()
            .any(|existing| existing.sequence == envelope.sequence)
        {
            log::trace!(
                "link({}): duplicate channel sequence {}",
                self.id,
                envelope.sequence
            );
            return;
        }

        self.channel_rx_ring.push(envelope);
        self.channel_rx_ring.sort_by_key(|envelope| {
            channel_sequence_distance(self.next_rx_channel_sequence, envelope.sequence)
        });

        while let Some(index) = self
            .channel_rx_ring
            .iter()
            .position(|envelope| envelope.sequence == self.next_rx_channel_sequence)
        {
            let envelope = self.channel_rx_ring.remove(index);
            self.next_rx_channel_sequence = self.next_rx_channel_sequence.wrapping_add(1);
            self.post_event(LinkEvent::Channel(envelope));
        }
    }

    fn channel_sequence_in_window(&self, sequence: u16) -> bool {
        channel_sequence_distance(self.next_rx_channel_sequence, sequence)
            < CHANNEL_WINDOW_MAX as u32
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
        if packed_request.len() > LINK_PACKET_MDU {
            return Err(RnsError::OutOfMemory);
        }

        self.encrypted_data_packet(&packed_request, PacketContext::Request)
    }

    pub fn response_packet(
        &self,
        request_id: AddressHash,
        data: Value,
    ) -> Result<Packet, RnsError> {
        let response = Value::Array(vec![Value::Binary(request_id.as_slice().to_vec()), data]);
        let packed_response = encode_msgpack(&response)?;
        if packed_response.len() > LINK_PACKET_MDU {
            return Err(RnsError::OutOfMemory);
        }

        self.encrypted_data_packet(&packed_response, PacketContext::Response)
    }

    pub fn keep_alive_packet(&self, data: u8) -> Packet {
        log::trace!("link({}): create keep alive {}", self.id, data);

        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(&[data]);

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
        packet_data.safe_write(hash.as_slice());
        packet_data.safe_write(&signature.to_bytes()[..]);

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
        self.priv_identity
            .encrypt(OsRng, text, &self.derived_key, out_buf)
    }

    pub fn decrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.priv_identity
            .decrypt(OsRng, text, &self.derived_key, out_buf)
    }

    pub fn destination(&self) -> &DestinationDesc {
        &self.destination
    }

    pub fn create_rtt(&self) -> Packet {
        let rtt = self.rtt.as_secs_f32();
        let mut buf = Vec::new();
        {
            buf.reserve(4);
            rmp::encode::write_f32(&mut buf, rtt).unwrap();
        }

        let mut packet_data = PacketDataBuffer::new();

        let token_len = {
            let token = self
                .encrypt(buf.as_slice(), packet_data.accuire_buf_max())
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
        );
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
    }

    pub fn elapsed(&self) -> Duration {
        self.request_time.elapsed()
    }

    pub fn status(&self) -> LinkStatus {
        self.status
    }

    pub fn id(&self) -> &LinkId {
        &self.id
    }

    pub fn rtt(&self) -> &Duration {
        &self.rtt
    }
}

fn validate_proof_packet(
    destination: &DestinationDesc,
    id: &LinkId,
    packet: &Packet,
) -> Result<Identity, RnsError> {
    const MIN_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;
    const MTU_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + LINK_MTU_SIZE;
    const SIGN_DATA_LEN: usize = ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE;

    if packet.data.len() < MIN_PROOF_LEN {
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
            output.write(mtu_bytes)?;
        }

        output.offset()
    };

    let identity = Identity::new_from_slices(
        &proof_data[ADDRESS_HASH_SIZE..ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH],
        verifying_key,
    );

    let signature = Signature::from_slice(&packet.data.as_slice()[..SIGNATURE_LENGTH])
        .map_err(|_| RnsError::CryptoError)?;

    identity
        .verify(&proof_data[..sign_data_len], &signature)
        .map_err(|_| RnsError::IncorrectSignature)?;

    Ok(identity)
}

fn validate_message_proof(peer_identity: &Identity, data: &[u8]) -> Result<Hash, RnsError> {
    if data.len() <= HASH_SIZE {
        return Err(RnsError::PacketError);
    }

    let maybe_signature = Signature::from_slice(&data[HASH_SIZE..]);
    let signature = match maybe_signature {
        Ok(s) => s,
        Err(_) => return Err(RnsError::PacketError),
    };

    let hash_slice = &data[..HASH_SIZE];

    if peer_identity.verify(hash_slice, &signature).is_ok() {
        Ok(Hash::new(hash_slice.try_into().unwrap()))
    } else {
        Err(RnsError::IncorrectSignature)
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

fn decode_link_request(data: &[u8], request_id: AddressHash) -> Result<LinkRequest, RnsError> {
    let value = read_value(&mut &data[..]).map_err(|_| RnsError::PacketError)?;
    let values = value.as_array().ok_or(RnsError::PacketError)?;
    if values.len() != 3 {
        return Err(RnsError::PacketError);
    }

    let requested_at = values[0].as_f64().ok_or(RnsError::PacketError)?;
    let path_hash = read_address_hash(&values[1])?;

    Ok(LinkRequest {
        request_id,
        path_hash,
        requested_at,
        data: values[2].clone(),
    })
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
    use crate::hash::AddressHash;
    use crate::identity::PrivateIdentity;
    use crate::packet::{DestinationType, PacketContext, PacketType, LINK_PACKET_MDU};
    use crate::serde::Serialize;
    use crate::test_vectors;

    use super::{ChannelEnvelope, ChannelMessage, Link, LinkEvent, LinkHandleResult};

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
        let identity = PrivateIdentity::new_from_name("link owner");
        let destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "link.requests"),
        );
        let (out_event_tx, mut out_event_rx) = tokio::sync::broadcast::channel(8);
        let (in_event_tx, mut in_event_rx) = tokio::sync::broadcast::channel(8);

        let mut out_link = Link::new(destination.desc, out_event_tx);
        let link_request = out_link.request();
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

        in_link.handle_packet(&request, false);

        let event = in_events.try_recv().expect("request event");
        match event.event {
            LinkEvent::Request(request) => {
                assert_eq!(request.request_id, request_id);
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
            vec![0x12, 0x34, 0x00, 0x02, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o']
        );
        assert_eq!(ChannelEnvelope::unpack(&raw).expect("unpacked"), envelope);
        assert!(ChannelEnvelope::unpack(&raw[..raw.len() - 1]).is_err());
    }

    #[test]
    fn channel_packet_uses_channel_context_and_sequence() {
        let (mut out_link, mut in_link, _out_events, mut in_events) = create_active_link_pair();
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
            LinkHandleResult::MessageReceived(Some(_))
        ));
        assert!(in_events.try_recv().is_err());

        assert!(matches!(
            in_link.handle_packet(&first, false),
            LinkHandleResult::MessageReceived(Some(_))
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
}
