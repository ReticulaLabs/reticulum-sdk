use core::fmt;

use sha2::Digest;

use crate::hash::AddressHash;
use crate::hash::Hash;

// Reticulum uses a fixed 500-byte interoperable packet MTU. The Python
// reference also reserves one byte for the minimum IFAC field size when
// calculating MDU: MDU = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE.
pub const RETICULUM_MTU: usize = 500usize;
pub const RETICULUM_HEADER_MINSIZE: usize = 2 + 1 + 16;
pub const RETICULUM_MAX_HEADER_SIZE: usize = 35usize;
pub const RETICULUM_MIN_IFAC_SIZE: usize = 1usize;
pub const PACKET_MDU: usize = RETICULUM_MTU - RETICULUM_MAX_HEADER_SIZE - RETICULUM_MIN_IFAC_SIZE;
// Default scratch capacity for locally-created packet payloads. Received packet
// payloads are dynamically sized to match the decoded frame.
pub const DEFAULT_PACKET_DATA_BUFFER_SIZE: usize = 2048usize;
pub const PACKET_IFAC_MAX_LENGTH: usize = 64usize;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum IfacFlag {
    Open = 0b0,
    Authenticated = 0b1,
}

impl From<u8> for IfacFlag {
    fn from(value: u8) -> Self {
        match value {
            0 => IfacFlag::Open,
            1 => IfacFlag::Authenticated,
            _ => IfacFlag::Open,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum HeaderType {
    Type1 = 0b0,
    Type2 = 0b1,
}

impl From<u8> for HeaderType {
    fn from(value: u8) -> Self {
        match value & 0b1 {
            0 => HeaderType::Type1,
            1 => HeaderType::Type2,
            _ => HeaderType::Type1,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ContextFlag {
    Unset = 0b0,
    Set = 0b1,
}

impl From<u8> for ContextFlag {
    fn from(value: u8) -> Self {
        match value & 0b1 {
            0b0 => ContextFlag::Unset,
            0b1 => ContextFlag::Set,
            _ => ContextFlag::Unset,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PropagationType {
    Broadcast = 0b0,
    Transport = 0b1,
}

impl From<u8> for PropagationType {
    fn from(value: u8) -> Self {
        match value & 0b1 {
            0b0 => PropagationType::Broadcast,
            0b1 => PropagationType::Transport,
            _ => PropagationType::Broadcast,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DestinationType {
    Single = 0b00,
    Group = 0b01,
    Plain = 0b10,
    Link = 0b11,
}

impl From<u8> for DestinationType {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0b00 => DestinationType::Single,
            0b01 => DestinationType::Group,
            0b10 => DestinationType::Plain,
            0b11 => DestinationType::Link,
            _ => DestinationType::Single,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketType {
    Data = 0b00,
    Announce = 0b01,
    LinkRequest = 0b10,
    Proof = 0b11,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0b00 => PacketType::Data,
            0b01 => PacketType::Announce,
            0b10 => PacketType::LinkRequest,
            0b11 => PacketType::Proof,
            _ => PacketType::Data,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketContext {
    None = 0x00,                    // Generic data packet
    Resource = 0x01,                // Packet is part of a resource
    ResourceAdvertisement = 0x02,   // Packet is a resource advertisement
    ResourceRequest = 0x03,         // Packet is a resource part request
    ResourceHashUpdate = 0x04,      // Packet is a resource hashmap update
    ResourceProof = 0x05,           // Packet is a resource proof
    ResourceInitiatorCancel = 0x06, // Packet is a resource initiator cancel message
    ResourceReceiverCancel = 0x07,  // Packet is a resource receiver cancel message
    CacheRequest = 0x08,            // Packet is a cache request
    Request = 0x09,                 // Packet is a request
    Response = 0x0A,                // Packet is a response to a request
    PathResponse = 0x0B,            // Packet is a response to a path request
    Command = 0x0C,                 // Packet is a command
    CommandStatus = 0x0D,           // Packet is a status of an executed command
    Channel = 0x0E,                 // Packet contains link channel data
    KeepAlive = 0xFA,               // Packet is a keepalive packet
    LinkIdentify = 0xFB,            // Packet is a link peer identification proof
    LinkClose = 0xFC,               // Packet is a link close message
    LinkProof = 0xFD,               // Packet is a link packet proof
    LinkRTT = 0xFE,                 // Packet is a link request round-trip time measurement
    LinkRequestProof = 0xFF,        // Packet is a link request proof
}

impl From<u8> for PacketContext {
    fn from(value: u8) -> Self {
        match value {
            0x01 => PacketContext::Resource,
            0x02 => PacketContext::ResourceAdvertisement,
            0x03 => PacketContext::ResourceRequest,
            0x04 => PacketContext::ResourceHashUpdate,
            0x05 => PacketContext::ResourceProof,
            0x06 => PacketContext::ResourceInitiatorCancel,
            0x07 => PacketContext::ResourceReceiverCancel,
            0x08 => PacketContext::CacheRequest,
            0x09 => PacketContext::Request,
            0x0A => PacketContext::Response,
            0x0B => PacketContext::PathResponse,
            0x0C => PacketContext::Command,
            0x0D => PacketContext::CommandStatus,
            0x0E => PacketContext::Channel,
            0xFA => PacketContext::KeepAlive,
            0xFB => PacketContext::LinkIdentify,
            0xFC => PacketContext::LinkClose,
            0xFD => PacketContext::LinkProof,
            0xFE => PacketContext::LinkRTT,
            0xFF => PacketContext::LinkRequestProof,
            _ => PacketContext::None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Header {
    pub ifac_flag: IfacFlag,
    pub header_type: HeaderType,
    pub context_flag: ContextFlag,
    pub propagation_type: PropagationType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
    pub hops: u8,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 0,
        }
    }
}

impl Header {
    pub fn to_meta(&self) -> u8 {
        let meta = (self.ifac_flag as u8) << 7
            | (self.header_type as u8) << 6
            | (self.context_flag as u8) << 5
            | (self.propagation_type as u8) << 4
            | (self.destination_type as u8) << 2
            | (self.packet_type as u8) << 0;
        meta
    }

    pub fn from_meta(meta: u8) -> Self {
        Self {
            ifac_flag: IfacFlag::from(meta >> 7),
            header_type: HeaderType::from(meta >> 6),
            context_flag: ContextFlag::from(meta >> 5),
            propagation_type: PropagationType::from(meta >> 4),
            destination_type: DestinationType::from(meta >> 2),
            packet_type: PacketType::from(meta >> 0),
            hops: 0,
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:b}{:b}{:b}{:b}{:0>2b}{:0>2b}.{}",
            self.ifac_flag as u8,
            self.header_type as u8,
            self.context_flag as u8,
            self.propagation_type as u8,
            self.destination_type as u8,
            self.packet_type as u8,
            self.hops,
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketDataBuffer {
    buffer: Vec<u8>,
}

impl PacketDataBuffer {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        Self {
            buffer: data.to_vec(),
        }
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    pub fn resize(&mut self, len: usize) {
        self.buffer.resize(len, 0);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn chain_write(&mut self, data: &[u8]) -> Result<&mut Self, crate::error::RnsError> {
        self.write(data)?;
        Ok(self)
    }

    pub fn finalize(&self) -> Self {
        self.clone()
    }

    pub fn safe_write(&mut self, data: &[u8]) -> usize {
        self.buffer.extend_from_slice(data);
        data.len()
    }

    pub fn chain_safe_write(&mut self, data: &[u8]) -> &mut Self {
        self.safe_write(data);
        self
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, crate::error::RnsError> {
        self.buffer.extend_from_slice(data);
        Ok(data.len())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub fn accuire_buf(&mut self, len: usize) -> &mut [u8] {
        self.resize(len);
        self.as_mut_slice()
    }

    pub fn try_accuire_buf(&mut self, len: usize) -> Result<&mut [u8], crate::error::RnsError> {
        self.resize(len);
        Ok(self.as_mut_slice())
    }

    pub fn accuire_buf_max(&mut self) -> &mut [u8] {
        self.resize(DEFAULT_PACKET_DATA_BUFFER_SIZE);
        self.as_mut_slice()
    }
}

impl Default for PacketDataBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PacketIfac {
    pub access_code: [u8; PACKET_IFAC_MAX_LENGTH],
    pub length: usize,
}

impl PacketIfac {
    pub fn new_from_slice(slice: &[u8]) -> Self {
        let mut access_code = [0u8; PACKET_IFAC_MAX_LENGTH];
        access_code[..slice.len()].copy_from_slice(slice);
        Self {
            access_code,
            length: slice.len(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.access_code[..self.length]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet {
    pub header: Header,
    pub ifac: Option<PacketIfac>,
    pub destination: AddressHash,
    pub transport: Option<AddressHash>,
    pub context: PacketContext,
    pub data: PacketDataBuffer,
}

impl Packet {
    pub fn hash(&self) -> Hash {
        Hash::new(
            Hash::generator()
                .chain_update(&[self.header.to_meta() & 0b00001111])
                .chain_update(self.destination.as_slice())
                .chain_update(&[self.context as u8])
                .chain_update(self.data.as_slice())
                .finalize()
                .into(),
        )
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            header: Default::default(),
            destination: AddressHash::new_empty(),
            data: Default::default(),
            ifac: None,
            transport: None,
            context: crate::packet::PacketContext::None,
        }
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}", self.header)?;

        if let Some(transport) = self.transport {
            write!(f, " {}", transport)?;
        }

        write!(f, " {}", self.destination)?;

        write!(f, " 0x[{}]]", self.data.len())?;

        Ok(())
    }
}
