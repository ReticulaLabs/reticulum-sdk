use alloc::collections::{BTreeMap, VecDeque};

use rand_core::OsRng;

use tokio::time::{Duration, Instant};

use crate::destination::DestinationName;
use crate::destination::PlainInputDestination;
use crate::hash::ADDRESS_HASH_SIZE;
use crate::hash::AddressHash;
use crate::identity::EmptyIdentity;
use crate::packet::ContextFlag;
use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::HeaderType;
use crate::packet::IfacFlag;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::packet::PropagationType;

pub fn create_path_request_destination() -> PlainInputDestination {
    PlainInputDestination::new(
        EmptyIdentity {},
        DestinationName::new("rnstransport", "path.request"),
    )
}

pub type TagBytes = Vec<u8>;

const PATH_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const PATH_REQUEST_GATE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_DISCOVERY_PATH_REQUEST_TAGS: usize = 32_000;

pub fn create_random_tag() -> TagBytes {
    AddressHash::new_from_rand(OsRng).as_slice().into()
}

pub struct PathRequest {
    pub destination: AddressHash,
    pub requesting_transport: Option<AddressHash>,
    pub tag_bytes: TagBytes,
}

#[derive(Clone)]
pub struct DiscoveryPathRequest {
    pub timeout: Instant,
    pub requesting_iface: AddressHash,
}

impl PathRequest {
    fn decode(data: &[u8], transport_name: &str) -> Option<Self> {
        if data.len() <= ADDRESS_HASH_SIZE {
            log::debug!(
                "tp({}): ignoring malformed path request: no {}",
                transport_name,
                if data.len() < ADDRESS_HASH_SIZE {
                    "destination"
                } else {
                    "tag"
                }
            );
            return None;
        }

        let mut destination = [0u8; ADDRESS_HASH_SIZE];
        destination.copy_from_slice(&data[..ADDRESS_HASH_SIZE]);
        let destination = AddressHash::new(destination);

        let mut requesting_transport = None;
        let mut tag_start = ADDRESS_HASH_SIZE;
        let mut tag_end = data.len();

        if data.len() > ADDRESS_HASH_SIZE * 2 {
            let mut transport = [0u8; ADDRESS_HASH_SIZE];
            transport.copy_from_slice(&data[ADDRESS_HASH_SIZE..2 * ADDRESS_HASH_SIZE]);
            requesting_transport = Some(AddressHash::new(transport));
            tag_start = ADDRESS_HASH_SIZE * 2;
        }

        if tag_end - tag_start > ADDRESS_HASH_SIZE {
            tag_end = tag_start + ADDRESS_HASH_SIZE;
        }

        let tag_bytes = data[tag_start..tag_end].into();

        Some(Self {
            destination,
            requesting_transport,
            tag_bytes,
        })
    }
}

pub struct PathRequests {
    cache: BTreeMap<(AddressHash, TagBytes), Instant>,
    cache_order: VecDeque<(AddressHash, TagBytes)>,
    name: String,
    transport_id: Option<AddressHash>,
    controlled_destination: PlainInputDestination,
    discovery: BTreeMap<AddressHash, DiscoveryPathRequest>,
}

impl PathRequests {
    pub fn new(name: &str, transport_id: Option<AddressHash>) -> Self {
        Self {
            cache: BTreeMap::new(),
            cache_order: VecDeque::new(),
            name: name.into(),
            transport_id,
            controlled_destination: create_path_request_destination(),
            discovery: BTreeMap::new(),
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Option<PathRequest> {
        let path_request = PathRequest::decode(data, &self.name);

        if let Some(ref request) = path_request {
            self.release_expired();

            let tag = (request.destination, request.tag_bytes.clone());
            if self.cache.contains_key(&tag) {
                log::debug!(
                    "tp({}): ignoring duplicate path request for destination {}",
                    self.name,
                    request.destination
                );
                return None;
            }

            self.cache
                .insert(tag.clone(), Instant::now() + PATH_REQUEST_GATE_TIMEOUT);
            self.cache_order.push_back(tag);
            self.enforce_cache_limit();
        }

        path_request
    }

    fn release_expired(&mut self) {
        let now = Instant::now();

        self.cache.retain(|_, expires| *expires > now);
        self.discovery.retain(|_, request| request.timeout > now);

        while let Some(tag) = self.cache_order.front() {
            if self.cache.contains_key(tag) {
                break;
            }
            self.cache_order.pop_front();
        }
    }

    fn enforce_cache_limit(&mut self) {
        while self.cache.len() > MAX_DISCOVERY_PATH_REQUEST_TAGS {
            match self.cache_order.pop_front() {
                Some(tag) => {
                    self.cache.remove(&tag);
                }
                None => break,
            }
        }
    }

    pub fn generate(&mut self, destination: &AddressHash, tag: Option<TagBytes>) -> Packet {
        let mut data = PacketDataBuffer::new_from_slice(destination.as_slice());

        if let Some(transport_id) = self.transport_id {
            data.safe_write(transport_id.as_slice());
        }

        data.safe_write(tag.unwrap_or_else(|| create_random_tag()).as_slice());

        log::trace!(
            "path_requests({}): generate destination={} data_len={} raw_data={:02x?}",
            self.name,
            destination,
            data.len(),
            data.as_slice(),
        );

        let destination = self.controlled_destination.desc.address_hash.clone();

        Packet {
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
            destination,
            transport: self.transport_id.clone(),
            context: PacketContext::None,
            data,
        }
    }

    fn allow_recursive(
        &mut self,
        destination: &AddressHash,
        requesting_iface: AddressHash,
    ) -> bool {
        let now = Instant::now();

        if let Some(timeout) = self.discovery.get(destination) {
            if timeout.timeout > now {
                log::debug!(
                    "tp({}): rejecting discovery path request for destination {} as a request is already pending",
                    self.name,
                    destination
                );
                return false;
            }
        }

        // TODO implement announce queue and announce cap, reject requests based on that

        self.discovery.insert(
            *destination,
            DiscoveryPathRequest {
                timeout: now + PATH_REQUEST_TIMEOUT,
                requesting_iface,
            },
        );

        true
    }

    pub fn take_discovery(&mut self, destination: &AddressHash) -> Option<AddressHash> {
        let request = self.discovery.remove(destination)?;

        if request.timeout > Instant::now() {
            Some(request.requesting_iface)
        } else {
            None
        }
    }

    pub fn pending_discovery_len(&self) -> usize {
        self.discovery.len()
    }

    pub fn generate_recursive(
        &mut self,
        destination: &AddressHash,
        requesting_iface: AddressHash,
        tag: Option<TagBytes>,
    ) -> Option<Packet> {
        if self.allow_recursive(destination, requesting_iface) {
            log::trace!(
                "tp({}): sending discovery path request for {}",
                self.name,
                destination
            );

            Some(self.generate(destination, tag))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors;

    #[test]
    fn path_request_roundtrip() {
        let mut testee = PathRequests::new("", None);

        let dest = AddressHash::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let tag = b"fixed-tag".to_vec();

        let encoded = testee.generate(&dest, Some(tag.clone()));
        assert_eq!(
            encoded.data.as_slice(),
            test_vectors::decode_hex(test_vectors::PATH_REQUEST_NO_TRANSPORT_DATA_HEX).as_slice()
        );
        let decoded = testee.decode(encoded.data.as_slice()).unwrap();

        assert_eq!(decoded.destination, dest);
        assert_eq!(decoded.requesting_transport, None);
        assert_eq!(decoded.tag_bytes, tag);
    }

    #[test]
    fn path_request_roundtrip_preserves_requesting_transport() {
        let transport_id = AddressHash::new([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ]);
        let mut testee = PathRequests::new("", Some(transport_id));

        let dest = AddressHash::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let tag = b"fixed-tag".to_vec();

        let encoded = testee.generate(&dest, Some(tag.clone()));
        assert_eq!(
            encoded.data.as_slice(),
            test_vectors::decode_hex(test_vectors::PATH_REQUEST_WITH_TRANSPORT_DATA_HEX).as_slice()
        );
        let decoded = testee.decode(encoded.data.as_slice()).unwrap();

        assert_eq!(decoded.destination, dest);
        assert_eq!(decoded.requesting_transport, Some(transport_id));
        assert_eq!(decoded.tag_bytes, tag);
    }

    #[test]
    fn recursive_path_request_tracks_requesting_interface() {
        let mut testee = PathRequests::new("", None);
        let destination = AddressHash::new_from_slice(b"destination");
        let iface = AddressHash::new_from_slice(b"requesting-iface");
        let tag = b"fixed-tag".to_vec();

        assert!(
            testee
                .generate_recursive(&destination, iface, Some(tag))
                .is_some()
        );
        assert_eq!(testee.take_discovery(&destination), Some(iface));
        assert_eq!(testee.take_discovery(&destination), None);
    }

    #[test]
    fn recursive_path_request_rejects_duplicate_pending_request() {
        let mut testee = PathRequests::new("", None);
        let destination = AddressHash::new_from_slice(b"destination");
        let iface = AddressHash::new_from_slice(b"requesting-iface");

        assert!(
            testee
                .generate_recursive(&destination, iface, None)
                .is_some()
        );
        assert!(
            testee
                .generate_recursive(&destination, iface, None)
                .is_none()
        );
    }

    #[test]
    fn duplicate_path_request_is_allowed_after_gate_timeout() {
        let mut testee = PathRequests::new("", None);
        let destination = AddressHash::new_from_slice(b"destination");
        let tag = b"fixed-tag".to_vec();
        let packet = testee.generate(&destination, Some(tag.clone()));

        assert!(testee.decode(packet.data.as_slice()).is_some());
        assert!(testee.decode(packet.data.as_slice()).is_none());

        let cache_key = (destination, tag);
        *testee.cache.get_mut(&cache_key).expect("cache entry") = Instant::now();

        assert!(testee.decode(packet.data.as_slice()).is_some());
    }

    #[test]
    fn duplicate_path_request_cache_is_bounded() {
        let mut testee = PathRequests::new("", None);
        let destination = AddressHash::new_from_slice(b"destination");

        for i in 0..(MAX_DISCOVERY_PATH_REQUEST_TAGS + 1) {
            let tag = i.to_be_bytes().to_vec();
            let packet = testee.generate(&destination, Some(tag));
            assert!(testee.decode(packet.data.as_slice()).is_some());
        }

        assert_eq!(testee.cache.len(), MAX_DISCOVERY_PATH_REQUEST_TAGS);
    }
}
