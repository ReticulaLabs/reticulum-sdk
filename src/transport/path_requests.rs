use alloc::collections::{BTreeMap, VecDeque};

use getrandom::SysRng;
use rand_core::UnwrapErr;

use tokio::time::{Duration, Instant};

use crate::destination::DestinationName;
use crate::destination::PlainInputDestination;
use crate::hash::AddressHash;
use crate::hash::ADDRESS_HASH_SIZE;
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
/// Stale discovery-order entries tolerated beyond the live discovery map size
/// before the queue is compacted.
const DISCOVERY_ORDER_COMPACT_SLACK: usize = 1024;

pub fn create_random_tag() -> TagBytes {
    let mut rng = UnwrapErr(SysRng);
    AddressHash::new_from_rand(&mut rng).as_slice().into()
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
    /// Monotonically increasing insertion stamp, used to discard stale
    /// expiry-queue entries when a destination is requested again.
    seq: u64,
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
    /// Insertion-ordered `(seq, destination)` queue for pending discovery
    /// requests.  All entries use the same fixed timeout, so insertion order
    /// is also expiry order.
    discovery_order: VecDeque<(u64, AddressHash)>,
    next_discovery_seq: u64,
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
            discovery_order: VecDeque::new(),
            next_discovery_seq: 0,
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Option<PathRequest> {
        let path_request = PathRequest::decode(data, &self.name);

        if let Some(ref request) = path_request {
            self.release_expired();

            let tag = (request.destination, request.tag_bytes.clone());
            if self.cache.contains_key(&tag) {
                log::trace!(
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

        // Cache entries use a fixed gate timeout, so insertion order is also
        // expiry order.  Expire from the front rather than sweeping the whole
        // map (which can hold MAX_DISCOVERY_PATH_REQUEST_TAGS entries).
        while let Some(tag) = self.cache_order.front() {
            let expired = match self.cache.get(tag) {
                Some(expires) => *expires <= now,
                // Entry removed by `enforce_cache_limit` or a test mutation.
                None => true,
            };

            if !expired {
                break;
            }

            if let Some(tag) = self.cache_order.pop_front() {
                self.cache.remove(&tag);
            }
        }

        // Pending discovery requests also use a fixed timeout.  The stamp
        // lets us skip queue entries superseded by a later request for the
        // same destination.
        while let Some(&(seq, destination)) = self.discovery_order.front() {
            let (expired, live) = match self.discovery.get(&destination) {
                Some(request) if request.seq == seq => (request.timeout <= now, true),
                // Superseded by a later insertion, or already taken.
                _ => (true, false),
            };

            if !expired {
                break;
            }

            self.discovery_order.pop_front();
            if live {
                self.discovery.remove(&destination);
            }
        }

        self.maybe_compact_discovery_order();
    }

    /// Drop superseded/taken discovery entries once they outnumber the live
    /// map by a comfortable margin.  Rebuilding is O(n log n) but rare, so
    /// steady-state decoding stays O(1) amortised.
    fn maybe_compact_discovery_order(&mut self) {
        let threshold = self
            .discovery
            .len()
            .saturating_add(DISCOVERY_ORDER_COMPACT_SLACK);
        if self.discovery_order.len() > threshold {
            let mut entries: Vec<(u64, AddressHash)> = self
                .discovery
                .iter()
                .map(|(destination, request)| (request.seq, *destination))
                .collect();
            entries.sort_unstable_by_key(|(seq, _)| *seq);
            self.discovery_order = entries.into();
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
            data.write(transport_id.as_slice());
        }

        data.write(tag.unwrap_or_else(|| create_random_tag()).as_slice());

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

        self.next_discovery_seq = self.next_discovery_seq.wrapping_add(1);
        let seq = self.next_discovery_seq;

        self.discovery.insert(
            *destination,
            DiscoveryPathRequest {
                timeout: now + PATH_REQUEST_TIMEOUT,
                requesting_iface,
                seq,
            },
        );
        self.discovery_order.push_back((seq, *destination));
        self.maybe_compact_discovery_order();

        true
    }

    pub fn take_discovery(&mut self, destination: &AddressHash) -> Option<AddressHash> {
        let request = self.discovery.remove(destination)?;
        self.maybe_compact_discovery_order();

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

        assert!(testee
            .generate_recursive(&destination, iface, Some(tag))
            .is_some());
        assert_eq!(testee.take_discovery(&destination), Some(iface));
        assert_eq!(testee.take_discovery(&destination), None);
    }

    #[test]
    fn recursive_path_request_rejects_duplicate_pending_request() {
        let mut testee = PathRequests::new("", None);
        let destination = AddressHash::new_from_slice(b"destination");
        let iface = AddressHash::new_from_slice(b"requesting-iface");

        assert!(testee
            .generate_recursive(&destination, iface, None)
            .is_some());
        assert!(testee
            .generate_recursive(&destination, iface, None)
            .is_none());
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
    fn expired_cache_entry_is_released_without_sweeping_live_entries() {
        let mut testee = PathRequests::new("", None);
        let destination = AddressHash::new_from_slice(b"destination");
        let first_tag = b"first-tag".to_vec();
        let second_tag = b"second-tag".to_vec();

        let first = testee.generate(&destination, Some(first_tag.clone()));
        let second = testee.generate(&destination, Some(second_tag));
        assert!(testee.decode(first.data.as_slice()).is_some());
        assert!(testee.decode(second.data.as_slice()).is_some());

        // Expire only the oldest cache entry.
        let first_key = (destination, first_tag);
        *testee.cache.get_mut(&first_key).expect("first cached") = Instant::now();

        // The next decode releases expired entries from the queue front.
        let third = testee.generate(&destination, Some(b"third-tag".to_vec()));
        assert!(testee.decode(third.data.as_slice()).is_some());

        assert!(!testee.cache.contains_key(&first_key));
        assert_eq!(testee.cache.len(), 2);
        assert_eq!(testee.cache_order.len(), 2);
    }

    #[test]
    fn discovery_expiry_skips_superseded_queue_entries() {
        let mut testee = PathRequests::new("", None);
        let first = AddressHash::new_from_slice(b"discovery-first");
        let second = AddressHash::new_from_slice(b"discovery-second");
        let iface = AddressHash::new_from_slice(b"requesting-iface");

        assert!(testee.generate_recursive(&first, iface, None).is_some());
        assert!(testee.generate_recursive(&second, iface, None).is_some());

        // Expire the first discovery request, then request it again.  This
        // leaves the original queue entry superseded by the new generation.
        testee.discovery.get_mut(&first).unwrap().timeout = Instant::now();
        assert!(testee.generate_recursive(&first, iface, None).is_some());

        // Expire the second request.  Sweeping must drop the stale first
        // generation and the expired second request, but keep the live
        // re-requested first destination.
        testee.discovery.get_mut(&second).unwrap().timeout = Instant::now();
        testee.release_expired();

        assert_eq!(testee.pending_discovery_len(), 1);
        assert!(testee.discovery.contains_key(&first));
        assert!(!testee.discovery.contains_key(&second));
        assert_eq!(testee.discovery_order.len(), 1);
    }

    #[test]
    fn discovery_order_is_compacted_after_repeated_takes() {
        let mut testee = PathRequests::new("", None);
        let iface = AddressHash::new_from_slice(b"requesting-iface");

        for i in 0..(DISCOVERY_ORDER_COMPACT_SLACK + 8) {
            let destination = AddressHash::new_from_slice(&i.to_be_bytes());
            assert!(
                testee
                    .generate_recursive(&destination, iface, None)
                    .is_some()
            );
            assert_eq!(testee.take_discovery(&destination), Some(iface));
        }

        assert_eq!(testee.pending_discovery_len(), 0);
        assert!(
            testee.discovery_order.len() <= DISCOVERY_ORDER_COMPACT_SLACK,
            "stale discovery queue entries must be compacted"
        );
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

        assert!(testee.cache.len() <= MAX_DISCOVERY_PATH_REQUEST_TAGS);
    }
}
