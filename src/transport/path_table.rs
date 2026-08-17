use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{
    destination::{NAME_HASH_LENGTH, RAND_HASH_LENGTH},
    hash::{AddressHash, Hash},
    identity::PUBLIC_KEY_LENGTH,
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType, PropagationType},
};

const MAX_RANDOM_BLOBS: usize = 64;
const ANNOUNCE_RANDOM_BLOB_OFFSET: usize = PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH;

type RandomBlob = [u8; RAND_HASH_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PathState {
    Unknown,
    #[allow(dead_code)]
    Responsive,
    Unresponsive,
}

pub struct PathEntry {
    pub timestamp: Instant,
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    #[allow(dead_code)]
    pub packet_hash: Hash,
    pub expires: Instant,
    path_expiry: Duration,
    random_blobs: Vec<RandomBlob>,
    state: PathState,
    /// Gravity of the interface this path was received on.  Used to prefer
    /// higher-gravity interfaces when the same announce is heard at the same
    /// hop count (matching Python's `Interface.gravity`).
    iface_gravity: i64,
    /// Effective bitrate (bps) of the interface this path was received on.
    /// Tie-breaker when gravity is equal.
    iface_bitrate: Option<f64>,
    /// The announce packet that installed this path.  Cached so the node can
    /// answer onward path requests for destinations it learned about via a
    /// path response (or whose announce has left the announce retransmit
    /// table), matching Python's `IDX_PT_PACKET` (Transport.py).
    announce: Option<Packet>,
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
    reroute_eager: bool,
}

impl PathTable {
    pub fn new(reroute_eager: bool) -> Self {
        Self {
            map: HashMap::new(),
            reroute_eager,
        }
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn remove_stale<F>(&mut self, mut is_active_iface: F) -> usize
    where
        F: FnMut(&AddressHash) -> bool,
    {
        let now = Instant::now();
        let initial_len = self.map.len();

        self.map.retain(|destination, entry| {
            if now >= entry.expires {
                log::debug!("path_table removed expired path to {}", destination);
                return false;
            }

            if !is_active_iface(&entry.iface) {
                log::debug!(
                    "path_table removed path to {} because interface {} is no longer active",
                    destination,
                    entry.iface
                );
                return false;
            }

            true
        });

        initial_len - self.map.len()
    }

    pub fn next_hop_route(
        &self,
        destination: &AddressHash,
    ) -> Option<(AddressHash, AddressHash, u8)> {
        self.map
            .get(destination)
            .map(|entry| (entry.received_from, entry.iface, entry.hops))
    }

    /// The announce packet that installed the path for `destination`, if any.
    /// Used to answer onward path requests even when the announce has already
    /// left the announce retransmit table.
    pub fn path_announce(&self, destination: &AddressHash) -> Option<Packet> {
        self.map.get(destination).and_then(|e| e.announce.clone())
    }

    pub fn next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.iface)
    }

    pub fn next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.received_from)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&AddressHash, &PathEntry)> {
        self.map.iter()
    }

    pub fn is_unresponsive(&self, destination: &AddressHash) -> bool {
        self.map
            .get(destination)
            .map(|entry| entry.state == PathState::Unresponsive)
            .unwrap_or(false)
    }

    pub fn mark_unresponsive(&mut self, destination: &AddressHash) {
        if let Some(entry) = self.map.get_mut(destination) {
            entry.state = PathState::Unresponsive;
            log::debug!("path_table mark {} unresponsive", destination);
        }
    }

    #[allow(dead_code)]
    pub fn mark_state_unknown(&mut self, destination: &AddressHash) {
        if let Some(entry) = self.map.get_mut(destination) {
            entry.state = PathState::Unknown;
        }
    }

    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
        path_expiry: Duration,
        iface_gravity: i64,
        iface_bitrate: Option<f64>,
    ) -> bool {
        if !self.would_update_path(announce, iface_gravity, iface_bitrate) {
            return false;
        }

        let hops = announce.header.hops;
        let random_blob = announce_random_blob(announce);
        let received_from = transport_id.unwrap_or(announce.destination);
        let direct_announce = transport_id.is_none();
        let self_referential_transport = transport_id == Some(announce.destination);

        log::trace!(
            "path_table install destination={} iface={} context_flag={:?} packet_hops={} \
installed_hops={} transport_id={} next_hop={} direct_announce={} \
self_referential_transport={}",
            announce.destination,
            iface,
            announce.header.context_flag,
            announce.header.hops,
            hops,
            transport_id
                .map(|transport| transport.to_string())
                .unwrap_or_else(|| "None".to_owned()),
            received_from,
            direct_announce,
            self_referential_transport,
        );

        let new_entry = PathEntry {
            timestamp: Instant::now(),
            received_from,
            hops,
            iface,
            packet_hash: announce.hash(),
            expires: Instant::now() + path_expiry,
            path_expiry,
            random_blobs: self
                .map
                .get(&announce.destination)
                .map(|entry| entry.updated_random_blobs(random_blob))
                .unwrap_or_else(|| random_blob.into_iter().collect()),
            state: PathState::Unknown,
            iface_gravity,
            iface_bitrate,
            announce: Some(announce.clone()),
        };

        self.map.insert(announce.destination, new_entry);

        log::debug!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );

        true
    }

    /// Whether an announce for this destination would update the installed
    /// path (a fresh destination, or a strictly better / newer emission).
    /// Non-mutating — used to gate the per-destination announce rate limiter
    /// on announces that actually change the path, matching Python's
    /// `should_add` gating (Transport.py).
    pub fn would_update_path(
        &self,
        announce: &Packet,
        incoming_gravity: i64,
        incoming_bitrate: Option<f64>,
    ) -> bool {
        let hops = announce.header.hops;
        let random_blob = announce_random_blob(announce);
        match self.map.get(&announce.destination) {
            None => true,
            Some(entry) => match random_blob {
                Some(blob) => {
                    entry.should_accept(announce.destination, hops, blob, incoming_gravity, incoming_bitrate)
                }
                None => {
                    if hops > entry.hops {
                        false
                    } else {
                        self.reroute_eager || hops < entry.hops
                    }
                }
            },
        }
    }

    /// Remove a specific destination from the path table.
    /// Returns `true` if the entry existed.
    pub fn remove(&mut self, destination: &AddressHash) -> bool {
        self.map.remove(destination).is_some()
    }

    /// Remove all paths whose next hop matches `via`.
    /// Returns the number of removed entries.
    pub fn drop_all_via(&mut self, via: &AddressHash) -> usize {
        let before = self.map.len();
        self.map.retain(|_, entry| entry.received_from != *via);
        before - self.map.len()
    }

    pub fn handle_inbound_packet(
        &self,
        original_packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        let lookup = lookup.unwrap_or(original_packet.destination);

        let entry = match self.map.get(&lookup) {
            Some(entry) => entry,
            None => return (original_packet.clone(), None),
        };

        let (header_type, propagation_type, transport) = if entry.hops > 1 {
            (
                HeaderType::Type2,
                PropagationType::Transport,
                Some(entry.received_from),
            )
        } else {
            (HeaderType::Type1, PropagationType::Broadcast, None)
        };

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type,
                    propagation_type,
                    hops: original_packet.header.hops,
                    ..original_packet.header
                },
                ifac: None,
                destination: original_packet.destination,
                transport,
                context: original_packet.context,
                data: original_packet.data.clone(),
            },
            Some(entry.iface),
        )
    }

    pub fn refresh(&mut self, destination: &AddressHash) {
        if let Some(entry) = self.map.get_mut(destination) {
            entry.timestamp = Instant::now();
            entry.expires = entry.timestamp + entry.path_expiry;
        }
    }

    /// In-place update of a path's hop count, used for link-proof rebalancing.
    ///
    /// When a link-request proof (LRPROOF) is received for a destination, the
    /// hop count of the proof is authoritative — it is the actual number of
    /// hops to the destination, cryptographically attested by the destination.
    /// If the path table's recorded hop count differs, update it in place.
    ///
    /// Returns `Some((old_hops, new_hops))` if a rebalance was performed, or
    /// `None` if the destination is unknown, the hops already match, or the
    /// rebalance would make the path longer.
    pub fn rebalance_hops(
        &mut self,
        destination: &AddressHash,
        new_hops: u8,
        source: &str,
    ) -> Option<(u8, u8)> {
        let entry = self.map.get_mut(destination)?;
        if new_hops == entry.hops {
            return None;
        }
        if new_hops > entry.hops {
            log::trace!(
                "path_table: ignoring longer rebalance for {} from {} to {} (source={})",
                destination,
                entry.hops,
                new_hops,
                source
            );
            return None;
        }
        let old_hops = entry.hops;
        entry.hops = new_hops;
        log::debug!(
            "path_table: rebalanced path to {} from {} to {} hops (source={})",
            destination,
            old_hops,
            new_hops,
            source
        );
        Some((old_hops, new_hops))
    }

    pub fn handle_packet(&self, packet: Packet) -> (Packet, Option<AddressHash>) {
        if packet.header.packet_type == PacketType::Announce {
            return (packet, None);
        }

        if packet.header.destination_type == DestinationType::Plain
            || packet.header.destination_type == DestinationType::Group
        {
            return (packet, None);
        }

        let entry = match self.map.get(&packet.destination) {
            Some(entry) => entry,
            None => {
                log::trace!(
                    "path_table: no path for dst={}, falling back to broadcast",
                    packet.destination
                );
                return (packet, None);
            }
        };

        // If the packet is already Type2 (e.g. locally-queued announce
        // retransmission or a forwarded Type2 packet) we still need to
        // select the correct egress interface.  Preserve the existing
        // routing metadata — only the iface lookup should change.
        let (header_type, propagation_type, transport) =
            if packet.header.header_type == HeaderType::Type2 {
                (packet.header.header_type, packet.header.propagation_type, packet.transport)
            } else if entry.hops > 1 {
                log::trace!(
                    "path_table: route dst={} via next-hop={} iface={} ({} hops)",
                    packet.destination,
                    entry.received_from,
                    entry.iface,
                    entry.hops,
                );
                (
                    HeaderType::Type2,
                    PropagationType::Transport,
                    Some(entry.received_from),
                )
            } else {
                log::trace!(
                    "path_table: direct dst={} on iface={} (1 hop)",
                    packet.destination,
                    entry.iface,
                );
                (HeaderType::Type1, PropagationType::Broadcast, None)
            };

        (
            Packet {
                header: Header {
                    header_type,
                    propagation_type,
                    ..packet.header
                },
                ifac: packet.ifac,
                destination: packet.destination,
                transport,
                context: packet.context,
                data: packet.data.clone(),
            },
            Some(entry.iface),
        )
    }
}

impl PathEntry {
    fn should_accept(
        &self,
        destination: AddressHash,
        hops: u8,
        random_blob: RandomBlob,
        incoming_gravity: i64,
        incoming_bitrate: Option<f64>,
    ) -> bool {
        let announce_emitted = timebase_from_random_blob(random_blob);
        let path_timebase = self.timebase();

        // For an announce at the same hop count as the installed path,
        // prefer the interface with higher gravity (matching Python
        // Transport.py:1836-1845); when gravity is equal, prefer the
        // interface with the higher bitrate.
        let prefers_interface = || {
            if incoming_gravity != self.iface_gravity {
                incoming_gravity > self.iface_gravity
            } else {
                match (incoming_bitrate, self.iface_bitrate) {
                    (Some(a), Some(b)) => a > b,
                    (Some(_), None) => true,
                    _ => false,
                }
            }
        };

        if self.random_blobs.contains(&random_blob) {
            // The same announce emission was already recorded. Accept it
            // if it arrives via a strictly closer (fewer-hop) path, or via
            // a preferred (higher-gravity, then higher-bitrate) interface at
            // the same hop count. This mirrors the Python reference, which
            // updates the path when the same announce is received on an
            // interface with higher gravity (Transport.py:1836-1845).
            if hops < self.hops {
                log::trace!(
                    "path_table accept same-emission announce for {} via closer path ({} < {} hops)",
                    destination,
                    hops,
                    self.hops,
                );
                return true;
            }
            if hops == self.hops && prefers_interface() {
                log::trace!(
                    "path_table accept same-emission announce for {} via preferred interface (gravity {} bitrate {:?})",
                    destination,
                    incoming_gravity,
                    incoming_bitrate,
                );
                return true;
            }
            log::trace!(
                "path_table reject duplicate announce for {} at timebase {}",
                destination,
                announce_emitted
            );
            return false;
        }

        if hops <= self.hops {
            if announce_emitted > path_timebase {
                return true;
            }

            // Same emission time: Python only updates the path for a
            // higher-gravity interface (Transport.py:1836-1845); extend that
            // with a bitrate tie-break when gravity is equal.
            if announce_emitted == path_timebase && prefers_interface() {
                log::trace!(
                    "path_table accept announce for {} via preferred interface (gravity {} bitrate {:?})",
                    destination,
                    incoming_gravity,
                    incoming_bitrate,
                );
                return true;
            }

            log::trace!(
                "path_table reject stale announce for {} at timebase {}, current {}",
                destination,
                announce_emitted,
                path_timebase
            );
            return false;
        }

        if Instant::now() >= self.expires {
            return true;
        }

        if announce_emitted > path_timebase {
            return true;
        }

        if announce_emitted == path_timebase && self.state == PathState::Unresponsive {
            return true;
        }

        log::trace!(
            "path_table reject longer stale announce for {} at timebase {}, current {}",
            destination,
            announce_emitted,
            path_timebase
        );
        false
    }

    fn timebase(&self) -> u64 {
        self.random_blobs
            .iter()
            .map(|blob| timebase_from_random_blob(*blob))
            .max()
            .unwrap_or(0)
    }

    fn updated_random_blobs(&self, random_blob: Option<RandomBlob>) -> Vec<RandomBlob> {
        let mut random_blobs = self.random_blobs.clone();

        if let Some(blob) = random_blob {
            if !random_blobs.contains(&blob) {
                random_blobs.push(blob);
            }
        }

        if random_blobs.len() > MAX_RANDOM_BLOBS {
            random_blobs.drain(0..random_blobs.len() - MAX_RANDOM_BLOBS);
        }

        random_blobs
    }
}

fn announce_random_blob(packet: &Packet) -> Option<RandomBlob> {
    let data = packet.data.as_slice();
    let end = ANNOUNCE_RANDOM_BLOB_OFFSET + RAND_HASH_LENGTH;
    if data.len() < end {
        return None;
    }

    data[ANNOUNCE_RANDOM_BLOB_OFFSET..end].try_into().ok()
}

fn timebase_from_random_blob(random_blob: RandomBlob) -> u64 {
    u64::from_be_bytes([
        0,
        0,
        0,
        random_blob[5],
        random_blob[6],
        random_blob[7],
        random_blob[8],
        random_blob[9],
    ])
}

#[cfg(test)]
mod tests {
    use super::PathTable;
    use crate::{
        hash::AddressHash,
        packet::{
            DestinationType, Header, HeaderType, Packet, PacketContext, PacketDataBuffer,
            PacketType, PropagationType,
        },
    };
    use std::time::{Duration, Instant};

    #[test]
    fn direct_path_forwarding_strips_transport_header() {
        let destination = AddressHash::new_from_slice(b"direct-destination");
        let iface = AddressHash::new_from_slice(b"direct-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let original = Packet {
            header: Header {
                packet_type: PacketType::Data,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_inbound_packet(&original, None);

        assert_eq!(forwarded_iface, Some(iface));
        assert_eq!(forwarded.header.header_type, HeaderType::Type1);
        assert_eq!(
            forwarded.header.propagation_type,
            PropagationType::Broadcast
        );
        assert_eq!(forwarded.header.hops, 0);
        assert_eq!(forwarded.transport, None);
    }

    #[test]
    fn would_update_path_matches_handle_announce_decision() {
        let destination = AddressHash::new_from_slice(b"rate-limit-destination");
        let iface = AddressHash::new_from_slice(b"rate-limit-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 1,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        // Fresh destination: the announce would install a path.
        assert!(table.would_update_path(&announce, 0, None));

        // After installation, an identical announce does not update the path.
        assert!(table.handle_announce(&announce, None, iface, Duration::from_secs(3600), 0, None));
        assert!(!table.would_update_path(&announce, 0, None));

        // A lower-hop announce would still update the path.
        let mut better = announce.clone();
        better.header.hops = 0;
        assert!(table.would_update_path(&better, 0, None));
        assert!(table.handle_announce(&better, None, iface, Duration::from_secs(3600), 0, None));

        // A higher-hop announce would not.
        let mut worse = announce.clone();
        worse.header.hops = 2;
        assert!(!table.would_update_path(&worse, 0, None));
    }

    #[test]
    fn multihop_path_forwarding_uses_transport_header() {
        let destination = AddressHash::new_from_slice(b"remote-destination");
        let transport = AddressHash::new_from_slice(b"next-transport");
        let iface = AddressHash::new_from_slice(b"next-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                header_type: HeaderType::Type2,
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 2,
                ..Default::default()
            },
            destination,
            transport: Some(transport),
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, Some(transport), iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let original = Packet {
            header: Header {
                packet_type: PacketType::Data,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_inbound_packet(&original, None);

        assert_eq!(forwarded_iface, Some(iface));
        assert_eq!(forwarded.header.header_type, HeaderType::Type2);
        assert_eq!(
            forwarded.header.propagation_type,
            PropagationType::Transport
        );
        assert_eq!(forwarded.header.hops, 0);
        assert_eq!(forwarded.transport, Some(transport));
    }

    #[test]
    fn forwarding_max_hop_packet_preserves_hop_count() {
        let destination = AddressHash::new_from_slice(b"direct-destination");
        let iface = AddressHash::new_from_slice(b"direct-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let original = Packet {
            header: Header {
                packet_type: PacketType::Data,
                destination_type: DestinationType::Single,
                hops: u8::MAX,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_inbound_packet(&original, None);

        assert_eq!(forwarded_iface, Some(iface));
        assert_eq!(forwarded.header.hops, u8::MAX);
    }

    #[test]
    fn removes_expired_paths() {
        let destination = AddressHash::new_from_slice(b"expired-destination");
        let iface = AddressHash::new_from_slice(b"expired-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);
        table.map.get_mut(&destination).unwrap().expires = Instant::now();

        assert_eq!(table.remove_stale(|_| true), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn removes_paths_for_inactive_interfaces() {
        let destination = AddressHash::new_from_slice(b"inactive-iface-destination");
        let iface = AddressHash::new_from_slice(b"inactive-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        assert_eq!(table.remove_stale(|_| false), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn refreshed_paths_are_not_removed_as_expired() {
        let destination = AddressHash::new_from_slice(b"refreshed-destination");
        let iface = AddressHash::new_from_slice(b"refreshed-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);
        table.map.get_mut(&destination).unwrap().expires = Instant::now();
        table.refresh(&destination);

        assert_eq!(table.remove_stale(|active_iface| *active_iface == iface), 0);
        assert_eq!(table.len(), 1);
    }

    fn random_blob(prefix: u8, emitted: u64) -> [u8; super::RAND_HASH_LENGTH] {
        let emitted = emitted.to_be_bytes();
        [
            prefix, prefix, prefix, prefix, prefix, emitted[3], emitted[4], emitted[5], emitted[6],
            emitted[7],
        ]
    }

    fn announce_with_random_blob(
        destination: AddressHash,
        hops: u8,
        blob: [u8; super::RAND_HASH_LENGTH],
    ) -> Packet {
        let mut data = PacketDataBuffer::new();
        data.resize(super::ANNOUNCE_RANDOM_BLOB_OFFSET);
        data.write(&blob);

        Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data,
        }
    }

    #[test]
    fn same_emission_with_fewer_hops_replaces_path() {
        let destination = AddressHash::new_from_slice(b"replayed-destination");
        let first_iface = AddressHash::new_from_slice(b"first-iface");
        let second_iface = AddressHash::new_from_slice(b"second-iface");
        let mut table = PathTable::new(true);
        let blob = random_blob(1, 100);

        table.handle_announce(
            &announce_with_random_blob(destination, 2, blob),
            None,
            first_iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);
        table.handle_announce(
            &announce_with_random_blob(destination, 1, blob),
            None,
            second_iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        // The same emission arriving via a strictly closer (fewer-hop)
        // path must replace the existing route, so a multi-interface node
        // converges on the closest peer for a single announce emission.
        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, second_iface);
        assert_eq!(hops, 1);
    }

    #[test]
    fn older_announce_does_not_replace_path_even_with_shorter_hop_count() {
        let destination = AddressHash::new_from_slice(b"stale-destination");
        let first_iface = AddressHash::new_from_slice(b"first-iface");
        let second_iface = AddressHash::new_from_slice(b"second-iface");
        let mut table = PathTable::new(true);

        table.handle_announce(
            &announce_with_random_blob(destination, 2, random_blob(1, 100)),
            None,
            first_iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);
        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(2, 99)),
            None,
            second_iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, first_iface);
        assert_eq!(hops, 2);
    }

    #[test]
    fn newer_equal_hop_announce_replaces_path_without_eager_reroute() {
        let destination = AddressHash::new_from_slice(b"newer-destination");
        let first_iface = AddressHash::new_from_slice(b"first-iface");
        let second_iface = AddressHash::new_from_slice(b"second-iface");
        let mut table = PathTable::new(false);

        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(1, 100)),
            None,
            first_iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);
        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(2, 101)),
            None,
            second_iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, second_iface);
        assert_eq!(hops, 1);
    }

    #[test]
    fn same_emission_prefers_higher_gravity_then_higher_bitrate() {
        let destination = AddressHash::new_from_slice(b"gravity-destination");
        let low_iface = AddressHash::new_from_slice(b"low-iface");
        let high_iface = AddressHash::new_from_slice(b"high-iface");
        let mut table = PathTable::new(false);

        // Same emission (same random blob), same hop count on two interfaces.
        let blob = random_blob(7, 100);
        table.handle_announce(
            &announce_with_random_blob(destination, 1, blob),
            None,
            low_iface,
            Duration::from_secs(60 * 60 * 24 * 7),
            0,
            Some(1_000_000.0),
        );

        // Same gravity (0), lower bitrate on the second interface: no switch.
        table.handle_announce(
            &announce_with_random_blob(destination, 1, blob),
            None,
            high_iface,
            Duration::from_secs(60 * 60 * 24 * 7),
            0,
            Some(100_000.0),
        );
        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, low_iface, "lower-bitrate tie must not win");
        assert_eq!(hops, 1);

        // Same gravity, higher bitrate on the second interface: switch.
        table.handle_announce(
            &announce_with_random_blob(destination, 1, blob),
            None,
            high_iface,
            Duration::from_secs(60 * 60 * 24 * 7),
            0,
            Some(10_000_000.0),
        );
        let (_, iface, _) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, high_iface, "higher-bitrate tie must win");

        // Higher gravity always wins, regardless of bitrate.
        table.handle_announce(
            &announce_with_random_blob(destination, 1, blob),
            None,
            low_iface,
            Duration::from_secs(60 * 60 * 24 * 7),
            5,
            Some(1_000_000.0),
        );
        let (_, iface, _) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, low_iface, "higher gravity must win");
    }

    #[test]
    fn different_emission_same_timebase_prefers_higher_gravity() {
        let destination = AddressHash::new_from_slice(b"gravity-dest-2");
        let first_iface = AddressHash::new_from_slice(b"first-iface");
        let second_iface = AddressHash::new_from_slice(b"second-iface");
        let mut table = PathTable::new(false);

        // First emission at timebase 100 on a low-gravity interface.
        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(1, 100)),
            None,
            first_iface,
            Duration::from_secs(60 * 60 * 24 * 7),
            0,
            None,
        );

        // A different blob with the same timebase on a higher-gravity
        // interface: the path switches (matching Python's gravity logic).
        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(2, 100)),
            None,
            second_iface,
            Duration::from_secs(60 * 60 * 24 * 7),
            3,
            None,
        );
        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, second_iface);
        assert_eq!(hops, 1);
    }

    #[test]
    fn outbound_direct_path_uses_type1_broadcast() {
        let destination = AddressHash::new_from_slice(b"outbound-direct");
        let iface = AddressHash::new_from_slice(b"outbound-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::LinkRequest,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, Some(iface));
        assert_eq!(forwarded.header.header_type, HeaderType::Type1);
        assert_eq!(
            forwarded.header.propagation_type,
            PropagationType::Broadcast
        );
        assert_eq!(forwarded.transport, None);
        assert_eq!(forwarded.header.hops, 0);
    }

    #[test]
    fn outbound_multihop_path_uses_type2_transport() {
        let destination = AddressHash::new_from_slice(b"outbound-remote");
        let next_hop = AddressHash::new_from_slice(b"outbound-next-hop");
        let iface = AddressHash::new_from_slice(b"outbound-iface");
        let mut table = PathTable::new(false);

        let announce = Packet {
            header: Header {
                header_type: HeaderType::Type2,
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 2,
                ..Default::default()
            },
            destination,
            transport: Some(next_hop),
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, Some(next_hop), iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::LinkRequest,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, Some(iface));
        assert_eq!(forwarded.header.header_type, HeaderType::Type2);
        assert_eq!(
            forwarded.header.propagation_type,
            PropagationType::Transport
        );
        assert_eq!(forwarded.transport, Some(next_hop));
        assert_eq!(forwarded.header.hops, 0);
    }

    #[test]
    fn outbound_no_path_falls_back_to_broadcast() {
        let destination = AddressHash::new_from_slice(b"outbound-unknown");
        let table = PathTable::new(false);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::LinkRequest,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: Some(AddressHash::new_from_slice(b"stale-transport")),
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, None);
        assert_eq!(forwarded.header.header_type, HeaderType::Type1);
        assert_eq!(
            forwarded.transport,
            Some(AddressHash::new_from_slice(b"stale-transport"))
        );
    }

    #[test]
    fn outbound_type2_packet_unknown_destination_passthrough() {
        let destination = AddressHash::new_from_slice(b"outbound-type2-dst");
        let table = PathTable::new(false);

        let packet = Packet {
            header: Header {
                header_type: HeaderType::Type2,
                packet_type: PacketType::LinkRequest,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, None);
        assert_eq!(forwarded.header.header_type, HeaderType::Type2);
    }

    #[test]
    fn outbound_type2_packet_with_known_path_is_routed() {
        let destination = AddressHash::new_from_slice(b"outbound-type2-routed");
        let next_hop = AddressHash::new_from_slice(b"outbound-next-hop");
        let iface = AddressHash::new_from_slice(b"outbound-iface");
        let mut table = PathTable::new(false);

        table.handle_announce(
            &Packet {
                header: Header {
                    header_type: HeaderType::Type2,
                    packet_type: PacketType::Announce,
                    destination_type: DestinationType::Single,
                    hops: 2,
                    ..Default::default()
                },
                destination,
                transport: Some(next_hop),
                context: PacketContext::None,
                ifac: None,
                data: Default::default(),
            },
            Some(next_hop),
            iface,
            Duration::from_secs(60 * 60 * 24 * 7), 0, None);

        let packet = Packet {
            header: Header {
                header_type: HeaderType::Type2,
                packet_type: PacketType::Data,
                destination_type: DestinationType::Single,
                hops: 1,
                ..Default::default()
            },
            destination,
            transport: Some(next_hop),
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, Some(iface));
        assert_eq!(forwarded.header.header_type, HeaderType::Type2);
        assert_eq!(forwarded.transport, Some(next_hop));
    }

    #[test]
    fn outbound_announce_packet_passthrough() {
        let destination = AddressHash::new_from_slice(b"outbound-announce");
        let table = PathTable::new(false);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, None);
        assert_eq!(forwarded.header.header_type, HeaderType::Type1);
    }

    #[test]
    fn outbound_plain_destination_passthrough() {
        let destination = AddressHash::new_from_slice(b"outbound-plain");
        let table = PathTable::new(false);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::Data,
                destination_type: DestinationType::Plain,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, None);
        assert_eq!(forwarded.header.destination_type, DestinationType::Plain);
    }

    #[test]
    fn outbound_group_destination_passthrough() {
        let destination = AddressHash::new_from_slice(b"outbound-group");
        let table = PathTable::new(false);

        let packet = Packet {
            header: Header {
                packet_type: PacketType::Data,
                destination_type: DestinationType::Group,
                hops: 0,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };

        let (forwarded, forwarded_iface) = table.handle_packet(packet);

        assert_eq!(forwarded_iface, None);
        assert_eq!(forwarded.header.destination_type, DestinationType::Group);
    }

    fn install_announce_with_hops(table: &mut PathTable, destination: AddressHash, iface: AddressHash, hops: u8) {
        let announce = Packet {
            header: Header {
                packet_type: PacketType::Announce,
                destination_type: DestinationType::Single,
                hops,
                ..Default::default()
            },
            destination,
            transport: None,
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, None, iface, Duration::from_secs(60 * 60 * 24 * 7), 0, None);
    }

    #[test]
    fn rebalance_hops_shortens_recorded_path() {
        let destination = AddressHash::new_from_slice(b"rebalance-target");
        let iface = AddressHash::new_from_slice(b"rebalance-iface");
        let mut table = PathTable::new(false);

        install_announce_with_hops(&mut table, destination, iface, 5);
        assert_eq!(table.get(&destination).unwrap().hops, 5);

        let rebalanced = table.rebalance_hops(&destination, 2, "test");
        assert_eq!(rebalanced, Some((5, 2)));
        assert_eq!(table.get(&destination).unwrap().hops, 2);
    }

    #[test]
    fn rebalance_hops_ignores_equal_hops() {
        let destination = AddressHash::new_from_slice(b"rebalance-equal");
        let iface = AddressHash::new_from_slice(b"rebalance-iface");
        let mut table = PathTable::new(false);

        install_announce_with_hops(&mut table, destination, iface, 3);
        let rebalanced = table.rebalance_hops(&destination, 3, "test");
        assert_eq!(rebalanced, None);
        assert_eq!(table.get(&destination).unwrap().hops, 3);
    }

    #[test]
    fn rebalance_hops_ignores_longer_hops() {
        let destination = AddressHash::new_from_slice(b"rebalance-longer");
        let iface = AddressHash::new_from_slice(b"rebalance-iface");
        let mut table = PathTable::new(false);

        install_announce_with_hops(&mut table, destination, iface, 2);
        let rebalanced = table.rebalance_hops(&destination, 7, "test");
        assert_eq!(rebalanced, None);
        assert_eq!(table.get(&destination).unwrap().hops, 2);
    }

    #[test]
    fn rebalance_hops_returns_none_for_unknown_destination() {
        let destination = AddressHash::new_from_slice(b"rebalance-unknown");
        let mut table = PathTable::new(false);
        let rebalanced = table.rebalance_hops(&destination, 1, "test");
        assert_eq!(rebalanced, None);
    }
}
