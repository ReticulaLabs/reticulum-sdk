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

const PATHFINDER_E: Duration = Duration::from_secs(60 * 60 * 24 * 7);
const MAX_RANDOM_BLOBS: usize = 64;
const ANNOUNCE_RANDOM_BLOB_OFFSET: usize = PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH;

type RandomBlob = [u8; RAND_HASH_LENGTH];

pub struct PathEntry {
    pub timestamp: Instant,
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    pub packet_hash: Hash,
    expires: Instant,
    random_blobs: Vec<RandomBlob>,
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

    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map
            .get(destination)
            .map(|entry| (entry.received_from, entry.iface))
    }

    pub fn next_hop_route(
        &self,
        destination: &AddressHash,
    ) -> Option<(AddressHash, AddressHash, u8)> {
        self.map
            .get(destination)
            .map(|entry| (entry.received_from, entry.iface, entry.hops))
    }

    pub fn next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.iface)
    }

    pub fn next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.received_from)
    }

    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
    ) {
        let Some(hops) = announce.header.hops.checked_add(1) else {
            return;
        };

        let random_blob = announce_random_blob(announce);

        if let Some(existing_entry) = self.map.get(&announce.destination) {
            let should_install = match random_blob {
                Some(blob) => existing_entry.should_accept(announce.destination, hops, blob),
                None => {
                    if hops > existing_entry.hops {
                        false
                    } else {
                        self.reroute_eager || hops < existing_entry.hops
                    }
                }
            };

            if !should_install {
                return;
            }
        }

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
            expires: Instant::now() + PATHFINDER_E,
            random_blobs: self
                .map
                .get(&announce.destination)
                .map(|entry| entry.updated_random_blobs(random_blob))
                .unwrap_or_else(|| random_blob.into_iter().collect()),
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );
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

        let Some(hops) = original_packet.header.hops.checked_add(1) else {
            return (original_packet.clone(), None);
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
                    hops,
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
        }
    }

    pub fn handle_packet(&self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        if original_packet.header.header_type == HeaderType::Type2 {
            return (original_packet.clone(), None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (original_packet.clone(), None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (original_packet.clone(), None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (original_packet.clone(), None),
        };

        (
            Packet {
                header: Header {
                    header_type: HeaderType::Type2,
                    propagation_type: PropagationType::Transport,
                    ..original_packet.header
                },
                ifac: original_packet.ifac,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data.clone(),
            },
            Some(entry.iface),
        )
    }
}

impl PathEntry {
    fn should_accept(&self, destination: AddressHash, hops: u8, random_blob: RandomBlob) -> bool {
        let announce_emitted = timebase_from_random_blob(random_blob);
        let path_timebase = self.timebase();

        if self.random_blobs.contains(&random_blob) {
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
        table.handle_announce(&announce, None, iface);

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
        assert_eq!(forwarded.header.hops, 1);
        assert_eq!(forwarded.transport, None);
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
                hops: 1,
                ..Default::default()
            },
            destination,
            transport: Some(transport),
            context: PacketContext::None,
            ifac: None,
            data: Default::default(),
        };
        table.handle_announce(&announce, Some(transport), iface);

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
        assert_eq!(forwarded.header.hops, 1);
        assert_eq!(forwarded.transport, Some(transport));
    }

    #[test]
    fn forwarding_max_hop_packet_does_not_overflow() {
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
        table.handle_announce(&announce, None, iface);

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

        let (_, forwarded_iface) = table.handle_inbound_packet(&original, None);

        assert_eq!(forwarded_iface, None);
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
        data.safe_write(&blob);

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
    fn duplicate_announce_random_blob_does_not_replace_path() {
        let destination = AddressHash::new_from_slice(b"replayed-destination");
        let first_iface = AddressHash::new_from_slice(b"first-iface");
        let second_iface = AddressHash::new_from_slice(b"second-iface");
        let mut table = PathTable::new(true);
        let blob = random_blob(1, 100);

        table.handle_announce(
            &announce_with_random_blob(destination, 2, blob),
            None,
            first_iface,
        );
        table.handle_announce(
            &announce_with_random_blob(destination, 1, blob),
            None,
            second_iface,
        );

        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, first_iface);
        assert_eq!(hops, 3);
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
        );
        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(2, 99)),
            None,
            second_iface,
        );

        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, first_iface);
        assert_eq!(hops, 3);
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
        );
        table.handle_announce(
            &announce_with_random_blob(destination, 1, random_blob(2, 101)),
            None,
            second_iface,
        );

        let (_, iface, hops) = table.next_hop_route(&destination).unwrap();
        assert_eq!(iface, second_iface);
        assert_eq!(hops, 2);
    }
}
