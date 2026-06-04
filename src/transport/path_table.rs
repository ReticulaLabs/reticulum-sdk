use std::{collections::HashMap, time::Instant};

use crate::{
    hash::{AddressHash, Hash},
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType, PropagationType},
};

pub struct PathEntry {
    pub timestamp: Instant,
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    pub packet_hash: Hash,
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

        if let Some(existing_entry) = self.map.get(&announce.destination) {
            if hops > existing_entry.hops {
                return;
            }
            if !self.reroute_eager && hops == existing_entry.hops {
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
            None => return (*original_packet, None),
        };

        let Some(hops) = original_packet.header.hops.checked_add(1) else {
            return (*original_packet, None);
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
                data: original_packet.data,
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
            return (*original_packet, None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (*original_packet, None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (*original_packet, None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (*original_packet, None),
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
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::PathTable;
    use crate::{
        hash::AddressHash,
        packet::{
            DestinationType, Header, HeaderType, Packet, PacketContext, PacketType, PropagationType,
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
}
