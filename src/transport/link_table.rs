use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, Packet};

pub struct LinkEntry {
    pub timestamp: Instant,
    pub proof_timeout: Instant,
    pub next_hop_iface: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    pub taken_hops: u8,
    pub remaining_hops: u8,
    pub validated: bool,
}

fn propagate(packet: &Packet, iface: AddressHash) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            hops: packet.header.hops,
            ..packet.header
        },
        ifac: None,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data.clone(),
    };

    (propagated, iface)
}

pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        iface: AddressHash,
        remaining_hops: u8,
    ) {
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();
        let taken_hops = link_request.header.hops;

        let entry = LinkEntry {
            timestamp: now,
            proof_timeout: now + Duration::from_secs(600), // TODO
            next_hop_iface: iface,
            received_from,
            original_destination: destination,
            taken_hops,
            remaining_hops,
            validated: false,
        };

        self.0.insert(link_id, entry);
    }

    pub fn original_destination(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0
            .get(&link_id)
            .filter(|e| e.validated)
            .map(|e| e.original_destination)
    }

    pub fn handle_keepalive(&mut self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        let result = self.0.get_mut(&packet.destination).map(|entry| {
            log::trace!(
                "link_table: forward keepalive for link {} to {}",
                packet.destination,
                entry.received_from,
            );
            entry.timestamp = Instant::now();
            propagate(packet, entry.received_from)
        });
        if result.is_none() {
            log::trace!(
                "link_table: no entry for keepalive dst={}",
                packet.destination,
            );
        }
        result
    }

    pub fn handle_packet(
        &mut self,
        packet: &Packet,
        received_on: AddressHash,
    ) -> Option<(Packet, AddressHash)> {
        let entry = self.0.get_mut(&packet.destination)?;

        if !entry.validated {
            log::trace!(
                "link_table: unvalidated entry for link {} on iface {}, dropping",
                packet.destination,
                received_on,
            );
            return None;
        }

        let outbound_iface = if entry.next_hop_iface == entry.received_from {
            if packet.header.hops == entry.remaining_hops || packet.header.hops == entry.taken_hops
            {
                Some(entry.next_hop_iface)
            } else {
                log::trace!(
                    "link_table: hop mismatch for link {} on iface {}: \
                     packet_hops={} remaining_hops={} taken_hops={}",
                    packet.destination,
                    received_on,
                    packet.header.hops,
                    entry.remaining_hops,
                    entry.taken_hops,
                );
                None
            }
        } else if received_on == entry.next_hop_iface {
            if packet.header.hops == entry.remaining_hops {
                Some(entry.received_from)
            } else {
                log::trace!(
                    "link_table: hop mismatch for link {} from next-hop iface {}: \
                     packet_hops={} remaining_hops={}",
                    packet.destination,
                    received_on,
                    packet.header.hops,
                    entry.remaining_hops,
                );
                None
            }
        } else if received_on == entry.received_from {
            if packet.header.hops == entry.taken_hops {
                Some(entry.next_hop_iface)
            } else {
                log::trace!(
                    "link_table: hop mismatch for link {} from received-from iface {}: \
                     packet_hops={} taken_hops={}",
                    packet.destination,
                    received_on,
                    packet.header.hops,
                    entry.taken_hops,
                );
                None
            }
        } else {
            log::trace!(
                "link_table: no matching interface for link {} (received_on={}, \
                 next_hop={}, received_from={})",
                packet.destination,
                received_on,
                entry.next_hop_iface,
                entry.received_from,
            );
            None
        };

        outbound_iface.map(|iface| {
            log::trace!(
                "link_table: forward link data {} to iface {}",
                packet.destination,
                iface,
            );
            entry.timestamp = Instant::now();
            propagate(packet, iface)
        })
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                log::trace!(
                    "link_table: forward proof for link {} ({} hops) to {}",
                    proof.destination,
                    proof.header.hops,
                    entry.received_from,
                );

                entry.remaining_hops = proof.header.hops;
                entry.validated = true;

                Some(propagate(proof, entry.received_from))
            }
            None => {
                log::trace!("link_table: no entry for proof dst={}", proof.destination,);
                None
            }
        }
    }

    pub fn remove_stale(&mut self, max_age: Duration) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            if entry.validated {
                if entry.timestamp + max_age <= now {
                    log::info!(
                        "link_table: remove stale validated entry for link {} (idle for {}s)",
                        link_id,
                        now.duration_since(entry.timestamp).as_secs(),
                    );
                    stale.push(link_id.clone());
                }
            } else {
                if entry.proof_timeout <= now {
                    log::trace!(
                        "link_table: remove stale entry for link {} (proof timeout)",
                        link_id,
                    );
                    stale.push(link_id.clone());
                }
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LinkTable;
    use crate::{
        destination::link::LinkId,
        hash::AddressHash,
        packet::{DestinationType, Header, Packet, PacketContext, PacketType},
    };

    fn link_request(destination: AddressHash) -> Packet {
        Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
                hops: 0,
                ..Default::default()
            },
            ifac: None,
            destination,
            transport: None,
            context: PacketContext::None,
            data: Default::default(),
        }
    }

    fn link_data(link_id: LinkId, hops: u8) -> Packet {
        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                hops,
                ..Default::default()
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: Default::default(),
        }
    }

    #[test]
    fn forwards_validated_link_packets_in_both_directions() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let request_iface = AddressHash::new_from_slice(b"request-iface");
        let destination_iface = AddressHash::new_from_slice(b"destination-iface");
        let request = link_request(destination);
        let link_id = LinkId::from(&request);
        let mut table = LinkTable::new();

        table.add(&request, destination, request_iface, destination_iface, 0);

        let proof = link_data(link_id, 0);
        table.handle_proof(&proof).expect("link proof forwards");

        let forward = link_data(link_id, 0);
        let (forwarded, iface) = table
            .handle_packet(&forward, request_iface)
            .expect("request side packet forwards");
        assert_eq!(iface, destination_iface);
        assert_eq!(forwarded.header.hops, 0);
        assert_eq!(forwarded.transport, None);

        let backward = link_data(link_id, 0);
        let (forwarded, iface) = table
            .handle_packet(&backward, destination_iface)
            .expect("destination side packet forwards");
        assert_eq!(iface, request_iface);
        assert_eq!(forwarded.header.hops, 0);
        assert_eq!(forwarded.transport, None);
    }
}
