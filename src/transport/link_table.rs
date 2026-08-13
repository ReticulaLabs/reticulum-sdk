use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, IfacFlag, Packet, PacketContext};

pub struct LinkEntry {
    pub timestamp: Instant,
    pub proof_timeout: Instant,
    pub next_hop_iface: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    pub taken_hops: u8,
    pub remaining_hops: u8,
    pub validated: bool,
    /// Set true once the path table for `original_destination` has been
    /// rebalanced based on the actual hop count learned from an LRPROOF.
    /// Prevents re-rebalancing on every subsequent proof received for the
    /// same link.
    pub rebalanced: bool,
    /// Cumulative number of data packets forwarded through this link entry.
    pub forward_count: u64,
}

/// Result of processing an inbound proof against the link table.
///
/// `propagation` is the packet/interface to forward the proof to (always
/// present when the function returns `Some`).
///
/// `rebalance` is `Some` only when the proof had `PacketContext::LinkRequestProof`
/// and the entry has not already been rebalanced. The caller is expected to
/// verify the proof's signature against the destination's identity before
/// applying the rebalance to the path table.
pub struct HandleProofOutcome {
    pub propagation: (Packet, AddressHash),
    pub rebalance: Option<RebalanceInfo>,
}

/// Information needed to rebalance the path table after a link-request proof.
pub struct RebalanceInfo {
    pub destination: AddressHash,
    pub hops: u8,
}

fn propagate(packet: &Packet, iface: AddressHash) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
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

/// Outcome of adding a link request to the link table.
#[derive(Debug, PartialEq, Eq)]
pub enum AddLinkRequest {
    /// A new entry was created; forward the request.
    New,
    /// The link is already known and the request arrived from the original
    /// ingress direction (a legitimate initiator retransmission); forward it.
    Retransmission,
    /// The link is already known and the request arrived on the interface
    /// it was previously forwarded out of — i.e. it has looped back through
    /// a stale path. Drop it to break the loop.
    Loop,
}

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
    ) -> AddLinkRequest {
        let link_id = LinkId::from(link_request);

        if let Some(existing) = self.0.get(&link_id) {
            // The link is already known from a previous forward of this
            // request. If it now arrives with a strictly higher hop count
            // than when we first forwarded it, it has looped back through
            // a stale path and must be dropped. If it arrives with the
            // same hop count, it is a legitimate initiator retransmission
            // and should be forwarded again.
            if link_request.header.hops > existing.taken_hops {
                log::trace!(
                    "link_table: link request {} looped back at {} hops (first seen at {}), dropping",
                    link_id,
                    link_request.header.hops,
                    existing.taken_hops,
                );
                return AddLinkRequest::Loop;
            }
            log::trace!(
                "link_table: link request {} retransmitted at {} hops, forwarding",
                link_id,
                link_request.header.hops,
            );
            return AddLinkRequest::Retransmission;
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
            rebalanced: false,
            forward_count: 0,
        };

        self.0.insert(link_id, entry);
        AddLinkRequest::New
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
            // The link is carried on a single shared medium, so the
            // receiving and outbound interface are the same. Direction
            // doesn't matter: simply repeat the packet on that interface,
            // matching the Python reference (Transport.py "Link transport
            // handling"). This also covers the common single-interface
            // node, where `received_on` always equals the shared interface
            // — packets must NOT be dropped just because they arrived on
            // the very interface we would transmit them on (loop prevention
            // is handled by the hop-count checks below).
            if packet.header.hops == entry.remaining_hops
                || packet.header.hops == entry.taken_hops
            {
                Some(entry.next_hop_iface)
            } else {
                log::trace!(
                    "link_table: hop mismatch for link {} on shared iface {}: \
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
            entry.forward_count += 1;
            propagate(packet, iface)
        })
    }

    /// Process an incoming proof packet for a relayed link.
    ///
    /// Returns `Some(HandleProofOutcome)` if a link entry exists for the
    /// proof's destination. The outcome contains the packet/iface to forward
    /// the proof to, and (only for LRPROOF context, only if the entry has
    /// not already been rebalanced) an optional rebalance request describing
    /// the authoritative hop count learned from the proof.
    pub fn handle_proof(&mut self, proof: &Packet) -> Option<HandleProofOutcome> {
        let entry = self.0.get_mut(&proof.destination)?;

        log::trace!(
            "link_table: forward proof for link {} ({} hops, ctx={:?}) to {}",
            proof.destination,
            proof.header.hops,
            proof.context,
            entry.received_from,
        );

        entry.remaining_hops = proof.header.hops;
        entry.validated = true;

        let rebalance = if proof.context == PacketContext::LinkRequestProof && !entry.rebalanced {
            entry.rebalanced = true;
            Some(RebalanceInfo {
                destination: entry.original_destination,
                hops: proof.header.hops,
            })
        } else {
            None
        };

        Some(HandleProofOutcome {
            propagation: propagate(proof, entry.received_from),
            rebalance,
        })
    }

    /// Returns the maximum forward count across all validated entries,
    /// and the total number of forwards. Useful for detecting links
    /// with unusually high forwarding activity.
    pub fn forward_stats(&self) -> (u64, u64) {
        let mut max_fwd = 0u64;
        let mut total_fwd = 0u64;
        for entry in self.0.values() {
            if entry.validated {
                max_fwd = max_fwd.max(entry.forward_count);
                total_fwd += entry.forward_count;
            }
        }
        (max_fwd, total_fwd)
    }

    pub fn remove_stale(&mut self, max_age: Duration) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
                if entry.validated {
                if entry.timestamp + max_age <= now {
                    log::debug!(
                        "link_table: remove stale validated entry for link {} (idle for {}s, forwarded {}x)",
                        link_id,
                        now.duration_since(entry.timestamp).as_secs(),
                        entry.forward_count,
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
    use super::{AddLinkRequest, LinkTable};
    use crate::{
        destination::link::LinkId,
        hash::AddressHash,
        packet::{DestinationType, Header, IfacFlag, Packet, PacketContext, PacketType},
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
        table
            .handle_proof(&proof)
            .expect("link proof forwards")
            .propagation;

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

    #[test]
    fn forwards_link_data_on_single_shared_medium() {
        // A node with a single shared-medium interface (e.g. one radio):
        // next_hop and received_from are the same interface, and every
        // inbound packet arrives on it. The link table must repeat link
        // data back out that interface (hop-checked), not drop it just
        // because the packet arrived on the same interface it would be
        // transmitted on.
        let destination = AddressHash::new_from_slice(b"link-destination");
        let shared_iface = AddressHash::new_from_slice(b"shared-medium");
        let request = link_request(destination);
        let link_id = LinkId::from(&request);
        let mut table = LinkTable::new();

        table.add(&request, destination, shared_iface, shared_iface, 0);

        let proof = link_data(link_id, 0);
        table
            .handle_proof(&proof)
            .expect("link proof forwards")
            .propagation;

        // Data received on the shared interface with a matching hop count
        // must be forwarded back out the same interface.
        let forward = link_data(link_id, 0);
        let (forwarded, iface) = table
            .handle_packet(&forward, shared_iface)
            .expect("link data forwards on the shared medium");
        assert_eq!(iface, shared_iface);
        assert_eq!(forwarded.header.hops, 0);

        // Hop-count mismatch still prevents loops.
        let mismatched = link_data(link_id, 1);
        assert!(
            table.handle_packet(&mismatched, shared_iface).is_none(),
            "link data with mismatched hop count must not be forwarded"
        );
    }

    #[test]
    fn propagate_forwards_link_data_with_ifac_flag_reset_to_open() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let request_iface = AddressHash::new_from_slice(b"request-iface");
        let destination_iface = AddressHash::new_from_slice(b"destination-iface");
        let request = link_request(destination);
        let link_id = LinkId::from(&request);
        let mut table = LinkTable::new();

        table.add(&request, destination, request_iface, destination_iface, 0);

        let proof = link_data(link_id, 0);
        table
            .handle_proof(&proof)
            .expect("link proof forwards")
            .propagation;

        // Forward a packet that has ifac_flag=Authenticated but no ifac data.
        // propagate() must reset the flag to Open to keep serialization consistent.
        let forward = Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                hops: 0,
                ..Default::default()
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: Default::default(),
        };

        let (forwarded, _iface) = table
            .handle_packet(&forward, request_iface)
            .expect("packet should be forwarded");

        assert_eq!(forwarded.header.ifac_flag, IfacFlag::Open);
        assert!(forwarded.ifac.is_none());
    }

    #[test]
    fn propagate_forwards_link_proof_with_ifac_flag_reset_to_open() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let request_iface = AddressHash::new_from_slice(b"request-iface");
        let destination_iface = AddressHash::new_from_slice(b"destination-iface");
        let request = link_request(destination);
        let link_id = LinkId::from(&request);
        let mut table = LinkTable::new();

        table.add(&request, destination, request_iface, destination_iface, 0);

        // Proof with ifac_flag=Authenticated but no ifac data.
        let proof = Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: 0,
                ..Default::default()
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: Default::default(),
        };

        let (propagated, _iface) = table
            .handle_proof(&proof)
            .expect("proof should be forwarded")
            .propagation;

        assert_eq!(propagated.header.ifac_flag, IfacFlag::Open);
        assert!(propagated.ifac.is_none());
    }

    #[test]
    fn link_entry_starts_with_rebalanced_false() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let request_iface = AddressHash::new_from_slice(b"request-iface");
        let destination_iface = AddressHash::new_from_slice(b"destination-iface");
        let request = link_request(destination);
        let mut table = LinkTable::new();

        table.add(&request, destination, request_iface, destination_iface, 0);

        let link_id = LinkId::from(&request);
        let rebalanced_before = table.0.get(&link_id).unwrap().rebalanced;
        assert!(!rebalanced_before);
        assert!(!table.0.get(&link_id).unwrap().validated);
    }

    #[test]
    fn lrproof_signals_rebalance_once() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let request_iface = AddressHash::new_from_slice(b"request-iface");
        let destination_iface = AddressHash::new_from_slice(b"destination-iface");
        let request = link_request(destination);
        let link_id = LinkId::from(&request);
        let mut table = LinkTable::new();

        table.add(&request, destination, request_iface, destination_iface, 0);

        let lrproof = Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: 2,
                ..Default::default()
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::LinkRequestProof,
            data: Default::default(),
        };

        let outcome = table
            .handle_proof(&lrproof)
            .expect("lrproof should be forwarded");

        let rebalance = outcome
            .rebalance
            .expect("lrproof should signal a rebalance on first receipt");
        assert_eq!(rebalance.destination, destination);
        assert_eq!(rebalance.hops, 2);
        assert!(table.0.get(&link_id).unwrap().rebalanced);

        // Second LRPROOF for the same link must NOT signal another rebalance.
        let outcome2 = table
            .handle_proof(&lrproof)
            .expect("lrproof forwards on second receipt");
        assert!(
            outcome2.rebalance.is_none(),
            "second LRPROOF for the same link must not re-trigger rebalance"
        );
    }

    #[test]
    fn non_lrproof_does_not_signal_rebalance() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let request_iface = AddressHash::new_from_slice(b"request-iface");
        let destination_iface = AddressHash::new_from_slice(b"destination-iface");
        let request = link_request(destination);
        let link_id = LinkId::from(&request);
        let mut table = LinkTable::new();

        table.add(&request, destination, request_iface, destination_iface, 0);

        // A regular message proof (context=None) must not request a rebalance,
        // even though the entry is otherwise validated by handle_proof.
        let regular_proof = Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: 0,
                ..Default::default()
            },
            ifac: None,
            destination: link_id,
            transport: None,
            context: PacketContext::None,
            data: Default::default(),
        };

        let outcome = table
            .handle_proof(&regular_proof)
            .expect("regular proof should forward");
        assert!(
            outcome.rebalance.is_none(),
            "non-LRPROOF context must never signal a rebalance"
        );
    }

    #[test]
    fn first_link_request_is_new_and_subsequent_ingress_repeat_is_retransmission() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let ingress_iface = AddressHash::new_from_slice(b"ingress-iface");
        let egress_iface = AddressHash::new_from_slice(b"egress-iface");
        let request = link_request(destination);
        let mut table = LinkTable::new();

        // First arrival: a new entry is created and the request forwarded.
        assert_eq!(
            table.add(&request, destination, ingress_iface, egress_iface, 0),
            AddLinkRequest::New
        );

        // A retransmission arriving again from the same ingress direction
        // at the same hop count is a legitimate initiator retry and must
        // still be forwarded.
        assert_eq!(
            table.add(&request, destination, ingress_iface, egress_iface, 0),
            AddLinkRequest::Retransmission
        );
    }

    #[test]
    fn link_request_looped_back_with_higher_hops_is_dropped() {
        let destination = AddressHash::new_from_slice(b"link-destination");
        let ingress_iface = AddressHash::new_from_slice(b"ingress-iface");
        let egress_iface = AddressHash::new_from_slice(b"egress-iface");
        let mut request = link_request(destination);
        let mut table = LinkTable::new();

        // First forward: request arrives with 1 hop, forwarded out the
        // egress interface.
        request.header.hops = 1;
        assert_eq!(
            table.add(&request, destination, ingress_iface, egress_iface, 0),
            AddLinkRequest::New
        );

        // The same request comes back after having been forwarded once more
        // (now 2 hops): it looped through a stale path. It must be dropped,
        // not re-forwarded.
        request.header.hops = 2;
        assert_eq!(
            table.add(&request, destination, egress_iface, ingress_iface, 0),
            AddLinkRequest::Loop
        );
    }

    #[test]
    fn same_hop_retransmission_on_single_interface_is_not_dropped() {
        // A node with a single shared-medium interface (e.g. LoRa) sees the
        // initiator's retransmission on the same interface it forwards out
        // of. The retransmission must not be misclassified as a loop: only a
        // strictly higher hop count marks a loop.
        let destination = AddressHash::new_from_slice(b"link-destination");
        let single_iface = AddressHash::new_from_slice(b"only-iface");
        let mut request = link_request(destination);
        let mut table = LinkTable::new();

        request.header.hops = 1;
        assert_eq!(
            table.add(&request, destination, single_iface, single_iface, 0),
            AddLinkRequest::New
        );

        // Retransmission at the same hop count: forward it.
        assert_eq!(
            table.add(&request, destination, single_iface, single_iface, 0),
            AddLinkRequest::Retransmission
        );

        // A looped copy at a higher hop count: drop it.
        request.header.hops = 3;
        assert_eq!(
            table.add(&request, destination, single_iface, single_iface, 0),
            AddLinkRequest::Loop
        );
    }
}
