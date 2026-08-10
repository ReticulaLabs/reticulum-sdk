use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::{
    hash::AddressHash,
    packet::{Header, IfacFlag, Packet},
};

pub struct ReverseEntry {
    pub timestamp: Instant,
    /// Interface the original packet was received on. The proof for that
    /// packet is forwarded back out on this interface (Python
    /// `IDX_RT_RCVD_IF`).
    pub received_from: AddressHash,
    /// Interface the original packet was forwarded out on. A proof may only
    /// be forwarded back if it arrives on this interface (Python
    /// `IDX_RT_OUTB_IF`).
    pub outbound_interface: AddressHash,
}

fn send_backwards(packet: &Packet, entry: &ReverseEntry) -> (Packet, AddressHash) {
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

    (propagated, entry.received_from)
}

pub struct ReverseTable(HashMap<AddressHash, ReverseEntry>);

impl ReverseTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(
        &mut self,
        packet: &Packet,
        received_from: AddressHash,
        outbound_interface: AddressHash,
    ) {
        let truncated_packet_hash = AddressHash::new_from_hash(&packet.hash());
        let entry = ReverseEntry {
            timestamp: Instant::now(),
            received_from,
            outbound_interface,
        };

        self.0.insert(truncated_packet_hash, entry);
    }

    /// Handle a received proof. Like the Python reference
    /// (`Transport.py:2338-2347`), the reverse entry is consumed whenever a
    /// proof for its destination is seen, and the proof is only forwarded
    /// back to the previous hop if it arrived on the same interface the
    /// original packet was forwarded out on. A proof arriving on any other
    /// interface is dropped, preventing a spoofed proof from redirecting
    /// traffic onto a different interface.
    pub fn handle_proof(
        &mut self,
        proof: &Packet,
        received_on: AddressHash,
    ) -> Option<(Packet, AddressHash)> {
        self.0.remove(&proof.destination).and_then(|entry| {
            if received_on == entry.outbound_interface {
                Some(send_backwards(proof, &entry))
            } else {
                None
            }
        })
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn remove_stale(&mut self, max_age: Duration) {
        self.0
            .retain(|_, entry| entry.timestamp.elapsed() <= max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::ReverseTable;
    use crate::{
        hash::AddressHash,
        packet::{DestinationType, Header, IfacFlag, Packet, PacketContext, PacketDataBuffer, PacketType},
    };

    #[test]
    fn forwards_proof_back_to_previous_hop() {
        let original_destination = AddressHash::new_from_slice(b"probe-destination");
        let previous_hop_iface = AddressHash::new_from_slice(b"previous-hop-iface");
        let next_hop_iface = AddressHash::new_from_slice(b"next-hop-iface");

        let mut original_data = PacketDataBuffer::new();
        original_data.write(b"payload");

        let original = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: original_destination,
            transport: None,
            context: PacketContext::None,
            data: original_data,
        };

        let mut reverse_table = ReverseTable::new();
        reverse_table.add(&original, previous_hop_iface, next_hop_iface);

        let mut proof_data = PacketDataBuffer::new();
        proof_data.write(b"proof");
        let proof = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_hash(&original.hash()),
            transport: None,
            context: PacketContext::None,
            data: proof_data,
        };

        // The proof arrives on the same interface the original packet was
        // forwarded out on, so it is routed back to the previous hop.
        let (propagated, iface) = reverse_table
            .handle_proof(&proof, next_hop_iface)
            .expect("reverse entry exists");

        assert_eq!(iface, previous_hop_iface);
        assert_eq!(propagated.destination, proof.destination);
        assert_eq!(propagated.transport, None);
        assert_eq!(propagated.header.hops, proof.header.hops);
    }

    #[test]
    fn proof_on_wrong_interface_is_dropped() {
        let original_destination = AddressHash::new_from_slice(b"probe-destination");
        let previous_hop_iface = AddressHash::new_from_slice(b"previous-hop-iface");
        let next_hop_iface = AddressHash::new_from_slice(b"next-hop-iface");
        let attacker_iface = AddressHash::new_from_slice(b"attacker-iface");

        let mut original_data = PacketDataBuffer::new();
        original_data.write(b"payload");

        let original = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: original_destination,
            transport: None,
            context: PacketContext::None,
            data: original_data,
        };

        let mut reverse_table = ReverseTable::new();
        reverse_table.add(&original, previous_hop_iface, next_hop_iface);

        let mut proof_data = PacketDataBuffer::new();
        proof_data.write(b"proof");
        let proof = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_hash(&original.hash()),
            transport: None,
            context: PacketContext::None,
            data: proof_data,
        };

        // A spoofed proof injected on a different interface must not be
        // forwarded back towards the sender.
        assert!(
            reverse_table.handle_proof(&proof, attacker_iface).is_none(),
            "proof arriving on the wrong interface must be dropped"
        );
    }

    #[test]
    fn reverse_entry_is_consumed_once_handled() {
        let original_destination = AddressHash::new_from_slice(b"probe-destination");
        let previous_hop_iface = AddressHash::new_from_slice(b"previous-hop-iface");
        let next_hop_iface = AddressHash::new_from_slice(b"next-hop-iface");

        let mut original_data = PacketDataBuffer::new();
        original_data.write(b"payload");

        let original = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: original_destination,
            transport: None,
            context: PacketContext::None,
            data: original_data,
        };

        let mut reverse_table = ReverseTable::new();
        reverse_table.add(&original, previous_hop_iface, next_hop_iface);

        let mut proof_data = PacketDataBuffer::new();
        proof_data.write(b"proof");
        let proof = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_hash(&original.hash()),
            transport: None,
            context: PacketContext::None,
            data: proof_data,
        };

        assert!(
            reverse_table.handle_proof(&proof, next_hop_iface).is_some(),
            "first proof on the correct interface is forwarded"
        );
        assert!(
            reverse_table.handle_proof(&proof, next_hop_iface).is_none(),
            "the reverse entry is consumed after the first proof"
        );
    }

    #[test]
    fn send_backwards_resets_ifac_flag_to_open() {
        let original_destination = AddressHash::new_from_slice(b"probe-destination");
        let previous_hop_iface = AddressHash::new_from_slice(b"previous-hop-iface");
        let next_hop_iface = AddressHash::new_from_slice(b"next-hop-iface");

        let mut original_data = PacketDataBuffer::new();
        original_data.write(b"payload");

        let original = Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: original_destination,
            transport: None,
            context: PacketContext::None,
            data: original_data,
        };

        let mut reverse_table = ReverseTable::new();
        reverse_table.add(&original, previous_hop_iface, next_hop_iface);

        // Proof with ifac_flag=Authenticated but no ifac data.
        // send_backwards() must reset the flag to Open.
        let mut proof_data = PacketDataBuffer::new();
        proof_data.write(b"proof");
        let proof = Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_hash(&original.hash()),
            transport: None,
            context: PacketContext::None,
            data: proof_data,
        };

        let (propagated, _iface) = reverse_table
            .handle_proof(&proof, next_hop_iface)
            .expect("reverse entry exists");

        assert_eq!(propagated.header.ifac_flag, IfacFlag::Open);
        assert!(propagated.ifac.is_none());
    }
}
