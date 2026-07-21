use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::{
    hash::AddressHash,
    packet::{Header, IfacFlag, Packet},
};

pub struct ReverseEntry {
    pub timestamp: Instant,
    pub received_from: AddressHash,
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

    pub fn add(&mut self, packet: &Packet, received_from: AddressHash) {
        let truncated_packet_hash = AddressHash::new_from_hash(&packet.hash());
        let entry = ReverseEntry {
            timestamp: Instant::now(),
            received_from,
        };

        self.0.insert(truncated_packet_hash, entry);
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        self.0.get_mut(&proof.destination).map(|entry| {
            entry.timestamp = Instant::now();
            send_backwards(proof, entry)
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

        let mut original_data = PacketDataBuffer::new();
        original_data.safe_write(b"payload");

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
        reverse_table.add(&original, previous_hop_iface);

        let mut proof_data = PacketDataBuffer::new();
        proof_data.safe_write(b"proof");
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

        let (propagated, iface) = reverse_table
            .handle_proof(&proof)
            .expect("reverse entry exists");

        assert_eq!(iface, previous_hop_iface);
        assert_eq!(propagated.destination, proof.destination);
        assert_eq!(propagated.transport, None);
        assert_eq!(propagated.header.hops, proof.header.hops);
    }

    #[test]
    fn send_backwards_resets_ifac_flag_to_open() {
        let original_destination = AddressHash::new_from_slice(b"probe-destination");
        let previous_hop_iface = AddressHash::new_from_slice(b"previous-hop-iface");

        let mut original_data = PacketDataBuffer::new();
        original_data.safe_write(b"payload");

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
        reverse_table.add(&original, previous_hop_iface);

        // Proof with ifac_flag=Authenticated but no ifac data.
        // send_backwards() must reset the flag to Open.
        let mut proof_data = PacketDataBuffer::new();
        proof_data.safe_write(b"proof");
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
            .handle_proof(&proof)
            .expect("reverse entry exists");

        assert_eq!(propagated.header.ifac_flag, IfacFlag::Open);
        assert!(propagated.ifac.is_none());
    }
}
