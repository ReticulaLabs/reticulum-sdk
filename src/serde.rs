use crate::{
    buffer::{InputBuffer, OutputBuffer},
    error::RnsError,
    hash::AddressHash,
    packet::{
        Header, HeaderType, IfacFlag, PACKET_IFAC_MAX_LENGTH, Packet, PacketContext,
        PacketDataBuffer, PacketIfac,
    },
};

pub trait Serialize {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError>;
}

impl Serialize for AddressHash {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(self.as_slice())
    }
}

impl Serialize for Header {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[self.to_meta(), self.hops])
    }
}
impl Serialize for PacketContext {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[*self as u8])
    }
}

impl Serialize for Packet {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        self.header.serialize(buffer)?;

        if self.header.ifac_flag == IfacFlag::Authenticated {
            if let Some(ifac) = &self.ifac {
                buffer.write(ifac.as_slice())?;
            } else {
                return Err(RnsError::PacketError);
            }
        }

        if self.header.header_type == HeaderType::Type2 {
            let transport = self.transport.as_ref().ok_or(RnsError::PacketError)?;
            transport.serialize(buffer)?;
        }

        self.destination.serialize(buffer)?;

        self.context.serialize(buffer)?;

        buffer.write(self.data.as_slice())
    }
}

impl Header {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Header, RnsError> {
        let mut header = Header::from_meta(buffer.read_byte()?);
        header.hops = buffer.read_byte()?;

        Ok(header)
    }
}

impl AddressHash {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<AddressHash, RnsError> {
        let mut address = AddressHash::new_empty();

        buffer.read(&mut address.as_mut_slice())?;

        Ok(address)
    }
}

impl PacketContext {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<PacketContext, RnsError> {
        Ok(PacketContext::from(buffer.read_byte()?))
    }
}
impl Packet {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Packet, RnsError> {
        Self::deserialize_with_ifac_len(buffer, 0)
    }

    pub fn deserialize_with_ifac_len(
        buffer: &mut InputBuffer,
        ifac_len: usize,
    ) -> Result<Packet, RnsError> {
        let mut header = Header::deserialize(buffer)?;

        let ifac = if ifac_len > 0 {
            if ifac_len > PACKET_IFAC_MAX_LENGTH {
                return Err(RnsError::PacketError);
            }
            let mut ifac_data = [0u8; PACKET_IFAC_MAX_LENGTH];
            buffer.read(&mut ifac_data[..ifac_len])?;
            Some(PacketIfac::new_from_slice(&ifac_data[..ifac_len]))
        } else {
            None
        };

        header.ifac_flag = if ifac.is_some() {
            IfacFlag::Authenticated
        } else {
            IfacFlag::Open
        };

        let transport = if header.header_type == HeaderType::Type2 {
            Some(AddressHash::deserialize(buffer)?)
        } else {
            None
        };

        let destination = AddressHash::deserialize(buffer)?;

        let context = PacketContext::deserialize(buffer)?;

        let mut packet = Packet {
            header,
            ifac,
            destination,
            transport,
            context,
            data: PacketDataBuffer::new(),
        };

        let data_len = buffer.bytes_left();
        buffer.read(packet.data.try_accuire_buf(data_len)?)?;

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{
        buffer::{InputBuffer, OutputBuffer},
        error::RnsError,
        hash::AddressHash,
        packet::{
            ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PACKET_IFAC_MAX_LENGTH,
            PACKET_MDU, Packet, PacketContext, PacketDataBuffer, PacketIfac, PacketType,
            PropagationType, RETICULUM_MTU,
        },
        test_vectors,
    };

    use super::Serialize;

    #[test]
    fn serialize_forwarded_announce_matches_golden_vector() {
        let announce_bytes = test_vectors::decode_hex(test_vectors::ANNOUNCE_PACKET_HEX);
        let mut input_buffer = InputBuffer::new(&announce_bytes);
        let mut packet = Packet::deserialize(&mut input_buffer).expect("deserialized announce");

        packet.header.header_type = HeaderType::Type2;
        packet.header.propagation_type = PropagationType::Transport;
        packet.header.hops = 1;
        packet.transport = Some(AddressHash::new(
            test_vectors::FIXED_FORWARDED_ANNOUNCE_TRANSPORT_ID,
        ));

        let mut output_data = [0u8; 4096];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("serialized forwarded announce");

        let expected = test_vectors::decode_hex(test_vectors::FORWARDED_ANNOUNCE_PACKET_HEX);
        assert_eq!(output_buffer.as_slice(), expected.as_slice());
    }

    #[test]
    fn deserialize_announce_vector() {
        let packet_bytes = test_vectors::decode_hex(test_vectors::ANNOUNCE_PACKET_HEX);
        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let packet = Packet::deserialize(&mut input_buffer).expect("deserialized announce");

        assert_eq!(packet.header.header_type, HeaderType::Type1);
        assert_eq!(packet.header.propagation_type, PropagationType::Broadcast);
        assert_eq!(packet.header.destination_type, DestinationType::Single);
        assert_eq!(packet.header.packet_type, PacketType::Announce);
        assert_eq!(packet.context, PacketContext::None);
        assert_eq!(packet.transport, None);

        let mut output_data = [0u8; 4096];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("reserialized announce");
        assert_eq!(output_buffer.as_slice(), packet_bytes.as_slice());
    }

    #[test]
    fn deserialize_path_response_vector() {
        let packet_bytes = test_vectors::decode_hex(test_vectors::PATH_RESPONSE_PACKET_HEX);
        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let packet = Packet::deserialize(&mut input_buffer).expect("deserialized path response");

        assert_eq!(packet.header.header_type, HeaderType::Type1);
        assert_eq!(packet.header.propagation_type, PropagationType::Broadcast);
        assert_eq!(packet.header.destination_type, DestinationType::Single);
        assert_eq!(packet.header.packet_type, PacketType::Announce);
        assert_eq!(packet.context, PacketContext::PathResponse);
        assert_eq!(packet.transport, None);

        let mut output_data = [0u8; 4096];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("reserialized path response");
        assert_eq!(output_buffer.as_slice(), packet_bytes.as_slice());
    }

    #[test]
    fn deserialize_lrproof_vector() {
        let packet_bytes = test_vectors::decode_hex(test_vectors::LRPROOF_PACKET_HEX);
        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let packet = Packet::deserialize(&mut input_buffer).expect("deserialized lrproof");

        assert_eq!(packet.header.header_type, HeaderType::Type1);
        assert_eq!(packet.header.destination_type, DestinationType::Link);
        assert_eq!(packet.header.packet_type, PacketType::Proof);
        assert_eq!(packet.context, PacketContext::LinkRequestProof);
        assert_eq!(
            packet.destination,
            AddressHash::new(test_vectors::FIXED_LRPROOF_LINK_ID)
        );
        assert_eq!(packet.transport, None);

        let mut output_data = [0u8; 4096];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("reserialized lrproof");
        assert_eq!(output_buffer.as_slice(), packet_bytes.as_slice());
    }

    #[test]
    fn header_meta_preserves_context_and_propagation_bits() {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            context_flag: ContextFlag::Set,
            propagation_type: PropagationType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 4,
        };

        let mut output_data = [0u8; 8];
        let mut buffer = OutputBuffer::new(&mut output_data);
        header.serialize(&mut buffer).expect("serialized header");

        assert_eq!(buffer.as_slice()[0], 0b01110000);
        assert_eq!(buffer.as_slice()[1], 4);

        let mut input_buffer = InputBuffer::new(buffer.as_slice());
        let decoded = Header::deserialize(&mut input_buffer).expect("deserialized header");

        assert_eq!(decoded, header);
    }

    #[test]
    fn serialized_packet_fits_reticulum_mtu() {
        let mut output_data = [0u8; RETICULUM_MTU];
        let mut buffer = OutputBuffer::new(&mut output_data);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: Some(AddressHash::new_from_rand(OsRng)),
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
        };

        packet.data.resize(PACKET_MDU);

        packet.serialize(&mut buffer).expect("serialized packet");

        assert!(buffer.offset() <= RETICULUM_MTU);
        assert_eq!(buffer.offset(), RETICULUM_MTU - 1);
    }

    #[test]
    fn serialize_rejects_type2_packet_without_transport_id() {
        let mut output_data = [0u8; RETICULUM_MTU];
        let mut buffer = OutputBuffer::new(&mut output_data);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new(),
        };

        let result = packet.serialize(&mut buffer);

        assert!(matches!(result, Err(RnsError::PacketError)));
    }

    #[test]
    fn deserialize_accepts_high_mtu_packet_data() {
        let mut packet_bytes = Vec::new();
        packet_bytes.extend_from_slice(&[Header::default().to_meta(), 0]);
        packet_bytes.extend_from_slice(AddressHash::new_empty().as_slice());
        packet_bytes.push(PacketContext::None as u8);
        let data_len = 2547;
        packet_bytes.resize(packet_bytes.len() + data_len, 0x42);

        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let packet = Packet::deserialize(&mut input_buffer).expect("deserialized high-MTU packet");

        assert_eq!(packet.data.len(), data_len);

        let mut output_data = vec![0u8; packet_bytes.len()];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("reserialized high-MTU packet");
        assert_eq!(output_buffer.as_slice(), packet_bytes.as_slice());
    }

    #[test]
    fn ifac_roundtrip() {
        let ifac_bytes = [0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05];
        let ifac = PacketIfac::new_from_slice(&ifac_bytes);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 3,
                ..Default::default()
            },
            ifac: Some(ifac),
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"hello"),
        };

        let mut output_data = [0u8; 1024];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("serialized with ifac");

        let mut input_buffer = InputBuffer::new(output_buffer.as_slice());
        let decoded = Packet::deserialize_with_ifac_len(&mut input_buffer, ifac_bytes.len())
            .expect("deserialized with ifac");

        assert_eq!(decoded.header, packet.header);
        assert_eq!(decoded.destination, packet.destination);
        assert_eq!(decoded.context, packet.context);
        assert_eq!(decoded.data.as_slice(), packet.data.as_slice());
        assert_eq!(decoded.transport, None);

        let decoded_ifac = decoded.ifac.expect("ifac should be present");
        assert_eq!(decoded_ifac.as_slice(), ifac_bytes);
    }

    #[test]
    fn ifac_type2_roundtrip() {
        let ifac_bytes = [0x11, 0x22, 0x33, 0x44];
        let ifac = PacketIfac::new_from_slice(&ifac_bytes);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 1,
                ..Default::default()
            },
            ifac: Some(ifac),
            destination: AddressHash::new_from_rand(OsRng),
            transport: Some(AddressHash::new_from_rand(OsRng)),
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"world"),
        };

        let mut output_data = [0u8; 1024];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        packet
            .serialize(&mut output_buffer)
            .expect("serialized type2 with ifac");

        let mut input_buffer = InputBuffer::new(output_buffer.as_slice());
        let decoded = Packet::deserialize_with_ifac_len(&mut input_buffer, ifac_bytes.len())
            .expect("deserialized type2 with ifac");

        assert_eq!(decoded.header, packet.header);
        assert_eq!(decoded.destination, packet.destination);
        assert_eq!(decoded.transport, packet.transport);
        assert_eq!(decoded.context, packet.context);
        assert_eq!(decoded.data.as_slice(), packet.data.as_slice());

        let decoded_ifac = decoded.ifac.expect("ifac should be present");
        assert_eq!(decoded_ifac.as_slice(), ifac_bytes);
    }

    #[test]
    fn serialize_rejects_ifac_flag_without_ifac_data() {
        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Authenticated,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"data"),
        };

        let mut output_data = [0u8; 1024];
        let mut output_buffer = OutputBuffer::new(&mut output_data);
        let result = packet.serialize(&mut output_buffer);

        assert!(matches!(result, Err(RnsError::PacketError)));
    }

    #[test]
    fn deserialize_skips_ifac_when_ifac_len_is_zero() {
        let ifac_bytes = vec![0x42u8; 8];
        let mut packet_bytes = Vec::new();
        let header = Header {
            ifac_flag: IfacFlag::Authenticated,
            ..Default::default()
        };
        packet_bytes.extend_from_slice(&[header.to_meta(), 0]);
        packet_bytes.extend_from_slice(&ifac_bytes);
        packet_bytes.extend_from_slice(AddressHash::new_empty().as_slice());
        packet_bytes.push(PacketContext::None as u8);
        packet_bytes.push(0x00);

        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let packet = Packet::deserialize(&mut input_buffer)
            .expect("deserialize with ifac_len=0 should succeed");
        assert_eq!(packet.header.ifac_flag, IfacFlag::Open);
        assert!(packet.ifac.is_none());
    }

    #[test]
    fn deserialize_rejects_ifac_len_exceeds_max() {
        let mut packet_bytes = Vec::new();
        let header = Header {
            ifac_flag: IfacFlag::Authenticated,
            ..Default::default()
        };
        packet_bytes.extend_from_slice(&[header.to_meta(), 0]);
        packet_bytes.extend_from_slice(&[0u8; PACKET_IFAC_MAX_LENGTH + 1]);
        packet_bytes.extend_from_slice(AddressHash::new_empty().as_slice());
        packet_bytes.push(PacketContext::None as u8);
        packet_bytes.push(0x00);

        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let result =
            Packet::deserialize_with_ifac_len(&mut input_buffer, PACKET_IFAC_MAX_LENGTH + 1);
        assert!(matches!(result, Err(RnsError::PacketError)));
    }

    #[test]
    fn deserialize_reads_ifac_bytes_when_ifac_len_provided() {
        let ifac_data = [0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut packet_bytes = Vec::new();
        let header = Header {
            ifac_flag: IfacFlag::Open,
            ..Default::default()
        };
        packet_bytes.extend_from_slice(&[header.to_meta(), 0]);
        packet_bytes.extend_from_slice(&ifac_data);
        packet_bytes.extend_from_slice(AddressHash::new_empty().as_slice());
        packet_bytes.push(PacketContext::None as u8);
        packet_bytes.extend_from_slice(b"data");

        let mut input_buffer = InputBuffer::new(&packet_bytes);
        let packet = Packet::deserialize_with_ifac_len(&mut input_buffer, ifac_data.len())
            .expect("should read IFAC bytes when ifac_len > 0");

        assert!(packet.ifac.is_some());
        assert_eq!(packet.header.ifac_flag, IfacFlag::Authenticated);
        assert_eq!(packet.ifac.unwrap().as_slice(), &ifac_data);
        assert_eq!(packet.data.as_slice(), b"data");
    }
}
