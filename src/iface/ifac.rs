use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};

use crate::error::RnsError;
use crate::packet::{IfacFlag, Header, Packet, PacketIfac};

/// Configuration for Interface Access Codes (IFAC) on a single interface.
///
/// The IFAC is an Ed25519 signature (or truncated version) of the entire
/// packet, inserted between the header and the address fields. It is derived
/// from a shared access code (passphrase) that all peers on the interface
/// know.
///
/// Because the keypair is deterministically derived from the shared access
/// code, verification of truncated signatures works by re-signing the data
/// and comparing the first `ifac_len` bytes. Only full 64-byte signatures
/// use `verify_strict()`.
#[derive(Clone)]
pub struct IfacConfig {
    sign_key: SigningKey,
    verify_key: VerifyingKey,
    ifac_len: usize,
}

impl IfacConfig {
    /// Derive an IFAC identity from an access code.
    ///
    /// Hashes the access code with SHA-256 to produce a deterministic
    /// Ed25519 keypair, exactly like the Python reference implementation:
    /// `RNS.Interfaces.Interface._derive_access_identity()`.
    pub fn derive(access_code: &[u8], ifac_len: usize) -> Self {
        let seed: [u8; 32] = Sha256::digest(access_code).into();
        let sign_key = SigningKey::from_bytes(&seed);
        let verify_key = sign_key.verifying_key();
        let ifac_len = ifac_len.min(SIGNATURE_LENGTH);
        Self {
            sign_key,
            verify_key,
            ifac_len,
        }
    }

    /// Compute and attach an IFAC to a packet.
    ///
    /// Signs the packet's `signed_data()` (header with IFAC flag cleared,
    /// addresses, context, and data) using the configured Ed25519 key. Stores
    /// the (possibly truncated) signature in `packet.ifac` and sets
    /// `ifac_flag` to `Authenticated`.
    pub fn attach(&self, packet: &mut Packet) -> Result<(), RnsError> {
        let signed_data = packet.signed_data()?;

        let signature = self.sign_key.sign(&signed_data);
        let sig_bytes = signature.to_bytes();

        let truncated_len = self.ifac_len.min(SIGNATURE_LENGTH);
        packet.header.ifac_flag = IfacFlag::Authenticated;
        packet.ifac = Some(PacketIfac::new_from_slice(&sig_bytes[..truncated_len]));

        Ok(())
    }

    /// Verify the IFAC on a received packet.
    ///
    /// Checks the signature against `packet.signed_data()` using the
    /// configured Ed25519 verifying key. Returns `Ok(())` on success.
    pub fn verify_packet(&self, packet: &Packet) -> Result<(), RnsError> {
        if packet.header.ifac_flag != IfacFlag::Authenticated {
            return Err(RnsError::PacketError);
        }

        let ifac = packet.ifac.as_ref().ok_or(RnsError::PacketError)?;
        self.verify_raw(&packet.header, ifac.as_slice(), &packet.signed_data()?)
    }

    /// Verify an IFAC directly from header, IFAC bytes, and signed data.
    ///
    /// Useful when processing raw bytes before constructing a full `Packet`.
    ///
    /// For full 64-byte signatures, uses `verify_strict()`. For truncated
    /// signatures (len < 64), the verifier re-computes the full signature
    /// using the shared signing key and compares only the first `ifac_len`
    /// bytes. This works because both sides derive the same keypair from
    /// the shared access code.
    pub fn verify_raw(
        &self,
        header: &Header,
        ifac_bytes: &[u8],
        signed_data: &[u8],
    ) -> Result<(), RnsError> {
        if header.ifac_flag != IfacFlag::Authenticated {
            return Err(RnsError::PacketError);
        }
        if ifac_bytes.is_empty() || ifac_bytes.len() > SIGNATURE_LENGTH {
            return Err(RnsError::PacketError);
        }

        if ifac_bytes.len() < SIGNATURE_LENGTH {
            // Truncated IFAC: re-sign and compare the prefix.
            // Both sides share the same signing key (derived from the
            // access code), so the verifier can deterministically
            // reconstruct the full signature.
            let expected = self.sign_key.sign(signed_data);
            let expected_bytes = expected.to_bytes();
            if &expected_bytes[..ifac_bytes.len()] == ifac_bytes {
                Ok(())
            } else {
                Err(RnsError::IncorrectSignature)
            }
        } else {
            // Full 64-byte signature: standard Ed25519 verification.
            let signature =
                Signature::from_slice(ifac_bytes).map_err(|_| RnsError::CryptoError)?;
            self.verify_key
                .verify_strict(signed_data, &signature)
                .map_err(|_| RnsError::IncorrectSignature)
        }
    }

    /// The configured IFAC length in bytes.
    pub fn ifac_len(&self) -> usize {
        self.ifac_len
    }

    /// Reference to the Ed25519 verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verify_key
    }

    /// Reference to the Ed25519 signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.sign_key
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::packet::{
        Header, HeaderType, PacketContext, PacketDataBuffer, PropagationType, DestinationType,
        PacketType,
    };
    use crate::hash::AddressHash;

    #[test]
    fn derive_is_deterministic() {
        let a = IfacConfig::derive(b"test_access_code", 64);
        let b = IfacConfig::derive(b"test_access_code", 64);
        assert_eq!(a.sign_key.to_bytes(), b.sign_key.to_bytes());
    }

    #[test]
    fn different_access_codes_differ() {
        let a = IfacConfig::derive(b"code_a", 64);
        let b = IfacConfig::derive(b"code_b", 64);
        assert_ne!(a.sign_key.to_bytes(), b.sign_key.to_bytes());
    }

    #[test]
    fn ifac_len_clamps_to_signature_length() {
        let config = IfacConfig::derive(b"test", 200);
        assert_eq!(config.ifac_len, SIGNATURE_LENGTH);
        let config = IfacConfig::derive(b"test", 0);
        assert_eq!(config.ifac_len, 0);
    }

    #[test]
    fn attach_and_verify_roundtrip() {
        let config = IfacConfig::derive(b"secret", 64);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new([0x01; 16]),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"hello"),
        };

        config.attach(&mut packet).expect("attach ifac");
        assert_eq!(packet.header.ifac_flag, IfacFlag::Authenticated);
        assert!(packet.ifac.is_some());

        config.verify_packet(&packet).expect("verify ifac");
    }

    #[test]
    fn verify_rejects_tampered_data() {
        let alice = IfacConfig::derive(b"alice", 64);
        let eve = IfacConfig::derive(b"eve", 64);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new([0x02; 16]),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"secret message"),
        };

        alice.attach(&mut packet).expect("attach ifac");

        // Eve should NOT be able to verify Alice's IFAC
        let result = eve.verify_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_modified_payload() {
        let config = IfacConfig::derive(b"secret", 64);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new([0x03; 16]),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"original"),
        };

        config.attach(&mut packet).expect("attach ifac");

        // Tamper with the data
        packet.data = PacketDataBuffer::new_from_slice(b"tampered");

        let result = config.verify_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_ifac_still_verifies() {
        let config = IfacConfig::derive(b"truncated_test", 16);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 2,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new([0x04; 16]),
            transport: Some(AddressHash::new([0x05; 16])),
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"truncated test payload"),
        };

        config.attach(&mut packet).expect("attach truncated ifac");

        // The IFAC should only be 16 bytes
        assert_eq!(
            packet.ifac.as_ref().map(|i| i.as_slice().len()),
            Some(16)
        );

        // The verify takes the truncated IFAC and pad with zeroes
        config.verify_packet(&packet).expect("verify truncated ifac");
    }

    #[test]
    fn verify_rejects_packet_without_ifac_flag() {
        let config = IfacConfig::derive(b"test", 64);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new([0x06; 16]),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"no ifac"),
        };

        let result = config.verify_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn verify_raw_matches_serialized_ifac_flow() {
        let config = IfacConfig::derive(b"roundtrip_test", 64);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 3,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new([0x07; 16]),
            transport: Some(AddressHash::new([0x08; 16])),
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(b"raw ifac verify"),
        };

        config.attach(&mut packet).expect("attach ifac");

        // Simulate what a receiver would do with raw bytes:
        // 1. Serialize the packet
        // 2. Deserialize with ifac_len
        // 3. Verify

        use crate::buffer::OutputBuffer;
        use crate::serde::Serialize;

        let mut buf = [0u8; 1024];
        let mut output = OutputBuffer::new(&mut buf);
        packet.serialize(&mut output).expect("serialize");

        let raw_bytes = output.as_slice().to_vec();

        use crate::buffer::InputBuffer;
        let mut input = InputBuffer::new(&raw_bytes);
        let parsed = Packet::deserialize_with_ifac_len(&mut input, 64).expect("deserialize with ifac");

        config.verify_packet(&parsed).expect("verify after deserialization");
    }
}
