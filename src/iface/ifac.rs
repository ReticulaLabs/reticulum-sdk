use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::RnsError;
use crate::packet::{Header, IfacFlag, Packet, PacketIfac};

/// IFAC derivation salt, matching `RNS.Reticulum.IFAC_SALT` in the Python
/// reference implementation (`RNS/Reticulum.py`).
///
/// This constant must remain byte-for-byte identical to the Python value
/// for IFAC-signed packets to be interoperable across implementations.
const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

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
    /// Derive an IFAC identity from a network name and optional key, using
    /// the exact algorithm from the Python reference implementation
    /// (`RNS/Interfaces/TCPInterface.py` `TCPServerInterface.incoming_connection`,
    /// and `RNS/Reticulum.py._synthesize_interface`):
    ///
    /// ```text
    /// ifac_origin       = SHA256(netname_utf8) || SHA256(netkey_utf8)   # omitted if None
    /// ifac_origin_hash  = SHA256(ifac_origin)
    /// ifac_key          = HKDF-SHA256(64 bytes, ikm=ifac_origin_hash, salt=IFAC_SALT, info=None)
    /// signing_seed      = ifac_key[32..64]
    /// ```
    ///
    /// The Ed25519 signing key is derived from `ifac_key[32..64]`. The
    /// X25519 portion (`ifac_key[0..32]`) is what the Python reference
    /// stores in `interface.ifac_key` and is used to construct
    /// `RNS.Identity.from_bytes(ifac_key)`.
    ///
    /// At least one of `netname` / `netkey` must be `Some`. If both are
    /// `None`, the resulting `ifac_origin` is empty and the derived key is
    /// ill-defined; this function returns an empty signing key in that case
    /// (callers are expected to provide at least one input).
    pub fn derive(netname: Option<&str>, netkey: Option<&str>, ifac_len: usize) -> Self {
        let mut ifac_origin = Vec::with_capacity(64);
        if let Some(name) = netname {
            ifac_origin.extend_from_slice(&Sha256::digest(name.as_bytes()));
        }
        if let Some(key) = netkey {
            ifac_origin.extend_from_slice(&Sha256::digest(key.as_bytes()));
        }

        let ifac_origin_hash = Sha256::digest(&ifac_origin);
        let mut ifac_key = [0u8; 64];
        // The Python `hkdf()` is HKDF-SHA256 with `info=None` (empty).
        // HKDF-Expand with an empty info produces a well-defined output
        // for any length, so this match is wire-compatible.
        let _ = Hkdf::<Sha256>::new(Some(&IFAC_SALT), &ifac_origin_hash)
            .expand(&[], &mut ifac_key[..]);

        let sign_seed: [u8; 32] = ifac_key[32..64]
            .try_into()
            .expect("hkdf produced 64 bytes");
        let sign_key = SigningKey::from_bytes(&sign_seed);
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
            let signature = Signature::from_slice(ifac_bytes).map_err(|_| RnsError::CryptoError)?;
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
    use super::*;
    use crate::hash::AddressHash;
    use crate::packet::{
        DestinationType, Header, HeaderType, PacketContext, PacketDataBuffer, PacketType,
        PropagationType,
    };

    #[test]
    fn derive_is_deterministic() {
        let a = IfacConfig::derive(Some("test_access_code"), Some("test_access_code"), 64);
        let b = IfacConfig::derive(Some("test_access_code"), Some("test_access_code"), 64);
        assert_eq!(a.sign_key.to_bytes(), b.sign_key.to_bytes());
    }

    #[test]
    fn different_access_codes_differ() {
        let a = IfacConfig::derive(Some("code_a"), None, 64);
        let b = IfacConfig::derive(Some("code_b"), None, 64);
        assert_ne!(a.sign_key.to_bytes(), b.sign_key.to_bytes());
    }

    #[test]
    fn ifac_len_clamps_to_signature_length() {
        let config = IfacConfig::derive(Some("test"), None, 200);
        assert_eq!(config.ifac_len, SIGNATURE_LENGTH);
        let config = IfacConfig::derive(Some("test"), None, 0);
        assert_eq!(config.ifac_len, 0);
    }

    /// Test vector verified against the Python reference implementation
    /// (`RNS.Interfaces.TCPInterface` `TCPServerInterface.incoming_connection`):
    ///
    /// For `netname="test", netkey=None`:
    ///   ifac_origin       = SHA256("test")                              # 9f86d081...
    ///   ifac_origin_hash  = SHA256(ifac_origin)                         # 954d5a49...
    ///   ifac_key          = HKDF-SHA256(64, ifac_origin_hash, IFAC_SALT) # a370c4fe...7f8294df...
    ///   signing_seed      = ifac_key[32..64]                             # 7f8294df95dc55f9...
    ///   verify_key        = Ed25519(signing_seed).public                # b68a5da769bac1467dee00c9d103ca14e2befa6658242f378034ed9d5377daab
    #[test]
    fn derive_matches_python_reference_vector() {
        let config = IfacConfig::derive(Some("test"), None, 64);
        assert_eq!(
            config.sign_key.to_bytes().to_vec(),
            vec![
                0x7f, 0x82, 0x94, 0xdf, 0x95, 0xdc, 0x55, 0xf9, 0x04, 0x6b, 0xf1, 0x9d, 0x06, 0x51,
                0xd3, 0xd3, 0xb8, 0x1e, 0xef, 0xc5, 0xe9, 0x92, 0x27, 0xab, 0x0e, 0xae, 0xd6, 0x1c,
                0x97, 0xc9, 0xf0, 0xba,
            ],
        );
        assert_eq!(
            config.verifying_key().to_bytes().to_vec(),
            vec![
                0xb6, 0x8a, 0x5d, 0xa7, 0x69, 0xba, 0xc1, 0x46, 0x7d, 0xee, 0x00, 0xc9, 0xd1, 0x03,
                0xca, 0x14, 0xe2, 0xbe, 0xfa, 0x66, 0x58, 0x24, 0x2f, 0x37, 0x80, 0x34, 0xed, 0x9d,
                0x53, 0x77, 0xda, 0xab,
            ],
        );
    }

    /// Test vector for `netname="test", netkey="secret"`. Matches:
    ///   ifac_origin_hash = c8e2d6f65e9122c16eaed8a63837e86ddd897a8757b26d0d34f2d467e673a0ee
    ///   ifac_key[32..64] = 374ad85a9a55820bc7b60d8d9248008cdf4650d73b4becdd21a3a97af07fd90c
    #[test]
    fn derive_with_netkey_matches_python_reference_vector() {
        let config = IfacConfig::derive(Some("test"), Some("secret"), 64);
        assert_eq!(
            config.sign_key.to_bytes().to_vec(),
            vec![
                0x37, 0x4a, 0xd8, 0x5a, 0x9a, 0x55, 0x82, 0x0b, 0xc7, 0xb6, 0x0d, 0x8d, 0x92, 0x48,
                0x00, 0x8c, 0xdf, 0x46, 0x50, 0xd7, 0x3b, 0x4b, 0xec, 0xdd, 0x21, 0xa3, 0xa9, 0x7a,
                0xf0, 0x7f, 0xd9, 0x0c,
            ],
        );
    }

    #[test]
    fn attach_and_verify_roundtrip() {
        let config = IfacConfig::derive(Some("secret"), None, 64);

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
        let alice = IfacConfig::derive(Some("alice"), None, 64);
        let eve = IfacConfig::derive(Some("eve"), None, 64);

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
        let config = IfacConfig::derive(Some("secret"), None, 64);

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
        let config = IfacConfig::derive(Some("truncated_test"), None, 16);

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
        assert_eq!(packet.ifac.as_ref().map(|i| i.as_slice().len()), Some(16));

        // The verify takes the truncated IFAC and pad with zeroes
        config
            .verify_packet(&packet)
            .expect("verify truncated ifac");
    }

    #[test]
    fn verify_rejects_packet_without_ifac_flag() {
        let config = IfacConfig::derive(Some("test"), None, 64);

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
        let config = IfacConfig::derive(Some("roundtrip_test"), None, 64);

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
        let parsed =
            Packet::deserialize_with_ifac_len(&mut input, 64).expect("deserialize with ifac");

        config
            .verify_packet(&parsed)
            .expect("verify after deserialization");
    }
}
