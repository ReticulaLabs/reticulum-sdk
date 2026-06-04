pub mod link;
pub mod link_map;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use rand_core::{CryptoRngCore, OsRng};
use x25519_dalek::PublicKey;

use core::{fmt, marker::PhantomData};

use crate::{
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{EmptyIdentity, HashIdentity, Identity, PrivateIdentity, PUBLIC_KEY_LENGTH},
    packet::{
        self, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
        PacketDataBuffer, PacketType, PropagationType,
    },
};
use sha2::Digest;

//***************************************************************************//

pub trait Direction {}

pub struct Input;
pub struct Output;

impl Direction for Input {}
impl Direction for Output {}

//***************************************************************************//

pub trait Type {
    fn destination_type() -> DestinationType;
}

pub struct Single;
pub struct Plain;
pub struct Group;

impl Type for Single {
    fn destination_type() -> DestinationType {
        DestinationType::Single
    }
}

impl Type for Plain {
    fn destination_type() -> DestinationType {
        DestinationType::Plain
    }
}

impl Type for Group {
    fn destination_type() -> DestinationType {
        DestinationType::Group
    }
}

pub const NAME_HASH_LENGTH: usize = 10;
pub const RAND_HASH_LENGTH: usize = 10;
pub const MIN_ANNOUNCE_DATA_LENGTH: usize =
    PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH + RAND_HASH_LENGTH + SIGNATURE_LENGTH;

#[derive(Copy, Clone)]
pub struct DestinationName {
    pub hash: Hash,
}

impl DestinationName {
    pub fn new(app_name: &str, aspects: &str) -> Self {
        let mut hasher = Hash::generator();
        hasher = hasher.chain_update(app_name.as_bytes());
        if !aspects.is_empty() {
            hasher = hasher.chain_update(".".as_bytes());
            hasher = hasher.chain_update(aspects.as_bytes());
        }

        let hash = Hash::new(hasher.finalize().into());

        Self { hash }
    }

    pub fn new_from_hash_slice(hash_slice: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash[..hash_slice.len()].copy_from_slice(hash_slice);

        Self {
            hash: Hash::new(hash),
        }
    }

    pub fn as_name_hash_slice(&self) -> &[u8] {
        &self.hash.as_slice()[..NAME_HASH_LENGTH]
    }
}

#[derive(Copy, Clone)]
pub struct DestinationDesc {
    pub identity: Identity,
    pub address_hash: AddressHash,
    pub name: DestinationName,
}

impl fmt::Display for DestinationDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address_hash)?;

        Ok(())
    }
}

pub type DestinationAnnounce = Packet;

impl DestinationAnnounce {
    pub fn validate(packet: &Packet) -> Result<(SingleOutputDestination, &[u8]), RnsError> {
        if packet.header.packet_type != PacketType::Announce {
            return Err(RnsError::PacketError);
        }

        let announce_data = packet.data.as_slice();

        if announce_data.len() < MIN_ANNOUNCE_DATA_LENGTH {
            return Err(RnsError::OutOfMemory);
        }

        let mut offset = 0usize;

        let public_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;

            VerifyingKey::from_bytes(&key_data).map_err(|_| RnsError::CryptoError)?
        };

        let identity = Identity::new(public_key, verifying_key);

        let name_hash = &announce_data[offset..(offset + NAME_HASH_LENGTH)];
        offset += NAME_HASH_LENGTH;
        let rand_hash = &announce_data[offset..(offset + RAND_HASH_LENGTH)];
        offset += RAND_HASH_LENGTH;

        let ratchet = if packet.header.context_flag == ContextFlag::Set {
            if announce_data.len() < MIN_ANNOUNCE_DATA_LENGTH + PUBLIC_KEY_LENGTH {
                return Err(RnsError::OutOfMemory);
            }

            let ratchet = &announce_data[offset..(offset + PUBLIC_KEY_LENGTH)];
            offset += PUBLIC_KEY_LENGTH;
            ratchet
        } else {
            &[]
        };

        let signature = &announce_data[offset..(offset + SIGNATURE_LENGTH)];
        offset += SIGNATURE_LENGTH;
        let app_data = &announce_data[offset..];

        let destination = &packet.destination;
        let expected_destination = AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update(name_hash)
                .chain_update(identity.address_hash.as_slice())
                .finalize()
                .into(),
        ));

        if *destination != expected_destination {
            return Err(RnsError::IncorrectHash);
        }

        // Keeping signed data on stack is only option for now.
        // Verification function doesn't support prehashed message.
        let signed_data = PacketDataBuffer::new()
            .chain_write(destination.as_slice())?
            .chain_write(public_key.as_bytes())?
            .chain_write(verifying_key.as_bytes())?
            .chain_write(name_hash)?
            .chain_write(rand_hash)?
            .chain_write(ratchet)?
            .chain_write(app_data)?
            .finalize();

        let signature = Signature::from_slice(signature).map_err(|_| RnsError::CryptoError)?;

        identity.verify(signed_data.as_slice(), &signature)?;

        Ok((
            SingleOutputDestination::new(identity, DestinationName::new_from_hash_slice(name_hash)),
            app_data,
        ))
    }
}

pub struct Destination<I: HashIdentity, D: Direction, T: Type> {
    pub direction: PhantomData<D>,
    pub r#type: PhantomData<T>,
    pub identity: I,
    pub desc: DestinationDesc,
    accept_link_requests: bool,
    prove_packets: bool,
}

impl<I: HashIdentity, D: Direction, T: Type> Destination<I, D, T> {
    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::destination_type()
    }
}

// impl<I: DecryptIdentity + HashIdentity, T: Type> Destination<I, Input, T> {
//     pub fn decrypt<'b, R: CryptoRngCore + Copy>(
//         &self,
//         rng: R,
//         data: &[u8],
//         out_buf: &'b mut [u8],
//     ) -> Result<&'b [u8], RnsError> {
//         self.identity.decrypt(rng, data, out_buf)
//     }
// }

// impl<I: EncryptIdentity + HashIdentity, D: Direction, T: Type> Destination<I, D, T> {
//     pub fn encrypt<'b, R: CryptoRngCore + Copy>(
//         &self,
//         rng: R,
//         text: &[u8],
//         out_buf: &'b mut [u8],
//     ) -> Result<&'b [u8], RnsError> {
//         // self.identity.encrypt(
//         //     rng,
//         //     text,
//         //     Some(self.identity.as_address_hash_slice()),
//         //     out_buf,
//         // )
//     }
// }

pub enum DestinationHandleStatus {
    None,
    LinkProof,
}

impl Destination<PrivateIdentity, Input, Single> {
    fn build_announce_packet_data(
        &self,
        rand_hash: &[u8],
        app_data: Option<&[u8]>,
    ) -> Result<PacketDataBuffer, RnsError> {
        let mut packet_data = PacketDataBuffer::new();
        let pub_key = self.identity.as_identity().public_key_bytes();
        let verifying_key = self.identity.as_identity().verifying_key_bytes();

        packet_data
            .chain_safe_write(self.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash);

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        let signature = self.identity.sign(packet_data.as_slice());

        packet_data.reset();

        packet_data
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash)
            .chain_safe_write(&signature.to_bytes());

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        Ok(packet_data)
    }

    fn build_announce_rand_hash<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        timestamp_secs: u64,
    ) -> [u8; RAND_HASH_LENGTH] {
        let rand_hash = Hash::new_from_rand(rng);
        let timestamp = timestamp_secs.to_be_bytes();
        let rand_hash = [
            &rand_hash.as_slice()[..RAND_HASH_LENGTH / 2],
            &timestamp[3..],
        ]
        .concat();

        rand_hash.try_into().expect("rand hash has fixed length")
    }

    pub fn new(identity: PrivateIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        let pub_identity = identity.as_identity().clone();

        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc: DestinationDesc {
                identity: pub_identity,
                name,
                address_hash,
            },
            accept_link_requests: true,
            prove_packets: false,
        }
    }

    pub fn announce<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let timestamp_secs = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as u64;
        let rand_hash = self.build_announce_rand_hash(rng, timestamp_secs);
        let packet_data = self.build_announce_packet_data(&rand_hash, app_data)?;

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    pub fn path_response<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let mut announce = self.announce(rng, app_data)?;
        announce.context = PacketContext::PathResponse;

        Ok(announce)
    }

    #[cfg(test)]
    fn announce_with_rand_hash(
        &self,
        rand_hash: [u8; RAND_HASH_LENGTH],
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let packet_data = self.build_announce_packet_data(&rand_hash, app_data)?;

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    #[cfg(test)]
    fn announce_with_timestamp<R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        timestamp_secs: u64,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let rand_hash = self.build_announce_rand_hash(rng, timestamp_secs);
        let packet_data = self.build_announce_packet_data(&rand_hash, app_data)?;

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    pub fn handle_packet(&mut self, packet: &Packet) -> DestinationHandleStatus {
        if self.desc.address_hash != packet.destination {
            return DestinationHandleStatus::None;
        }

        match packet.header.packet_type {
            PacketType::LinkRequest => {
                if self.accept_link_requests {
                    return DestinationHandleStatus::LinkProof;
                }
            }
            _ => {}
        }

        DestinationHandleStatus::None
    }

    pub fn set_accept_link_requests(&mut self, accept_link_requests: bool) {
        self.accept_link_requests = accept_link_requests;
    }

    pub fn set_prove_packets(&mut self, prove_packets: bool) {
        self.prove_packets = prove_packets;
    }

    pub fn prove_packets(&self) -> bool {
        self.prove_packets
    }

    pub fn proof_packet(&self, packet_hash: &Hash) -> Packet {
        let signature = self.identity.sign(packet_hash.as_slice());

        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(packet_hash.as_slice());
        packet_data.safe_write(&signature.to_bytes());

        Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: AddressHash::new_from_hash(packet_hash),
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        }
    }

    pub fn sign_key(&self) -> &SigningKey {
        self.identity.sign_key()
    }

    pub fn decrypt<'a>(&self, data: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.identity.decrypt_packet(
            OsRng,
            data,
            Some(self.identity.as_address_hash_slice()),
            out_buf,
        )
    }
}

impl Destination<Identity, Output, Single> {
    pub fn new(identity: Identity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc: DestinationDesc {
                identity,
                name,
                address_hash,
            },
            accept_link_requests: false,
            prove_packets: false,
        }
    }

    pub fn new_from_desc(desc: DestinationDesc) -> Self {
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity: desc.identity,
            desc,
            accept_link_requests: false,
            prove_packets: false,
        }
    }

    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.identity.encrypt_packet(
                OsRng,
                data,
                Some(self.identity.as_address_hash_slice()),
                packet_data.accuire_buf_max(),
            )?;
            cipher_text.len()
        };

        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }
}

impl<D: Direction> Destination<EmptyIdentity, D, Plain> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc: DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
            accept_link_requests: false,
            prove_packets: false,
        }
    }
}

fn create_address_hash<I: HashIdentity>(identity: &I, name: &DestinationName) -> AddressHash {
    AddressHash::new_from_hash(&Hash::new(
        Hash::generator()
            .chain_update(name.as_name_hash_slice())
            .chain_update(identity.as_address_hash_slice())
            .finalize()
            .into(),
    ))
}

pub type SingleInputDestination = Destination<PrivateIdentity, Input, Single>;
pub type SingleOutputDestination = Destination<Identity, Output, Single>;
pub type PlainInputDestination = Destination<EmptyIdentity, Input, Plain>;
pub type PlainOutputDestination = Destination<EmptyIdentity, Output, Plain>;

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
    use rand_core::OsRng;
    use sha2::Digest;

    use crate::buffer::OutputBuffer;
    use crate::hash::{AddressHash, Hash};
    use crate::identity::{PrivateIdentity, PUBLIC_KEY_LENGTH};
    use crate::packet::{ContextFlag, PacketContext, PacketDataBuffer, PacketType};
    use crate::serde::Serialize;
    use crate::test_vectors;

    use super::{DestinationAnnounce, DestinationName, SingleInputDestination, RAND_HASH_LENGTH};

    fn python_announce_rand_hash() -> [u8; RAND_HASH_LENGTH] {
        let timestamp = test_vectors::FIXED_ANNOUNCE_TIMESTAMP.to_be_bytes();
        let mut rand_hash = [0u8; RAND_HASH_LENGTH];
        rand_hash[..RAND_HASH_LENGTH / 2].copy_from_slice(
            &test_vectors::FIXED_ANNOUNCE_RANDOM_HASH_BYTES[..RAND_HASH_LENGTH / 2],
        );
        rand_hash[RAND_HASH_LENGTH / 2..].copy_from_slice(&timestamp[3..]);
        rand_hash
    }

    #[test]
    fn create_announce() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        let single_in_destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "in"));

        let announce_packet = single_in_destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        assert_eq!(
            announce_packet.header.packet_type,
            crate::packet::PacketType::Announce
        );
        assert_eq!(
            announce_packet.destination,
            single_in_destination.desc.address_hash
        );
        assert_eq!(announce_packet.context, crate::packet::PacketContext::None);
        DestinationAnnounce::validate(&announce_packet).expect("announce validates");
    }

    #[test]
    fn create_path_request_hash() {
        let name = DestinationName::new("rnstransport", "path.request");

        assert_eq!(
            name.hash.to_string(),
            "7926bbe7dd7f9aba88b061551600a25d06ef0f7578202730bd2f224200715efe"
        );
        assert_eq!(
            Hash::new_from_slice(name.as_name_hash_slice()).to_string(),
            "6b9f66014d9853faab220fba47d027615ec53a8b35c2d620d1f4e0da65de3008"
        );
    }

    #[test]
    fn create_destination_hash_without_aspects_matches_python() {
        let mut identity_hash_bytes = [0u8; crate::hash::ADDRESS_HASH_SIZE];
        identity_hash_bytes.copy_from_slice(&test_vectors::decode_hex(
            "f9cd9aa2712d27402dcccb26643c520a",
        ));
        let identity_hash = AddressHash::new(identity_hash_bytes);
        let name = DestinationName::new("kallisti5 desktop", "");

        assert_eq!(
            name.hash.to_string(),
            "8bad7554c1eef952c038463e10b382d9f0cd248e14ceb0edb8ce583e5d461ae8"
        );
        let destination_hash = AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update(name.as_name_hash_slice())
                .chain_update(identity_hash.as_slice())
                .finalize()
                .into(),
        ));
        assert_eq!(
            destination_hash.to_string(),
            "/a03387d93d7059f3ef2f8306a13e043c/"
        );
    }

    #[test]
    fn compare_announce() {
        let priv_identity = test_vectors::fixed_private_identity();

        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        assert_eq!(
            destination.desc.address_hash.to_string(),
            "/2419dca3c93718497b91990373df1503/"
        );
        assert_eq!(
            destination.desc.name.hash.to_string(),
            "6f233dfd9aa4cbd4a1e26592edf0627d9ad547d147c9f077d9fd1ce838aa46ee"
        );

        let announce = destination
            .announce_with_rand_hash(python_announce_rand_hash(), None)
            .expect("valid announce packet");

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);

        announce.serialize(&mut buffer).expect("correct data");

        assert_eq!(announce.header.packet_type, PacketType::Announce);
        assert_eq!(
            buffer.as_slice(),
            test_vectors::decode_hex(test_vectors::ANNOUNCE_PACKET_HEX)
        );
        DestinationAnnounce::validate(&announce).expect("announce validates");
    }

    #[test]
    fn validate_rejects_announce_with_wrong_destination_hash() {
        let priv_identity = test_vectors::fixed_private_identity();

        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let mut announce = destination
            .announce_with_rand_hash(python_announce_rand_hash(), None)
            .expect("valid announce packet");
        announce.destination = AddressHash::new_from_slice(b"not the announced destination");

        assert!(matches!(
            DestinationAnnounce::validate(&announce),
            Err(crate::error::RnsError::IncorrectHash)
        ));
    }

    #[test]
    fn compare_path_response() {
        let priv_identity = test_vectors::fixed_private_identity();
        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let announce = destination
            .announce_with_rand_hash(python_announce_rand_hash(), None)
            .expect("valid announce packet");
        let mut path_response = announce.clone();
        path_response.context = PacketContext::PathResponse;

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);
        path_response.serialize(&mut buffer).expect("correct data");

        assert_eq!(
            buffer.as_slice(),
            test_vectors::decode_hex(test_vectors::PATH_RESPONSE_PACKET_HEX)
        );
        DestinationAnnounce::validate(&path_response).expect("path response validates");
    }

    #[test]
    fn validate_ratchet_announce() {
        let priv_identity = test_vectors::fixed_private_identity();
        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let rand_hash = python_announce_rand_hash();
        let ratchet = [0x42u8; PUBLIC_KEY_LENGTH];
        let app_data = b"ratchet announce";
        let pub_key = destination.identity.as_identity().public_key_bytes();
        let verifying_key = destination.identity.as_identity().verifying_key_bytes();

        let mut signed_data = PacketDataBuffer::new();
        signed_data
            .chain_safe_write(destination.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(destination.desc.name.as_name_hash_slice())
            .chain_safe_write(&rand_hash)
            .chain_safe_write(&ratchet)
            .chain_safe_write(app_data);

        let signature = destination.identity.sign(signed_data.as_slice());

        let mut announce = destination
            .announce_with_rand_hash(rand_hash, Some(app_data))
            .expect("valid announce packet");
        let mut packet_data = PacketDataBuffer::new();
        packet_data
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(destination.desc.name.as_name_hash_slice())
            .chain_safe_write(&rand_hash)
            .chain_safe_write(&ratchet)
            .chain_safe_write(&signature.to_bytes())
            .chain_safe_write(app_data);

        announce.header.context_flag = ContextFlag::Set;
        announce.data = packet_data;

        DestinationAnnounce::validate(&announce).expect("ratchet announce validates");
    }

    #[test]
    fn check_announce() {
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);

        let destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        DestinationAnnounce::validate(&announce).expect("valid announce");
    }

    #[test]
    fn create_explicit_packet_proof() {
        let identity = test_vectors::fixed_private_identity();
        let destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );
        let packet_hash = Hash::new_from_slice(b"probe packet");
        let proof = destination.proof_packet(&packet_hash);

        assert_eq!(proof.destination, packet_hash.into());
        assert_eq!(proof.header.packet_type, crate::packet::PacketType::Proof);
        assert_eq!(proof.data.len(), crate::hash::HASH_SIZE + SIGNATURE_LENGTH);
        assert_eq!(
            &proof.data.as_slice()[..crate::hash::HASH_SIZE],
            packet_hash.as_slice()
        );

        let signature = Signature::from_slice(&proof.data.as_slice()[crate::hash::HASH_SIZE..])
            .expect("valid signature");

        destination
            .desc
            .identity
            .verify(packet_hash.as_slice(), &signature)
            .expect("signature validates");

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);
        proof.serialize(&mut buffer).expect("serialized proof");
        assert_eq!(
            buffer.as_slice(),
            test_vectors::decode_hex(test_vectors::EXPLICIT_PACKET_PROOF_HEX)
        );
    }

    #[test]
    fn single_packet_roundtrip() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let input_destination = SingleInputDestination::new(
            identity,
            DestinationName::new("example_utilities", "single.roundtrip"),
        );
        let output_destination =
            super::SingleOutputDestination::new_from_desc(input_destination.desc);

        let payload = b"hello over single destination";
        let packet = output_destination
            .data_packet(payload)
            .expect("encrypted single packet");

        assert_ne!(packet.data.as_slice(), payload);

        let mut plain_text = [0u8; crate::packet::PACKET_MDU];
        let decrypted = input_destination
            .decrypt(packet.data.as_slice(), &mut plain_text)
            .expect("decrypted single packet");

        assert_eq!(decrypted, payload);
    }
}
