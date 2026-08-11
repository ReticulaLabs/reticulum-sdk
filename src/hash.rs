use core::cmp;
use core::fmt;

use crypto_common::OutputSizeUser;
use crypto_common::typenum::Unsigned;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};

use crate::error::RnsError;

pub const HASH_SIZE: usize = <<Sha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
pub const ADDRESS_HASH_SIZE: usize = 16;

pub fn create_hash(data: &[u8], out: &mut [u8]) {
    out.copy_from_slice(
        &Sha256::new().chain_update(data).finalize().as_slice()[..cmp::min(out.len(), HASH_SIZE)],
    );
}

/// Encode `data` as a lowercase hex string.
pub(crate) fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode the first `N` bytes of a hex string. Accepts upper- and lowercase
/// hex digits, and returns `RnsError::IncorrectHash` instead of panicking on
/// malformed input.
pub(crate) fn hex_decode<const N: usize>(hex: &[u8]) -> Result<[u8; N], RnsError> {
    if hex.len() < N * 2 {
        return Err(RnsError::IncorrectHash);
    }

    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_digit(hex[i * 2]).ok_or(RnsError::IncorrectHash)?;
        let lo = hex_digit(hex[i * 2 + 1]).ok_or(RnsError::IncorrectHash)?;
        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash([u8; HASH_SIZE]);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub struct AddressHash([u8; ADDRESS_HASH_SIZE]);

impl Hash {
    pub fn generator() -> Sha256 {
        Sha256::new()
    }

    pub const fn new(hash: [u8; HASH_SIZE]) -> Self {
        Self { 0: hash }
    }

    pub const fn new_empty() -> Self {
        Self {
            0: [0u8; HASH_SIZE],
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }

    pub fn new_from_rand<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        let mut data = [0u8; HASH_SIZE];

        rng.fill_bytes(&mut data[..]);

        create_hash(&data, &mut hash);
        Self { 0: hash }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AddressHash {
    pub const fn new(hash: [u8; ADDRESS_HASH_SIZE]) -> Self {
        Self { 0: hash }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; ADDRESS_HASH_SIZE];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }

    pub fn new_from_hash(hash: &Hash) -> Self {
        let mut address_hash = [0u8; ADDRESS_HASH_SIZE];
        address_hash.copy_from_slice(&hash.0[0..ADDRESS_HASH_SIZE]);
        Self { 0: address_hash }
    }

    pub fn new_from_rand<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new_from_hash(&Hash::new_from_rand(rng))
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        let bytes = hex_decode(hex_string.as_bytes())?;
        Ok(Self { 0: bytes })
    }

    pub const fn new_empty() -> Self {
        Self {
            0: [0u8; ADDRESS_HASH_SIZE],
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub fn to_hex_string(&self) -> String {
        hex_encode(&self.0)
    }
}

impl From<Hash> for AddressHash {
    fn from(hash: Hash) -> Self {
        Self::new_from_hash(&hash)
    }
}

impl fmt::Display for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/")?;
        for data in self.0.iter() {
            write!(f, "{:0>2x}", data)?;
        }
        write!(f, "/")?;

        Ok(())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for data in self.0.iter() {
            write!(f, "{:0>2x}", data)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use rand_core::UnwrapErr;
    use getrandom::SysRng;

    use crate::hash::AddressHash;

    #[test]
    fn address_hex_string() {
        let mut rng = UnwrapErr(SysRng);
        let original_address_hash = AddressHash::new_from_rand(&mut rng);

        let address_hash_hex = original_address_hash.to_hex_string();

        let actual_address_hash =
            AddressHash::new_from_hex_string(&address_hash_hex).expect("valid hash");

        assert_eq!(
            actual_address_hash.as_slice(),
            original_address_hash.as_slice()
        );
    }

    #[test]
    fn address_hex_decode_rejects_malformed_input() {
        let hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(
            AddressHash::new_from_hex_string(hex).is_err(),
            "non-hex characters must return an error, not panic"
        );
    }

    #[test]
    fn address_hex_decode_accepts_uppercase() {
        let mut rng = UnwrapErr(SysRng);
        let original_address_hash = AddressHash::new_from_rand(&mut rng);
        let upper = original_address_hash.to_hex_string().to_uppercase();

        let actual_address_hash =
            AddressHash::new_from_hex_string(&upper).expect("valid hash");

        assert_eq!(
            actual_address_hash.as_slice(),
            original_address_hash.as_slice()
        );
    }
}
