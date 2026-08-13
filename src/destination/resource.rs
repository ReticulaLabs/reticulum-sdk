use core::time::Duration;
use std::collections::VecDeque;
use std::io::{Read, Write};

use getrandom::SysRng;
use rand_core::{Rng, UnwrapErr};
use sha2::{Digest, Sha256};

use rmpv::{Value, decode::read_value, encode::write_value};

use crate::{
    error::RnsError,
    hash::{HASH_SIZE, Hash},
    packet::{RETICULUM_AES_BLOCK_SIZE, RETICULUM_TOKEN_OVERHEAD},
};

// ============================================================================
// Constants (matching Python RNS.Resource exactly)
// ============================================================================

pub const WINDOW: usize = 4;
pub const WINDOW_MIN: usize = 2;
pub const WINDOW_MAX_SLOW: usize = 10;
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
pub const WINDOW_MAX_FAST: usize = 75;
pub const WINDOW_MAX: usize = WINDOW_MAX_FAST;
pub const FAST_RATE_THRESHOLD: usize = WINDOW_MAX_SLOW - WINDOW - 2;
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
pub const RATE_FAST: f64 = (50.0 * 1000.0) / 8.0;
pub const RATE_VERY_SLOW: f64 = (2.0 * 1000.0) / 8.0;
pub const WINDOW_FLEXIBILITY: usize = 4;
pub const MAPHASH_LEN: usize = 4;
pub const RANDOM_HASH_SIZE: usize = 4;
pub const MAX_EFFICIENT_SIZE: usize = 1 * 1024 * 1024 - 1;
pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;
pub const METADATA_MAX_SIZE: usize = 16 * 1024 * 1024 - 1;
pub const AUTO_COMPRESS_MAX_SIZE: usize = 64 * 1024 * 1024;
pub const PART_TIMEOUT_FACTOR: f64 = 4.0;
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;
pub const PROOF_TIMEOUT_FACTOR: f64 = 3.0;
pub const HMU_WAIT_FACTOR: f64 = 3.5;
pub const MAX_RETRIES: usize = 16;
pub const MAX_ADV_RETRIES: usize = 4;
pub const SENDER_GRACE_TIME: f64 = 10.0;
pub const PROCESSING_GRACE: f64 = 1.0;
pub const RETRY_GRACE_TIME: f64 = 0.25;
pub const PER_RETRY_DELAY: f64 = 0.5;
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

/// Compress with bz2 at level 9 (matching Python `bz2.compress`, whose
/// default level is also 9).
fn bzip2_compress(data: &[u8]) -> Result<Vec<u8>, RnsError> {
    use bzip2::{Compression, write::BzEncoder};

    let mut encoder = BzEncoder::new(Vec::new(), Compression::new(9));
    encoder
        .write_all(data)
        .and_then(|()| encoder.finish())
        .map_err(|_| RnsError::PacketError)
}

/// Decompress a bz2 stream into a `Vec`, rejecting output larger than
/// `limit`. Mirrors Python's `bz2.BZ2Decompressor(max_length=...)` + eof
/// check, which caps the decompressed size of inbound resources.
fn bzip2_decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, RnsError> {
    use bzip2::read::BzDecoder;

    let decoder = BzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| RnsError::PacketError)?;
    if out.len() > limit {
        return Err(RnsError::PacketError);
    }
    Ok(out)
}

// ============================================================================
// ResourceStatus
// ============================================================================

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ResourceStatus {
    None = 0x00,
    Queued = 0x01,
    Advertised = 0x02,
    Transferring = 0x03,
    AwaitingProof = 0x04,
    Assembling = 0x05,
    Complete = 0x06,
    Failed = 0x07,
    Corrupt = 0x08,
}

impl ResourceStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => ResourceStatus::None,
            0x01 => ResourceStatus::Queued,
            0x02 => ResourceStatus::Advertised,
            0x03 => ResourceStatus::Transferring,
            0x04 => ResourceStatus::AwaitingProof,
            0x05 => ResourceStatus::Assembling,
            0x06 => ResourceStatus::Complete,
            0x07 => ResourceStatus::Failed,
            0x08 => ResourceStatus::Corrupt,
            _ => ResourceStatus::Failed,
        }
    }
}

// ============================================================================
// ResourceAdvertisement
// ============================================================================

pub const ADV_OVERHEAD: usize = 134;

/// Maximum number of hashmap entries per advertisement segment.
pub fn hashmap_max_len(link_mdu: usize) -> usize {
    link_mdu.saturating_sub(ADV_OVERHEAD) / MAPHASH_LEN
}

pub fn collision_guard_size(link_mdu: usize) -> usize {
    2 * WINDOW_MAX + hashmap_max_len(link_mdu)
}

/// Wire-format compatible with Python `RNS.ResourceAdvertisement`.
#[derive(Debug, Clone)]
pub struct ResourceAdvertisement {
    pub transfer_size: usize,
    pub data_size: usize,
    pub num_parts: usize,
    pub hash: Hash,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    pub original_hash: Hash,
    pub hashmap: Vec<u8>,
    pub flags: u8,
    pub segment_index: usize,
    pub total_segments: usize,
    /// ID of the associated request, as raw bytes. The Python reference uses
    /// a 16-byte truncated hash here; the exact bytes must be preserved so
    /// that peers can correlate the resource with its pending request.
    pub request_id: Option<Vec<u8>>,
}

impl ResourceAdvertisement {
    pub fn from_resource(resource: &Resource) -> Self {
        let compressed = resource.compressed;
        let encrypted = resource.encrypted;
        let has_metadata = resource.has_metadata;
        let is_request = resource.request_id.is_some() && !resource.is_response;
        let is_response = resource.request_id.is_some() && resource.is_response;

        let mut flags: u8 = 0x00;
        if encrypted {
            flags |= 0x01;
        }
        if compressed {
            flags |= 0x02;
        }
        if resource.split {
            flags |= 0x04;
        }
        if is_request {
            flags |= 0x08;
        }
        if is_response {
            flags |= 0x10;
        }
        if has_metadata {
            flags |= 0x20;
        }

        ResourceAdvertisement {
            transfer_size: resource.size,
            data_size: resource.total_size,
            num_parts: resource.total_parts,
            hash: resource.hash,
            random_hash: resource.random_hash,
            original_hash: resource.original_hash,
            hashmap: resource.hashmap.clone(),
            flags,
            segment_index: resource.segment_index,
            total_segments: resource.total_segments,
            request_id: resource.request_id.clone(),
        }
    }

    pub fn pack(&self, segment: usize, link_mdu: usize) -> Result<Vec<u8>, RnsError> {
        let hml = hashmap_max_len(link_mdu);
        let hashmap_start = segment * hml;
        let hashmap_end = core::cmp::min((segment + 1) * hml, self.num_parts);

        let mut hashmap_seg = Vec::new();
        for i in hashmap_start..hashmap_end {
            let pos = i * MAPHASH_LEN;
            if pos + MAPHASH_LEN <= self.hashmap.len() {
                hashmap_seg.extend_from_slice(&self.hashmap[pos..pos + MAPHASH_LEN]);
            }
        }

        let mut dict = Vec::new();
        dict.push((Value::from("t"), Value::from(self.transfer_size as i64)));
        dict.push((Value::from("d"), Value::from(self.data_size as i64)));
        dict.push((Value::from("n"), Value::from(self.num_parts as i64)));
        dict.push((
            Value::from("h"),
            Value::Binary(self.hash.to_bytes().to_vec()),
        ));
        dict.push((Value::from("r"), Value::Binary(self.random_hash.to_vec())));
        dict.push((
            Value::from("o"),
            Value::Binary(self.original_hash.to_bytes().to_vec()),
        ));
        dict.push((Value::from("i"), Value::from(self.segment_index as i64)));
        dict.push((Value::from("l"), Value::from(self.total_segments as i64)));
        dict.push((Value::from("f"), Value::from(self.flags as i64)));
        dict.push((Value::from("m"), Value::Binary(hashmap_seg)));
        dict.push((
            Value::from("q"),
            self.request_id
                .as_ref()
                .map(|id| Value::Binary(id.clone()))
                .unwrap_or(Value::Nil),
        ));

        let map = Value::Map(dict);
        let mut out = Vec::new();
        write_value(&mut out, &map).map_err(|_| RnsError::InvalidArgument)?;
        Ok(out)
    }

    pub fn unpack(data: &[u8]) -> Result<Self, RnsError> {
        let value = read_value(&mut &data[..]).map_err(|_| RnsError::PacketError)?;
        let dict = value.as_map().ok_or(RnsError::PacketError)?;

        let mut adv = ResourceAdvertisement {
            transfer_size: 0,
            data_size: 0,
            num_parts: 0,
            hash: Hash::new_empty(),
            random_hash: [0u8; RANDOM_HASH_SIZE],
            original_hash: Hash::new_empty(),
            hashmap: Vec::new(),
            flags: 0,
            segment_index: 0,
            total_segments: 0,
            request_id: None,
        };

        for (key, val) in dict {
            let key_str = key.as_str().unwrap_or("");
            match key_str {
                "t" => adv.transfer_size = val.as_i64().unwrap_or(0) as usize,
                "d" => adv.data_size = val.as_i64().unwrap_or(0) as usize,
                "n" => adv.num_parts = val.as_i64().unwrap_or(0) as usize,
                "h" => {
                    if let Some(bytes) = val.as_slice() {
                        let mut h = [0u8; HASH_SIZE];
                        let n = core::cmp::min(bytes.len(), HASH_SIZE);
                        h[..n].copy_from_slice(&bytes[..n]);
                        adv.hash = Hash::new(h);
                    }
                }
                "r" => {
                    if let Some(bytes) = val.as_slice() {
                        let n = core::cmp::min(bytes.len(), RANDOM_HASH_SIZE);
                        adv.random_hash[..n].copy_from_slice(&bytes[..n]);
                    }
                }
                "o" => {
                    if let Some(bytes) = val.as_slice() {
                        let mut h = [0u8; HASH_SIZE];
                        let n = core::cmp::min(bytes.len(), HASH_SIZE);
                        h[..n].copy_from_slice(&bytes[..n]);
                        adv.original_hash = Hash::new(h);
                    }
                }
                "i" => adv.segment_index = val.as_i64().unwrap_or(0) as usize,
                "l" => adv.total_segments = val.as_i64().unwrap_or(0) as usize,
                "f" => adv.flags = val.as_i64().unwrap_or(0) as u8,
                "m" => {
                    if let Some(bytes) = val.as_slice() {
                        adv.hashmap = bytes.to_vec();
                    }
                }
                "q" => {
                    if let Some(bytes) = val.as_slice() {
                        if !bytes.is_empty() {
                            adv.request_id = Some(bytes.to_vec());
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(adv)
    }
}

// ============================================================================
// ResourcePart (sender side)
// ============================================================================

struct ResourcePart {
    data: Vec<u8>,
    map_hash: [u8; MAPHASH_LEN],
    sent: bool,
}

// ============================================================================
// Resource
// ============================================================================

#[allow(dead_code)]
pub struct Resource {
    // Identity
    hash: Hash,
    random_hash: [u8; RANDOM_HASH_SIZE],
    original_hash: Hash,
    expected_proof: [u8; HASH_SIZE],

    // Status
    status: ResourceStatus,

    // Data sizes
    size: usize,
    total_size: usize,
    uncompressed_size: usize,
    compressed: bool,
    encrypted: bool,
    has_metadata: bool,

    // Segmentation
    segment_index: usize,
    total_segments: usize,
    split: bool,

    // Parts and hashmap
    sdu: usize,
    total_parts: usize,
    parts: Vec<ResourcePart>,
    hashmap: Vec<u8>,
    hashmap_height: usize,

    // Sender state
    sent_parts: usize,
    receiver_min_consecutive_height: usize,

    // Receiver state
    received_parts: Vec<Option<Vec<u8>>>,
    received_count: usize,
    outstanding_parts: usize,
    consecutive_completed_height: isize,
    waiting_for_hmu: bool,
    receiving_part: bool,
    assembly_lock: bool,

    // Window management
    window: usize,
    window_max: usize,
    window_min: usize,
    window_flexibility: usize,
    fast_rate_rounds: usize,
    very_slow_rate_rounds: usize,

    // Timing
    last_activity: std::time::Instant,
    rtt: Option<Duration>,
    part_timeout_factor: f64,
    retries_left: usize,
    max_retries: usize,
    max_adv_retries: usize,
    adv_sent: Option<std::time::Instant>,

    // RTT tracking
    rtt_rxd_bytes: usize,
    req_sent: Option<std::time::Instant>,
    req_sent_bytes: usize,
    req_resp: Option<std::time::Instant>,
    req_resp_rtt_rate: f64,
    rtt_rxd_bytes_at_part_req: usize,
    req_data_rtt_rate: f64,
    eifr: Option<f64>,
    previous_eifr: Option<f64>,
    last_part_sent: Option<std::time::Instant>,

    // Request linking
    pub request_id: Option<Vec<u8>>,
    pub is_response: bool,

    // Dedup
    req_hashlist: VecDeque<Hash>,

    // Original plaintext data (for hash/proof computation)
    original_plaintext: Vec<u8>,
    // Assembled plaintext (set during assemble, used for proof)
    assembled_plaintext: Vec<u8>,
}

impl Resource {
    /// Build an outgoing resource from plaintext data.
    ///
    /// The data is bz2-compressed at level 9 when `auto_compress` is enabled,
    /// the payload fits within `AUTO_COMPRESS_MAX_SIZE` and compression
    /// actually shrinks it (matching the Python reference). The resource hash
    /// and proof are always computed over the original plaintext. The caller
    /// supplies `encrypt`, which wraps the assembled payload for transmission.
    pub fn new(
        data: &[u8],
        link_mdu: usize,
        encrypt: impl FnOnce(&[u8], &mut Vec<u8>) -> Result<usize, RnsError>,
        request_id: Option<Vec<u8>>,
        is_response: bool,
        auto_compress: bool,
    ) -> Result<Self, RnsError> {
        let original_plaintext = data.to_vec();
        let total_size = data.len();
        let sdu = link_mdu;

        // bz2-compress the payload when auto-compression is enabled and the
        // compressed form is smaller (matching the Python reference). The
        // resource hash and proof are still computed over the *original*
        // plaintext, so the receiver can verify after decompressing.
        let (payload, compressed) = if auto_compress && data.len() <= AUTO_COMPRESS_MAX_SIZE {
            let compressed_data = bzip2_compress(data)?;
            if compressed_data.len() < data.len() {
                (compressed_data, true)
            } else {
                (data.to_vec(), false)
            }
        } else {
            (data.to_vec(), false)
        };

        // Generate random hash (used for map hash computation, matching Python)
        let random_hash: [u8; RANDOM_HASH_SIZE] = {
            let mut buf = [0u8; RANDOM_HASH_SIZE];
            let mut rng = UnwrapErr(SysRng);
            rng.fill_bytes(&mut buf);
            buf
        };

        // Build plaintext blob: inline_random_hash(4) + payload
        // (the inline random hash is separate from self.random_hash)
        let mut plaintext_blob = Vec::with_capacity(RANDOM_HASH_SIZE + payload.len());
        let mut inline_random = [0u8; RANDOM_HASH_SIZE];
        let mut rng = UnwrapErr(SysRng);
        rng.fill_bytes(&mut inline_random);
        plaintext_blob.extend_from_slice(&inline_random);
        plaintext_blob.extend_from_slice(&payload);

        // Encrypt the entire blob
        let mut encrypted_buf = Vec::with_capacity(
            plaintext_blob.len() + RETICULUM_TOKEN_OVERHEAD + RETICULUM_AES_BLOCK_SIZE,
        );
        encrypted_buf.resize(
            plaintext_blob.len() + RETICULUM_TOKEN_OVERHEAD + RETICULUM_AES_BLOCK_SIZE,
            0,
        );
        let encrypted_len = encrypt(&plaintext_blob, &mut encrypted_buf)?;
        encrypted_buf.truncate(encrypted_len);

        let encrypted = true;
        let size = encrypted_buf.len();
        let total_parts = size.div_ceil(sdu);

        // Compute resource hash: SHA-256(original_plaintext || random_hash)
        // This matches Python: full_hash(data+self.random_hash) where data is
        // the plaintext payload (before inline_random_hash prepend and encryption)
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.update(&random_hash);
            Hash::new(hasher.finalize().into())
        };

        let original_hash = hash;
        let mut hashmap_ok = false;
        let mut parts: Vec<ResourcePart> = Vec::with_capacity(total_parts);
        let mut hashmap = Vec::with_capacity(total_parts * MAPHASH_LEN);
        let mut random_hash_value = random_hash;
        let cgs = collision_guard_size(link_mdu);

        while !hashmap_ok {
            parts.clear();
            hashmap.clear();
            hashmap_ok = true;
            let mut collision_guard: Vec<[u8; MAPHASH_LEN]> = Vec::new();

            for i in 0..total_parts {
                let start = i * sdu;
                let end = core::cmp::min(start + sdu, size);
                let part_data = &encrypted_buf[start..end];

                let map_hash = {
                    let mut h = Sha256::new();
                    h.update(part_data);
                    h.update(&random_hash_value);
                    let result = h.finalize();
                    let mut mh = [0u8; MAPHASH_LEN];
                    mh.copy_from_slice(&result[..MAPHASH_LEN]);
                    mh
                };

                if collision_guard.contains(&map_hash) {
                    // Collision - regenerate random hash and retry
                    let mut rng = UnwrapErr(SysRng);
                    rng.fill_bytes(&mut random_hash_value);
                    hashmap_ok = false;
                    break;
                }

                collision_guard.push(map_hash);
                if collision_guard.len() > cgs {
                    collision_guard.remove(0);
                }

                hashmap.extend_from_slice(&map_hash);
                parts.push(ResourcePart {
                    data: part_data.to_vec(),
                    map_hash,
                    sent: false,
                });
            }
        }

        // Recompute hash with final random_hash if it changed
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.update(&random_hash_value);

            Hash::new(hasher.finalize().into())
        };

        // Compute expected proof after final hash is known
        let expected_proof = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.update(hash.as_slice());
            let result = hasher.finalize();
            let mut proof = [0u8; HASH_SIZE];
            proof.copy_from_slice(&result);
            proof
        };

        let now = std::time::Instant::now();

        Ok(Resource {
            hash,
            random_hash: random_hash_value,
            original_hash,
            expected_proof,
            status: ResourceStatus::None,
            size,
            total_size,
            uncompressed_size: total_size,
            compressed,
            encrypted,
            has_metadata: false,
            segment_index: 1,
            total_segments: 1,
            split: false,
            sdu,
            total_parts,
            parts,
            hashmap,
            hashmap_height: total_parts,
            sent_parts: 0,
            receiver_min_consecutive_height: 0,
            received_parts: Vec::new(),
            received_count: 0,
            outstanding_parts: 0,
            consecutive_completed_height: -1,
            waiting_for_hmu: false,
            receiving_part: false,
            assembly_lock: false,
            window: WINDOW,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            last_activity: now,
            rtt: None,
            part_timeout_factor: PART_TIMEOUT_FACTOR,
            retries_left: MAX_RETRIES,
            max_retries: MAX_RETRIES,
            max_adv_retries: MAX_ADV_RETRIES,
            adv_sent: None,
            rtt_rxd_bytes: 0,
            req_sent: None,
            req_sent_bytes: 0,
            req_resp: None,
            req_resp_rtt_rate: 0.0,
            rtt_rxd_bytes_at_part_req: 0,
            req_data_rtt_rate: 0.0,
            eifr: None,
            previous_eifr: None,
            last_part_sent: None,
            request_id,
            is_response,
            req_hashlist: VecDeque::new(),
            original_plaintext,
            assembled_plaintext: Vec::new(),
        })
    }

    pub fn new_from_advertisement(
        adv: &ResourceAdvertisement,
        link_mdu: usize,
        rtt: Duration,
        request_id: Option<Vec<u8>>,
    ) -> Result<Self, RnsError> {
        let sdu = link_mdu;
        let total_parts = adv.num_parts;
        let encrypted = (adv.flags & 0x01) != 0;
        let compressed = (adv.flags & 0x02) != 0;
        let split = (adv.flags & 0x04) != 0;
        let _is_request_flag = (adv.flags & 0x08) != 0;
        let is_response_flag = (adv.flags & 0x10) != 0;
        let has_metadata = (adv.flags & 0x20) != 0;

        let now = std::time::Instant::now();

        Ok(Resource {
            hash: adv.hash,
            random_hash: adv.random_hash,
            original_hash: adv.original_hash,
            expected_proof: [0u8; HASH_SIZE],
            status: ResourceStatus::None,
            size: adv.transfer_size,
            total_size: adv.data_size,
            uncompressed_size: adv.data_size,
            compressed,
            encrypted,
            has_metadata,
            segment_index: adv.segment_index,
            total_segments: adv.total_segments,
            split,
            sdu,
            total_parts,
            parts: Vec::new(),
            hashmap: vec![0u8; total_parts * MAPHASH_LEN],
            hashmap_height: 0,
            sent_parts: 0,
            receiver_min_consecutive_height: 0,
            received_parts: vec![None; total_parts],
            received_count: 0,
            outstanding_parts: 0,
            consecutive_completed_height: -1,
            waiting_for_hmu: false,
            receiving_part: false,
            assembly_lock: false,
            window: WINDOW,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            last_activity: now,
            rtt: Some(rtt),
            part_timeout_factor: PART_TIMEOUT_FACTOR,
            retries_left: MAX_RETRIES,
            max_retries: MAX_RETRIES,
            max_adv_retries: MAX_ADV_RETRIES,
            adv_sent: None,
            rtt_rxd_bytes: 0,
            req_sent: None,
            req_sent_bytes: 0,
            req_resp: None,
            req_resp_rtt_rate: 0.0,
            rtt_rxd_bytes_at_part_req: 0,
            req_data_rtt_rate: 0.0,
            eifr: None,
            previous_eifr: None,
            last_part_sent: None,
            request_id,
            is_response: is_response_flag,
            req_hashlist: VecDeque::new(),
            original_plaintext: Vec::new(),
            assembled_plaintext: Vec::new(),
        })
    }

    /// Start receiving: set status, apply initial hashmap, return first part request.
    ///
    /// `initial_hashmap` is the hashmap data from the resource advertisement.
    pub fn start_receive(&mut self, initial_hashmap: &[u8]) -> Result<Vec<u8>, RnsError> {
        self.status = ResourceStatus::Transferring;
        self.last_activity = std::time::Instant::now();
        self.apply_hashmap(0, initial_hashmap)?;
        self.build_request()
    }

    pub fn apply_hashmap(&mut self, segment: usize, hashmap_data: &[u8]) -> Result<(), RnsError> {
        let hml = hashmap_max_len(self.sdu);
        if hml == 0 {
            return Err(RnsError::OutOfMemory);
        }
        let num_hashes = hashmap_data.len() / MAPHASH_LEN;
        for i in 0..num_hashes {
            let idx = i + segment * hml;
            if idx < self.total_parts {
                let start = i * MAPHASH_LEN;
                let end = start + MAPHASH_LEN;
                let slice = &hashmap_data[start..end];
                let pos = idx * MAPHASH_LEN;
                if self.hashmap[pos..pos + MAPHASH_LEN].iter().all(|&b| b == 0) {
                    self.hashmap_height += 1;
                }
                self.hashmap[pos..pos + MAPHASH_LEN].copy_from_slice(slice);
            }
        }
        self.waiting_for_hmu = false;
        Ok(())
    }

    /// Build a part request for the next window of missing parts.
    pub fn build_request(&mut self) -> Result<Vec<u8>, RnsError> {
        if self.waiting_for_hmu {
            return Err(RnsError::InvalidArgument);
        }
        self.outstanding_parts = 0;
        let mut hashmap_exhausted = HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes = Vec::new();

        let search_start = (self.consecutive_completed_height + 1) as usize;
        let search_end = core::cmp::min(search_start + self.window, self.total_parts);

        let mut count = 0;
        for pn in search_start..search_end {
            if self.received_parts[pn].is_none() {
                let pos = pn * MAPHASH_LEN;
                let part_hash = &self.hashmap[pos..pos + MAPHASH_LEN];
                if part_hash.iter().any(|&b| b != 0) {
                    requested_hashes.extend_from_slice(part_hash);
                    self.outstanding_parts += 1;
                    count += 1;
                } else {
                    hashmap_exhausted = HASHMAP_IS_EXHAUSTED;
                }
            }
            if count >= self.window || hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
                break;
            }
        }

        let mut request_data = Vec::new();
        request_data.push(hashmap_exhausted);
        if hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
            if self.hashmap_height > 0 {
                let last_pos = (self.hashmap_height - 1) * MAPHASH_LEN;
                request_data.extend_from_slice(&self.hashmap[last_pos..last_pos + MAPHASH_LEN]);
            }
            self.waiting_for_hmu = true;
        }
        request_data.extend_from_slice(self.hash.as_slice());
        request_data.extend_from_slice(&requested_hashes);
        Ok(request_data)
    }

    /// Handle an incoming part (receiver side). Returns true if the part was accepted.
    pub fn receive_part(&mut self, part_data: &[u8]) -> bool {
        self.receiving_part = true;
        self.last_activity = std::time::Instant::now();
        self.retries_left = self.max_retries;

        if self.req_resp.is_none() && self.req_sent.is_some() {
            let now = std::time::Instant::now();
            self.req_resp = Some(now);
            if let Some(req_sent) = self.req_sent {
                let rtt_dur = now.duration_since(req_sent);
                let rtt_secs = rtt_dur.as_secs_f64();
                self.part_timeout_factor = PART_TIMEOUT_FACTOR_AFTER_RTT;
                if rtt_secs > 0.0 {
                    let cost = part_data.len() + self.req_sent_bytes;
                    self.req_resp_rtt_rate = cost as f64 / rtt_secs;

                    if self.req_resp_rtt_rate > RATE_FAST
                        && self.fast_rate_rounds < FAST_RATE_THRESHOLD
                    {
                        self.fast_rate_rounds += 1;
                        if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                            self.window_max = WINDOW_MAX_FAST;
                        }
                    }
                }
            }
        }

        if self.status == ResourceStatus::Failed {
            self.receiving_part = false;
            return false;
        }
        self.status = ResourceStatus::Transferring;

        let part_hash = {
            let mut h = Sha256::new();
            h.update(part_data);
            h.update(&self.random_hash);
            let result = h.finalize();
            let mut mh = [0u8; MAPHASH_LEN];
            mh.copy_from_slice(&result[..MAPHASH_LEN]);
            mh
        };

        let search_start = core::cmp::max(0, self.consecutive_completed_height + 1) as usize;
        let search_end = core::cmp::min(search_start + self.window, self.total_parts);

        let mut found = false;
        for i in search_start..search_end {
            let pos = i * MAPHASH_LEN;
            if pos + MAPHASH_LEN <= self.hashmap.len() {
                let stored = &self.hashmap[pos..pos + MAPHASH_LEN];
                if stored == part_hash && self.received_parts[i].is_none() {
                    self.received_parts[i] = Some(part_data.to_vec());
                    self.rtt_rxd_bytes += part_data.len();
                    self.received_count += 1;
                    self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                    if i as isize == self.consecutive_completed_height + 1 {
                        self.consecutive_completed_height = i as isize;
                    }
                    let mut cp = self.consecutive_completed_height + 1;
                    while (cp as usize) < self.total_parts
                        && self.received_parts[cp as usize].is_some()
                    {
                        self.consecutive_completed_height = cp;
                        cp += 1;
                    }

                    // Window increase when outstanding reaches 0
                    if self.outstanding_parts == 0 && self.window < self.window_max {
                        self.window += 1;
                        if self.window - self.window_min > self.window_flexibility - 1 {
                            self.window_min += 1;
                        }
                    }

                    found = true;
                    break;
                }
            }
        }

        self.receiving_part = false;
        found
    }

    pub fn all_parts_received(&self) -> bool {
        self.received_count >= self.total_parts
    }

    /// Assemble received parts, decrypt, verify hash, return original plaintext.
    pub fn assemble(
        &mut self,
        decrypt: impl FnOnce(&[u8], &mut Vec<u8>) -> Result<usize, RnsError>,
    ) -> Result<Vec<u8>, RnsError> {
        self.status = ResourceStatus::Assembling;
        let mut stream = Vec::with_capacity(self.size);
        for part in &self.received_parts {
            match part {
                Some(data) => stream.extend_from_slice(data),
                None => {
                    self.status = ResourceStatus::Corrupt;
                    return Err(RnsError::PacketError);
                }
            }
        }

        let decrypted = if self.encrypted {
            let mut buf = Vec::with_capacity(
                stream.len() + RETICULUM_TOKEN_OVERHEAD + RETICULUM_AES_BLOCK_SIZE,
            );
            buf.resize(
                stream.len() + RETICULUM_TOKEN_OVERHEAD + RETICULUM_AES_BLOCK_SIZE,
                0,
            );
            let len = decrypt(&stream, &mut buf)?;
            buf.truncate(len);
            buf
        } else {
            stream
        };

        // Strip inline random hash (first 4 bytes)
        if decrypted.len() < RANDOM_HASH_SIZE {
            self.status = ResourceStatus::Corrupt;
            return Err(RnsError::PacketError);
        }
        let payload = &decrypted[RANDOM_HASH_SIZE..];

        // Decompress when the advertisement's compressed flag is set.
        // Matching Python, the decompressed size is capped to protect the
        // receiver against resource-exhaustion via an oversized payload.
        let plaintext = if self.compressed {
            let decompressed = bzip2_decompress(payload, AUTO_COMPRESS_MAX_SIZE)?;
            if self.total_segments <= 1 && decompressed.len() != self.uncompressed_size {
                self.status = ResourceStatus::Corrupt;
                return Err(RnsError::PacketError);
            }
            decompressed
        } else {
            payload.to_vec()
        };

        // Verify hash: SHA-256(plaintext || random_hash)  (matching Python)
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        hasher.update(&self.random_hash);
        let calculated = hasher.finalize();
        let calculated_hash = Hash::new(calculated.into());

        if calculated_hash != self.hash {
            self.status = ResourceStatus::Corrupt;
            return Err(RnsError::PacketError);
        }

        self.assembled_plaintext = plaintext.clone();

        Ok(plaintext)
    }

    /// Build proof data for a completed receive.
    ///
    /// proof = SHA-256(assembled_plaintext || hash)
    /// Matches Python: full_hash(self.data+self.hash)
    pub fn build_proof(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(HASH_SIZE * 2);
        data.extend_from_slice(self.hash.as_slice());

        let proof_hash = {
            let mut h = Sha256::new();
            h.update(&self.assembled_plaintext);
            h.update(self.hash.as_slice());
            let result = h.finalize();
            let mut buf = [0u8; HASH_SIZE];
            buf.copy_from_slice(&result);
            buf
        };
        data.extend_from_slice(&proof_hash);

        data
    }

    pub fn validate_proof(&self, proof_data: &[u8]) -> bool {
        if proof_data.len() < HASH_SIZE * 2 {
            return false;
        }
        let received_proof = &proof_data[HASH_SIZE..];
        received_proof == self.expected_proof
    }

    /// Handle an incoming part request (sender side).
    pub fn handle_request(
        &mut self,
        request_data: &[u8],
        packet_hash: Option<Hash>,
    ) -> Result<ResourceRequestResult, RnsError> {
        if self.status == ResourceStatus::Failed {
            return Err(RnsError::LinkClosed);
        }

        if let Some(hash) = packet_hash {
            if self.req_hashlist.contains(&hash) {
                return Ok(ResourceRequestResult {
                    parts: Vec::new(),
                    hmu_packet: None,
                    all_sent: false,
                });
            }
            self.req_hashlist.push_back(hash);
            while self.req_hashlist.len() > MAX_RETRIES * 4 {
                self.req_hashlist.pop_front();
            }
        }

        if request_data.is_empty() {
            return Err(RnsError::InvalidArgument);
        }

        let wants_more_hashmap = request_data[0] == HASHMAP_IS_EXHAUSTED;
        let pad = if wants_more_hashmap {
            1 + MAPHASH_LEN
        } else {
            1
        };
        if request_data.len() < pad + HASH_SIZE {
            return Err(RnsError::PacketError);
        }

        let requested_hashes = &request_data[pad + HASH_SIZE..];

        if self.adv_sent.is_some() && self.rtt.is_none() {
            let elapsed = std::time::Instant::now().duration_since(self.adv_sent.unwrap());
            self.rtt = Some(elapsed);
        }

        if self.status != ResourceStatus::Transferring {
            self.status = ResourceStatus::Transferring;
        }
        self.retries_left = self.max_retries;

        let num_requested = requested_hashes.len() / MAPHASH_LEN;
        let mut map_hashes: Vec<[u8; MAPHASH_LEN]> = Vec::with_capacity(num_requested);
        for i in 0..num_requested {
            let start = i * MAPHASH_LEN;
            let mut mh = [0u8; MAPHASH_LEN];
            mh.copy_from_slice(&requested_hashes[start..start + MAPHASH_LEN]);
            map_hashes.push(mh);
        }

        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(
            search_start + collision_guard_size(self.sdu),
            self.total_parts,
        );

        let mut sent_parts_data = Vec::new();
        for i in search_start..search_end {
            if i >= self.parts.len() {
                break;
            }
            if map_hashes.contains(&self.parts[i].map_hash) {
                sent_parts_data.push(self.parts[i].data.clone());
                if !self.parts[i].sent {
                    self.sent_parts += 1;
                    self.parts[i].sent = true;
                }
                self.last_activity = std::time::Instant::now();
                self.last_part_sent = Some(std::time::Instant::now());
            }
        }

        let mut hmu_packet: Option<Vec<u8>> = None;
        if wants_more_hashmap {
            let last_map_hash = &request_data[1..1 + MAPHASH_LEN];
            let hml = hashmap_max_len(self.sdu);
            let mut part_index = self.receiver_min_consecutive_height;
            for i in search_start..search_end {
                if i < self.parts.len() && &self.parts[i].map_hash[..] == last_map_hash {
                    part_index = i + 1;
                    break;
                }
            }

            self.receiver_min_consecutive_height = part_index.saturating_sub(1 + WINDOW_MAX);

            if hml > 0 && part_index % hml != 0 {
                self.status = ResourceStatus::Failed;
                return Err(RnsError::OutOfMemory);
            }

            let segment = if hml > 0 { part_index / hml } else { 0 };
            let hashmap_start = segment * hml;
            let hashmap_end = core::cmp::min((segment + 1) * hml, self.total_parts);

            let mut hashmap_seg = Vec::new();
            for i in hashmap_start..hashmap_end {
                let pos = i * MAPHASH_LEN;
                if pos + MAPHASH_LEN <= self.hashmap.len() {
                    hashmap_seg.extend_from_slice(&self.hashmap[pos..pos + MAPHASH_LEN]);
                }
            }

            let hmu_value = Value::Array(vec![
                Value::from(segment as i64),
                Value::Binary(hashmap_seg),
            ]);
            let mut hmu_body = Vec::new();
            write_value(&mut hmu_body, &hmu_value).map_err(|_| RnsError::InvalidArgument)?;

            let mut hmu = Vec::with_capacity(HASH_SIZE + hmu_body.len());
            hmu.extend_from_slice(self.hash.as_slice());
            hmu.extend_from_slice(&hmu_body);
            hmu_packet = Some(hmu);
        }

        let all_sent = self.sent_parts >= self.total_parts;
        if all_sent {
            self.status = ResourceStatus::AwaitingProof;
            self.retries_left = 3;
        }

        Ok(ResourceRequestResult {
            parts: sent_parts_data,
            hmu_packet,
            all_sent,
        })
    }

    // ---- Timeout / retry handling ----

    /// Timeout before re-requesting missing parts (receiver side), or
    /// before deciding the transfer has stalled. Scales with the measured
    /// RTT, the number of outstanding parts, and how many retries have
    /// already been burned (each retry adds `PER_RETRY_DELAY`).
    fn part_timeout(&self) -> Duration {
        let rtt = self.rtt.unwrap_or(Duration::from_secs(1)).as_secs_f64();
        let outstanding = self.outstanding_parts.max(1) as f64;
        let retries_used = (self.max_retries.saturating_sub(self.retries_left)) as f64;
        let extra_wait = retries_used * PER_RETRY_DELAY;
        // Each outstanding part is expected to take roughly one RTT;
        // scale by the part timeout factor for a safety margin (the
        // Python reference reaches the same value when EIFR ≈ one part
        // per RTT).
        let expected = self.part_timeout_factor * outstanding * rtt;
        Duration::from_secs_f64(expected + RETRY_GRACE_TIME + extra_wait)
    }

    /// Timeout before re-advertising on the sender side (waiting for the
    /// first part request), and before re-querying the proof once all
    /// parts have been sent.
    fn sender_timeout(&self) -> Duration {
        let rtt = self.rtt.unwrap_or(Duration::from_secs(1)).as_secs_f64();
        Duration::from_secs_f64(rtt * PROOF_TIMEOUT_FACTOR + SENDER_GRACE_TIME)
    }

    /// Check whether the transfer has stalled past its timeout budget.
    ///
    /// A driver should call this periodically (e.g. once per link tick)
    /// and act on the returned [`ResourceTimeoutAction`]. On a timeout the
    /// retry budget is decremented and a retry action is returned; once the
    /// budget is exhausted the resource is marked [`ResourceStatus::Failed`]
    /// so the caller can tear it down. Without this, a stalled transfer
    /// would hang forever with no retransmission or expiry path.
    pub fn check_timeout(&mut self) -> Result<ResourceTimeoutAction, RnsError> {
        let now = std::time::Instant::now();
        match self.status {
            ResourceStatus::Advertised => {
                // Sender advertised but no part request arrived yet.
                let deadline = self
                    .adv_sent
                    .unwrap_or(self.last_activity)
                    .checked_add(self.sender_timeout());
                if deadline.is_none_or(|d| now >= d) {
                    if self.max_adv_retries == 0 {
                        self.status = ResourceStatus::Failed;
                        return Ok(ResourceTimeoutAction::Failed);
                    }
                    self.max_adv_retries -= 1;
                    Ok(ResourceTimeoutAction::RetryAdvertisement)
                } else {
                    Ok(ResourceTimeoutAction::None)
                }
            }
            ResourceStatus::Transferring => {
                let deadline = self.last_activity.checked_add(self.part_timeout());
                if deadline.is_none_or(|d| now >= d) {
                    if self.retries_left == 0 {
                        self.status = ResourceStatus::Failed;
                        return Ok(ResourceTimeoutAction::Failed);
                    }
                    self.retries_left -= 1;
                    // Shrink the window on timeout (matches Python).
                    if self.window > self.window_min {
                        self.window -= 1;
                        if self.window_max > self.window_min {
                            self.window_max -= 1;
                            if self.window_max - self.window > self.window_flexibility - 1 {
                                self.window_max -= 1;
                            }
                        }
                    }
                    self.waiting_for_hmu = false;
                    let request = self.build_request()?;
                    Ok(ResourceTimeoutAction::RetryPartRequest(request))
                } else {
                    Ok(ResourceTimeoutAction::None)
                }
            }
            ResourceStatus::AwaitingProof => {
                // Sender has sent all parts but no proof arrived.
                let deadline = self
                    .last_part_sent
                    .unwrap_or(self.last_activity)
                    .checked_add(self.sender_timeout());
                if deadline.is_none_or(|d| now >= d) {
                    if self.retries_left == 0 {
                        self.status = ResourceStatus::Failed;
                        return Ok(ResourceTimeoutAction::Failed);
                    }
                    self.retries_left -= 1;
                    Ok(ResourceTimeoutAction::RetryProof)
                } else {
                    Ok(ResourceTimeoutAction::None)
                }
            }
            _ => Ok(ResourceTimeoutAction::None),
        }
    }

    // ---- Getters ----

    pub fn hash(&self) -> &Hash {
        &self.hash
    }
    pub fn request_id(&self) -> Option<&[u8]> {
        self.request_id.as_deref()
    }
    pub fn original_hash(&self) -> &Hash {
        &self.original_hash
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn total_size(&self) -> usize {
        self.total_size
    }
    pub fn status(&self) -> ResourceStatus {
        self.status
    }
    pub fn set_status(&mut self, s: ResourceStatus) {
        self.status = s;
    }
    pub fn total_parts(&self) -> usize {
        self.total_parts
    }
    pub fn sent_parts(&self) -> usize {
        self.sent_parts
    }
    pub fn received_count(&self) -> usize {
        self.received_count
    }
    pub fn window(&self) -> usize {
        self.window
    }
    pub fn outstanding_parts(&self) -> usize {
        self.outstanding_parts
    }
    pub fn eifr(&self) -> Option<f64> {
        self.eifr
    }
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
    pub fn has_metadata(&self) -> bool {
        self.has_metadata
    }
    pub fn set_has_metadata(&mut self, has_metadata: bool) {
        self.has_metadata = has_metadata;
    }
    pub fn random_hash_bytes(&self) -> &[u8; RANDOM_HASH_SIZE] {
        &self.random_hash
    }
    pub fn segment_index(&self) -> usize {
        self.segment_index
    }
    pub fn total_segments(&self) -> usize {
        self.total_segments
    }
    pub fn split(&self) -> bool {
        self.split
    }
}

// ============================================================================
// ResourceRequestResult
// ============================================================================

pub struct ResourceRequestResult {
    pub parts: Vec<Vec<u8>>,
    pub hmu_packet: Option<Vec<u8>>,
    pub all_sent: bool,
}

/// What a resource timeout check decided the driver should do next.
///
/// The resource state machine alone cannot send packets, so it reports
/// the action a driver should perform when a transfer stalls past its
/// timeout budget. Each action decrements the corresponding retry budget;
/// once the budget is exhausted the resource is marked `Failed`.
#[derive(Debug, PartialEq, Eq)]
pub enum ResourceTimeoutAction {
    /// The transfer is still within its timeout budget; nothing to do yet.
    None,
    /// The receiver should re-send a part request (request payload included).
    RetryPartRequest(Vec<u8>),
    /// The sender should re-send the resource advertisement.
    RetryAdvertisement,
    /// The sender should re-query the network cache for the resource proof.
    RetryProof,
    /// The transfer failed and must be torn down and cleaned up.
    Failed,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_encrypt(data: &[u8], buf: &mut Vec<u8>) -> Result<usize, RnsError> {
        let len = data.len();
        buf[..len].copy_from_slice(data);
        Ok(len)
    }

    fn dummy_decrypt(data: &[u8], buf: &mut Vec<u8>) -> Result<usize, RnsError> {
        let len = data.len();
        buf[..len].copy_from_slice(data);
        Ok(len)
    }

    #[test]
    fn resource_advertisement_pack_unpack_roundtrip() {
        let data = b"Hello, Resource World!";
        let link_mdu = 400;
        let resource =
            Resource::new(data, link_mdu, dummy_encrypt, None, false, true).expect("resource creation");

        let adv = ResourceAdvertisement::from_resource(&resource);
        let packed = adv.pack(0, link_mdu).expect("pack");
        let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack");

        assert_eq!(adv.transfer_size, unpacked.transfer_size);
        assert_eq!(adv.data_size, unpacked.data_size);
        assert_eq!(adv.num_parts, unpacked.num_parts);
        assert_eq!(adv.hash, unpacked.hash);
        assert_eq!(adv.random_hash, unpacked.random_hash);
        assert_eq!(adv.flags, unpacked.flags);
        assert_eq!(adv.segment_index, unpacked.segment_index);
        assert_eq!(adv.total_segments, unpacked.total_segments);
        assert_eq!(adv.request_id, unpacked.request_id);
    }

    #[test]
    fn resource_send_and_receive_small() {
        let original_data = b"Test data!";
        let link_mdu = 400;

        let mut sender =
            Resource::new(original_data, link_mdu, dummy_encrypt, None, false, true).expect("sender");

        let adv = ResourceAdvertisement::from_resource(&sender);
        let rtt = Duration::from_millis(50);
        let mut receiver =
            Resource::new_from_advertisement(&adv, link_mdu, rtt, None).expect("receiver");

        let first_req = receiver.start_receive(&adv.hashmap).expect("first request");
        let req_result = sender.handle_request(&first_req, None).expect("handle req");

        for part in &req_result.parts {
            assert!(receiver.receive_part(part), "part accepted");
        }

        if let Some(hmu) = &req_result.hmu_packet {
            let hmu_body = &hmu[HASH_SIZE..];
            if let Ok(val) = read_value(&mut &hmu_body[..]) {
                if let Some(arr) = val.as_array() {
                    if arr.len() >= 2 {
                        let seg = arr[0].as_i64().unwrap_or(0) as usize;
                        if let Some(hdata) = arr[1].as_slice() {
                            receiver.apply_hashmap(seg, hdata).expect("apply hmu");
                        }
                    }
                }
            }
            let next_req = receiver.build_request().expect("next request");
            let next_result = sender.handle_request(&next_req, None).expect("handle next");
            for part in &next_result.parts {
                assert!(receiver.receive_part(part), "part accepted");
            }
        }

        assert!(receiver.all_parts_received(), "all parts received");

        let plaintext = receiver.assemble(dummy_decrypt).expect("assemble");
        assert_eq!(plaintext, original_data);

        let proof = receiver.build_proof();
        assert!(sender.validate_proof(&proof), "proof valid");
    }

    #[test]
    fn resource_auto_compresses_and_roundtrips() {
        // Highly repetitive data so bz2 compresses it well.
        let original_data = b"compress me, I repeat, compress me, I repeat, ".repeat(64);
        let link_mdu = 400;

        let mut sender =
            Resource::new(&original_data, link_mdu, dummy_encrypt, None, false, true)
                .expect("sender");

        assert!(sender.is_compressed(), "compressible data should be compressed");

        let adv = ResourceAdvertisement::from_resource(&sender);
        assert_ne!(adv.flags & 0x02, 0, "compressed flag must be set");

        let rtt = Duration::from_millis(50);
        let mut receiver =
            Resource::new_from_advertisement(&adv, link_mdu, rtt, None).expect("receiver");
        assert!(receiver.is_compressed());

        let first_req = receiver.start_receive(&adv.hashmap).expect("first request");
        let req_result = sender.handle_request(&first_req, None).expect("handle req");
        for part in &req_result.parts {
            assert!(receiver.receive_part(part), "part accepted");
        }

        assert!(receiver.all_parts_received(), "all parts received");

        let plaintext = receiver.assemble(dummy_decrypt).expect("assemble");
        assert_eq!(plaintext, original_data);

        let proof = receiver.build_proof();
        assert!(sender.validate_proof(&proof), "proof valid");
    }

    #[test]
    fn resource_does_not_compress_incompressible_data() {
        // Random bytes defeat bz2 compression.
        let mut data = vec![0u8; 512];
        let mut rng = UnwrapErr(SysRng);
        rng.fill_bytes(&mut data);
        let link_mdu = 400;

        let sender = Resource::new(&data, link_mdu, dummy_encrypt, None, false, true)
            .expect("sender");

        assert!(!sender.is_compressed(), "incompressible data must be sent uncompressed");

        let adv = ResourceAdvertisement::from_resource(&sender);
        assert_eq!(adv.flags & 0x02, 0, "compressed flag must be clear");
    }

    // A bz2 stream produced by Python 3's `bz2.compress(data)` (level 9,
    // the default), where data is `b"Reticulum resource compression interop
    // test data! " * 40` (2000 bytes). Used to prove our decompressor accepts
    // exactly what the Python reference emits, and that our compressor is
    // byte-identical to it.
    const PYTHON_BZ2_GOLDEN: &str = "425a683931415926535937b963f500009f9380600010002e27de003000d8050d34c001434d300014a94608da989813613b13913913f09c09b89a89f44e84f62644c0991351340981322604d04ec4f027813813813027026a2682644d84dc4c89d09b09815604fc27426a26827227827d13f8bb9229c28481bdcb1fa8";

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn bzip2_interops_with_python_reference() {
        let data = b"Reticulum resource compression interop test data! ".repeat(40);

        // Our compressor must be byte-identical to Python's bz2.compress.
        let compressed = bzip2_compress(&data).expect("compress");
        assert_eq!(compressed, decode_hex(PYTHON_BZ2_GOLDEN));

        // Our decompressor must accept the Python-produced stream.
        let decompressed = bzip2_decompress(&decode_hex(PYTHON_BZ2_GOLDEN), data.len())
            .expect("decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn bzip2_decompress_rejects_oversized_output() {
        let data = vec![0x41u8; 8192];
        let compressed = bzip2_compress(&data).expect("compress");

        assert!(matches!(
            bzip2_decompress(&compressed, 1024),
            Err(RnsError::PacketError)
        ));
    }

    #[test]
    fn resource_hash_verification() {
        let data = b"Verify my hash!";
        let link_mdu = 200;
        let resource = Resource::new(data, link_mdu, dummy_encrypt, None, false, true).expect("resource");

        // Hash should be SHA-256(original_plaintext || random_hash)
        let mut expected = Sha256::new();
        expected.update(data);
        expected.update(resource.random_hash_bytes());
        let expected_hash = Hash::new(expected.finalize().into());

        assert_eq!(
            *resource.hash(),
            expected_hash,
            "resource hash must be SHA-256(plaintext || random_hash)"
        );
    }

    #[test]
    fn receiver_part_request_is_reissued_after_timeout() {
        // Data large enough to span several parts, with non-repeating
        // bytes so the (dummy-encrypted) parts have distinct map hashes.
        let data: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect();
        let link_mdu = 400;
        let mut sender =
            Resource::new(&data, link_mdu, dummy_encrypt, None, false, true).expect("sender");
        let adv = ResourceAdvertisement::from_resource(&sender);
        let rtt = Duration::from_millis(50);
        let mut receiver =
            Resource::new_from_advertisement(&adv, link_mdu, rtt, None).expect("receiver");

        // Start transfer: receiver issues a part request.
        let first_req = receiver.start_receive(&adv.hashmap).expect("first request");
        let req_result = sender.handle_request(&first_req, None).expect("handle req");
        assert!(sender.total_parts() > 1, "test requires multiple parts");

        // Receive only the first part, leaving parts outstanding.
        assert!(receiver.receive_part(&req_result.parts[0]), "part accepted");

        // No timeout has elapsed yet: nothing due.
        receiver.last_activity = std::time::Instant::now();
        assert_eq!(
            receiver.check_timeout().expect("check"),
            ResourceTimeoutAction::None
        );

        // Force a timeout: the retry budget is consumed and a fresh part
        // request must be produced so the missing parts can be re-fetched.
        receiver.last_activity =
            std::time::Instant::now() - Duration::from_secs(3600);
        let retries_before = receiver.retries_left;
        let action = receiver.check_timeout().expect("check");
        assert_eq!(receiver.retries_left, retries_before - 1, "retry budget decremented");
        match action {
            ResourceTimeoutAction::RetryPartRequest(request) => {
                assert!(!request.is_empty(), "re-request must carry hashes");
                // The re-request must actually solicit the missing parts.
                let req_result = sender
                    .handle_request(&request, None)
                    .expect("handle re-request");
                assert!(!req_result.parts.is_empty(), "re-request must yield parts");
            }
            other => panic!("expected RetryPartRequest, got {other:?}"),
        }
    }

    #[test]
    fn receiver_fails_after_retries_exhausted() {
        let data: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect();
        let link_mdu = 400;
        let mut sender =
            Resource::new(&data, link_mdu, dummy_encrypt, None, false, true).expect("sender");
        let adv = ResourceAdvertisement::from_resource(&sender);
        let rtt = Duration::from_millis(50);
        let mut receiver =
            Resource::new_from_advertisement(&adv, link_mdu, rtt, None).expect("receiver");

        let first_req = receiver.start_receive(&adv.hashmap).expect("first request");
        let req_result = sender.handle_request(&first_req, None).expect("handle req");
        assert!(receiver.receive_part(&req_result.parts[0]), "part accepted");

        // Burn the entire retry budget with timeouts. Each timeout must
        // consume a retry and eventually transition the transfer to Failed
        // rather than hanging forever. `max_retries + 1` iterations are
        // needed: the first `max_retries` consume the budget (each returns
        // a retry), and the final one observes it exhausted.
        let mut failed = false;
        for _ in 0..=receiver.max_retries {
            receiver.last_activity =
                std::time::Instant::now() - Duration::from_secs(3600);
            let action = receiver.check_timeout().expect("check");
            match action {
                ResourceTimeoutAction::RetryPartRequest(_) => {
                    // Keep stalling: the next timeout will consume another retry.
                }
                ResourceTimeoutAction::Failed => {
                    failed = true;
                    break;
                }
                other => panic!("unexpected action {other:?}"),
            }
        }

        assert!(failed, "transfer must fail once the retry budget is exhausted");
        assert_eq!(receiver.status(), ResourceStatus::Failed);
    }

    #[test]
    fn sender_re_advertises_then_fails_without_first_request() {
        let data = b"Advertise but nobody asks!";
        let link_mdu = 400;
        let mut sender =
            Resource::new(data, link_mdu, dummy_encrypt, None, false, true).expect("sender");

        // Simulate an advertisement having been sent and no part request
        // ever arriving.
        sender.status = ResourceStatus::Advertised;
        sender.adv_sent = Some(std::time::Instant::now() - Duration::from_secs(3600));
        sender.max_adv_retries = 2;
        sender.retries_left = MAX_ADV_RETRIES;

        // First timeout: re-advertise.
        assert_eq!(
            sender.check_timeout().expect("check"),
            ResourceTimeoutAction::RetryAdvertisement
        );
        assert_eq!(sender.max_adv_retries, 1);

        // Second timeout: re-advertise again.
        assert_eq!(
            sender.check_timeout().expect("check"),
            ResourceTimeoutAction::RetryAdvertisement
        );
        assert_eq!(sender.max_adv_retries, 0);

        // Budget exhausted: the transfer fails.
        assert_eq!(
            sender.check_timeout().expect("check"),
            ResourceTimeoutAction::Failed
        );
        assert_eq!(sender.status(), ResourceStatus::Failed);
    }

    #[test]
    fn sender_re_queries_proof_then_fails_without_proof() {
        let data = b"All sent, where is my proof?";
        let link_mdu = 400;
        let mut sender =
            Resource::new(data, link_mdu, dummy_encrypt, None, false, true).expect("sender");

        // Force the sender into the awaiting-proof state, as if all parts
        // were sent and the proof never arrived.
        sender.status = ResourceStatus::AwaitingProof;
        sender.last_part_sent = Some(std::time::Instant::now() - Duration::from_secs(3600));
        sender.retries_left = 2;

        // First timeout: re-query the proof.
        assert_eq!(
            sender.check_timeout().expect("check"),
            ResourceTimeoutAction::RetryProof
        );
        assert_eq!(sender.retries_left, 1);

        // Second timeout: re-query again.
        assert_eq!(
            sender.check_timeout().expect("check"),
            ResourceTimeoutAction::RetryProof
        );
        assert_eq!(sender.retries_left, 0);

        // Budget exhausted: the transfer fails instead of hanging forever.
        assert_eq!(
            sender.check_timeout().expect("check"),
            ResourceTimeoutAction::Failed
        );
        assert_eq!(sender.status(), ResourceStatus::Failed);
    }
}
