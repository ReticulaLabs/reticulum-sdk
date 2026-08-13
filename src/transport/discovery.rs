use std::time::Duration;

use ed25519_dalek::Signature;
use getrandom::SysRng;
use hkdf::Hkdf;
use rand_core::{Rng, UnwrapErr};
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::{Digest, Sha256};
use tokio::time;

use crate::{
    buffer::StaticBuffer,
    destination::{DestinationDesc, DestinationName, SingleInputDestination},
    error::RnsError,
    hash::{AddressHash, HASH_SIZE, Hash},
    identity::PrivateIdentity,
    packet::PacketDataBuffer,
};

const KEY_NAME: u8 = 0xFF;
const KEY_TRANSPORT_ID: u8 = 0xFE;
const KEY_INTERFACE_TYPE: u8 = 0x00;
const KEY_TRANSPORT: u8 = 0x01;
const KEY_REACHABLE_ON: u8 = 0x02;
const KEY_LATITUDE: u8 = 0x03;
const KEY_LONGITUDE: u8 = 0x04;
const KEY_HEIGHT: u8 = 0x05;
const KEY_PORT: u8 = 0x06;
const KEY_IFAC_NETNAME: u8 = 0x07;
const KEY_IFAC_NETKEY: u8 = 0x08;
const KEY_FREQUENCY: u8 = 0x09;
const KEY_BANDWIDTH: u8 = 0x0A;
const KEY_SPREADINGFACTOR: u8 = 0x0B;
const KEY_CODINGRATE: u8 = 0x0C;

pub const DISCOVERY_APP_NAME: &str = "rnstransport";
pub const DISCOVERY_ASPECTS: &str = "discovery.interface";
pub const DISCOVERY_JOB_INTERVAL: Duration = Duration::from_secs(60);
pub const DISCOVERY_MIN_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const DISCOVERY_DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Default proof-of-work difficulty (leading zero bits) for interface
/// discovery stamps. Must match the Python reference implementation's
/// `InterfaceAnnouncer.DEFAULT_STAMP_VALUE` (16) for discovery announces
/// to be accepted by Python peers: a stamp generated with a lower
/// difficulty is rejected by them.
const DEFAULT_STAMP_COST: u8 = 16;
const WORKBLOCK_EXPAND_ROUNDS: usize = 20;
const FLAG_SIGNED: u8 = 0b0000_0001;
const FLAG_ENCRYPTED: u8 = 0b0000_0010;

#[derive(Clone, Debug)]
pub enum DiscoveryInterfaceKind {
    TcpServer { reachable_on: String, port: u16 },
    Backbone { reachable_on: String, port: u16 },
    RNode { frequency: u64, bandwidth: u32, spreadingfactor: u8, codingrate: u8 },
    LoRa { frequency: u64, bandwidth: f64, spreadingfactor: u8, codingrate: u8 },
}

impl DiscoveryInterfaceKind {
    fn interface_type(&self) -> &'static str {
        match self {
            Self::TcpServer { .. } => "TCPServerInterface",
            Self::Backbone { .. } => "BackboneInterface",
            Self::RNode { .. } => "RNodeInterface",
            Self::LoRa { .. } => "LoRaInterface",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveryInterfaceConfig {
    pub name: String,
    pub kind: DiscoveryInterfaceKind,
    pub announce_interval: Duration,
    pub stamp_cost: u8,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
}

impl DiscoveryInterfaceConfig {
    pub fn tcp_server<TName, THost>(name: TName, reachable_on: THost, port: u16) -> Self
    where
        TName: Into<String>,
        THost: Into<String>,
    {
        Self {
            name: sanitize(&name.into()),
            kind: DiscoveryInterfaceKind::TcpServer {
                reachable_on: sanitize(&reachable_on.into()),
                port,
            },
            announce_interval: DISCOVERY_DEFAULT_ANNOUNCE_INTERVAL,
            stamp_cost: DEFAULT_STAMP_COST,
            latitude: None,
            longitude: None,
            height: None,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn backbone<TName, THost>(name: TName, reachable_on: THost, port: u16) -> Self
    where
        TName: Into<String>,
        THost: Into<String>,
    {
        Self {
            name: sanitize(&name.into()),
            kind: DiscoveryInterfaceKind::Backbone {
                reachable_on: sanitize(&reachable_on.into()),
                port,
            },
            announce_interval: DISCOVERY_DEFAULT_ANNOUNCE_INTERVAL,
            stamp_cost: DEFAULT_STAMP_COST,
            latitude: None,
            longitude: None,
            height: None,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn rnode<TName>(name: TName, frequency: u64, bandwidth: u32, spreadingfactor: u8, codingrate: u8) -> Self
    where
        TName: Into<String>,
    {
        Self {
            name: sanitize(&name.into()),
            kind: DiscoveryInterfaceKind::RNode { frequency, bandwidth, spreadingfactor, codingrate },
            announce_interval: DISCOVERY_DEFAULT_ANNOUNCE_INTERVAL,
            stamp_cost: DEFAULT_STAMP_COST,
            latitude: None,
            longitude: None,
            height: None,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn lora<TName>(name: TName, frequency: u64, bandwidth: f64, spreadingfactor: u8, codingrate: u8) -> Self
    where
        TName: Into<String>,
    {
        Self {
            name: sanitize(&name.into()),
            kind: DiscoveryInterfaceKind::LoRa { frequency, bandwidth, spreadingfactor, codingrate },
            announce_interval: DISCOVERY_DEFAULT_ANNOUNCE_INTERVAL,
            stamp_cost: DEFAULT_STAMP_COST,
            latitude: None,
            longitude: None,
            height: None,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn with_announce_interval(mut self, interval: Duration) -> Self {
        self.announce_interval = interval.max(DISCOVERY_MIN_ANNOUNCE_INTERVAL);
        self
    }

    pub fn with_stamp_cost(mut self, stamp_cost: u8) -> Self {
        self.stamp_cost = stamp_cost;
        self
    }

    pub fn with_position(
        mut self,
        latitude: Option<f64>,
        longitude: Option<f64>,
        height: Option<f64>,
    ) -> Self {
        self.latitude = latitude;
        self.longitude = longitude;
        self.height = height;
        self
    }

    pub fn with_ifac<TName, TKey>(mut self, ifac_netname: TName, ifac_netkey: TKey) -> Self
    where
        TName: Into<String>,
        TKey: Into<String>,
    {
        self.ifac_netname = Some(sanitize(&ifac_netname.into()));
        self.ifac_netkey = Some(sanitize(&ifac_netkey.into()));
        self
    }

    pub fn build_app_data(
        &self,
        transport_enabled: bool,
        transport_id: &AddressHash,
    ) -> Result<PacketDataBuffer, RnsError> {
        let mut info = vec![
            (
                u8_value(KEY_INTERFACE_TYPE),
                Value::from(self.kind.interface_type()),
            ),
            (u8_value(KEY_TRANSPORT), Value::Boolean(transport_enabled)),
            (
                u8_value(KEY_TRANSPORT_ID),
                Value::Binary(transport_id.as_slice().to_vec()),
            ),
            (u8_value(KEY_NAME), Value::from(self.name.as_str())),
            (u8_value(KEY_LATITUDE), optional_f64(self.latitude)),
            (u8_value(KEY_LONGITUDE), optional_f64(self.longitude)),
            (u8_value(KEY_HEIGHT), optional_f64(self.height)),
        ];

        match &self.kind {
            DiscoveryInterfaceKind::TcpServer { reachable_on, port }
            | DiscoveryInterfaceKind::Backbone { reachable_on, port } => {
                info.push((
                    u8_value(KEY_REACHABLE_ON),
                    Value::from(reachable_on.as_str()),
                ));
                info.push((u8_value(KEY_PORT), Value::from(*port)));
            }
            DiscoveryInterfaceKind::RNode { frequency, bandwidth, spreadingfactor, codingrate } => {
                info.push((u8_value(KEY_FREQUENCY), Value::from(*frequency)));
                info.push((u8_value(KEY_BANDWIDTH), Value::from(*bandwidth)));
                info.push((u8_value(KEY_SPREADINGFACTOR), Value::from(*spreadingfactor)));
                info.push((u8_value(KEY_CODINGRATE), Value::from(*codingrate)));
            }
            DiscoveryInterfaceKind::LoRa { frequency, bandwidth, spreadingfactor, codingrate } => {
                info.push((u8_value(KEY_FREQUENCY), Value::from(*frequency)));
                info.push((u8_value(KEY_BANDWIDTH), Value::from(*bandwidth)));
                info.push((u8_value(KEY_SPREADINGFACTOR), Value::from(*spreadingfactor)));
                info.push((u8_value(KEY_CODINGRATE), Value::from(*codingrate)));
            }
        }

        if let Some(ifac_netname) = &self.ifac_netname {
            info.push((
                u8_value(KEY_IFAC_NETNAME),
                Value::from(ifac_netname.as_str()),
            ));
        }
        if let Some(ifac_netkey) = &self.ifac_netkey {
            info.push((u8_value(KEY_IFAC_NETKEY), Value::from(ifac_netkey.as_str())));
        }

        let mut packed = Vec::new();
        write_value(&mut packed, &Value::Map(info)).map_err(|_| RnsError::PacketError)?;

        let infohash = Hash::new_from_slice(&packed);
        let stamp = generate_stamp(
            infohash.as_slice(),
            self.stamp_cost,
            WORKBLOCK_EXPAND_ROUNDS,
        )?;

        let mut payload = PacketDataBuffer::new();
        payload.write(&[0u8]);
        payload.write(&packed);
        payload.write(&stamp);
        Ok(payload)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RegisteredDiscoveryInterface {
    pub config: DiscoveryInterfaceConfig,
    pub last_announce: time::Instant,
}

impl RegisteredDiscoveryInterface {
    pub(crate) fn new(config: DiscoveryInterfaceConfig) -> Self {
        let announce_interval = config.announce_interval;
        Self {
            config,
            last_announce: time::Instant::now() - announce_interval,
        }
    }

    pub(crate) fn is_due(&self, now: time::Instant) -> bool {
        now.duration_since(self.last_announce) >= self.config.announce_interval
    }
}

#[derive(Clone)]
pub struct DiscoveredInterface {
    pub source: DestinationDesc,
    pub interface_type: String,
    pub name: String,
    pub transport_enabled: bool,
    pub transport_id: AddressHash,
    pub hops: u8,
    pub reachable_on: Option<String>,
    pub port: Option<u16>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub stamp_value: u8,
    pub encrypted: bool,
    pub config_entry: Option<String>,
    pub frequency: Option<u64>,
    pub bandwidth: Option<f64>,
    pub spreadingfactor: Option<u8>,
    pub codingrate: Option<u8>,
}

impl DiscoveredInterface {
    pub fn from_announce(
        source: DestinationDesc,
        hops: u8,
        app_data: &[u8],
    ) -> Result<Self, RnsError> {
        Self::from_announce_with_required_value(source, hops, app_data, DEFAULT_STAMP_COST)
    }

    /// Parse and validate a discovery announce, requiring the embedded
    /// proof-of-work stamp to have at least `required_stamp_value` leading
    /// zero bits. This mirrors the `required_value` parameter of the Python
    /// reference `InterfaceDiscovery` listener (default
    /// `InterfaceAnnouncer.DEFAULT_STAMP_VALUE`).
    pub fn from_announce_with_required_value(
        source: DestinationDesc,
        hops: u8,
        app_data: &[u8],
        required_stamp_value: u8,
    ) -> Result<Self, RnsError> {
        if app_data.is_empty() {
            return Err(RnsError::PacketError);
        }

        let flags = app_data[0];
        if flags & FLAG_ENCRYPTED != 0 {
            return Err(RnsError::PacketError);
        }

        let is_signed = flags & FLAG_SIGNED != 0;

        let min_len = if is_signed {
            1 + HASH_SIZE + ed25519_dalek::SIGNATURE_LENGTH
        } else {
            1 + HASH_SIZE
        };
        if app_data.len() <= min_len {
            return Err(RnsError::PacketError);
        }

        let stamp_start = if is_signed {
            app_data.len() - HASH_SIZE - ed25519_dalek::SIGNATURE_LENGTH
        } else {
            app_data.len() - HASH_SIZE
        };
        let packed = &app_data[1..stamp_start];
        let stamp = &app_data[stamp_start..stamp_start + HASH_SIZE];

        if is_signed {
            let sig_start = stamp_start + HASH_SIZE;
            let sig_bytes = &app_data[sig_start..sig_start + ed25519_dalek::SIGNATURE_LENGTH];
            let signature =
                Signature::from_slice(sig_bytes).map_err(|_| RnsError::IncorrectSignature)?;

            let mut signed_data = Vec::with_capacity(packed.len() + HASH_SIZE);
            signed_data.extend_from_slice(packed);
            signed_data.extend_from_slice(stamp);

            source.identity.verify(&signed_data, &signature)?;
        }

        let infohash = Hash::new_from_slice(packed);
        let workblock = stamp_workblock(infohash.as_slice(), WORKBLOCK_EXPAND_ROUNDS)?;
        if !stamp_valid(stamp, required_stamp_value, &workblock) {
            return Err(RnsError::IncorrectSignature);
        }
        let stamp_value = stamp_value(stamp, &workblock);

        let value = read_value(&mut &packed[..]).map_err(|_| RnsError::PacketError)?;
        let map = value.as_map().ok_or(RnsError::PacketError)?;

        let interface_type = get_string(map, KEY_INTERFACE_TYPE)?.ok_or(RnsError::PacketError)?;
        let transport_enabled = get_bool(map, KEY_TRANSPORT)?.unwrap_or(false);
        let transport_id = get_address_hash(map, KEY_TRANSPORT_ID)?.ok_or(RnsError::PacketError)?;
        let name = get_string(map, KEY_NAME)?
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("Discovered {interface_type}"));
        let reachable_on = get_string(map, KEY_REACHABLE_ON)?;
        let port = get_u16(map, KEY_PORT)?;
        let latitude = get_f64(map, KEY_LATITUDE)?;
        let longitude = get_f64(map, KEY_LONGITUDE)?;
        let height = get_f64(map, KEY_HEIGHT)?;
        let ifac_netname = get_string(map, KEY_IFAC_NETNAME)?;
        let ifac_netkey = get_string(map, KEY_IFAC_NETKEY)?;

        // The announced transport identity is intentionally independent of
        // the announce's source identity.  Python's `InterfaceAnnouncer`
        // announces the discovery destination using the configured network
        // identity while embedding `RNS.Transport.identity.hash` as the
        // TRANSPORT_ID field (Discovery.py:55-58, 133); `InterfaceAnnounce
        // Handler` stores the two as separate `transport_id`/`network_id`
        // fields and never requires them to match.  Requiring equality here
        // would reject legitimate Python peers, so no cross-check is applied.

        let frequency = get_u64(map, KEY_FREQUENCY)?;
        let bandwidth = get_f64(map, KEY_BANDWIDTH)?;
        let spreadingfactor = get_u8(map, KEY_SPREADINGFACTOR)?;
        let codingrate = get_u8(map, KEY_CODINGRATE)?;

        let config_entry = match (interface_type.as_str(), reachable_on.as_deref(), port) {
            ("TCPServerInterface", Some(reachable_on), Some(port)) => {
                let identity = transport_id.to_hex_string();
                let mut entry = format!(
                    "[[{name}]]\n type = TCPClientInterface\n enabled = yes\n target_host = {reachable_on}\n target_port = {port}\n transport_identity = {identity}"
                );
                if let Some(ifac_netname) = &ifac_netname {
                    entry.push_str(&format!("\n network_name = {ifac_netname}"));
                }
                if let Some(ifac_netkey) = &ifac_netkey {
                    entry.push_str(&format!("\n passphrase = {ifac_netkey}"));
                }
                Some(entry)
            }
            ("BackboneInterface", Some(reachable_on), Some(port)) => {
                let identity = transport_id.to_hex_string();
                let mut entry = format!(
                    "[[{name}]]\n type = BackboneInterface\n enabled = yes\n target_host = {reachable_on}\n target_port = {port}\n transport_identity = {identity}"
                );
                if let Some(ifac_netname) = &ifac_netname {
                    entry.push_str(&format!("\n network_name = {ifac_netname}"));
                }
                if let Some(ifac_netkey) = &ifac_netkey {
                    entry.push_str(&format!("\n passphrase = {ifac_netkey}"));
                }
                Some(entry)
            }
            ("RNodeInterface", _, _) => {
                let identity = transport_id.to_hex_string();
                let freq = frequency.unwrap_or(0);
                let bw = bandwidth.unwrap_or(0.0);
                let sf = spreadingfactor.unwrap_or(0);
                let cr = codingrate.unwrap_or(0);
                let mut entry = format!(
                    "[[{name}]]\n type = RNodeInterface\n enabled = yes\n port = \n frequency = {freq}\n bandwidth = {bw}\n spreadingfactor = {sf}\n codingrate = {cr}"
                );
                if let Some(ifac_netname) = &ifac_netname {
                    entry.push_str(&format!("\n network_name = {ifac_netname}"));
                }
                if let Some(ifac_netkey) = &ifac_netkey {
                    entry.push_str(&format!("\n passphrase = {ifac_netkey}"));
                }
                entry.push_str(&format!("\n transport_identity = {identity}"));
                Some(entry)
            }
            _ => None,
        };

        Ok(Self {
            source,
            interface_type,
            name,
            transport_enabled,
            transport_id,
            hops,
            reachable_on,
            port,
            latitude,
            longitude,
            height,
            ifac_netname,
            ifac_netkey,
            stamp_value,
            encrypted: false,
            config_entry,
            frequency,
            bandwidth,
            spreadingfactor,
            codingrate,
        })
    }
}

pub fn create_discovery_destination(identity: PrivateIdentity) -> SingleInputDestination {
    SingleInputDestination::new(
        identity,
        DestinationName::new(DISCOVERY_APP_NAME, DISCOVERY_ASPECTS),
    )
}

pub fn is_discovery_destination(destination: &DestinationDesc) -> bool {
    destination.name.as_name_hash_slice()
        == DestinationName::new(DISCOVERY_APP_NAME, DISCOVERY_ASPECTS).as_name_hash_slice()
}

fn sanitize(value: &str) -> String {
    value.replace('\n', "").replace('\r', "").trim().to_string()
}

fn u8_value(value: u8) -> Value {
    Value::from(value)
}

fn optional_f64(value: Option<f64>) -> Value {
    value.map(Value::from).unwrap_or(Value::Nil)
}

fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Result<StaticBuffer<8192>, RnsError> {
    let mut workblock = StaticBuffer::<8192>::new();

    for round in 0..expand_rounds {
        let mut round_buf = Vec::new();
        write_value(&mut round_buf, &Value::from(round as u64))
            .map_err(|_| RnsError::PacketError)?;

        let salt = Hash::generator()
            .chain_update(material)
            .chain_update(&round_buf)
            .finalize();

        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), material);
        let mut block = [0u8; 256];
        hkdf.expand(&[], &mut block)
            .map_err(|_| RnsError::CryptoError)?;
        workblock.write(&block)?;
    }

    Ok(workblock)
}

fn stamp_valid(stamp: &[u8], target_cost: u8, workblock: &StaticBuffer<8192>) -> bool {
    count_leading_zero_bits(
        Hash::generator()
            .chain_update(workblock.as_slice())
            .chain_update(stamp)
            .finalize()
            .as_slice(),
    ) >= target_cost
}

fn stamp_value(stamp: &[u8], workblock: &StaticBuffer<8192>) -> u8 {
    count_leading_zero_bits(
        Hash::generator()
            .chain_update(workblock.as_slice())
            .chain_update(stamp)
            .finalize()
            .as_slice(),
    )
}

fn generate_stamp(
    material: &[u8],
    stamp_cost: u8,
    expand_rounds: usize,
) -> Result<[u8; HASH_SIZE], RnsError> {
    let workblock = stamp_workblock(material, expand_rounds)?;
    let mut rng = UnwrapErr(SysRng);

    loop {
        let mut stamp = [0u8; HASH_SIZE];
        rng.fill_bytes(&mut stamp);

        if stamp_valid(&stamp, stamp_cost, &workblock) {
            return Ok(stamp);
        }
    }
}

fn count_leading_zero_bits(data: &[u8]) -> u8 {
    let mut zeros = 0u8;

    for byte in data {
        if *byte == 0 {
            zeros = zeros.saturating_add(8);
            continue;
        }

        zeros = zeros.saturating_add(byte.leading_zeros() as u8);
        break;
    }

    zeros
}

fn map_value<'a>(map: &'a [(Value, Value)], key: u8) -> Option<&'a Value> {
    map.iter()
        .find_map(|(candidate, value)| (candidate.as_u64() == Some(key as u64)).then_some(value))
}

fn get_string(map: &[(Value, Value)], key: u8) -> Result<Option<String>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(Value::String(value)) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or(RnsError::PacketError),
        Some(Value::Binary(bytes)) => std::str::from_utf8(bytes)
            .map(|value| Some(value.to_string()))
            .map_err(|_| RnsError::PacketError),
        _ => Err(RnsError::PacketError),
    }
}

fn get_bool(map: &[(Value, Value)], key: u8) -> Result<Option<bool>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(Value::Boolean(value)) => Ok(Some(*value)),
        _ => Err(RnsError::PacketError),
    }
}

fn get_f64(map: &[(Value, Value)], key: u8) -> Result<Option<f64>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(value) => value.as_f64().map(Some).ok_or(RnsError::PacketError),
    }
}

fn get_u16(map: &[(Value, Value)], key: u8) -> Result<Option<u16>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .map(Some)
            .ok_or(RnsError::PacketError),
    }
}

fn get_u64(map: &[(Value, Value)], key: u8) -> Result<Option<u64>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(RnsError::PacketError),
    }
}

fn get_u8(map: &[(Value, Value)], key: u8) -> Result<Option<u8>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .map(Some)
            .ok_or(RnsError::PacketError),
    }
}

fn get_address_hash(map: &[(Value, Value)], key: u8) -> Result<Option<AddressHash>, RnsError> {
    match map_value(map, key) {
        Some(Value::Nil) | None => Ok(None),
        Some(Value::Binary(bytes)) if bytes.len() == AddressHash::new_empty().len() => {
            let mut value = [0u8; crate::hash::ADDRESS_HASH_SIZE];
            value.copy_from_slice(bytes);
            Ok(Some(AddressHash::new(value)))
        }
        _ => Err(RnsError::PacketError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::identity::PrivateIdentity;

    #[test]
    fn discovery_payload_roundtrip() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let config = DiscoveryInterfaceConfig::tcp_server("Rust Node", "127.0.0.1", 4242)
            .with_position(Some(55.0), Some(12.0), Some(10.0))
            .with_ifac("mesh", "shared-secret");
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();

        assert_eq!(decoded.interface_type, "TCPServerInterface");
        assert_eq!(decoded.name, "Rust Node");
        assert!(decoded.transport_enabled);
        assert_eq!(decoded.transport_id, transport_id);
        assert_eq!(decoded.reachable_on.as_deref(), Some("127.0.0.1"));
        assert_eq!(decoded.port, Some(4242));
        assert_eq!(decoded.ifac_netname.as_deref(), Some("mesh"));
        assert_eq!(decoded.ifac_netkey.as_deref(), Some("shared-secret"));
        assert!(decoded.stamp_value >= DEFAULT_STAMP_COST);
    }

    #[test]
    fn discovery_backbone_roundtrip() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let config = DiscoveryInterfaceConfig::backbone("Backbone Node", "10.0.0.1", 8475)
            .with_position(Some(55.0), Some(12.0), Some(10.0))
            .with_ifac("mesh", "shared-secret");
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();

        assert_eq!(decoded.interface_type, "BackboneInterface");
        assert_eq!(decoded.name, "Backbone Node");
        assert!(decoded.transport_enabled);
        assert_eq!(decoded.transport_id, transport_id);
        assert_eq!(decoded.reachable_on.as_deref(), Some("10.0.0.1"));
        assert_eq!(decoded.port, Some(8475));
        assert_eq!(decoded.ifac_netname.as_deref(), Some("mesh"));
        assert_eq!(decoded.ifac_netkey.as_deref(), Some("shared-secret"));
        assert!(decoded.stamp_value >= DEFAULT_STAMP_COST);
    }

    #[test]
    fn discovery_payload_accepts_unicode_names() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let config = DiscoveryInterfaceConfig::tcp_server("København 測試", "127.0.0.1", 4242)
            .with_ifac("møøse-net", "nøgle");
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();

        assert_eq!(decoded.name, "København 測試");
        assert_eq!(decoded.ifac_netname.as_deref(), Some("møøse-net"));
        assert_eq!(decoded.ifac_netkey.as_deref(), Some("nøgle"));
        assert!(
            decoded
                .config_entry
                .as_deref()
                .unwrap()
                .contains("[[København 測試]]")
        );
    }

    #[test]
    fn discovery_rnode_roundtrip() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let config = DiscoveryInterfaceConfig::rnode("RNode Device", 868_000_000, 125_000, 7, 5)
            .with_position(Some(55.0), Some(12.0), Some(10.0));
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();

        assert_eq!(decoded.interface_type, "RNodeInterface");
        assert_eq!(decoded.name, "RNode Device");
        assert!(decoded.transport_enabled);
        assert_eq!(decoded.transport_id, transport_id);
        assert_eq!(decoded.reachable_on, None);
        assert_eq!(decoded.port, None);
        assert_eq!(decoded.frequency, Some(868_000_000));
        assert_eq!(decoded.bandwidth, Some(125_000.0));
        assert_eq!(decoded.spreadingfactor, Some(7));
        assert_eq!(decoded.codingrate, Some(5));
        assert!(decoded.config_entry.is_some());
        assert!(decoded.stamp_value >= DEFAULT_STAMP_COST);
    }

    #[test]
    fn discovery_lora_roundtrip() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let config = DiscoveryInterfaceConfig::lora("LoRa Node", 915_000_000, 250_000.0, 10, 6)
            .with_position(Some(55.0), Some(12.0), Some(10.0));
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();

        assert_eq!(decoded.interface_type, "LoRaInterface");
        assert_eq!(decoded.name, "LoRa Node");
        assert!(decoded.transport_enabled);
        assert_eq!(decoded.transport_id, transport_id);
        assert_eq!(decoded.reachable_on, None);
        assert_eq!(decoded.port, None);
        assert_eq!(decoded.frequency, Some(915_000_000));
        assert_eq!(decoded.bandwidth, Some(250_000.0));
        assert_eq!(decoded.spreadingfactor, Some(10));
        assert_eq!(decoded.codingrate, Some(6));
        assert!(decoded.config_entry.is_none());
        assert!(decoded.stamp_value >= DEFAULT_STAMP_COST);
    }

    #[test]
    fn discovery_payload_accepts_utf8_binary_names_from_python() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let info = vec![
            (
                u8_value(KEY_INTERFACE_TYPE),
                Value::Binary(b"TCPServerInterface".to_vec()),
            ),
            (u8_value(KEY_TRANSPORT), Value::Boolean(true)),
            (
                u8_value(KEY_TRANSPORT_ID),
                Value::Binary(transport_id.as_slice().to_vec()),
            ),
            (
                u8_value(KEY_NAME),
                Value::Binary("København 測試".as_bytes().to_vec()),
            ),
            (u8_value(KEY_LATITUDE), Value::Nil),
            (u8_value(KEY_LONGITUDE), Value::Nil),
            (u8_value(KEY_HEIGHT), Value::Nil),
            (
                u8_value(KEY_REACHABLE_ON),
                Value::Binary(b"127.0.0.1".to_vec()),
            ),
            (u8_value(KEY_PORT), Value::from(4242u16)),
        ];
        let app_data = build_test_discovery_app_data(info);

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();
        assert_eq!(decoded.interface_type, "TCPServerInterface");
        assert_eq!(decoded.name, "København 測試");
        assert_eq!(decoded.reachable_on.as_deref(), Some("127.0.0.1"));
    }

    fn build_test_discovery_app_data(info: Vec<(Value, Value)>) -> PacketDataBuffer {
        let mut packed = Vec::new();
        write_value(&mut packed, &Value::Map(info)).unwrap();
        let infohash = Hash::new_from_slice(&packed);
        let stamp = generate_stamp(
            infohash.as_slice(),
            DEFAULT_STAMP_COST,
            WORKBLOCK_EXPAND_ROUNDS,
        )
        .unwrap();

        let mut app_data = PacketDataBuffer::new();
        app_data.write(&[0u8]);
        app_data.write(&packed);
        app_data.write(&stamp);
        app_data
    }

    /// Build a discovery app_data blob whose embedded stamp has exactly
    /// `difficulty` leading zero bits, independent of `DEFAULT_STAMP_COST`.
    fn build_discovery_app_data_with_difficulty(
        info: Vec<(Value, Value)>,
        difficulty: u8,
    ) -> PacketDataBuffer {
        let mut packed = Vec::new();
        write_value(&mut packed, &Value::Map(info)).unwrap();
        let infohash = Hash::new_from_slice(&packed);
        let workblock = stamp_workblock(infohash.as_slice(), WORKBLOCK_EXPAND_ROUNDS).unwrap();
        let stamp = stamp_with_exact_difficulty(&workblock, difficulty);

        let mut app_data = PacketDataBuffer::new();
        app_data.write(&[0u8]);
        app_data.write(&packed);
        app_data.write(&stamp);
        app_data
    }

    /// Brute-force a random stamp whose `count_leading_zero_bits` value is
    /// exactly `difficulty`.
    fn stamp_with_exact_difficulty(workblock: &StaticBuffer<8192>, difficulty: u8) -> [u8; HASH_SIZE] {
        let mut rng = UnwrapErr(SysRng);
        loop {
            let mut stamp = [0u8; HASH_SIZE];
            rng.fill_bytes(&mut stamp);
            let value = count_leading_zero_bits(
                Hash::generator()
                    .chain_update(workblock.as_slice())
                    .chain_update(&stamp)
                    .finalize()
                    .as_slice(),
            );
            if value == difficulty {
                return stamp;
            }
        }
    }

    fn discovery_info(transport_id: &AddressHash, name: &str) -> Vec<(Value, Value)> {
        vec![
            (
                u8_value(KEY_INTERFACE_TYPE),
                Value::from("TCPServerInterface"),
            ),
            (u8_value(KEY_TRANSPORT), Value::Boolean(true)),
            (
                u8_value(KEY_TRANSPORT_ID),
                Value::Binary(transport_id.as_slice().to_vec()),
            ),
            (u8_value(KEY_NAME), Value::from(name)),
            (u8_value(KEY_LATITUDE), Value::Nil),
            (u8_value(KEY_LONGITUDE), Value::Nil),
            (u8_value(KEY_HEIGHT), Value::Nil),
            (u8_value(KEY_REACHABLE_ON), Value::from("127.0.0.1")),
            (u8_value(KEY_PORT), Value::from(4242u16)),
        ]
    }

    /// A discovery stamp with difficulty 14 (the old Rust default) must be
    /// rejected by the Python-compatible default required value of 16.
    #[test]
    fn weak_stamp_rejected_at_python_compatible_difficulty() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let app_data = build_discovery_app_data_with_difficulty(
            discovery_info(&transport_id, "Weak Stamp Node"),
            14,
        );

        let result = DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice());
        assert!(
            matches!(result, Err(RnsError::IncorrectSignature)),
            "stamp with difficulty 14 must be rejected at the default required value of 16"
        );
    }

    /// A discovery stamp with the Python-compatible difficulty of 16 is
    /// accepted, and its reported value reflects the actual difficulty.
    #[test]
    fn strong_stamp_accepted_at_python_compatible_difficulty() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let app_data = build_discovery_app_data_with_difficulty(
            discovery_info(&transport_id, "Strong Stamp Node"),
            16,
        );

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();
        assert_eq!(decoded.name, "Strong Stamp Node");
        assert!(decoded.stamp_value >= DEFAULT_STAMP_COST);
    }

    /// A discovery announce whose transport_id differs from the announced
    /// source identity must still be accepted.  Python announces the
    /// discovery destination under the network identity while embedding the
    /// transport identity as TRANSPORT_ID; the two are independent fields
    /// and must not be required to match.
    #[test]
    fn transport_id_independent_from_announce_identity() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = AddressHash::new([0x42; 16]);

        let app_data = build_discovery_app_data_with_difficulty(
            discovery_info(&transport_id, "Network Identity Node"),
            16,
        );

        let decoded =
            DiscoveredInterface::from_announce(source_desc, 1, app_data.as_slice()).unwrap();
        assert_eq!(decoded.name, "Network Identity Node");
        assert_eq!(decoded.transport_id, transport_id);
        assert_ne!(decoded.transport_id, source_desc.identity.address_hash);
    }

    /// The required value is configurable: a stamp with difficulty 14 is
    /// accepted when the listener explicitly requires a lower value.
    #[test]
    fn weak_stamp_accepted_when_required_value_is_lowered() {
        let identity = PrivateIdentity::new_from_name("discovery");
        let source_desc = create_discovery_destination(identity).desc;
        let transport_id = source_desc.identity.address_hash;

        let app_data = build_discovery_app_data_with_difficulty(
            discovery_info(&transport_id, "Weak Stamp Node"),
            14,
        );

        let decoded = DiscoveredInterface::from_announce_with_required_value(
            source_desc,
            1,
            app_data.as_slice(),
            14,
        )
        .unwrap();
        assert_eq!(decoded.name, "Weak Stamp Node");
    }
}
