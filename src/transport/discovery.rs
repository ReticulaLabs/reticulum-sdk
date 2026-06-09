use std::time::Duration;

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use rmpv::{decode::read_value, encode::write_value, Value};
use sha2::{Digest, Sha256};
use tokio::time;

use crate::{
    buffer::StaticBuffer,
    destination::{DestinationDesc, DestinationName, SingleInputDestination},
    error::RnsError,
    hash::{AddressHash, Hash, HASH_SIZE},
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

pub const DISCOVERY_APP_NAME: &str = "rnstransport";
pub const DISCOVERY_ASPECTS: &str = "discovery.interface";
pub const DISCOVERY_JOB_INTERVAL: Duration = Duration::from_secs(60);
pub const DISCOVERY_MIN_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const DISCOVERY_DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

const DEFAULT_STAMP_COST: u8 = 14;
const WORKBLOCK_EXPAND_ROUNDS: usize = 20;
const FLAG_SIGNED: u8 = 0b0000_0001;
const FLAG_ENCRYPTED: u8 = 0b0000_0010;

#[derive(Clone, Debug)]
pub enum DiscoveryInterfaceKind {
    TcpServer { reachable_on: String, port: u16 },
}

impl DiscoveryInterfaceKind {
    fn interface_type(&self) -> &'static str {
        match self {
            Self::TcpServer { .. } => "TCPServerInterface",
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
            DiscoveryInterfaceKind::TcpServer { reachable_on, port } => {
                info.push((
                    u8_value(KEY_REACHABLE_ON),
                    Value::from(reachable_on.as_str()),
                ));
                info.push((u8_value(KEY_PORT), Value::from(*port)));
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
        payload.write(&[0u8])?;
        payload.write(&packed)?;
        payload.write(&stamp)?;
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
}

impl DiscoveredInterface {
    pub fn from_announce(
        source: DestinationDesc,
        hops: u8,
        app_data: &[u8],
    ) -> Result<Self, RnsError> {
        if app_data.len() <= HASH_SIZE + 1 {
            return Err(RnsError::PacketError);
        }

        let flags = app_data[0];
        if flags & FLAG_SIGNED != 0 {
            return Err(RnsError::PacketError);
        }
        if flags & FLAG_ENCRYPTED != 0 {
            return Err(RnsError::PacketError);
        }

        let stamp_start = app_data.len() - HASH_SIZE;
        let packed = &app_data[1..stamp_start];
        let stamp = &app_data[stamp_start..];

        let infohash = Hash::new_from_slice(packed);
        let workblock = stamp_workblock(infohash.as_slice(), WORKBLOCK_EXPAND_ROUNDS)?;
        if !stamp_valid(stamp, DEFAULT_STAMP_COST, &workblock) {
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

    loop {
        let mut stamp = [0u8; HASH_SIZE];
        OsRng.fill_bytes(&mut stamp);

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
        let config = DiscoveryInterfaceConfig::tcp_server("Rust Node", "127.0.0.1", 4242)
            .with_position(Some(55.0), Some(12.0), Some(10.0))
            .with_ifac("mesh", "shared-secret");
        let transport_id = AddressHash::new_from_slice(b"transport-id");
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let source = create_discovery_destination(PrivateIdentity::new_from_name("discovery")).desc;
        let decoded = DiscoveredInterface::from_announce(source, 1, app_data.as_slice()).unwrap();

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
    fn discovery_payload_accepts_unicode_names() {
        let config = DiscoveryInterfaceConfig::tcp_server("København 測試", "127.0.0.1", 4242)
            .with_ifac("møøse-net", "nøgle");
        let transport_id = AddressHash::new_from_slice(b"transport-id");
        let app_data = config.build_app_data(true, &transport_id).unwrap();

        let source = create_discovery_destination(PrivateIdentity::new_from_name("discovery")).desc;
        let decoded = DiscoveredInterface::from_announce(source, 1, app_data.as_slice()).unwrap();

        assert_eq!(decoded.name, "København 測試");
        assert_eq!(decoded.ifac_netname.as_deref(), Some("møøse-net"));
        assert_eq!(decoded.ifac_netkey.as_deref(), Some("nøgle"));
        assert!(decoded
            .config_entry
            .as_deref()
            .unwrap()
            .contains("[[København 測試]]"));
    }

    #[test]
    fn discovery_payload_accepts_utf8_binary_names_from_python() {
        let transport_id = AddressHash::new_from_slice(b"transport-id");
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

        let source = create_discovery_destination(PrivateIdentity::new_from_name("discovery")).desc;
        let decoded = DiscoveredInterface::from_announce(source, 1, app_data.as_slice()).unwrap();
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
        app_data.write(&[0u8]).unwrap();
        app_data.write(&packed).unwrap();
        app_data.write(&stamp).unwrap();
        app_data
    }
}
