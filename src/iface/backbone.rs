use std::cmp;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::{
    configured_bitrate, Interface, InterfaceContext, RxMessage, MAX_AUTOCONFIGURED_HW_MTU,
};
use crate::packet::{
    Header, HeaderType, Packet, RETICULUM_HEADER_MINSIZE, RETICULUM_MAX_HEADER_SIZE,
};
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;

const PACKET_TRACE: bool = false;
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
const DECODE_FAILURE_HEX_PREVIEW_LEN: usize = 96;
const TCP_READ_BUFFER_SIZE: usize = 64 * 1024;

pub const BACKBONE_DEFAULT_HW_MTU: usize = 1_048_576;
pub const BACKBONE_DEFAULT_BITRATE: f64 = 1_000_000_000.0;

/// Server-side listening interface modeled after Python's `BackboneInterface`.
/// Accepts incoming TCP connections and spawns `BackboneClient` handlers.
/// Designed for high throughput with no connection limit.
pub struct BackboneServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<crate::iface::InterfaceManager>>,
    listener: Option<std::net::TcpListener>,
    bitrate: Option<f64>,
    hw_mtu: usize,
    ifac_netname: Option<String>,
    ifac_netkey: Option<String>,
}

impl BackboneServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<crate::iface::InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            listener: None,
            bitrate: configured_bitrate(BACKBONE_DEFAULT_BITRATE),
            hw_mtu: BACKBONE_DEFAULT_HW_MTU,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn new_from_listener<T: Into<String>>(
        addr: T,
        listener: std::net::TcpListener,
        iface_manager: Arc<tokio::sync::Mutex<crate::iface::InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            listener: Some(listener),
            bitrate: configured_bitrate(BACKBONE_DEFAULT_BITRATE),
            hw_mtu: BACKBONE_DEFAULT_HW_MTU,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn with_bitrate(mut self, bitrate: f64) -> Self {
        self.bitrate = configured_bitrate(bitrate);
        self
    }

    pub fn with_hw_mtu(mut self, mtu: usize) -> Self {
        self.hw_mtu = mtu;
        self
    }

    pub fn with_ifac(mut self, netname: Option<String>, netkey: Option<String>) -> Self {
        self.ifac_netname = netname;
        self.ifac_netkey = netkey;
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let mut listener = { context.inner.lock().unwrap().listener.take() };
        let bitrate = { context.inner.lock().unwrap().bitrate };
        let hw_mtu = { context.inner.lock().unwrap().hw_mtu };
        let ifac_netname = { context.inner.lock().unwrap().ifac_netname.clone() };
        let ifac_netkey = { context.inner.lock().unwrap().ifac_netkey.clone() };

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = match listener.take() {
                Some(listener) => listener
                    .set_nonblocking(true)
                    .map(|_| listener)
                    .map_err(|_| RnsError::ConnectionError)
                    .and_then(|listener| {
                        tokio::net::TcpListener::from_std(listener)
                            .map_err(|_| RnsError::ConnectionError)
                    }),
                None => tokio::net::TcpListener::bind(addr.clone())
                    .await
                    .map_err(|_| RnsError::ConnectionError),
            };

            if let Err(_) = listener {
                log::warn!("backbone_server: couldn't bind to <{}>", addr);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            log::info!("backbone_server: listen on <{}>", addr);

            let listener = listener.unwrap();

            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            let cancel = context.cancel.clone();

            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }
                    client = listener.accept() => {
                        if let Ok(client) = client {
                            log::info!(
                                "backbone_server: new client <{}> connected to <{}>",
                                client.1,
                                addr,
                            );

                            let mut iface_manager = iface_manager.lock().await;

                            iface_manager.spawn(
                                BackboneClient::new_from_stream(client.1.to_string(), client.0)
                                    .with_optional_bitrate(bitrate)
                                    .with_hw_mtu(hw_mtu)
                                    .with_ifac(ifac_netname.clone(), ifac_netkey.clone()),
                                |context| async move {
                                    BackboneClient::spawn(context).await;
                                },
                            );
                        }
                    }
                }
            }

            let _ = tokio::join!(tx_task);
        }
    }
}

impl Interface for BackboneServer {
    fn hw_mtu(&self) -> usize {
        self.hw_mtu
    }

    fn bitrate(&self) -> Option<f64> {
        self.bitrate
    }

    fn autoconfigure_mtu(&self) -> bool {
        true
    }
}

/// Per-connection client handler for the BackboneInterface.
/// Used for both server-accepted (incoming) and client-initiated (outgoing) connections.
pub struct BackboneClient {
    addr: String,
    stream: Option<TcpStream>,
    bitrate: Option<f64>,
    hw_mtu: usize,
    ifac_netname: Option<String>,
    ifac_netkey: Option<String>,
}

impl BackboneClient {
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
            bitrate: configured_bitrate(BACKBONE_DEFAULT_BITRATE),
            hw_mtu: BACKBONE_DEFAULT_HW_MTU,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
            bitrate: configured_bitrate(BACKBONE_DEFAULT_BITRATE),
            hw_mtu: BACKBONE_DEFAULT_HW_MTU,
            ifac_netname: None,
            ifac_netkey: None,
        }
    }

    pub fn with_bitrate(mut self, bitrate: f64) -> Self {
        self.bitrate = configured_bitrate(bitrate);
        self
    }

    pub(crate) fn with_optional_bitrate(mut self, bitrate: Option<f64>) -> Self {
        self.bitrate = bitrate;
        self
    }

    pub fn with_hw_mtu(mut self, mtu: usize) -> Self {
        self.hw_mtu = mtu;
        self
    }

    pub fn with_ifac(mut self, netname: Option<String>, netkey: Option<String>) -> Self {
        self.ifac_netname = netname;
        self.ifac_netkey = netkey;
        self
    }

    pub async fn spawn(context: InterfaceContext<BackboneClient>) {
        let iface_stop = context.channel.stop.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_address = context.channel.address;
        let mut stream = { context.inner.lock().unwrap().stream.take() };

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));
        let mut reconnect_backoff = INITIAL_RECONNECT_BACKOFF;

        let mut running = true;
        'outer: loop {
            if !running || context.cancel.is_cancelled() {
                break;
            }

            let stream = match stream.take() {
                Some(stream) => {
                    running = false;
                    Ok(stream)
                }
                None => {
                    let mut tx_channel = tx_channel.lock().await;

                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => {
                            break;
                        }
                        result = TcpStream::connect(addr.clone()) => {
                            result.map_err(|_| RnsError::ConnectionError)
                        }
                        Some(_) = tx_channel.recv() => {
                            continue;
                        }
                    }
                }
            };

            if let Err(_) = stream {
                log::info!(
                    "backbone_client: couldn't connect to <{}>, retrying in {}s",
                    addr,
                    reconnect_backoff.as_secs(),
                );
                let retry_at = tokio::time::Instant::now() + reconnect_backoff;
                reconnect_backoff =
                    cmp::min(reconnect_backoff.saturating_mul(2), MAX_RECONNECT_BACKOFF);

                loop {
                    let mut tx_channel = tx_channel.lock().await;

                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => {
                            break 'outer;
                        }
                        _ = tokio::time::sleep_until(retry_at) => {
                            break;
                        }
                        Some(_) = tx_channel.recv() => {}
                    }
                }
                continue;
            }

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let stream = stream.unwrap();
            reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
            let (read_stream, write_stream) = stream.into_split();

            log::info!("backbone_client connected to <{}>", addr);

            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mut stream = read_stream;
                let rx_channel = rx_channel.clone();
                let rx_addr = addr.clone();

                tokio::spawn(async move {
                    let mut frame_buffer = Vec::with_capacity(TCP_READ_BUFFER_SIZE);
                    let mut hdlc_rx_buffer = Vec::new();
                    let mut tcp_buffer = [0u8; TCP_READ_BUFFER_SIZE];

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            _ = stop.cancelled() => {
                                break;
                            }
                            result = stream.read(&mut tcp_buffer[..]) => {
                                match result {
                                    Ok(0) => {
                                        log::warn!("backbone_client: connection closed");
                                        stop.cancel();
                                        break;
                                    }
                                    Ok(n) => {
                                        frame_buffer.extend_from_slice(&tcp_buffer[..n]);

                                        while let Some(frame) = Hdlc::find(&frame_buffer[..]) {
                                            let frame_bytes = frame_buffer[frame.0..frame.1 + 1].to_vec();
                                            frame_buffer.drain(..frame.1 + 1);

                                            hdlc_rx_buffer.resize(frame_bytes.len(), 0);
                                            let mut output = OutputBuffer::new(&mut hdlc_rx_buffer[..]);
                                            match Hdlc::decode(&frame_bytes, &mut output) {
                                                Ok(decoded_len) => {
                                                    let decoded = output.as_slice();
                                                    let min_decoded_len = minimum_decoded_packet_len(decoded);
                                                    if decoded_len < min_decoded_len {
                                                        log::trace!(
                                                            "backbone_client: ignored short hdlc frame iface={} peer=<{}> tcp_read_len={} hdlc_frame={}..{} hdlc_frame_len={} decoded_len={} min_decoded_len={} decoded_preview={}",
                                                            iface_address,
                                                            rx_addr,
                                                            n,
                                                            frame.0,
                                                            frame.1,
                                                            frame.1 - frame.0 + 1,
                                                            decoded_len,
                                                            min_decoded_len,
                                                            hex_preview(decoded, DECODE_FAILURE_HEX_PREVIEW_LEN),
                                                        );
                                                        continue;
                                                    }

                                                    match Packet::deserialize(&mut InputBuffer::new(decoded)) {
                                                        Ok(packet) => {
                                                            if PACKET_TRACE {
                                                                log::trace!("backbone_client: rx << ({}) {}", iface_address, packet);
                                                            }
                                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                        }
                                                        Err(err) => {
                                                            log::warn!(
                                                                "backbone_client: couldn't decode packet iface={} peer=<{}> tcp_read_len={} hdlc_frame={}..{} hdlc_frame_len={} decoded_len={} min_decoded_len={} first_byte={} header_hint={} decoded_preview={}",
                                                                iface_address,
                                                                rx_addr,
                                                                n,
                                                                frame.0,
                                                                frame.1,
                                                                frame.1 - frame.0 + 1,
                                                                decoded_len,
                                                                min_decoded_len,
                                                                first_byte_hex(decoded),
                                                                header_hint(decoded),
                                                                hex_preview(decoded, DECODE_FAILURE_HEX_PREVIEW_LEN),
                                                            );
                                                            log::trace!(
                                                                "backbone_client: packet decode error iface={} peer=<{}> error={:?}",
                                                                iface_address,
                                                                rx_addr,
                                                                err,
                                                            );
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    log::warn!(
                                                        "backbone_client: couldn't decode hdlc frame iface={} peer=<{}> tcp_read_len={} hdlc_frame={}..{} hdlc_frame_len={} error={:?} frame_preview={}",
                                                        iface_address,
                                                        rx_addr,
                                                        n,
                                                        frame.0,
                                                        frame.1,
                                                        frame.1 - frame.0 + 1,
                                                        err,
                                                        hex_preview(&frame_bytes, DECODE_FAILURE_HEX_PREVIEW_LEN),
                                                    );
                                                }
                                            }
                                        }

                                        if frame_buffer.len() > MAX_AUTOCONFIGURED_HW_MTU {
                                            log::warn!(
                                                "backbone_client: dropping oversized partial hdlc frame iface={} peer=<{}> buffered_len={} max_len={}",
                                                iface_address,
                                                rx_addr,
                                                frame_buffer.len(),
                                                MAX_AUTOCONFIGURED_HW_MTU,
                                            );
                                            frame_buffer.clear();
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("backbone_client: connection error {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                })
            };

            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let mut stream = write_stream;

                tokio::spawn(async move {
                    let mut hdlc_tx_buffer = vec![0u8; MAX_AUTOCONFIGURED_HW_MTU + 2];
                    let mut tx_buffer = vec![0u8; MAX_AUTOCONFIGURED_HW_MTU];

                    loop {
                        if stop.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            _ = stop.cancelled() => {
                                break;
                            }
                            Some(message) = tx_channel.recv() => {
                                let packet = message.packet;
                                if PACKET_TRACE {
                                    log::trace!("backbone_client: tx >> ({}) {}", iface_address, packet);
                                }
                                let mut output = OutputBuffer::new(&mut tx_buffer[..]);
                                if let Ok(_) = packet.serialize(&mut output) {
                                    let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);
                                    if let Ok(_) = Hdlc::encode(output.as_slice(), &mut hdlc_output) {
                                        let _ = stream.write_all(hdlc_output.as_slice()).await;
                                        let _ = stream.flush().await;
                                    }
                                }
                            }
                        }
                    }
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            log::info!("backbone_client: disconnected from <{}>", addr);
        }

        iface_stop.cancel();
    }
}

impl Interface for BackboneClient {
    fn hw_mtu(&self) -> usize {
        self.hw_mtu
    }

    fn bitrate(&self) -> Option<f64> {
        self.bitrate
    }

    fn autoconfigure_mtu(&self) -> bool {
        true
    }
}

fn first_byte_hex(data: &[u8]) -> String {
    match data.first() {
        Some(byte) => format!("0x{byte:02x}"),
        None => "none".to_owned(),
    }
}

fn header_hint(data: &[u8]) -> String {
    match data.first() {
        Some(byte) => {
            let mut header = Header::from_meta(*byte);
            if let Some(hops) = data.get(1) {
                header.hops = *hops;
            }
            format!("{header:?}")
        }
        None => "none".to_owned(),
    }
}

fn minimum_decoded_packet_len(data: &[u8]) -> usize {
    match data.first() {
        Some(byte) if Header::from_meta(*byte).header_type == HeaderType::Type2 => {
            RETICULUM_MAX_HEADER_SIZE
        }
        _ => RETICULUM_HEADER_MINSIZE + 1,
    }
}

fn hex_preview(data: &[u8], max_len: usize) -> String {
    let preview_len = data.len().min(max_len);
    let mut preview = String::with_capacity(preview_len.saturating_mul(3) + 24);

    for (index, byte) in data.iter().take(preview_len).enumerate() {
        if index > 0 {
            preview.push(' ');
        }
        let _ = write!(&mut preview, "{byte:02x}");
    }

    if data.len() > preview_len {
        let _ = write!(&mut preview, " ... +{} bytes", data.len() - preview_len);
    }

    preview
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitrate_defaults_to_one_gbps() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(crate::iface::InterfaceManager::new(
            1,
        )));
        let server = BackboneServer::new("127.0.0.1:0", iface_manager);
        assert_eq!(server.bitrate(), Some(BACKBONE_DEFAULT_BITRATE));
    }

    #[test]
    fn bitrate_can_be_configured() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(crate::iface::InterfaceManager::new(
            1,
        )));
        let server = BackboneServer::new("127.0.0.1:0", iface_manager)
            .with_bitrate(100_000_000.0);
        assert_eq!(server.bitrate(), Some(100_000_000.0));
    }

    #[test]
    fn hw_mtu_defaults_to_one_mib() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(crate::iface::InterfaceManager::new(
            1,
        )));
        let server = BackboneServer::new("127.0.0.1:0", iface_manager);
        assert_eq!(server.hw_mtu(), BACKBONE_DEFAULT_HW_MTU);
    }

    #[test]
    fn hw_mtu_can_be_configured() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(crate::iface::InterfaceManager::new(
            1,
        )));
        let server = BackboneServer::new("127.0.0.1:0", iface_manager).with_hw_mtu(2048);
        assert_eq!(server.hw_mtu(), 2048);
    }

    #[test]
    fn client_bitrate_defaults_to_one_gbps() {
        let client = BackboneClient::new("127.0.0.1:0");
        assert_eq!(client.bitrate(), Some(BACKBONE_DEFAULT_BITRATE));
    }

    #[test]
    fn client_hw_mtu_defaults_to_one_mib() {
        let client = BackboneClient::new("127.0.0.1:0");
        assert_eq!(client.hw_mtu(), BACKBONE_DEFAULT_HW_MTU);
    }
}
