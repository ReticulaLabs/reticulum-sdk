use std::cmp;
use std::fmt::Write as _;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::OutputBuffer;
use crate::error::RnsError;
use crate::iface::{
    decode_rx, encode_tx, CONNECT_TIMEOUT, DEFAULT_HW_MTU, INITIAL_RECONNECT_BACKOFF, Interface,
    InterfaceContext, InterfaceMode, MAX_AUTOCONFIGURED_HW_MTU, MAX_RECONNECT_BACKOFF, RxMessage,
    configured_bitrate, set_tcp_sockopts,
};
use crate::packet::{Header, HeaderType, RETICULUM_HEADER_MINSIZE, RETICULUM_MAX_HEADER_SIZE};

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
const DECODE_FAILURE_HEX_PREVIEW_LEN: usize = 96;
const TCP_READ_BUFFER_SIZE: usize = 16 * 1024;

pub struct TcpClient {
    addr: String,
    stream: Option<TcpStream>,
    bitrate: Option<f64>,
    mode: InterfaceMode,
}

impl TcpClient {
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
            bitrate: None,
            mode: InterfaceMode::Full,
        }
    }

    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
            bitrate: None,
            mode: InterfaceMode::Full,
        }
    }

    pub fn with_bitrate(mut self, bitrate: f64) -> Self {
        self.bitrate = configured_bitrate(bitrate);
        self
    }

    pub fn with_interface_mode(mut self, mode: InterfaceMode) -> Self {
        self.mode = mode;
        self
    }

    pub(crate) fn with_optional_bitrate(mut self, bitrate: Option<f64>) -> Self {
        self.bitrate = bitrate;
        self
    }

    pub async fn spawn(context: InterfaceContext<TcpClient>) {
        let iface_stop = context.channel.stop.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_address = context.channel.address;
        let mut stream = { context.inner.lock().unwrap().stream.take() };
        let ifac_config = context.channel.ifac_config();

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
                    // Connect to completion without draining the transmit
                    // channel. Previously, outbound traffic arriving while
                    // the connect was in flight would fire a
                    // `tx_channel.recv()` branch, aborting the connect and
                    // restarting it from scratch (and dropping the message).
                    // Messages now simply queue in the bounded tx channel
                    // and are drained by the transmit task once the
                    // connection is established.
                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => {
                            break;
                        }
                        result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr.clone())) => {
                            match result {
                                Ok(Ok(stream)) => Ok(stream),
                                Ok(Err(_)) | Err(_) => Err(RnsError::ConnectionError),
                            }
                        }
                    }
                }
            };

            if let Err(_) = stream {
                log::info!(
                    "tcp_client: couldn't connect to <{}>, retrying in {}s",
                    addr,
                    reconnect_backoff.as_secs()
                );
                let delay = reconnect_backoff;
                reconnect_backoff =
                    cmp::min(reconnect_backoff.saturating_mul(2), MAX_RECONNECT_BACKOFF);

                if super::wait_to_reconnect(&context.cancel, &tx_channel, delay).await {
                    break 'outer;
                }
                continue;
            }

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let stream = stream.unwrap();
            set_tcp_sockopts(&stream);
            let connected_at = tokio::time::Instant::now();
            let (read_stream, write_stream) = stream.into_split();

            log::info!("tcp_client connected to <{}>", addr);

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mut stream = read_stream;
                let rx_channel = rx_channel.clone();
                let rx_addr = addr.clone();
                let ifac_config = ifac_config.clone();

                tokio::spawn(async move {
                    let mut frame_buffer = Vec::with_capacity(DEFAULT_HW_MTU);
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
                                            log::warn!("tcp_client: connection closed");
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
                                                                "tcp_client: ignored short hdlc frame iface={} peer=<{}> tcp_read_len={} hdlc_frame={}..{} hdlc_frame_len={} decoded_len={} min_decoded_len={} decoded_preview={}",
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

                                                        match decode_rx(ifac_config.as_ref(), decoded) {
                                                            Ok(packet) => {
                                                                if PACKET_TRACE {
                                                                    log::trace!("tcp_client: rx << ({}) {}", iface_address, packet);
                                                                }
                                                                let _ = rx_channel.send(RxMessage { address: iface_address, snr: None, rssi: None, packet }).await;
                                                            }
                                                            Err(err) => {
                                                                log::warn!(
                                                                    "tcp_client: couldn't decode packet iface={} peer=<{}> tcp_read_len={} hdlc_frame={}..{} hdlc_frame_len={} decoded_len={} min_decoded_len={} first_byte={} header_hint={} decoded_preview={}",
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
                                                                    "tcp_client: packet decode error iface={} peer=<{}> error={:?}",
                                                                    iface_address,
                                                                    rx_addr,
                                                                    err,
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(err) => {
                                                        log::warn!(
                                                            "tcp_client: couldn't decode hdlc frame iface={} peer=<{}> tcp_read_len={} hdlc_frame={}..{} hdlc_frame_len={} error={:?} frame_preview={}",
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
                                                    "tcp_client: dropping oversized partial hdlc frame iface={} peer=<{}> buffered_len={} max_len={}",
                                                    iface_address,
                                                    rx_addr,
                                                    frame_buffer.len(),
                                                    MAX_AUTOCONFIGURED_HW_MTU,
                                                );
                                                frame_buffer.clear();
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("tcp_client: connection error {}", e);
                                            stop.cancel();
                                            break;
                                        }
                                    }
                                },
                        };
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let mut stream = write_stream;
                let ifac_config = ifac_config.clone();

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
                                    log::trace!("tcp_client: tx >> ({}) {}", iface_address, packet);
                                }
                                if let Ok(len) = encode_tx(ifac_config.as_ref(), &packet, &mut tx_buffer[..]) {

                                    let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);

                                    if let Ok(_) = Hdlc::encode(&tx_buffer[..len], &mut hdlc_output) {
                                        if let Err(_) = stream.write_all(hdlc_output.as_slice()).await {
                                            stop.cancel();
                                            break;
                                        }
                                        if let Err(_) = stream.flush().await {
                                            stop.cancel();
                                            break;
                                        }
                                    }
                                }
                            }
                        };
                    }
                })
            };

            let _ = tx_task.await;
            let _ = rx_task.await;

            log::info!("tcp_client: disconnected from <{}>", addr);

            // A connection provided by a parent (e.g. an accepted
            // TcpServer client) is one-shot: tear down instead of
            // reconnecting.
            if !running {
                break 'outer;
            }

            // Reconnecting immediately after a dropped connection can turn
            // accept-then-drop peers into a reconnect storm.  Apply the
            // same 1s→30s exponential backoff used for failed connections,
            // resetting it after a connection that stayed up long enough to
            // be considered stable.
            let delay = super::reconnect_backoff_after_drop(
                connected_at,
                &mut reconnect_backoff,
                INITIAL_RECONNECT_BACKOFF,
                MAX_RECONNECT_BACKOFF,
            );

            if super::wait_to_reconnect(&context.cancel, &tx_channel, delay).await {
                break 'outer;
            }
        }

        iface_stop.cancel();
    }
}

impl Interface for TcpClient {
    fn hw_mtu(&self) -> usize {
        DEFAULT_HW_MTU
    }

    fn bitrate(&self) -> Option<f64> {
        self.bitrate
    }

    fn interface_mode(&self) -> InterfaceMode {
        self.mode
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
    fn bitrate_defaults_to_unreported() {
        assert_eq!(TcpClient::new("127.0.0.1:0").bitrate(), None);
    }

    #[test]
    fn bitrate_can_be_configured() {
        assert_eq!(
            TcpClient::new("127.0.0.1:0")
                .with_bitrate(1_000_000.0)
                .bitrate(),
            Some(1_000_000.0)
        );
    }

    #[test]
    fn invalid_bitrate_is_not_reported() {
        assert_eq!(
            TcpClient::new("127.0.0.1:0").with_bitrate(0.0).bitrate(),
            None
        );
        assert_eq!(
            TcpClient::new("127.0.0.1:0")
                .with_bitrate(f64::INFINITY)
                .bitrate(),
            None
        );
    }
}
