use std::cmp;
use std::fmt::Write as _;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::{
    DEFAULT_HW_MTU, Interface, InterfaceContext, MAX_AUTOCONFIGURED_HW_MTU, RxMessage,
    configured_bitrate,
};
use crate::packet::{
    Header, HeaderType, Packet, RETICULUM_HEADER_MINSIZE, RETICULUM_MAX_HEADER_SIZE,
};
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

fn set_tcp_sockopts(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);

    #[cfg(target_os = "linux")]
    {
        let fd = stream.as_raw_fd();
        let on: libc::c_int = 1;
        let idle: libc::c_int = 5;
        let intvl: libc::c_int = 2;
        let cnt: libc::c_int = 12;
        let uto: libc::c_int = 24_000;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &idle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                &intvl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                &cnt as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &uto as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

use super::hdlc::Hdlc;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
const DECODE_FAILURE_HEX_PREVIEW_LEN: usize = 96;
const TCP_READ_BUFFER_SIZE: usize = 16 * 1024;

pub struct TcpClient {
    addr: String,
    stream: Option<TcpStream>,
    bitrate: Option<f64>,
}

impl TcpClient {
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
            bitrate: None,
        }
    }

    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
            bitrate: None,
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

    pub async fn spawn(context: InterfaceContext<TcpClient>) {
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
                    "tcp_client: couldn't connect to <{}>, retrying in {}s",
                    addr,
                    reconnect_backoff.as_secs()
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
            set_tcp_sockopts(&stream);
            reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
            let (read_stream, write_stream) = stream.into_split();

            log::info!("tcp_client connected to <{}>", addr);

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mut stream = read_stream;
                let rx_channel = rx_channel.clone();
                let rx_addr = addr.clone();

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

                                                        match Packet::deserialize(&mut InputBuffer::new(decoded)) {
                                                            Ok(packet) => {
                                                                if PACKET_TRACE {
                                                                    log::trace!("tcp_client: rx << ({}) {}", iface_address, packet);
                                                                }
                                                                let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
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
                                let mut output = OutputBuffer::new(&mut tx_buffer[..]);
                                if let Ok(_) = packet.serialize(&mut output) {

                                    let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);

                                    if let Ok(_) = Hdlc::encode(output.as_slice(), &mut hdlc_output) {
                                        let _ = stream.write_all(hdlc_output.as_slice()).await;
                                        let _ = stream.flush().await;
                                    }
                                }
                            }
                        };
                    }
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            log::info!("tcp_client: disconnected from <{}>", addr);
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
