use std::io;
use std::sync::Arc;

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::hdlc::Hdlc;
use crate::iface::{Interface, InterfaceContext, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

const HW_MTU: usize = 564;
const MAX_CHUNK: usize = 32_768;
const DEFAULT_SPEED: u32 = 9_600;
const FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
const STARTUP_DELAY: std::time::Duration = std::time::Duration::from_secs(2);
const BYTE_POLL_SLEEP: std::time::Duration = std::time::Duration::from_millis(80);

const PACKET_TRACE: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialParity {
    None,
    Even,
    Odd,
}

#[derive(Debug, Clone)]
pub struct SerialInterface {
    port: String,
    speed: u32,
    databits: u8,
    parity: SerialParity,
    stopbits: u8,
    compatibility_mode: bool,
}

impl SerialInterface {
    pub fn new<T: Into<String>>(port: T) -> Self {
        Self {
            port: port.into(),
            speed: DEFAULT_SPEED,
            databits: 8,
            parity: SerialParity::None,
            stopbits: 1,
            compatibility_mode: false,
        }
    }

    pub fn with_serial_params(
        mut self,
        speed: u32,
        databits: u8,
        parity: SerialParity,
        stopbits: u8,
    ) -> Self {
        self.speed = speed;
        self.databits = databits;
        self.parity = parity;
        self.stopbits = stopbits;
        self
    }

    pub fn with_compatibility_mode(mut self, enabled: bool) -> Self {
        self.compatibility_mode = enabled;
        self
    }

    #[cfg(unix)]
    fn open_port(&self) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(&self.port)?;
        configure_serial_fd(
            file.as_raw_fd(),
            self.speed,
            self.databits,
            self.parity,
            self.stopbits,
        )?;
        Ok(file)
    }

    #[cfg(not(unix))]
    fn open_port(&self) -> io::Result<File> {
        let _ = self;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SerialInterface is only implemented on Unix",
        ))
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let iface_address = context.channel.address;
        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let config = { context.inner.lock().unwrap().clone() };
            let serial = match config.open_port() {
                Ok(serial) => tokio::fs::File::from_std(serial),
                Err(e) => {
                    log::info!(
                        "serial_interface: couldn't open serial port <{}>: {}, retrying in {}s",
                        config.port,
                        e,
                        RECONNECT_DELAY.as_secs()
                    );
                    tokio::select! {
                        _ = context.cancel.cancelled() => break,
                        _ = tokio::time::sleep(RECONNECT_DELAY) => continue,
                    }
                }
            };

            tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = tokio::time::sleep(STARTUP_DELAY) => {}
            }

            log::info!("serial_interface: serial port <{}> is open", config.port);

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();
            let (read_serial, write_serial) = tokio::io::split(serial);

            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();

                tokio::spawn(async move {
                    if config.compatibility_mode {
                        read_loop_byte(
                            read_serial,
                            iface_address,
                            rx_channel,
                            cancel,
                            stop,
                        )
                        .await;
                    } else {
                        read_loop(
                            read_serial,
                            iface_address,
                            rx_channel,
                            cancel,
                            stop,
                        )
                        .await;
                    }
                })
            };

            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let stop = stop.clone();

                tokio::spawn(async move {
                    write_loop(
                        write_serial,
                        iface_address,
                        tx_channel,
                        cancel,
                        stop,
                    )
                    .await;
                })
            };

            let _ = tx_task.await;
            let _ = rx_task.await;

            log::info!("serial_interface: serial port <{}> closed", config.port);
        }

        iface_stop.cancel();
    }
}

impl Interface for SerialInterface {
    fn hw_mtu(&self) -> usize {
        HW_MTU
    }

    fn bitrate(&self) -> Option<f64> {
        if self.speed > 0 {
            Some(self.speed as f64)
        } else {
            None
        }
    }
}

struct HdlcDecoder {
    in_frame: bool,
    escape: bool,
    data: Vec<u8>,
}

impl HdlcDecoder {
    fn new() -> Self {
        Self {
            in_frame: false,
            escape: false,
            data: Vec::with_capacity(HW_MTU),
        }
    }

    fn push(&mut self, byte: u8) -> Option<Vec<u8>> {
        if self.escape {
            self.escape = false;
            self.data.push(byte ^ 0x20);
            return None;
        }

        match byte {
            0x7e => {
                if self.in_frame {
                    let frame = std::mem::take(&mut self.data);
                    self.in_frame = false;
                    return Some(frame);
                }
                self.in_frame = true;
                self.escape = false;
                self.data.clear();
            }
            0x7d => {
                if self.in_frame {
                    self.escape = true;
                }
            }
            _ => {
                if self.in_frame && self.data.len() < HW_MTU {
                    self.data.push(byte);
                }
            }
        }

        None
    }

    fn reset_timed_out(&mut self) {
        if !self.data.is_empty() {
            self.in_frame = false;
            self.escape = false;
            self.data.clear();
        }
    }
}

async fn read_loop<R>(
    mut serial: R,
    iface_address: crate::hash::AddressHash,
    rx_channel: crate::iface::InterfaceRxSender,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    R: tokio::io::AsyncReadExt + Unpin,
{
    let mut decoder = HdlcDecoder::new();
    let mut chunk = [0u8; MAX_CHUNK];
    let mut idle = tokio::time::interval(FRAME_TIMEOUT);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = idle.tick() => {
                decoder.reset_timed_out();
            }
            result = serial.read(&mut chunk) => {
                match result {
                    Ok(0) => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Ok(n) => {
                        for &byte in &chunk[..n] {
                            if let Some(frame) = decoder.push(byte) {
                                if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&frame)) {
                                    if PACKET_TRACE {
                                        log::trace!("serial_interface: rx << ({}) {}", iface_address, packet);
                                    }
                                    let _ = rx_channel.send(RxMessage { address: iface_address, snr: None, rssi: None, packet }).await;
                                } else {
                                    log::warn!("serial_interface: couldn't decode packet");
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(e) => {
                        log::warn!("serial_interface: serial read error {}", e);
                        stop.cancel();
                        break;
                    }
                }
            }
        }
    }
}

async fn read_loop_byte<R>(
    mut serial: R,
    iface_address: crate::hash::AddressHash,
    rx_channel: crate::iface::InterfaceRxSender,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    R: tokio::io::AsyncReadExt + Unpin,
{
    let mut decoder = HdlcDecoder::new();
    let mut single = [0u8; 1];
    let mut last_activity = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep(BYTE_POLL_SLEEP) => {
                if last_activity.elapsed() > FRAME_TIMEOUT {
                    decoder.reset_timed_out();
                }
            }
            result = serial.read(&mut single) => {
                match result {
                    Ok(n) => {
                        if n == 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        } else {
                            last_activity = tokio::time::Instant::now();
                            for &byte in &single[..n] {
                                if let Some(frame) = decoder.push(byte) {
                                    if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&frame)) {
                                        if PACKET_TRACE {
                                            log::trace!("serial_interface: rx << ({}) {}", iface_address, packet);
                                        }
                                        let _ = rx_channel.send(RxMessage { address: iface_address, snr: None, rssi: None, packet }).await;
                                    } else {
                                        log::warn!("serial_interface: couldn't decode packet");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if last_activity.elapsed() > FRAME_TIMEOUT {
                            decoder.reset_timed_out();
                        }
                    }
                    Err(e) => {
                        log::warn!("serial_interface: serial read error {}", e);
                        stop.cancel();
                        break;
                    }
                }
            }
        }
    }
}

async fn write_loop<W>(
    mut serial: W,
    iface_address: crate::hash::AddressHash,
    tx_channel: Arc<tokio::sync::Mutex<crate::iface::InterfaceTxReceiver>>,
    cancel: CancellationToken,
    stop: CancellationToken,
) where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    loop {
        if stop.is_cancelled() {
            break;
        }

        let mut tx_channel = tx_channel.lock().await;
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = stop.cancelled() => break,
            Some(message) = tx_channel.recv() => {
                let mut tx_buffer = [0u8; HW_MTU * 2 + 4];
                let mut output = OutputBuffer::new(&mut tx_buffer);
                if message.packet.serialize(&mut output).is_err() {
                    log::warn!("serial_interface: couldn't encode packet");
                    continue;
                }

                let packet_data = output.as_slice();
                let mut hdlc_buffer = [0u8; HW_MTU * 2 + 4 + 2];
                let mut hdlc_output = OutputBuffer::new(&mut hdlc_buffer);
                if Hdlc::encode(packet_data, &mut hdlc_output).is_err() {
                    log::warn!("serial_interface: couldn't encode HDLC frame");
                    continue;
                }

                if PACKET_TRACE {
                    log::trace!(
                        "serial_interface: tx >> ({}) {} bytes",
                        iface_address,
                        hdlc_output.as_slice().len()
                    );
                }

                if let Err(e) = serial.write_all(hdlc_output.as_slice()).await {
                    log::warn!("serial_interface: serial write error {}", e);
                    stop.cancel();
                    break;
                }
                let _ = serial.flush().await;
            }
        }
    }
}

#[cfg(unix)]
fn configure_serial_fd(
    fd: std::os::fd::RawFd,
    speed: u32,
    databits: u8,
    parity: SerialParity,
    stopbits: u8,
) -> io::Result<()> {
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut termios = unsafe { termios.assume_init() };

    unsafe {
        libc::cfmakeraw(&mut termios);
    }

    termios.c_cflag |= libc::CREAD | libc::CLOCAL;
    termios.c_cflag &= !libc::CSIZE;
    termios.c_cflag |= match databits {
        5 => libc::CS5,
        6 => libc::CS6,
        7 => libc::CS7,
        _ => libc::CS8,
    };

    match parity {
        SerialParity::None => {
            termios.c_cflag &= !libc::PARENB;
        }
        SerialParity::Even => {
            termios.c_cflag |= libc::PARENB;
            termios.c_cflag &= !libc::PARODD;
        }
        SerialParity::Odd => {
            termios.c_cflag |= libc::PARENB;
            termios.c_cflag |= libc::PARODD;
        }
    }

    if stopbits == 2 {
        termios.c_cflag |= libc::CSTOPB;
    } else {
        termios.c_cflag &= !libc::CSTOPB;
    }

    let baud = baud_constant(speed)?;
    if unsafe { libc::cfsetispeed(&mut termios, baud) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::cfsetospeed(&mut termios, baud) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
fn baud_constant(speed: u32) -> io::Result<libc::speed_t> {
    let baud = match speed {
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1_200 => libc::B1200,
        1_800 => libc::B1800,
        2_400 => libc::B2400,
        4_800 => libc::B4800,
        9_600 => libc::B9600,
        19_200 => libc::B19200,
        38_400 => libc::B38400,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        57_600 => libc::B57600,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        115_200 => libc::B115200,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        230_400 => libc::B230400,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        460_800 => libc::B460800,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        500_000 => libc::B500000,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        576_000 => libc::B576000,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        921_600 => libc::B921600,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported serial baud rate {speed}"),
            ));
        }
    };

    Ok(baud)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_hdlc_frame() {
        let input = b"hello world\x00\x01\x02";
        let mut encode_buf = [0u8; 256];
        let mut encode_output = OutputBuffer::new(&mut encode_buf);
        Hdlc::encode(input, &mut encode_output).expect("encode");
        let encoded = encode_output.as_slice();

        let mut decoder = HdlcDecoder::new();
        let mut result = None;
        for &byte in encoded {
            if let Some(frame) = decoder.push(byte) {
                result = Some(frame);
            }
        }

        assert_eq!(result, Some(input.to_vec()));
    }

    #[test]
    fn decodes_hdlc_with_escaping() {
        let mut decoder = HdlcDecoder::new();
        // 0x7e, 0x7d 0x5e (= escaped 0x7e), 0x7d 0x5d (= escaped 0x7d), remaining data, 0x7e
        let frame = [
            0x7e,
            0x01,
            0x7d, 0x5e,
            0x02,
            0x7d, 0x5d,
            0x03,
            0x7e,
        ];
        let mut result = None;
        for &byte in &frame {
            if let Some(data) = decoder.push(byte) {
                result = Some(data);
            }
        }

        assert_eq!(result, Some(vec![0x01, 0x7e, 0x02, 0x7d, 0x03]));
    }

    #[test]
    fn decoder_resets_on_timeout() {
        let mut decoder = HdlcDecoder::new();
        // Start a frame but don't finish it
        decoder.push(0x7e);
        decoder.push(0x01);
        decoder.push(0x02);
        assert!(decoder.in_frame);
        assert!(!decoder.data.is_empty());

        decoder.reset_timed_out();
        assert!(!decoder.in_frame);
        assert!(decoder.data.is_empty());

        // After reset, a new complete frame should work
        decoder.push(0x7e);
        decoder.push(0x03);
        let frame = decoder.push(0x7e);
        assert_eq!(frame, Some(vec![0x03]));
    }

    #[test]
    fn ignores_data_outside_frame() {
        let mut decoder = HdlcDecoder::new();
        // Data before a frame flag should be ignored
        decoder.push(0x01);
        decoder.push(0x02);
        decoder.push(0x7e);
        decoder.push(0x03);
        let frame = decoder.push(0x7e);
        assert_eq!(frame, Some(vec![0x03]));
    }

    #[test]
    fn empty_hdlc_frame() {
        let mut decoder = HdlcDecoder::new();
        decoder.push(0x7e);
        let frame = decoder.push(0x7e);
        assert_eq!(frame, Some(vec![]));
    }

    #[test]
    fn reports_serial_speed_as_bitrate() {
        assert_eq!(
            SerialInterface::new("/dev/ttyUSB0").bitrate(),
            Some(DEFAULT_SPEED as f64)
        );
        assert_eq!(
            SerialInterface::new("/dev/ttyUSB0")
                .with_serial_params(115_200, 8, SerialParity::None, 1)
                .bitrate(),
            Some(115_200.0)
        );
    }

    #[test]
    fn zero_speed_is_not_reported_as_bitrate() {
        assert_eq!(
            SerialInterface::new("/dev/ttyUSB0")
                .with_serial_params(0, 8, SerialParity::None, 1)
                .bitrate(),
            None
        );
    }

    #[test]
    fn compatibility_mode_defaults_to_off() {
        let iface = SerialInterface::new("/dev/ttyUSB0");
        assert!(!iface.compatibility_mode);
    }

    #[test]
    fn compatibility_mode_can_be_enabled() {
        let iface = SerialInterface::new("/dev/ttyUSB0").with_compatibility_mode(true);
        assert!(iface.compatibility_mode);
    }

    #[test]
    fn encodes_roundtrip_matches_exact_bytes() {
        let input = [0x7e, 0x7d, 0x01, 0x02, 0x03];
        let mut encode_buf = [0u8; 256];
        let mut encode_output = OutputBuffer::new(&mut encode_buf);
        Hdlc::encode(&input, &mut encode_output).expect("encode");
        let encoded = encode_output.as_slice();

        // Verify HDLC framing: starts and ends with 0x7e
        assert_eq!(encoded[0], 0x7e);
        assert_eq!(encoded[encoded.len() - 1], 0x7e);

        // Decode and verify
        let mut decoder = HdlcDecoder::new();
        let mut result = None;
        for &byte in encoded {
            if let Some(frame) = decoder.push(byte) {
                result = Some(frame);
            }
        }
        assert_eq!(result, Some(input.to_vec()));
    }

    #[test]
    fn hdlc_encoder_produces_wire_compatible_output() {
        // Verify that Hdlc::encode produces output that the Python SerialInterface
        // would accept: 0x7E | escaped_payload | 0x7E with 0x7D escape, XOR 0x20
        let input = [0x7e, 0x7d];
        let mut encode_buf = [0u8; 256];
        let mut encode_output = OutputBuffer::new(&mut encode_buf);
        Hdlc::encode(&input, &mut encode_output).expect("encode");
        let encoded = encode_output.as_slice();

        // Expected: 0x7e, 0x7d, 0x5e (= 0x7e ^ 0x20), 0x7d, 0x5d (= 0x7d ^ 0x20), 0x7e
        let expected: &[u8] = &[0x7e, 0x7d, 0x5e, 0x7d, 0x5d, 0x7e];
        assert_eq!(encoded, expected);
    }
}
