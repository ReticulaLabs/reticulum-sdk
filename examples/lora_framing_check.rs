//! Verifies the Reticulum LoRa on-air framing against a reference model of
//! what radio firmware does on the air.
//!
//! The reference adds a one-byte header before handing a frame to the modem
//! and strips it before passing data up to the host. The direct chipset
//! drivers bypass that firmware, so they must add and strip the byte
//! themselves — otherwise a peer reads every frame one byte out of step.
//!
//! Run: cargo run --features lora --example lora_framing_check

use reticulum_sdk::hash::AddressHash;
use reticulum_sdk::iface::decode_rx;
use reticulum_sdk::iface::encode_tx;
use reticulum_sdk::iface::ifac::IfacConfig;
use reticulum_sdk::iface::lora::{LORA_FLAG_SPLIT, Reassembler, frames_for_tx};
use reticulum_sdk::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};

/// Reference model: split `data` the way radio firmware does on transmit.
fn reference_tx(data: &[u8], sequence: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let header = if data.len() > 254 {
        (sequence & 0xF0) | LORA_FLAG_SPLIT
    } else {
        sequence & 0xF0
    };
    let mut chunk: Vec<u8> = Vec::with_capacity(255);
    chunk.push(header);
    for &b in data {
        chunk.push(b);
        if chunk.len() == 255 && (header & LORA_FLAG_SPLIT) != 0 {
            out.push(std::mem::take(&mut chunk));
            chunk.push(header);
        }
    }
    out.push(chunk);
    out
}

/// Reference model: consume a raw frame the way radio firmware does on
/// receive, returning the bytes it would hand to the host.
#[derive(Default)]
struct ReferenceRx {
    sequence: Option<u8>,
    buffer: Vec<u8>,
}

impl ReferenceRx {
    fn accept(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let (&header, data) = frame.split_first()?;
        if header & LORA_FLAG_SPLIT == 0 {
            self.sequence = None;
            return Some(data.to_vec());
        }
        let seq = header & 0xF0;
        if self.sequence == Some(seq) {
            self.buffer.extend_from_slice(data);
            self.sequence = None;
            Some(std::mem::take(&mut self.buffer))
        } else {
            self.sequence = Some(seq);
            self.buffer = data.to_vec();
            None
        }
    }
}

fn build_packet(ifac: &IfacConfig, payload: &[u8]) -> Packet {
    let mut packet = Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
            hops: 1,
            ..Default::default()
        },
        ifac: None,
        destination: AddressHash::new([0x42; 16]),
        transport: None,
        context: PacketContext::None,
        data: PacketDataBuffer::new_from_slice(payload),
    };
    ifac.attach(&mut packet).expect("attach ifac");
    packet
}

fn main() {
    let ifac = IfacConfig::derive(Some("test"), None, 8);
    let mut failures = 0;

    println!(
        "{:>6} {:>6} {:>7} {:>7} {:>10} {:>12}",
        "size", "frames", "ref bytes", "ours", "tx matches", "rx decodes"
    );
    println!("{}", "-".repeat(58));

    // Sweep across the single-frame boundary and well past it.
    for size in [
        1usize, 20, 48, 100, 181, 200, 253, 254, 255, 256, 300, 400, 470,
    ] {
        let packet = build_packet(&ifac, &vec![0xABu8; size]);
        let mut buf = [0u8; 1024];
        let len = encode_tx(Some(&ifac), &packet, &mut buf).expect("encode_tx");
        let data = &buf[..len];

        let sequence = 0x70u8;
        let ours = frames_for_tx(data, sequence);
        let theirs = reference_tx(data, sequence);

        let tx_match = ours == theirs;
        let total: usize = ours.iter().map(|f| f.len()).sum();

        // Now receive our own frames through the reference model and check the
        // interface data decodes.
        let mut rx = ReferenceRx::default();
        let mut assembled: Option<Vec<u8>> = None;
        for frame in &ours {
            if let Some(complete) = rx.accept(frame) {
                assembled = Some(complete);
            }
        }
        let rx_ok = match &assembled {
            Some(bytes) => decode_rx(Some(&ifac), bytes).is_ok(),
            None => false,
        };

        if !tx_match || !rx_ok {
            failures += 1;
        }
        println!(
            "{:>6} {:>6} {:>7} {:>7} {:>10} {:>12}",
            data.len(),
            ours.len(),
            total,
            total,
            if tx_match { "ok" } else { "MISMATCH" },
            if rx_ok { "ok" } else { "FAILED" }
        );
    }

    println!("{}", "-".repeat(58));

    // Cross-check: our reassembler must consume frames produced by the
    // reference transmitter.
    for size in [48usize, 254, 300, 470] {
        let packet = build_packet(&ifac, &vec![0x5Cu8; size]);
        let mut buf = [0u8; 1024];
        let len = encode_tx(Some(&ifac), &packet, &mut buf).expect("encode_tx");
        let data = &buf[..len];

        let frames = reference_tx(data, 0x30);
        if frames.len() > 2 {
            println!(
                "reassembler on reference frames, size {:>4}: skipped (exceeds air MTU)",
                data.len()
            );
            continue;
        }
        let mut reassembler = Reassembler::new();
        let mut assembled: Option<Vec<u8>> = None;
        for frame in &frames {
            if let Some(complete) = reassembler.accept(frame) {
                assembled = Some(complete);
            }
        }
        let ok = assembled.is_some() && decode_rx(Some(&ifac), assembled.as_ref().unwrap()).is_ok();
        if !ok {
            failures += 1;
        }
        println!(
            "reassembler on reference frames, size {:>4}: {}",
            data.len(),
            if ok { "ok" } else { "FAILED" }
        );
    }

    println!();
    if failures == 0 {
        println!("All framing cases match the reference and decode cleanly.");
    } else {
        println!("{failures} framing case(s) FAILED");
        std::process::exit(1);
    }
}
