//! Cross-check the SDK's derived preamble length against the rule used by
//! reference LoRa modem firmware.
//!
//! The reference computes the preamble in its `updateBitrate()` as:
//!
//! ```text
//! symbol_time_ms = (2^SF / BW_Hz) * 1000
//! bitrate        = SF * ((4/CR) / ((2^SF) / (BW_kHz))) * 1000
//! fast           = bitrate > 30_000
//! target_ms      = fast ? (24 - 18) : 24
//! symbols        = ceil(target_ms / symbol_time_ms)
//! symbols        = max(symbols, 18)
//! ```
//!
//! This example re-derives that independently and compares, so a change to
//! either side shows up as a mismatch rather than as a silent air-interface
//! divergence.
//!
//! Run: cargo run --features lora --example lora_preamble_check

use reticulum_sdk::iface::lora::{PREAMBLE_TARGET_MS, reticulum_preamble_length};

const BANDWIDTHS: [f64; 4] = [62_500.0, 125_000.0, 250_000.0, 500_000.0];
const CODING_RATES: [u8; 4] = [5, 6, 7, 8];

/// Independent transcription of the reference formula, used as the oracle.
fn rnode_reference(sf: u8, bw_khz: f64, cr: u8) -> (u16, f64) {
    let symbol_time_ms = (1u64 << sf) as f64 / (bw_khz * 1000.0) * 1000.0;
    let bitrate = sf as f64 * ((4.0 / cr as f64) / ((1u64 << sf) as f64 / bw_khz)) * 1000.0;
    let target_ms = if bitrate > 30_000.0 {
        PREAMBLE_TARGET_MS - 18.0
    } else {
        PREAMBLE_TARGET_MS
    };
    let symbols = (target_ms / symbol_time_ms).ceil();
    let symbols = if symbols < 18.0 { 18.0 } else { symbols };
    (symbols as u16, bitrate)
}

fn main() {
    let mut mismatches = 0;
    let mut checked = 0;

    println!(
        "{:>3} {:>7} {:>3} {:>8} {:>9} {:>6} {:>7} {:>5} {:>9}",
        "SF", "BW kHz", "CR", "sym ms", "bitrate", "ours", "rnode", "fast", "result"
    );
    println!("{}", "-".repeat(70));

    for sf in 7..=12u8 {
        for bw in BANDWIDTHS {
            for cr in CODING_RATES {
                let ours = reticulum_preamble_length(sf, bw, cr);
                let (theirs, bitrate) = rnode_reference(sf, bw / 1000.0, cr);
                let fast = bitrate > 30_000.0;
                let ok = ours == theirs;
                checked += 1;
                if !ok {
                    mismatches += 1;
                }
                println!(
                    "{:>3} {:>7} {:>3} {:>8.3} {:>9.0} {:>6} {:>7} {:>5} {:>9}",
                    sf,
                    bw as u64 / 1000,
                    cr,
                    (1u64 << sf) as f64 / bw * 1000.0,
                    bitrate,
                    ours,
                    theirs,
                    if fast { "yes" } else { "no" },
                    if ok { "ok" } else { "MISMATCH" }
                );
            }
        }
    }

    println!("{}", "-".repeat(70));
    if mismatches == 0 {
        println!("All {checked} configurations match the reference formula.");
    } else {
        println!("{mismatches} of {checked} configurations MISMATCH the reference formula");
        std::process::exit(1);
    }

    // The regression this guards: the T-Deck default (SF7 / 125 kHz / CR4-5).
    let p = reticulum_preamble_length(7, 125_000.0, 5);
    println!();
    println!("T-Deck default (SF7 / 125 kHz / CR4-5): {p} symbols");
    assert!(
        p >= 18,
        "preamble must never fall below the 18-symbol floor"
    );
    println!("(was hardcoded to 8 before the fix, below the floor)");
}
