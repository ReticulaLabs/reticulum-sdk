//! Offline trace of every SPI transaction the SX1262 driver emits during
//! `init()` + `transmit()`, captured through a mock SPI/GPIO pair.
//!
//! Run with:
//!   cargo run --features lora --example sx1262_trace
//!
//! The point is to be able to diff the emitted command stream byte-for-byte
//! against a known-good implementation without any hardware attached.

use std::collections::HashMap;
use std::time::Duration;

use reticulum_sdk::iface::lora::sx1262::SX1262;
use reticulum_sdk::iface::lora::{GpioPins, LoRaChipset, LoRaConfig, LoRaGpio, LoRaSpi};

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x80 => "SetStandby",
        0x81 => "SetFs",
        0x82 => "SetRx",
        0x83 => "SetTx",
        0x84 => "SetSleep",
        0x8A => "SetPacketType",
        0x12 => "GetIrqStatus",
        0x02 => "ClearIrqStatus",
        0x08 => "SetDioIrqParams",
        0x86 => "SetRfFrequency",
        0x8F => "SetBufferBaseAddress",
        0x8B => "SetModulationParams",
        0x8C => "SetPacketParams",
        0x8E => "SetTxParams",
        0x95 => "SetPaConfig",
        0x96 => "SetRegulatorMode",
        0x9D => "SetDio2AsRfSwitchCtrl",
        0x97 => "SetDio3AsTcxoCtrl",
        0x98 => "CalibrateImage",
        0x13 => "GetRxBufferStatus",
        0x14 => "GetPacketStatus",
        0x15 => "GetRssiInst",
        0x0E => "WriteBuffer",
        0x1E => "ReadBuffer",
        0x0D => "WriteRegister",
        0x1D => "ReadRegister",
        0x89 => "Calibrate",
        0x17 => "GetDeviceErrors",
        0x07 => "ClearDeviceErrors",
        0xC0 => "GetStatus",
        _ => "???",
    }
}

/// Mock chip: models enough register/mode state for `init()` and `transmit()`
/// to complete, and records every transaction.
struct MockSpi {
    regs: HashMap<u16, u8>,
    log: Vec<String>,
    tracing: bool,
    /// Last standby mode requested via SetStandby (0x00 = RC, 0x01 = XOSC).
    mode: u8,
}

impl MockSpi {
    fn new(tracing: bool) -> Self {
        let mut regs = HashMap::new();
        // Reset defaults that the driver reads back.
        regs.insert(0x0740, 0x14); // LoRaSyncWordMSB
        regs.insert(0x0741, 0x24); // LoRaSyncWordLSB
        regs.insert(0x0150, 0x02); // chip version
        regs.insert(0x08D8, 0x1E); // TxClampConfig
        regs.insert(0x0889, 0x04); // TxModulation
        regs.insert(0x0736, 0x00); // IqPolaritySetup
        regs.insert(0x08AC, 0x00); // LnaGain
        regs.insert(0x08E7, 0x18); // OcpConfiguration
        regs.insert(0x0902, 0x00); // RtcControl
        regs.insert(0x0944, 0x00); // EventMask
        Self {
            regs,
            log: Vec::new(),
            tracing,
            mode: 0x00,
        }
    }

    fn mode_status(&self) -> u8 {
        // Chip-mode field bits 6:4: 0x2 = STDBY_RC, 0x3 = STDBY_XOSC.
        (self.mode + 2) << 4
    }
}

impl LoRaSpi for MockSpi {
    fn xfer(
        &mut self,
        tx: &[u8],
        rx: &mut [u8],
    ) -> Result<(), reticulum_sdk::iface::lora::LoRaError> {
        for b in rx.iter_mut() {
            *b = 0x00;
        }
        let op = tx[0];
        let args = &tx[1..];
        let hex: String = tx.iter().map(|b| format!("{b:02X} ")).collect();

        if self.tracing {
            println!("  {:<26} [{hex}]", opcode_name(op));
        }
        self.log.push(format!("{:02X} {}", op, hex.trim_end()));

        match op {
            // ── writes ────────────────────────────────────────────────────
            0x0D => {
                // WriteRegister: addr_hi, addr_lo, data...
                if args.len() >= 3 {
                    let addr = ((args[0] as u16) << 8) | args[1] as u16;
                    if self.tracing {
                        println!(
                            "      -> reg 0x{addr:04X} = {}",
                            args[2..]
                                .iter()
                                .map(|b| format!("0x{b:02X}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }
                    for (i, b) in args[2..].iter().enumerate() {
                        self.regs.insert(addr + i as u16, *b);
                    }
                }
            }
            0x80 => {
                // SetStandby: 0x00 = STDBY_RC, 0x01 = STDBY_XOSC
                if let Some(&m) = args.first() {
                    self.mode = m;
                }
            }
            0x07 => { /* ClearDeviceErrors */ }
            0x02 => { /* ClearIrqStatus */ }

            // ── reads ────────────────────────────────────────────────────
            0x1D if args.len() >= 2 => {
                let addr = ((args[0] as u16) << 8) | args[1] as u16;
                let n = rx.len();
                // The driver always reads `read_len` bytes; infer it from the
                // transaction length so multi-byte register reads (ping /
                // validate_communication read the 16-bit sync word) work.
                let read_len = n - 4;
                for i in 0..read_len {
                    rx[n - read_len + i] =
                        self.regs.get(&(addr + i as u16)).copied().unwrap_or(0x00);
                }
            }
            0xC0 => {
                let n = rx.len();
                rx[n - 1] = self.mode_status();
            }
            0x12 => {
                // GetIrqStatus: report TX_DONE so transmit() completes.
                let n = rx.len();
                if n >= 2 {
                    rx[n - 2] = 0x00;
                    rx[n - 1] = 0x01; // IRQ_TX_DONE
                }
            }
            0x17 => {
                let n = rx.len();
                if n >= 2 {
                    rx[n - 2] = 0x00;
                    rx[n - 1] = 0x00; // no latched errors
                }
            }
            0x13 => {
                let n = rx.len();
                if n >= 2 {
                    rx[n - 2] = 0x00; // payload length
                    rx[n - 1] = 0x00; // start pointer
                }
            }
            0x14 => {
                let n = rx.len();
                if n >= 3 {
                    rx[n - 3] = 0xC8; // rssi raw
                    rx[n - 2] = 0x40; // snr raw
                    rx[n - 1] = 0xC8;
                }
            }
            0x15 => {
                let n = rx.len();
                rx[n - 1] = 0xC8;
            }
            0x1E => { /* ReadBuffer */ }
            _ => {}
        }
        Ok(())
    }
}

/// Mock GPIO. `busy` always reads low (chip never busy), so the driver takes
/// the fast path through its BUSY-wait logic.
struct MockPin {
    level: bool,
}

impl LoRaGpio for MockPin {
    fn get_value(&self) -> Result<bool, reticulum_sdk::iface::lora::LoRaError> {
        Ok(self.level)
    }
    fn set_value(&self, _value: bool) -> Result<(), reticulum_sdk::iface::lora::LoRaError> {
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Same configuration the T-Deck firmware builds: 125 kHz, SF7, CR4/5,
    // 14 dBm, 1.8 V TCXO, DIO2 as RF switch.
    let config = LoRaConfig::new("", 869_525_000.0 as u64, 125_000.0, 14, 7, 5)
        .with_tcxo_voltage(1.8)
        .with_tcxo_startup_delay(Duration::from_millis(320));

    let gpio = GpioPins {
        busy: Some(Box::new(MockPin { level: false })),
        reset: Some(Box::new(MockPin { level: false })),
        dio1: Some(Box::new(MockPin { level: true })),
    };

    let mut spi = MockSpi::new(true);
    let mut chipset = SX1262::new(Box::new(spi), gpio);

    println!("=== init() ===");
    chipset.init(&config)?;

    println!("\n=== transmit(32 bytes) ===");
    chipset.transmit(&[0xAB; 32])?;

    println!("\n=== effective config ===");
    println!(
        "  freq={} Hz  bw={} Hz  sf={}  cr=4/{}  preamble={}  crc={}  iq_inverted={}",
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.effective_preamble_length(),
        config.crc_enabled,
        config.iq_inverted,
    );
    println!(
        "  sync_word=0x{:04X}  tx_power={} dBm  dio_rf_switch={}  dcdc={}",
        config.sync_word, config.tx_power, config.dio_rf_switch, config.dcdc
    );
    Ok(())
}
