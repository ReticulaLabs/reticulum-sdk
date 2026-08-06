use std::time::{Duration, Instant};

use super::{GpioLine, GpioPins, LoRaChipset, LoRaConfig, LoRaError, ReceivedPacket, SpiBus};

// ── Frequency bands (LR1121-specific) ─────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyBand {
    SubGhz,   // 150–960 MHz
    LBand,    // 1.525–1.660 GHz
    SBand,    // 1.9–2.1 GHz
    Band2p4G, // 2.4–2.5 GHz ISM
}

impl FrequencyBand {
    pub fn from_freq(hz: u64) -> Self {
        if hz < 1_000_000_000 {
            FrequencyBand::SubGhz
        } else if hz <= 1_660_000_000 {
            FrequencyBand::LBand
        } else if hz <= 2_100_000_000 {
            FrequencyBand::SBand
        } else {
            FrequencyBand::Band2p4G
        }
    }
}

// ── 16-bit command opcodes (Semtech LR11xx driver, lr11xx_system.h
//    and lr11xx_radio.h / lr11xx_regmem.h) ────────────────────────────────

// System configuration
const CMD_GET_STATUS: u16 = 0x0100;
const CMD_GET_VERSION: u16 = 0x0101;
const CMD_GET_ERRORS: u16 = 0x010D;
const CMD_CLEAR_ERRORS: u16 = 0x010E;
const CMD_CALIBRATE: u16 = 0x010F;
const CMD_SET_REG_MODE: u16 = 0x0110;
const CMD_CALIB_IMAGE: u16 = 0x0111;
const CMD_SET_DIO_AS_RF_SWITCH: u16 = 0x0112;
const CMD_SET_DIO_IRQ_PARAMS: u16 = 0x0113;
const CMD_CLEAR_IRQ: u16 = 0x0114;
const CMD_CFG_LFCLK: u16 = 0x0116;
const CMD_SET_TXCO_MODE: u16 = 0x0117;
const CMD_SET_SLEEP: u16 = 0x011B;
const CMD_SET_STANDBY: u16 = 0x011C;

// Radio configuration / status
const CMD_GET_RX_BUFFER_STATUS: u16 = 0x0203;
const CMD_GET_PACKET_STATUS: u16 = 0x0204;
const CMD_GET_RSSI_INST: u16 = 0x0205;
const CMD_SET_RX: u16 = 0x0209;
const CMD_SET_TX: u16 = 0x020A;
const CMD_SET_RF_FREQUENCY: u16 = 0x020B;
const CMD_SET_PACKET_TYPE: u16 = 0x020E;
const CMD_SET_MODULATION_PARAMS: u16 = 0x020F;
const CMD_SET_PACKET_PARAMS: u16 = 0x0210;
const CMD_SET_TX_PARAMS: u16 = 0x0211;
const CMD_SET_PA_CONFIG: u16 = 0x0215;
const CMD_SET_LORA_SYNC_WORD: u16 = 0x022B;

// RF Switch Settings
const RFSW0_HIGH: u8 = 0b00001; // DIO5 Built-in RfSw
const RFSW1_HIGH: u8 = 0b00010; // DIO6 Built-in RfSw
const RFSW2_HIGH: u8 = 0b00100; // DIO7
const RFSW3_HIGH: u8 = 0b01000; // DIO8
//const RFSW4_HIGH: u8 = 0b10000; // DIO9??

// Buffer access
const CMD_WRITE_BUFFER_8: u16 = 0x0109;
const CMD_READ_BUFFER_8: u16 = 0x010A;

// Register/memory access (LR11xx regmem)
// 0x0105: WRITE_REGMEM32
// 0x0106: READ_REGMEM32
// 0x010C: WRITE_REGMEM32_MASK
const CMD_WRITE_REGMEM32: u16 = 0x0105;
const CMD_READ_REGMEM32: u16 = 0x0106;
const CMD_WRITE_REGMEM32_MASK: u16 = 0x010C;

// RX boosted mode
const CMD_SET_RX_BOOSTED: u16 = 0x0227;

// ── Bootloader opcodes (Semtech SWTL001 / lr11xx_bootloader.c) ─────────────
// These opcodes (0x8000..=0x800D) are only valid when the chip is running
// in bootloader mode. GetVersion (0x0101) and GetStatus (0x0100) are
// shared with the system command set and work in both modes.
//
// Note: there are TWO Reboot commands in the LR11xx command set with
// the same `0x03` / `0x00` stay-in-bootloader argument but different
// opcodes that work in different modes. The system-mode Reboot
// (0x0118) is what the system firmware uses to reboot the chip and is
// the only way to enter bootloader from system mode via SPI. The
// bootloader-mode Reboot (0x8005) is the bootloader's own reboot, only
// valid when the chip is already in bootloader mode.

const CMD_SYSTEM_REBOOT: u16 = 0x0118;
const CMD_BL_ERASE_FLASH: u16 = 0x8000;
const CMD_BL_WRITE_FLASH_ENCRYPTED: u16 = 0x8003;
const CMD_BL_GET_HASH: u16 = 0x8004;
const CMD_BL_REBOOT: u16 = 0x8005;
const CMD_BL_GET_PIN: u16 = 0x800B;
const CMD_BL_READ_CHIP_EUI: u16 = 0x800C;
const CMD_BL_READ_JOIN_EUI: u16 = 0x800D;

/// Bootloader flash write chunk size: 64 u32 words = 256 bytes per
/// WriteFlashEncrypted command. The final chunk may be shorter.
const BL_FLASH_CHUNK_WORDS: usize = 64;

/// Bootloader version returned by GetVersion (0x0101) when the chip is
/// running in bootloader mode. Same wire format as the system version:
/// 4 bytes packed as [hw, type, fw_major, fw_minor]. Per
/// `lr11xx_bootloader_types.h`, `type` encodes 0x00=LR1110, 0x02=LR1120,
/// 0x03=LR1121 and `fw` is a big-endian 16-bit major.minor version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlVersion {
    pub hw: u8,
    pub typ: u8,
    pub fw: u16,
}

// ── Packet types (LR1121 UM §8.1.1) ──────────────────────────────────────
// 0x00 = None, 0x01 = (G)FSK, 0x02 = LoRa, 0x03 = Sigfox, 0x04 = LR-FHSS

const PACKET_TYPE_LORA: u8 = 0x02;

// ── Standby modes (LR1121 UM §2.1.2.1) ────────────────────────────────────

const STANDBY_RC: u8 = 0x00;
const STANDBY_XOSC: u8 = 0x01;

// ── Chip modes (lr11xx_system.h) ───────────────────────────────────────────
// The LR11xx encodes the current chip mode in stat2_byte bits 3:1. Values
// are 0x1..=0x5 (FSM=0x0 is reserved / unused on the public interface).
// These differ from the SX1262, which puts the chip mode in stat1 bits 6:4
// with values 0x2..=0x6.
#[allow(dead_code)] // STBY_RC/FS/RX/TX retained for future callers / docs
const CHIP_MODE_STBY_RC: u8 = 0x1;
const CHIP_MODE_STBY_XOSC: u8 = 0x2;
#[allow(dead_code)]
const CHIP_MODE_FS: u8 = 0x3;
#[allow(dead_code)]
const CHIP_MODE_RX: u8 = 0x4;
#[allow(dead_code)]
const CHIP_MODE_TX: u8 = 0x5;

// ── Regulator mode (LR1121 UM §5.3.1) ─────────────────────────────────────

const REG_MODE_DCDC: u8 = 0x01;

// ── PA ramp times (LR1121 UM §9.5.2) ──────────────────────────────────────

const RAMP_800U: u8 = 0x05;

// ── 32-bit IRQ flags (LR1121 UM §4.1, Table 4-2) ──────────────────────────

const IRQ_TX_DONE: u32 = 1 << 2;
const IRQ_RX_DONE: u32 = 1 << 3;
const IRQ_PREAMBLE_DETECTED: u32 = 1 << 4;
const IRQ_SYNC_WORD_VALID: u32 = 1 << 5;
const IRQ_HEADER_ERR: u32 = 1 << 6;
const IRQ_ERR: u32 = 1 << 7;
const IRQ_CAD_DONE: u32 = 1 << 8;
const IRQ_CAD_DETECTED: u32 = 1 << 9;
const IRQ_TIMEOUT: u32 = 1 << 10;

const IRQ_MASK_ALL: u32 = IRQ_TX_DONE
    | IRQ_RX_DONE
    | IRQ_HEADER_ERR
    | IRQ_ERR
    | IRQ_TIMEOUT;

// ── Device error word (LR1121 UM §3.6.1, Table 3-5) ────────────────────────
// Bit assignments are unique to the LR11xx family (they differ from the
// SX1262/SX1276 OpError layout). Bits accumulate since the last
// ClearErrors (0x010E) call.

const ERR_LF_RC_CALIB: u16 = 0x0001;
const ERR_HF_RC_CALIB: u16 = 0x0002;
const ERR_ADC_CALIB: u16 = 0x0004;
const ERR_PLL_CALIB: u16 = 0x0008;
const ERR_IMG_CALIB: u16 = 0x0010;
const ERR_HF_XOSC_START: u16 = 0x0020;
const ERR_LF_XOSC_START: u16 = 0x0040;
const ERR_PLL_LOCK: u16 = 0x0080;
const ERR_RX_ADC_OFFSET: u16 = 0x0100;

// ── LoRa bandwidth codes (LR1121 UM §8.3.1) ───────────────────────────────
// Sub-GHz: 0x03=62.5k, 0x04=125k, 0x05=250k, 0x06=500k
// 2.4 GHz: 0x0D=203k, 0x0E=406k, 0x0F=812k

fn lora_bandwidth_code_subghz(bw_hz: u32) -> u8 {
    if bw_hz < 93_800 {
        0x03 // 62.5 kHz
    } else if bw_hz < 187_500 {
        0x04 // 125 kHz
    } else if bw_hz < 375_000 {
        0x05 // 250 kHz
    } else {
        0x06 // 500 kHz
    }
}

/// Map a TCXO supply voltage (volts) to the 4-bit LR11xx code. Codes
/// follow `lr11xx_system_tcxo_supply_voltage_t`: 1.6V=0x00, 1.7V=0x01,
/// 1.8V=0x02, 2.2V=0x03, 2.4V=0x04, 2.7V=0x05, 3.0V=0x06, 3.3V=0x07.
fn tcxo_voltage_code(voltage_v: f64) -> u8 {
    if voltage_v >= 1.6 && voltage_v < 1.7 {
        0x00
    } else if voltage_v < 1.8 {
        0x01
    } else if voltage_v < 2.2 {
        0x02
    } else if voltage_v < 2.4 {
        0x03
    } else if voltage_v < 2.7 {
        0x04
    } else if voltage_v < 3.0 {
        0x05
    } else if voltage_v < 3.3 {
        0x06
    } else {
        0x07
    }
}

fn lora_bandwidth_code_2p4g(bw_hz: u32) -> u8 {
    match bw_hz {
        x if x <= 206_000 => 0x0D, // 203.125 kHz
        x if x <= 413_000 => 0x0E, // 406.25 kHz
        x if x <= 825_000 => 0x0F, // 812.5 kHz
        _ => 0x0F,                  // 812.5 kHz (fallback)
    }
}

// ── Coding rate (LR1121 UM §8.3.1) ────────────────────────────────────────
// 0x01=4/5, 0x02=4/6, 0x03=4/7, 0x04=4/8

fn lora_coding_rate_code(cr: u8) -> u8 {
    if (5..=8).contains(&cr) {
        cr - 4
    } else {
        0x01
    }
}

fn needs_ldro(sf: u8, bw_hz: u32) -> bool {
    let symbol_time_ms = ((1u64 << sf) as f64) / (bw_hz as f64) * 1000.0;
    symbol_time_ms >= 16.38
}

// ── CalibrateImage band pairs (LR1121 UM §2.1.3.1, Table 2-3) ─────────────

fn calibrate_image_bands(freq_hz: u64) -> Option<(u8, u8)> {
    if freq_hz < 446_000_000 {
        Some((0x6B, 0x6E))  // 430–440 MHz
    } else if freq_hz < 734_000_000 {
        Some((0x75, 0x81))  // 470–510 MHz
    } else if freq_hz < 828_000_000 {
        Some((0xC1, 0xC5))  // 779–787 MHz
    } else if freq_hz < 877_000_000 {
        Some((0xD7, 0xDB))  // 863–870 MHz
    } else if freq_hz < 1_000_000_000 {
        Some((0xE1, 0xE9))  // 902–928 MHz
    } else {
        None                // HF bands: no image calibration needed
    }
}

// ── PA configuration helpers ──────────────────────────────────────────────

fn subghz_pa_duty_cycle(power_dbm: i8) -> (u8, u8) {
    let clamped = power_dbm.clamp(-9, 22);
    if clamped >= 22 {
        (0x04, 0x07)
    } else if clamped >= 20 {
        (0x03, 0x05)
    } else if clamped >= 17 {
        (0x02, 0x03)
    } else if clamped >= 14 {
        (0x02, 0x02)
    } else {
        (0x00, 0x00)
    }
}

// ── LR1121 driver ─────────────────────────────────────────────────────────

pub struct LR1121 {
    spi: SpiBus,
    busy: Option<GpioLine>,
    reset: Option<GpioLine>,
    dio_irq: Option<GpioLine>,
    config: Option<LoRaConfig>,
    command_delay: Duration,
    band: FrequencyBand,
    rx_active: bool,
    tx_active: bool,
    prev_status: Option<(u16, u8)>, // (opcode, Stat1) from last command
}

impl LR1121 {
    /// Log the command status carried in a Stat1 byte (bits 3:1, values
    /// follow RadioLib/`lr11xx_system.h` semantics: 0=CMD_FAIL, 1=P_ERR,
    /// 2=CMD_OK, 3=CMD_DATA, 6/7=TX/RX_DONE; everything else is success).
    fn log_cmd_status(&self, opcode: u16, stat1: u8) {
        match (stat1 >> 1) & 0x07 {
            0 => log::warn!("lr1121: command 0x{opcode:04X} CMD_FAIL"),
            1 => log::warn!("lr1121: command 0x{opcode:04X} CMD_P_ERR"),
            2 => log::trace!("lr1121: command 0x{opcode:04X} CMD_OK"),
            3 => log::trace!("lr1121: command 0x{opcode:04X} CMD_DATA"),
            6 => log::trace!("lr1121: command 0x{opcode:04X} CMD_TX_DONE"),
            7 => log::trace!("lr1121: command 0x{opcode:04X} CMD_RX_DONE"),
            _ => {}
        }
    }

    /// Decode the command-status field of the most recent write
    /// command and turn failures into an `Err(...)`. Used by the
    /// bootloader write/erase paths to surface `CMD_FAIL` /
    /// `CMD_P_ERR` responses — `write_command` itself only logs
    /// those (it has to, because some read paths rely on the
    /// non-fatal path), but for write commands a failure means the
    /// chip rejected the operation and callers want to know.
    fn check_prev_status(&self, opcode: u16, label: &str) -> Result<(), LoRaError> {
        let stat1 = match self.prev_status {
            Some((op, s)) if op == opcode => s,
            _ => return Ok(()),
        };
        match (stat1 >> 1) & 0x07 {
            0 => Err(LoRaError::Chipset(format!(
                "lr1121: {label} failed: CMD_FAIL (stat1=0x{stat1:02X}). \
                 The chip rejected the command — most often because it is \
                 not in bootloader mode, or because a previous command is \
                 still being processed (BUSY line not connected, no \
                 inter-chunk delay)."
            ))),
            1 => Err(LoRaError::Chipset(format!(
                "lr1121: {label} failed: CMD_P_ERR (stat1=0x{stat1:02X}). \
                 The chip rejected a parameter (offset, length, or arg) — \
                 check that the offset is in range, the chunk size is \
                 1..=64 words, and the chip is in bootloader mode."
            ))),
            // 2=CMD_OK, 3=CMD_DATA, 6/7=TX_DONE/RX_DONE — all valid successes.
            _ => Ok(()),
        }
    }


    fn wait_ready(&self) -> Result<(), LoRaError> {
        // Default wait covers a normal radio command (~10ms typical) plus
        // the WriteFlashEncrypted per-chunk budget (see below). Use
        // `wait_ready_with_max_busy` for long-running operations like the
        // XOSC startup, where the chip can hold BUSY for the configured
        // TCXO startup delay (hundreds of ms by default, up to seconds).
        self.wait_ready_with_max_busy(Duration::from_millis(200))
    }

    /// Wait for the chip to be ready to accept the next command, bounded by
    /// `max_busy`. `max_busy` is the expected worst-case time the chip will
    /// spend in BUSY for the previous (or about-to-issue) command:
    ///
    ///   * Normal radio command: ~10 ms typical, ~50 ms worst case.
    ///   * Calibrate(0x3F): ~10–30 ms.
    ///   * SetStandby(XOSC): up to the configured `tcxo_startup_delay`
    ///     (default 320 ms, can be several seconds). The 32 MHz reference
    ///     is only declared stable after this window; if it's not
    ///     oscillating the chip latches HF_XOSC_START_ERR.
    ///   * WriteFlashEncrypted: 30 ms per 32-byte internal page (handled
    ///     separately by the bootloader path).
    ///
    /// The default 200 ms covers normal commands plus a WriteFlashEncrypted
    /// chunk (~2 × 200 ms ≈ 400 ms per chunk). For `SetStandby(XOSC)` the
    /// caller MUST pass the configured TCXO startup delay — otherwise the
    /// next command is sent while the chip is still BUSY and is silently
    /// dropped (MISO returns garbage, command appears to fail with
    /// CMD_FAIL). This is the common cause of "SetTx dropped after
    /// SetStandby(XOSC)" on boards without a wired BUSY line.
    fn wait_ready_with_max_busy(&self, max_busy: Duration) -> Result<(), LoRaError> {
        match &self.busy {
            Some(busy) => {
                let deadline = Instant::now() + max_busy;
                while Instant::now() < deadline {
                    let val = busy
                        .get_value()
                        .map_err(|e| LoRaError::Gpio(format!("busy read: {}", e)))?;
                    if !val {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_micros(500));
                }
                Err(LoRaError::Timeout)
            }
            None => {
                // Without a BUSY pin we must use a safe minimum delay.
                // The 200 ms default covers the worst case for a 64-word
                // (256-byte) WriteFlashEncrypted chunk: the LR11xx programs
                // 32-byte internal pages at up to ~30 ms each, so 8 pages +
                // command-processing overhead is the upper bound.
                // write_command calls wait_ready twice per chunk (before
                // and after the SPI transfer), so 2 × 200 ms ≈ 400 ms per
                // chunk.
                //
                // For longer operations (notably SetStandby(XOSC) whose
                // BUSY window is the configured tcxo_startup_delay) the
                // caller's `max_busy` overrides this floor. The
                // LR1121_NO_BUSY_SLEEP_MS env var still hard-overrides for
                // users who know their hardware is faster (or slower).
                // The proper fix is to wire BUSY to a host GPIO and let
                // the poll loop above return as soon as the chip is
                // actually ready.
                let ms = std::env::var("LR1121_NO_BUSY_SLEEP_MS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or_else(|| max_busy.as_millis().max(200) as u64);
                std::thread::sleep(std::cmp::max(
                    self.command_delay,
                    Duration::from_millis(ms),
                ));
                Ok(())
            }
        }
    }

    /// Max busy time the chip can spend on `SetStandby(XOSC)` — the
    /// configured `tcxo_startup_delay` plus a 100 ms margin to absorb
    /// SPI/IO jitter. Falls back to 420 ms if no config is loaded (e.g.
    /// before `init()`), which is enough for the default 320 ms TCXO
    /// startup with margin.
    fn xosc_max_busy(&self) -> Duration {
        self.config
            .as_ref()
            .map(|c| c.tcxo_startup_delay + Duration::from_millis(100))
            .unwrap_or(Duration::from_millis(420))
    }

    /// Hardware reset via the NRESET pin (no-op if reset is not wired).
    /// Public so callers can put the chip into a known state without
    /// running the full `init` sequence (which would try to start the
    /// XOSC and fail with HF_XOSC_START_ERR on a broken TCXO).
    pub fn hardware_reset(&mut self) -> Result<(), LoRaError> {
        match &self.reset {
            Some(reset) => {
                reset.set_value(true)
                    .map_err(|e| LoRaError::Gpio(format!("reset high: {}", e)))?;
                std::thread::sleep(Duration::from_millis(10));
                reset.set_value(false)
                    .map_err(|e| LoRaError::Gpio(format!("reset low: {}", e)))?;
                std::thread::sleep(Duration::from_millis(10));
                reset.set_value(true)
                    .map_err(|e| LoRaError::Gpio(format!("reset high: {}", e)))?;
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    }

    /// Write command: send 16-bit opcode + args.
    /// Returns the 32-bit IrqStatus embedded in the response.
    ///
    /// Uses the default 200 ms BUSY wait, which is the worst case for a
    /// normal radio command or a 64-word WriteFlashEncrypted chunk. For
    /// long-running operations — specifically `SetStandby(XOSC)` whose
    /// BUSY window is the configured `tcxo_startup_delay` — callers
    /// must use `write_command_with_max_busy` with the XOSC budget,
    /// otherwise the post-wait returns while the chip is still BUSY and
    /// the next command is silently dropped.
    fn write_command(&mut self, opcode: u16, args: &[u8]) -> Result<u32, LoRaError> {
        self.write_command_with_max_busy(opcode, args, Duration::from_millis(200))
    }

    /// Write command with an explicit BUSY budget. See
    /// `wait_ready_with_max_busy` for guidance on choosing `max_busy`.
    /// Returns the 32-bit IrqStatus embedded in the response.
    fn write_command_with_max_busy(
        &mut self,
        opcode: u16,
        args: &[u8],
        max_busy: Duration,
    ) -> Result<u32, LoRaError> {
        self.wait_ready_with_max_busy(max_busy)?;
        let mut tx = vec![(opcode >> 8) as u8, (opcode & 0xFF) as u8];
        tx.extend_from_slice(args);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        self.wait_ready_with_max_busy(max_busy)?;

        let stat1 = rx.first().copied().unwrap_or(0);
        log::trace!("lr1121: tx={:02X?} rx={:02X?} stat1=0x{stat1:02X}", tx, rx);

        self.log_cmd_status(opcode, stat1);
        self.prev_status = Some((opcode, stat1));

        let irq = if rx.len() >= 6 {
            (rx[2] as u32) << 24 | (rx[3] as u32) << 16 | (rx[4] as u32) << 8 | rx[5] as u32
        } else {
            0
        };
        Ok(irq)
    }

    /// Read command: send 16-bit opcode + args, wait BUSY, then read response.
    fn read_command(&mut self, opcode: u16, args: &[u8], read_len: usize) -> Result<Vec<u8>, LoRaError> {
        self.wait_ready()?;
        // Phase 1 — send command; Stat1 reflects previous command status
        let mut tx = vec![(opcode >> 8) as u8, (opcode & 0xFF) as u8];
        tx.extend_from_slice(args);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        let stat1 = rx.first().copied().unwrap_or(0);
        log::trace!("lr1121: readcmd tx={:02X?} rx={:02X?} stat1=0x{stat1:02X}", tx, rx);
        self.log_cmd_status(opcode, stat1);
        self.prev_status = Some((opcode, stat1));
        self.wait_ready()?;

        // Phase 2 — read response data (preceded by Stat1)
        let read_tx = vec![0x00u8; read_len + 1];
        let mut read_rx = vec![0x00u8; read_len + 1];
        self.spi.xfer(&read_tx, &mut read_rx)?;
        self.wait_ready()?;
        log::trace!("lr1121: readcmd phase2 tx={:02X?} rx={:02X?}", read_tx, read_rx);

        // First byte is Stat1, remaining bytes are the actual response
        Ok(read_rx[1..].to_vec())
    }

    /// Read the 32-bit IRQ status word (LR1121 UM §4.1, GetIrqStatus 0x0100).
    /// Bits: bit 2=TX_DONE, 3=RX_DONE, 4=PREAMBLE_DETECTED,
    /// 5=SYNC_WORD_VALID, 6=HEADER_ERR, 7=ERR, 8=CAD_DONE,
    /// 9=CAD_DETECTED, 10=TIMEOUT.
    pub fn get_irq_status(&mut self) -> Result<u32, LoRaError> {
        // Wait for the previous command to finish (if any) before sampling
        // status; otherwise stat1 we read will reflect that command rather
        // than the current state.
        self.wait_ready()?;

        // LR11xx returns stat1+stat2+irq[4] on any NSS-low transaction. A
        // direct NOP read (zero bytes on MOSI) is simpler than sending
        // CMD_GET_STATUS with trailing NOPs and avoids any chance of the
        // chip entering BUSY mid-transaction.
        let rx = self.read_status_pair()?;
        let stat1 = rx[0];
        let stat2 = rx[1];
        log::trace!(
            "lr1121: get_irq rx={:02X?} stat1=0x{stat1:02X} stat2=0x{stat2:02X}",
            rx
        );

        if let Some((prev_opcode, prev_stat1)) = self.prev_status.take() {
            self.log_cmd_status(prev_opcode, prev_stat1);
        }
        self.prev_status = Some((CMD_GET_STATUS, stat1));
        Ok((rx[2] as u32) << 24 | (rx[3] as u32) << 16 | (rx[4] as u32) << 8 | rx[5] as u32)
    }

    /// Read both LR11xx status bytes (GetStatus 0x0100, or equivalently a
    /// direct NSS-low NOP read). The chip always returns 6 bytes on any
    /// NSS-low transaction: stat1, stat2, irq[4].
    ///
    /// LR11xx stat1 layout: bit 0 = interrupt pending, bits 3:1 = last
    /// command's status. LR11xx stat2 layout: bit 0 = running from flash,
    /// bits 3:1 = chip mode, bits 7:4 = reset status.
    fn read_status_pair(&mut self) -> Result<[u8; 6], LoRaError> {
        // The LR11xx returns stat1+stat2+irq[4] on any NSS-low transaction
        // (see lr11xx_system_get_status in the Semtech driver). We do a
        // direct 6-byte NSS-low NOP read so we don't have to deal with the
        // chip entering BUSY for a "real" command, and we don't have to
        // wait for the response-carrying second half of read_command.
        let mut rx = [0u8; 6];
        self.spi.xfer(&[0u8; 6], &mut rx)?;
        Ok(rx)
    }

    /// Read the raw stat2 byte (LR11xx system status). This is the byte
    /// that carries the chip mode: bits 3:1 hold one of `CHIP_MODE_*`
    /// (0x1=STBY_RC, 0x2=STBY_XOSC, 0x3=FS, 0x4=RX, 0x5=TX). Bit 0 is
    /// "running from flash" and bits 7:4 are the reset reason.
    ///
    /// Note: this layout is *different* from the SX1262, which puts the
    /// chip mode in stat1 bits 6:4 with values 0x2..=0x6. Don't
    /// cross-port SX1262 status checks without re-checking the layout.
    pub fn get_status(&mut self) -> Result<u8, LoRaError> {
        let rx = self.read_status_pair()?;
        // rx[0] = stat1, rx[1] = stat2
        Ok(rx[1])
    }

    /// Read just the chip-mode field from stat2. Returns one of
    /// `CHIP_MODE_*` (0x1..=0x5). `Ok(0x0)` is reserved (FSM) and a
    /// dead-bus / not-yet-responding value.
    pub fn get_chip_mode(&mut self) -> Result<u8, LoRaError> {
        let stat2 = self.get_status()?;
        Ok((stat2 & 0x0F) >> 1)
    }

    /// Explicitly enter STDBY_XOSC so the host can verify the XO actually
    /// starts (diagnostic helper; status is visible on the next read).
    /// Uses the configured `tcxo_startup_delay` as the BUSY budget so the
    /// chip has time to attempt the XOSC startup before we report a
    /// status (otherwise the post-wait returns while BUSY is still
    /// asserted and the next read sees garbage).
    pub fn set_standby_xosc(&mut self) -> Result<(), LoRaError> {
        self.write_command_with_max_busy(CMD_SET_STANDBY, &[STANDBY_XOSC], self.xosc_max_busy())
            .map(|_| ())
    }

    /// Wait until the chip reports STBY_XOSC. The chip holds BUSY during
    /// the XO startup window but still answers NSS-low status reads, so
    /// polling the stat2 chip-mode field is the software BUSY-wait.
    /// Returns Ok(true) if STBY_XOSC was reached within `timeout`.
    pub fn wait_for_standby_xosc(&mut self, timeout: Duration) -> Result<bool, LoRaError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.get_chip_mode()? == CHIP_MODE_STBY_XOSC {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(false)
    }

    /// Enter STDBY_XOSC and wait for the XO to come up, retrying for a slow
    /// or marginal TCXO. On success any latched XOSC/PLL startup error is
    /// cleared so later checks aren't misread. Without a BUSY line we poll
    /// the status byte; this is the software equivalent of waiting for
    /// BUSY to release.
    pub fn enter_standby_xosc(
        &mut self,
        startup_delay: Duration,
    ) -> Result<(), LoRaError> {
        let timeout = startup_delay + Duration::from_millis(100);
        let max_busy = startup_delay + Duration::from_millis(100);
        for attempt in 0..4 {
            self.write_command_with_max_busy(
                CMD_SET_STANDBY,
                &[STANDBY_XOSC],
                max_busy,
            )
            .map(|_| ())?;
            if self.wait_for_standby_xosc(timeout)? {
                let _ = self.clear_device_errors();
                return Ok(());
            }
            log::warn!(
                "lr1121: STDBY_XOSC attempt {attempt} timed out (delay {startup_delay:?}); retrying"
            );
        }
        Err(LoRaError::Chipset(
            "XO did not reach STBY_XOSC within timeout".into(),
        ))
    }

    /// Ensure the chip is awake in STBY_RC without ever putting it to sleep.
    /// NSS falling edges wake a sleeping chip and trigger a cold restart into
    /// STBY_RC (LR1121 UM §2.1.9); on an already-awake chip they are harmless
    /// no-ops. Polls with repeated edges up to a bounded budget.
    ///
    /// This is what `init` uses instead of `software_cold_start`: putting the
    /// chip into Powerdown and waking it via NSS is unreliable on boards whose
    /// TCXO is marginal (a stalled post-wake restart strands the chip in SLEEP
    /// and only a physical NRESET recovers it), and a warm restart plus the
    /// normal init sequence's `clear_device_errors` achieves the same clean
    /// slate without that risk.
    fn wake_to_standby_rc(&mut self) -> Result<(), LoRaError> {
        // If the chip is awake this moves it to STBY_RC instantly; if it is
        // asleep the command's NSS falling edge is the wake trigger (the
        // command itself is ignored until the restart completes).
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC]).map(|_| ())?;
        std::thread::sleep(Duration::from_millis(10));
        let deadline = Instant::now() + Duration::from_millis(3000);
        while Instant::now() < deadline {
            if let Ok(mode) = self.get_chip_mode() {
                if mode == CHIP_MODE_STBY_RC {
                    log::debug!("lr1121: awake in STBY_RC");
                    return Ok(());
                }
            }
            self.spi.xfer(&[0x00, 0x00], &mut [0u8; 2])?;
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(LoRaError::Chipset(
            "lr1121: chip did not reach STBY_RC; NRESET required".into(),
        ))
    }

    /// POR-equivalent software reset via SetSleep cold start.
    ///
    /// The LR1121 has no SPI reset command and the NRST pin may not be wired
    /// on every board. Without a hardware reset, a warm restart leaves the
    /// chip in its previous run's state (e.g. a latched HF_XOSC_START_ERR)
    /// and re-initialization can silently fail. Entering SLEEP in cold-start
    /// mode and waking the device by dropping NSS performs a full restart
    /// into STBY_RC (LR1121 UM §2.1.9; ResetStatus afterwards reads "Wakeup
    /// NSS toggling"). The sleep/wake cycle is verified by `probe_sleep`.
    ///
    /// NOTE: `init` does NOT call this. A failed wake leaves the chip in
    /// Powerdown (all-0xFF reads, ~0 µA draw) that only a physical NRESET can
    /// recover, and the wake is unreliable on boards with a marginal TCXO. Use
    /// `wake_to_standby_rc` for normal operation and reserve this for explicit
    /// sleep testing (e.g. `probe_sleep`) where the NRESET risk is accepted.
    pub fn software_cold_start(&mut self) -> Result<(), LoRaError> {
        // Retry the whole sleep/wake cycle a few times. The post-wake cold
        // restart is ~30ms typical (LR11xx UM §2.1.9) but can stall far
        // longer on a marginal board (e.g. a TCXO that never starts leaves
        // the boot in limbo), so each cycle polls with repeated NSS wake
        // edges up to a bounded budget, and a fresh cycle re-arms the wake
        // with a brand-new SetStandby -> SetSleep -> NSS edge sequence.
        for attempt in 0..3 {
            // SetSleep is only accepted from STDBY.
            self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
            std::thread::sleep(Duration::from_millis(5));

            // SleepConfig = 0x00: RTC wakeup disabled, cold start (no
            // retention). sleep_time = 0: NSS falling edge is the wake-up
            // trigger. BUSY stays asserted for the whole sleep period, so we
            // don't wait on it here.
            let args = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            self.spi.xfer(
                &[(CMD_SET_SLEEP >> 8) as u8, CMD_SET_SLEEP as u8, args[0], args[1], args[2], args[3], args[4], args[5]],
                &mut [0u8; 8],
            )?;
            std::thread::sleep(Duration::from_millis(50));

            // NSS falling edge wakes the device; each dummy read is a wake
            // trigger. After waking it boots cold into STBY_RC.
            let deadline = Instant::now() + Duration::from_millis(3000);
            while Instant::now() < deadline {
                self.spi.xfer(&[0x00, 0x00], &mut [0u8; 2])?;
                std::thread::sleep(Duration::from_millis(20));
                if let Ok(mode) = self.get_chip_mode() {
                    if mode == CHIP_MODE_STBY_RC {
                        log::debug!(
                            "lr1121: software cold-start OK (mode={mode}, attempt={attempt})"
                        );
                        return Ok(());
                    }
                }
            }
            log::warn!("lr1121: software cold-start wake attempt {attempt} timed out");
        }

        // The wake never completed. Never leave the chip in SLEEP if we can
        // avoid it: fall back to a hardware reset when a reset line is wired
        // (clean POR-equivalent boot into STBY_RC). Otherwise the chip stays
        // in Powerdown and needs a physical NRESET to come back.
        if self.reset.is_some() {
            log::warn!("lr1121: NSS wake timed out, falling back to hardware reset");
            self.hardware_reset()?;
            self.wait_ready()?;
            std::thread::sleep(Duration::from_millis(10));
            let mode = self.get_chip_mode()?;
            if mode == CHIP_MODE_STBY_RC {
                log::debug!("lr1121: hardware reset OK (mode={mode})");
                return Ok(());
            }
            return Err(LoRaError::Chipset(format!(
                "software cold-start: chip not in STBY_RC after hardware reset (mode={mode})"
            )));
        }

        Err(LoRaError::Chipset(
            "software cold-start: chip did not wake into STBY_RC after SetSleep; NRESET required"
                .into(),
        ))
    }

    /// Probe whether SetSleep actually puts the chip into SLEEP. A genuinely
    /// fresh (power-cycled) chip honours SetSleep and is unresponsive during
    /// the wake transaction; a warm-stuck chip ignores SetSleep and stays
    /// responsive. Returns true if the chip was asleep at the time of the
    /// wake read.
    pub fn probe_sleep(&mut self) -> Result<bool, LoRaError> {
        // SetSleep is only accepted from STDBY. Move to STDBY_RC first so a
        // warm-stuck chip that is still in TX or RX is in a defined mode
        // before we ask it to sleep.
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC]).map(|_| ())?;
        std::thread::sleep(Duration::from_millis(5));

        // SetSleep args: bit 0 = warm_start, bit 1 = rtc_wakeup. We use
        // 0x00 (cold start) for a clean POR-equivalent state, and pass
        // sleep_time = 0 because we don't need RTC wake — NSS falling edge
        // is what will wake the chip.
        let args = [0x00, 0x00, 0x00, 0x00, 0x00];
        self.write_command(CMD_SET_SLEEP, &args)?;
        std::thread::sleep(Duration::from_millis(50));

        // Blind NSS-low NOP read: the LR11xx returns stat1+stat2+irq on
        // any NSS-low transaction that isn't a command (see
        // lr11xx_system_get_status). NSS falling edge is the wake-up
        // trigger for SetSleep cold-start, so if the chip was actually
        // asleep the MISO line is still floating during the first byte
        // of the response and we read garbage. If SetSleep was ignored
        // (warm/stuck chip) the chip is fully responsive and returns a
        // real status byte. We deliberately do NOT call wait_ready()
        // here — the 50ms wait in `command_delay` would let the chip
        // finish waking up and defeat the test.
        let mut rx = [0u8; 6];
        self.spi.xfer(&[0u8; 6], &mut rx)?;
        std::thread::sleep(Duration::from_millis(10));

        let was_asleep = rx.iter().all(|&b| b == 0x00 || b == 0xFF);
        log::info!(
            "lr1121: probe_sleep: status bytes = {:02X?} -> chip was {}",
            rx,
            if was_asleep { "ASLEEP (fresh POR)" } else { "AWAKE (warm/stuck)" }
        );
        Ok(was_asleep)
    }

    /// Read a single 32-bit register/memory word (WriteRegmem32 / ReadRegmem32,
    /// LR11xx regmem driver §3.1-3.2). Returns the raw 32-bit value.
    pub fn read_register(&mut self, addr: u32) -> Result<u32, LoRaError> {
        // ReadRegmem32: opcode(2) + address(4) + length(1) → response is
        // length*4 bytes. Our read_command helper prepends a Stat1 byte
        // (status from the *previous* command), so pass length=1 and let
        // read_command pull off the leading byte.
        let args = [
            (addr >> 24) as u8,
            (addr >> 16) as u8,
            (addr >> 8) as u8,
            addr as u8,
            0x01, // length: one 32-bit word
        ];
        let data = self.read_command(CMD_READ_REGMEM32, &args, 4)?;
        if data.len() < 4 {
            return Err(LoRaError::Chipset(format!(
                "lr1121: read_register(0x{addr:08X}) short response ({} bytes)",
                data.len()
            )));
        }
        Ok((data[0] as u32) << 24
            | (data[1] as u32) << 16
            | (data[2] as u32) << 8
            | data[3] as u32)
    }

    /// Write a single 32-bit register/memory word (WriteRegmem32,
    /// LR11xx regmem driver §3.1).
    pub fn write_register(&mut self, addr: u32, value: u32) -> Result<(), LoRaError> {
        // WriteRegmem32: opcode(2) + address(4) + data(N*4). The opcode
        // length is fixed; the data payload goes in args.
        let mut args = vec![
            (addr >> 24) as u8,
            (addr >> 16) as u8,
            (addr >> 8) as u8,
            addr as u8,
        ];
        args.extend_from_slice(&value.to_be_bytes());
        self.write_command(CMD_WRITE_REGMEM32, &args).map(|_| ())
    }

    /// Quick SPI ping: read the chip version register and verify the
    /// response is a plausible value (not all-zeros, all-ones, or other
    /// floating-bus garbage). This catches wiring problems before we
    /// start trying to drive the radio.
    pub fn ping(&mut self) -> Result<(), LoRaError> {
        let data = self.read_command(CMD_GET_VERSION, &[], 4)?;
        if data.len() < 4 {
            return Err(LoRaError::Chipset(
                "lr1121: SPI ping failed (no response)".into(),
            ));
        }
        let v = (data[0] as u32) << 24
            | (data[1] as u32) << 16
            | (data[2] as u32) << 8
            | data[3] as u32;
        if v == 0x0000_0000 || v == 0xFFFF_FFFF {
            return Err(LoRaError::Chipset(format!(
                "lr1121: SPI ping returned 0x{v:08X} (bus floating or chip not connected)"
            )));
        }
        // hardware_id (data[0]) is 0x04 for LR1110/LR1121. Other Semtech
        // parts use 0x01/0x02, but anything in 0x00-0x0F is plausible.
        let hw = data[0];
        log::debug!(
            "lr1121: SPI ping OK (version=0x{v:08X}, hw=0x{hw:02X}, fw=0x{:02X}{:02X})",
            data[2], data[3]
        );
        Ok(())
    }

    /// Read the chip identity via GetVersion (0x0101). Returns the packed
    /// 4 bytes: [hw_revision, type, fw_major, fw_minor]. Use this to
    /// confirm which LR11xx die is fitted (e.g. LR1110 vs LR1120/LR1121),
    /// since the SPI protocol differs subtly between variants.
    pub fn get_chip_version(&mut self) -> Result<u32, LoRaError> {
        let data = self.read_command(CMD_GET_VERSION, &[], 4)?;
        if data.len() < 4 {
            return Err(LoRaError::Chipset(
                "lr1121: GetVersion returned no data".into(),
            ));
        }
        Ok((data[0] as u32) << 24
            | (data[1] as u32) << 16
            | (data[2] as u32) << 8
            | data[3] as u32)
    }

    /// Configure the TCXO (SetTcxoMode, 0x0117): DIO3 sources the TCXO
    /// supply at `voltage_v` while the firmware starts the 32 MHz reference.
    /// `startup_delay` is the timeout the firmware waits for the TCXO to
    /// oscillate, in 30.52µs steps (WaveShare default ~9.2ms = 300 steps).
    ///
    /// This is a public knob for diagnostics: a working TCXO module only
    /// starts its reference clock when this command has been accepted
    /// (DIO3 becomes live at the selected voltage). If the XO gate still
    /// fails after this, measure DIO3 with a multimeter — 0V here means the
    /// TCXO was never powered (software/harness), ~3.0V means the clock
    /// path itself is the problem.
    pub fn set_tcxo_mode(&mut self, voltage_v: f64, startup_delay: Duration) -> Result<(), LoRaError> {
        let code = tcxo_voltage_code(voltage_v);
        // TCXO startup timeout is 24 bits in 30.52µs steps. Honour the
        // caller's delay (clamped to a sane window); the WaveShare default
        // of 9.2ms corresponds to ~300 steps.
        let delay: u32 = (startup_delay
            .as_micros()
            .saturating_div(30)
            .min(0xFF_FFFF) as u32)
            .max(1);
        self.write_command(CMD_SET_TXCO_MODE, &[
            code,
            (delay >> 16) as u8,
            (delay >> 8) as u8,
            delay as u8,
        ])?;
        std::thread::sleep(Duration::from_millis(15));
        log::info!(
            "lr1121: SetTcxoMode accepted (v={voltage_v}V code=0x{code:02X}, timeout={startup_delay:?} = {delay} steps) — DIO3 should now be sourcing ~{voltage_v}V"
        );
        Ok(())
    }

    fn set_rf_frequency(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        // Frequency in Hz directly (matches Semtech lr11xx_radio_set_rf_freq)
        let args = [
            (freq_hz >> 24) as u8,
            (freq_hz >> 16) as u8,
            (freq_hz >> 8) as u8,
            freq_hz as u8,
        ];
        self.write_command(CMD_SET_RF_FREQUENCY, &args)?;
        Ok(())
    }

    fn set_modulation_params(&mut self, sf: u8, bw_hz: u32, cr: u8, band: FrequencyBand) -> Result<(), LoRaError> {
        let bw = match band {
            FrequencyBand::Band2p4G => lora_bandwidth_code_2p4g(bw_hz),
            _ => lora_bandwidth_code_subghz(bw_hz),
        };
        let cr_code = lora_coding_rate_code(cr);
        let ldro = if needs_ldro(sf, bw_hz) { 0x01 } else { 0x00 };
        self.write_command(CMD_SET_MODULATION_PARAMS, &[sf, bw, cr_code, ldro])?;
        Ok(())
    }

    fn set_packet_params(&mut self, preamble: u16, header_mode: u8, payload_len: u8, crc: u8, iq: u8) -> Result<(), LoRaError> {
        self.write_command(
            CMD_SET_PACKET_PARAMS,
            &[
                (preamble >> 8) as u8,
                (preamble & 0xFF) as u8,
                header_mode,
                payload_len,
                crc,
                iq,
            ],
        )?;
        Ok(())
    }

    fn set_tx_params(&mut self, power_dbm: i8, band: FrequencyBand) -> Result<(), LoRaError> {
        match band {
            FrequencyBand::SubGhz => {
                // High power PA: range -9 to +22 dBm (0xF7 to 0x16)
                let clamped = power_dbm.clamp(-9, 22);
                let power = if clamped >= 14 { 0x16 } else { clamped as u8 };
                self.write_command(CMD_SET_TX_PARAMS, &[power, RAMP_800U])?;
            }
            FrequencyBand::LBand | FrequencyBand::SBand | FrequencyBand::Band2p4G => {
                // High frequency PA: range -18 to +13 dBm (0xEE to 0x0F)
                let clamped = power_dbm.clamp(-18, 13);
                self.write_command(CMD_SET_TX_PARAMS, &[clamped as u8, RAMP_800U])?;
            }
        }
        Ok(())
    }

    fn set_pa_config(&mut self, power_dbm: i8, band: FrequencyBand) -> Result<(), LoRaError> {
        match band {
            FrequencyBand::SubGhz => {
                if power_dbm <= 14 {
                    // Low Power PA (PaSel=0x00): range -17 to +14 dBm
                    self.write_command(CMD_SET_PA_CONFIG, &[0x00, 0x00, 0x04, 0x00])?;
                } else {
                    // High Power PA (PaSel=0x01): range -9 to +22 dBm
                    let (pa_duty_cycle, hp_max) = subghz_pa_duty_cycle(power_dbm);
                    self.write_command(CMD_SET_PA_CONFIG, &[0x01, 0x01, pa_duty_cycle, hp_max])?;
                }
            }
            FrequencyBand::LBand | FrequencyBand::SBand | FrequencyBand::Band2p4G => {
                // High frequency PA
                self.write_command(CMD_SET_PA_CONFIG, &[0x02, 0x00, 0x00, 0x00])?;
            }
        }
        Ok(())
    }

    fn set_sync_word(&mut self, word: u16) -> Result<(), LoRaError> {
        // LR1121 uses a single-byte sync word (MSB of SX1262 16-bit word)
        let sync = if (word >> 8) != 0 { (word >> 8) as u8 } else { word as u8 };
        self.write_command(CMD_SET_LORA_SYNC_WORD, &[sync])?;
        Ok(())
    }

    fn set_dio_irq_params(&mut self, enabled: bool) -> Result<(), LoRaError> {
        let irq_mask = if enabled { IRQ_MASK_ALL } else { 0 };
        self.write_command(
            CMD_SET_DIO_IRQ_PARAMS,
            &[
                (irq_mask >> 24) as u8,
                (irq_mask >> 16) as u8,
                (irq_mask >> 8) as u8,
                irq_mask as u8,
                0, 0, 0, 0,
            ],
        )?;
        Ok(())
    }

    fn set_dio_as_rf_switch(&mut self, enabled: bool) -> Result<(), LoRaError> {
        if enabled {
            // Core1121-HF PE4259 SPDT: V1(DIO5/RFSW0), V2(DIO6/RFSW1).
            self.write_command(CMD_SET_DIO_AS_RF_SWITCH, &[
                RFSW0_HIGH | RFSW1_HIGH,  // RfswEnableCfg enable DIO5,6
                0x00,                     // RfswStbyCfg standby
                RFSW0_HIGH,               // RfswRxCfg RX
                RFSW0_HIGH | RFSW1_HIGH,  // RfSwTxCfg TX
                RFSW1_HIGH,               // RfSwTxHPCfg: High Power TX
                0x00,                     // RfSwTxHfCfg: High Frequency TX
                0x00,                     // RFU. GNSS?
                0x00,                     // RFU. Wifi?
            ])?;
        }
        Ok(())
    }

    fn apply_high_acp_workaround(&mut self) -> Result<(), LoRaError> {
        // Semtech workaround: clear bit 30 of register 0x00F30054
        // before RX, TX, CAD to avoid high adjacent channel power.
        let args = [
            0x00, 0xF3, 0x00, 0x54,  // address
            0x40, 0x00, 0x00, 0x00,  // mask = 1 << 30
            0x00, 0x00, 0x00, 0x00,  // data = 0
        ];
        self.write_command(CMD_WRITE_REGMEM32_MASK, &args)?;
        Ok(())
    }

    fn calibrate_image(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        if let Some((f1, f2)) = calibrate_image_bands(freq_hz) {
            self.write_command(CMD_CALIB_IMAGE, &[f1, f2])?;
        }
        Ok(())
    }

    fn clear_irq_status(&mut self, mask: u32) -> Result<(), LoRaError> {
        self.write_command(
            CMD_CLEAR_IRQ,
            &[
                (mask >> 24) as u8,
                (mask >> 16) as u8,
                (mask >> 8) as u8,
                mask as u8,
            ],
        )?;
        Ok(())
    }

    fn read_buffer(&mut self, offset: u8, count: usize) -> Result<Vec<u8>, LoRaError> {
        self.read_command(CMD_READ_BUFFER_8, &[offset, count as u8], count)
    }

    fn get_rx_buffer_status(&mut self) -> Result<(usize, u8), LoRaError> {
        let data = self.read_command(CMD_GET_RX_BUFFER_STATUS, &[], 2)?;
        if data.len() >= 2 {
            Ok((data[0] as usize, data[1]))
        } else {
            Ok((0, 0))
        }
    }

    fn get_packet_status(&mut self) -> Result<(f32, f32, f32), LoRaError> {
        let data = self.read_command(CMD_GET_PACKET_STATUS, &[], 3)?;
        if data.len() >= 3 {
            let rssi_raw = data[0] as i16;
            let snr_raw = data[1] as i8;
            let signal_rssi_raw = data[2] as i16;
            let rssi = -(rssi_raw as f32) / 2.0;
            let snr = (snr_raw as f32) * 0.25;
            let signal_rssi = -(signal_rssi_raw as f32) / 2.0;
            Ok((rssi, snr, signal_rssi))
        } else {
            Ok((0.0, 0.0, 0.0))
        }
    }

    /// Read the 16-bit device error word (LR1121 UM §2.1.5, GetErrors 0x010D).
    /// Bits accumulate since the last `clear_device_errors` call and cover
    /// oscillator startup/tune failures, PLL lock/calib failures, PA failures
    /// and image-calibration failures.
    pub fn get_device_errors(&mut self) -> Result<u16, LoRaError> {
        let data = self.read_command(CMD_GET_ERRORS, &[], 2)?;
        if data.len() >= 2 {
            Ok(((data[0] as u16) << 8) | data[1] as u16)
        } else {
            Ok(0)
        }
    }

    /// Clear the latched device error word (LR1121 UM §2.1.5,
    /// ClearErrors 0x010E). Always safe to call.
    pub fn clear_device_errors(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_CLEAR_ERRORS, &[]).map(|_| ())
    }

    /// Decode the 16-bit error word to a list of symbolic bit names.
    /// Bit meanings follow LR1121 UM Table 3-5.
    /// Exposed for diagnostic logging.
    pub fn decode_device_errors(err: u16) -> Vec<&'static str> {
        let mut bits = Vec::new();
        if err & ERR_LF_RC_CALIB != 0 { bits.push("LF_RC_CALIB_ERR"); }
        if err & ERR_HF_RC_CALIB != 0 { bits.push("HF_RC_CALIB_ERR"); }
        if err & ERR_ADC_CALIB != 0 { bits.push("ADC_CALIB_ERR"); }
        if err & ERR_PLL_CALIB != 0 { bits.push("PLL_CALIB_ERR"); }
        if err & ERR_IMG_CALIB != 0 { bits.push("IMG_CALIB_ERR"); }
        if err & ERR_HF_XOSC_START != 0 { bits.push("HF_XOSC_START_ERR"); }
        if err & ERR_LF_XOSC_START != 0 { bits.push("LF_XOSC_START_ERR"); }
        if err & ERR_PLL_LOCK != 0 { bits.push("PLL_LOCK_ERR"); }
        if err & ERR_RX_ADC_OFFSET != 0 { bits.push("RX_ADC_OFFSET_ERR"); }
        bits
    }

    // ── Bootloader commands (LR11xx bootloader 0x8000..=0x800D) ────────────
    //
    // These commands are only accepted by the chip when it is running in
    // bootloader mode. To reach that mode, send a `Reboot(0x8005)` with
    // `stay_in_bootloader=true` (arg 0x03) and wait for the chip to come
    // back up — the same physical NSS/BUSY/MISO wiring is used, but the
    // command set exposed is the bootloader set rather than the radio/
    // system one. GetVersion (0x0101) and GetStatus (0x0100) are shared
    // with the system command set and work in both modes.
    //
    // Typical update flow (see SWTL001 `lr11xx_bootloader_update.c`):
    //   1. bl_reboot(true) — chip enters bootloader
    //   2. bl_get_version() — confirm bootloader is alive and at a
    //      compatible version
    //   3. bl_erase_flash() — wipe the existing flash
    //   4. bl_write_flash_encrypted_full(image) — stream the new image
    //      in 64-word chunks
    //   5. bl_reboot(false) — leave bootloader and execute the new FW

    /// Read the bootloader version (GetVersion 0x0101). Same opcode as
    /// the system version command; the response format is identical.
    pub fn bl_get_version(&mut self) -> Result<BlVersion, LoRaError> {
        let data = self.read_command(CMD_GET_VERSION, &[], 4)?;
        if data.len() < 4 {
            return Err(LoRaError::Chipset(
                "bl: GetVersion returned no data".into(),
            ));
        }
        Ok(BlVersion {
            hw: data[0],
            typ: data[1],
            fw: ((data[2] as u16) << 8) | data[3] as u16,
        })
    }

    /// Reboot the chip from system mode (Reboot 0x0118). If
    /// `stay_in_bootloader` is true the chip boots into the bootloader
    /// (which exposes the firmware-update opcodes) instead of executing
    /// the application firmware. This is the **only** SPI command that
    /// can move the chip from system mode into bootloader mode. The
    /// argument byte is `0x03` for stay-in-bootloader, `0x00` to run
    /// the application firmware after the reboot.
    ///
    /// Note: this is the system-mode Reboot, distinct from
    /// `bl_reboot` (0x8005) which is the bootloader's own reboot. Both
    /// use the same `0x03`/`0x00` argument, but each is only accepted
    /// in its own mode.
    pub fn system_reboot(&mut self, stay_in_bootloader: bool) -> Result<(), LoRaError> {
        let arg = if stay_in_bootloader { 0x03 } else { 0x00 };
        self.write_command(CMD_SYSTEM_REBOOT, &[arg]).map(|_| ())
    }

    /// Reboot the chip from bootloader mode (Reboot 0x8005). If
    /// `stay_in_bootloader` is true the chip stays in the bootloader
    /// after the reboot; otherwise it runs the application firmware.
    ///
    /// This is the bootloader-mode Reboot, only valid when the chip is
    /// already running the bootloader. To **enter** bootloader from
    /// system mode use `system_reboot` (0x0118) instead.
    pub fn bl_reboot(&mut self, stay_in_bootloader: bool) -> Result<(), LoRaError> {
        let arg = if stay_in_bootloader { 0x03 } else { 0x00 };
        self.write_command(CMD_BL_REBOOT, &[arg]).map(|_| ())
    }

    /// Reboot the chip using the opcode appropriate to the current
    /// mode. The chip's mode is read from `stat2` bit 0
    /// (`is_running_from_flash`): if the application firmware is
    /// executing, this issues the system Reboot (0x0118); if the
    /// bootloader is executing, this issues the bootloader's Reboot
    /// (0x8005). Both opcodes share the same `0x03`/`0x00` argument
    /// but each is only accepted in its own mode, so issuing the
    /// wrong one results in a `CMD_P_ERR` (visible as a `WARN` log
    /// from the SDK and a failed command). Use this method from
    /// contexts where you don't want to track the mode yourself
    /// (e.g. generic firmware-update tooling); use `system_reboot`
    /// or `bl_reboot` directly when you already know which mode the
    /// chip is in.
    pub fn reboot(&mut self, stay_in_bootloader: bool) -> Result<(), LoRaError> {
        let stat2 = self.get_status()?;
        let running_from_flash = (stat2 & 0x01) != 0;
        log::trace!(
            "lr1121: reboot(stay_in_bootloader={stay_in_bootloader}) \
             in {} mode (stat2=0x{stat2:02X})",
            if running_from_flash { "system" } else { "bootloader" }
        );
        if running_from_flash {
            self.system_reboot(stay_in_bootloader)
        } else {
            self.bl_reboot(stay_in_bootloader)
        }
    }

    /// Erase the entire flash (EraseFlash 0x8000). Must be called
    /// before any WriteFlashEncrypted; the chip returns CMD_FAIL if a
    /// write is attempted on a non-erased region.
    pub fn bl_erase_flash(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_BL_ERASE_FLASH, &[])?;
        self.check_prev_status(CMD_BL_ERASE_FLASH, "EraseFlash")?;
        // EraseFlash erases the *entire* flash and can take several
        // seconds. The `write_command` helper only waits the standard
        // ~200 ms (the no-BUSY fallback), which is way too short for a
        // full chip erase and would let subsequent `WriteFlashEncrypted`
        // commands start before the erase actually finishes. Sleep an
        // additional 10 s here when BUSY isn't wired (the same 10 s
        // would be a no-op with BUSY since the poll loop in
        // `wait_ready` would just return immediately). The proper
        // solution is still to wire BUSY; this is the no-BUSY fallback.
        if self.busy.is_none() {
            std::thread::sleep(Duration::from_secs(10));
        }
        Ok(())
    }

    /// Write a single chunk of encrypted flash data
    /// (WriteFlashEncrypted 0x8003). `data` must contain 1..=`BL_FLASH_CHUNK_WORDS`
    /// (64) `u32` words. The offset is in bytes from the start of flash
    /// and must be 256-byte aligned for every chunk except possibly the
    /// last one.
    pub fn bl_write_flash_encrypted(
        &mut self,
        offset: u32,
        data: &[u32],
    ) -> Result<(), LoRaError> {
        if data.is_empty() || data.len() > BL_FLASH_CHUNK_WORDS {
            return Err(LoRaError::Chipset(format!(
                "bl: WriteFlashEncrypted chunk must be 1..={} words, got {}",
                BL_FLASH_CHUNK_WORDS,
                data.len()
            )));
        }
        let mut args = Vec::with_capacity(4 + data.len() * 4);
        args.extend_from_slice(&offset.to_be_bytes());
        for &word in data {
            args.extend_from_slice(&word.to_be_bytes());
        }
        self.write_command(CMD_BL_WRITE_FLASH_ENCRYPTED, &args)?;
        self.check_prev_status(
            CMD_BL_WRITE_FLASH_ENCRYPTED,
            &format!("WriteFlashEncrypted at offset 0x{offset:08X}"),
        )
    }

    /// Write a complete encrypted firmware image to flash, chunking
    /// internally into 64-word (256-byte) WriteFlashEncrypted commands.
    /// `data` length in words may be any positive multiple of 1.
    pub fn bl_write_flash_encrypted_full(
        &mut self,
        offset: u32,
        data: &[u32],
    ) -> Result<(), LoRaError> {
        let mut remaining = data;
        let mut local_offset = offset;
        while !remaining.is_empty() {
            let chunk = remaining.len().min(BL_FLASH_CHUNK_WORDS);
            self.bl_write_flash_encrypted(local_offset, &remaining[..chunk])?;
            remaining = &remaining[chunk..];
            local_offset += (chunk as u32) * 4;
        }
        Ok(())
    }

    /// Read the calculated 16-byte SHA-256 (or chip-specific) hash of
    /// the current flash content (GetHash 0x8004). Used to verify that
    /// a freshly-written image matches the reference image on the host
    /// before the bootloader hands control over to it.
    pub fn bl_get_hash(&mut self) -> Result<[u8; 16], LoRaError> {
        let data = self.read_command(CMD_BL_GET_HASH, &[], 16)?;
        if data.len() < 16 {
            return Err(LoRaError::Chipset(
                "bl: GetHash short response".into(),
            ));
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&data[..16]);
        // The read_command helper treats the first byte of the
        // response as stat1 and strips it; check it here too so a
        // CMD_FAIL / CMD_P_ERR reply doesn't get returned as a
        // "hash" of garbage bytes. Without this check, callers
        // (notably `bl_is_in_bootloader`) can incorrectly conclude
        // that the chip is in bootloader mode when the read actually
        // failed.
        if let Some((_, stat1)) = self.prev_status {
            match (stat1 >> 1) & 0x07 {
                0 => return Err(LoRaError::Chipset(format!(
                    "bl: GetHash failed: CMD_FAIL (stat1=0x{stat1:02X})"
                ))),
                1 => return Err(LoRaError::Chipset(format!(
                    "bl: GetHash failed: CMD_P_ERR (stat1=0x{stat1:02X})"
                ))),
                _ => {}
            }
        }
        Ok(hash)
    }

    /// Probe whether the chip is currently running in bootloader mode.
    ///
    /// The bootloader's command set (opcodes 0x8000..=0x800D) is not
    /// recognized by the system firmware, so issuing a bootloader-only
    /// command and checking the response is a reliable probe. This
    /// method issues `GetHash` (0x8004) and treats the chip as being
    /// in bootloader mode if the response looks like a real 16-byte
    /// hash. In system mode the chip rejects the command, the SPI bus
    /// is not driven during the response phase, and the host reads
    /// either all-zeros or all-FF — both distinguishable from a real
    /// flash-content hash. Returns `false` on any I/O error so callers
    /// can use this as a single pre-flight check.
    pub fn bl_is_in_bootloader(&mut self) -> bool {
        match self.bl_get_hash() {
            Ok(hash) => {
                let all_zero = hash.iter().all(|&b| b == 0x00);
                let all_ff = hash.iter().all(|&b| b == 0xFF);
                !(all_zero || all_ff)
            }
            Err(_) => false,
        }
    }

    /// Read the 4-byte device PIN (GetPin 0x800B). Returned as a fixed
    /// `[u8; 4]`; the encoding is chip-specific and host code is expected
    /// to format it as needed.
    pub fn bl_read_pin(&mut self) -> Result<[u8; 4], LoRaError> {
        let data = self.read_command(CMD_BL_GET_PIN, &[], 4)?;
        if data.len() < 4 {
            return Err(LoRaError::Chipset(
                "bl: GetPin short response".into(),
            ));
        }
        let mut pin = [0u8; 4];
        pin.copy_from_slice(&data[..4]);
        Ok(pin)
    }

    /// Read the 8-byte chip EUI (ReadChipEui 0x800C).
    pub fn bl_read_chip_eui(&mut self) -> Result<[u8; 8], LoRaError> {
        let data = self.read_command(CMD_BL_READ_CHIP_EUI, &[], 8)?;
        if data.len() < 8 {
            return Err(LoRaError::Chipset(
                "bl: ReadChipEui short response".into(),
            ));
        }
        let mut eui = [0u8; 8];
        eui.copy_from_slice(&data[..8]);
        Ok(eui)
    }

    /// Read the 8-byte join EUI (ReadJoinEui 0x800D).
    pub fn bl_read_join_eui(&mut self) -> Result<[u8; 8], LoRaError> {
        let data = self.read_command(CMD_BL_READ_JOIN_EUI, &[], 8)?;
        if data.len() < 8 {
            return Err(LoRaError::Chipset(
                "bl: ReadJoinEui short response".into(),
            ));
        }
        let mut eui = [0u8; 8];
        eui.copy_from_slice(&data[..8]);
        Ok(eui)
    }

}

impl LoRaChipset for LR1121 {
    fn new(spi: SpiBus, gpio: GpioPins) -> Self {
        Self {
            spi,
            busy: gpio.busy,
            reset: gpio.reset,
            dio_irq: gpio.dio1,
            config: None,
            command_delay: Duration::from_millis(2),
            band: FrequencyBand::SubGhz,
            rx_active: false,
            tx_active: false,
            prev_status: None,
        }
    }

    fn init(&mut self, config: &LoRaConfig) -> Result<(), LoRaError> {
        self.command_delay = config.command_delay;
        self.band = FrequencyBand::from_freq(config.frequency);

        self.hardware_reset()?;
        // Warm restart only: never SetSleep the chip here. A failed NSS-wake
        // from Powerdown strands it in SLEEP (all-0xFF, only physical NRESET
        // recovers), and the wake is unreliable on boards with a marginal
        // TCXO. `wake_to_standby_rc` just forces the chip to STBY_RC and the
        // sequence below clears any latched errors.
        self.wake_to_standby_rc()?;
        self.wait_ready()?;
        std::thread::sleep(Duration::from_millis(10));
        log::trace!("lr1121: post-reset, starting init sequence");
        self.prev_status = None;

        // Quick SPI ping: confirm the chip is alive on the bus before we
        // start driving configuration commands. Catches wiring problems
        // (CS/MISO/MOSI/SCK swapped, missing ground, wrong mode) before
        // we blame the driver for a silent TX failure.
        self.ping()?;

        // Stash the config up-front so the radio stays usable (e.g. for a
        // diagnostic TX) even if a later init step below is tolerated.
        self.config = Some(config.clone());

        // Core1121-HF init sequence based on the Semtech LR11xx reference
        // init and RadioLib's LR11x0::modSetup: standby RC -> set regulator
        // -> set TCXO -> clear errors -> calibrate all -> and only then
        // switch to XOSC. POR with a TCXO connected skips all start-up
        // calibrations, so Calibrate must be re-issued after SetTcxoMode
        // and before any XOSC use, otherwise the first SetStandby(XOSC)
        // fails with HF_XOSC_START_ERR.

        // 1. Standby RC (the only mode available before TCXO is running)
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;

        // 1b. Set the LoRa packet type early so the whole transmit path is
        //     valid even if a later init step (XO startup) fails and init
        //     aborts — keeps the post-failure TX diagnostics meaningful.
        self.write_command(CMD_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;

        // 2. Calibrate the image for the target sub-GHz band. Done BEFORE the
        //    TCXO is enabled, matching the Semtech/WaveShare reference init
        //    (lr1121_config.c: SetStandby -> CalibrateImage -> SetRegMode ->
        //    ... -> SetTcxoMode -> CfgLfClk -> ClearErrors -> Calibrate).
        //    Image calibration on a TCXO module fails if run after the TCXO
        //    is configured but the reference clock is not yet up, and a
        //    latched IMG_CALIB error would otherwise poison XOSC startup.
        self.calibrate_image(config.frequency)?;

        // 3. Set regulator mode. Datasheet default is LDO (0x00); the DC-DC
        //    converter (0x01) needs a 15µH inductor and is only exercised in
        //    STDBY_XOSC/FS/RX/TX, so on boards without a working DC-DC rail
        //    the first XOSC start fails. RadioLib also defaults to LDO.
        self.write_command(CMD_SET_REG_MODE, &[if config.dcdc { REG_MODE_DCDC } else { 0x00 }])?;

        // 4. Configure TCXO — Core1121-HF uses 3.0V (code 0x06).
        //    Follow the user's voltage if set, otherwise default to 3.0V.
        self.set_tcxo_mode(
            config.tcxo_voltage.unwrap_or(3.0),
            config.tcxo_startup_delay,
        )?;

        // 5. Configure the low-frequency clock. The Core1121-HF module has a
        //    32.768 kHz crystal on DIO10/32k_N and DIO11/32k_P, so use the
        //    crystal source and wait for it to be ready (byte = 0x01 XTAL |
        //    0x04 wait, per the vendor reference CfgLfClk(XTAL, true)).
        self.write_command(CMD_CFG_LFCLK, &[0x05])?;

        // 6. Clear any device errors latched during cold-start or the TCXO
        //    bring-up so calibration starts from a clean state.
        let _ = self.clear_device_errors();

        // 7. Full calibration of all blocks. The device returns to Standby
        //    RC when done. This re-launches the calibrations that POR
        //    skipped because a TCXO (not an XO) is fitted. Re-assert STBY_RC
        //    first (matching the functional SX1262 calibrate() in
        //    sx1262.rs): the chip may still be settling the VTCXO/TCXO path
        //    after SetTcxoMode, and calibration is only guaranteed valid from
        //    a clean STDBY_RC.
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        self.write_command(CMD_CALIBRATE, &[0x3F])?;
        std::thread::sleep(Duration::from_millis(15));
        self.wait_ready()?;

        // 7b. Diagnostic: report which calibration blocks failed (or
        //     succeeded). If IMG_CALIB_ERR is set here, the XO was not
        //     running even during calibration, i.e. the TCXO is not
        //     oscillating despite SetTcxoMode.
        match self.get_device_errors() {
            Ok(err) if err != 0 => {
                let bits = Self::decode_device_errors(err);
                log::warn!(
                    "lr1121: device errors after calibrate = 0x{err:04X} ({})",
                    bits.join(", "),
                );
            }
            Ok(_) => log::info!("lr1121: no device errors after calibrate"),
            Err(e) => log::warn!("lr1121: could not read device errors after calibrate: {e}"),
        }

        // 8. Switch to XOSC mode. The TCXO is configured and all blocks are
        //    calibrated, so the XO must come up cleanly; poll the status
        //    byte (GetStatus is answered even while BUSY is asserted) and
        //    retry for a slow/marginal TCXO so a later TX is not silently
        //    rejected with PLL/XOSC_START_ERR.
        self.enter_standby_xosc(config.tcxo_startup_delay)?;

        // 9. Clear IRQs and any errors latched during the above.
        self.write_command(CMD_CLEAR_IRQ, &[0xFF, 0xFF, 0xFF, 0xFF])?;
        let _ = self.clear_device_errors();

        // Set PA config based on power and frequency band
        self.set_pa_config(config.tx_power, self.band)?;

        // Configure DIO as RF switch if needed
        self.set_dio_as_rf_switch(config.dio_rf_switch)?;

        // Configure radio parameters
        self.set_rf_frequency(config.frequency)?;
        self.set_modulation_params(
            config.spreading_factor,
            config.bandwidth as u32,
            config.coding_rate,
            self.band,
        )?;

        // Set TX parameters
        self.set_tx_params(config.tx_power, self.band)?;

        // Set sync word
        self.set_sync_word(config.sync_word)?;

        // Set DIO IRQ params
        self.set_dio_irq_params(config.dio1_line.is_some())?;

        // Clear any stale IRQ flags (e.g. from failed init steps)
        self.clear_irq_status(0xFFFFFFFF)?;

        // Diagnostic: report latched device errors so TCXO/XOSC/PLL/PA
        // startup failures are visible.
        match self.get_device_errors() {
            Ok(err) if err != 0 => {
                let bits = Self::decode_device_errors(err);
                log::warn!(
                    "lr1121: device errors after init = 0x{err:04X} ({})",
                    bits.join(", "),
                );
            }
            Ok(_) => {
                log::info!("lr1121: no device errors after init (XO started)");
            }
            Err(e) => log::warn!("lr1121: could not read device errors: {}", e),
        }

        log::info!(
            "lr1121: configured band={:?} freq={} Hz bw={} kHz sf={} cr={} power={} dBm tcxo={}v",
            self.band,
            config.frequency,
            config.bandwidth / 1000.0,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
            config.tcxo_voltage.unwrap_or(0.0),
        );

        Ok(())
    }

    fn transmit(&mut self, payload: &[u8]) -> Result<(), LoRaError> {
        let cfg = self
            .config
            .clone()
            .ok_or_else(|| LoRaError::Chipset("not initialised".into()))?;

        self.tx_active = true;
        self.rx_active = false;

        // Write payload to TX buffer (WriteBuffer8: no offset)
        self.write_command(CMD_WRITE_BUFFER_8, payload)?;

        // Set packet params with exact payload length
        let header_mode = if cfg.implicit_header { 0x01 } else { 0x00 };
        let crc = if cfg.crc_enabled { 0x01 } else { 0x00 };
        let iq = if cfg.iq_inverted { 0x01 } else { 0x00 };
        self.set_packet_params(cfg.preamble_length, header_mode, payload.len() as u8, crc, iq)?;

        // Apply high ACP workaround for compliant TX spectrum
        self.apply_high_acp_workaround()?;

        // Ensure stable XOSC reference, then TX. The SetStandby(XOSC)
        // post-wait must cover the configured tcxo_startup_delay — the
        // chip can hold BUSY for the full window, and SetTx that follows
        // is dropped if it's issued before BUSY clears.
        self.write_command_with_max_busy(
            CMD_SET_STANDBY,
            &[STANDBY_XOSC],
            self.xosc_max_busy(),
        )?;
        self.write_command(CMD_SET_TX, &[0x00, 0x00, 0x00])?;

        log::trace!("lr1121: transmitted {} bytes on {:?}", payload.len(), self.band);
        Ok(())
    }

    fn start_receive(&mut self) -> Result<(), LoRaError> {
        let cfg = self
            .config
            .clone()
            .ok_or_else(|| LoRaError::Chipset("not initialised".into()))?;

        let header_mode = if cfg.implicit_header { 0x01 } else { 0x00 };
        let crc = if cfg.crc_enabled { 0x01 } else { 0x00 };
        let iq = if cfg.iq_inverted { 0x01 } else { 0x00 };

        self.set_packet_params(cfg.preamble_length, header_mode, 0xFF, crc, iq)?;

        // Apply high ACP workaround for sensitive RX
        self.apply_high_acp_workaround()?;

        // Enable RX boosted mode for improved sensitivity
        self.write_command(CMD_SET_RX_BOOSTED, &[0x01])?;

        // Ensure stable XOSC reference, then enter continuous RX. The
        // SetStandby(XOSC) post-wait must cover the configured
        // tcxo_startup_delay — the chip can hold BUSY for the full
        // window, and SetRx that follows is dropped if it's issued
        // before BUSY clears.
        self.write_command_with_max_busy(
            CMD_SET_STANDBY,
            &[STANDBY_XOSC],
            self.xosc_max_busy(),
        )?;
        self.write_command(CMD_SET_RX, &[0xFF, 0xFF, 0xFF])?;

        self.rx_active = true;
        self.tx_active = false;
        Ok(())
    }

    fn process_irq(&mut self) -> Result<Vec<ReceivedPacket>, LoRaError> {
        let mut packets = Vec::new();

        // Check DIO IRQ line if available
        if let Some(dio) = &self.dio_irq {
            if !self.tx_active {
                let val = dio
                    .get_value()
                    .map_err(|e| LoRaError::Gpio(format!("dio_irq read: {}", e)))?;
                if !val {
                    return Ok(packets);
                }
            }
        }

        // Read IRQ status
        let irq_status = self.get_irq_status()?;

        if irq_status == 0 {
            return Ok(packets);
        }

        if irq_status & IRQ_ERR != 0 {
            log::warn!("lr1121: CRC error in received packet");
        }
        if irq_status & IRQ_HEADER_ERR != 0 {
            log::warn!("lr1121: header error in received packet");
        }

        if irq_status & IRQ_RX_DONE != 0 {
            let (payload_len, start_ptr) = self.get_rx_buffer_status()?;
            if payload_len > 0 {
                let payload = self.read_buffer(start_ptr, payload_len)?;
                let (rssi, snr, _signal_rssi) = self.get_packet_status()?;

                if irq_status & IRQ_ERR == 0 {
                    packets.push(ReceivedPacket { payload, rssi, snr });
                } else {
                    log::warn!("lr1121: dropping corrupted packet (CRC error)");
                }
            }
        }

        if irq_status & IRQ_TX_DONE != 0 {
            log::trace!("lr1121: TX complete");
        }

        self.clear_irq_status(irq_status)?;

        if irq_status
            & (IRQ_RX_DONE | IRQ_TX_DONE | IRQ_TIMEOUT | IRQ_HEADER_ERR | IRQ_ERR)
            != 0
        {
            self.start_receive()?;
        }

        Ok(packets)
    }

    fn reset(&mut self) -> Result<(), LoRaError> {
        self.hardware_reset()?;
        if let Some(config) = &self.config.clone() {
            self.init(config)?;
        }
        Ok(())
    }

    fn current_rssi(&mut self) -> Result<f32, LoRaError> {
        let data = self.read_command(CMD_GET_RSSI_INST, &[], 1)?;
        if let Some(&raw) = data.first() {
            Ok(-(raw as f32) / 2.0)
        } else {
            Ok(-127.0)
        }
    }
}

impl Drop for LR1121 {
    fn drop(&mut self) {
        let _ = self.write_command(CMD_SET_STANDBY, &[STANDBY_RC]);
    }
}
