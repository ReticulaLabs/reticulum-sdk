use std::time::{Duration, Instant};

use super::{
    GpioLine, GpioPins, LoRaChipset, LoRaConfig, LoRaError, ReceivedPacket, SpiBus,
};

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

// ── 16-bit command opcodes (LR1121 User Manual §14) ───────────────────────

// System configuration
const CMD_GET_STATUS: u16 = 0x0100;
const CMD_GET_VERSION: u16 = 0x0101;
const CMD_CALIBRATE: u16 = 0x010F;
const CMD_SET_REG_MODE: u16 = 0x0110;
const CMD_CALIB_IMAGE: u16 = 0x0111;
const CMD_SET_DIO_AS_RF_SWITCH: u16 = 0x0112;
const CMD_SET_DIO_IRQ_PARAMS: u16 = 0x0113;
const CMD_CLEAR_IRQ: u16 = 0x0114;
const CMD_SET_TXCO_MODE: u16 = 0x0117;
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

// Buffer access
const CMD_WRITE_BUFFER_8: u16 = 0x0109;
const CMD_READ_BUFFER_8: u16 = 0x010A;

// ── Packet types (LR1121 UM §8.1.1) ──────────────────────────────────────
// 0x00 = None, 0x01 = (G)FSK, 0x02 = LoRa, 0x03 = Sigfox, 0x04 = LR-FHSS

const PACKET_TYPE_LORA: u8 = 0x02;

// ── Standby modes (LR1121 UM §2.1.2.1) ────────────────────────────────────

const STANDBY_RC: u8 = 0x00;
const STANDBY_XOSC: u8 = 0x01;

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
    fn wait_ready(&self) -> Result<(), LoRaError> {
        match &self.busy {
            Some(busy) => {
                let deadline = Instant::now() + Duration::from_secs(5);
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
                // 50 ms covers the longest operations (TCXO startup ~10ms,
                // calibration ~15ms, etc.).
                std::thread::sleep(std::cmp::max(self.command_delay, Duration::from_millis(50)));
                Ok(())
            }
        }
    }

    fn hardware_reset(&mut self) -> Result<(), LoRaError> {
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
    fn write_command(&mut self, opcode: u16, args: &[u8]) -> Result<u32, LoRaError> {
        self.wait_ready()?;
        let mut tx = vec![(opcode >> 8) as u8, (opcode & 0xFF) as u8];
        tx.extend_from_slice(args);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        self.wait_ready()?;

        let stat1 = rx.first().copied().unwrap_or(0);
        log::trace!("lr1121: tx={:02X?} rx={:02X?} stat1=0x{stat1:02X}", tx, rx);

        if let Some((prev_opcode, prev_stat1)) = self.prev_status.take() {
            let prev_cmd_status = (prev_stat1 >> 1) & 0x07;
            match prev_cmd_status {
                0 => log::warn!("lr1121: command 0x{prev_opcode:04X} CMD_FAIL"),
                1 => log::warn!("lr1121: command 0x{prev_opcode:04X} CMD_PERR"),
                _ => {}
            }
        }
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
        if let Some((prev_opcode, prev_stat1)) = self.prev_status.take() {
            let prev_cmd_status = (prev_stat1 >> 1) & 0x07;
            match prev_cmd_status {
                0 => log::warn!("lr1121: command 0x{prev_opcode:04X} CMD_FAIL"),
                1 => log::warn!("lr1121: command 0x{prev_opcode:04X} CMD_PERR"),
                _ => {}
            }
        }
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

    fn get_irq_status(&mut self) -> Result<u32, LoRaError> {
        self.wait_ready()?;
        let tx = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut rx = vec![0u8; 6];
        self.spi.xfer(&tx, &mut rx)?;
        let stat1 = rx.first().copied().unwrap_or(0);
        log::trace!("lr1121: get_irq rx={:02X?} stat1=0x{stat1:02X}", rx);
        if let Some((prev_opcode, prev_stat1)) = self.prev_status.take() {
            let prev_cmd_status = (prev_stat1 >> 1) & 0x07;
            match prev_cmd_status {
                0 => log::warn!("lr1121: command 0x{prev_opcode:04X} CMD_FAIL"),
                1 => log::warn!("lr1121: command 0x{prev_opcode:04X} CMD_PERR"),
                _ => {}
            }
        }
        self.prev_status = Some((0x0100, stat1));
        self.wait_ready()?;
        Ok((rx[2] as u32) << 24 | (rx[3] as u32) << 16 | (rx[4] as u32) << 8 | rx[5] as u32)
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
        self.wait_ready()?;
        std::thread::sleep(Duration::from_millis(10));
        log::trace!("lr1121: post-reset, starting init sequence");
        self.prev_status = None;

        // Core1121-HF init sequence based on WaveShare demo.
        // The sealed module contains a 3.0V TCXO.

        // 1. Standby RC (the only mode available before TCXO is running)
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;

        // 2. Configure TCXO — Core1121-HF uses 3.0V (code 0x06).
        //    Follow the user's voltage if set, otherwise default to 3.0V.
        let tcxo_v = config.tcxo_voltage.unwrap_or(3.0);
        let code = if tcxo_v >= 1.6 && tcxo_v < 1.7 { 0x00 }
            else if tcxo_v < 1.8 { 0x01 }
            else if tcxo_v < 2.2 { 0x02 }
            else if tcxo_v < 2.4 { 0x03 }
            else if tcxo_v < 2.7 { 0x04 }
            else if tcxo_v < 3.0 { 0x05 }
            else if tcxo_v < 3.3 { 0x06 }
            else { 0x07 };
        let delay: u32 = 300; // 300 × 30.52 µs ≈ 9.2 ms, matches demo
        self.write_command(CMD_SET_TXCO_MODE, &[
            code,
            (delay >> 16) as u8,
            (delay >> 8) as u8,
            delay as u8,
        ])?;
        std::thread::sleep(Duration::from_millis(15));

        // 3. Switch to XOSC mode — TCXO is configured and should start
        self.write_command(CMD_SET_STANDBY, &[STANDBY_XOSC])?;
        std::thread::sleep(Duration::from_millis(10));

        // 4. Calibrate image for target sub-GHz band
        self.calibrate_image(config.frequency)?;

        // 5. Set regulator mode (DC-DC)
        self.write_command(CMD_SET_REG_MODE, &[REG_MODE_DCDC])?;

        // 6. Full calibration with TCXO stable
        self.write_command(CMD_CALIBRATE, &[0x3F])?;
        std::thread::sleep(Duration::from_millis(15));
        self.wait_ready()?;

        // 7. Clear errors and IRQs
        self.write_command(CMD_CLEAR_IRQ, &[0xFF, 0xFF, 0xFF, 0xFF])?;

        // 8. Set packet type to LoRa
        self.write_command(CMD_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;

        // Set PA config based on power and frequency band
        self.set_pa_config(config.tx_power, self.band)?;

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

        self.config = Some(config.clone());

        log::info!(
            "lr1121: configured band={:?} freq={} Hz bw={} kHz sf={} cr={} power={} dBm",
            self.band,
            config.frequency,
            config.bandwidth / 1000.0,
            config.spreading_factor,
            config.coding_rate,
            config.tx_power,
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

        // Ensure stable XOSC reference, then TX.
        self.write_command(CMD_SET_STANDBY, &[STANDBY_XOSC])?;
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

        // Enter continuous RX (0xFFFFFF disables timeout)
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
