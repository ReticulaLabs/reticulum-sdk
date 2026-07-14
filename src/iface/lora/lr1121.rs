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

// ── Command opcodes (shared SX126x family) ────────────────────────────────

const CMD_SET_STANDBY: u8 = 0x80;
const CMD_SET_TX: u8 = 0x83;
const CMD_SET_RX: u8 = 0x82;
const CMD_SET_PACKET_TYPE: u8 = 0x8A;
const CMD_GET_IRQ_STATUS: u8 = 0x12;
const CMD_CLEAR_IRQ_STATUS: u8 = 0x02;
const CMD_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const CMD_SET_RF_FREQUENCY: u8 = 0x86;
const CMD_SET_BUFFER_BASE_ADDRESS: u8 = 0x8F;
const CMD_SET_MODULATION_PARAMS: u8 = 0x8B;
const CMD_SET_PACKET_PARAMS: u8 = 0x8C;
const CMD_SET_TX_PARAMS: u8 = 0x8E;
const CMD_SET_PA_CONFIG: u8 = 0x95;
const CMD_SET_REGULATOR_MODE: u8 = 0x96;
const CMD_SET_DIO2_AS_RF_SWITCH_CTRL: u8 = 0x9D;
const CMD_SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;
const CMD_CALIBRATE_IMAGE: u8 = 0x98;
const CMD_GET_RX_BUFFER_STATUS: u8 = 0x13;
const CMD_GET_PACKET_STATUS: u8 = 0x14;
const CMD_GET_RSSI_INST: u8 = 0x15;
const CMD_WRITE_BUFFER: u8 = 0x0E;
const CMD_READ_BUFFER: u8 = 0x1E;
const CMD_WRITE_REGISTER: u8 = 0x0D;
const CMD_READ_REGISTER: u8 = 0x1D;

// ── LR1121 registers ──────────────────────────────────────────────────────

const REG_IQ_POLARITY_SETUP: u16 = 0x0736;
const REG_LORA_SYNC_WORD_MSB: u16 = 0x0740;
const REG_TX_MODULATION: u16 = 0x0889;
const REG_TX_CLAMP_CONFIG: u16 = 0x08D8;
const REG_RTC_CONTROL: u16 = 0x0902;
const REG_EVENT_MASK: u16 = 0x0944;

// ── Packet types ──────────────────────────────────────────────────────────

const PACKET_TYPE_LORA: u8 = 0x01;

// ── Standby modes ─────────────────────────────────────────────────────────

const STANDBY_RC: u8 = 0x00;

// ── Regulator modes ───────────────────────────────────────────────────────

const REGULATOR_DCDC: u8 = 0x01;

// ── LR1121: 32-bit IRQ flags ──────────────────────────────────────────────

const IRQ_TX_DONE: u32 = 0x0000_0001;
const IRQ_RX_DONE: u32 = 0x0000_0002;
const IRQ_HEADER_ERR: u32 = 0x0000_0020;
const IRQ_CRC_ERR: u32 = 0x0000_0040;
const IRQ_TIMEOUT: u32 = 0x0000_0200;
const IRQ_MASK_ALL: u32 = IRQ_TX_DONE | IRQ_RX_DONE | IRQ_HEADER_ERR | IRQ_CRC_ERR | IRQ_TIMEOUT;

// ── PA ramp times ─────────────────────────────────────────────────────────

const RAMP_800U: u8 = 0x05;

// ── LoRa bandwidth codes: sub-GHz (same as SX1262) ────────────────────────

fn lora_bandwidth_code_subghz(bw_hz: u32) -> u8 {
    if bw_hz < 9_100 {
        0x00
    } else if bw_hz < 13_000 {
        0x08
    } else if bw_hz < 18_200 {
        0x01
    } else if bw_hz < 26_000 {
        0x09
    } else if bw_hz < 36_500 {
        0x02
    } else if bw_hz < 52_100 {
        0x0A
    } else if bw_hz < 93_800 {
        0x03
    } else if bw_hz < 187_500 {
        0x04
    } else if bw_hz < 375_000 {
        0x05
    } else {
        0x06
    }
}

// ── LoRa bandwidth codes: 2.4 GHz band ────────────────────────────────────
// Uses SX128x-style bandwidth codes (different from sub-GHz)

fn lora_bandwidth_code_2p4g(bw_hz: u32) -> u8 {
    match bw_hz {
        x if x <= 206_000 => 0x00, // 203.125 kHz
        x if x <= 413_000 => 0x01, // 406.25 kHz
        x if x <= 825_000 => 0x02, // 812.5 kHz
        _ => 0x03,                  // 1.625 MHz (default for 2.4 GHz)
    }
}

// ── Coding rate (same across all bands) ───────────────────────────────────

fn lora_coding_rate_code(cr: u8) -> u8 {
    match cr {
        5 => 0x01,
        6 => 0x01,
        7 => 0x01,
        8 => 0x01,
        _ => 0x00,
    }
}

fn needs_ldro(sf: u8, bw_hz: u32) -> bool {
    let symbol_time_ms = ((1u64 << sf) as f64) / (bw_hz as f64) * 1000.0;
    symbol_time_ms >= 16.38
}

// ── CalibrateImage band pairs (LR1121 multi-band) ─────────────────────────

fn calibrate_image_bands(freq_hz: u64) -> (u8, u8) {
    // LR1121 covers more bands than SX1262
    if freq_hz < 446_000_000 {
        (0x6B, 0x6F) // 430–440 MHz
    } else if freq_hz < 734_000_000 {
        (0x75, 0x81) // 470–510 MHz
    } else if freq_hz < 828_000_000 {
        (0xC1, 0xC5) // 779–787 MHz
    } else if freq_hz < 877_000_000 {
        (0xD7, 0xDB) // 863–870 MHz
    } else if freq_hz < 1_000_000_000 {
        (0xE1, 0xE9) // 902–928 MHz
    } else if freq_hz < 1_525_000_000 {
        // L-band not explicitly calibrated, use defaults
        (0x00, 0x00)
    } else if freq_hz <= 1_660_000_000 {
        (0x05, 0x08) // L-band: 1.5–1.7 GHz
    } else if freq_hz <= 2_100_000_000 {
        (0x08, 0x0C) // S-band: 1.9–2.1 GHz
    } else {
        (0x0C, 0x10) // 2.4 GHz band
    }
}

// ── LR1121 driver ─────────────────────────────────────────────────────────

pub struct LR1121 {
    spi: SpiBus,
    busy: Option<GpioLine>,
    reset: Option<GpioLine>,
    dio1: Option<GpioLine>,
    config: Option<LoRaConfig>,
    command_delay: Duration,
    band: FrequencyBand,
    rx_active: bool,
    tx_active: bool,
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
                std::thread::sleep(self.command_delay);
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

    fn write_command(&mut self, opcode: u8, args: &[u8]) -> Result<(), LoRaError> {
        self.wait_ready()?;
        let tx = {
            let mut buf = vec![opcode];
            buf.extend_from_slice(args);
            buf
        };
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        self.wait_ready()?;
        Ok(())
    }

    fn read_command(&mut self, opcode: u8, read_len: usize, args: &[u8]) -> Result<Vec<u8>, LoRaError> {
        self.wait_ready()?;
        let mut tx = vec![opcode];
        tx.extend_from_slice(args);
        tx.push(0x00);
        tx.resize(tx.len() + read_len, 0x00);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        self.wait_ready()?;
        Ok(rx[rx.len() - read_len..].to_vec())
    }

    fn write_register(&mut self, addr: u16, data: &[u8]) -> Result<(), LoRaError> {
        let mut args = vec![(addr >> 8) as u8, (addr & 0xFF) as u8];
        args.extend_from_slice(data);
        self.write_command(CMD_WRITE_REGISTER, &args)
    }

    fn read_register(&mut self, addr: u16) -> Result<u8, LoRaError> {
        let data = self.read_command(CMD_READ_REGISTER, 1, &addr.to_be_bytes())?;
        Ok(data.first().copied().unwrap_or(0))
    }

    fn set_rf_frequency(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        // LR1121 uses the same PLL formula as SX1262 for all bands:
        //   rf_freq = freq_hz * 2^25 / 32_000_000
        let value = (freq_hz * (1u64 << 25)) / 32_000_000;
        let args = [
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        self.write_command(CMD_SET_RF_FREQUENCY, &args)
    }

    fn set_modulation_params(&mut self, sf: u8, bw_hz: u32, cr: u8, band: FrequencyBand) -> Result<(), LoRaError> {
        let bw = match band {
            FrequencyBand::Band2p4G => lora_bandwidth_code_2p4g(bw_hz),
            _ => lora_bandwidth_code_subghz(bw_hz),
        };
        let cr_code = lora_coding_rate_code(cr);
        let ldro = if needs_ldro(sf, bw_hz) { 0x01 } else { 0x00 };
        self.write_command(CMD_SET_MODULATION_PARAMS, &[sf, bw, cr_code, ldro, 0, 0, 0, 0])
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
                0, 0, 0,
            ],
        )
    }

    fn set_tx_params(&mut self, power_dbm: i8, band: FrequencyBand) -> Result<(), LoRaError> {
        match band {
            FrequencyBand::SubGhz => {
                // Same as SX1262 sub-GHz PA
                let clamped = power_dbm.clamp(-9, 22);
                let power = if clamped >= 14 { 0x16 } else { clamped as u8 };
                self.write_command(CMD_SET_TX_PARAMS, &[power, RAMP_800U])
            }
            FrequencyBand::LBand | FrequencyBand::SBand | FrequencyBand::Band2p4G => {
                // HF PA path: range -17 to +13 dBm (0xEF to 0x0D)
                let clamped = power_dbm.clamp(-17, 13);
                // For HF PA, power byte is direct 2's complement of dBm
                self.write_command(CMD_SET_TX_PARAMS, &[clamped as u8, RAMP_800U])
            }
        }
    }

    fn set_pa_config(&mut self, power_dbm: i8, band: FrequencyBand) -> Result<(), LoRaError> {
        match band {
            FrequencyBand::SubGhz => {
                // SX1262-style sub-GHz high-power PA config
                let clamped = power_dbm.clamp(-9, 22);
                let (pa_duty_cycle, hp_max) = if clamped >= 22 {
                    (0x04, 0x07)
                } else if clamped >= 20 {
                    (0x03, 0x05)
                } else if clamped >= 17 {
                    (0x02, 0x03)
                } else if clamped >= 14 {
                    (0x02, 0x02)
                } else {
                    (0x00, 0x00)
                };
                // deviceSel=0x00 (high-power PA), paLut=0x01
                self.write_command(CMD_SET_PA_CONFIG, &[pa_duty_cycle, hp_max, 0x00, 0x01])
            }
            FrequencyBand::LBand | FrequencyBand::SBand | FrequencyBand::Band2p4G => {
                // HF PA config: deviceSel=0x01 (low-power PA), no paDutyCycle
                self.write_command(CMD_SET_PA_CONFIG, &[0x00, 0x00, 0x01, 0x01])
            }
        }
    }

    fn set_buffer_base_address(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80])
    }

    fn set_sync_word(&mut self, word: u16) -> Result<(), LoRaError> {
        self.write_register(REG_LORA_SYNC_WORD_MSB, &[(word >> 8) as u8, (word & 0xFF) as u8])
    }

    fn set_dio_irq_params(&mut self, dio1_enabled: bool) -> Result<(), LoRaError> {
        // LR1121 uses 32-bit IRQ registers, host only reads upper bits.
        // The SetDioIrqParams command still uses the same 8-byte format.
        let mask_hi = (IRQ_MASK_ALL >> 16) as u8;
        let mask_mh = (IRQ_MASK_ALL >> 8) as u8;
        let mask_lo = (IRQ_MASK_ALL & 0xFF) as u8;
        let dio1_hi = if dio1_enabled { mask_hi } else { 0x00 };
        let dio1_mh = if dio1_enabled { mask_mh } else { 0x00 };
        self.write_command(
            CMD_SET_DIO_IRQ_PARAMS,
            &[mask_hi, mask_mh, mask_lo, dio1_hi, dio1_mh, 0x00, 0x00, 0x00, 0x00],
        )
    }

    fn calibrate_image(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        let (f1, f2) = calibrate_image_bands(freq_hz);
        self.write_command(CMD_CALIBRATE_IMAGE, &[f1, f2])
    }

    fn clear_irq_status(&mut self, mask: u32) -> Result<(), LoRaError> {
        let bytes = mask.to_be_bytes();
        self.write_command(CMD_CLEAR_IRQ_STATUS, &[bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn read_buffer(&mut self, offset: u8, count: usize) -> Result<Vec<u8>, LoRaError> {
        self.read_command(CMD_READ_BUFFER, count, &[offset])
    }

    fn get_rx_buffer_status(&mut self) -> Result<(usize, u8), LoRaError> {
        let data = self.read_command(CMD_GET_RX_BUFFER_STATUS, 2, &[])?;
        if data.len() >= 2 {
            Ok((data[0] as usize, data[1]))
        } else {
            Ok((0, 0))
        }
    }

    fn get_packet_status(&mut self) -> Result<(f32, f32, f32), LoRaError> {
        let data = self.read_command(CMD_GET_PACKET_STATUS, 3, &[])?;
        if data.len() >= 3 {
            let rssi_raw = data[0] as i16;
            let snr_raw = data[1] as i8;
            let signal_rssi_raw = data[2] as i16;
            // Same RSSI/SNR formulas as SX1262 (datasheet Table 13-80)
            let rssi = -(rssi_raw as f32) / 2.0;
            let snr = (snr_raw as f32) * 0.25;
            let signal_rssi = -(signal_rssi_raw as f32) / 2.0;
            Ok((rssi, snr, signal_rssi))
        } else {
            Ok((0.0, 0.0, 0.0))
        }
    }

    fn set_regulator_mode(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_SET_REGULATOR_MODE, &[REGULATOR_DCDC])
    }

    // ── LR1121 Errata workarounds (same as SX1262 where shared) ──────────

    fn fix_resistance_antenna(&mut self) -> Result<(), LoRaError> {
        let val = self.read_register(REG_TX_CLAMP_CONFIG)?;
        self.write_register(REG_TX_CLAMP_CONFIG, &[val | 0x1E])
    }

    fn fix_inverted_iq(&mut self, invert: bool) -> Result<(), LoRaError> {
        let val = self.read_register(REG_IQ_POLARITY_SETUP)?;
        let new_val = if invert { val | 0x04 } else { val & 0xFB };
        self.write_register(REG_IQ_POLARITY_SETUP, &[new_val])
    }

    fn fix_lora_bw500(&mut self, bw_hz: u32) -> Result<(), LoRaError> {
        let val = self.read_register(REG_TX_MODULATION)?;
        let new_val = if bw_hz >= 375_000 { val & 0xFB } else { val | 0x04 };
        self.write_register(REG_TX_MODULATION, &[new_val])
    }

    fn fix_rx_timeout(&mut self) -> Result<(), LoRaError> {
        self.write_register(REG_RTC_CONTROL, &[0x00])?;
        let val = self.read_register(REG_EVENT_MASK)?;
        self.write_register(REG_EVENT_MASK, &[val | 0x02])
    }
}

impl LoRaChipset for LR1121 {
    fn new(spi: SpiBus, gpio: GpioPins) -> Self {
        Self {
            spi,
            busy: gpio.busy,
            reset: gpio.reset,
            dio1: gpio.dio1,
            config: None,
            command_delay: Duration::from_millis(2),
            band: FrequencyBand::SubGhz,
            rx_active: false,
            tx_active: false,
        }
    }

    fn init(&mut self, config: &LoRaConfig) -> Result<(), LoRaError> {
        self.command_delay = config.command_delay;
        self.band = FrequencyBand::from_freq(config.frequency);

        self.hardware_reset()?;

        // Enter standby RC mode
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        std::thread::sleep(Duration::from_millis(5));

        // Set packet type to LoRa
        self.write_command(CMD_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;

        // Set regulator mode (DC-DC)
        self.set_regulator_mode()?;

        // Configure DIO2 as RF switch if needed
        self.write_command(CMD_SET_DIO2_AS_RF_SWITCH_CTRL, &[config.dio2_rf_switch as u8])?;

        // Configure TCXO if needed
        if let Some(v) = config.tcxo_voltage {
            // TCXO config uses same format as SX1262
            let code = if v >= 1.6 && v < 1.7 { 0x00 }
                else if v < 1.8 { 0x01 }
                else if v < 2.2 { 0x02 }
                else if v < 2.4 { 0x03 }
                else if v < 2.7 { 0x04 }
                else if v < 3.0 { 0x05 }
                else if v < 3.3 { 0x06 }
                else { 0x07 };
            let delay: u32 = 0x0280;
            self.write_command(CMD_SET_DIO3_AS_TCXO_CTRL, &[
                code, (delay >> 16) as u8, (delay >> 8) as u8, delay as u8,
            ])?;
        }

        // Errata workarounds
        self.fix_resistance_antenna()?;

        // Calibrate image rejection for the target frequency band
        self.calibrate_image(config.frequency)?;

        // Set PA config based on power and frequency band
        self.set_pa_config(config.tx_power, self.band)?;

        // Configure radio parameters
        self.set_rf_frequency(config.frequency)?;
        self.set_modulation_params(
            config.spreading_factor,
            config.bandwidth as u32 * 1000,
            config.coding_rate,
            self.band,
        )?;

        // Set TX parameters
        self.set_tx_params(config.tx_power, self.band)?;

        // Set buffer base addresses
        self.set_buffer_base_address()?;

        // Set sync word
        self.set_sync_word(config.sync_word)?;

        // Set DIO IRQ params
        self.set_dio_irq_params(config.dio1_line.is_some())?;

        // BW500 workaround (sub-GHz only)
        if self.band == FrequencyBand::SubGhz {
            self.fix_lora_bw500(config.bandwidth as u32 * 1000)?;
        }

        self.config = Some(config.clone());

        log::info!(
            "lr1121: configured band={:?} freq={} Hz bw={} kHz sf={} cr={} power={} dBm",
            self.band,
            config.frequency,
            config.bandwidth,
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

        // Write payload to TX FIFO at offset 0
        let mut write_args = vec![0x00];
        write_args.extend_from_slice(payload);
        self.write_command(CMD_WRITE_BUFFER, &write_args)?;

        // Set packet params with exact payload length
        let header_mode = if cfg.implicit_header { 0x01 } else { 0x00 };
        let crc = if cfg.crc_enabled { 0x01 } else { 0x00 };
        let iq = if cfg.iq_inverted { 0x01 } else { 0x00 };
        self.set_packet_params(cfg.preamble_length, header_mode, payload.len() as u8, crc, iq)?;

        // BW500 workaround (sub-GHz only)
        if self.band == FrequencyBand::SubGhz {
            self.fix_lora_bw500(cfg.bandwidth as u32 * 1000)?;
        }

        // Trigger TX with no timeout
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

        // BW500 workaround (sub-GHz only)
        if self.band == FrequencyBand::SubGhz {
            self.fix_lora_bw500(cfg.bandwidth as u32 * 1000)?;
        }

        self.set_packet_params(cfg.preamble_length, header_mode, 0xFF, crc, iq)?;
        self.fix_inverted_iq(cfg.iq_inverted)?;
        self.fix_rx_timeout()?;

        // Enter continuous RX
        self.write_command(CMD_SET_RX, &[0xFF, 0xFF, 0xFF])?;

        self.rx_active = true;
        self.tx_active = false;
        Ok(())
    }

    fn process_irq(&mut self) -> Result<Vec<ReceivedPacket>, LoRaError> {
        let mut packets = Vec::new();

        // Check DIO1 if available
        if let Some(dio1) = &self.dio1 {
            if !self.tx_active {
                let val = dio1
                    .get_value()
                    .map_err(|e| LoRaError::Gpio(format!("dio1 read: {}", e)))?;
                if !val {
                    return Ok(packets);
                }
            }
        }

        // Read IRQ status (32-bit on LR1121)
        let irq_data = self.read_command(CMD_GET_IRQ_STATUS, 4, &[])?;
        if irq_data.len() < 4 {
            return Ok(packets);
        }

        let irq_status = (irq_data[0] as u32) << 24
            | (irq_data[1] as u32) << 16
            | (irq_data[2] as u32) << 8
            | irq_data[3] as u32;

        if irq_status == 0 {
            return Ok(packets);
        }

        if irq_status & IRQ_CRC_ERR != 0 {
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

                if irq_status & IRQ_CRC_ERR == 0 {
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
            & (IRQ_RX_DONE | IRQ_TX_DONE | IRQ_TIMEOUT | IRQ_HEADER_ERR | IRQ_CRC_ERR)
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
        let data = self.read_command(CMD_GET_RSSI_INST, 1, &[])?;
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
