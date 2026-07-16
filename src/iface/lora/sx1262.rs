use std::time::{Duration, Instant};

use super::{
    GpioLine, GpioPins, LoRaChipset, LoRaConfig, LoRaError, ReceivedPacket, SpiBus,
};

// ── Command opcodes ───────────────────────────────────────────────────────

const CMD_SET_STANDBY: u8 = 0x80;
const CMD_SET_FS: u8 = 0x81;
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
const CMD_CALIBRATE: u8 = 0x89;

// ── Register addresses ────────────────────────────────────────────────────

const REG_IQ_POLARITY_SETUP: u16 = 0x0736;
const REG_LORA_SYNC_WORD_MSB: u16 = 0x0740;
const REG_LNA: u16 = 0x08AC;
const REG_TX_MODULATION: u16 = 0x0889;
const REG_TX_CLAMP_CONFIG: u16 = 0x08D8;
const REG_OCP: u16 = 0x08E7;
const REG_RTC_CONTROL: u16 = 0x0902;
const REG_EVENT_MASK: u16 = 0x0944;

// ── Packet types ──────────────────────────────────────────────────────────

const PACKET_TYPE_LORA: u8 = 0x01;

// ── Standby modes ─────────────────────────────────────────────────────────

const STANDBY_RC: u8 = 0x00;
const STANDBY_XOSC: u8 = 0x01;

// ── Regulator modes ───────────────────────────────────────────────────────

const REGULATOR_DCDC: u8 = 0x01;

// ── IRQ flags ─────────────────────────────────────────────────────────────

const IRQ_TX_DONE: u16 = 0x0001;
const IRQ_RX_DONE: u16 = 0x0002;
const IRQ_HEADER_ERR: u16 = 0x0020;
const IRQ_CRC_ERR: u16 = 0x0040;
const IRQ_TIMEOUT: u16 = 0x0200;
const IRQ_MASK_ALL: u16 = IRQ_TX_DONE | IRQ_RX_DONE | IRQ_HEADER_ERR | IRQ_CRC_ERR | IRQ_TIMEOUT;

// ── Calibration masks ─────────────────────────────────────────────────────

const MASK_CALIBRATE_ALL: u8 = 0x7F;

// ── OCP value ─────────────────────────────────────────────────────────────
// Over-current protection threshold: 125 mA (SX1262 typical at 22 dBm).
// Formula: I = 5 + 5 * N, so N = (125 - 5) / 5 = 24 = 0x18.
const OCP_125MA: u8 = 0x18;

// ── PA ramp times ─────────────────────────────────────────────────────────

const RAMP_800U: u8 = 0x05;

// ── LoRa bandwidth codes ──────────────────────────────────────────────────

fn lora_bandwidth_code(bw_hz: u32) -> u8 {
    // Ranges from LoRaRF-Python SX126x.setLoRaModulation
    if bw_hz < 9_100 {
        0x00 // 7.8 kHz
    } else if bw_hz < 13_000 {
        0x08 // 10.4 kHz
    } else if bw_hz < 18_200 {
        0x01 // 15.6 kHz
    } else if bw_hz < 26_000 {
        0x09 // 20.8 kHz
    } else if bw_hz < 36_500 {
        0x02 // 31.25 kHz
    } else if bw_hz < 52_100 {
        0x0A // 41.7 kHz
    } else if bw_hz < 93_800 {
        0x03 // 62.5 kHz
    } else if bw_hz < 187_500 {
        0x04 // 125 kHz
    } else if bw_hz < 375_000 {
        0x05 // 250 kHz
    } else {
        0x06 // 500 kHz
    }
}

fn lora_coding_rate_code(cr: u8) -> u8 {
    // Python: cr = cr - 4; if cr > 4 { cr = 0 }
    match cr {
        5 => 0x01, // 4/5
        6 => 0x01, // 4/6 (same code as 4/5 per SX1262)
        7 => 0x01, // 4/7
        8 => 0x01, // 4/8
        _ => 0x00, // invalid → 4/4 (no coding)
    }
}

fn needs_ldro(sf: u8, bw_hz: u32) -> bool {
    let symbol_time_ms = ((1u64 << sf) as f64) / (bw_hz as f64) * 1000.0;
    symbol_time_ms >= 16.38
}

fn calibrate_image_bands(freq_hz: u64) -> (u8, u8) {
    // Band-pair calibration values from Semtech HAL / LoRaRF-Python
    if freq_hz < 446_000_000 {
        (0x6B, 0x6F) // 430–440 MHz
    } else if freq_hz < 734_000_000 {
        (0x75, 0x81) // 470–510 MHz
    } else if freq_hz < 828_000_000 {
        (0xC1, 0xC5) // 779–787 MHz
    } else if freq_hz < 877_000_000 {
        (0xD7, 0xDB) // 863–870 MHz
    } else {
        (0xE1, 0xE9) // 902–928 MHz
    }
}

// ── SX1262 driver ─────────────────────────────────────────────────────────

pub struct SX1262 {
    spi: SpiBus,
    busy: Option<GpioLine>,
    reset: Option<GpioLine>,
    dio1: Option<GpioLine>,
    config: Option<LoRaConfig>,
    command_delay: Duration,
    rx_active: bool,
    tx_active: bool,
}

impl SX1262 {
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



    fn read_command(
        &mut self,
        opcode: u8,
        read_len: usize,
        args: &[u8],
    ) -> Result<Vec<u8>, LoRaError> {
        self.wait_ready()?;
        let mut tx = vec![opcode];
        tx.extend_from_slice(args);
        tx.push(0x00);
        tx.resize(tx.len() + read_len, 0x00);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        self.wait_ready()?;
        // The response data starts 1 byte (status) into the rx.
        // We skip opcode + args + NOP and take the last read_len bytes.
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
        let value = (freq_hz * (1u64 << 25)) / 32_000_000;
        let args = [
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        self.write_command(CMD_SET_RF_FREQUENCY, &args)
    }

    fn set_modulation_params(&mut self, sf: u8, bw_hz: u32, cr: u8) -> Result<(), LoRaError> {
        let bw = lora_bandwidth_code(bw_hz);
        let cr_code = lora_coding_rate_code(cr);
        let ldro = if needs_ldro(sf, bw_hz) { 0x01 } else { 0x00 };
        // SX1262 expects 8 bytes: sf, bw, cr, ldro, reserved=0,0,0,0
        self.write_command(CMD_SET_MODULATION_PARAMS, &[sf, bw, cr_code, ldro, 0, 0, 0, 0])
    }

    fn set_packet_params(
        &mut self,
        preamble: u16,
        header_mode: u8,
        payload_len: u8,
        crc: u8,
        iq: u8,
    ) -> Result<(), LoRaError> {
        // SX1262 expects 9 bytes for LoRa packet params
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
        )?;

        // SX1262 errata 15.4: SetPacketParams resets register 0x0736 to an
        // incorrect default.  Re-apply the correct IQ polarity after every
        // call, otherwise LoRa RX demodulation fails silently.
        self.fix_inverted_iq(iq != 0)
    }

    fn set_tx_params(&mut self, power_dbm: i8) -> Result<(), LoRaError> {
        let clamped = power_dbm.clamp(-9, 22);
        // SX1262 high-power PA (deviceSel=0x00):
        //   Optimal settings (Table 13-21): power is always 0x16 (+22 dBm),
        //     actual output set by PA config.
        //   Non-optimal: power byte is 2's complement of dBm value.
        let power = if clamped >= 14 {
            0x16
        } else {
            clamped as u8
        };

        // Set over-current protection — matches RNode OCP_TUNED
        self.write_register(REG_OCP, &[OCP_125MA])?;

        self.write_command(CMD_SET_TX_PARAMS, &[power, RAMP_800U])
    }

    fn set_pa_config(&mut self, power_dbm: i8) -> Result<(), LoRaError> {
        let clamped = power_dbm.clamp(-9, 22);
        // SX1262 optimal PA settings per datasheet Table 13-21
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
        // deviceSel: 0x00 = SX1262 high-power PA, 0x01 = SX1261 low-power PA
        // paLut: always 0x01 (reserved)
        self.write_command(CMD_SET_PA_CONFIG, &[pa_duty_cycle, hp_max, 0x00, 0x01])
    }

    fn set_buffer_base_address(&mut self) -> Result<(), LoRaError> {
        // Both TX and RX start at 0 — the FIFO is 256 bytes and these are
        // mutually exclusive operations.  Using RxBase=0 allows TX payloads
        // up to 255 bytes without overlapping the RX reservation.
        self.write_command(CMD_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x00])
    }

    fn set_sync_word(&mut self, word: u16) -> Result<(), LoRaError> {
        self.write_register(REG_LORA_SYNC_WORD_MSB, &[(word >> 8) as u8, (word & 0xFF) as u8])
    }

    fn set_dio_irq_params(&mut self, dio1_enabled: bool) -> Result<(), LoRaError> {
        let mask_hi = (IRQ_MASK_ALL >> 8) as u8;
        let mask_lo = (IRQ_MASK_ALL & 0xFF) as u8;
        let dio1_hi = if dio1_enabled { mask_hi } else { 0x00 };
        let dio1_lo = if dio1_enabled { mask_lo } else { 0x00 };
        self.write_command(
            CMD_SET_DIO_IRQ_PARAMS,
            &[mask_hi, mask_lo, dio1_hi, dio1_lo, 0x00, 0x00, 0x00, 0x00],
        )
    }

    fn set_dio2_as_rf_switch(&mut self, enabled: bool) -> Result<(), LoRaError> {
        self.write_command(CMD_SET_DIO2_AS_RF_SWITCH_CTRL, &[enabled as u8])
    }

    fn set_dio3_as_tcxo_ctrl(&mut self, voltage: f64) -> Result<(), LoRaError> {
        // Voltage code lookup matches Python DIO3_OUTPUT_*
        let code = if voltage >= 1.6 && voltage < 1.7 {
            0x00
        } else if voltage < 1.8 {
            0x01
        } else if voltage < 2.2 {
            0x02
        } else if voltage < 2.4 {
            0x03
        } else if voltage < 2.7 {
            0x04
        } else if voltage < 3.0 {
            0x05
        } else if voltage < 3.3 {
            0x06
        } else {
            0x07
        };
        // Use 5ms delay as a conservative default
        let delay: u32 = 0x0280;
        self.write_command(
            CMD_SET_DIO3_AS_TCXO_CTRL,
            &[code, (delay >> 16) as u8, (delay >> 8) as u8, delay as u8],
        )
    }

    fn calibrate(&mut self) -> Result<(), LoRaError> {
        // Put in STDBY_RC before calibration (XO must be stopped)
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;

        // Calibrate RC64k, RC13M, PLL, ADC and image
        self.write_command(CMD_CALIBRATE, &[MASK_CALIBRATE_ALL])?;

        std::thread::sleep(Duration::from_millis(5));
        self.wait_ready()?;
        Ok(())
    }

    fn calibrate_image(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        let (f1, f2) = calibrate_image_bands(freq_hz);
        // SX1262 CalibrateImage takes 2 bytes: frequency band start and end
        self.write_command(CMD_CALIBRATE_IMAGE, &[f1, f2])
    }

    fn clear_irq_status(&mut self, mask: u16) -> Result<(), LoRaError> {
        self.write_command(CMD_CLEAR_IRQ_STATUS, &[(mask >> 8) as u8, (mask & 0xFF) as u8])
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
        // Returns (rssi_dbm, snr_db, signal_rssi_dbm)
        let data = self.read_command(CMD_GET_PACKET_STATUS, 3, &[])?;
        if data.len() >= 3 {
            let rssi_raw = data[0] as i16;
            let snr_raw = data[1] as i8; // signed 2's complement
            let signal_rssi_raw = data[2] as i16;
            // Packet RSSI: -(raw / 2) dBm  (matches LoRaRF-Python packetRssi)
            let rssi = -(rssi_raw as f32) / 2.0;
            // SNR: raw / 4 dB  (with 2's complement handled by i8 cast)
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

    // ── SX1262 Errata workarounds (from LoRaRF-Python) ─────────────────

    /// Errata 2.3: TX clamp config to avoid current spikes.
    fn fix_resistance_antenna(&mut self) -> Result<(), LoRaError> {
        let val = self.read_register(REG_TX_CLAMP_CONFIG)?;
        self.write_register(REG_TX_CLAMP_CONFIG, &[val | 0x1E])
    }

    /// Errata 2.7: IQ polarity must be configured through register 0x0736
    fn fix_inverted_iq(&mut self, invert: bool) -> Result<(), LoRaError> {
        let val = self.read_register(REG_IQ_POLARITY_SETUP)?;
        let new_val = if invert { val | 0x04 } else { val & 0xFB };
        self.write_register(REG_IQ_POLARITY_SETUP, &[new_val])
    }

    /// Errata 2.1: For 500 kHz BW in LoRa mode, bit 2 of TX_MODULATION must
    /// be cleared.
    fn fix_lora_bw500(&mut self, bw_hz: u32) -> Result<(), LoRaError> {
        let val = self.read_register(REG_TX_MODULATION)?;
        let new_val = if bw_hz >= 375_000 {
            // 500 kHz band — clear bit 2
            val & 0xFB
        } else {
            val | 0x04
        };
        self.write_register(REG_TX_MODULATION, &[new_val])
    }

    /// Workaround for RX timeout spurious IRQ: clear RTC control and set
    /// event mask bit 1.
    fn fix_rx_timeout(&mut self) -> Result<(), LoRaError> {
        self.write_register(REG_RTC_CONTROL, &[0x00])?;
        let val = self.read_register(REG_EVENT_MASK)?;
        self.write_register(REG_EVENT_MASK, &[val | 0x02])
    }

    /// Quick SPI ping: read a register and verify the chip responds with
    /// valid data (not all-zeros or all-ones).
    fn ping(&mut self) -> Result<(), LoRaError> {
        let data = self.read_command(CMD_READ_REGISTER, 2, &REG_LORA_SYNC_WORD_MSB.to_be_bytes())?;
        if data.len() < 2 {
            return Err(LoRaError::Chipset(
                "SPI ping: chip did not respond (no data)".into(),
            ));
        }
        let sync = (data[0] as u16) << 8 | data[1] as u16;
        if sync == 0x0000 || sync == 0xFFFF {
            return Err(LoRaError::Chipset(format!(
                "SPI ping: chip returned invalid data 0x{sync:04X} \
                 (bus may be floating or chip not connected)"
            )));
        }
        log::debug!("sx1262: SPI ping OK (sync_reg=0x{sync:04X})");
        Ok(())
    }

    fn validate_communication(&mut self, sync_word: u16) -> Result<(), LoRaError> {
        let data = self.read_command(CMD_READ_REGISTER, 2, &REG_LORA_SYNC_WORD_MSB.to_be_bytes())?;
        if data.len() < 2 {
            return Err(LoRaError::Chipset("SPI validation failed: no data received".into()));
        }
        let read_word = (data[0] as u16) << 8 | data[1] as u16;
        if read_word != sync_word {
            return Err(LoRaError::Chipset(format!(
                "SPI validation failed: wrote sync word 0x{sync_word:04X} but read back 0x{read_word:04X}"
            )));
        }
        log::debug!("sx1262: SPI communication validated (sync word 0x{sync_word:04X})");
        Ok(())
    }
}

impl LoRaChipset for SX1262 {
    fn new(spi: SpiBus, gpio: GpioPins) -> Self {
        Self {
            spi,
            busy: gpio.busy,
            reset: gpio.reset,
            dio1: gpio.dio1,
            config: None,
            command_delay: Duration::from_millis(2),
            rx_active: false,
            tx_active: false,
        }
    }

    fn init(&mut self, config: &LoRaConfig) -> Result<(), LoRaError> {
        self.command_delay = config.command_delay;

        self.hardware_reset()?;

        // Enter standby RC mode
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        std::thread::sleep(Duration::from_millis(5));

        // Quick SPI ping to confirm the chip is alive and in the right mode
        self.ping()?;

        // Set packet type to LoRa
        self.write_command(CMD_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;

        // Set regulator mode (DC-DC)
        self.set_regulator_mode()?;

        // Configure DIO2 as RF switch if needed
        self.set_dio2_as_rf_switch(config.dio2_rf_switch)?;

        // Configure TCXO if needed
        if let Some(v) = config.tcxo_voltage {
            self.set_dio3_as_tcxo_ctrl(v)?;
        }

        // Errata workarounds
        self.fix_resistance_antenna()?;

        // Full calibration: RC64k, RC13M, PLL, ADC (recommended after
        // power-on per SX1262 datasheet)
        self.calibrate()?;

        // Band-specific image calibration
        self.calibrate_image(config.frequency)?;

        // Switch to STDBY_XOSC for a stable XO reference before frequency
        // synthesis and TX/RX operations.
        self.write_command(CMD_SET_STANDBY, &[STANDBY_XOSC])?;

        // Set PA config based on TX power
        self.set_pa_config(config.tx_power)?;

        // Configure radio parameters
        self.set_rf_frequency(config.frequency)?;
        self.set_modulation_params(
            config.spreading_factor,
            config.bandwidth as u32 * 1000,
            config.coding_rate,
        )?;

        // Set TX parameters (also applies OCP)
        self.set_tx_params(config.tx_power)?;

        // LNA boost — improves receiver sensitivity
        self.write_register(REG_LNA, &[0x96])?;

        // Set buffer base addresses
        self.set_buffer_base_address()?;

        // Set sync word
        self.set_sync_word(config.sync_word)?;

        // Set DIO IRQ params
        self.set_dio_irq_params(config.dio1_line.is_some())?;

        // BW500 workaround
        self.fix_lora_bw500(config.bandwidth as u32 * 1000)?;

        // Initial packet params (triggers IQ polarity fix internally)
        let header_mode = if config.implicit_header { 0x01 } else { 0x00 };
        let crc = if config.crc_enabled { 0x01 } else { 0x00 };
        let iq = if config.iq_inverted { 0x01 } else { 0x00 };
        self.set_packet_params(config.preamble_length, header_mode, 0xFF, crc, iq)?;

        self.config = Some(config.clone());

        self.validate_communication(config.sync_word)?;

        log::info!(
            "sx1262: configured freq={} Hz bw={} kHz sf={} cr={} power={} dBm",
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

        // BW500 workaround for TX
        self.fix_lora_bw500(cfg.bandwidth as u32 * 1000)?;

        // CMD_SET_TX requires the device to be in STDBY / FS mode, not RX.
        // Use STDBY_XOSC so the PLL has a stable reference before TX.
        self.write_command(CMD_SET_STANDBY, &[STANDBY_XOSC])?;

        // Trigger TX with no timeout
        self.write_command(CMD_SET_TX, &[0x00, 0x00, 0x00])?;

        log::trace!("sx1262: transmitted {} bytes", payload.len());
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

        // BW500 workaround for RX
        self.fix_lora_bw500(cfg.bandwidth as u32 * 1000)?;

        // Set packet params (payload len 0xFF, ignored in explicit header mode)
        // NOTE: IQ polarity errata fix is applied inside set_packet_params.
        self.set_packet_params(cfg.preamble_length, header_mode, 0xFF, crc, iq)?;

        // RX timeout workaround
        self.fix_rx_timeout()?;

        // Enter continuous RX
        self.write_command(CMD_SET_RX, &[0xFF, 0xFF, 0xFF])?;

        self.rx_active = true;
        self.tx_active = false;
        Ok(())
    }

    fn process_irq(&mut self) -> Result<Vec<ReceivedPacket>, LoRaError> {
        let mut packets = Vec::new();

        // Check DIO1 if available (skip when TX is active to catch TX_DONE)
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

        // Read IRQ status
        let irq_data = self.read_command(CMD_GET_IRQ_STATUS, 2, &[])?;
        if irq_data.len() < 2 {
            return Ok(packets);
        }

        let irq_status = (irq_data[0] as u16) << 8 | irq_data[1] as u16;

        // Sanity: TX_DONE + RX_DONE are mutually exclusive.  If both are set
        // the chip is in a fault state.  Clear everything and re-enter RX without
        // processing events.
        if irq_status & IRQ_TX_DONE != 0 && irq_status & IRQ_RX_DONE != 0 {
            log::trace!(
                "sx1262: IRQ fault — TX_DONE+RX_DONE simultaneous (0x{irq_status:04X}), \
                 resetting",
            );
            self.clear_irq_status(0xFFFF)?;
            self.start_receive()?;
            return Ok(packets);
        }

        log::trace!(
            "sx1262: IRQ status = 0x{irq_status:04X} (raw bytes [{:02X}, {:02X}])",
            irq_data[0],
            irq_data[1],
        );

        if irq_status == 0 {
            return Ok(packets);
        }

        // Log errors
        if irq_status & IRQ_CRC_ERR != 0 {
            log::warn!("sx1262: CRC error in received packet");
        }
        if irq_status & IRQ_HEADER_ERR != 0 {
            log::warn!("sx1262: header error in received packet");
        }

        // Handle RX done
        if irq_status & IRQ_RX_DONE != 0 {
            let (payload_len, start_ptr) = self.get_rx_buffer_status()?;
            if payload_len > 0 {
                let payload = self.read_buffer(start_ptr, payload_len)?;
                let (rssi, snr, _signal_rssi) = self.get_packet_status()?;

                if irq_status & IRQ_CRC_ERR == 0 {
                    packets.push(ReceivedPacket { payload, rssi, snr });
                } else {
                    log::warn!("sx1262: dropping corrupted packet (CRC error)");
                }
            }
        }

        // Log TX done
        if irq_status & IRQ_TX_DONE != 0 {
            log::trace!("sx1262: TX complete");
        }

        // Clear IRQ
        self.clear_irq_status(irq_status)?;

        // Re-enter RX after any completion, timeout, or error.
        // Add a short delay after errors so RF reflections from TX can decay
        // before we listen again — otherwise the chip detects its own echo.
        if irq_status & (IRQ_HEADER_ERR | IRQ_CRC_ERR) != 0 {
            std::thread::sleep(Duration::from_millis(100));
        }
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
        // Instantaneous RSSI from CMD_GET_RSSI_INST
        // Datasheet 13.5.4: Signal power in dBm = –RssiInst/2
        let data = self.read_command(CMD_GET_RSSI_INST, 1, &[])?;
        if let Some(&raw) = data.first() {
            Ok(-(raw as f32) / 2.0)
        } else {
            Ok(-127.0)
        }
    }
}

impl Drop for SX1262 {
    fn drop(&mut self) {
        let _ = self.write_command(CMD_SET_STANDBY, &[STANDBY_RC]);
    }
}
