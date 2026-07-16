use std::time::Duration;

use super::{
    GpioLine, GpioPins, LoRaChipset, LoRaConfig, LoRaError, ReceivedPacket, SpiBus,
};

// ── Registers ──────────────────────────────────────────────────────────────

const REG_FIFO: u8 = 0x00;
const REG_OP_MODE: u8 = 0x01;
const REG_FRF_MSB: u8 = 0x06;
const REG_FRF_MID: u8 = 0x07;
const REG_FRF_LSB: u8 = 0x08;
const REG_PA_CONFIG: u8 = 0x09;
const REG_PA_DAC: u8 = 0x4D;
const REG_OCP: u8 = 0x0B;
const REG_LNA: u8 = 0x0C;
const REG_FIFO_ADDR_PTR: u8 = 0x0D;
const REG_FIFO_TX_BASE_ADDR: u8 = 0x0E;
const REG_FIFO_RX_BASE_ADDR: u8 = 0x0F;
const REG_FIFO_RX_CURRENT_ADDR: u8 = 0x10;
const REG_IRQ_FLAGS: u8 = 0x12;
const REG_RX_NB_BYTES: u8 = 0x13;
const REG_PKT_SNR_VALUE: u8 = 0x19;
const REG_PKT_RSSI_VALUE: u8 = 0x1A;
const REG_RSSI_VALUE: u8 = 0x1B;
const REG_MODEM_CONFIG_1: u8 = 0x1D;
const REG_MODEM_CONFIG_2: u8 = 0x1E;
const REG_PREAMBLE_MSB: u8 = 0x20;
const REG_PREAMBLE_LSB: u8 = 0x21;
const REG_PAYLOAD_LENGTH: u8 = 0x22;
const REG_MODEM_CONFIG_3: u8 = 0x26;
const REG_DETECTION_OPTIMIZE: u8 = 0x31;
const REG_INVERTIQ: u8 = 0x33;
const REG_HIGH_BW_OPTIMIZE_1: u8 = 0x36;
const REG_DETECTION_THRESHOLD: u8 = 0x37;
const REG_SYNC_WORD: u8 = 0x39;
const REG_HIGH_BW_OPTIMIZE_2: u8 = 0x3A;
const REG_INVERTIQ2: u8 = 0x3B;
const REG_VERSION: u8 = 0x42;

// ── OP_MODE values ─────────────────────────────────────────────────────────

const LONG_RANGE_MODE: u8 = 0x80;
const MODE_SLEEP: u8 = 0x00;
const MODE_STDBY: u8 = 0x01;
const MODE_TX: u8 = 0x03;
const MODE_FSRX: u8 = 0x04;
const MODE_RX_CONTINUOUS: u8 = 0x05;

// ── PA config ──────────────────────────────────────────────────────────────

const PA_BOOST: u8 = 0x80;

// ── IRQ flags ──────────────────────────────────────────────────────────────

const IRQ_TX_DONE: u8 = 0x08;
const IRQ_RX_DONE: u8 = 0x40;
const IRQ_CRC_ERR: u8 = 0x20;

// ── OCP ────────────────────────────────────────────────────────────────────
// 0x2B = OcpOn=1, OcpTrim=0x0B → ~100 mA – matches RadioHead default.

const OCP_VALUE: u8 = 0x2B;

// ── Maximum payload length ──────────────────────────────────────────────────
// SX1276 FIFO is 256 bytes; PayloadLength register is 8 bits.

const MAX_PAYLOAD_LEN: usize = 255;

// ── RSSI offset ────────────────────────────────────────────────────────────
// RSSI(dBm) = reg_value – RSSI_OFFSET_HF   (freq >= 820 MHz)
// RSSI(dBm) = reg_value – RSSI_OFFSET_LF   (freq <  820 MHz)

const RSSI_OFFSET_HF: i16 = 157;
const RSSI_OFFSET_LF: i16 = 164;

// ── Expected chip version ──────────────────────────────────────────────────

const CHIP_VERSION: u8 = 0x12;

// ── LoRa bandwidth codes (SX127x MODEM_CONFIG_1 bits 7-4) ──────────────────

fn lora_bandwidth_code(bw_khz: u32) -> u8 {
    match bw_khz {
        x if x <= 7 => 0x00,   // 7.8 kHz
        x if x <= 10 => 0x01,  // 10.4 kHz
        x if x <= 15 => 0x02,  // 15.6 kHz
        x if x <= 20 => 0x03,  // 20.8 kHz
        x if x <= 31 => 0x04,  // 31.25 kHz
        x if x <= 41 => 0x05,  // 41.7 kHz
        x if x <= 62 => 0x06,  // 62.5 kHz
        x if x <= 125 => 0x07, // 125 kHz
        x if x <= 250 => 0x08, // 250 kHz
        _ => 0x09,             // 500 kHz
    }
}

fn needs_ldro(sf: u8, bw_khz: u32) -> bool {
    let symbol_time_ms = ((1u64 << sf) as f64) / (bw_khz as f64);
    symbol_time_ms > 16.0
}

// ── SX1276 driver ──────────────────────────────────────────────────────────

pub struct SX1276 {
    spi: SpiBus,
    reset: Option<GpioLine>,
    config: Option<LoRaConfig>,
    command_delay: Duration,
    rx_active: bool,
    tx_active: bool,
}

impl SX1276 {
    // ── SPI helpers ────────────────────────────────────────────────────────

    fn read_register(&mut self, addr: u8) -> Result<u8, LoRaError> {
        let tx = [addr & 0x7F, 0x00];
        let mut rx = [0u8; 2];
        self.spi.xfer(&tx, &mut rx)?;
        Ok(rx[1])
    }

    fn write_register(&mut self, addr: u8, value: u8) -> Result<(), LoRaError> {
        let tx = [addr | 0x80, value];
        let mut rx = [0u8; 2];
        self.spi.xfer(&tx, &mut rx)?;
        Ok(())
    }

    fn read_registers(&mut self, addr: u8, len: usize) -> Result<Vec<u8>, LoRaError> {
        let mut tx = vec![addr & 0x7F];
        tx.resize(1 + len, 0x00);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        Ok(rx[1..].to_vec())
    }

    fn write_registers(&mut self, addr: u8, data: &[u8]) -> Result<(), LoRaError> {
        let mut tx = vec![addr | 0x80];
        tx.extend_from_slice(data);
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        Ok(())
    }

    fn set_op_mode(&mut self, mode: u8) -> Result<(), LoRaError> {
        self.write_register(REG_OP_MODE, LONG_RANGE_MODE | mode)
    }

    fn hardware_reset(&mut self) -> Result<(), LoRaError> {
        match &self.reset {
            Some(reset) => {
                reset
                    .set_value(true)
                    .map_err(|e| LoRaError::Gpio(format!("reset high: {}", e)))?;
                std::thread::sleep(Duration::from_millis(10));
                reset
                    .set_value(false)
                    .map_err(|e| LoRaError::Gpio(format!("reset low: {}", e)))?;
                std::thread::sleep(Duration::from_millis(10));
                reset
                    .set_value(true)
                    .map_err(|e| LoRaError::Gpio(format!("reset high: {}", e)))?;
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    }

    // ── SPI ping & validation ──────────────────────────────────────────────

    fn ping(&mut self) -> Result<(), LoRaError> {
        // Read REG_VERSION — should be 0x12 for SX1276/77/78/79.
        // 0xFF means MISO is pulled high (bus floating / chip not connected).
        // 0x00 means MISO is pulled low (chip not driving / stuck).
        let version = self.read_register(REG_VERSION)?;
        if version == 0xFF {
            return Err(LoRaError::Chipset(
                "SPI ping: chip returned 0xFF — bus may be floating or chip not connected".into(),
            ));
        }
        if version == 0x00 {
            return Err(LoRaError::Chipset(
                "SPI ping: chip returned 0x00 — chip not responding".into(),
            ));
        }
        if version != CHIP_VERSION {
            log::warn!(
                "sx1276: unexpected chip version 0x{version:02X} (expected 0x{CHIP_VERSION:02X})"
            );
        }
        log::debug!("sx1276: SPI ping OK (version 0x{version:02X})");
        Ok(())
    }

    fn sync_word_byte(word: u16) -> u8 {
        // SX127x uses an 8-bit sync word.  RNode standard is 0x12.
        // Map the 16-bit LoRaConfig value:
        //   - 0x1424 (Reticulum SX1262 default) → 0x12 (RNode standard)
        //   - 0x00XX                            → XX (explicit 8-bit value)
        //   - Otherwise                         → upper byte
        if word == 0x1424 {
            0x12
        } else if (word >> 8) == 0 {
            word as u8
        } else {
            (word >> 8) as u8
        }
    }

    fn validate_communication(&mut self, sync_word: u16) -> Result<(), LoRaError> {
        let expected = Self::sync_word_byte(sync_word);
        let read_back = self.read_register(REG_SYNC_WORD)?;
        if read_back != expected {
            return Err(LoRaError::Chipset(format!(
                "SPI validation failed: wrote sync word 0x{expected:02X} but read back 0x{read_back:02X}"
            )));
        }
        log::debug!("sx1276: SPI communication validated (sync word 0x{expected:02X})");
        Ok(())
    }

    // ── Frequency ──────────────────────────────────────────────────────────

    fn set_frequency(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        // FRF = freq_hz * 2^19 / 32_000_000
        let frf = (freq_hz << 19) / 32_000_000;
        self.write_register(REG_FRF_MSB, (frf >> 16) as u8)?;
        self.write_register(REG_FRF_MID, (frf >> 8) as u8)?;
        self.write_register(REG_FRF_LSB, frf as u8)?;
        Ok(())
    }

    // ── Modulation parameters ──────────────────────────────────────────────

    fn set_modulation_params(
        &mut self,
        sf: u8,
        bw_khz: u32,
        cr: u8,
    ) -> Result<(), LoRaError> {
        let bw_code = lora_bandwidth_code(bw_khz);

        // RegModemConfig1: BW[7:4], CR[3:1], ImplicitHdr[0]
        let mc1_val = (bw_code << 4) | ((cr - 4) << 1);
        self.write_register(REG_MODEM_CONFIG_1, mc1_val)?;

        // RegModemConfig2: SF[7:4], TxContinuous[3], CrcOn[2], PreambleDetect[1:0]
        let mut mc2_val = (sf << 4) & 0xF0;
        if sf == 6 {
            mc2_val |= 0x00; // No auto preamble detection for SF6
        }
        self.write_register(REG_MODEM_CONFIG_2, mc2_val)?;

        // RegModemConfig3: LDRO[3], AutoAGC[2]
        let ldro = needs_ldro(sf, bw_khz);
        let mut mc3_val = 0x04; // Auto AGC on
        if ldro {
            mc3_val |= 0x08;
        }
        self.write_register(REG_MODEM_CONFIG_3, mc3_val)?;

        // Detection settings for SF6 vs SF7-12
        if sf == 6 {
            self.write_register(REG_DETECTION_OPTIMIZE, 0xC5)?;
            self.write_register(REG_DETECTION_THRESHOLD, 0x0C)?;
        } else {
            self.write_register(REG_DETECTION_OPTIMIZE, 0xC3)?;
            self.write_register(REG_DETECTION_THRESHOLD, 0x0A)?;
        }

        // High-bandwidth optimisation
        self.optimize_modem_sensitivity(bw_code)?;

        Ok(())
    }

    fn optimize_modem_sensitivity(&mut self, bw_code: u8) -> Result<(), LoRaError> {
        // When using 500 kHz bandwidth, optimise sensitivity for the
        // frequency band (SX1276 datasheet §4.1.18, §4.1.26).
        if bw_code == 9 {
            let freq = self.get_frequency();
            if (410_000_000..=525_000_000).contains(&freq) {
                self.write_register(REG_HIGH_BW_OPTIMIZE_1, 0x02)?;
                self.write_register(REG_HIGH_BW_OPTIMIZE_2, 0x7F)?;
            } else if (820_000_000..=1_020_000_000).contains(&freq) {
                self.write_register(REG_HIGH_BW_OPTIMIZE_1, 0x02)?;
                self.write_register(REG_HIGH_BW_OPTIMIZE_2, 0x64)?;
            } else {
                self.write_register(REG_HIGH_BW_OPTIMIZE_1, 0x03)?;
            }
        } else {
            self.write_register(REG_HIGH_BW_OPTIMIZE_1, 0x03)?;
        }
        Ok(())
    }

    fn get_frequency(&mut self) -> u64 {
        let msb = self.read_register(REG_FRF_MSB).unwrap_or(0) as u64;
        let mid = self.read_register(REG_FRF_MID).unwrap_or(0) as u64;
        let lsb = self.read_register(REG_FRF_LSB).unwrap_or(0) as u64;
        let frf = (msb << 16) | (mid << 8) | lsb;
        (frf * 32_000_000) >> 19
    }

    // ── PA and power ───────────────────────────────────────────────────────

    fn set_pa_config(&mut self, power_dbm: i8) -> Result<(), LoRaError> {
        // Always use PA_BOOST pin for higher output power.
        // Power range: +2 to +20 dBm.
        let clamped = power_dbm.clamp(2, 20);

        if clamped >= 20 {
            // High-power PA: enable +20 dBm mode
            self.write_register(REG_PA_DAC, 0x87)?;
            // PA_BOOST | 15 → 2 + 15 = 17 dBm base, plus PA_DAC boost to 20
            self.write_register(REG_PA_CONFIG, PA_BOOST | 0x0F)?;
        } else {
            self.write_register(REG_PA_DAC, 0x84)?;
            // level - 2 maps power level (2..17 dBm) to register value (0..15)
            let reg_val = (clamped - 2).max(0).min(15) as u8;
            self.write_register(REG_PA_CONFIG, PA_BOOST | reg_val)?;
        }

        // Over-current protection
        self.write_register(REG_OCP, OCP_VALUE)?;

        Ok(())
    }

    // ── Sync word ──────────────────────────────────────────────────────────

    fn set_sync_word(&mut self, word: u16) -> Result<(), LoRaError> {
        let byte = Self::sync_word_byte(word);
        log::info!("sx1276: sync word 0x{byte:02X} (from config 0x{word:04X})");
        self.write_register(REG_SYNC_WORD, byte)
    }

    // ── Preamble ───────────────────────────────────────────────────────────

    fn set_preamble_length(&mut self, symbols: u16) -> Result<(), LoRaError> {
        // The chip preamble count is (register_value + 4) symbols,
        // so we store (wanted – 4).
        let count = symbols.saturating_sub(4);
        self.write_register(REG_PREAMBLE_MSB, (count >> 8) as u8)?;
        self.write_register(REG_PREAMBLE_LSB, (count & 0xFF) as u8)
    }

    // ── CRC ────────────────────────────────────────────────────────────────

    fn set_crc(&mut self, enabled: bool) -> Result<(), LoRaError> {
        let val = self.read_register(REG_MODEM_CONFIG_2)?;
        if enabled {
            self.write_register(REG_MODEM_CONFIG_2, val | 0x04)
        } else {
            self.write_register(REG_MODEM_CONFIG_2, val & 0xFB)
        }
    }

    // ── IQ inversion ───────────────────────────────────────────────────────

    fn set_iq_inverted(&mut self, invert: bool) -> Result<(), LoRaError> {
        if invert {
            self.write_register(REG_INVERTIQ, 0x66)?;
            self.write_register(REG_INVERTIQ2, 0x19)
        } else {
            self.write_register(REG_INVERTIQ, 0x27)?;
            self.write_register(REG_INVERTIQ2, 0x1D)
        }
    }

    // ── IRQ helpers ────────────────────────────────────────────────────────

    fn clear_irq_flags(&mut self, mask: u8) -> Result<(), LoRaError> {
        // Writing a 1 to a bit clears that IRQ flag.
        self.write_register(REG_IRQ_FLAGS, mask)
    }

    fn read_irq_flags(&mut self) -> Result<u8, LoRaError> {
        self.read_register(REG_IRQ_FLAGS)
    }

    // ── RSSI helpers ───────────────────────────────────────────────────────

    fn rssi_offset(&self) -> i16 {
        // Config may not be available yet; default to HF offset.
        match &self.config {
            Some(cfg) if cfg.frequency < 820_000_000 => RSSI_OFFSET_LF,
            _ => RSSI_OFFSET_HF,
        }
    }

    fn get_packet_rssi_snr(&mut self) -> Result<(f32, f32), LoRaError> {
        let pkt_rssi_raw = self.read_register(REG_PKT_RSSI_VALUE)? as i16;
        let pkt_snr_raw = self.read_register(REG_PKT_SNR_VALUE)? as i8;

        let snr = (pkt_snr_raw as f32) * 0.25;
        let offset = self.rssi_offset();
        let mut rssi = (pkt_rssi_raw - offset) as f32;

        if snr < 0.0 {
            rssi += snr;
        } else {
            rssi *= 1.066;
        }

        Ok((rssi, snr))
    }

    // ── FIFO / payload helpers ─────────────────────────────────────────────

    fn read_fifo_payload(&mut self) -> Result<Vec<u8>, LoRaError> {
        // Fetch the start pointer from the chip's current RX address.
        let current_addr = self.read_register(REG_FIFO_RX_CURRENT_ADDR)?;

        // Determine packet length: explicit header → RX_NB_BYTES,
        // implicit header → PAYLOAD_LENGTH.
        let mc1 = self.read_register(REG_MODEM_CONFIG_1)?;
        let payload_len = if mc1 & 0x01 == 0 {
            self.read_register(REG_RX_NB_BYTES)?
        } else {
            self.read_register(REG_PAYLOAD_LENGTH)?
        };

        if payload_len == 0 || payload_len as usize > MAX_PAYLOAD_LEN {
            return Ok(Vec::new());
        }

        // Point the FIFO pointer to the start of the received packet.
        self.write_register(REG_FIFO_ADDR_PTR, current_addr)?;

        // Burst-read the FIFO.
        let payload = self.read_registers(REG_FIFO, payload_len as usize)?;

        // Reset FIFO pointer for next operation.
        self.write_register(REG_FIFO_ADDR_PTR, 0)?;

        Ok(payload)
    }
}

impl LoRaChipset for SX1276 {
    fn new(spi: SpiBus, gpio: GpioPins) -> Self {
        Self {
            spi,
            reset: gpio.reset,
            config: None,
            command_delay: Duration::from_millis(2),
            rx_active: false,
            tx_active: false,
        }
    }

    fn init(&mut self, config: &LoRaConfig) -> Result<(), LoRaError> {
        self.command_delay = config.command_delay;

        // 1. Hardware reset
        self.hardware_reset()?;

        // 2. Enter sleep + LoRa mode
        self.set_op_mode(MODE_SLEEP)?;
        std::thread::sleep(Duration::from_millis(5));

        // 3. Ping the chip: read a known register to confirm SPI is working
        self.ping()?;

        // 4. Set frequency
        self.set_frequency(config.frequency)?;

        // 5. Configure FIFO base addresses
        self.write_register(REG_FIFO_TX_BASE_ADDR, 0)?;
        self.write_register(REG_FIFO_RX_BASE_ADDR, 0)?;

        // 6. Configure LNA: max gain (G1), HF boost, reserved bits
        //    G1=0b000 + LnaBoostHf=1 + reserved=011 → 0x1B
        self.write_register(REG_LNA, 0x1B)?;

        // 7. Set LoRa modulation parameters
        let bw_khz = config.bandwidth as u32;
        self.set_modulation_params(config.spreading_factor, bw_khz, config.coding_rate)?;

        // 8. Set preamble length
        self.set_preamble_length(config.preamble_length)?;

        // 9. Set sync word
        self.set_sync_word(config.sync_word)?;

        // 10. Validate communication: read back the sync word
        self.validate_communication(config.sync_word)?;

        // 11. CRC
        self.set_crc(config.crc_enabled)?;

        // 12. IQ inversion
        self.set_iq_inverted(config.iq_inverted)?;

        // 13. PA configuration and power
        self.set_pa_config(config.tx_power)?;

        // 14. Enter standby
        self.set_op_mode(MODE_STDBY)?;
        std::thread::sleep(Duration::from_millis(2));

        self.config = Some(config.clone());

        log::info!(
            "sx1276: configured freq={} Hz bw={} kHz sf={} cr={} power={} dBm",
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

        // Clamp to FIFO size
        let payload = if payload.len() > MAX_PAYLOAD_LEN {
            log::warn!(
                "sx1276: payload too large ({} bytes > max {}) – truncating",
                payload.len(),
                MAX_PAYLOAD_LEN,
            );
            &payload[..MAX_PAYLOAD_LEN]
        } else {
            payload
        };

        self.tx_active = true;
        self.rx_active = false;

        // Enter standby before configuring TX
        self.set_op_mode(MODE_STDBY)?;
        std::thread::sleep(self.command_delay);

        // Reset FIFO pointer and write payload
        self.write_register(REG_FIFO_ADDR_PTR, 0)?;
        self.write_registers(REG_FIFO, payload)?;
        self.write_register(REG_PAYLOAD_LENGTH, payload.len() as u8)?;

        // Ensure CRC / header mode are correct
        self.set_crc(cfg.crc_enabled)?;
        if cfg.implicit_header {
            let mc1 = self.read_register(REG_MODEM_CONFIG_1)?;
            self.write_register(REG_MODEM_CONFIG_1, mc1 | 0x01)?;
        } else {
            let mc1 = self.read_register(REG_MODEM_CONFIG_1)?;
            self.write_register(REG_MODEM_CONFIG_1, mc1 & 0xFE)?;
        }

        // Start TX
        self.set_op_mode(MODE_TX)?;

        log::trace!("sx1276: transmitted {} bytes", payload.len());
        Ok(())
    }

    fn start_receive(&mut self) -> Result<(), LoRaError> {
        let cfg = self
            .config
            .clone()
            .ok_or_else(|| LoRaError::Chipset("not initialised".into()))?;

        self.set_op_mode(MODE_STDBY)?;
        std::thread::sleep(self.command_delay);

        // Set header mode
        if cfg.implicit_header {
            let mc1 = self.read_register(REG_MODEM_CONFIG_1)?;
            self.write_register(REG_MODEM_CONFIG_1, mc1 | 0x01)?;
        } else {
            let mc1 = self.read_register(REG_MODEM_CONFIG_1)?;
            self.write_register(REG_MODEM_CONFIG_1, mc1 & 0xFE)?;
        }

        // Clear any pending IRQs
        self.clear_irq_flags(0xFF)?;

        // Enter RX via FSRX (frequency synthesis) so the PLL locks before
        // the receiver is enabled.  The SX1276 datasheet recommends this
        // two-step transition from STDBY to RX.
        self.set_op_mode(MODE_FSRX)?;
        std::thread::sleep(Duration::from_millis(2));

        self.set_op_mode(MODE_RX_CONTINUOUS)?;
        std::thread::sleep(Duration::from_millis(2));

        let op_mode = self.read_register(REG_OP_MODE)?;
        let expected = LONG_RANGE_MODE | MODE_RX_CONTINUOUS;
        if op_mode != expected {
            log::error!(
                "sx1276: failed to enter RX mode — wrote 0x{expected:02X}, read back 0x{op_mode:02X}"
            );
            return Err(LoRaError::Chipset(format!(
                "failed to enter RX mode: wrote 0x{expected:02X}, read back 0x{op_mode:02X}"
            )));
        }

        self.rx_active = true;
        self.tx_active = false;
        Ok(())
    }

    fn process_irq(&mut self) -> Result<Vec<ReceivedPacket>, LoRaError> {
        let mut packets = Vec::new();

        let irq = self.read_irq_flags()?;
        if irq == 0 {
            return Ok(packets);
        }

        // 0xFF means SPI communication has failed — chip not driving MISO
        if irq == 0xFF {
            return Err(LoRaError::Chipset(
                "IRQ flags = 0xFF — SPI bus not responding".into(),
            ));
        }

        log::trace!("sx1276: IRQ flags = 0x{irq:02X}");

        // Handle CRC errors
        if irq & IRQ_CRC_ERR != 0 {
            log::warn!("sx1276: CRC error in received packet");
        }

        // Handle RX done
        if irq & IRQ_RX_DONE != 0 {
            log::trace!("sx1276: RX received");
            // If CRC failed, skip the payload
            if irq & IRQ_CRC_ERR == 0 {
                let payload = self.read_fifo_payload()?;
                if !payload.is_empty() {
                    let (rssi, snr) = self.get_packet_rssi_snr()?;
                    packets.push(ReceivedPacket { payload, rssi, snr });
                }
                log::trace!("sx1276: RX complete");
            }
        }

        // Handle TX done
        if irq & IRQ_TX_DONE != 0 {
            log::trace!("sx1276: TX complete");
        }

        // Clear processed IRQs
        self.clear_irq_flags(irq)?;

        // Re-enter RX after any completion or error
        if irq & (IRQ_RX_DONE | IRQ_TX_DONE | IRQ_CRC_ERR) != 0 {
            if irq & IRQ_CRC_ERR != 0 {
                std::thread::sleep(Duration::from_millis(100));
            }
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
        let raw = self.read_register(REG_RSSI_VALUE)? as i16;
        Ok((raw - self.rssi_offset()) as f32)
    }
}

impl Drop for SX1276 {
    fn drop(&mut self) {
        let _ = self.set_op_mode(MODE_SLEEP);
    }
}
