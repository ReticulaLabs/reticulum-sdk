use std::time::{Duration, Instant};

use super::{
    GpioLine, GpioPins, LoRaChipset, LoRaConfig, LoRaError, ReceivedPacket, SpiBus,
};

// ── Command opcodes ───────────────────────────────────────────────────────

const CMD_SET_STANDBY: u8 = 0x80;
const CMD_SET_FS: u8 = 0x81;
const CMD_SET_TX: u8 = 0x83;
const CMD_SET_RX: u8 = 0x82;
const CMD_SET_SLEEP: u8 = 0x84;
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
const CMD_GET_DEVICE_ERRORS: u8 = 0x17;
// NB: datasheet rev 1.2 (DS.SX1261-2.W.APP) Table 11-5 lists ClearDeviceErrors
// as 0x07 (not 0x18). The rev-1.2 history explicitly notes "Correction of the
// ClearDeviceError command". 0x18 is silently ignored by this silicon.
const CMD_CLEAR_DEVICE_ERRORS: u8 = 0x07;
const CMD_GET_STATUS: u8 = 0xC0;

// ── Register addresses ────────────────────────────────────────────────────

const REG_IQ_POLARITY_SETUP: u16 = 0x0736;
const REG_LORA_SYNC_WORD_MSB: u16 = 0x0740;
const REG_LNA: u16 = 0x08AC;
const REG_TX_MODULATION: u16 = 0x0889;
const REG_TX_CLAMP_CONFIG: u16 = 0x08D8;
const REG_OCP: u16 = 0x08E7;
const REG_RTC_CONTROL: u16 = 0x0902;
const REG_EVENT_MASK: u16 = 0x0944;

// ── Maximum payload length ─────────────────────────────────────────────────
// SX1262 FIFO is 256 bytes; payload length field in SetPacketParams is 8 bits.
const MAX_PAYLOAD_LEN: usize = 255;

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
    // SX1262 SetModulationParams CR field:
    // 0x01 = 4/5, 0x02 = 4/6, 0x03 = 4/7, 0x04 = 4/8
    if (5..=8).contains(&cr) {
        cr - 4
    } else {
        0x00 // invalid → 4/4 (no coding)
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
        // Default wait covers a normal radio command (~10ms typical). Use
        // `wait_ready_with_max_busy` for long-running operations like
        // SetStandby(XOSC) (BUSY held for the configured TCXO startup delay,
        // hundreds of ms by default) and Calibrate(0x7F) (~400ms), which the
        // plain `command_delay` fallback does not cover.
        self.wait_ready_with_max_busy(Duration::from_millis(200))
    }

    /// Wait for the chip to be ready to accept the next command, bounded by
    /// `max_busy`. `max_busy` is the expected worst-case time the chip will
    /// spend in BUSY for the previous (or about-to-issue) command:
    ///
    ///   * Normal radio command: ~10 ms typical, ~50 ms worst case.
    ///   * Calibrate(0x7F, all blocks): up to ~400 ms.
    ///   * CalibrateImage: up to ~320 ms (also gated by the DIO3 TCXO ramp).
    ///   * SetStandby(XOSC): up to the configured `tcxo_startup_delay`
    ///     (default 320 ms, can be several seconds). The 32 MHz reference
    ///     is only declared stable after this window; if it's not
    ///     oscillating the chip latches XOSC_START_ERR.
    ///
    /// With a wired BUSY pin the poll loop returns as soon as the chip
    /// de-asserts BUSY, so the deadline is just a safety bound. Without a
    /// BUSY pin we must sleep a safe minimum: the caller's `max_busy`
    /// (floored at 200 ms) so a command sent while the chip is still BUSY
    /// is not silently dropped — the common cause of "SetTx dropped after
    /// SetStandby(XOSC)" on boards without a wired BUSY line. The
    /// SX1262_NO_BUSY_SLEEP_MS env var hard-overrides for users who know
    /// their hardware is faster (or slower).
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
                log::warn!("sx1262: BUSY still asserted after {max_busy:?}");
                Err(LoRaError::Timeout)
            }
            None => {
                let ms = std::env::var("SX1262_NO_BUSY_SLEEP_MS")
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

    /// Max busy time for `Calibrate(0x7F)` / `CalibrateImage`, whose BUSY
    /// window is gated by the DIO3 TCXO ramp (~320 ms) on top of the
    /// per-block calibration time.
    fn calibrate_max_busy(&self) -> Duration {
        Duration::from_millis(600)
    }

    /// Estimate the worst-case on-air time (seconds) for a `payload_len`
    /// byte packet under the current link config, using the standard LoRa
    /// packet time formula. Used to size the TX window budget: the chip
    /// does not assert BUSY during the RF transmission itself (BUSY is
    /// low for the whole TX, measured ~78 ms for a 28-byte packet at
    /// SF8/BW250), so TX completion must be confirmed via the TX_DONE IRQ
    /// within a window that covers the full packet airtime.
    fn estimate_airtime(&self, payload_len: usize) -> f64 {
        let Some(cfg) = &self.config else {
            return 0.0;
        };
        let bw_hz = cfg.bandwidth.max(1.0);
        let sf = cfg.spreading_factor.clamp(7, 12) as u64;
        let cr = cfg.coding_rate.max(4) as f64;
        let crc = if cfg.crc_enabled { 1.0 } else { 0.0 };
        let ih = if cfg.implicit_header { 1.0 } else { 0.0 };
        // Low-data-rate optimization applies when the symbol time would
        // exceed ~16 ms (SF11/SF12 at 125 kHz).
        let de = if sf >= 11 && bw_hz <= 125_000.0 { 1.0 } else { 0.0 };
        let symbol_time = ((1u64 << sf) as f64) / bw_hz;
        let n_preamble = cfg.preamble_length as f64 + 4.25;
        let numerator = 8.0 * payload_len as f64 - 4.0 * sf as f64 + 28.0 + 16.0 * crc - 20.0 * ih;
        let denominator = 4.0 * (sf as f64 - 2.0 * de);
        let n_payload = 8.0 + (numerator / denominator).ceil().max(0.0) * cr;
        (n_preamble + n_payload) * symbol_time
    }

    /// Max window for CMD_SET_TX completion: estimated on-air time plus a
    /// 2 s margin, floored at 1 s. Used by the no-BUSY sleep path so the
    /// post-SetTx wait covers the whole packet (a long SF12/BW125 packet
    /// can exceed the 500 ms TX_DONE poll deadline on its own), and as a
    /// generous upper bound for the wired-BUSY poll.
    fn tx_max_busy(&self, payload_len: usize) -> Duration {
        Duration::from_millis((self.estimate_airtime(payload_len) * 1000.0) as u64 + 2000)
            .max(Duration::from_secs(1))
    }

    /// POR-equivalent software reset via SetSleep (0x84, cold start).
    ///
    /// The SX1262 has no SPI reset command and the NRST pin may not be wired
    /// on every board. Without a hardware reset, a warm restart leaves the
    /// chip in its previous run's state (e.g. continuous RX) and TX is
    /// silently rejected. Entering SLEEP in cold-start mode and waking the
    /// device by dropping NSS performs a full POR-like reset into STDBY_RC.
    fn software_cold_start(&mut self) -> Result<(), LoRaError> {
        // SetSleep is only accepted in STDBY mode.
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        std::thread::sleep(Duration::from_millis(5));

        // SleepConfig = 0x00: RTC timeout disabled, cold start (no retention).
        // Must not be followed by further commands for ~500µs; BUSY stays
        // asserted for the whole sleep period, so we don't wait on it here.
        self.spi.xfer(&[CMD_SET_SLEEP, 0x00], &mut [0u8; 2])?;
        std::thread::sleep(Duration::from_millis(10));

        // The next falling edge on NSS wakes the device. spidev drives CS per
        // transaction, so this dummy write is the wake-up trigger. The device
        // then boots in cold start (full reset) into STDBY_RC.
        self.spi.xfer(&[0x00], &mut [0u8; 1])?;
        self.wait_ready()?;
        std::thread::sleep(Duration::from_millis(10));

        // Verify the chip is back in STDBY_RC. Note the GetStatus chip-mode
        // field (bits 6:4) uses a different encoding than the SetStandby
        // argument: 0x2 = STBY_RC, 0x3 = STBY_XOSC, 0x5 = RX, 0x6 = TX.
        let data = self.read_command(CMD_GET_STATUS, 1, &[])?;
        let status = data.first().copied().unwrap_or(0x00);
        if (status >> 4) & 0x07 != 0x02 {
            return Err(LoRaError::Chipset(format!(
                "software cold-start: chip not in STDBY_RC after wake (status=0x{status:02X})"
            )));
        }
        log::debug!("sx1262: software cold-start OK (status=0x{status:02X})");
        Ok(())
    }

    /// Probe whether SetSleep actually puts the chip into SLEEP. Diagnostic
    /// POR-detector: a genuinely fresh (power-cycled) chip honours SetSleep and
    /// is unresponsive during the wake transaction (garbage status byte); a
    /// warm-stuck chip ignores SetSleep and stays responsive (clean status).
    pub fn probe_sleep(&mut self) -> Result<bool, LoRaError> {
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        self.spi.xfer(&[CMD_SET_SLEEP, 0x00], &mut [0u8; 2])?;
        std::thread::sleep(Duration::from_millis(50));

        let mut rx = [0u8; 2];
        self.spi.xfer(&[CMD_GET_STATUS, 0x00], &mut rx)?;
        std::thread::sleep(Duration::from_millis(10));

        let was_asleep = matches!(rx[1], 0x00 | 0xFF);
        log::info!(
            "sx1262: probe_sleep: status during wake xact = 0x{:02X} -> chip was {}",
            rx[1],
            if was_asleep { "ASLEEP (fresh POR)" } else { "AWAKE (warm/stuck)" }
        );
        Ok(was_asleep)
    }

    /// Diagnostic POR-detector: reports whether the chip retains a RAM canary
    /// written by the previous run. A true power cycle resets RAM to default
    /// (sync-word MSB 0x0740 = 0x14); a warm chip still holds 0xAB.
    pub fn check_por_canary(&mut self) -> Result<(), LoRaError> {
        let v = self.read_register(REG_LORA_SYNC_WORD_MSB)?;
        log::info!(
            "sx1262: POR canary 0x0740 = 0x{v:02X} -> {}",
            if v == 0xAB {
                "WARM (RAM retained, NOT power-cycled)"
            } else if v == 0x14 {
                "FRESH (RAM at default, power-cycled)"
            } else {
                "UNKNOWN"
            }
        );
        Ok(())
    }

    /// Diagnostic: arm the POR canary for the next run (write 0xAB to sync MSB).
    pub fn set_por_canary(&mut self) -> Result<(), LoRaError> {
        self.write_register(REG_LORA_SYNC_WORD_MSB, &[0xAB, 0x24])
    }

    /// Hardware reset via the NRESET pin (no-op if reset is not wired).
    /// Public so callers can put the chip into a known state without
    /// running the full `init` sequence.
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

    fn write_command(&mut self, opcode: u8, args: &[u8]) -> Result<(), LoRaError> {
        self.write_command_with_max_busy(opcode, args, Duration::from_millis(200))
    }

    /// Write command with an explicit BUSY budget. See
    /// `wait_ready_with_max_busy` for guidance on choosing `max_busy`.
    fn write_command_with_max_busy(
        &mut self,
        opcode: u8,
        args: &[u8],
        max_busy: Duration,
    ) -> Result<(), LoRaError> {
        self.wait_ready_with_max_busy(max_busy)?;
        let tx = {
            let mut buf = vec![opcode];
            buf.extend_from_slice(args);
            buf
        };
        let mut rx = vec![0u8; tx.len()];
        self.spi.xfer(&tx, &mut rx)?;
        log::trace!(
            "sx1262: cmd 0x{opcode:02X} resp status=0x{:02X}",
            rx.first().copied().unwrap_or(0xFF)
        );
        self.wait_ready_with_max_busy(max_busy)?;
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

    fn set_tx_params(&mut self, power_dbm: i8, sx1261_mode: bool) -> Result<(), LoRaError> {
        if sx1261_mode {
            let clamped = power_dbm.clamp(-17, 15);
            if clamped == 15 {
                self.write_command(CMD_SET_PA_CONFIG, &[0x06, 0x00, 0x01, 0x01])?;
            } else {
                self.write_command(CMD_SET_PA_CONFIG, &[0x04, 0x00, 0x01, 0x01])?;
            }
            let power = if clamped >= 14 { 14u8 } else { clamped.max(-17) as u8 };
            self.write_register(REG_OCP, &[0x10])?;
            self.write_command(CMD_SET_TX_PARAMS, &[power, RAMP_800U])
        } else {
            let clamped = power_dbm.clamp(-9, 22);
            // Semtech HAL: always use optimal PA config for SX1262
            self.write_command(CMD_SET_PA_CONFIG, &[0x04, 0x07, 0x00, 0x01])?;
            // Errata 15.2: Better resistance to antenna mismatch
            let val = self.read_register(REG_TX_CLAMP_CONFIG)?;
            self.write_register(REG_TX_CLAMP_CONFIG, &[val | 0x1E])?;
            self.write_register(REG_OCP, &[OCP_125MA])?;
            self.write_command(CMD_SET_TX_PARAMS, &[clamped as u8, RAMP_800U])
        }
    }

    fn set_pa_config(&mut self, power_dbm: i8, sx1261_mode: bool) -> Result<(), LoRaError> {
        let clamped = power_dbm.clamp(-9, if sx1261_mode { 15 } else { 22 });
        // SX1262 optimal PA settings per datasheet Table 13-21
        let (pa_duty_cycle, hp_max, device_sel) = if sx1261_mode {
            if clamped >= 15 {
                (0x04, 0x00, 0x01) // SX1261: +15 dBm max
            } else if clamped >= 14 {
                (0x02, 0x00, 0x01) // +14 dBm
            } else if clamped >= 10 {
                (0x01, 0x00, 0x01) // +10 dBm
            } else {
                (0x00, 0x00, 0x01) // min power
            }
        } else {
            if clamped >= 22 {
                (0x04, 0x07, 0x00) // SX1262: +22 dBm
            } else if clamped >= 20 {
                (0x03, 0x05, 0x00) // +20 dBm
            } else if clamped >= 17 {
                (0x02, 0x03, 0x00) // +17 dBm
            } else if clamped >= 14 {
                (0x02, 0x02, 0x00) // +14 dBm
            } else {
                (0x00, 0x00, 0x00) // min power
            }
        };
        // paLut: always 0x01 (reserved)
        self.write_command(CMD_SET_PA_CONFIG, &[pa_duty_cycle, hp_max, device_sel, 0x01])
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

    fn set_dio3_as_tcxo_ctrl(
        &mut self,
        voltage: f64,
        startup_delay: Duration,
    ) -> Result<(), LoRaError> {
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
        // TCXO startup timeout. Delay(23:0) units are 15.625µs. If the XO is
        // not stable within this window the chip latches XOSC_START_ERR and
        // aborts the STBY_XOSC transition. Core1262 modules need a generous
        // timeout (51.2ms is not enough and TX is then silently rejected).
        let delay: u32 = (startup_delay.as_millis().clamp(1, 1_000_000) as u32
            * 1000)
            / 16;
        self.write_command(
            CMD_SET_DIO3_AS_TCXO_CTRL,
            &[code, (delay >> 16) as u8, (delay >> 8) as u8, delay as u8],
        )
    }

    fn calibrate(&mut self) -> Result<(), LoRaError> {
        // Put in STDBY_RC before calibration (XO must be stopped)
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;

        // Calibrate RC64k, RC13M, PLL, ADC and image. Holds BUSY for the
        // whole window (gated by the DIO3 TCXO ramp when configured), so
        // it needs the full calibrate budget even with a wired BUSY line.
        self.write_command_with_max_busy(
            CMD_CALIBRATE,
            &[MASK_CALIBRATE_ALL],
            self.calibrate_max_busy(),
        )?;

        std::thread::sleep(Duration::from_millis(5));
        self.wait_ready()?;
        Ok(())
    }

    fn calibrate_image(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        let (f1, f2) = calibrate_image_bands(freq_hz);
        // SX1262 CalibrateImage takes 2 bytes: frequency band start and end.
        // Also gated by the TCXO ramp on some boards, so use the full budget.
        self.write_command_with_max_busy(
            CMD_CALIBRATE_IMAGE,
            &[f1, f2],
            self.calibrate_max_busy(),
        )
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

    fn set_regulator_mode(&mut self, dcdc: bool) -> Result<(), LoRaError> {
        let mode = if dcdc { REGULATOR_DCDC } else { 0x00 };
        self.write_command(CMD_SET_REGULATOR_MODE, &[mode])
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

    /// Read the device error register (datasheet 13.6.1, Table 13-85).
    /// Returns the 16-bit OpError value: bit 5 = XOSC_START_ERR,
    /// bit 6 = PLL_LOCK_ERR, bit 8 = PA_RAMP_ERR.
    pub fn get_device_errors(&mut self) -> Result<u16, LoRaError> {
        let data = self.read_command(CMD_GET_DEVICE_ERRORS, 2, &[])?;
        if data.len() >= 2 {
            Ok(((data[0] as u16) << 8) | data[1] as u16)
        } else {
            Ok(0)
        }
    }

    /// Clear all latched device errors (datasheet 13.6.2).
    pub fn clear_device_errors(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_CLEAR_DEVICE_ERRORS, &[0x00, 0x00])
    }

    /// Read the current IRQ status word (GetIrqStatus, 0x12).
    /// Bit 0 = TX_DONE, bit 1 = RX_DONE, bit 9 = timeout.
    pub fn get_irq_status(&mut self) -> Result<u16, LoRaError> {
        let data = self.read_command(CMD_GET_IRQ_STATUS, 2, &[])?;
        if data.len() >= 2 {
            Ok(((data[0] as u16) << 8) | data[1] as u16)
        } else {
            Ok(0)
        }
    }

    /// Explicitly enter STDBY_XOSC so the host can verify the XO actually
    /// starts (diagnostic helper; status is visible on the next read).
    /// Uses the configured `tcxo_startup_delay` as the BUSY budget so the
    /// chip has time to attempt the XOSC startup before we report a status
    /// (otherwise the post-wait returns while BUSY is still asserted and
    /// the next command is silently dropped).
    pub fn set_standby_xosc(&mut self) -> Result<(), LoRaError> {
        self.write_command_with_max_busy(CMD_SET_STANDBY, &[STANDBY_XOSC], self.xosc_max_busy())
    }

    /// Read the raw status byte (GetStatus, 0xC0). Chip-mode field (bits
    /// 6:4): 0x2=STBY_RC, 0x3=STBY_XOSC, 0x4=FS, 0x5=RX, 0x6=TX.
    pub fn get_status(&mut self) -> Result<u8, LoRaError> {
        let data = self.read_command(CMD_GET_STATUS, 1, &[])?;
        Ok(data.first().copied().unwrap_or(0x00))
    }

    /// Wait until the chip reports STBY_XOSC (0x3), i.e. the XO is up and
    /// stable. The chip holds BUSY (unwired here) during the XO startup
    /// window and drops every command except GetStatus, so polling the
    /// status byte is the software BUSY-wait. Returns Ok if STBY_XOSC was
    /// reached within `timeout`.
    pub fn wait_for_standby_xosc(&mut self, timeout: Duration) -> Result<bool, LoRaError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let status = self.get_status()?;
            if (status >> 4) & 0x07 == 0x03 {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(false)
    }

    /// Enter STDBY_XOSC and wait for the XO to come up, retrying for a slow
    /// or marginal TCXO. On success any latched XOSC/PLL startup error is
    /// cleared so later checks aren't misread. This is the software
    /// equivalent of waiting for BUSY to release (no BUSY line is wired).
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
            )?;
            if self.wait_for_standby_xosc(timeout)? {
                let _ = self.clear_device_errors();
                return Ok(());
            }
            log::warn!(
                "sx1262: STDBY_XOSC attempt {attempt} timed out (delay {startup_delay:?}); retrying"
            );
        }
        Err(LoRaError::Chipset(
            "XO did not reach STBY_XOSC within timeout".into(),
        ))
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
            command_delay: Duration::from_millis(50),
            rx_active: false,
            tx_active: false,
        }
    }

    fn init(&mut self, config: &LoRaConfig) -> Result<(), LoRaError> {
        self.command_delay = config.command_delay;

        // Hardware reset if a reset line is wired; software cold-start always,
        // so the chip reaches a POR-equivalent state even when NRST is absent.
        self.hardware_reset()?;
        self.software_cold_start()?;

        // Enter standby RC mode
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        std::thread::sleep(Duration::from_millis(5));

        // Quick SPI ping to confirm the chip is alive and in the right mode
        self.ping()?;

        // Read chip version for diagnostics
        let fw_version = self.read_register(0x0150).unwrap_or(0xFF);
        log::info!("sx1262: chip version register 0x0150 = 0x{fw_version:02X}");

        // Set packet type to LoRa
        self.write_command(CMD_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;

        // Set regulator mode (LDO or DC-DC per config)
        self.set_regulator_mode(config.dcdc)?;

        // Configure DIO2 as RF switch if needed
        self.set_dio2_as_rf_switch(config.dio_rf_switch)?;

        // Configure TCXO if needed
        if let Some(v) = config.tcxo_voltage {
            self.set_dio3_as_tcxo_ctrl(v, config.tcxo_startup_delay)?;
        }

        // Errata workarounds
        self.fix_resistance_antenna()?;

        // Full calibration: RC64k, RC13M, PLL, ADC (recommended after
        // power-on per SX1262 datasheet)
        self.calibrate()?;

        // Band-specific image calibration
        self.calibrate_image(config.frequency)?;

        // Switch to STDBY_XOSC for a stable XO reference before frequency
        // synthesis and TX/RX operations. Without a BUSY line we poll the
        // status byte (GetStatus is answered even while BUSY) and retry for
        // a slow/marginal TCXO, so a later TX is not silently rejected.
        self.enter_standby_xosc(config.tcxo_startup_delay)?;

        // Diagnostic: after the first XOSC standby attempt, report latched
        // device errors so XO/TCXO/PLL startup failures are visible.
        match self.get_device_errors() {
            Ok(err) => {
                if err != 0 {
                    let mut bits = Vec::new();
                    if err & 0x20 != 0 { bits.push("XOSC_START_ERR"); }
                    if err & 0x40 != 0 { bits.push("PLL_LOCK_ERR"); }
                    if err & 0x100 != 0 { bits.push("PA_RAMP_ERR"); }
                    if err & 0x01 != 0 { bits.push("RC64K_CALIB_ERR"); }
                    if err & 0x02 != 0 { bits.push("RC13M_CALIB_ERR"); }
                    if err & 0x04 != 0 { bits.push("PLL_CALIB_ERR"); }
                    if err & 0x08 != 0 { bits.push("ADC_CALIB_ERR"); }
                    if err & 0x10 != 0 { bits.push("IMG_CALIB_ERR"); }
                    log::warn!(
                        "sx1262: device errors after STDBY_XOSC = 0x{err:04X} ({})",
                        bits.join(", "),
                    );
                } else {
                    log::info!("sx1262: no device errors after STDBY_XOSC (XO started)");
                }
            }
            Err(e) => log::warn!("sx1262: could not read device errors: {}", e),
        }

        // Configure radio parameters
        self.set_rf_frequency(config.frequency)?;
        self.set_modulation_params(
            config.spreading_factor,
            config.bandwidth as u32,
            config.coding_rate,
        )?;

        // Set TX parameters (also applies OCP)
        self.set_tx_params(config.tx_power, config.sx1261_mode)?;

        // LNA boost — improves receiver sensitivity
        self.write_register(REG_LNA, &[0x96])?;

        // Set buffer base addresses
        self.set_buffer_base_address()?;

        // Set sync word
        self.set_sync_word(config.sync_word)?;

        // Set DIO IRQ params
        self.set_dio_irq_params(config.dio1_line.is_some())?;

        // BW500 workaround
        self.fix_lora_bw500(config.bandwidth as u32)?;

        // Initial packet params (triggers IQ polarity fix internally)
        let header_mode = if config.implicit_header { 0x01 } else { 0x00 };
        let crc = if config.crc_enabled { 0x01 } else { 0x00 };
        let iq = if config.iq_inverted { 0x01 } else { 0x00 };
        self.set_packet_params(config.preamble_length, header_mode, 0xFF, crc, iq)?;

        self.config = Some(config.clone());

        self.validate_communication(config.sync_word)?;

        log::info!(
            "sx1262: configured freq={} Hz bw={} kHz sf={} cr={} power={} dBm tcxo={}v",
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

        // SX1262 FIFO is 256 bytes and the packet params payload length field
        // is 8 bits. Clamp to the maximum, matching the reference HAL.
        let payload = if payload.len() > MAX_PAYLOAD_LEN {
            log::warn!(
                "sx1262: payload too large ({} bytes > max {}) – truncating",
                payload.len(),
                MAX_PAYLOAD_LEN,
            );
            &payload[..MAX_PAYLOAD_LEN]
        } else {
            payload
        };

        self.tx_active = true;
        self.rx_active = false;

        // CMD_WRITE_BUFFER and packet params must be issued in STDBY mode,
        // not while the chip is in RX.  Exit RX first and, for a TCXO, wait
        // for the XO to come up so the FIFO write isn't dropped while the
        // chip is still BUSY starting the oscillator.
        self.enter_standby_xosc(cfg.tcxo_startup_delay)?;
        log::debug!(
            "sx1262: tx step status 0x{:02X} (after SetStandby XOSC)",
            self.get_status().unwrap_or(0)
        );

        // Write payload to TX FIFO at offset 0
        let mut write_args = vec![0x00];
        write_args.extend_from_slice(payload);
        self.write_command(CMD_WRITE_BUFFER, &write_args)?;
        log::debug!(
            "sx1262: tx step status 0x{:02X} (after WriteBuffer)",
            self.get_status().unwrap_or(0)
        );

        // Set packet params with exact payload length
        let header_mode = if cfg.implicit_header { 0x01 } else { 0x00 };
        let crc = if cfg.crc_enabled { 0x01 } else { 0x00 };
        let iq = if cfg.iq_inverted { 0x01 } else { 0x00 };
        self.set_packet_params(cfg.preamble_length, header_mode, payload.len() as u8, crc, iq)?;
        log::debug!(
            "sx1262: tx step status 0x{:02X} (after SetPacketParams)",
            self.get_status().unwrap_or(0)
        );

        // BW500 workaround for TX
        self.fix_lora_bw500(cfg.bandwidth as u32)?;

        // Trigger TX with no timeout. BUSY is low during the RF
        // transmission itself (verified by capture), so this wait only needs
        // to cover SetTx command processing and the PLL/XO ramp; the
        // `tx_budget` wait additionally absorbs the full airtime on the
        // no-BUSY sleep path so the TX_DONE poll below never starts while
        // the packet is still on air. The pre-wait uses the short default
        // since the chip is in standby here.
        let tx_budget = self.tx_max_busy(payload.len());
        self.wait_ready()?;
        self.spi
            .xfer(&[CMD_SET_TX, 0x00, 0x00, 0x00], &mut [0u8; 4])?;
        self.wait_ready_with_max_busy(tx_budget)?;
        let st_after_tx = self.get_status().unwrap_or(0x00);
        log::debug!("sx1262: status after CMD_SET_TX = 0x{st_after_tx:02X}");

        // Confirm TX_DONE. By now the chip has left the TX window (BUSY
        // released or the airtime sleep elapsed), so the IRQ read is not
        // dropped; the bounded retry loop is a safety net against the chip
        // silently rejecting CMD_SET_TX (bad PA config, PLL or frequency).
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut tx_ok = false;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            let irq_data = self.read_command(CMD_GET_IRQ_STATUS, 2, &[])?;
            if irq_data.len() >= 2 {
                let irq = (irq_data[0] as u16) << 8 | irq_data[1] as u16;
                if irq & IRQ_TX_DONE != 0 {
                    tx_ok = true;
                    break;
                }
            }
        }

        if tx_ok {
            self.clear_irq_status(IRQ_TX_DONE)?;
            self.tx_active = false;
            // Re-enter RX mode so the chip can receive and the poll loop
            // doesn't keep seeing IRQ=0 in standby.
            self.start_receive()?;
            log::trace!("sx1262: TX_DONE after {} bytes", payload.len());
        } else {
            let status = self.get_status().unwrap_or(0x00);
            log::error!(
                "sx1262: TX failed — no TX_DONE within 500ms \
                 (chip may have rejected CMD_SET_TX) [status=0x{status:02X}]"
            );
            // Return to a known state so the poll loop can recover.
            self.clear_irq_status(0xFFFF)?;
            self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
            self.tx_active = false;
            return Err(LoRaError::Chipset("TX never started — chip rejected CMD_SET_TX".into()));
        }

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
        self.fix_lora_bw500(cfg.bandwidth as u32)?;

        // Set packet params (payload len 0xFF, ignored in explicit header mode)
        // NOTE: IQ polarity errata fix is applied inside set_packet_params.
        self.set_packet_params(cfg.preamble_length, header_mode, 0xFF, crc, iq)?;

        // RX timeout workaround
        self.fix_rx_timeout()?;

        // Enter continuous RX. RX entry from STBY_RC re-starts the 32 MHz
        // XO, and the chip holds BUSY for the full configured TCXO startup
        // window (measured ~311 ms on this hardware vs the 320 ms delay).
        // The short 200 ms default `wait_ready` budget times out here, so
        // use the XOSC budget.
        self.write_command_with_max_busy(
            CMD_SET_RX,
            &[0xFF, 0xFF, 0xFF],
            self.xosc_max_busy(),
        )?;

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
