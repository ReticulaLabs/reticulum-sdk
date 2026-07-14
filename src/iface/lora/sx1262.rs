use std::time::{Duration, Instant};

use super::{
    GpioLine, GpioPins, LoRaChipset, LoRaConfig, LoRaError, ReceivedPacket, SpiBus,
};

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
const CMD_WRITE_BUFFER: u8 = 0x0E;
const CMD_READ_BUFFER: u8 = 0x1E;
const CMD_WRITE_REGISTER: u8 = 0x0D;

const REG_LORA_SYNC_WORD: u16 = 0x0740;

const PACKET_TYPE_LORA: u8 = 0x01;
const STANDBY_RC: u8 = 0x00;
const REGULATOR_DCDC: u8 = 0x01;

const IRQ_TX_DONE: u16 = 0x0001;
const IRQ_RX_DONE: u16 = 0x0002;
const IRQ_HEADER_ERR: u16 = 0x0020;
const IRQ_CRC_ERR: u16 = 0x0040;
const IRQ_TIMEOUT: u16 = 0x0200;
const IRQ_MASK_ALL: u16 =
    IRQ_TX_DONE | IRQ_RX_DONE | IRQ_HEADER_ERR | IRQ_CRC_ERR | IRQ_TIMEOUT;

const RAMP_200U: u8 = 0x04;

fn lora_bandwidth_code(bw_khz: f64) -> Result<u8, LoRaError> {
    match bw_khz as u32 {
        7 => Ok(0x00),
        10 => Ok(0x08),
        15 => Ok(0x01),
        20 => Ok(0x09),
        31 => Ok(0x02),
        41 => Ok(0x0A),
        62 => Ok(0x03),
        125 => Ok(0x04),
        250 => Ok(0x05),
        500 => Ok(0x06),
        _ => Err(LoRaError::Config(format!(
            "unsupported bandwidth {} kHz",
            bw_khz
        ))),
    }
}

fn lora_coding_rate_code(cr: u8) -> Result<u8, LoRaError> {
    match cr {
        5 => Ok(0x01),
        6 => Ok(0x02),
        7 => Ok(0x03),
        8 => Ok(0x04),
        _ => Err(LoRaError::Config(format!(
            "invalid coding rate index {}",
            cr
        ))),
    }
}

fn needs_ldro(sf: u8, bw_khz: f64) -> bool {
    let symbol_time_ms = ((1u64 << sf) as f64) / (bw_khz * 1000.0) * 1000.0;
    symbol_time_ms >= 16.38
}

fn tcxo_voltage_code(v: f64) -> Result<u8, LoRaError> {
    match v {
        x if x >= 1.6 && x < 1.7 => Ok(0x00),
        x if x >= 1.7 && x < 1.8 => Ok(0x01),
        x if x >= 1.8 && x < 2.2 => Ok(0x02),
        x if x >= 2.2 && x < 2.4 => Ok(0x03),
        x if x >= 2.4 && x < 2.7 => Ok(0x04),
        x if x >= 2.7 && x < 3.0 => Ok(0x05),
        x if x >= 3.0 && x < 3.3 => Ok(0x06),
        x if x >= 3.3 => Ok(0x07),
        _ => Err(LoRaError::Config(format!("invalid TCXO voltage {}", v))),
    }
}

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
                let deadline = Instant::now() + Duration::from_secs(1);
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
                reset
                    .set_value(true)
                    .map_err(|e| LoRaError::Gpio(format!("reset set high: {}", e)))?;
                std::thread::sleep(Duration::from_millis(10));
                reset
                    .set_value(false)
                    .map_err(|e| LoRaError::Gpio(format!("reset set low: {}", e)))?;
                std::thread::sleep(Duration::from_millis(10));
                reset
                    .set_value(true)
                    .map_err(|e| LoRaError::Gpio(format!("reset set high: {}", e)))?;
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
        Ok(rx[rx.len() - read_len..].to_vec())
    }

    fn write_register(&mut self, addr: u16, data: &[u8]) -> Result<(), LoRaError> {
        let mut args = vec![(addr >> 8) as u8, (addr & 0xFF) as u8];
        args.extend_from_slice(data);
        self.write_command(CMD_WRITE_REGISTER, &args)
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

    fn set_modulation_params(
        &mut self,
        sf: u8,
        bw_khz: f64,
        cr: u8,
    ) -> Result<(), LoRaError> {
        let bw = lora_bandwidth_code(bw_khz)?;
        let cr_code = lora_coding_rate_code(cr)?;
        let ldro = if needs_ldro(sf, bw_khz) { 0x01 } else { 0x00 };
        self.write_command(CMD_SET_MODULATION_PARAMS, &[sf, bw, cr_code, ldro])
    }

    fn set_packet_params(
        &mut self,
        preamble: u16,
        header_mode: u8,
        payload_len: u8,
        crc: u8,
        iq: u8,
    ) -> Result<(), LoRaError> {
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
        )
    }

    fn set_tx_params(&mut self, power_dbm: i8) -> Result<(), LoRaError> {
        let clamped = power_dbm.clamp(-9, 22);
        self.write_command(CMD_SET_TX_PARAMS, &[clamped as u8, RAMP_200U])
    }

    fn set_pa_config(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_SET_PA_CONFIG, &[0x04, 0x07, 0x00, 0x01])
    }

    fn set_buffer_base_address(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80])
    }

    fn set_sync_word(&mut self, word: u16) -> Result<(), LoRaError> {
        self.write_register(REG_LORA_SYNC_WORD, &[(word >> 8) as u8, (word & 0xFF) as u8])
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
        let code = tcxo_voltage_code(voltage)?;
        let delay = if voltage >= 1.6 && voltage < 1.7 {
            0x28
        } else if voltage < 1.8 {
            0x28
        } else if voltage < 2.2 {
            0x3C
        } else if voltage < 2.4 {
            0x50
        } else if voltage < 2.7 {
            0x64
        } else if voltage < 3.0 {
            0x78
        } else {
            0x8C
        };
        self.write_command(CMD_SET_DIO3_AS_TCXO_CTRL, &[code, delay])
    }

    fn calibrate_image(&mut self, freq_hz: u64) -> Result<(), LoRaError> {
        let band = if freq_hz < 779_000_000 {
            0x00
        } else if freq_hz < 900_000_000 {
            0x01
        } else if freq_hz < 1_100_000_000 {
            0x02
        } else if freq_hz < 1_300_000_000 {
            0x03
        } else {
            0x04
        };
        self.write_command(CMD_CALIBRATE_IMAGE, &[band])
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

    fn get_packet_status(&mut self) -> Result<(f32, f32), LoRaError> {
        let data = self.read_command(CMD_GET_PACKET_STATUS, 3, &[])?;
        if data.len() >= 2 {
            let rssi_raw = data[0] as i16;
            let snr_raw = data[1] as i8;
            let rssi = -37.0 + (rssi_raw as f32 * -0.25);
            let snr = snr_raw as f32 * 0.25;
            Ok((rssi, snr))
        } else {
            Ok((0.0, 0.0))
        }
    }

    fn set_regulator_mode(&mut self) -> Result<(), LoRaError> {
        self.write_command(CMD_SET_REGULATOR_MODE, &[REGULATOR_DCDC])
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
        self.write_command(CMD_SET_STANDBY, &[STANDBY_RC])?;
        std::thread::sleep(Duration::from_millis(5));
        self.write_command(CMD_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;
        self.set_regulator_mode()?;
        self.set_dio2_as_rf_switch(config.dio2_rf_switch)?;

        if let Some(v) = config.tcxo_voltage {
            self.set_dio3_as_tcxo_ctrl(v)?;
        }

        self.calibrate_image(config.frequency)?;
        self.set_pa_config()?;
        self.set_rf_frequency(config.frequency)?;
        self.set_modulation_params(config.spreading_factor, config.bandwidth, config.coding_rate)?;
        self.set_tx_params(config.tx_power)?;
        self.set_buffer_base_address()?;
        self.set_sync_word(config.sync_word)?;
        self.set_dio_irq_params(config.dio1_line.is_some())?;

        self.config = Some(config.clone());

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

        let mut write_args = vec![0x00];
        write_args.extend_from_slice(payload);
        self.write_command(CMD_WRITE_BUFFER, &write_args)?;

        let header_mode = if cfg.implicit_header { 0x01 } else { 0x00 };
        let crc = if cfg.crc_enabled { 0x01 } else { 0x00 };
        let iq = if cfg.iq_inverted { 0x01 } else { 0x00 };
        self.set_packet_params(cfg.preamble_length, header_mode, payload.len() as u8, crc, iq)?;

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
        self.set_packet_params(cfg.preamble_length, header_mode, 0xFF, crc, iq)?;
        self.write_command(CMD_SET_RX, &[0xFF, 0xFF, 0xFF])?;

        self.rx_active = true;
        self.tx_active = false;
        Ok(())
    }

    fn process_irq(&mut self) -> Result<Vec<ReceivedPacket>, LoRaError> {
        let mut packets = Vec::new();

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

        let irq_data = self.read_command(CMD_GET_IRQ_STATUS, 2, &[])?;
        if irq_data.len() < 2 {
            return Ok(packets);
        }

        let irq_status = (irq_data[0] as u16) << 8 | irq_data[1] as u16;

        if irq_status == 0 {
            return Ok(packets);
        }

        if irq_status & IRQ_CRC_ERR != 0 {
            log::warn!("sx1262: CRC error in received packet");
        }
        if irq_status & IRQ_HEADER_ERR != 0 {
            log::warn!("sx1262: header error in received packet");
        }

        if irq_status & IRQ_RX_DONE != 0 {
            let (payload_len, start_ptr) = self.get_rx_buffer_status()?;
            if payload_len > 0 {
                let payload = self.read_buffer(start_ptr, payload_len)?;
                let (rssi, snr) = self.get_packet_status()?;

                if irq_status & IRQ_CRC_ERR == 0 {
                    packets.push(ReceivedPacket {
                        payload,
                        rssi,
                        snr,
                    });
                } else {
                    log::warn!("sx1262: dropping corrupted packet (CRC error)");
                }
            }
        }

        if irq_status & IRQ_TX_DONE != 0 {
            log::trace!("sx1262: TX complete");
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
        let data = self.read_command(CMD_GET_PACKET_STATUS, 3, &[])?;
        if data.len() >= 1 {
            let raw = data[0] as i16;
            Ok(-37.0 + (raw as f32 * -0.25))
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
