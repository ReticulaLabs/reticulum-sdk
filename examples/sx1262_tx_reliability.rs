//! Outbound (TX) reliability walkthrough for the SX1262.
//!
//! For each iteration this records, at the chip level:
//!   - chip mode before TX (expect RX 0x5x after the previous TX re-arms RX)
//!   - device errors before TX (expect 0x0000)
//!   - chip mode immediately after CMD_SET_TX (expect TX 0x6x)
//!   - whether TX_DONE was seen and how long it took
//!   - device errors after TX (expect 0x0000)
//!   - IRQ status after TX (expect 0x0000 — cleared)
//!   - instantaneous RSSI after TX (sanity: must not read like a live carrier)
//!
//! Every chip-level "TX_DONE" SHOULD correspond to an on-air burst you can
//! see on the SDR. If the chip reports TX_DONE but the SDR misses bursts,
//! the problem is downstream of the chip (PA / RF switch / antenna / SDR
//! trigger), not the SPI driver.
//!
//! Env knobs:
//!   TX_COUNT   iterations (default 20)
//!   TX_GAP_MS  pause between bursts, ms (default 1500)
//!   TX_LEN     payload length, bytes (default 64)

use std::time::{Duration, Instant};

use reticulum_sdk::iface::lora::sx1262::SX1262;
use reticulum_sdk::iface::lora::{GpioPins, LoRaConfig, LoRaChipset, SpiBus};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1" || v == "true").unwrap_or(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let count = env_u64("TX_COUNT", 20);
    let gap = Duration::from_millis(env_u64("TX_GAP_MS", 1500));
    let tx_len = env_u64("TX_LEN", 64).clamp(1, 200) as usize;

    let spi = SpiBus::open("/dev/spidev0.0", 4_000_000)?;
    let gpio = GpioPins::open(&LoRaConfig::new(
        "/dev/spidev0.0", 914_875_000, 250_000.0, 22, 8, 5,
    ))?;

    let mut config = LoRaConfig::new(
        "/dev/spidev0.0", 914_875_000, 250_000.0, 22, 8, 5,
    );
    config.tcxo_voltage = Some(3.0);
    config.tcxo_startup_delay = Duration::from_millis(320);
    config.dio_rf_switch = true;
    config.spi_speed = 4_000_000;
    config.command_delay = Duration::from_millis(2);
    config.rx_poll_interval = Duration::from_millis(50);

    let mut chipset = SX1262::new(Box::new(spi), gpio);
    chipset.init(&config)?;
    log::info!("init OK — chip now in RX (re-armed by open_chipset); starting TX walkthrough");
    log::info!(
        "params: count={count} gap={gap:?} payload={tx_len}B freq=914.875MHz sf=8 bw=250k \
         (airtime ~{:.2}s/burst)",
        tx_len as f64 * 8.0 / 250_000.0 * 2.0 + 0.2
    );

    let payload: Vec<u8> = (0..tx_len as u32).map(|i| (i % 251) as u8).collect();

    let mut ok = 0u32;
    let mut tx_done_fails = 0u32;
    let mut err_fails = 0u32;

    for i in 0..count {
        std::thread::sleep(gap);

        let pre_status = chipset.get_status().unwrap_or(0xFF);
        let pre_err = chipset.get_device_errors().unwrap_or(0xFFFF);

        let t0 = Instant::now();
        let result = chipset.transmit(&payload);
        let elapsed = t0.elapsed();

        let post_status = chipset.get_status().unwrap_or(0xFF);
        let post_err = chipset.get_device_errors().unwrap_or(0xFFFF);
        let irq = chipset.get_irq_status().unwrap_or(0xFFFF);
        let rssi = chipset.current_rssi().unwrap_or(-127.0);

        let pre_mode = (pre_status >> 4) & 0x07;
        let post_mode = (post_status >> 4) & 0x07;

        match &result {
            Ok(()) => {
                ok += 1;
                log::info!(
                    "[tx {i:02}] pre=0x{pre_status:02X}(mode{pre_mode:X}) pre_err=0x{pre_err:04X} \
                     -> TX_DONE after {elapsed:?} -> post=0x{post_status:02X}(mode{post_mode:X}) \
                     post_err=0x{post_err:04X} irq=0x{irq:04X} rssi={rssi:.1}dBm"
                );
            }
            Err(e) => {
                tx_done_fails += 1;
                log::error!(
                    "[tx {i:02}] FAILED: {e} (pre=0x{pre_status:02X} pre_err=0x{pre_err:04X} \
                     post=0x{post_status:02X} post_err=0x{post_err:04X})"
                );
            }
        }

        if post_err != 0 {
            err_fails += 1;
            log::error!(
                "[tx {i:02}] latched device errors after TX: 0x{post_err:04X}"
            );
        }

        // Optional: verify the chip re-armed RX after TX_DONE (expect mode 0x5).
        if result.is_ok() && post_mode != 0x5 && post_mode != 0x2 {
            log::warn!(
                "[tx {i:02}] chip did not return to RX/STBY after TX (mode {post_mode:X}); \
                 polling may be blind"
            );
        }
    }

    log::info!(
        "=== summary: {ok}/{count} TX_DONE, {tx_done_fails} failed, {err_fails} with errors ==="
    );
    if env_flag("END_IN_RX") {
        chipset.start_receive()?;
        log::info!("chip left in RX");
    }
    Ok(())
}
