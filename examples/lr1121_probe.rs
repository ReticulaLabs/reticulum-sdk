use std::time::{Duration, Instant};

use reticulum_sdk::iface::lora::lr1121::LR1121;
use reticulum_sdk::iface::lora::{GpioPins, LoRaConfig, LoRaChipset, SpiBus};

// LR11xx chip-mode values (encoded in stat2 bits 3:1). These are
// different from the SX1262 — don't cross-port status checks.
#[allow(dead_code)] // STBY_RC/FS retained for future probes / docs
const MODE_STBY_RC: u8 = 0x1;
const MODE_STBY_XOSC: u8 = 0x2;
#[allow(dead_code)]
const MODE_FS: u8 = 0x3;

fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1" || v == "true").unwrap_or(false)
}

fn chip_mode(stat2: u8) -> u8 {
    (stat2 & 0x0F) >> 1
}

fn poll_for_status(
    chipset: &mut LR1121,
    mode_bits: u8,
    timeout: Duration,
) -> Option<u8> {
    let deadline = Instant::now() + timeout;
    let mut last = 0u8;
    while Instant::now() < deadline {
        let s = chipset.get_status().unwrap_or(0x00);
        last = s;
        if chip_mode(s) == mode_bits {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(last)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let no_sleep = env_flag("PROBE_NO_SLEEP");
    let tcxo = match std::env::var("PROBE_TCXO").as_deref() {
        Ok("none") => None,
        Ok("3.0") => Some(3.0),
        Ok("3.3") => Some(3.3),
        _ => Some(1.8),
    };
    let retries = std::env::var("PROBE_RETRIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2);

    let spi = SpiBus::open("/dev/spidev0.0", 4_000_000)?;
    let gpio = GpioPins::open(&LoRaConfig::new(
        "/dev/spidev0.0", 914_875_000, 250_000.0, 22, 8, 5,
    ))?;

    let mut config = LoRaConfig::new(
        "/dev/spidev0.0", 914_875_000, 250_000.0, 22, 8, 5,
    );
    config.tcxo_voltage = tcxo;
    config.tcxo_startup_delay = Duration::from_millis(320);
    config.dio_rf_switch = true;
    config.spi_speed = 4_000_000;
    config.command_delay = Duration::from_millis(2);
    config.rx_poll_interval = Duration::from_millis(50);

    let mut chipset = LR1121::new(Box::new(spi), gpio);
    if !no_sleep {
        let _ = chipset.probe_sleep();
    } else {
        log::info!("probe: PROBE_NO_SLEEP=1 — skipping probe_sleep");
    }
    log::info!(
        "probe: config tcxo_voltage = {:?}, tcxo_startup_delay = {:?}",
        tcxo,
        config.tcxo_startup_delay,
    );

    // PHASE 1: RAW SetStandby(XOSC) on the fresh chip with DIO3/TCXO
    // UNTOUCHED. On a crystal module this should reach STBY_XOSC;
    // on a TCXO module DIO3 is off so it must fail.
    log::info!("probe: PHASE 1 — raw SetStandby(XOSC), DIO3 untouched");
    chipset.set_standby_xosc()?;
    match poll_for_status(&mut chipset, MODE_STBY_XOSC, Duration::from_secs(5)) {
        Some(s) if chip_mode(s) == MODE_STBY_XOSC => {
            log::info!("probe: PHASE 1 OK — reached STBY_XOSC (stat2=0x{s:02X}) with no TCXO config -> module has a plain XTAL");
        }
        Some(s) => {
            log::info!(
                "probe: PHASE 1 — stuck at stat2=0x{s:02X} (mode={:X}, never STBY_XOSC); errors = 0x{:04X}",
                chip_mode(s),
                chipset.get_device_errors()?
            );
        }
        None => {}
    }

    // PHASE 2: retry XOSC for a slow/marginal TCXO (each retry 5s).
    for i in 0..retries {
        chipset.set_standby_xosc()?;
        match poll_for_status(&mut chipset, MODE_STBY_XOSC, Duration::from_secs(5)) {
            Some(s) if chip_mode(s) == MODE_STBY_XOSC => {
                log::info!("probe: PHASE 2 retry {i}: reached STBY_XOSC (stat2=0x{s:02X})");
                break;
            }
            Some(s) => {
                log::info!(
                    "probe: PHASE 2 retry {i}: stuck at stat2=0x{s:02X} (mode={:X}); errors = 0x{:04X}",
                    chip_mode(s),
                    chipset.get_device_errors()?
                );
            }
            None => {}
        }
    }

    // PHASE 3: full init, then XOSC, then unconditional TX attempt.
    log::info!(
        "probe: PHASE 3 — full init (tcxo={:?}, cold_start={})",
        tcxo,
        !env_flag("SKIP_COLD_START") && !env_flag("PROBE_NO_COLD_START")
    );
    chipset.init(&config)?;
    log::info!(
        "probe: init done, errors = 0x{:04X}",
        chipset.get_device_errors()?
    );
    chipset.set_standby_xosc()?;
    match poll_for_status(&mut chipset, MODE_STBY_XOSC, Duration::from_secs(5)) {
        Some(s) if chip_mode(s) == MODE_STBY_XOSC => {
            log::info!("probe: after init reached STBY_XOSC (stat2=0x{s:02X})");
        }
        Some(s) => {
            log::info!(
                "probe: after init stuck at stat2=0x{s:02X} (mode={:X}); errors = 0x{:04X}",
                chip_mode(s),
                chipset.get_device_errors()?
            );
        }
        None => {}
    }

    log::info!("probe: attempting TX (unconditional)...");
    match chipset.transmit(b"probe diagnostic packet") {
        Ok(()) => log::info!("probe: TX OK"),
        Err(e) => log::error!("probe: TX FAILED: {}", e),
    }

    Ok(())
}
