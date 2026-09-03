use std::time::{Duration, Instant};

use reticulum_sdk::iface::lora::sx1262::SX1262;
use reticulum_sdk::iface::lora::{GpioPins, LoRaConfig, LoRaChipset, SpiBus};

fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1" || v == "true").unwrap_or(false)
}

fn poll_for_status(
    chipset: &mut SX1262,
    mode_bits: u8,
    timeout: Duration,
) -> Option<u8> {
    let deadline = Instant::now() + timeout;
    let mut last = 0u8;
    while Instant::now() < deadline {
        let s = chipset.get_status().unwrap_or(0x00);
        last = s;
        if (s >> 4) & 0x07 == mode_bits {
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

    let mut chipset = SX1262::new(Box::new(spi), gpio);
    chipset.check_por_canary()?;
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
    // UNTOUCHED. On a crystal module this should reach STBY_XOSC (0x32);
    // on a TCXO module DIO3 is off so it must fail.
    log::info!("probe: PHASE 1 — raw SetStandby(XOSC), DIO3 untouched");
    chipset.set_standby_xosc()?;
    match poll_for_status(&mut chipset, 0x3, Duration::from_secs(5)) {
        Some(s) if (s >> 4) & 0x07 == 0x3 => {
            log::info!("probe: PHASE 1 OK — reached STBY_XOSC (0x{s:02X}) with no TCXO config -> module has a plain XTAL");
        }
        Some(s) => {
            log::info!(
                "probe: PHASE 1 — stuck at status 0x{s:02X} (never STBY_XOSC); errors = 0x{:04X}",
                chipset.get_device_errors()?
            );
        }
        None => {}
    }

    // PHASE 2: retry XOSC for a slow/marginal TCXO (each retry 5s).
    for i in 0..retries {
        chipset.set_standby_xosc()?;
        match poll_for_status(&mut chipset, 0x3, Duration::from_secs(5)) {
            Some(s) if (s >> 4) & 0x07 == 0x3 => {
                log::info!("probe: PHASE 2 retry {i}: reached STBY_XOSC (0x{s:02X})");
                break;
            }
            Some(s) => {
                log::info!(
                    "probe: PHASE 2 retry {i}: stuck at 0x{s:02X}; errors = 0x{:04X}",
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
    match poll_for_status(&mut chipset, 0x3, Duration::from_secs(5)) {
        Some(s) if (s >> 4) & 0x07 == 0x3 => {
            log::info!("probe: after init reached STBY_XOSC (0x{s:02X})");
        }
        Some(s) => {
            log::info!(
                "probe: after init stuck at 0x{s:02X}; errors = 0x{:04X}",
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

    // Arm the canary so the NEXT run can verify whether a power cycle
    // actually reset the chip's RAM.
    chipset.set_por_canary()?;
    log::info!("probe: POR canary armed (0x0740 = 0xAB24)");

    Ok(())
}
