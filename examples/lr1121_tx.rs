use std::time::Duration;

use reticulum_sdk::iface::lora::lr1121::LR1121;
use reticulum_sdk::iface::lora::{GpioPins, LoRaConfig, LoRaChipset, SpiBus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let spi = SpiBus::open("/dev/spidev0.0", 4_000_000)?;
    let gpio = GpioPins::open(&LoRaConfig::new(
        "/dev/spidev0.0", 914_875_000, 250_000.0, 22, 8, 5,
    ))?;

    let mut config = LoRaConfig::new(
        "/dev/spidev0.0",
        914_875_000,
        250_000.0,
        22,
        8,
        5,
    );
    config.tcxo_voltage = Some(3.0);
    config.dio_rf_switch = true;
    config.spi_speed = 4_000_000;
    config.command_delay = Duration::from_millis(2);
    config.rx_poll_interval = Duration::from_millis(50);

    let mut chipset = LR1121::new(spi, gpio);
    chipset.init(&config)?;
    log::info!("init OK, transmitting...");

    for i in 0..5u32 {
        let payload = format!("lr1121 tx test packet {}", i);
        log::info!("transmitting: {:?}", payload);
        match chipset.transmit(payload.as_bytes()) {
            Ok(()) => log::info!("TX {}: OK (TX_DONE seen)", i),
            Err(e) => log::error!("TX {}: FAILED: {}", i, e),
        }
        log::info!(
            "probe: device errors after TX attempt {} = 0x{:04X}",
            i,
            chipset.get_device_errors()?
        );
        chipset.clear_device_errors()?;
        std::thread::sleep(Duration::from_millis(500));
    }

    log::info!("rssi: {:.1} dBm", chipset.current_rssi()?);
    Ok(())
}
