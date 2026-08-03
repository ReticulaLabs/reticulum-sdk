use std::time::{Duration, Instant};

use reticulum_sdk::iface::lora::{GpioPins, LoRaConfig, SpiBus};

fn dump(spi: &mut SpiBus, tx: &[u8], rx_len: usize) -> Vec<u8> {
    let mut txb = tx.to_vec();
    txb.resize(rx_len, 0x00);
    let mut rx = vec![0u8; rx_len];
    spi.xfer(&txb, &mut rx).unwrap();
    rx
}

fn cmd(spi: &mut SpiBus, tx: &[u8]) -> (u8, u8) {
    let rx = dump(spi, tx, tx.len());
    (rx[0], rx[1])
}

fn mode_of(stat2: u8) -> u8 {
    (stat2 & 0x0F) >> 1
}

fn poll_mode(spi: &mut SpiBus, secs: u64) -> u8 {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut m = 0;
    while Instant::now() < deadline {
        let rx = dump(spi, &[], 6);
        m = mode_of(rx[1]);
        if m == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    m
}

fn errors(spi: &mut SpiBus) -> u16 {
    dump(spi, &[0x01, 0x0D], 2);
    std::thread::sleep(Duration::from_millis(100));
    let rx = dump(spi, &[], 8);
    ((rx[1] as u16) << 8) | rx[2] as u16
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut spi = SpiBus::open("/dev/spidev0.0", 4_000_000)?;
    let _gpio = GpioPins::open(&LoRaConfig::new(
        "/dev/spidev0.0", 914_875_000, 250_000.0, 22, 8, 5,
    ))?;

    println!("--- proper cold sleep + wake (SetSleep = 6 bytes) ---");
    let (s1, s2) = cmd(&mut spi, &[0x01, 0x1B, 0x00, 0x00, 0x00, 0x00]);
    println!("SetSleep: stat1=0x{s1:02X} stat2=0x{s2:02X} (expect R_ERR-ish if busy, sleep may abort tx)");
    std::thread::sleep(Duration::from_millis(300));
    dump(&mut spi, &[0x00], 1); // wake: NSS low
    std::thread::sleep(Duration::from_millis(300)); // POR to STBY_RC ~237ms
    let (s1, s2) = cmd(&mut spi, &[0x01, 0x1C, 0x00]);
    println!("SetStandby RC: stat1=0x{s1:02X} stat2=0x{s2:02X} mode={}", mode_of(s2));
    std::thread::sleep(Duration::from_millis(50));
    let (s1, s2) = cmd(&mut spi, &[0x01, 0x0E]);
    println!("ClearErrors:   stat1=0x{s1:02X} stat2=0x{s2:02X} mode={}", mode_of(s2));
    std::thread::sleep(Duration::from_millis(50));

    let (s1, s2) = cmd(&mut spi, &[0x01, 0x17, 0x06, 0x01, 0x00, 0x00]);
    println!("SetTcxoMode:   stat1=0x{s1:02X} stat2=0x{s2:02X} mode={} (3.0V, 2s timeout)", mode_of(s2));
    std::thread::sleep(Duration::from_millis(50));

    let (s1, s2) = cmd(&mut spi, &[0x01, 0x1C, 0x01]);
    println!("SetStandby XOSC: stat1=0x{s1:02X} stat2=0x{s2:02X} mode={}", mode_of(s2));
    let m = poll_mode(&mut spi, 6);
    println!("polled mode after SetStandby XOSC = {m} (2 = STBY_XOSC)");
    println!("errors = 0x{:04X}", errors(&mut spi));

    Ok(())
}
