//! LR1121 firmware management tool.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use reticulum_sdk::iface::lora::lr1121::{BlVersion, LR1121};
use reticulum_sdk::iface::lora::{GpioPins, LoRaConfig, LoRaChipset, SpiBus};

// ── CLI ────────────────────────────────────────────────────────────────────

enum Subcommand {
    Version,
    Update(PathBuf),
    Help,
}

struct Args {
    subcommand: Subcommand,
    show_bl: bool,
    yes: bool,
    big_endian: bool,
    /// `Some(fw)` if `--expected-version` was passed; verified after the
    /// write. Format is the same 16-bit `fw` field from GetVersion:
    /// major in the high byte, minor in the low byte (e.g. `0x0101`
    /// for fw 1.1).
    expected_version: Option<u16>,
    spi_path: String,
    spi_speed: u32,
}

fn print_usage(program: &str) {
    eprintln!("LR1121 firmware management tool");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  {program}                                  show system firmware version");
    eprintln!("  {program} --bl                             also show bootloader version");
    eprintln!("  {program} update <firmware.bin|firmware.h>  flash a new firmware image");
    eprintln!("  {program} update <firmware.bin|firmware.h> -y");
    eprintln!("                                             flash without confirmation");
    eprintln!("  {program} --help                           show this message");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --bl                       also show bootloader version (the chip must be in");
    eprintln!("                             bootloader mode for this to differ from --no-bl;");
    eprintln!("                             the version print is otherwise identical)");
    eprintln!("  -y, --yes                  skip the confirmation prompt for update");
    eprintln!("  --big-endian               interpret a .bin firmware file as big-endian u32");
    eprintln!("                             words (default: little-endian). Ignored for .h files.");
    eprintln!("  --expected-version <hex>   verify the new version matches this 16-bit value");
    eprintln!("                             (e.g. 0x0101 for fw 1.1) after the write. Works for");
    eprintln!("                             either the system firmware (transceiver/modem image)");
    eprintln!("                             or the bootloader (bootloader-updater image) — the");
    eprintln!("                             tool auto-detects which by reading stat2.");
    eprintln!();
    eprintln!("FILE FORMAT:");
    eprintln!("  Detected by extension: '.h' is parsed as a C header (looks for");
    eprintln!("  `const uint32_t lr11xx_firmware_image[] = {{ 0x..., ... }};`); any");
    eprintln!("  other extension is treated as a raw .bin of little-endian u32 words.");
    eprintln!();
    eprintln!("  '.h' version is recommended as it omits the endian concerns.");
    eprintln!();
    eprintln!("Firmware Types:");
    eprintln!("  * Transceiver - Likely what you want. MCU fully controls the radio.");
    eprintln!("  * Modem - Not what you want. Modem-E is LoRaWAN built into the radio.");
    eprintln!("  * Loader - Bootloader. Generally node needed (and untested :-|)");
    eprintln!();
    eprintln!("ENV VARS:");
    eprintln!("  SPI_PATH     SPI device path (default /dev/spidev0.0)");
    eprintln!("  SPI_SPEED    SPI clock Hz (default 4000000)");
}

fn parse_args() -> Result<Args, String> {
    let mut subcommand = Subcommand::Version;
    let mut show_bl = false;
    let mut yes = false;
    let mut big_endian = false;
    let mut expected_version: Option<u16> = None;
    let args: Vec<String> = env::args().collect();

    let mut i = 1;
    while i < args.len() {
        let cur = args[i].clone();
        match cur.as_str() {
            "update" => {
                i += 1;
                if i >= args.len() {
                    return Err("update subcommand requires a firmware file path".into());
                }
                subcommand = Subcommand::Update(PathBuf::from(&args[i]));
            }
            "-h" | "--help" => subcommand = Subcommand::Help,
            "--bl" => show_bl = true,
            "-y" | "--yes" => yes = true,
            "--big-endian" => big_endian = true,
            "--expected-version" => {
                i += 1;
                if i >= args.len() {
                    return Err("--expected-version requires a hex argument (e.g. 0x0101)".into());
                }
                let v = args[i].trim_start_matches("0x").trim_start_matches("0X");
                expected_version = Some(u16::from_str_radix(v, 16)
                    .map_err(|e| format!("--expected-version: invalid hex '{}': {}", args[i], e))?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    let spi_path = env::var("SPI_PATH").unwrap_or_else(|_| "/dev/spidev0.0".into());
    let spi_speed = env::var("SPI_SPEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4_000_000);

    Ok(Args {
        subcommand,
        show_bl,
        yes,
        big_endian,
        expected_version,
        spi_path,
        spi_speed,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn chip_type_name(typ: u8) -> &'static str {
    match typ {
        0x00 => "LR1110",
        0x02 => "LR1120",
        0x03 => "LR1121",
        _ => "unknown",
    }
}

fn print_version(label: &str, v: BlVersion) {
    let fw_major = (v.fw >> 8) as u8;
    let fw_minor = (v.fw & 0xFF) as u8;
    let typ = v.typ;
    let hw = v.hw;
    let fw = v.fw;
    log::info!(
        "{label} firmware: chip type 0x{typ:02X} ({name}), hw 0x{hw:02X}, fw 0x{fw:04X} ({fw_major}.{fw_minor})",
        name = chip_type_name(typ)
    );
}

/// Decode the packed `u32` returned by `LR1121::get_chip_version()` into
/// the same `BlVersion` shape used by the bootloader command. GetVersion
/// (0x0101) returns 4 bytes `[hw, type, fw_major, fw_minor]` in both
/// system and bootloader mode, so the wire format is identical.
fn unpack_version(packed: u32) -> BlVersion {
    BlVersion {
        hw: (packed >> 24) as u8,
        typ: (packed >> 16) as u8,
        fw: ((packed >> 8) as u16) << 8 | (packed & 0xFF) as u16,
    }
}

/// Read a raw .bin firmware file as a `Vec<u32>` of words. The SWTL001
/// reference stores the words in the host's native byte order, so on
/// little-endian hosts (x86/ARM) the on-disk bytes are little-endian.
/// Parse a C header-style firmware image (e.g. `lr1121_transceiver_0104.h`).
///
/// Looks for a `const uint32_t lr11xx_firmware_image[] = { 0x..., 0x..., ... };`
/// declaration and returns the words as a `Vec<u32>`. Comments, blank
/// lines, line continuations, whitespace and commas between hex
/// constants are all tolerated. The order in the array is preserved
/// (matches the SPI order — each word is sent big-endian by
/// `bl_write_flash_encrypted_full`).
fn parse_firmware_header(text: &str) -> Result<Vec<u32>, String> {
    // Locate the array. Tolerate arbitrary whitespace between `const
    // uint32_t` and the name, and the usual C spacing around `=`.
    let needle = "lr11xx_firmware_image";
    let start = text
        .find(needle)
        .ok_or_else(|| format!("header parser: '{needle}' not found"))?;
    let after_name = &text[start + needle.len()..];
    let brace = after_name
        .find('{')
        .ok_or_else(|| format!("header parser: '{{' after '{needle}' not found"))?;
    let body = &after_name[brace + 1..];
    let end = body
        .find('}')
        .ok_or_else(|| format!("header parser: closing '}}' for '{needle}' not found"))?;
    let body = &body[..end];

    // Strip C-style block comments and line comments so a stray
    // `/* ... 0xDEADBEEF ... */` inside the array body can't be
    // mistaken for data.
    let stripped = strip_c_comments(body);

    // Tokenise. The body must contain only `0x...` hex constants
    // and C punctuation (whitespace, commas, semicolons). Anything
    // else — a stray identifier, a decimal literal, a missing `0x`
    // prefix — is a hard error: silently skipping it would let a
    // mangled header produce a too-short image and a confusing
    // bootloader write.
    let mut words = Vec::new();
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() || b == b',' || b == b';' {
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && b == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j == i + 2 {
                return Err(format!(
                    "header parser: '0x' at offset {i} not followed by hex digits"
                ));
            }
            let token = &stripped[i + 2..j];
            let word = u32::from_str_radix(token, 16).map_err(|e| {
                format!("header parser: invalid hex '0x{token}' at offset {i}: {e}")
            })?;
            words.push(word);
            i = j;
            continue;
        }
        // Surface the offending byte so the user can find the typo.
        let end = (i + 16).min(bytes.len());
        let snippet = &stripped[i..end];
        return Err(format!(
            "header parser: unexpected token at offset {i}: {:?} (expected '0x...', whitespace, comma, or ';')",
            snippet
        ));
    }

    if words.is_empty() {
        return Err("header parser: no 0x... constants found in array body".into());
    }
    Ok(words)
}

/// Remove C `/* ... */` and `// ... \n` comments from a string. The
/// result is a best-effort clean copy; we don't try to handle trigraphs
/// or line continuations.
fn strip_c_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // Block comment — skip to matching `*/`.
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Line comment — skip to end of line.
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Read a firmware image, dispatching on the file extension.
///
/// `.h` files are parsed as C headers (see `parse_firmware_header`);
/// everything else is treated as a raw `.bin` of little-endian u32
/// words (override with `--big-endian`).
fn read_firmware(path: &PathBuf, big_endian: bool) -> Result<Vec<u32>, String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());

    if ext.as_deref() == Some("h") {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        return parse_firmware_header(&text);
    }

    let data = fs::read(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    if data.is_empty() {
        return Err("firmware file is empty".into());
    }
    if data.len() % 4 != 0 {
        return Err(format!(
            "firmware size {} is not a multiple of 4 bytes (the file is a sequence of u32 words)",
            data.len()
        ));
    }
    Ok(data
        .chunks_exact(4)
        .map(|c| {
            if big_endian {
                u32::from_be_bytes([c[0], c[1], c[2], c[3]])
            } else {
                u32::from_le_bytes([c[0], c[1], c[2], c[3]])
            }
        })
        .collect())
}

fn open_chipset(args: &Args) -> Result<LR1121, Box<dyn std::error::Error>> {
    let spi = SpiBus::open(&args.spi_path, args.spi_speed)?;
    let config = LoRaConfig::new(&args.spi_path, 914_875_000, 250_000.0, 22, 8, 5);
    let gpio = GpioPins::open(&config)?;
    Ok(LR1121::new(spi, gpio))
}

fn confirm(prompt: &str) -> Result<bool, io::Error> {
    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}

// ── Subcommands ────────────────────────────────────────────────────────────

fn show_versions(chipset: &mut LR1121, also_bl: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Detect the chip's mode before printing any version. The LR11xx
    // returns GetVersion (0x0101) in both system and bootloader mode
    // and the response is the same shape, so without this check we'd
    // happily print the bootloader's version with a "system" label
    // whenever the chip is running in bootloader (corrupt firmware,
    // interrupted update, or power-cycle with the boot GPIO
    // asserted). stat2 bit 0 (`is_running_from_flash`) is 1 when the
    // application firmware is executing and 0 when the bootloader
    // is executing — the canonical "is the chip's system firmware
    // actually running" signal.
    let stat2 = chipset.get_status()?;
    let running_from_flash = (stat2 & 0x01) != 0;
    let mode_label = if running_from_flash { "system" } else { "bootloader" };

    if !running_from_flash {
        log::warn!(
            "chip is in BOOTLOADER mode (stat2=0x{stat2:02X}, is_running_from_flash=0). \
             This usually means the system firmware is missing or corrupt, \
             an update was interrupted, or the module was power-cycled \
             with the boot GPIO asserted. The version printed below is \
             the BOOTLOADER's, not the system's — pass --bl to also \
             explicitly read the bootloader version, or run `update` to \
             flash a new image."
        );
    }

    // The version is shared between system and bootloader modes
    // (GetVersion opcode 0x0101), so we can use the same call either
    // way. The label is what tells the user which one's version
    // they're actually looking at.
    let packed = chipset.get_chip_version()?;
    let v = unpack_version(packed);
    print_version(mode_label, v);

    let chip_mode = chipset.get_chip_mode().unwrap_or(0xFF);
    log::info!("chip mode = 0x{chip_mode:X} (STBY_RC=0x1, STBY_XOSC=0x2)");

    let err = chipset.get_device_errors().unwrap_or(0);
    let errs = LR1121::decode_device_errors(err);
    log::info!(
        "device errors = 0x{err:04X} [{}]",
        if errs.is_empty() { "none".to_string() } else { errs.join(", ") }
    );

    if also_bl {
        // If the chip is already in bootloader mode (we detected
        // this above), the bl_reboot(true) round-trip would be a
        // no-op and we'd just print the same version twice. Skip
        // the dance in that case.
        if !running_from_flash {
            log::info!("chip is already in bootloader mode — skipping bl_reboot round-trip");
        } else {
            log::info!("rebooting into bootloader to read its version...");
            chipset.bl_reboot(true)?;
            std::thread::sleep(Duration::from_millis(500));
            let bl_v = chipset.bl_get_version()?;
            print_version("bootloader", bl_v);
            log::info!("rebooting back to system firmware...");
            chipset.bl_reboot(false)?;
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    Ok(())
}

fn update_firmware(
    chipset: &mut LR1121,
    path: &PathBuf,
    yes: bool,
    big_endian: bool,
    expected_version: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read and parse the firmware file
    let words = read_firmware(path, big_endian)?;
    let total_bytes = words.len() * 4;
    log::info!(
        "firmware file: {} ({} bytes = {} u32 words)",
        path.display(),
        total_bytes,
        words.len(),
    );

    // 2. Move the chip into bootloader mode via the system Reboot
    //    command (0x0118). The bootloader's own Reboot (0x8005) only
    //    works when the chip is already in bootloader mode, so the
    //    system-mode command is the one that actually transitions the
    //    chip. If the chip is already in bootloader mode (e.g. the
    //    user power-cycled with the boot GPIO asserted) the system
    //    firmware isn't running and the smart `reboot` helper will
    //    issue the bootloader's own Reboot (0x8005) instead — a
    //    no-op round-trip that keeps the chip in bootloader, which
    //    is what we want.
    log::info!("entering bootloader mode (reboot stay=0x03, auto-detecting opcode)...");
    let _ = chipset.reboot(true); // tolerated: may be a no-op if already in bootloader
    std::thread::sleep(Duration::from_millis(500));

    // 3. Verify we are actually in bootloader mode by issuing a
    //    bootloader-only read (GetHash 0x8004) and checking the
    //    response. If we are still in system mode the chip rejects
    //    the command and the response is garbage; we bail out.
    log::info!("probing for bootloader mode...");
    if !chipset.bl_is_in_bootloader() {
        return Err(
            "chip is not in bootloader mode after system_reboot(true). \
             The system firmware is presumably missing or corrupt. \
             Power-cycle the module with the boot GPIO asserted \
             (typically labelled BOOT or FORCE_BL on the module) to \
             force the chip into the bootloader and re-run this tool."
                .into(),
        );
    }
    log::info!("chip is in bootloader mode");

    // 4. Confirm with the user
    if !yes {
        eprintln!();
        eprintln!("About to ERASE the chip's flash and write {} bytes.", total_bytes);
        eprintln!("This is IRREVERSIBLE.");
        if !confirm("Continue?")? {
            log::info!("aborted by user");
            return Ok(());
        }
    }

    // 5. Stay-in-bootloader (no-op if already there; harmless to
    //    call). The `reboot` helper auto-detects the mode and issues
    //    the appropriate opcode; we expect to be in bootloader mode
    //    by this point (verified by step 3).
    log::info!("[1/5] requesting stay-in-bootloader...");
    chipset.reboot(true)?;
    std::thread::sleep(Duration::from_millis(500));

    // 6. Sanity-check: read the bootloader version we're about to use.
    log::info!("[2/5] reading bootloader version...");
    let bl_v = chipset.bl_get_version()?;
    print_version("bootloader", bl_v);

    // 7. Erase flash
    log::info!("[3/5] erasing flash (may take a few seconds)...");
    let t0 = Instant::now();
    chipset.bl_erase_flash()?;
    log::info!("flash erased in {:?}", t0.elapsed());

    // 8. Write the image in 64-word chunks.
    //
    // The base address is always 0. The LR11xx's bootloader lives in
    // mask ROM, so its single user-writable flash region starts at
    // offset 0 and is where every firmware image (transceiver, modem,
    // bootloader-updater) is written. There is no separate
    // "transceiver at 0x10000, modem at 0x20000, bootloader at 0x0"
    // layout. This matches the SWTL001 reference, which also passes
    // `0` to `lr11xx_bootloader_write_flash_encrypted_full`. The
    // `bl_write_flash_encrypted_full` primitive still accepts an
    // offset, so this can be made configurable later if a custom
    // layout ever needs it.
    log::info!("[4/5] writing {} u32 words in 64-word chunks...", words.len());
    let t0 = Instant::now();
    chipset.bl_write_flash_encrypted_full(0, &words)?;
    log::info!("write complete in {:?}", t0.elapsed());

    // 9. Reboot to let the new image take over.
    //
    // For a transceiver/modem image the chip runs the application
    // from system mode. For a bootloader-updater image the updater
    // runs once, replaces the bootloader, and the new bootloader
    // refuses to execute the updater image — the chip ends up back
    // in bootloader mode with the new bootloader. We don't know
    // which path we'll land on; that's what the post-write
    // auto-detect (step 10) figures out.
    log::info!("[5/5] rebooting...");
    chipset.reboot(false)?;
    std::thread::sleep(Duration::from_millis(500));

    // 10. Auto-detect which mode the chip is now in, then read the
    //     version that matches. stat2 bit 0 (`is_running_from_flash`)
    //     is 1 when the application firmware is executing (system
    //     mode) and 0 when the bootloader is executing. The LR11xx
    //     doesn't store "this is a modem" or "this is a transceiver"
    //     anywhere; it just knows the version of whatever is
    //     running, so we read whichever one is appropriate.
    let stat2 = chipset.get_status()?;
    let in_system_mode = (stat2 & 0x01) != 0;
    let label = if in_system_mode { "system" } else { "bootloader" };
    log::info!("auto-detect: chip is in {label} mode (stat2=0x{stat2:02X})");
    let new_v = if in_system_mode {
        let packed = chipset.get_chip_version()?;
        unpack_version(packed)
    } else {
        chipset.bl_get_version()?
    };
    log::info!("verifying new {label} firmware version:");
    print_version(label, new_v);

    // 11. Optionally compare against an expected version.
    if let Some(expected) = expected_version {
        if new_v.fw != expected {
            return Err(format!(
                "{label} firmware version mismatch: chip reports fw 0x{:04X} ({}.{}), \
                 expected 0x{:04X} ({}.{})",
                new_v.fw, new_v.fw >> 8, new_v.fw & 0xFF,
                expected, expected >> 8, expected & 0xFF,
            )
            .into());
        }
        log::info!(
            "OK: {label} firmware version matches expected 0x{expected:04X} ({}.{})",
            expected >> 8, expected & 0xFF,
        );
    }

    Ok(())
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!();
            print_usage("lr1121_firmware");
            return ExitCode::FAILURE;
        }
    };

    if matches!(args.subcommand, Subcommand::Help) {
        print_usage("lr1121_firmware");
        return ExitCode::SUCCESS;
    }

    let mut chipset = match open_chipset(&args) {
        Ok(c) => c,
        Err(e) => {
            log::error!("failed to open chipset: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = match args.subcommand {
        Subcommand::Version => show_versions(&mut chipset, args.show_bl),
        Subcommand::Update(path) => update_firmware(
            &mut chipset,
            &path,
            args.yes,
            args.big_endian,
            args.expected_version,
        ),
        Subcommand::Help => Ok(()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the header parser against a representative chunk of
    /// the Semtech reference file
    /// `lr1121_transceiver_0104.h`. The fixture is small enough to
    /// keep the test fast but covers the interesting cases: `const
    /// uint32_t` qualifier, whitespace, multi-line layout, comma
    /// separators, hex literals in upper and lower case, and a
    /// trailing semicolon.
    #[test]
    fn parses_lr11xx_firmware_image_header() {
        let fixture = "\
/*
 * LR11XX firmware image fixture
 */
#include <stdint.h>

#define LR11XX_FIRMWARE_VERSION 0x0104
#define LR11XX_FIRMWARE_UPDATE_TO LR1121_FIRMWARE_UPDATE_TO_TRX

const uint32_t lr11xx_firmware_image[] = {
    0x3c148020, 0xd90ba20f, 0x6e936da0, 0xdd0b1975, 0xce1b921e, 0x33a7059e, 0xd89aa873, 0x443e7f41,
    0x68255071, 0xe6cb6b6c, 0xf2cf37af, 0x29719005, 0x4004e56c, 0xa05d1a42, 0x467a3d86, 0x85e589c7,
    0xAABBCCDD, 0x00112233,
};
";
        let words = parse_firmware_header(fixture).expect("header parser should accept the fixture");
        assert_eq!(words.len(), 18);
        assert_eq!(words[0], 0x3c148020);
        assert_eq!(words[15], 0x85e589c7);
        // Mixed case literal
        assert_eq!(words[16], 0xAABBCCDD);
        assert_eq!(words[17], 0x00112233);
    }

    #[test]
    fn header_parser_rejects_garbage() {
        let bad = "const uint32_t lr11xx_firmware_image[] = { not_a_number, 0x1 };";
        assert!(parse_firmware_header(bad).is_err());
    }

    #[test]
    fn header_parser_rejects_missing_array() {
        let bad = "// no array here\nconst uint32_t something_else[] = { 0x1 };";
        assert!(parse_firmware_header(bad).is_err());
    }

    /// End-to-end check against the actual Semtech
    /// `lr1121_transceiver_0104.h` from
    /// https://raw.githubusercontent.com/Lora-net/radio_firmware_images.
    /// Ignored by default so the test only runs when the file has
    /// been fetched locally; run it with:
    ///
    /// ```text
    /// curl -sSL https://raw.githubusercontent.com/Lora-net/radio_firmware_images/refs/heads/master/lr1121/transceiver/lr1121_transceiver_0104.h -o /tmp/lr1121_transceiver_0104.h
    /// cargo test --example lr1121_firmware -- --ignored parses_real_semtech_header
    /// ```
    #[test]
    #[ignore = "requires /tmp/lr1121_transceiver_0104.h to be present locally"]
    fn parses_real_semtech_header() {
        let path = PathBuf::from("/tmp/lr1121_transceiver_0104.h");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let words = parse_firmware_header(&text)
            .unwrap_or_else(|e| panic!("parser rejected real Semtech header: {e}"));
        // The real LR1121 transceiver image is ~250 KB of u32 words.
        // Lower bound catches a "parsed nothing" bug; upper bound
        // catches a runaway that picked up a second array.
        assert!(
            words.len() > 10_000,
            "only parsed {} words — parser probably missed the array body",
            words.len()
        );
        assert!(
            words.len() < 1_000_000,
            "parsed {} words — suspiciously large",
            words.len()
        );
        // Sanity: every word should look like a 32-bit instruction or
        // literal, not the output of a hash that mostly contains 0
        // or 0xFFFF. We allow a small fraction of 0xFFFF because
        // ARM literal pools do use it.
        let ffff = words.iter().filter(|&&w| w == 0xFFFF_FFFF).count();
        assert!(
            ffff * 10 < words.len(),
            "{}/{} words are 0xFFFFFFFF — likely misaligned parse",
            ffff,
            words.len()
        );
        eprintln!("parsed {} u32 words from {}", words.len(), path.display());
    }
}
