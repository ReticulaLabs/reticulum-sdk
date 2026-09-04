# Reticulum SDK

An SDK of the Reticulum protocol in Rust.

## What is Reticulum?

A cryptography-based networking stack designed for building local and wide-area networks using
readily available hardware, allowing for secure communication without relying on traditional networking protocols.

Reticulum operates independently of traditional IP, and can function effectively in low-bandwidth environments.

## Implemented protocol features

* ✅ experimental TCP RPC control port (aka share_instance)
* ✅ rnstransport path.request
* ✅ rnstransport probe (aka respond_to_probes)
* ✅ rnstransport discovery (aka discoverable)
* ❌ rnstransport remote.management (aka enable_remote_management)
* ✅ info blackhole (aka publish_blackhole) — core table + expiry + announce rejection + RPC stub

## Implemented interfaces

> Physical communication interfaces implemented

### IP Network (LAN, WAN)

* ❌ AutoInterface
* ✅ BackboneInterface
* ❌ I2PInterface
* ✅ TCPClientInterface
* ✅ TCPServerInterface (bind_host ::1 will allow dual-stack functionality)
* ✅ UDPInterface

### Radio (HAM, LoRA)

* ❌ AX25KISSInterface
* ✅ [Modem73Interface](https://github.com/RFnexus/modem73)
* ✅ [RNodeInterface](https://unsigned.io/rnode/) (over Serial)
* ❌ RNodeMultiInterface
* ✅ KISSInterface
* ✅ LoRaInterface (Experimental, direct SPI communication to LoRA chipsets. SX126X, LR1121)

### Other

* ❌ BluetoothInterface
* ❌ PipeInterface
* ✅ SerialInterface

## Usage

### Compiling

```
cargo build
```

### Running Unit Tests

```
cargo test
```

### Using it in Rust

Cargo.toml
```toml
[dependencies]
reticulum-sdk = "2.3"
```

## Crate features

The crate is designed to function on resource-constrained (embedded) targets, so most
behavioral tuning and optional hardware backends are feature-gated. The default
features enable the full host build; adjust them for your target.

> Standard, full size desktop and server targets can use the default features for optimum performance.

| Feature | Default | Description |
|---|---|---|
| `alloc` | yes | Pulls in the `alloc` crate. Always safe to keep enabled on hosted targets. |
| `serial` | yes | Serial port interfaces (`SerialInterface`, `KISSInterface`, `RNodeInterface`) via `tokio-serial`. Disable for builds that only need network interfaces (UDP/TCP/backbone). |
| `lora` | yes | LoRa interface with an SPI/GPIO backend based on `embedded-hal`, usable on microcontrollers for SX126x / SX127x / LR1121 chipsets. |
| `lora-linux` | yes | Linux backends for the LoRa interface (spidev ioctls + `gpio-cdev` GPIO). Implies `lora`. Linux-only; leave off for embedded builds. |
| `embedded` | no | Tuned for resource-constrained targets (e.g. ESP32, ESP32-S3): shorter packet / destination / path retention and smaller cache bounds so transport state stays bounded within a few hundred KB of RAM on a busy network. Without it, the transport keeps the upstream (desktop) retention defaults. |
| `fernet-aes128` | no | Use 256-bit derived keys (AES-128) for identity encryption instead of the default 512-bit derived keys. Enables interop with Reticulum versions that use AES-128. |

### Examples

Embedded build with only network interfaces (no serial/LoRa):

```
cargo build --no-default-features --features alloc,embedded
```

Full desktop build (default):

```
cargo build
```

## Python Protocol Deviations

* The 2% announcement cap implemented in the official Python implementation can quickly begin
  to backlog and drop announcements from being sent over low-bitrate networks such as LoRA.
  (~27 announces per minute max on a reasonable 250kHz/SF8 encoding)
  * This implementation of Reticulum improves this design choice by allowing 6% of the interface
    to be used for announcements, and scaling down the announcement cap when interface load
    increases. (~81/min when quiet, ~27/min when channel under load)
  * The probability of infinite growth of announcement backlogs is reduced.

## Implementations

* Used by the [Rust reticulum-router daemon](https://github.com/ReticulaLabs/reticulum-router)

## License

Released under the terms of the MIT license
