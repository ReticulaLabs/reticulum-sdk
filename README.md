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
reticulum-sdk = "2.1"
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
