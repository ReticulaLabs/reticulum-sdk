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
* ❌ info blackhole (aka publish_blackhole)

## Implemented interfaces

> Physical communication interfaces implemented

### IP Network (LAN, WAN)

* ❌ AutoInterface
* ❌ BackboneInterface (Use TCPServerInterface instead for now)
* ❌ I2PInterface
* ✅ TCPClientInterface
* ✅ TCPServerInterface (bind_host ::1 will allow dual-stack functionality)
* ✅ UDPInterface

### Radio (HAM, LoRA)

* ❌ AX25KISSInterface
* ✅ [Modem73Interface](https://github.com/RFnexus/modem73)
* ✅ [RNodeInterface](https://unsigned.io/rnode/) (over Serial)
* ❌ RNodeMultiInterface
* ❌ KISSInterface

### Other

* ❌ BluetoothInterface
* ❌ PipeInterface
* ❌ SerialInterface

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
reticulum-sdk = "2.0"
```

## Implementations

* Used by the [Rust reticulum-router daemon](https://github.com/GhostMeshLabs/reticulum-router)

## License

Released under the terms of the MIT license
