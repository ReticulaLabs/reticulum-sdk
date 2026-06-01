# Reticulum SDK

An SDK of the Reticulum protocol in Rust.

## What is Reticulum?

A cryptography-based networking stack designed for building local and wide-area networks using
readily available hardware, allowing for secure communication without relying on traditional networking protocols.

Reticulum operates independently of traditional IP, and can function effectively in low-bandwidth environments.

## Implemented protocol features

> Features implemented from the core Reticulum Protocol

* ✅ rnstransport path.request
* ✅ rnstransport probe (aka respond_to_probes)
* ✅ rnstransport discovery (aka discoverable)
* ❌ rnstransport remote.management (aka enable_remote_management)
* ❌ info blackhole (aka publish_blackhole)

## Implemented interfaces

> Physical communication interfaces implemented

* ✅ TCPServerInterface
* ✅ TCPClientInterface
* ✅ UDPInterface
* ❌ AutoInterface
* ❌ BackboneInterface
* ❌ I2PInterface
* ❌ RNodeMultiInterface
* ❌ RNodeInterface
* ❌ SerialInterface
* ❌ PipeInterface
* ✅ KISSInterface
* ❌ AX25KISSInterface

## Usage

### Compiling

```
cargo build
```

### Running Unit Tests

```
cargo test
```

## Implementations

* Used by the [Rust reticulum-router daemon](https://github.com/GhostMeshLabs/reticulum-router)

## License

Released under the terms of the MIT license
