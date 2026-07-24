#!/usr/bin/env python3
"""
Export deterministic Reticulum wire-format vectors from the Python reference implementation.

Usage:
  python3 tools/export_python_vectors.py
  python3 tools/export_python_vectors.py --reticulum-path /path/to/Reticulum
  python3 tools/export_python_vectors.py --output vectors/python_vectors.json

The script imports the Python `RNS` package, drives packet construction through the
reference implementation, and writes JSON fixtures that can be consumed by Rust tests.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import pathlib
import sys
import time
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional


FIXED_DESTINATION_IDENTITY_HEX = (
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c"
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c"
)
FIXED_LINK_OWNER_IDENTITY_HEX = (
    "6d55d63ed7cf4c3f7f4206cbf4a1c0d1a5fbcc3121d296f6a4f54c0f7f3f868b"
    "8f3e3c498d8bd4c6025f3bb3edb34f7e18dfec53ca6f6d1e1c6db16a6b7cf1c1"
)

FIXED_ANNOUNCE_TIME = 1717171717
FIXED_ANNOUNCE_RNG_BYTES = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
FIXED_ANNOUNCE_RANDOM_HASH = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIXED_FORWARDED_TRANSPORT_ID = bytes.fromhex("aabbccddeeff00112233445566778899")

FIXED_PATH_REQUEST_DESTINATION = bytes.fromhex("00112233445566778899aabbccddeeff")
FIXED_PATH_REQUEST_TRANSPORT = bytes.fromhex("ffeeddccbbaa99887766554433221100")
FIXED_PATH_REQUEST_TAG = b"fixed-tag"

FIXED_LRPROOF_LINK_ID = bytes.fromhex("1032547698badcfe0123456789abcdef")
FIXED_LRPROOF_LINK_X25519_PRIVATE = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f10"
    "1112131415161718191a1b1c1d1e1f20"
)
FIXED_LRPROOF_LINK_ED25519_PRIVATE = bytes.fromhex(
    "2122232425262728292a2b2c2d2e2f30"
    "3132333435363738393a3b3c3d3e3f40"
)

FIXED_EXPLICIT_PROOF_HASH_INPUT = b"probe packet"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export deterministic packet vectors from the Python Reticulum reference."
    )
    parser.add_argument(
        "--reticulum-path",
        type=pathlib.Path,
        help="Path to a local Reticulum checkout containing the RNS package.",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        help="Write JSON output to this file instead of stdout.",
    )
    return parser.parse_args()


def load_rns_module(reticulum_path: Optional[pathlib.Path]):
    if reticulum_path is not None:
        sys.path.insert(0, str(reticulum_path.resolve()))

    try:
        import RNS  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "Could not import Python Reticulum reference implementation as `RNS`."
        ) from exc

    return RNS


@contextlib.contextmanager
def deterministic_announce_inputs(RNS):
    original_time = time.time
    original_random_hash = RNS.Identity.get_random_hash

    time.time = lambda: FIXED_ANNOUNCE_TIME
    RNS.Identity.get_random_hash = staticmethod(lambda: FIXED_ANNOUNCE_RANDOM_HASH)
    try:
        yield
    finally:
        time.time = original_time
        RNS.Identity.get_random_hash = original_random_hash


@contextlib.contextmanager
def capture_sent_packets(RNS):
    original_send = RNS.Packet.send
    packets = []

    def fake_send(packet):
        if not packet.packed:
            packet.pack()
        packet.sent = True
        packets.append(packet)
        return packet

    RNS.Packet.send = fake_send
    try:
        yield packets
    finally:
        RNS.Packet.send = original_send


@contextlib.contextmanager
def offline_transport_state(RNS):
    original_owner = getattr(RNS.Transport, "owner", None)
    had_owner = hasattr(RNS.Transport, "owner")
    original_register_destination = RNS.Transport.register_destination

    def register_destination_stub(_destination):
        return None

    if not had_owner:
        RNS.Transport.owner = SimpleNamespace(rpc_connected=False)
    elif original_owner is None:
        RNS.Transport.owner = SimpleNamespace(rpc_connected=False)

    RNS.Transport.register_destination = register_destination_stub
    try:
        yield
    finally:
        RNS.Transport.register_destination = original_register_destination
        if had_owner:
            RNS.Transport.owner = original_owner
        else:
            delattr(RNS.Transport, "owner")


def packet_type_name(RNS, packet_type: int) -> str:
    names = {
        RNS.Packet.DATA: "Data",
        RNS.Packet.ANNOUNCE: "Announce",
        RNS.Packet.LINKREQUEST: "LinkRequest",
        RNS.Packet.PROOF: "Proof",
    }
    return names.get(packet_type, f"Unknown({packet_type})")


def header_type_name(RNS, header_type: int) -> str:
    names = {
        RNS.Packet.HEADER_1: "Type1",
        RNS.Packet.HEADER_2: "Type2",
    }
    return names.get(header_type, f"Unknown({header_type})")


def transport_type_name(RNS, transport_type: int) -> str:
    names = {
        RNS.Transport.BROADCAST: "Broadcast",
        RNS.Transport.TRANSPORT: "Transport",
        getattr(RNS.Transport, "RELAY", 0x02): "Relay",
        getattr(RNS.Transport, "TUNNEL", 0x03): "Tunnel",
    }
    return names.get(transport_type, f"Unknown({transport_type})")


def destination_type_name(RNS, destination_type: int) -> str:
    names = {
        RNS.Destination.SINGLE: "Single",
        RNS.Destination.GROUP: "Group",
        RNS.Destination.PLAIN: "Plain",
        RNS.Destination.LINK: "Link",
    }
    return names.get(destination_type, f"Unknown({destination_type})")


def context_name(RNS, context: int) -> str:
    names = {
        RNS.Packet.NONE: "None",
        getattr(RNS.Packet, "PATH_RESPONSE", 0x0B): "PathResponse",
        getattr(RNS.Packet, "LRPROOF", 0xFF): "LinkRequestProof",
    }
    return names.get(context, f"Unknown({context})")


def packet_record(RNS, name: str, packet) -> Dict[str, Any]:
    if not packet.packed:
        packet.pack()

    destination_hash = getattr(packet, "destination_hash", None)
    destination_hex = destination_hash.hex() if destination_hash is not None else None
    transport_id = getattr(packet, "transport_id", None)
    if packet.context == getattr(RNS.Packet, "LRPROOF", 0xFF):
        destination_type = RNS.Destination.LINK
    else:
        destination_type = getattr(packet, "destination_type", packet.destination.type)

    return {
        "name": name,
        "raw_hex": packet.raw.hex(),
        "flags_hex": f"{packet.raw[0]:02x}",
        "hops": packet.hops,
        "header_type": header_type_name(RNS, packet.header_type),
        "transport_type": transport_type_name(RNS, packet.transport_type),
        "destination_type": destination_type_name(RNS, destination_type),
        "packet_type": packet_type_name(RNS, packet.packet_type),
        "context": context_name(RNS, packet.context),
        "context_flag": packet.context_flag,
        "destination_hash_hex": destination_hex,
        "transport_id_hex": None if transport_id is None else transport_id.hex(),
        "data_hex": packet.data.hex(),
    }


def make_fixed_identity(RNS, identity_hex: str):
    return RNS.Identity.from_bytes(bytes.fromhex(identity_hex))


class ProofDestination:
    def __init__(self, packet_hash: bytes, destination_type: int):
        self.hash = packet_hash[: len(packet_hash) // 2]
        self.type = destination_type

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext


def build_destination_vectors(RNS) -> List[Dict[str, Any]]:
    identity = make_fixed_identity(RNS, FIXED_DESTINATION_IDENTITY_HEX)
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "example_utilities",
        "announcesample",
        "fruits",
    )

    with deterministic_announce_inputs(RNS):
        announce = destination.announce(send=False)
        path_response = destination.announce(path_response=True, send=False)

    with deterministic_announce_inputs(RNS):
        forwarded = destination.announce(send=False)
    forwarded.header_type = RNS.Packet.HEADER_2
    forwarded.transport_type = RNS.Transport.TRANSPORT
    forwarded.transport_id = FIXED_FORWARDED_TRANSPORT_ID
    forwarded.hops = 1
    forwarded.flags = forwarded.get_packed_flags()

    packet_hash = RNS.Identity.full_hash(FIXED_EXPLICIT_PROOF_HASH_INPUT)
    signature = identity.sign(packet_hash)
    explicit_proof_destination = ProofDestination(packet_hash, RNS.Destination.SINGLE)
    explicit_proof = RNS.Packet(
        explicit_proof_destination,
        packet_hash + signature,
        packet_type=RNS.Packet.PROOF,
        create_receipt=False,
    )

    return [
        packet_record(RNS, "announce", announce),
        packet_record(RNS, "path_response", path_response),
        packet_record(RNS, "forwarded_announce", forwarded),
        packet_record(RNS, "explicit_packet_proof", explicit_proof),
    ]


def build_path_request_vectors(RNS) -> List[Dict[str, Any]]:
    path_request_destination = RNS.Destination(
        None,
        RNS.Destination.IN,
        RNS.Destination.PLAIN,
        "rnstransport",
        "path",
        "request",
    )

    without_transport_payload = FIXED_PATH_REQUEST_DESTINATION + FIXED_PATH_REQUEST_TAG
    with_transport_payload = (
        FIXED_PATH_REQUEST_DESTINATION
        + FIXED_PATH_REQUEST_TRANSPORT
        + FIXED_PATH_REQUEST_TAG
    )

    without_transport = RNS.Packet(
        path_request_destination,
        without_transport_payload,
        packet_type=RNS.Packet.DATA,
        transport_type=RNS.Transport.BROADCAST,
        header_type=RNS.Packet.HEADER_1,
        create_receipt=False,
    )
    with_transport = RNS.Packet(
        path_request_destination,
        with_transport_payload,
        packet_type=RNS.Packet.DATA,
        transport_type=RNS.Transport.BROADCAST,
        header_type=RNS.Packet.HEADER_1,
        create_receipt=False,
    )

    return [
        packet_record(RNS, "path_request_without_transport", without_transport),
        packet_record(RNS, "path_request_with_transport", with_transport),
    ]


def build_lrproof_vector(RNS) -> Dict[str, Any]:
    owner_identity = make_fixed_identity(RNS, FIXED_LINK_OWNER_IDENTITY_HEX)
    owner_destination = RNS.Destination(
        owner_identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "example_utilities",
        "link",
        "prove",
    )

    peer_pub_bytes = bytes.fromhex(
        "4142434445464748494a4b4c4d4e4f50"
        "5152535455565758595a5b5c5d5e5f60"
    )
    peer_sig_pub_bytes = owner_identity.get_public_key()[32:64]
    link = RNS.Link(
        owner=owner_destination,
        peer_pub_bytes=peer_pub_bytes,
        peer_sig_pub_bytes=peer_sig_pub_bytes,
    )

    x25519_private = RNS.Cryptography.X25519PrivateKey.from_private_bytes(
        FIXED_LRPROOF_LINK_X25519_PRIVATE
    )
    link.link_id = FIXED_LRPROOF_LINK_ID
    link.hash = FIXED_LRPROOF_LINK_ID
    link.pub = x25519_private.public_key()
    link.pub_bytes = link.pub.public_bytes()

    with capture_sent_packets(RNS) as packets:
        link.prove()

    if len(packets) != 1:
        raise RuntimeError(f"Expected exactly one LRPROOF packet, got {len(packets)}")

    return packet_record(RNS, "lrproof", packets[0])


def collect_vectors(RNS) -> Dict[str, Any]:
    packet_vectors = []
    with offline_transport_state(RNS):
        packet_vectors.extend(build_destination_vectors(RNS))
        packet_vectors.extend(build_path_request_vectors(RNS))
        packet_vectors.append(build_lrproof_vector(RNS))

    by_name = {entry["name"]: entry for entry in packet_vectors}

    return {
        "meta": {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rns_module": getattr(RNS, "__file__", None),
            "rns_version": getattr(RNS, "__version__", None),
        "fixed_announce_time": FIXED_ANNOUNCE_TIME,
        },
        "fixed_inputs": {
            "destination_identity_hex": FIXED_DESTINATION_IDENTITY_HEX,
            "link_owner_identity_hex": FIXED_LINK_OWNER_IDENTITY_HEX,
            "announce_rng_bytes_hex": FIXED_ANNOUNCE_RNG_BYTES.hex(),
            "announce_random_hash_hex": FIXED_ANNOUNCE_RANDOM_HASH.hex(),
            "forwarded_transport_id_hex": FIXED_FORWARDED_TRANSPORT_ID.hex(),
            "path_request_destination_hex": FIXED_PATH_REQUEST_DESTINATION.hex(),
            "path_request_transport_hex": FIXED_PATH_REQUEST_TRANSPORT.hex(),
            "path_request_tag_hex": FIXED_PATH_REQUEST_TAG.hex(),
            "lrproof_link_id_hex": FIXED_LRPROOF_LINK_ID.hex(),
            "lrproof_x25519_private_hex": FIXED_LRPROOF_LINK_X25519_PRIVATE.hex(),
            "lrproof_ed25519_private_hex": FIXED_LRPROOF_LINK_ED25519_PRIVATE.hex(),
        },
        "vectors": by_name,
    }


def main() -> int:
    args = parse_args()
    RNS = load_rns_module(args.reticulum_path)
    payload = collect_vectors(RNS)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
