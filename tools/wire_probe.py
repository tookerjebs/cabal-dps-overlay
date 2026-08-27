"""Nic pcap probe. Stdlib + tshark.

Default header XOR 0xD15FA427 and data/keychain.bin next to this tree.
"""
from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DEFAULT_TABLE = HERE / "data" / "keychain.bin"
HEADER_XOR = 0xD15FA427
MAGIC_NORMAL = 0xB7E2
MAGIC_CHECKSUM = 0xC8F3
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")


def load_u32(buf: bytes, off: int) -> int:
    if off + 4 > len(buf):
        return 0
    return struct.unpack_from("<I", buf, off)[0]


def packet_size(packet: bytes, table: bytes) -> int:
    if len(packet) < 4:
        return 0
    header = load_u32(packet, 0) ^ HEADER_XOR
    magic = header & 0xFFFF
    if magic == MAGIC_CHECKSUM:
        if len(packet) < 8:
            return 0
        t = (load_u32(packet, 0) & 0x3FFF) * 4
        key = load_u32(table, t)
        xh0 = load_u32(packet, 0) ^ HEADER_XOR
        xh1 = load_u32(packet, 4) ^ key
        return int((((xh1 << 32) | xh0) >> 16) & 0xFFFFFFFF)
    if magic != MAGIC_NORMAL:
        return 0
    return int(header >> 16)


def decrypt(packet: bytes, table: bytes) -> bytes | None:
    if len(packet) < 4:
        return None
    size = packet_size(packet, table)
    if size < 4 or size > len(packet) or size > 0x4D000:
        return None
    out = bytearray(packet[:size])
    key = load_u32(table, (load_u32(out, 0) & 0x3FFF) * 4)
    struct.pack_into("<I", out, 0, load_u32(out, 0) ^ HEADER_XOR)
    remain = (size - 4) & 3
    aligned = size - remain
    i = 4
    while i < aligned:
        t1 = load_u32(out, i)
        key ^= t1
        struct.pack_into("<I", out, i, key)
        key = load_u32(table, (t1 & 0x3FFF) * 4)
        i += 4
    if remain:
        raw = int.from_bytes(out[i : i + remain].ljust(4, b"\0"), "little")
        mask = 0xFFFFFFFF >> (8 * (4 - remain))
        xored = (raw ^ (key & mask)) & mask
        out[i : i + remain] = xored.to_bytes(4, "little")[:remain]
    mag = struct.unpack_from("<H", out, 0)[0]
    if mag not in (MAGIC_NORMAL, MAGIC_CHECKSUM):
        return None
    return bytes(out)


def tshark_payloads(pcap: Path) -> list[tuple[int, float, str, int, bytes]]:
    cmd = [
        str(TSHARK),
        "-r",
        str(pcap),
        "-Y",
        "tcp.len > 0",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time_relative",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.len",
        "-e",
        "tcp.payload",
    ]
    raw = subprocess.check_output(cmd, text=True, encoding="ascii", errors="replace")
    rows = []
    for line in raw.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 5 or not parts[4]:
            continue
        hx = parts[4].replace(":", "")
        try:
            blob = bytes.fromhex(hx)
        except ValueError:
            continue
        rows.append((int(parts[0]), float(parts[1]), parts[2], int(parts[3]), blob))
    return rows


def parse_frames(stream: bytes) -> list[bytes]:
    frames: list[bytes] = []
    i = 0
    while i + 4 <= len(stream):
        if stream[i] != 1:
            nxt = stream.find(b"\x01", i + 1)
            if nxt < 0:
                break
            i = nxt
            continue
        ln = int.from_bytes(stream[i + 1 : i + 4], "little")
        if ln < 1 or ln > 0x20000 or i + 4 + ln > len(stream):
            i += 1
            continue
        frames.append(stream[i + 4 : i + 4 + ln])
        i += 4 + ln
    return frames


def field23s(inner: bytes) -> list[bytes]:
    out: list[bytes] = []
    i = 0
    while i + 3 <= len(inner):
        tag = inner[i]
        fid = inner[i + 1]
        if tag == 5:
            ln = inner[i + 2]
            if i + 3 + ln > len(inner):
                break
            if fid == 0x23:
                out.append(inner[i + 3 : i + 3 + ln])
            i += 3 + ln
            continue
        if tag == 9:
            if fid == 0x23:
                out.append(inner[i + 4 :])
            break
        break
    return out


def looks_ae(dec: bytes) -> bool:
    if len(dec) < 0x78:
        return False
    if struct.unpack_from("<H", dec, 0)[0] != MAGIC_NORMAL:
        return False
    return struct.unpack_from("<H", dec, 2)[0] == 137 and struct.unpack_from("<H", dec, 4)[0] == 0xAE


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--table", default=str(DEFAULT_TABLE))
    parser.add_argument("--ports", default="", help="comma src ports; empty = all")
    args = parser.parse_args()
    pcap = Path(args.pcap)
    table = Path(args.table).read_bytes()
    if len(table) < 0x10000:
        print("table too small")
        return 1
    table = table[:0x10000]
    if not TSHARK.is_file():
        print("tshark not found")
        return 1
    ports = {p.strip() for p in args.ports.split(",") if p.strip()}
    by_port: dict[str, bytearray] = defaultdict(bytearray)
    for _num, _t, port, _ln, blob in tshark_payloads(pcap):
        if ports and port not in ports:
            continue
        by_port[port].extend(blob)
    ae = 0
    magic = 0
    for port, stream in by_port.items():
        raw = bytes(stream)
        payloads: list[bytes] = []
        for inner in parse_frames(raw):
            payloads.extend(field23s(inner))
        if not payloads:
            payloads = [raw]
        print(f"port={port} bytes={len(raw)} field23_or_raw={len(payloads)}")
        for blob in payloads:
            dec = decrypt(blob, table)
            if dec is None:
                continue
            magic += 1
            if looks_ae(dec):
                ae += 1
                dmg = struct.unpack_from("<i", dec, 0x68)[0]
                skill = struct.unpack_from("<H", dec, 0x06)[0]
                print(f"  AE137 port={port} skill={skill} dmg={dmg}")
    print(f"decrypted={magic} combat_0xAE={ae}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
