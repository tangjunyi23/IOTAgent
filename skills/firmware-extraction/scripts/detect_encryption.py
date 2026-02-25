#!/usr/bin/env python3
"""
Detect firmware encryption or obfuscation.
Usage: python3 detect_encryption.py <firmware_file>

Checks entropy, magic bytes, and known vendor encryption patterns.
"""
import sys
import math
import struct
from pathlib import Path


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (f / length) * math.log2(f / length) for f in freq if f > 0
    )


def check_known_patterns(data: bytes) -> list[str]:
    findings = []
    # D-Link DES encryption marker
    if data[:4] == b'SHRS':
        findings.append("D-Link SHRS encrypted firmware (DES-ECB)")
    # Netgear encrypted firmware
    if data[:4] == b'\x4e\x47\x52\x50':
        findings.append("Netgear NGRP encrypted firmware")
    # TP-Link standard header
    if data[:4] == b'\x01\x00\x00\x00' and data[4:8] == b'TP-LINK':
        findings.append("TP-Link standard firmware (likely not encrypted)")
    # UBI magic
    if b'UBI#' in data[:4096]:
        findings.append("UBI image detected (NAND flash)")
    # SquashFS
    if b'hsqs' in data or b'sqsh' in data:
        findings.append("SquashFS filesystem found (not encrypted)")
    # Broadcom TRX
    if data[:4] == b'HDR0':
        findings.append("Broadcom TRX header (not encrypted)")
    # XOR encryption detection (repeating pattern)
    chunk = data[:256]
    zero_count = chunk.count(0x00)
    if zero_count < 2 and len(chunk) == 256:
        findings.append("Possible XOR encryption (no null bytes in header)")
    return findings


def analyze_sections(data: bytes, block_size: int = 65536) -> list[dict]:
    sections = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        ent = calc_entropy(block)
        sections.append({
            "offset": i,
            "size": len(block),
            "entropy": round(ent, 4),
            "likely": "encrypted/compressed" if ent > 7.5 else
                      "code/data" if ent > 4.0 else
                      "sparse/padding"
        })
    return sections


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware_file>")
        sys.exit(1)

    fw_path = Path(sys.argv[1])
    if not fw_path.exists():
        print(f"Error: {fw_path} not found")
        sys.exit(1)

    data = fw_path.read_bytes()
    print(f"Firmware: {fw_path.name}")
    print(f"Size: {len(data)} bytes ({len(data) / 1024 / 1024:.2f} MB)")
    print(f"Overall entropy: {calc_entropy(data):.4f} / 8.0")
    print()

    patterns = check_known_patterns(data)
    if patterns:
        print("Known patterns detected:")
        for p in patterns:
            print(f"  - {p}")
    else:
        print("No known encryption patterns detected.")
    print()

    overall = calc_entropy(data)
    if overall > 7.8:
        print("WARNING: Very high entropy - firmware is likely fully encrypted")
    elif overall > 7.0:
        print("NOTE: High entropy - may be compressed or partially encrypted")
    else:
        print("OK: Moderate entropy - likely contains extractable sections")

    print("\nSection analysis (64KB blocks):")
    sections = analyze_sections(data)
    for s in sections[:20]:  # Show first 20 blocks
        bar = "#" * int(s["entropy"] * 4)
        print(f"  0x{s['offset']:08x}: {s['entropy']:.4f} [{bar:<32}] {s['likely']}")
    if len(sections) > 20:
        print(f"  ... ({len(sections) - 20} more blocks)")


if __name__ == "__main__":
    main()
