#!/usr/bin/env python3
"""
XOR Key Recovery Tool for Encrypted Firmware
Usage: python3 xor_key_recovery.py <encrypted_firmware>

Attempts to recover XOR encryption keys by testing known plaintext patterns
against the firmware at various offsets.
"""
import sys
import math
from pathlib import Path


KNOWN_PLAINTEXTS = {
    b'hsqs': 'SquashFS (little-endian)',
    b'sqsh': 'SquashFS (big-endian)',
    b'\x1f\x8b\x08': 'gzip compressed data',
    b'UBI#': 'UBI image',
    b'\x85\x19\x01\x20': 'JFFS2 (little-endian)',
    b'\x19\x85\x20\x01': 'JFFS2 (big-endian)',
    b'\x45\x3d\xcd\x28': 'CramFS',
    b'\x27\x05\x19\x56': 'U-Boot uImage',
    b'\xde\xad\xc0\xde': 'Common firmware marker',
    b'#!/bin/sh\n': 'Shell script',
    b'\x7fELF': 'ELF binary',
    b'Linux': 'Linux kernel string',
    b'BusyBox': 'BusyBox binary',
}


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


def try_single_byte_xor(data: bytes, max_offset: int = 8192) -> list:
    results = []
    for plaintext, name in KNOWN_PLAINTEXTS.items():
        plen = len(plaintext)
        for offset in range(min(max_offset, len(data) - plen)):
            key_bytes = bytes(a ^ b for a, b in zip(data[offset:offset + plen], plaintext))
            if len(set(key_bytes)) == 1:
                key = key_bytes[0]
                if key != 0:  # Skip null key (means it's already plaintext)
                    results.append({
                        'type': 'single-byte XOR',
                        'key': f'0x{key:02X}',
                        'offset': offset,
                        'matched': name,
                        'confidence': 'high' if plen >= 4 else 'medium',
                    })
    return results


def try_multi_byte_xor(data: bytes, max_offset: int = 4096) -> list:
    results = []
    for plaintext, name in KNOWN_PLAINTEXTS.items():
        plen = len(plaintext)
        if plen < 3:
            continue
        for klen in [2, 4, 8, 16]:
            if plen < klen:
                continue
            for offset in range(min(max_offset, len(data) - plen)):
                key_bytes = bytes(a ^ b for a, b in zip(data[offset:offset + klen], plaintext[:klen]))
                if all(b == 0 for b in key_bytes):
                    continue
                # Verify: decrypt a larger chunk and check if result looks valid
                test_len = min(256, len(data) - offset)
                decrypted = bytes(data[offset + i] ^ key_bytes[i % klen] for i in range(test_len))
                ent = calc_entropy(decrypted)
                # Decrypted data should have lower entropy than encrypted
                if ent < 6.5:
                    results.append({
                        'type': f'{klen}-byte XOR',
                        'key': key_bytes.hex(),
                        'offset': offset,
                        'matched': name,
                        'decrypted_entropy': round(ent, 2),
                        'confidence': 'high' if ent < 5.0 else 'medium',
                    })
    return results


def try_rolling_xor(data: bytes) -> list:
    """Detect rolling/incremental XOR patterns."""
    results = []
    # Check if consecutive byte differences reveal a pattern
    diffs = [data[i+1] ^ data[i] for i in range(min(256, len(data) - 1))]
    # If diffs are mostly the same value → rolling XOR with constant increment
    if len(diffs) > 16:
        from collections import Counter
        diff_counts = Counter(diffs)
        most_common = diff_counts.most_common(1)[0]
        if most_common[1] > len(diffs) * 0.3:
            results.append({
                'type': 'rolling XOR',
                'increment': f'0x{most_common[0]:02X}',
                'frequency': f'{most_common[1]}/{len(diffs)}',
                'confidence': 'low',
            })
    return results


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <encrypted_firmware>")
        sys.exit(1)

    fw_path = Path(sys.argv[1])
    if not fw_path.exists():
        print(f"Error: {fw_path} not found")
        sys.exit(1)

    data = fw_path.read_bytes()
    print(f"Analyzing: {fw_path.name} ({len(data)} bytes)")
    print(f"Overall entropy: {calc_entropy(data):.4f}")
    print()

    all_results = []

    print("[*] Testing single-byte XOR...")
    results = try_single_byte_xor(data)
    all_results.extend(results)

    print("[*] Testing multi-byte XOR...")
    results = try_multi_byte_xor(data)
    all_results.extend(results)

    print("[*] Testing rolling XOR...")
    results = try_rolling_xor(data)
    all_results.extend(results)

    if all_results:
        print(f"\n{'='*60}")
        print(f"Found {len(all_results)} potential XOR key(s):")
        print(f"{'='*60}")
        for i, r in enumerate(all_results, 1):
            print(f"\n[{i}] {r['type']}")
            for k, v in r.items():
                if k != 'type':
                    print(f"    {k}: {v}")
    else:
        print("\nNo XOR keys found. Firmware may use AES/DES or custom encryption.")
        print("Try:")
        print("  - Checking the bootloader for crypto keys")
        print("  - Searching vendor update tools for hardcoded keys")
        print("  - Comparing with older unencrypted firmware versions")


if __name__ == '__main__':
    main()
