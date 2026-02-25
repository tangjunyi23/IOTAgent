#!/usr/bin/env python3
"""
Block Cipher Detection Tool for Firmware Analysis
Usage: python3 block_cipher_detect.py <firmware_file>

Analyzes firmware binary to determine likely block cipher algorithms
by searching for S-box constants, key schedule artifacts, and
cipher-specific patterns.
"""
import sys
import struct
from pathlib import Path

# AES S-box (first 32 bytes are sufficient for detection)
AES_SBOX_HEAD = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
])

# DES initial permutation table (partial)
DES_IP = bytes([
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
])

# Blowfish P-array initial values (first 4 32-bit values)
BLOWFISH_P = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
]

# ChaCha20/Salsa20 constant "expand 32-byte k"
CHACHA_CONST = b'expand 32-byte k'

# RC4 state initialization pattern (0x00..0xFF sequence is too generic,
# look for typical RC4 key scheduling patterns in disassembly context)

CRYPTO_STRINGS = [
    (b'AES', 'AES reference'),
    (b'aes_', 'AES function prefix'),
    (b'AES_', 'AES function prefix'),
    (b'rijndael', 'AES/Rijndael'),
    (b'DES', 'DES reference'),
    (b'des_', 'DES function prefix'),
    (b'3DES', 'Triple-DES reference'),
    (b'blowfish', 'Blowfish'),
    (b'BLOWFISH', 'Blowfish'),
    (b'twofish', 'Twofish'),
    (b'camellia', 'Camellia'),
    (b'chacha', 'ChaCha20'),
    (b'salsa', 'Salsa20'),
    (b'rc4', 'RC4/ARC4'),
    (b'RC4', 'RC4/ARC4'),
    (b'openssl', 'OpenSSL library'),
    (b'OpenSSL', 'OpenSSL library'),
    (b'mbedtls', 'mbed TLS library'),
    (b'wolfssl', 'wolfSSL library'),
    (b'EVP_Cipher', 'OpenSSL EVP API'),
    (b'EVP_Encrypt', 'OpenSSL EVP Encrypt'),
    (b'EVP_Decrypt', 'OpenSSL EVP Decrypt'),
    (b'mbedtls_aes', 'mbed TLS AES'),
    (b'mbedtls_des', 'mbed TLS DES'),
]


def find_pattern(data: bytes, pattern: bytes) -> list:
    """Find all occurrences of pattern in data."""
    positions = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return positions


def detect_aes(data: bytes) -> list:
    results = []
    positions = find_pattern(data, AES_SBOX_HEAD)
    for pos in positions:
        results.append({
            'cipher': 'AES',
            'evidence': 'S-box lookup table found',
            'offset': f'0x{pos:08X}',
            'confidence': 'high',
        })
    # Also check for AES round constants
    rcon = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])
    positions = find_pattern(data, rcon)
    for pos in positions:
        results.append({
            'cipher': 'AES',
            'evidence': 'Round constants (Rcon) found',
            'offset': f'0x{pos:08X}',
            'confidence': 'medium',
        })
    return results


def detect_des(data: bytes) -> list:
    results = []
    positions = find_pattern(data, DES_IP)
    for pos in positions:
        results.append({
            'cipher': 'DES',
            'evidence': 'Initial permutation table found',
            'offset': f'0x{pos:08X}',
            'confidence': 'high',
        })
    return results


def detect_blowfish(data: bytes) -> list:
    results = []
    for endian in ['>', '<']:
        packed = b''.join(struct.pack(f'{endian}I', v) for v in BLOWFISH_P)
        positions = find_pattern(data, packed)
        for pos in positions:
            results.append({
                'cipher': 'Blowfish',
                'evidence': f'P-array constants found ({"big" if endian == ">" else "little"}-endian)',
                'offset': f'0x{pos:08X}',
                'confidence': 'high',
            })
    return results


def detect_chacha(data: bytes) -> list:
    results = []
    positions = find_pattern(data, CHACHA_CONST)
    for pos in positions:
        results.append({
            'cipher': 'ChaCha20/Salsa20',
            'evidence': '"expand 32-byte k" constant found',
            'offset': f'0x{pos:08X}',
            'confidence': 'high',
        })
    return results


def detect_strings(data: bytes) -> list:
    results = []
    seen = set()
    for pattern, name in CRYPTO_STRINGS:
        positions = find_pattern(data, pattern)
        if positions and name not in seen:
            seen.add(name)
            results.append({
                'cipher': name,
                'evidence': f'String reference "{pattern.decode(errors="replace")}" found',
                'offset': f'0x{positions[0]:08X}',
                'count': len(positions),
                'confidence': 'medium',
            })
    return results


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware_file>")
        sys.exit(1)

    fw_path = Path(sys.argv[1])
    if not fw_path.exists():
        print(f"Error: {fw_path} not found")
        sys.exit(1)

    data = fw_path.read_bytes()
    print(f"Analyzing: {fw_path.name} ({len(data)} bytes)")
    print()

    all_results = []

    print("[*] Scanning for AES artifacts...")
    all_results.extend(detect_aes(data))

    print("[*] Scanning for DES artifacts...")
    all_results.extend(detect_des(data))

    print("[*] Scanning for Blowfish artifacts...")
    all_results.extend(detect_blowfish(data))

    print("[*] Scanning for ChaCha20/Salsa20 artifacts...")
    all_results.extend(detect_chacha(data))

    print("[*] Scanning for crypto library strings...")
    all_results.extend(detect_strings(data))

    if all_results:
        # Sort by confidence
        order = {'high': 0, 'medium': 1, 'low': 2}
        all_results.sort(key=lambda r: order.get(r.get('confidence', 'low'), 3))

        print(f"\n{'='*60}")
        print(f"Detected {len(all_results)} crypto artifact(s):")
        print(f"{'='*60}")
        for i, r in enumerate(all_results, 1):
            print(f"\n[{i}] {r['cipher']}")
            for k, v in r.items():
                if k != 'cipher':
                    print(f"    {k}: {v}")
    else:
        print("\nNo known block cipher artifacts found.")
        print("The firmware may use:")
        print("  - Custom/proprietary encryption")
        print("  - Simple XOR (try xor_key_recovery.py)")
        print("  - Compression only (not encryption)")


if __name__ == '__main__':
    main()
