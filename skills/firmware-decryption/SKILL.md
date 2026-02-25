---
name: firmware-decryption
description: Firmware decryption, deobfuscation, and unpacking for encrypted IoT firmware images. Use when firmware entropy analysis reveals encrypted/obfuscated content, when binwalk extraction fails due to encryption, when decrypting vendor-specific firmware encryption (D-Link, Netgear, TP-Link, Hikvision, Dahua, ZTE), or when reversing custom XOR/AES/DES encryption applied to firmware update files.
---

# Firmware Decryption & Unpacking

Decrypt, deobfuscate, and unpack encrypted or obfuscated firmware images when standard extraction fails.

## Workflow

1. Confirm encryption (entropy analysis + header inspection)
2. Identify vendor and encryption scheme
3. Locate decryption keys (bootloader, update utility, prior firmware)
4. Decrypt and extract
5. Validate decrypted output

## Step 1: Confirm Encryption

```bash
# Entropy scan — encrypted data has entropy near 8.0 across all blocks
binwalk -E firmware.bin

# Inspect header for magic bytes / vendor markers
hexdump -C firmware.bin | head -20
file firmware.bin

# Check for known cleartext sections (partial encryption)
binwalk firmware.bin
# If binwalk finds nothing → likely fully encrypted
# If binwalk finds a header but no filesystem → header is cleartext, payload is encrypted
```

**Decision matrix:**

| Entropy | binwalk results | Likely state |
|---------|----------------|--------------|
| ~8.0 uniform | Nothing found | Fully encrypted |
| ~8.0 except header | Header only | Encrypted payload, cleartext header |
| ~7.0–7.9 | Compressed data | Compressed, not encrypted |
| Mixed high/low | Partial matches | Partial encryption or packed |

## Step 2: Vendor-Specific Decryption

### D-Link — DES-ECB / AES

```bash
# SHRS header → DES-ECB encrypted
hexdump -C firmware.bin | head -1
# If starts with "SHRS": D-Link encrypted firmware

# Known D-Link decryption (imgdecrypt tool)
# Extract from older unencrypted firmware: /usr/sbin/imgdecrypt
imgdecrypt firmware.bin

# Manual DES-ECB with known key (varies by model)
openssl enc -d -des-ecb -nopad -K <hex_key> -in firmware.bin -out decrypted.bin
```

Common D-Link keys (hex):
- DIR-882: `C05FBF1936C99429CE2A0781F08D6AD8` (AES-128)
- DIR-878: varies by hardware revision
- Model-specific keys often found in `/usr/sbin/imgdecrypt` binary

### Netgear — AES-256-CBC

```bash
# NGRP header → Netgear encrypted
hexdump -C firmware.bin | head -1

# Netgear uses OpenSSL AES-256-CBC with hardcoded password
openssl enc -d -aes-256-cbc -md md5 -k <password> -in encrypted.bin -out decrypted.bin

# Password often found in:
#   - Previous unencrypted firmware update binary
#   - /usr/sbin/nmbd or upgrade handler
#   - Strings search: strings <upgrade_binary> | grep -i "key\|pass\|secret"
```

### TP-Link — XOR + Custom Header

```bash
# TP-Link firmware often uses XOR obfuscation on parts
# Header: 4 bytes magic + version info (usually cleartext)
# Payload: XOR with vendor-specific key

python3 -c "
import sys
data = open('firmware.bin','rb').read()
# Skip TP-Link header (typically 0x200 bytes)
payload = data[0x200:]
# Try known XOR keys
keys = [0x78, 0xDA, 0xFF, 0x12]
for k in keys:
    dec = bytes(b ^ k for b in payload[:64])
    if b'sqsh' in dec or b'hsqs' in dec or b'UBI' in dec:
        print(f'XOR key found: 0x{k:02X}')
        open('decrypted.bin','wb').write(bytes(b ^ k for b in payload))
        break
"
```

### Hikvision — AES-128-ECB + Custom Container

```bash
# Hikvision digicap.dav format
# Header contains model info, payload AES-128-ECB encrypted
# Key is derived from device model string

# Common approach:
# 1. Extract key from Hikvision upgrade tool (Windows binary)
# 2. Or find in bootloader: strings u-boot.bin | grep -i "aes\|key\|crypt"

openssl enc -d -aes-128-ecb -nopad -K <hex_key> -in payload.bin -out decrypted.bin
```

### Dahua — ZIP + XOR Layers

```bash
# Dahua firmware is often a ZIP archive with XOR-encrypted contents
# Outer layer: standard ZIP
unzip firmware.bin -d stage1/

# Inner layer: XOR encrypted .bin files
# Key typically: 0x1A2B3C4D or model-specific
```

### ZTE — AES-CBC + RSA Signature

```bash
# ZTE uses AES-CBC encrypted payload with RSA signature verification
# AES key encrypted with RSA public key in header
# Private key sometimes found in device bootloader

# Steps:
# 1. Parse header to extract encrypted AES key
# 2. Find RSA private key in bootloader/previous firmware
# 3. Decrypt AES key with RSA
# 4. Decrypt payload with AES-CBC
```

## Step 3: Generic Key Recovery

When vendor-specific tools are unavailable:

### From Bootloader (U-Boot)

```bash
# Extract U-Boot from firmware image
binwalk -e firmware.bin
# Often at offset 0x0 or after a small header

# Search for crypto keys in U-Boot
strings u-boot.bin | grep -iE "aes|des|key|password|decrypt|enc"

# Search for key arrays (16/24/32 byte hex patterns)
strings u-boot.bin | grep -E "^[0-9a-fA-F]{32,64}$"

# Decompile U-Boot upgrade handler in Ghidra
# Function names to look for: do_fw_upgrade, fw_decrypt, verify_image
```

### From Update Application

```bash
# Vendor desktop/mobile update apps contain decryption routines
# For Windows .exe: use IDA/Ghidra to find crypto calls
# For Android .apk:
apktool d update_app.apk
grep -rn "AES\|DES\|decrypt\|SecretKey" update_app/smali/

# For JavaScript-based (web upload):
grep -rn "CryptoJS\|aes\|decrypt" web_interface/
```

### From Previous Firmware Versions

```bash
# Older firmware versions are often unencrypted
# 1. Download older firmware from vendor FTP/support page
# 2. Extract update handler binary
# 3. Find decryption key/routine
# 4. Apply to encrypted firmware
```

## Step 4: Custom Encryption Analysis

For unknown/custom encryption:

### Block Cipher Detection

```python
#!/usr/bin/env python3
"""Detect block cipher characteristics"""
import sys

data = open(sys.argv[1], 'rb').read()

# Check for block alignment (AES=16, DES=8)
for block_size in [8, 16, 32]:
    if len(data) % block_size == 0:
        print(f"Data aligned to {block_size}-byte blocks (possible {'DES' if block_size==8 else 'AES' if block_size==16 else 'unknown'})")

# Check for ECB mode (repeated blocks = ECB)
blocks = {}
bs = 16  # Try AES block size
for i in range(0, len(data) - bs, bs):
    block = data[i:i+bs]
    blocks[block] = blocks.get(block, 0) + 1

repeated = {k: v for k, v in blocks.items() if v > 1}
if repeated:
    print(f"ECB mode likely: {len(repeated)} repeated blocks found")
else:
    print("No repeated blocks — likely CBC/CTR mode or not block cipher")
```

### XOR Key Recovery

```python
#!/usr/bin/env python3
"""Attempt XOR key recovery using known plaintext"""
import sys

encrypted = open(sys.argv[1], 'rb').read()

# Known plaintext for common filesystem headers
known_plaintexts = {
    b'hsqs': 'SquashFS (LE)',
    b'sqsh': 'SquashFS (BE)',
    b'\x1f\x8b\x08': 'gzip',
    b'UBI#': 'UBI',
    b'\xde\xad\xc0\xde': 'Firmware marker',
    b'#!/bin/sh': 'Shell script',
    b'ELF': 'ELF binary',
}

for plaintext, name in known_plaintexts.items():
    # Try single-byte XOR
    for offset in range(min(4096, len(encrypted) - len(plaintext))):
        key_candidate = bytes(a ^ b for a, b in zip(encrypted[offset:], plaintext))
        if len(set(key_candidate)) == 1:
            key = key_candidate[0]
            print(f"Single-byte XOR key 0x{key:02X} at offset {offset} (matched {name})")

    # Try multi-byte XOR (key length 4, 8, 16)
    for klen in [4, 8, 16]:
        for offset in range(min(1024, len(encrypted) - len(plaintext))):
            key_bytes = bytes(a ^ b for a, b in zip(encrypted[offset:offset+len(plaintext)], plaintext))
            # Verify by checking if key repeats
            test_dec = bytes(encrypted[(offset+i) % len(encrypted)] ^ key_bytes[i % len(key_bytes)] for i in range(min(64, len(encrypted) - offset)))
            # Quick heuristic: decrypted should have more null bytes and printable chars
            nulls = test_dec.count(0)
            if nulls > 5:
                print(f"Multi-byte XOR key (len={klen}) candidate at offset {offset}: {key_bytes.hex()} (matched {name})")
```

## Step 5: Validate Decryption

```bash
# After decryption, verify the output is valid
file decrypted.bin
binwalk decrypted.bin
binwalk -E decrypted.bin  # Entropy should now show mixed high/low regions

# If successful, extract normally
binwalk -eM decrypted.bin
```

## References

- **XOR key recovery script**: See `scripts/xor_key_recovery.py` for automated XOR analysis
- **Block cipher detection**: See `scripts/block_cipher_detect.py` for cipher identification
