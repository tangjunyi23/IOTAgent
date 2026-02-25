---
name: firmware-extraction
description: Firmware extraction and filesystem analysis for IoT devices. Use when analyzing firmware binaries, extracting filesystems with binwalk, identifying firmware format/structure, locating key files after extraction, or performing initial reconnaissance on router/camera/IoT firmware images. Triggers on tasks involving .bin/.img/.trx/.chk firmware files.
---

# Firmware Extraction

Extract and analyze IoT device firmware to identify the filesystem structure and locate security-relevant files.

## Workflow

1. Identify firmware format (`file`, `binwalk` scan)
2. Extract filesystem (`binwalk -eM`)
3. Analyze entropy for encryption/compression (`binwalk -E`)
4. Map filesystem structure and locate key targets
5. Begin targeted file analysis

## Quick Start

```bash
# Scan firmware structure
binwalk firmware.bin

# Recursive extraction
binwalk -eM firmware.bin

# Entropy analysis (detect encrypted sections)
binwalk -E firmware.bin

# If binwalk fails, try manual offset extraction
dd if=firmware.bin of=extracted.squashfs bs=1 skip=<offset> count=<size>
```

## Key Target Files After Extraction

| Priority | Path Pattern | What to Look For |
|----------|-------------|------------------|
| 1 | `/etc/passwd`, `/etc/shadow` | Hardcoded credentials |
| 2 | `/usr/sbin/httpd`, `/usr/bin/goahead` | Web server binaries |
| 3 | `/www/cgi-bin/`, `/www/*.cgi` | CGI scripts (command injection) |
| 4 | `/etc/*.conf`, `/etc/config/` | Service configurations |
| 5 | `/lib/*.so`, `/usr/lib/*.so` | Shared libraries |
| 6 | `/sbin/`, `/usr/sbin/` | Network service daemons |
| 7 | `/etc/init.d/`, `/etc/rc.d/` | Startup scripts (backdoor indicators) |

## Filesystem Types

- **SquashFS** (most common): `unsquashfs` to extract, check compression type
- **JFFS2**: `jefferson` or `jffs2dump` for extraction
- **CramFS**: `cramfsck` to extract
- **UBIFS**: `ubireader_extract_files` for NAND flash images
- **YAFFS2**: `unyaffs` for extraction

## Encrypted/Obfuscated Firmware

When entropy analysis shows high entropy (>0.9) across the entire image:

1. Check for known encryption schemes (e.g., D-Link DES, Netgear AES)
2. Search for decryption routines in bootloader sections
3. Use `firmware-mod-kit` or vendor-specific tools
4. Check `scripts/detect_encryption.py` for automated detection

## References

- **Detailed extraction techniques**: See [references/advanced-extraction.md](references/advanced-extraction.md) for handling non-standard formats
- **Decryption script**: Run `scripts/detect_encryption.py` against firmware to identify encryption scheme
