# Advanced Extraction Techniques

## Non-Standard Firmware Formats

### TRX Headers (Broadcom)
```bash
# TRX format: 4-byte magic "HDR0" at offset 0
hexdump -C firmware.bin | head -5
# Extract after TRX header (typically 28 bytes)
dd if=firmware.bin of=payload.bin bs=1 skip=28
binwalk -eM payload.bin
```

### UBI Images (NAND Flash)
```bash
pip install ubi_reader
ubireader_extract_files firmware.ubi -o output/
# Or extract UBI from raw NAND dump
ubireader_extract_images nand_dump.bin -o ubi_images/
```

### Packed/Multi-Part Firmware
Some vendors concatenate multiple images (bootloader + kernel + rootfs + config):
```bash
# Use binwalk to find boundaries
binwalk -v firmware.bin
# Extract each section individually
dd if=firmware.bin of=section1.bin bs=1 skip=0 count=<boundary1>
dd if=firmware.bin of=section2.bin bs=1 skip=<boundary1> count=<size2>
```

### Vendor-Specific Formats

| Vendor | Tool | Notes |
|--------|------|-------|
| D-Link | `firmware-mod-kit`, `dlink-dec` | Often DES encrypted |
| TP-Link | `tplink-safeloader` | Custom header format |
| Netgear | `ambit-firmware-editor` | Proprietary TLV format |
| Ubiquiti | Built-in binwalk support | Usually straightforward |
| Hikvision | Custom tools needed | XOR or AES-128 encryption |

## Rebuilding Firmware (After Modification)

```bash
# Repack SquashFS
mksquashfs squashfs-root/ new_rootfs.squashfs -comp xz -b 65536
# Recalculate checksums if needed
python3 scripts/fix_checksum.py original.bin modified.bin
```
