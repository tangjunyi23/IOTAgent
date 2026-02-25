---
name: hardware-debug-interfaces
description: Hardware debug interface exploitation for embedded devices — UART, JTAG, SWD identification, connection, and security bypass through physical debug ports
---

# Hardware Debug Interface Exploitation

## UART (Universal Asynchronous Receiver-Transmitter)

### Identifying UART Pins on PCB
```
Physical Indicators:
- 4-pin header (TX, RX, GND, VCC) — often unpopulated
- 3-pin header (TX, RX, GND) — VCC omitted
- Test pads labeled J1, JP1, CON1, or UART
- Pins near SoC or debug header area

Pin Identification:
1. GND — Continuity test to ground plane / shield / USB ground
2. VCC — Multimeter reads 3.3V or 5V (steady)
3. TX  — Oscilloscope shows activity during boot (square wave)
         Multimeter fluctuates between 0V and VCC during boot
4. RX  — Steady high (pulled up to VCC) with no activity
```

### UART Connection
```bash
# Common baud rates for embedded devices (try in order):
# 115200, 57600, 38400, 19200, 9600, 1500000

# Auto-detect baud rate using baudrate.py or logic analyzer
# Connect: USB-UART adapter (FTDI, CP2102, CH340)
#   Adapter TX → Device RX
#   Adapter RX → Device TX
#   Adapter GND → Device GND
#   Do NOT connect VCC (power device separately)

# Linux connection:
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200
# or  
picocom -b 115200 /dev/ttyUSB0

# Windows:
# PuTTY → Serial → COM port → Speed 115200

# If no output: try swapping TX/RX, try different baud rates
# If garbled output: wrong baud rate, try next common rate
```

### UART Security Bypass
```
Common UART Security Measures & Bypasses:

1. No output (TX disabled in production)
   → Check if TX pad was physically cut — bridge with solder
   → Some devices re-enable UART via GPIO or bootloader env
   → Try sending input on RX even without TX output

2. Login prompt (password required)
   → Try default passwords: root/root, admin/admin, root/(blank)
   → Interrupt boot process to get bootloader shell
   → Boot into single-user mode: kernel cmdline "single" or "init=/bin/sh"

3. Restricted shell / limited commands
   → BusyBox escape: busybox sh
   → Environment variable injection: export PATH=/tmp:$PATH
   → Write to /etc/passwd if writable

4. Encrypted/obfuscated output
   → May be custom encoding, not standard UART
   → Try different data formats: 8N1, 7E1, 8E1
   → Logic analyzer to verify signal characteristics
```

## JTAG (Joint Test Action Group)

### JTAG Pin Identification
```
Standard JTAG Signals (IEEE 1149.1):
- TCK  — Test Clock (input to device)
- TMS  — Test Mode Select (input)
- TDI  — Test Data In (input)
- TDO  — Test Data Out (output)
- TRST — Test Reset (optional, input)
- GND  — Ground

Common Header Layouts:
- 20-pin ARM JTAG (standard ARM debug header)
- 14-pin TI JTAG
- 10-pin Compact JTAG (cJTAG/SWD)
- Custom vendor headers

Auto-detection Tools:
- JTAGulator (hardware tool for pin identification)
- JTAGenum (Arduino-based JTAG scanner)
- Glasgow Interface Explorer
```

### Identifying JTAG Pins with JTAGEnum
```
# Flash JTAGenum to Arduino
# Connect Arduino pins to suspected JTAG pads
# Run pin scan to identify TCK, TMS, TDI, TDO

Algorithm:
1. Set all pins as output LOW
2. For each pin combination:
   a. Toggle suspected TCK → observe TDO for state changes
   b. Apply TMS patterns → check for TAP state machine behavior
   c. Shift known IDCODE pattern via TDI → verify on TDO
3. Confirm by reading JTAG IDCODE
```

### JTAG Exploitation with OpenOCD
```bash
# Install OpenOCD
# Configure interface (FTDI, J-Link, ST-Link, etc.)

# Example: OpenOCD config for MIPS target with FTDI adapter
cat > target.cfg << 'EOF'
source [find interface/ftdi/generic.cfg]
adapter speed 1000

# JTAG chain
jtag newtap target cpu -irlen 5 -expected-id 0x1234abcd

# Target configuration (MIPS example)
target create target.cpu mips_m4k -chain-position target.cpu
target.cpu configure -work-area-phys 0x80000000 -work-area-size 0x10000
EOF

# Connect and interact
openocd -f target.cfg

# In OpenOCD telnet (port 4444):
> halt                          # Stop CPU
> reg                           # Read all registers
> mdw 0x80000000 256            # Read 256 words from RAM
> mww 0x80000000 0xDEADBEEF    # Write to memory
> dump_image flash.bin 0x9F000000 0x1000000  # Dump 16MB flash
> load_image payload.bin 0x80100000          # Load payload to RAM
> resume 0x80100000             # Execute from address

# GDB integration (port 3333):
arm-none-eabi-gdb firmware.elf
(gdb) target remote :3333
(gdb) monitor halt
(gdb) info registers
(gdb) x/100x 0x80000000
```

### Dumping Flash via JTAG
```bash
# Full flash dump through JTAG
openocd -f interface/ftdi/generic.cfg -f target/mips.cfg \
    -c "init; halt; flash read_bank 0 flash_dump.bin; shutdown"

# For memory-mapped SPI flash:
openocd -c "init; halt; dump_image spi_flash.bin 0x9F000000 0x1000000; shutdown"

# Alternative: use boundary scan to read flash
# Useful when CPU is locked but JTAG chain is accessible
```

## SWD (Serial Wire Debug)

### SWD vs JTAG
```
SWD is ARM-specific, uses only 2 pins:
- SWDIO — Bidirectional data
- SWCLK — Clock
- GND   — Ground

Advantages over JTAG:
- Fewer pins (2 vs 4-5)
- Often shared with JTAG pins (multiplexed)
- Standard on all ARM Cortex-M devices

SWD is preferred for:
- ARM Cortex-M0/M3/M4/M7 (MCU targets)
- Low pin-count debug headers
- Production test points
```

### SWD Connection
```bash
# Using ST-Link adapter (cheap and widely available):
# Connect: SWCLK, SWDIO, GND

# OpenOCD with SWD:
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg -c "transport select swd"

# Using pyOCD (Python-based debug tool):
pip install pyocd
pyocd commander -t stm32f103c8
> read32 0x08000000 100      # Read flash
> write32 0x20000000 0x41414141  # Write to RAM
> halt
> reg
```

### Bypassing Debug Lock (Read-Out Protection)
```
ARM Cortex-M Read-Out Protection Levels:
- Level 0: No protection (full debug access)
- Level 1: Flash read protected, but debug access available
           RAM accessible, can attach debugger
           Bypass: cold boot attack, glitching during RDP check
- Level 2: Permanent lock (JTAG/SWD completely disabled)
           Cannot be bypassed without silicon-level attack

STM32 RDP Bypass Techniques:
1. Level 1 → Level 0 downgrade (erases all flash — useful for analysis)
   openocd -c "init; halt; stm32f1x unlock 0; reset halt; shutdown"
   
2. Voltage glitching during RDP check
   - Target: comparison instruction in ROM bootloader
   - Glitch timing: typically within first 100ms of power-on
   - Tools: ChipWhisperer, custom glitcher

3. UV exposure (older devices)
   - Erase protection fuse with UV light through chip window
   - Only works on older EPROM-based devices

4. Laser fault injection (advanced)
   - Decap chip, target RDP check with focused laser
   - Skip branch instruction that enforces protection
```

## Physical Security Assessment

### PCB Analysis Workflow
```
1. Visual inspection — Identify test points, unpopulated headers, debug labels
2. Component identification — SoC, flash chip, RAM chip markings
3. Datasheet lookup — Find debug port pinouts from SoC datasheet
4. Multi-meter probing — Identify GND, VCC, signal pins
5. Logic analyzer — Capture boot sequence on suspected debug pins
6. UART connection — Most common success path
7. JTAG/SWD enumeration — If debug header found
8. Flash chip direct read — Last resort, desolder and read with programmer
```

### Direct Flash Reading
```bash
# When debug ports are locked, read flash chip directly
# Desolder SPI flash chip → read with flash programmer

# SPI flash identification:
# Look for 8-pin SOIC/WSON chip labeled:
# Winbond W25Q64, W25Q128
# Macronix MX25L6406
# GigaDevice GD25Q64
# Spansion S25FL064

# Read with flashrom (Linux):
flashrom -p ch341a_spi -r flash_dump.bin

# Read with Raspberry Pi SPI:
flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash_dump.bin

# In-circuit reading (without desoldering):
# Power off device, connect clip to flash chip
# Ensure SoC is held in reset (or VCC disconnected)
# to prevent bus contention
```

## Security Assessment Matrix

| Interface | Risk Level | Typical Outcome | Difficulty |
|-----------|-----------|-----------------|------------|
| UART (no auth) | Critical | Root shell | Easy |
| UART (with auth) | High | Bootloader access → root | Medium |
| JTAG (unlocked) | Critical | Full memory read/write | Medium |
| SWD (unlocked) | Critical | Full memory read/write | Medium |
| JTAG (locked) | Medium | May bypass with glitching | Hard |
| SWD (RDP Level 1) | High | Flash erase + re-flash | Medium |
| SWD (RDP Level 2) | Low | Requires silicon attack | Very Hard |
| SPI flash direct | High | Full firmware dump | Medium |
| I2C EEPROM | Medium | Config/credential extraction | Easy |
