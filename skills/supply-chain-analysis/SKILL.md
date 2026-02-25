---
name: supply-chain-analysis
description: Third-party component and supply chain vulnerability analysis for embedded firmware — outdated libraries, known CVEs, open-source component detection, and dependency risk assessment
---

# Supply Chain & Third-Party Component Analysis

## Overview

Embedded firmware extensively reuses open-source components (BusyBox, OpenSSL, curl, dnsmasq, etc.) that are frequently outdated and contain known vulnerabilities. Identifying these components and their versions is one of the highest-ROI activities in firmware security analysis.

## Component Identification

### Binary String Extraction
```bash
# Extract version strings from firmware filesystem
# Target: /usr/bin, /usr/sbin, /usr/lib, /lib

# OpenSSL / crypto libraries
strings lib/libssl.so* lib/libcrypto.so* | grep -iE "openssl|boringssl|libressl|wolfssl|mbedtls"

# BusyBox version
strings bin/busybox | grep "BusyBox v"

# Linux kernel version
strings vmlinux* | grep "Linux version"

# Common libraries
strings lib/*.so* | grep -iE "curl [0-9]\|libcurl/\|zlib [0-9]\|libpng\|libjpeg\|sqlite\|dnsmasq\|dropbear\|lighttpd"

# Web server versions
strings usr/sbin/httpd usr/bin/lighttpd usr/sbin/uhttpd 2>/dev/null | grep -iE "server:|version"

# Batch version extraction
for f in $(find . -type f -executable 2>/dev/null); do
    ver=$(strings "$f" 2>/dev/null | head -200 | grep -iE "version|v[0-9]+\.[0-9]" | head -3)
    if [ -n "$ver" ]; then
        echo "=== $f ==="
        echo "$ver"
    fi
done
```

### Package Manager Artifacts
```bash
# OpenWrt packages
cat /usr/lib/opkg/info/*.control 2>/dev/null
cat /usr/lib/opkg/status 2>/dev/null

# Buildroot package versions
cat /usr/share/buildroot/packages.txt 2>/dev/null

# Yocto/OE manifests
cat /usr/share/common-licenses/* 2>/dev/null
find / -name "manifest" -o -name "*.manifest" 2>/dev/null
```

### Binary Fingerprinting
```bash
# When strings aren't sufficient, use binary fingerprinting:

# Check ELF dynamic dependencies
readelf -d binary_file | grep NEEDED

# Library version symbols
readelf --version-info lib/libcrypto.so.1.0.0
nm -D lib/libssl.so | grep -i "SSL_"

# SHA256 hash comparison against known builds
sha256sum lib/libcrypto.so.1.0.0
# Compare hash against known vulnerable library builds
```

## High-Risk Component Database

### Critical Components to Check
| Component | Where Found | Known Vulnerability Classes |
|-----------|-------------|---------------------------|
| OpenSSL | libssl.so, libcrypto.so | Heartbleed, padding oracle, buffer overflows |
| BusyBox | /bin/busybox | Command injection, use-after-free |
| dnsmasq | /usr/sbin/dnsmasq | DNS rebinding, buffer overflow (DNSpooq) |
| curl/libcurl | /usr/bin/curl, libcurl.so | Buffer overflow, HSTS bypass, auth leaks |
| Dropbear SSH | /usr/sbin/dropbear | Auth bypass, use-after-free |
| lighttpd | /usr/sbin/lighttpd | Path traversal, DoS |
| mini_httpd | /usr/sbin/mini_httpd | Buffer overflow, path traversal |
| GoAhead | /usr/bin/goahead | RCE via CGI, stack overflow |
| UPnP (miniupnpd) | /usr/sbin/miniupnpd | Buffer overflow, info disclosure |
| Samba/SMB | /usr/sbin/smbd | SambaCry RCE, auth bypass |
| iptables/netfilter | kernel modules | Rule bypass, kernel exploits |
| SQLite | libsqlite3.so | Magellan vulnerabilities |
| libxml2 | libxml2.so | XXE, billion laughs, buffer overflow |
| zlib | libz.so | DoS, memory corruption |
| D-Link custom | various | Hardcoded backdoors, command injection |
| Realtek SDK | various | UDPCloud RCE, buffer overflow |

### Version-to-CVE Quick Reference

**OpenSSL**
| Version Range | Critical CVEs |
|--------------|---------------|
| < 1.0.1g | CVE-2014-0160 (Heartbleed) |
| < 1.0.1j | CVE-2014-3566 (POODLE) |
| < 1.0.2h | CVE-2016-2107 (Padding Oracle) |
| < 1.1.1k | CVE-2021-3449 (NULL ptr DoS) |
| < 3.0.7 | CVE-2022-3602 (X.509 overflow) |

**BusyBox**
| Version Range | Critical CVEs |
|--------------|---------------|
| < 1.30.0 | CVE-2018-20679 (DNS response handling) |
| < 1.33.1 | CVE-2021-42373 to 42386 (14 vulns, many RCE) |
| < 1.34.0 | CVE-2022-28391 (netstat applet) |

**dnsmasq**
| Version Range | Critical CVEs |
|--------------|---------------|
| < 2.78 | CVE-2017-14491 to 14496 (6 RCE/DoS vulns) |
| < 2.83 | CVE-2020-25681 to 25687 (DNSpooq, 7 vulns) |

**curl**
| Version Range | Critical CVEs |
|--------------|---------------|
| < 7.51.0 | CVE-2016-8615 to 8625 (11 vulns) |
| < 7.84.0 | CVE-2022-32221 (POST-after-PUT confusion) |
| < 8.4.0 | CVE-2023-38545 (SOCKS5 heap overflow) |

## Automated Analysis Tools

### SBOM Generation
```bash
# Software Bill of Materials extraction

# Using binwalk + manual analysis
binwalk -e firmware.bin
cd _firmware.bin.extracted/squashfs-root/

# Generate component inventory
echo "Component,Version,Path,License" > sbom.csv
for lib in $(find . -name "*.so*" -type f); do
    name=$(basename "$lib" | sed 's/\.so.*//')
    ver=$(strings "$lib" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "$name,$ver,$lib,unknown" >> sbom.csv
done

# Check against NVD (National Vulnerability Database)
# Use CVE search APIs or local CVE database
# cve-search: https://github.com/cve-search/cve-search
# nvdlib (Python): pip install nvdlib
```

### CVE Scanning Script
```python
#!/usr/bin/env python3
"""
Scan extracted firmware filesystem for known vulnerable components.
Usage: python3 cve_check.py <firmware_root_dir>
"""
import os
import re
import subprocess
import sys

# Known vulnerable component patterns
COMPONENTS = {
    'openssl': {
        'files': ['libssl.so*', 'libcrypto.so*', 'openssl'],
        'version_pattern': r'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)',
        'critical_below': '1.1.1w',
    },
    'busybox': {
        'files': ['busybox'],
        'version_pattern': r'BusyBox\s+v(\d+\.\d+\.\d+)',
        'critical_below': '1.34.0',
    },
    'dnsmasq': {
        'files': ['dnsmasq'],
        'version_pattern': r'dnsmasq-(\d+\.\d+)',
        'critical_below': '2.86',
    },
    'curl': {
        'files': ['curl', 'libcurl.so*'],
        'version_pattern': r'curl[/ ](\d+\.\d+\.\d+)',
        'critical_below': '8.4.0',
    },
    'dropbear': {
        'files': ['dropbear', 'dropbearmulti'],
        'version_pattern': r'dropbear(?:multi)?\s+v?(\d{4}\.\d+)',
        'critical_below': '2022.83',
    },
    'lighttpd': {
        'files': ['lighttpd'],
        'version_pattern': r'lighttpd[/ ](\d+\.\d+\.\d+)',
        'critical_below': '1.4.67',
    },
    'miniupnpd': {
        'files': ['miniupnpd'],
        'version_pattern': r'miniupnpd[/ ](\d+\.\d+)',
        'critical_below': '2.2.1',
    },
    'samba': {
        'files': ['smbd', 'libsmbclient.so*'],
        'version_pattern': r'Samba\s+(\d+\.\d+\.\d+)',
        'critical_below': '4.17.0',
    },
}


def find_files(root_dir, pattern):
    """Find files matching glob pattern."""
    import glob
    results = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if glob.fnmatch.fnmatch(fn, pattern):
                results.append(os.path.join(dirpath, fn))
    return results


def extract_version(filepath, pattern):
    """Extract version string from binary."""
    try:
        output = subprocess.check_output(
            ['strings', filepath], stderr=subprocess.DEVNULL
        ).decode(errors='replace')
        match = re.search(pattern, output)
        return match.group(1) if match else None
    except Exception:
        return None


def version_compare(v1, v2):
    """Compare version strings. Returns -1, 0, or 1."""
    def normalize(v):
        parts = []
        for p in re.split(r'[.\-]', v):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(p)
        return parts
    
    n1, n2 = normalize(v1), normalize(v2)
    for a, b in zip(n1, n2):
        if isinstance(a, int) and isinstance(b, int):
            if a < b: return -1
            if a > b: return 1
        else:
            a_s, b_s = str(a), str(b)
            if a_s < b_s: return -1
            if a_s > b_s: return 1
    return len(n1) - len(n2)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware_root_dir>")
        sys.exit(1)

    root = sys.argv[1]
    print(f"Scanning: {root}\n")
    
    findings = []
    for comp_name, info in COMPONENTS.items():
        for file_pattern in info['files']:
            files = find_files(root, file_pattern)
            for f in files:
                ver = extract_version(f, info['version_pattern'])
                if ver:
                    is_vuln = version_compare(ver, info['critical_below']) < 0
                    findings.append({
                        'component': comp_name,
                        'version': ver,
                        'path': f,
                        'vulnerable': is_vuln,
                        'threshold': info['critical_below'],
                    })

    if findings:
        vulns = [f for f in findings if f['vulnerable']]
        safe = [f for f in findings if not f['vulnerable']]
        
        if vulns:
            print(f"{'='*60}")
            print(f"VULNERABLE COMPONENTS ({len(vulns)}):")
            print(f"{'='*60}")
            for f in vulns:
                print(f"  [!] {f['component']} {f['version']} (needs >= {f['threshold']})")
                print(f"      Path: {f['path']}")
        
        if safe:
            print(f"\n{'='*60}")
            print(f"Components within acceptable range ({len(safe)}):")
            print(f"{'='*60}")
            for f in safe:
                print(f"  [OK] {f['component']} {f['version']}")
                print(f"       Path: {f['path']}")
    else:
        print("No known components detected via string analysis.")
        print("Try manual inspection or binary fingerprinting.")


if __name__ == '__main__':
    main()
```

## SDK / Chipset Vendor Vulnerabilities

### Common Vulnerable SDKs
| Vendor/SDK | Known Issues | Detection |
|-----------|-------------|-----------|
| Realtek SDK | CVE-2021-35392 to 35395, UDPCloud RCE | `realtek`, `rsdk`, `rlx-linux` |
| Qualcomm QSDK | Multiple buffer overflows in WLAN drivers | `qca-wifi`, `qsdk`, `ipq` |
| MediaTek SDK | Pre-auth RCE in wappd | `mt76`, `ralink`, `mediatek` |
| Broadcom SDK | Multiple CFE/wireless driver vulns | `broadcom`, `brcm`, `bcm` |
| Marvell SDK | Firmware parsing vulnerabilities | `marvell`, `mwl8k` |
| HiSilicon SDK | Hardcoded backdoors, telnet access | `hisilicon`, `hi35`, `liteos` |
| Espressif (ESP32) | Side-channel on secure boot | `esp32`, `esp-idf` |
| Xilinx | Bitstream encryption bypass | `xilinx`, `zynq` |

### Detection Commands
```bash
# Identify chipset/SDK vendor
strings firmware.bin | grep -iE "realtek|qualcomm|mediatek|broadcom|marvell|hisilicon|espressif"
cat /proc/cpuinfo 2>/dev/null
dmesg | grep -iE "realtek|qualcomm|mediatek|broadcom" 2>/dev/null
```

## GPL Compliance Audit

```bash
# Many embedded devices use GPL software without providing source
# GPL source can reveal:
# - Exact component versions used
# - Vendor-specific patches (may introduce vulnerabilities)
# - Build configuration (enabled features, disabled security options)
# - Third-party components included

# Check vendor website for GPL source release
# Common locations:
# - vendor.com/gpl
# - vendor.com/support/gpl
# - vendor.com/opensource

# Compare released source against binary to find unreleased modifications
# Vendor patches to open-source components are common vulnerability sources
```

## Analysis Workflow

1. **Extract filesystem** — `binwalk -e firmware.bin` → squashfs-root
2. **Enumerate components** — String extraction, library listing, package manifests
3. **Identify versions** — Version strings, binary fingerprints, build dates
4. **Cross-reference CVEs** — NVD, vendor advisories, exploit-db
5. **Prioritize by severity** — Focus on network-facing components
6. **Check SDK/chipset** — Vendor SDK often carries inherited vulnerabilities
7. **Verify patches** — Some vendors bump version strings without actually patching
8. **Generate report** — SBOM + CVE mapping + risk assessment
