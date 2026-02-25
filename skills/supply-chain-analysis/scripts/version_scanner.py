#!/usr/bin/env python3
"""
Embedded Firmware Component Version Scanner
Usage: python3 version_scanner.py <firmware_root_dir>

Scans extracted firmware filesystem for known open-source components,
extracts their versions, and flags outdated/vulnerable ones.
"""
import os
import re
import subprocess
import sys
import json
from pathlib import Path

COMPONENTS = [
    {
        'name': 'OpenSSL',
        'patterns': ['libssl.so*', 'libcrypto.so*', 'openssl'],
        'version_re': r'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)',
        'min_safe': '3.0.12',
    },
    {
        'name': 'BusyBox',
        'patterns': ['busybox'],
        'version_re': r'BusyBox\s+v(\d+\.\d+\.\d+)',
        'min_safe': '1.36.0',
    },
    {
        'name': 'dnsmasq',
        'patterns': ['dnsmasq'],
        'version_re': r'dnsmasq(?:[- ])(\d+\.\d+)',
        'min_safe': '2.89',
    },
    {
        'name': 'curl',
        'patterns': ['curl', 'libcurl.so*'],
        'version_re': r'curl[/ ](\d+\.\d+\.\d+)',
        'min_safe': '8.4.0',
    },
    {
        'name': 'Dropbear',
        'patterns': ['dropbear', 'dropbearmulti', 'dbclient'],
        'version_re': r'(?:dropbear|Dropbear)\s+v?(\d{4}\.\d+)',
        'min_safe': '2022.83',
    },
    {
        'name': 'lighttpd',
        'patterns': ['lighttpd'],
        'version_re': r'lighttpd[/ ](\d+\.\d+\.\d+)',
        'min_safe': '1.4.71',
    },
    {
        'name': 'OpenWrt uhttpd',
        'patterns': ['uhttpd'],
        'version_re': r'uhttpd[/ ](\d+\.\d+)',
        'min_safe': '2023.0',
    },
    {
        'name': 'miniupnpd',
        'patterns': ['miniupnpd'],
        'version_re': r'miniupnpd[/ ](\d+\.\d+)',
        'min_safe': '2.3.0',
    },
    {
        'name': 'SQLite',
        'patterns': ['libsqlite3.so*', 'sqlite3'],
        'version_re': r'(\d+\.\d+\.\d+)\s+\d{4}-\d{2}-\d{2}',
        'min_safe': '3.43.0',
    },
    {
        'name': 'Linux Kernel',
        'patterns': ['vmlinux*', 'zImage', 'uImage', 'bzImage'],
        'version_re': r'Linux version\s+(\d+\.\d+\.\d+)',
        'min_safe': '5.15.0',
    },
    {
        'name': 'GoAhead',
        'patterns': ['goahead', 'cgi-bin'],
        'version_re': r'GoAhead[/ ](\d+\.\d+\.\d+)',
        'min_safe': '5.2.0',
    },
    {
        'name': 'libxml2',
        'patterns': ['libxml2.so*'],
        'version_re': r'libxml2[/ ](\d+\.\d+\.\d+)',
        'min_safe': '2.11.0',
    },
    {
        'name': 'zlib',
        'patterns': ['libz.so*'],
        'version_re': r'(\d+\.\d+\.\d+)[^\d].*zlib|zlib[/ ](\d+\.\d+\.\d+)',
        'min_safe': '1.2.13',
    },
]


def find_files(root: str, pattern: str) -> list:
    import fnmatch
    found = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fnmatch.fnmatch(fn, pattern):
                found.append(os.path.join(dirpath, fn))
    return found


def extract_strings(filepath: str, max_bytes: int = 2 * 1024 * 1024) -> str:
    try:
        with open(filepath, 'rb') as f:
            data = f.read(max_bytes)
        # Extract printable ASCII strings of length >= 4
        result = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    result.append(''.join(current))
                current = []
        if len(current) >= 4:
            result.append(''.join(current))
        return '\n'.join(result)
    except Exception:
        return ''


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware_root_dir>")
        sys.exit(1)

    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"Error: {root} is not a directory")
        sys.exit(1)

    print(f"[*] Scanning firmware root: {root}")
    print(f"[*] Checking {len(COMPONENTS)} known components...\n")

    results = []

    for comp in COMPONENTS:
        for pattern in comp['patterns']:
            files = find_files(root, pattern)
            for f in files:
                strings_output = extract_strings(f)
                match = re.search(comp['version_re'], strings_output)
                if match:
                    version = match.group(1) if match.group(1) else match.group(2)
                    results.append({
                        'component': comp['name'],
                        'version': version,
                        'min_safe': comp['min_safe'],
                        'path': os.path.relpath(f, root),
                    })

    if results:
        # Deduplicate by component name (keep first found)
        seen = set()
        unique = []
        for r in results:
            key = f"{r['component']}:{r['version']}"
            if key not in seen:
                seen.add(key)
                unique.append(r)

        print(f"{'Component':<20} {'Version':<15} {'Min Safe':<15} {'Status':<10} Path")
        print('=' * 90)
        for r in unique:
            status = 'VULN' if r['version'] < r['min_safe'] else 'OK'
            marker = '[!]' if status == 'VULN' else '[+]'
            print(f"{marker} {r['component']:<17} {r['version']:<15} {r['min_safe']:<15} {status:<10} {r['path']}")

        vuln_count = sum(1 for r in unique if r['version'] < r['min_safe'])
        print(f"\n{'='*90}")
        print(f"Total components found: {len(unique)}")
        print(f"Potentially vulnerable: {vuln_count}")
    else:
        print("No known components detected.")
        print("Try manual string analysis on binary files.")


if __name__ == '__main__':
    main()
