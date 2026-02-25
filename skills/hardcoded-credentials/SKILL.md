---
name: hardcoded-credentials
description: Hardcoded credential and backdoor hunting in IoT firmware. Use when searching for default passwords, API keys, private keys, certificates, debug accounts, hidden backdoor accounts, or embedded secrets in firmware filesystems and binaries. Triggers on credential hunting, password discovery, secret scanning, or backdoor detection tasks.
---

# Hardcoded Credentials & Backdoor Hunting

Find embedded secrets, default credentials, and backdoor accounts in firmware.

## Workflow

1. Scan filesystem for credential files
2. Search binaries for password strings
3. Check for known default credentials
4. Identify backdoor indicators
5. Validate findings

## Filesystem Scan

```bash
# Password files
cat extracted_fs/etc/passwd
cat extracted_fs/etc/shadow
# Look for non-standard accounts with shells
grep -v "nologin\|false" extracted_fs/etc/passwd

# Configuration files with credentials
grep -rni "password\|passwd\|pwd\|secret\|credential\|api.key\|token\|auth" \
    extracted_fs/etc/ --include="*.conf" --include="*.cfg" --include="*.ini" --include="*.json"

# SSH keys
find extracted_fs/ -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "*.pem" -o -name "*.key"

# Certificates
find extracted_fs/ -name "*.crt" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks"

# Database files
find extracted_fs/ -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3"

# Web configuration
grep -rni "admin\|root\|default\|guest\|user\|login" \
    extracted_fs/www/ extracted_fs/var/www/ 2>/dev/null
```

## Binary String Extraction

```bash
# Extract printable strings and search
strings -n 6 <binary> | grep -iE "password|passwd|admin|root|secret|key|token|auth|login|default"

# Wide strings (UTF-16)
strings -n 6 -e l <binary> | grep -iE "password|admin|secret"

# Search for base64-encoded secrets
strings <binary> | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$" | while read s; do
    decoded=$(echo "$s" | base64 -d 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "Base64: $s -> $decoded"
    fi
done
```

## Backdoor Indicators

| Indicator | Check Method |
|-----------|-------------|
| Hidden telnet/SSH port | `grep -r "23\|2323\|22\|2222" init.d/ ; strings <binary> \| grep -i telnet` |
| Debug interface | `strings <binary> \| grep -i "debug\|diag\|test\|backdoor"` |
| Hidden URL paths | `strings httpd \| grep -E "^/"` |
| Hardcoded MAC check | `strings <binary> \| grep -iE "[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}"` |
| Factory reset accounts | Check if `/etc/passwd` is regenerated from binary |

## Known Default Credentials Database

| Vendor | Username | Password | Service |
|--------|----------|----------|---------|
| D-Link | admin | (blank) | HTTP |
| TP-Link | admin | admin | HTTP |
| Netgear | admin | password | HTTP |
| Hikvision | admin | 12345 | HTTP/RTSP |
| Dahua | admin | admin | HTTP/RTSP |
| Ubiquiti | ubnt | ubnt | SSH |
| MikroTik | admin | (blank) | SSH/HTTP |
| ZTE | admin | admin | HTTP |
| Zyxel | admin | 1234 | HTTP |

## CWE References

- **CWE-798**: Use of Hardcoded Credentials
- **CWE-259**: Use of Hard-coded Password
- **CWE-321**: Use of Hard-coded Cryptographic Key
- **CWE-912**: Hidden Functionality (Backdoor)
