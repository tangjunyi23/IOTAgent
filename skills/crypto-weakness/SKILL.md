---
name: crypto-weakness
description: Cryptographic weakness and insecure crypto implementation hunting in IoT firmware. Use when analyzing encryption implementations, TLS/SSL configurations, key management, random number generation, or any cryptographic operations in embedded device firmware. Triggers on crypto analysis, weak encryption, insecure TLS, or key management tasks.
---

# Cryptographic Weakness Hunting

Find weak or broken cryptographic implementations in IoT firmware.

## Workflow

1. Identify crypto library usage
2. Check TLS/SSL configuration
3. Analyze key management
4. Verify random number generation
5. Check for known weak algorithms

## Crypto Library Detection

```bash
# Check linked crypto libraries
readelf -d <binary> | grep -i "ssl\|crypto\|mbedtls\|wolfssl\|openssl"
ldd <binary> 2>/dev/null | grep -i "ssl\|crypto"

# Find crypto-related strings
strings <binary> | grep -iE "aes|des|rsa|sha|md5|rc4|ssl|tls|encrypt|decrypt|cipher|hmac"

# Check OpenSSL version (often outdated in IoT)
strings <binary> | grep -i "openssl"
find extracted_fs/ -name "libssl*" -o -name "libcrypto*" | xargs strings | grep "OpenSSL"
```

## Weakness Categories

### 1. Weak Algorithms
| Algorithm | Status | Why |
|-----------|--------|-----|
| MD5 | Broken | Collision attacks |
| SHA-1 | Deprecated | Theoretical collisions |
| DES/3DES | Deprecated | Small key/block size |
| RC4 | Broken | Biased output stream |
| RSA < 2048-bit | Weak | Factorable |
| ECB mode | Weak | Pattern preservation |

```bash
# Search for weak algorithm usage in binaries
strings <binary> | grep -iE "^(md5|des|rc4|ecb)"
# In Ghidra: search for MD5_Init, DES_ecb_encrypt, RC4
```

### 2. Hardcoded Keys/IVs

```bash
# Search for hex key patterns (16/32 bytes)
strings <binary> | grep -E "^[0-9a-fA-F]{32,64}$"

# Search for base64-encoded keys
strings <binary> | grep -E "^[A-Za-z0-9+/]{22,44}={0,2}$"

# Common hardcoded key indicators in decompiled code:
# key[] = {0x01, 0x02, 0x03, ...}
# iv = "0000000000000000"
# password = "default_key"
```

### 3. Weak Random Number Generation

```c
// VULNERABLE patterns in decompiled code:
srand(time(NULL));           // Predictable seed
rand() % range;              // Weak PRNG
getpid() as random source;   // Predictable
time(NULL) for session token; // Guessable
```

### 4. TLS/SSL Issues

```bash
# Test TLS configuration of running device
nmap --script ssl-enum-ciphers -p 443 <device_ip>

# Check certificate
openssl s_client -connect <device_ip>:443 </dev/null 2>/dev/null | openssl x509 -text

# Look for self-signed certs in firmware
find extracted_fs/ -name "*.pem" -o -name "*.crt" | while read f; do
    echo "=== $f ==="
    openssl x509 -in "$f" -text -noout 2>/dev/null | grep -E "Issuer|Subject|Not After|Signature Algorithm"
done
```

### 5. Firmware Update Verification

```bash
# Check if firmware updates are signed
# Look for signature verification in update handler
strings <update_binary> | grep -iE "verify|signature|rsa|ecdsa|sha256|digest"

# If no verification → firmware can be replaced with malicious version
```

## CWE References

- **CWE-327**: Use of a Broken or Risky Cryptographic Algorithm
- **CWE-328**: Use of Weak Hash
- **CWE-330**: Use of Insufficiently Random Values
- **CWE-326**: Inadequate Encryption Strength
- **CWE-295**: Improper Certificate Validation
- **CWE-347**: Improper Verification of Cryptographic Signature
