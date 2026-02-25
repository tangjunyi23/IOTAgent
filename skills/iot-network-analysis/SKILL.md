---
name: iot-network-analysis
description: IoT network service and protocol vulnerability analysis. Use when analyzing network-facing services (UPnP, MQTT, CoAP, Telnet, RTSP), scanning device ports, testing network service implementations, or analyzing protocol-level vulnerabilities in IoT devices.
---

# IoT Network & Protocol Analysis

Analyze network services and protocol implementations in IoT devices for security weaknesses.

## Workflow

1. Port scan and service identification
2. Analyze exposed services
3. Test protocol-specific vulnerabilities
4. Check for information leakage

## Service Discovery

```bash
# Full port scan
nmap -sV -sC -p- <device_ip> -oN scan_results.txt

# UDP scan (UPnP, CoAP, SNMP)
nmap -sU -p 161,1900,5353,5683 <device_ip>

# Identify service versions
nmap -sV --version-intensity 5 <device_ip>
```

## Protocol-Specific Analysis

### UPnP/SSDP (Port 1900)

```bash
# Discover UPnP devices
gssdp-discover --timeout=3

# Get device description
curl http://<device>:49152/rootDesc.xml

# List SOAP actions (attack surface)
curl http://<device>:49152/rootDesc.xml | grep -i "action\|service"
```

UPnP vulnerabilities:
- SOAP action parameter injection → command injection
- AddPortMapping abuse → NAT manipulation
- Information disclosure via device description

### MQTT (Port 1883/8883)

```bash
# Subscribe to all topics (no auth)
mosquitto_sub -h <device_ip> -t "#" -v

# Check for anonymous access
mosquitto_pub -h <device_ip> -t "test" -m "probe"

# Common IoT MQTT topics
# device/+/status, device/+/command, home/+/set
```

MQTT vulnerabilities:
- No authentication required
- Sensitive data in plaintext topics
- Command injection via topic payloads
- Wildcard subscription to all topics

### Telnet (Port 23/2323)

```bash
# Check for open telnet
nmap -p 23,2323 --script telnet-brute <device_ip>

# Hidden telnet (common in cameras)
nmap -p 9527,23456 <device_ip>
```

### RTSP (Port 554) - IP Cameras

```bash
# Probe RTSP streams
nmap --script rtsp-url-brute -p 554 <device_ip>

# Common RTSP paths
curl rtsp://<device_ip>/live/ch0
curl rtsp://<device_ip>/Streaming/Channels/1
curl rtsp://admin:admin@<device_ip>/cam/realmonitor
```

### CoAP (Port 5683)

```bash
# CoAP discovery
coap-client -m get coap://<device_ip>/.well-known/core

# Read resources
coap-client -m get coap://<device_ip>/sensor/temperature
```

### SNMP (Port 161)

```bash
# Community string bruteforce
snmpwalk -v2c -c public <device_ip>
snmpwalk -v2c -c private <device_ip>

# Get system info
snmpget -v2c -c public <device_ip> 1.3.6.1.2.1.1.1.0
```

## Common Network Service Weaknesses

| Issue | Impact | Check |
|-------|--------|-------|
| Unauth'd service access | Full device control | Try connecting without credentials |
| Plaintext protocols | Credential sniffing | Check for HTTP (not HTTPS), Telnet, unencrypted MQTT |
| Verbose error messages | Information leak | Send malformed requests |
| Missing rate limiting | Brute force | Attempt rapid login attempts |
| Default SNMP community | Full read/write | Try "public"/"private" strings |

## CWE References

- **CWE-319**: Cleartext Transmission of Sensitive Information
- **CWE-200**: Exposure of Sensitive Information
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-668**: Exposure of Resource to Wrong Sphere
