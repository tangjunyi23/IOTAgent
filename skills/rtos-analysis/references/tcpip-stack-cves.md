# RTOS Vulnerability Reference — TCP/IP Stack CVE Database

## Amnesia:33 (December 2020)
33 vulnerabilities across 4 open-source TCP/IP stacks used in millions of IoT devices.

### uIP (Contiki OS)
| CVE | Type | Impact | CVSS |
|-----|------|--------|------|
| CVE-2020-17437 | DNS response cache poisoning | Remote code execution | 8.1 |
| CVE-2020-17440 | IPv6 out-of-bounds read | Information disclosure | 7.5 |
| CVE-2020-17438 | TCP out-of-bounds write | Remote code execution | 7.0 |
| CVE-2020-17439 | DNS domain name parsing | Cache poisoning | 8.1 |

### PicoTCP
| CVE | Type | Impact | CVSS |
|-----|------|--------|------|
| CVE-2020-17441 | DNS response parsing overflow | Remote code execution | 8.2 |
| CVE-2020-17442 | IPv4 options parsing | Denial of service | 7.5 |
| CVE-2020-17443 | DNS domain name compression | Cache poisoning | 8.2 |
| CVE-2020-17444 | TCP options parsing | Denial of service | 5.3 |
| CVE-2020-17445 | IPv6 header parsing | Information disclosure | 5.3 |

### FNET
| CVE | Type | Impact | CVSS |
|-----|------|--------|------|
| CVE-2020-17467 | DNS response parsing | Cache poisoning | 8.2 |
| CVE-2020-17468 | IPv6 router advertisement | Denial of service | 5.3 |
| CVE-2020-17469 | IPv4 reassembly | Denial of service | 5.3 |
| CVE-2020-17470 | DNS TXID not random | Cache poisoning | 4.3 |

### Nut/Net
| CVE | Type | Impact | CVSS |
|-----|------|--------|------|
| CVE-2020-25107 | DNS response parsing overflow | Remote code execution | 9.8 |
| CVE-2020-25108 | ICMP payload parsing | Denial of service | 5.3 |
| CVE-2020-25109 | DNS domain name parsing | Remote code execution | 8.2 |
| CVE-2020-25110 | DNS response record parsing | Information disclosure | 5.3 |

## URGENT/11 (July 2019)
11 vulnerabilities in VxWorks IPnet TCP/IP stack, affecting ~200 million devices.

| CVE | Type | Impact | CVSS |
|-----|------|--------|------|
| CVE-2019-12256 | Stack overflow in IPv4 options | Remote code execution | 9.8 |
| CVE-2019-12255 | TCP Urgent Pointer integer underflow | Remote code execution | 9.8 |
| CVE-2019-12260 | TCP Urgent Pointer state confusion | Remote code execution | 9.8 |
| CVE-2019-12261 | TCP Urgent Pointer DoS | Remote code execution | 8.8 |
| CVE-2019-12263 | DHCP race condition | Remote code execution | 8.1 |
| CVE-2019-12257 | DHCP offer/ACK heap overflow | Remote code execution | 8.8 |
| CVE-2019-12258 | TCP connection DoS | Denial of service | 7.5 |
| CVE-2019-12259 | IGMP NULL pointer deref | Denial of service | 7.5 |
| CVE-2019-12262 | Logical flaw via malformed TCP | Denial of service | 7.1 |
| CVE-2019-12264 | IPv4 assignment via DHCP | Denial of service | 5.6 |
| CVE-2019-12265 | IGMP info disclosure | Information disclosure | 5.4 |

## DNSpooq (January 2021)
7 vulnerabilities in dnsmasq, affecting embedded Linux with RTOS components.

| CVE | Type | Impact | CVSS |
|-----|------|--------|------|
| CVE-2020-25681 | Heap overflow in DNSSEC | Remote code execution | 8.1 |
| CVE-2020-25682 | Buffer overflow in DNSSEC | Remote code execution | 8.1 |
| CVE-2020-25683 | Heap overflow in DNSSEC | Remote code execution | 5.9 |
| CVE-2020-25684 | Insufficient address validation | Cache poisoning | 3.7 |
| CVE-2020-25685 | Weak hash in DNS resource records | Cache poisoning | 3.7 |
| CVE-2020-25686 | Multiple DNS queries for same name | Cache poisoning | 3.7 |
| CVE-2020-25687 | Heap overflow in DNSSEC | Remote code execution | 5.9 |

## Ripple20 (June 2020)
19 vulnerabilities in Treck TCP/IP stack.

| CVE | Most Critical | Impact | CVSS |
|-----|--------------|--------|------|
| CVE-2020-11896 | IPv4 tunneling — heap overflow | Remote code execution | 10.0 |
| CVE-2020-11897 | IPv6 — out-of-bounds write | Remote code execution | 10.0 |
| CVE-2020-11901 | DNS resolver — heap overflow | Remote code execution | 9.0 |
| CVE-2020-11898 | IPv4/ICMPv4 — info disclosure | Information disclosure | 9.1 |

## FreeRTOS Vulnerabilities

| CVE | Component | Type | Impact |
|-----|-----------|------|--------|
| CVE-2018-16522 | TCP/IP | Remote code execution | Critical |
| CVE-2018-16524 | TCP/IP | Information disclosure | High |
| CVE-2018-16525 | TCP/IP | Remote code execution | Critical |
| CVE-2018-16526 | TCP/IP | Denial of service | High |
| CVE-2018-16527 | TCP/IP | Information disclosure | High |
| CVE-2018-16528 | TCP/IP | Remote code execution | Critical |
| CVE-2021-31571 | ARMv7-M MPU | Privilege escalation | High |
| CVE-2021-31572 | ARMv7-M MPU | Privilege escalation | High |

## Detection Methodology

```bash
# Step 1: Identify which TCP/IP stack is in use
strings firmware.bin | grep -iE "lwip|uip|picotcp|fnet|treck|ipnet|cyclone"

# Step 2: Match stack name to vulnerability database above

# Step 3: Verify exploitability
# - Is the vulnerable code path reachable from network?
# - Are there any vendor patches applied?
# - What network services are exposed?

# Step 4: Test with PoC
# Many Amnesia:33 and Ripple20 PoCs available on GitHub
# URGENT/11 PoCs from Armis research
```
