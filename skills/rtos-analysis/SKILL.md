---
name: rtos-analysis
description: Real-Time Operating System vulnerability analysis for embedded devices running FreeRTOS, VxWorks, ThreadX, eCos, and other RTOS platforms
---

# RTOS Vulnerability Analysis

## RTOS Identification

### Fingerprinting via Strings
```bash
# Search for RTOS identifiers in firmware
strings firmware.bin | grep -iE "freertos|vxworks|threadx|ecos|nucleus|zephyr|rtems|ucos|liteos|mbed.os"

# FreeRTOS-specific markers
strings firmware.bin | grep -iE "xTaskCreate|vTaskDelay|xQueue|xSemaphore|pvPortMalloc|FreeRTOS"

# VxWorks-specific markers
strings firmware.bin | grep -iE "taskSpawn|semTake|msgQSend|wdbAgent|VxWorks|Wind River"

# ThreadX-specific markers
strings firmware.bin | grep -iE "tx_thread_create|tx_queue|tx_semaphore|ThreadX|Express Logic"
```

### RTOS Version Detection
| RTOS | Version Strings | Key Functions |
|------|----------------|---------------|
| FreeRTOS | `FreeRTOS V`, `FreeRTOS Kernel V` | `xTaskCreate`, `vTaskStartScheduler` |
| VxWorks | `VxWorks`, `Wind River`, `WIND version` | `taskSpawn`, `taskInit` |
| ThreadX | `ThreadX`, `_tx_version_id` | `tx_thread_create`, `tx_kernel_enter` |
| eCos | `eCos`, `Red Hat eCos` | `cyg_thread_create`, `cyg_mutex_lock` |
| Zephyr | `zephyr`, `Zephyr RTOS` | `k_thread_create`, `k_sem_give` |
| LiteOS | `Huawei LiteOS`, `LOS_` | `LOS_TaskCreate`, `LOS_SemCreate` |

## Common RTOS Vulnerability Classes

### 1. Task/Thread Security Issues

**Priority Inversion & Starvation**
- Identify tasks with mismatched priorities accessing shared resources
- Look for mutex usage without priority inheritance enabled
- In Ghidra, trace `xSemaphoreCreateMutex` vs `xSemaphoreCreateBinary`

**Stack Overflow in Tasks**
```
# FreeRTOS: Check configured stack sizes
# Look for xTaskCreate calls — 4th parameter is stack depth
# Typical vulnerable pattern: stack depth < 256 words for complex tasks

# VxWorks: taskSpawn stack size (parameter 5)
# If stack size < 4096 for tasks handling network input → potential overflow
```

**Unsafe Task Deletion**
- `vTaskDelete()` without cleaning up held mutexes → deadlocks
- `taskDelete()` in VxWorks without releasing semaphores → resource leaks

### 2. Memory Management Vulnerabilities

**Heap Overflow**
```
# FreeRTOS heap implementations (heap_1 through heap_5)
# heap_1: No free — safest but wasteful
# heap_2: No coalescing — fragmentation attacks
# heap_3: Wraps malloc — inherits libc vulnerabilities
# heap_4: First-fit with coalescing — metadata corruption possible
# heap_5: Like heap_4 with non-contiguous regions

# Check which heap implementation is used:
strings firmware.bin | grep -i "heap_[1-5]"
grep -c "pvPortMalloc\|vPortFree" disassembly.txt
```

**Double Free**
- Search for multiple `vPortFree()` calls on same pointer without reassignment
- VxWorks `free()` on same block → heap metadata corruption

**Use-After-Free**
- Task communication via pointers to freed buffers
- Queue messages containing dangling pointers after `vPortFree`

### 3. Inter-Process Communication Flaws

**Message Queue Overflow**
- Queues created with insufficient depth for burst traffic
- No bounds checking on message content before enqueue
- `xQueueSend` without timeout → task blocks indefinitely

**Shared Memory Without Synchronization**
- Global variables accessed from multiple tasks without mutex protection
- ISR and task accessing same buffer without critical sections

**Unsafe Callback Registration**
```
# Look for function pointer tables that can be overwritten
# Timer callbacks: xTimerCreate → callback address in heap
# Software watchdog callbacks
# Interrupt handler tables in writable memory
```

### 4. Network Stack Vulnerabilities

**lwIP (Lightweight IP) — Common in FreeRTOS**
```bash
# Version detection
strings firmware.bin | grep -i "lwip\|lwIP" 
# Check for known CVEs against detected version
# Common issues: buffer overflow in DHCP, DNS rebinding, TCP sequence prediction
```

**VxWorks Network Stack**
- URGENT/11 vulnerabilities (CVE-2019-12256 through CVE-2019-12263)
- IPnet stack: TCP urgent pointer parsing, DHCP offer handling
- Check: `strings firmware.bin | grep -i "ipnet\|interpeak"`

| Stack | Common CVEs | Detection |
|-------|------------|-----------|
| lwIP | CVE-2020-22283, CVE-2020-22284 | `lwip`, `LWIP_` macros |
| uIP | CVE-2020-17437, CVE-2020-17440 | `uip_`, `UIP_CONF` |
| FNET | CVE-2020-17467, CVE-2020-17468 | `fnet_`, `FNET_CFG` |
| PicoTCP | CVE-2020-17441, CVE-2020-17443 | `pico_`, `PICO_` |
| Nut/Net | CVE-2020-25107 | `Nut/OS`, `NutTcp` |

### 5. Bootloader & Firmware Update Issues

**Unsigned Firmware Updates**
- Check OTA update handler for signature verification
- Look for: `mbedtls_pk_verify`, `RSA_verify`, crypto verification functions
- If absent → firmware can be replaced with malicious image

**Secure Boot Bypass**
- Trace boot sequence: ROM bootloader → secondary bootloader → RTOS image
- Check if signature verification in bootloader can be bypassed via:
  - UART/JTAG access during boot
  - Glitching attack on verification routine
  - Downgrade to older unsigned firmware version

## RTOS-Specific Exploitation

### FreeRTOS Exploitation
```
Attack Surface Priority:
1. Network input handlers (lwIP callbacks, MQTT parsers, HTTP handlers)
2. pvPortMalloc/vPortFree → heap metadata corruption
3. Task stack overflow → control flow hijack
4. Timer callback pointers → overwrite for code execution

Exploitation Notes:
- FreeRTOS heap metadata is simpler than glibc → easier to exploit
- No ASLR on most MCU targets (Cortex-M, etc.)
- No NX/DEP on Cortex-M0/M3 → stack buffer overflow = direct shellcode
- Cortex-M4/M7 with MPU: check if MPU is actually configured
```

### VxWorks Exploitation
```
Attack Surface Priority:
1. WDB agent (debug agent, often left enabled in production)
2. RPC services (portmapper, mountd)
3. Web server (typically on port 80)
4. SNMP agent
5. FTP/Telnet services

Key Checks:
- WDB agent on UDP port 17185 → remote code execution
  nmap -sU -p 17185 <target>
- taskSpawn via WDB → spawn arbitrary task with any function
- Memory read/write via WDB → dump credentials, modify config
```

### ThreadX Exploitation
```
Attack Surface:
1. NetX/NetX Duo network stack
2. FileX filesystem handling
3. USBX USB stack
4. GUIX graphics (if GUI-enabled device)

Memory Layout:
- ThreadX byte pools / block pools
- tx_byte_allocate → similar to malloc, first-fit
- Metadata corruption in byte pool → arbitrary write primitive
```

## Analysis Workflow

1. **Identify RTOS** — String analysis, function names, binary patterns
2. **Determine version** — Match against known CVE databases
3. **Map attack surface** — Network services, IPC mechanisms, debug interfaces
4. **Analyze memory protection** — MPU config, stack canaries, heap hardening
5. **Check crypto implementation** — Hardcoded keys, weak RNG (especially on MCUs without TRNG)
6. **Test update mechanism** — Signature verification, rollback protection, encrypted transport
7. **Examine debug interfaces** — JTAG/SWD left accessible, WDB agent, GDB stub

## Useful Ghidra Scripts for RTOS Analysis
```python
# Find FreeRTOS task creation calls and extract task parameters
# In Ghidra Python console:
from ghidra.program.model.symbol import SymbolType
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if "TaskCreate" in func.getName() or "taskSpawn" in func.getName():
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            print(f"Task created at: {ref.getFromAddress()}")
```

## References
- [FreeRTOS Security Updates](https://www.freertos.org/security/overview.html)
- [URGENT/11 — VxWorks TCP/IP Stack Vulnerabilities](https://www.armis.com/urgent11/)  
- [Amnesia:33 — TCP/IP Stack Vulnerabilities](https://www.forescout.com/research-labs/amnesia33/)
- [RTOS Exploit Mitigations Comparison](https://www.embedded.com/rtos-security-comparison/)
