---
name: buffer-overflow
description: Buffer overflow vulnerability hunting in IoT embedded binaries. Use when reverse-engineering ARM/MIPS/x86 binaries for stack-based or heap-based overflow vulnerabilities, analyzing unsafe memory operations (strcpy, sprintf, gets, memcpy), checking binary protections (NX, ASLR, canary), or building overflow PoCs for embedded targets.
---

# Buffer Overflow Hunting

Find memory corruption vulnerabilities in embedded device binaries.

## Workflow

1. Check binary protections (`checksec`)
2. Identify dangerous function imports
3. Trace user-controlled input to unsafe memory operations
4. Determine buffer sizes and overflow feasibility
5. Build PoC (crash → control EIP/PC → code execution)

## Protection Check

```bash
checksec --file=<binary>
# Key fields:
#   RELRO: Full/Partial/No
#   Stack Canary: Yes/No
#   NX: Yes/No
#   PIE: Yes/No
#   ASLR: Check /proc/sys/kernel/randomize_va_space on device
```

Most IoT devices: **No canary, No ASLR, No NX, No PIE** → trivially exploitable.

## Dangerous Functions

| Function | Risk | Safer Alternative |
|----------|------|-------------------|
| `strcpy(dst, src)` | No bounds check | `strncpy` |
| `strcat(dst, src)` | No bounds check | `strncat` |
| `sprintf(buf, fmt, ...)` | No bounds check | `snprintf` |
| `gets(buf)` | Never safe | `fgets` |
| `scanf("%s", buf)` | No bounds check | `scanf("%Ns", buf)` |
| `memcpy(dst, src, n)` | Unsafe if n user-controlled | Validate n |
| `read(fd, buf, n)` | Unsafe if n > buf size | Validate n |

## Binary Analysis in Ghidra

```python
# Find all calls to dangerous functions and their callers
dangerous = ["strcpy", "strcat", "sprintf", "gets", "scanf", "memcpy", "read"]
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getName().lower() in dangerous:
        print(f"\n=== {func.getName()} @ {func.getEntryPoint()} ===")
        for ref in getReferencesTo(func.getEntryPoint()):
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller:
                print(f"  Called from: {caller.getName()} @ {ref.getFromAddress()}")
```

## Architecture-Specific Notes

### ARM
- Return address in LR register, pushed to stack in function prologue
- Overflow target: saved LR on stack
- Thumb/ARM mode: ensure payload address has correct LSB
- Typical gadget: `POP {R0-R3, PC}` or `BLX R3`

### MIPS
- Return address in `$ra`, stored on stack
- **Cache coherency**: I-cache and D-cache are separate
- Shellcode needs `sleep(1)` or cache flush before execution
- Typical gadget: `lw $ra, offset($sp); jr $ra`
- **Null byte issue**: MIPS addresses often contain 0x00

### x86 (rare in IoT)
- Standard ROP: overwrite saved EBP + EIP on stack
- `ret2libc`: `system()` + "/bin/sh" string

## PoC Template

```python
import socket
import struct

target_ip = "<device_ip>"
target_port = <port>

# Architecture-specific pack
def p32(addr):
    return struct.pack("<I", addr)  # Little-endian 32-bit

# Buffer overflow payload
offset = <crash_offset>  # Found via pattern
payload = b"A" * offset
payload += p32(0x<return_address>)  # Overwrite saved return address
payload += b"C" * 100  # Padding/shellcode space

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, target_port))
sock.send(payload)
print(f"Sent {len(payload)} bytes")
```

## References

- **Architecture deep dive**: See [references/arch-specifics.md](references/arch-specifics.md) for ARM/MIPS exploitation details
- **ROP gadget finder script**: Run `scripts/find_gadgets.py` for automated gadget search
