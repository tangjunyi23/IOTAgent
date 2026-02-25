#!/usr/bin/env python3
"""
Simple ROP gadget finder for ARM/MIPS binaries.
Usage: python3 find_gadgets.py <binary_path>

Searches for common useful gadgets in the binary.
"""
import sys
import subprocess
import re
from pathlib import Path


def find_gadgets_objdump(binary: str, arch: str) -> list[dict]:
    """Use objdump to find ROP gadgets."""
    gadgets = []

    if arch == "arm":
        # ARM: look for POP {.., PC} and BLX patterns
        patterns = [
            (r'([0-9a-f]+):\s+.+pop\s+\{.*pc\}', "POP {.., PC}"),
            (r'([0-9a-f]+):\s+.+blx\s+r\d', "BLX Rx"),
            (r'([0-9a-f]+):\s+.+mov\s+pc,\s+lr', "MOV PC, LR"),
        ]
        tool = "arm-linux-gnueabi-objdump"
    elif arch == "mips":
        # MIPS: look for jr $ra and jalr patterns
        patterns = [
            (r'([0-9a-f]+):\s+.+jr\s+\$ra', "JR $ra"),
            (r'([0-9a-f]+):\s+.+jalr\s+\$', "JALR"),
            (r'([0-9a-f]+):\s+.+lw\s+\$ra,', "LW $ra"),
            (r'([0-9a-f]+):\s+.+addiu\s+\$sp,\$sp,', "ADDIU $sp"),
        ]
        tool = "mips-linux-gnu-objdump"
    else:
        # x86: look for ret
        patterns = [
            (r'([0-9a-f]+):\s+c3\s+ret', "RET"),
            (r'([0-9a-f]+):\s+.+pop\s+', "POP"),
        ]
        tool = "objdump"

    try:
        result = subprocess.run(
            [tool, "-d", binary],
            capture_output=True, text=True, timeout=60
        )
        disasm = result.stdout
    except FileNotFoundError:
        # Fallback to generic objdump
        result = subprocess.run(
            ["objdump", "-d", binary],
            capture_output=True, text=True, timeout=60
        )
        disasm = result.stdout

    for pattern, name in patterns:
        for match in re.finditer(pattern, disasm, re.IGNORECASE):
            addr = int(match.group(1), 16)
            gadgets.append({
                "address": f"0x{addr:08x}",
                "type": name,
                "context": match.group(0).strip()
            })

    return gadgets


def detect_arch(binary: str) -> str:
    result = subprocess.run(
        ["file", binary], capture_output=True, text=True
    )
    output = result.stdout.lower()
    if "arm" in output:
        return "arm"
    elif "mips" in output:
        return "mips"
    elif "x86" in output or "i386" in output or "x86-64" in output:
        return "x86"
    return "unknown"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_path>")
        sys.exit(1)

    binary = sys.argv[1]
    if not Path(binary).exists():
        print(f"Error: {binary} not found")
        sys.exit(1)

    arch = detect_arch(binary)
    print(f"Binary: {binary}")
    print(f"Architecture: {arch}")
    print()

    gadgets = find_gadgets_objdump(binary, arch)
    print(f"Found {len(gadgets)} potential gadgets:")
    for g in gadgets[:50]:  # Limit output
        print(f"  {g['address']}  [{g['type']}]  {g['context']}")
    if len(gadgets) > 50:
        print(f"  ... and {len(gadgets) - 50} more")


if __name__ == "__main__":
    main()
