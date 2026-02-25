---
name: reverse-engineering
description: Binary reverse engineering and code analysis for IoT firmware using Ghidra and Joern. Use when performing binary analysis with Ghidra headless mode (decompiling, cross-references, imports, dangerous calls), CPG-based vulnerability hunting with Joern (taint analysis, data flow tracking, pattern matching), or any reverse engineering task on ARM/MIPS/x86 embedded binaries. Triggers on tasks requiring decompilation, interprocedural analysis, or static vulnerability scanning of firmware binaries.
---

# Reverse Engineering (Ghidra + Joern)

Combined reverse engineering skill using Ghidra for binary decompilation and Joern for Code Property Graph analysis.

## Workflow

1. **Download binary** — `download_from_remote` to fetch target binary from remote server
2. **Ghidra analysis** — Decompile, list functions, find dangerous calls, trace cross-references
3. **Joern CPG analysis** — Import into CPG, query vulnerability patterns, trace taint flows
4. **Validate findings** — Cross-reference Ghidra decompilation with Joern data flow results

---

## Part 1: Ghidra Headless Analysis

### Quick Start

```bash
# One-shot: import + analyze + run script
analyzeHeadless /tmp/ghidra_proj Project \
    -import <binary> \
    -postScript <script.py> \
    -deleteProject 2>&1
```

### Decompile Functions

```python
from ghidra.app.decompiler import DecompInterface

decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()

# Decompile all (limit 50)
count = 0
for func in fm.getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompileCompleted():
        print(f"=== {func.getName()} @ {func.getEntryPoint()} ===")
        print(result.getDecompiledFunction().getC())
    count += 1
    if count > 50:
        break

# Decompile specific function
target = "<FUNCTION_NAME>"
for func in fm.getFunctions(True):
    if func.getName() == target:
        result = decomp.decompileFunction(func, 60, monitor)
        if result.decompileCompleted():
            print(result.getDecompiledFunction().getC())
        break
```

### Find Dangerous Function Calls

```python
dangerous = ["system", "popen", "execve", "strcpy", "sprintf",
             "gets", "strcat", "scanf", "memcpy", "doSystemCmd"]
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    name = func.getName().lower()
    if any(d in name for d in dangerous):
        print(f"\nDANGEROUS: {func.getName()} @ {func.getEntryPoint()}")
        for ref in getReferencesTo(func.getEntryPoint()):
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller:
                print(f"  Called from: {caller.getName()} @ {ref.getFromAddress()}")
```

### String Cross-References

```python
import re
pattern = "<SEARCH_PATTERN>"  # e.g., "password|admin|system"
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = str(data.getValue())
        if re.search(pattern, val, re.IGNORECASE):
            addr = data.getAddress()
            print(f"\nSTRING: '{val}' @ {addr}")
            for ref in getReferencesTo(addr):
                func = fm.getFunctionContaining(ref.getFromAddress())
                if func:
                    print(f"  Referenced by: {func.getName()} @ {ref.getFromAddress()}")
```

### Ghidra Tips

- **Large binaries**: Use `-analysisTimeoutPerFile` flag (default 300s)
- **Wrong arch detection**: Use `-processor` flag (e.g., `-processor ARM:LE:32:v7`)
- **Stripped binaries**: Ghidra auto-creates function entries, names will be `FUN_xxxxx`

---

## Part 2: Joern CPG Analysis

### Quick Start

```bash
# Import C source directory into CPG
joern-parse /path/to/source --output /tmp/firmware.cpg

# Launch Joern and load CPG
joern
importCpg("/tmp/firmware.cpg")
```

### Dangerous Function Calls

```scala
// Find all calls to dangerous functions
cpg.call.name("system|popen|execve|exec|strcpy|strcat|sprintf|gets|scanf|sscanf|vsprintf").l

// Find strcpy with non-constant source
cpg.call.name("strcpy").argument(2).whereNot(_.isLiteral).l
```

### Taint Analysis (Source → Sink)

```scala
// Define sources: user-controllable input
val sources = cpg.call.name("recv|read|fread|fgets|getenv|scanf|recvfrom").argument(1)

// Define sinks: dangerous execution
val sinks = cpg.call.name("system|popen|execve|exec").argument(1)

// Find taint flows
sinks.reachableByFlows(sources).p
```

### Command Injection Patterns

```scala
val userInput = cpg.call.name("recv|read|getenv|fgets").argument(1)
val cmdExec = cpg.call.name("system|popen|execve").argument(1)
cmdExec.reachableByFlows(userInput).p
```

### Buffer Overflow Patterns

```scala
cpg.call.name("strcpy|strcat|gets|sprintf")
  .where(_.argument(1).isIdentifier)
  .l
```

### Authentication & Hardcoded Credentials

```scala
cpg.call.name("strcmp|strncmp")
  .where(_.argument.isLiteral)
  .l
```

### Non-Interactive Batch Mode

```bash
joern --script /path/to/query.sc --params cpgFile=/tmp/firmware.cpg
```

### Joern Tips

- **Binary CPG limitations**: Binary-level CPG has less precise type info than source CPG
- **Large codebases**: Use `--max-num-def` to limit analysis scope
- **Joern memory**: Set `JAVA_OPTS="-Xmx4g"` for large firmware images

## References

- **Ghidra script templates**: See [references/ghidra-scripts.md](references/ghidra-scripts.md) for vulnerability scanner, call graph tracer, NVRAM tracker
- **CPG query cookbook**: See [references/cpg-queries.md](references/cpg-queries.md) for IoT-specific query patterns
- **Batch scan script**: Run `scripts/joern_batch_scan.py` to scan extracted filesystem for vulnerable binaries
