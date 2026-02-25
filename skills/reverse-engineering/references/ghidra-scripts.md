# Ghidra Script Templates

## Vulnerability Pattern Scanner
```python
"""Scan for common vulnerability patterns in decompiled code."""
from ghidra.app.decompiler import DecompInterface
import re

decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()

vuln_patterns = [
    (r'system\s*\(.*\+', "Potential command injection (variable in system())"),
    (r'sprintf\s*\([^,]+,\s*"[^"]*%s', "Potential buffer overflow (sprintf with %s)"),
    (r'strcpy\s*\(', "Unsafe strcpy usage"),
    (r'gets\s*\(', "Extremely unsafe gets() call"),
    (r'strcat\s*\(', "Potentially unsafe strcat"),
]

for func in fm.getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if not result.decompileCompleted():
        continue
    code = result.getDecompiledFunction().getC()
    for pattern, desc in vuln_patterns:
        matches = re.findall(pattern, code)
        if matches:
            print(f"[VULN] {desc}")
            print(f"  Function: {func.getName()} @ {func.getEntryPoint()}")
            for m in matches[:3]:
                print(f"  Match: {m}")
```

## Call Graph Tracer
```python
"""Trace call paths from HTTP handler to dangerous functions."""
from collections import deque

target_sinks = ["system", "popen", "execve", "doSystemCmd"]
fm = currentProgram.getFunctionManager()

def get_callees(func):
    callees = set()
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        for ref in inst.getReferencesFrom():
            if ref.getReferenceType().isCall():
                callee = fm.getFunctionAt(ref.getToAddress())
                if callee:
                    callees.add(callee)
    return callees

# BFS from each function to find paths to sinks
for func in fm.getFunctions(True):
    queue = deque([(func, [func.getName()])])
    visited = set()
    while queue:
        current, path = queue.popleft()
        if current.getName() in visited:
            continue
        visited.add(current.getName())
        if current.getName().lower() in target_sinks:
            print(f"PATH TO SINK: {' -> '.join(path)}")
            break
        for callee in get_callees(current):
            if callee.getName() not in visited:
                queue.append((callee, path + [callee.getName()]))
```

## NVRAM Usage Tracker
```python
"""Find all nvram_get/nvram_set calls and their key parameters."""
from ghidra.app.decompiler import DecompInterface
import re

decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()

nvram_funcs = ["nvram_get", "nvram_set", "nvram_safe_get", "acosNvramConfig_get"]

for func in fm.getFunctions(True):
    if not any(n in func.getName() for n in nvram_funcs):
        continue
    print(f"\n=== {func.getName()} references ===")
    for ref in getReferencesTo(func.getEntryPoint()):
        caller = fm.getFunctionContaining(ref.getFromAddress())
        if caller:
            result = decomp.decompileFunction(caller, 30, monitor)
            if result.decompileCompleted():
                code = result.getDecompiledFunction().getC()
                # Find the nvram key strings near the call
                for m in re.finditer(rf'{func.getName()}\s*\(\s*"([^"]*)"', code):
                    print(f"  {caller.getName()}: key=\"{m.group(1)}\"")
```
