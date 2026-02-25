# Vendor-Specific Command Injection Patterns

## D-Link

Common vulnerable endpoints:
- `/HNAP1/` - HNAP protocol handler, XML parameter injection
- `/cgi-bin/webproc` - proc handler with `getpage`/`set` commands
- `/goform/formPing` - Ping diagnostic, `pingAddr` parameter

Known sinks: `twsystem()`, `csteSystem()`, `lxmldbc_system()`

## TP-Link

Common vulnerable endpoints:
- `/cgi?1&5` - Numeric endpoint scheme
- `/cgi-bin/luci` - OpenWrt LuCI interface
- `/userRpm/PingIfr498.htm` - Ping diagnostic

Known sinks: `popen()`, `doSystemCmd()`, `backGo()`

## Netgear

Common vulnerable endpoints:
- `/setup.cgi` - Main configuration handler
- `/debug.htm` - Debug interface (sometimes accessible)
- `/hedwig.cgi` - D-Link/Netgear hedwig handler
- `/currentsetting.htm` - Sometimes exposes device info

Known sinks: `system()`, `acosNvramConfig_get()` → `system()`

## ASUS

Common vulnerable endpoints:
- `/appGet.cgi` - App API
- `/apply.cgi` - Configuration apply
- `/start_apply.htm` - Alternate apply endpoint

Known sinks: `system()`, `nvram_set()` → `system()`, `doSystem()`

## Hikvision / Dahua (IP Cameras)

Common vulnerable endpoints:
- `/ISAPI/` - ISAPI interface
- `/SDK/webLanguage` - Language file upload
- `/cgi-bin/magicBox.cgi` - Diagnostic interface

Known sinks: `system()`, `popen()`, custom wrappers
