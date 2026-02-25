# Joern CPG Query Cookbook — IoT Firmware

Common Code Property Graph queries for IoT firmware vulnerability hunting.

## 1. Network Input Tracing

```scala
// MQTT/CoAP/HTTP input handlers
val networkSources = cpg.call.name("recv|recvfrom|read|mqtt_read|coap_parse|httpd_read").argument(1)

// Trace to dangerous sinks
cpg.call.name("system|popen|strcpy|sprintf").argument(1)
  .reachableByFlows(networkSources).p
```

## 2. CGI/Web Handler Analysis

```scala
// getenv("QUERY_STRING") → system()
val cgiInput = cpg.call.name("getenv").where(_.argument(1).isLiteral.code(".*QUERY.*|.*REQUEST.*|.*CONTENT.*"))
val exec = cpg.call.name("system|popen|execve").argument(1)
exec.reachableByFlows(cgiInput).p
```

## 3. Format String Vulnerabilities

```scala
// printf-family with non-literal format string
cpg.call.name("printf|fprintf|sprintf|snprintf|syslog")
  .where(_.argument(1).whereNot(_.isLiteral))
  .l
```

## 4. Integer Overflow in Memory Allocation

```scala
// malloc with arithmetic expression
cpg.call.name("malloc|calloc|realloc")
  .where(_.argument(1).isCallTo(".*multiplication.*|.*add.*"))
  .l
```

## 5. Use-After-Free Patterns

```scala
// Identify free() calls and subsequent uses of the same variable
val freeTargets = cpg.call.name("free").argument(1).isIdentifier.name.l
freeTargets.foreach { name =>
  val usesAfterFree = cpg.identifier.name(name)
    .where(_.lineNumber.greaterThan(
      cpg.call.name("free").where(_.argument(1).isIdentifier.name(name)).lineNumber.head
    )).l
  if (usesAfterFree.nonEmpty) println(s"Potential UAF: $name")
}
```

## 6. Crypto Weakness Detection

```scala
// Weak crypto functions
cpg.call.name("DES_.*|MD5_.*|RC4|rand|srand").l

// Hardcoded crypto keys (literal byte arrays passed to crypto init)
cpg.call.name(".*_set_key|.*_init|.*_encrypt")
  .where(_.argument.isLiteral)
  .l
```

## 7. Privilege & Access Control

```scala
// setuid/setgid without proper checks
cpg.call.name("setuid|setgid|seteuid|setegid").l

// chmod with permissive modes
cpg.call.name("chmod").where(_.argument(2).isLiteral.code(".*777.*|.*666.*")).l
```

## 8. NVRAM/Config Value Injection

```scala
// IoT-specific: nvram_get flowing into command execution
val nvram = cpg.call.name("nvram_get|nvram_safe_get|acosNvramConfig_get").argument(0)
val cmdSink = cpg.call.name("system|popen|doSystemCmd|twsystem").argument(1)
cmdSink.reachableByFlows(nvram).p
```

## 9. Cross-Function Vulnerability Chains

```scala
// Find functions that both read input AND call dangerous functions
cpg.method
  .where(_.call.name("recv|read|fgets"))
  .where(_.call.name("system|strcpy|sprintf"))
  .fullName.l
```

## 10. Summary Report Query

```scala
// Generate vulnerability summary
println("=== Vulnerability Summary ===")
println(s"system() calls: ${cpg.call.name("system").size}")
println(s"strcpy() calls: ${cpg.call.name("strcpy").size}")
println(s"sprintf() calls: ${cpg.call.name("sprintf").size}")
println(s"gets() calls: ${cpg.call.name("gets").size}")
println(s"Hardcoded strcmp: ${cpg.call.name("strcmp").where(_.argument.isLiteral).size}")
```
