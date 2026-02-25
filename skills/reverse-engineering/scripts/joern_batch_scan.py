#!/usr/bin/env python3
"""
Joern Batch Scanner — Scan extracted firmware filesystem for vulnerable binaries.

Usage:
    python3 joern_batch_scan.py /path/to/extracted/firmware [--output report.json]

Scans ELF binaries in the firmware directory, imports each into Joern,
and runs a set of vulnerability-detection queries.
"""

import subprocess
import json
import os
import sys
import argparse
from pathlib import Path


DANGEROUS_FUNCTIONS = [
    "system", "popen", "execve", "exec", "strcpy", "strcat",
    "sprintf", "gets", "scanf", "sscanf", "vsprintf"
]

JOERN_QUERY_TEMPLATE = '''
@main def exec(cpgFile: String) = {{
  importCpg(cpgFile)

  val dangerous = List({funcs})
  val results = scala.collection.mutable.ListBuffer[String]()

  dangerous.foreach {{ name =>
    val calls = cpg.call.name(name).l
    calls.foreach {{ c =>
      val file = c.file.name.headOption.getOrElse("unknown")
      val line = c.lineNumber.getOrElse(0)
      results += s"${{name}}|${{file}}|${{line}}|${{c.code}}"
    }}
  }}

  // Hardcoded strcmp
  cpg.call.name("strcmp").where(_.argument.isLiteral).l.foreach {{ c =>
    val file = c.file.name.headOption.getOrElse("unknown")
    val line = c.lineNumber.getOrElse(0)
    results += s"strcmp_hardcoded|${{file}}|${{line}}|${{c.code}}"
  }}

  results.foreach(println)
}}
'''


def find_elf_binaries(directory: str) -> list:
    """Find ELF binaries in the given directory."""
    binaries = []
    for root, _, files in os.walk(directory):
        for f in files:
            filepath = os.path.join(root, f)
            try:
                result = subprocess.run(
                    ["file", filepath], capture_output=True, text=True, timeout=5
                )
                if "ELF" in result.stdout:
                    binaries.append(filepath)
            except (subprocess.TimeoutExpired, Exception):
                continue
    return binaries


def scan_binary(binary_path: str, joern_script: str) -> list:
    """Scan a single binary with Joern and return findings."""
    cpg_path = f"/tmp/joern_scan_{os.path.basename(binary_path)}.cpg"
    findings = []

    try:
        # Parse binary to CPG
        subprocess.run(
            ["joern-parse", binary_path, "--output", cpg_path],
            capture_output=True, text=True, timeout=120
        )

        if not os.path.exists(cpg_path):
            return findings

        # Run query
        result = subprocess.run(
            ["joern", "--script", joern_script, "--params", f"cpgFile={cpg_path}"],
            capture_output=True, text=True, timeout=180
        )

        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|", 3)
                if len(parts) == 4:
                    findings.append({
                        "binary": binary_path,
                        "vulnerability_type": parts[0],
                        "file": parts[1],
                        "line": int(parts[2]) if parts[2].isdigit() else 0,
                        "code": parts[3]
                    })
    except subprocess.TimeoutExpired:
        findings.append({
            "binary": binary_path,
            "vulnerability_type": "TIMEOUT",
            "file": "", "line": 0, "code": "Analysis timed out"
        })
    except Exception as e:
        findings.append({
            "binary": binary_path,
            "vulnerability_type": "ERROR",
            "file": "", "line": 0, "code": str(e)
        })
    finally:
        # Cleanup
        if os.path.exists(cpg_path):
            os.remove(cpg_path)

    return findings


def main():
    parser = argparse.ArgumentParser(description="Joern batch vulnerability scanner")
    parser.add_argument("firmware_dir", help="Path to extracted firmware directory")
    parser.add_argument("--output", "-o", default="joern_scan_report.json",
                        help="Output report file (JSON)")
    args = parser.parse_args()

    if not os.path.isdir(args.firmware_dir):
        print(f"Error: {args.firmware_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    # Generate Joern query script
    funcs_str = ", ".join(f'"{f}"' for f in DANGEROUS_FUNCTIONS)
    query_content = JOERN_QUERY_TEMPLATE.format(funcs=funcs_str)
    script_path = "/tmp/joern_batch_query.sc"
    with open(script_path, "w") as f:
        f.write(query_content)

    print(f"[*] Scanning {args.firmware_dir} for ELF binaries...")
    binaries = find_elf_binaries(args.firmware_dir)
    print(f"[*] Found {len(binaries)} ELF binaries")

    all_findings = []
    for i, binary in enumerate(binaries, 1):
        print(f"[{i}/{len(binaries)}] Scanning: {binary}")
        findings = scan_binary(binary, script_path)
        all_findings.extend(findings)
        if findings:
            print(f"    -> {len(findings)} findings")

    # Write report
    report = {
        "firmware_dir": args.firmware_dir,
        "binaries_scanned": len(binaries),
        "total_findings": len(all_findings),
        "findings": all_findings
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[*] Scan complete: {len(all_findings)} findings in {len(binaries)} binaries")
    print(f"[*] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
