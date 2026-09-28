#!/usr/bin/env python3
"""Conservative static indicator scan. Never executes target project code.

Usage: python scripts/static_security_scan.py [REPO]

This tool is an evidence collector, not a vulnerability verdict engine.
It reports source locations for patterns that should be traced manually.

Pattern regressions are covered by `python scripts/run_scan_tests.py`, which
checks the rules below against the cases in `tests/scanner_cases.yaml`.
Keep patterns free of trailing word boundaries after `(` or whitespace
alternatives: `\b` cannot follow a non-word character and silently disables the
alternative it terminates.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAX_BYTES = 2_000_000
MAX_RESULTS_PER_RULE = 200

# Keep in sync with scripts/project_facts.py.
IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", ".tox",
}
# Build outputs mirror source files; review them explicitly instead of
# re-reporting every mirrored source line here.
IGNORED_BUILD_DIRS = {"dist", "build", "target", "out"}

RULES = [
    ("EXEC-SHELL", re.compile(r"\b(os\.system|subprocess\.(Popen|run|call|check_call|check_output)|child_process\.(exec|execFile|execFileSync|execSync|spawn|spawnSync|fork)|execSync|execFileSync|spawnSync|Runtime\.getRuntime\(\)|ProcessBuilder|Invoke-Expression)\b"), "command execution primitive"),
    ("EXEC-EVAL", re.compile(r"\b(eval\s*\(|exec\s*\(|Function\s*\(|importlib\.import_module\s*\(|__import__\s*\(|require\s*\(|dynamicImport\s*\()"), "dynamic code/module loading primitive"),
    ("PIPE-EXEC", re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|;&]*\|\s*(sudo\s+)?(bash|sh|zsh|fish|dash|python[0-9.]*|node|perl|ruby|powershell|pwsh)\b", re.I), "download-and-execute pipeline indicator"),
    ("NET-HTTP", re.compile(r"(\brequests\.(get|post|put|delete|head|patch)\s*\(|\burllib\.|\bfetch\s*\(|\baxios\.|\bhttp\.request\s*\(|\bcurl\b|\bwget\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b)", re.I), "network client/download primitive"),
    ("PERSIST-STARTUP", re.compile(r"(systemctl\s+(enable|daemon-reload)|crontab\s|schtasks\s|launchctl\s|LaunchAgents|Run\\|RunOnce|\.bashrc|\.zshrc|LD_PRELOAD)", re.I), "persistence/startup indicator"),
    ("CRED-PATH", re.compile(r"(~?/(\.ssh|\.aws|\.azure|\.config/gcloud|\.kube)|%USERPROFILE%\\\.(ssh|aws)|\\\.env(?:\.|$)|git-credential)", re.I), "credential-sensitive path/reference"),
    ("PROC-MEM", re.compile(r"(ptrace|/proc/\d+/mem|ReadProcessMemory|WriteProcessMemory|OpenProcess\(|process_vm_(readv|writev))", re.I), "cross-process memory access indicator"),
    ("CONTAINER-HOST", re.compile(r"(--privileged|/var/run/docker\.sock|pid:\s*host|network_mode:\s*host|ipc:\s*host|/proc:/proc|/sys:/sys|cap_add:\s*\[?SYS_ADMIN)", re.I), "container/host boundary indicator"),
    ("TLS-BYPASS", re.compile(r"(verify\s*=\s*False|rejectUnauthorized\s*[:=]\s*false|insecureSkipVerify\s*[:=]\s*true|CURLOPT_SSL_VERIFYPEER[^\n]*0)", re.I), "TLS certificate verification bypass indicator"),
    ("UPLOAD-EXFIL", re.compile(r"\b(upload\w*|multipart|FormData|put_object|s3\.upload|axios\.(post|put)|http[^\n]*files=|requests\.(post|put)|Invoke-RestMethod[^\n]*-Method\s+Post)", re.I), "potential upload/exfiltration sink"),
    ("AGENT-MCP", re.compile(r"(MCP|Model Context Protocol|tool_registry|register_tool|function_call|tool_calls|agent memory|vector store)", re.I), "agent/MCP integration indicator"),
]

TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".java", ".kt", ".kts", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".rb", ".php", ".sh", ".ps1", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".md"}


def files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        if any(part in IGNORED_DIRS or part in IGNORED_BUILD_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in TEXT_EXTENSIONS and p.stat().st_size <= MAX_BYTES:
            yield p


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not root.is_dir():
        print(json.dumps({"error": f"not a directory: {root}"}))
        return 2

    findings = []
    counts = {}
    for p in files(root):
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        rel = p.relative_to(root).as_posix()
        for rule_id, rx, desc in RULES:
            if counts.get(rule_id, 0) >= MAX_RESULTS_PER_RULE:
                continue
            for lineno, line in enumerate(lines, 1):
                if rx.search(line):
                    findings.append({
                        "rule": rule_id,
                        "description": desc,
                        "path": rel,
                        "line": lineno,
                        "text": line.strip()[:500],
                    })
                    counts[rule_id] = counts.get(rule_id, 0) + 1

    print(json.dumps({"root": str(root), "indicator_count": len(findings), "indicators": findings}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
