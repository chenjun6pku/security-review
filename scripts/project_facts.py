#!/usr/bin/env python3
"""Collect repository facts without executing project code.

Usage: python scripts/project_facts.py [REPO]

Outputs JSON describing detected languages, package manifests, build files,
container/CI files, agent/MCP hints, and likely sensitive-file names.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

MAX_FILES = 200_000
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".java", ".kt", ".kts",
    ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".rb", ".php", ".sh",
    ".ps1", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".md",
}
SENSITIVE_NAMES = re.compile(r"(^|/)(\.env(?:\.|$)|id_rsa(?:\.|$)|id_ed25519(?:\.|$)|kubeconfig$|credentials$|secrets?\.|.*\.pem$|.*\.key$)", re.I)

MANIFESTS = {
    "package.json": "node",
    "pnpm-lock.yaml": "node",
    "yarn.lock": "node",
    "package-lock.json": "node",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "Pipfile": "python",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "jvm",
    "build.gradle": "jvm",
    "build.gradle.kts": "jvm",
    "*.csproj": "dotnet",
    "*.fsproj": "dotnet",
    "composer.json": "php",
    "Gemfile": "ruby",
}

BUILD_FILES = {
    "Makefile", "CMakeLists.txt", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Jenkinsfile", "Taskfile.yml", "Taskfile.yaml", "justfile",
}


def iter_files(root: Path):
    count = 0
    for p in root.rglob("*"):
        if p.is_symlink() or not p.is_file():
            continue
        parts = set(p.parts)
        if ".git" in parts or ".venv" in parts or "node_modules" in parts:
            continue
        count += 1
        if count > MAX_FILES:
            break
        yield p


def read_head(path: Path, n=16_384):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:n]
    except Exception:
        return ""


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not root.is_dir():
        print(json.dumps({"error": f"not a directory: {root}"}))
        return 2

    files = list(iter_files(root))
    extensions = Counter(p.suffix.lower() for p in files if p.suffix)
    languages = []
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript/React",
        ".rs": "Rust", ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".cs": ".NET",
        ".c": "C", ".cc": "C++", ".cpp": "C++", ".php": "PHP", ".rb": "Ruby", ".swift": "Swift",
    }
    for ext, name in ext_map.items():
        if extensions[ext]:
            languages.append(name)

    manifests = []
    build_files = []
    ci_files = []
    container_files = []
    agent_hints = []
    sensitive_names = []

    for p in files:
        rel = p.relative_to(root).as_posix()
        name = p.name
        if name in MANIFESTS or any(name == k for k in MANIFESTS if not k.startswith("*")):
            manifests.append(rel)
        if name in BUILD_FILES or name.startswith("Makefile") or name.startswith("Dockerfile"):
            build_files.append(rel)
        if rel.startswith(".github/workflows/") or "/.github/workflows/" in rel or name in {"Jenkinsfile", ".gitlab-ci.yml"}:
            ci_files.append(rel)
        if name.startswith("Dockerfile") or "docker-compose" in name or rel.startswith("k8s/") or rel.startswith("kubernetes/"):
            container_files.append(rel)
        if SENSITIVE_NAMES.search(rel):
            sensitive_names.append(rel)

        if p.suffix.lower() in TEXT_EXTENSIONS and p.stat().st_size <= 1_000_000:
            text = read_head(p)
            low = text.lower()
            if any(x in low for x in ["model context protocol", "mcp server", "mcp_tools", "tool_registry", "agentic"]):
                agent_hints.append(rel)

    facts = {
        "root": str(root),
        "file_count": len(files),
        "languages": sorted(set(languages)),
        "top_extensions": extensions.most_common(12),
        "manifests": sorted(set(manifests)),
        "build_files": sorted(set(build_files)),
        "ci_files": sorted(set(ci_files)),
        "container_files": sorted(set(container_files)),
        "agent_or_mcp_hints": sorted(set(agent_hints))[:200],
        "sensitive_named_files": sorted(set(sensitive_names))[:200],
    }
    print(json.dumps(facts, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
