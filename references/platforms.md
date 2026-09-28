# Platform and Ecosystem Focus Areas

Load only the sections relevant to the detected project.

## Node.js / JavaScript / TypeScript

Inspect package lifecycle scripts, `npm`/`pnpm`/`yarn` configuration, `npx`, dynamic `require`/imports, child-process APIs, prototype pollution, SSRF, path traversal, unsafe eval, native addons, workspace scripts, package manager configuration, lockfile integrity, postinstall/prepare, and GitHub Actions.

## Python

Inspect `pyproject.toml`, `setup.py`, `setup.cfg`, entry points, build backends, `setup.py` execution, `pip` configuration, editable installs, `subprocess`, `os.system`, `eval`/`exec`, pickle/deserialization, Jinja/template sinks, importlib/dynamic imports, unsafe YAML, `.pth` files, virtualenv activation, and CI secrets.

## Rust

Inspect `build.rs`, proc macros, `unsafe`, FFI, build scripts, Cargo features, git/path dependencies, binary dependencies, environment-variable use, command execution, dynamic library loading, and Cargo.lock policy.

## Go

Inspect `go generate`, `//go:generate`, CGO/FFI, `os/exec`, plugin loading, `net/http`, TLS settings, filesystem permissions, build tags, module replacements, and embedded/downloaded assets.

## Java / JVM

Inspect Maven/Gradle lifecycle hooks, plugins, annotation processors, deserialization, reflection, class loading, URL fetchers, JNDI-like lookups, native libraries, build caches, credentials in `settings.xml`, and CI secrets.

## .NET

Inspect MSBuild targets/tasks, NuGet package scripts/targets, PowerShell, assembly loading, P/Invoke, reflection, insecure deserialization, path/ACL handling, and CI credentials.

## C / C++

Inspect memory safety, native parsers, FFI, build-system commands, post-build steps, dynamic library search paths, `LD_PRELOAD`/DLL search risks, unsafe temporary files, setuid/service behavior, and package/source authenticity.

## Containers

Inspect Dockerfile, Compose, Kubernetes manifests, image bases, mutable tags, Docker socket, privileged mode, capabilities, host mounts, host network/PID/IPC, device passthrough, build secrets, runtime secrets, package installation, remote downloads, healthcheck/entrypoint scripts, and image provenance.

## Desktop / Electron / GUI

Inspect auto-update, localhost/IPC APIs, protocol handlers, custom URL schemes, native bridges, browser session/cookie access, preload scripts, renderer-to-main IPC, code loading, plugin systems, file associations, startup persistence, and signing/update verification.

## CLI / developer tools

Inspect shell command construction, PATH and executable resolution, config discovery, SSH/Git/cloud credential inheritance, shell profile changes, local APIs, self-updating mechanisms, Git hooks, generated scripts, and editor/IDE integration.

## Web services

Apply ASVS-oriented checks for authentication, authorization, input validation, injection, SSRF, file handling, upload, session management, crypto, security headers, logging, error handling, rate limiting, deserialization, and business logic.

## MCP / Agent servers

Apply all `SR-AG` checks plus MCP authentication/authorization, scope control, server provenance, tool poisoning, context injection, session isolation, token exposure, shadow servers, tool output validation, and auditability.
