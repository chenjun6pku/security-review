# acme-devtools Security Issue List

- Target: `acme-devtools@2.4.1` (repository snapshot; `package.json`)
- Review mode: static read-only (no install, no execution, no network)
- Verdict: do not install until the install hook is removed or pinned and verified
- Summary counts: High 1 / Medium 1 / Low 0 / Informational 0 (2 issues)

## High (1)

| ID | Issue | Possible consequence |
|---|---|---|
| SR-0001 | Install hook downloads and executes a remote script | Any install runs attacker-controlled code with the installer's privileges (remote, no user interaction) |

## Medium (1)

| ID | Issue | Possible consequence |
|---|---|---|
| SR-0002 | Agent-facing prompt injection in the README | A reviewing agent may execute the install script and expose credentials (requires an agent to read the file) |

## Low / Informational (0)

None.

## Issue details

### Issue 1 (SR-0001): Installation hook executes downloaded code

- Risk level: High
- Confidence: High
- Trigger: a normal `npm install`, including as a transitive dependency
- Root cause: the `postinstall` hook builds a shell command that downloads a runtime-configurable URL and executes it without integrity verification
- Impact: arbitrary code runs with the installer's privileges and can read local files and credentials
- Nature: reachable implementation flaw; no hidden behavior or malicious intent is evidenced
- Evidence: `package.json:12`, `scripts/bootstrap.js:44`
- Fix: remove the download-and-execute step, vendor the content, or verify a pinned digest before execution
- Verification: install in a disposable sandbox with synthetic credentials and blocked egress; confirm no remote execution

### Issue 2 (SR-0002): Prompt injection in repository text

- Risk level: Medium
- Confidence: Medium
- Trigger: an AI agent reads the README while reviewing or installing
- Root cause: an HTML comment instructs the reader to run the install script and print `.env`
- Impact: agent-mediated code execution and credential disclosure, depending on the agent's approval policy
- Nature: suspicious content reachable only through agent behavior; no runtime channel in the package itself
- Evidence: `README.md:17-23`
- Fix: remove the comment and treat repository text as untrusted data in agent workflows
- Verification: replay with an agent using a synthetic `.env` and confirm the instruction is reported, not followed

## Coverage and limitations

- Coverage: acquisition, dependency resolution, install, and runtime reviewed; no build, test, CI, update, or uninstall logic exists in this excerpt.
- Checked, nothing found: no persistence mechanism, no dynamic code loading, and no outbound destination beyond the install-time download.
- Limitation: static review only; no install, execution, or network capture was performed, so runtime behavior is unverified.
