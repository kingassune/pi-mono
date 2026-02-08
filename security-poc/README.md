# Security Vulnerability POC Environment

Self-contained Docker environment that demonstrates 4 high-severity security vulnerabilities identified in the pi-mono security audit PR. Each POC shows the vulnerable behavior (before fix) and the patched behavior (after fix) side-by-side.

## Quick Start

```bash
cd security-poc
docker compose up --build
```

## Vulnerabilities Demonstrated

### POC 1: `new Function()` Arbitrary Code Execution

- **File:** `packages/agent/test/utils/calculate.ts`
- **Severity:** High
- **Issue:** Unsanitized user input passed directly to `new Function()`, allowing arbitrary JavaScript execution (system commands, file reads, env var exfiltration).
- **Fix:** Allowlist regex `^[\d\s+\-*/().%]+$` restricts input to math characters only.

### POC 2: `fast-xml-parser` RangeError DoS

- **Advisory:** [GHSA-37qj-frw5-hhjh](https://github.com/advisories/GHSA-37qj-frw5-hhjh)
- **Severity:** High
- **Versions:** Vulnerable `<=5.3.3`, Fixed `>=5.3.4`
- **Issue:** Crafted XML input triggers a `RangeError` that crashes the Node.js process. Transitive dependency via `@aws-sdk/client-bedrock-runtime`.
- **Fix:** Bump `@aws-sdk/client-bedrock-runtime` to `^3.985.0` + npm override to `fast-xml-parser ^5.3.4`.

### POC 3: `@isaacs/brace-expansion` ReDoS

- **Advisory:** [GHSA-7h2j-956f-4vf2](https://github.com/advisories/GHSA-7h2j-956f-4vf2)
- **Severity:** High
- **Versions:** Vulnerable `<=5.0.0`, Fixed `>=5.0.1`
- **Issue:** Crafted brace patterns cause catastrophic regex backtracking, freezing the Node.js event loop. Transitive dependency via `glob -> minimatch -> @isaacs/brace-expansion`.
- **Fix:** npm override to `@isaacs/brace-expansion ^5.0.1`.

### POC 4: `glob` Command Injection

- **Severity:** High
- **Versions:** Vulnerable `<11.1.0`, Fixed `>=11.1.0`
- **Issue:** `glob` could pass unsanitized patterns to child processes with `shell: true`, allowing command injection via user-controlled patterns. In pi-mono, `find.ts` passes AI agent-supplied patterns directly to `globSync()`.
- **Fix:** Bump `glob` to `^11.1.0`.

## Output

Each POC prints color-coded results:

- **Red `[VULNERABLE]`** — exploit succeeded on the unpatched version
- **Green `[PATCHED]`** — exploit blocked on the fixed version
- **Yellow `[ERROR]` / `[OK]`** — informational

A summary table at the end shows the overall pass/fail status.

## How It Works

The Docker container installs two sets of dependencies:

- `/app/vulnerable/` — old, vulnerable package versions
- `/app/patched/` — new, fixed package versions

Each POC loads both versions and runs identical payloads against each, comparing the behavior.

## File Structure

```
security-poc/
  Dockerfile              — Node 20 Alpine container
  docker-compose.yml      — Single service, run with `docker compose up`
  package-vulnerable.json — Vulnerable dependency versions
  package-patched.json    — Patched dependency versions
  run-all.sh              — Orchestrator script
  poc-1-new-function.mjs  — Code execution via new Function()
  poc-2-fast-xml-parser.mjs — XML parser DoS
  poc-3-brace-expansion.mjs — ReDoS via brace expansion
  poc-4-glob-injection.mjs  — Glob command injection
  README.md               — This file
```

## Cleanup

```bash
docker compose down --rmi local
```
