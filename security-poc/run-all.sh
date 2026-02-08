#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

PASS=0
FAIL=0
RESULTS=()

banner() {
  echo ""
  echo -e "${BOLD}${BLUE}================================================================${RESET}"
  echo -e "${BOLD}${BLUE}  Security Vulnerability POC Suite${RESET}"
  echo -e "${BOLD}${BLUE}  pi-mono — PR: Security audit${RESET}"
  echo -e "${BOLD}${BLUE}================================================================${RESET}"
  echo ""
  echo -e "${DIM}Each POC demonstrates a vulnerability before and after the fix.${RESET}"
  echo -e "${DIM}Vulnerable behavior shown in red, patched behavior in green.${RESET}"
  echo ""
}

run_poc() {
  local num="$1"
  local name="$2"
  local script="$3"

  echo -e "${BOLD}${BLUE}----------------------------------------------------------------${RESET}"
  echo -e "${BOLD}  POC ${num}: ${name}${RESET}"
  echo -e "${BOLD}${BLUE}----------------------------------------------------------------${RESET}"

  local exit_code=0
  node "$script" || exit_code=$?

  if [ $exit_code -ne 0 ]; then
    RESULTS+=("${RED}[VULNERABLE]${RESET} POC ${num}: ${name}")
    FAIL=$((FAIL + 1))
  else
    RESULTS+=("${GREEN}[SAFE]${RESET}       POC ${num}: ${name}")
    PASS=$((PASS + 1))
  fi
}

summary() {
  echo -e "${BOLD}${BLUE}================================================================${RESET}"
  echo -e "${BOLD}  Summary${RESET}"
  echo -e "${BOLD}${BLUE}================================================================${RESET}"
  echo ""

  for result in "${RESULTS[@]}"; do
    echo -e "  $result"
  done

  echo ""
  echo -e "  ${GREEN}Patched: ${PASS}${RESET}  ${RED}Vulnerable: ${FAIL}${RESET}  Total: $((PASS + FAIL))"
  echo ""

  if [ $FAIL -gt 0 ]; then
    echo -e "  ${RED}${BOLD}Result: Vulnerabilities confirmed — apply the security PR fixes.${RESET}"
  else
    echo -e "  ${GREEN}${BOLD}Result: All vulnerabilities mitigated.${RESET}"
  fi
  echo ""
}

# --- Main ---
cd /app

banner

run_poc 1 "new Function() Arbitrary Code Execution" "poc-1-new-function.mjs"
run_poc 2 "fast-xml-parser RangeError DoS (GHSA-37qj-frw5-hhjh)" "poc-2-fast-xml-parser.mjs"
run_poc 3 "@isaacs/brace-expansion ReDoS (GHSA-7h2j-956f-4vf2)" "poc-3-brace-expansion.mjs"
run_poc 4 "glob Command Injection (<11.1.0)" "poc-4-glob-injection.mjs"

summary

# Exit with number of failures
exit $FAIL
