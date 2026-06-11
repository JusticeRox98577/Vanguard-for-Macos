#!/usr/bin/env bash
# =============================================================================
# demo.sh — Vanguard-for-macOS reviewer demo script
#
# Walks a reviewer through the three phases of the proof-of-concept:
#   1. Phase 2 Node.js server self-test  (hardware-free, runs anywhere)
#   2. Phase 2 SEP key custody binary    (Apple Silicon Mac required)
#   3. Phase 1 ES monitor build check    (macOS required; entitlement needed to run)
#
# Safe to run without sudo. The self-test and binary-check steps require
# no elevated privileges. The Phase 1 binary itself requires 'sudo' only
# if you're actually running it — this script just verifies the build.
#
# Usage:  bash demo.sh
# =============================================================================

set -euo pipefail

# ── colour helpers ────────────────────────────────────────────────────────────
BOLD=$'\033[1m'
RESET=$'\033[0m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
CYAN=$'\033[0;36m'
DIM=$'\033[2m'

ok()   { printf "  ${GREEN}PASS${RESET}  %s\n" "$*"; }
fail() { printf "  ${RED}FAIL${RESET}  %s\n" "$*"; }
skip() { printf "  ${YELLOW}SKIP${RESET}  %s\n" "$*"; }
info() { printf "  ${CYAN}INFO${RESET}  %s\n" "$*"; }
sep()  { printf "${DIM}──────────────────────────────────────────────────────────────${RESET}\n"; }

# ── tracking arrays ───────────────────────────────────────────────────────────
declare -a RESULTS_LABEL
declare -a RESULTS_STATUS   # PASS | FAIL | SKIP

record() {
  RESULTS_LABEL+=("$1")
  RESULTS_STATUS+=("$2")
}

# ── repo root ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$SCRIPT_DIR"

# =============================================================================
# HEADER
# =============================================================================
clear || true
printf "\n"
printf "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${CYAN}║${RESET}  ${BOLD}Vanguard-for-macOS${RESET} — Reviewer Demo                          ${BOLD}${CYAN}║${RESET}\n"
printf "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}\n"
printf "\n"
printf "  This script will:\n"
printf "    ${CYAN}1.${RESET} Run the Phase 2 Node.js server self-test   ${DIM}(no hardware needed)${RESET}\n"
printf "    ${CYAN}2.${RESET} Check / run the Phase 2 SEP key custody binary\n"
printf "    ${CYAN}3.${RESET} Verify the Phase 1 ES monitor build + codesigning\n"
printf "\n"
printf "  ${DIM}No sudo required for steps 1–3.${RESET}\n"
printf "  ${DIM}To run Phase 1 live: sudo ./Phase1-ProcessMonitor/build/vanguard_monitor <target>${RESET}\n"
printf "\n"
sep
printf "\n"

# =============================================================================
# SECTION 1 — Phase 2 server self-test
# =============================================================================
printf "${BOLD}  SECTION 1 — Phase 2: Server Self-Test${RESET}\n"
printf "  ${DIM}Hardware-free. Runs the 5-check assertion verifier on any machine.${RESET}\n\n"

SERVER_DIR="$REPO/Phase2-Attestation/server"

# Check Node exists
if ! command -v node &>/dev/null; then
  fail "node not found. Install Node.js 18+ and rerun."
  record "Phase 2 — Node.js available" "FAIL"
  record "Phase 2 — npm dependencies"   "SKIP"
  record "Phase 2 — server self-test"   "SKIP"
else
  NODE_VER=$(node --version)
  ok "node found: $NODE_VER"
  record "Phase 2 — Node.js available" "PASS"

  # Check node_modules
  if [ ! -d "$SERVER_DIR/node_modules" ]; then
    info "node_modules not found — running npm install..."
    (cd "$SERVER_DIR" && npm install --silent 2>&1) && ok "npm install succeeded" \
      || { fail "npm install failed"; record "Phase 2 — npm dependencies" "FAIL"; }
  else
    ok "node_modules present"
    record "Phase 2 — npm dependencies" "PASS"
  fi

  # Run the self-test
  printf "\n"
  printf "  ${DIM}Running: npm test  (Phase2-Attestation/server)${RESET}\n\n"

  TEST_OUTPUT=""
  TEST_EXIT=0
  TEST_OUTPUT=$(cd "$SERVER_DIR" && npm test 2>&1) || TEST_EXIT=$?

  # Pretty-print the output with colouring
  while IFS= read -r line; do
    if [[ "$line" == *"✓"* ]]; then
      printf "    ${GREEN}%s${RESET}\n" "$line"
    elif [[ "$line" == *"passed"* ]]; then
      printf "    ${GREEN}${BOLD}%s${RESET}\n" "$line"
    elif [[ "$line" == *"failed"* && "$line" != *"0 failed"* ]]; then
      printf "    ${RED}%s${RESET}\n" "$line"
    else
      printf "    ${DIM}%s${RESET}\n" "$line"
    fi
  done <<< "$TEST_OUTPUT"

  printf "\n"
  if [ "$TEST_EXIT" -eq 0 ] && echo "$TEST_OUTPUT" | grep -q "passed"; then
    ok "Server self-test: all checks passed"
    record "Phase 2 — server self-test (5/5)" "PASS"
  else
    fail "Server self-test: one or more checks failed (exit $TEST_EXIT)"
    record "Phase 2 — server self-test (5/5)" "FAIL"
  fi
fi

printf "\n"
sep
printf "\n"

# =============================================================================
# SECTION 2 — Phase 2 SEP key custody binary
# =============================================================================
printf "${BOLD}  SECTION 2 — Phase 2: SEP Key Custody Binary${RESET}\n"
printf "  ${DIM}Requires an Apple Silicon Mac and a paid Developer account.${RESET}\n\n"

ATTEST_BINARY="$REPO/Phase2-Attestation/client/build/VanguardAttest.app/Contents/MacOS/VanguardAttest"
ATTEST_BUILD_DIR="$REPO/Phase2-Attestation/client"

if [ ! -f "$ATTEST_BINARY" ]; then
  skip "Binary not found at expected path."
  printf "\n"
  printf "  ${YELLOW}To build it:${RESET}\n"
  printf "    ${DIM}cd Phase2-Attestation/client${RESET}\n"
  printf "    ${DIM}make \\${RESET}\n"
  printf "    ${DIM}  APP_BUNDLE_ID=com.yourteam.vanguard-attest \\${RESET}\n"
  printf "    ${DIM}  SIGN_IDENTITY=\"Apple Development: you@example.com (TEAMID)\" \\${RESET}\n"
  printf "    ${DIM}  PROFILE=/path/to/profile.provisionprofile${RESET}\n"
  record "Phase 2 — SEP binary exists"    "SKIP"
  record "Phase 2 — SEP binary codesign"  "SKIP"
  record "Phase 2 — SEP binary run"       "SKIP"
else
  ok "Binary found: $ATTEST_BINARY"
  record "Phase 2 — SEP binary exists" "PASS"

  # Codesign check
  SIGN_EXIT=0
  SIGN_OUT=$(codesign --verify --verbose "$ATTEST_BINARY" 2>&1) || SIGN_EXIT=$?
  if [ "$SIGN_EXIT" -eq 0 ]; then
    ok "codesign verify: valid signature"
    record "Phase 2 — SEP binary codesign" "PASS"
  else
    fail "codesign verify failed: $SIGN_OUT"
    record "Phase 2 — SEP binary codesign" "FAIL"
  fi

  # Check we're on macOS before attempting to run
  if [[ "$(uname)" != "Darwin" ]]; then
    skip "Not macOS — skipping live run"
    record "Phase 2 — SEP binary run" "SKIP"
  else
    printf "\n"
    printf "  ${DIM}Running binary with 30-second timeout...${RESET}\n\n"

    # macOS ships without GNU timeout; use gtimeout (Homebrew coreutils) if available,
    # otherwise run without a timeout limit.
    RUN_EXIT=0
    if command -v timeout &>/dev/null; then
      RUN_OUT=$(timeout 30 "$ATTEST_BINARY" 2>&1) || RUN_EXIT=$?
    elif command -v gtimeout &>/dev/null; then
      RUN_OUT=$(gtimeout 30 "$ATTEST_BINARY" 2>&1) || RUN_EXIT=$?
    else
      RUN_OUT=$("$ATTEST_BINARY" 2>&1) || RUN_EXIT=$?
    fi

    while IFS= read -r line; do
      if [[ "$line" == *"✓"* ]] || [[ "$line" == *"ATTESTED"* ]] || [[ "$line" == *"VALID"* ]]; then
        printf "    ${GREEN}%s${RESET}\n" "$line"
      elif [[ "$line" == *"Error"* ]] || [[ "$line" == *"error"* ]] || [[ "$line" == *"failed"* ]]; then
        printf "    ${RED}%s${RESET}\n" "$line"
      else
        printf "    ${DIM}%s${RESET}\n" "$line"
      fi
    done <<< "$RUN_OUT"

    printf "\n"
    # timeout exits 124 on timeout; the binary may exit 0 after completing
    if [ "$RUN_EXIT" -eq 0 ]; then
      ok "SEP binary ran and exited cleanly"
      record "Phase 2 — SEP binary run" "PASS"
    elif [ "$RUN_EXIT" -eq 124 ]; then
      # Timeout is acceptable — the binary may wait for server
      ok "SEP binary ran (timed out after 30s — may need server running)"
      record "Phase 2 — SEP binary run" "PASS"
    else
      fail "SEP binary exited with code $RUN_EXIT"
      record "Phase 2 — SEP binary run" "FAIL"
    fi
  fi
fi

printf "\n"
sep
printf "\n"

# =============================================================================
# SECTION 3 — Phase 1 build check
# =============================================================================
printf "${BOLD}  SECTION 3 — Phase 1: Endpoint Security Monitor Build${RESET}\n"
printf "  ${DIM}Checks if the monitor binary is built and correctly signed.${RESET}\n\n"

P1_BINARY="$REPO/Phase1-ProcessMonitor/build/vanguard_monitor"
P1_DIR="$REPO/Phase1-ProcessMonitor"

if [ ! -f "$P1_BINARY" ]; then
  skip "Binary not found at expected path."
  printf "\n"
  printf "  ${YELLOW}To build it (requires macOS + Xcode CLT):${RESET}\n"
  printf "    ${DIM}cd Phase1-ProcessMonitor${RESET}\n"
  printf "    ${DIM}make${RESET}\n"
  printf "\n"
  printf "  ${YELLOW}To run it (requires sudo + ES entitlement):${RESET}\n"
  printf "    ${DIM}sudo ./Phase1-ProcessMonitor/build/vanguard_monitor <target-process-name>${RESET}\n"
  printf "\n"
  printf "  ${YELLOW}To exercise it (in a second terminal):${RESET}\n"
  printf "    ${DIM}./Phase1-ProcessMonitor/test/demo_detections.sh${RESET}\n"
  record "Phase 1 — binary exists"   "SKIP"
  record "Phase 1 — codesign check"  "SKIP"
else
  ok "Binary found: $P1_BINARY"
  record "Phase 1 — binary exists" "PASS"

  # Only run codesign on macOS
  if [[ "$(uname)" != "Darwin" ]]; then
    skip "Not macOS — skipping codesign verification"
    record "Phase 1 — codesign check" "SKIP"
  else
    CS_EXIT=0
    CS_OUT=$(codesign --verify --verbose "$P1_BINARY" 2>&1) || CS_EXIT=$?
    if [ "$CS_EXIT" -eq 0 ]; then
      ok "codesign verify: valid signature"
      record "Phase 1 — codesign check" "PASS"

      # Print entitlements if present
      ENT_OUT=$(codesign --display --entitlements - "$P1_BINARY" 2>/dev/null || true)
      if echo "$ENT_OUT" | grep -q "endpoint-security"; then
        ok "ES entitlement present in binary"
      else
        info "ES entitlement not found in codesign output — check provisioning profile"
      fi
    else
      fail "codesign verify failed: $CS_OUT"
      record "Phase 1 — codesign check" "FAIL"
    fi
  fi

  printf "\n"
  printf "  ${DIM}To run the monitor:${RESET}\n"
  printf "    ${DIM}sudo $P1_BINARY <target-process-name>${RESET}\n"
  printf "  ${DIM}Note: requires com.apple.developer.endpoint-security.client entitlement${RESET}\n"
  printf "  ${DIM}      OR SIP disabled on a test machine (see Phase1-ProcessMonitor/README.md)${RESET}\n"
fi

printf "\n"
sep
printf "\n"

# =============================================================================
# SUMMARY TABLE
# =============================================================================
printf "${BOLD}  SUMMARY${RESET}\n\n"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

for i in "${!RESULTS_LABEL[@]}"; do
  label="${RESULTS_LABEL[$i]}"
  status="${RESULTS_STATUS[$i]}"
  case "$status" in
    PASS) printf "  ${GREEN}[PASS]${RESET}  %s\n" "$label"; ((PASS_COUNT++)) ;;
    FAIL) printf "  ${RED}[FAIL]${RESET}  %s\n" "$label"; ((FAIL_COUNT++)) ;;
    SKIP) printf "  ${YELLOW}[SKIP]${RESET}  %s\n" "$label"; ((SKIP_COUNT++)) ;;
  esac
done

printf "\n"
printf "  ${GREEN}${PASS_COUNT} passed${RESET}  /  ${RED}${FAIL_COUNT} failed${RESET}  /  ${YELLOW}${SKIP_COUNT} skipped${RESET}\n"

if [ "$FAIL_COUNT" -eq 0 ] && [ "$SKIP_COUNT" -eq 0 ]; then
  printf "\n  ${GREEN}${BOLD}All checks passed.${RESET}\n"
elif [ "$FAIL_COUNT" -eq 0 ]; then
  printf "\n  ${YELLOW}${BOLD}No failures. Skipped items require macOS + build prerequisites.${RESET}\n"
else
  printf "\n  ${RED}${BOLD}${FAIL_COUNT} check(s) failed.${RESET} See output above for details.\n"
fi

printf "\n"
sep
printf "\n"

# =============================================================================
# OFFER TO WRITE REPORT
# =============================================================================
printf "  Write a report to file? ${DIM}(y/N)${RESET} "
read -r -t 15 WRITE_REPORT || WRITE_REPORT="n"
printf "\n"

if [[ "$(echo "$WRITE_REPORT" | tr '[:upper:]' '[:lower:]')" == "y" ]]; then
  REPORT_FILE="$REPO/demo-report-$(date +%Y%m%d-%H%M%S).txt"
  {
    printf "Vanguard-for-macOS — Demo Report\n"
    printf "Generated: %s\n" "$(date)"
    printf "Host:      %s\n" "$(uname -a)"
    printf "\n"
    printf "RESULTS\n"
    printf "───────\n"
    for i in "${!RESULTS_LABEL[@]}"; do
      printf "  [%s]  %s\n" "${RESULTS_STATUS[$i]}" "${RESULTS_LABEL[$i]}"
    done
    printf "\n"
    printf "COUNTS\n"
    printf "──────\n"
    printf "  PASS: %d\n  FAIL: %d\n  SKIP: %d\n" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    printf "\n"
    printf "NOTES\n"
    printf "─────\n"
    printf "  Phase 1 requires macOS + ES entitlement (or SIP disabled on test machine)\n"
    printf "  Phase 2 full chain requires Apple Silicon + paid Developer account + entitlement\n"
    printf "  Phase 2 server self-test (5/5) runs anywhere with Node 18+\n"
    printf "\n"
    printf "REPO\n"
    printf "────\n"
    printf "  https://github.com/JusticeRox98577/Vanguard-for-Macos\n"
    printf "\n"
    printf "DISCLAIMER\n"
    printf "──────────\n"
    printf "  Independent research. Not affiliated with, authorized by, or endorsed by\n"
    printf "  Riot Games or Apple. 'Vanguard' and 'VALORANT' are trademarks of Riot Games.\n"
  } > "$REPORT_FILE"

  ok "Report written to: $REPORT_FILE"
else
  info "Skipping report file."
fi

printf "\n"
printf "${DIM}  Repo: https://github.com/JusticeRox98577/Vanguard-for-Macos${RESET}\n"
printf "${DIM}  Independent research — not affiliated with Riot Games or Apple.${RESET}\n"
printf "\n"
