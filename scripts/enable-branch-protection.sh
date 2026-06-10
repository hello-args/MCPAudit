#!/usr/bin/env bash
set -euo pipefail

# Apply branch protection requiring the CI "test" job to pass.
# Idempotent: updates an existing "Protect main" ruleset instead of creating duplicates.
# Requires: gh CLI authenticated with admin access to the repository.
#
# Usage:
#   ./scripts/enable-branch-protection.sh
#   ./scripts/enable-branch-protection.sh MCP-Audit/MCTS
#   ./scripts/enable-branch-protection.sh MCP-Audit/MCTS --dry-run

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
DRY_RUN=false
if [[ "${2:-}" == "--dry-run" ]]; then
  DRY_RUN=true
elif [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi

RULESET_FILE="$(cd "$(dirname "$0")/.." && pwd)/.github/rulesets/main.json"
RULESET_NAME="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['name'])" "${RULESET_FILE}")"

echo "Checking existing rulesets on ${REPO}..."
EXISTING_ID="$(
  gh api "repos/${REPO}/rulesets" --paginate \
    | python3 -c "
import json, sys
name = sys.argv[1]
for row in json.load(sys.stdin):
    if row.get('name') == name:
        print(row.get('id', ''))
        break
" "${RULESET_NAME}"
)"

if [[ -n "${EXISTING_ID}" ]]; then
  echo "Found existing ruleset \"${RULESET_NAME}\" (id=${EXISTING_ID}). Updating in place..."
  if [[ "${DRY_RUN}" == true ]]; then
    echo "[dry-run] Would PUT repos/${REPO}/rulesets/${EXISTING_ID}"
    exit 0
  fi
  gh api "repos/${REPO}/rulesets/${EXISTING_ID}" \
    --method PUT \
    --input "${RULESET_FILE}"
else
  echo "No existing ruleset named \"${RULESET_NAME}\". Creating..."
  if [[ "${DRY_RUN}" == true ]]; then
    echo "[dry-run] Would POST repos/${REPO}/rulesets"
    exit 0
  fi
  gh api "repos/${REPO}/rulesets" \
    --method POST \
    --input "${RULESET_FILE}"
fi

echo "Done. Verify at: https://github.com/${REPO}/settings/rules"
