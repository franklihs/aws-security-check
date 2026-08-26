#!/usr/bin/env bash
#
# setup-aws-security.sh
#
# Read-only AWS account security & cost-hygiene checker.
# Checks:
#   1. Root account MFA status
#   2. MFA status for every IAM user
#   3. Access keys older than a configurable threshold (default: 90 days)
#   4. Presence of at least one CloudWatch billing alarm
#
# Requirements: aws-cli v2 configured (aws configure / aws sts get-caller-identity working)
#
# Usage:
#   ./setup-aws-security.sh [--max-key-age-days 90] [--json]
#
set -euo pipefail

MAX_KEY_AGE_DAYS=90
OUTPUT_JSON=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-key-age-days)
      MAX_KEY_AGE_DAYS="$2"
      shift 2
      ;;
    --json)
      OUTPUT_JSON=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# ---- colors (disabled automatically when not a TTY, e.g. inside CI logs still show plain text) ----
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi

PASS=0
WARN=0
FAIL=0
declare -a FINDINGS=()

log_pass() { PASS=$((PASS+1)); FINDINGS+=("PASS|$1"); [[ "$OUTPUT_JSON" == false ]] && echo -e "${GREEN}[PASS]${RESET} $1"; }
log_warn() { WARN=$((WARN+1)); FINDINGS+=("WARN|$1"); [[ "$OUTPUT_JSON" == false ]] && echo -e "${YELLOW}[WARN]${RESET} $1"; }
log_fail() { FAIL=$((FAIL+1)); FINDINGS+=("FAIL|$1"); [[ "$OUTPUT_JSON" == false ]] && echo -e "${RED}[FAIL]${RESET} $1"; }

need_bin() {
  command -v "$1" >/dev/null 2>&1 || { echo "Required command '$1' not found in PATH." >&2; exit 1; }
}
need_bin aws
need_bin jq

[[ "$OUTPUT_JSON" == false ]] && echo -e "${BOLD}=== AWS Account Security & Cost Hygiene Check ===${RESET}\n"

# Sanity check: are we authenticated?
if ! IDENTITY_JSON=$(aws sts get-caller-identity --output json 2>/dev/null); then
  echo "Could not authenticate with AWS. Run 'aws configure' first." >&2
  exit 1
fi
ACCOUNT_ID=$(echo "$IDENTITY_JSON" | jq -r '.Account')
[[ "$OUTPUT_JSON" == false ]] && echo "Account: $ACCOUNT_ID"$'\n'

# ---------------------------------------------------------------------------
# 1. Root account MFA
# ---------------------------------------------------------------------------
ROOT_MFA=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
if [[ "$ROOT_MFA" == "1" ]]; then
  log_pass "Root account has MFA enabled."
else
  log_fail "Root account does NOT have MFA enabled. Enable it immediately in IAM > Root user."
fi

# ---------------------------------------------------------------------------
# 2 & 3. Per-user MFA status + access key age
# ---------------------------------------------------------------------------
USERS=$(aws iam list-users --query 'Users[*].UserName' --output text)

if [[ -z "$USERS" ]]; then
  log_warn "No IAM users found (only root exists). Consider creating a scoped IAM user instead of using root for daily work."
else
  for USER in $USERS; do
    MFA_COUNT=$(aws iam list-mfa-devices --user-name "$USER" --query 'length(MFADevices)' --output text)
    if [[ "$MFA_COUNT" -gt 0 ]]; then
      log_pass "User '$USER' has MFA enabled."
    else
      log_fail "User '$USER' has NO MFA device configured."
    fi

    KEYS_JSON=$(aws iam list-access-keys --user-name "$USER" --output json)
    KEY_COUNT=$(echo "$KEYS_JSON" | jq '.AccessKeyMetadata | length')

    if [[ "$KEY_COUNT" -eq 0 ]]; then
      log_pass "User '$USER' has no access keys (fine if this user only uses console/MFA login)."
    else
      echo "$KEYS_JSON" | jq -c '.AccessKeyMetadata[]' | while read -r KEY; do
        KEY_ID=$(echo "$KEY" | jq -r '.AccessKeyId')
        CREATE_DATE=$(echo "$KEY" | jq -r '.CreateDate')
        STATUS=$(echo "$KEY" | jq -r '.Status')
        CREATE_EPOCH=$(date -d "$CREATE_DATE" +%s 2>/dev/null || date -jf "%Y-%m-%dT%H:%M:%S" "${CREATE_DATE%+*}" +%s)
        NOW_EPOCH=$(date +%s)
        AGE_DAYS=$(( (NOW_EPOCH - CREATE_EPOCH) / 86400 ))

        if [[ "$STATUS" != "Active" ]]; then
          log_warn "User '$USER' key $KEY_ID is $STATUS (inactive) — consider deleting if unused."
        elif [[ "$AGE_DAYS" -gt "$MAX_KEY_AGE_DAYS" ]]; then
          log_warn "User '$USER' key $KEY_ID is $AGE_DAYS days old (> $MAX_KEY_AGE_DAYS). Rotate it."
        else
          log_pass "User '$USER' key $KEY_ID is $AGE_DAYS days old — within policy."
        fi
      done
    fi
  done
fi

# ---------------------------------------------------------------------------
# 4. Billing alarm present
# ---------------------------------------------------------------------------
# Billing metrics only exist in us-east-1, regardless of your default region.
ALARM_COUNT=$(aws cloudwatch describe-alarms \
  --region us-east-1 \
  --query "length(MetricAlarms[?Namespace=='AWS/Billing'])" \
  --output text 2>/dev/null || echo "0")

if [[ "$ALARM_COUNT" -gt 0 ]]; then
  log_pass "Found $ALARM_COUNT CloudWatch billing alarm(s) in us-east-1."
else
  log_fail "No CloudWatch billing alarm found. Create one to avoid surprise charges (Billing preferences > Alerts, then CloudWatch alarm on EstimatedCharges in us-east-1)."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ "$OUTPUT_JSON" == true ]]; then
  jq -n --arg account "$ACCOUNT_ID" --argjson pass "$PASS" --argjson warn "$WARN" --argjson fail "$FAIL" \
    '{account: $account, summary: {pass: $pass, warn: $warn, fail: $fail}}'
else
  echo
  echo -e "${BOLD}=== Summary ===${RESET}"
  echo -e "${GREEN}Pass: $PASS${RESET}  ${YELLOW}Warn: $WARN${RESET}  ${RED}Fail: $FAIL${RESET}"
  if [[ "$FAIL" -gt 0 ]]; then
    exit 2
  elif [[ "$WARN" -gt 0 ]]; then
    exit 1
  fi
fi
