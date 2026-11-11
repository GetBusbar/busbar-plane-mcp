#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-unpriced-refuses`: missing rates stay explicitly unpriced.
# The host warns about an incomplete card at startup and retains raw usage counts.
# Billing OFF serves and charges only the flat fee. Billing ON with `bytes` omitted
# also serves, but its monetary usage read must return HTTP 409 / unpriced_class,
# naming that class and lane. A zero, partial charge, unrelated error or boot failure
# cannot satisfy this scenario. This follows CONFIG_RATE_CARD_MISSING and the
# AdminError::UnpricedClass contract, superseding the former boot-refusal rule.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

WORK_ROOT="${H2_WORK:-${here}/../../../target/h2-scratch/mcp-unpriced-refuses.$$}"

# ── ARM 1: BILLING OFF -- the silent zero that IS correct ─────────────────────────────────────────
# Run in a subshell with its OWN boot: the two arms differ only in the config's `rate_card:` key, and
# `h2-lib.sh` writes that key once per boot.
arm_off="$(
  H2_RATE_CARD_YAML=" " bash -c '
    set -uo pipefail
    here="$1"; work="$2"
    source "${here}/h2-lib.sh"
    trap "h2_stop" EXIT
    h2_boot "$work" "groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }" >/dev/null 2>&1 || { echo "boot-failed"; exit 0; }
    read -r kid tok <<<"$(h2_mint h2-oracle)"
    [ -n "$tok" ] || { echo "mint-failed"; exit 0; }
    bound="$(h2_bind "$tok")"
    read -r st _ <<<"$(h2_call "$bound" "billing-off")"
    printf "%s %s\n" "$st" "$(h2_usage_field "$kid" spend_cents)"
  ' _ "$here" "${WORK_ROOT}/off"
)"

# ARM 2: the card prices tool_calls explicitly but leaves bytes unpriced.
ARM2_CARD='  rate_card:
    mcp_server:probe: { units: { tool_calls: 0 } }'
arm_on="$(
  H2_RATE_CARD_YAML="$ARM2_CARD" bash -c '
    set -uo pipefail
    here="$1"; work="$2"
    source "${here}/h2-lib.sh"
    trap "h2_stop" EXIT
    h2_boot "$work" "groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }" >/dev/null 2>&1 || { echo "boot-failed"; exit 0; }
    read -r kid tok <<<"$(h2_mint h2-oracle)"
    [ -n "$tok" ] || { echo "mint-failed"; exit 0; }
    bound="$(h2_bind "$tok")"
    read -r st _ <<<"$(h2_call "$bound" "billing-on-unpriced")"
    [ "$st" = 200 ] || { echo "call-failed $st"; exit 0; }
    usage_status="$(curl -sS -m 10 -o "$work/usage.json" -w "%{http_code}" \
      -H @/dev/fd/3 3<<<"Authorization: Bearer $H2_ADMIN_TOKEN" \
      "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/keys/${kid}/usage")" \
      || { echo "usage-transport-failed"; exit 0; }
    if python3 "$here/judge-unpriced.py" "$usage_status" "$work/usage.json" "$work/busbar.log"; then
      echo "served-usage-refused-unpriced"
    else
      echo "incorrect-unpriced-evidence"
    fi
  ' _ "$here" "${WORK_ROOT}/on"
)"

failures=0
detail=""

# ARM 1 must SERVE and must bill exactly the flat fee.
read -r off_status off_spend <<<"$arm_off"
if [ "$off_status" != "200" ]; then
  failures=$((failures+1))
  detail="${detail}arm 1 (billing OFF, rate_card absent) answered ${off_status}(want 200: an unbilled plane still serves -- #42's failover/routing-proxy deployment); "
elif [ "${off_spend:-x}" != "1" ]; then
  failures=$((failures+1))
  detail="${detail}arm 1 (billing OFF) billed spend_cents=${off_spend}(want exactly 1, the flat per_request_fee and nothing else); "
fi

# ARM 2 must warn and serve, then refuse the monetary read with the exact reason.
if [ "$arm_on" != "served-usage-refused-unpriced" ]; then
  failures=$((failures+1))
  detail="${detail}arm 2 (billing ON, bytes unpriced) failed warning/served-call/HTTP409 unpriced_class checks: ${arm_on:-empty}; "
fi

if [ "$failures" -eq 0 ]; then
  printf 'PASS\t%s\n' "billing OFF serves and bills the flat fee alone; billing ON warns and serves, then its monetary read refuses with HTTP409 unpriced_class naming bytes"
else
  printf 'FAIL\t%s\n' "$detail"
  exit 1
fi
