#!/usr/bin/env bash
# The first end-to-end demo of ZTC: ztc-ca, ztc-pdp, a protected upstream and
# ztc-pep on localhost, and four requests that show the decision chain of
# NIST SP 800-207. It exits 0 only if every request got the status it should.
#
#   200  a PMU with a token from ztc-ca writes telemetry
#   401  a request with an invalid token, and one without a token
#   403  the same PMU after the IDS has reported it compromised
#   503  the same PMU with the PDP stopped: fail closed
#
# Every key and secret lives in a temporary directory that only the user can
# read and that is removed at the end. Secrets reach curl through header
# files, and the PDP token reaches the services through the environment,
# never through arguments, which ps would show to every user. The processes
# are stopped by their PIDs, never by name, so nothing else on the machine is
# hit.
#
# Usage: scripts/demo.sh    (or: make demo)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="$repo_root/bin"

# Ports away from the defaults, so the demo runs next to services you have
# started yourself.
ca_port=18090
pdp_port=18181
upstream_port=19000
pep_port=18080

umask 077
work_dir="$(mktemp -d)"
process_ids=()
failures=0

# stop_everything stops every process the demo started and removes the
# temporary directory. It runs on every exit, also after an error or Ctrl+C.
stop_everything() {
  for process_id in ${process_ids[@]+"${process_ids[@]}"}; do
    kill "$process_id" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$work_dir"
}
trap stop_everything EXIT

# start runs a command in the background with its output in <name>.log, and
# remembers its PID in process_ids and in last_process_id.
start() {
  local name="$1"
  shift
  "$@" >"$work_dir/$name.log" 2>&1 &
  last_process_id=$!
  process_ids+=("$last_process_id")
}

# wait_until_ready waits up to ten seconds for url to answer 200. If it does
# not, it prints the log of name and stops the demo.
wait_until_ready() {
  local name="$1" url="$2"
  for _ in $(seq 1 100); do
    if curl -fs -o /dev/null "$url"; then
      return 0
    fi
    sleep 0.1
  done
  echo "$name did not become ready at $url. Its log:" >&2
  cat "$work_dir/$name.log" >&2
  exit 1
}

# status_of sends a POST with telemetry through the PEP, with the headers in
# header_file if it is not empty, and prints the status code.
status_of() {
  local header_file="$1"
  local header_option=()
  if [[ -n "$header_file" ]]; then
    header_option=(-H "@$header_file")
  fi
  curl -s -o /dev/null -w '%{http_code}' -X POST ${header_option[@]+"${header_option[@]}"} \
    -d '{"voltage":230.1}' "http://127.0.0.1:$pep_port/bay-1/telemetry/pmu-1"
}

# expect prints whether got equals want, and counts the failures.
expect() {
  local description="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    printf '  PASS  %-46s %s\n' "$description" "$got"
  else
    printf '  FAIL  %-46s %s, want %s\n' "$description" "$got" "$want"
    failures=$((failures + 1))
  fi
}

echo "Building the services"
make -C "$repo_root" --no-print-directory build >/dev/null

echo "Creating keys and secrets in $work_dir"
"$bin/ztcctl" keys gen -out "$work_dir/ca.key" >"$work_dir/ca.pub" 2>/dev/null
python3 -c 'import secrets; print(secrets.token_hex(32))' >"$work_dir/pmu.secret"
python3 -c 'import secrets; print(secrets.token_hex(32))' >"$work_dir/pdp.token"
pmu_secret_hash="$(tr -d '\n' <"$work_dir/pmu.secret" | python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
printf 'Authorization: Bearer %s\n' "$(cat "$work_dir/pmu.secret")" >"$work_dir/pmu-secret.header"
printf 'Authorization: Bearer not-a-token\n' >"$work_dir/invalid-token.header"

# The PDP token goes to ztc-pdp, ztc-pep and ztcctl through the environment,
# which, unlike arguments, other users cannot read.
ZTC_PDP_TOKEN="$(cat "$work_dir/pdp.token")"
export ZTC_PDP_TOKEN

cat >"$work_dir/clients.json" <<CLIENTS
{"clients": [{
  "secretSHA256": "$pmu_secret_hash",
  "subject": "spiffe://grid.example/edge/pmu/1",
  "audience": ["ztc-pep"],
  "scope": ["telemetry:write"],
  "zone": "bay-1"
}]}
CLIENTS
cat >"$work_dir/routes.json" <<ROUTES
[{"prefix": "/bay-1/telemetry/", "upstream": "http://127.0.0.1:$upstream_port",
  "resourceType": "telemetry", "zone": "bay-1", "layer": "fog", "sensitivity": 1}]
ROUTES

echo "Starting ztc-ca, ztc-pdp, the upstream and ztc-pep"
start ztc-ca env ZTC_LISTEN="127.0.0.1:$ca_port" ZTC_CA_KEY_FILE="$work_dir/ca.key" \
  ZTC_CA_CLIENTS_FILE="$work_dir/clients.json" "$bin/ztc-ca"
start ztc-pdp env ZTC_LISTEN="127.0.0.1:$pdp_port" "$bin/ztc-pdp"
pdp_process_id=$last_process_id
start upstream python3 "$repo_root/scripts/demo-upstream.py" "$upstream_port"
wait_until_ready ztc-ca "http://127.0.0.1:$ca_port/healthz"
wait_until_ready ztc-pdp "http://127.0.0.1:$pdp_port/healthz"
wait_until_ready upstream "http://127.0.0.1:$upstream_port/"
start ztc-pep env ZTC_LISTEN="127.0.0.1:$pep_port" ZTC_PEP_ROUTES_FILE="$work_dir/routes.json" \
  ZTC_PEP_SOURCE_ZONE=substation-lan ZTC_PDP_URL="http://127.0.0.1:$pdp_port" \
  ZTC_CA_URL="http://127.0.0.1:$ca_port" "$bin/ztc-pep"
wait_until_ready ztc-pep "http://127.0.0.1:$pep_port/readyz"

echo "The PMU gets a token from ztc-ca"
curl -fs -X POST -H "@$work_dir/pmu-secret.header" "http://127.0.0.1:$ca_port/v1/token" |
  python3 -c 'import json, sys; print("Authorization: Bearer " + json.load(sys.stdin)["token"])' \
    >"$work_dir/pmu-token.header"

echo "Requests through ztc-pep:"
expect "PMU with a valid token writes telemetry" 200 "$(status_of "$work_dir/pmu-token.header")"
expect "invalid token" 401 "$(status_of "$work_dir/invalid-token.header")"
expect "no token" 401 "$(status_of "")"

ZTC_PDP_URL="http://127.0.0.1:$pdp_port" "$bin/ztcctl" signal -subject spiffe://grid.example/edge/pmu/1 -kind behaviour -value 0.95
expect "the same PMU after the IDS reports it" 403 "$(status_of "$work_dir/pmu-token.header")"

kill "$pdp_process_id"
wait "$pdp_process_id" 2>/dev/null || true
expect "the same PMU with the PDP stopped" 503 "$(status_of "$work_dir/pmu-token.header")"

if ((failures > 0)); then
  echo "$failures request(s) got the wrong status. The log of ztc-pep:"
  cat "$work_dir/ztc-pep.log"
  exit 1
fi
echo "All requests got the status they should."
