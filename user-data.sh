#!/usr/bin/env bash
# user-data.sh — burst-compute first-boot script (SPEC §5, §7, §9.4).
# Runs ONCE at boot as root: arms the 60-min default self-terminate,
# installs the launch-injected deploy-keys bundle, fetches the kit
# (bootstrap.sh, orchestrator.py, cold-run-battery.sh, manifest,
# parallel-lock.json) from KIT_SOURCE and hash-verifies it, re-arms
# self-terminate at MAX_HOURS-15m, runs bootstrap.sh (KVM gate first),
# then starts the orchestrator detached. Fails loudly on any bad step.
# Payload produced ONLY by kit/render-user-data.py (fills the REQUIRED
# vars + injects keys); never hand-edit a payload. SMOKE=1 proves
# bootstrap + self-terminate + SSH only (no manifest, no orchestrator).
# Full procedure: kit/LAUNCH_CHECKLIST.md. Exit 0 = orchestrator
# started (or SMOKE proof done); 1 = loud failure above.
set -euo pipefail

# ------------------------------------------------------------------ fill-ins
# REQUIRED — the operator fills these in before launch. Empty defaults
# are deliberate: an unfilled variable must fail loudly below, never
# silently take a guessed value.
KIT_SOURCE="${KIT_SOURCE:-}"
HOURLY_PRICE_USD="${HOURLY_PRICE_USD:-}"
MAX_HOURS="${MAX_HOURS:-}"
KIT_SHA256S="${KIT_SHA256S:-}"

# Optional, with safe defaults.
CAMPAIGN="${CAMPAIGN:-camp-1}"
SMOKE="${SMOKE:-0}"   # SMOKE=1: bootstrap proof only — no manifest fetch, no orchestrator start (F-3).
BURST_HOME="${BURST_HOME:-/opt/burst}"
KIT_DIR="${KIT_DIR:-$BURST_HOME/kit}"
MANIFEST_FILE="${MANIFEST_FILE:-manifest.yaml}"
LOG="${BURST_USER_DATA_LOG:-/var/log/burst-user-data.log}"
DEPLOY_KEYS_DIR="${DEPLOY_KEYS_DIR:-$BURST_HOME/deploy-keys}"
# DEPLOY_KEYS_BUNDLE: '<name>:<base64-key>' lines, injected at launch by the render;
# the committed file carries NO key material. Rendered payloads are 0600, never committed.
DEPLOY_KEYS_BUNDLE=""

# ------------------------------------------------------------------ logging
mkdir -p "$(dirname "$LOG")" "$BURST_HOME/logs" "$KIT_DIR"
exec > >(tee -a "$LOG") 2>&1

log()  { printf '[user-data %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die()  { log "FATAL: $*"; exit 1; }

# ------------------------------------------- arm self-terminate (function)
# Defined up here, before §0, so the 60-minute default arm can run
# immediately after the epoch — before the vars check, the fetch, or
# the hash verify can fail (F-2). The §2 re-arm calls the same
# function with the derived value.
# self-terminate-arm-begin
# arm_self_terminate <minutes> <epoch> — schedule `shutdown -h now`
# at <minutes> after boot. systemd timer first (survives the whole
# run as a unit, visible in `systemctl list-timers`); a detached
# setsid sleep as fallback. Either way the arming is verified before
# this function returns, and its record lands in
# $BURST_HOME/self-terminate.armed for checklist step 7.
# Re-arming cancels any earlier arm first (the §0 60-minute default,
# if this is the §2 re-arm) so exactly one shutdown is ever
# scheduled — stopping a nonexistent unit is harmless (|| true).
# NOTE: keep this function between the self-terminate-arm-begin/end
# markers — the unit test extracts exactly this block from this file
# and tests the real code, not a copy.
arm_self_terminate() {
  local minutes="$1" epoch="$2"
  local armed_file="$BURST_HOME/self-terminate.armed"
  local mechanism=""
  systemctl stop burst-self-terminate.timer 2>/dev/null || true
  systemctl stop burst-self-terminate.service 2>/dev/null || true
  systemctl reset-failed burst-self-terminate.service 2>/dev/null || true
  pkill -f "burst-self-terminate" 2>/dev/null || true
  if command -v systemd-run >/dev/null 2>&1 \
      && systemd-run --on-active="${minutes}min" \
           --unit=burst-self-terminate \
           --description="Burst self-terminate (SPEC 9.4)" \
           /sbin/shutdown -h now 2>/dev/null; then
    # Transient timer creation can lag the list call; retry briefly
    # before concluding the systemd path failed — arming BOTH
    # mechanisms at once would leave a stray timer behind.
    for _ in 1 2 3 4 5; do
      if systemctl list-timers --all 2>/dev/null \
           | grep -q "burst-self-terminate"; then
        mechanism="systemd-timer"
        break
      fi
      sleep 1
    done
  fi
  if [ -z "$mechanism" ]; then
    # systemd path unavailable or failed (e.g. not the init system):
    # a detached setsid sleep is the fallback — still an armed
    # shutdown, still verified below. Stop any stray timer first so
    # exactly one mechanism is armed. Only a failure to arm by EITHER
    # mechanism is fatal.
    systemctl stop burst-self-terminate.timer 2>/dev/null || true
    setsid nohup bash -c "sleep $((minutes * 60)); exec /sbin/shutdown -h now" burst-self-terminate \
      >/dev/null 2>&1 < /dev/null &
    sleep 2
    if pgrep -f "burst-self-terminate" >/dev/null; then
      mechanism="setsid-sleep"
    else
      die "self-terminate arming FAILED by both mechanisms — no launch without the §9.4 backstop (V-R02)"
    fi
  fi
  printf 'armed_at_epoch=%s\nscheduled_shutdown_epoch=%s\nminutes_after_boot=%s\nmechanism=%s\n' \
    "$BOX_LAUNCH_EPOCH" "$epoch" "$minutes" "$mechanism" \
    > "$armed_file"
  log "self-terminate ARMED ($mechanism): shutdown at ${minutes}m after boot (epoch $epoch) — record in $armed_file"
}
# self-terminate-arm-end

# Install the injected deploy-keys bundle into $DEPLOY_KEYS_DIR (0700, keys 0600).
# Fails loudly on an empty bundle unless SMOKE=1; each key must be an OpenSSH key.
install_deploy_keys() {
  if [ "$SMOKE" = "1" ]; then
    log "SMOKE=1 — no deploy keys installed (orchestrator not started)"
    return 0
  fi
  [ -n "$DEPLOY_KEYS_BUNDLE" ] \
    || die "DEPLOY_KEYS_BUNDLE is empty — render the launch payload with kit/render-user-data.py --keys-dir <estate keys dir> (a campaign launch with no deploy keys burns the run on 401s; the bundle is injected at launch time only and never committed)"
  local keys_dir="$DEPLOY_KEYS_DIR"
  mkdir -p "$keys_dir" || die "cannot create $keys_dir"
  chmod 0700 "$keys_dir"
  local count=0 name b64
# Bundle lines are '<name>:<base64>'; split on the first ':' only.
  while IFS=: read -r name b64 || [ -n "$name" ]; do
    [ -n "$name" ] && [ -n "$b64" ] || die "malformed deploy-keys bundle line (expected <name>:<base64>)"
    case "$name" in *[!a-zA-Z0-9_-]*) die "malformed deploy-keys bundle name: '$name'" ;; esac
    printf '%s' "$b64" | base64 -d > "$keys_dir/$name" \
      || die "base64 decode failed for deploy key '$name'"
    chmod 0600 "$keys_dir/$name"
    # A decoded key must be an OpenSSH private key — a corrupted
    # bundle fails here, never hands ssh a garbage file.
    head -1 "$keys_dir/$name" | grep -q '^-----BEGIN OPENSSH PRIVATE KEY-----$' \
      || die "decoded deploy key '$name' is not an OpenSSH private key — bundle corrupted"
    count=$((count + 1))
  done < <(printf '%s' "$DEPLOY_KEYS_BUNDLE")
  [ "$count" -gt 0 ] || die "deploy-keys bundle decoded to zero keys"
  log "deploy keys installed: $count keys in $keys_dir (0600 each)"
}

# ------------------------------------------------------------------ 0. epoch
# Recorded FIRST, before any fetch or install bills time: this is the
# cost clock's start (V-R06). Everything the box does from here on is
# inside the cap because the clock already runs.
BOX_LAUNCH_EPOCH="$(date +%s)"
log "box launch epoch: $BOX_LAUNCH_EPOCH ($(date -u -d "@$BOX_LAUNCH_EPOCH" +%Y-%m-%dT%H:%M:%SZ))"

# F-2: arm the 60-minute DEFAULT self-terminate NOW, before the
# required-vars check, the fetch, or the hash verify can fail — a box
# must never run without a scheduled shutdown. Re-armed with the
# derived value at §2 once MAX_HOURS is validated.
arm_self_terminate 60 $((BOX_LAUNCH_EPOCH + 3600))

# ------------------------------------------------------- 0b. required vars
[ -n "$KIT_SOURCE" ]       || die "KIT_SOURCE is unset — the kit source is undesignated (IGNITION N-3): name the read-only location the box fetches bootstrap.sh, orchestrator.py, cold-run-battery.sh, the manifest, and parallel-lock.json from, and record it in the launch record. No launch without it."
[ -n "$HOURLY_PRICE_USD" ] || die "HOURLY_PRICE_USD is unset — pass the live \$/hr from the pre-flight print (checklist step 2). No launch without it."
[ -n "$MAX_HOURS" ]        || die "MAX_HOURS is unset — pass the derived max_hours from the pre-flight print (checklist step 2: min(6, (cap - \$0.50) / live price)). No launch without it."
[ -n "$KIT_SHA256S" ]      || die "KIT_SHA256S is unset — pass the sha256sum-format lines for the kit files, recorded at checklist step 0 (five lines for a campaign, three for SMOKE=1 — the smoke fetches no manifest and no lock registry). No launch on unverified kit bytes (SPEC §8.2)."
case "$MAX_HOURS" in
  ''|*[!0-9.]*)
    die "MAX_HOURS='$MAX_HOURS' is not a number — pass the derived max_hours (checklist step 2)." ;;
esac
# max_hours hard cap is 6 (SPEC §3); self-terminate needs > 15 min of room.
if ! awk -v h="$MAX_HOURS" 'BEGIN { exit !(h > 0.25 && h <= 6) }'; then
  die "MAX_HOURS='$MAX_HOURS' out of range — must be > 0.25 and <= 6 (SPEC §3 hard cap of 6 hours; self-terminate needs max_hours minus 15 minutes to stay positive)."
fi
SELF_TERMINATE_MIN="$(awk -v h="$MAX_HOURS" 'BEGIN { printf "%d", h * 60 - 15 }')"
SELF_TERMINATE_S=$((SELF_TERMINATE_MIN * 60))
SELF_TERMINATE_EPOCH=$((BOX_LAUNCH_EPOCH + SELF_TERMINATE_S))
log "derived max_hours=$MAX_HOURS — self-terminate at ${SELF_TERMINATE_MIN}m after boot (epoch $SELF_TERMINATE_EPOCH)"

# ---------------------------------------------------------------- 0c. keys
# Install the launch-injected deploy-keys bundle (§8.1) before any
# fetch or clone can need it. Fails loudly on an empty bundle unless
# SMOKE=1 (see install_deploy_keys above).
install_deploy_keys

# 1. Fetch kit files machine-to-machine from KIT_SOURCE (curl / aws s3 cp / cp).
fetch_one() {
  # Two statements, not one: bash expands every RHS of a single
  # `local` before assigning any of them, so
  # `local name="$1" dest="$KIT_DIR/$name"` dies under `set -u`.
  local name="$1"
  local dest="$KIT_DIR/$name"
  log "fetch: $name <- $KIT_SOURCE/$name"
  case "$KIT_SOURCE" in
    http://*|https://*)
      curl -fsSL "$KIT_SOURCE/$name" -o "$dest" \
        || die "fetch failed: $name from $KIT_SOURCE (curl rc=$?)" ;;
    s3://*)
      command -v aws >/dev/null 2>&1 \
        || die "fetch failed: aws CLI missing — cannot fetch $name from $KIT_SOURCE"
      aws s3 cp "$KIT_SOURCE/$name" "$dest" \
        || die "fetch failed: $name from $KIT_SOURCE (aws s3 cp rc=$?)" ;;
    file://*)
      cp "${KIT_SOURCE#file://}/$name" "$dest" \
        || die "fetch failed: $name from $KIT_SOURCE (cp rc=$?)" ;;
    *)
      die "KIT_SOURCE='$KIT_SOURCE' has an unsupported scheme — use http(s)://, s3://, or file:// (the transport is designated by the operator, never improvised)" ;;
  esac
}
fetch_one bootstrap.sh
fetch_one orchestrator.py
fetch_one cold-run-battery.sh
if [ "$SMOKE" = "1" ]; then
  log "SMOKE=1 — no manifest fetch (the smoke fetches no manifest, F-3)"
else
  fetch_one "$MANIFEST_FILE"
  fetch_one parallel-lock.json
fi
chmod +x "$KIT_DIR/bootstrap.sh" "$KIT_DIR/orchestrator.py" \
  "$KIT_DIR/cold-run-battery.sh"

# 1b. Verify fetched kit hashes (sha256sum -c); a mismatch aborts loudly.
printf '%s\n' "$KIT_SHA256S" > "$KIT_DIR/kit.sha256"
(cd "$KIT_DIR" && sha256sum -c kit.sha256) \
  || die "HASH MISMATCH: a fetched kit file does not match the step-0 hashes — aborting, no launch on unverified kit bytes (SPEC §8.2)"
log "kit hashes verified (sha256sum -c clean)"

# 2. Re-arm self-terminate with the derived value (cancels the 60-min default first).
arm_self_terminate "$SELF_TERMINATE_MIN" "$SELF_TERMINATE_EPOCH"

# ------------------------------------------------------- 3. bootstrap
log "running bootstrap.sh (BURST_HOME=$BURST_HOME)"
export BURST_HOME
(cd "$KIT_DIR" && bash bootstrap.sh) \
  || die "bootstrap.sh FAILED — campaign aborted at bootstrap, orchestrator never started (SPEC §7, §12)"
log "bootstrap complete"

# ---------------------------------------------------- 4. start orchestrator
# F-3: with SMOKE=1 the smoke stops after bootstrap — no manifest was
# fetched and the orchestrator is NOT started. The smoke proves
# bootstrap + self-terminate + SSH only.
if [ "$SMOKE" = "1" ]; then
  log "SMOKE=1 — bootstrap proof only: orchestrator NOT started, no manifest was fetched"
  log "user-data complete — smoke box: bootstrap proven, self-terminate armed at ${SELF_TERMINATE_MIN}m; the operator terminates it (SMOKE_TEST.md step 6)"
  exit 0
fi
# Detached: user-data must return; the orchestrator owns the campaign
# from here. Its log is the run's first artifact; the state-pull
# (checklist step 9) reads state.json out of the bundle it writes.
ORCH_LOG="$BURST_HOME/logs/orchestrator.log"
log "starting orchestrator (campaign=$CAMPAIGN, hourly-price=\$$HOURLY_PRICE_USD/hr, box-launch-epoch=$BOX_LAUNCH_EPOCH)"
setsid nohup python3 "$KIT_DIR/orchestrator.py" "$KIT_DIR/$MANIFEST_FILE" \
  --out "$BURST_HOME/results/$CAMPAIGN" \
  --work "$BURST_HOME/work/$CAMPAIGN" \
  --hourly-price "$HOURLY_PRICE_USD" \
  --box-launch-epoch "$BOX_LAUNCH_EPOCH" \
  --keys-dir "$DEPLOY_KEYS_DIR" \
  --lock-registry "$KIT_DIR/parallel-lock.json" \
  > "$ORCH_LOG" 2>&1 < /dev/null &
ORCH_PID=$!
# A short campaign can FINISH inside this window — a dead PID is
# success when the log carries the campaign completion line, and
# failure only when it carries neither a live process nor that line.
for _ in $(seq 1 10); do
  if kill -0 "$ORCH_PID" 2>/dev/null; then
    log "orchestrator started (pid $ORCH_PID, log $ORCH_LOG)"
    break
  fi
  if grep -qF "campaign $CAMPAIGN:" "$ORCH_LOG" 2>/dev/null; then
    log "orchestrator already finished (fast campaign — completion line in $ORCH_LOG)"
    break
  fi
  sleep 1
done
if ! kill -0 "$ORCH_PID" 2>/dev/null \
    && ! grep -qF "campaign $CAMPAIGN:" "$ORCH_LOG" 2>/dev/null; then
  die "orchestrator exited immediately (pid $ORCH_PID) without a campaign completion line — see $ORCH_LOG"
fi
log "user-data complete — box is running the campaign; self-terminate armed at ${SELF_TERMINATE_MIN}m"
exit 0
