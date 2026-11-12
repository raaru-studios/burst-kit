#!/usr/bin/env bash
# user-data.sh — burst-compute first-boot script (SPEC §5, §7, §9.4).
#
# Cloud-init user-data for the burst box. Runs ONCE at first boot as
# root. It does exactly these things, in this order (launch checklist
# step 5):
#   1. Fetch bootstrap.sh, orchestrator.py, cold-run-battery.sh, and the
#      linted manifest from KIT_SOURCE, machine-to-machine, and verify
#      each file's sha256 against the hashes recorded at checklist
#      step 0. A hash mismatch aborts loudly — no launch on unverified
#      kit bytes (SPEC §8.2).
#   2. Arm the self-terminate (§9.4): schedule `shutdown -h now` at
#      derived max_hours MINUS 15 minutes after boot. With
#      --instance-initiated-shutdown-behavior terminate (checklist
#      step 4) the shutdown destroys the box. If arming fails, the
#      script dies LOUDLY — a box with no self-terminate never runs
#      jobs (VAULT V-R02: this was prose only until this file).
#   3. Run `bash bootstrap.sh` (KVM gate first, toolchain phases with
#      retry + fail-closed). A failed phase aborts here — the
#      orchestrator never starts on a half-built box.
#   4. On bootstrap success, start the orchestrator detached, passing
#      --hourly-price AND --box-launch-epoch (VAULT V-R06: the cost
#      clock starts at box launch, so the bootstrap tax is inside the
#      cap — the epoch is recorded at the top of this script, before
#      anything else bills time).
#
# OPERATOR FILLS IN BEFORE LAUNCH (checklist step 5): the four
# REQUIRED variables below. The script FAILS LOUDLY if any is unset
# or empty — it never guesses a kit location, a price, a runtime, or
# a hash list. KIT_SOURCE is undesignated until the operator names it
# (IGNITION N-3, still open): it is a location prefix the box fetches
# the four files from — http(s)://..., s3://..., or file://... — and
# the operator records it in the launch record. Do NOT improvise a
# transport at launch time.
#
# Exit codes: 0 user-data complete, orchestrator started detached.
#   1 any loud failure above (unset variable, fetch failure, hash
#     mismatch, self-terminate arming failure, bootstrap failure).
#   The orchestrator's own exit code is in its log, not this script's.
#
# Verification on the box (checklist step 7): bootstrap log ends
# `bootstrap complete`; `self-terminate.armed` lists the scheduled
# shutdown; `systemctl list-timers` (or ps) shows the armed timer;
# orchestrator log exists under $BURST_HOME/logs/.

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
BURST_HOME="${BURST_HOME:-/opt/burst}"
KIT_DIR="${KIT_DIR:-$BURST_HOME/kit}"
MANIFEST_FILE="${MANIFEST_FILE:-manifest.yaml}"
LOG="${BURST_USER_DATA_LOG:-/var/log/burst-user-data.log}"

# ------------------------------------------------------------------ logging
mkdir -p "$(dirname "$LOG")" "$BURST_HOME/logs" "$KIT_DIR"
exec > >(tee -a "$LOG") 2>&1

log()  { printf '[user-data %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die()  { log "FATAL: $*"; exit 1; }

# ------------------------------------------------------------------ 0. epoch
# Recorded FIRST, before any fetch or install bills time: this is the
# cost clock's start (V-R06). Everything the box does from here on is
# inside the cap because the clock already runs.
BOX_LAUNCH_EPOCH="$(date +%s)"
log "box launch epoch: $BOX_LAUNCH_EPOCH ($(date -u -d "@$BOX_LAUNCH_EPOCH" +%Y-%m-%dT%H:%M:%SZ))"

# ------------------------------------------------------- 0b. required vars
[ -n "$KIT_SOURCE" ]       || die "KIT_SOURCE is unset — the kit source is undesignated (IGNITION N-3): name the read-only location the box fetches bootstrap.sh, orchestrator.py, cold-run-battery.sh, and the manifest from, and record it in the launch record. No launch without it."
[ -n "$HOURLY_PRICE_USD" ] || die "HOURLY_PRICE_USD is unset — pass the live \$/hr from the pre-flight print (checklist step 2). No launch without it."
[ -n "$MAX_HOURS" ]        || die "MAX_HOURS is unset — pass the derived max_hours from the pre-flight print (checklist step 2: min(6, (cap - \$0.50) / live price)). No launch without it."
[ -n "$KIT_SHA256S" ]      || die "KIT_SHA256S is unset — pass the sha256sum-format lines for the four kit files, recorded at checklist step 0. No launch on unverified kit bytes (SPEC §8.2)."
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

# ---------------------------------------------------------------- 1. fetch
# Fetch machine-to-machine (SPEC §5 pull model). Supported schemes:
# http(s):// (curl), s3:// (aws s3 cp — needs the instance profile;
# without it the fetch fails loudly here, never silently), file://
# (local copy — testing / a mounted read-only volume). Anything else
# is refused: the transport is designated, not improvised.
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
fetch_one "$MANIFEST_FILE"
chmod +x "$KIT_DIR/bootstrap.sh" "$KIT_DIR/orchestrator.py" \
  "$KIT_DIR/cold-run-battery.sh"

# ------------------------------------------------------- 1b. hash verify
# KIT_SHA256S holds sha256sum-format lines ("<sha256>  <filename>")
# for exactly the four files above, as recorded at checklist step 0.
printf '%s\n' "$KIT_SHA256S" > "$KIT_DIR/kit.sha256"
(cd "$KIT_DIR" && sha256sum -c kit.sha256) \
  || die "HASH MISMATCH: a fetched kit file does not match the step-0 hashes — aborting, no launch on unverified kit bytes (SPEC §8.2)"
log "kit hashes verified (sha256sum -c clean)"

# ------------------------------------------------- 2. arm self-terminate
# self-terminate-arm-begin
# arm_self_terminate <minutes> <epoch> — schedule `shutdown -h now`
# at <minutes> after boot. systemd timer first (survives the whole
# run as a unit, visible in `systemctl list-timers`); a detached
# setsid sleep as fallback. Either way the arming is verified before
# this function returns, and its record lands in
# $BURST_HOME/self-terminate.armed for checklist step 7.
# NOTE: keep this function between the self-terminate-arm-begin/end
# markers — the unit test extracts exactly this block from this file
# and tests the real code, not a copy.
arm_self_terminate() {
  local minutes="$1" epoch="$2"
  local armed_file="$BURST_HOME/self-terminate.armed"
  local mechanism=""
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
arm_self_terminate "$SELF_TERMINATE_MIN" "$SELF_TERMINATE_EPOCH"

# ------------------------------------------------------- 3. bootstrap
log "running bootstrap.sh (BURST_HOME=$BURST_HOME)"
export BURST_HOME
(cd "$KIT_DIR" && bash bootstrap.sh) \
  || die "bootstrap.sh FAILED — campaign aborted at bootstrap, orchestrator never started (SPEC §7, §12)"
log "bootstrap complete"

# ---------------------------------------------------- 4. start orchestrator
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
