#!/usr/bin/env bash
# boot-avd.sh — per-job Android emulator provisioning for the burst box.
#
# The gap it closes (found 2026-11-11, competitive audit): the estate
# cold-run battery assumes "an emulator already booted on the box with
# adb on PATH (the EMULATE leg's harness boots the AVD)" — but no such
# harness existed anywhere in the kit. Nothing created an AVD
# (bootstrap installs the emulator + system image and stops), nothing
# booted one, and the battery uses bare `adb` with no serial — so 8
# concurrent EMULATE workers would share one device (or none), and the
# P0 wait loop would burn 10 min per job waiting for a boot that never
# comes. The opening gate job (booth-l3, EMULATE) would fail on this
# alone, aborting the push at ~$0.50 on a harness gap rather than on
# the method. A rival team ships per-job AVDs; this is ours.
#
# Model: ONE base AVD (`burst-api36`, API 36 google_apis x86_64, created
# once, idempotent). Each EMULATE job boots its OWN emulator instance
# from that AVD with a unique console port (`-port <port>`), `-read-only`
# (each instance gets throwaway userdata, so concurrent instances never
# clobber each other), `-no-window -no-audio -no-boot-anim`, and the
# orchestrator sets ANDROID_SERIAL=emulator-<port> in the job env so
# the battery's bare `adb` calls land on exactly that device (adb
# honors ANDROID_SERIAL when set — no battery change needed).
#
# Snapshot fast-path (SPEC §11a-5): `boot-avd.sh snapshot` boots the
# base AVD once, waits for boot, saves snapshot `burst-ready`, and
# kills it. Later `boot` invocations pass `-snapshot burst-ready` when
# the snapshot exists (~10-20s to a booted device vs ~60-120s cold).
# Snapshot creation is best-effort and non-fatal: a missing snapshot
# just means a cold boot.
#
# Usage:
#   boot-avd.sh create            create the base AVD if missing (idempotent)
#   boot-avd.sh snapshot          save the `burst-ready` snapshot (best-effort)
#   boot-avd.sh boot <job-id> <port> [--dry-run]
#                                 boot a per-job emulator; prints
#                                 AVD_SERIAL=emulator-<port> on success
#   boot-avd.sh kill <serial> [--dry-run]
#                                 kill the emulator with that serial
#   boot-avd.sh --dry-run <cmd>  print the commands without running them
#
# Exit codes: 0 ok · 1 usage / boot failure / kill failure.
# Requires ANDROID_HOME (default /opt/burst/android-sdk, same as the
# orchestrator's job_env). Never touches the network except through
# avdmanager/emulator/adb themselves. No secrets, no AWS calls.
set -u

# The orchestrator's job environment may carry no HOME (cloud-init
# user-data runs without one); snapshot_exists() dereferences $HOME
# under `set -u`, and avdmanager keeps AVDs under $HOME/.android.
# Default it in the same idiom as bootstrap.sh / user-data.sh so the
# AVD home is the same /root the bootstrap toolchain used.
export HOME="${HOME:-/root}"

ANDROID_HOME="${ANDROID_HOME:-/opt/burst/android-sdk}"
AVD_NAME="${AVD_NAME:-burst-api36}"
SYSTEM_IMAGE="${SYSTEM_IMAGE:-system-images;android-36;google_apis;x86_64}"
DEVICE_DEF="${DEVICE_DEF:-pixel_7}"
SNAPSHOT_NAME="${SNAPSHOT_NAME:-burst-ready}"
BOOT_TIMEOUT_S="${BOOT_TIMEOUT_S:-600}"
DRY_RUN=0

log() { printf '[boot-avd %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# run <label> <cmd...> — in dry-run, print the command instead of running it.
run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '[dry-run] %s\n' "$*" >&2
    return 0
  fi
  "$@"
}

need_tools() {
  # Dry-run exists to show the commands on a machine with no SDK (e.g.
  # the estate VM): it must not die on missing tools.
  if [ "$DRY_RUN" = "1" ]; then
    export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH"
    return 0
  fi
  for t in "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" \
           "$ANDROID_HOME/emulator/emulator" \
           "$ANDROID_HOME/platform-tools/adb"; do
    [ -x "$t" ] || die "missing tool: $t (bootstrap android-sdk phase not done?)"
  done
  export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH"
}

avd_exists() {
  # Dry-run: pretend the AVD is missing so the create path prints.
  [ "$DRY_RUN" = "1" ] && return 1
  "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" list avd 2>/dev/null \
    | grep -q "Name: $AVD_NAME"
}

cmd_create() {
  need_tools
  if avd_exists; then
    log "base AVD $AVD_NAME already exists — skipping create"
    return 0
  fi
  log "creating base AVD $AVD_NAME ($SYSTEM_IMAGE, $DEVICE_DEF)"
  # `echo no` declines the custom-hardware-profile prompt.
  run bash -c "echo no | \"\$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager\" create avd -n \"$AVD_NAME\" -k \"$SYSTEM_IMAGE\" -d \"$DEVICE_DEF\" --force" \
    || die "avdmanager create avd failed"
  log "base AVD $AVD_NAME created"
}

snapshot_exists() {
  # Dry-run: pretend no snapshot exists so boot prints the cold-boot path.
  [ "$DRY_RUN" = "1" ] && return 1
  # Snapshots live under the AVD dir as snapshots/<name>.img (newer
  # emulator) or in snapshots.img; check both, best-effort.
  local avd_dir="$HOME/.android/avd/$AVD_NAME.avd"
  [ -d "$avd_dir/snapshots/$SNAPSHOT_NAME" ] \
    || [ -f "$avd_dir/snapshots.img" ]
}

cmd_snapshot() {
  need_tools
  cmd_create
  if snapshot_exists; then
    log "snapshot $SNAPSHOT_NAME already exists — skipping"
    return 0
  fi
  # Boot the base AVD on a scratch port, wait for boot, save the
  # snapshot, kill it. Best-effort: a failure here only costs the
  # fast path — later boots fall back to cold boot.
  local port=5580
  log "snapshot: booting base AVD on port $port to capture $SNAPSHOT_NAME"
  if ! cmd_boot "__snapshot__" "$port"; then
    log "snapshot: boot failed — skipping snapshot (cold boot still works)"
    return 0
  fi
  local serial="emulator-$port"
  if run "$ANDROID_HOME/platform-tools/adb" -s "$serial" emu avd snapshot save "$SNAPSHOT_NAME"; then
    log "snapshot $SNAPSHOT_NAME saved"
  else
    log "snapshot: save failed (non-fatal — cold boot still works)"
  fi
  cmd_kill "$serial" || true
  return 0
}

# cmd_boot <job-id> <port> — boot one per-job emulator; prints
# AVD_SERIAL=emulator-<port> on stdout on success.
cmd_boot() {
  local job_id="$1" port="$2"
  need_tools
  cmd_create
  local serial="emulator-$port"
  local emu_args=(
    -avd "$AVD_NAME" -port "$port"
    -no-window -no-audio -no-boot-anim -read-only -no-snapshot-save
    -gpu swiftshader_indirect -memory 4096
  )
  if snapshot_exists; then
    emu_args+=(-snapshot "$SNAPSHOT_NAME")
    log "job $job_id: booting $serial from snapshot $SNAPSHOT_NAME"
  else
    log "job $job_id: cold-booting $serial (no snapshot yet)"
  fi
  if [ "$DRY_RUN" = "1" ]; then
    printf '[dry-run] %s %s\n' "$ANDROID_HOME/emulator/emulator" "${emu_args[*]}" >&2
    printf 'AVD_SERIAL=%s\n' "$serial"
    return 0
  fi
  # Detached: the emulator outlives this script; the orchestrator kills
  # it with `boot-avd.sh kill` after the job.
  setsid nohup "$ANDROID_HOME/emulator/emulator" "${emu_args[@]}" \
    > "/tmp/boot-avd-$job_id-$port.log" 2>&1 < /dev/null &
  local i
  for i in $(seq 1 $((BOOT_TIMEOUT_S / 5))); do
    if [ "$("$ANDROID_HOME/platform-tools/adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
      log "job $job_id: $serial booted in $((i * 5))s"
      printf 'AVD_SERIAL=%s\n' "$serial"
      return 0
    fi
    sleep 5
  done
  log "job $job_id: $serial did not reach boot_completed in ${BOOT_TIMEOUT_S}s — killing it"
  cmd_kill "$serial" || true
  return 1
}

cmd_kill() {
  local serial="$1"
  need_tools
  if [ "$DRY_RUN" = "1" ]; then
    printf '[dry-run] %s -s %s emu kill\n' "$ANDROID_HOME/platform-tools/adb" "$serial" >&2
    return 0
  fi
  "$ANDROID_HOME/platform-tools/adb" -s "$serial" emu kill >/dev/null 2>&1 \
    || die "adb emu kill failed for $serial"
  log "killed $serial"
}

# ------------------------------------------------------------------ main
cmd="${1:-}"
case "$cmd" in
  --dry-run)
    DRY_RUN=1; shift; cmd="${1:-}";;
esac
case "$cmd" in
  create)   cmd_create ;;
  snapshot) cmd_snapshot ;;
  boot)
    [ $# -ge 3 ] || die "usage: boot-avd.sh boot <job-id> <port>"
    # `boot --dry-run` also accepted: boot-avd.sh boot <job-id> <port> --dry-run
    if [ "${4:-}" = "--dry-run" ]; then DRY_RUN=1; fi
    cmd_boot "$2" "$3" ;;
  kill)
    [ $# -ge 2 ] || die "usage: boot-avd.sh kill <serial>"
    if [ "${3:-}" = "--dry-run" ]; then DRY_RUN=1; fi
    cmd_kill "$2" ;;
  *) die "usage: boot-avd.sh {create|snapshot|boot <job-id> <port>|kill <serial>} [--dry-run]" ;;
esac
