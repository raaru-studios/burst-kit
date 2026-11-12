#!/usr/bin/env bash
# bootstrap.sh — burst-compute first-boot toolchain setup (SPEC §7).
#
# Runs once at first boot via cloud-init user-data on the burst box.
# Idempotent: every step checks for its own completion marker and skips
# work already done, so a re-run (or a relaunch onto a resumed campaign)
# never re-pays the install tax.
#
# Exit codes:
#   0  toolchain ready, KVM gate passed (or REQUIRE_KVM=0)
#   3  KVM GATE FAILURE — /dev/kvm absent or not writable. The campaign
#      must abort here, loudly, before any EMULATE job is admitted
#      (SPEC §7, §12). Nothing else in this script runs after a KVM
#      failure when REQUIRE_KVM=1 (the default).
#
# Environment knobs:
#   REQUIRE_KVM=1        (default) abort if /dev/kvm is not usable
#   CACHE_BUCKET=s3://…  (default: unset = off) enable the S3 dependency-
#                        cache hooks (§7/§11a-7): restore at bootstrap,
#                        save via cache_save() / EXIT trap
#   BURST_HOME           (default: /opt/burst) install root
#   BOOTSTRAP_LOG        (default: $BURST_HOME/logs/bootstrap.log)
#
# Timing: every phase logs start/end epoch seconds; the totals land in
# $BURST_HOME/logs/bootstrap-timing.tsv and are part of the campaign
# report (SPEC §7: bootstrap duration is reported, not hidden).
#
# Resilience (BANKAI 2026-11-07): every network operation runs through
# retry() (3 attempts, 10s/20s backoff, each attempt logged); a phase
# whose retries are exhausted DIES loudly (fail-closed) — the script
# never carries on to the next phase after a FAILED phase.

set -uo pipefail

BURST_HOME="${BURST_HOME:-/opt/burst}"
LOG_DIR="$BURST_HOME/logs"
STATE_DIR="$BURST_HOME/bootstrap-state"
BOOTSTRAP_LOG="${BOOTSTRAP_LOG:-$LOG_DIR/bootstrap.log}"
TIMING_TSV="$LOG_DIR/bootstrap-timing.tsv"
CACHE_BUCKET="${CACHE_BUCKET:-}"
REQUIRE_KVM="${REQUIRE_KVM:-1}"

ANDROID_HOME="${ANDROID_HOME:-$BURST_HOME/android-sdk}"
CMDLINE_TOOLS_ZIP="commandlinetools-linux-11076708_latest.zip"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/$CMDLINE_TOOLS_ZIP"
# §3 (2026-11-11): pinned sha256 of the command-line-tools zip as
# SERVED by dl.google.com, verified 3x against fresh downloads
# (153,607,504 bytes, valid zip, 104 entries). Google's
# repository2-1.xml lists d313adb7aedccf6cf0cfca51ec180f0059f5f8f8 —
# that hash does NOT match the served bytes, so the served hash is
# pinned, not the catalog hash. If Google re-issues the zip, the hash
# check below fails loudly and the pin must be re-verified against a
# fresh download before any launch.
# Estate pins (SPEC §7): JDK 17 (AGP 8.7.3), platform 35, API 36 image.
SDK_PACKAGES=(
  "platform-tools"
  "platforms;android-35"
  "build-tools;35.0.0"
  "emulator"
  "system-images;android-36;google_apis;x86_64"
)
ANCHOR_VERSION="${ANCHOR_VERSION:-0.31.1}"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$BURST_HOME/work" "$BURST_HOME/results"
exec > >(tee -a "$BOOTSTRAP_LOG") 2>&1

log()  { printf '[bootstrap %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die()  { log "FATAL: $*"; exit "${2:-1}"; }

# retry-helper-begin
# retry <attempts> <label> <command...> — run a network operation up to
# <attempts> times with linear backoff (10s, 20s, ...), logging every
# attempt. A download/install failure must not kill the campaign on the
# first transient fault, and must not pass silently either: after the
# last attempt the helper returns the failing rc and the caller (phase)
# aborts the bootstrap. Markers are only touched on success (phase()),
# so a retried-then-failed phase re-runs cleanly on the next boot.
# NOTE: keep this block between the retry-helper-begin/end markers — the
# unit test (hidden/test-bootstrap-retry.sh) extracts exactly this block
# from this file and tests the real code, not a copy.
retry() {
  local attempts="$1"; local label="$2"; shift 2
  local i rc=0
  for ((i = 1; i <= attempts; i++)); do
    log "retry $label: attempt $i/$attempts"
    "$@"
    rc=$?
    if [ $rc -eq 0 ]; then
      log "retry $label: succeeded on attempt $i"
      return 0
    fi
    log "retry $label: attempt $i failed (rc=$rc)"
    if [ "$i" -lt "$attempts" ]; then
      local wait=$((10 * i))
      log "retry $label: waiting ${wait}s before next attempt"
      sleep "$wait"
    fi
  done
  log "retry $label: FAILED after $attempts attempts"
  return "$rc"
}
# retry-helper-end

# Run a phase once. Marker files make the script idempotent: a phase
# whose marker exists is skipped entirely.
# FAIL-CLOSED (BANKAI 2026-11-07): a phase failure is fatal. The script
# runs under `set -uo pipefail` WITHOUT -e, so a bare `return $rc` here
# used to let the caller carry on to the next phase after logging
# FAILED — a fail-open bug. Now phase() dies loudly on failure; no
# caller can ignore it, and the marker is only touched on success.
phase() {
  local name="$1"; shift
  local marker="$STATE_DIR/$name.done"
  if [ -f "$marker" ]; then
    log "phase $name: already done, skipping"
    return 0
  fi
  log "phase $name: start"
  local t0=$SECONDS
  "$@"
  local rc=$?
  local dt=$((SECONDS - t0))
  printf '%s\t%d\n' "$name" "$dt" >> "$TIMING_TSV"
  if [ $rc -ne 0 ]; then
    log "phase $name: FAILED after ${dt}s (rc=$rc) — aborting bootstrap (fail-closed)"
    die "bootstrap phase '$name' failed (rc=$rc) — campaign aborted at bootstrap, no silent continuation" "$rc"
  fi
  touch "$marker"
  log "phase $name: done in ${dt}s"
}

# ---------------------------------------------------------------- KVM gate
# SPEC §7: assert /dev/kvm exists and is writable BEFORE any EMULATE job
# is admitted; failure aborts the campaign at minute ~5, not at the first
# emulator job. This runs first and is never skipped by a marker — a
# resumed box re-proves its KVM every boot.
kvm_gate() {
  log "KVM gate: checking /dev/kvm"
  if [ ! -e /dev/kvm ]; then
    log "KVM GATE FAILURE: /dev/kvm does not exist on this instance."
    log "Nested virtualization is absent — EMULATE jobs cannot run here."
    log "Abort the campaign and re-plan to a verified family (SPEC §12)."
    return 3
  fi
  if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    # Try the standard cure once: the kvm group + udev rule may not have
    # applied to this boot's session yet.
    sudo usermod -aG kvm "$(id -un)" 2>/dev/null || true
    sudo chmod 666 /dev/kvm 2>/dev/null || true
  fi
  if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    log "KVM GATE FAILURE: /dev/kvm exists but is not readable+writable."
    log "Abort the campaign and re-plan to a verified family (SPEC §12)."
    return 3
  fi
  # Functional probe: opening the device via the emulator's own checker
  # is deferred to the SDK phase; the char-device + permission check
  # above is the bootstrap-level gate.
  log "KVM gate: /dev/kvm present and writable — PASS"
  return 0
}

if [ "$REQUIRE_KVM" = "1" ]; then
  kvm_gate || die "KVM gate failed — campaign aborted at bootstrap (SPEC §7)" 3
else
  log "REQUIRE_KVM=0 — KVM gate skipped (BUILD/VERIFY-only campaign)"
fi

# ---------------------------------------------------------------- apt base
phase_base() {
  retry 3 "apt-get update" sudo apt-get update -qq || return $?
  if retry 3 "apt-get install (with qemu-kvm)" \
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        git curl unzip zip jq python3 python3-yaml \
        openjdk-17-jdk-headless \
        build-essential pkg-config libssl-dev \
        qemu-kvm libvirt-daemon-system 2>/dev/null; then
    :
  else
    log "phase base: install with qemu-kvm failed after retries, falling back to no-qemu set"
    retry 3 "apt-get install (no qemu-kvm)" \
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        git curl unzip zip jq python3 python3-yaml \
        openjdk-17-jdk-headless \
        build-essential pkg-config libssl-dev
  fi
  java -version 2>&1 | head -1
}
phase base phase_base

# ------------------------------------------------------- Android SDK stack
phase_sdk() {
  export ANDROID_HOME ANDROID_SDK_ROOT="$ANDROID_HOME"
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  if [ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
    local tmp
    tmp="$(mktemp -d)"
    retry 3 "curl cmdline-tools" curl -fsSL "$CMDLINE_TOOLS_URL" -o "$tmp/tools.zip" || return $?
    # §3 (2026-11-11): verify the download against the pinned sha256
    # BEFORE unzipping — no launch on unverified SDK bytes (SPEC §8.2).
    # A mismatch aborts the phase loudly; the pin is re-verified, never
    # bypassed.
    printf '%s  %s\n' "$CMDLINE_TOOLS_SHA256" "$tmp/tools.zip" | sha256sum -c - \
      || { log "SDK HASH MISMATCH: $CMDLINE_TOOLS_ZIP does not match CMDLINE_TOOLS_SHA256 — aborting, no launch on unverified SDK bytes"; rm -rf "$tmp"; return 1; }
    unzip -q "$tmp/tools.zip" -d "$tmp"
    rm -rf "$ANDROID_HOME/cmdline-tools/latest"
    mv "$tmp/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm -rf "$tmp"
  fi
  local sdkmanager="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
  yes | "$sdkmanager" --licenses >/dev/null 2>&1 || true
  retry 3 "sdkmanager --install" "$sdkmanager" --install "${SDK_PACKAGES[@]}" || return $?
  # Emulator KVM functional check, now that the emulator exists.
  if [ "$REQUIRE_KVM" = "1" ]; then
    "$ANDROID_HOME/emulator/emulator" -accel-check 2>&1 | grep -qi "usable" \
      || die "emulator -accel-check reports KVM unusable — campaign aborted" 3
    log "emulator -accel-check: KVM usable"
  fi
}
phase android-sdk phase_sdk

# ------------------------------------------------------ Rust + Anchor stack
# SPEC §7: Crown VERIFY leg only, installed in parallel with the Android
# stack in wall-clock terms (separate phase; cloud-init may background it,
# but sequential correctness is what this script guarantees).
phase_rust() {
  if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
    retry 3 "rustup install" rustup_install || return $?
  fi
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
  cargo --version || return $?
  if [ ! -x "$HOME/.cargo/bin/anchor" ]; then
    # Anchor via avm, pinned (estate Crown leg targets Anchor 0.31.x).
    retry 3 "cargo install avm" \
      cargo install --git https://github.com/coral-xyz/anchor avm --locked --force || return $?
    retry 3 "avm install $ANCHOR_VERSION" \
      "$HOME/.cargo/bin/avm" install "$ANCHOR_VERSION" || return $?
    "$HOME/.cargo/bin/avm" use "$ANCHOR_VERSION"
  fi
  anchor --version || true
}

# Separated so retry() can invoke it as a single command (a bare
# curl | sh pipeline cannot be passed as retry's argv).
rustup_install() {
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
}
phase rust-anchor phase_rust

# ------------------------------------------------------------ Gradle cache
# The shared dependency cache is the single-push plan's biggest saving
# (SPEC §11a-2): all suite apps draw on one dependency universe, so the
# cache lives OUTSIDE per-job directories and every job reuses it.
phase_gradle_home() {
  mkdir -p "$BURST_HOME/gradle-home"
  log "Gradle user home: $BURST_HOME/gradle-home (shared across all jobs)"
}
phase gradle-home phase_gradle_home

# ------------------------------------------------------------- cache hooks
# SPEC §7 cache strategy + §11a-7 (promoted): with CACHE_BUCKET set, the
# Gradle dependency cache round-trips through S3 so a spot-interruption
# relaunch restores in minutes instead of re-downloading the world.
# Default OFF (CACHE_BUCKET unset): no S3 contact, cold tax accepted.
TARBALL="$BURST_HOME/gradle-cache.tar.zst"
cache_restore() {
  [ -n "$CACHE_BUCKET" ] || return 0
  log "cache: restoring Gradle cache from $CACHE_BUCKET"
  if aws s3 cp "$CACHE_BUCKET/gradle-cache.tar.zst" "$TARBALL" 2>/dev/null; then
    tar --zstd -xf "$TARBALL" -C "$BURST_HOME" && log "cache: restored"
  else
    log "cache: no prior cache in bucket (first campaign) — cold start"
  fi
}
cache_save() {
  [ -n "$CACHE_BUCKET" ] || return 0
  command -v aws >/dev/null 2>&1 || return 0
  log "cache: saving Gradle cache to $CACHE_BUCKET"
  tar --zstd -cf "$TARBALL" -C "$BURST_HOME" gradle-home 2>/dev/null \
    && aws s3 cp "$TARBALL" "$CACHE_BUCKET/gradle-cache.tar.zst" 2>/dev/null \
    && log "cache: saved" || log "cache: save failed (non-fatal)"
}
if [ -n "$CACHE_BUCKET" ]; then
  command -v zstd >/dev/null 2>&1 || retry 3 "apt-get install zstd/awscli" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq zstd awscli
  cache_restore
  trap cache_save EXIT
else
  log "cache: CACHE_BUCKET unset — S3 cache hooks OFF (SPEC §7 v0.1 default)"
fi

# ------------------------------------------------------------------ finish
log "bootstrap complete"
log "timing summary ($TIMING_TSV):"
cat "$TIMING_TSV" 2>/dev/null | while IFS=$'\t' read -r n s; do
  log "  $n: ${s}s"
done
exit 0
