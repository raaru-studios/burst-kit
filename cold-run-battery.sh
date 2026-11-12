#!/usr/bin/env bash
# ESTATE COLD-RUN BATTERY — one script, every lane repo.
#
# Canonical copy: ~/workspace/burst-compute/kit/cold-run-battery.sh
# Committed at the ROOT of each lane repo; the burst manifest's EMULATE
# jobs run it with no arguments: `./cold-run-battery.sh`
#
# Modelled on the two proven estate batteries:
#   - gaspumpa android-app/ci/emulator-smoke.sh (phases, uitools.py,
#     ANR dismissal, first-screen polling, offline restore loop)
#   - VOIDRUNNER release-v1.0.2 verify-cold-run-m8a.sh (dump with
#     retries, host-ANR attribution, verdict vocabulary)
#
# Generic by construction: NOTHING lane-specific is hardcoded. The script
# auto-detects the package, launcher activity and debug APK from the
# checked-out repo, and reads an optional repo-root `cold-run.conf`
# (KEY=VALUE lines) for per-lane tuning:
#   PKG            applicationId incl. debug suffix, e.g. com.raaru.orepit.debug
#   ACT            launcher activity, e.g. com.raaru.orepit.MainActivity
#   APK            debug APK path (default: first $APP_DIR/build/
#                  outputs/apk/debug/*.apk, where $APP_DIR is
#                  android-app/app for lanes or app/ for root-layout repos)
#   FIRST_SCREEN   comma-separated first-screen markers, e.g.
#                  "Connect wallet,Before your first pump". If unset, a
#                  first screen counts as usable when its hierarchy dump
#                  carries at least one text node and the app is alive.
#   CONNECT_TEXT   node to tap for the no-wallet variant (default:
#                  "Connect wallet")
# Env vars of the same names override the config file.
#
# Evidence lands in ./cold-run-evidence/ at the repo root:
#   results.txt            the cold-run report (verdict lines)
#   cold-run-report.txt    copy of results.txt (manifest `produces` name)
#   logcat.txt             full logcat for the run (manifest `produces` name)
#   logcat-cold.txt / -nowallet.txt / -offline.txt, *.png, *.xml, *-texts.txt
#
# Hard-fail (exit 1) ONLY on: APK install failure, app process death,
# a FATAL EXCEPTION in the app's logcat, or an unusable cold first
# screen. Every variant step is capture-and-continue: evidence lands
# either way and results.txt records what happened.
#
# Phases:
#   P0 device info (waits for boot_completed, budget 10 min)
#   P1 cold run: fresh install -> launch -> logcat + screenshot + UI dump
#   P2 no-wallet: connect attempt with no wallet app present (stock
#      emulator) -> the error surface IS the no-wallet variant evidence
#   P3 offline: networking disabled -> relaunch -> first screen renders
#      -> connect attempt offline -> restore network
#   P4 wrap: total FATAL count, verdict
#
# Requires: an emulator already booted on the box with `adb` on PATH
# (the EMULATE leg's harness boots the AVD); the BUILD leg has already
# produced the debug APK. `--detect-only` prints the detected PKG/ACT/APK
# and exits without touching the device — use it to verify a lane
# resolves before pushing.
set -u

WS="$PWD"
OUT="$WS/cold-run-evidence"
mkdir -p "$OUT"
RESULTS="$OUT/results.txt"
: > "$RESULTS"
HARD_FAIL=0

log() { echo "$@" | tee -a "$RESULTS"; }

# --- config ---------------------------------------------------------------
[ -f "$WS/cold-run.conf" ] && set -a && . "$WS/cold-run.conf" && set +a

# App module dir: lanes keep the project under android-app/ (gradlew at
# android-app/gradlew), but VOIDRUNNER keeps it at the repo root (app/
# at root). Prefer android-app/app, fall back to root app/ — same
# build.gradle.kts / AndroidManifest.xml / APK layout either way.
# (2026-11-11 fix: the hardcoded android-app/ paths made --detect-only
# fail on the VOIDRUNNER repo — PKG/ACT empty, DETECT FAILED — so
# voidrunner-l3 would have failed at detection. Verified firsthand by
# cloning raaruofficial/voidrunner and running --detect-only.)
detect_app_dir() {
    if [ -f "$WS/android-app/app/build.gradle.kts" ]; then
        printf '%s' "android-app/app"
    elif [ -f "$WS/app/build.gradle.kts" ]; then
        printf '%s' "app"
    else
        return 1
    fi
}

APP_DIR="$(detect_app_dir || true)"

detect_base_id() {
    local gradle="$WS/$APP_DIR/build.gradle.kts"
    [ -f "$gradle" ] || return 1
    grep -m1 'applicationId = ' "$gradle" | sed 's/.*applicationId = "\(.*\)".*/\1/'
}

detect_pkg() {
    local gradle="$WS/$APP_DIR/build.gradle.kts" id=""
    id=$(detect_base_id) || return 1
    if grep -q 'applicationIdSuffix = ".debug"' "$gradle"; then
        id="${id}.debug"
    fi
    printf '%s' "$id"
}

detect_act() {
    local man="$WS/$APP_DIR/src/main/AndroidManifest.xml"
    [ -f "$man" ] || return 1
    python3 - "$man" <<'PY' 2>/dev/null
import sys, xml.etree.ElementTree as ET
NS = "{http://schemas.android.com/apk/res/android}"
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(1)
pkg = None
# applicationId lives in build.gradle.kts, not the manifest; the activity
# name may be relative (".MainActivity") — resolve it against PKG below.
for app in root.iter("application"):
    for act in app.iter("activity"):
        name = act.get(NS + "name") or ""
        for f in act.iter("intent-filter"):
            actions = {a.get(NS + "name") for a in f.iter("action")}
            cats = {c.get(NS + "name") for c in f.iter("category")}
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
                print(name)
                sys.exit(0)
sys.exit(1)
PY
}

PKG="${PKG:-$(detect_pkg || true)}"
ACT_RAW="${ACT:-$(detect_act || true)}"
APK="${APK:-}"
if [ -z "$APK" ]; then
    APK=$(ls "$WS"/$APP_DIR/build/outputs/apk/debug/app-debug.apk 2>/dev/null \
        || ls "$WS"/$APP_DIR/build/outputs/apk/debug/*.apk 2>/dev/null | head -n 1 || true)
fi
FIRST_SCREEN="${FIRST_SCREEN:-}"
CONNECT_TEXT="${CONNECT_TEXT:-Connect wallet}"

# Resolve a relative activity name (".MainActivity") against the BASE
# applicationId — the .debug suffix is an install-time applicationId, not
# part of the activity's class name.
BASE_ID="$(detect_base_id || true)"
ACT="$ACT_RAW"
case "$ACT_RAW" in
    .*) ACT="${BASE_ID:-$PKG}${ACT_RAW}" ;;
    *.*) : ;; # already fully qualified
    *) [ -n "$ACT_RAW" ] && ACT="${BASE_ID:-$PKG}.${ACT_RAW}" ;;
esac

if [ "${1:-}" = "--detect-only" ]; then
    echo "PKG=$PKG"
    echo "ACT=$ACT"
    echo "APK=$APK"
    echo "FIRST_SCREEN=$FIRST_SCREEN"
    # Push-time gate: only PKG/ACT are source-resolvable. The APK is a
    # build output produced by the BUILD leg on the burst box (build/ and
    # *.apk are gitignored); its absence here is expected, not a defect.
    # The full battery run still requires the APK (APK NOT FOUND below).
    if [ -n "$APK" ] && [ -f "$APK" ]; then
        echo "APK_STATUS=present"
    else
        echo "APK_STATUS=not-built-yet"
    fi
    [ -n "$PKG" ] && [ -n "$ACT" ] || { echo "DETECT FAILED: PKG or ACT missing (check build.gradle.kts / AndroidManifest.xml, or set PKG/ACT in cold-run.conf)"; exit 1; }
    echo "DETECT OK"
    exit 0
fi

if [ -z "$PKG" ] || [ -z "$ACT" ]; then
    log "DETECT FAILED: PKG='$PKG' ACT='$ACT' (check build.gradle.kts / AndroidManifest.xml, or set PKG/ACT in cold-run.conf)"
    exit 1
fi
# Burst APK wait (§5.1): the BUILD leg harvests the debug APK as evidence
# into $BURST_OUT, so an EMULATE job may start before its lane's BUILD
# finishes. APK may be a glob; APK_WAIT_S>0 polls for it; APK_WAIT_BUILD_ID
# names the BUILD job whose FAILED state in $BURST_OUT/state.json aborts
# the wait early instead of burning the whole window.
resolve_apk() {
    [ -n "$APK" ] || return 1
    local f=""
    f=$(ls $APK 2>/dev/null | head -n 1 || true)  # unquoted: glob expand
    [ -n "$f" ] && [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    return 1
}
build_failed() {
    [ -n "${BURST_OUT:-}" ] && [ -n "${APK_WAIT_BUILD_ID:-}" ] \
        && [ -f "$BURST_OUT/state.json" ] || return 1
    python3 - "$BURST_OUT/state.json" "$APK_WAIT_BUILD_ID" <<'PY' 2>/dev/null
import json, sys
try:
    s = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
sys.exit(0 if s.get("jobs", {}).get(sys.argv[2], {}).get("state") == "FAILED" else 1)
PY
}
APK_RESOLVED="$(resolve_apk || true)"
if [ -z "$APK_RESOLVED" ] && build_failed; then
    log "APK WAIT ABORT: BUILD job '$APK_WAIT_BUILD_ID' FAILED — no APK coming"
    exit 1
fi
_waited=0
if [ -z "$APK_RESOLVED" ]; then
    case "${APK_WAIT_S:-0}" in
        ''|*[!0-9]*) : ;;  # non-numeric: no wait, fail fast as before
        *)
            if [ "${APK_WAIT_S:-0}" -gt 0 ]; then
                _waited=1
                _deadline=$((SECONDS + APK_WAIT_S))
                while [ "$SECONDS" -lt "$_deadline" ]; do
                    sleep 15
                    APK_RESOLVED="$(resolve_apk || true)"
                    [ -n "$APK_RESOLVED" ] && break
                    if build_failed; then
                        log "APK WAIT ABORT: BUILD job '$APK_WAIT_BUILD_ID' FAILED — no APK coming"
                        exit 1
                    fi
                done
            fi
            ;;
    esac
fi
[ -n "$APK_RESOLVED" ] && APK="$APK_RESOLVED"
# Wait-expiry is a TIMING failure, not a missing-APK defect: the BUILD is
# slow, not failed. Emit the classifier contract string verbatim (shared
# with Team GRID: maps to INFRA/retryable) and never "APK NOT FOUND" on
# this path. Reached only when the loop ran to its deadline: a BUILD
# FAILED aborts inside the loop above, and a resolved APK skips this.
if [ -z "$APK_RESOLVED" ] && [ "$_waited" = 1 ]; then
    log "APK WAIT TIMEOUT after ${APK_WAIT_S}s: BUILD job '${APK_WAIT_BUILD_ID}' has not produced an APK yet (timing — the build is slow, not failed)"
    exit 1
fi
if [ -z "$APK" ] || [ ! -f "$APK" ]; then
    log "APK NOT FOUND: '$APK' (run the BUILD leg first, or set APK in cold-run.conf)"
    exit 1
fi

# --- helpers ---------------------------------------------------------------
TMPD="$(mktemp -d)"
cat > "$TMPD/uitools.py" <<'PYEOF'
import sys, xml.etree.ElementTree as ET

def nodes(path):
    try:
        tree = ET.parse(path)
    except Exception as e:
        print(f"PARSE_ERROR {e}", file=sys.stderr); return []
    return list(tree.getroot().iter("node"))

def cmd_texts(path):
    seen = []
    for n in nodes(path):
        t = (n.get("text") or "").strip()
        if t and t not in seen: seen.append(t)
    for t in seen: print(t)

def center(bounds):
    nums = bounds.replace("][", ",").strip("[]").split(",")
    x1, y1, x2, y2 = (int(v) for v in nums)
    return (x1 + x2) // 2, (y1 + y2) // 2

def cmd_tap_text(path, needle):
    for n in nodes(path):
        hay = ((n.get("text") or "") + " " + (n.get("content-desc") or ""))
        if needle.lower() in hay.lower():
            x, y = center(n.get("bounds"))
            print(f"{x} {y}"); return
    sys.exit(3)

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "texts": cmd_texts(sys.argv[2])
    elif cmd == "tap-text": cmd_tap_text(sys.argv[2], sys.argv[3])
PYEOF

# dump with retries: success = a complete hierarchy file exists.
dump_ui() { # $1 = destination file
    local dst="$1" attempt
    for attempt in 1 2 3 4 5 6 7 8; do
        adb shell rm -f /sdcard/window_dump.xml >/dev/null 2>&1 || true
        timeout 40 adb shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1 || true
        adb exec-out cat /sdcard/window_dump.xml > "$dst.tmp" 2>/dev/null || true
        if grep -q "</hierarchy>" "$dst.tmp" 2>/dev/null; then
            mv "$dst.tmp" "$dst"
            python3 "$TMPD/uitools.py" texts "$dst" > "${dst%.xml}-texts.txt" 2>/dev/null || true
            return 0
        fi
        sleep 4
    done
    log "DUMP $dst FAILED after 8 attempts"
    return 1
}

shot() { # $1 = name
    adb exec-out screencap -p > "$OUT/$1.png" 2>/dev/null \
        && log "SHOT $1 ok ($(wc -c < "$OUT/$1.png") bytes)" \
        || log "SHOT $1 FAILED"
}

tap_text() { # $1 = xmlfile, $2 = needle
    local xy
    xy=$(python3 "$TMPD/uitools.py" tap-text "$1" "$2" 2>/dev/null) || { log "TAP '$2' NOT FOUND in $1"; return 1; }
    adb shell input tap $xy
    log "TAP '$2' at $xy"
}

fatal_count() { grep -c "FATAL EXCEPTION" "$1" 2>/dev/null | tr -d '[:space:]'; }

# Usable first screen: with FIRST_SCREEN markers, one must match the dump's
# texts; without markers, any dump carrying at least one text node counts.
first_screen_usable() { # $1 = texts file
    local f="$1"
    [ -s "$f" ] || return 1
    if [ -n "$FIRST_SCREEN" ]; then
        local IFS=',' m
        for m in $FIRST_SCREEN; do
            m=$(printf '%s' "$m" | sed 's/^ *//;s/ *$//')
            [ -n "$m" ] && grep -qiF "$m" "$f" && return 0
        done
        return 1
    fi
    [ "$(grep -c . "$f")" -gt 0 ]
}

# Dismiss a host "isn't responding" ANR dialog if one occludes the UI.
# Attribution is by the process NAMED in its title: only the host's
# System UI dialog is dismissable. A dialog naming the app itself is a
# hard fail; any other named process is logged and dismissed.
dismiss_anr() { # $1 = phase label
    local f="$TMPD/anr-$1.xml" title=""
    dump_ui "$f" >/dev/null 2>&1 || return 0
    grep -q "isn.t responding" "${f%.xml}-texts.txt" 2>/dev/null || return 0
    title=$(grep -i "isn.t responding" "${f%.xml}-texts.txt" 2>/dev/null | head -1)
    log "ANR_DIALOG during $1: '${title}'"
    case "$title" in
        *"System UI"*) log "ANR: host System UI dialog; tapping Wait"; tap_text "$f" "Wait" >/dev/null 2>&1 && sleep 3 ;;
        *"$PKG"*) log "ANR: dialog names the app itself — hard fail"; HARD_FAIL=1 ;;
        *) log "ANR: host process dialog; tapping Wait"; tap_text "$f" "Wait" >/dev/null 2>&1 && sleep 3 ;;
    esac
}

# Poll until the first screen renders (or the budget runs out).
wait_first_screen() { # $1 = xmlname, $2 = budget seconds
    local i=0
    while [ $i -lt $2 ]; do
        if dump_ui "$OUT/$1.xml" && first_screen_usable "$OUT/$1-texts.txt"; then
            return 0
        fi
        sleep 10; i=$((i + 10))
    done
    return 1
}

# --- P0 device info ----------------------------------------------------------
log "=== estate cold-run battery :: $PKG :: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
log "APK=$APK"
adb wait-for-device
for _ in $(seq 1 120); do
    [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
    sleep 5
done
log "device.sdk=$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
log "device.release=$(adb shell getprop ro.build.version.release | tr -d '\r')"
log "device.model=$(adb shell getprop ro.product.model | tr -d '\r')"
adb shell settings put global window_animation_scale 0 >/dev/null 2>&1
adb shell settings put global transition_animation_scale 0 >/dev/null 2>&1
adb shell settings put global animator_duration_scale 0 >/dev/null 2>&1

# --- P1 cold run -------------------------------------------------------------
adb uninstall "$PKG" >/dev/null 2>&1 || true
if adb install "$APK" > "$OUT/install.txt" 2>&1; then
    log "INSTALL ok"
else
    log "INSTALL FAILED (see install.txt)"; HARD_FAIL=1
fi
adb shell am force-stop "$PKG" >/dev/null 2>&1
adb logcat -c >/dev/null 2>&1
adb logcat -v threadtime > "$OUT/logcat-full.txt" 2>&1 &
LOGPID=$!
START_MS="$(date +%s%3N)"
adb shell am start -W -n "$PKG/$ACT" > "$OUT/cold-am-start.txt" 2>&1
log "AM_START: $(grep -E 'Status:|TotalTime' "$OUT/cold-am-start.txt" | tr '\n' ' ')"
sleep 5
dismiss_anr cold
if wait_first_screen cold 90; then
    log "COLD first-screen rendered (polled)"
else
    log "COLD first-screen NOT rendered within 90s poll"
fi
PIDOF=$(adb shell pidof "$PKG" | tr -d '\r')
log "COLD pidof='${PIDOF}'"
[ -z "$PIDOF" ] && HARD_FAIL=1
shot cold
dump_ui "$OUT/cold.xml" || true
adb logcat -d -v threadtime > "$OUT/logcat-cold.txt" 2>&1
CF=$(fatal_count "$OUT/logcat-cold.txt")
log "COLD FATAL count=$CF"
[ "$CF" != "0" ] && HARD_FAIL=1
if first_screen_usable "$OUT/cold-texts.txt" 2>/dev/null; then
    log "COLD usable-first-screen=YES"
else
    log "COLD usable-first-screen=NO (see cold-texts.txt)"; HARD_FAIL=1
fi

# --- P2 no-wallet connect attempt --------------------------------------------
# The stock emulator image carries no MWA wallet app: whatever the connect
# attempt produces here IS the no-wallet variant evidence. Expected shape:
# a clean error state with a retry surface, process alive, no FATAL.
WALLETS=$(adb shell pm list packages | grep -ci "phantom\|solflare\|backpack\|seedvault\|mwallet" || true)
log "NOWALLET wallet-shaped packages installed: $WALLETS (stock image expected 0)"
adb shell pm list packages > "$OUT/packages.txt" 2>&1
if tap_text "$OUT/cold.xml" "$CONNECT_TEXT"; then
    sleep 15
    dismiss_anr nowallet
    shot nowallet
    dump_ui "$OUT/nowallet.xml" || true
    PID2=$(adb shell pidof "$PKG" | tr -d '\r')
    log "NOWALLET pidof='${PID2}'"
    [ -z "$PID2" ] && HARD_FAIL=1
    if grep -qi "Try again" "$OUT/nowallet-texts.txt" 2>/dev/null; then
        log "NOWALLET error-surface=YES (Try again offered)"
    else
        log "NOWALLET error-surface=UNCONFIRMED (see nowallet-texts.txt)"
    fi
else
    log "NOWALLET connect attempt UNRUN (no '$CONNECT_TEXT' node in cold dump)"
fi
adb logcat -d -v threadtime > "$OUT/logcat-nowallet.txt" 2>&1
NF=$(fatal_count "$OUT/logcat-nowallet.txt")
log "NOWALLET FATAL count=$NF"
[ "$NF" != "0" ] && HARD_FAIL=1

# --- P3 offline variant --------------------------------------------------------
adb shell am force-stop "$PKG" >/dev/null 2>&1
adb shell svc wifi disable >/dev/null 2>&1 || true
adb shell svc data disable >/dev/null 2>&1 || true
adb shell settings put global airplane_mode_on 1 >/dev/null 2>&1 || true
adb shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true >/dev/null 2>&1 || true
sleep 3
AM=$(adb shell settings get global airplane_mode_on | tr -d '\r')
PING=$(adb shell ping -c 1 -W 2 8.8.8.8 2>&1 | tail -1)
log "OFFLINE airplane_mode_on=$AM ping: $PING"
adb shell am start -W -n "$PKG/$ACT" > "$OUT/offline-am-start.txt" 2>&1
sleep 5
dismiss_anr offline
wait_first_screen offline 60 || log "OFFLINE first-screen NOT rendered within 60s poll"
PIDOF_OFF=$(adb shell pidof "$PKG" | tr -d '\r')
log "OFFLINE pidof='${PIDOF_OFF}'"
[ -z "$PIDOF_OFF" ] && HARD_FAIL=1
shot offline
dump_ui "$OUT/offline.xml" || true
if first_screen_usable "$OUT/offline-texts.txt" 2>/dev/null; then
    log "OFFLINE usable-first-screen=YES"
else
    log "OFFLINE usable-first-screen=UNCONFIRMED (see offline-texts.txt)"
fi
if tap_text "$OUT/offline.xml" "$CONNECT_TEXT"; then
    sleep 15
    dismiss_anr offline-connect
    shot offline-connect
    dump_ui "$OUT/offline-connect.xml" || true
    PID3=$(adb shell pidof "$PKG" | tr -d '\r')
    log "OFFLINE-CONNECT pidof='${PID3}'"
    [ -z "$PID3" ] && HARD_FAIL=1
else
    log "OFFLINE connect attempt UNRUN (no '$CONNECT_TEXT' node in offline dump)"
fi
adb logcat -d -v threadtime > "$OUT/logcat-offline.txt" 2>&1
OF=$(fatal_count "$OUT/logcat-offline.txt")
log "OFFLINE FATAL count=$OF"
[ "$OF" != "0" ] && HARD_FAIL=1
# Restore networking.
adb shell settings put global airplane_mode_on 0 >/dev/null 2>&1 || true
adb shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false >/dev/null 2>&1 || true
adb shell svc wifi enable >/dev/null 2>&1 || true
adb shell svc data enable >/dev/null 2>&1 || true
RESTORED="no"
for i in 1 2 3 4 5 6; do
    if adb shell ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then RESTORED="yes"; break; fi
    sleep 5
done
log "OFFLINE network restored=$RESTORED"

# --- P4 wrap -------------------------------------------------------------------
kill $LOGPID >/dev/null 2>&1 || true
sleep 2
cp "$OUT/logcat-full.txt" "$OUT/logcat.txt" 2>/dev/null || true
TF=$(fatal_count "$OUT/logcat-full.txt")
log "TOTAL FATAL count (full logcat)=$TF"
[ "$TF" != "0" ] && HARD_FAIL=1
cp "$RESULTS" "$OUT/cold-run-report.txt"
log "=== cold-run battery done :: HARD_FAIL=$HARD_FAIL ==="
exit $HARD_FAIL
