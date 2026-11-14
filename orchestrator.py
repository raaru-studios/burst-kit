#!/usr/bin/env python3
"""orchestrator.py — burst-compute campaign runner (SPEC §5, §10).

Loads a campaign manifest (SPEC §4), lints it hard, then runs BUILD /
EMULATE / VERIFY jobs in waves with bounded per-kind parallelism,
cheapest-signal-first ordering inside each kind, per-job timeouts and
isolated job directories, continuous state.json checkpointing (a spot
interruption resumes from artifacts, never from memory), and emits the
SPEC §10 results bundle: manifest as run, state.json, per-job logs +
declared evidence products, hashes.sha256, summary.json.

Usage:
  orchestrator.py MANIFEST.yaml [--out DIR] [--work DIR]
                  [--lint-only] [--resume] [--retry-failed]
                  [--hourly-price P] [--price-ceiling C]
                  [--box-launch-epoch E] [--keys-dir DIR]
                  [--build-par N] [--emulate-par N] [--verify-par N]

Exit codes: 0 all jobs DONE · 2 lint / pre-flight refusal (incl.
disk-space refusal) · 3 campaign finished with failures/aborts · 4 KVM
required but unavailable for EMULATE jobs.

This program never contacts AWS and never launches anything but the
manifest's own job commands, on the box it is already running on.
"""

import argparse
import calendar
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# YAML loading: PyYAML when present, else a subset parser for the §4 schema
# (the burst box is a stock AMI; the kit must not die on a missing module).
# --------------------------------------------------------------------------
try:
    import yaml  # type: ignore

    def load_yaml(text):
        return yaml.safe_load(text)

except ImportError:  # pragma: no cover - exercised only without pyyaml

    def _scalar(tok):
        tok = tok.strip()
        if tok in ("", "~", "null"):
            return None
        if (tok.startswith('"') and tok.endswith('"')) or (
            tok.startswith("'") and tok.endswith("'")
        ):
            return tok[1:-1]
        if tok.startswith("[") and tok.endswith("]"):
            inner = tok[1:-1].strip()
            return [_scalar(t) for t in inner.split(",")] if inner else []
        if tok.startswith("{") and tok.endswith("}"):
            out = {}
            inner = tok[1:-1].strip()
            if inner:
                for pair in inner.split(","):
                    k, _, v = pair.partition(":")
                    out[k.strip()] = _scalar(v)
            return out
        try:
            return int(tok)
        except ValueError:
            pass
        try:
            return float(tok)
        except ValueError:
            pass
        if tok.lower() in ("true", "false"):
            return tok.lower() == "true"
        return tok

    def load_yaml(text):
        """Minimal block-YAML subset: top-level keys, one list of flat
        job mappings under `jobs:`, inline flow values. Sufficient for
        the SPEC §4 manifest schema and nothing beyond it."""
        root = {}
        lines = []
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            lines.append(raw.rstrip())
        i = 0
        current_list = None
        current_item = None
        while i < len(lines):
            line = lines[i]
            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            if indent == 0:
                current_list = None
                current_item = None
                key, _, val = stripped.partition(":")
                key = key.strip()
                if val.strip() == "":
                    current_list = []
                    root[key] = current_list
                else:
                    root[key] = _scalar(val)
            elif stripped.startswith("- ") and current_list is not None:
                current_item = {}
                current_list.append(current_item)
                rest = stripped[2:]
                if rest:
                    k, _, v = rest.partition(":")
                    current_item[k.strip()] = _scalar(v)
            elif current_item is not None:
                k, _, v = stripped.partition(":")
                current_item[k.strip()] = _scalar(v)
            i += 1
        return root


# --------------------------------------------------------------------------
# Lint (SPEC §4 rules + §8 custody invariants). A refusal is total: the
# campaign does not partially run a bad manifest.
# --------------------------------------------------------------------------
KINDS = ("BUILD", "EMULATE", "VERIFY")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_KEY_RE = re.compile(
    r"(secret|token|password|passwd|keystore|private[_-]?key|mnemonic|"
    r"seed[_-]?phrase|credential|api[_-]?key|aws[_-]?access|aws[_-]?secret)",
    re.IGNORECASE,
)
SECRET_RUN_RE = re.compile(
    r"(\.jks\b|keystore|storePassword|keyPassword|mnemonic|seed phrase|"
    r"BEGIN [A-Z ]*PRIVATE KEY|\.env\b|id_rsa|aws_secret_access_key|"
    r"ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})",
    re.IGNORECASE,
)
# 2026-11-11 security audit: the run-content pattern previously caught
# only secret-shaped NAMES and a small set of file/key patterns. A raw
# credential VALUE pasted into a run command (a GitHub PAT, an OpenAI /
# Stripe secret key, an AWS access key, a Slack token) passed lint and
# would have landed in the job log and the evidence bundle. The
# credential-format alternations above close that hole. They are
# deliberately narrow (20+ chars after the prefix) so ordinary words
# do not trip them.


def scrub_url(url):
    """Redact credentials from a clone URL for logging (SECURITY 2026-11-11):
    a per-campaign GitHub token embedded as URL userinfo
    (https://<token>@github.com/...) must never land in a job log —
    job logs are pulled off the box into the results bundle and kept.
    Strips any userinfo, keeping scheme + host + path."""
    return re.sub(r"^(https?://)[^/@]+@", r"\1***@", url)


def scrub_log_file(path, secret):
    """Remove a secret string from a log file in place (SECURITY 2026-11-11):
    git prints the remote URL in its own error output, so a failed clone
    can leak an embedded token into the log even when the orchestrator's
    own emit() redacts it. Best-effort: read, replace, rewrite.
    Two passes: (1) the exact secret string; (2) ANY https://<userinfo>@
    pattern — git re-prints the URL in shortened forms (host only, no
    path), so exact-string matching alone misses it."""
    if not secret:
        return
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return
    new = text.replace(secret, "***")
    new = re.sub(r"(https?://)[^/@\s]+@", r"\1***@", new)
    if new != text:
        Path(path).write_text(new)
REQUIRED_JOB_FIELDS = ("id", "lane", "kind", "repo", "ref", "run",
                       "timeout_min", "produces", "custody")


class LintError(Exception):
    pass


def lint_manifest(m):
    """Return a list of human-readable refusal reasons ([] = clean)."""
    errs = []
    if not isinstance(m, dict):
        return ["manifest is not a mapping"]
    if not m.get("campaign"):
        errs.append("manifest: missing campaign id")
    cap = m.get("budget_cap_usd")
    if not isinstance(cap, (int, float)) or cap <= 0:
        errs.append("manifest: budget_cap_usd must be a positive number "
                    "(SPEC §9.2 — the cap is a number, not a vibe)")
    elif cap <= COST_MARGIN_USD:
        # VAULT V-R05: at cap <= $0.50 the derived runtime
        # (cap - $0.50)/price is not positive and the cost deadline is
        # silently disabled — refuse at lint, do not run degraded.
        errs.append("manifest: budget_cap_usd must exceed $0.50 "
                    "(SPEC §9.1 — the derived runtime "
                    "(cap - $0.50)/price is not positive at or below "
                    "the $0.50 margin; VAULT V-R05)")
    box = m.get("box") or {}
    max_hours = box.get("max_hours")
    if max_hours is not None and max_hours > 6:
        errs.append(f"box.max_hours={max_hours} exceeds the SPEC §3 hard "
                    f"cap of 6 hours")
    jobs = m.get("jobs")
    if not jobs or not isinstance(jobs, list):
        errs.append("manifest: no jobs list")
        return errs
    # Pool reserve (mitigation 5, 2026-11-12): a job may claim the
    # chain reserve only if it is actually in a chain — a §11a gate
    # job, or a leg of a multi-leg lane (the lane is the chain unit
    # in this codebase: the BUILD->EMULATE sibling dependency is
    # lane-scoped, and the §11a chain is the gate sequence). A job
    # alone in its lane has no chain to be part of, so a lone job
    # marked chain:true is a farm job claiming reserve it cannot
    # use; lint refuses it. NOTE on the narrower alternative: a
    # BUILD<->EMULATE-pair-only rule gives identical verdicts on the
    # real draft-camp-1.yaml (every multi-leg lane there is a
    # BUILD+EMULATE pair, every gate is a gate, and the one
    # single-job lane — paper-moon, a lone VERIFY — is rejected by
    # both rules; verified 2026-11-12, see the audit doc); the
    # lane-membership form is shipped because it is the form whose
    # admission path is provable end-to-end on a VM without /dev/kvm
    # (an EMULATE sibling trips the KVM gate, exit 4, before any
    # job runs, so a pair-only chain job could never reach the
    # scheduler here).
    _lane_counts = {}
    _lane_kinds = {}
    for _j in jobs:
        if isinstance(_j, dict) and _j.get("lane"):
            _lane_counts[_j["lane"]] = _lane_counts.get(_j["lane"], 0) + 1
            _lane_kinds.setdefault(_j["lane"], set()).add(_j.get("kind"))
    seen_ids = set()
    for j in jobs:
        jid = j.get("id", "<unnamed>")
        if jid in seen_ids:
            errs.append(f"job {jid}: duplicate id")
        seen_ids.add(jid)
        for field in REQUIRED_JOB_FIELDS:
            if field not in j:
                errs.append(f"job {jid}: missing required field '{field}'")
        # Custody: exactly one legal value (SPEC §4, §8).
        if "custody" in j and j["custody"] != "none":
            errs.append(
                f"job {jid}: custody={j['custody']!r} REFUSED — the only "
                f"legal value is 'none'; a job needing key material is "
                f"definitionally not a burst job (SPEC §4)")
        # Pinned refs only (SPEC §4).
        ref = str(j.get("ref", ""))
        if not SHA_RE.match(ref):
            errs.append(
                f"job {jid}: ref {ref!r} is not a full 40-char commit SHA "
                f"— floating refs are refused (SPEC §4)")
        if j.get("kind") not in KINDS:
            errs.append(f"job {jid}: kind {j.get('kind')!r} not in {KINDS}")
        t = j.get("timeout_min")
        if not isinstance(t, (int, float)) or t <= 0:
            errs.append(f"job {jid}: timeout_min must be positive")
        if not j.get("produces"):
            errs.append(f"job {jid}: produces is empty — every job must "
                        f"declare its evidence products (SPEC §4)")
        # Pool reserve markers (mitigation 5, 2026-11-12).
        if "chain" in j and not isinstance(j["chain"], bool):
            errs.append(f"job {jid}: chain must be a boolean "
                        f"(got {j['chain']!r})")
        if j.get("chain") is True:
            _in_chain = (bool(j.get("gate")) or
                         _lane_counts.get(j.get("lane"), 0) >= 2)
            if not _in_chain:
                errs.append(
                    f"job {jid}: chain:true on a farm job — the chain "
                    f"reserve is only for §11a gate jobs or a leg of "
                    f"a multi-leg lane (this job is neither: lane "
                    f"{j.get('lane')!r} holds "
                    f"{_lane_counts.get(j.get('lane'), 0)} job(s)); a "
                    f"farm job must not claim the reserve "
                    f"(mitigation 5)")
        if "priority" in j and (isinstance(j["priority"], bool)
                                or not isinstance(j["priority"], int)):
            errs.append(f"job {jid}: priority must be an integer "
                        f"(lower = sooner; got {j['priority']!r})")
        # Secrets, by key name anywhere in the job mapping…
        for key in j:
            if SECRET_KEY_RE.search(str(key)):
                errs.append(f"job {jid}: field name {key!r} names secret "
                            f"material — refused (SPEC §8)")
        # …and by content of the run command.
        run = str(j.get("run", ""))
        if SECRET_RUN_RE.search(run):
            errs.append(f"job {jid}: run command references secret "
                        f"material — refused (SPEC §8)")
        # …and by content of ANY string value in the job mapping
        # (2026-11-11 audit: a token pasted into a note, env, or other
        # field previously passed lint because only the run string was
        # scanned).
        for key, val in j.items():
            if isinstance(val, str) and key != "run" \
                    and SECRET_RUN_RE.search(val):
                errs.append(f"job {jid}: field {key!r} contains secret "
                            f"material — refused (SPEC §8)")
        # A clone_url carrying embedded credentials
        # (https://user:pass@github.com/…) would leak the credential
        # into git's error output and the job log on a failed clone.
        # Private repos use SSH deploy keys (SPEC §8.1), never a token
        # in the URL. (2026-11-11 audit.)
        curl = str(j.get("clone_url", ""))
        if curl and re.search(r"://[^/]*@", curl):
            errs.append(f"job {jid}: clone_url carries embedded "
                        f"credentials — refused (SPEC §8.1: SSH deploy "
                        f"keys, never a token in the URL)")
    return errs


# --------------------------------------------------------------------------
# Ordering: cheapest-signal-first within a kind (SPEC §5). JVM suites are
# the cheapest strong signal, then assembly, then everything else; a
# job may override with an explicit integer `priority` (lower = earlier).
# --------------------------------------------------------------------------
def signal_rank(job):
    if "priority" in job:
        return (0, int(job["priority"]))
    run = str(job.get("run", "")).lower()
    if "test" in run:
        tier = 0
    elif "assemble" in run or "bundle" in run:
        tier = 1
    elif "lint" in run or "verify" in run:
        tier = 2
    else:
        tier = 3
    return (1, tier, job.get("timeout_min", 999))


# §9 cost margin: the launch-derived runtime is (cap − margin) / price,
# so the run stops with this much cap headroom unspent.
COST_MARGIN_USD = 0.50

# §5.2 error checking: failure classes + one automatic retry for transient
# infra failures. A retry never repeats a defect — only cloud/box faults
# that a fresh attempt can clear.
MAX_ATTEMPTS = 2
RETRY_BACKOFF_S = 30

# §5.2 retry gate (BANKAI 2026-11-07, Team GRID): a retry is only
# attempted when the remaining campaign wall-clock can still fit the
# job's full timeout plus the backoff about to be spent. The timeout is
# a cap, not an estimate — no shorter number exists to gamble on — so
# the bar is the whole timeout: a retry that cannot run to its own cap
# is provably wasted wall-time, and the job ends FAILED either way
# (same class). RETRY_REMAINING_TIMEOUT_FACTOR = 1.0 means "the full
# timeout"; raise it only with a reason recorded in the campaign report.
RETRY_REMAINING_TIMEOUT_FACTOR = 1.0

# Proactive disk guard (added 2026-11-11): 20 repos + Gradle cache +
# APKs + emulator images on the SPEC §3 200 GB root is tight, and the
# ENOSPC failure signature only fires after jobs start failing one by
# one. The guard runs in main() before any job starts; below this
# floor the run refuses (exit 2) instead of burning the window.
DISK_MIN_FREE_GB = 20

# Per-job AVD boot budget (competitive audit 2026-11-11): a cold AVD
# boot takes ~60-120s, a snapshot boot ~10-20s. 600s is a generous
# ceiling; the boot runs inside the job's attempt, so a hung boot is
# bounded and the job fails INFRA (retryable) rather than hanging.
AVD_BOOT_TIMEOUT_S = 600


def disk_free_gb(path):
    """Free space in GiB on the filesystem holding path (0.0 when the
    filesystem cannot be read — a refusal, never a pass)."""
    try:
        return shutil.disk_usage(path).free / (1024 ** 3)
    except OSError:
        return 0.0


def check_disk_space(path, min_free_gb=DISK_MIN_FREE_GB):
    """Proactive disk guard: return (ok, free_gb)."""
    free_gb = disk_free_gb(path)
    return (free_gb >= min_free_gb, free_gb)

# Log-tail signatures, checked in priority order: the first match decides.
# Each entry: (patterns, class, retryable).
_FAILURE_SIGNATURES = (
    ((r"No space left on device", r"ENOSPC"), "INFRA", False),
    ((r"OutOfMemoryError", r"Cannot allocate memory",
      r"memory cgroup out of memory", r"\bKilled\b"), "INFRA", True),
    ((r"emulator: ERROR", r"emulator failed", r"device not found",
      r"\badb: ", r"Failed to start emulator", r"x86 emulation",
      r"\bKVM\b", r"APK WAIT TIMEOUT"), "INFRA", True),
    ((r"Could not resolve host", r"Temporary failure in name resolution",
      r"Connection refused", r"Connection timed out", r"Failed to connect",
      r"Network is unreachable", r"Too Many Requests",
      r"rate limit"), "INFRA", True),
    ((r"Gradle build daemon disappeared",
      r"Gradle daemon stopped"), "INFRA", True),
    ((r"BUILD FAILED", r"FAILURE: Build failed", r"tests? failed",
      r"BATTERY FAIL", r"APK NOT FOUND",
      r"APK WAIT ABORT"), "APP", False),
)


def _read_tail(path, lines=80):
    try:
        with open(path, errors="replace") as f:
            return f.readlines()[-lines:]
    except OSError:
        return []


def classify_failure(log_path, point, rc):
    """Return (failure_class, retryable, detail) for a failed attempt.
    Classes: INFRA (box/cloud), APP (the app under test), HARNESS (the
    job's own evidence contract), UNKNOWN. Only transient INFRA failures
    are retryable."""
    if point == "clone":
        return ("INFRA", True, "git clone failed")
    if point == "checkout":
        return ("INFRA", True, "git checkout of the pinned ref failed")
    if point == "pin":
        return ("INFRA", False, "HEAD != pinned ref after checkout")
    if point == "timeout":
        return ("INFRA", True, "timeout — hard kill")
    if point == "evidence":
        return ("HARNESS", False, "run succeeded but produced none of "
                "its declared evidence products")
    tail = "".join(_read_tail(log_path))
    for pats, cls, retryable in _FAILURE_SIGNATURES:
        for pat in pats:
            if re.search(pat, tail):
                return (cls, retryable, f"log matches {pat!r}")
    if rc == 137:
        return ("INFRA", True, "exit 137 (SIGKILL — OOM-kill shaped)")
    return ("UNKNOWN", False, f"exit rc={rc}, no signature matched")

# --------------------------------------------------------------------------
# Bootstrap gate (VAULT V-R10): bootstrap.sh phase() touches
# $BURST_HOME/bootstrap-state/<phase>.done on success only, and the
# SDK phase installs the emulator at $ANDROID_HOME/emulator/emulator.
# The orchestrator checks these before admitting EMULATE jobs — a
# toolchain-less box must fail the job as INFRA, never run it.
# --------------------------------------------------------------------------
BOOTSTRAP_PHASES = ("base", "android-sdk", "rust-anchor", "gradle-home")


def _parse_ts(s):
    """Parse a state.json UTC timestamp back to epoch seconds (None if
    unparseable). Used to measure a prior run's wall time on resume."""
    if not s:
        return None
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return None


def check_bootstrap():
    """Return (ok, missing): ok is True only when every bootstrap phase
    marker exists and the emulator binary is present and executable."""
    burst_home = os.environ.get("BURST_HOME", "/opt/burst")
    state_dir = Path(burst_home) / "bootstrap-state"
    missing = [f"{p}.done" for p in BOOTSTRAP_PHASES
               if not (state_dir / f"{p}.done").is_file()]
    android_home = os.environ.get(
        "ANDROID_HOME", str(Path(burst_home) / "android-sdk"))
    emulator = Path(android_home) / "emulator" / "emulator"
    if not (emulator.is_file() and os.access(emulator, os.X_OK)):
        missing.append(f"emulator binary ({emulator})")
    return (not missing, missing)


# --------------------------------------------------------------------------
# State: atomic writes (tmp + rename) so a SIGKILL mid-write can never
# leave a torn state.json behind (SPEC §4 checkpointing).
# --------------------------------------------------------------------------
class Campaign:
    def __init__(self, manifest, manifest_path, out_dir, work_dir, args):
        self.m = manifest
        self.manifest_path = Path(manifest_path)
        self.out = Path(out_dir)
        self.work = Path(work_dir)
        self.args = args
        self.campaign = str(manifest["campaign"])
        self.state_path = self.out / "state.json"
        self.lock = threading.Lock()
        self.started_at = time.time()
        # V-R06: the cost clock starts at BOX LAUNCH, not orchestrator
        # start — bootstrap (~15-30 min) bills before this process
        # exists, and the $0.50 margin does not cover it at the ceiling
        # price. user-data.sh records the launch epoch and passes it as
        # --box-launch-epoch. Without it the clock starts here and the
        # bootstrap tax is excluded: warn loudly and record it.
        self.box_launch_epoch = getattr(args, "box_launch_epoch", None)
        self.cost_start = (self.box_launch_epoch
                           if self.box_launch_epoch else self.started_at)
        self.cost_clock_degraded = self.box_launch_epoch is None
        if self.cost_clock_degraded:
            print("[orchestrator] WARNING: --box-launch-epoch not given; "
                  "cost clock starts at orchestrator start and the "
                  "bootstrap tax (~15-30 min) is EXCLUDED from projected "
                  "spend (VAULT V-R06) — degradation recorded in "
                  "state.json", file=sys.stderr)
        # Billable seconds already spent on THIS box before the
        # orchestrator started (bootstrap tax; 0 when the epoch is
        # absent — that is the degradation above, not a free pass).
        self.pre_orchestrator_s = max(
            0.0, self.started_at - self.cost_start)
        # §9 cost deadline: the box may not run longer than the budget
        # allows at the price actually paid. The launch operator passes
        # --hourly-price from the pre-flight print; the cost deadline
        # is the campaign-total (cap - margin) / price. The box cap is
        # per-box; the cost deadline is per-campaign (V-R07).
        self.hourly_price = getattr(args, "hourly_price", None)
        self.price_ceiling = getattr(args, "price_ceiling", 1.25)
        self.box_cap_s = float((manifest.get("box") or {}).get(
            "max_hours", 6)) * 3600
        self.cost_deadline_s = None
        cap = manifest.get("budget_cap_usd")
        if (self.hourly_price and self.hourly_price > 0
                and isinstance(cap, (int, float)) and cap > COST_MARGIN_USD):
            self.cost_deadline_s = ((cap - COST_MARGIN_USD)
                                    / self.hourly_price * 3600)
        # V-R07: cumulative billable time/spend across resumes — filled
        # in by _load_or_init_state from the prior bundle.
        self.cumulative_elapsed_s = 0.0
        self.cumulative_spend_usd = 0.0
        self.max_seconds = self.box_cap_s  # refined after resume load
        self.gate_ids = {j["id"] for j in manifest.get("jobs", [])
                         if j.get("gate")}
        self.relaunches = 0
        self.heartbeat_errors = 0  # consecutive-tolerant counter, §9
        self.aborted = None  # reason string once an abort triggers
        # V-R08: in-flight job processes, killed at the cost/deadline
        # trip instead of left to run out their own timeouts.
        self.live_procs = set()
        self.killed_pids = set()
        self._procs_lock = threading.Lock()
        # Per-job AVD console ports (competitive audit 2026-11-11): one
        # port per concurrent EMULATE worker (5554, 5556, ...). The pool
        # is sized to the EMULATE pool so a worker never blocks waiting
        # for a port. Ports are the emulator console ports; the adb
        # serial is emulator-<port>.
        self._avd_lock = threading.Lock()
        self._avd_free = [5554 + 2 * i
                          for i in range(getattr(args, "emulate_par", 8))]
        self._avd_in_use = set()
        self._avd_sessions = {}  # jid -> (serial, port) of booted emulator

        # V-R10: bootstrap gate, evaluated once per run.
        self.bootstrap_ok, self.bootstrap_missing = check_bootstrap()
        self.state = {
            "campaign": self.campaign,
            "status": "RUNNING",
            "started_at": self._ts(self.started_at),
            "started_at_epoch": self.started_at,
            "updated_at": self._ts(),
            "updated_at_epoch": self.started_at,
            "budget_cap_usd": cap,
            "hourly_price_usd": self.hourly_price,
            "price_ceiling_usd": self.price_ceiling,
            "cost_deadline_s": (round(self.cost_deadline_s, 1)
                                if self.cost_deadline_s else None),
            "box_launch_epoch": self.box_launch_epoch,
            "cost_clock": ("from_box_launch"
                           if not self.cost_clock_degraded
                           else "DEGRADED_orchestrator_start "
                           "(bootstrap tax excluded, V-R06)"),
            "pre_orchestrator_s": round(self.pre_orchestrator_s, 1),
            "cumulative_elapsed_s": 0.0,
            "cumulative_spend_usd": 0.0,
            "effective_max_s": round(self.max_seconds, 1),
            "in_flight_killed": 0,
            "relaunches": 0,
            "heartbeat_errors": 0,
            "lock_gate": None,
            "manifest_sha256": None,
            "manifest_resume": "fresh",
            "pool": {"reserve": dict(CHAIN_RESERVE), "refusals": [],
                     "paused": []},
            "jobs": {},
        }
        self._load_or_init_state()
        # Manifest hash for resume-never-repins (harvest audit,
        # mitigation 12, 2026-11-12): hash of the manifest-as-run
        # copy main() just wrote (scrubbed; deterministic, so the
        # same manifest re-hashes identically). main() compares it
        # against the prior bundle's recorded hash before any job
        # runs and refuses a resume whose manifest differs.
        self.manifest_sha256 = None
        try:
            self.manifest_sha256 = hashlib.sha256(
                (self.out / "manifest.yaml").read_bytes()).hexdigest()
        except OSError:
            pass
        self.state["manifest_sha256"] = self.manifest_sha256
        if self.args.resume:
            self.state["manifest_resume"] = (
                "hash-recorded" if self.prior_manifest_sha256 else
                "unverifiable-pre-fix-bundle")
        # Remaining wall for THIS box: the tighter of the per-box cap
        # (less time already spent on this box) and the campaign-total
        # cost deadline (less everything already billed). A resume that
        # has already spent the budget gets no wall at all — main()
        # refuses it (V-R06/V-R07).
        self.max_seconds = self._remaining_seconds()
        self.state["effective_max_s"] = round(self.max_seconds, 1)
        self.state["cumulative_elapsed_s"] = round(
            self.cumulative_elapsed_s, 1)
        self.state["cumulative_spend_usd"] = round(
            self.cumulative_spend_usd, 4)

    def alloc_avd_port(self):
        """Take one free AVD console port (None when the pool is empty)."""
        with self._avd_lock:
            if not self._avd_free:
                return None
            port = self._avd_free.pop(0)
            self._avd_in_use.add(port)
            return port

    def free_avd_port(self, port):
        """Return an AVD console port to the pool."""
        with self._avd_lock:
            self._avd_in_use.discard(port)
            if port not in self._avd_free:
                self._avd_free.append(port)
                self._avd_free.sort()

    def note_avd(self, jid, serial, port):
        """Record a booted per-job emulator so run_job can tear it down
        when the attempt ends (success, failure, or exception)."""
        with self._avd_lock:
            self._avd_sessions[jid] = (serial, port)

    def teardown_avd(self, jid):
        """Kill the per-job emulator for jid (best-effort — a failed
        kill never fails the job) and free its console port. No-op when
        the job never booted one."""
        with self._avd_lock:
            sess = self._avd_sessions.pop(jid, None)
        if not sess:
            return
        serial, port = sess
        try:
            boot_script = Path(__file__).resolve().parent / "boot-avd.sh"
            subprocess.run([str(boot_script), "kill", serial],
                           capture_output=True, timeout=60)
        except Exception:
            pass  # best-effort: the box dies with the campaign anyway
        self.free_avd_port(port)

    def _remaining_seconds(self):
        """Wall-clock seconds this box may still run: the per-box cap
        and the campaign cost deadline, each less what is already
        billed (prior runs + this box's pre-orchestrator time)."""
        remaining = self.box_cap_s - self.pre_orchestrator_s
        if self.cost_deadline_s is not None:
            remaining = min(
                remaining,
                self.cost_deadline_s - self.cumulative_elapsed_s
                - self.pre_orchestrator_s)
        return remaining

    def cost_elapsed_s(self):
        """Total billable seconds so far: prior runs + this box's
        pre-orchestrator time + this run's elapsed (V-R06/V-R07)."""
        return (self.cumulative_elapsed_s + self.pre_orchestrator_s
                + (time.time() - self.started_at))

    @staticmethod
    def _ts(t=None):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t or time.time()))

    def _load_or_init_state(self):
        prior = {}
        prior_top = {}
        if self.args.resume and self.state_path.exists():
            try:
                prior_top = json.loads(self.state_path.read_text())
                prior = prior_top.get("jobs", {})
            except Exception:
                prior = {}
        resets = 0
        # Resume-never-repins (harvest audit, mitigation 12,
        # 2026-11-12): the prior bundle's manifest hash, for main()
        # to compare against the manifest being resumed with. None
        # for pre-fix bundles (no hash was recorded) and for fresh
        # runs — main() records that as unverifiable, never as a pass.
        self.prior_manifest_sha256 = prior_top.get("manifest_sha256")
        self.resumed_from_prior = bool(prior_top)
        for j in self.m["jobs"]:
            jid = j["id"]
            old = prior.get(jid, {})
            status = old.get("state", "PENDING")
            demote_note = None
            if status == "RUNNING":
                status = "INTERRUPTED"  # was mid-flight when the box died
            if status == "INTERRUPTED" or (
                status == "FAILED" and self.args.retry_failed
            ):
                status = "PENDING"
                resets += 1
            elif status == "DONE" and self.args.resume and prior_top:
                # A resume trusts the prior state.json's DONE — but
                # the evidence may not have survived the pull: a box
                # reclaimed between a job finishing and the next
                # 10-min pull leaves DONE in state.json with no
                # evidence on disk, and the EMULATE sibling would
                # then wait 90 min for an APK that will never
                # arrive. A DONE without its evidence is not a DONE:
                # demote to PENDING so the job re-runs and
                # re-harvests. (Harvest audit, mitigation 12.)
                ev = self.out / "jobs" / jid / "evidence"
                if not (ev.is_dir()
                        and any(p.is_file() for p in ev.rglob("*"))):
                    status = "PENDING"
                    resets += 1
                    demote_note = ("evidence missing in resumed "
                                   "bundle (state said DONE) — "
                                   "re-running to re-harvest")
            self.state["jobs"][jid] = {
                "state": status,
                "kind": j["kind"],
                "lane": j.get("lane"),
                "chain": bool(j.get("chain")),
                "attempts": old.get("attempts", 0),
                "exit_code": old.get("exit_code"),
                "started_at": old.get("started_at"),
                "ended_at": old.get("ended_at"),
                "duration_s": old.get("duration_s"),
                "note": (demote_note if demote_note is not None
                         else old.get("note")),
                "failure_class": old.get("failure_class"),
            }
        # §9 relaunch cap: a resume that picks up interrupted work counts
        # as one relaunch; the cap (max 2) is enforced in main().
        if self.args.resume and prior_top and resets > 0:
            self.relaunches = int(prior_top.get("relaunches", 0)) + 1
        elif prior_top:
            self.relaunches = int(prior_top.get("relaunches", 0))
        self.state["relaunches"] = self.relaunches
        # V-R07: cumulative billable time/spend survives a resume — a
        # relaunch must NOT get a fresh cost clock. The prior run's
        # wall is measured from its cost-clock start (its box launch
        # epoch when recorded, else its orchestrator start) to its end
        # (ended_at when it finished cleanly, else last updated_at
        # when it was killed); its own cumulative fields carry forward
        # on top. Spend is priced at the prior run's hourly price
        # (falling back to this run's price for pre-fix bundles).
        if self.args.resume and prior_top:
            # Epoch fields when present (exact); the ISO strings are
            # the fallback for pre-fix bundles (1s resolution). A
            # killed run's wall is measured to its last checkpoint,
            # so the undercount is bounded by the 10s heartbeat tick.
            prior_start = (prior_top.get("box_launch_epoch")
                           or prior_top.get("started_at_epoch")
                           or _parse_ts(prior_top.get("started_at")))
            prior_end = (prior_top.get("updated_at_epoch")
                         or _parse_ts(prior_top.get("ended_at")
                                      or prior_top.get("updated_at")))
            prior_elapsed = 0.0
            if prior_start and prior_end and prior_end > prior_start:
                prior_elapsed = prior_end - prior_start
            prior_price = (prior_top.get("hourly_price_usd")
                           or self.hourly_price)
            self.cumulative_elapsed_s = (
                float(prior_top.get("cumulative_elapsed_s") or 0)
                + prior_elapsed)
            self.cumulative_spend_usd = (
                float(prior_top.get("cumulative_spend_usd") or 0)
                + (prior_elapsed / 3600 * prior_price
                   if prior_price else 0.0))
        # Heartbeat-error counter survives a resume like the relaunch
        # counter: it is evidence about the box, not about this process.
        self.heartbeat_errors = int(prior_top.get("heartbeat_errors", 0)
                                    or 0)
        self.state["heartbeat_errors"] = self.heartbeat_errors

    def save_state(self):
        with self.lock:
            self.state["updated_at"] = self._ts()
            self.state["updated_at_epoch"] = time.time()
            tmp = self.state_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.state, indent=2))
            tmp.replace(self.state_path)

    def note_heartbeat_error(self, where, exc):
        """Record one heartbeat failure: count it in state.json (so a
        dying disk / stuck trip is visible in the bundle, not silent),
        log it to stderr, and keep going. If the checkpoint itself is
        the failing part the counter rides along on the next successful
        save — it is never lost silently, only delayed."""
        self.heartbeat_errors += 1
        with self.lock:
            self.state["heartbeat_errors"] = self.heartbeat_errors
        print(f"[orchestrator] heartbeat error in {where}: {exc}",
              file=sys.stderr)
        try:
            self.save_state()
        except Exception:
            pass  # counted in memory; persisted on the next good save

    def heartbeat_tick(self):
        """One heartbeat iteration: checkpoint + cost trip, each guarded
        so a failure in one cannot kill the other or the loop. The cost
        trip is a safety control — it must survive a failing disk."""
        try:
            self.save_state()
        except Exception as exc:  # noqa: BLE001 - heartbeat must not die
            self.note_heartbeat_error("save_state", exc)
        try:
            self.check_cost_trip()
        except Exception as exc:  # noqa: BLE001 - heartbeat must not die
            self.note_heartbeat_error("check_cost_trip", exc)

    def set_job(self, jid, **kw):
        with self.lock:
            self.state["jobs"][jid].update(kw)
        self.save_state()
        if kw.get("state") == "FAILED":
            self.check_failure_trip()

    def deadline_exceeded(self):
        return time.time() - self.started_at > self.max_seconds

    def check_failure_trip(self):
        """§9 failure-rate trip: stop submitting new jobs when the run is
        systematically failing instead of burning the whole window.
        Gate jobs are excluded — they abort via the §11a abort gate."""
        if self.aborted:
            return
        jobs = [js for jid, js in self.state["jobs"].items()
                if jid not in self.gate_ids]
        failed = sum(1 for js in jobs if js["state"] == "FAILED")
        decided = sum(1 for js in jobs
                      if js["state"] in ("DONE", "FAILED"))
        if failed >= 5 or (decided >= 10 and failed / decided >= 0.30):
            reason = (f"failure-rate trip: {failed} failed of {decided} "
                      f"decided")
            with self.lock:
                self.aborted = reason
                if self.state["status"] == "RUNNING":
                    self.state["status"] = "ABORTED_FAILURE_TRIP"
            self.save_state()

    def register_proc(self, proc):
        with self._procs_lock:
            self.live_procs.add(proc)

    def unregister_proc(self, proc):
        with self._procs_lock:
            self.live_procs.discard(proc)

    def kill_in_flight_jobs(self):
        """V-R08: SIGKILL every in-flight job process group. The trip
        used to gate submissions only while in-flight jobs ran out
        their own timeouts (up to 150 min) — at the ceiling price the
        tail alone could push the campaign to ~$9.53 against the $8
        cap. The §9.4 self-terminate (kit/user-data.sh) is the second
        net; this is the first. Pids killed are recorded so the
        attempt path can label them instead of misclassifying the
        SIGKILL as an unknown failure."""
        with self._procs_lock:
            procs = list(self.live_procs)
        killed = 0
        for proc in procs:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                killed += 1
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                    killed += 1
                except Exception:
                    pass
            with self._procs_lock:
                self.killed_pids.add(proc.pid)
        if killed:
            with self.lock:
                self.state["in_flight_killed"] = (
                    self.state.get("in_flight_killed", 0) + killed)
            print(f"[orchestrator] cost/deadline trip: SIGKILLed "
                  f"{killed} in-flight job(s) (V-R08)",
                  file=sys.stderr)
        return killed

    def check_cost_trip(self):
        """§9 cost trip (needs --hourly-price): stop submitting new jobs
        when the projected spend reaches 80% of the cap, or the run is
        past 90% of its cost deadline — and TERMINATE in-flight jobs
        (V-R08), not just gate submissions. Projected spend counts
        everything billed: prior runs + this box's bootstrap tax +
        this run (V-R06/V-R07)."""
        if self.aborted or not self.hourly_price:
            return
        elapsed = self.cost_elapsed_s()
        projected = elapsed / 3600 * self.hourly_price
        cap = self.m.get("budget_cap_usd")
        reason = None
        if isinstance(cap, (int, float)) and projected >= 0.80 * cap:
            reason = (f"cost trip: projected ${projected:.2f} >= 80% of "
                      f"${cap} cap")
        elif (self.cost_deadline_s
                and elapsed >= 0.90 * self.cost_deadline_s):
            reason = (f"cost trip: {elapsed / 60:.0f}m elapsed >= 90% of "
                      f"cost deadline")
        if reason:
            with self.lock:
                self.aborted = reason
                if self.state["status"] == "RUNNING":
                    self.state["status"] = "ABORTED_COST"
            self.kill_in_flight_jobs()
            self.save_state()


# --------------------------------------------------------------------------
# Job execution
# --------------------------------------------------------------------------
SECRET_ENV_RE = re.compile(r"(SECRET|TOKEN|PASSWORD|KEYSTORE|PRIVATE_KEY|"
                           r"MNEMONIC|API_KEY)", re.IGNORECASE)


def job_env():
    """The orchestrator's environment, scrubbed: nothing secret-shaped is
    handed to a job process, whatever the operator shell carried (§8)."""
    env = {k: v for k, v in os.environ.items()
           if not SECRET_ENV_RE.search(k)}
    env.setdefault("GRADLE_USER_HOME",
                   os.path.join(os.environ.get("BURST_HOME", "/opt/burst"),
                                "gradle-home"))
    env.setdefault("ANDROID_HOME",
                   os.path.join(os.environ.get("BURST_HOME", "/opt/burst"),
                                "android-sdk"))
    env["ANDROID_SDK_ROOT"] = env["ANDROID_HOME"]
    env["CI"] = "true"
    return env


def run_job(camp: Campaign, job):
    """One job, up to MAX_ATTEMPTS attempts. Only transient INFRA
    failures retry (§5.2); a retry runs from a clean job dir after a
    backoff, and the bundle log keeps every attempt."""
    jid = job["id"]
    if camp.state["jobs"][jid]["state"] == "DONE":
        return
    if camp.aborted or camp.deadline_exceeded():
        return
    # V-R10: never admit an EMULATE job onto a toolchain-less box.
    # Bootstrap markers + the emulator binary were checked once at
    # startup; a missing piece fails the job as INFRA (retryable in
    # shape, but the run will trip/abort on the systematic failure
    # rather than burn the window job by job).
    if job["kind"] == "EMULATE" and not camp.bootstrap_ok:
        camp.set_job(jid, state="FAILED", ended_at=Campaign._ts(),
                     duration_s=0.0, exit_code=None,
                     note=("INFRA: bootstrap gate: missing "
                           + ", ".join(camp.bootstrap_missing)
                           + " — EMULATE not admitted on a "
                           "toolchain-less box (V-R10)"),
                     failure_class="INFRA")
        return
    t0 = time.time()
    base_attempts = camp.state["jobs"][jid]["attempts"]
    job_dir = camp.work / jid
    log_path = camp.out / "jobs" / jid / "log.txt"
    for attempt in range(1, MAX_ATTEMPTS + 1):
        # The per-job emulator (booted by _run_attempt for EMULATE jobs)
        # is torn down when the attempt ends — success, failure, or
        # exception — so a retry gets a clean device and no emulator
        # outlives its job. teardown_avd is a no-op for jobs that never
        # booted one.
        try:
            outcome = _run_attempt(camp, job, base_attempts + attempt, t0)
        finally:
            camp.teardown_avd(jid)
        if outcome[0] == "DONE":
            return
        _, cls, retryable, note, code = outcome
        if not retryable or attempt == MAX_ATTEMPTS:
            camp.set_job(jid, state="FAILED", ended_at=Campaign._ts(),
                         duration_s=round(time.time() - t0, 1),
                         exit_code=code, note=f"{cls}: {note}",
                         failure_class=cls)
            return
        # §5.2 retry gate: check BEFORE the 30s backoff. If the
        # remaining wall-clock cannot fit the job's full timeout (plus
        # the backoff about to be spent), the retry is skipped — it
        # could only die at the wall, burning time other jobs could
        # use, and the job ends FAILED either way. The failure class
        # is preserved; only the note records the skip.
        remaining_s = camp.max_seconds - (time.time() - camp.started_at)
        need_s = (float(job["timeout_min"]) * 60
                  * RETRY_REMAINING_TIMEOUT_FACTOR + RETRY_BACKOFF_S)
        if remaining_s < need_s:
            skip_note = (f"{cls}: {note} (retry skipped: only "
                         f"{remaining_s / 60:.1f}m left, job needs "
                         f"{job['timeout_min']}m)")
            with open(log_path, "a") as log:
                log.write(f"[orchestrator] {skip_note}\n")
            camp.set_job(jid, state="FAILED", ended_at=Campaign._ts(),
                         duration_s=round(time.time() - t0, 1),
                         exit_code=code, note=skip_note,
                         failure_class=cls)
            return
        with open(log_path, "a") as log:
            log.write(f"[orchestrator] {cls}: {note} — retrying in "
                      f"{RETRY_BACKOFF_S}s (attempt {attempt + 1} of "
                      f"{MAX_ATTEMPTS})\n")
        shutil.rmtree(job_dir, ignore_errors=True)
        time.sleep(RETRY_BACKOFF_S)
        if camp.aborted or camp.deadline_exceeded():
            camp.set_job(jid, state="FAILED", ended_at=Campaign._ts(),
                         duration_s=round(time.time() - t0, 1),
                         exit_code=code,
                         note=f"{cls}: {note} (retry pre-empted by "
                         f"abort/deadline)", failure_class=cls)
            return


def _run_attempt(camp: Campaign, job, attempt, t0):
    """One attempt. Returns ("DONE", None, None, None, 0) or
    ("FAILED", failure_class, retryable, note, exit_code)."""
    jid = job["id"]
    job_dir = camp.work / jid
    repo_dir = job_dir / "repo"
    log_path = camp.out / "jobs" / jid / "log.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    camp.set_job(jid, state="RUNNING", attempts=attempt,
                 started_at=Campaign._ts(), ended_at=None, note=None,
                 failure_class=None)

    def fail(point, code=None):
        cls, retryable, detail = classify_failure(log_path, point, code)
        return ("FAILED", cls, retryable, detail, code)

    env = job_env()
    # Burst artifact sharing (§5.1): jobs resolve cross-job evidence
    # (e.g. a BUILD leg's harvested APK) under this absolute bundle dir.
    env["BURST_OUT"] = str(camp.out.resolve())
    # L-05: jobs can reference the kit dir (for the orchestrator's own
    # --m01-check mode), the manifest as run, and the keys dir (the
    # M-01 gate job passes all three through to --m01-check).
    env["BURST_KIT_DIR"] = str(Path(__file__).resolve().parent)
    env["BURST_MANIFEST"] = str(camp.manifest_path.resolve())
    env["BURST_KEYS_DIR"] = str(getattr(camp.args, "keys_dir", "") or "")
    with open(log_path, "a") as log:
        def emit(msg):
            log.write(f"[orchestrator] {msg}\n")
            log.flush()

        # Clone machine-to-machine and verify the pin (SPEC §8.1–8.2).
        if not (repo_dir / ".git").exists():
            job_dir.mkdir(parents=True, exist_ok=True)
            clone_url = job.get("clone_url")
            clone_env = env
            keys_dir = getattr(camp.args, "keys_dir", None)
            if keys_dir:
                # SSH deploy-key path (SPEC §8.1): one read-only key
                # per repo, named <owner>-<repo> under keys_dir. An
                # explicit clone_url is honored as-is, but the key
                # must still exist — keys_dir declares the campaign's
                # auth mode, and a missing key refuses loudly rather
                # than falling back to https, which would mask a
                # credential failure and burn the run on 401s.
                key = Path(keys_dir) / job["repo"].replace("/", "-")
                if not key.is_file():
                    msg = (f"DEPLOY KEY MISSING: no key for "
                           f"{job['repo']} at {key} — refusing to "
                           f"fall back to https (a silent fallback "
                           f"would mask a credential failure)")
                    emit(msg)
                    return ("FAILED", "INFRA", False, msg, None)
                clone_env = dict(env)
                clone_env["GIT_SSH_COMMAND"] = (
                    "ssh -i " + shlex.quote(str(key)) +
                    " -o IdentitiesOnly=yes "
                    "-o StrictHostKeyChecking=accept-new")
                if not clone_url:
                    clone_url = f"git@github.com:{job['repo']}.git"
            if not clone_url:
                clone_url = f"https://github.com/{job['repo']}.git"
            # SECURITY: log the redacted URL only — an embedded
            # per-campaign token must never reach the job log.
            emit(f"clone {job['repo']} @ {job['ref']} ({scrub_url(clone_url)})")
            rc = subprocess.run(
                ["git", "clone", "--quiet", clone_url, str(repo_dir)],
                stdout=log, stderr=subprocess.STDOUT,
                env=clone_env).returncode
            if rc != 0:
                # SECURITY: git prints the remote URL in its own error
                # output — scrub any embedded token from the log before
                # the failure is recorded (the log is pulled off-box).
                log.flush()
                scrub_log_file(log_path, clone_url)
                return fail("clone", rc)
            rc = subprocess.run(
                ["git", "-C", str(repo_dir), "checkout", "--quiet",
                 str(job["ref"])],
                stdout=log, stderr=subprocess.STDOUT, env=env).returncode
            if rc != 0:
                return fail("checkout", rc)
        head = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, env=env).stdout.strip()
        if head != str(job["ref"]):
            return fail("pin")
        emit(f"pin verified: HEAD == {head}")

        # Per-job AVD provisioning (competitive audit 2026-11-11): the
        # battery assumes a booted emulator, but nothing in the kit ever
        # booted one — EMULATE jobs would burn their P0 budget waiting
        # for a device that does not exist, and concurrent workers would
        # share one device with no serial selection. Boot one emulator
        # per EMULATE job from the base AVD; ANDROID_SERIAL pins the
        # battery's bare `adb` calls to exactly that device (adb honors
        # ANDROID_SERIAL when set — no battery change needed). The
        # emulator is torn down by run_job (teardown_avd) when the
        # attempt ends, so a retry gets a clean device. When
        # boot-avd.sh is absent the job proceeds as before (whatever
        # device adb sees). An operator-set ANDROID_SERIAL is honored
        # as-is (no boot). A boot failure is INFRA/retryable.
        if job["kind"] == "EMULATE" and not env.get("ANDROID_SERIAL"):
            boot_script = Path(__file__).resolve().parent / "boot-avd.sh"
            if boot_script.is_file() and os.access(boot_script, os.X_OK):
                avd_port = camp.alloc_avd_port()
                if avd_port is None:
                    msg = ("AVD PORT POOL EXHAUSTED: no free emulator "
                           "console port — refusing rather than sharing "
                           "a device")
                    emit(msg)
                    return ("FAILED", "INFRA", True, msg, None)
                try:
                    boot = subprocess.run(
                        [str(boot_script), "boot", jid, str(avd_port)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, timeout=AVD_BOOT_TIMEOUT_S, env=env)
                    boot_rc, boot_out = boot.returncode, boot.stdout
                except subprocess.TimeoutExpired as exc:
                    boot_rc, boot_out = None, (exc.stdout or "") \
                        if isinstance(exc.stdout, str) else ""
                    boot_out += (f"\n[orchestrator] AVD boot timed out "
                                 f"after {AVD_BOOT_TIMEOUT_S}s\n")
                serial = None
                for line in (boot_out or "").splitlines():
                    if line.startswith("AVD_SERIAL="):
                        serial = line.split("=", 1)[1].strip()
                log.write(boot_out or "")
                log.flush()
                if boot_rc != 0 or not serial:
                    camp.free_avd_port(avd_port)
                    msg = (f"AVD BOOT FAILED for {jid} on port "
                           f"{avd_port} (rc={boot_rc}) — see log")
                    emit(msg)
                    return ("FAILED", "INFRA", True, msg, None)
                camp.note_avd(jid, serial, avd_port)
                env["ANDROID_SERIAL"] = serial
                emit(f"AVD provisioned: {serial} (port {avd_port})")
            else:
                emit("no boot-avd.sh next to the orchestrator — battery "
                     "uses whatever device adb sees (legacy, no per-job AVD)")

        # Run the job command with a hard timeout (SPEC §5).
        emit(f"run: {job['run']} (timeout {job['timeout_min']}m)")
        proc = subprocess.Popen(
            str(job["run"]), shell=True, cwd=str(repo_dir),
            stdout=log, stderr=subprocess.STDOUT, env=env,
            start_new_session=True)
        camp.register_proc(proc)
        try:
            rc = proc.wait(timeout=float(job["timeout_min"]) * 60)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()
            return fail("timeout")
        finally:
            camp.unregister_proc(proc)
        # V-R08: an attempt SIGKILLed by the cost/deadline trip is
        # INFRA, non-retryable, and labelled as the trip — not an
        # unknown exit -9.
        if rc == -9 and proc.pid in camp.killed_pids:
            return ("FAILED", "INFRA", False,
                    "killed by orchestrator at cost/deadline trip "
                    "(SIGKILL, V-R08)", rc)
        if rc != 0:
            return fail("exit", rc)

        # Harvest declared evidence products into the bundle (§10).
        ev_root = camp.out / "jobs" / jid / "evidence"
        found = []
        for name in job["produces"]:
            # `produces` entries are file/dir names or globs, matched
            # anywhere under the repo (e.g. "test-reports", "*.apk").
            hits = sorted(repo_dir.rglob(name))
            for hit in hits:
                dest = ev_root / name / hit.relative_to(repo_dir)
                dest.parent.mkdir(parents=True, exist_ok=True)
                if hit.is_dir():
                    shutil.copytree(hit, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(hit, dest)
                found.append(str(hit.relative_to(repo_dir)))
        emit(f"evidence harvested: {found or 'NONE FOUND'}")
        if not found:
            return fail("evidence", rc)
    camp.set_job(jid, state="DONE", ended_at=Campaign._ts(),
                 duration_s=round(time.time() - t0, 1), exit_code=0,
                 note=None)
    return ("DONE", None, None, None, 0)


# --------------------------------------------------------------------------
# Bundle finalisation: hashes.sha256 (§8.3, §10) + summary.json (§10 feed)
# --------------------------------------------------------------------------
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def finalize_bundle(camp: Campaign):
    waves = {}
    for jid, js in camp.state["jobs"].items():
        if js.get("started_at") and js.get("ended_at"):
            w = waves.setdefault(js["kind"], {"jobs": 0, "wall_s": 0.0})
            w["jobs"] += 1
            w["wall_s"] += js.get("duration_s") or 0.0
    # Per-job + per-lane cost attribution (competitive audit 2026-11-11):
    # the campaign's scorecard needs cost per job and per lane so each
    # campaign can beat the last one on a number, not a feeling. Cost is
    # wall time priced at the campaign's hourly price — the box bills by
    # the hour whether a worker is busy or idle, so per-job cost here is
    # the job's share of the campaign's billable wall, not a metered
    # per-job charge. None when no hourly price was given.
    price = camp.hourly_price
    jobs_out = {}
    per_lane = {}
    for jid, js in camp.state["jobs"].items():
        dur = js.get("duration_s") or 0.0
        cost = (dur / 3600 * price) if price else None
        jobs_out[jid] = {"state": js["state"],
                         "duration_s": js.get("duration_s"),
                         "failure_class": js.get("failure_class"),
                         "cost_usd": (round(cost, 4) if cost is not None
                                      else None)}
        lane = js.get("lane") or "?"
        roll = per_lane.setdefault(
            lane, {"jobs": 0, "done": 0, "failed": 0, "total_s": 0.0,
                   "cost_usd": 0.0})
        roll["jobs"] += 1
        if js["state"] == "DONE":
            roll["done"] += 1
        if js["state"] == "FAILED":
            roll["failed"] += 1
        roll["total_s"] = round(roll["total_s"] + dur, 1)
        if cost is not None:
            roll["cost_usd"] = round(roll["cost_usd"] + cost, 4)
    wall_h = max((time.time() - camp.started_at) / 3600, 1e-9)
    summary = {
        "campaign": camp.campaign,
        "status": camp.state["status"],
        "wall_s_total": round(time.time() - camp.started_at, 1),
        "cumulative_elapsed_s": round(camp.cost_elapsed_s(), 1),
        "price_ceiling_usd": camp.price_ceiling,
        "jobs": jobs_out,
        "per_lane": per_lane,
        "per_kind_job_seconds": waves,
        "jobs_per_hour": round(len(camp.state["jobs"]) / wall_h, 1),
    }
    # §5.2 error checking: the failure breakdown by class, and how many
    # jobs only finished because a transient infra failure retried.
    failures_by_class = {}
    retried_to_done = 0
    for js in camp.state["jobs"].values():
        if js["state"] == "FAILED":
            cls = js.get("failure_class") or "UNKNOWN"
            failures_by_class[cls] = failures_by_class.get(cls, 0) + 1
        if js["state"] == "DONE" and (js.get("attempts") or 0) > 1:
            retried_to_done += 1
    summary["failures_by_class"] = failures_by_class
    summary["retried_to_done"] = retried_to_done
    # §9 success bar: the campaign counts as a success only if ≥90% of
    # jobs are DONE; below that the report is partial and no seal may
    # cite it.
    done = sum(1 for js in camp.state["jobs"].values()
               if js["state"] == "DONE")
    total = len(camp.state["jobs"])
    summary["success_bar"] = {
        "required_done_frac": 0.90,
        "done": done,
        "total": total,
        "met": (done / total >= 0.90) if total else False,
    }
    # Campaign scorecard (competitive audit 2026-11-11): the numbers the
    # next campaign has to beat — total spend (billable wall priced at
    # the campaign's hourly price, including the bootstrap tax via the
    # cost clock), cost per DONE job, and the wall-clock cost of the
    # campaign. None when no hourly price was given.
    if price:
        total_spend = round(camp.cost_elapsed_s() / 3600 * price, 4)
        summary["total_spend_usd"] = total_spend
        summary["cost_per_done_job_usd"] = (
            round(total_spend / done, 4) if done else None)
    # E14 (competitive audit 2026-11-11): deterministic APK hashes in
    # summary.json — the audit needs byte-identical APKs per job, so
    # every APK in the bundle is hashed here (relative path -> sha256).
    # Files only: a produce pattern that never expanded can land as a
    # literal directory named `*.apk` in evidence, and opening a
    # directory must not take down finalisation.
    apk_hashes = {}
    for apk in sorted(camp.out.rglob("*.apk")):
        if apk.is_file():
            apk_hashes[str(apk.relative_to(camp.out))] = sha256_of(apk)
    summary["apk_hashes"] = apk_hashes
    (camp.out / "summary.json").write_text(json.dumps(summary, indent=2))
    lines = []
    for p in sorted(camp.out.rglob("*")):
        if p.is_file() and p.name != "hashes.sha256":
            lines.append(f"{sha256_of(p)}  {p.relative_to(camp.out)}")
    (camp.out / "hashes.sha256").write_text("\n".join(lines) + "\n")
    return summary


# --------------------------------------------------------------------------
# L-05 dispatch gate: the lock registry (kit/lock-check.py v2) as code.
# --------------------------------------------------------------------------
LOCK_REGISTRY_MAX_AGE_S = 3600
LOCK_SPOT_WORKERS = 8
LOCK_SPOT_TIMEOUT_S = 30


def _ls_remote_head(repo, keys_dir):
    """Live HEAD of a repo via git ls-remote. SSH with the repo's deploy
    key when --keys-dir is set and the key exists, else plain https.
    Returns (head-or-None, method, error-or-None)."""
    key = None
    if keys_dir:
        cand = Path(keys_dir) / repo.replace("/", "-")
        if cand.is_file():
            key = cand
    env = dict(os.environ)
    if key is not None:
        env["GIT_SSH_COMMAND"] = (
            "ssh -i " + shlex.quote(str(key)) +
            " -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new")
        url = f"git@github.com:{repo}.git"
        method = "ssh"
    else:
        url = f"https://github.com/{repo}.git"
        method = "https"
    try:
        p = subprocess.run(["git", "ls-remote", url, "HEAD"],
                           capture_output=True, text=True, env=env,
                           timeout=LOCK_SPOT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None, method, f"ls-remote timed out after {LOCK_SPOT_TIMEOUT_S}s"
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()
        return None, method, (err.splitlines()[-1][:160] if err
                              else "ls-remote failed")
    head = p.stdout.split()[0] if p.stdout.split() else None
    return head, method, None


def lock_registry_gate(manifest, registry_path, keys_dir):
    """L-05: enforce the lock registry at dispatch. Returns
    (ok, result-dict, refusals-list). Refuses (fail closed) when the
    registry is missing/unreadable/stale, when any manifest repo is
    missing from it, UNLOCKED in it, or pinned to a different HEAD
    than the registry records, or when the parallel ls-remote spot
    check disagrees on any repo's HEAD. No bundle dir or job exists
    yet when this runs — the caller refuses before creating them."""
    refusals = []
    result = {"registry": str(registry_path), "repos_checked": 0,
              "spot_check": {}, "refusals": refusals}
    try:
        registry = json.loads(Path(registry_path).read_text())
    except Exception as exc:
        refusals.append(f"registry unreadable ({registry_path}): {exc}")
        return False, result, refusals
    generated_by = str(registry.get("generated_by", ""))
    if not generated_by.startswith("kit/lock-check.py"):
        refusals.append(f"registry not produced by kit/lock-check.py "
                        f"(generated_by={generated_by!r}) — refusing a "
                        f"hand-written registry")
        return False, result, refusals
    epoch = registry.get("generated_at_epoch")
    if not isinstance(epoch, (int, float)):
        refusals.append("registry has no generated_at_epoch — cannot "
                        "check freshness")
        return False, result, refusals
    age = time.time() - epoch
    result["generated_at"] = registry.get("generated_at")
    result["age_s"] = round(age, 1)
    if age > LOCK_REGISTRY_MAX_AGE_S:
        refusals.append(f"registry stale: generated {age / 60:.1f}m ago "
                        f"(max {LOCK_REGISTRY_MAX_AGE_S // 60}m) — re-run "
                        f"kit/lock-check.py and re-publish it")
    by_repo = {}
    for r in registry.get("riders", []):
        if r.get("repo"):
            by_repo[r["repo"]] = r
    pins = {}
    for job in manifest["jobs"]:
        # str(): yaml parses an all-digit SHA as an int (e.g. 40 zeros);
        # refs are compared and passed to git as strings.
        pins.setdefault(job["repo"], set()).add(str(job["ref"]))
    result["repos_checked"] = len(pins)
    for repo in sorted(pins):
        entry = by_repo.get(repo)
        if entry is None:
            refusals.append(f"{repo}: no registry entry — not verified "
                            f"by lock-check")
            continue
        if entry.get("state") != "LOCKED":
            failing = [k for k, v in (entry.get("blocking_items") or {}).items()
                       if str(v).startswith("FAIL")]
            refusals.append(f"{repo}: registry state {entry.get('state')} "
                            f"({', '.join(failing) or 'no failing items listed'})")
            continue
        refs = pins[repo]
        if len(refs) != 1 or entry.get("head") not in refs:
            refusals.append(f"{repo}: registry HEAD "
                            f"{str(entry.get('head'))[:7]} != manifest pin(s) "
                            f"{sorted(r[:7] for r in refs)}")
    # Spot check (second net, L-06): parallel git ls-remote per distinct
    # manifest repo — the registry is never trusted on its own word.
    def spot(repo):
        head, method, err = _ls_remote_head(repo, keys_dir)
        return repo, head, method, err

    with ThreadPoolExecutor(max_workers=LOCK_SPOT_WORKERS) as ex:
        for repo, head, method, err in ex.map(spot, sorted(pins)):
            result["spot_check"][repo] = {
                "head": head, "method": method,
                "ok": head is not None and head in pins[repo],
                "error": err}
            if head is None:
                refusals.append(f"{repo}: spot check unreadable "
                                f"({method}: {err})")
            elif head not in pins[repo]:
                refusals.append(f"{repo}: spot check HEAD {head[:7]} != "
                                f"manifest pin(s) "
                                f"{sorted(r[:7] for r in pins[repo])}")
    return (not refusals), result, refusals


# --------------------------------------------------------------------------
# M-01 live rail re-check: the disarm, re-read at dispatch.
# --------------------------------------------------------------------------
MONEY_RIDERS = {
    # repo: (flag path, expected disarmed string)
    "raaruofficial/voidrunner": (
        "app/src/main/java/com/voidrunner/app/money/MoneyConfig.kt",
        "MONEY_RAIL_ENABLED: Boolean = false"),
    "raaruofficial/paper-moon": (
        "app/src/main/java/com/hindsight/app/money/MoneyConfig.kt",
        "SALES_ENABLED: Boolean = false"),
}
M01_GIT_TIMEOUT_S = 60


def _m01_read_flag(repo, pin, flag_path, keys_dir, tmp_root):
    """Read the rail flag file for one repo at HEAD and at the manifest
    pin. Returns (head, head_text, pin_text, error). A clone is the only
    transport GitHub supports for a read at an arbitrary SHA (git
    archive --remote is refused by the protocol), so: clone --depth 1
    (HEAD), then fetch --depth 1 origin <pin> and git show <pin>:<path>.
    Any unreadable step fails closed with the error, never a pass."""
    key = None
    if keys_dir:
        cand = Path(keys_dir) / repo.replace("/", "-")
        if cand.is_file():
            key = cand
    env = dict(os.environ)
    if key is not None:
        env["GIT_SSH_COMMAND"] = (
            "ssh -i " + shlex.quote(str(key)) +
            " -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new")
        url = f"git@github.com:{repo}.git"
    else:
        url = f"https://github.com/{repo}.git"
    work = Path(tmp_root) / repo.replace("/", "-")
    try:
        p = subprocess.run(["git", "clone", "--quiet", "--depth", "1",
                            url, str(work)],
                           capture_output=True, text=True, env=env,
                           timeout=M01_GIT_TIMEOUT_S)
        if p.returncode != 0:
            err = (p.stderr or p.stdout or "").strip()
            return None, None, None, (
                f"clone failed: {err.splitlines()[-1][:160] if err else 'rc=' + str(p.returncode)}")
        head = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"],
                              capture_output=True, text=True, env=env,
                              timeout=M01_GIT_TIMEOUT_S).stdout.strip()
        flag_file = work / flag_path
        head_text = flag_file.read_text() if flag_file.is_file() else None
        if head_text is None:
            return head, None, None, f"flag file {flag_path} missing at HEAD"
        p = subprocess.run(["git", "-C", str(work), "fetch", "--quiet",
                            "--depth", "1", "origin", pin],
                           capture_output=True, text=True, env=env,
                           timeout=M01_GIT_TIMEOUT_S)
        if p.returncode != 0:
            err = (p.stderr or p.stdout or "").strip()
            return head, head_text, None, (
                f"fetch of pin {pin[:7]} failed: "
                f"{err.splitlines()[-1][:160] if err else 'rc=' + str(p.returncode)}")
        p = subprocess.run(["git", "-C", str(work), "show", f"{pin}:{flag_path}"],
                           capture_output=True, text=True, env=env,
                           timeout=M01_GIT_TIMEOUT_S)
        if p.returncode != 0:
            return head, head_text, None, (
                f"flag file {flag_path} missing at pin {pin[:7]}")
        return head, head_text, p.stdout, None
    except subprocess.TimeoutExpired:
        return None, None, None, (
            f"git operation timed out after {M01_GIT_TIMEOUT_S}s")
    except Exception as exc:
        return None, None, None, f"git error: {exc}"


def m01_check(manifest, keys_dir, report_path):
    """M-01: re-read the live money-rail state for every money rider in
    the manifest and verify the disarm holds, at HEAD and at the
    manifest pin. Returns 0 iff every rider reads disarmed at both
    revisions; 1 otherwise. Fail closed: zero money riders in the
    manifest, an unreadable state, or an armed rail all fail. Writes
    the JSON report (per-repo lines + verdict) to report_path."""
    report = {"checked_at": datetime.now(timezone.utc).isoformat(),
              "manifest": None, "riders": [], "state": "FAIL"}
    if not isinstance(manifest, dict) or not manifest.get("jobs"):
        print("M-01 FAIL: manifest has no jobs — nothing to check",
              file=sys.stderr)
        report["reason"] = "manifest has no jobs"
        Path(report_path).write_text(json.dumps(report, indent=2))
        return 1
    report["manifest"] = manifest.get("campaign")
    pins = {}
    for job in manifest["jobs"]:
        # str(): yaml parses an all-digit SHA as an int (e.g. 40 zeros);
        # refs are compared and passed to git as strings.
        pins.setdefault(job["repo"], set()).add(str(job["ref"]))
    riders = [r for r in sorted(MONEY_RIDERS) if r in pins]
    if not riders:
        print("M-01 FAIL: no money rider in this manifest — the rail "
              "check has nothing to verify (failing closed: a check "
              "that verifies nothing is a vacuous pass)",
              file=sys.stderr)
        report["reason"] = "no money riders in manifest"
        Path(report_path).write_text(json.dumps(report, indent=2))
        return 1
    ok_all = True
    with tempfile.TemporaryDirectory(prefix="m01-check-") as tmp_root:
        for repo in riders:
            flag_path, expected = MONEY_RIDERS[repo]
            refs = pins[repo]
            row = {"repo": repo, "flag": flag_path, "expect": expected,
                   "state": "FAIL"}
            if len(refs) != 1:
                row["reason"] = (f"manifest pins {len(refs)} different "
                                 f"refs for {repo} — refusing an ambiguous pin")
                ok_all = False
            else:
                pin = next(iter(refs))
                head, head_text, pin_text, err = _m01_read_flag(
                    repo, pin, flag_path, keys_dir, tmp_root)
                row["head"] = head
                row["pin"] = pin
                if err:
                    row["reason"] = err
                    ok_all = False
                else:
                    head_ok = expected in (head_text or "")
                    pin_ok = expected in (pin_text or "")
                    row["head_disarmed"] = head_ok
                    row["pin_disarmed"] = pin_ok
                    if head_ok and pin_ok:
                        row["state"] = "PASS"
                        row["reason"] = (f"flag reads disarmed at HEAD "
                                         f"{head[:7]} and pin {pin[:7]}")
                    else:
                        which = []
                        if not head_ok:
                            which.append(f"HEAD {head[:7]}")
                        if not pin_ok:
                            which.append(f"pin {pin[:7]}")
                        row["reason"] = (f"rail NOT disarmed at "
                                         f"{', '.join(which)} (expected "
                                         f"'{expected}' in {flag_path})")
                        ok_all = False
            report["riders"].append(row)
            print(f"M-01 {row['state']}: {repo} "
                  f"head={str(row.get('head'))[:7] if row.get('head') else '-'} "
                  f"pin={str(row.get('pin'))[:7] if row.get('pin') else '-'} "
                  f"— {row['reason']}")
    report["state"] = "PASS" if ok_all else "FAIL"
    Path(report_path).write_text(json.dumps(report, indent=2))
    print(f"M-01 {'PASS' if ok_all else 'FAIL'}: "
          f"{len(report['riders'])} money rider(s) checked — "
          f"report {report_path}")
    return 0 if ok_all else 1


# --------------------------------------------------------------------------
# Pool reserve + preemption (mitigation 5, 2026-11-12).
#
# The box is m8i.12xlarge: 48 vCPU / 192 GB (SPEC §3, §9.1). The chain
# reserve is one third of the box: 16 vCPU + 64 GB. The orchestrator
# cannot reserve cores or RAM directly — it reserves WORKER SLOTS in
# the per-kind ThreadPoolExecutor pools, one slot per job, as the
# mechanism the code actually controls:
#   reserve(kind) = round(pool(kind) / 3)
#   BUILD   round(10/3) = 3   EMULATE round(8/3) = 3   VERIFY round(4/3) = 1
# Resource cross-check against SPEC §5 sizes (BUILD daemon + test
# forks ~6-8 GB, ~4.8 vCPU share of 48/10; EMULATE AVD 2-4 vCPU +
# 6-8 GB): 3 BUILD ~= 14 vCPU / ~21 GB, 3 EMULATE ~= 9 vCPU /
# ~21 GB. Both kinds saturated at once would be ~23 vCPU / ~42 GB
# — inside the 64 GB envelope but OVER the 16-vCPU envelope — so the
# 16-core figure is a sizing target, not a simultaneously-enforced
# hard cap: the enforced mechanism is slot counts. A true hard cap
# would need cgroups on the box; that is NOT built here (recorded
# gap, harvest-audit doc 2026-11-12).
#
# Admission rule (enforced in main()'s scheduler, below):
#   - chain jobs (chain:true, or §11a gate jobs) are admitted first
#     and may use any slot up to the pool size;
#   - farm jobs may always use up to (pool - reserve) slots, and may
#     use reserved slots ONLY when no chain job of that kind is
#     queued (PENDING) — otherwise they are refused for this tick,
#     recorded in state.json pool.refusals, and retried by the
#     scheduler (exit path unchanged: a deferred job still runs
#     once the chain drains, or ends PENDING on abort/deadline
#     exactly as an unsubmitted job did before).
#
# Preemption — what is honestly implementable:
#   - ThreadPoolExecutor CANNOT preempt a running thread. A farm job
#     already RUNNING is never killed mid-run for a chain job (the
#     only kill in this codebase is the §9 cost/deadline trip,
#     which is an abort, not a pause, and is not repurposed here).
#   - What CAN be preempted is a farm job SUBMITTED but NOT YET
#     STARTED: concurrent.futures.Future.cancel() removes it from
#     the pool queue (True iff it had not started). pause_queued_
#     farm() does exactly that, marks the job PAUSED in state.json,
#     and the scheduler re-queues it for later re-submission. If no
#     queued farm future exists (pool full of RUNNING farm jobs),
#     the chain job waits for the next scheduler tick — that wait
#     is the recorded limitation, not a silent queue-jump.
# --------------------------------------------------------------------------
CHAIN_RESERVE = {"BUILD": 3, "EMULATE": 3, "VERIFY": 1}


class PoolAdmission:
    """Slot-level admission control for the per-kind worker pools."""

    def __init__(self, par, reserve, camp):
        self.par = dict(par)
        # A reserve larger than its pool would bar farm jobs
        # entirely (farm cap 0 is legal, negative is not); clamp.
        self.reserve = {k: min(reserve.get(k, 0), self.par[k])
                        for k in self.par}
        self.camp = camp
        self._lock = threading.Lock()
        self._fut_job = {}  # future -> (kind, jid, is_chain)
        self._refused = set()  # jids refused in this pending episode

    def _active_locked(self, kind):
        live = [(f, v) for f, v in self._fut_job.items()
                if v[0] == kind and not f.done()]
        for f, _v in list(self._fut_job.items()):
            if f.done():
                self._fut_job.pop(f, None)
        return len(live)

    def _chain_pending_locked(self, kind):
        # PENDING chain jobs of this kind, read from state.json's
        # own per-job records (chain flag recorded at resume/load).
        # A chain job already SUBMITTED (live future in _fut_job)
        # does not count: its worker thread marks it RUNNING a
        # moment after submit, and counting that window as "queued"
        # would refuse farm jobs for a whole scheduler tick after
        # every chain submission (observed in the 2026-11-12 dry
        # run: farm-a1 refused at tick 1 although a slot was free).
        submitted = {v[1] for v in self._fut_job.values()}
        return sum(
            1 for jid, js in self.camp.state["jobs"].items()
            if jid not in submitted
            and js.get("state") == "PENDING" and js.get("chain")
            and js.get("kind") == kind)

    def admit(self, kind, is_chain):
        """True iff a job of this kind/chain-ness may take a slot now."""
        with self._lock:
            active = self._active_locked(kind)
            if is_chain:
                return active < self.par[kind]
            if active < self.par[kind] - self.reserve[kind]:
                return True
            if (self._chain_pending_locked(kind) == 0
                    and active < self.par[kind]):
                return True
            return False

    def note_submit(self, kind, fut, jid, is_chain):
        with self._lock:
            self._fut_job[fut] = (kind, jid, is_chain)
            self._refused.discard(jid)

    def refuse(self, job, kind, reason):
        """Record one farm-job refusal in state.json (first refusal
        per pending episode only — the scheduler retries every 10s
        and must not spam the bundle)."""
        jid = job["id"]
        with self._lock:
            if jid in self._refused:
                return
            self._refused.add(jid)
        rec = {"job": jid, "kind": kind, "reason": reason,
               "at": Campaign._ts()}
        with self.camp.lock:
            self.camp.state["pool"]["refusals"].append(rec)
            self.camp.state["jobs"][jid]["note"] = (
                f"POOL REFUSED: {reason} — deferred, retried by the "
                f"scheduler (mitigation 5)")
        self.camp.save_state()

    def pause_queued_farm(self, kind):
        """Preempt farm jobs of this kind that are submitted but not
        yet started: cancel their futures, mark them PAUSED in
        state.json, and return their ids for re-queueing. Running
        jobs are never touched (cannot be — see the module note
        above); a future that started between the check and the
        cancel simply fails to cancel and is left alone."""
        with self._lock:
            cands = [(fut, jid) for fut, (k, jid, chain)
                     in list(self._fut_job.items())
                     if k == kind and not chain
                     and not fut.done() and not fut.running()]
        paused = []
        for fut, jid in cands:
            if fut.cancel():
                paused.append(jid)
                with self._lock:
                    self._fut_job.pop(fut, None)
        for jid in paused:
            with self.camp.lock:
                self.camp.state["pool"]["paused"].append(
                    {"job": jid, "kind": kind, "at": Campaign._ts()})
            self.camp.set_job(
                jid, state="PAUSED",
                note=("POOL PAUSE: queued farm job pre-empted for a "
                      "chain job — re-queued, not killed "
                      "(mitigation 5)"))
        return paused


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="burst-compute orchestrator")
    ap.add_argument("manifest")
    ap.add_argument("--out", default=None,
                    help="results bundle dir (default results/<campaign>)")
    ap.add_argument("--work", default=None,
                    help="job work dir (default work/<campaign>)")
    ap.add_argument("--lint-only", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="resume from an existing bundle state.json")
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--hourly-price", type=float, default=None,
                    help="live $/hr paid for this box, from the pre-flight "
                    "print (SPEC §9): REQUIRED — enables the cost deadline "
                    "+ trip; the run refuses to start without it (V-R04)")
    ap.add_argument("--box-launch-epoch", type=float, default=None,
                    help="epoch seconds when the box launched (recorded by "
                    "kit/user-data.sh at boot, SPEC §9/V-R06): the cost "
                    "clock starts there so the bootstrap tax is inside the "
                    "cap. Without it the clock starts at orchestrator "
                    "start, the bootstrap tax is excluded, and a loud "
                    "warning is printed + the degradation recorded in "
                    "state.json")
    ap.add_argument("--price-ceiling", type=float, default=1.25,
                    help="SPEC §9.1 pre-flight price ceiling ($/hr): "
                    "refuse to start when --hourly-price exceeds it; "
                    "raise explicitly (and record why) to override")
    ap.add_argument("--keys-dir", default=os.environ.get(
        "BURST_DEPLOY_KEYS_DIR"),
        help="dir of per-repo read-only SSH deploy keys, one file per "
        "repo named <owner>-<repo> (SPEC §8.1, "
        "kit/GITHUB_CREDENTIAL.md). When set, every job clones via "
        "git@github.com with its repo's key (an explicit clone_url "
        "is honored as-is) and a missing key refuses loudly rather "
        "than falling back to https. Unset: plain https clone as "
        "before. Also honored via env BURST_DEPLOY_KEYS_DIR.")
    ap.add_argument("--lock-registry", default=None,
                    help="L-05 dispatch gate: path to parallel-lock.json "
                    "(kit/lock-check.py v2, generated <1h before "
                    "dispatch). When set, the run refuses (exit 2, "
                    "before any bundle dir or job) unless the registry "
                    "is fresh, every manifest repo reads LOCKED in it "
                    "with its pin equal to the registry HEAD, and a "
                    "parallel git ls-remote spot check agrees on every "
                    "repo's HEAD. Unset: the gate is not enforced "
                    "(a warning is printed); user-data.sh always "
                    "passes it.")
    ap.add_argument("--m01-check", action="store_true",
                    help="M-01 live rail re-check (standalone mode, like "
                    "--lint-only): re-read the live money-rail state "
                    "for every money rider in the manifest (VOIDRUNNER "
                    "+ Paper Moon) at both HEAD and the manifest pin "
                    "and verify the disarm holds. Exit 0 iff every "
                    "rider's flag reads disarmed at both revisions; "
                    "exit 1 otherwise (unreadable state or an armed "
                    "rail fails closed). Writes a JSON report to "
                    "--report (default m01-rail-check.json in the cwd) "
                    "for evidence harvesting.")
    ap.add_argument("--report", default="m01-rail-check.json",
                    help="JSON report path for --m01-check (default: "
                    "m01-rail-check.json in the cwd)")
    # Pool defaults are the low end of the SPEC §5 ranges: 10 daemons +
    # 8 AVDs peak ~144 GB on the 192 GB box, leaving headroom for daemon
    # spikes; 12+10 could peak ~176 GB and risk OOM kills (SPEC §9).
    ap.add_argument("--build-par", type=int, default=10)
    ap.add_argument("--emulate-par", type=int, default=8)
    ap.add_argument("--verify-par", type=int, default=4)
    args = ap.parse_args(argv)

    text = Path(args.manifest).read_text()
    try:
        manifest = load_yaml(text)
    except Exception as exc:
        print(f"MANIFEST PARSE FAILURE — campaign will not run: {exc}",
              file=sys.stderr)
        return 2
    # M-01 is a standalone verification mode (like --lint-only): it
    # checks the rail only, so it runs before the lint refusal — a
    # manifest with lint errors still gets its rail state read.
    if args.m01_check:
        return m01_check(manifest, args.keys_dir, args.report)
    errs = lint_manifest(manifest if isinstance(manifest, dict) else {})
    if errs:
        print("MANIFEST LINT REFUSAL — campaign will not run:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 2
    if args.lint_only:
        print(f"lint OK: campaign {manifest['campaign']}, "
              f"{len(manifest['jobs'])} jobs, cap "
              f"${manifest['budget_cap_usd']}")
        return 0

    # V-R04: --hourly-price is REQUIRED. Omitting it (or passing 0 / a
    # negative price) silently disabled the cost deadline, the cost
    # trip, AND the price-ceiling check — a run with no cost control
    # before the 6h box cap. Refuse to start (exit 2), like the
    # ceiling refusal. This check sits after --lint-only on purpose:
    # linting a manifest needs no price.
    if args.hourly_price is None or args.hourly_price <= 0:
        print("HOURLY PRICE REQUIRED: pass --hourly-price <live $/hr> "
              "from the pre-flight print (SPEC §9.1) — without a "
              "positive hourly price there is no cost deadline, no "
              "cost trip, and no price-ceiling check (VAULT V-R04); "
              "the run refuses to start rather than run unguarded",
              file=sys.stderr)
        return 2

    # §9.1 price ceiling, enforced mechanically (BANKAI 2026-11-07,
    # Team GRID): the launch procedure's pre-flight print is a human
    # step and humans misread prints. Above the ceiling there is no
    # launch at all — exit 2 before any bundle dir or job exists.
    if (args.hourly_price is not None
            and args.hourly_price > args.price_ceiling):
        print(f"PRICE CEILING REFUSAL: --hourly-price "
              f"${args.hourly_price}/hr exceeds the --price-ceiling "
              f"${args.price_ceiling}/hr (SPEC §9.1) — no launch, no "
              f"jobs run; wait for a cheaper hour, or raise the "
              f"ceiling explicitly and record why",
              file=sys.stderr)
        return 2

    # Deploy-keys dir must exist before any job runs: a typo'd path
    # would otherwise refuse every job one by one as DEPLOY KEY
    # MISSING. Lint-only already returned above, so linting a
    # manifest needs no keys.
    if args.keys_dir and not Path(args.keys_dir).is_dir():
        print(f"KEYS DIR REFUSAL: --keys-dir {args.keys_dir} is not a "
              f"directory — the per-repo deploy keys are not where "
              f"the run expects them (SPEC §8.1) — refusing to run",
              file=sys.stderr)
        return 2

    # L-05 dispatch gate: the lock registry, enforced before any bundle
    # dir or job exists. --lock-registry is always passed by
    # user-data.sh (§4); a hand run without it proceeds without the
    # gate, loudly noted.
    lock_gate_result = None
    if args.lock_registry:
        gate_ok, lock_gate_result, gate_refusals = lock_registry_gate(
            manifest, args.lock_registry, args.keys_dir)
        if not gate_ok:
            print("LOCK REGISTRY REFUSAL — dispatch stopped before any "
                  "bundle dir or job:", file=sys.stderr)
            for r in gate_refusals:
                print(f"  - {r}", file=sys.stderr)
            return 2
        print(f"LOCK REGISTRY OK: {lock_gate_result['repos_checked']} "
              f"manifest repos LOCKED in {args.lock_registry} "
              f"(generated {lock_gate_result['age_s']:.0f}s ago) + "
              f"ls-remote spot check agrees on all of them")
    else:
        print("LOCK REGISTRY NOT ENFORCED: no --lock-registry passed "
              "(user-data.sh always passes it; a hand run without it "
              "proceeds without the dispatch gate)", file=sys.stderr)

    campaign = str(manifest["campaign"])
    out_dir = Path(args.out or f"results/{campaign}")
    work_dir = Path(args.work or f"work/{campaign}")
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    # Manifest as run (§10) — copy with credentials redacted (SECURITY
    # 2026-11-11): a clone_url carrying an embedded per-campaign token
    # must not be persisted verbatim into the results bundle. The copy
    # is byte-identical except any https://<userinfo>@ is scrubbed.
    manifest_text = Path(args.manifest).read_text()
    scrubbed = re.sub(r"(https?://)[^/@\s]+@", r"\1***@", manifest_text)
    (out_dir / "manifest.yaml").write_text(scrubbed)

    # EMULATE jobs need the KVM gate to have passed on this box (§7).
    kinds_present = {j["kind"] for j in manifest["jobs"]}
    if "EMULATE" in kinds_present and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        print("KVM GATE FAILURE: EMULATE jobs present but /dev/kvm is not "
              "readable+writable — aborting before any job runs (SPEC §7)",
              file=sys.stderr)
        return 4

    # Proactive disk guard: refuse before any job runs when the work
    # filesystem is below the floor (DISK_MIN_FREE_GB). Checked against
    # work_dir — the filesystem the jobs actually write to.
    disk_ok, disk_free = check_disk_space(work_dir)
    if not disk_ok:
        print(f"DISK SPACE REFUSAL: only {disk_free:.1f} GB free on "
              f"{work_dir} — need >= {DISK_MIN_FREE_GB} GB free before "
              f"jobs start (20 repos + Gradle cache + APKs + emulator "
              f"images on a 200 GB root; SPEC §3) — refusing to run",
              file=sys.stderr)
        return 2

    camp = Campaign(manifest, args.manifest, out_dir, work_dir, args)
    # Resume-never-repins (harvest audit, mitigation 12, 2026-11-12):
    # a resume must resume the locked manifest byte-identical. The
    # hash is of the manifest-as-run copy (scrubbed; deterministic).
    # Refuse before any state is saved or any job runs. A prior
    # bundle from before hash recording cannot be proven identical:
    # proceed with a loud warning, recorded in state.json
    # (manifest_resume=unverifiable-pre-fix-bundle), never as a pass.
    if args.resume and camp.resumed_from_prior:
        if (camp.prior_manifest_sha256 and camp.manifest_sha256
                and camp.prior_manifest_sha256 != camp.manifest_sha256):
            print(f"MANIFEST CHANGED ON RESUME: the manifest given "
                  f"({args.manifest}) hashes "
                  f"{camp.manifest_sha256[:12]} but the bundle being "
                  f"resumed was run with "
                  f"{camp.prior_manifest_sha256[:12]} — a resume "
                  f"re-pins nothing and resumes nothing different; "
                  f"resume with the manifest as run "
                  f"({out_dir}/manifest.yaml) or start a fresh "
                  f"campaign (mitigation 12)", file=sys.stderr)
            return 2
        if not camp.prior_manifest_sha256:
            print(f"[orchestrator] WARNING: prior bundle predates "
                  f"manifest-hash recording — resume cannot prove "
                  f"the manifest is byte-identical; proceeding, "
                  f"recorded as unverifiable-pre-fix-bundle in "
                  f"state.json", file=sys.stderr)
    if lock_gate_result is not None:
        with camp.lock:
            camp.state["lock_gate"] = lock_gate_result
        camp.save_state()
    if camp.relaunches > 2:
        print(f"RELAUNCH CAP: campaign {campaign} has already relaunched "
              f"{camp.relaunches} times (max 2 per SPEC §9) — refusing to "
              f"run; continuing needs the owner's word", file=sys.stderr)
        return 2
    # V-R06/V-R07: prior runs + this box's bootstrap tax already spent
    # the campaign's cost-derived runtime — there is no wall left.
    # Refuse rather than run a box that cannot fit inside the cap.
    if camp.max_seconds <= 0:
        print(f"COST BUDGET EXHAUSTED: prior runs + bootstrap tax "
              f"already consumed the campaign's cost-derived runtime "
              f"({camp.cumulative_elapsed_s / 3600:.2f}h cumulative + "
              f"{camp.pre_orchestrator_s / 60:.0f}m pre-orchestrator "
              f"against a "
              f"{(camp.cost_deadline_s or 0) / 3600:.2f}h cost deadline)"
              f" — refusing to run; continuing needs the owner's word",
              file=sys.stderr)
        return 2
    camp.save_state()

    # Schedule-fit warning (competitive audit 2026-11-11): the campaign
    # only fits inside the box cap if real job durations are far below
    # their timeouts — and nobody had checked. Worst case, every job
    # runs to its timeout: BUILD rounds x max BUILD timeout + EMULATE
    # rounds x max EMULATE timeout, plus the bootstrap tax already
    # spent. For camp-1 that worst case is 27 BUILD / 10 workers x
    # 40m + 27 EMULATE / 8 workers x 150m = 108m + 600m = 11.8h
    # against a 6h box cap — the campaign fits ONLY if real batteries
    # average well under ~80 min. This is a WARNING, not a refusal:
    # timeouts are caps, not estimates, and real batteries are expected
    # at ~10-25 min. But if campaign 0 measures EMULATE p50 above
    # ~60 min, the wave does not fit and the manifest's timeouts (or
    # the pool sizes, or the box) must change before campaign 1. The
    # warning is recorded in state.json so the campaign report carries it.
    import math
    build_jobs = [j for j in manifest["jobs"] if j["kind"] == "BUILD"]
    emulate_jobs = [j for j in manifest["jobs"] if j["kind"] == "EMULATE"]
    worst_s = 0.0
    if build_jobs:
        worst_s += (math.ceil(len(build_jobs) / max(args.build_par, 1))
                    * max(float(j["timeout_min"]) for j in build_jobs) * 60)
    if emulate_jobs:
        worst_s += (math.ceil(len(emulate_jobs) / max(args.emulate_par, 1))
                    * max(float(j["timeout_min"]) for j in emulate_jobs) * 60)
    worst_s += camp.pre_orchestrator_s
    fit_ok = worst_s <= camp.max_seconds
    if not fit_ok:
        warn = (f"SCHEDULE-FIT WARNING: worst-case wall "
                 f"({worst_s / 3600:.1f}h if every job ran to its timeout) "
                 f"exceeds the effective wall "
                 f"({camp.max_seconds / 3600:.1f}h) — the campaign fits "
                 f"only if real job durations are well below their "
                 f"timeouts (EMULATE must average well under "
                 f"{(camp.max_seconds - camp.pre_orchestrator_s) / 3600:.1f}h "
                 f"of wave time). Measure real durations in the report; "
                 f"if EMULATE p50 exceeds ~60 min, retune timeouts, "
                 f"pools, or the box before the next campaign.")
        print(f"[orchestrator] {warn}", file=sys.stderr)
        with camp.lock:
            camp.state["schedule_fit_warning"] = warn
        camp.save_state()

    jobs = sorted(manifest["jobs"], key=lambda j: (
        0 if j.get("gate") else 1,
        0 if j.get("chain") else 1, signal_rank(j)))
    gate_ids = {j["id"] for j in jobs if j.get("gate")}

    def heartbeat():
        # Each tick is internally guarded (heartbeat_tick): a failure
        # in save_state cannot kill check_cost_trip and vice versa, and
        # failures are counted in state.json, never silent.
        while camp.state["status"] == "RUNNING":
            camp.heartbeat_tick()
            time.sleep(10)

    hb = threading.Thread(target=heartbeat, daemon=True)
    hb.start()

    par = {"BUILD": args.build_par, "EMULATE": args.emulate_par,
           "VERIFY": args.verify_par}
    pools = {k: ThreadPoolExecutor(max_workers=v) for k, v in par.items()}
    # Pool reserve (mitigation 5): chain jobs first, farm jobs only
    # into unreserved / chain-free slots; refused farm jobs are
    # deferred and retried, never dropped.
    admission = PoolAdmission(par, CHAIN_RESERVE, camp)

    # §11a abort gate: gate jobs run first; any gate failure aborts the
    # push before the expensive waves begin (~$0.50 exposure by design).
    def run_set(job_list):
        futures = {}
        for job in job_list:
            if camp.state["jobs"][job["id"]]["state"] != "PENDING":
                continue
            futures[pools[job["kind"]].submit(run_job, camp, job)] = job["id"]
        for fut in futures:
            fut.result()
        return futures

    def try_submit(job, futures):
        """Submit one non-gate job through pool admission. Returns the
        future, or None when the job is refused/deferred this tick
        (it stays PENDING/PAUSED and the scheduler retries it) or is
        no longer submittable. Gate jobs bypass this: run_set runs
        them first, sequentially, before any pool is contended."""
        jid = job["id"]
        st = camp.state["jobs"][jid]["state"]
        if st == "PAUSED":
            # Re-queueing a pre-empted farm job: back to PENDING so
            # run_job and the dispatch checks see it as submittable.
            camp.set_job(jid, state="PENDING", note=None)
            st = "PENDING"
        if st != "PENDING":
            return None
        kind = job["kind"]
        chain = bool(job.get("chain")) or jid in gate_ids
        if not admission.admit(kind, chain):
            if chain:
                # A chain job that cannot get a slot tries honest
                # preemption first: cancel queued (not yet started)
                # farm futures of this kind, then re-check. Running
                # farm jobs are never killed; if none was queued the
                # chain job waits for the next tick (recorded
                # limitation — see the PoolAdmission module note).
                paused = admission.pause_queued_farm(kind)
                if paused:
                    print(f"[orchestrator] POOL PREEMPT: paused queued "
                          f"farm job(s) {paused} for chain job {jid}",
                          file=sys.stderr)
                if not admission.admit(kind, chain):
                    return None
            else:
                admission.refuse(
                    job, kind,
                    "no spare slot: chain jobs queued / reserve held")
                return None
        fut = pools[kind].submit(run_job, camp, job)
        admission.note_submit(kind, fut, jid, chain)
        futures[fut] = jid
        return fut

    if gate_ids:
        # Gate jobs run SEQUENTIALLY in sorted order (cheapest first:
        # m01-rail-check, priority 0, before booth-l3) and the first
        # failure stops the rest — a failed cheap gate must not pay
        # for an expensive gate behind it (L-05/M-01). The existing
        # failed_gates check below still aborts the push.
        for gj in [j for j in jobs if j["id"] in gate_ids]:
            run_set([gj])
            if camp.state["jobs"][gj["id"]]["state"] == "FAILED":
                break
        failed_gates = [jid for jid in gate_ids
                        if camp.state["jobs"][jid]["state"] == "FAILED"]
        if failed_gates:
            camp.aborted = f"abort gate failed: {failed_gates}"
            camp.state["status"] = "ABORTED_GATE"
    if not camp.aborted:
        # Dependency-aware dispatch (competitive audit 2026-11-11)
        # + pool admission (mitigation 5, 2026-11-12), unified: the
        # old shape submitted all non-EMULATE jobs at once and each
        # EMULATE job the moment its BUILD sibling landed, with no
        # admission control — a farm wave could occupy every slot
        # while a chain job waited. Now every non-gate job goes
        # through try_submit() each tick (chain first by sort order):
        # an EMULATE job is still submitted only when its same-lane
        # BUILD sibling is DONE (in BUILD-completion order, so the
        # earliest ready battery runs first), preserving the §11a
        # overlap without the parking; when the BUILD sibling FAILED
        # the EMULATE job is marked FAILED at once. EMULATE jobs with
        # no BUILD sibling submit immediately, as before. Refused
        # farm jobs stay PENDING and are retried every 10s until the
        # chain drains or the run aborts / hits its deadline.
        non_gate = [j for j in jobs if j["id"] not in gate_ids]
        by_id = {j["id"]: j for j in non_gate}
        build_by_lane = {j["lane"]: j["id"] for j in non_gate
                         if j["kind"] == "BUILD"}
        futures = {}
        pending = list(non_gate)
        while pending or any(not f.done() for f in futures):
            if camp.aborted or camp.deadline_exceeded():
                break
            still_pending = []
            for job in pending:
                jid = job["id"]
                if job["kind"] == "EMULATE":
                    sibling_id = build_by_lane.get(job["lane"])
                    if sibling_id is not None:
                        sibling = camp.state["jobs"][sibling_id]["state"]
                        if sibling == "FAILED":
                            camp.set_job(
                                jid, state="FAILED",
                                ended_at=Campaign._ts(), duration_s=0.0,
                                exit_code=None,
                                note=("APP: BUILD sibling "
                                      f"{sibling_id} FAILED — no APK will "
                                      "arrive; EMULATE skipped without "
                                      "occupying a worker"),
                                failure_class="APP")
                            continue
                        if sibling != "DONE":
                            still_pending.append(job)
                            continue
                if try_submit(job, futures) is None:
                    if camp.state["jobs"][jid]["state"] in (
                            "PENDING", "PAUSED"):
                        still_pending.append(job)
            # Re-queue farm jobs pre-empted this tick: their futures
            # were cancelled before starting and their state is
            # PAUSED; the next tick re-submits them through admission.
            for fut, jid in list(futures.items()):
                if fut.cancelled():
                    del futures[fut]
                    if camp.state["jobs"][jid]["state"] == "PAUSED":
                        still_pending.append(by_id[jid])
            pending = still_pending
            if pending:
                time.sleep(10)
        for fut in futures:
            try:
                fut.result()
            except CancelledError:
                pass  # paused farm job: cancelled before it ran; it
                # was re-queued above and re-ran (or the run ended)

    for pool in pools.values():
        pool.shutdown(wait=True)

    if camp.deadline_exceeded() and camp.state["status"] == "RUNNING":
        camp.state["status"] = "DEADLINE"
    elif camp.state["status"] == "RUNNING":
        states = {js["state"] for js in camp.state["jobs"].values()}
        camp.state["status"] = (
            "DONE" if states <= {"DONE"} else "DONE_WITH_FAILURES")
    camp.state["ended_at"] = Campaign._ts()
    camp.save_state()
    summary = finalize_bundle(camp)
    bar = summary["success_bar"]
    fbc = summary["failures_by_class"]
    print(f"campaign {campaign}: {camp.state['status']} — bundle at "
          f"{out_dir} — success bar "
          f"{'MET' if bar['met'] else 'NOT MET'} "
          f"({bar['done']}/{bar['total']} DONE, bar 90%)"
          + (f" — failures by class: {fbc}" if fbc else "")
          + (f" — {summary['retried_to_done']} retried to DONE"
             if summary["retried_to_done"] else ""))
    return 0 if camp.state["status"] == "DONE" else 3


if __name__ == "__main__":
    sys.exit(main())
