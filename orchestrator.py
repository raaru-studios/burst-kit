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
                  [--box-launch-epoch E]
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
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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
    r"BEGIN [A-Z ]*PRIVATE KEY|\.env\b|id_rsa|aws_secret_access_key)",
    re.IGNORECASE,
)
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
            "jobs": {},
        }
        self._load_or_init_state()
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
        for j in self.m["jobs"]:
            jid = j["id"]
            old = prior.get(jid, {})
            status = old.get("state", "PENDING")
            if status == "RUNNING":
                status = "INTERRUPTED"  # was mid-flight when the box died
            if status == "INTERRUPTED" or (
                status == "FAILED" and self.args.retry_failed
            ):
                status = "PENDING"
                resets += 1
            self.state["jobs"][jid] = {
                "state": status,
                "kind": j["kind"],
                "lane": j.get("lane"),
                "attempts": old.get("attempts", 0),
                "exit_code": old.get("exit_code"),
                "started_at": old.get("started_at"),
                "ended_at": old.get("ended_at"),
                "duration_s": old.get("duration_s"),
                "note": old.get("note"),
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
        outcome = _run_attempt(camp, job, base_attempts + attempt, t0)
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
    with open(log_path, "a") as log:
        def emit(msg):
            log.write(f"[orchestrator] {msg}\n")
            log.flush()

        # Clone machine-to-machine and verify the pin (SPEC §8.1–8.2).
        if not (repo_dir / ".git").exists():
            job_dir.mkdir(parents=True, exist_ok=True)
            clone_url = job.get("clone_url") or f"https://github.com/{job['repo']}.git"
            emit(f"clone {job['repo']} @ {job['ref']}")
            rc = subprocess.run(
                ["git", "clone", "--quiet", clone_url, str(repo_dir)],
                stdout=log, stderr=subprocess.STDOUT, env=env).returncode
            if rc != 0:
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
    summary = {
        "campaign": camp.campaign,
        "status": camp.state["status"],
        "wall_s_total": round(time.time() - camp.started_at, 1),
        "cumulative_elapsed_s": round(camp.cost_elapsed_s(), 1),
        "price_ceiling_usd": camp.price_ceiling,
        "jobs": {jid: {"state": js["state"],
                       "duration_s": js.get("duration_s"),
                       "failure_class": js.get("failure_class")}
                 for jid, js in camp.state["jobs"].items()},
        "per_kind_job_seconds": waves,
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
    (camp.out / "summary.json").write_text(json.dumps(summary, indent=2))
    lines = []
    for p in sorted(camp.out.rglob("*")):
        if p.is_file() and p.name != "hashes.sha256":
            lines.append(f"{sha256_of(p)}  {p.relative_to(camp.out)}")
    (camp.out / "hashes.sha256").write_text("\n".join(lines) + "\n")
    return summary


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

    campaign = str(manifest["campaign"])
    out_dir = Path(args.out or f"results/{campaign}")
    work_dir = Path(args.work or f"work/{campaign}")
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    # Manifest as run (§10) — byte-identical copy.
    shutil.copy2(args.manifest, out_dir / "manifest.yaml")

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

    jobs = sorted(manifest["jobs"], key=lambda j: (
        0 if j.get("gate") else 1, signal_rank(j)))
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

    if gate_ids:
        run_set([j for j in jobs if j["id"] in gate_ids])
        failed_gates = [jid for jid in gate_ids
                        if camp.state["jobs"][jid]["state"] == "FAILED"]
        if failed_gates:
            camp.aborted = f"abort gate failed: {failed_gates}"
            camp.state["status"] = "ABORTED_GATE"
    if not camp.aborted:
        run_set([j for j in jobs if j["id"] not in gate_ids])

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
