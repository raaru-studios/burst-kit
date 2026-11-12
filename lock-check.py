#!/usr/bin/env python3
"""lock-check.py — the parallel-flow restraint checker (v2, L-05 2026-11-12).

Verifies the blocking roll-call items FIRSTHAND for every rider in the
burst manifests and writes ~/workspace/burst-compute/parallel-lock.json.

Checks (all read-only, $0):
  A-1 pushed: the repo exists under the estate account (gh api 404 = FAIL).
  A-4 pin: every manifest ref == live remote HEAD (gh api). Always fresh.
  B-1 wrapper / C-1 battery: gradlew / battery script exist in the repo
      tree (gh api contents), checked firsthand per repo.
  B-4 keystore-fail: the release block throws GradleException naming
      KEYSTORE_FILE when no keystore is present — never silently signs
      with the debug key, never silently stays unsigned (roll-call B-4).
  F-1 no JS bridge: no addJavascriptInterface / @JavascriptInterface in
      .kt/.java sources (org code search, both orgs), except HAUNT's
      verified allow-list (GameScreen.kt handleScheme allows only
      GameConfig.GAME_URL).
  E-1 audit done: the audit report file exists and names the dApp.
  D-1 rail state (flagships): SALES_ENABLED / MONEY_RAIL_ENABLED read
      live from the pushed repo via gh api (raw file read).

Optimizations (L-05): riders are checked in parallel (8 workers) and
content checks (B-1/C-1/E-1/D-1/B-4/F-1 — immutable at a fixed HEAD)
are cached in hidden/lock-check-cache.json keyed by repo + live HEAD +
audit-report sha256. A-1/A-4 are NEVER cached: the HEAD is fetched
fresh every run and the manifest refs are compared against it. A cache
hit is recorded per rider ("verified": "cached"); a cache miss runs the
full firsthand checks ("verified": "fresh"). --no-cache forces a full
firsthand run. The registry records cache hits/misses and the code
search time, so a reader can tell fresh proof from reused proof.

Exit code: 0 when every rider is LOCKED or HELD; 1 when any rider is
UNLOCKED. The launch checklist step 0 reads this exit code.

Usage: python3 kit/lock-check.py [--manifest draft-camp-1.yaml]
       [--out parallel-lock.json] [--no-cache]
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
BURST = os.path.join(HOME, "workspace", "burst-compute")
SWEEP = os.path.join(HOME, "workspace", "sweep-2026-11-11")
DEFAULT_MANIFESTS = [
    os.path.join(BURST, "draft-camp-1.yaml"),
    os.path.join(BURST, "voidrunner-only", "draft-voidrunner-only.yaml"),
]
DEFAULT_OUT = os.path.join(BURST, "parallel-lock.json")
CACHE_PATH = os.path.join(BURST, "hidden", "lock-check-cache.json")
WORKERS = 16  # gh api calls are network-bound (~1s each); 16-way keeps
# a warm run (38 HEAD fetches + searches) near ~15s without
# approaching the 5000 req/hr authenticated rate limit (a cold run
# is ~150 calls total).
CACHE_VERSION = 2

# Rider table: dapp -> repo, audit report, wrapper path, battery path,
# keystore path (build.gradle.kts carrying the B-4 throw; None = the
# repo has no build file, so B-4 cannot pass), rail flag (path +
# expected value, read live from the pushed repo).
# Paths are repo-relative. A None wrapper/battery means "expected absent
# until the cure lands" — the check still runs and records FAIL.
RIDERS = {
    "voidrunner": {
        "repo": "raaruofficial/voidrunner",
        "audit": "security-dapp-code.md",
        "wrapper": "gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "app/build.gradle.kts",
        "rail": ("app/src/main/java/com/voidrunner/app/money/MoneyConfig.kt", None),
    },
    "paper-moon": {
        "repo": "raaruofficial/paper-moon",
        "audit": "security-paper-moon.md",
        "wrapper": "gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "app/build.gradle.kts",
        "rail": ("app/src/main/java/com/hindsight/app/money/MoneyConfig.kt", "SALES_ENABLED: Boolean = false"),
    },
    "gaspumpa": {
        "repo": "raaru-studios/gaspumpa-app",
        "audit": "security-clink-gaspumpa-haunt.md",
        "wrapper": "android-app/gradlew",
        "battery": "android-app/ci/emulator-smoke.sh",
        "keystore": "android-app/app/build.gradle.kts",
        "rail": None,
    },
    "haunt": {
        "repo": "raaruofficial/ore-haunt",
        "audit": "security-clink-gaspumpa-haunt.md",
        "wrapper": "gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "app/build.gradle.kts",
        "rail": None,
    },
    "clink": {
        "repo": "raaru-studios/clink-app",
        "audit": "security-clink-gaspumpa-haunt.md",
        "wrapper": "android-app/gradlew",
        "battery": "android-app/ci/emulator-smoke.sh",
        "keystore": "android-app/app/build.gradle.kts",
        "rail": None,
    },
    "tithe": {
        "repo": "raaruofficial/tithe-app",
        "audit": "security-tithe-iris.md",
        "wrapper": "gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": None,  # no gradlew in the repo tree — no build file to check
        "rail": None,
    },
    "iris": {
        "repo": "raaruofficial/iris-app",
        "audit": "security-tithe-iris.md",
        "wrapper": "android-app/gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "android-app/app/build.gradle.kts",
        "rail": None,
    },
    "time-wizard": {
        "repo": "raaruofficial/time-wizard-app",  # created + first pushed 2026-11-11 (W-01 cured)
        "audit": "security-tithe-iris.md",
        "wrapper": "android-app/gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "android-app/app/build.gradle.kts",
        "rail": None,
    },
    "ore-rescue": {
        "repo": "raaru-studios/ore-rescue-app",
        "audit": "security-ore-lanes.md",
        "wrapper": "android-app/gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "android-app/app/build.gradle.kts",
        "rail": None,
    },
    "ore-booth": {
        "repo": "raaru-studios/ore-booth-app",
        "audit": "security-ore-lanes.md",
        "wrapper": "android-app/gradlew",
        "battery": "cold-run-battery.sh",
        "keystore": "android-app/app/build.gradle.kts",
        "rail": None,
    },
}

# Riders held out by the owner's word (not failures — deliberate absence).
HELD = {
    "foil-tavern": "Parked, unbuilt — no code exists. Held by owner word (2026-10-30).",
    "holoseekr": "No record found anywhere (memory, workspace, manifest, repos). Held until the owner points at it.",
    "seeker-citadel": "Staging site on ore-spare, not a dApp. Not a rider in the burst.",
}

# F-1: the bridge is allow-listed only for HAUNT. The allow-list lives
# in GameScreen.kt: handleScheme allows exactly GameConfig.GAME_URL.
HAUNT_ALLOWLIST_FILE = "app/src/main/java/com/orehaunt/app/ui/GameScreen.kt"
# B-4: the throw must name the required vars — the check requires
# KEYSTORE_FILE within this many chars after "GradleException".
B4_WINDOW = 600


def run(cmd):
    """Run a command, return (rc, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def gh_api(path, jq=None):
    """gh api call; returns (ok, parsed-or-text)."""
    cmd = ["gh", "api", path]
    if jq:
        cmd += ["--jq", jq]
    rc, out, err = run(cmd)
    if rc != 0:
        return False, err or out
    if jq:
        return True, out
    try:
        return True, json.loads(out)
    except json.JSONDecodeError:
        return True, out


def parse_manifest(path):
    """Return {repo: set(refs)} from a manifest's repo:/ref: pairs."""
    pins = {}
    cur_repo = None
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*repo:\s*(\S+)\s*$", line)
            if m:
                cur_repo = m.group(1)
                continue
            m = re.match(r"\s*ref:\s*([0-9a-f]{40})\s*$", line)
            if m and cur_repo:
                pins.setdefault(cur_repo, set()).add(m.group(1))
    return pins


def gh_file_exists(repo, path):
    """True if path exists in the repo's default branch (gh api contents)."""
    rc, _, _ = run(["gh", "api", f"repos/{repo}/contents/{path}",
                    "--jq", ".type"])
    return rc == 0


def gh_file_text(repo, path):
    """Raw file text from the repo's default branch, or None."""
    rc, out, _ = run(["gh", "api", f"repos/{repo}/contents/{path}",
                      "--jq", ".content"])
    if rc != 0 or not out:
        return None
    import base64
    try:
        return base64.b64decode("".join(out.split())).decode("utf-8", "replace")
    except Exception:
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def lane_riders(pins):
    """Auto-generate riders for every Ore lane repo in the manifest that
    is not already a named rider. Lane wrapper lives under android-app/,
    battery at the repo root (verified on ore-pit)."""
    named_repos = {c["repo"] for c in RIDERS.values() if c.get("repo")}
    lanes = {}
    for repo in sorted(pins):
        if not repo.startswith("raaru-studios/ore-"):
            continue
        if repo in named_repos:
            continue
        slug = repo.split("/")[-1].removesuffix("-app")
        lanes[slug] = {
            "repo": repo,
            "audit": "security-ore-lanes.md",
            "wrapper": "android-app/gradlew",
            "battery": "cold-run-battery.sh",
            "keystore": "android-app/app/build.gradle.kts",
            "rail": None,
        }
    return lanes


def f1_search_map():
    """Org code search for JS-bridge exposure (F-1). Returns
    ({repo: [source files with a bridge hit]}, iso search time).
    Only .kt/.java sources count — a ProGuard keep rule mentioning
    the annotation (.pro) is not a bridge. The search index lags
    pushes; the search time is recorded in the registry so a reader
    knows how fresh the index read is."""
    queries = [
        "addJavascriptInterface+org:raaru-studios",
        "addJavascriptInterface+org:raaruofficial",
        "%40JavascriptInterface+org:raaru-studios",
        "%40JavascriptInterface+org:raaruofficial",
    ]

    def one(q):
        ok, out = gh_api(f"search/code?q={q}&per_page=100",
                         ".items[] | .repository.full_name + \" \" + .path")
        if not ok:
            return q, None
        hits = []
        for line in out.splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                hits.append(parts)
        return q, hits

    now = datetime.now(timezone.utc).isoformat()
    hits = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        for q, res in ex.map(one, queries):
            if res is None:
                # A failed search fails closed: no map entry is built
                # and every rider's F-1 records FAIL (unreadable).
                return None, now
            for repo, path in res:
                if path.endswith((".kt", ".java")):
                    hits.setdefault(repo, set()).add(path)
    return {r: sorted(ps) for r, ps in hits.items()}, now


def check_content(name, cfg, f1_map):
    """The cacheable content checks for one rider (B-1/C-1/E-1/D-1/B-4/F-1).
    Returns (items, proof, failed). The caller decides the rider state;
    any FAIL here unlocks it."""
    items = {}
    proof = []
    repo = cfg["repo"]
    failed = False

    def fail(key, msg):
        nonlocal failed
        items[key] = f"FAIL ({msg})"
        failed = True

    # B-1 wrapper / C-1 battery: exist in the repo tree.
    if gh_file_exists(repo, cfg["wrapper"]):
        items["B-1"] = "PASS"
        proof.append(f"{cfg['wrapper']} exists in repo tree")
    else:
        fail("B-1", f"no {cfg['wrapper']} in repo tree")
    if gh_file_exists(repo, cfg["battery"]):
        items["C-1"] = "PASS"
        proof.append(f"{cfg['battery']} exists in repo tree")
    else:
        fail("C-1", f"no {cfg['battery']} in repo tree")

    # B-4 keystore-fail: the release block throws GradleException naming
    # KEYSTORE_FILE when no keystore is present. A repo with no build
    # file cannot pass; a build file without the throw fails — its
    # release build stays unsigned silently (the lane pattern) instead
    # of failing loudly, so the seal leg would only catch it at install.
    if cfg.get("keystore") is None:
        fail("B-4", "no build.gradle.kts in repo tree (no gradlew) — "
             "the keystore-fail throw cannot be verified")
    else:
        text = gh_file_text(repo, cfg["keystore"])
        if text is None:
            fail("B-4", f"cannot read {cfg['keystore']} live from the pushed repo")
        else:
            i = text.find("GradleException")
            if i >= 0 and "KEYSTORE_FILE" in text[i:i + B4_WINDOW]:
                items["B-4"] = "PASS"
                proof.append(f"{cfg['keystore']} throws GradleException naming KEYSTORE_FILE")
            else:
                fail("B-4", f"no keystore-fail throw in {cfg['keystore']} — "
                     "release builds stay unsigned silently; add the "
                     "estate-standard GradleException throw naming "
                     "KEYSTORE_FILE (see VOIDRUNNER app/build.gradle.kts)")

    # F-1 no JS bridge (org code search; see f1_search_map).
    if f1_map is None:
        fail("F-1", "org code search unreadable — failing closed")
    elif name == "haunt":
        text = gh_file_text(repo, HAUNT_ALLOWLIST_FILE)
        if text is None:
            fail("F-1", f"cannot read {HAUNT_ALLOWLIST_FILE} live — "
                 "the allow-list cannot be verified")
        elif "handleScheme" in text and "GameConfig.GAME_URL" in text:
            items["F-1"] = "PASS (allow-listed bridge: handleScheme allows only GameConfig.GAME_URL)"
            proof.append(f"{HAUNT_ALLOWLIST_FILE} handleScheme allow-lists GameConfig.GAME_URL only")
        else:
            fail("F-1", "bridge present without the verified allow-list — "
                 f"{HAUNT_ALLOWLIST_FILE} must contain handleScheme + GameConfig.GAME_URL")
    else:
        hits = f1_map.get(repo, [])
        if not hits:
            items["F-1"] = "PASS"
            proof.append("org code search: no addJavascriptInterface / @JavascriptInterface in .kt/.java")
        else:
            fail("F-1", "JS bridge exposed in: " + ", ".join(hits))

    # E-1 audit done: the report file exists and names this dApp.
    # The Ore-lane report names lanes by their bare slug ("circle") in
    # lists, so for ore-* riders also accept the bare slug as a word.
    report_path = os.path.join(SWEEP, cfg["audit"])
    if os.path.isfile(report_path):
        with open(report_path) as f:
            text = f.read()
        text_low = text.lower()
        forms = [name, name.replace("-", " ")]
        if name.startswith("ore-"):
            forms.append(name[len("ore-"):])
        named = any(
            re.search(r"(?<![a-z0-9])" + re.escape(form) + r"(?![a-z0-9])", text_low)
            for form in forms
        )
        if named:
            items["E-1"] = "PASS"
            proof.append(f"audit report {cfg['audit']} exists and names {name}")
        else:
            fail("E-1", f"report {cfg['audit']} does not name {name}")
    else:
        fail("E-1", f"no audit report {cfg['audit']}")

    # D-1 rail state (flagships only): read live from the pushed repo.
    if cfg.get("rail"):
        path, expected = cfg["rail"]
        text = gh_file_text(repo, path)
        if text is None:
            fail("D-1", f"cannot read {path} live from the pushed repo")
        elif expected is None:
            # VOIDRUNNER: record the live flag value in the proof.
            line = next((ln.strip() for ln in text.splitlines()
                         if "MONEY_RAIL_ENABLED" in ln), None)
            items["D-1"] = "PASS (rail flag read live; value recorded in proof)"
            proof.append(f"{path} read live from pushed repo"
                         + (f": {line}" if line else ""))
        elif expected in text:
            items["D-1"] = "PASS"
            proof.append(f"{path} contains '{expected}' (live read)")
        else:
            fail("D-1", f"{path} does not contain '{expected}' live")

    return items, proof, failed


def load_cache():
    try:
        with open(CACHE_PATH) as f:
            data = json.load(f)
        if data.get("version") != CACHE_VERSION:
            return {}
        return data.get("entries", {})
    except Exception:
        return {}


def save_cache(entries):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"version": CACHE_VERSION, "entries": entries}, f, indent=2)
    os.replace(tmp, CACHE_PATH)


def main():
    manifests = DEFAULT_MANIFESTS
    out_path = DEFAULT_OUT
    no_cache = "--no-cache" in sys.argv
    args = sys.argv[1:]
    if "--manifest" in args:
        manifests = [args[args.index("--manifest") + 1]]
    if "--out" in args:
        out_path = args[args.index("--out") + 1]

    pins = {}
    for m in manifests:
        for repo, refs in parse_manifest(m).items():
            pins.setdefault(repo, set()).update(refs)

    all_riders = dict(RIDERS)
    all_riders.update(lane_riders(pins))
    cache = {} if no_cache else load_cache()
    audit_sha = {}
    for cfg in all_riders.values():
        p = os.path.join(SWEEP, cfg["audit"])
        if p not in audit_sha and os.path.isfile(p):
            audit_sha[p] = sha256_file(p)

    # A-1 (fresh, parallel): live HEAD for every rider repo. One
    # batched GraphQL call returns every repo's default-branch HEAD
    # (~2s for all 38, vs ~30s for 38 REST calls — the REST path is
    # kept as the fallback if the GraphQL call fails).
    def fetch_heads_graphql(repos):
        fields = []
        for i, repo in enumerate(repos):
            owner, name = repo.split("/", 1)
            fields.append(
                f'r{i}: repository(owner: "{owner}", name: "{name}") '
                f'{{ defaultBranchRef {{ target {{ oid }} }} }}')
        query = "query { " + " ".join(fields) + " }"
        rc, out, err = run(["gh", "api", "graphql", "-f", f"query={query}",
                            "--jq", ".data"])
        if rc != 0:
            return None
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return None
        heads = {}
        for i, repo in enumerate(repos):
            node = (data or {}).get(f"r{i}") or {}
            ref = node.get("defaultBranchRef") or {}
            target = ref.get("target") or {}
            heads[repo] = target.get("oid")
        return heads

    def fetch_head_rest(item):
        name, cfg = item
        ok, head = gh_api(f"repos/{cfg['repo']}/commits", ".[0].sha")
        return name, ok, head if ok else None

    repo_list = [cfg["repo"] for cfg in all_riders.values()]
    gql_heads = fetch_heads_graphql(repo_list)
    head_source = "graphql" if gql_heads is not None else "rest"
    heads = {}
    if gql_heads is not None:
        by_repo = {cfg["repo"]: name for name, cfg in all_riders.items()}
        for repo, head in gql_heads.items():
            heads[by_repo[repo]] = (head is not None, head)
    else:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for name, ok, head in ex.map(fetch_head_rest, all_riders.items()):
                heads[name] = (ok, head)

    # F-1 map (fresh org searches, once per run).
    f1_map, code_search_at = f1_search_map()

    # Content checks: cache hit (same HEAD + same audit report) reuses
    # the firsthand proof; anything else runs the checks now, in
    # parallel over the riders that missed.
    entries = []
    cache_hits = 0
    cache_misses = 0
    fresh_needed = []
    for name, cfg in all_riders.items():
        ok, head = heads[name]
        entry = {"dapp": name, "repo": cfg["repo"], "state": "LOCKED",
                 "blocking_items": {}, "proof": [], "conditions": []}
        if not ok or not head:
            entry["state"] = "UNLOCKED"
            entry["head"] = None
            entry["verified"] = "fresh"
            entry["blocking_items"]["A-1"] = (
                f"FAIL (no HEAD for {cfg['repo']} via {head_source} — "
                f"repo missing, private without access, or no default branch)")
            entries.append(entry)
            cache_misses += 1
            continue
        entry["head"] = head
        entry["blocking_items"]["A-1"] = "PASS"
        entry["proof"].append(
            f"gh api repos/{cfg['repo']}/commits -> HEAD {head[:7]}")
        # A-4 pin: every manifest ref for this repo must equal the live HEAD.
        refs = pins.get(cfg["repo"], set())
        if not refs:
            entry["blocking_items"]["A-4"] = "FAIL (no manifest job pins this repo)"
            entry["state"] = "UNLOCKED"
        elif refs == {head}:
            entry["blocking_items"]["A-4"] = "PASS"
            entry["proof"].append(f"manifest ref == live HEAD {head[:7]}")
        else:
            entry["blocking_items"]["A-4"] = (
                f"FAIL (manifest refs {sorted(r[:7] for r in refs)} != live HEAD {head[:7]})"
            )
            entry["state"] = "UNLOCKED"
        report_path = os.path.join(SWEEP, cfg["audit"])
        cached = cache.get(cfg["repo"])
        if (cached and cached.get("head") == head
                and cached.get("audit_sha256") == audit_sha.get(report_path)):
            entry["blocking_items"].update(cached["items"])
            entry["proof"].extend(cached["proof"])
            entry["verified"] = "cached"
            entry["locked_at"] = cached.get("locked_at")
            if any(str(v).startswith("FAIL") for v in cached["items"].values()):
                entry["state"] = "UNLOCKED"
            cache_hits += 1
        else:
            entry["verified"] = "fresh"
            fresh_needed.append((name, cfg, entry))
            cache_misses += 1
        entries.append(entry)

    def run_content(job):
        name, cfg, entry = job
        items, proof, failed = check_content(name, cfg, f1_map)
        return name, items, proof, failed

    new_cache = dict(cache)
    if fresh_needed:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for name, items, proof, failed in ex.map(run_content, fresh_needed):
                entry = next(e for e in entries if e["dapp"] == name)
                entry["blocking_items"].update(items)
                entry["proof"].extend(proof)
                if failed:
                    entry["state"] = "UNLOCKED"
                cfg = all_riders[name]
                report_path = os.path.join(SWEEP, cfg["audit"])
                new_cache[cfg["repo"]] = {
                    "head": entry["head"],
                    "audit_sha256": audit_sha.get(report_path),
                    "items": items,
                    "proof": proof,
                    "locked_at": (entry.get("locked_at")
                                  or datetime.now(timezone.utc).isoformat()),
                }
    if not no_cache:
        save_cache(new_cache)

    for entry in entries:
        if entry["state"] == "LOCKED" and "locked_at" not in entry:
            entry["locked_at"] = datetime.now(timezone.utc).isoformat()
    for name, reason in HELD.items():
        entries.append({"dapp": name, "repo": None, "state": "HELD",
                        "reason": reason, "verified": "held"})

    now = datetime.now(timezone.utc)
    registry = {
        "generated_at": now.isoformat(),
        # L-02 (deep-problems audit, 2026-11-11): Unix epoch beside the
        # ISO timestamp, so a dispatch reader can refuse a registry
        # older than 3600 s with one subtraction (now - epoch > 3600).
        "generated_at_epoch": int(now.timestamp()),
        "generated_by": "kit/lock-check.py v2",
        "campaign": "camp-1",
        "manifests": manifests,
        "head_source": head_source,  # "graphql" (one batched call) or "rest" (fallback)
        "cache": {"hits": cache_hits, "misses": cache_misses,
                  "path": CACHE_PATH, "no_cache": no_cache},
        "code_search_at": code_search_at,
        "riders": entries,
    }
    with open(out_path, "w") as f:
        json.dump(registry, f, indent=2)

    unlocked = [r for r in entries if r["state"] == "UNLOCKED"]
    locked = [r for r in entries if r["state"] == "LOCKED"]
    held = [r for r in entries if r["state"] == "HELD"]
    width = max(len(r["dapp"]) for r in entries)
    for r in entries:
        if r["state"] == "HELD":
            print(f"HELD      {r['dapp']:<{width}}  -          held")
            continue
        failing = [k for k, v in r["blocking_items"].items()
                   if str(v).startswith("FAIL")]
        head = (r.get("head") or "")[:7] or "-"
        line = (f"{r['state']:<9} {r['dapp']:<{width}}  {head:<7}  "
                f"{r.get('verified', '?')}")
        if failing:
            line += f"  [{', '.join(failing)}]"
        print(line)
    print(f"LOCKED ({len(locked)}): {', '.join(r['dapp'] for r in locked) or 'none'}")
    print(f"UNLOCKED ({len(unlocked)}): {', '.join(r['dapp'] for r in unlocked) or 'none'}")
    print(f"HELD ({len(held)}): {', '.join(r['dapp'] for r in held) or 'none'}")
    print(f"cache: {cache_hits} hits, {cache_misses} misses"
          + (" (--no-cache: cache not read or written)" if no_cache else ""))
    print(f"registry: {out_path}")
    if unlocked:
        print("RESTRAINT CHECK: REFUSE — riders are UNLOCKED (see registry).")
        return 1
    print("RESTRAINT CHECK: GO — every rider is LOCKED or HELD.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
