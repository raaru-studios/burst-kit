#!/usr/bin/env python3
"""render-user-data.py — build the burst launch payload (SPEC §8.1/§9).

Reads kit/user-data.sh, fills in the four REQUIRED launch variables,
and (for a campaign launch) injects the 35 per-repo read-only SSH
deploy keys from the estate keys dir into DEPLOY_KEYS_BUNDLE — the
hook in user-data.sh decodes the bundle on the box into
$BURST_HOME/deploy-keys/ (0700, each key 0600) and the orchestrator
is started with --keys-dir pointing at it.

This script is the ONLY way a campaign payload is produced. A
hand-edited user-data.sh has no keys and the §0c hook refuses it
(unless SMOKE=1). The rendered payload CONTAINS PRIVATE KEY BYTES:
it is written mode 0600 to a path OUTSIDE the kit repo, it is never
committed, never pasted, and never put in the launch record — only
its sha256 and the key NAMES go in the record.

Usage (campaign):
    python3 kit/render-user-data.py \\
        --keys-dir ~/workspace/estate-keys/burst-deploy-keys \\
        --kit-source https://raw.githubusercontent.com/raaru-studios/burst-kit/main \\
        --hourly-price 0.8033 --max-hours 6 \\
        --kit-sha256s /path/to/kit.sha256 \\
        --manifest draft-camp-1.yaml \\
        --out ~/workspace/burst-compute/hidden/launch-user-data.sh
    # then: aws ec2 run-instances ... --user-data file://<the --out file>

Usage (smoke — no keys, no manifest, orchestrator not started):
    python3 kit/render-user-data.py --smoke \\
        --kit-source ... --hourly-price ... --max-hours 2 \\
        --kit-sha256s /path/to/kit.sha256 \\
        --out ~/workspace/burst-compute/hidden/smoke-user-data.sh

Coverage check only (no payload written; exit 1 if any manifest repo
lacks a key):
    python3 kit/render-user-data.py --check-only \\
        --keys-dir ... --manifest draft-camp-1.yaml

--check-only REQUIRES --manifest: a bare --check-only (no manifest)
is a VACUOUS pass — 0 repos covered, exit 0 — and must never be read
as a coverage proof (L-05, 2026-11-12). The real gate always passes
--manifest explicitly.

Manifest coverage is a WARNING at render time, not a refusal: a
manifest could list a repo with no key, and refusing the render
would make the mechanism unusable while that gap is decided. (The
2026-11-11 gap — clink-app, iris-app, time-wizard-app, private with
no deploy key issued — was CURED 2026-11-12: 35 keys, all 33 camp-1
repos + the voidrunner-only repo covered; --check-only passes on
both manifests.) The gap is a launch blocker of its own (the
orchestrator refuses a job whose key is missing) and is reported,
not hidden. --check-only is the hard gate for the launch checklist.
"""

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

# The estate keys dir (documented custody location, GITHUB_CREDENTIAL.md).
DEFAULT_KEYS_DIR = Path.home() / "workspace" / "estate-keys" / "burst-deploy-keys"

REPO_LINE = re.compile(r"^\s*repo:\s*(\S+)\s*$", re.MULTILINE)
SHA256_LINE = re.compile(r"^[0-9a-f]{64}  \S+$")


def fail(msg):
    print(f"render-user-data: FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print(f"render-user-data: WARNING: {msg}", file=sys.stderr)


def shquote(value):
    """Single-quote a value for bash; the only escape needed is ' itself."""
    return "'" + value.replace("'", "'\\''") + "'"


def ansi_c_quote(value):
    """$'...' quoting for a multi-line value (KIT_SHA256S lines)."""
    esc = value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return "$'" + esc + "'"


def read_keys(keys_dir):
    """Return {name: base64} for every private key file in keys_dir.

    Public keys (*.pub) are skipped. Names are the filenames, which
    the orchestrator matches as <owner>-<repo>. Only key NAMES are
    ever printed; key bytes are never logged.
    """
    if not keys_dir.is_dir():
        fail(f"--keys-dir {keys_dir} is not a directory")
    keys = {}
    for path in sorted(keys_dir.iterdir()):
        if not path.is_file() or path.name.endswith(".pub"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_-]+", path.name):
            fail(f"unexpected key filename {path.name!r} in {keys_dir}")
        keys[path.name] = base64.b64encode(path.read_bytes()).decode("ascii")
    return keys


def manifest_repos(manifest_paths):
    repos = set()
    for manifest in manifest_paths:
        text = Path(manifest).read_text()
        repos.update(REPO_LINE.findall(text))
    return sorted(repos)


def replace_once(text, pattern, replacement, label):
    """Replace exactly one occurrence; fail loudly on zero or many."""
    count = text.count(pattern)
    if count != 1:
        fail(f"template drift: expected exactly 1 occurrence of {label}, "
             f"found {count} — refusing to render (template changed?)")
    return text.replace(pattern, replacement, 1)


def main():
    ap = argparse.ArgumentParser(
        description="Render the burst launch user-data payload "
                    "(fill-ins + deploy-keys bundle).")
    ap.add_argument("--template", default=None,
                    help="user-data.sh template (default: user-data.sh "
                         "next to this script)")
    ap.add_argument("--keys-dir", default=None,
                    help="dir of per-repo read-only SSH deploy keys "
                         "(default: $BURST_DEPLOY_KEYS_DIR or the estate "
                         "keys dir)")
    ap.add_argument("--kit-source", default=None,
                    help="KIT_SOURCE (the read-only kit location)")
    ap.add_argument("--hourly-price", default=None,
                    help="HOURLY_PRICE_USD (live $/hr from pre-flight)")
    ap.add_argument("--max-hours", default=None,
                    help="MAX_HOURS (derived, > 0.25 and <= 6)")
    ap.add_argument("--kit-sha256s", default=None,
                    help="file holding the KIT_SHA256S lines "
                         "(checklist step 0)")
    ap.add_argument("--kit-sha256s-string", default=None,
                    help="KIT_SHA256S lines as a literal string "
                         "(alternative to --kit-sha256s)")
    ap.add_argument("--campaign", default=None,
                    help="CAMPAIGN name (default: the template's camp-1)")
    ap.add_argument("--smoke", action="store_true",
                    help="SMOKE=1 payload: no keys injected, no manifest "
                         "fetch, orchestrator not started")
    ap.add_argument("--manifest", action="append", default=[],
                    help="manifest to check key coverage against "
                         "(repeatable; coverage is a warning at render)")
    ap.add_argument("--out", default=None,
                    help="output payload path (REQUIRED unless "
                         "--check-only). Must be OUTSIDE the kit dir.")
    ap.add_argument("--check-only", action="store_true",
                    help="verify manifest key coverage only; write no "
                         "payload; exit 1 if any manifest repo lacks a key. "
                         "--manifest is REQUIRED: a bare --check-only is a "
                         "vacuous pass (0 repos, exit 0).")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    template = Path(args.template) if args.template else script_dir / "user-data.sh"
    if not template.is_file():
        fail(f"template not found: {template}")

    keys_dir = None
    if args.keys_dir:
        keys_dir = Path(args.keys_dir)
    elif os.environ.get("BURST_DEPLOY_KEYS_DIR"):
        keys_dir = Path(os.environ["BURST_DEPLOY_KEYS_DIR"])
    elif DEFAULT_KEYS_DIR.is_dir():
        keys_dir = DEFAULT_KEYS_DIR

    keys = {}
    if not args.smoke:
        if keys_dir is None:
            fail("--keys-dir is required for a campaign render "
                 "(or set BURST_DEPLOY_KEYS_DIR)")
        keys = read_keys(keys_dir)
        if not keys:
            fail(f"no private key files in {keys_dir}")

    # ---- manifest coverage (warning at render, hard gate at check-only)
    unkeyed = []
    if args.manifest:
        repos = manifest_repos(args.manifest)
        unkeyed = [r for r in repos if r.replace("/", "-") not in keys]
        if unkeyed:
            warn("manifest repos with NO deploy key "
                 f"({len(unkeyed)}): {', '.join(unkeyed)} — the "
                 "orchestrator refuses those jobs (DEPLOY KEY MISSING) "
                 "when --keys-dir is set; this is a launch blocker, "
                 "not a render failure")
        else:
            print(f"coverage: all {len(repos)} manifest repos have a key")
    if args.check_only:
        if not args.manifest:
            fail("--check-only requires --manifest: a bare --check-only "
                 "is a VACUOUS pass (0 manifest repos covered, exit 0) "
                 "and must never be read as a coverage proof — pass "
                 "--manifest explicitly (L-05)")
        if unkeyed:
            fail(f"coverage gate: {len(unkeyed)} manifest repo(s) lack a "
                 "deploy key")
        print(f"coverage OK: {len(keys)} keys, "
              f"{len(manifest_repos(args.manifest)) if args.manifest else 0} "
              "manifest repos covered")
        return 0

    if not args.out:
        fail("--out is required (the rendered payload path)")

    out = Path(args.out)
    if out.resolve() == template.resolve():
        fail("--out must not be the template itself")
    if script_dir.resolve() in out.resolve().parents:
        fail(f"--out {out} is inside the kit dir {script_dir} — the "
             "rendered payload contains private key bytes and must "
             "never live in (or be committed from) the kit repo")

    # ---- fill-ins (all four REQUIRED for a launch payload)
    for flag, value in (("--kit-source", args.kit_source),
                        ("--hourly-price", args.hourly_price),
                        ("--max-hours", args.max_hours)):
        if not value:
            fail(f"{flag} is required for a launch payload "
                 "(the box fails loudly on an unset variable; fail here "
                 "instead, before any money is spent)")
    try:
        price = float(args.hourly_price)
        if price <= 0:
            raise ValueError
    except ValueError:
        fail(f"--hourly-price {args.hourly_price!r} is not a positive number")
    try:
        hours = float(args.max_hours)
    except ValueError:
        fail(f"--max-hours {args.max_hours!r} is not a number")
    if not (0.25 < hours <= 6):
        fail(f"--max-hours {hours} out of range — must be > 0.25 and <= 6 "
             "(same range user-data.sh enforces)")

    if args.kit_sha256s and args.kit_sha256s_string:
        fail("pass only one of --kit-sha256s and --kit-sha256s-string")
    if args.kit_sha256s:
        sha_lines = Path(args.kit_sha256s).read_text().strip("\n")
    elif args.kit_sha256s_string:
        sha_lines = args.kit_sha256s_string.strip("\n")
    else:
        fail("--kit-sha256s (or --kit-sha256s-string) is required "
             "(checklist step 0: the sha256sum-format lines)")
    for line in sha_lines.split("\n"):
        if not SHA256_LINE.match(line):
            fail(f"malformed KIT_SHA256S line: {line!r} "
                 "(expected '<sha256>  <filename>')")

    text = template.read_text()
    text = replace_once(text, 'KIT_SOURCE="${KIT_SOURCE:-}"',
                        f"KIT_SOURCE={shquote(args.kit_source)}", "KIT_SOURCE")
    text = replace_once(text, 'HOURLY_PRICE_USD="${HOURLY_PRICE_USD:-}"',
                        f"HOURLY_PRICE_USD={shquote(args.hourly_price)}",
                        "HOURLY_PRICE_USD")
    text = replace_once(text, 'MAX_HOURS="${MAX_HOURS:-}"',
                        f"MAX_HOURS={shquote(args.max_hours)}", "MAX_HOURS")
    text = replace_once(text, 'KIT_SHA256S="${KIT_SHA256S:-}"',
                        f"KIT_SHA256S={ansi_c_quote(sha_lines)}", "KIT_SHA256S")
    if args.campaign:
        text = replace_once(text, 'CAMPAIGN="${CAMPAIGN:-camp-1}"',
                            f"CAMPAIGN={shquote(args.campaign)}", "CAMPAIGN")
    if args.smoke:
        text = replace_once(text, 'SMOKE="${SMOKE:-0}"', 'SMOKE="1"', "SMOKE")
        if 'DEPLOY_KEYS_BUNDLE=""' not in text:
            fail("template drift: DEPLOY_KEYS_BUNDLE placeholder missing")
    else:
        # No trailing newline: the hook feeds the bundle with
        # `printf '%s'`, and a trailing newline would be harmless
        # either way — the join is the canonical form.
        bundle = "\n".join(f"{name}:{b64}" for name, b64 in keys.items())
        text = replace_once(text, 'DEPLOY_KEYS_BUNDLE=""',
                            f"DEPLOY_KEYS_BUNDLE='{bundle}'",
                            "DEPLOY_KEYS_BUNDLE placeholder")

    # ---- write (0600, never inside the kit repo) and syntax-check
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.chmod(out, 0o600)
    rc = subprocess.run(["bash", "-n", str(out)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        out.unlink(missing_ok=True)
        fail(f"rendered payload failed bash -n (deleted {out}): "
             f"{rc.stderr.strip()}")

    digest = hashlib.sha256(text.encode()).hexdigest()
    print(f"rendered: {out}")
    print(f"  sha256: {digest}")
    print(f"  template: {template}")
    print(f"  campaign: {args.campaign or 'camp-1'}"
          f"{'  SMOKE=1' if args.smoke else ''}")
    if args.smoke:
        print("  deploy keys: none (SMOKE=1 — orchestrator not started)")
    else:
        print(f"  deploy keys: {len(keys)} injected "
              f"({', '.join(keys)})")
        print(f"  keys dir: {keys_dir}")
    print("  WARNING: this file contains private key bytes — mode 0600, "
          "never commit it, never paste it, never put it in the launch "
          "record. Only its sha256 and the key names above go on record.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
