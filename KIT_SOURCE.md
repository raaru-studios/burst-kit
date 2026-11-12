# KIT_SOURCE — designated 2026-11-11

Closes IGNITION N-3 (user-data.sh failed loudly on an unset KIT_SOURCE).
The burst box fetches the kit machine-to-machine from this read-only
public location and verifies each file's sha256 against the hashes
recorded at launch-checklist step 0 before running anything (SPEC §8.2).

## Designated value

```
KIT_SOURCE=https://raw.githubusercontent.com/raaru-studios/burst-kit/main
```

Repo: https://github.com/raaru-studios/burst-kit (public, raaru-studios org).
No secrets, no key material, no credentials of any kind in the repo —
the orchestrator's custody lint refuses secret-shaped content, and
repos are cloned on the box with a separate per-campaign read-only
GitHub credential (SPEC §8.1), never from this repo.

## What the box fetches from it

`user-data.sh` runs `curl -fsSL "$KIT_SOURCE/<file>"` for exactly:

- `bootstrap.sh`
- `orchestrator.py`
- `cold-run-battery.sh`
- `manifest.yaml` (the campaign manifest; `MANIFEST_FILE` overrides)
- `parallel-lock.json` (the lock registry, L-05 2026-11-12 — fresh
  <1h at dispatch, published to this repo at launch-checklist step 0)

Verified 2026-11-11 from this VM: all four return HTTP 200, and the
served `orchestrator.py` is byte-identical to the local kit copy
(sha256 `6c500cf5c74b6dbbd244327efaa68cd4bc35ea4aafd4541c648519c877b228d1`,
carrying the disk guard AND the `--keys-dir` deploy-key wiring;
previous hash `6e05ed8a…73f4f` was the disk-guard-only version — the
record was updated when the wiring landed 2026-11-11, and the repo
copy was re-synced the same day). The repo also holds `user-data.sh`
itself (passed at launch, not fetched), `voidrunner-only.yaml`,
`parallel-lock.json` (the lock registry, L-05), `lock-check.py`,
`render-user-data.py`, `LAUNCH_CHECKLIST.md`, `GITHUB_CREDENTIAL.md`,
and this file. The served hashes change whenever the kit changes —
re-verify the served copies are byte-identical to the local kit
before launch (L-05 publish 2026-11-12: orchestrator.py, user-data.sh,
render-user-data.py, lock-check.py, LAUNCH_CHECKLIST.md,
GITHUB_CREDENTIAL.md, KIT_SOURCE.md, parallel-lock.json — re-verify
each served sha256 at the next launch-checklist step 0).

Note: the authoritative hashes are the ones the operator records at
launch-checklist step 0 from the LOCAL kit files (`KIT_SHA256S`) —
this note is a cross-check, not the launch record. If the local kit
changes again, re-verify the served copy is byte-identical before
launch.

## Fetch command (what the box runs)

```bash
KIT_SOURCE=https://raw.githubusercontent.com/raaru-studios/burst-kit/main
curl -fsSL "$KIT_SOURCE/bootstrap.sh" -o "$KIT_DIR/bootstrap.sh"
curl -fsSL "$KIT_SOURCE/orchestrator.py" -o "$KIT_DIR/orchestrator.py"
curl -fsSL "$KIT_SOURCE/cold-run-battery.sh" -o "$KIT_DIR/cold-run-battery.sh"
curl -fsSL "$KIT_SOURCE/manifest.yaml" -o "$KIT_DIR/manifest.yaml"
curl -fsSL "$KIT_SOURCE/parallel-lock.json" -o "$KIT_DIR/parallel-lock.json"
```

## Manifest freshness note

`manifest.yaml` in the repo is the current draft of the suite manifest
(camp-1). It is re-placed at launch time once pinned: the operator
copies the linted manifest in as `manifest.yaml` and records its sha256
at checklist step 0. Do not treat the file in the repo as launch-ready
unless the lint passes.
