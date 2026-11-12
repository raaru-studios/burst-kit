# burst-kit — read-only kit source for the burst box

Public, read-only fetch source named as `KIT_SOURCE` for the burst-compute
launch (`kit/user-data.sh`, IGNITION N-3 — designated 2026-11-11).

The box fetches exactly these files from this location, machine-to-machine,
and verifies each sha256 against the hashes recorded at launch-checklist
step 0 before running anything (SPEC §8.2):

- `bootstrap.sh` — toolchain bootstrap (KVM gate first, fail-closed)
- `orchestrator.py` — campaign runner (lint, cost trip, abort gate)
- `cold-run-battery.sh` — estate cold-run battery
- `manifest.yaml` — the campaign manifest for the launch

Also in this repo (not fetched by user-data.sh): `user-data.sh` itself
(the cloud-init script, passed at launch) and `voidrunner-only.yaml`
(the VOIDRUNNER-only campaign manifest; place as `manifest.yaml` or
set `MANIFEST_FILE` when that campaign fires).

## What this repo is not

- No secrets, no key material, no credentials of any kind. The
  orchestrator's custody lint refuses secret-shaped content, and
  nothing here names a key, token, or password. Repos are cloned on
  the box with a separate per-campaign read-only GitHub credential
  (SPEC §8.1), never from this repo.
- `manifest.yaml` is the **current draft** of the suite manifest
  (camp-1). It is re-placed at launch time once pinned: the operator
  copies the linted manifest in as `manifest.yaml` and records its
  sha256 at checklist step 0. Do not treat the file here as
  launch-ready unless the lint passes.

## Fetch model

`KIT_SOURCE=https://raw.githubusercontent.com/raaru-studios/burst-kit/main`
— the box runs `curl -fsSL "$KIT_SOURCE/<file>"` for each of the four
files above. Any other transport must be designated by the operator
before launch; user-data.sh refuses an undesignated or unsupported
scheme loudly.
