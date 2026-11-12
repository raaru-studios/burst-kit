# Burst per-campaign GitHub credential

Created 2026-11-11 (UTC 2026-11-12 ~01:15). Per SPEC §8.1: read-only,
per-campaign, revoked at teardown.

## Credential type

**Per-repo read-only SSH deploy keys (ed25519), one keypair per repo.**
35 keypairs total — one for each repo the burst clones (32 issued
2026-11-11; 3 more issued 2026-11-12 for the private repos that had
none: `raaru-studios/clink-app`, `raaruofficial/iris-app`,
`raaruofficial/time-wizard-app`).

Why deploy keys and not a fine-grained PAT:
- The GitHub REST API cannot create fine-grained PATs (`POST
  user/personal-access-tokens` returns 404 Not Found; PATs require the
  interactive web UI). A PAT remains the cleaner single-token alternative
  if the owner creates one in the UI (Settings > Developer settings >
  Personal access tokens > Fine-grained tokens, read-only Contents,
  7-day expiry, scoped to the repos below).
- A single deploy key cannot be reused across repos (GitHub returns 422
  "key is already in use"). Hence one keypair per repo.
- Deploy keys were DISABLED at the raaru-studios org level
  (`deploy_keys_enabled_for_repositories: false`). Enabled via API
  (`PATCH orgs/raaru-studios`, verified read-back `true`) so the org
  keys could be added (28 then; 29 with clink-app, added 2026-11-12).
  This is an org security setting change — it only permits deploy keys
  to be added; it grants no access by itself.

## Custody

Private keys: `~/workspace/estate-keys/burst-deploy-keys/<owner>-<repo>`
(0600, directory 0700). Public keys alongside (`.pub`).
The original voidrunner keypair also lives at
`~/workspace/estate-keys/burst-github-deploy-key` (0600); the per-repo
copy is `burst-deploy-keys/raaruofficial-voidrunner`.
NEVER print a private key. NEVER commit a private key to any repo.

Key IDs (GitHub deploy-key IDs, for revocation):
- raaruofficial/voidrunner: 169586629
- raaruofficial/paper-moon: 169586766
- raaruofficial/ore-haunt: 169586769
- raaruofficial/ore-kingdom: 169586771
- raaruofficial/iris-app: 169674606
- raaruofficial/time-wizard-app: 169674622
- raaru-studios/clink-app: 169674582
- raaru-studios/gaspumpa-app: 169586932
- raaru-studios/ore-almanac-app: 169586935
- raaru-studios/ore-anomaly-app: 169586938
- raaru-studios/ore-booth-app: 169586940
- raaru-studios/ore-bounty-app: 169586943
- raaru-studios/ore-circle-app: 169586947
- raaru-studios/ore-data-app: 169586951
- raaru-studios/ore-edge-app: 169586957
- raaru-studios/ore-escrow-app: 169586959
- raaru-studios/ore-fleet-app: 169586962
- raaru-studios/ore-guild-app: 169586968
- raaru-studios/ore-harvest-app: 169586972
- raaru-studios/ore-ledger-app: 169586973
- raaru-studios/ore-legacy-app: 169586978
- raaru-studios/ore-machine-app: 169586980
- raaru-studios/ore-pay-app: 169586983
- raaru-studios/ore-pin-app: 169586986
- raaru-studios/ore-pit-app: 169586991
- raaru-studios/ore-pocket-app: 169586996
- raaru-studios/ore-print-app: 169586998
- raaru-studios/ore-radio-app: 169587001
- raaru-studios/ore-reclaim-app: 169587003
- raaru-studios/ore-rescue-app: 169587006
- raaru-studios/ore-scout-app: 169587013
- raaru-studios/ore-season-app: 169587018
- raaru-studios/ore-seat-app: 169587022
- raaru-studios/ore-vault-app: 169587028
- raaru-studios/ore-watch-app: 169587032

Verified 2026-11-11: SSH clone of raaruofficial/voidrunner and
raaru-studios/ore-pit-app both succeeded with their deploy keys
(`GIT_SSH_COMMAND="ssh -i <key> -o IdentitiesOnly=yes"`). Test clones
removed after verification.

## How the orchestrator injects it — WIRED 2026-11-11

The orchestrator (`kit/orchestrator.py`, `--keys-dir`, also honored
via env `BURST_DEPLOY_KEYS_DIR`) selects the key per repo and clones
via SSH. Verified firsthand on this VM: SSH clone of
`raaruofficial/voidrunner` at the pinned ref with
`--keys-dir ~/workspace/estate-keys/burst-deploy-keys` succeeds and
the pin verifies; a keys dir missing the repo's key refuses the job
loudly as `DEPLOY KEY MISSING` (INFRA, non-retryable, exit 3) with no
https fallback and no repo dir created; a nonexistent keys dir refuses
the run at startup (exit 2). Without `--keys-dir` the orchestrator
clones plain https as before (backward compatible — and 401s on every
private repo from a box with no GitHub auth). A test manifest proving
all of this lives at
`~/workspace/burst-compute/hidden/test-keys-manifest.yaml`.

Mechanics, for the record:
- Clone URL: derived as `git@github.com:{owner}/{repo}.git` unless
  the job sets an explicit `clone_url`, which is honored as-is.
- Key selection: `GIT_SSH_COMMAND="ssh -i <keys-dir>/<owner>-<repo>
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"` per
  clone invocation, with the key path shell-quoted. The key is never
  written into the manifest or the job log beyond its path.
- The `~/.ssh/config` Host-stanza approach described in the earlier
  draft of this note is NOT needed — the per-clone `GIT_SSH_COMMAND`
  supersedes it.

What remains is delivery: the keys must be present on the box at
launch (see "Key delivery to the box" below). Until a delivery
mechanism is chosen, the burst cannot use this credential.

## Key delivery to the box — DECIDED: option (a) embed, IMPLEMENTED 2026-11-12

The 35 private keys live only in estate custody on this VM
(`~/workspace/estate-keys/burst-deploy-keys/`, 0600). They must reach
the box before the orchestrator starts, at the path passed as
`--keys-dir`. How they get there was a security decision for the
owner — the three options, with tradeoffs, plainly:

**(a) Embed in user-data at launch.** The launch operator pastes the
keys into the EC2 user-data script, which writes them to (e.g.)
`/opt/burst/deploy-keys` at boot.
- Pros: simplest; no new infrastructure; works with the existing
  launch flow.
- Cons: user-data is visible in the EC2 console to anyone with
  console access and persists on the instance for its lifetime; the
  keys sit in the launch record; a leaked launch record leaks all 35
  keys. Mitigation: the keys are read-only deploy keys, revoked at
  teardown — a leak's blast radius is read-only repo access until
  revocation, not write or billing.

**(b) Fetch from S3 at boot via an instance-profile role.** The keys
are uploaded to a private S3 bucket; the box's instance profile
grants `GetObject` on that prefix only, and bootstrap fetches them
before starting the orchestrator.
- Pros: keys never transit the launch record or the console; access
  is scoped by IAM and auditable via CloudTrail; revocation is
  deleting the objects / the role.
- Cons: needs the S3 bucket `raaru-burst-cache-079214218218` and the
  instance-profile role, which do not exist yet (see
  `kit/s3-cache-setup.sh` — prepared, not executed); needs the
  `iam:PassRole` addition to the burst-agent policy (see
  `kit/iam-policy-patch.json` — prepared, not applied); more moving
  parts on the boot path, each of which can fail the launch.

**(c) A single fine-grained PAT created by the owner in the GitHub
UI, injected via https.** The owner creates one fine-grained token
(Settings > Developer settings > Personal access tokens >
Fine-grained tokens; read-only Contents; 7-day expiry; scoped to
the 34 repos) and the orchestrator clones via
`https://<token>@github.com/<repo>.git` (per-job `clone_url`
override, or an `Authorization` header via `git -c
http.extraHeader`).
- Pros: one token instead of 35 keys; no SSH key management on the
  box; revocation is one click in the GitHub UI.
- Cons: the GitHub API cannot create fine-grained PATs, so this needs
  the owner's tap in the web UI (it cannot be scripted); the PAT
  itself still needs a delivery mechanism to reach the box — options
  (a) and (b) above apply to the token exactly as they do to the
  keys, so this option does not remove the delivery question, it
  only changes what is delivered; a leaked PAT is also read-only
  until revoked, same blast radius as (a). (Token scope would be the
  34 repos.)

No option is chosen here. The choice is the owner's; whichever is
picked, the launch record must record it, and teardown must revoke
whatever was issued (deploy keys by ID below, or the PAT in the
GitHub UI).

**DECIDED + IMPLEMENTED 2026-11-12 (~01:30 PST) — option (a) embed,
under the owner's 00:17 no-cost programme authorization** ("take care
of all the things you have immediate access to... do not let me
down"). The 2026-11-11 note in this file said "do not choose for
him"; the programme word overrode it for the embed recommendation —
keys injected at launch time only, never in the public kit repo.
Mechanism (DRY-verified, $0, no launch):
- `kit/render-user-data.py` (launch side, this VM): fills in the
  four REQUIRED launch variables AND injects the keys into
  `DEPLOY_KEYS_BUNDLE` (`<name>:<base64>` per key). Writes the
  payload mode 0600 OUTSIDE the kit repo; refuses to write into the
  kit dir. `--check-only` verifies manifest coverage (exit 1 on a
  missing key). `--smoke` renders a keyless payload (SMOKE=1).
- `kit/user-data.sh` §0c `install_deploy_keys()`: decodes the bundle
  into `$BURST_HOME/deploy-keys/` (0700, each key 0600), verifies
  each decodes to an OpenSSH private key, fails loudly on an empty
  bundle (unless SMOKE=1) or a corrupted key. §4 passes
  `--keys-dir "$BURST_HOME/deploy-keys"` to the orchestrator.
- Committed files carry NO key material (`DEPLOY_KEYS_BUNDLE=""` in
  the repo; verified: repo diff contained zero key bytes — no dummy
  material, no base64 key lines). Pushed to `raaru-studios/burst-kit`
  `334f70e` (21a13c0→334f70e, `[skip ci]`); served copies verified
  byte-identical to local. New `user-data.sh` sha256
  `5ba36809a5a0bbf68b43699388693e6fc648d58fe7dfe32de4110799891a8a51`
  (handed to DRAGONITE for L-05's KIT_SHA256S change — NOT changed
  here). `render-user-data.py` sha256
  `4606d720e107c88764ba4306cfff0637911e7c233ffb6093b09901036422a883`.
- DRY proof (dummy keys, harness ran the SHIPPED hook function):
  2 dummy keys installed byte-identical (0700/0600); SMOKE=1 skips
  (exit 0); empty bundle dies loudly (exit 1); corrupted key dies
  (exit 1). One real hook bug caught by the dry run and fixed
  (heredoc appended a phantom empty line — now process substitution).
- **BLOCKER (2026-11-11, now CURED — this paragraph is the pre-cure
  record; the operative state is the CURED note below):** the manifests
  listed 34 distinct repos but only 32 keys existed. Three PRIVATE repos
  had NO deploy key — `raaru-studios/clink-app`,
  `raaruofficial/iris-app`, `raaruofficial/time-wizard-app`
  (verified private: unauthenticated GitHub API returns 404; the
  earlier "public" read was the `gh` credential helper silently
  authenticating). With `--keys-dir` set, the orchestrator REFUSED
  those jobs (DEPLOY KEY MISSING) — so camp-1 could not run as
  manifested until 3 more keys were issued OR the orchestrator learned
  a public/https fallback (a fail-closed design change). The render
  script WARNS on unkeyed repos (does not refuse); `--check-only`
  is the hard gate (exit 1, lists the 3). The spare
  `raaruofficial-ore-kingdom` key (public repo, no job) is unused.
  **CURED 2026-11-12 (~09:00 PST):** the 3 keys were issued under
  Jacob's 00:17 no-cost programme authorization (fresh ed25519
  keypairs, title `burst-campaign-2026-11-11`, read-only; IDs
  169674582 clink-app, 169674606 iris-app, 169674622
  time-wizard-app — listed above for revocation). `--check-only`
  now passes on both manifests: camp-1 all 33 repos covered,
  voidrunner-only all 1 covered, exit 0. No key material left the
  keys dir; no repo diff contains key bytes.

## Revocation (teardown — REQUIRED)

Delete every deploy key by ID (run from this VM with the gh CLI):

```bash
gh api -X DELETE repos/raaruofficial/voidrunner/keys/169586629
gh api -X DELETE repos/raaruofficial/paper-moon/keys/169586766
gh api -X DELETE repos/raaruofficial/ore-haunt/keys/169586769
gh api -X DELETE repos/raaruofficial/ore-kingdom/keys/169586771
gh api -X DELETE repos/raaruofficial/iris-app/keys/169674606
gh api -X DELETE repos/raaruofficial/time-wizard-app/keys/169674622
gh api -X DELETE repos/raaru-studios/clink-app/keys/169674582
gh api -X DELETE repos/raaru-studios/gaspumpa-app/keys/169586932
gh api -X DELETE repos/raaru-studios/ore-almanac-app/keys/169586935
gh api -X DELETE repos/raaru-studios/ore-anomaly-app/keys/169586938
gh api -X DELETE repos/raaru-studios/ore-booth-app/keys/169586940
gh api -X DELETE repos/raaru-studios/ore-bounty-app/keys/169586943
gh api -X DELETE repos/raaru-studios/ore-circle-app/keys/169586947
gh api -X DELETE repos/raaru-studios/ore-data-app/keys/169586951
gh api -X DELETE repos/raaru-studios/ore-edge-app/keys/169586957
gh api -X DELETE repos/raaru-studios/ore-escrow-app/keys/169586959
gh api -X DELETE repos/raaru-studios/ore-fleet-app/keys/169586962
gh api -X DELETE repos/raaru-studios/ore-guild-app/keys/169586968
gh api -X DELETE repos/raaru-studios/ore-harvest-app/keys/169586972
gh api -X DELETE repos/raaru-studios/ore-ledger-app/keys/169586973
gh api -X DELETE repos/raaru-studios/ore-legacy-app/keys/169586978
gh api -X DELETE repos/raaru-studios/ore-machine-app/keys/169586980
gh api -X DELETE repos/raaru-studios/ore-pay-app/keys/169586983
gh api -X DELETE repos/raaru-studios/ore-pin-app/keys/169586986
gh api -X DELETE repos/raaru-studios/ore-pit-app/keys/169586991
gh api -X DELETE repos/raaru-studios/ore-pocket-app/keys/169586996
gh api -X DELETE repos/raaru-studios/ore-print-app/keys/169586998
gh api -X DELETE repos/raaru-studios/ore-radio-app/keys/169587001
gh api -X DELETE repos/raaru-studios/ore-reclaim-app/keys/169587003
gh api -X DELETE repos/raaru-studios/ore-rescue-app/keys/169587006
gh api -X DELETE repos/raaru-studios/ore-scout-app/keys/169587013
gh api -X DELETE repos/raaru-studios/ore-season-app/keys/169587018
gh api -X DELETE repos/raaru-studios/ore-seat-app/keys/169587022
gh api -X DELETE repos/raaru-studios/ore-vault-app/keys/169587028
gh api -X DELETE repos/raaru-studios/ore-watch-app/keys/169587032
```

Then delete the private keys from estate custody and, if desired,
re-disable deploy keys at the org level:

```bash
rm -rf ~/workspace/estate-keys/burst-deploy-keys ~/workspace/estate-keys/burst-github-deploy-key*
gh api -X PATCH orgs/raaru-studios -F deploy_keys_enabled_for_repositories=false
```

Verify revocation by confirming each repo's key list is empty of the
`burst-campaign-2026-11-11` title:
`gh api repos/<owner>/<repo>/keys --jq '.[].title'`
