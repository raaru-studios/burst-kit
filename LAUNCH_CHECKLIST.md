# Burst-compute launch checklist (SPEC §9, §11a)

**Author:** Team IGNITION (TEKKADAN BANKAI 2026-11-07). **Status:** procedure
v1 — written from the ratified SPEC, the verified kit, and firsthand
service-model evidence. It has never been executed end to end: the
campaign has not fired.

**Campaign:** `camp-1` · **Box:** `m8i.12xlarge`, `us-west-2`, spot ·
**Cap:** $8 (owner-confirmed) · **Price ceiling:** $1.25/hr (§9.1 — refuse
to launch above it) · **Max hours:** 6, derived tighter by
`min(6, (cap − $0.50) / live $/hr)`.

**Operator fills before step 1:** AMI_ID ______ · SUBNET_ID ______
· SG_ID ______ · KEY_NAME ______ · OPERATOR_IP ______ · MANIFEST_PATH
`draft-camp-1.yaml` (lint must pass — see step 0) · KIT_SOURCE ______
(the read-only location the box fetches `bootstrap.sh`,
`orchestrator.py`, `cold-run-battery.sh`, the manifest, and
`parallel-lock.json` from — see step 5).

**How to use this file:** run the steps in order. Every step names its
verification — the check the operator performs before moving on. A step
whose verification fails stops the launch; never skip ahead past a
failed verification. `INSTANCE_ID` below is the id returned by step 6.

**Where the commands run:** AWS CLI shapes are written for CloudShell /
the operator browser path (SPEC §2's access path). The same reads can
run from this VM via the venv botocore scripts in `hidden/`
(`verify-burst-key.py` proves the path works — SPEC §2's claim that
"this VM's shell cannot reach AWS APIs" is STALE). Either path is fine;
the verification read-back is what matters, not the shell it ran in.

---

## 0. Gate: the launch is allowed at all

- [ ] **Owner fire word** naming this campaign received, with the $8 cap
      confirmed in the same word (SPEC §2 arm flag: `BURST_ARMED=false`
      until then). Record the word + time: ____________
- [ ] **AWS card funded** (owner item 1, READINESS.md). If not funded,
      stop — the push does not fire.
- [ ] **Manifest lints clean:** `python3 kit/orchestrator.py
      draft-camp-1.yaml --lint-only` exits 0. (Verified 2026-11-12:
      lint OK, 66 live jobs — all 25 lane repos exist, pushed and
      pinned; 0 unpinned refs; m01-rail-check gate job included. The
      2026-11-06 note below about a lint refusal on 50 unpinned refs
      is superseded.)
- [ ] **Lock registry fresh + published (L-05, 2026-11-12):**
      `python3 kit/lock-check.py` exits 0 (or, while riders are
      UNLOCKED on a curable item, records the honest state — the
      dispatch gate refuses on it, see below). Copy the fresh
      `parallel-lock.json` into the burst-kit checkout, commit + push
      `[skip ci]`, and record its sha256 as the FIFTH KIT_SHA256S line
      (below). The registry must be <1h old at dispatch — the
      orchestrator refuses a stale one (exit 2). The registry is the
      dispatch gate's first net; its second net is a parallel
      `git ls-remote` spot check of every manifest repo on the box.
- [ ] **Kit hashes recorded (FIVE files, not four):** `sha256sum
      kit/bootstrap.sh kit/orchestrator.py kit/cold-run-battery.sh
      <the linted manifest, e.g. draft-camp-1.yaml>
      <the fresh lock registry, parallel-lock.json>` — write all five
      here: ____________ (the box re-verifies them after fetch, SPEC
      §8.2). **Security note (2026-11-11 audit):** this step previously
      listed only the three kit files. `user-data.sh` requires
      KIT_SHA256S to cover exactly the fetched files, and
      `sha256sum -c` only verifies the lines present — a manifest hash
      missing from the list meant the manifest (the file that decides
      WHAT CODE RUNS) was fetched but never verified. A compromised
      kit repo could have swapped the manifest and the box would have
      accepted it. Always record the manifest's hash from the LOCAL
      linted copy, never from a repo-fetched copy (recording it from
      the repo would make the gate circular). The same holds for the
      lock registry (L-05): record its hash from the LOCAL fresh
      copy, never from a repo-fetched copy.
- [ ] **Coverage gate with --manifest (L-05, 2026-11-12):**
      `python3 kit/render-user-data.py --check-only --keys-dir
      ~/workspace/estate-keys/burst-deploy-keys --manifest
      draft-camp-1.yaml` exits 0. **A bare `--check-only` (no
      `--manifest`) is a VACUOUS pass — 0 repos covered, exit 0 — and
      must never be read as a coverage proof; the real gate always
      passes `--manifest` explicitly.** (The render script now
      refuses a bare `--check-only` with exit 1.)
- [ ] **Budgets alarm confirmed live** (§9.3): `hidden/verify-budgets.py`
      shows budget `Estate cap 5`, $5.00 USD MONTHLY, ACTUAL 50/85/100%
      + FORECASTED 100%, all EMAIL to `raaruofficial@gmail.com`
      (verified 2026-11-07). Note the mismatch to SPEC §9.3's "50/80/100%":
      the real thresholds are 50/**85**/100, and the $5 budget limit is
      BELOW the $8 campaign cap — the 100% alarm will fire mid-campaign.
      That is a warning, not a stop; the cap is enforced by steps 2–3
      and the orchestrator, not by Budgets.
- **Verification before moving on:** fire word recorded, card funded,
  lint exit 0, kit hashes written down, Budgets read-back on file.
  Any one missing → do not launch.

## 1. IAM / key check

- [ ] Run `~/workspace/.venv-aws/bin/python
      hidden/verify-burst-key.py` (or the STS + spot-price calls from
      CloudShell).
- **Verification:** output reads `STS OK: account=079214218218
  arn=arn:aws:iam::079214218218:user/burst-agent` and prints a live spot
  price. Anything else (401, AccessDenied, wrong account) → stop and
  report; do not proceed on an unverified key. Never print or paste the
  secret key value anywhere.
- [ ] **F-6 — `run-instances --dry-run` permission proof** (smoke-test
      safety audit, 2026-11-11): run the step-6 launch call with
      `--dry-run` and the exact parameters (AMI, type, key, subnet,
      SG, spot options, CPU options, volume, shutdown behavior,
      user-data file). Expect `DryRunOperation` — permission OK.
      `UnauthorizedOperation` means the key lacks the permission:
      stop, do not launch, report. (The smoke runs the same proof
      with its own parameters in SMOKE_TEST.md step 0.)

## 2. Pre-flight print — live price, ceiling, estimate (SPEC §9.1)

- [ ] Print live spot prices across candidate AZs (cheapest-AZ launch,
      §11a-6):
      ```
      aws ec2 describe-spot-price-history --instance-types m8i.12xlarge \
        --product-descriptions Linux/UNIX --region us-west-2 \
        --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
        --query 'SpotPriceHistory[*].{AZ:AvailabilityZone,Price:SpotPrice}' \
        --output table
      ```
      Cheapest AZ: ______ at $______/hr. Fallbacks if `us-west-2` has no
      capacity: `m8i.12xlarge` in `us-east-1`, then `c8i.12xlarge` /
      `r8i.12xlarge` (§3 ladder — each step printed before taken).
- [ ] **REFUSE TO LAUNCH ABOVE $1.25/hr.** If the cheapest live price is
      > $1.25/hr: stop, wait for a cheaper hour, report to the owner.
      This is the §9.1 pre-flight price ceiling and it is enforced HERE,
      by refusal — the first net. Two more nets back it: the step-6 Spot
      MaxPrice ($1.25) and the orchestrator's `--price-ceiling` flag
      (default $1.25, exit 2 refusal — Team GRID, BANKAI 2026-11-07;
      see step 8).
- [ ] **K-05 — refuse above 1.5× the quoted price (deep-problems audit,
      2026-11-11).** The $1.25/hr ceiling alone lets a price spike
      through ($0.80/hr quoted vs $1.25/hr ceiling is a 56% swing,
      ~$2.70 on a 6h run). Record the QUOTED price in the launch
      record next to the live price (the price the fire word was given
      with — for camp-1 the standing quote is $0.8033/hr, us-west-2d
      12xlarge, read 2026-11-11 ~17:10 PST; re-read at launch, never
      paste from memory), and REFUSE if the live price is above
      **1.5× the quoted price** (for camp-1: above ~$1.20/hr at the
      standing quote — the 1.5× band binds before the $1.25 ceiling).
      The refusal is a comparison of two recorded numbers, not a
      judgment call. Record: quoted $______/hr · live $______/hr ·
      1.5× quoted $______/hr · refuse? ______.
- [ ] Compute the derived runtime: `max_hours = min(6, (8 − 0.50) /
      live_price)`. At $0.801/hr → 6h binds (6 × $0.80 = $4.80, 60% of
      cap). At $1.25/hr → 6.0h, cost trip at ~5.1h. Record:
      live $______/hr · derived max_hours ______ · estimated cost
      $______ (live price × derived hours + pennies for storage/egress).
- **Verification:** estimate ≤ $8 cap AND live price ≤ $1.25/hr, both
  written down. Either fails → no launch.

## 3. Nested virtualization — enable at launch (verified mechanism)

The KVM gate (`bootstrap.sh`, first thing at boot) fails at minute ~5
and aborts the campaign if nested virt is off. It must be enabled in
the launch call itself — it is opt-in per instance.

- [ ] Pass `--cpu-options NestedVirtualization=enabled` in the step-6
      launch call. **Verified mechanism (not guessed):** the local
      botocore EC2 service model (1.43.126, `ec2/2016-11-15`) defines
      `RunInstancesRequest.CpuOptions` →
      `CpuOptionsRequest.NestedVirtualization`, shape
      `NestedVirtualizationSpecification`, enum `enabled | disabled`,
      documented "supported only on 8th generation Intel-based instance
      types (c8i, m8i, r8i, and their flex variants)" and "when nested
      virtualization is enabled, Virtual Secure Mode (VSM) is
      automatically disabled for the instance."
- [ ] After launch, read it back before trusting it:
      ```
      aws ec2 describe-instances --instance-ids $INSTANCE_ID \
        --query 'Reservations[].Instances[].CpuOptions.NestedVirtualization' \
        --region us-west-2
      ```
      **Verification:** read-back is `enabled`. If it is `disabled` or
      absent → do NOT let the campaign proceed; use the fallback below.
- [ ] At first SSH (step 7), before the gate runs: `ls -l /dev/kvm`
      must exist and be readable+writable. This is the on-box
      confirmation; the API read-back and the device check must agree.
- **Fallback if the launch forgot the flag (or the read-back is wrong):**
  the attribute can only be changed while the instance is STOPPED
  (verified: `ModifyInstanceCpuOptions` operation doc, "The instance
  must be in a `Stopped` state before you make changes"):
  ```
  aws ec2 stop-instances --instance-ids $INSTANCE_ID --region us-west-2
  aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID --region us-west-2
  aws ec2 modify-instance-cpu-options --instance-id $INSTANCE_ID \
    --nested-virtualization enabled --region us-west-2
  aws ec2 start-instances --instance-ids $INSTANCE_ID --region us-west-2
  ```
  Then repeat the read-back above. **Do NOT use
  `modify-instance-attribute` for this:** the service model shows its
  request has no `CpuOptions` member — it cannot set nested virt.
  Cost of the fallback: minutes of stopped time, not a re-launch.

## 4. Launch parameters — fill-ins resolved, not guessed

- [ ] **AMI:** Ubuntu 24.04 LTS x86_64, stock AWS AMI (§3). Resolve the
      current AMI id by query, do not paste one from memory:
      ```
      aws ec2 describe-images --owners 099720109477 --region us-west-2 \
        --filters "Name=name=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text
      ```
      AMI_ID used: ______
- [ ] **Subnet:** a public subnet in the cheapest AZ from step 2.
      SUBNET_ID used: ______
- [ ] **Security group:** SSH (22) open ONLY to the operator's current
      IP; all other inbound closed (§3). SG_ID used: ______ ·
      operator IP: ______
- [ ] **Key pair:** KEY_NAME used: ______ (the operator holds the
      private key; it never goes in user-data or on the box).
- [ ] **Root volume:** 200 GB gp3, delete-on-termination = true (§3).
- [ ] **Spot MaxPrice = $1.25** (the §9.1 ceiling, enforced by the
      request itself as a second net behind the step-2 refusal).
- [ ] **Instance-initiated shutdown behavior = terminate** (§9.4's
      self-terminate only destroys the box if shutdown terminates it).
- **Verification:** every blank above is filled with a value read back
  from AWS in this session. A parameter carried from memory is a
  launch refusal.

## 5. User-data — bootstrap, self-terminate, kit fetch

User-data is a cloud-init script (base64 by the CLI's `file://` form).
It must do exactly these things, in this order:

0. Arm a 60-minute DEFAULT self-terminate immediately after the epoch
   (F-2, 2026-11-11): the box can never outlive 60 minutes without a
   safety, even if the fetch/hash steps below fail. It is re-armed
   with the derived value at step 2 below.
1. Fetch `bootstrap.sh`, `orchestrator.py`, `cold-run-battery.sh`, the
   linted manifest, and the lock registry (`parallel-lock.json`,
   L-05) from KIT_SOURCE (step-0 fill-in) **machine-to-
   machine** (SPEC §5 pull model — file bytes never travel through
   agent message text) and verify each file's sha256 against the hashes
   recorded in step 0. A hash mismatch aborts user-data loudly.
2. Re-arm the self-terminate (§9.4): schedule `shutdown -h now` at
   `derived max_hours − 15 minutes` after boot (a background
   `sleep` + `shutdown`, or a systemd timer — either way it must
   survive the bootstrap and the orchestrator run). The re-arm cancels
   the §0 default first, so exactly one shutdown is scheduled. With
   `--instance-initiated-shutdown-behavior terminate` (step 4) the
   shutdown destroys the box.
3. Run `bash bootstrap.sh` (cloud-init user-data). Bootstrap runs the
   KVM gate first, then the toolchain phases with retry (3 attempts,
   10s/20s backoff) and fail-closed phases — a failed phase aborts
   the bootstrap, it never carries on.
4. On bootstrap success, start the orchestrator (step 8).

- **Render the launch payload (2026-11-12 — the ONLY way a campaign
  payload is produced):**
  ```bash
  python3 kit/render-user-data.py \
    --keys-dir ~/workspace/estate-keys/burst-deploy-keys \
    --kit-source https://raw.githubusercontent.com/raaru-studios/burst-kit/main \
    --hourly-price <live $/hr from step 2> --max-hours <derived> \
    --kit-sha256s <step-0 hash file> \
    --manifest draft-camp-1.yaml \
    --out ~/workspace/burst-compute/hidden/launch-user-data.sh
  ```
  The render fills in the four variables AND injects the 35 deploy
  keys (the §0c hook decodes them on the box into
  `$BURST_HOME/deploy-keys/`). Do NOT hand-edit `kit/user-data.sh` —
  a hand-edited file has no keys and the §0c hook refuses it
  (unless SMOKE=1). The rendered file contains private key bytes
  (mode 0600): never commit it, never paste it; only its sha256
  goes in the launch record. `--check-only` (same args, no `--out`,
  `--manifest` REQUIRED) is the coverage gate — it exits 1 while
  any manifest repo lacks a key. **A bare `--check-only` (no
  `--manifest`) is a VACUOUS pass (0 repos, exit 0) and is refused
  outright by the render script (L-05, 2026-11-12).** The 2026-11-11
  gap (3 unkeyed private repos: clink-app, iris-app, time-wizard-app)
  was CURED 2026-11-12 — 35 keys, all 33 camp-1 repos + the
  voidrunner-only repo covered; see `kit/GITHUB_CREDENTIAL.md`.
  For the smoke, render with `--smoke` instead (no keys,
  no manifest): `--out .../hidden/smoke-user-data.sh`.
- **KIT_SOURCE DESIGNATED 2026-11-11** (was an open item — now closed):
  `https://raw.githubusercontent.com/raaru-studios/burst-kit/main`
  (public repo `raaru-studios/burst-kit`; all four kit files verified
  HTTP 200 + sha256). Fill it in at the top of this file before launch.
  `kit/user-data.sh` exists in the kit (written 2026-11-09, VAULT V-R02
  fix: fetch + hash-verify, self-terminate arming, bootstrap,
  orchestrator start with `--box-launch-epoch`).
- **Verification:** user-data file written and reviewed line by line;
  KIT_SOURCE + hashes filled in; self-terminate line present with the
  derived minutes from step 2 (______ min). No user-data → no launch.

## 6. Spot request — exact CLI shape

```
aws ec2 run-instances \
  --region us-west-2 \
  --image-id $AMI_ID \
  --instance-type m8i.12xlarge \
  --key-name $KEY_NAME \
  --subnet-id $SUBNET_ID \
  --security-group-ids $SG_ID \
  --instance-market-options '{"MarketType":"spot","SpotOptions":{"MaxPrice":"1.25","SpotInstanceType":"one-time"}}' \
  --cpu-options NestedVirtualization=enabled \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":200,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --instance-initiated-shutdown-behavior terminate \
  --user-data file://../hidden/launch-user-data.sh \
  # ^ the RENDERED payload from step 5 (run from kit/; the file lives
  # in burst-compute/hidden/, NOT kit/user-data.sh — the unrendered
  # file has no keys and the §0c hook refuses it)
  --tag-specifications \
    'ResourceType=instance,Tags=[{Key=estate,Value=burst},{Key=campaign,Value=camp-1},{Key=owner,Value=raaru}]' \
    'ResourceType=volume,Tags=[{Key=estate,Value=burst},{Key=campaign,Value=camp-1},{Key=owner,Value=raaru}]' \
  --query 'Instances[0].InstanceId' --output text
```

- **Verification:** the call returns an instance id — record it:
  INSTANCE_ID ______ · launch time (UTC) ______ · AZ ______ ·
  spot price actually charged (from the instance record)
  $______/hr. Then immediately run the step-3 `CpuOptions`
  read-back and confirm `enabled`. If the call fails twice on
  capacity, follow the §3 ladder (family → AZ → region → on-demand
  twin) with each step printed; two failures = pause and report,
  never loop spend (§12). The on-demand twin (~$2.30/hr) is NEVER
  launched under an $8 cap — above the $1.25 ceiling the launch waits
  (§9.1 worked example).

## 7. SSH verification — first contact, before any job runs

- [ ] Wait for `2/2 status checks passed`, then SSH:
      `ssh -i $KEYFILE ubuntu@$PUBLIC_IP` (PUBLIC_IP from
      `describe-instances --query Reservations[].Instances[].PublicIpAddress`).
- [ ] On the box, in order:
  - `ls -l /dev/kvm` — exists, readable+writable (step-3 device check).
  - `tail -f /opt/burst/logs/bootstrap.log` (or `$BURST_HOME/logs/`) —
    watch the KVM gate line: `KVM gate: /dev/kvm present and writable —
    PASS`. If the log shows `KVM GATE FAILURE` (exit 3), the campaign
    is aborted at bootstrap cost (~$0.10) and re-plans to a verified
    family (§12) — do not admit any EMULATE job.
  - Bootstrap completes: log ends `bootstrap complete` and
    `bootstrap-timing.tsv` lists all four phases with durations.
  - Self-terminate armed: the scheduled `shutdown` / timer is listed
    (`ps aux | grep -i shutdown` or `systemctl list-timers`).
- **Verification before moving on:** KVM PASS in the log, bootstrap
  complete, self-terminate visibly armed. Any one missing → stop and
  diagnose; a box whose bootstrap failed is not a box that runs jobs.

## 8. Start the run — orchestrator handoff (hourly price)

On the box, from the kit directory:

```
python3 orchestrator.py manifest.yaml \
  --out results/camp-1 \
  --hourly-price <LIVE_PRICE_FROM_STEP_2> \
  --keys-dir <KEYS_DIR_ON_BOX>
```

- `--hourly-price` is the live $/hr actually paid (step 2 / step 6
  read-back). It enables the orchestrator's cost deadline
  (`(cap − $0.50) / price`) and the §9.1 in-run cost trip (stop
  submitting at projected spend ≥ 80% of cap; status
  `ABORTED_COST`). **Verification:** `state.json` in the bundle shows
  `hourly_price_usd` equal to the live price and `cost_deadline_s`
  equal to the derived runtime from step 2.
- **`--price-ceiling` EXISTS** (default $1.25/hr, Team GRID, BANKAI
  2026-11-07): the orchestrator refuses to start (exit 2, before any
  bundle dir or job) when `--hourly-price` exceeds it. The $1.25
  ceiling is enforced by the step-2 refusal, the step-6 Spot
  MaxPrice, AND the orchestrator flag — three nets. Pass
  `--price-ceiling` explicitly only to record a deliberate override,
  and record why.
- **`--box-launch-epoch`** is passed by `kit/user-data.sh`
  automatically (it records the box launch epoch at boot, VAULT V-R06
  fix 2026-11-09). If starting the orchestrator by hand, pass the box
  launch epoch yourself — without it the cost clock starts at
  orchestrator start and the bootstrap tax is excluded (a loud warning
  is printed and the degradation recorded in `state.json`).
- **`--keys-dir` (REQUIRED for private repos, wired 2026-11-11):**
  the on-box directory holding the 35 per-repo read-only SSH deploy
  keys, one file per repo named `<owner>-<repo>` (SPEC §8.1,
  `kit/GITHUB_CREDENTIAL.md`). With it set, every job clones via
  `git@github.com` with its repo's key (an explicit `clone_url` is
  honored as-is); a missing key refuses the job loudly as
  `DEPLOY KEY MISSING` instead of falling back to https. Without it
  the orchestrator clones plain https, which 401s on every private
  repo — the burst cannot run. Also honored via env
  `BURST_DEPLOY_KEYS_DIR`. **`kit/user-data.sh` passes this flag
  automatically (§4, wired with the key delivery 2026-11-12)** — the
  keys must be present on the box at launch, 0600, before the
  orchestrator starts — a nonexistent dir refuses the run at startup
  (exit 2).
- **`--lock-registry` (L-05 dispatch gate, 2026-11-12):** passed
  automatically by `kit/user-data.sh` (§4) as
  `--lock-registry "$KIT_DIR/parallel-lock.json"`. The orchestrator
  refuses to start (exit 2, before any bundle dir or job) when the
  registry is stale (>1h old), was not produced by
  `kit/lock-check.py`, or lists any manifest repo as UNLOCKED or
  pinned to a different HEAD — and re-checks every manifest repo's
  HEAD with a parallel `git ls-remote` spot check on the box. The
  registry is fetched + hash-verified with the kit files (step 0,
  fifth KIT_SHA256S line). `state.json` records the gate result
  under `lock_gate`.
- **Verification before leaving the box:** the orchestrator is running,
  the gate jobs (`m01-rail-check` first, then `booth-l3`) run before
  the waves, and `state.json` exists with status `RUNNING`.

## 9. State-pull — start the harvest watch (another team's script)

Start the state-pull from THIS VM (home side), exactly:

```
~/workspace/burst-compute/hidden/pull-state.py --host H --user U --key KEYFILE --out BUNDLE_DIR --interval-s 600
```

where `H` is the box's public IP/DNS, `U` is `ubuntu`, `KEYFILE` is the
operator's SSH private key, `BUNDLE_DIR` is
`~/workspace/burst-compute/results/camp-1/`, and `--interval-s 600`
pulls every 10 minutes. (The script is built by another team to
exactly this CLI; this checklist references it verbatim.)

- **Verification:** the first pull lands within ~10 minutes and
  `BUNDLE_DIR/state.json` appears with status `RUNNING`; the pull
  process stays alive for the campaign. If the first pull fails, check
  SSH reachability (step 7) before assuming the box is down.

## 10. Liveness checks — +1h and +3h (SPEC §9.1)

At **+1 hour** and **+3 hours** after launch (operator's clock, times
recorded here: +1h ______ · +3h ______):

- [ ] `state.json` freshness: `updated_at` within the last 15 minutes.
      **Stale > 15 min → investigate immediately**; if the box is
      unresponsive, terminate on sight (§9.1).
- [ ] Gate-job outcome: the §11a opening gates (`m01-rail-check` +
      `booth-l3`) passed, or the push aborted at ~30 min / ~$0.50 as
      designed. A failed gate with the push continuing is a procedure
      violation — stop it.
- [ ] Job counts: DONE / FAILED / RUNNING from `summary.json` (or
      `state.json`); failure-rate trip is ≥5 FAILED or ≥30% of decided
      jobs failed (≥10 decided) → orchestrator aborts with
      `ABORTED_FAILURE_TRIP`.
- [ ] Spend so far: elapsed × live price; must be < 80% of cap or the
      cost trip has already wound the run down (`ABORTED_COST`).
- **Verification each time:** freshness, gate outcome, counts, and
  spend written down with the check time. A missed liveness check is
  itself a finding in the campaign report.

## 11. Dead-man check — campaign end + 1 hour (SPEC §9.5)

- [ ] At campaign end + 1 hour (time: ______), from CloudShell:
      ```
      aws ec2 describe-instances --region us-west-2 \
        --filters "Name=tag:estate,Values=burst" "Name=tag:campaign,Values=camp-1" \
        --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name}'
      ```
- [ ] **A tagged burst instance alive past its cap is terminated on
      sight, no questions:**
      `aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region us-west-2`
- **Verification:** the read-back shows zero burst-tagged instances in
  any state but `terminated`, or the termination call + its
  confirmation is recorded here: ____________

## 12. Teardown — close the campaign (SPEC §9.7, §10)

Run `kit/teardown_checklist.md` in full, in order. Its checks, in brief:

- [ ] Evidence secured: bundle complete at
      `~/workspace/burst-compute/results/camp-1/` (`manifest.yaml`,
      `state.json`, per-job logs + evidence, `hashes.sha256`,
      `summary.json`); `sha256sum -c hashes.sha256` verified back home.
- [ ] Box terminated (step 11 read-back, not assumption).
- [ ] Standing-cost audit read-backs: zero burst-tagged instances,
      volumes, snapshots.
- [ ] Per-campaign GitHub credential revoked; Budgets state noted.
- [ ] **Next day:** Cost Explorer read for the campaign's tags filed in
      the campaign record — actual cost $______ (the cost line, not "it
      should have stopped").
- [ ] Campaign report filed from `kit/campaign_report_template.md`;
      lane GATE.md files + CI Meter updated back home from the verified
      bundle only.
- **Verification:** every teardown checkbox is checked from a live
  read-back or a filed artifact, with the values written in. Standing
  cost $0.00 is *verified*, never assumed.

---

## Known gaps this checklist does NOT close (do not launch past them)

1. **Per-campaign GitHub credential — CLOSED 2026-11-12** (was NONE
   EXISTS, 2026-11-11): 35 per-repo read-only deploy keys issued,
   delivered via `kit/render-user-data.py` at launch, `--check-only`
   passes on both manifests (see `kit/GITHUB_CREDENTIAL.md`). Struck
   from the gaps list; the credential now exists and is verified.
2. **S3 cache decision — OWNER OWED:** bucket + instance-profile role
   do not exist; §7 vs §11a-7 contradiction unresolved. Launch
   cache-OFF (cold tax accepted) or promoted (run
   `kit/s3-cache-setup.sh` + apply `kit/iam-policy-patch.json` first).
3. **Budgets ≠ SPEC text:** real thresholds 50/85/100 (not 50/80/100),
   $5 limit below the $8 cap (step 0).
4. **Bootstrap never fully run on this VM** (needs sudo/apt): `bash -n`
   clean + retry-helper unit test passed, but no full bootstrap proof
   exists. The first full run is campaign 0's opening minutes — the
   KVM gate + retry logging are the tripwires. (Smoke-test package
   `kit/SMOKE_TEST.md` — safety fixes F-1–F-10 applied 2026-11-11,
   unit-tested, still not launched — needs the fire word + Opt-in 2/3.)
5. **IAM gaps (burst-agent has no IAM write):** nested-virt fallback
   (Stop/Start/ModifyInstanceCpuOptions), `iam:PassRole` (S3 only),
   `cloudtrail:LookupEvents` — patch at `kit/iam-policy-patch.json`,
   apply in the console. Without it the nested-virt fallback FAILS.
6. **Crown VERIFY leg missing** (no Crown repo) and **VOIDRUNNER
   re-audit fixes unauthorised** (5 CAT / 12 MAJOR / 18 small) —
   owner decisions, not launch blockers for the suite push.

*Note 2026-11-11: the earlier gaps list had the manifest lint and the
KIT_SOURCE designation as gaps 1–3 (the kit-source entry was listed
twice). Both are now closed — manifest lints OK (55 jobs, exit 0,
0 unpinned refs); KIT_SOURCE designated — so they are removed from
this list rather than left quotable.*
