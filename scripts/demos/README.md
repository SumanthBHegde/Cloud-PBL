# Demo Scripts — SQL Data Leak Detection

This folder has **6 demo scripts**, one for each type of data leak our system
detects. Each script does two things:

1. **Generates the suspicious activity** for its case (so CloudTrail records it).
2. **Runs the Athena SQL rule** that detects it, and prints whether the rule fired.

Think of each script as a mini story: *"here's the attack → here's the SQL that
catches it → here's the result."*

---

## Before you run anything

- The stack must already be deployed (`../setup.sh` has been run and
  `../../pbl-state.env` exists — the demos read resource IDs from it).
- Run from **Git Bash**. You can run a demo from anywhere; it finds its own paths.
- **CloudTrail delivery lag (important):** CloudTrail takes **5–15 minutes** to
  write logs to S3. On the **first** run a query often shows **0 rows** for the
  activity you just generated — that's normal. Wait ~10–15 min and **re-run the
  same script**; the match then appears.

```bash
cd "/d/MCA/Cloud PBL/scripts/demos"
./demo-1-high-frequency.sh        # run one case
./run-all-demos.sh                # or run all six
```

---

## The files

| File | What it is |
|---|---|
| `_common.sh` | **Shared helper — not run directly.** Loads `pbl-state.env`, prints banners, and provides `run_athena()` which runs a detection query and shows the result. Every demo `source`s this. |
| `run-all-demos.sh` | Runs all 6 demos back-to-back. Best used as: run once to generate activity, wait ~15 min, run again to see all the matches. |
| `demo-1-high-frequency.sh` | Case 1 — high-frequency access |
| `demo-2-off-hours.sh` | Case 2 — off-hours access |
| `demo-3-unknown-region.sh` | Case 3 — unknown region |
| `demo-4-policy-modification.sh` | Case 4 — policy modification |
| `demo-5-failed-logins.sh` | Case 5 — failed logins |
| `demo-6-bulk-download.sh` | Case 6 — bulk S3 download |

---

## What each demo does

### `demo-1-high-frequency.sh` — High-Frequency Access
- **Threat:** one IP hammering the account (a bot or a stolen credential
  scraping/exfiltrating data).
- **What it generates:** fires **60 harmless API calls** from your machine. Each
  call is logged by CloudTrail with your public IP.
- **Detection SQL:** group by `sourceIPAddress`, flag any IP with **> 50 events**.
- **Expected result:** your IP appears with an access count above 50 → rule fires.

### `demo-2-off-hours.sh` — Off-Hours Access
- **Threat:** activity at 3 AM when no legitimate staff are working — a classic
  exfiltration sign.
- **What it generates:** a few API calls, and prints the current **UTC hour**.
- **Detection SQL:** events whose time falls **between 00:00 and 05:00 UTC**.
- **Note:** this only matches *live* activity if you run it **between 00:00–05:00
  UTC**. Outside that window it still reports any past off-hours events. The
  script tells you which case you're in.

### `demo-3-unknown-region.sh` — Unknown Region
- **Threat:** an attacker operating from a region we don't use (our stack is all
  in `ap-south-1` / Mumbai).
- **What it generates:** read-only API calls in **us-east-1** (a different
  region). Our multi-region CloudTrail captures them.
- **Detection SQL:** events where `awsRegion` is **not `ap-south-1`**.
- **Expected result:** `us-east-1` shows up → rule fires.

### `demo-4-policy-modification.sh` — Policy Modification
- **Threat:** someone weakening the security of the log/data bucket (e.g. to make
  it public) or tampering with the audit logs.
- **What it generates:** re-applies the bucket's **own existing policy** (a
  no-op) so a real `PutBucketPolicy` event is recorded. **Nothing about the
  bucket's real permissions changes.**
- **Detection SQL:** events where `eventName` is **`PutBucketPolicy` or
  `PutBucketAcl`**.
- **Expected result:** the policy event appears → rule fires.

### `demo-5-failed-logins.sh` — Consecutive Failed Logins
- **Threat:** brute-force / password guessing against the AWS Console.
- **Important:** a `ConsoleLogin` event is **only** produced by the AWS web
  sign-in page — it **cannot** be generated from the CLI. So this demo is
  **part-manual**: it prints the exact browser steps (sign in with a wrong
  password 3–4 times), then runs the query. It also fires 3 failed **DB** logins
  as an on-host illustration (note: DB auth failures are *not* CloudTrail events,
  so they don't feed this rule — only browser console sign-ins do).
- **Detection SQL:** `ConsoleLogin` failures, grouped by IP, **≥ 3** from one IP.
- **Expected result:** matches only after you do the browser sign-in failures.

### `demo-6-bulk-download.sh` — Bulk S3 Download
- **Threat:** mass data exfiltration — pulling a whole bucket.
- **Important:** `GetObject` is an S3 **data event**, which CloudTrail does *not*
  log by default. So this demo first **turns on S3 data-event logging** for the
  bucket, then uploads a few sample objects and **downloads them 120 times**.
- **Detection SQL:** `GetObject` events, grouped by IP, **> 100** from one IP.
- **Expected result:** your IP shows 120 downloads → rule fires. (`teardown.sh`
  removes the trail, so the data-event setting goes with it.)

---

## Reading the output

At the end of each query the script prints one of:

- **`RULE WOULD FIRE: N matching row(s)`** — the pattern was detected. In the
  automated system, the detector Lambda would email an SNS alert here.
- **`0 matching rows -> rule NOT triggered yet`** — either the activity hasn't
  been delivered by CloudTrail yet (wait & re-run), or (case 2/5) the special
  condition above isn't met.

---

## Quick reference — the 6 cases

| # | Case | Fires when… |
|---|------|-------------|
| 1 | High-frequency access | one IP makes > 50 API calls |
| 2 | Off-hours access | activity happens 00:00–05:00 UTC |
| 3 | Unknown region | an API call comes from outside `ap-south-1` |
| 4 | Policy modification | a `PutBucketPolicy` / `PutBucketAcl` happens |
| 5 | Failed logins | ≥ 3 failed console sign-ins from one IP |
| 6 | Bulk download | one IP makes > 100 `GetObject` calls |
