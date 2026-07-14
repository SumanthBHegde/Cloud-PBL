# Attacker Demo Scripts — SQL Data Leak Detection

These 6 scripts are the **attacker** side of the project. Each one **simulates a
data-leak scenario** by generating the matching suspicious activity — and that's
*all* they do. They do **not** run any SQL or check anything themselves.

**Detection is automatic and happens in the cloud.** A `DataLeakDetector` Lambda
holds all 6 SQL rules and is triggered by an **EventBridge schedule** (every
1 minute). It runs the rules against the CloudTrail logs in Athena and, when a
rule matches, emails an alert via SNS. No human runs a query.

```
  attacker demo script          (this folder)
        │  generates suspicious activity
        ▼
   CloudTrail ──▶ S3 logs
        │  (automatic, every 1 minute)
   EventBridge ──▶ DataLeakDetector Lambda ──▶ runs 6 SQL rules in Athena
                                             ──▶ SNS email  (only on a match)
```

---

## Before you run anything

- The stack + automation layer must be deployed:
  `../setup.sh` **and** `../setup-automation.sh` have been run, so
  `../../pbl-state.env` exists (the scripts read resource IDs from it).
- Run from **Git Bash**.
- **CloudTrail delivery lag:** CloudTrail writes logs to S3 in batches — usually
  **5–15 minutes** after the activity. So the detector can only "see" an attack a
  few minutes after you launch it; the alert email arrives shortly after that.

### Turn the automatic detector on around your demo

The 1-minute schedule is created **DISABLED** (otherwise it would re-alert on the
same historical logs every minute). Enable it just before demoing, disable after:

```bash
source ../../pbl-state.env
aws events enable-rule  --region "$REGION" --name "$SCHEDULE_RULE_NAME"   # ~2 min before
# ... launch attacker scripts, watch the alert email arrive ...
aws events disable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"   # after
```

Prefer an instant result instead of waiting for a cycle? Invoke the detector by
hand — it still does the detection itself:

```bash
aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" out.json && cat out.json
```

### Launch an attack

```bash
cd "/d/MCA/Cloud PBL/scripts/demos"
./demo-1-high-frequency.sh        # run one scenario
./run-all-demos.sh                # or run all six
```

---

## The files

| File | What it is |
|---|---|
| `_common.sh` | **Shared helper — not run directly.** Loads `pbl-state.env`, prints banners, the CloudTrail-lag note, and the "you'll be caught automatically" message. Every attacker script `source`s it. |
| `run-all-demos.sh` | Runs all 6 attacker scenarios back-to-back. |
| `demo-1-high-frequency.sh` | Scenario 1 — high-frequency access |
| `demo-2-off-hours.sh` | Scenario 2 — off-hours access |
| `demo-3-unknown-region.sh` | Scenario 3 — unknown region |
| `demo-4-policy-modification.sh` | Scenario 4 — policy modification |
| `demo-5-failed-logins.sh` | Scenario 5 — failed logins |
| `demo-6-bulk-download.sh` | Scenario 6 — bulk S3 download |

---

## What each attacker script does

### `demo-1-high-frequency.sh` — High-Frequency Access
- **Attack:** one IP hammering the account (a bot / stolen credential scraping data).
- **What it generates:** fires **60 API calls** from your machine — each logged by
  CloudTrail with your public IP.
- **Detected by rule:** any IP with **> 50 events**.

### `demo-2-off-hours.sh` — Off-Hours Access
- **Attack:** activity at 3 AM when no legitimate staff are working.
- **What it generates:** a few API calls; prints the current **UTC hour**.
- **Detected by rule:** events between **00:00 and 05:00 UTC**.
- **Note:** only counts as off-hours if run **between 00:00–05:00 UTC** — the rule
  keys off the recorded event time.

### `demo-3-unknown-region.sh` — Unknown Region
- **Attack:** operating from a region we don't use (our stack is all `ap-south-1`).
- **What it generates:** read-only API calls in **us-east-1** (captured by our
  multi-region trail).
- **Detected by rule:** any `awsRegion` **other than `ap-south-1`**.

### `demo-4-policy-modification.sh` — Policy Modification
- **Attack:** weakening the log/data bucket's security (or tampering with the logs).
- **What it generates:** re-applies the bucket's **own existing policy** (a no-op)
  so a real `PutBucketPolicy` event is recorded. **Real permissions don't change.**
- **Detected by rule:** `eventName` in **`PutBucketPolicy` / `PutBucketAcl`**.

### `demo-5-failed-logins.sh` — Consecutive Failed Logins
- **Attack:** brute-force / password guessing against the AWS Console.
- **Important — part manual:** a `ConsoleLogin` event is **only** produced by the
  AWS web sign-in page, so it can't be generated from the CLI. The script fires 3
  failed **DB** logins as an illustration, but DB auth failures are *not* CloudTrail
  events — only browser Console sign-ins feed this rule. To create a real match, in
  a **web browser**:
  1. Open `https://<ACCOUNT_ID>.signin.aws.amazon.com/console`
     (your account ID is in `pbl-state.env`).
  2. Enter a **valid** IAM user name but a **wrong** password.
  3. Click **Sign in** and let it fail.
  4. Repeat **3–4 times** — that's ≥3 failed `ConsoleLogin` events from your IP.
- **Detected by rule:** **≥ 3** failed `ConsoleLogin` from one IP.

### `demo-6-bulk-download.sh` — Bulk S3 Download
- **Attack:** mass data exfiltration — pulling a whole bucket.
- **What it generates:** uploads a few sample objects, then **downloads them 120
  times**.
- **Needs S3 data events:** `GetObject` is an S3 *data* event, not logged by
  default. The **defender** turns this on in `../setup-automation.sh` (an attacker
  wouldn't log their own downloads), so this script just does the downloads.
- **Detected by rule:** any IP with **> 100 `GetObject`** calls.

---

## Quick reference — the 6 scenarios

| # | Scenario | The detector flags it when… |
|---|----------|-----------------------------|
| 1 | High-frequency access | one IP makes > 50 API calls |
| 2 | Off-hours access | activity happens 00:00–05:00 UTC |
| 3 | Unknown region | an API call comes from outside `ap-south-1` |
| 4 | Policy modification | a `PutBucketPolicy` / `PutBucketAcl` happens |
| 5 | Failed logins | ≥ 3 failed console sign-ins from one IP |
| 6 | Bulk download | one IP makes > 100 `GetObject` calls |

> The SQL for each rule lives in the detector Lambda — see the `RULES` list in
> `../setup-automation.sh`.
