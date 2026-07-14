# SQL-Based Data Leak Detection on AWS

A cloud security project (Cloud PBL) that detects **data leaks and suspicious
access** by writing **SQL detection rules against CloudTrail audit logs** using
Amazon Athena, and raising email alerts via SNS + Lambda.

The whole stack is built, demoed, and torn down with a handful of bash scripts —
no console clicking required.

---

## What it does

Every API call in the AWS account is captured by **CloudTrail** and written as
JSON logs to **S3**. **Athena** queries those logs with plain SQL. A set of
**6 detection rules** looks for the fingerprints of a data leak; when a rule
matches, a **Lambda** function publishes an **SNS** alert email.

```
                 ┌─────────────┐      writes logs      ┌────────────┐
   AWS activity  │ CloudTrail  │ ────────────────────▶ │  S3 bucket │
  (RDS, S3, IAM) │ (audit)     │   (JSON, gzipped)     │  (logs)    │
                 └─────────────┘                       └─────┬──────┘
                                                             │ SQL over logs
                                                       ┌─────▼──────┐
                                                       │   Athena   │
                                                       │ 6 SQL rules│
                                                       └─────┬──────┘
                                            rule matched ?   │ yes
                                                       ┌─────▼──────┐   publish   ┌───────┐
                                                       │   Lambda   │ ──────────▶ │  SNS  │─▶ email
                                                       │ (detector) │             └───────┘
                                                       └────────────┘
```

### The 6 detection rules (the cases this project detects)

| # | Case | Detection rule (Athena SQL) | Attacker script |
|---|------|-----------------------------|-----------------|
| 1 | **High-frequency access** | `> 50` events from one `sourceIPAddress` | `demos/demo-1-high-frequency.sh` |
| 2 | **Off-hours access** | activity between `00:00–05:00 UTC` | `demos/demo-2-off-hours.sh` |
| 3 | **Unknown region** | `awsRegion` not in the approved region | `demos/demo-3-unknown-region.sh` |
| 4 | **Policy modification** | `PutBucketPolicy` / `PutBucketAcl` events | `demos/demo-4-policy-modification.sh` |
| 5 | **Consecutive failed logins** | `>= 3` failed `ConsoleLogin` from one IP | `demos/demo-5-failed-logins.sh` |
| 6 | **Bulk S3 download** | `> 100` `GetObject` calls from one IP | `demos/demo-6-bulk-download.sh` |

---

## Repository layout

```
Cloud PBL/
├── README.md                 ← you are here
├── context.md                ← full narrative + raw commands (reference)
├── pbl-state.env             ← resource IDs, written by setup.sh (do not delete)
├── scripts/
│   ├── setup.sh              ← builds the whole stack (VPC→RDS→CloudTrail→Athena→SNS→Lambda)
│   ├── setup-automation.sh   ← adds the scheduled auto-detector (EventBridge every 1 min)
│   ├── demo.sh               ← one-command demo: run attacks + manually trigger the detector
│   ├── teardown.sh           ← deletes everything (stop AWS billing)
│   └── demos/                ← attacker scripts: one per scenario (generate activity only)
│       ├── _common.sh        ← shared helper (loads state, banners, notes)
│       ├── demo-1-high-frequency.sh
│       ├── demo-2-off-hours.sh
│       ├── demo-3-unknown-region.sh
│       ├── demo-4-policy-modification.sh
│       ├── demo-5-failed-logins.sh
│       ├── demo-6-bulk-download.sh
│       └── run-all-demos.sh  ← runs all 6 in sequence
└── docs/                     ← report + slide decks
```

---

## Step-by-step

### Step 0 — Prerequisites (one time)

Runs on Windows via **Git Bash**. Install and confirm each tool is on PATH:

| Tool | Why | Install |
|------|-----|---------|
| Git for Windows (Git Bash) | bash shell on Windows | https://git-scm.com/download/win |
| AWS CLI v2 | runs every `aws …` command | https://awscli.amazonaws.com/AWSCLIV2.msi |
| `jq` | JSON parsing | `winget install jqlang.jq` |
| `zip` | packages the Lambda code | `winget install GnuWin32.Zip` |
| MySQL client | seed/query the RDS DB (cases 1, 5) | https://dev.mysql.com/downloads/installer/ |
| Python 3 | teardown's S3 version purge | https://www.python.org/downloads/ |

After installing, **reopen Git Bash**, then verify:

```bash
aws --version && jq --version && zip -v && mysql --version
```

### Step 1 — Configure AWS credentials

Your IAM user needs permissions for EC2/VPC, S3, CloudTrail, RDS, Athena, SNS,
Lambda, IAM, and (for the automation layer) EventBridge.

```bash
aws configure
#   AWS Access Key ID:     <paste>
#   AWS Secret Access Key: <paste>
#   Default region name:   ap-south-1
#   Default output format: json

aws sts get-caller-identity     # confirm it works
```

> Never commit your keys. They live in `~/.aws/credentials`.

### Step 2 — Build the stack

```bash
cd "/d/MCA/Cloud PBL"

# optional overrides (defaults already work)
export SUFFIX='1rv25mc103'          # your unique tag
export DB_PASS='Admin12345!'        # RDS master password
export SNS_EMAIL='you@example.com'  # where alerts go

./scripts/setup.sh                  # ~10 min (mostly waiting on RDS)
```

This creates the VPC, S3 log bucket, CloudTrail trail, RDS MySQL (+ seeded
`employee_data` table), the Athena `cloudtrail_logs` table, the SNS topic, and
the alert Lambda. Every resource ID is written to **`pbl-state.env`** — the
demo and teardown scripts read it, so **don't delete that file**.

### Step 3 — Confirm the SNS email subscription

`setup.sh` sends a **"Confirm subscription"** email to `$SNS_EMAIL`. **Open it
and click the link**, otherwise no alert emails will be delivered.

### Step 4 — Deploy the automatic detector

This is what makes detection **hands-off**: a `DataLeakDetector` Lambda that holds
all 6 SQL rules and is triggered by an **EventBridge** schedule — no human runs a
query.

```bash
./scripts/setup-automation.sh
```

This creates the **`DataLeakDetector`** Lambda (its own scoped IAM role), turns on
S3 **data-event logging** (so the bulk-download rule can see `GetObject`), and an
**EventBridge** rule on `rate(1 minute)` — created **DISABLED** on purpose (the
detector is stateless and would otherwise re-alert on the same historical logs
every minute). New resource IDs append to `pbl-state.env`.

> Needs `events:PutRule`, `events:PutTargets`, `lambda:AddPermission`. On an
> `events:PutRule` AccessDenied, attach `AmazonEventBridgeFullAccess` and re-run.

### Step 5 — Simulate attacks & watch the automatic alerts

The scripts in `scripts/demos/` are the **attacker** — each one only *generates*
the suspicious activity for one scenario. Detection and the alert email happen
automatically in the cloud.

**Arm the detector**, launch an attack, then **disarm**:

```bash
source pbl-state.env
aws events enable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"   # ~2 min before

cd scripts/demos
./demo-1-high-frequency.sh      # burst of >50 API calls from one IP
./demo-2-off-hours.sh           # activity in the 00:00–05:00 UTC window
./demo-3-unknown-region.sh      # an API call from us-east-1
./demo-4-policy-modification.sh # a PutBucketPolicy event
./demo-5-failed-logins.sh       # failed ConsoleLogin attempts (part manual)
./demo-6-bulk-download.sh       # >100 GetObject calls (bulk exfiltration)
./run-all-demos.sh              # ...or all six at once

cd ../..
aws events disable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"  # after the demo
```

For an **instant** check instead of waiting for a schedule tick, invoke the
detector directly (it still does the detection itself):

```bash
aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" out.json && cat out.json
# e.g. {"body": "2 rule(s) triggered; alert sent."}
```

> **⏱ CloudTrail delivery lag.** CloudTrail batches logs to S3 every **5–15
> minutes**, so the detector sees a fresh attack a few minutes after you launch
> it. Three scenarios need extra care:
> - **Case 2 (off-hours)** only matches if the activity happens **between 00:00
>   and 05:00 UTC** — the script prints the current UTC hour.
> - **Case 5 (failed logins)** needs real **browser** console sign-in failures
>   (CLI calls don't produce `ConsoleLogin` events) — the script prints the steps.
> - **Case 6 (bulk download)** relies on S3 **data-event** logging, enabled by
>   `setup-automation.sh` in Step 4.

**Manual-trigger fallback.** Don't want to enable the schedule? `./scripts/demo.sh`
runs all the attacker scenarios and then **manually invokes the detector** for you
(same detection, no EventBridge needed). Use `./scripts/demo.sh --skip-attacks` to
just trigger detection on the existing logs.

### Step 6 — Tear everything down (avoid ongoing cost)

```bash
cd "/d/MCA/Cloud PBL"
./scripts/teardown.sh
```

Deletes (in dependency order) the automation layer, both Lambdas + IAM roles,
SNS topic, Athena table, CloudTrail trail, RDS instance + subnet group, the S3
bucket (all object versions), security group, route table, subnets, IGW, and
VPC. It's best-effort (`|| true` on every call) — **re-run once or twice** if a
step was skipped (e.g. RDS still finalizing), then confirm in the AWS Console
that nothing billable remains.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `aws: command not found` | Reopen Git Bash after installing AWS CLI v2 |
| `Unable to locate credentials` | Run `aws configure` again |
| `jq: command not found` | `winget install jqlang.jq`, reopen Git Bash |
| No alert email after an attack | Detector needs the enabled schedule (`enable-rule`) **and** a confirmed SNS subscription; also allow CloudTrail's 5–15 min lag. Invoke the detector directly to check faster. |
| Detector reports "0 rule(s) triggered" | CloudTrail hasn't delivered the attack yet — wait a few minutes and invoke again |
| Inbox flooded with alerts | The 1-min schedule is on and re-alerting on old logs — `disable-rule` |
| Case 2 never matches | Attack must occur between 00:00–05:00 UTC (script prints the hour) |
| Case 5 never matches | Fail real **browser** console logins; CLI can't produce `ConsoleLogin` |
| Case 6 shows no `GetObject` | Run `setup-automation.sh` (it enables S3 data events); needs `cloudtrail:PutEventSelectors` |
| Setup hangs at RDS step | Normal — `rds wait db-instance-available` takes 5–10 min |
| `teardown.sh` leaves the S3 bucket | Versioned objects remain — re-run teardown (it has a boto3 purge pass) |
| Permission denied (IAM) | Your IAM user needs EC2, S3, RDS, CloudTrail, Athena, SNS, Lambda, IAM, EventBridge |

---

## Reference

- **`context.md`** — full narrative, every raw command, and the original manual
  walkthrough this automation is based on.
- **`docs/`** — the project report and slide decks (`SQL_Data_Leak_Detection_AWS.pptx`
  slides 11–14 describe the automation layer).
