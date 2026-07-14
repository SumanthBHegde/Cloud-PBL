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

| # | Case | Detection rule (Athena SQL) | Demo script |
|---|------|-----------------------------|-------------|
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
│   ├── setup-automation.sh   ← adds the scheduled auto-detector (EventBridge every 15 min)
│   ├── demo.sh               ← quick end-to-end demo (all activity at once)
│   ├── teardown.sh           ← deletes everything (stop AWS billing)
│   └── demos/                ← one focused demo per detection case ★ NEW
│       ├── _common.sh        ← shared helper (loads state, runs Athena queries)
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

### Step 4 — Demonstrate each detection case

Each script **generates the suspicious activity for its case, then runs the
matching SQL detection query** and prints the result.

```bash
cd "/d/MCA/Cloud PBL/scripts/demos"

./demo-1-high-frequency.sh      # burst of >50 API calls from one IP
./demo-2-off-hours.sh           # activity in the 00:00–05:00 UTC window
./demo-3-unknown-region.sh      # an API call from us-east-1
./demo-4-policy-modification.sh # a PutBucketPolicy event
./demo-5-failed-logins.sh       # failed ConsoleLogin attempts (part manual)
./demo-6-bulk-download.sh       # >100 GetObject calls (bulk exfiltration)

# ...or all six at once:
./run-all-demos.sh
```

> **⏱ CloudTrail delivery lag.** CloudTrail batches logs to S3 every **5–15
> minutes**. On the **first** run a query often shows **0 rows** for the
> activity you just generated — that's expected. Wait ~10–15 minutes and
> **re-run the same demo** (or `run-all-demos.sh` a second time); the matches
> will appear. Two cases need extra care:
> - **Case 2 (off-hours)** only matches live activity if you run it **between
>   00:00 and 05:00 UTC** — the script prints the current UTC hour.
> - **Case 5 (failed logins)** needs real **browser** console sign-in failures
>   (CLI calls don't produce `ConsoleLogin` events) — the script prints the
>   exact steps.
> - **Case 6 (bulk download)** turns on S3 **data-event** logging first, since
>   `GetObject` isn't a management event.

The classic all-in-one walkthrough (from the PDF) still works too:

```bash
cd "/d/MCA/Cloud PBL"
./scripts/demo.sh
```

### Step 5 — (Optional) Enable the automatic detector

`demo.sh`/the per-case demos are manual. To get the **hands-off** monitoring
layer — a Lambda that runs all 6 rules on a schedule and emails only on a real
hit:

```bash
./scripts/setup-automation.sh
```

This adds the **`DataLeakDetector`** Lambda (its own scoped IAM role) and an
**EventBridge** rule on `rate(15 minutes)`. Trigger a cycle immediately:

```bash
source pbl-state.env
aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" out.json && cat out.json
```

An alert email arrives only if a rule matched. New resources are appended to
`pbl-state.env` so teardown removes them.

> Needs `events:PutRule`, `events:PutTargets`, `lambda:AddPermission`. On an
> `events:PutRule` AccessDenied, attach `AmazonEventBridgeFullAccess` and re-run.

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
| Demo query shows 0 rows | CloudTrail lag — wait 10–15 min, re-run the demo |
| Case 2 never matches | Run it between 00:00–05:00 UTC (script prints the hour) |
| Case 5 never matches | Fail real **browser** console logins; CLI can't produce `ConsoleLogin` |
| Case 6 shows no `GetObject` | S3 data events must be on — the script enables them; needs `cloudtrail:PutEventSelectors` |
| Setup hangs at RDS step | Normal — `rds wait db-instance-available` takes 5–10 min |
| `teardown.sh` leaves the S3 bucket | Versioned objects remain — re-run teardown (it has a boto3 purge pass) |
| Permission denied (IAM) | Your IAM user needs EC2, S3, RDS, CloudTrail, Athena, SNS, Lambda, IAM, EventBridge |

---

## Reference

- **`context.md`** — full narrative, every raw command, and the original manual
  walkthrough this automation is based on.
- **`docs/`** — the project report and slide decks (`SQL_Data_Leak_Detection_AWS.pptx`
  slides 11–14 describe the automation layer).
