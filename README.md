# README — Configuring AWS CLI + Running the Scripts (Git Bash on Windows)

This guide walks through setting up your terminal so you can run `setup.sh` /
`teardown.sh` (the bash scripts embedded in [context.md](context.md)) from a
Windows machine using **Git Bash**.

---

## 1. Install prerequisites

| Tool | Why | Install |
|------|-----|---------|
| Git for Windows (Git Bash) | gives you a bash shell on Windows | https://git-scm.com/download/win |
| AWS CLI v2 | runs all `aws ...` commands in the scripts | https://awscli.amazonaws.com/AWSCLIV2.msi |
| `jq` | JSON parsing used by the scripts | see step 1.1 |
| `zip` | packages the Lambda function code | see step 1.1 |
| MySQL client | optional — to seed/query `employee_data` | https://dev.mysql.com/downloads/installer/ |
| Python 3 | optional — used by `teardown.sh` to purge S3 object versions | https://www.python.org/downloads/ |

Run the MSI installers normally (Next → Next → Finish), then **close and
reopen Git Bash** so the new `PATH` entries are picked up.

### 1.1 Get `jq` and `zip` into Git Bash

Git Bash doesn't ship with `jq`/`zip`. Easiest options:

```bash
# Option A: winget (Windows 10/11)
winget install jqlang.jq
winget install GnuWin32.Zip

# Option B: download jq.exe manually and drop it on your PATH
# https://github.com/jqlang/jq/releases  -> jq-windows-amd64.exe
# rename to jq.exe and place in C:\Windows or any folder already on PATH
```

Verify everything is visible inside Git Bash:

```bash
aws --version
jq --version
zip -v
python3 --version
mysql --version
```

If any command isn't found, restart Git Bash (and your machine, if you just
installed something) and try again.

---

## 2. Configure AWS CLI credentials

You need an AWS IAM user (or SSO profile) with permissions for: EC2/VPC, S3,
CloudTrail, RDS, Athena, SNS, Lambda, IAM (role creation).

1. In the AWS Console → IAM → Users → your user → **Security credentials** →
   **Create access key** (choose "Command Line Interface (CLI)").
2. Copy the **Access Key ID** and **Secret Access Key** (shown once).
3. In Git Bash:

```bash
aws configure
# AWS Access Key ID:     <paste>
# AWS Secret Access Key: <paste>
# Default region name:   ap-south-1
# Default output format: json
```

4. Confirm it works:

```bash
aws sts get-caller-identity
```

You should see your account ID, user ARN, etc. If you get a credentials
error, re-run `aws configure` and double-check the keys.

> Keep these keys private — never commit them or paste them into shared
> files. `~/.aws/credentials` is where `aws configure` stores them.

---

## 3. Extract the scripts from context.md

The full source of `setup.sh` and `teardown.sh` lives inside
[context.md](context.md) as fenced code blocks (`## setup.sh` / `## teardown.sh`
sections). Open `context.md`, copy each block into its own file:

```bash
cd "/d/MCA/Cloud PBL"
# create setup.sh and teardown.sh, paste the corresponding code block into each,
# then save and close.
```

(In Git Bash, `/d/MCA/Cloud PBL` is the Windows path `D:\MCA\Cloud PBL`.)

Make both scripts executable:

```bash
chmod +x setup.sh teardown.sh
```

---

## 4. Run the project

```bash
cd "/d/MCA/Cloud PBL"

# optional overrides — defaults already match the names used in setup.sh
export DB_PASS='YourStrongPass!'
export SNS_EMAIL='you@example.com'
export REGION='ap-south-1'
export SUFFIX='1rv25mc090'

# build everything (~10 min, mostly waiting on RDS to become available)
./setup.sh
```

While it runs:
- An SNS subscription confirmation email will be sent to `$SNS_EMAIL` —
  open it and click **Confirm subscription**, or the Lambda's alert emails
  won't be delivered.
- Resource IDs created along the way are saved to `pbl-state.env` in the
  same folder — **don't delete this file**, `teardown.sh` needs it.

Test the alert path:

```bash
aws lambda invoke --region "$REGION" \
  --function-name "data-leak-alert-handler-Serah-$SUFFIX" \
  /tmp/out.json
cat /tmp/out.json
```

Run the suspicious-activity SQL and Athena hunt queries from `context.md`
(sections "Suspicious-activity simulation" and "Athena hunt queries") to
exercise the monitoring pipeline.

---

## 5. Demo the pipeline end-to-end

Once `setup.sh` has finished and the SNS subscription is confirmed, run:

```bash
./demo.sh
```

This automates the manual walkthrough from the PDF against the live stack
(reads `pbl-state.env`):

1. Simulates suspicious DB activity (Part E) — massive `SELECT *` extraction,
   high-value target queries, and failed brute-force login attempts.
2. Runs the three Athena hunt queries (Part F) against `cloudtrail_logs` and
   prints results. Note: CloudTrail can take 5–15 minutes to deliver recent
   events to S3, so a freshly-created trail may show empty results at first —
   re-run later if you need to see specific events show up.
3. Invokes the Lambda directly (Part H) to dispatch the SNS alert email —
   this is the same manual trigger the PDF uses (there's no automatic
   Athena → Lambda wiring in this project), so the email arrives right after
   this step runs, not automatically on a schedule.

---

## 6. Enable the automated detection pipeline (optional)

`demo.sh` is a manual trigger. To get the **fully automated** monitoring layer
described in `SQL_Data_Leak_Detection_AWS.pptx` (slides 11–14) — where the
system hunts and alerts on its own with no human in the loop — run:

```bash
./setup-automation.sh
```

This adds, on top of the `setup.sh` stack:

- A new **`DataLeakDetector`** Lambda that runs the **6 detection rules**
  (high-frequency access, off-hours, unknown region, policy modification,
  failed logins, bulk download) as Athena SQL queries and publishes a
  structured SNS alert **only when a rule matches** (returns ≥1 row).
- Its own IAM role scoped to Athena + S3 + `sns:Publish` (the original
  `data-leak-alert-handler` Lambda is left untouched).
- An **EventBridge rule** `DataLeakDetectionSchedule` on `rate(15 minutes)`
  that invokes the detector automatically — this is the "every 15-minute
  monitoring cycle" from the PPT.

> Your IAM user needs `events:PutRule`, `events:PutTargets`, and
> `lambda:AddPermission`. If you hit an `events:PutRule` AccessDenied, attach
> `AmazonEventBridgeFullAccess` (or equivalent) to your user and re-run.

Once enabled, the detector fires on its own every 15 minutes. To trigger a
cycle immediately for a demo:

```bash
source pbl-state.env
aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" out.json && cat out.json
```

The alert email arrives only if a rule matched (e.g. an IP with >50 events).
The new resources are appended to `pbl-state.env`, so `teardown.sh` removes
them automatically.

---

## 7. Tear everything down (avoid ongoing AWS cost)

```bash
cd "/d/MCA/Cloud PBL"
./teardown.sh
```

This deletes, in order: Lambda + its IAM role, the SNS topic, the Athena
table, the CloudTrail trail, the RDS instance + subnet group, the S3 bucket
(including all object versions), the security group, route table, subnets,
internet gateway, and the VPC. It uses `set -uo pipefail` (no `-e`) with
`|| true` on every destructive call, so it keeps going even if one step
fails (e.g. RDS still finalizing) — re-run it once or twice if anything was
skipped, then check the AWS Console (Billing → Bills, and each service's
console page) to confirm nothing billable is left running.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `aws: command not found` | Reopen Git Bash after installing AWS CLI v2, or add `C:\Program Files\Amazon\AWSCLIV2` to PATH |
| `Unable to locate credentials` | Run `aws configure` again |
| `jq: command not found` | See step 1.1 |
| Script hangs at RDS step | Normal — `aws rds wait db-instance-available` can take 5–10 min |
| `teardown.sh` leaves the S3 bucket behind | Versioned objects/delete markers remain; re-run `./teardown.sh` — it includes a Python/boto3 cleanup pass for exactly this case |
| Permission denied (IAM) errors | Your IAM user/role needs broader permissions (EC2, S3, RDS, CloudTrail, Athena, SNS, Lambda, IAM) |
