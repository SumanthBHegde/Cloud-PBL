# Notes — SQL-Based Data Leak Detection on AWS

## Abstract

This project is a cloud-native **data leak detection system** built on AWS. It
continuously audits every API call in the account, stores those audit logs in
S3, and runs **SQL detection rules** over them using Amazon Athena to spot
suspicious access patterns that signal a data leak. When a rule matches, an AWS
Lambda function publishes an alert to an SNS topic, which emails the security
team. The sensitive asset being protected is an `employee_data` table (salaries,
emails) in an RDS MySQL database. The system detects **6 leak patterns**:
high-frequency access, off-hours activity, access from unknown regions, bucket
policy tampering, repeated failed logins, and bulk S3 downloads. The core idea:
express each threat as a simple `SELECT … WHERE …` query instead of a costly
SIEM — cheap, transparent, and easy to extend.

## Technologies Used

- **Amazon Web Services (AWS)** — the cloud platform hosting the entire system
- **AWS CLI v2** — provisions and drives all cloud resources
- **Amazon Athena SQL** — the language of the detection rules
- **Serverless computing** — event-driven Lambda + EventBridge (no servers to manage)
- **Infrastructure automation** — reproducible one-command deploy / teardown
- **MySQL on Amazon RDS** — the managed relational database being protected

## Cloud Services Used (AWS)

| Service | Purpose in the project |
|---|---|
| **VPC** (+ subnets, IGW, route table, security group) | Isolated network for the database |
| **RDS (MySQL)** | Hosts the sensitive `employee_data` — the asset we protect |
| **CloudTrail** | Records every API call as audit logs (multi-region) |
| **S3** | Stores CloudTrail logs and Athena query results |
| **Athena** | Runs the 6 SQL detection rules over the S3 logs (serverless) |
| **SNS** | Sends alert emails (pub/sub) |
| **Lambda** | Runs detection logic / publishes alerts (serverless compute) |
| **IAM** | Roles & least-privilege permissions for Lambda |
| **EventBridge** | (Optional) schedules the detector every 15 minutes |

## Deployment Steps

1. **Prerequisites** — install AWS CLI v2, `jq`, `zip`, MySQL client, Python 3
   (Git Bash on Windows). Verify each is on PATH.
2. **Configure credentials** — `aws configure` (region `ap-south-1`), then
   confirm with `aws sts get-caller-identity`.
3. **Build the stack** — `./scripts/setup.sh`
   (creates VPC → S3 → CloudTrail → RDS + seeded table → Athena table → SNS →
   Lambda; ~10 min, mostly waiting on RDS). Resource IDs are saved to
   `pbl-state.env`.
4. **Confirm the SNS email** — click the "Confirm subscription" link emailed to
   your address, or no alerts are delivered.
5. **Deploy the automatic detector** — `./scripts/setup-automation.sh` adds a
   `DataLeakDetector` Lambda + EventBridge rule that runs all 6 SQL rules on a
   schedule and emails via SNS only on a match. Detection is automatic — no human
   runs a query. (The 1-minute schedule is created disabled; enable it around a
   demo with `aws events enable-rule ...`.)
6. **Simulate attacks** — the scripts in `scripts/demos/` are the *attacker*; each
   only generates the suspicious activity for one scenario. The cloud detector
   catches it automatically.
   ```bash
   cd scripts/demos && ./run-all-demos.sh
   ```
   Note: CloudTrail has a 5–15 min log-delivery lag, so the alert arrives a few
   minutes after the attack.
7. **Tear down** — `./scripts/teardown.sh` deletes every resource to stop AWS
   billing.
