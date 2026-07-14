# Viva Preparation — SQL-Based Data Leak Detection on AWS

A complete question–answer study guide for the project viva/demo. Covers the
problem statement, architecture, every AWS service used, the detection logic,
networking & security concepts, cost, limitations, and rapid-fire questions.

> **Tip for the viva:** if you understand the one-line story below, you can
> answer 80% of questions by reasoning from it:
> *"Every action in AWS is logged by CloudTrail into S3; Athena runs SQL over
> those logs to spot data-leak patterns; when a rule matches, Lambda sends an
> SNS email alert."*

---

## 1. Project overview

**Q: What is your project about?**
It is a cloud-native **data leak detection system**. It continuously monitors
all activity in an AWS account and detects suspicious access patterns that
indicate a data leak or breach — such as one IP pulling huge volumes of data,
activity at odd hours, access from unexpected regions, permission tampering,
brute-force logins, and bulk downloads. Detection is done with **SQL queries**
over audit logs, and alerts are emailed automatically.

**Q: What problem does it solve?**
Organisations store sensitive data (here, an `employee_data` table with salaries
and emails) in the cloud. A data leak — insider misuse or a compromised
credential — can go unnoticed for weeks. This project gives **near-real-time
detection and alerting** so the security team is notified the moment a
leak-like pattern appears.

**Q: Why "SQL-based"?**
Because the detection rules are written as **Amazon Athena SQL queries** against
CloudTrail logs. Instead of buying an expensive SIEM, we express each threat as
a `SELECT … WHERE …` query. It is cheap, transparent, and easy to extend — add
a new threat by writing one more SQL query.

**Q: What are the objectives?**
1. Audit every API call in the account (CloudTrail).
2. Make those logs queryable with SQL (Athena over S3).
3. Encode 6 leak-detection rules as SQL.
4. Alert automatically via email when a rule fires (Lambda + SNS).
5. Automate the whole cycle on a schedule (EventBridge).

---

## 2. Architecture

**Q: Explain the architecture / data flow.**

```
AWS activity (RDS, S3, IAM, console)
        │  every API call
        ▼
   CloudTrail (audit trail, multi-region)
        │  writes gzipped JSON logs
        ▼
   S3 bucket (central log store)
        │  queried in place
        ▼
   Athena  ── runs 6 SQL detection rules over the logs
        │  if a rule returns ≥1 row
        ▼
   Lambda (detector) ── builds alert message
        │  publish
        ▼
   SNS topic ── email ──▶ security team's inbox

   EventBridge triggers the Lambda every 15 minutes (automation layer)
```

**Q: Which AWS services did you use and why?**

| Service | Role in the project | Why this service |
|---|---|---|
| **VPC** | Isolated private network for the database | Network isolation & control |
| **RDS (MySQL)** | Holds the sensitive `employee_data` | Managed relational DB, the "asset" we protect |
| **CloudTrail** | Records every API call as audit logs | The evidence/source of truth for detection |
| **S3** | Stores CloudTrail logs (+ Athena results) | Cheap, durable, scalable object storage |
| **Athena** | Runs SQL detection rules over the S3 logs | Serverless SQL, pay-per-query, no servers |
| **SNS** | Delivers alert emails | Managed pub/sub notification |
| **Lambda** | Runs detection logic, publishes alerts | Serverless compute, no server to manage |
| **EventBridge** | Triggers the detector every 15 min | Serverless scheduler (cron for the cloud) |
| **IAM** | Roles/permissions for Lambda etc. | Least-privilege access control |

---

## 3. Service-by-service Q&A

### VPC & Networking

**Q: What is a VPC?**
A Virtual Private Cloud — a logically isolated virtual network inside AWS where
you launch resources. Ours is `10.0.0.0/16`.

**Q: What is CIDR? What does /16 and /24 mean?**
CIDR (Classless Inter-Domain Routing) notation defines an IP range. `/16` gives
65,536 addresses (`10.0.0.0`–`10.0.255.255`); `/24` gives 256 addresses. Our two
subnets are `10.0.1.0/24` and `10.0.2.0/24`.

**Q: Why two subnets in two Availability Zones?**
RDS requires a **DB subnet group spanning at least two AZs** for high
availability. We use `ap-south-1a` and `ap-south-1b`.

**Q: What is an Internet Gateway (IGW) and a Route Table?**
The IGW connects the VPC to the internet. The route table has a rule
`0.0.0.0/0 → IGW`, meaning "send all non-local traffic to the internet",
making the subnets public.

**Q: What is a Security Group? How is it different from a NACL?**
A Security Group is a **stateful** virtual firewall at the instance level — ours
opens TCP **3306** (MySQL). Stateful = return traffic is auto-allowed. A NACL is
**stateless** and operates at the subnet level.

**Q: Your security group allows 3306 from 0.0.0.0/0 — isn't that insecure?**
Yes — that is a deliberate weakness **for the demo** so we can connect and
simulate attacks from anywhere. In production you would restrict it to a known
IP/CIDR or keep the DB fully private. This is a good point to raise proactively.

### RDS (MySQL)

**Q: What is RDS? Why not host MySQL on EC2?**
RDS is a **managed** relational database service — AWS handles patching, backups,
and availability. It saves operational effort versus running MySQL yourself on
EC2.

**Q: What's in the database?**
A table `employee_data` with `emp_id, name, salary, email, department` — the
sensitive asset an attacker would want to steal.

**Q: What's a DB subnet group?**
A collection of subnets RDS can place the instance in; must cover ≥2 AZs.

**Q: Is the RDS data encrypted?**
Yes — `--storage-encrypted` enables encryption at rest.

### S3

**Q: What is S3? Why use it for logs?**
S3 is object storage — cheap, durable (11 nines), effectively unlimited. Perfect
for append-only log data that Athena reads directly.

**Q: What security is on the S3 bucket?**
1. **Block Public Access** (all four settings on).
2. **Default encryption** (SSE-S3 / AES-256 with a bucket key).
3. A **bucket policy** that lets only the CloudTrail service write logs.

**Q: What is the bucket policy for?**
It grants `cloudtrail.amazonaws.com` permission to `s3:GetBucketAcl` and
`s3:PutObject` (with `bucket-owner-full-control`) so CloudTrail can deliver logs
into our bucket — nothing else can write.

**Q: What is S3 versioning and why does it matter at teardown?**
Versioning keeps every version of an object. CloudTrail/Athena buckets often end
up versioned, so deleting requires removing all versions and delete markers —
that's why `teardown.sh` has a Python/boto3 purge pass.

### CloudTrail

**Q: What is CloudTrail?**
A service that records every API call (who did what, when, from which IP) as JSON
log files delivered to S3. It is the **audit backbone** of the project.

**Q: Management events vs data events?**
- **Management events** (default): control-plane actions — `RunInstances`,
  `PutBucketPolicy`, `ConsoleLogin`, etc.
- **Data events** (opt-in, extra cost): high-volume object-level actions —
  S3 `GetObject`/`PutObject`, Lambda invokes.
This distinction matters: the **bulk-download rule needs data events ON**,
because `GetObject` is a data event (demo-6 enables it).

**Q: What is a multi-region trail?**
`--is-multi-region-trail` captures activity from **all** AWS regions into the one
bucket. This is what makes the **unknown-region** detection possible.

**Q: What is log file validation?**
`--enable-log-file-validation` creates digest files so you can prove logs weren't
tampered with — important for an audit/forensics tool.

**Q: How long before logs appear?**
CloudTrail batches delivery — typically **5–15 minutes** of lag. This is the #1
thing to explain if a live query shows no results during the demo.

### Athena

**Q: What is Athena?**
A **serverless** interactive query service that runs standard SQL directly on
data in S3 — no database to load or manage. You pay **per query** (per TB
scanned).

**Q: How does Athena read CloudTrail's JSON?**
We create an **external table** `cloudtrail_logs` that maps columns
(`eventTime`, `eventName`, `sourceIPAddress`, `awsRegion`, …) onto the log files,
using a **SerDe**.

**Q: What is a SerDe? Why the special CloudTrail SerDe?**
SerDe = **Ser**ializer/**De**serializer — tells Athena how to parse each record.
CloudTrail wraps events in a `{"Records":[…]}` envelope; the generic JSON SerDe
would leave every column NULL, so we use
`com.amazon.emr.hive.serde.CloudTrailSerde`, which flattens the `Records[]`
array correctly.

**Q: What is an external table?**
A table definition (schema) that points at data already in S3. Athena reads it
in place — dropping the table doesn't delete the underlying data.

**Q: Where do Athena query results go?**
To `s3://<bucket>/athena-results/` — configured on the `primary` workgroup.

### SNS

**Q: What is SNS?**
Simple Notification Service — a **pub/sub** messaging service. Publishers send to
a **topic**; subscribers (here, an email endpoint) receive the message.

**Q: Why did you have to click a confirmation email?**
Email subscriptions must be **confirmed** by the recipient (double opt-in) before
SNS will deliver messages — prevents spamming arbitrary addresses.

### Lambda

**Q: What is Lambda?**
Serverless compute — runs your code (Python 3.12 here) on demand without
provisioning servers. You pay only for execution time.

**Q: What do your Lambdas do?**
- **`data-leak-alert-handler`** — the simple one: publishes a fixed alert message
  to SNS when invoked (used by `demo.sh`).
- **`DataLeakDetector`** — the smart one (automation layer): runs all **6 SQL
  rules** via Athena and publishes a structured alert **only if a rule matches**.

**Q: How does Lambda get permission to call Athena/SNS?**
Through an **IAM execution role** attached to the function. The detector's role
allows Athena, Glue (Athena's catalog), S3 (read logs / write results), and
`sns:Publish` — scoped to just what it needs (least privilege).

### IAM

**Q: What is an IAM role vs a user?**
A **user** is a permanent identity (a person/app) with long-term credentials. A
**role** is a temporary identity that AWS services *assume* to get short-lived
permissions — Lambda assumes its execution role.

**Q: What is a trust policy?**
The policy that says **who can assume the role**. Ours allows
`lambda.amazonaws.com` to assume it (`sts:AssumeRole`).

**Q: What is least privilege?**
Granting only the permissions actually needed. The detector role is scoped to
specific actions and, where possible, specific resources (the exact SNS topic
ARN, the exact bucket).

### EventBridge (automation layer)

**Q: What is EventBridge and what does it do here?**
An event bus / scheduler. We create a **rule** with a `rate(1 minute)` schedule
that **invokes the detector Lambda automatically**, so monitoring runs with no
human in the loop. (The design default is `rate(15 minutes)`; we use 1 minute so
the automatic alert is fast enough to show live in the demo.)

**Q: rate() vs cron()?**
`rate(1 minute)` = fixed interval. `cron(…)` = specific times (e.g. every day at
2 AM). We used `rate` for a simple periodic sweep.

**Q: Why is the schedule left disabled until the demo?**
The detector is **stateless** — each run re-evaluates all historical logs, so it
would keep re-alerting on the same old events every minute. We enable the rule
just before the demo and disable it after. (A production fix: scope each query to
a recent time window, or de-duplicate alerts.)

---

## 4. The 6 detection rules (know these cold)

Each rule is a SQL query over `cloudtrail_logs`; **any returned row = the rule
fires**.

| # | Rule | Threat it catches | SQL logic (plain English) |
|---|------|-------------------|---------------------------|
| 1 | **High-frequency access** | Automated scraping / a runaway stolen credential | Group by `sourceIPAddress`, flag any IP with `COUNT(*) > 50` |
| 2 | **Off-hours access** | Exfiltration while staff are asleep | `WHERE hour(eventTime) BETWEEN 0 AND 5` (UTC) |
| 3 | **Unknown region** | Attacker operating from another region | `WHERE awsRegion NOT IN ('ap-south-1')` |
| 4 | **Policy modification** | Weakening bucket security before a leak / tampering with the log bucket | `WHERE eventName IN ('PutBucketPolicy','PutBucketAcl')` |
| 5 | **Consecutive failed logins** | Brute-force / password guessing | `ConsoleLogin` with an error, `GROUP BY IP HAVING COUNT(*) >= 3` |
| 6 | **Bulk S3 download** | Mass data exfiltration | `eventName='GetObject'`, `GROUP BY IP HAVING COUNT(*) > 100` |

**Q: How would you add a 7th rule?**
Write one more SQL query in the detector Lambda's `RULES` list (e.g. detect
`DeleteTrail` — someone disabling logging). No infrastructure change needed —
that's the strength of the SQL approach.

**Q: Why threshold of 50 / 100 / 3?**
They're tunable heuristics chosen to separate normal from abnormal volume. In
production you'd baseline real traffic and set thresholds statistically (e.g.
mean + 3σ). Good to acknowledge they are demo values.

---

## 5. Security & domain concepts

**Q: What is a data leak / data exfiltration?**
Unauthorised movement of sensitive data out of a system. Exfiltration is the
"theft" step — e.g. downloading the whole `employee_data` table or bucket.

**Q: What is defense in depth?**
Multiple layers of security so no single failure is fatal — here: network
isolation (VPC/SG), encryption (S3 + RDS), least-privilege IAM, auditing
(CloudTrail), and detection (Athena rules).

**Q: Is this prevention or detection?**
Primarily **detection & alerting** (a monitoring/SIEM-style control). It doesn't
block the attack; it surfaces it fast so humans can respond. You could bolt on
prevention (auto-block an IP).

**Q: How is this like a SIEM?**
It mirrors a SIEM (Security Information and Event Management): collect logs →
correlate/query → alert. We built a lightweight one from managed AWS primitives.

**Q: What's the CIA triad and where does this fit?**
Confidentiality, Integrity, Availability. This project defends
**Confidentiality** (detecting data theft) and supports **Integrity** (log-file
validation, tamper detection).

---

## 6. Cost, cleanup & operations

**Q: What does this cost?**
Mostly the **RDS** instance (`db.t4g.micro`) while running, plus tiny CloudTrail,
S3, Athena (per-query), and Lambda charges. Serverless parts cost ~nothing when
idle. **`teardown.sh` deletes everything** to stop billing.

**Q: How do you tear it down safely?**
`./scripts/teardown.sh` removes resources in reverse dependency order
(automation → Lambdas/roles → SNS → Athena table → CloudTrail → RDS → S3 → SG →
route table → subnets → IGW → VPC). It's best-effort; re-run if a step was
skipped (e.g. RDS still deleting).

**Q: How is state tracked between scripts?**
`setup.sh` writes every resource ID to **`pbl-state.env`**; `demo.sh`,
`setup-automation.sh`, and `teardown.sh` source that file. That's why you must
not delete it until after teardown.

---

## 7. Limitations & future improvements

**Q: What are the limitations of your project?**
- **CloudTrail lag** (5–15 min) → not truly real-time.
- Detection thresholds are **static heuristics**, not ML-based.
- Rule 5 needs real **console** logins; rule 6 needs **data events** enabled.
- The SG open to `0.0.0.0/0` is intentionally insecure for the demo.
- It **detects** but doesn't **prevent/auto-remediate**.

**Q: How would you improve it?**
- Add **auto-remediation** (Lambda blocks the IP via a NACL / revokes creds).
- Use **Amazon GuardDuty** or ML anomaly detection instead of fixed thresholds.
- Push to a **dashboard** (QuickSight / OpenSearch) instead of email only.
- **Partition** the Athena table by date to cut query cost/time.
- Restrict the security group; move RDS to a private subnet.

**Q: Why not just use GuardDuty?**
GuardDuty is the managed AWS answer to this problem. We built it from primitives
to **learn** how CloudTrail + Athena + SQL detection actually work under the hood
— and it's fully customisable and cheaper for a fixed rule set.

---

## 8. Rapid-fire (one-liners)

- **Serverless services used?** Athena, Lambda, SNS, EventBridge (and S3).
- **Region?** `ap-south-1` (Mumbai).
- **DB engine?** MySQL 8.4 on RDS.
- **Lambda runtime?** Python 3.12.
- **How are logs stored?** Gzipped JSON in S3, under `AWSLogs/<account>/CloudTrail/`.
- **Query language for detection?** SQL (Presto/Trino dialect via Athena).
- **How is the detector triggered automatically?** EventBridge `rate(15 minutes)`.
- **What confirms an alert reached you?** An email from the SNS topic.
- **Encryption at rest?** S3 SSE-S3 (AES-256) and RDS storage encryption.
- **What proves logs are untampered?** CloudTrail log-file validation (digest files).
- **Stateful firewall?** Security Group (port 3306).
- **What flattens CloudTrail JSON for Athena?** The CloudTrail SerDe.

---

## 9. Live demo script (what to do & say tomorrow)

The model to convey: **the demo scripts are the *attacker*; detection & alerting
are automatic in the cloud.** You launch an attack; the `DataLeakDetector` Lambda
(EventBridge, every 1 min) runs the 6 SQL rules itself and emails on a match — you
never run a query.

1. **Show the architecture** (Section 2 diagram) — give the one-line story.
2. **Show the database** — connect and `SELECT * FROM employee_data;` to show the
   sensitive asset you're protecting.
3. **Arm the automatic detector** (~2 min before you start attacking):
   ```bash
   cd "/d/MCA/Cloud PBL" && source pbl-state.env
   aws events enable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"
   ```
4. **Launch an attack** — run an attacker script:
   ```bash
   cd scripts/demos && ./demo-1-high-frequency.sh
   ```
   Explain: it fires 60 API calls from one IP → CloudTrail logs them to S3. The
   script does **not** detect anything — it's just the attacker.
5. **Explain the CloudTrail lag:** logs take 5–15 min to reach S3, so the detector
   sees the attack shortly after. Your logs are **pre-warmed**, so the detector
   already has plenty to catch.
6. **Show the automatic alert** — the enabled schedule fires the detector every
   minute; show the **alert email** landing in the inbox. For an instant, on-demand
   proof, invoke the detector yourself (it still does the detection):
   ```bash
   aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" out.json && cat out.json
   # e.g. {"body": "2 rule(s) triggered; alert sent."}
   ```
7. **Walk the 6 rules** (Section 4 table) — one sentence each; note the SQL lives
   in the detector Lambda's `RULES` list.
8. **Disarm + mention teardown:**
   ```bash
   aws events disable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"
   ```
   and note you can destroy everything with `./scripts/teardown.sh` to avoid cost.

> **Pre-demo checklist:** confirm the **SNS email subscription** (or no alert
> arrives); logs are already pre-warmed, but you can re-run
> `./scripts/demos/run-all-demos.sh` for fresh activity; `enable-rule` ~2 min
> before you start and `disable-rule` after; keep the architecture diagram open.

> **Why the schedule is disabled by default:** the detector is stateless and would
> otherwise re-alert on the same historical logs every minute (see §3 EventBridge).
> Enabling it only around the demo keeps your inbox sane.
