"""
DataLeakDetector - the automatic detection Lambda.

Triggered by the EventBridge schedule (or invoked manually via scripts/demo.sh),
it runs the 6 SQL detection rules against the `cloudtrail_logs` Athena table and
publishes an SNS alert whenever a rule returns >= 1 row.

Each rule is SCOPED TO THE LAST `DETECT_WINDOW_MIN` MINUTES, so historical logs
that already contain the same attack patterns do NOT keep re-triggering every
run. A fresh demo therefore only shows the case(s) you just triggered.

Configuration comes from environment variables (set by scripts/setup-automation.sh):
    REGION            - AWS region, e.g. ap-south-1
    S3_BUCKET         - bucket holding CloudTrail logs + the athena-results/ prefix
    SNS_TOPIC_ARN     - SNS topic to publish alerts to
    DETECT_WINDOW_MIN - lookback window in minutes (default: 20)

TEAMMATES: edit this file, then run  scripts/update-detector.sh  to deploy it.
Only the Lambda code/config is updated - no infrastructure is recreated.
"""
import os
import time

import boto3

REGION     = os.environ["REGION"]
S3_BUCKET  = os.environ["S3_BUCKET"]
TOPIC_ARN  = os.environ["SNS_TOPIC_ARN"]
WINDOW_MIN = int(os.environ.get("DETECT_WINDOW_MIN", "20"))

DATABASE   = "default"
WORKGROUP  = "primary"
OUTPUT_LOC = f"s3://{S3_BUCKET}/athena-results/"

athena = boto3.client("athena", region_name=REGION)
sns    = boto3.client("sns", region_name=REGION)

# Only consider events from the last WINDOW_MIN minutes. This is the one line
# that makes old attack patterns "age out" so each demo shows fresh cases only.
RECENT = (
    "from_iso8601_timestamp(eventTime) > "
    f"(current_timestamp - interval '{WINDOW_MIN}' minute)"
)

# Each rule: (name, human-readable trigger, SQL). ANY returned row => rule fired.
RULES = [
    ("High-Frequency Access", f">50 requests / IP in the last {WINDOW_MIN} min",
     "SELECT sourceIPAddress, COUNT(*) AS access_count "
     "FROM cloudtrail_logs "
     f"WHERE {RECENT} "
     "GROUP BY sourceIPAddress HAVING COUNT(*) > 50"),
    ("Off-Hours Access", "activity between 00:00-05:00 UTC",
     "SELECT eventTime, eventSource, eventName, sourceIPAddress "
     "FROM cloudtrail_logs "
     "WHERE hour(from_iso8601_timestamp(eventTime)) BETWEEN 0 AND 5 "
     f"AND {RECENT}"),
    ("Unknown Region", "API calls from unauthorized regions",
     "SELECT awsRegion, COUNT(*) AS cnt FROM cloudtrail_logs "
     f"WHERE awsRegion NOT IN ('{REGION}') AND {RECENT} "
     "GROUP BY awsRegion"),
    ("Policy Modification", "PutBucketPolicy / PutBucketAcl events",
     "SELECT eventTime, eventName, sourceIPAddress, awsRegion "
     "FROM cloudtrail_logs "
     "WHERE eventName IN ('PutBucketPolicy', 'PutBucketAcl') "
     f"AND {RECENT}"),
    ("Consecutive Failed Logins", ">=3 ConsoleLogin failures",
     "SELECT sourceIPAddress, COUNT(*) AS fails FROM cloudtrail_logs "
     "WHERE eventName = 'ConsoleLogin' AND errorMessage IS NOT NULL "
     f"AND {RECENT} "
     "GROUP BY sourceIPAddress HAVING COUNT(*) >= 3"),
    ("Bulk S3 Download", ">100 GetObject calls",
     "SELECT sourceIPAddress, COUNT(*) AS downloads FROM cloudtrail_logs "
     f"WHERE eventName = 'GetObject' AND {RECENT} "
     "GROUP BY sourceIPAddress HAVING COUNT(*) > 100"),
]


def run_query(sql):
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": DATABASE},
        ResultConfiguration={"OutputLocation": OUTPUT_LOC},
        WorkGroup=WORKGROUP,
    )["QueryExecutionId"]

    # poll up to ~50s for completion
    state = "RUNNING"
    for _ in range(25):
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2)

    if state != "SUCCEEDED":
        print(f"  query {state}: {sql[:60]}...")
        return []

    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    # row[0] is the header; data rows are everything after it
    return rows[1:]


def lambda_handler(event, context):
    triggered = []

    # Optional: scope this run to a SINGLE rule by passing {"rule": "<name>"} in
    # the invoke payload (used by the per-demo triggers so running one attacker
    # script only alerts on that one case, regardless of other logs in the
    # window). Matching is case-insensitive substring, so {"rule": "region"}
    # selects "Unknown Region". No "rule" key => run all 6 rules.
    wanted = ""
    if isinstance(event, dict) and event.get("rule"):
        wanted = str(event["rule"]).strip().lower()

    active_rules = RULES
    if wanted:
        active_rules = [r for r in RULES if wanted in r[0].lower()]
        if not active_rules:
            names = ", ".join(r[0] for r in RULES)
            print(f"No rule matches '{wanted}'. Available: {names}")
            return {"statusCode": 400, "body": f"No rule matches '{wanted}'."}
        print(f"Scoped to rule(s): {', '.join(r[0] for r in active_rules)}")

    for name, trigger, sql in active_rules:
        try:
            data_rows = run_query(sql)
        except Exception as e:
            print(f"Rule '{name}' query error: {e}")
            continue

        if data_rows:
            first = [c.get("VarCharValue", "") for c in data_rows[0]["Data"]]
            triggered.append({
                "rule": name,
                "trigger": trigger,
                "match_count": len(data_rows),
                "sample": ", ".join(first),
            })

    if not triggered:
        print("No anomalies detected this cycle.")
        return {"statusCode": 200, "body": "No anomalies detected."}

    lines = [
        "SECURITY ALERT - SUSPICIOUS ACTIVITY DETECTED",
        "=" * 45,
        "",
        f"{len(triggered)} detection rule(s) triggered in the last {WINDOW_MIN} min:",
        "",
    ]
    for t in triggered:
        lines += [
            f"Rule Triggered : {t['rule']}",
            f"Condition      : {t['trigger']}",
            f"Matches        : {t['match_count']}",
            f"Sample         : {t['sample']}",
            "-" * 45,
        ]
    lines += [
        "",
        "Recommended Action:",
        "  -> Review CloudTrail logs immediately",
        "  -> Block source IP if unauthorized",
        "  -> Check IAM credentials for compromise",
    ]
    message = "\n".join(lines)

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject="[SECURITY] Data Leak Alert",
        Message=message,
    )
    print(f"Alert published: {len(triggered)} rule(s) triggered.")
    return {"statusCode": 200, "body": f"{len(triggered)} rule(s) triggered; alert sent."}
