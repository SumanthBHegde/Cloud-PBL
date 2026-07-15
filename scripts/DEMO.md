# `demo.sh` — one-command detection trigger

`demo.sh` is the **manual trigger** for the data-leak detector. The attacker
scripts in `demos/` only *generate* suspicious activity; they never detect or
alert. Detection is done in the cloud by the **DataLeakDetector Lambda**, which
runs the 6 SQL rules in Athena and emails the SNS topic when a rule matches.
`demo.sh` is how you fire that Lambda on demand during a live demo.

## Why not just let it run automatically?

There is an EventBridge schedule (`rate(1 minute)`) that can invoke the detector
automatically, but it is kept **DISABLED on purpose**. The detector is
*stateless* — it has no memory of what it already alerted on. Each run scans the
last `DETECT_WINDOW_MIN` minutes (default **20**). If the schedule ran every
minute, a single anomaly would sit inside that 20-minute window for 20 minutes
and be re-emailed on **every one of those ~20 runs** → inbox spam.

> The 20-minute window ages out *old* logs correctly. It cannot stop the *same
> recent* anomaly from being re-reported each minute. That is why the schedule
> stays off and we trigger detection by hand instead.

If you ever see minute-by-minute alerts, the schedule got enabled. Turn it off:

```bash
source pbl-state.env
aws events disable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"
```

## Usage

Run from the project root (or `scripts/`):

```bash
# 1. Run all attacker scenarios, then trigger detection on ALL 6 rules
./scripts/demo.sh

# 2. Trigger detection only (no attackers) on already-delivered logs, all rules
./scripts/demo.sh --skip-attacks

# 3. Trigger ONLY one case -> exactly one alert for that case
./scripts/demo.sh --case region
```

### Single-case mode (`--case`)

`--case <name>` tells the detector to run **only that one rule**, so no matter
what other patterns exist in the log window, only the case you chose can alert.
This is the flow for "run this demo → only this case fires."

| `--case` name | Detection rule | Attacker that generates it |
|---------------|----------------|-----------------------------|
| `frequency`   | High-Frequency Access (>50 req/IP) | `demos/demo-1-high-frequency.sh` |
| `off-hours`   | Off-Hours Access (00:00–05:00 UTC) | `demos/demo-2-off-hours.sh` |
| `region`      | Unknown Region | `demos/demo-3-unknown-region.sh` |
| `policy`      | Policy Modification (PutBucketPolicy/Acl) | `demos/demo-4-policy-modification.sh` |
| `failed`      | Consecutive Failed Logins (≥3) | `demos/demo-5-failed-logins.sh` |
| `bulk`        | Bulk S3 Download (>100 GetObject) | `demos/demo-6-bulk-download.sh` |

The name is a case-insensitive substring match, so `--case region` selects
"Unknown Region".

## Recommended demo flow

Because CloudTrail delivers events to S3 with a **5–15 minute lag**, freshly
generated activity is not queryable immediately. Plan around it:

1. Run the attacker for the case ~10 min early, e.g.
   `bash scripts/demos/demo-3-unknown-region.sh`
   (or `bash scripts/demos/run-all-demos.sh` for all cases at once).
2. Wait ~10–15 min for CloudTrail to deliver the logs to S3.
3. Trigger the single case: `./scripts/demo.sh --case region` → one email.

Leave the EventBridge schedule **disabled** the whole time.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Alert emails every minute | The EventBridge schedule is enabled. Disable it (command above). |
| Every case alerts at once | You invoked with all rules and multiple patterns are in the window. Use `--case <name>` to scope to one. |
| `--case` returns "No anomalies detected" | That case's activity hasn't been delivered by CloudTrail yet (5–15 min lag), or it aged out of the 20-min window. Re-run the attacker and wait. |
| "No rule matches '<name>'" | Bad `--case` name. Use one from the table above. |
| No email at all | SNS subscription not confirmed, or nothing matched. Check the inbox for `$SNS_TOPIC_ARN` and confirm the subscription. |

## Related

- `demos/` — the attacker scripts and their README.
- `detector/lambda_function.py` — the detector code (the 6 SQL rules + `--case` scoping).
- `update-detector.sh` — redeploy the detector after editing that file.
