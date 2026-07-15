#!/usr/bin/env bash
#==============================================================================
# CASE 1 - HIGH-FREQUENCY ACCESS
#
#   Rule    : one source IP makes an unusually large number of API calls.
#   Trigger : > 50 events from the same sourceIPAddress.
#   Real-world meaning: an attacker (or a runaway script using stolen
#   credentials) hammering the account - scraping, enumerating, exfiltrating.
#
# HOW THIS DEMO TRIGGERS IT
#   We fire ~60 harmless read-only AWS API calls from THIS machine. Every call
#   is recorded by CloudTrail with our public IP as sourceIPAddress, so the
#   "> 50 events from one IP" rule matches.
#
# Usage:  ./demo-1-high-frequency.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

for i in $(seq 1 60); do
  aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1
done
