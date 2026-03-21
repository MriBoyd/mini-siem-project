#!/usr/bin/env python3
"""
send_alert.py

Simple script to send one or many alert-style logs to the Mini-SIEM backend API.

Usage examples:
  python3 send_alert.py                      # send one sample alert to http://localhost:8080
  python3 send_alert.py --url http://127.0.0.1:8080 --api-key mykey
  python3 send_alert.py --count 10 --batch    # send 10 logs as a single batch

Requires: requests (`pip install requests`)
"""
import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

import requests


EVENT_TYPES = [
    "login_failed",
    "login_success",
    "alert_intrusion",
    "malware_detected",
    "suspicious_activity",
]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "DEBUG"]


def make_log(i=0):
    now = datetime.now(timezone.utc).isoformat()
    src_ip = "198.51.100.%d" % (random.randint(1, 250))
    event = "malware_detected"
    severity = "CRITICAL"
    msg = f"Test alert {i} - {event} detected from {src_ip}"

    return {
        "event_type": event,
        "source_ip": src_ip,
        "target_user": None,
        "service": "auth",
        "message": msg,
        "severity": severity,
        "timestamp": now,
    }


def post_single(url, payload, api_key=None, timeout=5):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    r = requests.post(url.rstrip("/") + "/api/v1/logs/ingest", json=payload, headers=headers, timeout=timeout)
    return r


def post_batch(url, payloads, api_key=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    body = {"logs": payloads}
    r = requests.post(url.rstrip("/") + "/api/v1/logs/batch", json=body, headers=headers, timeout=timeout)
    return r


def main():
    p = argparse.ArgumentParser(description="Send alert logs to Mini-SIEM backend")
    p.add_argument("--url", default="http://localhost:8080", help="Base URL of the backend API")
    p.add_argument("--api-key", default=None, help="X-API-Key header value (optional)")
    p.add_argument("--count", type=int, default=1, help="Number of logs to send")
    p.add_argument("--batch", action="store_true", help="Send logs as a single batch request")
    p.add_argument("--interval", type=float, default=0.1, help="Interval between sends when not batching")

    args = p.parse_args()

    if args.count <= 0:
        print("--count must be >= 1")
        sys.exit(2)

    if args.batch and args.count == 1:
        # still valid: batch with single entry
        pass

    logs = [make_log(i + 1) for i in range(args.count)]

    try:
        if args.batch:
            print(f"Sending batch of {len(logs)} logs to {args.url}/api/v1/logs/batch")
            r = post_batch(args.url, logs, api_key=args.api_key)
            print(r.status_code, r.text)
        else:
            for i, l in enumerate(logs, start=1):
                print(f"Sending log {i}/{len(logs)} to {args.url}/api/v1/logs/ingest")
                r = post_single(args.url, l, api_key=args.api_key)
                print(r.status_code, r.text)
                if i < len(logs):
                    time.sleep(args.interval)
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
