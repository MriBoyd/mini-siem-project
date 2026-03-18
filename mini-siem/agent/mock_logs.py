#!/usr/bin/env python3
# mock_logs.py — safe generator of failed-login logs (writes JSON Lines)

import argparse, time, uuid, json
from datetime import datetime, timezone

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def make_log(ip, idx):
    return {
        "id": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "event_type": "login_failed",
        "source_ip": ip,
        "target_user": f"user{idx%5}",
        "service": "sshd",
        "message": f"Failed password for invalid user user{idx%5} from {ip} port 22 ssh2",
        "severity": "INFO",
        "metadata": {},
        "received_at": now_iso(),
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="/tmp/siem-agent-test.log", help="output log file (appended)")
    p.add_argument("--ip", default="192.0.2.10", help="source IP to simulate")
    p.add_argument("--attempts", type=int, default=20, help="number of failed attempts")
    p.add_argument("--interval", type=float, default=0.5, help="seconds between attempts")
    args = p.parse_args()

    with open(args.out, "a", encoding="utf-8") as f:
        for i in range(args.attempts):
            log = make_log(args.ip, i)
            f.write(json.dumps(log) + "\n")
            f.flush()
            time.sleep(args.interval)

if __name__ == "__main__":
    main()