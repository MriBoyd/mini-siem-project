#!/usr/bin/env python3
"""
Run the Mini-SIEM reliability drills and print the resulting reports.

Usage examples:
  python3 reliability_drill.py --url http://localhost:8080 --token <jwt>
  python3 reliability_drill.py --url http://127.0.0.1:8080 --token <jwt> --skip-chaos

The script calls the backend drill endpoints, which store timestamped reports
for replay and chaos proof records.
"""

import argparse
import json
import sys

import requests


def headers(token: str | None) -> dict[str, str]:
    result = {"Content-Type": "application/json"}
    if token:
        result["Authorization"] = f"Bearer {token}"
    return result


def post(url: str, path: str, token: str | None):
    response = requests.post(url.rstrip("/") + path, headers=headers(token), json={})
    response.raise_for_status()
    return response.json()


def get(url: str, path: str, token: str | None):
    response = requests.get(url.rstrip("/") + path, headers=headers(token), timeout=15)
    response.raise_for_status()
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Mini SIEM reliability drills")
    parser.add_argument("--url", default="http://localhost:8080", help="Backend base URL")
    parser.add_argument("--token", default=None, help="JWT access token")
    parser.add_argument("--skip-chaos", action="store_true", help="Skip the chaos drill")
    parser.add_argument("--skip-replay", action="store_true", help="Skip the replay drill")
    args = parser.parse_args()

    results = {}

    try:
        if not args.skip_replay:
            results["replay"] = post(args.url, "/api/v1/reliability/drills/replay", args.token)
        if not args.skip_chaos:
            results["chaos"] = post(args.url, "/api/v1/reliability/drills/chaos", args.token)
        results["overview"] = get(args.url, "/api/v1/reliability/overview", args.token)
    except requests.RequestException as exc:
        print(f"Reliability drill failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())