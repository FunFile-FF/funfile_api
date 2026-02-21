#!/usr/bin/env python3

import os
import sys
import json
import time
import hmac
import hashlib
import argparse
import requests

# ==========================================================
# CONFIG
# ==========================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")


def load_config():
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}


def resolve_credentials(args):
    config = load_config()

    api_key = args.api_key or config.get("api_key")
    secret = args.secret or config.get("secret")
    base_url = args.base_url or config.get(
        "base_url", "https://www.funfile.org/api"
    )

    if not api_key or not secret:
        print("❌ API key or secret missing.")
        sys.exit(1)

    return api_key, secret, base_url.rstrip("/")


# ==========================================================
# HMAC
# ==========================================================

def build_signature(secret, timestamp, body=None):
    payload = str(timestamp)
    if body:
        payload += body

    return hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


# ==========================================================
# CORE API REQUEST
# ==========================================================

def api_request(method, endpoint, api_key, secret, base_url, body_dict=None):
    url = f"{base_url}{endpoint}"
    timestamp = int(time.time())

    body_json = json.dumps(body_dict) if body_dict else None
    signature = build_signature(secret, timestamp, body_json)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Timestamp": str(timestamp),
        "X-Signature": signature,
    }

    if method == "GET":
        return requests.get(url, headers=headers)

    return requests.post(url, headers=headers, data=body_json)


# ==========================================================
# UTIL
# ==========================================================

def detect_public_ip():
    try:
        r = requests.get("https://api.ipify.org", timeout=5)
        return r.text.strip()
    except Exception:
        return None


def print_response(response):
    print(f"\nStatus: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2))
    except Exception:
        print(response.text)


# ==========================================================
# SEEDBOX IP COMMANDS
# ==========================================================

def handle_seedboxip(args):
    api_key, secret, base_url = resolve_credentials(args)

    if args.action == "list":
        response = api_request(
            "GET",
            "/v1/seedbox-ips",
            api_key,
            secret,
            base_url
        )
        print_response(response)
        return

    # For add/remove/replace
    if args.ips:
        ip_list = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
    else:
        auto_ip = detect_public_ip()
        if not auto_ip:
            print("❌ No IP provided and failed to detect public IP.")
            sys.exit(1)
        print(f"Auto-detected public IP: {auto_ip}")
        ip_list = [auto_ip]

    body = {"seedbox_ips": ip_list}

    endpoint_map = {
        "add": "/v1/seedbox-ips/add",
        "remove": "/v1/seedbox-ips/remove",
        "replace": "/v1/seedbox-ips/replace",
    }

    response = api_request(
        "POST",
        endpoint_map[args.action],
        api_key,
        secret,
        base_url,
        body
    )

    print_response(response)


# ==========================================================
# MAIN CLI
# ==========================================================

def main():
    parser = argparse.ArgumentParser(
        prog="funfile",
        description="FunFile API CLI"
    )

    parser.add_argument("--api-key")
    parser.add_argument("--secret")
    parser.add_argument("--base-url")

    subparsers = parser.add_subparsers(dest="module")

    # ---- seedboxip module ----
    seedbox_parser = subparsers.add_parser(
        "seedboxip",
        help="Manage seedbox IPs"
    )

    seedbox_sub = seedbox_parser.add_subparsers(dest="action")

    for action in ["list", "add", "remove", "replace"]:
        action_parser = seedbox_sub.add_parser(action)
        if action != "list":
            action_parser.add_argument(
                "--ips",
                help="Single or comma-separated IPs"
            )

    args = parser.parse_args()

    if args.module == "seedboxip":
        handle_seedboxip(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

