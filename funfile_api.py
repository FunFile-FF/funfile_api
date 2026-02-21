#!/usr/bin/env python3
"""
FunFile API CLI
Module: seedboxip
"""

import argparse
import json
import sys
import time
import ipaddress
import requests
from pathlib import Path
import hmac
import hashlib
from urllib.parse import urlparse

CONFIG_PATH = Path(__file__).parent / "config.json"
ALLOWED_HOSTS = ["www.funfile.org"]

# -------------------------
# CONFIG LOADING
# -------------------------
def load_config():
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def resolve_credentials(args):
    cfg = load_config()
    api_key = args.api_key or cfg.get("api_key")
    secret = args.secret or cfg.get("secret")
    base_url = args.base_url or cfg.get("base_url", "https://www.funfile.org/api")

    if not api_key or not secret:
        sys.exit("API key and secret must be provided via config.json or CLI flags")
    return api_key, secret, base_url.rstrip("/")

# -------------------------
# IP VALIDATION
# -------------------------
def validate_public_ip(ip_str: str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        sys.exit(f"Invalid IP address: {ip_str}")

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        sys.exit(f"Blocked non-public IP address: {ip_str}")
    return ip_str

def parse_ips(ips_arg):
    if not ips_arg:
        return None
    ips = []
    for ip in ips_arg.split(","):
        ip = ip.strip()
        if not ip:
            continue
        ips.append(validate_public_ip(ip))
    return ips

def detect_public_ip():
    try:
        r = requests.get("https://api.ipify.org", timeout=5)
        ip = r.text.strip()
        return validate_public_ip(ip)
    except Exception:
        sys.exit("Could not detect public IP")

# -------------------------
# HMAC SIGNING
# -------------------------
def sign_request(secret, timestamp, body=None):
    payload = str(timestamp)
    if body:
        payload += body
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

# -------------------------
# URL VALIDATION
# -------------------------
def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        sys.exit(f"Blocked invalid URL scheme: {parsed.scheme}")
    if parsed.hostname not in ALLOWED_HOSTS:
        sys.exit(f"Blocked request to unapproved host: {parsed.hostname}")
    return url

# -------------------------
# API REQUESTS
# -------------------------
def api_request(method, url, api_key, secret, body=None):
    url = validate_url(url)  # <- validate host
    timestamp = int(time.time())
    signature = sign_request(secret, timestamp, body=json.dumps(body) if body else None)
    headers = {
        "X-API-Key": api_key,
        "X-Timestamp": str(timestamp),
        "X-Signature": signature,
        "Content-Type": "application/json"
    }
    try:
        if method.upper() == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        else:
            r = requests.post(url, headers=headers, json=body, timeout=10)
        return r
    except Exception as e:
        sys.exit(f"Request failed: {e}")

# -------------------------
# SEEDBOX IP MODULE
# -------------------------
def seedboxip_module(args, api_key, secret, base_url):
    endpoint = f"{base_url}/v1/seedbox-ips"

    if args.action == "list":
        r = api_request("GET", endpoint, api_key, secret)
    else:
        ips = parse_ips(args.ips) if args.ips else [detect_public_ip()]
        body = {"seedbox_ips": ips}
        if args.action == "add":
            r = api_request("POST", f"{endpoint}/add", api_key, secret, body)
        elif args.action == "remove":
            r = api_request("POST", f"{endpoint}/remove", api_key, secret, body)
        elif args.action == "replace":
            r = api_request("POST", f"{endpoint}/replace", api_key, secret, body)
        else:
            sys.exit(f"Unknown action: {args.action}")

    print(f"Status: {r.status_code}\n")
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text)

# -------------------------
# ARGUMENT PARSING
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="FunFile API CLI")
    parser.add_argument("--api-key", help="Public API key")
    parser.add_argument("--secret", help="Secret key")
    parser.add_argument("--base-url", help="API base URL")

    subparsers = parser.add_subparsers(dest="module", required=True)

    # Seedbox IP module
    sb_parser = subparsers.add_parser("seedboxip", help="Manage seedbox IPs")
    sb_parser.add_argument("action", choices=["list", "add", "remove", "replace"], help="Action to perform")
    sb_parser.add_argument("--ips", help="Comma-separated IPs")

    args = parser.parse_args()

    api_key, secret, base_url = resolve_credentials(args)

    if args.module == "seedboxip":
        seedboxip_module(args, api_key, secret, base_url)
    else:
        sys.exit(f"Unknown module: {args.module}")

if __name__ == "__main__":
    main()

