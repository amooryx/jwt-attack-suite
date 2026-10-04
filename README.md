<div align="center">
  <img src="./banner.svg" alt="jwt-attack-suite" width="800">
</div>

# JWT Attack Suite

A Python CLI for offline JWT inspection and controlled, authorized audit probes. It generates candidate tokens for common validation checks; candidate generation is not evidence that a server accepts a token or is vulnerable.

## Checks

- Generate `alg:none`, claim-tampering, `kid` lookup, and (when supplied an RSA public key) RS256-to-HS256 candidates.
- Check HS256 signatures against a small built-in list and an optional wordlist. A matching secret is reported without printing its value.
- Optionally send candidates to a target. Responses are reported as inconclusive because HTTP status codes alone cannot establish JWT acceptance or a bypass.

## Installation

Python 3.8 or newer is required.

```bash
python -m pip install -r requirements.txt
```

## Usage

Show safe token metadata without running checks:

```bash
python main.py --token '<JWT>' --info
```

Generate candidates and run offline checks (no network requests):

```bash
python main.py --token '<JWT>' --attack all
```

To perform active probes, provide the target and explicitly acknowledge authorization:

```bash
python main.py --token '<JWT>' --attack none \
  --url https://your-authorized-target.example/endpoint --authorized
```

The tool verifies TLS certificates, uses bounded timeouts, does not follow redirects, and sends the token in the selected header as a Bearer credential. Do not use `--url` unless you have permission to test that specific system. Use `python main.py --help` for all options.

Token contents and matched secret values are not printed. Treat the input token, any generated candidates, and any wordlist as sensitive.

## Disclaimer

Use only against systems and tokens you are explicitly authorized to assess. This tool is intended for controlled security auditing, not for accessing systems without permission.
