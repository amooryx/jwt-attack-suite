# JWT Attack Suite

A Python-based utility designed to security-audit JSON Web Tokens (JWT) for common configuration flaws, signature bypasses, and validation weaknesses.

## 📋 Features

- **Algorithm Bypasses (`alg:none`)**: Evaluates if the backend incorrectly validates unsigned tokens.
- **Weak HMAC Key Detection**: Audits signature strength against a list of common secrets.
- **Key ID (`kid`) Header Check**: Tests lookup behavior for injection or path traversal vectors.
- **RS256 to HS256 Confusion**: Audits if asymmetric signatures can be verified using symmetric verification logic.

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/amooryx/jwt-attack-suite.git
   cd jwt-attack-suite
   ```

2. Install Python dependencies:
   ```bash
   pip install PyJWT cryptography
   ```

## 🚀 Usage

Run the utility by providing a target JWT token for passive verification checks:

```bash
python main.py <JWT_TOKEN>
```

For advanced arguments and key dictionary checks:

```bash
python main.py --help
```

## 🛡️ Disclaimer

This tool is designed for educational and security compliance auditing purposes only. Ensure you have authorized permission prior to running scans against active environments.
