<p align="center">
  <img src="ShinNexus-Shield-edel.png" width="200" alt="ShinNexus Shield">
</p>

<h1 align="center">ShinNexus</h1>
<p align="center"><strong>Decentralized Identity Service</strong></p>
<p align="center"><em>Same Knowledge. Your Ownership.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.5.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/bitcoin-chain--of--trust-f59e0b" alt="Bitcoin Verified">
  <img src="https://img.shields.io/badge/crypto-ML--DSA--65%20%2B%20ML--KEM--768-7ab8e0" alt="PQ Crypto">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-green" alt="License">
</p>

---

## What is ShinNexus?

ShinNexus is a self-hosted, decentralized identity service. You own your identity. No cloud. No corporation. No middleman.

Every version is anchored on the **Bitcoin blockchain** via OP_RETURN — tamper-proof, verifiable by anyone, forever.

## Features

- **Bitcoin Chain-of-Trust** — Code-hash anchored on-chain (`SHINPAI-AI:version:hash`). Every instance verifies itself against the blockchain at startup and every 6 hours.
- **Whitelist System** — Trust network between Nexus instances. Public GET, Smart-Paste import, migration gatekeeping.
- **Revoke Broadcast** — Revoked versions are detected automatically by scanning the anchor wallet's transactions.
- **Post-Quantum Cryptography** — ML-DSA-65 (signatures) + ML-KEM-768 (key encapsulation). Future-proof against quantum attacks.
- **AES-256-GCM Vault** — All sensitive data encrypted at rest, machine-bound.
- **Migration** — Move your identity between Nexus instances. Whitelist-verified, transport-encrypted, PQ-signed.
- **2FA (TOTP)** — Mandatory for all accounts. QR + manual secret.
- **Recovery Seed** — 24-word BIP39 seed for account recovery.
- **Self-Hosted** — Runs on any machine. No external dependencies except Python.

## Installation

### Linux (AppImage)

Download `ShinNexus-x86_64.AppImage` from [Releases](https://github.com/Shinpai-AI/ShinNexus/releases), then:

```bash
chmod +x ShinNexus-x86_64.AppImage
./ShinNexus-x86_64.AppImage
```

Installs via Zenity dialog with folder selection. Creates desktop shortcut and system tray icon.

### Windows (Installer)

Download `ShinNexus-Setup.exe` from [Releases](https://github.com/Shinpai-AI/ShinNexus/releases) and run it. Includes embedded Python — no system Python needed. Creates Start Menu shortcut, desktop icon, and system tray. Configures Windows Firewall automatically.

### Android (Termux)

Install [Termux](https://github.com/termux/termux-app/releases) from GitHub (not Play Store!), then run:

```bash
curl -sL https://raw.githubusercontent.com/Shinpai-AI/ShinNexus/main/installer/android/install-termux.sh | bash
```

Start afterwards with: `bash ~/shinnexus-start.sh`

**Note:** Requires a device with at least 4 GB RAM (Android 2020+). Older devices may fail to compile the cryptography package.

### Manual (any platform)

```bash
git clone https://github.com/Shinpai-AI/ShinNexus.git
cd ShinNexus
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
python3 ShinNexus.py
```

Open `https://localhost:12345` — first account becomes Owner.

## Bitcoin Verification

Every ShinNexus instance verifies its own code integrity against the Bitcoin blockchain:

1. `anchor-nexus.json` contains the TXID of the on-chain anchor
2. At startup, the instance fetches the TX from mempool.space
3. Compares the OP_RETURN hash with its own `sha256(ShinNexus.py)`
4. **Match** = green footer "On-chain verified"
5. **Mismatch** = red footer "Tampering detected"

You can verify any instance yourself:
- Click the footer to copy `Version + Hash + TXID`
- Check the TXID on [mempool.space](https://mempool.space)
- Compare the OP_RETURN data with the file hash

## Architecture

```
ShinNexus.py          — Single-file application (~16k lines)
anchor-nexus.json     — Bitcoin chain-of-trust certificate
anchor-kneipe.json    — Cross-program trust (Kneipe anchor)
requirements.txt      — Python dependencies
start.sh              — Service management (start/stop/restart/status/logs)
```

No database server required. SQLite + JSON + encrypted vault files.

## Security

| Layer | Technology |
|-------|-----------|
| Signatures | ML-DSA-65 (Post-Quantum) |
| Key Exchange | ML-KEM-768 (Post-Quantum) |
| Vault | AES-256-GCM (machine-bound) |
| Passwords | Argon2 / PBKDF2 |
| Transport | TLS + PQ-signed payloads |
| Chain-of-Trust | Bitcoin OP_RETURN |
| 2FA | TOTP (mandatory) |

## License

This project is licensed under the **GNU Affero General Public License v3.0** — see [LICENSE](LICENSE) for details.

If you fork this project, you **must** publish your modified source code under the same license.

---

<p align="center">
  <strong>Shinpai-AI</strong><br>
  <em>Ist einfach passiert.</em>
</p>
