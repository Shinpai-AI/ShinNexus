#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShinNexus — Portable Identity Service
Die vierte Säule von Projekt SAI: Dein digitaler Personalausweis.

Phase N1 MVP:
  - Account erstellen (Name + Email + Keypair)
  - Shinpai-ID generieren
  - Vault (AES-256-GCM, Passwort-basiert)
  - HTTP-Server (GET /api/identity, /api/ping)
  - Challenge-Response (/api/verify)
  - Config (Port, Einstellungen)

(c) 2026 Shinpai-AI — Same Knowledge. Your Ownership.
"""

import os
import sys
import ssl
import json
import hashlib
import secrets
import threading
import time
import getpass
import base64
import re
from pathlib import Path
from datetime import datetime, date
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
import urllib.request
import urllib.error

# ── Crypto (PFLICHT — kein Fallback!) ──────────────────────────────
import oqs
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── Optional ───────────────────────────────────────────────────────
try:
    from argon2 import PasswordHasher
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

try:
    import pyotp
    HAS_TOTP = True
except ImportError:
    HAS_TOTP = False

try:
    import segno
    import io as _io
    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    import segno
    HAS_SEGNO = True
except ImportError:
    HAS_SEGNO = False

try:
    import stripe as _stripe_mod
    HAS_STRIPE = True
except ImportError:
    HAS_STRIPE = False
    _stripe_mod = None

import subprocess
import shutil
import signal

# ══════════════════════════════════════════════════════════════════════
#  KONSTANTEN & PFADE
# ══════════════════════════════════════════════════════════════════════

VERSION = "1.5.5"  # V1.5.5: Owner-Migration, Nexus-Dissolve, UI-Polish, Neon-LED, Bot-Counter, Member-Sort, Veriff-Toggle
APP_NAME = "ShinNexus"
DEFAULT_PORT = 12345


# ══════════════════════════════════════════════════════════════════════
#  ICON-ASSETS — Bronze-Gold-SVG (inline, ohne extra Assets)
#  Werden in UI-Kontexten per .format(size=...) oder direkt eingebettet.
# ══════════════════════════════════════════════════════════════════════

# Bot-Icon (Klassisch, Antenne + rechteckiger Kopf — Bot-#7 aus Preview)
BOT_ICON_SVG = '<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style="filter:drop-shadow(0 0 4px rgba(212,168,80,0.4));"><line x1="32" y1="6" x2="32" y2="14" stroke="#d4a850" stroke-width="3"/><circle cx="32" cy="5" r="3" fill="#e8c464"/><rect x="14" y="16" width="36" height="30" rx="5" fill="rgba(212,168,80,0.08)" stroke="#d4a850" stroke-width="3"/><circle cx="24" cy="30" r="4" fill="#e8c464"/><circle cx="40" cy="30" r="4" fill="#e8c464"/><line x1="22" y1="38" x2="42" y2="38" stroke="#d4a850" stroke-width="2.5"/><line x1="20" y1="46" x2="20" y2="54" stroke="#d4a850" stroke-width="3"/><line x1="44" y1="46" x2="44" y2="54" stroke="#d4a850" stroke-width="3"/></svg>'

# Kind-Icon (Baby mit Schnuller + Pausbacken — Kind-#2 aus Preview)
# Wird aktiviert sobald die Perso+KK-basierte Account-Typ-Ableitung steht.
KIND_ICON_SVG = '<svg width="{size}" height="{size}" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style="filter:drop-shadow(0 0 4px rgba(212,168,80,0.4));"><path d="M 28 12 Q 32 4 36 12" fill="none" stroke="#d4a850" stroke-width="3"/><circle cx="32" cy="30" r="18" fill="rgba(212,168,80,0.08)" stroke="#d4a850" stroke-width="3"/><path d="M 22 28 Q 25 26 28 28" stroke="#d4a850" stroke-width="2.5" fill="none"/><path d="M 36 28 Q 39 26 42 28" stroke="#d4a850" stroke-width="2.5" fill="none"/><ellipse cx="32" cy="38" rx="4" ry="2.5" fill="rgba(232,196,100,0.3)" stroke="#e8c464" stroke-width="2"/><rect x="30" y="40" width="4" height="5" rx="1" fill="#e8c464"/><circle cx="32" cy="46" r="2.5" fill="rgba(212,168,80,0.2)" stroke="#d4a850" stroke-width="1.5"/><circle cx="22" cy="34" r="1.8" fill="#d4a850" fill-opacity="0.6"/><circle cx="42" cy="34" r="1.8" fill="#d4a850" fill-opacity="0.6"/></svg>'

BASE = Path(__file__).resolve().parent
CONFIG_FILE = BASE / "config.json"
VAULT_DIR = BASE / "vault"
LOGS_DIR = BASE / "logs"
CREDENTIALS_DIR = BASE / "credentials"

# Vault-Dateien
IDENTITY_VAULT = VAULT_DIR / "identity.vault"
HIVES_VAULT = VAULT_DIR / "hives.vault"
USER_HIVES_VAULT = VAULT_DIR / "user_hives.vault"  # {username: [{hive_url, hive_name, role, ...}]}

# Recovery
RECOVERY_HASH_FILE = VAULT_DIR / "recovery.hash"    # Seed-Hash (außerhalb Vault!)
RECOVERY_KEY_FILE = VAULT_DIR / "recovery.enc"       # Vault-PW verschlüsselt mit Seed

# PQ-Vault-Wrap (KEK/DEK/ML-KEM — siehe PQ-Architektur.md Abschnitt "Schicht 1 konkret")
VAULT_KEM_PRIV_FILE = CREDENTIALS_DIR / "vault_kem_priv.vault"       # ML-KEM-Private AES-GCM(KEK(PW+machine_id))
VAULT_KEM_PRIV_SEED_FILE = CREDENTIALS_DIR / "vault_kem_priv.seed.vault"  # dito mit Seed-Key — Phase 2
VAULT_KEM_PUB_FILE = CREDENTIALS_DIR / "vault_kem_pub.key"           # ML-KEM-Public (Klartext, nur für Encap nötig)
DEK_WRAP_FILE = VAULT_DIR / "dek.wrap"                               # DEK als ML-KEM-Encapsulation + AES-GCM(shared)
PERSO_BLACKLIST_FILE = VAULT_DIR / "perso_blacklist.json"            # Temporäre Perso-Hash-Blacklist (90 Tage nach Self-Delete)

# Users (Multi-User Accounts)
USERS_VAULT = VAULT_DIR / "users.vault"

# Migration-Abuse-Detection (pro IP: Fails + Sperre + Redemption + Stufe)
MIGRATE_ABUSE_VAULT = VAULT_DIR / "migrate_abuse.vault"

# Account-Type-Switch-Abuse (pro shinpai_id: Switch-Historie + Sperre)
TYPE_SWITCH_ABUSE_VAULT = VAULT_DIR / "type_switch_abuse.vault"

# Agents (Bots, Phoenixe)
AGENTS_VAULT = VAULT_DIR / "agents.vault"

# Friends + DMs
FRIENDS_VAULT = VAULT_DIR / "friends.vault"
DM_PENDING_DIR = VAULT_DIR / "dm_pending"
DM_PENDING_DIR.mkdir(parents=True, exist_ok=True)

# System Vault (maschinengebunden)
SYSTEM_VAULT_FILE = VAULT_DIR / "system.vault"     # System-Secrets (Keys, Certs)
SYSTEM_SALT_FILE = VAULT_DIR / "system.salt"        # Install-spezifischer Salt (random)
SYSTEM_OWNER_SIG = VAULT_DIR / "system.owner.sig"   # Owner-Signatur (Segen)

# Lizenzmodell (Phase 1 MVP) — siehe Doku/Lizenzmodell.md
LICENSES_ISSUED_VAULT = VAULT_DIR / "licenses_issued.vault"       # Vom Owner ausgestellte Lizenzen
LICENSES_RECEIVED_VAULT = VAULT_DIR / "licenses_received.vault"   # An den Owner ausgestellte Lizenzen
TRUST_ISSUERS_VAULT = VAULT_DIR / "trust_issuers.vault"           # Trust-Liste akzeptierter Aussteller
REVOKED_LICENSES_VAULT = VAULT_DIR / "revoked_licenses.vault"     # Eigene Widerrufs-Liste

# Federation / Verzeichnis — dezentrale Amt-Listen (Phase 1 Step 2)
# Der Owner abonniert eine oder mehrere JSON-URLs, die je eine Liste von Ämtern
# im Federation-Format ausliefern (siehe lab.shinpai.de/amt-list.json).
# Andere Nexus-Instanzen können ihre eigenen Listen hosten, der Owner wählt
# welchen Listen er vertraut (wie AdBlock-Filter).
AMT_LIST_SUBSCRIPTIONS_VAULT = VAULT_DIR / "amt_list_subscriptions.vault"  # Abonnierte Listen-URLs + Cache
AMT_WATCHLIST_VAULT = VAULT_DIR / "amt_watchlist.vault"                   # Ämter die für Stufe-3-Antrag vorgemerkt sind
BTC_WALLET_VAULT = VAULT_DIR / "btc_wallet.vault"                         # Bitcoin Wallet (WIF + Adresse) für Blockchain-Verankerung

# Ignition Key — 1:1 Shidow-Pattern!
# Eigener Ordner: ShinNexus-Igni-{kuerzel}/vault_bootstrap.enc
_IGNITION_DIR: Path | None = None
_VAULT_BOOTSTRAP: Path | None = None
_IGNI_SALT = b"ShinNexus-Igni-2026"


def _igni_dir_name(kuerzel: str = "") -> str:
    return f"ShinNexus-Igni-{kuerzel}" if kuerzel else "ShinNexus-Igni"


def _igni_auto_detect() -> Path | None:
    """Sucht ShinNexus-Igni-* im Arbeitsverzeichnis."""
    for p in BASE.glob("ShinNexus-Igni-*"):
        if p.is_dir() and (p / "vault_bootstrap.enc").exists():
            return p
    return None


def _igni_resolve(cfg: dict) -> Path | None:
    """Igni-Pfad ermitteln: Config → Auto-Detect → None."""
    igni_path = cfg.get("igni_path", "").strip()
    if igni_path:
        p = Path(igni_path)
        if p.is_dir() and (p / "vault_bootstrap.enc").exists():
            return p
    kuerzel = cfg.get("shinpai_name_hash", cfg.get("shinpai_kuerzel", ""))
    if kuerzel:
        p = BASE / _igni_dir_name(kuerzel)
        if p.is_dir() and (p / "vault_bootstrap.enc").exists():
            return p
    return _igni_auto_detect()


def _igni_init(cfg: dict):
    """Setzt _IGNITION_DIR und _VAULT_BOOTSTRAP. Aufgerufen beim Start."""
    global _IGNITION_DIR, _VAULT_BOOTSTRAP
    resolved = _igni_resolve(cfg)
    if resolved:
        _IGNITION_DIR = resolved
        _VAULT_BOOTSTRAP = resolved / "vault_bootstrap.enc"
        return
    kuerzel = cfg.get("shinpai_name_hash", cfg.get("shinpai_kuerzel", ""))
    _IGNITION_DIR = BASE / _igni_dir_name(kuerzel) if kuerzel else BASE / "ShinNexus-Igni"
    _VAULT_BOOTSTRAP = _IGNITION_DIR / "vault_bootstrap.enc"


def _igni_bootstrap_key() -> bytes:
    """Bootstrap-Key: SHA256(Salt + machine-id) → Fernet-Key."""
    try:
        mid = Path("/etc/machine-id").read_text().strip().encode()
    except Exception:
        import platform
        mid = platform.node().encode()
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(_IGNI_SALT + mid).digest())


def igni_save(password: str):
    """Vault-Passwort + Metadata verschlüsselt in Igni-Ordner speichern."""
    from cryptography.fernet import Fernet
    _IGNITION_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(_IGNITION_DIR, 0o700)
    bootstrap = {
        "vault_password": password,
        "mode": "auto-unlock",
        "created_at": int(time.time()),
    }
    f = Fernet(_igni_bootstrap_key())
    _VAULT_BOOTSTRAP.write_bytes(f.encrypt(json.dumps(bootstrap).encode("utf-8")))
    os.chmod(_VAULT_BOOTSTRAP, 0o600)
    nexus_log("🔑 Igni-Key gespeichert (Auto-Unlock aktiv)", "green")


def igni_load() -> str | None:
    """Vault-Passwort aus Igni-Bootstrap entschlüsseln."""
    if not _VAULT_BOOTSTRAP or not _VAULT_BOOTSTRAP.exists():
        return None
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_igni_bootstrap_key())
        bootstrap = json.loads(f.decrypt(_VAULT_BOOTSTRAP.read_bytes()).decode("utf-8"))
        if bootstrap.get("mode") != "auto-unlock":
            return None
        return bootstrap.get("vault_password")
    except Exception:
        return None


def igni_delete():
    """Igni-Key löschen."""
    if _VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists():
        _VAULT_BOOTSTRAP.unlink()
        nexus_log("🔑 Igni-Key gelöscht", "yellow")
    if _IGNITION_DIR and _IGNITION_DIR.exists():
        try:
            _IGNITION_DIR.rmdir()
        except OSError:
            pass

# Signing Key
SIGNING_KEY_FILE = CREDENTIALS_DIR / "signing_key.vault"

# Vault Magic — NVAULT2 = AES-256-GCM (definiert im Vault-Block unten)

# Verzeichnisse anlegen
for d in (VAULT_DIR, LOGS_DIR, CREDENTIALS_DIR):
    d.mkdir(parents=True, exist_ok=True)
try:
    CREDENTIALS_DIR.chmod(0o700)
except OSError:
    pass

# ══════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════

# ANSI-Farben
_C_RESET = "\033[0m"
_C_CYAN = "\033[36m"
_C_GREEN = "\033[32m"
_C_YELLOW = "\033[33m"
_C_RED = "\033[31m"
_C_DIM = "\033[2m"


def nexus_log(text: str, color: str = ""):
    """Log ins Terminal + Tagesdatei."""
    ts = datetime.now().strftime("%H:%M:%S")
    # Datei
    log_file = LOGS_DIR / f"{date.today().isoformat()}.log"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {text}\n")
    # Terminal
    c = {"green": _C_GREEN, "yellow": _C_YELLOW, "red": _C_RED,
         "cyan": _C_CYAN, "dim": _C_DIM}.get(color, "")
    print(f"{c}[{ts}] {text}{_C_RESET}")


# ══════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "port": DEFAULT_PORT,
    "host": "0.0.0.0",
    "mode": "",  # "server" oder "client"
    "server_url": "",  # Client-Modus: URL zum ShinNexus-Server
    "name": "",
    "email": "",
    "shinpai_id": "",
    "public_key": "",
    "kem_public_key": "",
    "auth_provider": "local",
    "tls": {"mode": "auto"},
    "owner_vault_mode": "standard",  # "standard" = Igni an (Auto-Unlock), "paranoid" = kein Igni
    "bot_quota": 20,  # 0/20/50/100/200/1000 — siehe _BOT_QUOTA_LABELS
    "version": VERSION,
}


# Bot-Quote Gimmick-Labels (Login-Banner-Charakter)
_BOT_QUOTA_LABELS = {
    0: "Nope Wir sind Biologisch!",
    20: "ein paar Helferlein, passt schon",
    50: "richtig produktiv jetzt!",
    100: "okay du meinst es ernst mit Bots",
    200: "Bot-Farm Deluxe, volle Ladung",
    1000: "ich weiß was ich tue, ich bin Enterprise oder verrückt!",
}
_BOT_QUOTA_VALUES = [0, 20, 50, 100, 200, 1000]


def get_bot_policy(cfg: dict = None) -> dict:
    """Liefert die aktuelle Bot-Politik: Quote + Label + aktuelle Belegung."""
    cfg = cfg or load_config()
    quota = int(cfg.get("bot_quota", 20))
    if quota not in _BOT_QUOTA_LABELS:
        # Fallback auf naechste bekannte Zahl
        quota = min(_BOT_QUOTA_VALUES, key=lambda x: abs(x - quota))
    current = sum(1 for a in _agents if (a.get("type") or "").lower() in ("bot", "b"))
    # Perso-Count: unique Perso-Hashes (Veriff-bestätigt)
    perso_hashes = set()
    for u in _users.values():
        if u.get("id_verified") and u.get("perso_hash"):
            perso_hashes.add(u["perso_hash"])
    if _identity and _identity.get("id_verified") and _identity.get("perso_hash"):
        perso_hashes.add(_identity["perso_hash"])
    return {
        "quota": quota,
        "label": _BOT_QUOTA_LABELS[quota],
        "current": current,
        "available_values": _BOT_QUOTA_VALUES,
        "perso_count": len(perso_hashes),
        "bot_count": current,
    }


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return {**DEFAULT_CONFIG, **cfg}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict):
    """Config speichern — sensitive Keys rausfiltern!"""
    out = dict(cfg)
    # Private/Sensitive Keys NIEMALS in Config!
    for k in ("_vault_key", "_master_password"):
        out.pop(k, None)
    # SMTP-Passwort in Vault verschlüsseln statt Klartext!
    if "smtp" in out and out["smtp"].get("password"):
        smtp_pw = out["smtp"]["password"]
        out["smtp"] = dict(out["smtp"])
        out["smtp"]["password"] = ""  # Nie in Config!
        out["smtp"]["_pw_in_vault"] = True
        # In Vault speichern wenn unlocked
        if vault_is_unlocked():
            smtp_vault = VAULT_DIR / "smtp.vault"
            smtp_vault.write_bytes(vault_encrypt(smtp_pw.encode("utf-8")))
    # CONFIG DATEI SCHREIBEN!
    CONFIG_FILE.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def _get_smtp_password() -> str:
    """SMTP-Passwort aus Vault laden."""
    smtp_vault = VAULT_DIR / "smtp.vault"
    if smtp_vault.exists() and vault_is_unlocked():
        try:
            return vault_decrypt(smtp_vault.read_bytes()).decode("utf-8")
        except Exception:
            return ""
    return ""


# ══════════════════════════════════════════════════════════════════════
#  VAULT — AES-256-GCM + PBKDF2 + Machine-Bound (Quantum-Resistant!)
#  Kein Fernet! Direkt AES-256-GCM via cryptography.hazmat!
#  Format: NVAULT2(7) + Salt(32) + Nonce(12) + AES-256-GCM(data)
# ══════════════════════════════════════════════════════════════════════

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VAULT_MAGIC = b"NVAULT2"  # V2 = AES-256-GCM (V1 war Fernet/AES-128)
_vault_master_key: bytes | None = None  # Abgeleiteter 256-bit Key, NIE raw password!
_vault_unlock_time: float = 0.0
_VAULT_MAX_AGE = 86400  # 24h Timeout → auto-lock


def _derive_vault_key(password: str, salt: bytes) -> bytes:
    """256-bit AES Key aus Passwort + Salt (PBKDF2, 600k Iterationen)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 Bytes = 256 Bit!
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode("utf-8"))


def _derive_file_key(salt: bytes) -> bytes:
    """Per-File AES-256 Key: SHA256(DEK + machine_id + file_salt).
    Nutzt DEK (neu, PQ-gewrapped) wenn verfügbar, sonst Legacy-Master-Key."""
    base = _dek if _dek is not None else _vault_master_key
    if base is None:
        raise RuntimeError("Vault gesperrt — unlock() zuerst!")
    try:
        mid = Path("/etc/machine-id").read_text().strip().encode()
    except Exception:
        import platform
        mid = platform.node().encode()
    return hashlib.sha256(base + mid + salt).digest()


def vault_encrypt(plaintext: bytes, password: str = None) -> bytes:
    """AES-256-GCM Encrypt. Format: NVAULT2(7) + Salt(32) + Nonce(12) + Ciphertext."""
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    if password:
        key = _derive_vault_key(password, salt)
    else:
        key = _derive_file_key(salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _VAULT_MAGIC)  # Magic als AAD!
    return _VAULT_MAGIC + salt + nonce + ciphertext


def vault_decrypt(ciphertext: bytes, password: str = None) -> bytes:
    """AES-256-GCM Decrypt. Erwartet: NVAULT2(7) + Salt(32) + Nonce(12) + Ciphertext."""
    if not ciphertext.startswith(_VAULT_MAGIC):
        raise ValueError("Keine Vault-Datei (Magic mismatch — erwartet NVAULT2)")
    salt = ciphertext[7:39]      # 32 Bytes
    nonce = ciphertext[39:51]    # 12 Bytes
    encrypted = ciphertext[51:]
    if password:
        key = _derive_vault_key(password, salt)
    else:
        key = _derive_file_key(salt)
    return AESGCM(key).decrypt(nonce, encrypted, _VAULT_MAGIC)  # Magic als AAD!


def _verify_owner_password(password: str) -> bool:
    """Prueft ob ein Passwort den Owner-Vault oeffnen kann, ohne den aktuellen
    _vault_master_key zu ueberschreiben. Nutzt dieselbe Ableitung wie vault_unlock."""
    if not IDENTITY_VAULT.exists() or not password:
        return False
    try:
        mid = Path("/etc/machine-id").read_text().strip().encode()
    except Exception:
        import platform
        mid = platform.node().encode()
    candidate_master = hashlib.sha256(
        b"shinpai-nexus-vault-v2" + password.encode("utf-8") + mid
    ).digest()
    raw = IDENTITY_VAULT.read_bytes()
    if not raw.startswith(_VAULT_MAGIC):
        return False
    salt = raw[7:39]
    nonce = raw[39:51]
    encrypted = raw[51:]
    # _derive_file_key = SHA256(master + mid + salt)
    file_key = hashlib.sha256(candidate_master + mid + salt).digest()
    try:
        AESGCM(file_key).decrypt(nonce, encrypted, _VAULT_MAGIC)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════
#  PQ-VAULT-WRAP — KEK/DEK mit ML-KEM-768 (siehe PQ-Architektur.md)
#  Schicht 1 konkret: Vault-Daten mit DEK, DEK mit ML-KEM gewrappt,
#  ML-KEM-Private mit KEK(PW+machine-id) verschlüsselt. PQ-nativer Key-Wrap.
# ══════════════════════════════════════════════════════════════════════

_dek: bytes | None = None              # Data Encryption Key — RAM-only
# _vault_master_key bleibt als Legacy-Fallback solange Migration läuft (alte Files lesen)


def _pq_get_machine_id_bytes() -> bytes:
    try:
        return Path("/etc/machine-id").read_text().strip().encode()
    except Exception:
        import platform
        return platform.node().encode()


def _pq_derive_kek(password: str, salt: bytes = b"pq-kek-v3") -> bytes:
    """32-byte KEK aus Password + machine-id + konstanter Salt."""
    mid = _pq_get_machine_id_bytes()
    return hashlib.sha256(b"shinpai-vault-kek-v3-" + salt + password.encode("utf-8") + mid).digest()


def _pq_derive_seed_key(seed_phrase: str) -> bytes:
    """32-byte Seed-Key aus Seed-Phrase + machine-id."""
    mid = _pq_get_machine_id_bytes()
    normalized = " ".join(seed_phrase.strip().lower().split())
    return hashlib.sha256(b"shinpai-vault-seed-v3-" + normalized.encode("utf-8") + mid).digest()


def _pq_encrypt_priv(kem_sk: bytes, key: bytes, aad: bytes) -> bytes:
    """ML-KEM-Private mit AES-256-GCM verschlüsseln. Format: salt(32) + nonce(12) + ct."""
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    derived = hashlib.sha256(key + salt).digest()
    ct = AESGCM(derived).encrypt(nonce, kem_sk, aad)
    return salt + nonce + ct


def _pq_decrypt_priv(blob: bytes, key: bytes, aad: bytes) -> bytes:
    """ML-KEM-Private entschlüsseln."""
    salt = blob[:32]
    nonce = blob[32:44]
    ct = blob[44:]
    derived = hashlib.sha256(key + salt).digest()
    return AESGCM(derived).decrypt(nonce, ct, aad)


def _pq_wrap_dek(dek: bytes, kem_pk: bytes) -> bytes:
    """DEK mit ML-KEM-768 encapsulieren. Format: len(ct)(4) + encap_ct + nonce(12) + aes_ct."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    encap_ct, shared = kem.encap_secret(kem_pk)
    kem.free()
    nonce = secrets.token_bytes(12)
    aes_key = hashlib.sha256(shared).digest()[:32]
    aes_ct = AESGCM(aes_key).encrypt(nonce, dek, b"vault-dek-wrap-v3")
    return len(encap_ct).to_bytes(4, "big") + encap_ct + nonce + aes_ct


def _pq_unwrap_dek(wrap_blob: bytes, kem_sk: bytes) -> bytes:
    """DEK über ML-KEM-Private entkapseln."""
    ct_len = int.from_bytes(wrap_blob[:4], "big")
    encap_ct = wrap_blob[4:4 + ct_len]
    nonce = wrap_blob[4 + ct_len:4 + ct_len + 12]
    aes_ct = wrap_blob[4 + ct_len + 12:]
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=kem_sk)
    shared = kem.decap_secret(encap_ct)
    kem.free()
    aes_key = hashlib.sha256(shared).digest()[:32]
    return AESGCM(aes_key).decrypt(nonce, aes_ct, b"vault-dek-wrap-v3")


_pq_pending_kem_sk: bytes | None = None  # Temp: KEM-SK aus init, cleared nach Seed-Backup

def _pq_init_fresh(password: str, seed_phrase: str | None = None) -> bytes:
    """Erstinitialisierung: DEK + ML-KEM-Pair generieren, alle Wrap-Files schreiben.
    Gibt DEK zurück (im RAM behalten für weitere Operationen)."""
    global _pq_pending_kem_sk
    dek = secrets.token_bytes(32)
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    kem_pk = kem.generate_keypair()
    kem_sk = kem.export_secret_key()
    kem.free()

    # DEK wrappen mit Public-Key
    wrap_blob = _pq_wrap_dek(dek, kem_pk)
    DEK_WRAP_FILE.write_bytes(wrap_blob)
    try:
        os.chmod(DEK_WRAP_FILE, 0o600)
    except OSError:
        pass

    # ML-KEM-Public speichern (Klartext)
    VAULT_KEM_PUB_FILE.write_bytes(kem_pk)
    try:
        os.chmod(VAULT_KEM_PUB_FILE, 0o644)
    except OSError:
        pass

    # ML-KEM-Private mit KEK(PW) verschlüsseln
    kek = _pq_derive_kek(password)
    priv_blob = _pq_encrypt_priv(kem_sk, kek, b"vault-kem-priv-pw-v3")
    VAULT_KEM_PRIV_FILE.write_bytes(priv_blob)
    try:
        os.chmod(VAULT_KEM_PRIV_FILE, 0o600)
    except OSError:
        pass

    # Seed-Backup falls Seed übergeben
    if seed_phrase:
        seed_key = _pq_derive_seed_key(seed_phrase)
        seed_blob = _pq_encrypt_priv(kem_sk, seed_key, b"vault-kem-priv-seed-v3")
        VAULT_KEM_PRIV_SEED_FILE.write_bytes(seed_blob)
        try:
            os.chmod(VAULT_KEM_PRIV_SEED_FILE, 0o600)
        except OSError:
            pass
        _pq_pending_kem_sk = None  # Sofort clearen — Seed-Backup existiert
    else:
        # KEM-SK im RAM halten bis create_account den Seed generiert hat
        _pq_pending_kem_sk = kem_sk

    nexus_log("🌿 PQ-Vault initialisiert (ML-KEM-768 Wrap, KEK/DEK)", "green")
    return dek


def _pq_create_seed_backup(seed_phrase: str) -> bool:
    """Nachträgliches Seed-Backup für ML-KEM-Private erstellen.
    Wird aus create_account aufgerufen wenn Seed erst nach vault_unlock generiert wird."""
    global _pq_pending_kem_sk
    if _pq_pending_kem_sk is None:
        return False
    try:
        seed_key = _pq_derive_seed_key(seed_phrase)
        seed_blob = _pq_encrypt_priv(_pq_pending_kem_sk, seed_key, b"vault-kem-priv-seed-v3")
        VAULT_KEM_PRIV_SEED_FILE.write_bytes(seed_blob)
        try:
            os.chmod(VAULT_KEM_PRIV_SEED_FILE, 0o600)
        except OSError:
            pass
        nexus_log("🌿 PQ-Seed-Backup nachträglich erstellt", "green")
        return True
    finally:
        _pq_pending_kem_sk = None  # Immer clearen


def _pq_unlock_dek_via_password(password: str) -> bytes | None:
    """PW → KEK → ML-KEM-Private entschlüsseln → DEK entwrappen."""
    if not VAULT_KEM_PRIV_FILE.exists() or not DEK_WRAP_FILE.exists():
        return None
    try:
        kek = _pq_derive_kek(password)
        kem_sk = _pq_decrypt_priv(
            VAULT_KEM_PRIV_FILE.read_bytes(), kek, b"vault-kem-priv-pw-v3"
        )
        return _pq_unwrap_dek(DEK_WRAP_FILE.read_bytes(), kem_sk)
    except Exception:
        return None


def _pq_unlock_dek_via_seed(seed_phrase: str) -> bytes | None:
    """Seed → Seed-Key → ML-KEM-Private entschlüsseln → DEK entwrappen."""
    if not VAULT_KEM_PRIV_SEED_FILE.exists() or not DEK_WRAP_FILE.exists():
        return None
    try:
        seed_key = _pq_derive_seed_key(seed_phrase)
        kem_sk = _pq_decrypt_priv(
            VAULT_KEM_PRIV_SEED_FILE.read_bytes(), seed_key, b"vault-kem-priv-seed-v3"
        )
        return _pq_unwrap_dek(DEK_WRAP_FILE.read_bytes(), kem_sk)
    except Exception:
        return None


def _pq_rewrap_kem_priv(old_password: str, new_password: str) -> bool:
    """Atomischer PW-Change: ML-KEM-Private mit neuer KEK neu verschlüsseln.
    DEK und Vault-Files bleiben unberührt — nur eine kleine Datei wird ersetzt.
    Returns True bei Erfolg."""
    if not VAULT_KEM_PRIV_FILE.exists():
        return False
    try:
        old_kek = _pq_derive_kek(old_password)
        kem_sk = _pq_decrypt_priv(
            VAULT_KEM_PRIV_FILE.read_bytes(), old_kek, b"vault-kem-priv-pw-v3"
        )
        new_kek = _pq_derive_kek(new_password)
        new_blob = _pq_encrypt_priv(kem_sk, new_kek, b"vault-kem-priv-pw-v3")
        VAULT_KEM_PRIV_FILE.write_bytes(new_blob)
        try:
            os.chmod(VAULT_KEM_PRIV_FILE, 0o600)
        except OSError:
            pass
        return True
    except Exception as e:
        nexus_log(f"⚠️ PQ-Rewrap fehlgeschlagen: {e}", "red")
        return False


def _pq_write_seed_backup(seed_phrase: str) -> bool:
    """Erstellt/aktualisiert kem_priv.seed.vault. Braucht aktives _dek und den ML-KEM-Private.
    Wird aufgerufen bei: Register, 2FA-Refresh-Confirm (neuer Seed), PW-Reset-Set.
    """
    if _dek is None:
        return False
    # ML-KEM-Private über aktuelle PW-Kette holen?
    # Pragmatik: In diesem Moment sind wir per PW entsperrt. Wir haben den ML-KEM-Sk
    # nicht im RAM gecacht, also holen wir ihn über die gleiche File + gleiche KEK-Ableitung.
    # Owner-PW haben wir im Scope nicht — also der Caller muss den kem_sk übergeben.
    nexus_log("⚠️ _pq_write_seed_backup ohne kem_sk aufgerufen", "yellow")
    return False


def _pq_write_seed_backup_with_sk(seed_phrase: str, kem_sk: bytes) -> bool:
    """Schreibt kem_priv.seed.vault wenn kem_sk bekannt."""
    try:
        seed_key = _pq_derive_seed_key(seed_phrase)
        blob = _pq_encrypt_priv(kem_sk, seed_key, b"vault-kem-priv-seed-v3")
        VAULT_KEM_PRIV_SEED_FILE.write_bytes(blob)
        try:
            os.chmod(VAULT_KEM_PRIV_SEED_FILE, 0o600)
        except OSError:
            pass
        return True
    except Exception as e:
        nexus_log(f"⚠️ Seed-Backup-Write fehlgeschlagen: {e}", "red")
        return False


def _pq_get_kem_sk_via_password(password: str) -> bytes | None:
    """Holt ML-KEM-Private per PW (intern genutzt)."""
    if not VAULT_KEM_PRIV_FILE.exists():
        return None
    try:
        kek = _pq_derive_kek(password)
        return _pq_decrypt_priv(
            VAULT_KEM_PRIV_FILE.read_bytes(), kek, b"vault-kem-priv-pw-v3"
        )
    except Exception:
        return None


def vault_unlock(password: str) -> bool:
    """Vault entsperren. Neu: PQ-basiert (KEK → ML-KEM-Priv → DEK).
    Legacy-Fallback für Vaults aus v2 (Migration läuft dann beim nächsten Schreiben automatisch)."""
    global _vault_master_key, _vault_unlock_time, _dek

    # Neuer Weg: PQ-Wrap vorhanden?
    if VAULT_KEM_PRIV_FILE.exists() and DEK_WRAP_FILE.exists():
        dek = _pq_unlock_dek_via_password(password)
        if dek is None:
            _dek = None
            _vault_master_key = None
            _vault_unlock_time = 0
            nexus_log("Vault-Passwort falsch!", "red")
            return False
        _dek = dek
        # Legacy-Master für v2-Files noch mit ableiten (Migration-Kompatibilität)
        _vault_master_key = hashlib.sha256(
            b"shinpai-nexus-vault-v2" + password.encode("utf-8") + _pq_get_machine_id_bytes()
        ).digest()
        _vault_unlock_time = time.time()
        nexus_log("🔒 Vault entsperrt (PQ-Wrap: ML-KEM-768 + DEK)", "green")
        try:
            import threading as _thr_vu
            _thr_vu.Thread(target=_license_cascade_refresh, daemon=True).start()
        except Exception:
            pass
        return True

    # Legacy-Weg: alter v2-Master-Key (ohne PQ-Wrap)
    mid = _pq_get_machine_id_bytes()
    _vault_master_key = hashlib.sha256(
        b"shinpai-nexus-vault-v2" + password.encode("utf-8") + mid
    ).digest()
    _vault_unlock_time = time.time()
    _dek = None
    if IDENTITY_VAULT.exists():
        try:
            vault_decrypt(IDENTITY_VAULT.read_bytes())
            nexus_log("🔒 Vault entsperrt (Legacy v2 — Migration zu PQ beim nächsten Start)", "yellow")
            # Auto-Migrate: Beim ersten erfolgreichen Legacy-Unlock → PQ-Struktur aufbauen
            _pq_migrate_from_legacy(password)
            import threading as _thr_vu
            _thr_vu.Thread(target=_license_cascade_refresh, daemon=True).start()
            return True
        except Exception:
            _vault_master_key = None
            _vault_unlock_time = 0
            nexus_log("Vault-Passwort falsch!", "red")
            return False
    # Kein Vault → erstes Mal — PQ-Wrap direkt aufbauen
    try:
        _dek = _pq_init_fresh(password)
        nexus_log("🔒 Neuer Vault — PQ-Wrap (ML-KEM-768 + DEK) initialisiert", "green")
    except Exception as e:
        nexus_log(f"⚠️ PQ-Init fehlgeschlagen: {e} — Legacy-Modus", "yellow")
        _dek = None
    return True


def _pq_migrate_from_legacy(password: str):
    """Einmal-Migration: bestehenden v2-Vault auf PQ-Wrap umstellen.
    Läuft bei Legacy-Unlock automatisch. Vault-Dateien werden NICHT angefasst —
    beim nächsten Schreiben werden sie automatisch mit DEK re-verschlüsselt (via _derive_file_key)."""
    global _dek
    if VAULT_KEM_PRIV_FILE.exists() and DEK_WRAP_FILE.exists():
        return  # Schon migriert
    try:
        # DEK = der alte Master-Key selbst (als 32-byte-Seed für DEK).
        # Das macht die Migration GEGEN die alten Dateien abwärtskompatibel:
        # _derive_file_key nutzt (_dek oder _vault_master_key) → beide identisch.
        _dek = _vault_master_key
        # ML-KEM-Pair generieren + DEK wrappen + kem_priv mit KEK(PW) verschlüsseln
        _pq_init_fresh_with_dek(password, _dek)
        nexus_log("🌿 Auto-Migration v2 → PQ-Wrap abgeschlossen", "green")
    except Exception as e:
        nexus_log(f"⚠️ Auto-Migration fehlgeschlagen: {e}", "yellow")
        _dek = None


def _pq_init_fresh_with_dek(password: str, dek: bytes):
    """Wie _pq_init_fresh aber mit vorgegebenem DEK (für Migration)."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    kem_pk = kem.generate_keypair()
    kem_sk = kem.export_secret_key()
    kem.free()
    wrap_blob = _pq_wrap_dek(dek, kem_pk)
    DEK_WRAP_FILE.write_bytes(wrap_blob)
    try:
        os.chmod(DEK_WRAP_FILE, 0o600)
    except OSError:
        pass
    VAULT_KEM_PUB_FILE.write_bytes(kem_pk)
    kek = _pq_derive_kek(password)
    priv_blob = _pq_encrypt_priv(kem_sk, kek, b"vault-kem-priv-pw-v3")
    VAULT_KEM_PRIV_FILE.write_bytes(priv_blob)
    try:
        os.chmod(VAULT_KEM_PRIV_FILE, 0o600)
    except OSError:
        pass


def vault_lock():
    """Vault sperren — alle Keys aus RAM löschen."""
    global _vault_master_key, _vault_unlock_time, _dek
    _vault_master_key = None
    _dek = None
    _vault_unlock_time = 0
    nexus_log("🔒 Vault gesperrt", "yellow")


def vault_is_unlocked() -> bool:
    if _vault_master_key is None and _dek is None:
        return False
    if time.time() - _vault_unlock_time > _VAULT_MAX_AGE:
        vault_lock()
        nexus_log("🔒 Vault: 24h Timeout — automatisch gesperrt", "yellow")
        return False
    return True


def _save_recovery_data(password: str, recovery_seed: str):
    """Speichert Recovery-Daten AUSSERHALB des Vaults.
    - recovery.hash = SHA-256 des Seeds (zum Verifizieren)
    - recovery.enc  = Vault-Passwort verschlüsselt mit Seed-Key (zum Wiederherstellen)
    """
    # Hash zum Verifizieren
    seed_hash = hashlib.sha256(recovery_seed.encode()).hexdigest()
    RECOVERY_HASH_FILE.write_text(seed_hash)
    try:
        os.chmod(RECOVERY_HASH_FILE, 0o600)
    except OSError:
        pass

    # Vault-Passwort verschlüsselt mit Seed als Key (AES-256-GCM!)
    seed_salt = hashlib.sha256(b"nexus-recovery-salt-" + recovery_seed.encode()).digest()
    seed_key = _derive_vault_key(recovery_seed, seed_salt)
    nonce = secrets.token_bytes(12)
    encrypted_pw = AESGCM(seed_key).encrypt(nonce, password.encode("utf-8"), b"nexus-recovery")
    RECOVERY_KEY_FILE.write_bytes(seed_salt + nonce + encrypted_pw)
    try:
        os.chmod(RECOVERY_KEY_FILE, 0o600)
    except OSError:
        pass


def _recover_vault_password(recovery_seed: str) -> str | None:
    """Recovery: Seed eingeben → altes Vault-Passwort entschlüsseln."""
    # Seed-Hash verifizieren
    if not RECOVERY_HASH_FILE.exists():
        return None
    stored_hash = RECOVERY_HASH_FILE.read_text().strip()
    if hashlib.sha256(recovery_seed.encode()).hexdigest() != stored_hash:
        return None

    # Vault-Passwort entschlüsseln
    if not RECOVERY_KEY_FILE.exists():
        return None
    try:
        raw = RECOVERY_KEY_FILE.read_bytes()
        seed_salt = raw[:32]
        nonce = raw[32:44]
        encrypted_pw = raw[44:]
        seed_key = _derive_vault_key(recovery_seed, seed_salt)
        return AESGCM(seed_key).decrypt(nonce, encrypted_pw, b"nexus-recovery").decode("utf-8")
    except Exception:
        return None


def _vault_change_password(old_password: str, new_password: str) -> bool:
    """Vault-Passwort ändern — ATOMISCH über PQ-Rewrap (nur kem_priv.vault neu).
    DEK und alle Vault-Daten-Files bleiben unberührt — kein Totalschaden-Risiko.
    Legacy-Fallback: wenn noch kein PQ-Wrap existiert, alte Re-Encrypt-Logik."""
    # Neu: PQ-Weg (ein kleiner File wird umgewrapped)
    if VAULT_KEM_PRIV_FILE.exists():
        if not _pq_rewrap_kem_priv(old_password, new_password):
            return False
        nexus_log("🔑 Vault-PW geändert (atomisch via ML-KEM-Rewrap)", "green")
        return True

    # Legacy-Fallback (sollte nach Migration nie erreicht werden)
    global _vault_master_key, _vault_unlock_time
    vault_files = list(VAULT_DIR.glob("*.vault")) + [SIGNING_KEY_FILE]
    vault_files = [f for f in vault_files if f.exists()]
    if not vault_unlock(old_password):
        return False
    decrypted = {}
    for vf in vault_files:
        try:
            decrypted[vf] = vault_decrypt(vf.read_bytes())
        except Exception:
            nexus_log(f"Konnte {vf.name} nicht entschlüsseln!", "red")
            vault_lock()
            return False
    vault_unlock(new_password)
    for vf, data in decrypted.items():
        vf.write_bytes(vault_encrypt(data))
    nexus_log("Vault-Passwort geändert (Legacy AES-256-GCM)", "yellow")
    return True


# ══════════════════════════════════════════════════════════════════════
#  SYSTEM VAULT — Maschinengebunden, überlebt Owner-Wechsel
# ══════════════════════════════════════════════════════════════════════

_system_vault_key: bytes | None = None   # RAM-only
# System-Vault hat nur noch EINEN Modus: machine-bound composite key aus
# machine-id + Install-Salt + Owner-Signatur. Kein PARANOID-Wechsel, kein
# Hive-Backup-Key — das waren Hive-/Shidow-Konzepte, hier in Nexus redundant.


def _get_machine_id() -> str:
    """Machine-ID lesen (Linux: /etc/machine-id, Fallback: hostname)."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            mid = Path(path).read_text().strip()
            if mid:
                return mid
        except (OSError, PermissionError):
            continue
    # Fallback: hostname + os info
    import platform
    return hashlib.sha256(f"{platform.node()}-{platform.machine()}".encode()).hexdigest()


def _ensure_system_salt() -> bytes:
    """Install-spezifischen Salt erzeugen (einmalig) oder laden."""
    if SYSTEM_SALT_FILE.exists():
        return SYSTEM_SALT_FILE.read_bytes()
    salt = secrets.token_bytes(32)
    SYSTEM_SALT_FILE.write_bytes(salt)
    try:
        os.chmod(SYSTEM_SALT_FILE, 0o600)
    except OSError:
        pass
    nexus_log("System-Salt generiert", "green")
    return salt


def _derive_system_key(machine_id: str, salt: bytes, owner_sig: bytes) -> bytes:
    """Composite Key: machine-id + install-salt + owner-signature → Fernet-Key."""
    composite = machine_id.encode() + salt + owner_sig
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    raw = kdf.derive(composite)
    return base64.urlsafe_b64encode(raw)


def system_vault_init(cfg: dict, owner_password: str = None) -> bool:
    """System Vault initialisieren — Composite-Key-Modus (maschinengebunden).

    Key = machine-id + Install-Salt + Owner-Signatur. Laeuft ohne weitere
    Owner-Interaktion nach dem ersten Segnungs-Boot.
    """
    global _system_vault_key
    machine_id = _get_machine_id()
    salt = _ensure_system_salt()

    # Owner-Signatur laden oder erzeugen
    if SYSTEM_OWNER_SIG.exists():
        owner_sig = SYSTEM_OWNER_SIG.read_bytes()
    elif owner_password:
        # Erste Initialisierung: Owner signiert das System
        owner_sig = hashlib.sha256(
            f"nexus-owner-sig-{owner_password}-{machine_id}".encode()
        ).digest()
        SYSTEM_OWNER_SIG.write_bytes(owner_sig)
        try:
            os.chmod(SYSTEM_OWNER_SIG, 0o600)
        except OSError:
            pass
        nexus_log("Owner-Signatur erstellt (System gesegnet)", "green")
    else:
        # Kein Passwort, keine Signatur → kann nicht öffnen
        if not SYSTEM_OWNER_SIG.exists():
            return False
        owner_sig = SYSTEM_OWNER_SIG.read_bytes()

    _system_vault_key = _derive_system_key(machine_id, salt, owner_sig)

    # Prüfen ob bestehendes System-Vault entschlüsselbar ist
    if SYSTEM_VAULT_FILE.exists():
        try:
            raw = SYSTEM_VAULT_FILE.read_bytes()
            if raw.startswith(_VAULT_MAGIC):
                slt = raw[7:39]
                enc = raw[39:]
                fkey = _derive_system_key(machine_id, slt, owner_sig)
                Fernet(fkey).decrypt(enc)
        except Exception:
            nexus_log("System-Vault Key stimmt nicht! Composite-Mismatch.", "red")
            _system_vault_key = None
            return False

    nexus_log("System Vault: bereit (machine-bound composite)", "cyan")
    return True


def system_vault_encrypt(plaintext: bytes) -> bytes:
    """Verschlüsselt mit System-Vault-Key (AES-256-GCM, machine-bound)."""
    if not _system_vault_key:
        raise RuntimeError("System Vault gesperrt")
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    machine_id = _get_machine_id()
    owner_sig = SYSTEM_OWNER_SIG.read_bytes() if SYSTEM_OWNER_SIG.exists() else b""
    key = hashlib.sha256(_derive_system_key(machine_id, salt, owner_sig)).digest()
    encrypted = AESGCM(key).encrypt(nonce, plaintext, _VAULT_MAGIC)
    return _VAULT_MAGIC + salt + nonce + encrypted


def system_vault_decrypt(ciphertext: bytes) -> bytes:
    """Entschlüsselt System-Vault-Datei (AES-256-GCM, machine-bound)."""
    if not _system_vault_key:
        raise RuntimeError("System Vault gesperrt")
    if not ciphertext.startswith(_VAULT_MAGIC):
        raise ValueError("Keine Vault-Datei (Magic mismatch)")
    salt = ciphertext[7:39]
    nonce = ciphertext[39:51]
    encrypted = ciphertext[51:]
    machine_id = _get_machine_id()
    owner_sig = SYSTEM_OWNER_SIG.read_bytes() if SYSTEM_OWNER_SIG.exists() else b""
    key = hashlib.sha256(_derive_system_key(machine_id, salt, owner_sig)).digest()
    return AESGCM(key).decrypt(nonce, encrypted, _VAULT_MAGIC)


def system_vault_save(data: dict):
    """System-Daten in System-Vault speichern."""
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    SYSTEM_VAULT_FILE.write_bytes(system_vault_encrypt(raw))
    try:
        os.chmod(SYSTEM_VAULT_FILE, 0o600)
    except OSError:
        pass


def system_vault_load() -> dict:
    """System-Daten aus System-Vault laden."""
    if not SYSTEM_VAULT_FILE.exists():
        return {}
    try:
        raw = system_vault_decrypt(SYSTEM_VAULT_FILE.read_bytes())
        return json.loads(raw.decode("utf-8"))
    except Exception:
        nexus_log("System-Vault konnte nicht gelesen werden!", "red")
        return {}


def system_vault_is_unlocked() -> bool:
    return _system_vault_key is not None


def system_vault_lock():
    global _system_vault_key
    _system_vault_key = None
    nexus_log("System Vault gesperrt", "yellow")


# ══════════════════════════════════════════════════════════════════════
#  SHINPAI-ID (konsistent mit Shidow/ShinShare)
# ══════════════════════════════════════════════════════════════════════

_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _b62_hash(seed: str, length: int = 6) -> str:
    """Base62 Hash (A-Za-z0-9) der gegebenen Länge aus einem Seed."""
    h = int(hashlib.sha256(seed.encode()).hexdigest(), 16)
    result = ""
    for _ in range(length):
        result = _B62[h % 62] + result
        h //= 62
    return result


def _generate_shinpai_id(name: str, email: str) -> str:
    """Nexus Shinpai-ID: [NameHash6]-[EmailHash6]. Permanent."""
    name_hash = _b62_hash(f"shinpai-name-{name}")
    email_hash = _b62_hash(f"shinpai-email-{email}")
    return f"{name_hash}-{email_hash}"


# ══════════════════════════════════════════════════════════════════════
#  PLATZHALTER-OWNER (System First-Start-Account)
#  Deterministisch aus Code-Konstante + machine-id. Nur im RAM.
#  Löst das Henne-Ei-Problem: Server hat eine interne Identität bevor
#  der erste echte Owner existiert. Niemals von außen zugänglich.
# ══════════════════════════════════════════════════════════════════════


def _derive_placeholder_owner() -> dict:
    """Deterministischer System-Account — rein internes Bootstrap-Objekt.

    Wird niemals persistiert, niemals geloggt, niemals per API ausgeliefert.
    ID ist für jede Maschine reproduzierbar (aus machine-id), damit
    Neustarts im Provisioning-Modus konsistent bleiben.
    """
    mid = _get_machine_id()
    # Code-Konstante als Seed-Präfix — verhindert Kollision mit echten IDs
    seed = hashlib.sha256(b"sai-sfs-bootstrap-v1-" + mid.encode()).digest()
    name_hash = _b62_hash("__sfs__" + seed.hex()[:16])
    machine_hash = _b62_hash("__sfs__" + seed.hex()[16:32])
    return {
        "name": "",                        # kein extern sichtbarer Name
        "shinpai_id": f"{name_hash}-{machine_hash}",
        "is_placeholder": True,
        "created": int(time.time()),
    }


def _placeholder_activate():
    """Platzhalter im RAM aktivieren — nur wenn noch kein echter Owner da.

    Loggt NICHT die ID — nur die Tatsache, dass das Bootstrap-Gerüst steht.
    """
    global _placeholder_owner
    if _identity is not None:
        return
    if _placeholder_owner is not None:
        return
    _placeholder_owner = _derive_placeholder_owner()
    nexus_log("⏳ System First-Start aktiv (interner RAM-Platzhalter, kein Owner)", "dim")


def _placeholder_dismiss():
    """Platzhalter verwerfen — nach erfolgreicher Owner-Registrierung.

    Der Platzhalter existiert danach nie wieder; einziger Weg ist Frischkopie
    des Programms auf eine neue Maschine.
    """
    global _placeholder_owner
    if _placeholder_owner is None:
        return
    _placeholder_owner = None
    nexus_log("✅ Platzhalter verworfen — echter Owner übernimmt", "dim")


def _is_placeholder_mode() -> bool:
    """True solange noch kein echter Owner registriert ist."""
    return _identity is None and _placeholder_owner is not None


# ══════════════════════════════════════════════════════════════════════
#  PQ CRYPTO — ML-DSA-65 + ML-KEM-768
# ══════════════════════════════════════════════════════════════════════

_pq_keys: dict | None = None


def _ensure_keypair(cfg: dict):
    """Erzeugt ML-DSA-65 + ML-KEM-768 Keypair. Braucht offenen Vault!"""
    global _pq_keys

    if not vault_is_unlocked():
        raise RuntimeError("Vault gesperrt — Keypair kann nicht geladen werden")

    # Vorhandenes Keypair laden
    if SIGNING_KEY_FILE.exists():
        try:
            raw = vault_decrypt(SIGNING_KEY_FILE.read_bytes())
            keys = json.loads(raw.decode())
            if keys.get("algo") == "ML-DSA-65":
                _pq_keys = keys
                cfg["public_key"] = keys["sig_pk"]
                cfg["kem_public_key"] = keys["kem_pk"]
                nexus_log("PQ-Keypair geladen (ML-DSA-65 + ML-KEM-768)", "green")
                return
        except Exception:
            nexus_log("Alter Signing-Key defekt — erzeuge neuen PQ-Keypair!", "yellow")

    # Neues PQ-Keypair
    sig = oqs.Signature("ML-DSA-65")
    sig_pk = sig.generate_keypair()
    sig_sk = sig.export_secret_key()

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    kem_pk = kem.generate_keypair()
    kem_sk = kem.export_secret_key()

    keys = {
        "algo": "ML-DSA-65",
        "sig_sk": sig_sk.hex(),
        "sig_pk": sig_pk.hex(),
        "kem_sk": kem_sk.hex(),
        "kem_pk": kem_pk.hex(),
        "created": int(time.time()),
    }
    key_bytes = json.dumps(keys).encode()
    SIGNING_KEY_FILE.write_bytes(vault_encrypt(key_bytes))
    try:
        os.chmod(SIGNING_KEY_FILE, 0o600)
    except OSError:
        pass

    cfg["public_key"] = keys["sig_pk"]
    cfg["kem_public_key"] = keys["kem_pk"]
    save_config(cfg)
    _pq_keys = keys
    nexus_log("ML-DSA-65 + ML-KEM-768 Keypair erzeugt", "green")


def _sign_data(data: bytes) -> str:
    """Signiert Daten mit ML-DSA-65. Gibt Signatur als Hex zurück."""
    if not _pq_keys:
        raise RuntimeError("PQ-Keys nicht geladen")
    sig_obj = oqs.Signature("ML-DSA-65", secret_key=bytes.fromhex(_pq_keys["sig_sk"]))
    signature = sig_obj.sign(data)
    return signature.hex()


def _verify_signature(data: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """Prüft ML-DSA-65 Signatur gegen Public Key."""
    try:
        sig_obj = oqs.Signature("ML-DSA-65")
        return sig_obj.verify(
            data,
            bytes.fromhex(signature_hex),
            bytes.fromhex(public_key_hex),
        )
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════
#  LIZENZMODELL — Phase 1 MVP
#  Siehe: /media/shinpai/KI-Tools/Projekt-SAI/Doku/Lizenzmodell.md
# ══════════════════════════════════════════════════════════════════════
#
# Eine Lizenz ist ein digital signierter Datensatz der aussagt:
#   "Aussteller A bescheinigt Empfänger B im Kontext eines oder mehrerer
#    Produkte eine bestimmte Rolle/Erlaubnis, gültig bis Datum D, mit
#    Signatur S."
#
# Drei Subjekt-Arten: person / nexus_instance / service
# Drei Aussteller-Arten: owner / nexus_instance / root
# Scope ist modular erweiterbar (nexus/shidow/hive/kneipe + zukünftig mehr)

LICENSE_VERSION = 1
LICENSE_ALGORITHM = "ML-DSA-65"
LICENSE_ID_PREFIX = "LIC"

# Die fünf Oberkategorien für Stufe-3-Amt-Verifikationen (5×5 Struktur)
# Reihenfolge innerhalb jeder Kategorie: von häufig/alltäglich zu speziell/selten
# (Stand 2026-04-11, abgestimmt mit Hasi in Kneipe-Session)
LICENSE_AMT_CATEGORIES = {
    "identity":     ["birth_certificate", "personal_id", "passport", "registration_certificate", "residence_permit"],
    "finance":      ["creditworthiness", "tax_certificate", "income_proof", "payment_capability", "wealth_proof"],
    "health":       ["vaccination_record", "medical_certificate", "lab_result", "psychological_assessment", "disability_certificate"],
    "authority":    ["drivers_license", "professional_license", "craftsman_register", "weapons_license", "pilot_license"],
    "affiliation":  ["club_membership", "religious_affiliation", "union_membership", "party_membership", "nationality"],
}

# Multi-Instanz Subklassen: hier dürfen mehrere Ämter pro Subklasse abonniert werden.
# Singleton (nicht gelistet): nur ein Amt pro Subklasse (Anti-Doctor-Shopping).
# Bestätigt 2026-04-12 von Jay.
LICENSE_MULTI_SUBCLASSES = {
    # Finanzen
    "income_proof",
    # Gesundheit
    "vaccination_record", "medical_certificate", "lab_result",
    # Befugnis
    "drivers_license", "professional_license", "craftsman_register", "pilot_license",
    # Zugehörigkeit
    "club_membership", "nationality",
}

# Trust-Level Mapping (0–5), siehe Lizenzmodell.md
LICENSE_TRUST_UNKNOWN = 0        # Kein Vertrauen
LICENSE_TRUST_BASIC = 1          # Basic (Account vorhanden, Selbstauskunft)
LICENSE_TRUST_STRIPE = 2         # Stripe verifiziert (18+)
LICENSE_TRUST_VERIFF = 3         # Perso verifiziert (Veriff)
LICENSE_TRUST_AMT = 4            # Amt-bestätigt
LICENSE_TRUST_ROOT = 5           # Root / Owner (höchste Stufe)


def _license_generate_id() -> str:
    """Erzeugt eine neue Lizenz-ID: LIC_<12_hex>."""
    import secrets
    return f"{LICENSE_ID_PREFIX}_{secrets.token_hex(6)}"


def _license_anchor_prerequisites(cfg: dict | None = None) -> tuple[bool, list[str]]:
    """
    Prüft ob die Lizenz-Identität für einen Bitcoin-Anker ausreicht.
    Bitcoin verifiziert DURCH die Blockchain — nicht durch eine URL. Wir brauchen
    nur Firmenname + Logo als Label/Identität des Ankers. Die Prüf-Nexus URL im
    Lizenzen-Tab ist Self-Attestation ("verifiziert VON") und für BTC irrelevant.
    Returns: (is_complete, list_of_missing_fields)
    """
    if cfg is None:
        cfg = load_config()
    missing = []
    if not (cfg.get("license_company", "") or "").strip():
        missing.append("Firmenname")
    logo = (cfg.get("license_logo", "") or "").strip()
    if not (logo and logo.startswith("data:image")):
        missing.append("Logo")
    return (len(missing) == 0, missing)


def _license_canonical_json(license_dict: dict) -> bytes:
    """
    Kanonische JSON-Serialisierung für Signatur-Berechnung.
    - sorted keys
    - no whitespace
    - Ohne das signature-Feld selbst (wird ja erst angehängt)
    """
    # Kopie, ohne signature/signed_payload_hash
    to_sign = {k: v for k, v in license_dict.items() if k not in ("signature", "signed_payload_hash")}
    return json.dumps(to_sign, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _license_compute_payload_hash(license_dict: dict) -> str:
    """SHA-256 des canonical JSON, als Hex."""
    return hashlib.sha256(_license_canonical_json(license_dict)).hexdigest()


def _license_make(
    issuer_type: str,
    issuer_shinpai_id: str,
    issuer_display_name: str,
    issuer_public_key: str,
    subject_type: str,
    subject_shinpai_id: str,
    subject_display_name: str,
    scope: dict,
    trust_level: int,
    valid_days: int = 365,
    origins: list = None,
    code_hash: str = None,
    app_id: str = None,
    amt_categories: dict = None,
    realized_by: str = None,
    notes: str = None,
) -> dict:
    """
    Baut eine neue Lizenz (ohne Signatur!).
    Der Aufrufer muss danach `_license_sign()` rufen, um die Signatur anzuhängen.
    """
    now = int(time.time())
    license_dict = {
        "license_id": _license_generate_id(),
        "version": LICENSE_VERSION,
        "algorithm": LICENSE_ALGORITHM,
        "issuer": {
            "type": issuer_type,            # "owner" | "nexus_instance" | "root"
            "shinpai_id": issuer_shinpai_id,
            "display_name": issuer_display_name,
            "public_key": issuer_public_key,  # embedded für spätere Prüfung
        },
        "subject": {
            "type": subject_type,           # "person" | "nexus_instance" | "service"
            "shinpai_id": subject_shinpai_id,
            "display_name": subject_display_name,
            "origins": origins or [],
            "code_hash": code_hash or "",
            "app_id": app_id or "",
        },
        "scope": scope,                     # { "nexus": {level, paths}, "shidow": {...}, ... }
        "amt_categories": amt_categories or {},
        "trust_level": trust_level,
        "valid_from": now,
        "valid_until": now + (valid_days * 86400),
        "issued_at": now,
        "revoked": False,
        "realized_by": realized_by or "",   # Provider-ID (stripe/veriff/amt:berlin/self)
        "notes": notes or "",
    }
    return license_dict


def _license_sign(license_dict: dict) -> dict:
    """
    Signiert eine Lizenz mit dem lokalen PQ-Private-Key.
    Fügt `signature` und `signed_payload_hash` hinzu und gibt die Lizenz zurück.
    """
    if not _pq_keys:
        raise RuntimeError("PQ-Keys nicht geladen — kann keine Lizenz signieren")

    payload_hash = _license_compute_payload_hash(license_dict)
    signature_hex = _sign_data(bytes.fromhex(payload_hash))

    license_dict["signed_payload_hash"] = payload_hash
    license_dict["signature"] = signature_hex
    return license_dict


def _license_verify(license_dict: dict) -> tuple[bool, list[str]]:
    """
    Prüft eine Lizenz auf:
      1. Signatur-Gültigkeit (gegen eingebetteten Public Key)
      2. Zeitfenster (valid_from / valid_until)
      3. Widerruf-Status (revoked flag)

    Gibt zurück: (valid, reasons)
      - valid: True wenn alle Checks bestehen
      - reasons: Liste von Problem-Strings (leer wenn valid)

    Hinweis: Chain-of-Trust-Prüfung und Widerrufs-Liste-Abgleich
    kommen in Phase 2 dazu.
    """
    reasons = []

    # 1. Struktur-Check
    required = ("license_id", "version", "issuer", "subject", "signature", "signed_payload_hash", "valid_from", "valid_until")
    for k in required:
        if k not in license_dict:
            reasons.append(f"field_missing:{k}")
    if reasons:
        return False, reasons

    # 2. Revoked?
    if license_dict.get("revoked"):
        reasons.append("revoked")

    # 3. Zeitfenster
    now = int(time.time())
    if now < license_dict["valid_from"]:
        reasons.append("not_yet_valid")
    if now >= license_dict["valid_until"]:
        reasons.append("expired")

    # 4. Signatur
    try:
        stored_hash = license_dict["signed_payload_hash"]
        computed_hash = _license_compute_payload_hash(license_dict)
        if stored_hash != computed_hash:
            reasons.append("payload_hash_mismatch")
        else:
            issuer_pk = license_dict.get("issuer", {}).get("public_key", "")
            if not issuer_pk:
                reasons.append("issuer_public_key_missing")
            else:
                sig_ok = _verify_signature(
                    bytes.fromhex(computed_hash),
                    license_dict.get("signature", ""),
                    issuer_pk,
                )
                if not sig_ok:
                    reasons.append("signature_invalid")
    except Exception as e:
        reasons.append(f"verify_exception:{e}")

    return (len(reasons) == 0), reasons


def _license_load_vault(vault_path: Path) -> list:
    """Lädt eine Lizenz-Liste aus einem Vault-File. Gibt leere Liste zurück wenn nicht vorhanden."""
    if not vault_path.exists():
        return []
    if not vault_is_unlocked():
        return []
    try:
        raw = vault_decrypt(vault_path.read_bytes())
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        nexus_log(f"Lizenz-Vault-Ladefehler {vault_path.name}: {e}", "yellow")
        return []


def _license_save_vault(vault_path: Path, licenses: list) -> bool:
    """Speichert eine Lizenz-Liste in ein Vault-File (verschlüsselt)."""
    if not vault_is_unlocked():
        return False
    try:
        raw = json.dumps(licenses, ensure_ascii=False).encode("utf-8")
        vault_path.write_bytes(vault_encrypt(raw))
        return True
    except Exception as e:
        nexus_log(f"Lizenz-Vault-Schreibfehler {vault_path.name}: {e}", "red")
        return False


def licenses_issued_list() -> list:
    """Gibt die Liste der vom Owner ausgestellten Lizenzen zurück."""
    return _license_load_vault(LICENSES_ISSUED_VAULT)


def licenses_received_list() -> list:
    """Gibt die Liste der an den Owner ausgestellten Lizenzen zurück."""
    return _license_load_vault(LICENSES_RECEIVED_VAULT)


def licenses_trust_issuers() -> list:
    """Gibt die aktuelle Trust-Liste zurück (akzeptierte Aussteller)."""
    return _license_load_vault(TRUST_ISSUERS_VAULT)


def licenses_revoked_list() -> list:
    """Gibt die eigene Widerrufs-Liste zurück."""
    return _license_load_vault(REVOKED_LICENSES_VAULT)


# ══════════════════════════════════════════════════════════════════════
#  FEDERATION — Amt-Listen-Abos (Phase 1 Step 2)
# ══════════════════════════════════════════════════════════════════════
#
# Der Owner abonniert externe JSON-Listen mit Ämtern (wie AdBlock-Filter).
# Jedes Abo ist eine URL, die auf ein JSON-Dokument im Federation-Format zeigt:
#
#   {
#     "list_name": "...",
#     "list_owner": "...",
#     "list_url": "...",
#     "version": 1,
#     "updated_at": <timestamp>,
#     "amter": [
#       { "name": "...", "country": "DE", "city": "...", "language": "de",
#         "trust_level": <int>, "categories": {"identity": [...]},
#         "shinpai_id": "...", "endpoint": "..." },
#       ...
#     ]
#   }
#
# Jede Subscription im Vault:
#   { "id": "sub_<8 hex>", "url": "...", "name": "...", "enabled": True,
#     "added_at": <ts>, "last_fetched": <ts|None>, "last_status": "ok|error:...",
#     "last_count": <int>, "trust_level": 1..5, "cache": { ...Listen-Rohdaten... } }

def _amt_subs_load() -> list:
    """Lädt die Abo-Liste aus dem Vault. Leere Liste wenn nicht vorhanden."""
    if not AMT_LIST_SUBSCRIPTIONS_VAULT.exists():
        return []
    if not vault_is_unlocked():
        return []
    try:
        raw = vault_decrypt(AMT_LIST_SUBSCRIPTIONS_VAULT.read_bytes())
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        nexus_log(f"Amt-Listen-Vault-Ladefehler: {e}", "yellow")
        return []


def _amt_subs_save(subs: list) -> bool:
    """Speichert die Abo-Liste (verschlüsselt)."""
    if not vault_is_unlocked():
        return False
    try:
        raw = json.dumps(subs, ensure_ascii=False).encode("utf-8")
        AMT_LIST_SUBSCRIPTIONS_VAULT.write_bytes(vault_encrypt(raw))
        return True
    except Exception as e:
        nexus_log(f"Amt-Listen-Vault-Schreibfehler: {e}", "red")
        return False


def _amt_subs_new_id() -> str:
    """Erzeugt eine neue Abo-ID."""
    return "sub_" + secrets.token_hex(4)


# Convention over Configuration: Jede Amt-Liste liegt unter diesem Standardpfad,
# direkt am Root der Domäne. Wer davon abweicht, kann explizit eine volle URL
# angeben, aber der Normalfall ist "nur Domain eingeben, Nexus holt den Rest".
AMT_LIST_STANDARD_PATH = "/amt-list.json"


def _amt_subs_normalize_url(raw: str) -> str:
    """Akzeptiert entweder eine volle URL oder nur eine Domain.
    Bei nur-Domain wird https:// und der Standardpfad automatisch drangehängt.
    Beispiele:
      'lab.shinpai.de'                        -> 'https://lab.shinpai.de/amt-list.json'
      'https://lab.shinpai.de'                -> 'https://lab.shinpai.de/amt-list.json'
      'https://lab.shinpai.de/'               -> 'https://lab.shinpai.de/amt-list.json'
      'https://lab.shinpai.de/amt-list.json'  -> unverändert
      'https://example.com/custom/list.json'  -> unverändert (voller Pfad)
    """
    raw = (raw or "").strip()
    if not raw:
        return raw
    # Schema ergänzen falls nur Domain
    if not (raw.startswith("http://") or raw.startswith("https://")):
        raw = "https://" + raw
    # Parsen und Pfad prüfen
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw
    if not parsed.netloc:
        return raw
    path = (parsed.path or "").rstrip("/")
    # Kein Pfad oder leerer Pfad → Standardpfad dranhängen
    if not path:
        return f"{parsed.scheme}://{parsed.netloc}{AMT_LIST_STANDARD_PATH}"
    # Bereits der Standardpfad → so lassen
    if path == AMT_LIST_STANDARD_PATH:
        return f"{parsed.scheme}://{parsed.netloc}{AMT_LIST_STANDARD_PATH}"
    # Alles andere (eigener Pfad) → unverändert übernehmen, Owner weiß was er tut
    return raw


def _amt_subs_fetch(url: str, timeout: int = 10) -> tuple[bool, dict | str]:
    """Holt eine Amt-Liste von der angegebenen URL.
    Gibt (True, dict) bei Erfolg oder (False, error_message) bei Fehler.
    Max 5 MB Payload, validiert Grundstruktur."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "ShinNexus-Federation/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ctype = resp.headers.get("Content-Type", "")
            if "json" not in ctype.lower():
                return False, f"wrong_content_type:{ctype}"
            data = resp.read(5 * 1024 * 1024 + 1)
            if len(data) > 5 * 1024 * 1024:
                return False, "payload_too_large"
            try:
                parsed = json.loads(data.decode("utf-8"))
            except Exception as e:
                return False, f"json_parse_error:{e}"
            if not isinstance(parsed, dict):
                return False, "not_a_dict"
            if "amter" not in parsed or not isinstance(parsed["amter"], list):
                return False, "missing_amter_list"
            return True, parsed
    except urllib.error.HTTPError as e:
        return False, f"http_{e.code}"
    except urllib.error.URLError as e:
        return False, f"url_error:{e.reason}"
    except Exception as e:
        return False, f"fetch_error:{e}"


def _amt_subs_refresh_one(sub: dict) -> dict:
    """Aktualisiert ein einzelnes Abo in-place. Gibt das aktualisierte Dict zurück."""
    ok, result = _amt_subs_fetch(sub["url"])
    sub["last_fetched"] = int(time.time())
    if ok:
        sub["last_status"] = "ok"
        sub["last_count"] = len(result.get("amter", []))
        sub["cache"] = result
        # Listen-Name aus dem Dokument übernehmen, falls im Abo noch nicht gesetzt
        if not sub.get("name"):
            sub["name"] = result.get("list_name", sub["url"])
    else:
        sub["last_status"] = f"error:{result}"
    return sub


def amt_subs_list() -> list:
    """Gibt alle Abos zurück, ohne das sperrige cache-Feld im Ergebnis."""
    subs = _amt_subs_load()
    light = []
    for sub in subs:
        item = {k: v for k, v in sub.items() if k != "cache"}
        light.append(item)
    return light


def amt_subs_all_amter() -> list:
    """Aggregiert alle gecachten Ämter aus allen aktiven Abos."""
    subs = _amt_subs_load()
    all_amter = []
    for sub in subs:
        if not sub.get("enabled", True):
            continue
        cache = sub.get("cache") or {}
        for amt in cache.get("amter", []):
            enriched = dict(amt)
            enriched["_source_sub_id"] = sub.get("id")
            enriched["_source_list"] = sub.get("name") or sub.get("url")
            all_amter.append(enriched)
    return all_amter


def amt_subs_all_titel() -> list:
    """Aggregiert alle Titel-Definitionen aus allen aktiven Amt-Listen."""
    subs = _amt_subs_load()
    all_titel = []
    for sub in subs:
        if not sub.get("enabled", True):
            continue
        cache = sub.get("cache") or {}
        for titel in cache.get("titel", []):
            enriched = dict(titel)
            enriched["_source_list"] = sub.get("name") or sub.get("url")
            all_titel.append(enriched)
    return all_titel


def _evaluate_titles() -> list:
    """Prüft welche Titel der Owner basierend auf aktiven Lizenzen verdient hat.
    Gibt Liste von {titel_def, fulfilled, missing, cycle_count} zurück."""
    all_titel = amt_subs_all_titel()
    if not all_titel:
        return []
    # Aktive Lizenzen sammeln (nicht abgelaufen)
    now = int(time.time())
    received = licenses_received_list()
    active_keys = set()  # "category/subclass" strings
    for lic in received:
        if int(lic.get("valid_until", 0)) > now:
            for cat, subs in (lic.get("amt_categories") or {}).items():
                for sub in subs:
                    active_keys.add(f"{cat}/{sub}")
    # Zyklen-Zähler: wie oft wurden Lizenzen erneuert (Anzahl empfangener Lizenzen als Proxy)
    cycle_count = len(received)
    results = []
    for titel in all_titel:
        requires = titel.get("requires", [])
        min_cycles = int(titel.get("min_cycles", 0))
        fulfilled_reqs = []
        missing_reqs = []
        for req in requires:
            key = f"{req['category']}/{req['subclass']}"
            if key in active_keys:
                fulfilled_reqs.append(key)
            else:
                missing_reqs.append(key)
        all_reqs_met = len(missing_reqs) == 0
        cycles_met = cycle_count >= min_cycles
        results.append({
            "id": titel.get("id", ""),
            "name": titel.get("name", ""),
            "badge_emoji": titel.get("badge_emoji", ""),
            "badge_color": titel.get("badge_color", ""),
            "description": titel.get("description", ""),
            "grade": titel.get("grade", ""),
            "earned": all_reqs_met and cycles_met,
            "fulfilled": len(fulfilled_reqs),
            "total": len(requires),
            "missing": missing_reqs,
            "cycles_needed": min_cycles,
            "cycles_current": cycle_count,
            "_source_list": titel.get("_source_list", ""),
        })
    return results


# ══════════════════════════════════════════════════════════════════════
#  FEDERATION — Algorithmische Semantik-Suche (keine LLM-Abhängigkeit)
# ══════════════════════════════════════════════════════════════════════
#
# Deutsche Alltagsbegriffe → Kategorie/Subklasse.
# Die Map ist absichtlich großzügig und deckt Synonyme, Umgangssprache
# und häufige Schreibvarianten ab. Neue Begriffe werden bei Bedarf
# ergänzt. Reicht für MVP; später könnte ein lokales Embedding-Modell
# ergänzt werden.

AMT_SEARCH_SYNONYMS = {
    "identity": {
        "_keywords": ["identität", "identitaet", "ausweis", "identifikation", "persönlich", "personenstand"],
        "birth_certificate": ["geburt", "geburtsurkunde", "geboren", "abstammungsurkunde", "geburtsnachweis"],
        "personal_id": ["perso", "personalausweis", "ausweis", "id karte", "id-karte", "personenausweis"],
        "passport": ["reisepass", "pass", "reisen", "auslandsreise", "ausland"],
        "registration_certificate": ["meldebescheinigung", "meldung", "wohnsitz", "adresse", "gemeldet", "einwohnermeldeamt", "bürgeramt", "buergeramt"],
        "residence_permit": ["aufenthalt", "aufenthaltstitel", "visum", "aufenthaltserlaubnis", "einwanderung", "migration", "asyl", "bamf"],
    },
    "finance": {
        "_keywords": ["finanzen", "geld", "finanzlage"],
        "creditworthiness": ["bonität", "bonitaet", "schufa", "score", "kreditwürdigkeit", "creditreform", "bonitätsnachweis", "bonitaetsnachweis", "bonitätscheck", "bonitaetscheck"],
        "tax_certificate": ["steuer", "finanzamt", "steuererklärung", "steuererklaerung", "steuerbescheid", "steuernachweis", "elster"],
        "income_proof": ["einkommen", "einkommensnachweis", "gehaltsnachweis", "lohn", "gehalt", "arbeitgeber", "gewerbe", "verdienst"],
        "payment_capability": ["zahlungsfähig", "zahlungsfaehig", "zahlungsfähigkeit", "liquidität", "liquiditaet", "insolvenz", "pfändung", "pfaendung"],
        "wealth_proof": ["vermögen", "vermoegen", "vermögensnachweis", "kontostand", "eigentum", "reichtum"],
    },
    "health": {
        "_keywords": ["gesundheit", "medizin", "medizinisch"],
        "vaccination_record": ["impfung", "impfpass", "geimpft", "impfnachweis", "impfbuch", "impfstoff"],
        "medical_certificate": ["krank", "arzt", "doktor", "krankschreibung", "au", "attest", "arztbrief", "hausarzt", "facharzt", "medizinisches gutachten", "ärztliche bescheinigung", "aerztliche bescheinigung", "kranksein"],
        "lab_result": ["labor", "blut", "bluttest", "laborergebnis", "laborbefund", "analyse"],
        "psychological_assessment": ["psyche", "psycho", "psychologie", "psychisch", "therapie", "therapeut", "psychologisches gutachten", "psychiater"],
        "disability_certificate": ["behinderung", "schwerbehindert", "schwerbehinderung", "behindertenausweis", "grad der behinderung", "gdb", "versorgungsamt"],
    },
    "authority": {
        "_keywords": ["befugnis", "erlaubnis", "lizenz", "schein", "berechtigung"],
        "drivers_license": ["führerschein", "fuehrerschein", "auto", "fahren", "lappen", "fahrerlaubnis", "pkw", "lkw", "motorrad", "kraftfahrzeug", "fuehrerscheinstelle"],
        "professional_license": ["beruf", "berufserlaubnis", "zulassung", "approbation", "berufsausübung", "berufsausuebung", "kammer"],
        "craftsman_register": ["handwerk", "meister", "gewerbe", "handwerksrolle", "zunft", "handwerkskammer", "hwk"],
        "weapons_license": ["waffe", "waffenschein", "pistole", "gewehr", "jagdschein", "schusswaffe", "waffenbesitzkarte"],
        "pilot_license": ["pilot", "flugzeug", "fliegen", "luftfahrt", "privatpilot", "pilotenschein", "lba"],
    },
    "affiliation": {
        "_keywords": ["zugehörigkeit", "zugehoerigkeit", "mitglied", "mitgliedschaft"],
        "club_membership": ["verein", "mitglied", "klub", "club", "bayern", "fußball", "fussball", "sportverein", "mitgliedschaft verein", "gilde", "zunft", "innung", "orden"],
        "religious_affiliation": ["religion", "glaube", "konfession", "kirche", "religionsgemeinschaft", "evangelisch", "katholisch", "islam", "moslem", "muslim", "jüdisch", "buddhistisch", "hinduistisch", "atheist", "kirchensteuer", "moschee", "synagoge", "tempel"],
        "union_membership": ["gewerkschaft", "ig metall", "ig bce", "verdi", "gewerkschafts mitglied", "betriebsrat"],
        "party_membership": ["partei", "parteimitglied", "politik", "fraktion", "ortsverband"],
        "nationality": ["staatsbürger", "staatsbuerger", "staatsangehörigkeit", "staatsangehoerigkeit", "nationalität", "nationalitaet", "einbürgerung", "einbuergerung", "pass staat"],
    },
}


def _amt_watchlist_load() -> list:
    """Lädt die Watchlist aus dem Vault."""
    if not AMT_WATCHLIST_VAULT.exists():
        return []
    if not vault_is_unlocked():
        return []
    try:
        raw = vault_decrypt(AMT_WATCHLIST_VAULT.read_bytes())
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        nexus_log(f"Watchlist-Vault-Ladefehler: {e}", "yellow")
        return []


def _amt_watchlist_save(items: list) -> bool:
    """Speichert die Watchlist verschlüsselt."""
    if not vault_is_unlocked():
        return False
    try:
        raw = json.dumps(items, ensure_ascii=False).encode("utf-8")
        AMT_WATCHLIST_VAULT.write_bytes(vault_encrypt(raw))
        return True
    except Exception as e:
        nexus_log(f"Watchlist-Vault-Schreibfehler: {e}", "red")
        return False


def _amt_search(query: str) -> list:
    """
    Matcht query gegen die Synonym-Map und gibt sortierte Liste von Treffern zurück.
    Jeder Treffer: {category, subclass, score, matched_keyword}
    Score: 3 = Kategorie+Subklasse-Match, 2 = Subklasse-Match, 1 = nur Kategorie.
    """
    q = (query or "").lower().strip()
    if not q:
        return []
    results = []
    for cat_key, cat_map in AMT_SEARCH_SYNONYMS.items():
        cat_keywords = cat_map.get("_keywords", [])
        cat_match = any(kw in q for kw in cat_keywords)
        for sub_key, sub_keywords in cat_map.items():
            if sub_key == "_keywords":
                continue
            sub_hit = None
            for kw in sub_keywords:
                if kw in q or (len(kw) >= 5 and kw in q.replace(" ", "")):
                    sub_hit = kw
                    break
            if sub_hit:
                score = 3 if cat_match else 2
                results.append({"category": cat_key, "subclass": sub_key, "score": score, "matched_keyword": sub_hit})
            elif cat_match:
                results.append({"category": cat_key, "subclass": sub_key, "score": 1, "matched_keyword": None})
    # Deduplizieren nach (category, subclass), höchsten Score behalten
    seen = {}
    for r in sorted(results, key=lambda x: -x["score"]):
        key = (r["category"], r["subclass"])
        if key not in seen:
            seen[key] = r
    return list(seen.values())


# ══════════════════════════════════════════════════════════════════════
#  IDENTITY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

_identity: dict | None = None  # {name, email, shinpai_id, created}
_hive_stamps: list = []  # [{hive_url, hive_name, role, joined_at, hive_signature}]
_agents: list = []  # [{shinpai_id, name, type, service_token, owner_shinpai_id, public_key, ...}]
_users: dict = {}  # {username: {name, email, shinpai_id, password_hash, password_salt, totp_secret, totp_confirmed, created}}
_user_hives: dict = {}  # {username: [{hive_url, hive_name, role, joined_at, hive_signature}]}

# ── Platzhalter-Owner (System First-Start-Account) ────────────────────
# Deterministisch aus Code + machine-id abgeleitet. Niemals persistent.
# Hält die internen Kryptogerüste bis der erste echte Owner registriert.
# Von außen nie abrufbar: keine API liefert ihn, kein Log nennt die ID,
# keine DB/Config speichert ihn. Sobald echter Owner da → verworfen.
_placeholder_owner: dict | None = None

# Friends: {shinpai_id: {friends: [...], pending_in: [...], pending_out: [...], blocked: [...]}}
# Jeder Eintrag in friends/pending = {shinpai_id, name, nexus_url, public_key, kem_public_key, hive_source, since}
_friends_data: dict = {}

# Recovery-Seed Wortliste (BIP39 Subset — 256 Wörter für 12-Wort-Seed)
_WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "action", "actor", "actual", "adapt", "add",
    "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "affair", "afford", "afraid", "again", "agree", "ahead", "aim", "air",
    "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all",
    "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor",
    "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology",
    "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena",
    "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect",
    "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack",
    "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author",
    "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag",
    "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely",
    "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean",
    "beauty", "because", "become", "beef", "before", "begin", "behave", "behind",
    "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird",
    "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
    "bless", "blind", "blood", "blossom", "blow", "blue", "blur", "blush",
    "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book",
    "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box",
    "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
    "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken",
    "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget",
    "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunny", "burden",
    "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm",
    "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe",
    "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card",
]


SEED_WORD_COUNT = 24  # Syncron zu Kneipe — 24 Wörter, Leerzeichen getrennt

def _generate_recovery_seed() -> str:
    """12 zufällige Wörter als Recovery-Seed."""
    return " ".join(secrets.choice(_WORDLIST) for _ in range(SEED_WORD_COUNT))


# ═══════════════════════════════════════
# Username-Validierung
# ═══════════════════════════════════════

_USERNAME_RE = re.compile(r'^[A-Za-z0-9]{3,12}$')


def validate_username(name: str) -> str | None:
    """Prüft Username-Regeln. Gibt Fehlermeldung zurück oder None bei OK.
    Regeln: 3-12 Zeichen, nur A-Za-z0-9, case-sensitive."""
    if not name:
        return "Username darf nicht leer sein!"
    if len(name) < 3:
        return "Username zu kurz! Mindestens 3 Zeichen."
    if len(name) > 12:
        return "Username zu lang! Maximal 12 Zeichen."
    if not _USERNAME_RE.match(name):
        return "Username darf nur A-Z, a-z und 0-9 enthalten!"
    return None


def create_account(name: str, email: str, vault_password: str = None) -> dict:
    """Erstellt neuen Nexus-Account. Gibt {shinpai_id, recovery_seed, totp_secret, totp_uri} zurück."""
    global _identity, _hive_stamps

    if _identity:
        raise RuntimeError("Account existiert bereits! Erst löschen oder Recovery nutzen.")

    name_err = validate_username(name)
    if name_err:
        raise ValueError(f"Ungültiger Username: {name_err}")

    shinpai_id = _generate_shinpai_id(name, email)
    recovery_seed = _generate_recovery_seed()
    totp_secret = totp_generate_secret()
    totp_uri = totp_get_uri(totp_secret, f"ShinNexus-{name}")

    # Recovery-Daten AUSSERHALB des Vaults speichern
    if vault_password:
        _save_recovery_data(vault_password, recovery_seed)
    # PQ-Seed-Backup nachholen (KEM-SK aus _pq_init_fresh zwischengespeichert)
    _pq_create_seed_backup(recovery_seed)

    _identity = {
        "name": name,
        "email": email,
        "shinpai_id": shinpai_id,
        "recovery_seed_hash": hashlib.sha256(recovery_seed.encode()).hexdigest(),
        "totp_secret": totp_secret,
        "totp_confirmed": False,  # Erst True nach erster Code-Bestätigung
        "created": int(time.time()),
    }
    _hive_stamps = []

    # Identity in Vault speichern
    _save_identity()
    _save_hives()

    nexus_log(f"Account erstellt: {name} ({shinpai_id})", "green")
    return {
        "shinpai_id": shinpai_id,
        "recovery_seed": recovery_seed,
        "totp_secret": totp_secret,
        "totp_uri": totp_uri,
    }


def _save_identity():
    """Identity-Daten in Vault speichern."""
    if not _identity:
        return
    data = json.dumps(_identity, ensure_ascii=False).encode("utf-8")
    IDENTITY_VAULT.write_bytes(vault_encrypt(data))
    try:
        os.chmod(IDENTITY_VAULT, 0o600)
    except OSError:
        pass


def _load_identity() -> bool:
    """Identity aus Vault laden. Gibt True zurück bei Erfolg."""
    global _identity
    if not IDENTITY_VAULT.exists():
        return False
    try:
        raw = vault_decrypt(IDENTITY_VAULT.read_bytes())
        _identity = json.loads(raw.decode())
        nexus_log(f"Identity geladen: {_identity['name']} ({_identity['shinpai_id']})", "green")
        return True
    except Exception as e:
        nexus_log(f"Identity laden fehlgeschlagen: {e}", "red")
        return False


def _save_hives():
    """Hive-Stempel in Vault speichern."""
    data = json.dumps(_hive_stamps, ensure_ascii=False).encode("utf-8")
    HIVES_VAULT.write_bytes(vault_encrypt(data))
    try:
        os.chmod(HIVES_VAULT, 0o600)
    except OSError:
        pass


def _load_hives() -> bool:
    """Hive-Stempel aus Vault laden."""
    global _hive_stamps
    if not HIVES_VAULT.exists():
        _hive_stamps = []
        return True
    try:
        raw = vault_decrypt(HIVES_VAULT.read_bytes())
        _hive_stamps = json.loads(raw.decode())
        nexus_log(f"{len(_hive_stamps)} Hive-Stempel geladen", "green")
        return True
    except Exception as e:
        nexus_log(f"Hive-Stempel laden fehlgeschlagen: {e}", "red")
        _hive_stamps = []
        return False


# ══════════════════════════════════════════════════════════════════════
#  AGENTS (Bots, Phoenixe)
# ══════════════════════════════════════════════════════════════════════

def _save_agents():
    """Agent-Liste in Vault speichern."""
    data = json.dumps(_agents, ensure_ascii=False).encode("utf-8")
    AGENTS_VAULT.write_bytes(vault_encrypt(data))
    try:
        os.chmod(AGENTS_VAULT, 0o600)
    except OSError:
        pass


def _load_agents() -> bool:
    """Agent-Liste aus Vault laden."""
    global _agents
    if not AGENTS_VAULT.exists():
        _agents = []
        return True
    try:
        raw = vault_decrypt(AGENTS_VAULT.read_bytes())
        _agents = json.loads(raw.decode())
        nexus_log(f"{len(_agents)} Agent(s) geladen", "green")
        return True
    except Exception as e:
        nexus_log(f"Agents laden fehlgeschlagen: {e}", "red")
        _agents = []
        return False


def _save_users():
    """User-Dict in Vault speichern."""
    data = json.dumps(_users, ensure_ascii=False).encode("utf-8")
    USERS_VAULT.write_bytes(vault_encrypt(data))
    try:
        os.chmod(USERS_VAULT, 0o600)
    except OSError:
        pass


def _load_users() -> bool:
    """User-Dict aus Vault laden."""
    global _users
    if not USERS_VAULT.exists():
        _users = {}
        return True
    try:
        raw = vault_decrypt(USERS_VAULT.read_bytes())
        _users = json.loads(raw.decode())
        nexus_log(f"{len(_users)} User geladen", "green")
        return True
    except Exception as e:
        nexus_log(f"Users laden fehlgeschlagen: {e}", "red")
        _users = {}
        return False


# ══════════════════════════════════════════════════════════════════════
#  MIGRATION ABUSE-DETECTION — gestaffelte Sperren mit Redemption
#  Ziel: Spam/Hacker abwehren, ehrliche Bot-Armee-Migrationen durchlassen.
# ══════════════════════════════════════════════════════════════════════

_migrate_abuse: dict = {}   # {ip: {"fails": [ts...], "blocked_until": ts, "level": 0-3, "redemption_until": ts}}

# Stufenmodell (level → (trigger_windows_sec, block_dur_sec, redemption_dur_sec))
# trigger_windows: Liste [(count, window_sec), ...] — eine erfuellte Bedingung reicht
_MIGRATE_ABUSE_STAGES = {
    # Stufe 1: 3 Fails in 5 Minuten → 24h Sperre, 14 Tage Redemption
    1: {"triggers": [(3, 300)],                             "block": 24*3600,       "redemption": 14*86400},
    # Stufe 2: 3 Fails in 7 Tagen (nach Stufe-1-Redemption nochmal) → 90 Tage, 180 Tage Redemption
    2: {"triggers": [(3, 300), (3, 7*86400)],               "block": 90*86400,      "redemption": 180*86400},
    # Stufe 3: 3 Fails in 180 Tagen (nach Stufe-2-Redemption nochmal) → 365 Tage, 5 Jahre Redemption
    3: {"triggers": [(3, 300), (3, 7*86400), (3, 180*86400)], "block": 365*86400,  "redemption": 5*365*86400},
    # Rezidiv in Stufe 3: 3 Fails in 5 Jahren → nochmal 365 Tage, Redemption bleibt
}


def _save_migrate_abuse():
    """Persistiert Abuse-State. Sperren von Tagen/Jahren muessen Neustart ueberleben."""
    if not vault_is_unlocked():
        return  # Vault zu — kein Save, wird beim naechsten Moment versucht
    try:
        data = json.dumps(_migrate_abuse, ensure_ascii=False).encode("utf-8")
        MIGRATE_ABUSE_VAULT.write_bytes(vault_encrypt(data))
        try:
            os.chmod(MIGRATE_ABUSE_VAULT, 0o600)
        except OSError:
            pass
    except Exception as e:
        nexus_log(f"⚠️ Migrate-Abuse-Save Fehler: {e}", "yellow")


def _load_migrate_abuse():
    """Laedt Abuse-State beim Start (nach Vault-Unlock)."""
    global _migrate_abuse
    if not MIGRATE_ABUSE_VAULT.exists() or not vault_is_unlocked():
        _migrate_abuse = {}
        return
    try:
        raw = vault_decrypt(MIGRATE_ABUSE_VAULT.read_bytes())
        _migrate_abuse = json.loads(raw.decode())
    except Exception as e:
        nexus_log(f"⚠️ Migrate-Abuse-Load Fehler: {e} — starte leer", "yellow")
        _migrate_abuse = {}


def _fmt_duration(sec: float) -> str:
    """Sekunden → '2d 3h' / '45min' usw."""
    sec = int(max(0, sec))
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}min"
    if sec < 86400:
        h = sec // 3600
        m = (sec % 3600) // 60
        return f"{h}h {m}min" if m else f"{h}h"
    d = sec // 86400
    h = (sec % 86400) // 3600
    return f"{d}T {h}h" if h else f"{d}T"


def _migrate_abuse_check(ip: str):
    """Prueft ob IP aktuell gesperrt ist. Redemption abgelaufen → Stufe 0.
    Returns (allowed: bool, error_msg: str, retry_after: int)"""
    now = time.time()
    entry = _migrate_abuse.get(ip)
    if not entry:
        return True, "", 0
    blocked_until = entry.get("blocked_until", 0)
    if now < blocked_until:
        wait = int(blocked_until - now)
        level = entry.get("level", 1)
        return False, f"Gesperrt (Stufe {level}). Noch {_fmt_duration(wait)}.", wait
    # Redemption durchgelaufen? → Stufe zurueck auf 0, Historie leeren
    red_end = entry.get("redemption_until", 0)
    if red_end and now > red_end:
        entry["level"] = 0
        entry["redemption_until"] = 0
        entry["fails"] = []
        _save_migrate_abuse()
    return True, "", 0


def _migrate_abuse_register_fail(ip: str, reason: str = ""):
    """Zaehlt einen Migration-Fehlversuch und eskaliert falls Schwelle erreicht."""
    now = time.time()
    entry = _migrate_abuse.setdefault(ip, {
        "fails": [], "blocked_until": 0, "level": 0, "redemption_until": 0,
    })
    entry["fails"].append(now)
    # Alte Fails (> 5 Jahre) ausmisten
    entry["fails"] = [t for t in entry["fails"] if now - t < 5 * 365 * 86400]
    current_level = entry.get("level", 0)
    next_level = current_level + 1 if current_level < 3 else 3
    # Rezidiv auf Stufe 3: bei 5-Jahres-Fenster neuer 365-Tage-Block
    if current_level >= 3:
        fails_in_5y = [t for t in entry["fails"] if now - t < 5 * 365 * 86400]
        if len(fails_in_5y) >= 3:
            entry["blocked_until"] = now + 365 * 86400
            entry["redemption_until"] = entry["blocked_until"] + 5 * 365 * 86400
            entry["fails"] = []
            nexus_log(f"🚫 Migrate-Abuse Rezidiv auf Stufe 3 von {ip}: +365 Tage Sperre", "red")
            _save_migrate_abuse()
        return
    # Pruefen ob der naechste Level getriggert wird
    stage = _MIGRATE_ABUSE_STAGES.get(next_level)
    if not stage:
        return
    triggered = False
    for count, window in stage["triggers"]:
        fails_in_win = [t for t in entry["fails"] if now - t < window]
        if len(fails_in_win) >= count:
            triggered = True
            break
    if triggered:
        entry["level"] = next_level
        entry["blocked_until"] = now + stage["block"]
        entry["redemption_until"] = entry["blocked_until"] + stage["redemption"]
        entry["fails"] = []  # nach Eskalation zuruecksetzen
        nexus_log(
            f"🚫 Migrate-Abuse Stufe {next_level} von {ip}"
            f" — Sperre {_fmt_duration(stage['block'])},"
            f" Redemption {_fmt_duration(stage['redemption'])}. Grund: {reason or '?'}",
            "red",
        )
    _save_migrate_abuse()


def _save_user_hives():
    """User-Hive-Stempel in Vault speichern."""
    data = json.dumps(_user_hives, ensure_ascii=False).encode("utf-8")
    USER_HIVES_VAULT.write_bytes(vault_encrypt(data))
    try:
        os.chmod(USER_HIVES_VAULT, 0o600)
    except OSError:
        pass


def _load_user_hives() -> bool:
    """User-Hive-Stempel aus Vault laden."""
    global _user_hives
    if not USER_HIVES_VAULT.exists():
        _user_hives = {}
        return True
    try:
        raw = vault_decrypt(USER_HIVES_VAULT.read_bytes())
        _user_hives = json.loads(raw.decode())
        nexus_log(f"User-Hive-Stempel geladen ({len(_user_hives)} User)", "green")
        return True
    except Exception as e:
        nexus_log(f"User-Hive-Stempel laden fehlgeschlagen: {e}", "red")
        _user_hives = {}
        return False


def _generate_qr_svg_b64(data: str) -> str:
    """Erzeugt QR-Code als base64-encoded SVG Data-URL. Gibt '' zurück wenn segno fehlt."""
    if not HAS_QR:
        return ""
    try:
        qr = segno.make(data)
        buf = _io.BytesIO()
        qr.save(buf, kind="svg", scale=8, dark="#000000", light="#ffffff", border=2)
        svg_bytes = buf.getvalue()
        b64 = base64.b64encode(svg_bytes).decode("ascii")
        return f"data:image/svg+xml;base64,{b64}"
    except Exception:
        return ""


def _generate_user_keypair() -> dict:
    """Erzeugt ML-DSA-65 + ML-KEM-768 Keypair für einen User. Gibt Keys-Dict zurück."""
    sig = oqs.Signature("ML-DSA-65")
    sig_pk = sig.generate_keypair()
    sig_sk = sig.export_secret_key()

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    kem_pk = kem.generate_keypair()
    kem_sk = kem.export_secret_key()

    return {
        "algo": "ML-DSA-65",
        "sig_sk": sig_sk.hex(),
        "sig_pk": sig_pk.hex(),
        "kem_sk": kem_sk.hex(),
        "kem_pk": kem_pk.hex(),
        "created": int(time.time()),
    }


# ══════════════════════════════════════════════════════════════════════
#  SMTP — Email-Verifizierung (Kneipe-Style!)
# ══════════════════════════════════════════════════════════════════════

def smtp_configured(cfg: dict = None) -> bool:
    if not cfg:
        cfg = load_config()
    smtp = cfg.get("smtp", {})
    has_pw = bool(smtp.get("password")) or smtp.get("_pw_in_vault")
    return bool(smtp.get("host") and smtp.get("user") and has_pw)


def send_nexus_email(to_email: str, subject: str, html: str, cfg: dict = None):
    """Email via SMTP senden. Gibt True/False zurück."""
    if not cfg:
        cfg = load_config()
    smtp = cfg.get("smtp", {})
    if not smtp.get("host"):
        nexus_log("SMTP nicht konfiguriert!", "red")
        return False
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp.get("from", smtp["user"])
        msg["To"] = to_email
        msg.attach(MIMEText(html, "html"))
        port = int(smtp.get("port", 587))
        if port == 465:
            server = smtplib.SMTP_SSL(smtp["host"], port, timeout=30)
        else:
            server = smtplib.SMTP(smtp["host"], port, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()
        smtp_pw = smtp.get("password") or _get_smtp_password()
        server.login(smtp["user"], smtp_pw)
        server.sendmail(msg["From"], to_email, msg.as_string())
        server.quit()
        nexus_log(f"📧 Mail gesendet", "green")
        return True
    except Exception as e:
        nexus_log(f"📧 Mail fehlgeschlagen: {e}", "red")
        return False


# ══════════════════════════════════════════════════════════════════════
#  FIREMAIL — PQ-signierte, selbstzerstörende Nachrichten
# ══════════════════════════════════════════════════════════════════════

# Erlaubte TTLs (Sekunden) — mehr gibt's nicht!
FIREMAIL_TTLS = {
    '10s': 10, '30s': 30, '60s': 60,
    '3min': 180, '5min': 300, '10min': 600, '15min': 900,
    '60min': 3600, '3h': 10800, '6h': 21600, '12h': 43200,
    '24h': 86400, '3d': 259200, '7d': 604800,
    '30d': 2592000, '365d': 31536000,
}
FIREMAIL_MAX_TTL = 157680000  # 5 Jahre absolutes Maximum

# In-Memory Store: {firemail_id: {sender_id, sender_name, text, hash, signature, created, expires, read_count, max_reads}}
_firemails: dict = {}


def firemail_create(sender_id: str, sender_name: str, text: str, ttl_key: str, max_reads: int = 1) -> dict:
    """Firemail erstellen: PQ-signiert, gehashed, mit Ablaufdatum."""
    ttl = FIREMAIL_TTLS.get(ttl_key)
    if not ttl:
        return {"error": f"Ungültige TTL! Erlaubt: {list(FIREMAIL_TTLS.keys())}"}
    if ttl > FIREMAIL_MAX_TTL:
        return {"error": "Max 5 Jahre!"}
    if not text or len(text) > 10000:
        return {"error": "Text: 1-10000 Zeichen!"}

    now = int(time.time())
    firemail_id = secrets.token_hex(16)

    # Hash der Nachricht (Integrität)
    content_hash = hashlib.sha256(f"{firemail_id}:{sender_id}:{now}:{text}".encode()).hexdigest()

    # PQ-Signatur (Beweis der Identität)
    sign_input = f"firemail:{firemail_id}:{sender_id}:{now}:{content_hash}".encode()
    try:
        signature = _sign_data(sign_input)
    except Exception:
        signature = ""

    _firemails[firemail_id] = {
        "sender_id": sender_id,
        "sender_name": sender_name,
        "text": text,
        "hash": content_hash,
        "signature": signature,
        "public_key": _pq_keys.get("sig_pk", "") if _pq_keys else "",
        "created": now,
        "expires": now + ttl,
        "ttl_key": ttl_key,
        "read_count": 0,
        "max_reads": max_reads,
    }

    nexus_log(f"🔥 FIREMAIL erstellt TTL={ttl_key}", "cyan")

    return {
        "ok": True,
        "firemail_id": firemail_id,
        "hash": content_hash,
        "expires": now + ttl,
        "ttl": ttl_key,
        "max_reads": max_reads,
    }


def firemail_read(firemail_id: str) -> dict:
    """Firemail lesen. Zählt Reads, löscht bei Ablauf oder Max-Reads."""
    fm = _firemails.get(firemail_id)
    if not fm:
        return {"error": "Firemail nicht gefunden oder bereits verbrannt 🔥"}

    now = int(time.time())

    # Abgelaufen?
    if now > fm["expires"]:
        del _firemails[firemail_id]
        nexus_log(f"🔥 FIREMAIL VERBRANNT (TTL)", "yellow")
        return {"error": "Firemail abgelaufen und verbrannt 🔥"}

    fm["read_count"] += 1
    remaining = fm["expires"] - now

    result = {
        "ok": True,
        "sender_name": fm["sender_name"],
        "sender_id": fm["sender_id"],
        "text": fm["text"],
        "hash": fm["hash"],
        "signature": fm["signature"],
        "public_key": fm["public_key"],
        "created": fm["created"],
        "expires": fm["expires"],
        "remaining_seconds": remaining,
        "ttl": fm["ttl_key"],
        "read_count": fm["read_count"],
        "max_reads": fm["max_reads"],
        "verified": bool(fm["signature"]),
    }

    # Max Reads erreicht? → Verbrennen!
    if fm["max_reads"] > 0 and fm["read_count"] >= fm["max_reads"]:
        del _firemails[firemail_id]
        result["burned"] = True
        nexus_log(f"🔥 FIREMAIL VERBRANNT (Max-Reads)", "yellow")

    return result


def firemail_verify(firemail_id: str, content_hash: str) -> dict:
    """Firemail-Hash verifizieren (auch nach dem Lesen überprüfbar)."""
    fm = _firemails.get(firemail_id)
    if not fm:
        return {"error": "Firemail nicht gefunden"}
    return {
        "ok": True,
        "hash_match": fm["hash"] == content_hash,
        "signature_present": bool(fm["signature"]),
        "sender_id": fm["sender_id"],
        "sender_name": fm["sender_name"],
    }


def _firemail_cleanup():
    """Abgelaufene Firemails aufräumen."""
    now = time.time()
    expired = [fid for fid, fm in _firemails.items() if now > fm["expires"]]
    for fid in expired:
        del _firemails[fid]
        nexus_log(f"🔥 FIREMAIL VERBRANNT (Cleanup) — {fid[:8]}...", "yellow")
    return len(expired)


# Verifizierungs-Tokens: {token: {email, shinpai_id, created}}
# Email-Verify — 1:1 Kneipe-Muster: 6-stelliger Ziffern-Code, 10 min gueltig
VERIFY_CODE_TTL = 600  # 10 Minuten


def generate_verify_code() -> str:
    """6-stelliger Ziffern-Code (wie Kneipe). Einfach, DAU-tauglich."""
    return ''.join(secrets.choice('0123456789') for _ in range(6))


def send_verify_email(to_email: str, username: str, shinpai_id: str, verify_code: str, cfg: dict = None):
    """Shinpai-AI Verifizierungs-Mail mit 6-stelligem Code (Kneipe-Muster)."""
    html = f"""
    <div style="background:#0a0a0a;color:#e0d8c8;font-family:Georgia,serif;padding:40px;max-width:520px;margin:0 auto;border:1px solid #1a1a1a;">
      <div style="text-align:center;">
        <div style="font-size:42px;margin-bottom:10px;">🛡️</div>
        <h1 style="color:#7ab8e0;margin:0 0 5px 0;font-size:22px;">ShinNexus</h1>
        <div style="color:#556677;font-size:12px;letter-spacing:2px;margin-bottom:25px;">SAME KNOWLEDGE. YOUR OWNERSHIP.</div>

        <div style="background:#0d1117;border:1px solid #1a2a3a;border-radius:10px;padding:20px;margin:20px 0;">
          <div style="font-size:16px;color:#e0d8c8;">Hallo <strong style="color:#7ab8e0;">{username}</strong></div>
          <div style="font-size:13px;color:#556677;margin-top:5px;">Shinpai-ID: <code style="color:#7ab8e0;">{shinpai_id}</code></div>
        </div>

        <div style="margin:28px 0;padding:24px 12px;background:#1a3a5a;border:1px solid #3a5a7a;border-radius:12px;">
          <div style="font-size:12px;color:#7ab8e0;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;">Dein Bestaetigungs-Code</div>
          <div style="font-family:monospace;font-size:42px;letter-spacing:12px;color:#7ab8e0;font-weight:bold;">{verify_code}</div>
          <div style="font-size:11px;color:#556677;margin-top:12px;">10 Minuten gueltig</div>
        </div>

        <div style="font-size:13px;color:#887755;line-height:1.6;">
          Code im ShinNexus-Dashboard eingeben (Sicherheits-Tab).<br>
          Du hast den Code nicht angefordert? Einfach ignorieren.
        </div>

        <div style="background:#0d1117;border-left:3px solid #3a5a7a;padding:15px;margin:25px 0;text-align:left;border-radius:0 8px 8px 0;">
          <div style="font-size:11px;color:#3a5a7a;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Shinpai-AI Weisheit</div>
          <div style="font-size:14px;color:#998870;font-style:italic;">"Deine Identitaet gehoert dir. Nicht der Cloud. Nicht dem Konzern. Nicht dem Algorithmus. Dir."</div>
        </div>

        <hr style="border:none;border-top:1px solid #1a1a1a;margin:25px 0;">

        <div style="font-size:11px;color:#334455;">
          Shinpai-AI — Same Knowledge. Your Ownership.<br>
          <span style="color:#556677;">Ist einfach passiert. 🐉</span>
        </div>
      </div>
    </div>
    """
    subject = f"🛡️ ShinNexus-Code: {verify_code}"
    return send_nexus_email(to_email, subject, html, cfg)


def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Passwort hashen mit PBKDF2. Gibt (hash_hex, salt_hex) zurück."""
    if salt is None:
        salt_bytes = secrets.token_bytes(32)
    else:
        salt_bytes = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 600_000)
    return dk.hex(), salt_bytes.hex()


def _verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """Passwort gegen gespeicherten Hash prüfen."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(stored_salt), 600_000)
    return secrets.compare_digest(dk.hex(), stored_hash)


def _generate_agent_shinpai_id(name: str) -> str:
    """Agent-Shinpai-ID: [NameHash6]-[RandomHash6]. Einmalig."""
    name_hash = _b62_hash(f"agent-{name}-{time.time()}")
    rand_hash = _b62_hash(f"agent-rand-{secrets.token_hex(16)}")
    return f"{name_hash}-{rand_hash}"


def _find_agent(shinpai_id: str) -> dict | None:
    """Agent anhand Shinpai-ID finden."""
    for a in _agents:
        if a.get("shinpai_id") == shinpai_id:
            return a
    return None


# ══════════════════════════════════════════════════════════════════════
#  FRIENDS & DM SYSTEM
# ══════════════════════════════════════════════════════════════════════

def _save_friends():
    """Freundschaften in Vault speichern."""
    data = json.dumps(_friends_data, ensure_ascii=False).encode("utf-8")
    FRIENDS_VAULT.write_bytes(vault_encrypt(data))
    try:
        os.chmod(FRIENDS_VAULT, 0o600)
    except OSError:
        pass


def _load_friends() -> bool:
    """Freundschaften aus Vault laden."""
    global _friends_data
    if not FRIENDS_VAULT.exists():
        _friends_data = {}
        return True
    try:
        raw = vault_decrypt(FRIENDS_VAULT.read_bytes())
        _friends_data = json.loads(raw.decode())
        total = sum(len(v.get("friends", [])) for v in _friends_data.values())
        nexus_log(f"{total} Freundschaften geladen", "green")
        return True
    except Exception as e:
        nexus_log(f"Freundschaften laden fehlgeschlagen: {e}", "red")
        _friends_data = {}
        return False


def _get_friends_entry(shinpai_id: str) -> dict:
    """Friends-Eintrag fuer eine Shinpai-ID (erstellt wenn noetig)."""
    if shinpai_id not in _friends_data:
        _friends_data[shinpai_id] = {
            "friends": [],
            "pending_in": [],
            "pending_out": [],
            "blocked": [],
        }
    return _friends_data[shinpai_id]


def _make_contact(shinpai_id: str, name: str, nexus_url: str,
                  public_key: str = "", kem_public_key: str = "",
                  hive_source: str = "") -> dict:
    """Kontakt-Objekt erstellen (Federation-ready: volle Info!)."""
    return {
        "shinpai_id": shinpai_id,
        "name": name,
        "nexus_url": nexus_url,
        "public_key": public_key,
        "kem_public_key": kem_public_key,
        "hive_source": hive_source,
        "since": datetime.now().isoformat(),
    }


def _find_contact_in_list(lst: list, shinpai_id: str) -> dict | None:
    """Kontakt in einer Liste finden."""
    for c in lst:
        if c.get("shinpai_id") == shinpai_id:
            return c
    return None


def _remove_contact_from_list(lst: list, shinpai_id: str) -> bool:
    """Kontakt aus einer Liste entfernen. Returns True wenn gefunden."""
    for i, c in enumerate(lst):
        if c.get("shinpai_id") == shinpai_id:
            lst.pop(i)
            return True
    return False


def _dm_store_pending(to_shinpai_id: str, from_shinpai_id: str,
                      from_name: str, encrypted_blob: str,
                      from_nexus_url: str = "",
                      kem_ciphertext: str = "") -> str:
    """Verschluesselte DM als Pending speichern. Returns message_id.

    kem_ciphertext: ML-KEM-768 Ciphertext (hex) — Empfaenger braucht diesen
    um den shared_secret per Decapsulation abzuleiten und encrypted_blob
    mit AES-256-GCM zu entschluesseln. E2E: ShinNexus sieht nur Blobs!
    """
    msg_id = secrets.token_hex(8)
    msg = {
        "id": msg_id,
        "from_shinpai_id": from_shinpai_id,
        "from_name": from_name,
        "from_nexus_url": from_nexus_url,
        "encrypted_blob": encrypted_blob,
        "kem_ciphertext": kem_ciphertext,
        "timestamp": datetime.now().isoformat(),
    }
    target_dir = DM_PENDING_DIR / to_shinpai_id
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / f"{msg_id}.json").write_text(
        json.dumps(msg, ensure_ascii=False), encoding="utf-8")
    return msg_id


def _dm_get_pending(shinpai_id: str) -> list:
    """Alle pending DMs fuer eine Shinpai-ID laden."""
    target_dir = DM_PENDING_DIR / shinpai_id
    if not target_dir.exists():
        return []
    msgs = []
    for f in sorted(target_dir.glob("*.json")):
        try:
            msgs.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return msgs


def _dm_ack_messages(shinpai_id: str, message_ids: list) -> int:
    """Bestaetigte DMs loeschen. Returns Anzahl geloescht."""
    target_dir = DM_PENDING_DIR / shinpai_id
    if not target_dir.exists():
        return 0
    count = 0
    for mid in message_ids:
        f = target_dir / f"{mid}.json"
        if f.exists():
            f.unlink()
            count += 1
    return count


# ══════════════════════════════════════════════════════════════════════
#  CHALLENGE SYSTEM
# ══════════════════════════════════════════════════════════════════════

# Aktive Challenges: {challenge_id: {challenge, created, source}}
_active_challenges: dict = {}
_CHALLENGE_TTL = 60  # 60 Sekunden gültig


def _create_challenge(source: str = "unknown") -> dict:
    """Erstellt neue Challenge für Verifizierung."""
    challenge_id = secrets.token_hex(16)
    challenge = secrets.token_hex(32)
    _active_challenges[challenge_id] = {
        "challenge": challenge,
        "created": time.time(),
        "source": source,
    }
    # Alte Challenges aufräumen
    now = time.time()
    expired = [k for k, v in _active_challenges.items() if now - v["created"] > _CHALLENGE_TTL]
    for k in expired:
        del _active_challenges[k]

    return {"challenge_id": challenge_id, "challenge": challenge}


def _verify_challenge(challenge_id: str, signature_hex: str) -> bool:
    """Prüft ob die Signatur zur Challenge passt."""
    if challenge_id not in _active_challenges:
        return False
    ch = _active_challenges.pop(challenge_id)
    if time.time() - ch["created"] > _CHALLENGE_TTL:
        return False
    # Signatur prüfen: Wir haben den eigenen PubKey, also Self-Verify
    challenge_bytes = ch["challenge"].encode()
    if not _pq_keys:
        return False
    return _verify_signature(challenge_bytes, signature_hex, _pq_keys["sig_pk"])


# ══════════════════════════════════════════════════════════════════════
#  RATE LIMITING
# ══════════════════════════════════════════════════════════════════════

_rate_limits: dict = {}  # {ip: [timestamps]}
_RATE_LIMIT_WINDOW = 60  # 1 Minute
_RATE_LIMIT_MAX = 300  # 5/sek normale Dashboard-Nutzung — Brute-Force-Schutz separat via _auth_fail


def _check_rate_limit(ip: str) -> bool:
    """True = erlaubt, False = zu viele Requests.
    Localhost ist ausgenommen (vertrauenswürdig, Owner sitzt direkt dran)."""
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    now = time.time()
    if ip not in _rate_limits:
        _rate_limits[ip] = []
    _rate_limits[ip] = [t for t in _rate_limits[ip] if now - t < _RATE_LIMIT_WINDOW]
    if len(_rate_limits[ip]) >= _RATE_LIMIT_MAX:
        return False
    _rate_limits[ip].append(now)
    return True


# ══════════════════════════════════════════════════════════════════════
#  TOTP / 2FA (konsistent mit Shidow/ShinShare)
# ══════════════════════════════════════════════════════════════════════


def totp_generate_secret() -> str:
    """Neues TOTP-Secret generieren."""
    if HAS_TOTP:
        return pyotp.random_base32()
    return secrets.token_hex(20).upper()


def totp_verify(secret: str, code: str) -> bool:
    """TOTP-Code prüfen (±30s Fenster)."""
    if not HAS_TOTP or not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


def totp_get_uri(secret: str, name: str) -> str:
    """otpauth:// URI für Authenticator-App / QR-Code."""
    if not HAS_TOTP:
        return ""
    return pyotp.TOTP(secret).provisioning_uri(
        name=name, issuer_name="ShinNexus"
    )


# ══════════════════════════════════════════════════════════════════════
#  FRPC TUNNEL — NAT-Traversal für Remote-Zugriff
# ══════════════════════════════════════════════════════════════════════

_frpc_process: subprocess.Popen | None = None


def _find_frpc() -> str | None:
    """frpc Binary finden."""
    # 1. Im ShinNexus-Ordner
    local = BASE / "frpc"
    if local.exists() and os.access(local, os.X_OK):
        return str(local)
    # 2. System PATH
    found = shutil.which("frpc")
    if found:
        return found
    return None


def _generate_frpc_toml(cfg: dict) -> str:
    """frpc.toml für ShinNexus-Tunnel generieren."""
    tunnel = cfg.get("tunnel", {})
    server = tunnel.get("server", "")
    server_port = tunnel.get("server_port", 7000)
    token = tunnel.get("token", "")
    domain = tunnel.get("domain", "")

    nexus_port = cfg.get("port", DEFAULT_PORT)
    proto = "https" if cfg.get("tls", {}).get("mode", "auto") != "off" else "http"

    # Subdomain: nexus.domain.de
    subdomain = tunnel.get("subdomain", "nexus")

    toml = f"""# ShinNexus frpc — Auto-Generated
serverAddr = "{server}"
serverPort = {server_port}
auth.token = "{token}"

[[proxies]]
name = "nexus"
type = "{proto}"
localPort = {nexus_port}
"""
    if domain:
        toml += f'customDomains = ["{subdomain}.{domain}"]\n'
    else:
        toml += f'subdomain = "{subdomain}"\n'

    # Optional: Shidow + ShinShare mit-tunneln
    shidow_tunnel = tunnel.get("shidow", {})
    if shidow_tunnel.get("enabled"):
        s_port = shidow_tunnel.get("port", 1208)
        s_sub = shidow_tunnel.get("subdomain", "shidow")
        s_proto = shidow_tunnel.get("proto", "https")
        toml += f"""
[[proxies]]
name = "shidow"
type = "{s_proto}"
localPort = {s_port}
"""
        if domain:
            toml += f'customDomains = ["{s_sub}.{domain}"]\n'
        else:
            toml += f'subdomain = "{s_sub}"\n'

    shinshare_tunnel = tunnel.get("shinshare", {})
    if shinshare_tunnel.get("enabled"):
        ss_port = shinshare_tunnel.get("port", 3669)
        ss_sub = shinshare_tunnel.get("subdomain", "hive")
        ss_proto = shinshare_tunnel.get("proto", "https")
        toml += f"""
[[proxies]]
name = "shinshare"
type = "{ss_proto}"
localPort = {ss_port}
"""
        if domain:
            toml += f'customDomains = ["{ss_sub}.{domain}"]\n'
        else:
            toml += f'subdomain = "{ss_sub}"\n'

    return toml


def start_tunnel(cfg: dict) -> bool:
    """frpc Tunnel starten (non-blocking)."""
    global _frpc_process
    tunnel = cfg.get("tunnel", {})
    if not tunnel.get("enabled"):
        return False

    frpc = _find_frpc()
    if not frpc:
        nexus_log("frpc nicht gefunden! Install: https://github.com/fatedier/frp/releases", "red")
        return False

    server = tunnel.get("server", "")
    if not server:
        nexus_log("tunnel.server fehlt in Config!", "red")
        return False

    # frpc.toml schreiben
    toml_path = BASE / "frpc.toml"
    toml_content = _generate_frpc_toml(cfg)
    toml_path.write_text(toml_content, encoding="utf-8")
    try:
        os.chmod(toml_path, 0o600)  # Token drin!
    except OSError:
        pass

    # frpc starten
    try:
        _frpc_process = subprocess.Popen(
            [frpc, "-c", str(toml_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Log-Thread für frpc Output
        def _log_frpc():
            for line in _frpc_process.stdout:
                line = line.strip()
                if line:
                    nexus_log(f"[frpc] {line}", "dim")
        threading.Thread(target=_log_frpc, daemon=True).start()

        domain = tunnel.get("domain", tunnel.get("server", ""))
        subdomain = tunnel.get("subdomain", "nexus")
        nexus_log(f"frpc Tunnel gestartet → {subdomain}.{domain}", "green")

        # Shidow/ShinShare Tunnel-Info loggen
        if tunnel.get("shidow", {}).get("enabled"):
            s_sub = tunnel["shidow"].get("subdomain", "shidow")
            nexus_log(f"  Shidow Tunnel  → {s_sub}.{domain}", "green")
        if tunnel.get("shinshare", {}).get("enabled"):
            ss_sub = tunnel["shinshare"].get("subdomain", "hive")
            nexus_log(f"  ShinShare Tunnel → {ss_sub}.{domain}", "green")

        return True
    except Exception as e:
        nexus_log(f"frpc Start fehlgeschlagen: {e}", "red")
        return False


def stop_tunnel():
    """frpc Tunnel stoppen."""
    global _frpc_process
    if _frpc_process:
        _frpc_process.terminate()
        try:
            _frpc_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _frpc_process.kill()
        _frpc_process = None
        nexus_log("frpc Tunnel gestoppt", "yellow")


# ══════════════════════════════════════════════════════════════════════
#  CLOUDFLARE QUICK TUNNEL — Free Public URL für DAUs
# ══════════════════════════════════════════════════════════════════════

_cloudflared_process: subprocess.Popen | None = None
_public_url: str = ""  # https://random-words.trycloudflare.com


def _find_cloudflared() -> str | None:
    """cloudflared Binary finden."""
    local = BASE / "cloudflared"
    if local.exists() and os.access(local, os.X_OK):
        return str(local)
    found = shutil.which("cloudflared")
    if found:
        return found
    return None


def _download_cloudflared() -> str | None:
    """cloudflared automatisch runterladen (Linux amd64)."""
    import platform
    arch = platform.machine()
    arch_map = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm"}
    cf_arch = arch_map.get(arch, "amd64")

    url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}"
    dest = BASE / "cloudflared"
    nexus_log(f"Lade cloudflared herunter ({cf_arch})...", "cyan")
    try:
        import urllib.request
        urllib.request.urlretrieve(url, str(dest))
        os.chmod(dest, 0o755)
        nexus_log("cloudflared heruntergeladen!", "green")
        return str(dest)
    except Exception as e:
        nexus_log(f"cloudflared Download fehlgeschlagen: {e}", "red")
        return None


def start_cloudflare_tunnel(port: int) -> bool:
    """Cloudflare Quick Tunnel starten — braucht KEINEN Account!"""
    global _cloudflared_process, _public_url

    cf = _find_cloudflared()
    if not cf:
        cf = _download_cloudflared()
    if not cf:
        nexus_log("cloudflared nicht verfügbar!", "red")
        return False

    try:
        _cloudflared_process = subprocess.Popen(
            [cf, "tunnel", "--url", f"http://localhost:{port}", "--no-autoupdate"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # URL aus cloudflared Output extrahieren
        def _watch_cloudflared():
            global _public_url
            for line in _cloudflared_process.stdout:
                line = line.strip()
                if "trycloudflare.com" in line or "cfargotunnel.com" in line:
                    # URL extrahieren
                    import re
                    match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                    if match:
                        _public_url = match.group(0)
                        nexus_log(f"Öffentliche URL: {_public_url}", "green")
                        nexus_log("Jeder kann dich jetzt über diese URL erreichen!", "green")
                elif line and not line.startswith("2"):  # Nicht die Timestamp-Zeilen
                    nexus_log(f"[cloudflared] {line}", "dim")

        threading.Thread(target=_watch_cloudflared, daemon=True).start()
        nexus_log("Cloudflare Quick Tunnel wird gestartet...", "cyan")
        return True
    except Exception as e:
        nexus_log(f"cloudflared Start fehlgeschlagen: {e}", "red")
        return False


def stop_cloudflare_tunnel():
    """Cloudflare Tunnel stoppen."""
    global _cloudflared_process, _public_url
    if _cloudflared_process:
        _cloudflared_process.terminate()
        try:
            _cloudflared_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _cloudflared_process.kill()
        _cloudflared_process = None
        _public_url = ""
        nexus_log("Cloudflare Tunnel gestoppt", "yellow")


def get_public_url() -> str:
    """Aktuelle öffentliche URL (Cloudflare oder frpc)."""
    return _public_url


# ══════════════════════════════════════════════════════════════════════
#  AUTH ENDPOINT — Externe Services authentifizieren User über Nexus
# ══════════════════════════════════════════════════════════════════════

# Auth-Session Tokens: {token: {shinpai_id, created, expires, source}}
_auth_sessions: dict = {}
_AUTH_SESSION_TTL = 3600  # 1 Stunde


def _create_auth_session(source: str = "", user_override: dict = None) -> dict:
    """Erstellt eine signierte Auth-Session nach erfolgreicher Authentifizierung.
    user_override: {shinpai_id, name, pq_keys} für Non-Owner-User."""
    sid = user_override["shinpai_id"] if user_override else (_identity or {}).get("shinpai_id", "")
    sname = user_override["name"] if user_override else (_identity or {}).get("name", "")
    if not sid:
        return {}
    # User's eigene Keys für Signatur (Owner-Keys als Fallback)
    if user_override and user_override.get("pq_keys"):
        user_keys = user_override["pq_keys"]
    else:
        user_keys = _pq_keys
    if not user_keys:
        return {}
    token = secrets.token_hex(32)
    ts = int(time.time())
    session = {
        "token": token,
        "shinpai_id": sid,
        "name": sname,
        "created": ts,
        "expires": ts + _AUTH_SESSION_TTL,
        "source": source,
    }
    # Session signieren mit den Keys des eingeloggten Users
    sign_input = f"session:{token}:{ts}:{sid}".encode()
    try:
        sig = oqs.Signature("ML-DSA-65", secret_key=bytes.fromhex(user_keys["sig_sk"]))
        session["signature"] = sig.sign(sign_input).hex()
    except Exception:
        session["signature"] = _sign_data(sign_input)  # Fallback Owner-Key
    session["public_key"] = user_keys.get("sig_pk", "")

    _auth_sessions[token] = session

    # Alte Sessions aufräumen
    now = time.time()
    expired = [k for k, v in _auth_sessions.items() if now > v["expires"]]
    for k in expired:
        del _auth_sessions[k]

    return session


def validate_auth_session(token: str) -> dict | None:
    """Prüft ob eine Auth-Session gültig ist. Gibt Session-Daten zurück oder None."""
    session = _auth_sessions.get(token)
    if not session:
        return None
    if time.time() > session["expires"]:
        del _auth_sessions[token]
        return None
    return session


# ══════════════════════════════════════════════════════════════════════
#  VERIFICATION SYSTEM — Drei-Stufen-Verifikation (N1-N4)
# ══════════════════════════════════════════════════════════════════════

# Verification-State (RAM)
_verification_sessions: dict = {}  # {session_id: {shinpai_id, provider, level, status, created, ...}}
_VERIFY_SESSION_TTL = 3600  # 1 Stunde für Verifikations-Flow


class VerificationProvider:
    """Abstrakte Basis-Klasse für Verifikations-Provider (N4: Plugin-System).
    Jeder Provider implementiert start() und callback()."""

    name: str = "base"
    level: int = 0  # 1=Kreditkarte, 2=Perso, 3=Amt

    def available(self) -> bool:
        """Prüft ob der Provider konfiguriert und nutzbar ist."""
        return False

    def start(self, shinpai_id: str, cfg: dict) -> dict:
        """Startet den Verifikations-Flow.
        Returns: {session_id, client_secret/redirect_url, ...} oder {error}"""
        return {"error": "Provider nicht implementiert"}

    def callback(self, session_id: str, data: dict) -> dict:
        """Verarbeitet Callback/Bestätigung vom Provider.
        Returns: {verified: True/False, details: ...}"""
        return {"error": "Callback nicht implementiert"}


class StripeSetupIntentProvider(VerificationProvider):
    """Stufe 1: Kreditkartencheck via Stripe SetupIntent.
    Verifiziert echte Kreditkarte OHNE Abbuchung = 18+ Nachweis.
    Kosten: 0€ (SetupIntent ist kostenlos).
    Nexus speichert: KEINE Kartendaten! Nur verified_stripe: true."""

    name = "stripe"
    level = 1

    def available(self) -> bool:
        if not HAS_STRIPE:
            return False
        cfg = load_config()
        return bool(cfg.get("stripe_secret_key"))

    def start(self, shinpai_id: str, cfg: dict) -> dict:
        if not HAS_STRIPE:
            return {"error": "stripe Modul nicht installiert (pip install stripe)"}

        sk = cfg.get("stripe_secret_key")
        if not sk:
            return {"error": "stripe_secret_key nicht in Config"}

        _stripe_mod.api_key = sk

        session_id = secrets.token_hex(16)
        try:
            # Customer anlegen (für spätere Abbuchungen bei Stufe 2)
            customer = _stripe_mod.Customer.create(
                metadata={"shinpai_id": shinpai_id},
            )
            # SetupIntent an Customer binden — Karte wird dauerhaft gespeichert
            si = _stripe_mod.SetupIntent.create(
                customer=customer.id,
                usage="off_session",
                metadata={"shinpai_id": shinpai_id, "nexus_session": session_id},
            )
            _verification_sessions[session_id] = {
                "shinpai_id": shinpai_id,
                "provider": self.name,
                "level": self.level,
                "status": "pending",
                "stripe_si_id": si.id,
                "stripe_customer_id": customer.id,
                "created": int(time.time()),
            }
            return {
                "session_id": session_id,
                "client_secret": si.client_secret,
                "provider": self.name,
                "level": self.level,
            }
        except Exception as e:
            nexus_log(f"❌ Stripe SetupIntent Fehler: {e}", "red")
            return {"error": f"Stripe Fehler: {str(e)}"}

    def callback(self, session_id: str, data: dict) -> dict:
        vs = _verification_sessions.get(session_id)
        if not vs or vs["provider"] != self.name:
            return {"error": "Ungültige Session"}
        if vs["status"] != "pending":
            return {"error": f"Session bereits {vs['status']}"}

        cfg = load_config()
        sk = cfg.get("stripe_secret_key")
        if not sk:
            return {"error": "stripe_secret_key nicht in Config"}

        _stripe_mod.api_key = sk

        try:
            si = _stripe_mod.SetupIntent.retrieve(vs["stripe_si_id"])
            if si.status == "succeeded":
                vs["status"] = "verified"
                # Echtes Karten-Ablaufdatum für die Lizenz holen
                real_expiry_ts = None
                try:
                    _pm_id_lookup = si.payment_method
                    if _pm_id_lookup:
                        _pm = _stripe_mod.PaymentMethod.retrieve(_pm_id_lookup)
                        _card = getattr(_pm, "card", None)
                        if _card is not None:
                            _em = int(getattr(_card, "exp_month", 0) or 0)
                            _ey = int(getattr(_card, "exp_year", 0) or 0)
                            if _em and _ey:
                                import calendar as _cal
                                _last_day = _cal.monthrange(_ey, _em)[1]
                                real_expiry_ts = int(datetime(_ey, _em, _last_day, 23, 59, 59).timestamp())
                                # KEIN Logging von Karten-Details (DSGVO)
                                nexus_log(f"💳 Karten-Ablauf gelesen (in Vault gespeichert)", "cyan")
                except Exception:
                    # KEIN Logging des Exception-Bodies (kann Daten enthalten)
                    nexus_log(f"⚠️ Karten-Ablauf nicht lesbar (siehe Vault)", "yellow")
                # Verifikation in Identity/User speichern (mit echtem Ablauf)
                _apply_verification(vs["shinpai_id"], self.name, self.level, real_expiry_ts=real_expiry_ts)
                # Stripe Customer ID beim User persistieren (für spätere Abbuchungen)
                _cust_id = vs.get("stripe_customer_id", "")
                _pm_id = si.payment_method  # PaymentMethod aus SetupIntent
                if _cust_id and _pm_id:
                    try:
                        # PaymentMethod an Customer attachen (wenn nicht schon)
                        try:
                            _stripe_mod.PaymentMethod.attach(_pm_id, customer=_cust_id)
                        except Exception:
                            pass  # Schon attached → ok
                        # Als Default setzen für off_session Abbuchungen
                        _stripe_mod.Customer.modify(
                            _cust_id,
                            invoice_settings={"default_payment_method": _pm_id},
                        )
                        nexus_log(f"💳 PaymentMethod an Customer gebunden (default)", "green")
                    except Exception as ae:
                        nexus_log(f"⚠️ PaymentMethod Attach fehlgeschlagen: {ae}", "yellow")
                if _cust_id:
                    sid = vs["shinpai_id"]
                    if _identity and _identity.get("shinpai_id") == sid:
                        _identity["stripe_customer_id"] = _cust_id
                        _save_identity()
                    else:
                        for uname, udata in _users.items():
                            if udata.get("shinpai_id") == sid:
                                udata["stripe_customer_id"] = _cust_id
                                _save_users()
                                break
                nexus_log(f"✅ STRIPE VERIFIED: {vs['shinpai_id']} (customer: {_cust_id})", "green")
                return {"verified": True, "level": self.level, "provider": self.name}
            else:
                vs["status"] = "failed"
                return {"verified": False, "stripe_status": si.status}
        except Exception as e:
            nexus_log(f"❌ Stripe Callback Fehler: {e}", "red")
            return {"error": f"Stripe Fehler: {str(e)}"}


class VeriffIDProvider(VerificationProvider):
    """Stufe 2: Perso-Verifikation via Veriff (oder IDnow).
    Perso scannen + Gesicht abgleichen = echte Identität bestätigt.
    Kosten: 1-2€ pro Verifikation (User zahlt).
    Nexus speichert: KEINE Perso-Daten! Nur id_verified: true."""

    name = "veriff"
    level = 2

    def available(self) -> bool:
        cfg = load_config()
        if not cfg.get("veriff_enabled", True):
            return False
        return bool(cfg.get("veriff_api_key"))

    def start(self, shinpai_id: str, cfg: dict) -> dict:
        if not cfg.get("veriff_enabled", True):
            return {"error": "Veriff ist deaktiviert"}
        api_key = cfg.get("veriff_api_key")
        api_url = cfg.get("veriff_api_url", "https://stationapi.veriff.com/v1")
        if not api_key:
            return {"error": "veriff_api_key nicht in Config"}

        session_id = secrets.token_hex(16)

        # User auflösen: Username + stripe_customer_id
        username = ""
        stripe_customer_id = ""
        if _identity and _identity.get("shinpai_id") == shinpai_id:
            username = _identity.get("name", "")
            stripe_customer_id = _identity.get("stripe_customer_id", "")
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == shinpai_id:
                    username = uname
                    stripe_customer_id = udata.get("stripe_customer_id", "")
                    break

        # Sofort-Abbuchung via Stripe (Anti-Troll): User zahlt für Versuch
        stripe_payment_intent_id = ""
        if HAS_STRIPE and stripe_customer_id and cfg.get("stripe_secret_key"):
            _stripe_mod.api_key = cfg["stripe_secret_key"]
            try:
                # Default PaymentMethod vom Customer holen (Stripe-Objekt → getattr!)
                cust = _stripe_mod.Customer.retrieve(stripe_customer_id)
                pm_id = None
                inv_settings = getattr(cust, "invoice_settings", None)
                if inv_settings is not None:
                    pm_id = getattr(inv_settings, "default_payment_method", None)
                if not pm_id:
                    pms = _stripe_mod.PaymentMethod.list(customer=stripe_customer_id, type="card", limit=1)
                    if pms.data:
                        pm_id = pms.data[0].id
                if not pm_id:
                    return {"error": "Keine Karte hinterlegt — bitte Stufe 1 neu verifizieren"}

                price_eur = float(cfg.get("veriff_price_eur", 3.0))
                amount_cents = int(round(price_eur * 100))
                # SOFORT-Abbuchung (Anti-Troll): User zahlt für den VERSUCH.
                # Keine Erstattung bei Veriff-Fehlschlag (im UI klar kommuniziert).
                # Statement Descriptor: kommt direkt vom Stripe-Konto-Namen
                # (im Stripe-Dashboard unter Settings → Public business info ändern!)
                pi = _stripe_mod.PaymentIntent.create(
                    amount=amount_cents,
                    currency="eur",
                    customer=stripe_customer_id,
                    payment_method=pm_id,
                    confirm=True,
                    off_session=True,
                    metadata={"shinpai_id": shinpai_id, "purpose": "veriff_verification"},
                )
                stripe_payment_intent_id = pi.id
                nexus_log(f"💳 Sofort-Abbuchung {price_eur}€ erfolgreich", "green")
            except Exception as e:
                nexus_log(f"❌ Stripe Sofort-Abbuchung Fehler: {type(e).__name__}: {e}", "red")
                return {"error": f"Abbuchung fehlgeschlagen: {type(e).__name__}: {str(e)[:120]}"}
        elif not stripe_customer_id:
            return {"error": "Keine Stripe Customer ID — bitte erst Stufe 1 neu verifizieren"}

        try:
            import urllib.request
            # person.firstName = Firmenname (oder "privat"), person.lastName = Username
            # Im Veriff Monitoring sichtbar als "[Firma] [User]"
            company = cfg.get("license_company", "").strip() or "privat"
            # vendorData = nexus_session_id:shinpai_id (Webhook braucht session_id zum matchen)
            verification_body = {
                "vendorData": f"{session_id}:{shinpai_id}",
                "person": {
                    "firstName": company,
                    "lastName": username or "unknown",
                },
            }
            public_url = cfg.get("public_url", "").rstrip("/")
            if public_url:
                # Veriff "callback" ist die BROWSER-REDIRECT URL (GET) nach Verifikation,
                # NICHT die Webhook-URL! Webhook wird zentral im Veriff-Account-Settings
                # konfiguriert (Webhook Event URL + Decision URL).
                verification_body["callback"] = f"{public_url}/api/verify/callback"
            req_data = json.dumps({"verification": verification_body}).encode()
            req = urllib.request.Request(
                f"{api_url}/sessions",
                data=req_data,
                headers={"Content-Type": "application/json", "X-AUTH-CLIENT": api_key},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read())
            except urllib.error.HTTPError as he:
                err_body = he.read().decode("utf-8", errors="ignore")
                nexus_log(f"❌ Veriff HTTP {he.code} (Body nicht geloggt, DSGVO)", "red")
                # Veriff-Session nie zustande gekommen → User refunden (kein Versuch stattgefunden)
                if stripe_payment_intent_id:
                    try:
                        _stripe_mod.Refund.create(payment_intent=stripe_payment_intent_id)
                        nexus_log(f"💳 Refund: Veriff nie gestartet, erstattet", "yellow")
                    except Exception as ce:
                        nexus_log(f"⚠️ Refund fehlgeschlagen: {ce}", "yellow")
                return {"error": f"Veriff HTTP {he.code}"}

            veriff_session = result.get("verification", {})
            _verification_sessions[session_id] = {
                "shinpai_id": shinpai_id,
                "provider": self.name,
                "level": self.level,
                "status": "pending",
                "veriff_session_id": veriff_session.get("id", ""),
                "stripe_payment_intent_id": stripe_payment_intent_id,
                "created": int(time.time()),
            }
            return {
                "session_id": session_id,
                "redirect_url": veriff_session.get("url", ""),
                "provider": self.name,
                "level": self.level,
            }
        except Exception as e:
            nexus_log(f"❌ Veriff Fehler: {e}", "red")
            # Veriff nie gestartet → User refunden
            if stripe_payment_intent_id:
                try:
                    _stripe_mod.Refund.create(payment_intent=stripe_payment_intent_id)
                    nexus_log(f"💳 Refund: Veriff nie gestartet, {stripe_payment_intent_id} erstattet", "yellow")
                except Exception as ce:
                    nexus_log(f"⚠️ Refund fehlgeschlagen: {ce}", "yellow")
            return {"error": f"Veriff Fehler: {str(e)}"}

    def callback(self, session_id: str, data: dict) -> dict:
        vs = _verification_sessions.get(session_id)
        if not vs or vs["provider"] != self.name:
            return {"error": "Ungültige Session"}
        if vs["status"] != "pending":
            return {"error": f"Session bereits {vs['status']}"}

        cfg = load_config()
        if not cfg.get("veriff_enabled", True):
            return {"error": "Veriff ist deaktiviert"}
        api_key = cfg.get("veriff_api_key")
        if not api_key:
            return {"error": "veriff_api_key nicht in Config"}

        try:
            import urllib.request
            api_url = cfg.get("veriff_api_url", "https://stationapi.veriff.com/v1")
            vid = vs.get("veriff_session_id", "")
            req = urllib.request.Request(
                f"{api_url}/sessions/{vid}/decision",
                headers={"Content-Type": "application/json", "X-AUTH-CLIENT": api_key},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())

            status = result.get("verification", {}).get("status", "")
            pi_id = vs.get("stripe_payment_intent_id", "")
            if status == "approved":
                vs["status"] = "verified"
                perso_hash = _build_perso_hash(result)
                _apply_verification(vs["shinpai_id"], self.name, self.level, perso_hash=perso_hash)
                nexus_log(f"✅ VERIFF VERIFIED: {vs['shinpai_id']} (PI: {pi_id})", "green")
                return {"verified": True, "level": self.level, "provider": self.name}
            else:
                vs["status"] = "failed"
                # KEIN Refund — User hat für den Versuch bezahlt (Anti-Troll)
                nexus_log(f"❌ VERIFF FAILED: {vs['shinpai_id']} ({status}) — kein Refund (PI: {pi_id})", "yellow")
                return {"verified": False, "veriff_status": status}
        except Exception as e:
            nexus_log(f"❌ Veriff Callback Fehler: {e}", "red")
            return {"error": f"Veriff Fehler: {str(e)}"}


# Provider Registry
_VERIFICATION_PROVIDERS: dict[str, VerificationProvider] = {
    "stripe": StripeSetupIntentProvider(),
    "veriff": VeriffIDProvider(),
    # Später: "idnow": IDnowProvider(), "eu_ewallet": EUeWalletProvider()
}


def _create_verification_license(subject_sid: str, subject_name: str, provider: str, level: int, real_expiry_ts: int | None = None) -> dict | None:
    """
    Baut und signiert eine Lizenz für eine erfolgreiche Verifikation.
    Issuer = Shinpai-Nexus (dieser Nexus), signiert mit lokalem PQ-Key.
    realized_by = Provider-Name (stripe/veriff/amt:<id>).
    Scope = nexus.level.
    real_expiry_ts: optional, Unix-Timestamp des echten Dokumenten-Ablaufs
      (Karten-Ablauf bei Stripe, Perso/Pass-Ablauf bei Veriff). Wenn gesetzt,
      läuft die Lizenz am echten Datum ab, sonst Default je Provider.
    Gibt die signierte Lizenz zurück (oder None bei Fehler).
    """
    if not _pq_keys:
        nexus_log("⚠️ Kann keine Lizenz erzeugen: PQ-Keys nicht geladen", "yellow")
        return None
    if not _identity:
        nexus_log("⚠️ Kann keine Lizenz erzeugen: keine Identity", "yellow")
        return None
    try:
        issuer_sid = _identity.get("shinpai_id", "")
        issuer_name = _identity.get("name") or "Shinpai-Nexus"
        cfg_local = load_config()
        issuer_pk = cfg_local.get("public_key", "")
        # Label & Fallback-Default je nach Provider
        if provider == "veriff":
            default_days = 365 * 10
            display_label = "Identität (Perso/Reisepass)"
        elif provider == "stripe":
            default_days = 365 * 5
            display_label = "Volljährigkeit (Kreditkarte)"
        else:
            default_days = 365
            display_label = provider
        # Gültigkeit: echtes Ablaufdatum, sonst Default
        now = int(time.time())
        if real_expiry_ts and real_expiry_ts > now:
            valid_days = max(1, (real_expiry_ts - now) // 86400)
        else:
            valid_days = default_days
        lic = _license_make(
            issuer_type="nexus_instance",
            issuer_shinpai_id=issuer_sid,
            issuer_display_name=issuer_name,
            issuer_public_key=issuer_pk,
            subject_type="person",
            subject_shinpai_id=subject_sid,
            subject_display_name=subject_name or subject_sid,
            scope={"nexus": {"level": level, "provider": provider}},
            trust_level=level + 1,  # Lizenz trust_level ≈ Nexus-Verifikationsstufe + Shift
            valid_days=valid_days,
            realized_by=provider,
            notes=display_label,
        )
        signed = _license_sign(lic)
        # In globaler Vault speichern (filtert später nach subject.shinpai_id pro User)
        existing = _license_load_vault(LICENSES_RECEIVED_VAULT)
        # Duplikat-Check: gleicher Subject + Provider → alte rauswerfen (Replacement)
        existing = [x for x in existing if not (
            x.get("subject", {}).get("shinpai_id") == subject_sid and
            x.get("realized_by") == provider
        )]
        existing.append(signed)
        _license_save_vault(LICENSES_RECEIVED_VAULT, existing)
        nexus_log(f"📜 Lizenz erzeugt: {signed['license_id']} für {subject_sid} via {provider}", "green")
        return signed
    except Exception as e:
        nexus_log(f"⚠️ Lizenz-Erzeugung fehlgeschlagen: {type(e).__name__}: {e}", "red")
        return None


LICENSE_GRACE_PERIOD_DAYS = 7


def _license_expiry_tick():
    """
    Läuft periodisch im Hintergrund-Thread. Prüft alle erhaltenen Lizenzen:
      - Abgelaufen → Status auf 'expired' setzen (state field), Grace-Period beginnt
      - In Grace Period → Auto-Refresh versuchen (nur für Amt-Lizenzen)
      - Grace Period > 7 Tage → Lizenz aus Vault löschen
    Auto-Refresh ruft intern den Amt-Endpoint auf (nur Amt-Lizenzen, nicht Stripe/Veriff).
    Stripe/Veriff-Lizenzen haben lange Laufzeiten und werden nicht auto-refresht.
    """
    if not vault_is_unlocked():
        return
    all_lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
    if not all_lics:
        return
    now = int(time.time())
    changed = False
    keep = []
    for lic in all_lics:
        valid_until = int(lic.get("valid_until", 0))
        realized_by = lic.get("realized_by", "")
        # Aktueller State des Eintrags: valid | expired | refreshing | deleting
        state = lic.get("_state", "valid")
        expired_at = int(lic.get("_expired_at", 0))
        # Lizenz ist noch gültig → nichts tun
        if now < valid_until:
            if state != "valid":
                lic["_state"] = "valid"
                lic.pop("_expired_at", None)
                lic.pop("_grace_until", None)
                changed = True
            keep.append(lic)
            continue
        # Lizenz ist abgelaufen
        if state == "valid":
            # Erstmals abgelaufen → markieren, Grace beginnt jetzt
            lic["_state"] = "expired"
            lic["_expired_at"] = now
            lic["_grace_until"] = now + (LICENSE_GRACE_PERIOD_DAYS * 86400)
            nexus_log(f"⌛ Lizenz abgelaufen: {lic.get('license_id')} ({realized_by})", "yellow")
            changed = True
            expired_at = now
            state = "expired"
        # Auto-Refresh NUR für Amt-Lizenzen (realized_by beginnt mit "test-" oder ist keine Provider-ID)
        is_amt_license = realized_by not in ("stripe", "veriff") and realized_by != ""
        fee_eur = float(lic.get("fee_eur", 0))
        if state == "expired" and is_amt_license:
            # Cost-Aware: Kostenpflichtige Lizenzen NICHT auto-refreshen
            if fee_eur > 0:
                lic["_needs_paid_refresh"] = True
                nexus_log(f"💰 Lizenz abgelaufen, Erneuerung kostet {fee_eur}€: {lic.get('license_id')}", "yellow")
                keep.append(lic)
                changed = True
                continue
            # Gratis → Auto-Refresh
            refresh_ok = _license_try_auto_refresh(lic)
            if refresh_ok:
                nexus_log(f"🔄 Lizenz auto-refreshed: {lic.get('license_id')}", "green")
                changed = True
                # Die neue Lizenz ist schon in der Vault durch _create_amt_license
                # Die alte hier nicht behalten — sie wurde durch die neue ersetzt
                continue
        # Grace-Period noch nicht abgelaufen → behalten, User sieht Hinweis
        grace_until = int(lic.get("_grace_until", expired_at + LICENSE_GRACE_PERIOD_DAYS * 86400))
        if now < grace_until:
            keep.append(lic)
            continue
        # Grace abgelaufen → löschen
        nexus_log(f"🗑️ Lizenz Grace abgelaufen, entfernt: {lic.get('license_id')}", "yellow")
        changed = True
        # (kein keep.append → Eintrag fällt raus)
    if changed:
        # MERGE: Vault nochmal laden, um Lizenzen zu behalten die während des Ticks
        # durch _create_amt_license (Auto-Refresh) hinzugefügt wurden.
        # Ohne Merge überschreibt keep die neuen Lizenzen → Race Condition (Bug 2026-04-12).
        current_vault = _license_load_vault(LICENSES_RECEIVED_VAULT)
        keep_ids = {l.get("license_id") for l in keep if l.get("license_id")}
        for lic_cv in current_vault:
            lid = lic_cv.get("license_id")
            if lid and lid not in keep_ids:
                keep.append(lic_cv)
        _license_save_vault(LICENSES_RECEIVED_VAULT, keep)

    # WATCHLIST-SYNC: Wenn eine Amt-Lizenz verschwunden ist (Grace abgelaufen, Refresh
    # fehlgeschlagen), muss der zugehörige Watchlist-Eintrag von "confirmed" zurück auf
    # "pending" fallen, damit der Beantragen-Button wieder klickbar wird.
    try:
        watchlist = _amt_watchlist_load()
        if watchlist:
            final_lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
            active_amt_ids = {l.get("realized_by") for l in final_lics if l.get("realized_by")}
            wl_changed = False
            for entry in watchlist:
                if entry.get("status") == "confirmed" and entry.get("shinpai_id") not in active_amt_ids:
                    entry["status"] = "pending"
                    entry.pop("requested_at", None)
                    entry.pop("status_updated_at", None)
                    wl_changed = True
                    nexus_log(f"🔄 Watchlist-Sync: Amt zurück auf pending (Lizenz fehlt)", "yellow")
            if wl_changed:
                _amt_watchlist_save(watchlist)
    except Exception as wle:
        nexus_log(f"⚠️ Watchlist-Sync Fehler: {wle}", "yellow")


def _license_cascade_refresh():
    """Login-Trigger: refresht alle abgelaufenen Amt-Lizenzen in Abhängigkeits-Reihenfolge.
    Wurzel-Lizenzen (keine Dependencies) werden zuerst refrescht, danach die Kinder.
    Topologische Sortierung: solange Fortschritt möglich ist, wird weiter refrescht.
    Wird beim Vault-Unlock in einem Background-Thread aufgerufen."""
    if not vault_is_unlocked():
        return
    all_lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
    if not all_lics:
        return
    now = int(time.time())

    # Schritt 1: expired Amt-Lizenzen sammeln, gültige Keys merken
    expired = []
    valid_keys = set()
    for lic in all_lics:
        valid_until = int(lic.get("valid_until", 0))
        realized_by = lic.get("realized_by", "")
        is_amt = realized_by not in ("stripe", "veriff") and realized_by != ""
        cats = lic.get("amt_categories") or {}
        cat_key = None
        for cat, subs in cats.items():
            if subs:
                cat_key = f"{cat}/{subs[0]}"
                break
        if now < valid_until:
            if cat_key:
                valid_keys.add(cat_key)
        elif is_amt and cat_key:
            expired.append((lic, cat_key))

    if not expired:
        return

    nexus_log(f"🔄 Kaskade-Refresh: {len(expired)} abgelaufene Amt-Lizenzen gefunden", "cyan")
    refreshed_keys = set(valid_keys)
    remaining = list(expired)
    total_refreshed = 0
    max_passes = len(remaining) + 1

    # Schritt 2: Topologische Refresh-Reihenfolge (Wurzeln zuerst)
    for pass_nr in range(max_passes):
        if not remaining:
            break
        next_remaining = []
        for lic, cat_key in remaining:
            deps = lic.get("dependencies") or []
            # Prüfe ob alle Dependencies jetzt gültig sind
            all_met = True
            for dep in deps:
                dep_key = f"{dep.get('category', '')}/{dep.get('subclass', '')}"
                if dep_key and dep_key not in refreshed_keys:
                    all_met = False
                    break
            if all_met:
                ok = _license_try_auto_refresh(lic)
                if ok:
                    refreshed_keys.add(cat_key)
                    total_refreshed += 1
                    nexus_log(f"🔄 Kaskade: {cat_key} refrescht", "green")
                else:
                    nexus_log(f"⚠️ Kaskade: {cat_key} Refresh fehlgeschlagen", "yellow")
            else:
                next_remaining.append((lic, cat_key))
        if len(next_remaining) == len(remaining):
            break  # Kein Fortschritt → zirkuläre Deps oder unerfüllbar
        remaining = next_remaining

    if remaining:
        nexus_log(f"⚠️ Kaskade: {len(remaining)} Lizenz(en) nicht refrescht (unerfüllte Dependencies)", "yellow")
    if total_refreshed:
        nexus_log(f"✅ Kaskade-Refresh abgeschlossen: {total_refreshed} Lizenzen erneuert", "green")


def _license_try_auto_refresh(lic: dict) -> bool:
    """
    Versucht eine abgelaufene Amt-Lizenz automatisch zu erneuern.
    Ruft den Amt-Request-Endpoint mit den Daten der alten Lizenz auf.
    Bei Erfolg wird eine NEUE Lizenz erzeugt (ersetzt die alte durch Duplikat-Check).
    Gibt True zurück bei Erfolg.
    """
    try:
        subject = lic.get("subject") or {}
        subject_sid = subject.get("shinpai_id", "")
        subject_name = subject.get("display_name", "")
        amt_sid = lic.get("realized_by", "")
        amt_categories = lic.get("amt_categories") or {}
        category = ""
        subclass = ""
        for cat, subs in amt_categories.items():
            if subs:
                category = cat
                subclass = subs[0]
                break
        if not subject_sid or not amt_sid:
            return False
        # Federation-Cache nach dem Amt durchsuchen
        request_url = None
        amt_name = amt_sid
        if amt_sid.startswith("test-"):
            for sub in _amt_subs_load():
                for a in (sub.get("cache") or {}).get("amter", []):
                    if a.get("shinpai_id") == amt_sid:
                        list_url = sub.get("url", "")
                        if list_url.endswith("/amt-list.json"):
                            request_url = list_url.replace("/amt-list.json", "/amt/request")
                        amt_name = a.get("name", amt_sid)
                        break
                if request_url:
                    break
        else:
            # Produktions-Amt: endpoint aus Federation-Cache lesen
            for amt in amt_subs_all_amter():
                if amt.get("shinpai_id") == amt_sid:
                    ep = amt.get("endpoint", "").rstrip("/")
                    if ep:
                        request_url = f"{ep}/amt/request"
                    amt_name = amt.get("name", amt_sid)
                    break
        if not request_url:
            return False
        req_body = {
            "amt_shinpai_id": amt_sid,
            "user_shinpai_id": subject_sid,
            "category": category,
            "subclass": subclass,
        }
        try:
            req = urllib.request.Request(
                request_url,
                data=json.dumps(req_body).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "ShinNexus-Federation/1.0 auto-refresh"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read(1024 * 1024).decode("utf-8")
                amt_response = json.loads(raw)
        except Exception as e:
            nexus_log(f"⚠️ Auto-Refresh {amt_sid}: {e}", "yellow")
            return False
        if not amt_response.get("confirmed"):
            return False
        valid_until_ts = int(amt_response.get("valid_until", 0))
        _create_amt_license(
            subject_sid=subject_sid,
            subject_name=subject_name,
            amt_shinpai_id=amt_sid,
            amt_name=amt_name,
            category=category,
            subclass=subclass,
            valid_until_ts=valid_until_ts,
            response_hint=amt_response.get("response_hint", ""),
            response_link=amt_response.get("response_link", ""),
            dependencies=amt_response.get("dependencies"),
        )
        return True
    except Exception as e:
        nexus_log(f"⚠️ Auto-Refresh Exception: {e}", "yellow")
        return False


def _create_amt_license(subject_sid: str, subject_name: str, amt_shinpai_id: str, amt_name: str,
                        category: str, subclass: str, valid_until_ts: int,
                        response_hint: str = "", response_link: str = "",
                        dependencies: list | None = None) -> dict | None:
    """
    Baut und signiert eine Amt-Lizenz (Stufe 3).
    Issuer = der Shinpai-Nexus selbst (signiert im Namen des Amts mit lokalem PQ-Key).
    realized_by = Amt-Shinpai-ID (so wird sichtbar von welchem Amt die Bestätigung kam).
    valid_until_ts = echter Ablauf-Timestamp (vom Amt geliefert, z.B. 5 Minuten für Tests).
    dependencies = Liste von {category, subclass} Dicts — vom Amt gelieferte Abhängigkeiten.
    """
    if not _pq_keys or not _identity:
        return None
    try:
        issuer_sid = _identity.get("shinpai_id", "")
        issuer_name = _identity.get("name") or "Shinpai-Nexus"
        cfg_local = load_config()
        issuer_pk = cfg_local.get("public_key", "")
        now = int(time.time())
        valid_days = max(1, (valid_until_ts - now) // 86400) if valid_until_ts > now else 1
        # Wenn sehr kurze Gültigkeit (< 1 Tag), 1 Tag als Minimum, aber valid_until_ts übernehmen
        lic = _license_make(
            issuer_type="nexus_instance",
            issuer_shinpai_id=issuer_sid,
            issuer_display_name=issuer_name,
            issuer_public_key=issuer_pk,
            subject_type="person",
            subject_shinpai_id=subject_sid,
            subject_display_name=subject_name or subject_sid,
            scope={"nexus": {"level": 3, "provider": "amt"}, "amt": {"shinpai_id": amt_shinpai_id, "name": amt_name}},
            amt_categories={category: [subclass]} if category and subclass else {},
            trust_level=4,  # Amt-bestätigt
            valid_days=valid_days,
            realized_by=amt_shinpai_id,
            notes=f"{amt_name} — {subclass or category}" if (category or subclass) else amt_name,
        )
        # Echtes valid_until überschreiben (statt valid_days hochgerechnet)
        lic["valid_until"] = int(valid_until_ts)
        # Response-Hinweis und Link mitaufnehmen (für UI)
        if response_hint:
            lic["response_hint"] = response_hint
        if response_link:
            lic["response_link"] = response_link
        # Dependencies vom Amt speichern (für Kaskaden-Logik)
        if dependencies:
            lic["dependencies"] = dependencies
        signed = _license_sign(lic)
        existing = _license_load_vault(LICENSES_RECEIVED_VAULT)
        # Duplikat-Check: gleiches subject + gleicher Amt realized_by → ersetzen
        existing = [x for x in existing if not (
            x.get("subject", {}).get("shinpai_id") == subject_sid and
            x.get("realized_by") == amt_shinpai_id
        )]
        existing.append(signed)
        _license_save_vault(LICENSES_RECEIVED_VAULT, existing)
        nexus_log(f"📜 Amt-Lizenz erzeugt ({category}/{subclass})", "green")
        return signed
    except Exception as e:
        nexus_log(f"⚠️ Amt-Lizenz-Erzeugung fehlgeschlagen: {type(e).__name__}: {e}", "red")
        return None


# ══════════════════════════════════════════════════════════════════════
#  BITCOIN WALLET — Chain of Trust (Phase 2)
# ══════════════════════════════════════════════════════════════════════

def _btc_wallet_load() -> dict:
    """Wallet aus dem Vault laden. Gibt {wif, address, entries[]} zurück oder {}."""
    if not vault_is_unlocked() or not BTC_WALLET_VAULT.exists():
        return {}
    try:
        raw = vault_decrypt(BTC_WALLET_VAULT.read_bytes())
        return json.loads(raw)
    except Exception:
        return {}


def _btc_wallet_save(data: dict) -> bool:
    """Wallet-Daten in den Vault speichern."""
    if not vault_is_unlocked():
        return False
    try:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        BTC_WALLET_VAULT.write_bytes(vault_encrypt(raw))
        return True
    except Exception:
        return False


def _btc_wallet_create() -> dict:
    """Neues Bitcoin-Wallet erzeugen mit BIP39 Seed. Gibt {wif, address, mnemonic} zurück."""
    try:
        import secrets as _secrets
        from hdwallet import HDWallet
        from hdwallet.cryptocurrencies import Bitcoin
        from hdwallet.hds import BIP84HD
        from hdwallet.mnemonics.bip39 import BIP39Mnemonic
        from hdwallet.entropies.bip39 import BIP39Entropy
        from hdwallet.derivations import BIP84Derivation
        # 256 bit Entropy → 24 Wörter BIP39
        entropy = BIP39Entropy(entropy=_secrets.token_hex(16))
        mnemonic_words = BIP39Mnemonic.from_entropy(entropy, language="english")
        # HD-Wallet ableiten (BIP84 Native SegWit)
        mn = BIP39Mnemonic(mnemonic=mnemonic_words)
        hd = HDWallet(cryptocurrency=Bitcoin, hd=BIP84HD, network="mainnet")
        hd.from_mnemonic(mn)
        hd.from_derivation(BIP84Derivation(coin_type=0, account=0, change="external-chain", address=0))
        wif = hd.wif()
        addr = hd.address()
        return {"wif": wif, "address": addr, "mnemonic": mnemonic_words, "entries": [], "created_at": int(time.time())}
    except Exception as e:
        nexus_log(f"⚠️ BTC Wallet-Erzeugung fehlgeschlagen: {e}", "red")
        return {}


def _btc_get_fee() -> int:
    """Dynamische Fee von mempool.space holen. Gibt sat/vB zurück (Ziel: ≤1h)."""
    try:
        import urllib.request
        with urllib.request.urlopen("https://mempool.space/api/v1/fees/recommended", timeout=10) as r:
            fees = json.loads(r.read())
        return max(int(fees.get("hourFee", 3)), 1)
    except Exception:
        return 3  # Fallback: 3 sat/vB (niedrig aber durchkommt)


def _btc_get_price_eur() -> float:
    """Aktuellen BTC-Preis in EUR holen."""
    try:
        import urllib.request
        with urllib.request.urlopen("https://mempool.space/api/v1/prices", timeout=10) as r:
            prices = json.loads(r.read())
        return float(prices.get("EUR", 0))
    except Exception:
        return 0.0


def _btc_estimate_fee_sats() -> tuple[int, int]:
    """Fee berechnen für OP_RETURN TX. Gibt (fee_sats, sat_per_vb) zurück."""
    sat_per_vb = _btc_get_fee()
    tx_size_vb = 150  # Typische OP_RETURN TX
    return sat_per_vb * tx_size_vb, sat_per_vb


def _btc_check_tx_confirmed(txid: str) -> dict:
    """TX-Status von mempool.space prüfen. Gibt {confirmed, block_height, block_time} zurück."""
    try:
        import urllib.request
        url = f"https://mempool.space/api/tx/{txid}"
        with urllib.request.urlopen(url, timeout=10) as r:
            tx = json.loads(r.read())
        status = tx.get("status", {})
        return {
            "confirmed": bool(status.get("confirmed")),
            "block_height": status.get("block_height", 0),
            "block_time": status.get("block_time", 0),
        }
    except Exception:
        return {"confirmed": False, "block_height": 0, "block_time": 0}


ANCHOR_JSON = BASE / "anchor.json"


def _btc_write_anchor_json(entry: dict):
    """anchor.json neben ShinNexus.py schreiben — das öffentliche Zertifikat."""
    try:
        existing = []
        if ANCHOR_JSON.exists():
            old = json.loads(ANCHOR_JSON.read_text("utf-8"))
            existing = old.get("history", [])
        existing.append(entry)
        cfg = load_config()
        anchor = {
            "version": entry["version"],
            "code_hash": entry["code_hash"],
            "txid": entry["txid"],
            "btc_address": entry["address"],
            "timestamp": entry["timestamp"],
            "op_return": entry.get("op_return", ""),
            "company": (cfg.get("license_company") or "").strip(),
            "revoked": False,
            "history": existing,
        }
        ANCHOR_JSON.write_text(json.dumps(anchor, indent=2, ensure_ascii=False), "utf-8")
        nexus_log("📄 anchor.json geschrieben", "cyan")
    except Exception as e:
        nexus_log(f"⚠️ anchor.json schreiben fehlgeschlagen: {e}", "red")


def _nexus_dissolve(migrated_to: str = "") -> None:
    """Nexus auflösen nach Owner-Migration.
    Löscht: Identity, Users, Vault, Credentials, Config-Secrets, Wallet.
    Behält: ShinNexus.py, anchor.json, start.sh, Assets.
    Ergebnis: Totes Skelett das händisch neu eingerichtet werden muss.
    """
    global _identity, _pq_keys, _users, _user_hives, _friends_data
    try:
        # Config strippen (nur Skelett-Infos behalten)
        cfg = load_config()
        dissolved_cfg = {
            "dissolved": True,
            "dissolved_at": int(time.time()),
            "migrated_to": migrated_to,
            "former_owner": cfg.get("name", ""),
            "former_company": cfg.get("license_company", ""),
            "port": cfg.get("port", 12345),
        }
        save_config(dissolved_cfg)
        # Identity löschen
        id_path = BASE / "identity.json"
        if id_path.exists():
            id_path.unlink()
        _identity = None
        _pq_keys = {}
        # Users löschen
        _users.clear()
        _user_hives.clear()
        _friends_data.clear()
        users_path = BASE / "users.json"
        if users_path.exists():
            users_path.unlink()
        # Vault löschen
        vault_dir = BASE / "vault"
        if vault_dir.exists():
            import shutil
            shutil.rmtree(vault_dir, ignore_errors=True)
        # Credentials löschen
        cred_dir = BASE / "credentials"
        if cred_dir.exists():
            import shutil
            shutil.rmtree(cred_dir, ignore_errors=True)
        # Igni-Key löschen
        for igni in BASE.glob("ShinNexus-Igni-*"):
            igni.unlink(missing_ok=True)
        # Wallet löschen
        wallet_path = BASE / "wallet.json"
        if wallet_path.exists():
            wallet_path.unlink()
        # Logs behalten (für Forensik)
        nexus_log(f"💀 NEXUS AUFGELÖST. Migriert nach: {migrated_to}", "red")
        nexus_log("💀 Skelett bleibt stehen. Händische Neueinrichtung erforderlich.", "red")
    except Exception as e:
        nexus_log(f"⚠️ Dissolve-Fehler: {e}", "red")


def _btc_write_anchor_json_raw(anchor: dict) -> None:
    """anchor.json direkt überschreiben (für Updates wie Revoke-Markierungen)."""
    try:
        ANCHOR_JSON.write_text(json.dumps(anchor, indent=2, ensure_ascii=False), "utf-8")
    except Exception as e:
        nexus_log(f"⚠️ anchor.json raw-write fehlgeschlagen: {e}", "red")


def _btc_update_anchor_status(updates: dict) -> None:
    """Merge updates in anchor.json (z.B. live_verify_status, last_live_verify)."""
    try:
        if not ANCHOR_JSON.exists():
            return
        data = json.loads(ANCHOR_JSON.read_text("utf-8"))
        data.update(updates)
        ANCHOR_JSON.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
    except Exception as e:
        nexus_log(f"⚠️ anchor.json Update fehlgeschlagen: {e}", "yellow")


def _parse_op_return_from_script(scriptpubkey_hex: str) -> str | None:
    """Extract push-data from an OP_RETURN scriptPubKey (hex encoded)."""
    if not scriptpubkey_hex or not scriptpubkey_hex.startswith("6a"):
        return None
    try:
        remaining = scriptpubkey_hex[2:]
        if not remaining:
            return None
        op = int(remaining[:2], 16)
        if 1 <= op <= 75:
            data_hex = remaining[2:2 + op * 2]
        elif op == 0x4c:
            length = int(remaining[2:4], 16)
            data_hex = remaining[4:4 + length * 2]
        elif op == 0x4d:
            length = int(remaining[4:6] + remaining[2:4], 16)
            data_hex = remaining[6:6 + length * 2]
        else:
            return None
        return bytes.fromhex(data_hex).decode("utf-8", errors="replace")
    except Exception:
        return None


def _btc_verify_anchor_live(txid: str, expected_hash: str, timeout: float = 10.0) -> dict:
    """
    Live-Verifikation: Fetcht die Bitcoin-TX via mempool.space und vergleicht
    den OP_RETURN-Hash mit dem lokal live-berechneten Code-Hash.

    Returns dict mit:
      - status: "match" | "mismatch" | "network_error" | "bad_format"
      - checked_at: Unix-Timestamp
      - (bei match/mismatch) on_chain_hash_prefix, on_chain_version, block_height, confirmed
      - (bei network_error/bad_format) error
    """
    if not txid or not expected_hash:
        return {
            "status": "bad_format",
            "checked_at": int(time.time()),
            "error": "txid oder expected_hash fehlt",
        }
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://mempool.space/api/tx/{txid}",
            headers={"User-Agent": f"ShinNexus/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            tx_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {
            "status": "network_error",
            "checked_at": int(time.time()),
            "error": f"mempool.space nicht erreichbar: {e}",
        }
    op_return_text = None
    for vout in tx_data.get("vout", []) or []:
        if vout.get("scriptpubkey_type") == "op_return":
            text = _parse_op_return_from_script(vout.get("scriptpubkey", ""))
            if text:
                op_return_text = text
                break
    if not op_return_text:
        return {
            "status": "bad_format",
            "checked_at": int(time.time()),
            "error": "Keine OP_RETURN in dieser TX gefunden",
        }
    parts = op_return_text.split(":")
    if len(parts) < 3 or parts[0] != "SHINPAI-AI":
        return {
            "status": "bad_format",
            "checked_at": int(time.time()),
            "error": f"OP_RETURN nicht im SHINPAI-AI-Format: {op_return_text[:40]}",
        }
    on_chain_version = parts[1]
    on_chain_hash_prefix = parts[2]
    expected_prefix = expected_hash[:len(on_chain_hash_prefix)]
    match = (on_chain_hash_prefix.lower() == expected_prefix.lower())
    status_info = tx_data.get("status", {}) or {}
    confirmed = bool(status_info.get("confirmed", False))
    return {
        "status": "match" if match else "mismatch",
        "checked_at": int(time.time()),
        "on_chain_hash_prefix": on_chain_hash_prefix,
        "on_chain_version": on_chain_version,
        "block_height": int(status_info.get("block_height", 0)) if confirmed else 0,
        "confirmed": confirmed,
    }


def _whitelist_check_remote_nexus(target_url: str, timeout: float = 5.0) -> tuple[bool, dict, list[str]]:
    """
    Prüft einen fremden Nexus gegen die lokale Whitelist.
    Ruft dort GET /api/chain/info ab und vergleicht Hash+TXID mit dem eigenen
    whitelist-Array in der Config.

    Returns: (is_trusted, remote_info_dict, reasons_for_rejection)
    - is_trusted: True wenn Hash des Fremden in lokaler Whitelist matcht
    - remote_info_dict: was /api/chain/info geliefert hat (oder leer bei Fehler)
    - reasons: Liste von Gründen warum nicht vertrauenswürdig (leer wenn trusted)
    """
    target_url = (target_url or "").strip().rstrip("/")
    if not target_url:
        return (False, {}, ["Keine Ziel-URL angegeben"])
    if not target_url.startswith(("http://", "https://")):
        return (False, {}, ["URL muss mit http:// oder https:// beginnen"])
    try:
        import urllib.request
        import ssl
        req = urllib.request.Request(
            f"{target_url}/api/chain/info",
            headers={"Accept": "application/json", "User-Agent": f"ShinNexus/{VERSION}"},
        )
        ctx = ssl.create_default_context()
        # Wir sind tolerant zu Self-Signed — Vertrauen kommt aus der Whitelist, nicht aus dem TLS-Cert
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
    except Exception as e:
        return (False, {}, [f"Ziel nicht erreichbar: {e}"])
    remote_hash = (data.get("code_hash") or "").lower()
    remote_txid = (data.get("txid") or "").lower()
    if not remote_hash:
        return (False, data, ["Ziel liefert keinen Code-Hash"])
    if data.get("revoked"):
        return (False, data, ["Ziel-Version ist widerrufen"])
    cfg = load_config()
    wl = cfg.get("whitelist") or []
    for entry in wl:
        entry_hash = (entry.get("hash") or "").lower()
        entry_txid = (entry.get("txid") or "").lower()
        if entry_hash == remote_hash:
            # Hash matcht. Wenn TXID im Whitelist-Eintrag gesetzt, muss der Remote
            # auch diese TXID liefern (sonst Fake-Hash ohne echten Anker).
            if entry_txid and remote_txid and entry_txid != remote_txid:
                continue
            return (True, data, [])
    return (False, data, [
        f"Code-Hash {remote_hash[:16]}… nicht in deiner Whitelist"
    ])


def _whitelist_auto_default_from_anchor(entry: dict) -> bool:
    """
    Nach erfolgreicher BTC-Verankerung automatisch einen Whitelist-Default-Eintrag
    für die eigene Version einfügen.
    - Alte auto_default Einträge werden entfernt (nur einer aktiv zur Zeit)
    - Label = Firmenname aus Lizenz + "(Default)"
    - Löschbar wie jeder andere Eintrag
    Returns True wenn ein neuer Default geschrieben wurde.
    """
    try:
        h = (entry.get("code_hash") or "").lower()
        if not h:
            return False
        cfg = load_config()
        items = cfg.get("whitelist") or []
        # Alte auto_default-Einträge aufräumen (nur EIN aktueller Default)
        items = [it for it in items if not it.get("auto_default")]
        # Wenn Owner den Hash schon manuell eingetragen hat → nichts hinzufügen,
        # nur die alten auto_default entfernen und speichern
        if any((it.get("hash", "").lower() == h) for it in items):
            cfg["whitelist"] = items
            save_config(cfg)
            return False
        # Label aus anchor.json (= der echte Verankerer), nicht aus lokaler Config
        company = (entry.get("company") or "").strip()
        if not company:
            company = (cfg.get("license_company") or "").strip() or "Verified Source"
        items.append({
            "version": entry.get("version", ""),
            "hash": h,
            "txid": (entry.get("txid") or "").lower(),
            "label": f"{company} (Default)",
            "auto_default": True,
            "added_at": int(time.time()),
        })
        cfg["whitelist"] = items
        save_config(cfg)
        try:
            NexusHandler.config = cfg
        except Exception:
            pass
        nexus_log(f"🦋 Whitelist Auto-Default gesetzt: v{entry.get('version','?')} ({company})", "cyan")
        return True
    except Exception as e:
        nexus_log(f"⚠️ Whitelist Auto-Default fehlgeschlagen: {e}", "red")
        return False


def _btc_read_anchor_json() -> dict:
    """anchor.json lesen. Gibt {} zurück wenn nicht vorhanden."""
    try:
        if ANCHOR_JSON.exists():
            return json.loads(ANCHOR_JSON.read_text("utf-8"))
    except Exception:
        pass
    return {}


def _btc_startup_integrity_check():
    """Beim Start: Code-Hash mit anchor.json vergleichen UND on-chain live verifizieren."""
    anchor = _btc_read_anchor_json()
    if not anchor or not anchor.get("code_hash"):
        nexus_log("ℹ️ Keine Verankerung vorhanden", "cyan")
        return
    try:
        with open(__file__, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return
    if anchor.get("revoked"):
        nexus_log(f"🔴 ACHTUNG: Version {anchor.get('version', '?')} wurde WIDERRUFEN!", "red")
        return
    if current_hash != anchor["code_hash"]:
        nexus_log("⚠️ Code seit letzter Verankerung geändert (nicht verankert)", "yellow")
        return
    nexus_log(f"✅ Code-Hash stimmt mit Verankerung v{anchor.get('version', '?')} überein (lokal)", "green")
    # Zusätzlich: Live-Check gegen Bitcoin-Blockchain
    _btc_live_verify_and_persist(anchor, current_hash)


def _btc_live_verify_and_persist(anchor: dict | None = None, current_hash: str | None = None) -> dict:
    """Live-Check und persistiere live_verify_status in anchor.json.
    Bei match: automatisch eigenen Hash als Whitelist-Default eintragen."""
    if anchor is None:
        anchor = _btc_read_anchor_json()
    if not anchor or not anchor.get("txid") or not anchor.get("code_hash"):
        return {"status": "no_anchor"}
    if current_hash is None:
        try:
            with open(__file__, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return {"status": "no_local_hash"}
    result = _btc_verify_anchor_live(anchor["txid"], current_hash)
    _btc_update_anchor_status({
        "live_verify_status": result.get("status"),
        "last_live_verify": result.get("checked_at"),
        "live_verify_detail": {
            "on_chain_hash_prefix": result.get("on_chain_hash_prefix"),
            "on_chain_version": result.get("on_chain_version"),
            "block_height": result.get("block_height"),
            "confirmed": result.get("confirmed"),
            "error": result.get("error"),
        },
    })
    icons = {
        "match": ("✅", "green", "on-chain verifiziert"),
        "mismatch": ("🚨", "red", "MISMATCH! Hash stimmt nicht mit Anker überein"),
        "network_error": ("🌐", "yellow", "mempool.space nicht erreichbar"),
        "bad_format": ("⚠️", "yellow", "OP_RETURN nicht lesbar"),
    }
    icon, color, msg = icons.get(result.get("status", ""), ("ℹ️", "cyan", result.get("status", "?")))
    nexus_log(f"{icon} Live-Anker-Check: {msg}", color)
    # Bei match: Auto-Whitelist-Default aus anchor.json (löst leere Whitelist auf kopierten Instanzen)
    if result.get("status") == "match":
        _whitelist_auto_default_from_anchor(anchor)
    # Revoke-Broadcast-Check: Adresse scannen nach REVOKE-TXs für unseren Hash
    if anchor.get("btc_address") and current_hash and not anchor.get("revoked"):
        _btc_check_revoke_broadcast(anchor, current_hash)
    return result


def _btc_check_revoke_broadcast(anchor: dict, current_hash: str) -> bool:
    """Scannt die BTC-Adresse aus anchor.json nach REVOKE-TXs für unseren Hash.
    Wenn gefunden → anchor.json lokal auf revoked=true setzen.
    Returns True wenn Revoke erkannt wurde."""
    addr = anchor.get("btc_address", "")
    if not addr:
        return False
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://mempool.space/api/address/{addr}/txs",
            headers={"User-Agent": f"ShinNexus/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            txs = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        nexus_log(f"⚠️ Revoke-Broadcast-Scan fehlgeschlagen: {e}", "yellow")
        return False
    hash_short = current_hash[:32]
    for tx in txs:
        for vout in (tx.get("vout") or []):
            if vout.get("scriptpubkey_type") != "op_return":
                continue
            text = _parse_op_return_from_script(vout.get("scriptpubkey", ""))
            if not text:
                continue
            # SHINPAI-AI:REVOKE:<hash_prefix> suchen
            if text.startswith("SHINPAI-AI:REVOKE:") and text.split(":")[2] == hash_short:
                nexus_log(f"🔴 REVOKE on-chain erkannt für Hash {hash_short[:16]}…!", "red")
                anchor["revoked"] = True
                anchor["revoked_at"] = int(time.time())
                anchor["revoke_txid"] = tx.get("txid", "")
                # History-Eintrag auch markieren
                for entry in (anchor.get("history") or []):
                    if (entry.get("code_hash") or "")[:32] == hash_short:
                        entry["revoked"] = True
                        entry["revoked_at"] = int(time.time())
                        entry["revoke_txid"] = tx.get("txid", "")
                _btc_write_anchor_json_raw(anchor)
                return True
    return False


def _btc_wallet_anchor_hash(code_hash: str, version: str) -> dict | None:
    """Code-Hash als OP_RETURN in die Bitcoin-Blockchain schreiben.
    Gibt {txid, hash, version, timestamp, fee_sats, status} zurück oder None."""
    wallet = _btc_wallet_load()
    if not wallet or not wallet.get("wif"):
        return None
    try:
        from bitcoinutils.setup import setup
        from bitcoinutils.keys import PrivateKey
        from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
        from bitcoinutils.script import Script
        import urllib.request
        setup("mainnet")

        pk = PrivateKey.from_wif(wallet["wif"])
        pub = pk.get_public_key()
        addr = pub.get_segwit_address()
        addr_str = addr.to_string()

        # UTXOs holen via mempool.space API
        utxo_url = f"https://mempool.space/api/address/{addr_str}/utxo"
        with urllib.request.urlopen(utxo_url, timeout=15) as resp:
            utxos = json.loads(resp.read())

        if not utxos:
            nexus_log("⚠️ BTC: Keine UTXOs, Wallet leer", "yellow")
            return None

        # Größtes UTXO nehmen
        utxo = max(utxos, key=lambda u: u["value"])
        txin = TxInput(utxo["txid"], utxo["vout"])

        # OP_RETURN Daten: "SHINPAI-AI:<version>:<hash_short>"
        op_data = f"SHINPAI-AI:{version}:{code_hash[:32]}".encode("utf-8")
        if len(op_data) > 80:
            op_data = op_data[:80]

        # Dynamische Fee
        fee_sats, sat_per_vb = _btc_estimate_fee_sats()
        change = utxo["value"] - fee_sats
        if change < 0:
            nexus_log(f"⚠️ BTC: Nicht genug Sats ({utxo['value']} vorhanden, {fee_sats} nötig)", "yellow")
            return None

        # Outputs: OP_RETURN + Change
        op_return_out = TxOutput(0, Script(["OP_RETURN", op_data.hex()]))
        change_out = TxOutput(change, addr.to_script_pub_key())

        tx = Transaction([txin], [op_return_out, change_out], has_segwit=True)
        # P2WPKH SegWit-Signing: script_code ist das P2PKH-Script des Pubkey-Hash
        script_code = Script(["OP_DUP", "OP_HASH160", pub.to_hash160(),
                              "OP_EQUALVERIFY", "OP_CHECKSIG"])
        sig = pk.sign_segwit_input(tx, 0, script_code, utxo["value"])
        tx.witnesses.append(TxWitnessInput([sig, pub.to_hex()]))

        # Broadcast via mempool.space
        raw_tx = tx.serialize()
        broadcast_url = "https://mempool.space/api/tx"
        req = urllib.request.Request(broadcast_url, data=raw_tx.encode("utf-8"),
                                     headers={"Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            txid = resp.read().decode("utf-8").strip()

        entry = {
            "txid": txid,
            "code_hash": code_hash,
            "version": version,
            "timestamp": int(time.time()),
            "address": addr_str,
            "op_return": op_data.decode("utf-8"),
            "fee_sats": fee_sats,
            "status": "pending",
        }
        wallet.setdefault("entries", []).append(entry)
        wallet["pending_anchor"] = entry
        _btc_wallet_save(wallet)
        nexus_log(f"₿ TX broadcast: {txid[:16]}... ({fee_sats} sats Fee)", "green")
        return entry

    except Exception as e:
        nexus_log(f"⚠️ BTC Blockchain-Eintrag fehlgeschlagen: {e}", "red")
        return None


def _btc_wallet_revoke(code_hash: str) -> dict | None:
    """Version widerrufen via OP_RETURN REVOKE."""
    wallet = _btc_wallet_load()
    if not wallet or not wallet.get("wif"):
        return None
    try:
        from bitcoinutils.setup import setup
        from bitcoinutils.keys import PrivateKey
        from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
        from bitcoinutils.script import Script
        import urllib.request
        setup("mainnet")

        pk = PrivateKey.from_wif(wallet["wif"])
        pub = pk.get_public_key()
        addr = pub.get_segwit_address()
        addr_str = addr.to_string()

        utxo_url = f"https://mempool.space/api/address/{addr_str}/utxo"
        with urllib.request.urlopen(utxo_url, timeout=15) as resp:
            utxos = json.loads(resp.read())
        if not utxos:
            return None

        utxo = max(utxos, key=lambda u: u["value"])
        txin = TxInput(utxo["txid"], utxo["vout"])

        op_data = f"SHINPAI-AI:REVOKE:{code_hash[:32]}".encode("utf-8")
        fee_sats, _ = _btc_estimate_fee_sats()
        change = utxo["value"] - fee_sats
        if change < 0:
            return None

        op_return_out = TxOutput(0, Script(["OP_RETURN", op_data.hex()]))
        change_out = TxOutput(change, addr.to_script_pub_key())

        tx = Transaction([txin], [op_return_out, change_out], has_segwit=True)
        script_code = Script(["OP_DUP", "OP_HASH160", pub.to_hash160(),
                              "OP_EQUALVERIFY", "OP_CHECKSIG"])
        sig = pk.sign_segwit_input(tx, 0, script_code, utxo["value"])
        tx.witnesses.append(TxWitnessInput([sig, pub.to_hex()]))

        raw_tx = tx.serialize()
        req = urllib.request.Request("https://mempool.space/api/tx", data=raw_tx.encode("utf-8"),
                                     headers={"Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            txid = resp.read().decode("utf-8").strip()

        revoke_entry = {
            "txid": txid,
            "code_hash": code_hash,
            "type": "revoke",
            "timestamp": int(time.time()),
            "address": addr_str,
        }
        revoke_entry["status"] = "pending"
        wallet.setdefault("revocations", []).append(revoke_entry)
        wallet["pending_revoke"] = revoke_entry
        _btc_wallet_save(wallet)

        # anchor.json updaten
        anchor = _btc_read_anchor_json()
        if anchor:
            anchor["revoked"] = True
            anchor["revoked_at"] = int(time.time())
            anchor["revoke_txid"] = txid
            ANCHOR_JSON.write_text(json.dumps(anchor, indent=2, ensure_ascii=False), "utf-8")

        nexus_log(f"🔴 Version widerrufen: {code_hash[:16]}... TX: {txid[:16]}...", "red")
        return revoke_entry
    except Exception as e:
        nexus_log(f"⚠️ Revocation fehlgeschlagen: {e}", "red")
        return None


def _apply_verification(shinpai_id: str, provider: str, level: int, real_expiry_ts: int | None = None, perso_hash: str | None = None):
    """Speichert Verifikations-Level in Identity oder User-Daten (N3: DB Schema).
    Setzt zusaetzlich separate Flags fuer Kind/Bot/Erwachsen-Logik:
      - Stripe → verified_stripe=True, stripe_verified_at=ts
      - Veriff → id_verified=True, perso_verified_at=ts, perso_hash=...
    Veriff erkennt Zweit-Accounts via perso_hash-Match (First-come-first-serve).
    """
    now = int(time.time())
    vdata = {
        "verification_level": level,
        "verified_at": now,
        "verified_by": provider,
    }

    def _resolve_card_replace(target):
        if not target.get("card_pending_replacement"):
            return
        if provider != "stripe":
            return
        saved_lvl = int(target.get("saved_verification_level_before_card_replace", 0))
        target["card_pending_replacement"] = False
        target["saved_verification_level_before_card_replace"] = 0
        if saved_lvl > target.get("verification_level", 0):
            target["verification_level"] = saved_lvl
            nexus_log(f"💳 CardReplace erfolgreich: Level {saved_lvl} wiederhergestellt", "green")

    def _set_provider_flags(target):
        """Setzt separate KK/Perso-Flags + Zweit-Account-Erkennung + Limits."""
        if provider == "stripe":
            target["verified_stripe"] = True
            target["stripe_verified_at"] = now
        elif provider == "veriff":
            target["id_verified"] = True
            target["perso_verified_at"] = now
            if perso_hash:
                # Blacklist-Check: wurde diese Perso kürzlich per Self-Delete gelöscht?
                if _perso_blacklist_check(perso_hash):
                    nexus_log(f"🚫 Perso-Hash auf Blacklist — Self-Delete cooldown aktiv", "red")
                    return  # Stille Ablehnung — kein Fehler nach außen, Veriff-Callback verarbeitet
                target["perso_hash"] = perso_hash
                # First-come-first-serve: ist die Perso schon bei einem anderen Account?
                primary_sid = _find_primary_by_perso_hash(perso_hash, exclude_sid=shinpai_id)
                if primary_sid:
                    target["is_secondary_account"] = True
                    target["primary_account_sid"] = primary_sid
                    nexus_log(f"🔗 Zweit-Account erkannt ({shinpai_id} → primary {primary_sid})", "yellow")
                    # Limit-Checks: 6-Kinder-Max, 1007-Total-Max (1 + 6 + bot_quota)
                    counts = count_secondary_by_primary(primary_sid)
                    bot_quota = int(load_config().get("bot_quota", 20))
                    max_total = 1 + 6 + bot_quota  # 1 Erwachsener + 6 Kinder + bot_quota Bots
                    has_kk = bool(target.get("verified_stripe"))
                    scheduled = now + 7 * 86400  # 7 Tage Gnadenfrist bevor echt gelöscht
                    if counts["total"] >= max_total - 1:
                        # Gesamt-Limit erreicht — Account zur Löschung markieren
                        target["account_scheduled_delete_at"] = scheduled
                        target["account_delete_reason"] = "persona_limit_exceeded"
                        nexus_log(f"🚫 Perso-Limit voll ({counts['total']}/{max_total}) — {shinpai_id} zur Löschung in 7d markiert", "red")
                    elif counts["kinder"] >= 6:
                        # 6-Kinder voll — ohne KK kein Platz, mit KK auto-Bot
                        if has_kk:
                            target["type_override"] = "bot"
                            nexus_log(f"🤖 6-Kinder-Limit erreicht — {shinpai_id} automatisch als Bot eingeordnet", "cyan")
                        else:
                            target["account_scheduled_delete_at"] = scheduled
                            target["account_delete_reason"] = "kinder_limit_no_kk"
                            nexus_log(f"🚫 6-Kinder-Limit ohne KK — {shinpai_id} zur Löschung in 7d markiert", "red")

    # Owner?
    if _identity and _identity.get("shinpai_id") == shinpai_id:
        if level > _identity.get("verification_level", 0):
            _identity.update(vdata)
        _resolve_card_replace(_identity)
        _set_provider_flags(_identity)
        _save_identity()
        nexus_log(f"✅ Owner Verifikation Level {level} ({provider})", "green")
        _create_verification_license(shinpai_id, _identity.get("name", ""), provider, level, real_expiry_ts=real_expiry_ts)
        return

    # User?
    for uname, udata in _users.items():
        if udata.get("shinpai_id") == shinpai_id:
            if level > udata.get("verification_level", 0):
                udata.update(vdata)
            _resolve_card_replace(udata)
            _set_provider_flags(udata)
            _save_users()
            nexus_log(f"✅ Verifikation Level {level} ({provider})", "green")
            _create_verification_license(shinpai_id, udata.get("name", uname), provider, level, real_expiry_ts=real_expiry_ts)
            return

    nexus_log(f"⚠️ Verifikation für unbekannte Shinpai-ID: {shinpai_id}", "yellow")


# ══════════════════════════════════════════════════════════════════════
#  ACCOUNT-TYPE-ABLEITUNG — Kind / Erwachsener / Bot (Perso + KK-Matrix)
# ══════════════════════════════════════════════════════════════════════

def _find_primary_by_perso_hash(perso_hash: str, exclude_sid: str = "") -> str:
    """Sucht Erst-Account mit gegebenem perso_hash (first-come-first-serve).
    Returns shinpai_id des Primary-Accounts oder "" wenn keiner existiert."""
    candidates = []
    if _identity and _identity.get("perso_hash") == perso_hash and _identity.get("shinpai_id") != exclude_sid:
        candidates.append((
            _identity.get("perso_verified_at", 0),
            _identity.get("shinpai_id", ""),
        ))
    for u in _users.values():
        if u.get("perso_hash") == perso_hash and u.get("shinpai_id") != exclude_sid:
            candidates.append((
                u.get("perso_verified_at", 0),
                u.get("shinpai_id", ""),
            ))
    # Primary = der mit frühestem perso_verified_at, der NICHT is_secondary ist
    for _u in _users.values():
        pass  # linting
    primaries = [c for c in candidates if not _is_secondary_sid(c[1])]
    if not primaries:
        return ""
    primaries.sort(key=lambda x: x[0])
    return primaries[0][1]


def _is_secondary_sid(sid: str) -> bool:
    """True wenn Account als Zweit-Account markiert ist."""
    if _identity and _identity.get("shinpai_id") == sid:
        return bool(_identity.get("is_secondary_account"))
    for u in _users.values():
        if u.get("shinpai_id") == sid:
            return bool(u.get("is_secondary_account"))
    return False


def derive_account_type(record: dict) -> str:
    """Leitet Account-Typ aus Flags ab: 'kind' | 'erwachsener' | 'bot'.

    Matrix (Erst-Account, keine Perso-Kollision):
      - KK=❌, Perso=❌ → Kind
      - KK=❌, Perso=✅ → Kind (Perso allein = Jugendschutz-Gate)
      - KK=✅, Perso=❌ → Erwachsener (90-Tage-Probe)
      - KK=✅, Perso=✅ → Erwachsener (ewig)

    Zweit-Account (perso_hash matched Erst-Account):
      - Default → Kind (egal ob KK da)
      - type_override='bot' UND eigene KK → Bot
    """
    has_kk = bool(record.get("verified_stripe"))
    has_perso = bool(record.get("id_verified"))
    is_secondary = bool(record.get("is_secondary_account"))
    type_override = (record.get("type_override") or "").lower()

    if is_secondary:
        # Zweit-Account: Kind ist Default, Bot nur mit eigener KK + Override
        if type_override == "bot" and has_kk:
            return "bot"
        return "kind"

    # Erst-Account
    if has_kk:
        return "erwachsener"
    # Kein KK → Kind (egal ob Perso oder nicht)
    return "kind"


def _account_lifecycle_tick():
    """Cleanup-Tick: Entfernt abgelaufene Accounts + Owner-Reset-Überwachung.
    User: pw_reset_pending 7 Tage → Account gelöscht
    Owner: pw_reset_pending 24h → nexus_corrupt (Email an User), 30 Tage → Nexus-Schließung
    Perso-Blacklist: abgelaufene Einträge aufräumen.
    """
    if not vault_is_unlocked():
        return
    now = int(time.time())
    ninety_days = 90 * 86400
    # Perso-Blacklist aufräumen
    _perso_blacklist_cleanup()

    # ── Owner-Reset-Überwachung ──────────────────────────────────────
    if _identity and _identity.get("pw_reset_pending"):
        triggered = int(_identity.get("pw_reset_triggered_at") or 0)
        if triggered:
            elapsed = now - triggered
            # 24h ohne Änderung → Nexus korrupt, User benachrichtigen (einmalig)
            if elapsed >= 86400 and not _identity.get("nexus_corrupt_notified"):
                _identity["nexus_corrupt"] = True
                _identity["nexus_corrupt_since"] = now
                _identity["nexus_corrupt_notified"] = True
                _save_identity()
                nexus_log("⚠️ OWNER RESET 24h OHNE AKTION — Nexus als korrupt markiert!", "red")
                # Email an alle verifizierten User
                _notify_all_users_nexus_corrupt()
            # 30 Tage ohne Änderung → Nexus-Schließung
            if elapsed >= 30 * 86400:
                _identity["nexus_shutdown"] = True
                _identity["nexus_shutdown_at"] = now
                _save_identity()
                nexus_log("🔒 NEXUS GESCHLOSSEN — Owner hat 30 Tage im Reset-Modus nichts geändert!", "red")
                _notify_all_users_nexus_shutdown()

    # ── User-Cleanup ─────────────────────────────────────────────────
    deleted = []
    owner_sid = (_identity or {}).get("shinpai_id", "")
    to_delete = []
    for uname, u in _users.items():
        sid = u.get("shinpai_id", "")
        if sid == owner_sid:
            continue
        # Migrierte Accounts: 30-Tage-Zombie-Phase, danach endgültig löschen
        # → Name + Email + Shinpai-ID wieder frei für Neuregistrierung
        if u.get("migrated_to"):
            migrated_at = int(u.get("migrated_at") or 0)
            if migrated_at and (now - migrated_at) >= 30 * 86400:
                to_delete.append((uname, sid, "migrated_30d_cleanup"))
            continue
        # Scheduled-Delete überschrieben
        sched = int(u.get("account_scheduled_delete_at") or 0)
        if sched and now >= sched:
            to_delete.append((uname, sid, u.get("account_delete_reason", "scheduled")))
            continue
        # PW-Reset-Pending: 7 Tage ohne Aktion → Löschung (Kompromittierungs-Annahme)
        if u.get("pw_reset_pending"):
            triggered = int(u.get("pw_reset_triggered_at") or 0)
            if triggered and (now - triggered) >= 7 * 86400:
                to_delete.append((uname, sid, "pw_reset_timeout_7d"))
                continue
            continue
        # Perso-Schutz — aber 3-Jahres-Inaktivitäts-Grenze!
        if u.get("id_verified"):
            last_active = int(u.get("last_login") or u.get("created") or 0)
            if last_active and (now - last_active) >= 3 * 365 * 86400:
                to_delete.append((uname, sid, "3y_perso_inactive"))
                nexus_log(f"⏳ Perso-Account {uname} seit 3+ Jahren inaktiv — wird freigegeben", "yellow")
            continue
        # 90-Tage-Regel: Account ohne Perso
        created = int(u.get("created") or 0)
        if created and (now - created) >= ninety_days:
            to_delete.append((uname, sid, "90d_no_perso"))
    for uname, sid, reason in to_delete:
        _users.pop(uname, None)
        _user_hives.pop(uname, None)
        _friends_data.pop(sid, None)
        deleted.append((uname, sid, reason))
    if deleted:
        _save_users()
        for uname, sid, reason in deleted:
            nexus_log(f"🧹 Lifecycle-Cleanup: {uname} ({sid}) — Grund: {reason}", "yellow")


def _owner_clear_reset_flags():
    """Owner hat im Reset-Modus eine Aktion durchgeführt → alle Reset/Korrupt-Flags aufräumen."""
    if not _identity:
        return
    _identity["pw_reset_pending"] = False
    _identity.pop("pw_reset_triggered_at", None)
    _identity.pop("nexus_corrupt", None)
    _identity.pop("nexus_corrupt_since", None)
    _identity.pop("nexus_corrupt_notified", None)
    _identity.pop("nexus_shutdown", None)
    _identity.pop("nexus_shutdown_at", None)
    _save_identity()
    nexus_log("🟢 Owner-Reset-Modus deaktiviert — alle Korrupt-Flags gelöscht", "green")


def _notify_all_users_nexus_corrupt():
    """Benachrichtigt alle verifizierten User: Owner hat Zugangsdaten verloren, Nexus-Schließung droht."""
    owner_name = (_identity or {}).get("name", "Owner")
    cfg = load_config()
    subject = "⚠️ ShinNexus — Owner-Reset aktiv, Umsiedlung empfohlen"
    for uname, u in _users.items():
        email = u.get("email", "")
        if not email or not u.get("email_verified"):
            continue
        html = f"""<div style="font-family:sans-serif;background:#0a0f18;color:#aac0d8;padding:30px;">
        <h2 style="color:#e8c464;">⚠️ Nexus-Warnung</h2>
        <p>Der Owner dieses ShinNexus hat einen Passwort-Reset ausgelöst und seit 24 Stunden nichts geändert.</p>
        <p>Das bedeutet: <strong>Dieser Nexus gilt als möglicherweise kompromittiert.</strong></p>
        <p>Empfehlung: <strong>Sichere deine Daten und siedle zu einem anderen ShinNexus um.</strong></p>
        <p style="color:#887755;font-size:12px;">Falls der Owner seine Daten innerhalb von 30 Tagen wiederherstellt, bleibt der Nexus aktiv. Andernfalls wird er geschlossen.</p>
        <p style="color:#665540;font-size:11px;">— ShinNexus Lifecycle-System</p>
        </div>"""
        try:
            send_nexus_email(email, subject, html, cfg)
        except Exception:
            pass


def _notify_all_users_nexus_shutdown():
    """Benachrichtigt alle User: Nexus wird geschlossen."""
    cfg = load_config()
    subject = "🔒 ShinNexus — Nexus geschlossen"
    for uname, u in _users.items():
        email = u.get("email", "")
        if not email or not u.get("email_verified"):
            continue
        html = f"""<div style="font-family:sans-serif;background:#0a0f18;color:#aac0d8;padding:30px;">
        <h2 style="color:#e44;">🔒 Nexus geschlossen</h2>
        <p>Der Owner dieses ShinNexus hat 30 Tage nach dem Reset keine Änderung vorgenommen.</p>
        <p><strong>Dieser Nexus ist ab sofort geschlossen.</strong> Bitte siedle zu einem anderen ShinNexus um.</p>
        <p style="color:#887755;font-size:12px;">Du kannst über den Migrations-Tab deine Daten exportieren, solange der Server noch erreichbar ist.</p>
        <p style="color:#665540;font-size:11px;">— ShinNexus Lifecycle-System</p>
        </div>"""
        try:
            send_nexus_email(email, subject, html, cfg)
        except Exception:
            pass


# ── Perso-Hash-Blacklist (Anti-Rage-Quit bei Self-Delete) ─────────────
def _load_perso_blacklist() -> list:
    """Lädt [{perso_hash, deleted_at, expires_at}, ...] aus Datei."""
    if not PERSO_BLACKLIST_FILE.exists():
        return []
    try:
        return json.loads(PERSO_BLACKLIST_FILE.read_text("utf-8"))
    except Exception:
        return []


def _save_perso_blacklist(bl: list):
    PERSO_BLACKLIST_FILE.write_text(json.dumps(bl, ensure_ascii=False), "utf-8")
    try:
        os.chmod(PERSO_BLACKLIST_FILE, 0o600)
    except OSError:
        pass


def _perso_blacklist_add(perso_hash: str):
    """Perso-Hash für 90 Tage auf die Blacklist setzen."""
    bl = _load_perso_blacklist()
    now = int(time.time())
    bl.append({"perso_hash": perso_hash, "deleted_at": now, "expires_at": now + 90 * 86400})
    _save_perso_blacklist(bl)
    nexus_log(f"🚫 Perso-Hash auf 90-Tage-Blacklist (Self-Delete)", "yellow")


def _perso_blacklist_check(perso_hash: str) -> bool:
    """True wenn Hash noch auf der Blacklist ist."""
    bl = _load_perso_blacklist()
    now = int(time.time())
    return any(e["perso_hash"] == perso_hash and now < e["expires_at"] for e in bl)


def _perso_blacklist_cleanup():
    """Abgelaufene Einträge entfernen (im Lifecycle-Tick)."""
    bl = _load_perso_blacklist()
    now = int(time.time())
    cleaned = [e for e in bl if now < e["expires_at"]]
    if len(cleaned) != len(bl):
        _save_perso_blacklist(cleaned)
        nexus_log(f"🧹 Perso-Blacklist: {len(bl) - len(cleaned)} abgelaufene Einträge entfernt", "green")


def count_secondary_by_primary(primary_sid: str) -> dict:
    """Zählt {kinder, bots, total} die an diesem Primary hängen."""
    kinder = 0
    bots = 0
    for u in _users.values():
        if u.get("primary_account_sid") == primary_sid and u.get("is_secondary_account"):
            t = derive_account_type(u)
            if t == "bot":
                bots += 1
            elif t == "kind":
                kinder += 1
    return {"kinder": kinder, "bots": bots, "total": kinder + bots}


# ── Type-Switch-Abuse-Detection (pro Account: Switch-Historie + Sperre) ──
_type_switch_abuse: dict = {}  # {sid: {switches: [ts...], blocked_until: ts, level: 0-2}}


def _save_type_switch_abuse():
    if not vault_is_unlocked():
        return
    try:
        data = json.dumps(_type_switch_abuse, ensure_ascii=False).encode("utf-8")
        TYPE_SWITCH_ABUSE_VAULT.write_bytes(vault_encrypt(data))
        try:
            os.chmod(TYPE_SWITCH_ABUSE_VAULT, 0o600)
        except OSError:
            pass
    except Exception as e:
        nexus_log(f"⚠️ Type-Switch-Abuse-Save Fehler: {e}", "yellow")


def _load_type_switch_abuse():
    global _type_switch_abuse
    if not TYPE_SWITCH_ABUSE_VAULT.exists() or not vault_is_unlocked():
        _type_switch_abuse = {}
        return
    try:
        raw = vault_decrypt(TYPE_SWITCH_ABUSE_VAULT.read_bytes())
        _type_switch_abuse = json.loads(raw.decode())
    except Exception as e:
        nexus_log(f"⚠️ Type-Switch-Abuse-Load Fehler: {e}", "yellow")
        _type_switch_abuse = {}


def _type_switch_check(sid: str):
    """Prueft ob Account aktuell gesperrt ist fuer Typ-Switches.
    Returns (allowed, msg, retry_after_sec)."""
    now = time.time()
    entry = _type_switch_abuse.get(sid)
    if not entry:
        return True, "", 0
    blocked_until = entry.get("blocked_until", 0)
    if now < blocked_until:
        wait = int(blocked_until - now)
        return False, f"Gesperrt (3-Tage-Bann). Noch {_fmt_duration(wait)}.", wait
    # Redemption durchgelaufen (24h nach Sperr-Ende)?
    red_end = entry.get("redemption_until", 0)
    if red_end and now > red_end:
        entry["level"] = 0
        entry["redemption_until"] = 0
        entry["switches"] = []
        _save_type_switch_abuse()
    return True, "", 0


def _type_switch_register(sid: str):
    """Zaehlt einen Typ-Switch, eskaliert bei Spam (5/2min → Warnung, nochmal → 3-Tage-Sperre).
    Returns (result, msg) wobei result in {'ok', 'warning', 'banned'}."""
    now = time.time()
    entry = _type_switch_abuse.setdefault(sid, {
        "switches": [], "blocked_until": 0, "level": 0, "redemption_until": 0,
    })
    entry["switches"].append(now)
    # Alte Switches > 24h ausmisten
    entry["switches"] = [t for t in entry["switches"] if now - t < 86400]
    # 5 Switches in 2 Minuten?
    switches_2min = [t for t in entry["switches"] if now - t < 120]
    level = entry.get("level", 0)
    if len(switches_2min) >= 5:
        if level == 0:
            entry["level"] = 1
            _save_type_switch_abuse()
            return "warning", "⚠️ Achtung Spam erkannt! Bitte aufhören oder 3 Tage BANN!"
        elif level == 1:
            # Zweites Mal → 3-Tage-Sperre
            entry["level"] = 2
            entry["blocked_until"] = now + 3 * 86400
            entry["redemption_until"] = entry["blocked_until"] + 86400  # 24h Redemption nach Bann
            entry["switches"] = []
            _save_type_switch_abuse()
            nexus_log(f"🚫 Type-Switch-Spam: {sid} → 3 Tage Sperre", "red")
            return "banned", "🚫 Drei Tage Account-Sperre wegen wiederholtem Spam."
    _save_type_switch_abuse()
    return "ok", ""


def _build_perso_hash(decision_data: dict) -> str | None:
    """Baut DSGVO-safen Hash aus Veriff-Decision-Daten.
    Kombiniert document-number+country und/oder firstName+lastName+dateOfBirth.
    Nur der Hash wird gespeichert — Rohdaten verlassen nie den Webhook.
    """
    verif = decision_data.get("verification") or {}
    doc = verif.get("document") or {}
    person = verif.get("person") or {}
    doc_num = (doc.get("number") or "").strip()
    doc_country = (doc.get("country") or "").strip().upper()
    person_fn = (person.get("firstName") or "").strip().lower()
    person_ln = (person.get("lastName") or "").strip().lower()
    person_dob = (person.get("dateOfBirth") or "").strip()
    parts = []
    if doc_num and doc_country:
        parts.append(f"doc:{doc_country}:{doc_num}")
    if person_fn and person_ln and person_dob:
        parts.append(f"p:{person_fn}:{person_ln}:{person_dob}")
    if not parts:
        return None
    combined = "|".join(parts)
    return hashlib.sha256(f"shinnexus-perso-v1-{combined}".encode("utf-8")).hexdigest()


def get_verification_status(shinpai_id: str) -> dict:
    """Gibt aktuellen Verifikations-Status zurück."""
    # Owner?
    if _identity and _identity.get("shinpai_id") == shinpai_id:
        return {
            "verification_level": _identity.get("verification_level", 0),
            "verified_at": _identity.get("verified_at"),
            "verified_by": _identity.get("verified_by"),
            "email_verified": _identity.get("email_verified", False),
        }
    # User?
    for uname, udata in _users.items():
        if udata.get("shinpai_id") == shinpai_id:
            return {
                "verification_level": udata.get("verification_level", 0),
                "verified_at": udata.get("verified_at"),
                "verified_by": udata.get("verified_by"),
                "email_verified": udata.get("email_verified", False),
            }
    return {"verification_level": 0, "verified_at": None, "verified_by": None, "email_verified": False}


def _cleanup_verification_sessions():
    """Abgelaufene Verifikations-Sessions aufräumen."""
    now = time.time()
    expired = [k for k, v in _verification_sessions.items()
               if now - v["created"] > _VERIFY_SESSION_TTL]
    for k in expired:
        del _verification_sessions[k]


def _get_available_providers() -> list[dict]:
    """Gibt Liste verfügbarer Verifikations-Provider zurück."""
    result = []
    for name, prov in _VERIFICATION_PROVIDERS.items():
        result.append({
            "name": name,
            "level": prov.level,
            "available": prov.available(),
        })
    return result


# PQ-signierter Verifikations-Ausweis (N6)
def _sign_verification(shinpai_id: str) -> dict:
    """Erstellt PQ-signierten Nexus-Ausweis mit Verifikationsdaten."""
    status = get_verification_status(shinpai_id)
    if status["verification_level"] < 1:
        return {"error": "Keine Verifikation vorhanden"}

    name = ""
    if _identity and _identity.get("shinpai_id") == shinpai_id:
        name = _identity.get("name", "")
    else:
        for uname, udata in _users.items():
            if udata.get("shinpai_id") == shinpai_id:
                name = udata.get("name", uname)
                break

    ausweis = {
        "shinpai_id": shinpai_id,
        "name": name,
        "verification_level": status["verification_level"],
        "verified_at": status["verified_at"],
        "verified_by": status["verified_by"],
        "email_verified": status["email_verified"],
        "issued_at": int(time.time()),
        "issuer": "ShinNexus",
        "version": VERSION,
    }
    # PQ-Signatur (ML-DSA-65)
    ausweis_bytes = json.dumps(ausweis, sort_keys=True, ensure_ascii=False).encode()
    ausweis["signature"] = _sign_data(ausweis_bytes)
    cfg = load_config()
    ausweis["public_key"] = cfg.get("public_key", "")

    return ausweis


# ══════════════════════════════════════════════════════════════════════
#  AUTO TLS — Self-Signed Cert generieren
# ══════════════════════════════════════════════════════════════════════

_tls_active = False  # Wird beim Server-Start gesetzt


# ══════════════════════════════════════════════════════════════════════
#  NETWORK CHECK — Public-URL Verfügbarkeit (analog Kneipe)
#  2-Stage: Self-Test (/api/ping) + isitup.org Fallback (NAT-Loopback)
#  Manual-URL hat absoluten Vorrang. ThreadedServer verhindert Deadlock.
# ══════════════════════════════════════════════════════════════════════

_network_state: dict = {
    "external_ip": None,
    "local_ips": [],
    "reachable_external": False,
    "reachable_local": False,
    "reachable_via": None,   # "self" | "external" | None
    "best_url": None,
    "last_check": 0,
}
_network_state_lock = threading.Lock()


def _fetch_external_ip() -> str | None:
    """Externe IP via ipify.org. Timeout 3s."""
    try:
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "ShinNexus/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            ip = (data.get("ip") or "").strip()
            return ip or None
    except Exception:
        return None


def _detect_local_ips() -> list:
    """Lokale IPs ermitteln (ohne 127.* und IPv6)."""
    import socket as _sock
    ips = set()
    # Hostname-Aufloesung
    try:
        hostname = _sock.gethostname()
        for info in _sock.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    # UDP-Trick: Socket zu 8.8.8.8 aufmachen (ohne zu senden) und lokale IP lesen
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            ips.add(ip)
    except Exception:
        pass
    return sorted(ips)


def _selftest_url(url: str, timeout: int = 6) -> bool:
    """Self-Test gegen /api/ping — prueft app-Name == ShinNexus.
    Braucht ThreadedServer (ThreadingMixIn) — sonst Deadlock beim Self-Request!
    """
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        req = urllib.request.Request(url.rstrip("/") + "/api/ping", method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status != 200:
                return False
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("app") == "ShinNexus"
    except Exception:
        return False


def _externtest_url(url: str, timeout: int = 10) -> bool:
    """isitup.org als NAT-Loopback-Fallback. Robust gegen HTML-Antworten."""
    try:
        import urllib.parse as _up
        host = urlparse(url).hostname
        if not host:
            return False
        api_url = f"https://isitup.org/{_up.quote(host)}.json"
        req = urllib.request.Request(api_url, headers={"User-Agent": "ShinNexus/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore").strip()
            if not body or not body.startswith("{"):
                return False  # HTML statt JSON — isitup spuckt manchmal Schrott
            data = json.loads(body)
            rc = data.get("response_code")
            return rc in (200, 301, 302, 304)
    except Exception:
        return False


def _check_external_reachable(url: str) -> tuple:
    """(reachable, method) wobei method in {'self', 'external', 'none'}."""
    if _selftest_url(url):
        return True, "self"
    if _externtest_url(url):
        return True, "external"
    return False, "none"


def run_network_check(cfg: dict = None) -> dict:
    """Full Network-Check. Manual-URL hat Vorrang, sonst ext_ip:port."""
    global _network_state
    cfg = cfg or load_config()
    state = {
        "external_ip": _fetch_external_ip(),
        "local_ips": _detect_local_ips(),
        "reachable_external": False,
        "reachable_local": False,
        "reachable_via": None,
        "best_url": None,
        "last_check": int(time.time()),
    }
    port = int(cfg.get("port", DEFAULT_PORT))
    proto = "https" if _tls_active else "http"
    manual_url = (cfg.get("public_url", "") or "").rstrip("/")

    # 1) Manual hat Vorrang
    if manual_url:
        reachable, method = _check_external_reachable(manual_url)
        if reachable:
            state["reachable_external"] = True
            state["reachable_via"] = method
            state["best_url"] = manual_url
    # 2) Sonst: ext_ip:port testen
    elif state["external_ip"]:
        test_url = f"{proto}://{state['external_ip']}:{port}"
        reachable, method = _check_external_reachable(test_url)
        if reachable:
            state["reachable_external"] = True
            state["reachable_via"] = method
            state["best_url"] = test_url

    # 3) Lokal: erste erreichbare LAN-IP
    for ip in state["local_ips"]:
        local_url = f"{proto}://{ip}:{port}"
        if _selftest_url(local_url, timeout=3):
            state["reachable_local"] = True
            if not state["best_url"]:
                state["best_url"] = local_url
            break

    # 4) Fallback: localhost
    if not state["best_url"]:
        state["best_url"] = f"{proto}://localhost:{port}"

    with _network_state_lock:
        _network_state = state
    return state


def _ensure_self_signed_cert():
    """Generiert Self-Signed TLS-Cert wenn keins existiert."""
    cert_file = CREDENTIALS_DIR / "nexus.crt"
    key_file = CREDENTIALS_DIR / "nexus.key"
    if cert_file.exists() and key_file.exists():
        return cert_file, key_file

    nexus_log("Generiere Self-Signed TLS-Zertifikat...", "cyan")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import ipaddress

        # EC Key (schnell, klein)
        key = ec.generate_private_key(ec.SECP256R1())

        # Cert gültig 10 Jahre
        from datetime import timedelta
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ShinNexus"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Shinpai-AI"),
        ])
        now = datetime.now(tz=__import__("datetime").timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("*.local"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        key_file.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
        nexus_log("Self-Signed TLS-Cert erstellt (10 Jahre gültig)", "green")
    except Exception as e:
        nexus_log(f"TLS-Cert Generierung fehlgeschlagen: {e}", "red")
        return None, None
    return cert_file, key_file


# ── ACME Provider Fallback-Chain (5 Provider, wie ShinShare) ──────────

_ACME_PROVIDERS = [
    {"name": "Let's Encrypt",         "server": "https://acme-v02.api.letsencrypt.org/directory",
     "needs_email": False, "needs_eab": False},
    {"name": "ZeroSSL",               "server": "https://acme.zerossl.com/v2/DV90",
     "needs_email": True,  "needs_eab": True},
    {"name": "Buypass",               "server": "https://api.buypass.com/acme/directory",
     "needs_email": True,  "needs_eab": False},
    {"name": "SSL.com",               "server": "https://acme.ssl.com/sslcom-dv-rsa",
     "needs_email": True,  "needs_eab": True},
    {"name": "Google Trust Services",  "server": "https://dv.acme-v02.api.pki.goog/directory",
     "needs_email": True,  "needs_eab": True},
]

_ACME_STATE_FILE = CREDENTIALS_DIR / "acme_provider_state.json"
_ACME_CERT_DIR = CREDENTIALS_DIR / "acme"


def _acme_state_load() -> dict:
    try:
        if _ACME_STATE_FILE.exists():
            return json.loads(_ACME_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _acme_state_block(provider_name: str, reason: str):
    """Provider als geblockt markieren (LE=168h, Rest=24h)."""
    state = _acme_state_load()
    ttl = 168 * 3600 if "Encrypt" in provider_name else 24 * 3600
    state[provider_name] = {
        "blocked_at": time.time(),
        "blocked_until": time.time() + ttl,
        "reason": reason[:200],
    }
    try:
        _ACME_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


def _acme_state_is_blocked(provider_name: str) -> bool:
    state = _acme_state_load()
    entry = state.get(provider_name)
    if not entry:
        return False
    return time.time() < entry.get("blocked_until", 0)


def _zerossl_get_eab(email: str):
    """ZeroSSL EAB-Credentials per API holen."""
    import urllib.request
    try:
        data = f"email={email}".encode()
        req = urllib.request.Request(
            "https://api.zerossl.com/acme/eab-credentials-email",
            data=data, method="POST"
        )
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read())
            if resp.get("success"):
                return resp["eab_kid"], resp["eab_hmac_key"]
    except Exception as e:
        nexus_log(f"ZeroSSL EAB fehlgeschlagen: {e}", "yellow")
    return None


def _find_certbot() -> str | None:
    """certbot finden: erst im venv-bin, dann system-weit."""
    venv_certbot = Path(sys.executable).parent / "certbot"
    if venv_certbot.exists():
        return str(venv_certbot)
    found = shutil.which("certbot")
    return found


def _obtain_acme_cert(domain: str, acme_email: str = "") -> tuple:
    """Echtes TLS-Cert via ACME Provider-Chain (5 Provider, Standalone HTTP-01).
    Gibt (cert_path, key_path) zurück oder (None, None)."""
    import socket as _sock

    _ACME_CERT_DIR.mkdir(parents=True, exist_ok=True)

    dst_cert = _ACME_CERT_DIR / "fullchain.pem"
    dst_key = _ACME_CERT_DIR / "privkey.pem"

    # Bereits vorhanden und gültig?
    if dst_cert.exists() and dst_key.exists():
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", str(dst_cert), "-checkend", "86400", "-noout"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                nexus_log(f"ACME-Cert vorhanden und gültig: {domain}", "green")
                return dst_cert, dst_key
            else:
                nexus_log("ACME-Cert abgelaufen — erneuere...", "yellow")
        except FileNotFoundError:
            # openssl nicht da → Cert als gültig annehmen
            nexus_log(f"ACME-Cert vorhanden: {domain}", "green")
            return dst_cert, dst_key

    certbot_bin = _find_certbot()
    if not certbot_bin:
        nexus_log("certbot nicht gefunden!", "yellow")
        nexus_log("  Install: pip install certbot  (oder: sudo apt install certbot)", "yellow")
        return None, None

    _CONN_ERRORS = ("RemoteDisconnected", "ConnectionReset", "ConnectionRefused",
                    "NewConnectionError", "MaxRetryError", "SSLError")
    _RATE_ERRORS = ("too many certificates", "rate limit", "rateLimited",
                    "Error creating new order", "429")

    def _fix_certbot_permissions(cb_config):
        """Certbot-Verzeichnisse dem aktuellen User zurückgeben (nach sudo certbot)."""
        if os.geteuid() == 0:
            return  # Läuft als Root, passt schon
        uid, gid = os.getuid(), os.getgid()
        for root, dirs, files in os.walk(str(cb_config)):
            try:
                os.chown(root, uid, gid)
            except PermissionError:
                # Letzter Ausweg: sudo chown
                subprocess.run(["sudo", "-n", "chown", "-R", f"{uid}:{gid}", str(cb_config)],
                               capture_output=True, timeout=10)
                return  # Nach rekursivem chown fertig
            for f in files:
                try:
                    os.chown(os.path.join(root, f), uid, gid)
                except PermissionError:
                    pass

    def _find_existing_cert(cb_config):
        cb_live = cb_config / "live"
        if not cb_live.exists():
            return None
        try:
            entries = sorted(cb_live.iterdir())
        except PermissionError:
            # Certbot-Dirs gehören Root → Permissions fixen
            _fix_certbot_permissions(cb_config)
            try:
                entries = sorted(cb_live.iterdir())
            except PermissionError:
                nexus_log(f"ACME: Kein Lesezugriff auf {cb_live} — auch nach chown nicht", "red")
                return None
        for d in entries:
            if not d.is_dir():
                continue
            if d.name == domain or d.name.startswith(f"{domain}-"):
                fc = d / "fullchain.pem"
                pk = d / "privkey.pem"
                if fc.exists() and pk.exists():
                    return (fc, pk)
        return None

    # ── Provider Fallback-Chain ──
    tried = 0
    for provider in _ACME_PROVIDERS:
        pname = provider["name"]
        server = provider["server"]

        if _acme_state_is_blocked(pname):
            nexus_log(f"ACME: {pname} gesperrt (Rate-Limit), überspringe...", "dim")
            continue

        if provider["needs_email"] and not acme_email:
            nexus_log(f"ACME: {pname} braucht E-Mail → überspringe", "dim")
            continue

        tried += 1
        nexus_log(f"ACME: Versuche Provider {tried}/5: {pname}...", "cyan")

        # Cert-Dirs
        safe = pname.lower().replace("'", "").replace(" ", "_")
        cb_config = _ACME_CERT_DIR / f"certbot_{safe}"
        cb_work = cb_config / "work"
        cb_logs = LOGS_DIR / f"certbot_{safe}"
        for d in (cb_config, cb_work, cb_logs):
            d.mkdir(parents=True, exist_ok=True)

        # Vorhandenes Cert?
        existing = _find_existing_cert(cb_config)
        if existing:
            nexus_log(f"Cert in {pname}-Dir gefunden, kopiere...", "green")
            shutil.copy2(str(existing[0].resolve()), str(dst_cert))
            shutil.copy2(str(existing[1].resolve()), str(dst_key))
            dst_key.chmod(0o600)
            return dst_cert, dst_key

        # EAB (ZeroSSL etc.)
        eab_args = []
        if provider["needs_eab"]:
            if pname == "ZeroSSL":
                eab = _zerossl_get_eab(acme_email)
                if not eab:
                    continue
                eab_args = ["--eab-kid", eab[0], "--eab-hmac-key", eab[1]]
            else:
                continue

        # Server erreichbar?
        try:
            host = server.split("//")[1].split("/")[0]
            _sock.create_connection((host, 443), timeout=10)
        except OSError:
            nexus_log(f"ACME: {pname} nicht erreichbar, überspringe.", "yellow")
            continue

        # Email-Args
        if provider["needs_email"] and acme_email:
            email_args = ["--email", acme_email, "--no-eff-email"]
        else:
            email_args = ["--register-unsafely-without-email"]

        # certbot standalone (HTTP-01 Challenge)
        # Port 80 braucht root → sudo wenn nötig
        base_cmd = [
            certbot_bin, "certonly", "--standalone",
            "-d", domain,
            "--server", server,
            "--agree-tos",
            "--config-dir", str(cb_config),
            "--work-dir", str(cb_work),
            "--logs-dir", str(cb_logs),
            "--non-interactive",
            "--preferred-challenges", "http",
        ] + email_args + eab_args

        # Root? → direkt. Sonst sudo voranstellen (Port 80 braucht Privilegien)
        if os.geteuid() == 0:
            cmd = base_cmd
        else:
            cmd = ["sudo", "-n"] + base_cmd

        for attempt in range(1, 3):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                # Nach sudo certbot: Permissions dem aktuellen User zurückgeben
                if os.geteuid() != 0:
                    _fix_certbot_permissions(cb_config)
            except subprocess.TimeoutExpired:
                nexus_log(f"ACME: {pname} Timeout", "yellow")
                break
            except FileNotFoundError:
                nexus_log("certbot nicht gefunden!", "red")
                return None, None

            found = _find_existing_cert(cb_config)
            if found:
                nexus_log(f"ACME: {pname} Cert erhalten!", "green")
                shutil.copy2(str(found[0].resolve()), str(dst_cert))
                shutil.copy2(str(found[1].resolve()), str(dst_key))
                dst_key.chmod(0o600)
                return dst_cert, dst_key

            # Cert erfolgreich aber Permissions blocken _find_existing_cert?
            # → sudo cp direkt aus dem bekannten Pfad
            if "successfully received certificate" in (result.stdout or "").lower() + (result.stderr or "").lower():
                cb_live = cb_config / "live"
                for guess_name in (domain, f"{domain}-0001", f"{domain}-0002"):
                    src_fc = cb_live / guess_name / "fullchain.pem"
                    src_pk = cb_live / guess_name / "privkey.pem"
                    try:
                        subprocess.run(
                            ["sudo", "-n", "cp", str(src_fc), str(dst_cert)],
                            capture_output=True, timeout=10
                        )
                        subprocess.run(
                            ["sudo", "-n", "cp", str(src_pk), str(dst_key)],
                            capture_output=True, timeout=10
                        )
                        # Ownership dem aktuellen User geben
                        uid, gid = os.getuid(), os.getgid()
                        subprocess.run(
                            ["sudo", "-n", "chown", f"{uid}:{gid}", str(dst_cert), str(dst_key)],
                            capture_output=True, timeout=10
                        )
                        dst_key.chmod(0o600)
                        if dst_cert.exists() and dst_key.exists():
                            nexus_log(f"ACME: {pname} Cert via sudo cp übernommen!", "green")
                            return dst_cert, dst_key
                    except Exception:
                        continue

            stderr = (result.stderr or "") + (result.stdout or "")

            # sudo ohne Passwort gescheitert? → sudoers-Regel anlegen
            if "sudo: a password is required" in stderr or "sudo:" in stderr.lower() and "password" in stderr.lower():
                _user = os.environ.get("USER", "")
                if not _user:
                    nexus_log("ACME: sudo braucht Passwort und User unbekannt!", "red")
                    return None, None
                _sudoers_rule = f"{_user} ALL=(ALL) NOPASSWD: {certbot_bin} *"
                _sudoers_file = f"/etc/sudoers.d/shinnexus-certbot"
                nexus_log("ACME: certbot braucht sudo-Rechte für Port 80", "yellow")
                nexus_log("  Lege sudoers-Regel an (einmalig, braucht sudo-Passwort)...", "yellow")
                try:
                    _pw = getpass.getpass(f"  sudo-Passwort für {_user}: ")
                    _setup_cmd = f"echo '{_sudoers_rule}' | sudo -S tee {_sudoers_file} && sudo chmod 440 {_sudoers_file}"
                    _sr = subprocess.run(
                        ["sudo", "-S", "bash", "-c", f"echo '{_sudoers_rule}' > {_sudoers_file} && chmod 440 {_sudoers_file}"],
                        input=_pw + "\n", capture_output=True, text=True, timeout=10
                    )
                    if _sr.returncode == 0:
                        nexus_log("ACME: sudoers-Regel angelegt! Wiederhole certbot...", "green")
                        continue  # nochmal versuchen
                    else:
                        nexus_log(f"ACME: sudoers anlegen fehlgeschlagen: {_sr.stderr.strip()[:200]}", "red")
                        return None, None
                except Exception as _e:
                    nexus_log(f"ACME: sudoers-Setup Fehler: {_e}", "red")
                    return None, None

            if any(e.lower() in stderr.lower() for e in _RATE_ERRORS):
                nexus_log(f"ACME: {pname} Rate-Limit → sperre Provider!", "yellow")
                _acme_state_block(pname, f"Rate-Limit: {stderr.strip()[:200]}")
                break

            if any(e in stderr for e in _CONN_ERRORS) and attempt < 2:
                nexus_log(f"ACME: {pname} Verbindungsfehler (Versuch {attempt}/2), warte 5s...", "yellow")
                time.sleep(5)
                continue

            nexus_log(f"ACME: {pname} fehlgeschlagen: {stderr.strip()[:200]}", "yellow")
            _acme_state_block(pname, stderr.strip()[:200])
            break

    # ALLE AUSGEFALLEN
    nexus_log("=" * 50, "red")
    nexus_log("ALLE ACME-PROVIDER AUSGEFALLEN!", "red")
    nexus_log("Optionen:", "red")
    nexus_log("  1. Warten bis Rate-Limits ablaufen", "red")
    nexus_log("  2. certbot manuell: certbot certonly --standalone -d " + domain, "red")
    nexus_log("  3. Fallback: Self-Signed Cert", "red")
    nexus_log("=" * 50, "red")
    return None, None


# ══════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ══════════════════════════════════════════════════════════════════════

# Sensitive Endpoints — nur über TLS ODER localhost erlaubt!
_SENSITIVE_ENDPOINTS = {
    "/api/vault/unlock", "/api/vault/lock",
    "/api/account/create", "/api/account/update",
    "/api/2fa/setup", "/api/2fa/confirm",
    "/api/auth/login", "/api/auth/register", "/api/auth/password",
    "/api/agent/create", "/api/agent/delete",
    "/api/verify/start", "/api/verify/callback", "/api/verify/reset",
    "/api/stripe/config",
    "/api/veriff/config",
    "/api/veriff/toggle",
    "/api/veriff/price",
    "/api/public-url/save",
    "/api/public-url/check",
    "/api/public-url/config",
    "/api/license/save",
    "/api/migrate/export",
    "/api/migrate/import",
    "/api/migrate/owner-start",
    "/api/owner/igni",
    "/api/owner/igni/export",
    "/api/whitelist",
    "/api/whitelist/add",
    "/api/whitelist/delete",
    "/api/whitelist/import",
    "/api/owner/bot-quota",
    "/api/account/type-switch",
    "/api/account/delete-self",
    "/api/owner/members/delete",
    "/api/auth/seed-unlock",
    "/api/auth/pw-reset-set",
    "/api/auth/seed-refresh",
}

# Auth-geschützte Endpoints — brauchen 2FA wenn aktiviert
_AUTH_ENDPOINTS = {
    "/api/account/update", "/api/hive/join", "/api/hive/leave",
    "/api/authorize", "/api/tunnel/start", "/api/tunnel/stop",
}

# Brute-Force Schutz
_auth_fails: dict = {}  # {ip: count}
_AUTH_MAX_FAILS = 5
_AUTH_LOCKOUT = 300  # 5 Minuten


def _auth_fail(ip: str):
    _auth_fails[ip] = _auth_fails.get(ip, 0) + 1


def _auth_success(ip: str):
    _auth_fails.pop(ip, None)


def _auth_locked(ip: str) -> bool:
    return _auth_fails.get(ip, 0) >= _AUTH_MAX_FAILS


class ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class NexusHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler für ShinNexus API."""

    protocol_version = "HTTP/1.0"
    config: dict = {}

    def log_message(self, fmt, *args):
        """BaseHTTPRequestHandler-Logging unterdrücken."""
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length)
        return b""

    def _parse_json(self) -> dict:
        body = self._read_body()
        if not body:
            return {}
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {}

    def _client_ip(self) -> str:
        return self.client_address[0]

    # ── CORS ──────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    # ── GET Routes ────────────────────────────────────────────────
    def do_GET(self):
        ip = self._client_ip()
        if not _check_rate_limit(ip):
            self._send_json({"error": "Rate limit exceeded"}, 429)
            return

        path = urlparse(self.path).path.rstrip("/")

        if path == "/api/ping":
            self._handle_ping()
        elif path == "/api/identity":
            self._handle_identity()
        elif path == "/api/hives":
            self._handle_hives()
        elif path == "/api/challenge":
            self._handle_challenge_get()
        elif path == "/api/friends":
            self._handle_friends_list()
        elif path == "/api/dm/pending":
            self._handle_dm_pending()
        elif path.startswith("/api/friends/keys/"):
            # GET /api/friends/keys/{shinpai_id}
            target_id = path[len("/api/friends/keys/"):].strip("/")
            if not target_id:
                self._send_json({"error": "shinpai_id erforderlich"}, 400)
            else:
                self._handle_friends_keys(target_id)
        elif path == "/api/agent/list":
            self._handle_agent_list()
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/auth/email":
            self._handle_email_get()
        elif path == "/api/system/status":
            self._handle_system_status()
        elif path == "/api/owner/igni":
            self._handle_owner_igni_get()
        elif path == "/api/owner/igni/export":
            self._handle_owner_igni_export()
        elif path == "/api/public-url/status":
            self._handle_public_url_status()
        elif path == "/api/whitelist":
            self._handle_whitelist_get()
        elif path == "/api/public/bot-policy":
            self._handle_bot_policy_get()
        elif path == "/api/account/type":
            self._handle_account_type_status()
        elif path == "/api/owner/members":
            self._handle_owner_members_list()
        elif path.startswith("/api/public/shield"):
            self._handle_public_shield()
        elif path == "/api/public/chain":
            self._handle_public_chain()
        elif path == "/api/btc/wallet":
            self._handle_btc_wallet_get()
        elif path == "/api/titles":
            self._handle_titles()
        elif path == "/api/btc/anchor/preview":
            self._handle_btc_anchor_preview()
        elif path == "/api/btc/revoke/preview":
            self._handle_btc_revoke_preview()
        elif path == "/api/btc/revoke/status":
            self._handle_btc_revoke_status()
        elif path == "/api/btc/anchor/status":
            self._handle_btc_anchor_status()
        elif path.startswith("/widget/shield"):
            self._handle_widget_shield()
        elif path == "/ShinNexus-Logo.webp":
            # Butler-Logo (komplett, für Login/Dashboard-Header/Intro)
            logo = BASE / "ShinNexus-Logo.webp"
            if logo.exists():
                self.send_response(200)
                self.send_header("Content-Type", "image/webp")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(logo.read_bytes())
            else:
                self.send_error(404)
        elif path == "/ShinNexus-Shield.png":
            # Shield standard (ohne Stern, für Stufe 0-2)
            shield = BASE / "ShinNexus-Shield.png"
            if shield.exists():
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(shield.read_bytes())
            else:
                self.send_error(404)
        elif path == "/ShinNexus-Shield-edel.png":
            # Shield edel (mit Stern, für Stufe 3 = Amt-bestätigt; später Rollen/Amt-Kategorien)
            shield = BASE / "ShinNexus-Shield-edel.png"
            if shield.exists():
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(shield.read_bytes())
            else:
                self.send_error(404)
        elif path == "/api/email/verify":
            self._handle_email_verify()
        elif path == "/api/verify/status":
            self._handle_verify_status()
        elif path == "/api/verify/callback":
            # GET: User wird von Veriff/Stripe nach Abschluss hierher weitergeleitet
            # Zeige Success-Page die zum Dashboard zurückführt
            html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Verifikation</title>
<meta http-equiv="refresh" content="3;url=/">
<style>body{background:#0a0a0a;color:#e0d8c8;font-family:Georgia,serif;text-align:center;padding:50px;}
.card{max-width:420px;margin:60px auto;background:#0d0d1a;border:1px solid #2a2a3a;border-radius:12px;padding:40px;}
.icon{font-size:48px;margin-bottom:20px;}h2{color:#7ab8e0;}p{color:#998866;}
.bar{width:100%;height:3px;background:#1a1a2a;border-radius:2px;margin-top:20px;overflow:hidden;}
.bar-fill{height:100%;background:linear-gradient(90deg,#7ab8e0,#d4a850);animation:fill 3s linear forwards;}
@keyframes fill{from{width:0;}to{width:100%;}}</style>
</head><body><div class="card"><div class="icon">🛡️</div>
<h2>Verifikation erhalten</h2>
<p>Deine Verifikation wird jetzt geprüft. Du wirst gleich zum Dashboard weitergeleitet.</p>
<div class="bar"><div class="bar-fill"></div></div>
<p style="font-size:11px;color:#445566;margin-top:20px;">ShinNexus — Ist einfach passiert. 🐉</p>
</div></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode())))
            self.end_headers()
            self.wfile.write(html.encode())
        elif path == "/api/license/info":
            self._handle_license_info()
        elif path == "/api/chain/info":
            self._handle_chain_info()
        elif path == "/api/server/status":
            self._handle_server_status()
        elif path == "/api/amt-lists":
            self._handle_amt_lists_get()
        elif path == "/api/amt-lists/amter":
            self._handle_amt_lists_amter()
        elif path == "/api/amt-directory/browse":
            self._handle_amt_directory_browse()
        elif path == "/api/amt-directory/search":
            self._handle_amt_directory_search()
        elif path == "/api/amt-watchlist":
            self._handle_amt_watchlist_get()
        elif path == "/api/licenses/received":
            self._handle_licenses_received()
        elif path == "/api/licenses/issued":
            self._handle_licenses_issued()
        elif path == "/api/verify/providers":
            self._handle_verify_providers()
        elif path == "/api/verify/ausweis":
            self._handle_verify_ausweis()
        elif path.startswith("/api/firemail/read/"):
            fid = path[len("/api/firemail/read/"):].strip("/")
            self._handle_firemail_read(fid)
        elif path == "" or path == "/":
            self._handle_landing()
        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_email_verify(self):
        """GET /api/email/verify?token=XXX — OBSOLET. Link-Variante ersetzt durch
        POST /api/email/verify-code (6-stelliger Ziffern-Code, Kneipe-Muster)."""
        self._send_json({
            "error": "Dieser Link-Pfad wurde entfernt. Bitte Code-Eingabe im Dashboard nutzen.",
        }, 410)

    def _handle_email_verify_code(self):
        """POST /api/email/verify-code — 6-stelligen Ziffern-Code pruefen (Kneipe-Muster).

        Body: {email, code}
        Response: {ok, shinpai_id, message} bei Erfolg. 401 bei Fehler.
        Brute-Force-Schutz: max 5 falsche/min/IP.
        """
        ip = self._client_ip()
        # Rate-Limit: 5 falsche Versuche pro Minute pro IP
        now = time.time()
        if not hasattr(type(self), '_verify_code_fails'):
            type(self)._verify_code_fails = {}
        rc = type(self)._verify_code_fails
        entry = rc.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] > 60:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 5:
            self._send_json({"error": "Zu viele Fehlversuche — 1min warten"}, 429)
            return
        data = self._parse_json()
        email = (data.get("email") or "").strip().lower()
        code = str(data.get("code") or "").strip()
        if not email or not code:
            self._send_json({"error": "email und code erforderlich"}, 400)
            return
        if len(code) != 6 or not code.isdigit():
            self._send_json({"error": "Code muss 6 Ziffern sein"}, 400)
            return

        def _check(record, save_fn, label):
            stored = str(record.get("verify_token") or "")
            exp = float(record.get("verify_expires") or 0)
            if not stored:
                return False, "Kein Code angefordert. Erst /api/email/send-verify aufrufen."
            if time.time() > exp:
                # Abgelaufen — Token zuruecksetzen
                record["verify_token"] = ""
                record["verify_expires"] = 0
                save_fn()
                return False, "Code abgelaufen. Neuen Code anfordern."
            if not secrets.compare_digest(stored, code):
                return False, "Code falsch oder abgelaufen. Neuen Code anfordern."
            # Erfolg!
            record["email_verified"] = True
            record["verify_token"] = ""
            record["verify_expires"] = 0
            save_fn()
            nexus_log(f"✅ EMAIL VERIFIED via code — {label}", "green")
            return True, "Email verifiziert!"

        # Owner pruefen
        if _identity and (_identity.get("email") or "").lower() == email:
            ok, msg = _check(_identity, _save_identity, f"Owner {_identity.get('name')}")
            if ok:
                self._send_json({
                    "ok": True,
                    "shinpai_id": _identity.get("shinpai_id"),
                    "message": msg,
                })
                return
            entry["count"] += 1
            rc[ip] = entry
            self._send_json({"error": msg}, 401)
            return

        # User-Liste durchsuchen
        for uname, udata in _users.items():
            if (udata.get("email") or "").lower() == email:
                ok, msg = _check(udata, _save_users, f"User {uname}")
                if ok:
                    self._send_json({
                        "ok": True,
                        "shinpai_id": udata.get("shinpai_id"),
                        "message": msg,
                    })
                    return
                entry["count"] += 1
                rc[ip] = entry
                self._send_json({"error": msg}, 401)
                return

        # Email nicht gefunden — wie falscher Code behandeln (kein User-Enum-Leak)
        entry["count"] += 1
        rc[ip] = entry
        self._send_json({"error": "Code falsch oder abgelaufen. Neuen Code anfordern."}, 401)

    def _is_localhost(self) -> bool:
        """Echte localhost-Prüfung — erkennt Tunnel-Proxies!"""
        ip = self._client_ip()
        if ip not in ("127.0.0.1", "::1", "localhost"):
            return False
        # Tunnel-Erkennung: Wenn Proxy-Header vorhanden → NICHT localhost!
        # Cloudflare setzt CF-Connecting-IP, frpc setzt X-Forwarded-For
        if self.headers.get("CF-Connecting-IP"):
            return False
        if self.headers.get("X-Forwarded-For"):
            return False
        if self.headers.get("X-Real-IP"):
            return False
        return True

    def _is_truly_local(self) -> bool:
        """Strikteste Prüfung für destruktive Operationen (Kill-Switch etc.).
        Localhost UND kein aktiver Tunnel."""
        if not self._is_localhost():
            return False
        # Zusätzlich: Wenn ein Tunnel aktiv ist, KANN nichts wirklich lokal sein
        # weil der Tunnel alles weiterleitet. Extra-Auth wird erzwungen.
        if _cloudflared_process and _cloudflared_process.poll() is None:
            return False
        if _frpc_process and _frpc_process.poll() is None:
            return False
        return True

    # ── POST Routes ───────────────────────────────────────────────
    def do_POST(self):
        ip = self._client_ip()
        if not _check_rate_limit(ip):
            self._send_json({"error": "Rate limit exceeded"}, 429)
            return

        path = urlparse(self.path).path.rstrip("/")

        # Security-Gate: Sensitive Endpoints nur über TLS oder localhost!
        if path in _SENSITIVE_ENDPOINTS and not _tls_active and not self._is_localhost():
            self._send_json({
                "error": "Dieser Endpoint erfordert TLS oder localhost-Zugriff",
                "hint": "Passwörter/Keys werden NICHT über unverschlüsseltes HTTP gesendet!"
            }, 403)
            return

        if path == "/api/verify":
            self._handle_verify()
        elif path == "/api/authorize":
            self._handle_authorize()
        elif path == "/api/account/create":
            self._handle_account_create()
        elif path == "/api/account/update":
            self._handle_account_update()
        elif path == "/api/hive/join":
            self._handle_hive_join()
        elif path == "/api/hive/leave":
            self._handle_hive_leave()
        elif path == "/api/vault/unlock":
            self._handle_vault_unlock()
        elif path == "/api/vault/lock":
            self._handle_vault_lock()
        elif path == "/api/2fa/setup":
            self._handle_2fa_setup()
        elif path == "/api/2fa/confirm":
            self._handle_2fa_confirm()
        elif path == "/api/2fa/verify":
            self._handle_2fa_verify()
        elif path == "/api/tunnel/start":
            self._handle_tunnel_start()
        elif path == "/api/tunnel/stop":
            self._handle_tunnel_stop()
        elif path == "/api/auth/login":
            self._handle_auth_login()
        elif path == "/api/auth/password":
            self._handle_password_change()
        elif path == "/api/auth/email":
            self._handle_email_change()
        elif path == "/api/auth/register":
            self._handle_auth_register()
        elif path == "/api/auth/session":
            self._handle_auth_session()
        elif path == "/api/auth/verify-owner":
            self._handle_verify_owner()
        elif path == "/api/auth/verify-entity":
            self._handle_verify_entity()
        elif path == "/api/firemail/send":
            self._handle_firemail_send()
        elif path == "/api/firemail/verify":
            self._handle_firemail_verify()
        elif path == "/api/smtp/config":
            self._handle_smtp_config()
        elif path == "/api/email/send-verify":
            self._handle_send_verify_email()
        elif path == "/api/email/verify-code":
            self._handle_email_verify_code()
        elif path == "/api/auth/attest-link":
            self._handle_attest_link()
        elif path == "/api/auth/migrate":
            self._handle_migrate()
        elif path == "/api/agent/create":
            self._handle_agent_create()
        elif path == "/api/agent/delete":
            self._handle_agent_delete()
        elif path == "/api/auth/2fa-refresh":
            self._handle_2fa_refresh()
        elif path == "/api/auth/2fa-refresh-confirm":
            self._handle_2fa_refresh_confirm()
        elif path == "/api/auth/seed-refresh":
            self._handle_seed_refresh()
        elif path == "/api/auth/delete-account":
            self._handle_delete_account()
        elif path == "/api/auth/forgot":
            self._handle_forgot_password()
        elif path == "/api/auth/reset-password":
            self._handle_reset_password()
        elif path == "/api/auth/seed-recover":
            self._handle_seed_recover()
        elif path == "/api/auth/seed-unlock":
            self._handle_seed_unlock()
        elif path == "/api/auth/pw-reset-set":
            self._handle_pw_reset_set()
        elif path == "/api/auth/2fa/manage":
            self._handle_2fa_manage()
        elif path == "/api/tunnel/cloudflare":
            self._handle_cloudflare_tunnel()
        elif path == "/api/friends/request":
            self._handle_friend_request()
        elif path == "/api/friends/accept":
            self._handle_friend_accept()
        elif path == "/api/friends/reject":
            self._handle_friend_reject()
        elif path == "/api/friends/block":
            self._handle_friend_block()
        elif path == "/api/friends/unblock":
            self._handle_friend_unblock()
        elif path == "/api/friends/remove":
            self._handle_friend_remove()
        elif path == "/api/dm/send":
            self._handle_dm_send()
        elif path == "/api/dm/ack":
            self._handle_dm_ack()
        elif path == "/api/auth/public-keys":
            self._handle_public_keys_update()
        elif path == "/api/owner/igni":
            self._handle_owner_igni_set()
        elif path == "/api/owner/bot-quota":
            self._handle_bot_quota_set()
        elif path == "/api/whitelist/add":
            self._handle_whitelist_add()
        elif path == "/api/whitelist/delete":
            self._handle_whitelist_delete()
        elif path == "/api/whitelist/import":
            self._handle_whitelist_import()
        elif path == "/api/account/type-switch":
            self._handle_account_type_switch()
        elif path == "/api/account/delete-self":
            self._handle_account_delete_self()
        elif path == "/api/owner/members/delete":
            self._handle_owner_members_delete()
        elif path == "/api/verify/start":
            self._handle_verify_start()
        elif path == "/api/verify/callback":
            self._handle_verify_callback()
        elif path == "/api/btc/wallet/create":
            self._handle_btc_wallet_create()
        elif path == "/api/btc/wallet/import":
            self._handle_btc_wallet_import()
        elif path == "/api/btc/anchor":
            self._handle_btc_anchor()
        elif path == "/api/btc/revoke":
            self._handle_btc_revoke()
        elif path == "/api/verify/reset":
            self._handle_verify_reset()
        elif path == "/api/verify/card-replace":
            self._handle_verify_card_replace()
        elif path == "/api/verify/veriff-webhook":
            self._handle_veriff_webhook()
        elif path == "/api/stripe/config":
            self._handle_stripe_config()
        elif path == "/api/veriff/config":
            self._handle_veriff_config()
        elif path == "/api/veriff/toggle":
            self._handle_veriff_toggle()
        elif path == "/api/veriff/price":
            self._handle_veriff_price_save()
        elif path == "/api/public-url/save":
            self._handle_public_url_save()
        elif path == "/api/public-url/check":
            self._handle_public_url_check()
        elif path == "/api/public-url/config":
            self._handle_public_url_config()
        elif path == "/api/amt-lists/subscribe":
            self._handle_amt_lists_subscribe()
        elif path == "/api/amt-lists/remove":
            self._handle_amt_lists_remove()
        elif path == "/api/amt-lists/refresh":
            self._handle_amt_lists_refresh()
        elif path == "/api/amt-watchlist/add":
            self._handle_amt_watchlist_add()
        elif path == "/api/amt-watchlist/remove":
            self._handle_amt_watchlist_remove()
        elif path == "/api/amt-watchlist/status":
            self._handle_amt_watchlist_status()
        elif path == "/api/amt-watchlist/submit":
            self._handle_amt_watchlist_submit()
        elif path == "/api/amt-watchlist/inquire":
            self._handle_amt_watchlist_inquire()
        elif path == "/api/amt-watchlist/complaint":
            self._handle_amt_watchlist_complaint()
        elif path == "/api/license/save":
            self._handle_license_save()
        elif path == "/api/migrate/bundle":
            self._handle_migrate_bundle()
        elif path == "/api/migrate/confirm":
            self._handle_migrate_confirm()
        elif path == "/api/migrate/export":
            self._handle_migrate_export()
        elif path == "/api/migrate/import":
            self._handle_migrate_import()
        elif path == "/api/migrate/owner-start":
            self._handle_owner_migrate_start()
        else:
            self._send_json({"error": "Not found"}, 404)

    # ── Handler: Ping ─────────────────────────────────────────────
    def _handle_ping(self):
        self._send_json({
            "status": "online",
            "app": APP_NAME,
            "version": VERSION,
            "shinpai_id": _identity["shinpai_id"] if _identity else None,
            "vault_unlocked": vault_is_unlocked(),
        })

    # ── Handler: Identity (auth-basiert — gibt Identity des eingeloggten Users zurück) ──
    def _handle_identity(self):
        # Mit Auth → eigene Identity zurückgeben
        session = self._require_auth()
        if session:
            sid = session.get("shinpai_id", "")
            name = session.get("name", "")
            # Owner?
            if _identity and sid == _identity.get("shinpai_id"):
                cfg = self.config
                user_stamps = _hive_stamps
                self._send_json({
                    "shinpai_id": sid,
                    "name": _identity["name"],
                    "public_key": cfg.get("public_key", ""),
                    "kem_public_key": cfg.get("kem_public_key", ""),
                    "hive_count": len(user_stamps),
                    "created": _identity.get("created"),
                })
                return
            # Registrierter User?
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    user_keys = udata.get("pq_keys", {})
                    user_stamps = _user_hives.get(uname, [])
                    self._send_json({
                        "shinpai_id": sid,
                        "name": udata.get("name", uname),
                        "public_key": user_keys.get("sig_pk", ""),
                        "kem_public_key": user_keys.get("kem_pk", ""),
                        "hive_count": len(user_stamps),
                        "created": udata.get("created"),
                    })
                    return
            self._send_json({"error": "User nicht gefunden"}, 404)

    # ── Handler: Hives (auth-basiert — zeigt Hives des eingeloggten Users) ──
    def _handle_hives(self):
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        # Owner?
        if _identity and sid == _identity.get("shinpai_id"):
            stamps = _hive_stamps
        else:
            # User's Hive-Stempel
            uname = session.get("name", "")
            stamps = _user_hives.get(uname, [])
        public_stamps = [
            {
                "hive_url": s.get("hive_url"),
                "hive_name": s.get("hive_name"),
                "role": s.get("role"),
                "joined_at": s.get("joined_at"),
            }
            for s in stamps
        ]
        self._send_json({"hives": public_stamps})

    # ── Handler: Challenge (für Verify-Flow) ──────────────────────
    def _handle_challenge_get(self):
        source = parse_qs(urlparse(self.path).query).get("source", ["unknown"])[0]
        ch = _create_challenge(source)
        self._send_json(ch)

    # ── Handler: Verify (Challenge-Response) ──────────────────────
    def _handle_verify(self):
        """Empfängt Challenge + signiert sie mit privatem Key → Beweis der Identität."""
        if not _identity or not _pq_keys:
            self._send_json({"error": "Kein Account oder Keys nicht geladen"}, 403)
            return
        data = self._parse_json()
        challenge = data.get("challenge", "")
        if not challenge:
            self._send_json({"error": "challenge fehlt"}, 400)
            return

        # Challenge signieren
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        sign_input = f"{ts}:{nonce}:{challenge}".encode()
        signature = _sign_data(sign_input)

        self._send_json({
            "shinpai_id": _identity["shinpai_id"],
            "signature": signature,
            "timestamp": ts,
            "nonce": nonce,
            "public_key": _pq_keys["sig_pk"],
        })

    # ── Handler: Authorize (2FA-ähnlich für Hive-Aktionen) ────────
    def _handle_authorize(self):
        """Hive fragt um Erlaubnis für eine Aktion."""
        if not _identity or not _pq_keys:
            self._send_json({"error": "Nicht bereit"}, 403)
            return
        data = self._parse_json()
        hive_url = data.get("hive_url", "")
        action = data.get("requested_action", "")

        # Für MVP: Auto-Approve (später: User-Bestätigung via UI/Push)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        sign_input = f"authorize:{ts}:{nonce}:{hive_url}:{action}".encode()
        signature = _sign_data(sign_input)

        nexus_log(f"Authorize: {action} für {hive_url}", "cyan")

        self._send_json({
            "approved": True,
            "shinpai_id": _identity["shinpai_id"],
            "signature": signature,
            "timestamp": ts,
            "nonce": nonce,
        })

    # ── Handler: Account erstellen ────────────────────────────────
    def _handle_account_create(self):
        if not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return
        if _identity:
            self._send_json({"error": "Account existiert bereits"}, 409)
            return
        data = self._parse_json()
        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        if not name or not email:
            self._send_json({"error": "name und email erforderlich"}, 400)
            return
        name_err = validate_username(name)
        if name_err:
            self._send_json({"error": name_err}, 400)
            return

        result = create_account(name, email)

        # Keypair generieren
        cfg = self.config
        cfg["name"] = name
        cfg["email"] = email
        cfg["shinpai_id"] = result["shinpai_id"]
        _ensure_keypair(cfg)
        save_config(cfg)

        self._send_json({
            "shinpai_id": result["shinpai_id"],
            "recovery_seed": result["recovery_seed"],
            "public_key": cfg.get("public_key", ""),
            "message": "Account erstellt! Recovery-Seed JETZT aufschreiben!",
        }, 201)

    # ── Handler: Account update (auth-basiert — Owner UND User) ──
    def _handle_account_update(self):
        session = self._require_auth()
        if not session:
            return
        if not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")

        data = self._parse_json()
        changed = False

        if is_owner:
            if "name" in data and data["name"].strip():
                _identity["name"] = data["name"].strip()
                self.config["name"] = _identity["name"]
                changed = True
            if "email" in data and data["email"].strip():
                _identity["email"] = data["email"].strip()
                self.config["email"] = _identity["email"]
                changed = True
            if changed:
                _save_identity()
                _cfg = load_config()
                _cfg["name"] = _identity.get("name", _cfg.get("name", ""))
                _cfg["email"] = _identity.get("email", _cfg.get("email", ""))
                save_config(_cfg)
                self.config = _cfg
                nexus_log(f"Owner-Account aktualisiert: {_identity['name']}", "green")
            self._send_json({"ok": True, "shinpai_id": _identity["shinpai_id"]})
        else:
            user_data = _users.get(uname)
            if not user_data:
                self._send_json({"error": "User nicht gefunden"}, 404)
                return
            if "email" in data and data["email"].strip():
                user_data["email"] = data["email"].strip()
                changed = True
            # Name-Änderung bei Users nicht erlaubt (Username ist Key)
            if changed:
                _save_users()
                nexus_log(f"User-Account aktualisiert", "green")
            self._send_json({"ok": True, "shinpai_id": user_data["shinpai_id"]})

    # ── Handler: Hive beitreten (auth-basiert — Owner UND User) ──
    def _handle_hive_join(self):
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")

        # Identity + Keys bestimmen (Owner oder User)
        is_owner = _identity and sid == _identity.get("shinpai_id")
        if is_owner:
            join_sid = _identity["shinpai_id"]
            join_name = _identity["name"]
            join_pk = (_pq_keys or {}).get("sig_pk", "")
            join_kem_pk = (_pq_keys or {}).get("kem_pk", "")
            stamps_list = _hive_stamps
        else:
            user_data = _users.get(uname)
            if not user_data:
                self._send_json({"error": "User nicht gefunden"}, 404)
                return
            join_sid = user_data["shinpai_id"]
            join_name = user_data.get("name", uname)
            user_keys = user_data.get("pq_keys", {})
            join_pk = user_keys.get("sig_pk", "")
            join_kem_pk = user_keys.get("kem_pk", "")
            stamps_list = _user_hives.setdefault(uname, [])

        if not join_pk:
            self._send_json({"error": "Keine PQ-Keys vorhanden"}, 403)
            return

        data = self._parse_json()
        hive_url = data.get("hive_url", "").strip().rstrip("/")
        if not hive_url:
            self._send_json({"error": "hive_url erforderlich"}, 400)
            return

        # Prüfen ob schon Mitglied
        for s in stamps_list:
            if s.get("hive_url") == hive_url:
                self._send_json({"error": "Bereits Mitglied", "hive_url": hive_url}, 409)
                return

        # Hive kontaktieren: POST /api/nexus/register
        import urllib.request
        import urllib.error
        register_payload = json.dumps({
            "shinpai_id": join_sid,
            "name": join_name,
            "public_key": join_pk,
            "kem_public_key": join_kem_pk,
            "nexus_url": f"http://{self.config.get('host', '0.0.0.0')}:{self.config.get('port', DEFAULT_PORT)}",
        }, ensure_ascii=False).encode("utf-8")

        try:
            req = urllib.request.Request(
                f"{hive_url}/api/nexus/register",
                data=register_payload,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )
            import ssl as _ssl_hj
            _hj_ctx = _ssl_hj.create_default_context()
            _hj_ctx.check_hostname = False
            _hj_ctx.verify_mode = _ssl_hj.CERT_NONE
            with urllib.request.urlopen(req, timeout=15, context=_hj_ctx) as resp:
                result = json.loads(resp.read())

            # Stempel speichern
            stamp = {
                "hive_url": hive_url,
                "hive_name": result.get("hive_name", "Unbekannt"),
                "role": result.get("role", "S"),
                "joined_at": int(time.time()),
                "hive_signature": result.get("hive_signature", ""),
            }
            stamps_list.append(stamp)
            if is_owner:
                _save_hives()
            else:
                _save_user_hives()
            nexus_log(f"Hive beigetreten: {join_name} → {stamp['hive_name']} ({hive_url})", "green")
            self._send_json({"ok": True, "stamp": stamp}, 201)

        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            self._send_json({"error": f"Hive antwortete: HTTP {e.code}", "details": body}, 502)
        except Exception as e:
            self._send_json({"error": f"Hive nicht erreichbar: {e}"}, 502)

    # ── Handler: Hive verlassen (auth-basiert — Owner UND User) ──
    def _handle_hive_leave(self):
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")

        if is_owner:
            stamps_list = _hive_stamps
            leave_sid = _identity["shinpai_id"]
        else:
            stamps_list = _user_hives.get(uname, [])
            user_data = _users.get(uname)
            leave_sid = user_data["shinpai_id"] if user_data else sid

        data = self._parse_json()
        hive_url = data.get("hive_url", "").strip().rstrip("/")

        found = None
        for i, s in enumerate(stamps_list):
            if s.get("hive_url") == hive_url:
                found = i
                break

        if found is None:
            self._send_json({"error": "Kein Stempel für diesen Hive"}, 404)
            return

        removed = stamps_list.pop(found)
        if is_owner:
            _save_hives()
        else:
            _save_user_hives()

        # Optional: Hive informieren (best-effort)
        try:
            import urllib.request
            leave_payload = json.dumps({"shinpai_id": leave_sid}).encode("utf-8")
            req = urllib.request.Request(
                f"{hive_url}/api/nexus/leave",
                data=leave_payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass

        nexus_log(f"Hive verlassen", "yellow")
        self._send_json({"ok": True, "left": hive_url})

    # ── Handler: Vault Unlock ─────────────────────────────────────
    def _handle_vault_unlock(self):
        ip = self._client_ip()
        if _auth_locked(ip):
            self._send_json({"error": "Zu viele Fehlversuche — 5min gesperrt"}, 429)
            return
        data = self._parse_json()
        password = data.get("password", "")
        totp_code = data.get("totp_code", "")
        if not password:
            self._send_json({"error": "password erforderlich"}, 400)
            return
        if not vault_unlock(password):
            _auth_fail(ip)
            rem = _AUTH_MAX_FAILS - _auth_fails.get(ip, 0)
            self._send_json({"error": f"Falsches Passwort ({max(0, rem)} Versuche übrig)"}, 403)
            return
        # Identity laden um 2FA-Status zu prüfen
        _load_identity()
        _load_hives()
        _load_friends()
        _load_agents()
        _load_users()
        _load_user_hives()
        # 2FA Prüfung wenn aktiviert
        if _identity and _identity.get("totp_confirmed"):
            if not totp_code:
                # Passwort war richtig, aber 2FA fehlt noch
                vault_lock()  # Vault wieder sperren bis 2FA kommt!
                self._send_json({"totp_required": True, "message": "2FA-Code eingeben"}, 200)
                return
            if not totp_verify(_identity.get("totp_secret", ""), totp_code):
                _auth_fail(ip)
                vault_lock()
                rem = _AUTH_MAX_FAILS - _auth_fails.get(ip, 0)
                self._send_json({"error": f"Falscher 2FA-Code ({max(0, rem)} Versuche übrig)"}, 401)
                return
        _auth_success(ip)
        if _identity:
            _cfg = load_config()
            _ensure_keypair(_cfg)
            save_config(_cfg)
            self.config = _cfg
        self._send_json({"ok": True, "unlocked": True, "totp_active": bool(_identity and _identity.get("totp_confirmed"))})

    # ── Handler: Vault Lock ───────────────────────────────────────
    def _handle_vault_lock(self):
        global _pq_keys, _identity
        vault_lock()
        _pq_keys = None
        _identity = None
        self._send_json({"ok": True, "locked": True})

    # ── Handler: 2FA Setup (Secret + URI generieren) ────────────
    def _handle_2fa_setup(self):
        session = self._require_auth()
        if not session:
            return
        if not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")

        if is_owner:
            target = _identity
            label = f"ShinNexus-{_identity['name']}"
        else:
            target = _users.get(uname)
            if not target:
                self._send_json({"error": "User nicht gefunden"}, 404)
                return
            label = f"ShinNexus-{uname}"

        secret = target.get("totp_secret", "")
        if not secret:
            secret = totp_generate_secret()
            target["totp_secret"] = secret
            target["totp_confirmed"] = False
            if is_owner:
                _save_identity()
            else:
                _save_users()
        uri = totp_get_uri(secret, label)
        qr_data_url = _generate_qr_svg_b64(uri)
        self._send_json({
            "totp_secret": secret,
            "totp_uri": uri,
            "totp_qr": qr_data_url,
            "confirmed": target.get("totp_confirmed", False),
            "message": "QR-Code scannen oder Secret manuell eintragen!",
        })

    # ── Handler: 2FA Confirm (auth-basiert — Owner UND User) ─────────
    def _handle_2fa_confirm(self):
        session = self._require_auth()
        if not session:
            return
        ip = self._client_ip()
        if _auth_locked(ip):
            self._send_json({"error": "Zu viele Fehlversuche — 5min gesperrt"}, 429)
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")
        target = _identity if is_owner else _users.get(uname)
        if not target:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return
        data = self._parse_json()
        code = data.get("code", "").strip()
        if not code:
            self._send_json({"error": "code erforderlich"}, 400)
            return
        secret = target.get("totp_secret", "")
        if not secret:
            self._send_json({"error": "Kein TOTP-Secret vorhanden"}, 400)
            return
        if not totp_verify(secret, code):
            _auth_fail(ip)
            rem = _AUTH_MAX_FAILS - _auth_fails.get(ip, 0)
            self._send_json({"error": f"Falscher Code ({max(0, rem)} Versuche übrig)"}, 401)
            return
        _auth_success(ip)
        target["totp_confirmed"] = True
        if is_owner:
            _save_identity()
        else:
            _save_users()
        nexus_log(f"2FA bestätigt", "green")
        self._send_json({"ok": True, "message": "2FA aktiviert!"})

    # ── Handler: 2FA Verify (auth-basiert — Owner UND User) ────
    def _handle_2fa_verify(self):
        """Für externe Services: Schicke einen TOTP-Code und Nexus prüft."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")
        target = _identity if is_owner else _users.get(uname)
        if not target:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return
        ip = self._client_ip()
        if _auth_locked(ip):
            self._send_json({"error": "Gesperrt"}, 429)
            return
        data = self._parse_json()
        code = data.get("code", "").strip()
        if not code:
            self._send_json({"error": "code erforderlich"}, 400)
            return
        if not target.get("totp_confirmed"):
            self._send_json({"error": "2FA noch nicht aktiviert"}, 400)
            return
        secret = target.get("totp_secret", "")
        if totp_verify(secret, code):
            _auth_success(ip)
            ts = str(int(time.time()))
            nonce = secrets.token_hex(16)
            sign_input = f"2fa-ok:{ts}:{nonce}".encode()
            sig = _sign_data(sign_input)
            self._send_json({
                "verified": True,
                "shinpai_id": sid,
                "signature": sig,
                "timestamp": ts,
                "nonce": nonce,
            })
        else:
            _auth_fail(ip)
            self._send_json({"verified": False}, 401)

    # ── Handler: Tunnel Start ─────────────────────────────────
    def _handle_tunnel_start(self):
        if not _identity:
            self._send_json({"error": "Kein Account"}, 403)
            return
        if _frpc_process and _frpc_process.poll() is None:
            self._send_json({"error": "Tunnel läuft bereits"}, 409)
            return
        ok = start_tunnel(self.config)
        if ok:
            self._send_json({"ok": True, "message": "Tunnel gestartet"})
        else:
            self._send_json({"error": "Tunnel-Start fehlgeschlagen"}, 500)

    # ── Handler: Tunnel Stop ──────────────────────────────────
    def _handle_tunnel_stop(self):
        stop_tunnel()
        self._send_json({"ok": True, "message": "Tunnel gestoppt"})

    # ── Handler: Cloudflare Quick Tunnel ──────────────────────
    def _handle_cloudflare_tunnel(self):
        data = self._parse_json()
        action = data.get("action", "start")
        if action == "start":
            if _cloudflared_process and _cloudflared_process.poll() is None:
                self._send_json({"error": "Tunnel läuft bereits", "url": _public_url}, 409)
                return
            port = self.config.get("port", DEFAULT_PORT)
            ok = start_cloudflare_tunnel(port)
            # Kurz warten damit URL extrahiert werden kann
            for _ in range(20):
                if _public_url:
                    break
                time.sleep(0.5)
            if ok:
                _cfg = load_config()
                _cfg["public_url"] = _public_url
                save_config(_cfg)
                self.config = _cfg
                self._send_json({"ok": True, "url": _public_url})
            else:
                self._send_json({"error": "Tunnel-Start fehlgeschlagen"}, 500)
        elif action == "stop":
            stop_cloudflare_tunnel()
            _cfg = load_config()
            _cfg["public_url"] = ""
            save_config(_cfg)
            self.config = _cfg
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "action: start oder stop"}, 400)

    # ── Handler: Auth Login (3-Stufen: Username → Passwort → 2FA) ──
    def _handle_auth_login(self):
        """Externe Services authentifizieren User über ShinNexus.
        Flow: 1. Username prüfen → 2. Passwort → 3. 2FA → Auth-Session.
        Unterstützt Owner UND registrierte User."""
        if not _identity and not _users:
            self._send_json({"error": "Kein Account"}, 404)
            return
        ip = self._client_ip()
        if _auth_locked(ip):
            self._send_json({"error": "Zu viele Fehlversuche — gesperrt"}, 429)
            return

        data = self._parse_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        totp_code = data.get("totp_code", "")
        source = data.get("source", "unknown")  # z.B. "shinshare:hive.shidow.de"

        # Schritt 1: Username prüfen — Owner ODER registrierter User
        if not username:
            self._send_json({"error": "username erforderlich"}, 400)
            return

        is_owner = _identity and username == _identity["name"]
        is_user = username in _users
        if not is_owner and not is_user:
            _auth_fail(ip)
            rem = _AUTH_MAX_FAILS - _auth_fails.get(ip, 0)
            self._send_json({"error": f"Unbekannter User ({max(0, rem)} Versuche übrig)"}, 401)
            return

        # Migration-Lock: Wenn User bereits nach einem anderen Nexus migriert ist,
        # Login hier sperren (kein Doppel-Account). Owner ist davon ausgenommen.
        if is_user and _users[username].get("migrated_to"):
            target = _users[username]["migrated_to"]
            self._send_json({
                "error": f"Account migriert nach {target}. Login dort."
            }, 410)
            return

        # Shinpai-ID bestimmen
        if is_owner:
            user_shinpai_id = _identity["shinpai_id"]
        else:
            user_data = _users[username]
            user_shinpai_id = user_data["shinpai_id"]

        # Schritt 2: Passwort prüfen
        if not password:
            self._send_json({
                "step": "password",
                "username_ok": True,
                "shinpai_id": user_shinpai_id,
                "message": "Username erkannt. Passwort eingeben.",
            })
            return

        # Passwort-Prüfung: Owner = Vault-Decrypt, User = PBKDF2-Hash
        pw_ok = False
        if is_owner:
            if IDENTITY_VAULT.exists():
                try:
                    vault_unlock(password)
                    vault_decrypt(IDENTITY_VAULT.read_bytes())
                    pw_ok = True
                except Exception:
                    pw_ok = False
        else:
            user_data = _users[username]
            pw_ok = _verify_password(password, user_data.get("password_hash", ""), user_data.get("password_salt", ""))

        if not pw_ok:
            _auth_fail(ip)
            rem = _AUTH_MAX_FAILS - _auth_fails.get(ip, 0)
            self._send_json({"error": f"Falsches Passwort ({max(0, rem)} Versuche übrig)"}, 401)
            return

        # Schritt 3: 2FA prüfen (wenn aktiviert)
        if is_owner:
            totp_confirmed = _identity.get("totp_confirmed", False)
            totp_secret = _identity.get("totp_secret", "")
        else:
            user_data = _users[username]
            totp_confirmed = user_data.get("totp_confirmed", False)
            totp_secret = user_data.get("totp_secret", "")

        if totp_confirmed:
            if not totp_code:
                self._send_json({
                    "step": "2fa",
                    "password_ok": True,
                    "totp_required": True,
                    "message": "Passwort korrekt. 2FA-Code eingeben.",
                })
                return
            if not totp_verify(totp_secret, totp_code):
                _auth_fail(ip)
                rem = _AUTH_MAX_FAILS - _auth_fails.get(ip, 0)
                self._send_json({"error": f"Falscher 2FA-Code ({max(0, rem)} Versuche übrig)"}, 401)
                return

        # ALLES OK → Auth-Session erstellen!
        _auth_success(ip)
        # last_login aktualisieren (3-Jahres-Perso-Cleanup-Schutz)
        _now_login = int(time.time())
        if is_owner:
            if _identity:
                _identity["last_login"] = _now_login
                _save_identity()
            user_override = None
            user_pk = (_pq_keys or {}).get("sig_pk", "")
            user_kem_pk = (_pq_keys or {}).get("kem_pk", "")
        else:
            user_data = _users[username]
            user_data["last_login"] = _now_login
            _save_users()
            user_keys = user_data.get("pq_keys", {})
            user_override = {"shinpai_id": user_shinpai_id, "name": username, "pq_keys": user_keys}
            user_pk = user_keys.get("sig_pk", "")
            user_kem_pk = user_keys.get("kem_pk", "")
        session = _create_auth_session(source, user_override=user_override)
        nexus_log(f"Auth-Login OK von {source}", "green")

        response = {
            "step": "done",
            "authenticated": True,
            "session_token": session["token"],
            "shinpai_id": session["shinpai_id"],
            "name": session["name"],
            "expires": session["expires"],
            "signature": session["signature"],
            "public_key": user_pk,
            "kem_public_key": user_kem_pk,
        }
        # Kneipe-Quellen: TOTP-Secret + Email mitgeben für Pull-Sync!
        # Nexus = Source of Truth. Kneipe zieht beim Login jeweils aktuelle Daten.
        if source.startswith("kneipe:"):
            src = (_identity if is_owner else _users.get(username)) or {}
            totp_s = src.get("totp_secret", "")
            if totp_s:
                response["totp_secret"] = totp_s
            email_s = src.get("email", "")
            if email_s:
                response["email"] = email_s
        self._send_json(response)

    # ── Handler: Password Change (auth-basiert — Owner UND User) ──
    def _handle_password_change(self):
        """POST /api/auth/password — Passwort ändern. Erfordert altes PW + 2FA.
        Body: {old_password, new_password, totp_code}"""
        ip = self._client_ip()
        session = self._require_auth()
        if not session:
            return
        if not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")

        data = self._parse_json()
        old_pw = data.get("old_password", "")
        new_pw = data.get("new_password", "")
        totp_code = data.get("totp_code", "")

        if not old_pw:
            self._send_json({"error": "old_password erforderlich"}, 400)
            return
        if not new_pw:
            self._send_json({"error": "new_password erforderlich"}, 400)
            return
        if len(new_pw) < 6:
            self._send_json({"error": "Min. 6 Zeichen"}, 400)
            return

        # 2FA PFLICHT für PW-Änderung!
        target = _identity if is_owner else _users.get(uname)
        if not target:
            self._send_json({"error": "User nicht gefunden"}, 404)
            return
        if not target.get("totp_confirmed") or not target.get("totp_secret"):
            self._send_json({"error": "2FA muss aktiv sein um Passwort zu ändern!"}, 403)
            return
        if not totp_code:
            self._send_json({"error": "2FA-Code erforderlich"}, 401)
            return
        if not totp_verify(target.get("totp_secret", ""), totp_code):
            self._send_json({"error": "Falscher 2FA-Code"}, 401)
            return

        # Altes Passwort prüfen
        if is_owner:
            if not vault_unlock(old_pw):
                self._send_json({"error": "Altes Passwort falsch"}, 401)
                return
        else:
            if not _verify_password(old_pw, target.get("password_hash", ""), target.get("password_salt", "")):
                self._send_json({"error": "Altes Passwort falsch"}, 401)
                return

        # Neues Passwort setzen
        if is_owner:
            # Owner: ATOMISCH über PQ-Rewrap (nur kem_priv.vault), DEK bleibt
            if _vault_change_password(old_pw, new_pw):
                nexus_log("Owner-Passwort geändert (PQ-Rewrap atomisch)", "green")
                # Igni-Key ebenfalls mit neuem PW aktualisieren (sonst Auto-Unlock tot)
                try:
                    if _VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists():
                        igni_save(new_pw)
                        nexus_log("🔑 Igni-Key mit neuem PW aktualisiert", "cyan")
                except Exception as _ie:
                    nexus_log(f"⚠️ Igni-Update übersprungen: {_ie}", "yellow")
                # Recovery.enc auch neu binden (enthält PW-Klartext verschlüsselt mit Seed-Key)
                # Seed brauchen wir dafür — kommt aus recovery_seed_hash ist nicht rekonstruierbar.
                # User-Recovery-Seed müsste beim nächsten 2FA-Refresh regeneriert werden.
                # TODO: Wenn Seed-Phrase in Payload, auch recovery.enc neu schreiben.
            else:
                self._send_json({"error": "Passwort-Änderung fehlgeschlagen"})
                return
        else:
            # User: Hash aktualisieren
            pw_hash, pw_salt = _hash_password(new_pw)
            target["password_hash"] = pw_hash
            target["password_salt"] = pw_salt
            _save_users()
            nexus_log(f"User-Passwort geändert", "green")

        _auth_success(ip)
        self._send_json({"ok": True, "message": "Passwort geändert!"})

    # ── Handler: Email Get/Change (auth-basiert — Owner UND User) ──
    def _handle_email_get(self):
        """GET /api/auth/email — Aktuelle Email + email_verified Status."""
        session = self._require_auth()
        if not session:
            return
        if not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")
        src = _identity if is_owner else _users.get(uname)
        if not src:
            self._send_json({"error": "User nicht gefunden"}, 404)
            return
        self._send_json({
            "email": src.get("email", ""),
            "email_verified": bool(src.get("email_verified")),
        })

    def _handle_email_change(self):
        """POST /api/auth/email — Email ändern. Erfordert aktuelles PW + 2FA.
        Body: {new_email, password, totp_code}
        Sicherheit: Email ist Recovery-Anker → PW+TOTP schützen gegen Kontodiebstahl.
        Reset: email_verified=False — neue Email muss separat verifiziert werden (scope-next)."""
        ip = self._client_ip()
        session = self._require_auth()
        if not session:
            return
        if not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return
        sid = session.get("shinpai_id", "")
        uname = session.get("name", "")
        is_owner = _identity and sid == _identity.get("shinpai_id")

        data = self._parse_json()
        new_email = (data.get("new_email") or "").strip().lower()
        old_pw = data.get("password", "")
        totp_code = data.get("totp_code", "")

        if not new_email or "@" not in new_email or "." not in new_email:
            self._send_json({"error": "Gültige Email erforderlich"}, 400)
            return

        target = _identity if is_owner else _users.get(uname)
        if not target:
            self._send_json({"error": "User nicht gefunden"}, 404)
            return

        # Reset-Modus: KEIN altes PW / 2FA nötig (Seed war der Beweis)
        in_reset_mode = bool(target.get("pw_reset_pending"))

        if not in_reset_mode:
            if not old_pw:
                self._send_json({"error": "Aktuelles Passwort erforderlich"}, 400)
                return
            # 2FA PFLICHT
            if not target.get("totp_confirmed") or not target.get("totp_secret"):
                self._send_json({"error": "2FA muss aktiv sein um Email zu ändern!"}, 403)
                return
            if not totp_code:
                self._send_json({"error": "2FA-Code erforderlich"}, 401)
                return
            if not totp_verify(target.get("totp_secret", ""), totp_code):
                self._send_json({"error": "Falscher 2FA-Code"}, 401)
                return
            # Aktuelles Passwort prüfen
            if is_owner:
                if not vault_unlock(old_pw):
                    self._send_json({"error": "Passwort falsch"}, 401)
                    return
            else:
                if not _verify_password(old_pw, target.get("password_hash", ""), target.get("password_salt", "")):
                    self._send_json({"error": "Passwort falsch"}, 401)
                    return

        # Nichts zu tun wenn identisch
        if target.get("email", "").lower() == new_email:
            self._send_json({"ok": True, "email": new_email, "message": "Email unverändert."})
            return

        # Email setzen + email_verified resetten (neue Adresse muss verifiziert werden)
        old_email = target.get("email", "")
        target["email"] = new_email
        target["email_verified"] = False
        # Reset-Modus beenden — Email-Änderung zählt als gültige Aktion
        if in_reset_mode:
            if is_owner:
                _owner_clear_reset_flags()
            else:
                target["pw_reset_pending"] = False
                target.pop("pw_reset_triggered_at", None)
                nexus_log("🟢 Reset-Modus deaktiviert via Email-Change", "green")

        if is_owner:
            cfg = load_config()
            cfg["email"] = new_email
            _save_identity()
            save_config(cfg)
            self.config = cfg  # Snapshot aktualisieren
            # DSGVO: Emails NICHT im Log — nur Shinpai-ID
            nexus_log(f"Owner-Email geändert ({_identity.get('shinpai_id','?')})", "green")
        else:
            _save_users()
            nexus_log(f"User-Email geändert ({uname})", "green")

        _auth_success(ip)
        self._send_json({
            "ok": True,
            "email": new_email,
            "email_verified": False,
            "message": "Email geändert. Verifizierungs-Code wird gesendet.",
        })

    # ── Handler: User Registration ──────────────────────────────
    _register_counts: dict = {}  # {ip: {"count": int, "window_start": float}}

    def _handle_auth_register(self):
        """POST /api/auth/register — Neue User registrieren.

        Standard Web-Flow (2 Requests):
          Step 1: {username, email, password}               → Account angelegt, TOTP-Secret zurück
          Step 2: {username, totp_code}                     → 2FA bestätigen, Account aktiv

        Extern-Flow (Kneipe/Link, 1 Request):
          Combined: {username, email, password, totp_secret, totp_code}
                 → Account anlegen + direkt mit übergebenem TOTP-Secret bestätigen

        TOTP ist PFLICHT — Account wird erst aktiv wenn totp_confirmed=True.
        """
        # Kein Owner? → Erster Account wird automatisch Owner! (Kneipe-Provisioning!)
        global _identity, _pq_keys
        auto_owner = _identity is None
        if not auto_owner and not vault_is_unlocked():
            self._send_json({"error": "Nexus gerade gebootet! Owner muss erst freigeben!"}, 503)
            return

        # User-Limit: Max 200 pro Nexus (DSGVO-konform!)
        confirmed_users = sum(1 for u in _users.values() if u.get("totp_confirmed"))
        if confirmed_users >= 200:
            self._send_json({"error": "Maximale Nutzerzahl erreicht (200). Kontaktiere den Betreiber."}, 403)
            return

        ip = self._client_ip()
        # Rate-Limit: 5 Registrierungen pro Stunde pro IP
        now = time.time()
        rc = self._register_counts.get(ip, {"count": 0, "window_start": now})
        if now - rc["window_start"] > 3600:
            rc = {"count": 0, "window_start": now}
        if rc["count"] >= 5:
            self._send_json({"error": "Zu viele Registrierungen — 1h warten"}, 429)
            return

        data = self._parse_json()
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        totp_code = data.get("totp_code", "")

        if not username:
            self._send_json({"error": "username erforderlich"}, 400)
            return

        # Step 2 STANDALONE: nur totp_code ohne email/password → existing User bestätigt 2FA
        # (Bei Combined-Flow mit email+password wird totp_code weiter unten in Step 1 verarbeitet!)
        if totp_code and not (email and password):
            # Owner-Confirm?
            if _identity and _identity.get("name") == username and not _identity.get("totp_confirmed"):
                if totp_verify(_identity.get("totp_secret", ""), totp_code):
                    _identity["totp_confirmed"] = True
                    _save_identity()
                    nexus_log("Owner 2FA bestätigt", "green")
                    session = _create_auth_session("owner_claim")
                    token = session.get("token", "") if isinstance(session, dict) else ""
                    self._send_json({
                        "step": "done",
                        "message": "Owner erstellt + 2FA aktiv!",
                        "shinpai_id": _identity["shinpai_id"],
                        "session_token": token,
                    })
                else:
                    self._send_json({"error": "Falscher 2FA-Code"}, 401)
                return

            # User-Confirm?
            if username in _users:
                user_data = _users[username]
                if user_data.get("totp_confirmed"):
                    self._send_json({"error": "Account bereits aktiv"}, 409)
                    return
                if totp_verify(user_data.get("totp_secret", ""), totp_code):
                    user_data["totp_confirmed"] = True
                    _save_users()
                    nexus_log("User 2FA bestätigt", "green")
                    self._send_json({
                        "step": "done",
                        "message": "2FA bestätigt! Account aktiv.",
                        "shinpai_id": user_data["shinpai_id"],
                    })
                else:
                    self._send_json({"error": "Falscher 2FA-Code"}, 401)
                return

            self._send_json({"error": "Account nicht gefunden"}, 404)
            return

        # Step 1: Account erstellen
        if not email or not password:
            self._send_json({"error": "username, email und password erforderlich"}, 400)
            return

        # Username-Validierung
        name_err = validate_username(username)
        if name_err:
            self._send_json({"error": name_err}, 400)
            return

        # Duplikat-Check: Owner
        if _identity and username == _identity["name"]:
            self._send_json({"error": "Username bereits vergeben"}, 409)
            return

        # Duplikat-Check: Bestehende User
        if username in _users:
            if _users[username].get("totp_confirmed"):
                self._send_json({"error": "Username bereits vergeben"}, 409)
                return
            # Unbestätigter Account → überschreiben (neuer Versuch)

        # Shinpai-ID generieren
        shinpai_id = _generate_shinpai_id(username, email)

        # Duplikat-Check: Gleiche Shinpai-ID (gleiche Name+Email Kombi)
        for uname, udata in _users.items():
            if udata["shinpai_id"] == shinpai_id and uname != username:
                self._send_json({"error": "Diese Name/Email-Kombination existiert bereits"}, 409)
                return
        if _identity and _identity["shinpai_id"] == shinpai_id:
            self._send_json({"error": "Diese Name/Email-Kombination existiert bereits"}, 409)
            return

        # Passwort hashen
        pw_hash, pw_salt = _hash_password(password)

        # TOTP: Extern (von Kneipe) oder neu generieren
        external_totp = data.get("totp_secret", "")
        totp_secret = external_totp if external_totp else totp_generate_secret()
        totp_uri = totp_get_uri(totp_secret, f"ShinNexus-{username}")

        # Recovery-Seed (24 Wörter — gleich wie beim Owner!)
        recovery_seed = _generate_recovery_seed()
        recovery_seed_hash = hashlib.sha256(recovery_seed.encode()).hexdigest()

        # PQ-Keypair (ML-DSA-65 + ML-KEM-768 — gleich wie beim Owner!)
        pq_keys = _generate_user_keypair()

        if auto_owner:
            # ERSTER ACCOUNT → OWNER! Vault + Identity erstellen!
            vault_unlock(password)
            _identity = {
                "name": username,
                "email": email,
                "shinpai_id": shinpai_id,
                "totp_secret": totp_secret,
                "totp_confirmed": False,
                "email_verified": bool(data.get("email_verified")),
                "recovery_seed_hash": recovery_seed_hash,
                "pq_keys": pq_keys,
                "created": int(time.time()),
            }
            _pq_keys = pq_keys
            _save_identity()
            _save_recovery_data(password, recovery_seed)
            # PQ-Seed-Backup: ML-KEM-Private auch mit Seed-Key verschlüsseln
            try:
                _owner_kem_sk = _pq_get_kem_sk_via_password(password)
                if _owner_kem_sk:
                    _pq_write_seed_backup_with_sk(recovery_seed, _owner_kem_sk)
                    nexus_log("🌿 PQ-Seed-Backup geschrieben (Owner)", "cyan")
            except Exception as _e:
                nexus_log(f"⚠️ PQ-Seed-Backup übersprungen: {_e}", "yellow")
            # Config updaten — SMTP + Domain aus Kneipe übernehmen!
            cfg = load_config()
            cfg["name"] = username
            cfg["email"] = email
            cfg["shinpai_id"] = shinpai_id
            cfg["shinpai_name_hash"] = shinpai_id.split("-")[0]
            cfg["mode"] = "server"
            cfg["domain"] = data.get("domain", cfg.get("domain", ""))
            cfg["public_url"] = data.get("public_url", cfg.get("public_url", ""))
            # SMTP übernehmen wenn mitgeschickt
            if data.get("smtp"):
                cfg["smtp"] = data["smtp"]
            save_config(cfg)
            # Igni erstellen — nur wenn owner_vault_mode=standard (Default)
            _igni_init(cfg)
            if cfg.get("owner_vault_mode", "standard") == "standard":
                igni_save(password)
            # System Vault (machine-bound composite)
            system_vault_init(cfg, owner_password=password)
            # Platzhalter jetzt verwerfen — echter Owner übernimmt
            _placeholder_dismiss()
            nexus_log(f"👑 AUTO-OWNER CREATED via API", "green")
        else:
            # Normaler User
            _users[username] = {
                "name": username,
                "email": email,
                "shinpai_id": shinpai_id,
                "password_hash": pw_hash,
                "password_salt": pw_salt,
                "totp_secret": totp_secret,
                "totp_confirmed": False,
                "recovery_seed_hash": recovery_seed_hash,
                "pq_keys": pq_keys,
                "created": int(time.time()),
            }
            _save_users()

        rc["count"] += 1
        self._register_counts[ip] = rc

        role = "👑 Owner" if auto_owner else "User"
        nexus_log(f"{role} registriert (2FA pending)", "cyan")

        # Externer TOTP + Code? → Direkt bestätigen (Kneipe-Durchreichung!)
        if external_totp and totp_code and totp_verify(totp_secret, totp_code):
            if auto_owner:
                _identity["totp_confirmed"] = True
                _save_identity()
            else:
                _users[username]["totp_confirmed"] = True
                _save_users()
            nexus_log(f"{role} direkt bestätigt (extern)", "green")
            self._send_json({
                "step": "done",
                "shinpai_id": shinpai_id,
                "recovery_seed": recovery_seed,
                "message": "Nexus-Account erstellt und bestätigt!",
            }, 201)
            return

        # QR-Code für Authenticator-App
        qr_data_url = _generate_qr_svg_b64(totp_uri)

        self._send_json({
            "step": "2fa_setup",
            "shinpai_id": shinpai_id,
            "totp_secret": totp_secret,
            "totp_uri": totp_uri,
            "totp_qr": qr_data_url,
            "recovery_seed": recovery_seed,
            "public_key": pq_keys["sig_pk"],
            "kem_public_key": pq_keys["kem_pk"],
            "message": "Account erstellt! Recovery-Seed JETZT aufschreiben! Dann 2FA-Code eingeben.",
        }, 201)

    # ── Handler: Session prüfen ───────────────────────────────
    def _handle_auth_session(self):
        """Prüft ob ein Auth-Token gültig ist (für externe Services)."""
        data = self._parse_json()
        token = data.get("token", "")
        if not token:
            self._send_json({"error": "token erforderlich"}, 400)
            return
        session = validate_auth_session(token)
        if session:
            self._send_json({
                "valid": True,
                "shinpai_id": session["shinpai_id"],
                "name": session["name"],
                "expires": session["expires"],
            })
        else:
            self._send_json({"valid": False}, 401)

    # ── Handler: Verify Owner (öffentlich, rate-limited) ─────
    _verify_owner_counts: dict = {}  # {ip: {"count": int, "window_start": float}}

    def _handle_verify_owner(self):
        """POST /api/auth/verify-owner — Prüft ob ein User mit gegebener Shinpai-ID existiert.

        Öffentlicher Endpoint für Hive-Autoregistration (ShinShare ruft das auf).
        Rate-Limit: 10/min/IP gegen Enumeration.

        Body: {"shinpai_id": "vJkehN-BzEeB8"}
        Response: {"exists": true, "name": "shinpai"} oder {"exists": false}
        """
        # Rate-Limit: 10/min/IP
        ip = self._client_ip()
        now = time.time()
        entry = self._verify_owner_counts.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] >= 60:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 10:
            self._send_json({"error": "Rate limit — max 10/min"}, 429)
            return
        entry["count"] += 1
        self._verify_owner_counts[ip] = entry

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        sid = data.get("shinpai_id", "").strip()
        if not sid:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        # Identity-Check: Owner?
        if _identity and _identity.get("shinpai_id") == sid:
            self._send_json({"exists": True, "name": _identity.get("name", "")})
            return
        # Registrierte User?
        for uname, udata in _users.items():
            if udata.get("shinpai_id") == sid and udata.get("totp_confirmed"):
                self._send_json({"exists": True, "name": udata.get("name", uname)})
                return
        self._send_json({"exists": False})

    # ── Handler: Verify Entity (öffentlich, rate-limited) ──────
    _verify_entity_counts: dict = {}  # {ip: {"count": int, "window_start": float}}

    def _handle_verify_entity(self):
        """POST /api/auth/verify-entity — Universelle Entity-Prüfung.

        Öffentlich, rate-limited. Prüft ob Shinpai-ID existiert und gibt Typ zurück.
        Minimale Info: exists + type + owner_id. KEIN Name, KEINE Details!

        Body: {"shinpai_id": "ABC-DEF"}
        Response: {"exists": true, "type": "user|bot|phoenix", "owner_shinpai_id": "..."}
        """
        ip = self._client_ip()
        now = time.time()
        entry = self._verify_entity_counts.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] >= 60:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 10:
            self._send_json({"error": "Rate limit — max 10/min"}, 429)
            return
        entry["count"] += 1
        self._verify_entity_counts[ip] = entry

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        sid = data.get("shinpai_id", "").strip()
        if not sid:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return

        # 1. Check: Ist es der Owner/User selbst?
        if _identity and _identity.get("shinpai_id") == sid:
            self._send_json({"exists": True, "type": "user", "owner_shinpai_id": None})
            return

        # 2. Check: Ist es ein registrierter User?
        for uname, udata in _users.items():
            if udata.get("shinpai_id") == sid and udata.get("totp_confirmed"):
                self._send_json({"exists": True, "type": "user", "owner_shinpai_id": None})
                return

        # 3. Check: Ist es ein registrierter Agent?
        agent = _find_agent(sid)
        if agent:
            self._send_json({
                "exists": True,
                "type": agent.get("type", "bot"),
                "owner_shinpai_id": agent.get("owner_shinpai_id"),
            })
            return

        # 4. Nicht gefunden
        self._send_json({"exists": False})

    # ── Handler: Firemail ─────────────────────────────────
    def _handle_firemail_send(self):
        """POST /api/firemail/send — Firemail erstellen (Auth nötig!)."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        text = data.get("text", "").strip()
        ttl = data.get("ttl", "24h")
        max_reads = int(data.get("max_reads", 1))
        if max_reads < 0 or max_reads > 1000:
            max_reads = 1
        result = firemail_create(session["shinpai_id"], session["name"], text, ttl, max_reads)
        if result.get("ok"):
            cfg = load_config()
            nexus_url = cfg.get('public_url', '').rstrip('/') or f"https://{cfg.get('domain', 'localhost')}:{cfg.get('port', 12345)}"
            result["read_url"] = f"{nexus_url}/api/firemail/read/{result['firemail_id']}"
        self._send_json(result)

    def _handle_firemail_read(self, firemail_id: str):
        """GET /api/firemail/read/ID — Firemail lesen (öffentlich, rate-limited)."""
        ip = self._client_ip()
        result = firemail_read(firemail_id)
        if result.get("ok"):
            # Schöne HTML-Seite statt JSON
            fm = result
            burned_html = '<div style="color:#e55;font-size:14px;margin-top:15px;">🔥 Diese Nachricht wurde verbrannt und ist nicht mehr abrufbar.</div>' if fm.get("burned") else ''
            remaining = fm.get("remaining_seconds", 0)
            if remaining > 86400:
                time_str = f"{remaining // 86400} Tage"
            elif remaining > 3600:
                time_str = f"{remaining // 3600}h {(remaining % 3600) // 60}min"
            elif remaining > 60:
                time_str = f"{remaining // 60}min"
            else:
                time_str = f"{remaining}s"
            html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>🔥 Firemail — ShinNexus</title></head><body style="margin:0;background:#0a0a0a;color:#e0d8c8;font-family:Georgia,serif;">
            <div style="max-width:520px;margin:40px auto;padding:30px;">
              <div style="text-align:center;margin-bottom:25px;">
                <div style="font-size:48px;">🔥</div>
                <h1 style="color:#e08040;margin:5px 0;font-size:22px;">Firemail</h1>
                <div style="color:#556677;font-size:11px;letter-spacing:2px;">VERIFIZIERT · VERSCHLÜSSELT · VERGÄNGLICH</div>
              </div>
              <div style="background:#0d1117;border:1px solid #2a1a0a;border-radius:10px;padding:20px;margin-bottom:15px;">
                <div style="font-size:12px;color:#887755;margin-bottom:5px;">Von: <strong style="color:#e08040;">{fm['sender_name']}</strong></div>
                <div style="font-size:10px;color:#556677;margin-bottom:15px;">Shinpai-ID: <code style="color:#7ab8e0;">{fm['sender_id']}</code></div>
                <div style="font-size:15px;color:#e0d8c8;line-height:1.6;white-space:pre-wrap;">{fm['text']}</div>
              </div>
              <div style="background:#0d1117;border-left:3px solid #e08040;padding:12px;border-radius:0 8px 8px 0;margin-bottom:15px;">
                <div style="font-size:11px;color:#887755;">
                  ⏱️ Verbleibend: <strong style="color:#e08040;">{time_str}</strong> ·
                  📖 Gelesen: {fm['read_count']}/{fm['max_reads'] if fm['max_reads'] > 0 else '∞'} ·
                  {'✅ PQ-Signiert' if fm['verified'] else '⚠️ Unsigniert'}
                </div>
              </div>
              <div style="font-size:9px;color:#334455;margin-bottom:5px;">Hash: <code>{fm['hash'][:32]}...</code></div>
              {burned_html}
              <hr style="border:none;border-top:1px solid #1a1a1a;margin:20px 0;">
              <div style="text-align:center;font-size:11px;color:#334455;">
                ShinNexus — Same Knowledge. Your Ownership. 🐉
              </div>
            </div></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        else:
            # Verbrannt oder nicht gefunden → Feuer-Seite
            html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>🔥 Verbrannt — ShinNexus</title></head><body style="margin:0;background:#0a0a0a;color:#e0d8c8;font-family:Georgia,serif;">
            <div style="max-width:400px;margin:80px auto;text-align:center;padding:30px;">
              <div style="font-size:64px;">🔥</div>
              <h1 style="color:#e08040;font-size:20px;">Verbrannt</h1>
              <p style="color:#887755;font-size:14px;">{result.get('error', 'Diese Firemail existiert nicht mehr.')}</p>
              <p style="color:#334455;font-size:11px;margin-top:30px;">ShinNexus — Ist einfach passiert. 🐉</p>
            </div></body></html>"""
            self.send_response(410)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

    def _handle_firemail_verify(self):
        """POST /api/firemail/verify — Firemail-Hash prüfen."""
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        fid = data.get("firemail_id", "")
        content_hash = data.get("hash", "")
        self._send_json(firemail_verify(fid, content_hash))

    # ── Handler: SMTP Config (Owner-only) ─────
    def _handle_smtp_config(self):
        """POST /api/smtp/config — SMTP konfigurieren (nur Owner, nur localhost)."""
        if not self._is_localhost():
            session = self._require_auth()
            if not session:
                return
            if not _identity or session["shinpai_id"] != _identity.get("shinpai_id"):
                self._send_json({"error": "Nur Owner"}, 403)
                return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        cfg = load_config()
        cfg["smtp"] = {
            "host": data.get("host", "").strip(),
            "port": int(data.get("port", 587)),
            "user": data.get("user", "").strip(),
            "password": data.get("password", ""),
            "from": data.get("from", "").strip() or data.get("user", "").strip(),
        }
        save_config(cfg)
        NexusHandler.config = cfg  # Class-Config synchron halten!
        nexus_log(f"📧 SMTP konfiguriert: {cfg['smtp']['host']}", "green")
        # Test-Mail?
        test_to = data.get("test_email", "").strip()
        if test_to:
            ok = send_nexus_email(test_to, "🛡️ ShinNexus SMTP Test", "<div style='background:#0a0a0a;color:#7ab8e0;padding:30px;font-family:Georgia;text-align:center;'><h2>SMTP funktioniert! 🛡️</h2><p style='color:#998870;'>Same Knowledge. Your Ownership.</p></div>", cfg)
            self._send_json({"ok": True, "test_sent": ok, "message": f"SMTP gespeichert! Test-Mail an {test_to}: {'✅' if ok else '❌'}"})
        else:
            self._send_json({"ok": True, "message": "SMTP gespeichert!"})

    # ── Handler: Send Verify Email (Owner/Auth) ─────
    # Rate-Limit: 3 Verify-Mails pro 24h pro Shinpai-ID
    _verify_mail_counts: dict = {}  # {shinpai_id: {"count": int, "window_start": float}}
    _VERIFY_MAIL_MAX = 3
    _VERIFY_MAIL_WINDOW = 86400  # 24h

    def _handle_send_verify_email(self):
        """POST /api/email/send-verify — Verifizierungs-Mail senden. Max 3/Tag."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json() or {}
        target_email = data.get("email", "").strip()
        sid = session["shinpai_id"]
        name = session["name"]
        # Email aus Identity/User holen falls nicht angegeben
        if not target_email:
            if _identity and _identity.get("shinpai_id") == sid:
                target_email = _identity.get("email", "")
            else:
                for uname, udata in _users.items():
                    if udata.get("shinpai_id") == sid:
                        target_email = udata.get("email", "")
                        break
        if not target_email:
            self._send_json({"error": "Keine Email hinterlegt!"}, 400)
            return

        # Rate-Limit-Check: 3/Tag pro Identität
        now = time.time()
        entry = self._verify_mail_counts.get(sid, {"count": 0, "window_start": now})
        if now - entry["window_start"] >= self._VERIFY_MAIL_WINDOW:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= self._VERIFY_MAIL_MAX:
            rest_h = int((self._VERIFY_MAIL_WINDOW - (now - entry["window_start"])) / 3600) + 1
            self._send_json({
                "error": f"Limit erreicht ({self._VERIFY_MAIL_MAX}/Tag). Nächster Versuch in ~{rest_h}h.",
                "rate_limited": True,
                "retry_in_hours": rest_h,
            }, 429)
            return

        # Code generieren + im User-Record speichern (persistent, ueberlebt Restart)
        code = generate_verify_code()
        code_expires = now + VERIFY_CODE_TTL
        if _identity and _identity.get("shinpai_id") == sid:
            _identity["verify_token"] = code
            _identity["verify_expires"] = code_expires
            _identity["email"] = target_email  # falls Email gerade geaendert wurde
            _save_identity()
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    udata["verify_token"] = code
                    udata["verify_expires"] = code_expires
                    udata["email"] = target_email
                    _save_users()
                    break

        cfg = load_config()
        # SMTP konfiguriert? Sonst Dev-Fallback: Code direkt im Response (DAU-safe,
        # kein "Mail verschickt aber kam nie an"-Drama).
        if not smtp_configured(cfg):
            entry["count"] += 1
            self._verify_mail_counts[sid] = entry
            remaining = self._VERIFY_MAIL_MAX - entry["count"]
            self._send_json({
                "ok": True,
                "dev_mode": True,
                "verify_code": code,
                "message": f"SMTP nicht konfiguriert — Code direkt: {code} (10 Min gueltig)",
                "remaining_today": remaining,
            })
            return
        ok = send_verify_email(target_email, name, sid, code, cfg=cfg)
        if ok:
            entry["count"] += 1
            self._verify_mail_counts[sid] = entry
            remaining = self._VERIFY_MAIL_MAX - entry["count"]
            self._send_json({
                "ok": True,
                "message": f"Code an {target_email} gesendet! ({remaining}/{self._VERIFY_MAIL_MAX} heute uebrig)",
                "remaining_today": remaining,
            })
        else:
            self._send_json({"error": "Mail konnte nicht gesendet werden! SMTP pruefen!"})

    # ── Handler: Attest-Link (Account-Anbindung für externe Services) ─────
    _attest_link_counts: dict = {}

    def _handle_attest_link(self):
        """POST /api/auth/attest-link — Attestiert Identity für externen Service.

        Braucht aktive Auth-Session! Beweist: "Ja, ich bin dieser Shinpai-ID-Inhaber
        und erlaube Service X sich mit mir zu verbinden."

        Body: {"service_url": "https://bar.shinpai.de", "service_name": "Kneipen-Schlaegerei", "nonce": "random_hex"}
        Response: {"attested": true, "shinpai_id": "...", "name": "...", "signature": "...", "public_key": "...", "timestamp": ...}
        """
        # Rate-Limit: 5/min
        ip = self._client_ip()
        now = time.time()
        entry = self._attest_link_counts.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] >= 60:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 5:
            self._send_json({"error": "Rate limit — max 5/min"}, 429)
            return
        entry["count"] += 1
        self._attest_link_counts[ip] = entry

        # Auth prüfen
        session = self._require_auth()
        if not session:
            return

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        service_url = data.get("service_url", "").strip()
        service_name = data.get("service_name", "").strip()
        nonce = data.get("nonce", "").strip()

        if not service_url or not nonce:
            self._send_json({"error": "service_url und nonce erforderlich"}, 400)
            return

        sid = session["shinpai_id"]
        ts = int(time.time())

        # Attestation signieren
        sign_input = f"attest:{ts}:{nonce}:{sid}:{service_url}".encode()
        try:
            signature = _sign_data(sign_input)
        except Exception as e:
            self._send_json({"error": f"Signatur fehlgeschlagen: {e}"}, 500)
            return

        nexus_log(f"Attest-Link: {sid} → {service_name} ({service_url})", "cyan")

        self._send_json({
            "attested": True,
            "shinpai_id": sid,
            "name": session["name"],
            "signature": signature,
            "public_key": _pq_keys.get("sig_pk", "") if _pq_keys else "",
            "timestamp": ts,
            "nonce": nonce,
            "service_url": service_url,
        })

    # ── Handler: Migrate (Account-Migration zwischen Nexus-Instanzen) ────
    _migrate_counts: dict = {}

    def _handle_migrate(self):
        """POST /api/auth/migrate — Exportiert Identity-Daten für Migration.

        Braucht aktive Auth-Session! Gibt verschlüsselte Identity-Daten zurück
        die auf einem anderen Nexus importiert werden können.

        Body: {"target_nexus_url": "https://new-nexus.example.com"}
        Response: {"ok": true, "migration_token": "...", "shinpai_id": "...", "expires": ...}
        """
        ip = self._client_ip()
        now = time.time()
        entry = self._migrate_counts.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] >= 60:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 3:
            self._send_json({"error": "Rate limit — max 3/min"}, 429)
            return
        entry["count"] += 1
        self._migrate_counts[ip] = entry

        session = self._require_auth()
        if not session:
            return

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        target_url = data.get("target_nexus_url", "").strip()
        sid = session["shinpai_id"]
        name = session["name"]
        ts = int(time.time())

        # Migration-Token: Signierter Beweis dass dieser User von DIESEM Nexus migriert
        sign_input = f"migrate:{ts}:{sid}:{name}:{target_url}".encode()
        try:
            signature = _sign_data(sign_input)
        except Exception as e:
            self._send_json({"error": f"Signatur fehlgeschlagen: {e}"}, 500)
            return

        migration_token = secrets.token_hex(32)
        expires = ts + 3600  # 1 Stunde gültig

        nexus_log(f"Migration: {name} ({sid}) → {target_url or 'unbestimmt'}", "yellow")

        self._send_json({
            "ok": True,
            "migration_token": migration_token,
            "shinpai_id": sid,
            "name": name,
            "source_nexus": _identity.get("name", "?") if _identity else "?",
            "signature": signature,
            "public_key": _pq_keys.get("sig_pk", "") if _pq_keys else "",
            "timestamp": ts,
            "expires": expires,
        })

    # ── Handler: Agent Create (Owner-Auth PFLICHT!) ─────────
    def _handle_agent_create(self):
        """POST /api/agent/create — Neuen Agent (Bot) registrieren.

        NUR für eingeloggten Owner! Erstellt Shinpai-ID + Service-Token.

        Body: {"name": "Ray"}
        Response: {"ok": true, "shinpai_id": "...", "service_token": "...", "public_key": "..."}
        """
        session = self._require_auth()
        if not session:
            return

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        name = (data.get("name") or "").strip()[:32]
        if not name:
            self._send_json({"error": "name erforderlich"}, 400)
            return

        # Max 20 Agents pro Owner
        if len(_agents) >= 20:
            self._send_json({"error": "Maximum 20 Agents erreicht"}, 400)
            return

        # Agent-Shinpai-ID generieren
        agent_sid = _generate_agent_shinpai_id(name)

        # PQ-Keypair für den Agent generieren
        try:
            sig = oqs.Signature("ML-DSA-65")
            sig_pk = sig.generate_keypair()
            sig_sk = sig.export_secret_key()
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            kem_pk = kem.generate_keypair()
            kem_sk = kem.export_secret_key()
        except Exception as e:
            self._send_json({"error": f"Keypair-Generierung fehlgeschlagen: {e}"}, 500)
            return

        # Service-Token generieren (kryptographisch stark, langlebig)
        service_token = secrets.token_hex(48)  # 96 Zeichen

        agent_entry = {
            "shinpai_id": agent_sid,
            "name": name,
            "type": "bot",
            "service_token": hashlib.sha256(service_token.encode()).hexdigest(),  # Nur Hash speichern!
            "owner_shinpai_id": session["shinpai_id"],
            "public_key": sig_pk.hex(),
            "kem_public_key": kem_pk.hex(),
            "sig_secret_key": sig_sk.hex(),   # Verschlüsselt im Vault!
            "kem_secret_key": kem_sk.hex(),   # Verschlüsselt im Vault!
            "created": int(time.time()),
            "last_seen": 0,
        }

        _agents.append(agent_entry)
        _save_agents()

        nexus_log(f"Agent erstellt: {name} ({agent_sid}) für {session['name']}", "green")

        self._send_json({
            "ok": True,
            "shinpai_id": agent_sid,
            "name": name,
            "type": "bot",
            "service_token": service_token,  # Klartext NUR EINMAL zurückgeben!
            "public_key": sig_pk.hex(),
            "kem_public_key": kem_pk.hex(),
            "sig_secret_key": sig_sk.hex(),  # Agent braucht seinen Secret Key!
            "kem_secret_key": kem_sk.hex(),
            "owner_shinpai_id": session["shinpai_id"],
        })

    # ── Handler: Agent Delete (Owner-Auth PFLICHT!) ─────────
    def _handle_agent_delete(self):
        """POST /api/agent/delete — Agent löschen.

        NUR für eingeloggten Owner!

        Body: {"shinpai_id": "ABC-DEF"}
        """
        session = self._require_auth()
        if not session:
            return

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        sid = data.get("shinpai_id", "").strip()
        if not sid:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return

        agent = _find_agent(sid)
        if not agent:
            self._send_json({"error": "Agent nicht gefunden"}, 404)
            return

        # Nur der Owner darf löschen
        if agent.get("owner_shinpai_id") != session["shinpai_id"]:
            self._send_json({"error": "Nicht dein Agent"}, 403)
            return

        _agents.remove(agent)
        _save_agents()

        nexus_log(f"Agent gelöscht: {agent['name']} ({sid})", "yellow")
        self._send_json({"ok": True, "deleted": sid})

    # ── Handler: 2FA Refresh (Email + 10min Timer, 3 Fenster/7d) ───────────
    # Pro Shinpai-ID: Liste der Fenster-Timestamps (für 3/7d Limit) + aktuelles Pending
    _2fa_refresh_windows: dict = {}   # {sid: {attempts: [ts, ts, ...], current_pending: {...} | None}}
    _2fa_pending: dict = {}           # {sid: {new_secret, new_seed, expires, username, is_owner}} — aktives 10min-Fenster
    _2FA_WINDOW_TTL = 600             # 10 Minuten Code-Eingabe-Fenster
    _2FA_MAX_WINDOWS_PER_7D = 3       # max 3 Fenster pro 7 Tage

    def _handle_2fa_refresh(self):
        """POST /api/auth/2fa-refresh — Neues 2FA-Secret + neuer Recovery-Seed per Email.
        Wird erst bei Code-Confirmation aktiviert (Troll-Schutz).
        Limits: 3 Fenster/7d pro Account, jedes Fenster 10min Code-Zeit.
        Vage Meldung nach Verbrauch — keine Timer-Angabe (Chaoten sollen nicht timen können).
        """
        session = self._require_auth()
        if not session:
            return
        sid = session["shinpai_id"]
        uname = session["name"]
        is_owner = _identity and sid == _identity.get("shinpai_id")

        # Fenster-Buchhaltung
        now = time.time()
        wins = self._2fa_refresh_windows.setdefault(sid, {"attempts": [], "current_pending": None})
        # Alte Einträge (> 7 Tage) vergessen
        wins["attempts"] = [t for t in wins["attempts"] if now - t < 7 * 86400]
        if len(wins["attempts"]) >= self._2FA_MAX_WINDOWS_PER_7D:
            # Vage Meldung — keine Zeit, keine Details (gegen Timing-Spiele)
            self._send_json({
                "error": "2FA bereits in den letzten 7 Tagen benutzt. Bitte gedulden Sie sich oder prüfen Ihre Mails ordnungsgemäß.",
            }, 429)
            return

        # Email holen + verifiziert sein (unverified = keine 2FA-Änderung)
        if is_owner:
            email = (_identity or {}).get("email", "")
            email_verified = bool((_identity or {}).get("email_verified"))
            target = _identity
        else:
            target = _users.get(uname, {})
            email = target.get("email", "")
            email_verified = bool(target.get("email_verified"))
        if not email:
            self._send_json({"error": "Keine Email hinterlegt!"}, 400)
            return
        if not email_verified:
            self._send_json({"error": "Email muss verifiziert sein um 2FA zu erneuern!"}, 403)
            return

        # Nur neuer TOTP-Secret (Seed bleibt unberührt — Seed-Refresh ist eigener Endpoint!)
        new_secret = totp_generate_secret()
        new_uri = totp_get_uri(new_secret, f"ShinNexus-{uname}")

        # Altes Pending durch neues ersetzen (falls existent → vorheriges Fenster verfällt)
        self._2fa_pending[sid] = {
            "new_secret": new_secret,
            "expires": now + self._2FA_WINDOW_TTL,
            "username": uname,
            "is_owner": bool(is_owner),
        }
        wins["attempts"].append(now)
        wins["current_pending"] = self._2fa_pending[sid]

        qr_svg = _generate_qr_svg_b64(new_uri)
        cfg = load_config()
        html = f"""
        <div style="background:#0a0a0a;color:#e0d8c8;font-family:Georgia,serif;padding:30px;max-width:520px;margin:0 auto;">
          <div style="text-align:center;">
            <div style="font-size:36px;">🔐</div>
            <h1 style="color:#e08040;font-size:20px;">2FA-Erneuerung</h1>
            <p style="color:#887755;">Hallo {uname},</p>
            <p style="color:#998870;font-size:13px;">Scanne den QR-Code mit einer neuen Authenticator-App und bestätige den Code in ShinNexus.</p>
            <div style="margin:20px 0;background:#fff;padding:10px;border-radius:8px;display:inline-block;">
              <img src="{qr_svg}" style="max-width:200px;">
            </div>
            <div style="background:#111;padding:10px;border-radius:6px;margin:15px 0;">
              <div style="font-size:10px;color:#556677;">Manueller Key:</div>
              <code style="color:#7ab8e0;font-size:13px;letter-spacing:2px;">{new_secret}</code>
            </div>
            <div style="background:#1a0a0a;border:1px solid rgba(228,68,68,0.5);border-radius:8px;padding:12px;margin:15px 0;">
              <p style="color:#e55;font-size:13px;font-weight:bold;margin:0;">⏱️ 10 Minuten zum Bestätigen</p>
              <p style="color:#998870;font-size:11px;margin:6px 0 0;">Nach Ablauf verfällt dieser QR. Der alte 2FA-Code bleibt dann aktiv.</p>
            </div>
            <hr style="border:none;border-top:1px solid #1a1a1a;margin:20px 0;">
            <p style="color:#334455;font-size:10px;">ShinNexus — Same Knowledge. Your Ownership.</p>
          </div>
        </div>"""
        ok = send_nexus_email(email, "🔐 2FA-Erneuerung — ShinNexus", html, cfg)
        if ok:
            nexus_log(f"🔐 2FA-Refresh Mail gesendet ({sid}) — 10min Fenster", "cyan")
            # KEIN expires_in im Response (Chaoten sollen nicht timen) — UI zeigt eigenen Counter
            self._send_json({"ok": True, "message": "Email mit QR-Code + Seed gesendet. Code innerhalb von 10 Minuten eingeben."})
        else:
            del self._2fa_pending[sid]
            # Dieser Versuch zählt trotzdem nicht — attempt rückgängig machen
            wins["attempts"].pop()
            self._send_json({"error": "Email konnte nicht gesendet werden!"})

    def _handle_2fa_refresh_confirm(self):
        """POST /api/auth/2fa-refresh-confirm — Neuen 2FA-Code bestätigen (2min Fenster!)."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        totp_code = data.get("totp_code", "")
        if not totp_code:
            self._send_json({"error": "2FA-Code erforderlich"}, 400)
            return

        sid = session["shinpai_id"]
        pending = self._2fa_pending.get(sid)
        if not pending:
            self._send_json({"error": "Kein 2FA-Refresh aktiv! Erst anfordern."}, 400)
            return

        # 2min abgelaufen?
        if time.time() > pending["expires"]:
            del self._2fa_pending[sid]
            self._send_json({"error": "⏱️ 2 Minuten abgelaufen! Nochmal anfordern."}, 410)
            return

        # Code prüfen gegen NEUES Secret
        if not totp_verify(pending["new_secret"], totp_code):
            self._send_json({"error": "Falscher Code! QR nochmal scannen."}, 401)
            return

        # Bestätigt! Nur 2FA-Secret aktualisieren (Seed bleibt unverändert)
        new_secret = pending["new_secret"]
        reset_cleared = False

        if pending["is_owner"] and _identity:
            _identity["totp_secret"] = new_secret
            _identity["totp_confirmed"] = True
            # Reset-Modus beenden (2FA-Change ist eine gültige Reset-Aktion)
            if _identity.get("pw_reset_pending"):
                _owner_clear_reset_flags()
                reset_cleared = True
            else:
                _save_identity()
        else:
            user = _users.get(pending["username"])
            if user:
                user["totp_secret"] = new_secret
                user["totp_confirmed"] = True
                if user.get("pw_reset_pending"):
                    user["pw_reset_pending"] = False
                    user.pop("pw_reset_triggered_at", None)
                    reset_cleared = True
                _save_users()

        if reset_cleared:
            nexus_log(f"🟢 Reset-Modus deaktiviert via 2FA-Refresh ({pending['username']})", "green")

        # Windows-Tracking cleanen (erfolgreiche Rotation → User darf sofort wieder)
        self._2fa_pending.pop(sid, None)
        if sid in self._2fa_refresh_windows:
            self._2fa_refresh_windows[sid]["attempts"] = []
            self._2fa_refresh_windows[sid]["current_pending"] = None

        nexus_log(f"🔐 2FA REFRESHED — {pending['username']} ({sid})", "green")
        self._send_json({"ok": True, "message": "2FA aktualisiert! Alter Code ist ab jetzt ungültig."})

    def _handle_seed_refresh(self):
        """POST /api/auth/seed-refresh — Neuen Recovery-Seed ausstellen.
        Body: {password, totp_code}
        Erfordert verifizierte Email + PW + 2FA (höchste Sicherheitsstufe).
        Atomisch: neuer Seed → vault_kem_priv.seed.vault neu verschlüsselt → alter Seed ungültig.
        """
        ip = self._client_ip()
        session = self._require_auth()
        if not session:
            return
        if not vault_is_unlocked():
            self._send_json({"error": "Vault nicht entsperrt"}, 503)
            return
        sid = session["shinpai_id"]
        uname = session["name"]
        is_owner = _identity and sid == _identity.get("shinpai_id")
        if not is_owner:
            # Für Non-Owner ist der Seed aktuell nicht an vault_kem_priv.seed.vault gebunden
            # (User-Accounts haben nur password_hash, kein ML-KEM). Wir rotieren nur den hash.
            user = _users.get(uname)
            if not user:
                self._send_json({"error": "User nicht gefunden"}, 404)
                return

        target = _identity if is_owner else _users.get(uname)
        # Email muss verifiziert sein
        if not target.get("email_verified"):
            self._send_json({"error": "Email muss verifiziert sein für Seed-Refresh"}, 403)
            return
        # 2FA aktiv + Code prüfen
        if not target.get("totp_confirmed") or not target.get("totp_secret"):
            self._send_json({"error": "2FA muss aktiv sein"}, 403)
            return
        data = self._parse_json() or {}
        password = data.get("password", "")
        totp_code = (data.get("totp_code") or "").strip()
        if not password or not totp_code:
            self._send_json({"error": "password + totp_code erforderlich"}, 400)
            return
        if not totp_verify(target.get("totp_secret", ""), totp_code):
            self._send_json({"error": "Falscher 2FA-Code"}, 401)
            return
        # PW prüfen
        if is_owner:
            if not vault_unlock(password):
                self._send_json({"error": "Passwort falsch"}, 401)
                return
        else:
            if not _verify_password(password, target.get("password_hash", ""), target.get("password_salt", "")):
                self._send_json({"error": "Passwort falsch"}, 401)
                return

        # Neuen Seed generieren
        new_seed = _generate_recovery_seed()
        new_seed_hash = hashlib.sha256(new_seed.encode("utf-8")).hexdigest()

        if is_owner:
            # Atomisch: kem_sk per PW holen → mit neuem Seed verschlüsseln → seed.vault neu schreiben
            kem_sk = _pq_get_kem_sk_via_password(password)
            if kem_sk is None:
                self._send_json({"error": "ML-KEM-Private nicht ableitbar"}, 500)
                return
            if not _pq_write_seed_backup_with_sk(new_seed, kem_sk):
                self._send_json({"error": "Seed-Backup Schreibfehler"}, 500)
                return
            # kem_sk sofort weg
            kem_sk = None
            _identity["recovery_seed_hash"] = new_seed_hash
            _save_identity()
            # Legacy recovery.hash + recovery.enc parallel aktualisieren
            try:
                RECOVERY_HASH_FILE.write_text(new_seed_hash)
                try:
                    os.chmod(RECOVERY_HASH_FILE, 0o600)
                except OSError:
                    pass
                _save_recovery_data(password, new_seed)
            except Exception as _e:
                nexus_log(f"⚠️ Legacy-Recovery-Write teil-fehlgeschlagen: {_e}", "yellow")
            nexus_log("🌱 Owner-Seed rotiert (kem_priv.seed.vault + recovery.hash neu)", "green")
        else:
            user = _users.get(uname)
            user["recovery_seed_hash"] = new_seed_hash
            _save_users()
            nexus_log(f"🌱 User-Seed rotiert ({uname})", "green")

        _auth_success(ip)
        self._send_json({
            "ok": True,
            "recovery_seed": new_seed,
            "message": "Neuer Recovery-Seed. JETZT sicher aufschreiben — wird nur einmal gezeigt!",
        })

    # ── Handler: Account löschen (Auth PFLICHT!) ───────────
    def _handle_delete_account(self):
        """POST /api/auth/delete-account — Account löschen (DSGVO).
        Body: {"password": "...", "totp_code": "..."} — Identität bestätigen!

        Verwendet die gleiche Logik wie /api/account/delete-self:
        - Perso-Hash → 90-Tage-Blacklist (Anti-Veriff-Farm)
        - PW + 2FA Pflicht
        - Owner kann sich nicht selbst löschen
        """
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        password = data.get("password", "")
        totp_code = (data.get("totp_code") or "").strip()
        sid = session["shinpai_id"]
        username = session["name"]

        # Owner kann sich nicht selbst löschen
        if _identity and _identity.get("shinpai_id") == sid:
            self._send_json({"error": "Owner kann sich nicht selbst löschen"}, 403)
            return

        # User finden
        target_record = _users.get(username)
        if not target_record:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return

        # PW prüfen
        if not _verify_password(password, target_record.get("password_hash", ""), target_record.get("password_salt", "")):
            self._send_json({"error": "Falsches Passwort"}, 403)
            return
        # 2FA pflicht wenn aktiv
        if target_record.get("totp_confirmed"):
            if not totp_verify(target_record.get("totp_secret", ""), totp_code):
                self._send_json({"error": "2FA-Code PFLICHT"}, 403)
                return
        # Perso-Hash auf Blacklist setzen (90 Tage Anti-Rage-Quit)
        has_perso = target_record.get("id_verified")
        perso_hash = target_record.get("perso_hash", "")
        if has_perso and perso_hash:
            _perso_blacklist_add(perso_hash)
        # Löschen
        _users.pop(username, None)
        _user_hives.pop(username, None)
        _friends_data.pop(sid, None)
        _save_users()
        # Session invalidieren
        token = self.headers.get("X-Session-Token", "")
        if token in _auth_sessions:
            del _auth_sessions[token]
        nexus_log(f"🗑️ ACCOUNT DELETED: {username} ({sid}){' [Perso→Blacklist 90d]' if has_perso else ''}", "yellow")
        self._send_json({"ok": True, "message": f"Account {username} gelöscht." + (" Perso-Hash ist 90 Tage gesperrt." if has_perso else "")})

    # ── Handler: Passwort vergessen (Email-Reset) ───────────
    _forgot_counts: dict = {}  # {email: {count, window_start}}

    def _handle_forgot_password(self):
        """POST /api/auth/forgot — Step 1 des Seed-basierten Resets.
        Body: {"email": "...", "username": "..."}
        Prueft ob Email+Username zu einem Account passen. Bei Erfolg darf Step 2
        (Seed-Eingabe via /api/auth/seed-unlock) gestartet werden.
        KEIN Mail-Link mehr — der Seed ist die Autorisierung.
        """
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        email = (data.get("email") or "").strip().lower()
        username = (data.get("username") or "").strip()
        if not email or not username:
            self._send_json({"error": "Email und Username erforderlich"}, 400)
            return

        # Rate-Limit: 3 pro Stunde pro Email
        now = time.time()
        entry = self._forgot_counts.get(email, {"count": 0, "window_start": now})
        if now - entry["window_start"] > 3600:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 3:
            self._send_json({"error": "Zu viele Reset-Anfragen. 1h warten."}, 429)
            return
        entry["count"] += 1
        self._forgot_counts[email] = entry

        # Account finden — Owner UND User suchen; Email UND Username müssen passen
        ok_match = False
        if _identity and (
            (_identity.get("email") or "").lower() == email
            and _identity.get("name") == username
        ):
            ok_match = True
        else:
            u = _users.get(username)
            if u and (u.get("email") or "").lower() == email:
                ok_match = True

        # Immer gleiche Antwort-Struktur (kein User-Enum-Leak), aber eindeutig
        # ok=true nur wenn match → Frontend leitet zur Seed-Eingabe weiter
        self._send_json({
            "ok": ok_match,
            "message": "Weiter zur Seed-Eingabe" if ok_match else "Email + Username passen zu keinem Account.",
        })

    def _handle_reset_password(self):
        """POST /api/auth/reset-password — Neues Passwort setzen mit Reset-Token.
        Body: {"token": "...", "password": "..."}
        """
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        token = data.get("token", "").strip()
        new_pw = data.get("password", "")
        if not token or not new_pw:
            self._send_json({"error": "Token und Passwort erforderlich"}, 400)
            return
        if len(new_pw) < 6:
            self._send_json({"error": "Passwort: mindestens 6 Zeichen"}, 400)
            return

        reset_2fa = data.get("reset_2fa", False)
        now = time.time()
        for uname, udata in _users.items():
            if udata.get("_reset_token") == token and udata.get("_reset_expires", 0) > now:
                pw_hash, pw_salt = _hash_password(new_pw)
                udata["password_hash"] = pw_hash
                udata["password_salt"] = pw_salt
                del udata["_reset_token"]
                del udata["_reset_expires"]
                # 2FA zurücksetzen wenn gewünscht
                if reset_2fa:
                    udata["totp_secret"] = ""
                    udata["totp_confirmed"] = False
                    nexus_log(f"🔐 2FA RESET (via PW-Reset)", "yellow")
                _save_users()
                nexus_log(f"🔑 PW RESET", "green")
                self._send_json({"ok": True, "message": "Passwort geändert! Du kannst dich jetzt einloggen."})
                return

        self._send_json({"error": "Ungültiger oder abgelaufener Reset-Token"}, 400)

    def _handle_seed_recover(self):
        """POST /api/auth/seed-recover — Seed-Phrase als letzter Rettungsanker.
        Body: {seed, new_password?, new_totp?}
        Seed ist das Backup wenn weder Passwort noch Email-Reset-Token verfügbar.
        """
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        seed = (data.get("seed") or "").strip()
        new_pw = data.get("new_password", "")
        if not seed:
            self._send_json({"error": "Seed-Phrase erforderlich"}, 400)
            return

        old_pw = _recover_vault_password(seed)
        if not old_pw:
            self._send_json({"error": "Seed-Phrase stimmt nicht"}, 401)
            return

        # Altes Vault-PW wiederhergestellt. Jetzt Vault entsperren + Owner aus Identity lesen.
        if not vault_unlock(old_pw):
            self._send_json({"error": "Vault-Entsperren fehlgeschlagen"}, 500)
            return

        response = {"ok": True, "unlocked": True, "message": "Vault über Seed wiederhergestellt"}
        if new_pw:
            if len(new_pw) < 6:
                self._send_json({"error": "Neues Passwort: mindestens 6 Zeichen"}, 400)
                return
            # Vault-Passwort ändern (alle Vault-Files neu verschlüsseln)
            if not _vault_change_password(old_pw, new_pw):
                self._send_json({"error": "Passwort-Wechsel fehlgeschlagen"}, 500)
                return
            # Owner-User-Hash im User-Store ebenfalls aktualisieren
            owner_name = None
            for uname, udata in _users.items():
                if udata.get("is_owner"):
                    pw_hash, pw_salt = _hash_password(new_pw)
                    udata["password_hash"] = pw_hash
                    udata["password_salt"] = pw_salt
                    owner_name = uname
                    break
            _save_users()
            # Neuen Recovery-Seed erzeugen + abspeichern
            import string as _str
            new_seed = " ".join(secrets.choice(_str.ascii_lowercase.split() or ["a"]) for _ in range(24))
            try:
                # Wortliste aus vorhandenem Mechanismus wiederverwenden
                _save_recovery_data(new_pw, new_seed) if False else _save_recovery_data(new_pw, seed)  # behalte alten Seed
            except Exception:
                pass
            # Igni refresh falls vorhanden
            if _VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists():
                igni_save(new_pw)
            response["password_changed"] = True
            response["owner"] = owner_name
            nexus_log(f"🔑 SEED-RECOVERY + PW-WECHSEL ({owner_name})", "cyan")
        else:
            nexus_log("🔓 SEED-RECOVERY (ohne PW-Wechsel)", "cyan")

        self._send_json(response)

    def _handle_seed_unlock(self):
        """POST /api/auth/seed-unlock — Step 2 des Seed-Resets.
        Body: {username, seed_phrase}
        Prueft Seed-Hash gegen User-Record. Bei Erfolg:
          - Temporäre Session-Token (voll, damit User das Dashboard erreicht)
          - pw_reset_pending=true + pw_reset_triggered_at=now
          - Lifecycle-Thread entfernt Account in 7 Tagen falls nichts geändert
        """
        ip = self._client_ip()
        data = self._parse_json()
        username = (data.get("username") or "").strip()
        seed_phrase = (data.get("seed_phrase") or "").strip().lower()
        if not username or not seed_phrase:
            self._send_json({"error": "Username und Seed-Phrase erforderlich"}, 400)
            return
        # Seed normalisieren: Nur Wörter, Leerzeichen getrennt
        seed_normalized = " ".join(seed_phrase.split())
        seed_hash = hashlib.sha256(seed_normalized.encode("utf-8")).hexdigest()

        # Rate-Limit: 5 Fehlversuche/10min/IP (Brute-Force-Schutz)
        now = time.time()
        if not hasattr(type(self), "_seed_unlock_fails"):
            type(self)._seed_unlock_fails = {}
        rc = type(self)._seed_unlock_fails
        entry = rc.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] > 600:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 5:
            self._send_json({"error": "Zu viele Seed-Fehlversuche — 10min warten"}, 429)
            return

        # Owner oder User?
        target_record = None
        target_is_owner = False
        if _identity and _identity.get("name") == username:
            target_record = _identity
            target_is_owner = True
        elif username in _users:
            target_record = _users[username]

        if not target_record:
            entry["count"] += 1
            rc[ip] = entry
            self._send_json({"error": "Seed-Phrase oder Username falsch."}, 401)
            return

        stored_hash = (target_record.get("recovery_seed_hash") or "").lower()
        if not stored_hash or not secrets.compare_digest(seed_hash, stored_hash):
            entry["count"] += 1
            rc[ip] = entry
            self._send_json({"error": "Seed-Phrase oder Username falsch."}, 401)
            return

        # Seed korrekt → Reset-Pending setzen + Session ausstellen
        target_record["pw_reset_pending"] = True
        target_record["pw_reset_triggered_at"] = int(now)
        if target_is_owner:
            _save_identity()
        else:
            _save_users()

        sid = target_record.get("shinpai_id", "")
        if target_is_owner:
            session = _create_auth_session("seed-unlock")
        else:
            session = _create_auth_session("seed-unlock", user_override={
                "shinpai_id": sid,
                "name": username,
                "pq_keys": target_record.get("pq_keys"),
            })
        token = session.get("token", "") if isinstance(session, dict) else ""
        nexus_log(f"🔑 SEED-UNLOCK — {'Owner' if target_is_owner else username} im Reset-Pending-Modus (7d)", "yellow")
        self._send_json({
            "ok": True,
            "session_token": token,
            "shinpai_id": sid,
            "message": "Seed akzeptiert. Du bist im Reset-Modus — PW, 2FA oder Email innerhalb 7 Tagen erneuern.",
            "pw_reset_pending": True,
        })

    def _handle_pw_reset_set(self):
        """POST /api/auth/pw-reset-set — Neues Passwort setzen im Reset-Mode.
        Body: {new_password, confirm_password}
        Session muss zu einem User mit pw_reset_pending=true gehören.
        Bei Erfolg: PW-Hash aktualisieren, pw_reset_pending=false setzen.
        """
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        data = self._parse_json()
        new_pw = data.get("new_password") or ""
        confirm = data.get("confirm_password") or ""
        if len(new_pw) < 6:
            self._send_json({"error": "Neues Passwort: mindestens 6 Zeichen"}, 400)
            return
        if new_pw != confirm:
            self._send_json({"error": "Passwörter stimmen nicht überein"}, 400)
            return

        # Target finden
        target_record = None
        target_is_owner = False
        if _identity and _identity.get("shinpai_id") == sid:
            target_record = _identity
            target_is_owner = True
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    target_record = udata
                    break
        if not target_record:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return
        if not target_record.get("pw_reset_pending"):
            self._send_json({"error": "Nicht im Reset-Modus"}, 403)
            return

        if target_is_owner:
            # Owner-PW-Reset ATOMISCH via PQ-Seed-Path:
            # 1. ML-KEM-Private aus kem_priv.seed.vault holen (via Seed)
            # 2. Mit neuer KEK verschlüsseln → kem_priv.vault schreiben
            # DEK + Vault-Daten bleiben unberührt.
            seed_phrase = (data.get("seed_phrase") or "").strip().lower()
            if not seed_phrase:
                self._send_json({"error": "Für Owner-PW-Reset: seed_phrase mit in den Body!"}, 400)
                return
            seed_normalized = " ".join(seed_phrase.split())

            # Variante A: PQ-Seed-Backup existiert — atomisch
            if VAULT_KEM_PRIV_SEED_FILE.exists():
                try:
                    seed_key = _pq_derive_seed_key(seed_normalized)
                    kem_sk = _pq_decrypt_priv(
                        VAULT_KEM_PRIV_SEED_FILE.read_bytes(), seed_key, b"vault-kem-priv-seed-v3"
                    )
                except Exception:
                    self._send_json({"error": "Seed-Phrase passt nicht zum PQ-Seed-Backup"}, 401)
                    return
                # Neue KEK ableiten, ML-KEM-Priv neu verschlüsseln
                new_kek = _pq_derive_kek(new_pw)
                new_priv_blob = _pq_encrypt_priv(kem_sk, new_kek, b"vault-kem-priv-pw-v3")
                VAULT_KEM_PRIV_FILE.write_bytes(new_priv_blob)
                try:
                    os.chmod(VAULT_KEM_PRIV_FILE, 0o600)
                except OSError:
                    pass
                # Recovery.enc auch neu binden damit Legacy-Seed-Pfad konsistent bleibt
                try:
                    _save_recovery_data(new_pw, seed_normalized)
                except Exception:
                    pass
                # Igni aktualisieren wenn Standard-Modus
                if _VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists():
                    igni_save(new_pw)
                nexus_log("🔑 Owner-PW atomisch erneuert (PQ-Seed-Path)", "green")
            else:
                # Variante B (Legacy): über recovery.enc das alte PW holen, dann Standard-Change
                old_pw = _recover_vault_password(seed_normalized)
                if not old_pw:
                    self._send_json({"error": "Seed-Phrase passt nicht zum Owner-Vault"}, 401)
                    return
                if not _vault_change_password(old_pw, new_pw):
                    self._send_json({"error": "Vault-PW-Wechsel fehlgeschlagen"}, 500)
                    return
                try:
                    _save_recovery_data(new_pw, seed_normalized)
                except Exception:
                    pass
                if _VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists():
                    igni_save(new_pw)
                nexus_log("🔑 Owner-PW erneuert (Legacy-Path via recovery.enc)", "yellow")

            _owner_clear_reset_flags()
        else:
            pw_hash, pw_salt = _hash_password(new_pw)
            target_record["password_hash"] = pw_hash
            target_record["password_salt"] = pw_salt
            target_record["pw_reset_pending"] = False
            target_record.pop("pw_reset_triggered_at", None)
            _save_users()
            nexus_log(f"🔑 User-PW im Reset-Mode erneuert ({target_record.get('name','?')})", "green")
        self._send_json({"ok": True, "message": "Passwort erneuert. Reset-Modus deaktiviert."})

    def _handle_2fa_manage(self):
        """POST /api/auth/2fa/manage — 2FA an/aus-schalten per Email-Bestätigung.
        Body: {action: 'enable'|'disable'|'reset'|'confirm', token?, totp_code?}
        """
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return
        action = (data.get("action") or "").strip()

        if action in ("enable", "disable", "reset"):
            # Aktion anfordern → Email mit Token
            session = self._require_auth()
            if not session:
                return
            uname = session["username"]
            udata = _users.get(uname)
            if not udata:
                self._send_json({"error": "User nicht gefunden"}, 404)
                return
            token = secrets.token_urlsafe(32)
            udata["_2fa_action_token"] = token
            udata["_2fa_action"] = action
            udata["_2fa_action_expires"] = time.time() + 3600  # 1h
            _save_users()
            email = udata.get("email", "")
            cfg = load_config()
            if email and smtp_configured(cfg):
                action_label = {"enable": "aktivieren", "disable": "deaktivieren", "reset": "zurücksetzen"}.get(action, action)
                base_url = cfg.get("public_url", "").rstrip("/") or f"http://{cfg.get('host','localhost')}:{cfg.get('port', DEFAULT_PORT)}"
                link = f"{base_url}/#2fa-confirm?token={token}"
                html = f"<p>Bestätige: 2FA {action_label}</p><p><a href='{link}'>{link}</a></p><p>1h gültig.</p>"
                send_nexus_email(email, f"🔐 2FA {action_label} — ShinNexus", html, cfg)
                nexus_log(f"🔐 2FA-{action} Bestätigungsmail gesendet an {uname}", "cyan")
            self._send_json({"ok": True, "message": "Bestätigungsmail gesendet (1h gültig)"})
            return

        if action == "confirm":
            token = (data.get("token") or "").strip()
            totp_code = (data.get("totp_code") or "").strip()
            if not token:
                self._send_json({"error": "Token erforderlich"}, 400)
                return
            now = time.time()
            for uname, udata in _users.items():
                if udata.get("_2fa_action_token") == token and udata.get("_2fa_action_expires", 0) > now:
                    act = udata.get("_2fa_action")
                    if act == "enable":
                        # Secret generieren + TOTP-Code prüfen
                        if not udata.get("totp_secret"):
                            udata["totp_secret"] = pyotp.random_base32()
                        if not totp_code:
                            # QR zurückgeben ohne zu aktivieren, User muss TOTP-Code liefern
                            uri = pyotp.totp.TOTP(udata["totp_secret"]).provisioning_uri(
                                name=uname, issuer_name="ShinNexus")
                            self._send_json({"ok": True, "step": "verify", "totp_uri": uri, "totp_secret": udata["totp_secret"]})
                            return
                        if pyotp.TOTP(udata["totp_secret"]).verify(totp_code, valid_window=1):
                            udata["totp_confirmed"] = True
                            del udata["_2fa_action_token"]
                            del udata["_2fa_action"]
                            del udata["_2fa_action_expires"]
                            _save_users()
                            nexus_log(f"🔐 2FA AKTIVIERT für {uname}", "green")
                            self._send_json({"ok": True, "message": "2FA aktiviert!"})
                            return
                        self._send_json({"error": "Falscher TOTP-Code"}, 401)
                        return
                    if act == "disable":
                        udata["totp_secret"] = ""
                        udata["totp_confirmed"] = False
                        del udata["_2fa_action_token"]
                        del udata["_2fa_action"]
                        del udata["_2fa_action_expires"]
                        _save_users()
                        nexus_log(f"🔐 2FA DEAKTIVIERT für {uname}", "yellow")
                        self._send_json({"ok": True, "message": "2FA deaktiviert"})
                        return
                    if act == "reset":
                        udata["totp_secret"] = pyotp.random_base32()
                        udata["totp_confirmed"] = False
                        del udata["_2fa_action_token"]
                        del udata["_2fa_action"]
                        del udata["_2fa_action_expires"]
                        _save_users()
                        uri = pyotp.totp.TOTP(udata["totp_secret"]).provisioning_uri(
                            name=uname, issuer_name="ShinNexus")
                        nexus_log(f"🔐 2FA RESET (neuer Secret) für {uname}", "yellow")
                        self._send_json({"ok": True, "step": "verify", "totp_uri": uri, "totp_secret": udata["totp_secret"]})
                        return
            self._send_json({"error": "Token ungültig oder abgelaufen"}, 400)
            return

        self._send_json({"error": "Unbekannte action (enable|disable|reset|confirm)"}, 400)

    # ── Handler: Agent List (Owner-Auth PFLICHT!) ───────────
    def _handle_agent_list(self):
        """GET /api/agent/list — Alle Agents des eingeloggten Owners.

        NUR für eingeloggten Owner! Gibt KEINE Secret Keys zurück.
        """
        session = self._require_auth()
        if not session:
            return

        owner_sid = session["shinpai_id"]
        my_agents = []
        for a in _agents:
            if a.get("owner_shinpai_id") == owner_sid:
                my_agents.append({
                    "shinpai_id": a["shinpai_id"],
                    "name": a["name"],
                    "type": a.get("type", "bot"),
                    "created": a.get("created", 0),
                    "last_seen": a.get("last_seen", 0),
                    "public_key": a.get("public_key", ""),
                })
        self._send_json({"agents": my_agents, "count": len(my_agents)})

    # ── Handler: System Vault ─────────────────────────────────
    def _handle_system_status(self):
        # Nur für localhost: volle Details. Remote: nur ob System läuft.
        if self._is_localhost():
            self._send_json({
                "system_vault_unlocked": system_vault_is_unlocked(),
                "has_owner_sig": SYSTEM_OWNER_SIG.exists(),
                "has_salt": SYSTEM_SALT_FILE.exists(),
            })
        else:
            # Remote: Minimale Info, keine Architektur-Details!
            self._send_json({
                "system_vault_unlocked": system_vault_is_unlocked(),
            })

    # ── Friends & DM Handlers ────────────────────────────────────

    def _require_auth(self) -> dict | None:
        """Auth-Session aus Token validieren. Gibt Session oder None (+ sendet 401)."""
        token = self.headers.get("X-Session-Token", "")
        if not token:
            # Fallback: Query-Param
            qs = parse_qs(urlparse(self.path).query)
            token = qs.get("token", [""])[0]
        if not token:
            self._send_json({"error": "Auth erforderlich"}, 401)
            return None
        session = validate_auth_session(token)
        if not session:
            self._send_json({"error": "Session ungueltig oder abgelaufen"}, 401)
            return None
        return session

    def _handle_friends_list(self):
        """GET /api/friends — Freundesliste + Pending fuer authentifizierten User."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        entry = _get_friends_entry(sid)
        self._send_json({
            "friends": entry["friends"],
            "pending_in": entry["pending_in"],
            "pending_out": entry["pending_out"],
            "blocked": [{"shinpai_id": c.get("shinpai_id", ""), "name": c.get("name", "?")} for c in entry["blocked"]],
        })

    def _handle_friend_request(self):
        """POST /api/friends/request — Freundschaftsanfrage empfangen.

        Kann von:
        - ShinShare Relay (Hive leitet weiter)
        - Anderem ShinNexus (Federation)
        - Eigenem Shidow (direkter Nexus-Zugriff)
        """
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        target_id = data.get("target_shinpai_id", "").strip()
        from_id = data.get("from_shinpai_id", "").strip()
        from_name = data.get("from_name", "").strip()
        from_nexus = data.get("from_nexus_url", "").strip().rstrip("/")
        from_pubkey = data.get("from_public_key", "")
        from_kem = data.get("from_kem_public_key", "")
        hive_source = data.get("hive_source", "")

        if not target_id or not from_id or not from_name:
            self._send_json({"error": "target_shinpai_id, from_shinpai_id und from_name erforderlich"}, 400)
            return

        # Ist der Ziel-User bei uns? (Owner ODER registrierter User)
        _found = (_identity and _identity.get("shinpai_id") == target_id)
        if not _found:
            _found = any(u.get("shinpai_id") == target_id for u in _users.values())
        if not _found:
            self._send_json({"error": "User nicht auf diesem ShinNexus"}, 404)
            return

        target_entry = _get_friends_entry(target_id)

        # Schon Freunde?
        if _find_contact_in_list(target_entry["friends"], from_id):
            self._send_json({"ok": True, "already_friends": True})
            return

        # Geblockt?
        if _find_contact_in_list(target_entry["blocked"], from_id):
            self._send_json({"ok": True})  # Silent — kein Hinweis auf Block
            return

        # Schon pending?
        if _find_contact_in_list(target_entry["pending_in"], from_id):
            self._send_json({"ok": True, "already_pending": True})
            return

        # Kontakt erstellen und in pending_in eintragen
        contact = _make_contact(from_id, from_name, from_nexus,
                                from_pubkey, from_kem, hive_source)
        target_entry["pending_in"].append(contact)
        _save_friends()

        nexus_log(f"Freundschaftsanfrage: {from_name} ({from_id}) → {_identity['name']}", "cyan")
        self._send_json({"ok": True, "pending": True})

    def _handle_friend_accept(self):
        """POST /api/friends/accept — Anfrage annehmen."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        my_id = session.get("shinpai_id", "")
        target_id = data.get("target_shinpai_id", "").strip()
        if not target_id:
            self._send_json({"error": "target_shinpai_id erforderlich"}, 400)
            return

        my_entry = _get_friends_entry(my_id)

        # Aus pending_in suchen
        contact = _find_contact_in_list(my_entry["pending_in"], target_id)
        if not contact:
            self._send_json({"error": "Keine Anfrage von diesem User"}, 404)
            return

        # Von pending_in → friends
        _remove_contact_from_list(my_entry["pending_in"], target_id)
        my_entry["friends"].append(contact)

        # Gegenseite: Mich bei denen als Freund eintragen (wenn gleicher Nexus)
        target_entry = _get_friends_entry(target_id)
        _my_name = session.get("name", session.get("username", _identity.get("name", "")))
        my_contact = _make_contact(
            my_id, _my_name,
            "",  # Eigene Nexus-URL — wird vom Gegenueber ausgefuellt
            _pq_keys.get("sig_pk", "") if _pq_keys else "",
            _pq_keys.get("kem_pk", "") if _pq_keys else "",
            contact.get("hive_source", ""),
        )
        _remove_contact_from_list(target_entry["pending_out"], my_id)
        if not _find_contact_in_list(target_entry["friends"], my_id):
            target_entry["friends"].append(my_contact)

        _save_friends()
        nexus_log(f"Freundschaft akzeptiert: {_identity['name']} ↔ {contact['name']}", "green")

        # TODO: Bei Federation → Nexus B benachrichtigen
        self._send_json({"ok": True, "friends": True})

    def _handle_friend_reject(self):
        """POST /api/friends/reject — Anfrage ablehnen."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        my_id = session.get("shinpai_id", "")
        target_id = data.get("target_shinpai_id", "").strip()
        my_entry = _get_friends_entry(my_id)
        _remove_contact_from_list(my_entry["pending_in"], target_id)
        _save_friends()
        self._send_json({"ok": True})

    def _handle_friend_block(self):
        """POST /api/friends/block — User blocken (silent, kein Feedback an Geblockte)."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        my_id = session.get("shinpai_id", "")
        target_id = data.get("target_shinpai_id", "").strip()
        my_entry = _get_friends_entry(my_id)

        # Kontakt-Info sichern BEVOR aus Listen entfernt wird
        existing = (_find_contact_in_list(my_entry["friends"], target_id)
                    or _find_contact_in_list(my_entry["pending_in"], target_id)
                    or _find_contact_in_list(my_entry["pending_out"], target_id))

        # Aus allen Listen entfernen
        _remove_contact_from_list(my_entry["friends"], target_id)
        _remove_contact_from_list(my_entry["pending_in"], target_id)
        _remove_contact_from_list(my_entry["pending_out"], target_id)

        # In blocked eintragen
        if not _find_contact_in_list(my_entry["blocked"], target_id):
            block_entry = existing or {"shinpai_id": target_id, "name": data.get("name", "?"),
                                       "nexus_url": "", "since": datetime.now().isoformat()}
            my_entry["blocked"].append(block_entry)

        _save_friends()
        self._send_json({"ok": True})

    def _handle_friend_unblock(self):
        """POST /api/friends/unblock — User entblocken."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        my_id = session.get("shinpai_id", "")
        target_id = data.get("target_shinpai_id", "").strip()
        my_entry = _get_friends_entry(my_id)
        _remove_contact_from_list(my_entry["blocked"], target_id)
        _save_friends()
        nexus_log(f"Entblockt: {target_id}", "cyan")
        self._send_json({"ok": True})

    def _handle_friend_remove(self):
        """POST /api/friends/remove — Freundschaft beenden (beidseitig)."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        my_id = session.get("shinpai_id", "")
        target_id = data.get("target_shinpai_id", "").strip()
        my_entry = _get_friends_entry(my_id)
        target_entry = _get_friends_entry(target_id)
        _remove_contact_from_list(my_entry["friends"], target_id)
        _remove_contact_from_list(target_entry["friends"], my_id)
        _save_friends()
        nexus_log(f"Freundschaft entfernt: {my_id} ↔ {target_id}", "yellow")
        self._send_json({"ok": True})

    def _handle_friends_keys(self, target_shinpai_id: str):
        """GET /api/friends/keys/{shinpai_id} — Oeffentliche Keys eines Freundes abrufen.

        Nur fuer akzeptierte Freunde (nicht pending/blocked).
        Shidow braucht den KEM-PubKey des Empfaengers fuer E2E-DM-Verschluesselung.
        """
        session = self._require_auth()
        if not session:
            return

        my_id = session.get("shinpai_id", "")
        my_entry = _get_friends_entry(my_id)

        # Nur akzeptierte Freunde!
        contact = _find_contact_in_list(my_entry["friends"], target_shinpai_id)
        if not contact:
            self._send_json({"error": "Kein akzeptierter Freund mit dieser ID"}, 404)
            return

        self._send_json({
            "shinpai_id": contact["shinpai_id"],
            "name": contact.get("name", ""),
            "public_key": contact.get("public_key", ""),
            "kem_public_key": contact.get("kem_public_key", ""),
        })

    def _handle_public_keys_update(self):
        """POST /api/auth/public-keys — Eigene oeffentliche Keys aktualisieren.

        Body: {public_key: hex, kem_public_key: hex}
        Speichert in Config + aktualisiert bei allen Freunden die gespeicherten Keys.
        """
        session = self._require_auth()
        if not session:
            return

        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        pub_key = data.get("public_key", "").strip()
        kem_pub_key = data.get("kem_public_key", "").strip()

        if not pub_key and not kem_pub_key:
            self._send_json({"error": "Mindestens public_key oder kem_public_key erforderlich"}, 400)
            return

        # Validierung: Hex-Strings pruefen
        for label, val in [("public_key", pub_key), ("kem_public_key", kem_pub_key)]:
            if val:
                try:
                    bytes.fromhex(val)
                except ValueError:
                    self._send_json({"error": f"{label} muss gültiger Hex-String sein"}, 400)
                    return

        # Keys aktualisieren: Owner → Config, User → _users Record
        my_id = session.get("shinpai_id", "")
        is_owner = _identity and my_id == _identity.get("shinpai_id")
        if is_owner:
            cfg = load_config()
            if pub_key:
                cfg["public_key"] = pub_key
            if kem_pub_key:
                cfg["kem_public_key"] = kem_pub_key
            save_config(cfg)
        else:
            uname = session.get("name", "")
            user_data = _users.get(uname)
            if user_data and user_data.get("pq_keys"):
                if pub_key:
                    user_data["pq_keys"]["sig_pk"] = pub_key
                if kem_pub_key:
                    user_data["pq_keys"]["kem_pk"] = kem_pub_key
                _save_users()
            cfg = load_config()  # Für Response

        # Freundschaften aktualisieren: Bei allen Freunden die mich kennen,
        # meinen gespeicherten Key updaten
        my_id = session.get("shinpai_id", "")
        updated_friends = 0
        for sid, entry in _friends_data.items():
            if sid == my_id:
                continue
            for contact in entry.get("friends", []):
                if contact.get("shinpai_id") == my_id:
                    if pub_key:
                        contact["public_key"] = pub_key
                    if kem_pub_key:
                        contact["kem_public_key"] = kem_pub_key
                    updated_friends += 1

        if updated_friends > 0:
            _save_friends()

        nexus_log(f"Public Keys aktualisiert (bei {updated_friends} Freunden propagiert)", "green")
        self._send_json({
            "ok": True,
            "public_key": cfg.get("public_key", ""),
            "kem_public_key": cfg.get("kem_public_key", ""),
            "friends_updated": updated_friends,
        })

    def _handle_dm_send(self):
        """POST /api/dm/send — E2E-verschluesselte DM empfangen und speichern/weiterleiten.

        E2E-Ablauf (ShinNexus = reiner Relay, sieht NIX!):
        1. Sender holt Empfaenger-KEM-PubKey via GET /api/friends/keys/{id}
        2. Sender macht ML-KEM-768 Encapsulation → shared_secret + kem_ciphertext
        3. Sender verschluesselt Nachricht mit AES-256-GCM(shared_secret) → encrypted_blob
        4. Sender schickt {to, from, encrypted_blob, kem_ciphertext} an ShinNexus
        5. Empfaenger holt pending DMs, decapsuliert kem_ciphertext → gleicher shared_secret
        6. Empfaenger entschluesselt encrypted_blob mit AES-256-GCM(shared_secret)
        """
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        to_id = data.get("to_shinpai_id", "").strip()
        from_id = data.get("from_shinpai_id", "").strip()
        from_name = data.get("from_name", "")
        from_nexus = data.get("from_nexus_url", "")
        encrypted_blob = data.get("encrypted_blob", "")
        kem_ciphertext = data.get("kem_ciphertext", "")

        if not to_id or not from_id or not encrypted_blob:
            self._send_json({"error": "to_shinpai_id, from_shinpai_id und encrypted_blob erforderlich"}, 400)
            return

        if not kem_ciphertext:
            self._send_json({"error": "kem_ciphertext erforderlich fuer E2E-Verschluesselung"}, 400)
            return

        # Ist der Ziel-User bei uns? (Owner ODER registrierter User)
        _target_name = None
        if _identity and _identity.get("shinpai_id") == to_id:
            _target_name = _identity.get("name", "?")
        else:
            for _uname, _udata in _users.items():
                if _udata.get("shinpai_id") == to_id:
                    _target_name = _udata.get("name", _uname)
                    break

        if _target_name:
            # Lokal speichern als pending
            msg_id = _dm_store_pending(to_id, from_id, from_name, encrypted_blob,
                                       from_nexus, kem_ciphertext)
            nexus_log(f"DM empfangen (E2E): {from_name} → {_target_name} (id={msg_id})", "cyan")
            self._send_json({"ok": True, "message_id": msg_id})
            return

        # TODO: Federation — an anderen Nexus weiterleiten
        self._send_json({"error": "User nicht auf diesem ShinNexus"}, 404)

    def _handle_dm_pending(self):
        """GET /api/dm/pending — Pending DMs fuer authentifizierten User abrufen."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        msgs = _dm_get_pending(sid)
        self._send_json({"messages": msgs, "count": len(msgs)})

    def _handle_dm_ack(self):
        """POST /api/dm/ack — DMs als empfangen bestaetigen (loescht Pending)."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        if not data:
            self._send_json({"error": "JSON erforderlich"}, 400)
            return

        sid = session.get("shinpai_id", "")
        msg_ids = data.get("message_ids", [])
        if not msg_ids:
            self._send_json({"error": "message_ids erforderlich"}, 400)
            return
        count = _dm_ack_messages(sid, msg_ids)
        self._send_json({"ok": True, "deleted": count})

    # ── Handler: Account-Type (Kind/Bot/Erwachsen) ────────────

    def _handle_account_type_status(self):
        """GET /api/account/type — Status des eingeloggten Accounts.
        Antwort: {type, is_secondary, can_switch_to_bot, can_switch_to_kind, has_perso}
        """
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        record = None
        if _identity and _identity.get("shinpai_id") == sid:
            record = _identity
        else:
            for u in _users.values():
                if u.get("shinpai_id") == sid:
                    record = u
                    break
        if not record:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return
        acc_type = derive_account_type(record)
        is_owner_record = bool(_identity and _identity.get("shinpai_id") == sid)
        is_secondary = bool(record.get("is_secondary_account"))
        has_kk = bool(record.get("verified_stripe"))
        has_perso = bool(record.get("id_verified"))
        # Wechsel-Möglichkeiten: nur für Zweit-Accounts
        can_switch_to_bot = is_secondary and has_kk and acc_type != "bot"
        can_switch_to_kind = is_secondary and acc_type != "kind"
        self._send_json({
            "type": acc_type,
            "is_secondary": is_secondary,
            "has_kk": has_kk,
            "has_perso": has_perso,
            "can_switch_to_bot": can_switch_to_bot,
            "can_switch_to_kind": can_switch_to_kind,
            "pw_reset_pending": bool(record.get("pw_reset_pending")),
            "pw_reset_triggered_at": record.get("pw_reset_triggered_at"),
            "is_owner": is_owner_record,
        })

    def _handle_account_type_switch(self):
        """POST /api/account/type-switch — Kind↔Bot Wechsel fuer Zweit-Accounts.
        Body: {target_type: 'bot'|'kind', password}
        Nur fuer Zweit-Accounts. Bot-Wechsel braucht eigene KK. Anti-Spam-Staffel greift.
        """
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        # Anti-Spam
        allowed, abuse_msg, retry = _type_switch_check(sid)
        if not allowed:
            self._send_json({"error": abuse_msg, "retry_after": retry}, 423)
            return

        data = self._parse_json()
        target_type = (data.get("target_type") or "").lower()
        password = data.get("password") or ""
        if target_type not in ("bot", "kind"):
            self._send_json({"error": "target_type muss 'bot' oder 'kind' sein"}, 400)
            return
        if not password:
            self._send_json({"error": "Passwort erforderlich"}, 400)
            return

        # Ziel-Record finden
        record = None
        record_ref = None  # Tuple (container, key) für _save
        if _identity and _identity.get("shinpai_id") == sid:
            record = _identity
            record_ref = ("identity", None)
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    record = udata
                    record_ref = ("user", uname)
                    break
        if not record:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return

        # Passwort prüfen (Owner vs User)
        if record_ref[0] == "identity":
            if not _verify_owner_password(password):
                self._send_json({"error": "Falsches Passwort"}, 403)
                return
        else:
            if not _verify_password(password, record.get("password_hash", ""), record.get("password_salt", "")):
                self._send_json({"error": "Falsches Passwort"}, 403)
                return

        # Nur Zweit-Accounts können switchen
        if not record.get("is_secondary_account"):
            self._send_json({"error": "Nur Zweit-Accounts können Typ wechseln"}, 403)
            return
        # Bot-Wechsel braucht eigene KK
        if target_type == "bot" and not record.get("verified_stripe"):
            self._send_json({"error": "Bot-Wechsel benötigt eigene Kreditkarte (verified_stripe)"}, 403)
            return
        # Set Override
        record["type_override"] = target_type
        if record_ref[0] == "identity":
            _save_identity()
        else:
            _save_users()
        # Spam-Zähler aktualisieren
        result, msg = _type_switch_register(sid)
        new_type = derive_account_type(record)
        resp = {"ok": True, "type": new_type, "spam_result": result}
        if msg:
            resp["message"] = msg
        nexus_log(f"🔄 Type-Switch {sid}: → {new_type} (spam: {result})", "cyan")
        self._send_json(resp)

    def _handle_account_delete_self(self):
        """POST /api/account/delete-self — User loescht eigenen Account.
        Body: {password, totp_code}
        GESPERRT wenn Perso hinterlegt (id_verified=True) — Perso-Schutz.
        """
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        # Owner darf NICHT per Self-Delete weg (sonst ist der ganze Nexus kaputt)
        if _identity and _identity.get("shinpai_id") == sid:
            self._send_json({"error": "Owner kann sich nicht selbst löschen"}, 403)
            return
        # User finden
        target_uname = None
        target_record = None
        for uname, udata in _users.items():
            if udata.get("shinpai_id") == sid:
                target_uname = uname
                target_record = udata
                break
        if not target_record:
            self._send_json({"error": "Account nicht gefunden"}, 404)
            return
        data = self._parse_json()
        password = data.get("password") or ""
        totp_code = (data.get("totp_code") or "").strip()
        # PW prüfen
        if not _verify_password(password, target_record.get("password_hash", ""), target_record.get("password_salt", "")):
            self._send_json({"error": "Falsches Passwort"}, 403)
            return
        # 2FA pflicht wenn aktiv
        if target_record.get("totp_confirmed"):
            if not totp_verify(target_record.get("totp_secret", ""), totp_code):
                self._send_json({"error": "2FA-Code PFLICHT"}, 403)
                return
        # Perso-Hash auf Blacklist setzen (90 Tage Anti-Rage-Quit)
        has_perso = target_record.get("id_verified")
        perso_hash = target_record.get("perso_hash", "")
        if has_perso and perso_hash:
            _perso_blacklist_add(perso_hash)
        # Löschen
        _users.pop(target_uname, None)
        _user_hives.pop(target_uname, None)
        _friends_data.pop(sid, None)
        _save_users()
        nexus_log(f"🗑️ Self-Delete: User {target_uname} ({sid}){' [Perso→Blacklist 90d]' if has_perso else ''}", "yellow")
        self._send_json({"ok": True, "message": "Account gelöscht" + (" — Perso-Hash ist 90 Tage gesperrt, danach Neuanfang möglich." if has_perso else "")})

    def _handle_owner_members_list(self):
        """GET /api/owner/members — Nur Owner. Liste aller Nexus-Member mit Perso-Status.
        Antwort: {members: [{shinpai_id, has_perso, has_kk, is_secondary, type, perso_protected}]}
        """
        if not self._owner_only_session():
            return
        members = []
        # Owner zuerst (immer geschützt, nicht löschbar)
        if _identity:
            members.append({
                "shinpai_id": _identity.get("shinpai_id", ""),
                "has_perso": bool(_identity.get("id_verified")),
                "has_kk": bool(_identity.get("verified_stripe")),
                "is_secondary": False,
                "type": "Owner",
                "perso_protected": True,  # Owner ist IMMER geschützt
            })
        for uname, u in _users.items():
            sid = u.get("shinpai_id", "")
            has_perso = bool(u.get("id_verified"))
            has_kk = bool(u.get("verified_stripe"))
            members.append({
                "shinpai_id": sid,
                "has_perso": has_perso,
                "has_kk": has_kk,
                "is_secondary": bool(u.get("is_secondary_account")),
                "type": derive_account_type(u),
                "perso_protected": has_perso,  # Perso hinterlegt → nicht löschbar
            })
        self._send_json({"members": members, "count": len(members)})

    def _handle_owner_members_delete(self):
        """POST /api/owner/members/delete — Owner loescht Member (ausser mit Perso).
        Body: {shinpai_id, password, totp_code}
        """
        if not self._owner_only_session():
            return
        data = self._parse_json()
        target_sid = (data.get("shinpai_id") or "").strip()
        password = data.get("password") or ""
        totp_code = (data.get("totp_code") or "").strip()
        if not target_sid:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        if not _verify_owner_password(password):
            self._send_json({"error": "Falsches Owner-Passwort"}, 403)
            return
        if _identity and _identity.get("totp_confirmed"):
            if not totp_verify(_identity.get("totp_secret", ""), totp_code):
                self._send_json({"error": "2FA-Code PFLICHT"}, 403)
                return
        # Ziel finden
        target_uname = None
        target_record = None
        for uname, u in _users.items():
            if u.get("shinpai_id") == target_sid:
                target_uname = uname
                target_record = u
                break
        if not target_record:
            self._send_json({"error": "Member nicht gefunden"}, 404)
            return
        # Perso-Schutz
        if target_record.get("id_verified"):
            self._send_json({
                "error": "Perso-verifizierter Account nicht löschbar (Veriff-Abuse-Schutz)",
            }, 403)
            return
        _users.pop(target_uname, None)
        _user_hives.pop(target_uname, None)
        _friends_data.pop(target_sid, None)
        _save_users()
        nexus_log(f"🗑️ Owner-Delete Member: {target_uname} ({target_sid})", "yellow")
        self._send_json({"ok": True, "deleted": target_uname})

    # ── Handler: Owner-Igni (Haus­schlüssel) ──────────────────

    def _owner_only_session(self) -> dict | None:
        """Nur der Owner darf Igni managen. Liefert Session oder None (+ sendet 403)."""
        session = self._require_auth()
        if not session:
            return None
        if not _identity:
            self._send_json({"error": "Kein Owner registriert"}, 403)
            return None
        if session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur der Owner darf das"}, 403)
            return None
        return session

    def _handle_bot_policy_get(self):
        """GET /api/public/bot-policy — öffentlich, für Login-Banner und Besucher.
        Antwort: {quota, label, current, available_values}"""
        self._send_json(get_bot_policy())

    def _handle_bot_quota_set(self):
        """POST /api/owner/bot-quota — Owner setzt die Bot-Quote.

        Body: {quota: 0|20|50|100|200|1000, password, totp_code}
        Passwort + 2FA Pflicht wenn aktiv (analog Igni-Setting).
        """
        if not self._owner_only_session():
            return
        data = self._parse_json()
        try:
            new_quota = int(data.get("quota"))
        except (TypeError, ValueError):
            self._send_json({"error": "quota muss Zahl sein"}, 400)
            return
        if new_quota not in _BOT_QUOTA_VALUES:
            self._send_json({
                "error": f"quota muss einer von {_BOT_QUOTA_VALUES} sein",
            }, 400)
            return
        password = data.get("password") or ""
        if not password:
            self._send_json({"error": "Passwort erforderlich"}, 400)
            return
        if not _verify_owner_password(password):
            ip = self._client_ip()
            _auth_fail(ip)
            self._send_json({"error": "Falsches Passwort"}, 403)
            return
        if _identity and _identity.get("totp_confirmed"):
            totp_code = (data.get("totp_code") or "").strip()
            if not totp_verify(_identity.get("totp_secret", ""), totp_code):
                self._send_json({"error": "2FA-Code PFLICHT"}, 403)
                return
        cfg = load_config()
        cfg["bot_quota"] = new_quota
        save_config(cfg)
        policy = get_bot_policy(cfg)
        nexus_log(f"🤖 Bot-Quote gesetzt: {new_quota} — {policy['label']}", "cyan")
        self._send_json({
            "ok": True,
            **policy,
            "message": f"Quote auf {new_quota} gesetzt — {policy['label']}",
        })

    # ── Handler: Whitelist (vertrauenswürdige Versionen) ───────────
    def _handle_whitelist_get(self):
        """GET /api/whitelist — Liste vertrauenswürdiger Versionen (PUBLIC).

        Öffentlich lesbar — Whitelist enthält nur öffentliche Daten (Version, Hash, TXID).
        Jeder Nexus publiziert damit welchen Code-Versionen er vertraut.
        Schreiben bleibt Owner-only (add/delete Endpoints).
        """
        cfg = load_config()
        items = cfg.get("whitelist") or []
        self._send_json({"items": items})

    def _handle_whitelist_add(self):
        """POST /api/whitelist/add — Neuen Eintrag hinzufügen (Owner-only).
        Body: {version, hash, txid, label?}
        """
        if not self._owner_only_session():
            return
        data = self._parse_json() or {}
        version = (data.get("version") or "").strip()
        code_hash = (data.get("hash") or "").strip().lower()
        txid = (data.get("txid") or "").strip().lower()
        label = (data.get("label") or "").strip()[:64]
        if not version:
            self._send_json({"error": "version erforderlich"}, 400)
            return
        if not code_hash or len(code_hash) < 16:
            self._send_json({"error": "hash erforderlich (mind. 16 Zeichen)"}, 400)
            return
        if not txid or len(txid) < 16:
            self._send_json({"error": "txid erforderlich (Bitcoin-Transaktion)"}, 400)
            return
        cfg = load_config()
        items = cfg.get("whitelist") or []
        # Duplikat-Check via hash (Hash ist einzigartig)
        for it in items:
            if it.get("hash") == code_hash:
                self._send_json({"error": "Eintrag mit diesem Hash existiert bereits"}, 409)
                return
        items.append({
            "version": version,
            "hash": code_hash,
            "txid": txid,
            "label": label,
            "added_at": int(time.time()),
        })
        cfg["whitelist"] = items
        save_config(cfg)
        NexusHandler.config = cfg
        nexus_log(f"🦋 Whitelist-Eintrag hinzugefügt: v{version}", "cyan")
        self._send_json({"ok": True, "items": items})

    def _handle_whitelist_delete(self):
        """POST /api/whitelist/delete — Eintrag entfernen (Owner-only).
        Body: {hash: "..."}
        """
        if not self._owner_only_session():
            return
        data = self._parse_json() or {}
        code_hash = (data.get("hash") or "").strip().lower()
        if not code_hash:
            self._send_json({"error": "hash erforderlich"}, 400)
            return
        cfg = load_config()
        items = cfg.get("whitelist") or []
        new_items = [it for it in items if it.get("hash") != code_hash]
        if len(new_items) == len(items):
            self._send_json({"error": "Eintrag nicht gefunden"}, 404)
            return
        cfg["whitelist"] = new_items
        save_config(cfg)
        NexusHandler.config = cfg
        nexus_log(f"🦋 Whitelist-Eintrag entfernt: hash={code_hash[:16]}…", "yellow")
        self._send_json({"ok": True, "items": new_items})

    def _handle_whitelist_import(self):
        """POST /api/whitelist/import — Whitelist von einem fremden Nexus importieren (Owner-only).
        Body: {url: "https://fremder-nexus.beispiel.de"}
        Fetcht GET /api/whitelist vom Ziel und mergt neue Einträge (Deduplizierung per Hash).
        """
        if not self._owner_only_session():
            return
        data = self._parse_json() or {}
        target_url = (data.get("url") or "").strip().rstrip("/")
        if not target_url or not target_url.startswith(("http://", "https://")):
            self._send_json({"error": "Gültige URL erforderlich (https://...)"}, 400)
            return
        # Fremde Whitelist abrufen
        try:
            import urllib.request
            import ssl
            req = urllib.request.Request(
                f"{target_url}/api/whitelist",
                headers={"Accept": "application/json", "User-Agent": f"ShinNexus/{VERSION}"},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                remote = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            self._send_json({"error": f"Abruf fehlgeschlagen: {e}"}, 502)
            return
        remote_items = remote.get("items") or []
        if not isinstance(remote_items, list):
            self._send_json({"error": "Ungültiges Whitelist-Format vom Ziel"}, 502)
            return
        # Mergen: nur neue Hashes, keine Duplikate
        cfg = load_config()
        local_items = cfg.get("whitelist") or []
        existing_hashes = {(it.get("hash") or "").lower() for it in local_items}
        added = 0
        for ri in remote_items:
            h = (ri.get("hash") or "").lower()
            if not h or h in existing_hashes:
                continue
            local_items.append({
                "version": ri.get("version", ""),
                "hash": h,
                "txid": (ri.get("txid") or "").lower(),
                "label": (ri.get("label") or "")[:64],
                "added_at": int(time.time()),
                "imported_from": target_url,
            })
            existing_hashes.add(h)
            added += 1
        cfg["whitelist"] = local_items
        save_config(cfg)
        NexusHandler.config = cfg
        nexus_log(f"🦋 Whitelist-Import von {target_url}: {added} neue Einträge", "cyan")
        self._send_json({"ok": True, "added": added, "total": len(local_items), "items": local_items})

    def _handle_owner_igni_get(self):
        """GET /api/owner/igni — Status des Haus­schlüssels (Igni)."""
        if not self._owner_only_session():
            return
        cfg = load_config()
        _igni_init(cfg)
        mode = cfg.get("owner_vault_mode", "standard")
        active = bool(_VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists())
        self._send_json({
            "mode": mode,
            "active": active,
            "path": str(_IGNITION_DIR) if _IGNITION_DIR else "",
        })

    def _handle_owner_igni_set(self):
        """POST /api/owner/igni — Modus wechseln.

        Body: {mode: "standard"|"paranoid", password: str, totp_code: str (wenn 2FA aktiv)}
        - standard → Igni wird erzeugt (falls nicht vorhanden)
        - paranoid → Igni wird gelöscht (falls vorhanden)
        """
        if not self._owner_only_session():
            return
        data = self._parse_json()
        new_mode = (data.get("mode") or "").strip().lower()
        password = data.get("password") or ""
        if new_mode not in ("standard", "paranoid"):
            self._send_json({"error": "mode muss 'standard' oder 'paranoid' sein"}, 400)
            return
        if not password:
            self._send_json({"error": "Passwort erforderlich"}, 400)
            return
        if not _verify_owner_password(password):
            ip = self._client_ip()
            _auth_fail(ip)
            self._send_json({"error": "Falsches Passwort"}, 403)
            return
        # 2FA Pflicht wenn aktiv
        if _identity and _identity.get("totp_confirmed"):
            totp_code = (data.get("totp_code") or "").strip()
            if not totp_verify(_identity.get("totp_secret", ""), totp_code):
                self._send_json({"error": "2FA-Code PFLICHT für Haus­schlüssel-Wechsel"}, 403)
                return
        cfg = load_config()
        _igni_init(cfg)
        if new_mode == "standard":
            igni_save(password)
            cfg["owner_vault_mode"] = "standard"
            save_config(cfg)
            self._send_json({
                "status": "ok",
                "mode": "standard",
                "active": True,
                "message": "Haus­schlüssel aktiv — nächster Start entsperrt automatisch.",
            })
        else:
            igni_delete()
            cfg["owner_vault_mode"] = "paranoid"
            save_config(cfg)
            self._send_json({
                "status": "ok",
                "mode": "paranoid",
                "active": False,
                "message": "Paranoid-Modus — jeder Server-Start verlangt Passwort + 2FA.",
            })

    def _handle_owner_igni_export(self):
        """GET /api/owner/igni/export — Haus­schlüssel als ZIP herunterladen (USB-Kopie).

        Enthält den gesamten Igni-Ordner. Funktioniert NUR auf dieser Maschine
        (machine-id-Bindung) — USB-Transport auf andere Maschine = wertlos.
        """
        if not self._owner_only_session():
            return
        if not (_IGNITION_DIR and _VAULT_BOOTSTRAP and _VAULT_BOOTSTRAP.exists()):
            self._send_json({"error": "Kein Igni aktiv — erst Modus 'standard' setzen"}, 404)
            return
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            dir_name = _IGNITION_DIR.name
            for f in _IGNITION_DIR.iterdir():
                if f.is_file():
                    zf.write(str(f), arcname=f"{dir_name}/{f.name}")
        payload = buf.getvalue()
        filename = f"{_IGNITION_DIR.name}.zip"
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)
        nexus_log(f"🔑 Igni exportiert ({len(payload)} bytes, nur auf dieser Maschine gültig)", "cyan")

    # ── Handler: Status ───────────────────────────────────────
    def _handle_public_shield(self):
        """GET /api/public/shield?shinpai_id=XXX — Öffentlicher Shield-Status.
        Keine Auth nötig. Liefert verification_level und active_subclasses für ein gegebenes Shinpai-ID.
        Wird von der Kneipe für Lazy-Sync des Shield-Glows verwendet."""
        from urllib.parse import urlparse, parse_qs as _pqs
        qs = _pqs(urlparse(self.path).query)
        sid = (qs.get("shinpai_id") or [""])[0].strip()
        if not sid:
            self._send_json({"verification_level": 0, "active_subclasses": []})
            return
        # Level aus Identity oder Users
        vlevel = 0
        if _identity and _identity.get("shinpai_id") == sid:
            vlevel = int(_identity.get("verification_level", 0))
        else:
            for _un, _ud in _users.items():
                if _ud.get("shinpai_id") == sid:
                    vlevel = int(_ud.get("verification_level", 0))
                    break
        # Active subclasses aus Lizenz-Vault
        active_subs = []
        if vault_is_unlocked():
            _now_ps = int(time.time())
            for lic in _license_load_vault(LICENSES_RECEIVED_VAULT):
                if lic.get("subject", {}).get("shinpai_id") != sid:
                    continue
                if int(lic.get("valid_until", 0)) <= _now_ps:
                    continue
                for _pc, _pss in (lic.get("amt_categories") or {}).items():
                    for _ps in _pss:
                        active_subs.append(f"{_pc}/{_ps}")
        # Code-Hash für Trust-Prüfung mitliefern
        try:
            with open(__file__, "rb") as _chf:
                _code_hash = hashlib.sha256(_chf.read()).hexdigest()
        except Exception:
            _code_hash = ""
        self._send_json({
            "verification_level": vlevel,
            "active_subclasses": list(set(active_subs)),
            "code_hash": _code_hash,
            "version": VERSION,
        })

    def _handle_public_chain(self):
        """GET /api/public/chain — Öffentliche Chain of Trust Daten.
        Keine Auth nötig. Liefert Bitcoin-Adresse, alle Anchors, aktuellen Code-Hash."""
        w = _btc_wallet_load() if vault_is_unlocked() else {}
        anchor = _btc_read_anchor_json()
        try:
            with open(__file__, "rb") as _chf:
                _code_hash = hashlib.sha256(_chf.read()).hexdigest()
        except Exception:
            _code_hash = ""
        last_anchor_hash = anchor.get("code_hash", "")
        self._send_json({
            "nexus_version": VERSION,
            "code_hash": _code_hash,
            "btc_address": w.get("address", ""),
            "anchors": [e for e in w.get("entries", []) if e.get("status") != "pending"],
            "revocations": w.get("revocations", []),
            "has_wallet": bool(w.get("address")),
            "owner_id": (_identity or {}).get("shinpai_id", ""),
            "current_hash_matches_anchor": _code_hash == last_anchor_hash if last_anchor_hash else False,
            "latest_anchor_revoked": anchor.get("revoked", False),
        })

    def _require_owner(self) -> bool:
        """Owner-Zugriff prüfen: Lokal ODER Auth-Session mit Owner-ID. Sendet 401/403 bei Fehler."""
        if self._is_localhost() and _identity:
            return True
        session = self._require_auth()
        if not session:
            return False
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return False
        return True

    def _handle_btc_wallet_get(self):
        """GET /api/btc/wallet — Wallet-Status (Owner only)."""
        if not self._require_owner():
            return
        w = _btc_wallet_load()
        if not w:
            self._send_json({"has_wallet": False})
            return
        try:
            with open(__file__, "rb") as f:
                code_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            code_hash = ""
        # Wallet-Entries mit anchor.json history abgleichen (revoked-Flags nachholen)
        entries = w.get("entries", [])
        anchor = _btc_read_anchor_json()
        if anchor:
            revoked_hashes = {}
            for h in (anchor.get("history") or []):
                if h.get("revoked"):
                    revoked_hashes[(h.get("code_hash") or "").lower()] = h
            dirty = False
            for e in entries:
                eh = (e.get("code_hash") or "").lower()
                if eh in revoked_hashes and not e.get("revoked"):
                    rh = revoked_hashes[eh]
                    e["revoked"] = True
                    e["revoked_at"] = rh.get("revoked_at", 0)
                    e["revoke_txid"] = rh.get("revoke_txid", "")
                    dirty = True
            if dirty:
                _btc_wallet_save(w)
        self._send_json({
            "has_wallet": True,
            "address": w.get("address", ""),
            "mnemonic": w.get("mnemonic", ""),
            "entries": entries,
            "created_at": w.get("created_at", 0),
            "code_hash": code_hash,
            "pending_revoke": w.get("pending_revoke"),
        })

    def _handle_btc_wallet_create(self):
        """POST /api/btc/wallet/create — Neues Wallet (Owner only)."""
        if not self._require_owner():
            return
        if _btc_wallet_load():
            self._send_json({"error": "Wallet existiert bereits"}, 409)
            return
        w = _btc_wallet_create()
        if not w:
            self._send_json({"error": "Wallet konnte nicht erzeugt werden"}, 500)
            return
        wif_backup = w["wif"]
        _btc_wallet_save(w)
        self._send_json({
            "ok": True,
            "address": w["address"],
            "backup_key": wif_backup,
            "warning": "Diesen Schlüssel JETZT sichern! Er wird nur einmal angezeigt.",
        })

    def _handle_btc_wallet_import(self):
        """POST /api/btc/wallet/import — Bestehendes Wallet importieren (WIF oder Seed, Owner only)."""
        if not self._require_owner():
            return
        data = self._parse_json()
        wif = (data.get("wif") or "").strip()
        seed = (data.get("seed") or "").strip()

        if not wif and not seed:
            self._send_json({"error": "WIF oder Seed-Wörter erforderlich"}, 400)
            return

        try:
            from bitcoinutils.setup import setup
            from bitcoinutils.keys import PrivateKey
            setup("mainnet")

            if seed:
                # Seed-Wörter → WIF via BIP39/BIP84 (Native SegWit m/84'/0'/0'/0/0)
                from hdwallet import HDWallet
                from hdwallet.cryptocurrencies import Bitcoin
                from hdwallet.hds import BIP84HD
                from hdwallet.mnemonics import BIP39Mnemonic
                from hdwallet.derivations import BIP84Derivation
                mn = BIP39Mnemonic(mnemonic=seed)
                hd = HDWallet(cryptocurrency=Bitcoin, hd=BIP84HD, network="mainnet")
                hd.from_mnemonic(mn)
                hd.from_derivation(BIP84Derivation(coin_type=0, account=0, change="external-chain", address=0))
                wif = hd.wif()

            pk = PrivateKey.from_wif(wif)
            addr = pk.get_public_key().get_segwit_address().to_string()
        except Exception as e:
            self._send_json({"error": f"Import fehlgeschlagen: {e}"}, 400)
            return
        w = {"wif": wif, "address": addr, "mnemonic": seed if seed else "", "entries": [], "created_at": int(time.time())}
        _btc_wallet_save(w)
        self._send_json({"ok": True, "address": addr})

    def _handle_titles(self):
        """GET /api/titles — Titel-Register (Owner oder localhost)."""
        if not self._require_owner():
            return
        titles = _evaluate_titles()
        earned = [t for t in titles if t["earned"]]
        progress = [t for t in titles if not t["earned"]]
        self._send_json({
            "earned": earned,
            "progress": progress,
            "total_available": len(titles),
        })

    def _handle_btc_anchor_preview(self):
        """GET /api/btc/anchor/preview — Kosten-Vorschau (Owner only)."""
        if not self._require_owner():
            return
        fee_sats, sat_per_vb = _btc_estimate_fee_sats()
        btc_eur = _btc_get_price_eur()
        fee_eur = (fee_sats / 100_000_000) * btc_eur if btc_eur else 0
        try:
            with open(__file__, "rb") as f:
                code_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            code_hash = ""
        # Duplikat-Check
        w = _btc_wallet_load()
        already = any(e.get("code_hash") == code_hash and e.get("status") != "revoked" for e in w.get("entries", []))
        # Lizenz-Prerequisite (Firma + Nexus-URL + Logo müssen gesetzt sein)
        license_ok, license_missing = _license_anchor_prerequisites()
        self._send_json({
            "fee_sats": fee_sats,
            "sat_per_vb": sat_per_vb,
            "fee_eur": round(fee_eur, 4),
            "code_hash": code_hash,
            "version": VERSION,
            "already_anchored": already,
            "license_complete": license_ok,
            "license_missing": license_missing,
        })

    def _handle_btc_anchor(self):
        """POST /api/btc/anchor — Version in die Blockchain schreiben (Owner only)."""
        if not self._require_owner():
            return
        # Lizenz-Prerequisite: ohne Firma/Nexus-URL/Logo kein Anker
        # (sonst wäre "verifiziert durch" leer und der Anker sinnlos)
        license_ok, license_missing = _license_anchor_prerequisites()
        if not license_ok:
            self._send_json({
                "error": f"Lizenz-Daten unvollständig: {', '.join(license_missing)}. Erst im Lizenzen-Tab eintragen!",
                "license_missing": license_missing,
            }, 400)
            return
        try:
            with open(__file__, "rb") as f:
                code_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            self._send_json({"error": "Code-Hash nicht lesbar"}, 500)
            return
        # Duplikat-Check
        w = _btc_wallet_load()
        if any(e.get("code_hash") == code_hash for e in w.get("entries", [])):
            self._send_json({"error": "Dieser Code-Hash ist bereits verankert"}, 409)
            return
        entry = _btc_wallet_anchor_hash(code_hash, VERSION)
        if not entry:
            self._send_json({"error": "Eintrag fehlgeschlagen. Wallet leer oder nicht erreichbar?"}, 500)
            return
        self._send_json({"ok": True, "entry": entry})

    def _handle_btc_anchor_status(self):
        """GET /api/btc/anchor/status — Bestätigungsstatus der letzten pending TX."""
        if not self._require_owner():
            return
        w = _btc_wallet_load()
        pending = w.get("pending_anchor")
        if not pending or not pending.get("txid"):
            self._send_json({"status": "none"})
            return
        # Blockchain fragen
        tx_status = _btc_check_tx_confirmed(pending["txid"])
        if tx_status["confirmed"]:
            # Bestätigt! Status updaten + anchor.json schreiben
            pending["status"] = "confirmed"
            pending["block_height"] = tx_status["block_height"]
            pending["confirmed_at"] = tx_status["block_time"]
            # Entry in entries-Liste updaten
            for e in w.get("entries", []):
                if e.get("txid") == pending["txid"]:
                    e.update(pending)
                    break
            w.pop("pending_anchor", None)
            _btc_wallet_save(w)
            _btc_write_anchor_json(pending)
            # Auto-Default in Whitelist für die eigene on-chain-bestätigte Version
            _whitelist_auto_default_from_anchor(pending)
            nexus_log(f"✅ Verankerung bestätigt: v{pending.get('version', '?')} Block #{tx_status['block_height']}", "green")
            self._send_json({
                "status": "confirmed",
                "txid": pending["txid"],
                "block_height": tx_status["block_height"],
                "confirmed_at": tx_status["block_time"],
            })
        else:
            elapsed = int(time.time()) - pending.get("timestamp", int(time.time()))
            cycle = elapsed // 3600 + 1
            self._send_json({
                "status": "pending",
                "txid": pending["txid"],
                "elapsed_sec": elapsed,
                "cycle": min(cycle, 4),
            })

    def _handle_btc_revoke_preview(self):
        """GET /api/btc/revoke/preview — Kosten-Vorschau + aktive Versionen für Widerruf (Owner only)."""
        if not self._require_owner():
            return
        anchor = _btc_read_anchor_json()
        if not anchor or not anchor.get("code_hash"):
            self._send_json({"error": "Keine Verankerung vorhanden"}, 404)
            return
        # Alle aktiven (confirmed + nicht revoked) Versionen aus History sammeln
        history = anchor.get("history") or []
        active_versions = []
        for entry in history:
            if entry.get("status") == "confirmed" and not entry.get("revoked"):
                active_versions.append({
                    "version": entry.get("version", "?"),
                    "code_hash": entry.get("code_hash", ""),
                    "txid": entry.get("txid", ""),
                    "timestamp": entry.get("timestamp", 0),
                })
        # Auch aktuellen Top-Level-Eintrag prüfen (falls nicht in history)
        if not anchor.get("revoked") and anchor.get("txid"):
            top_hash = anchor.get("code_hash", "")
            if not any(v["code_hash"] == top_hash for v in active_versions):
                active_versions.insert(0, {
                    "version": anchor.get("version", "?"),
                    "code_hash": top_hash,
                    "txid": anchor.get("txid", ""),
                    "timestamp": anchor.get("timestamp", 0),
                })
        if not active_versions:
            self._send_json({"error": "Keine aktiven Versionen zum Widerrufen"}, 404)
            return
        fee_sats, sat_per_vb = _btc_estimate_fee_sats()
        btc_eur = _btc_get_price_eur()
        fee_eur = (fee_sats / 100_000_000) * btc_eur if btc_eur else 0
        self._send_json({
            "fee_sats": fee_sats,
            "sat_per_vb": sat_per_vb,
            "fee_eur": round(fee_eur, 4),
            "active_versions": active_versions,
        })

    def _handle_btc_revoke_status(self):
        """GET /api/btc/revoke/status — Bestätigungsstatus der letzten pending Revoke-TX."""
        if not self._require_owner():
            return
        w = _btc_wallet_load()
        pending = w.get("pending_revoke")
        if not pending or not pending.get("txid"):
            self._send_json({"status": "none"})
            return
        tx_status = _btc_check_tx_confirmed(pending["txid"])
        if tx_status["confirmed"]:
            pending["status"] = "confirmed"
            pending["block_height"] = tx_status["block_height"]
            pending["confirmed_at"] = tx_status["block_time"]
            # Revocations-Liste updaten
            for r in w.get("revocations", []):
                if r.get("txid") == pending["txid"]:
                    r.update(pending)
                    break
            w.pop("pending_revoke", None)
            _btc_wallet_save(w)
            nexus_log(f"✅ Widerruf bestätigt: {pending.get('code_hash','?')[:16]}… Block #{tx_status['block_height']}", "green")
            self._send_json({
                "status": "confirmed",
                "txid": pending["txid"],
                "block_height": tx_status["block_height"],
                "confirmed_at": tx_status["block_time"],
                "code_hash": pending.get("code_hash", ""),
            })
        else:
            elapsed = int(time.time()) - pending.get("timestamp", int(time.time()))
            cycle = elapsed // 3600 + 1
            self._send_json({
                "status": "pending",
                "txid": pending["txid"],
                "elapsed_sec": elapsed,
                "cycle": min(cycle, 4),
                "code_hash": pending.get("code_hash", ""),
            })

    def _handle_btc_revoke(self):
        """POST /api/btc/revoke — Gezielte Version widerrufen (Owner only, 2FA).
        Body: {totp_code, code_hash} — code_hash bestimmt WELCHE Version widerrufen wird.
        """
        if not self._require_owner():
            return
        data = self._parse_json()
        totp_code = data.get("totp_code", "")
        target_hash = (data.get("code_hash") or "").strip().lower()
        if not _identity or not totp_code:
            self._send_json({"error": "2FA-Code erforderlich"}, 400)
            return
        if not target_hash:
            self._send_json({"error": "code_hash erforderlich (welche Version?)"}, 400)
            return
        if not totp_verify(_identity.get("totp_secret", ""), totp_code):
            self._send_json({"error": "Falscher 2FA-Code"}, 401)
            return
        anchor = _btc_read_anchor_json()
        if not anchor:
            self._send_json({"error": "Keine Verankerung vorhanden"}, 404)
            return
        # Prüfen ob die gewählte Version in der History existiert und aktiv ist
        history = anchor.get("history") or []
        target_entry = None
        for entry in history:
            if (entry.get("code_hash") or "").lower() == target_hash:
                target_entry = entry
                break
        if not target_entry:
            self._send_json({"error": f"Version mit Hash {target_hash[:16]}… nicht gefunden"}, 404)
            return
        if target_entry.get("revoked"):
            self._send_json({"error": "Diese Version ist bereits widerrufen"}, 409)
            return
        result = _btc_wallet_revoke(target_hash)
        if not result:
            self._send_json({"error": "Revocation fehlgeschlagen. Wallet leer?"}, 500)
            return
        # History-Eintrag als revoked markieren (anchor.json)
        target_entry["revoked"] = True
        target_entry["revoked_at"] = int(time.time())
        target_entry["revoke_txid"] = result["txid"]
        # Wenn es die aktuelle Top-Level-Version ist, auch dort revoked setzen
        if (anchor.get("code_hash") or "").lower() == target_hash:
            anchor["revoked"] = True
            anchor["revoked_at"] = int(time.time())
            anchor["revoke_txid"] = result["txid"]
        _btc_write_anchor_json_raw(anchor)
        # Wallet-Entries auch als revoked markieren (für Versions-Übersicht)
        w = _btc_wallet_load()
        if w:
            for we in w.get("entries", []):
                if (we.get("code_hash") or "").lower() == target_hash:
                    we["revoked"] = True
                    we["revoked_at"] = int(time.time())
                    we["revoke_txid"] = result["txid"]
            _btc_wallet_save(w)
        nexus_log(f"🔴 Version widerrufen: {target_entry.get('version','?')} (Hash {target_hash[:16]}…)", "red")
        self._send_json({"ok": True, "revoke_txid": result["txid"], "version": target_entry.get("version", "?")})

    def _handle_widget_shield(self):
        """GET /widget/shield?shinpai_id=XXX — Self-contained Shield-Widget als HTML.
        Wird von der Kneipe (und anderen) als iframe eingebettet. 1:1 identisch mit dem
        Dashboard-Shield. Keine Auth nötig, öffentlich."""
        from urllib.parse import urlparse, parse_qs as _pqs2
        qs = _pqs2(urlparse(self.path).query)
        sid = (qs.get("shinpai_id") or [""])[0].strip()
        # Daten sammeln (gleiche Logik wie _handle_public_shield)
        vlevel = 0
        if sid:
            if _identity and _identity.get("shinpai_id") == sid:
                vlevel = int(_identity.get("verification_level", 0))
            else:
                for _un2, _ud2 in _users.items():
                    if _ud2.get("shinpai_id") == sid:
                        vlevel = int(_ud2.get("verification_level", 0))
                        break
        active_subs_js = "[]"
        if sid and vault_is_unlocked():
            _now_ws = int(time.time())
            _asubs = []
            for lic in _license_load_vault(LICENSES_RECEIVED_VAULT):
                if lic.get("subject", {}).get("shinpai_id") != sid:
                    continue
                if int(lic.get("valid_until", 0)) <= _now_ws:
                    continue
                for _wc, _wss in (lic.get("amt_categories") or {}).items():
                    for _ws in _wss:
                        _asubs.append(f"{_wc}/{_ws}")
            active_subs_js = json.dumps(list(set(_asubs)))
        # Shield-Bild URL
        pub = (_public_url or "").rstrip("/")
        shield_std = f"{pub}/ShinNexus-Shield.png" if pub else "/ShinNexus-Shield.png"
        shield_edel = f"{pub}/ShinNexus-Shield-edel.png?v=4" if pub else "/ShinNexus-Shield-edel.png?v=4"
        # HTML Widget rendern
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>*{{margin:0;padding:0;box-sizing:border-box;}}body{{background:transparent;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100%;overflow:visible;}}</style>
</head><body>
<img id="s" src="{shield_std}" style="width:40px;height:40px;display:block;">
<div id="l" style="font-size:8px;font-weight:bold;color:#665540;margin-top:2px;text-align:center;font-family:sans-serif;">ShinNexus</div>
<script>
var vl={vlevel},as={active_subs_js};
var img=document.getElementById('s'),lb=document.getElementById('l');
if(vl>=3){{
  img.src='{shield_edel}';
  var gc=['#ff9090','#ff6060','#ee4040','#c82828','#8e1818','#ffe488','#f5c858','#d4a850','#a6822c','#6e5410','#88e896','#5bc870','#4caf50','#358a3a','#1b5e20','#9ed4f0','#7ab8e0','#5a9ed0','#3a7cbf','#1a5a9f','#d0a0ff','#b082ff','#aa78ff','#7e4ad0','#4e1c88'];
  var gi=0;setInterval(function(){{var c=gc[gi%25],c2=gc[(gi+1)%25];img.style.filter='drop-shadow(0 0 8px '+c+') drop-shadow(0 0 4px '+c2+') drop-shadow(0 0 14px '+c+')';gi=(gi+1)%25;}},320);
  lb.style.color='#d4a850';lb.textContent='Amtlich bestätigt';
}}else if(vl>=2){{
  img.style.filter='drop-shadow(0 0 6px #d4a850) drop-shadow(0 0 12px #d4a850)';
  lb.style.color='#d4a850';lb.textContent='Verifiziert';
}}else if(vl>=1){{
  img.style.filter='drop-shadow(0 0 6px #a33333) drop-shadow(0 0 12px #a33333)';
  lb.style.color='#a33333';lb.textContent='18+';
}}else{{
  img.style.filter='grayscale(100%)';lb.style.color='#665540';lb.textContent='ShinNexus';
}}
</script></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _handle_status(self):
        tunnel_running = _frpc_process is not None and _frpc_process.poll() is None
        cf_running = _cloudflared_process is not None and _cloudflared_process.poll() is None
        self._send_json({
            "app": APP_NAME,
            "version": VERSION,
            "vault_unlocked": vault_is_unlocked(),
            "has_account": _identity is not None,
            "shinpai_id": _identity["shinpai_id"] if _identity else None,
            "name": _identity["name"] if _identity else None,
            "hive_count": len(_hive_stamps),
            "keys_loaded": _pq_keys is not None,
            "totp_active": bool(_identity and _identity.get("totp_confirmed")),
            "email_verified": bool(_identity and _identity.get("email_verified")),
            "smtp_configured": smtp_configured(),
            "tls_active": _tls_active,
            "tunnel_active": tunnel_running,
            "cloudflare_active": cf_running,
            "public_url": _public_url,
            "system_vault_unlocked": system_vault_is_unlocked(),
            "stripe_publishable_key": load_config().get("stripe_publishable_key", ""),
            "verification_providers": _get_available_providers(),
        })

    # ── Handler: Verification (N1-N6) ──────────────────────────────

    def _handle_verify_status(self):
        """GET /api/verify/status — Verifikations-Status abrufen (auth-basiert).
        Liefert auch Karten-Info live von Stripe (nicht gespeichert!)."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        status = get_verification_status(sid)
        status["available_providers"] = _get_available_providers()
        # Card-Replacement-Flag: effective_level=0 während Austausch,
        # verification_level bleibt erhalten für späteres Zurücksetzen.
        target_for_flag = None
        if _identity and _identity.get("shinpai_id") == sid:
            target_for_flag = _identity
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    target_for_flag = udata
                    break
        # Auto-Upgrade: wenn User Amt-Lizenzen hat aber verification_level < 3 → korrigieren
        # (Migration für Lizenzen die mit altem Code erstellt wurden)
        if target_for_flag and int(target_for_flag.get("verification_level", 0)) < 3:
            all_lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
            has_amt = any(
                l.get("subject", {}).get("shinpai_id") == sid
                and l.get("realized_by", "") not in ("stripe", "veriff", "")
                and int(l.get("valid_until", 0)) > int(time.time())
                for l in all_lics
            )
            if has_amt:
                target_for_flag["verification_level"] = 3
                target_for_flag["verified_by"] = "amt"
                target_for_flag["verified_at"] = int(time.time())
                if target_for_flag is _identity:
                    _save_identity()
                else:
                    _save_users()
                status["verification_level"] = 3
                nexus_log(f"🏅 Auto-Upgrade: Verification-Level auf 3 (bestehende Amt-Lizenzen)", "green")
        pending = bool((target_for_flag or {}).get("card_pending_replacement", False))
        saved_lvl = int((target_for_flag or {}).get("saved_verification_level_before_card_replace", 0))
        status["card_pending_replacement"] = pending
        status["saved_verification_level"] = saved_lvl if pending else 0
        # effective_level = 0 während Austausch, sonst verification_level
        status["effective_level"] = 0 if pending else int(status.get("verification_level", 0))
        # Separate Flags für Kind/Bot/Erwachsen-Matrix (unabhängig vom Level)
        rec = target_for_flag or {}
        status["verified_stripe"] = bool(rec.get("verified_stripe"))
        status["id_verified"] = bool(rec.get("id_verified"))
        status["stripe_verified_at"] = rec.get("stripe_verified_at")
        status["perso_verified_at"] = rec.get("perso_verified_at")
        # Aktive Amt-Subklassen für Shield-Glow (25-Farben-System)
        active_subs = []
        if vault_is_unlocked():
            _now_as = int(time.time())
            for lic in _license_load_vault(LICENSES_RECEIVED_VAULT):
                if lic.get("subject", {}).get("shinpai_id") != sid:
                    continue
                if int(lic.get("valid_until", 0)) <= _now_as:
                    continue
                for _ac, _asubs in (lic.get("amt_categories") or {}).items():
                    for _as in _asubs:
                        active_subs.append(f"{_ac}/{_as}")
        status["active_subclasses"] = list(set(active_subs))
        # Pending Sessions für diesen User finden
        _cleanup_verification_sessions()
        pending = []
        for sess_id, vs in _verification_sessions.items():
            if vs.get("shinpai_id") == sid and vs.get("status") == "pending":
                pending.append({
                    "provider": vs.get("provider", ""),
                    "level": vs.get("level", 0),
                    "started": vs.get("created", 0),
                    "age_seconds": int(time.time()) - vs.get("created", 0),
                })
        status["pending"] = pending

        # Karten-Info LIVE von Stripe holen (nichts gespeichert im Nexus)
        status["card"] = None
        cust_id = ""
        if _identity and _identity.get("shinpai_id") == sid:
            cust_id = _identity.get("stripe_customer_id", "")
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    cust_id = udata.get("stripe_customer_id", "")
                    break

        cfg = load_config()
        if cust_id and HAS_STRIPE and cfg.get("stripe_secret_key"):
            try:
                _stripe_mod.api_key = cfg["stripe_secret_key"]
                cust = _stripe_mod.Customer.retrieve(cust_id)
                # Stripe-Objekte mit getattr ansprechen, nicht .get()
                pm_id = None
                inv_settings = getattr(cust, "invoice_settings", None)
                if inv_settings is not None:
                    pm_id = getattr(inv_settings, "default_payment_method", None)
                if not pm_id:
                    pms = _stripe_mod.PaymentMethod.list(customer=cust_id, type="card", limit=1)
                    if pms.data:
                        pm_id = pms.data[0].id
                if pm_id:
                    pm = _stripe_mod.PaymentMethod.retrieve(pm_id)
                    card = getattr(pm, "card", None)
                    if card is not None:
                        status["card"] = {
                            "brand": getattr(card, "brand", "") or "",
                            "last4": getattr(card, "last4", "") or "",
                            "exp_month": getattr(card, "exp_month", 0) or 0,
                            "exp_year": getattr(card, "exp_year", 0) or 0,
                        }
            except Exception as ce:
                nexus_log(f"⚠️ Stripe Card-Info fehlgeschlagen: {type(ce).__name__}: {ce}", "yellow")

        self._send_json(status)

    def _handle_verify_providers(self):
        """GET /api/verify/providers — Verfügbare Provider auflisten."""
        self._send_json({"providers": _get_available_providers()})

    def _handle_verify_ausweis(self):
        """GET /api/verify/ausweis — PQ-signierten Nexus-Ausweis abrufen (auth-basiert)."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        ausweis = _sign_verification(sid)
        if "error" in ausweis:
            self._send_json(ausweis, 400)
        else:
            self._send_json(ausweis)

    def _handle_verify_start(self):
        """POST /api/verify/start — Verifikations-Flow starten.
        Body: {provider: "stripe"} — startet SetupIntent."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        provider_name = data.get("provider", "stripe")

        provider = _VERIFICATION_PROVIDERS.get(provider_name)
        if not provider:
            self._send_json({"error": f"Unbekannter Provider: {provider_name}"}, 400)
            return
        if not provider.available():
            self._send_json({
                "error": f"Provider '{provider_name}' nicht verfügbar",
                "hint": "Konfiguration prüfen (stripe_secret_key in Config)" if provider_name == "stripe" else "",
            }, 400)
            return

        sid = session.get("shinpai_id", "")
        # Schon auf diesem Level verifiziert?
        # ABER: Wenn Kartentausch pending ist und Stripe angefragt wird, den Check überspringen
        # (User muss Stufe 1 neu durchlaufen um das Flag aufzuheben, auch wenn Level > 1)
        current = get_verification_status(sid)
        _target_check = None
        if _identity and _identity.get("shinpai_id") == sid:
            _target_check = _identity
        else:
            for _u, _ud in _users.items():
                if _ud.get("shinpai_id") == sid:
                    _target_check = _ud
                    break
        _card_pending = bool((_target_check or {}).get("card_pending_replacement", False))
        skip_level_check = (provider_name == "stripe" and _card_pending)
        if not skip_level_check and current["verification_level"] >= provider.level:
            self._send_json({
                "error": "Bereits auf diesem Level verifiziert",
                "verification_level": current["verification_level"],
            }, 409)
            return

        _cleanup_verification_sessions()
        cfg = load_config()
        result = provider.start(sid, cfg)

        if "error" in result:
            self._send_json(result, 500)
        else:
            self._send_json(result)

    def _handle_verify_callback(self):
        """POST /api/verify/callback — Verifikation bestätigen.
        Body: {session_id: "xxx"} — prüft ob SetupIntent erfolgreich."""
        session = self._require_auth()
        if not session:
            return
        data = self._parse_json()
        session_id = data.get("session_id", "")

        if not session_id:
            self._send_json({"error": "session_id erforderlich"}, 400)
            return

        vs = _verification_sessions.get(session_id)
        if not vs:
            self._send_json({"error": "Unbekannte oder abgelaufene Session"}, 404)
            return

        # Session gehört dem eingeloggten User?
        if vs["shinpai_id"] != session.get("shinpai_id", ""):
            self._send_json({"error": "Session gehört anderem User"}, 403)
            return

        provider = _VERIFICATION_PROVIDERS.get(vs["provider"])
        if not provider:
            self._send_json({"error": "Provider nicht verfügbar"}, 500)
            return

        result = provider.callback(session_id, data)
        if "error" in result:
            self._send_json(result, 400)
        else:
            self._send_json(result)

    def _handle_veriff_webhook(self):
        """POST /api/verify/veriff-webhook — Empfängt Decision/Event-Webhooks von Veriff.
        Veriff hat zwei Webhook-Typen:
        1) Event-Webhook: top-level action/code/vendorData (z.B. action=submitted)
        2) Decision-Webhook: verification.status/code (z.B. status=approved)
        Manche Events haben top-level status=success/fail.
        Wir matchen über vendorData (Format: nexus_session_id:shinpai_id)."""
        data = self._parse_json()
        if not data:
            self._send_json({"error": "kein body"}, 400)
            return

        verif = data.get("verification") or {}
        # vendorData kann an verschiedenen Stellen sein
        vendor_raw = (
            verif.get("vendorData")
            or data.get("vendorData")
            or data.get("vendor_data")
            or ""
        )
        nexus_session_id = vendor_raw.split(":", 1)[0] if vendor_raw else ""

        # Status-Felder aus allen möglichen Stellen sammeln
        v_status = (verif.get("status") or "").lower()
        d_status = (data.get("status") or "").lower()
        d_action = (data.get("action") or "").lower()
        d_code = data.get("code") or verif.get("code")
        veriff_session_id = verif.get("id") or data.get("id") or ""

        # DSGVO: KEINE Session-IDs oder Status-Details in Logs
        nexus_log(f"📥 Veriff-Webhook empfangen", "cyan")

        if not nexus_session_id:
            self._send_json({"error": "vendorData fehlt"}, 400)
            return

        vs = _verification_sessions.get(nexus_session_id)
        if not vs:
            nexus_log(f"⚠️ Veriff-Webhook: unbekannte Session", "yellow")
            self._send_json({"error": "unknown session"}, 404)
            return

        if vs.get("provider") != "veriff":
            self._send_json({"error": "wrong provider"}, 400)
            return

        # Erfolg-Mapping: Veriff nutzt verschiedene Wörter
        # - verification.status = "approved" (V1 Decision)
        # - status = "success" (Real-time / V2)
        # - code 9001 = approved (Veriff-Code)
        is_approved = (
            v_status == "approved"
            or d_status == "success"
            or d_code == 9001
        )
        is_failed = (
            v_status in ("declined", "resubmission_requested", "expired", "abandoned")
            or d_status in ("fail", "declined", "expired")
            or d_code in (9102, 9103, 9104)
        )

        if is_approved:
            if vs["status"] != "verified":
                vs["status"] = "verified"
                # Der Event-Webhook enthält keine Dokumentdaten.
                # Zusatz-API-Call an /v1/sessions/{id}/decision holt das echte Perso/Pass-Ablaufdatum.
                real_expiry_ts = None
                dec_result = None
                try:
                    cfg_lv = load_config()
                    api_key_lv = cfg_lv.get("veriff_api_key", "")
                    api_url_lv = cfg_lv.get("veriff_api_url", "https://stationapi.veriff.com/v1")
                    if api_key_lv and veriff_session_id:
                        dec_req = urllib.request.Request(
                            f"{api_url_lv}/sessions/{veriff_session_id}/decision",
                            headers={"Content-Type": "application/json", "X-AUTH-CLIENT": api_key_lv},
                        )
                        with urllib.request.urlopen(dec_req, timeout=15) as resp:
                            dec_result = json.loads(resp.read())
                        dec_ver = dec_result.get("verification") or {}
                        dec_doc = dec_ver.get("document") or {}
                        doe = (
                            dec_doc.get("validUntil")
                            or dec_doc.get("valid_until")
                            or dec_doc.get("dateOfExpiry")
                            or dec_doc.get("expiryDate")
                        )
                        if doe:
                            _dt = datetime.strptime(str(doe)[:10], "%Y-%m-%d")
                            real_expiry_ts = int(_dt.timestamp())
                            # KEIN Logging des Dokument-Datums (DSGVO)
                            nexus_log(f"🪪 Veriff Dokument validUntil gelesen (in Vault gespeichert)", "cyan")
                        else:
                            nexus_log(f"⚠️ Veriff Decision ohne validUntil Feld", "yellow")
                except Exception:
                    nexus_log(f"⚠️ Veriff-Decision-Abfrage fehlgeschlagen", "yellow")
                # Perso-Hash aus Decision-Daten — First-come-first-serve Zweit-Account-Erkennung
                perso_hash = _build_perso_hash(dec_result or {})
                _apply_verification(vs["shinpai_id"], "veriff", 2, real_expiry_ts=real_expiry_ts, perso_hash=perso_hash)
                nexus_log(f"✅ VERIFF VERIFIED via Webhook: {vs['shinpai_id']}", "green")
        elif is_failed:
            vs["status"] = "failed"
            nexus_log(f"❌ VERIFF FAILED via Webhook: {vs['shinpai_id']} (v.status={v_status} d.status={d_status} code={d_code})", "yellow")
        else:
            # Zwischenstatus (started/submitted/...) — noch kein Endergebnis
            nexus_log(f"📥 Veriff-Webhook: Zwischenstatus action={d_action} status={v_status or d_status}, warte weiter", "dim")

        self._send_json({"ok": True})

    def _handle_verify_reset(self):
        """POST /api/verify/reset — Komplette Verifikation zurücksetzen.
        Setzt verification_level auf 0, entfernt Stripe-Customer-ID,
        cancelt laufende Pre-Auths. Eingeloggter User resettet sich selbst."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        if not sid:
            self._send_json({"error": "Keine Shinpai-ID in Session"}, 400)
            return

        cfg = load_config()

        # 1. Laufende Pre-Auths canceln
        cancelled_pi = []
        for sess_id, vs in list(_verification_sessions.items()):
            if vs.get("shinpai_id") != sid:
                continue
            pi_id = vs.get("stripe_payment_intent_id", "")
            if pi_id and HAS_STRIPE and cfg.get("stripe_secret_key"):
                try:
                    _stripe_mod.api_key = cfg["stripe_secret_key"]
                    _stripe_mod.PaymentIntent.cancel(pi_id)
                    cancelled_pi.append(pi_id)
                    nexus_log(f"💳 Reset: Pre-Auth gecancelt {pi_id}", "yellow")
                except Exception as ce:
                    nexus_log(f"⚠️ Reset: Cancel fehlgeschlagen {pi_id}: {ce}", "yellow")
            del _verification_sessions[sess_id]

        # 2. Stripe-Customer löschen (optional, weicher Reset)
        old_customer_id = ""
        target = None
        if _identity and _identity.get("shinpai_id") == sid:
            target = _identity
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    target = udata
                    break

        if target is None:
            self._send_json({"error": "User nicht gefunden"}, 404)
            return

        old_customer_id = target.get("stripe_customer_id", "")
        if old_customer_id and HAS_STRIPE and cfg.get("stripe_secret_key"):
            try:
                _stripe_mod.api_key = cfg["stripe_secret_key"]
                _stripe_mod.Customer.delete(old_customer_id)
                nexus_log(f"💳 Reset: Stripe Customer gelöscht", "yellow")
            except Exception as ce:
                nexus_log(f"⚠️ Reset: Customer-Delete fehlgeschlagen: {ce}", "yellow")

        # 3. Verifikations-Felder zurücksetzen
        target["verification_level"] = 0
        target["verified_at"] = None
        target["verified_by"] = None
        target["stripe_customer_id"] = ""
        # Card-Replacement-Flags räumen (falls noch gesetzt)
        target.pop("card_pending_replacement", None)
        target.pop("saved_verification_level_before_card_replace", None)

        if target is _identity:
            _save_identity()
        else:
            _save_users()

        # 4. ALLE Lizenzen dieses Users aus dem Vault entfernen
        # Begründung: Reset ist ein expliziter Admin-Akt des eigenen Users,
        # er weiß was er tut. Lizenzen ohne Verifikation wären Geister-Einträge.
        lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
        before = len(lics)
        lics = [l for l in lics if l.get("subject", {}).get("shinpai_id") != sid]
        removed = before - len(lics)
        if removed:
            _license_save_vault(LICENSES_RECEIVED_VAULT, lics)
            nexus_log(f"🗑️ Reset: {removed} Lizenz(en) entfernt", "yellow")

        # 5. Amt-Watchlist komplett leeren (nur Owner hat eine Watchlist).
        # Reset ist die "Große Gummi-Taste" — abonnierte Ämter, offene Anträge,
        # Beantragen-Status, Nachfragen, Beschwerden: ALLES weg.
        # Re-Subscription unangetastet: Wer später ein Amt neu abonniert, startet
        # mit sauberem pending. Das gilt bewusst nicht hier, hier wird echt gelöscht.
        amt_removed = 0
        if target is _identity:
            watchlist = _amt_watchlist_load()
            amt_removed = len(watchlist)
            if amt_removed > 0:
                _amt_watchlist_save([])
                nexus_log(f"🗑️ Reset: {amt_removed} Amt-Abonnement(s) + Anträge entfernt", "yellow")

        nexus_log(f"🔄 Verifikation komplett zurückgesetzt", "cyan")
        self._send_json({
            "ok": True,
            "verification_level": 0,
            "cancelled_payments": len(cancelled_pi),
            "stripe_customer_removed": bool(old_customer_id),
            "licenses_removed": removed,
            "amt_subscriptions_removed": amt_removed,
        })

    def _handle_verify_card_replace(self):
        """POST /api/verify/card-replace — Nur die Kreditkarte tauschen ohne Stufen-Verlust.
        Löscht Stripe-Customer, setzt card_pending_replacement=True.
        verification_level BLEIBT gespeichert, wird aber effektiv als 0 behandelt bis neue Karte da ist.
        Nach erfolgreichem Stripe-Verify wird das Flag zurückgesetzt und alle Stufen sind wieder aktiv."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        if not sid:
            self._send_json({"error": "Keine Shinpai-ID in Session"}, 400)
            return
        cfg = load_config()
        # Target finden (Owner oder User)
        target = None
        if _identity and _identity.get("shinpai_id") == sid:
            target = _identity
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid:
                    target = udata
                    break
        if target is None:
            self._send_json({"error": "User nicht gefunden"}, 404)
            return
        current_level = int(target.get("verification_level", 0))
        if current_level < 1:
            self._send_json({"error": "Keine aktive Verifikation zum Tauschen vorhanden"}, 400)
            return
        # Laufende Pre-Auths canceln (nur Stripe)
        cancelled_pi = []
        for sess_id, vs in list(_verification_sessions.items()):
            if vs.get("shinpai_id") != sid:
                continue
            if vs.get("provider") != "stripe":
                continue
            pi_id = vs.get("stripe_payment_intent_id", "")
            if pi_id and HAS_STRIPE and cfg.get("stripe_secret_key"):
                try:
                    _stripe_mod.api_key = cfg["stripe_secret_key"]
                    _stripe_mod.PaymentIntent.cancel(pi_id)
                    cancelled_pi.append(pi_id)
                except Exception as ce:
                    nexus_log(f"⚠️ CardReplace: Cancel fehlgeschlagen {pi_id}: {ce}", "yellow")
            del _verification_sessions[sess_id]
        # Alte Stripe-Karte löschen
        old_customer_id = target.get("stripe_customer_id", "")
        if old_customer_id and HAS_STRIPE and cfg.get("stripe_secret_key"):
            try:
                _stripe_mod.api_key = cfg["stripe_secret_key"]
                _stripe_mod.Customer.delete(old_customer_id)
                nexus_log(f"💳 CardReplace: Stripe Customer gelöscht", "cyan")
            except Exception as ce:
                nexus_log(f"⚠️ CardReplace: Customer-Delete fehlgeschlagen: {ce}", "yellow")
        # Flag setzen, Level + Verified-At speichern fürs spätere Zurücksetzen
        # WICHTIG: verification_level bleibt unverändert, effective_level=0 wird beim Status ausgerechnet
        if not target.get("card_pending_replacement"):
            target["saved_verification_level_before_card_replace"] = current_level
        target["card_pending_replacement"] = True
        target["stripe_customer_id"] = ""
        if target is _identity:
            _save_identity()
        else:
            _save_users()
        # Alte Stripe-Lizenz entfernen (sie gehörte zur alten Karte)
        lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
        before_cnt = len(lics)
        lics = [l for l in lics if not (
            l.get("subject", {}).get("shinpai_id") == sid and
            l.get("realized_by") == "stripe"
        )]
        removed_cnt = before_cnt - len(lics)
        if removed_cnt:
            _license_save_vault(LICENSES_RECEIVED_VAULT, lics)
            nexus_log(f"🗑️ Kartentausch: {removed_cnt} alte Stripe-Lizenz(en) entfernt", "yellow")
        nexus_log(f"💳 Kartentausch gestartet für {sid}, Stufen {current_level} geparkt", "cyan")
        self._send_json({
            "ok": True,
            "card_pending_replacement": True,
            "saved_verification_level": current_level,
            "cancelled_payments": len(cancelled_pi),
            "licenses_removed": removed_cnt,
        })

    def _handle_stripe_config(self):
        """POST /api/stripe/config — Stripe API-Key konfigurieren (Owner only, TLS-geschützt).
        Body: {stripe_secret_key: "sk_...", stripe_publishable_key: "pk_..."}"""
        session = self._require_auth()
        if not session:
            return
        # Owner-Check
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner darf Stripe konfigurieren"}, 403)
            return

        data = self._parse_json()
        sk = data.get("stripe_secret_key", "")
        pk = data.get("stripe_publishable_key", "")

        if not sk:
            self._send_json({"error": "stripe_secret_key erforderlich"}, 400)
            return

        cfg = load_config()
        cfg["stripe_secret_key"] = sk
        if pk:
            cfg["stripe_publishable_key"] = pk
        save_config(cfg)
        nexus_log("✅ Stripe API-Keys konfiguriert", "green")
        self._send_json({"ok": True, "stripe_configured": True})

    def _handle_server_status(self):
        """GET /api/server/status — Server-Konfig Status (Owner only, maskiert)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        cfg = load_config()
        def _mask(val: str, keep: int = 8) -> str:
            if not val:
                return ""
            if len(val) <= keep:
                return val + "..."
            return val[:keep] + "..."
        # SMTP (verschachtelt: cfg["smtp"] = {host, port, user, password, from})
        _smtp_cfg = cfg.get("smtp", {})
        smtp = {
            "configured": smtp_configured(),
            "host": _smtp_cfg.get("host", ""),
            "port": _smtp_cfg.get("port", ""),
            "user": _smtp_cfg.get("user", ""),
            "from_addr": _smtp_cfg.get("from", ""),
            "password_set": bool(_smtp_cfg.get("password", "")) or _smtp_cfg.get("_pw_in_vault", False),
        }
        # Stripe
        stripe_cfg = {
            "configured": bool(cfg.get("stripe_secret_key", "")),
            "publishable_key": cfg.get("stripe_publishable_key", ""),
            "secret_key_masked": _mask(cfg.get("stripe_secret_key", ""), 12),
        }
        # Veriff
        veriff_cfg = {
            "enabled": cfg.get("veriff_enabled", True),
            "configured": bool(cfg.get("veriff_api_key", "") and cfg.get("veriff_enabled", True)),
            "api_key_masked": _mask(cfg.get("veriff_api_key", ""), 8),
            "secret_set": bool(cfg.get("veriff_shared_secret", "")),
            "price_eur": cfg.get("veriff_price_eur", 3.0),
        }
        # Public URL
        public_cfg = {
            "url": cfg.get("public_url", ""),
        }
        self._send_json({"smtp": smtp, "stripe": stripe_cfg, "veriff": veriff_cfg, "public": public_cfg})

    # ── Federation: Amt-Listen-Abos (Phase 1 Step 2) ─────────────────
    def _handle_amt_lists_get(self):
        """GET /api/amt-lists — Liste aller abonnierten Amt-Listen (Owner only)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        self._send_json({"subscriptions": amt_subs_list()})

    def _handle_amt_lists_amter(self):
        """GET /api/amt-lists/amter — Aggregierte Liste aller Ämter aus allen aktiven Abos."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        amter = amt_subs_all_amter()
        self._send_json({"count": len(amter), "amter": amter})

    def _handle_amt_lists_subscribe(self):
        """POST /api/amt-lists/subscribe — Neues Abo anlegen.
        Body: {url: "https://...", name?: "...", trust_level?: 1-5}"""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        raw_input = (data.get("url") or "").strip()
        if not raw_input:
            self._send_json({"error": "url oder domain erforderlich"}, 400)
            return
        # Convention over Configuration: Domain reicht, Standardpfad wird ergänzt
        url = _amt_subs_normalize_url(raw_input)
        if not url.startswith("http://") and not url.startswith("https://"):
            self._send_json({"error": "URL konnte nicht normalisiert werden"}, 400)
            return
        subs = _amt_subs_load()
        # Duplikat-Check
        for existing in subs:
            if existing.get("url") == url:
                self._send_json({"error": "Diese URL ist bereits abonniert", "id": existing.get("id")}, 409)
                return
        trust = int(data.get("trust_level", 1))
        if trust < 1:
            trust = 1
        if trust > 5:
            trust = 5
        sub = {
            "id": _amt_subs_new_id(),
            "url": url,
            "name": (data.get("name") or "").strip() or None,
            "enabled": True,
            "added_at": int(time.time()),
            "last_fetched": None,
            "last_status": "pending",
            "last_count": 0,
            "trust_level": trust,
            "cache": None,
        }
        # Direkt ersten Fetch versuchen
        _amt_subs_refresh_one(sub)
        subs.append(sub)
        if not _amt_subs_save(subs):
            self._send_json({"error": "Vault-Schreibfehler"}, 500)
            return
        nexus_log(f"✅ Amt-Liste abonniert: {url} — Status: {sub['last_status']}", "green")
        # Antwort ohne cache-Feld
        light = {k: v for k, v in sub.items() if k != "cache"}
        self._send_json({"ok": True, "subscription": light})

    def _handle_amt_lists_remove(self):
        """POST /api/amt-lists/remove — Abo entfernen.
        Body: {id: "sub_..."}"""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        sub_id = (data.get("id") or "").strip()
        if not sub_id:
            self._send_json({"error": "id erforderlich"}, 400)
            return
        subs = _amt_subs_load()
        before = len(subs)
        subs = [s for s in subs if s.get("id") != sub_id]
        if len(subs) == before:
            self._send_json({"error": "ID nicht gefunden"}, 404)
            return
        if not _amt_subs_save(subs):
            self._send_json({"error": "Vault-Schreibfehler"}, 500)
            return
        nexus_log(f"🗑️ Amt-Liste entfernt: {sub_id}", "yellow")
        self._send_json({"ok": True, "id": sub_id})

    def _handle_amt_lists_refresh(self):
        """POST /api/amt-lists/refresh — Abo(s) manuell neu fetchen.
        Body: {id?: "sub_..."}  (ohne id = alle)"""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        target_id = (data.get("id") or "").strip()
        subs = _amt_subs_load()
        refreshed = []
        for sub in subs:
            if target_id and sub.get("id") != target_id:
                continue
            if not sub.get("enabled", True):
                continue
            _amt_subs_refresh_one(sub)
            refreshed.append({k: v for k, v in sub.items() if k != "cache"})
        if not _amt_subs_save(subs):
            self._send_json({"error": "Vault-Schreibfehler"}, 500)
            return
        nexus_log(f"🔄 Amt-Listen refresh: {len(refreshed)} Abo(s) aktualisiert", "cyan")
        self._send_json({"ok": True, "refreshed": refreshed})

    # ── Federation: Amt-Directory öffentlich browsen + suchen ────────
    def _handle_amt_directory_browse(self):
        """GET /api/amt-directory/browse?category=X&subclass=Y — öffentliches Browsen.
        Gibt alle gecachten Ämter zurück, optional gefiltert nach Kategorie/Subklasse.
        Diese Daten stammen aus öffentlichen Amt-Listen, daher keine Owner-Auth nötig."""
        qs = parse_qs(urlparse(self.path).query)
        category = qs.get("category", [""])[0].strip()
        subclass = qs.get("subclass", [""])[0].strip()
        all_amter = amt_subs_all_amter()
        filtered = []
        for amt in all_amter:
            cats = amt.get("categories") or {}
            if category:
                if category not in cats:
                    continue
                if subclass and subclass not in cats.get(category, []):
                    continue
            filtered.append(amt)
        self._send_json({
            "count": len(filtered),
            "amter": filtered,
            "filter": {"category": category, "subclass": subclass},
        })

    def _handle_amt_directory_search(self):
        """GET /api/amt-directory/search?q=... — Algorithmische Semantik-Suche.
        Tippt der User "ich bin krank", bekommt er Treffer auf
        Gesundheit→Ärztliche Bescheinigung mit allen passenden Ämtern.
        Keine Auth nötig (öffentliches Browsen)."""
        qs = parse_qs(urlparse(self.path).query)
        query = qs.get("q", [""])[0]
        matches = _amt_search(query)
        all_amter = amt_subs_all_amter()
        enriched_results = []
        for match in matches:
            cat = match["category"]
            sub = match["subclass"]
            matching_amter = []
            for amt in all_amter:
                cats = amt.get("categories") or {}
                if cat in cats and sub in cats[cat]:
                    matching_amter.append(amt)
            enriched_results.append({
                "category": cat,
                "subclass": sub,
                "score": match["score"],
                "matched_keyword": match["matched_keyword"],
                "amter": matching_amter,
                "amter_count": len(matching_amter),
            })
        # Treffer mit Ämtern zuerst, dann nach Score absteigend
        enriched_results.sort(key=lambda r: (-int(r["amter_count"] > 0), -r["score"]))
        self._send_json({
            "query": query,
            "result_count": len(enriched_results),
            "results": enriched_results,
        })

    # ── Lizenzen: Erhaltene + Ausgestellte (Phase 1 L9/L10) ──────────
    def _handle_licenses_received(self):
        """GET /api/licenses/received — Liste der für diesen User ausgestellten Lizenzen.
        Filtert nach subject.shinpai_id aus der globalen Received-Vault."""
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        if not sid:
            self._send_json({"error": "Keine Shinpai-ID"}, 400)
            return
        all_lics = _license_load_vault(LICENSES_RECEIVED_VAULT)
        mine = []
        now = int(time.time())
        for lic in all_lics:
            if lic.get("subject", {}).get("shinpai_id") != sid:
                continue
            # Valid-Status berechnen
            valid_until = int(lic.get("valid_until", 0))
            is_valid = not lic.get("revoked") and now < valid_until
            # Leichte Version zurückgeben (ohne signature blob für Übersicht)
            mine.append({
                "license_id": lic.get("license_id"),
                "issuer_name": lic.get("issuer", {}).get("display_name"),
                "issuer_shinpai_id": lic.get("issuer", {}).get("shinpai_id"),
                "subject_shinpai_id": lic.get("subject", {}).get("shinpai_id"),
                "scope": lic.get("scope"),
                "trust_level": lic.get("trust_level"),
                "realized_by": lic.get("realized_by"),
                "notes": lic.get("notes"),
                "issued_at": lic.get("issued_at"),
                "valid_from": lic.get("valid_from"),
                "valid_until": valid_until,
                "revoked": lic.get("revoked", False),
                "is_valid": is_valid,
                "state": lic.get("_state", "valid" if is_valid else "expired"),
                "grace_until": int(lic.get("_grace_until", 0)),
                "response_hint": lic.get("response_hint", ""),
                "response_link": lic.get("response_link", ""),
                "fee_eur": float(lic.get("fee_eur", 0)),
                "needs_paid_refresh": bool(lic.get("_needs_paid_refresh")),
                "signature_short": (lic.get("signature") or "")[:32],
                "algorithm": lic.get("algorithm"),
            })
        mine.sort(key=lambda x: x.get("issued_at", 0), reverse=True)
        self._send_json({"count": len(mine), "licenses": mine})

    def _handle_licenses_issued(self):
        """GET /api/licenses/issued — Vom Owner ausgestellte Lizenzen (Owner only)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        lics = _license_load_vault(LICENSES_ISSUED_VAULT)
        light = []
        now = int(time.time())
        for lic in lics:
            valid_until = int(lic.get("valid_until", 0))
            is_valid = not lic.get("revoked") and now < valid_until
            light.append({
                "license_id": lic.get("license_id"),
                "subject_name": lic.get("subject", {}).get("display_name"),
                "subject_shinpai_id": lic.get("subject", {}).get("shinpai_id"),
                "scope": lic.get("scope"),
                "trust_level": lic.get("trust_level"),
                "realized_by": lic.get("realized_by"),
                "issued_at": lic.get("issued_at"),
                "valid_until": valid_until,
                "is_valid": is_valid,
            })
        light.sort(key=lambda x: x.get("issued_at", 0), reverse=True)
        self._send_json({"count": len(light), "licenses": light})

    # ── Amt-Watchlist (vorgemerkte Ämter für Stufe-3-Verifikation) ───
    def _handle_amt_watchlist_get(self):
        """GET /api/amt-watchlist — Liste der vorgemerkten Ämter (Owner only)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        items = _amt_watchlist_load()
        self._send_json({"count": len(items), "items": items})

    def _handle_amt_watchlist_add(self):
        """POST /api/amt-watchlist/add — Amt vormerken.
        Body: {shinpai_id, name, category, subclass}"""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        shinpai_id = (data.get("shinpai_id") or "").strip()
        if not shinpai_id:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        category = (data.get("category") or "").strip()
        subclass = (data.get("subclass") or "").strip()
        items = _amt_watchlist_load()
        # Duplikat-Check auf shinpai_id
        for existing in items:
            if existing.get("shinpai_id") == shinpai_id:
                self._send_json({"ok": True, "already_listed": True})
                return
        # Regel: Ein Amt pro Subklasse (Anti-Doctor-Shopping) — NUR für Singleton-Subklassen.
        # Multi-Instanz Subklassen (LICENSE_MULTI_SUBCLASSES) dürfen mehrere Ämter haben.
        if category and subclass and subclass not in LICENSE_MULTI_SUBCLASSES:
            for existing in items:
                if existing.get("category") == category and existing.get("subclass") == subclass:
                    self._send_json({
                        "error": "Für diese Unterkategorie ist bereits ein Amt abonniert. Entferne das alte zuerst.",
                        "conflict": True,
                        "existing": {
                            "shinpai_id": existing.get("shinpai_id"),
                            "name": existing.get("name"),
                            "category": category,
                            "subclass": subclass,
                        },
                    }, 409)
                    return
        # Trust-Level + processing_time_days + fee_eur aus dem Federation-Cache holen
        trust_level = 1
        processing_time_days = 7
        fee_eur = 0
        for amt in amt_subs_all_amter():
            if amt.get("shinpai_id") == shinpai_id:
                trust_level = int(amt.get("trust_level", 1))
                processing_time_days = int(amt.get("processing_time_days", 7))
                fee_eur = float(amt.get("fee_eur", 0))
                break
        new_entry = {
            "shinpai_id": shinpai_id,
            "name": (data.get("name") or "").strip() or shinpai_id,
            "category": category,
            "subclass": subclass,
            "trust_level": trust_level,
            "processing_time_days": processing_time_days,
            "fee_eur": fee_eur,
            "added_at": int(time.time()),
            "status": "pending",  # pending | requested | in_progress | confirmed | rejected
            "inquiries": [],       # Liste von Timestamps, wann nachgefragt wurde
            "complaints": [],      # Liste von Timestamps, wann Beschwerde eingereicht
        }
        items.append(new_entry)
        if not _amt_watchlist_save(items):
            self._send_json({"error": "Vault-Schreibfehler"}, 500)
            return
        nexus_log(f"⭐ Amt abonniert: {shinpai_id}", "cyan")
        self._send_json({"ok": True, "item": new_entry})

    def _handle_amt_watchlist_remove(self):
        """POST /api/amt-watchlist/remove — Amt aus der Watchlist entfernen.
        Body: {shinpai_id}"""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        shinpai_id = (data.get("shinpai_id") or "").strip()
        if not shinpai_id:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        items = _amt_watchlist_load()
        before = len(items)
        items = [i for i in items if i.get("shinpai_id") != shinpai_id]
        if len(items) == before:
            self._send_json({"ok": True, "not_listed": True})
            return
        if not _amt_watchlist_save(items):
            self._send_json({"error": "Vault-Schreibfehler"}, 500)
            return
        nexus_log(f"🗑️ Amt aus Watchlist entfernt: {shinpai_id}", "yellow")
        self._send_json({"ok": True, "shinpai_id": shinpai_id})

    def _handle_amt_watchlist_status(self):
        """POST /api/amt-watchlist/status — Status eines Eintrags setzen.
        Body: {shinpai_id, status}
        Erlaubte Stati: pending, requested, received, in_progress, confirmed, rejected"""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        shinpai_id = (data.get("shinpai_id") or "").strip()
        new_status = (data.get("status") or "").strip()
        if not shinpai_id:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        valid_states = {"pending", "requested", "received", "in_progress", "confirmed", "rejected"}
        if new_status not in valid_states:
            self._send_json({"error": f"Status muss einer sein: {', '.join(sorted(valid_states))}"}, 400)
            return
        items = _amt_watchlist_load()
        updated = False
        for item in items:
            if item.get("shinpai_id") == shinpai_id:
                item["status"] = new_status
                item["status_updated_at"] = int(time.time())
                if new_status == "requested":
                    item["requested_at"] = int(time.time())
                updated = True
                break
        if not updated:
            self._send_json({"error": "Amt nicht in der Watchlist"}, 404)
            return
        if not _amt_watchlist_save(items):
            self._send_json({"error": "Vault-Schreibfehler"}, 500)
            return
        nexus_log(f"📮 Amt-Status: {shinpai_id} → {new_status}", "cyan")
        self._send_json({"ok": True, "shinpai_id": shinpai_id, "status": new_status})

    def _handle_amt_watchlist_submit(self):
        """POST /api/amt-watchlist/submit — Antrag an das Amt senden.
        Body: {shinpai_id: "amt-...", watchlist_id?: optional}
        Ruft den /amt/request Endpoint des Amt-Servers auf (via endpoint URL),
        nimmt die Bestätigung entgegen und erzeugt eine signierte Amt-Lizenz."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        amt_sid = (data.get("shinpai_id") or "").strip()
        if not amt_sid:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        # Watchlist-Eintrag finden
        items = _amt_watchlist_load()
        wl_item = None
        for item in items:
            if item.get("shinpai_id") == amt_sid:
                wl_item = item
                break
        if wl_item is None:
            self._send_json({"error": "Amt nicht in der Watchlist"}, 404)
            return
        # Amt-Endpoint aus der Federation finden
        amt_entry = None
        for amt in amt_subs_all_amter():
            if amt.get("shinpai_id") == amt_sid:
                amt_entry = amt
                break
        if amt_entry is None:
            self._send_json({"error": "Amt nicht im Federation-Cache"}, 404)
            return
        # Für Test-Ämter (test- prefix): URL leiten auf Lab-Domain /amt/request
        # (weil die endpoint URLs in der Test-Liste fake sind)
        request_url = None
        if amt_sid.startswith("test-"):
            # Lab-Server kennt alle Test-Ämter
            # Finde die Lab-URL aus der abonnierten Listen
            for sub in _amt_subs_load():
                for a in (sub.get("cache") or {}).get("amter", []):
                    if a.get("shinpai_id") == amt_sid:
                        # Lab-URL aus der Liste ableiten
                        list_url = sub.get("url", "")
                        # amt-list.json → /amt/request
                        if list_url.endswith("/amt-list.json"):
                            request_url = list_url.replace("/amt-list.json", "/amt/request")
                        break
                if request_url:
                    break
        else:
            # Produktions-Amt: Endpoint direkt aus dem Amt-Eintrag
            endpoint = amt_entry.get("endpoint", "").rstrip("/")
            if endpoint:
                request_url = f"{endpoint}/amt/request"
        if not request_url:
            self._send_json({"error": "Kein Request-Endpoint für dieses Amt gefunden"}, 500)
            return
        # Anfrage an das Amt schicken
        sid_user = session.get("shinpai_id", "")
        subject_name = _identity.get("name") or sid_user
        req_body = {
            "amt_shinpai_id": amt_sid,
            "user_shinpai_id": sid_user,
            "category": wl_item.get("category", ""),
            "subclass": wl_item.get("subclass", ""),
        }
        try:
            req = urllib.request.Request(
                request_url,
                data=json.dumps(req_body).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "ShinNexus-Federation/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read(1024 * 1024).decode("utf-8")
                amt_response = json.loads(raw)
        except Exception as e:
            nexus_log(f"⚠️ Amt-Request fehlgeschlagen {request_url}: {e}", "yellow")
            self._send_json({"error": f"Amt nicht erreichbar: {e}", "endpoint": request_url}, 502)
            return
        if not amt_response.get("confirmed"):
            self._send_json({"error": "Amt hat abgelehnt", "amt_response": amt_response}, 400)
            return
        valid_until_ts = int(amt_response.get("valid_until", 0))
        response_hint = amt_response.get("response_hint", "")
        response_link = amt_response.get("response_link", "")
        amt_name = amt_response.get("amt_name", amt_entry.get("name", amt_sid))
        # Lizenz erzeugen (dependencies vom Amt mitgeben)
        lic = _create_amt_license(
            subject_sid=sid_user,
            subject_name=subject_name,
            amt_shinpai_id=amt_sid,
            amt_name=amt_name,
            category=wl_item.get("category", ""),
            subclass=wl_item.get("subclass", ""),
            valid_until_ts=valid_until_ts,
            response_hint=response_hint,
            response_link=response_link,
            dependencies=amt_response.get("dependencies"),
        )
        if not lic:
            self._send_json({"error": "Lizenz-Erzeugung fehlgeschlagen"}, 500)
            return
        # Verification-Level auf 3 hochstufen wenn noch nicht da (Amt-bestätigt → Shield leuchtet)
        target_v = None
        if _identity and _identity.get("shinpai_id") == sid_user:
            target_v = _identity
        else:
            for uname, udata in _users.items():
                if udata.get("shinpai_id") == sid_user:
                    target_v = udata
                    break
        if target_v and int(target_v.get("verification_level", 0)) < 3:
            target_v["verification_level"] = 3
            target_v["verified_by"] = "amt"
            target_v["verified_at"] = int(time.time())
            if target_v is _identity:
                _save_identity()
            else:
                _save_users()
            nexus_log(f"🏅 Verification-Level auf 3 (Amt-bestätigt)", "green")
        # Watchlist-Status auf confirmed + Timestamp
        now = int(time.time())
        for item in items:
            if item.get("shinpai_id") == amt_sid:
                item["status"] = "confirmed"
                item["status_updated_at"] = now
                item["license_id"] = lic.get("license_id")
                item["license_valid_until"] = valid_until_ts
                item["response_hint"] = response_hint
                item["response_link"] = response_link
                break
        _amt_watchlist_save(items)
        self._send_json({
            "ok": True,
            "license_id": lic.get("license_id"),
            "valid_until": valid_until_ts,
            "response_hint": response_hint,
        })

    def _handle_amt_watchlist_inquire(self):
        """POST /api/amt-watchlist/inquire — Nachfrage beim Amt eintragen.
        Body: {shinpai_id}
        Prüft Cooldown (processing_time_days seit letzter Aktion)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        shinpai_id = (data.get("shinpai_id") or "").strip()
        if not shinpai_id:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        items = _amt_watchlist_load()
        now = int(time.time())
        for item in items:
            if item.get("shinpai_id") != shinpai_id:
                continue
            if item.get("status") == "pending":
                self._send_json({"error": "Antrag wurde noch nicht gesendet, Nachfrage nicht möglich"}, 400)
                return
            cooldown_days = int(item.get("processing_time_days", 7))
            inquiries = list(item.get("inquiries") or [])
            # Letzte Aktion: entweder requested_at oder letzte Nachfrage
            last_ts = item.get("requested_at", item.get("added_at", now))
            if inquiries:
                last_ts = max(last_ts, inquiries[-1])
            delta = now - int(last_ts)
            if delta < cooldown_days * 86400:
                remaining = cooldown_days * 86400 - delta
                self._send_json({
                    "error": f"Cooldown aktiv, noch {remaining // 86400} Tage warten",
                    "cooldown_seconds": remaining,
                }, 429)
                return
            inquiries.append(now)
            item["inquiries"] = inquiries
            item["last_inquiry_at"] = now
            if not _amt_watchlist_save(items):
                self._send_json({"error": "Vault-Schreibfehler"}, 500)
                return
            nexus_log(f"📨 Nachfrage #{len(inquiries)} an {shinpai_id}", "cyan")
            self._send_json({"ok": True, "inquiry_count": len(inquiries), "shinpai_id": shinpai_id})
            return
        self._send_json({"error": "Amt nicht in der Watchlist"}, 404)

    def _handle_amt_watchlist_complaint(self):
        """POST /api/amt-watchlist/complaint — Beschwerde eintragen.
        Body: {shinpai_id}
        Bedingung: mind. 3 Nachfragen seit letzter Beschwerde (oder Antragsstart)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        shinpai_id = (data.get("shinpai_id") or "").strip()
        if not shinpai_id:
            self._send_json({"error": "shinpai_id erforderlich"}, 400)
            return
        items = _amt_watchlist_load()
        now = int(time.time())
        for item in items:
            if item.get("shinpai_id") != shinpai_id:
                continue
            if item.get("status") == "pending":
                self._send_json({"error": "Antrag wurde noch nicht gesendet"}, 400)
                return
            inquiries = list(item.get("inquiries") or [])
            complaints = list(item.get("complaints") or [])
            # Zähle Nachfragen seit der letzten Beschwerde (oder vom Start)
            since = complaints[-1] if complaints else 0
            relevant_inquiries = [t for t in inquiries if t > since]
            if len(relevant_inquiries) < 3:
                self._send_json({
                    "error": f"Noch nicht genug Nachfragen. Brauche mindestens drei (aktuell {len(relevant_inquiries)}).",
                    "needed": 3,
                    "current": len(relevant_inquiries),
                }, 400)
                return
            complaints.append(now)
            item["complaints"] = complaints
            item["last_complaint_at"] = now
            if not _amt_watchlist_save(items):
                self._send_json({"error": "Vault-Schreibfehler"}, 500)
                return
            complaint_num = len(complaints)
            nexus_log(f"⚠️ Beschwerde #{complaint_num} gegen {shinpai_id}", "yellow")
            # Stub: Bei 2. Beschwerde Notiz für späteren Owner-Mail-Flow
            escalation_ready = complaint_num >= 2
            self._send_json({
                "ok": True,
                "complaint_count": complaint_num,
                "shinpai_id": shinpai_id,
                "escalation_ready": escalation_ready,
                "template": f"Dieser Antrag wurde {complaint_num * 3} Wochen nicht bearbeitet. Bitte um Klärung.",
            })
            return
        self._send_json({"error": "Amt nicht in der Watchlist"}, 404)

    def _handle_license_info(self):
        """GET /api/license/info — Aktuelle Lizenz-Anzeige (öffentlich, ohne sensitive Daten)."""
        cfg = load_config()
        # Code-Hash für Anzeige (zeigt an dass Lizenz an spezifischen Code gebunden ist)
        try:
            with open(__file__, 'rb') as f:
                code_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            code_hash = ""
        self._send_json({
            "company": cfg.get("license_company", ""),
            "verifier_url": cfg.get("license_verifier_url", ""),
            "glow_color": cfg.get("license_glow_color", "#7ab8e0"),
            "license_id": cfg.get("license_id", ""),
            "code_hash": code_hash,
            "logo": cfg.get("license_logo", ""),
        })

    def _handle_chain_info(self):
        """GET /api/chain/info — Öffentliche Chain-Identität für Whitelist-Gatekeeping.

        Liefert die Kern-Daten die ein fremder Nexus braucht um Vertrauen zu prüfen:
        Version + Code-Hash + Bitcoin-TXID der on-chain-verankerten Version.
        Öffentlich (kein Auth), keine sensitiven Daten.
        """
        try:
            with open(__file__, 'rb') as f:
                code_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            code_hash = ""
        anchor = _btc_read_anchor_json()
        cfg = load_config()
        revoked = bool(anchor.get("revoked"))
        self._send_json({
            "version": VERSION,
            "code_hash": code_hash,
            "txid": "" if revoked else (anchor.get("txid") or ""),
            "anchored_version": anchor.get("version", ""),
            "anchored_at": anchor.get("timestamp", 0),
            "revoked": revoked,
            "company": cfg.get("license_company", ""),  # nur UI-Anzeige, NICHT trust-relevant
        })

    def _handle_license_save(self):
        """POST /api/license/save — Lizenz-Config speichern (Owner only)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner darf Lizenz konfigurieren"}, 403)
            return
        data = self._parse_json()
        company = data.get("company", "").strip()
        if company and (len(company) < 3 or len(company) > 12):
            self._send_json({"error": "Firmenname: 3-12 Zeichen!"}, 400)
            return
        cfg = load_config()
        cfg["license_company"] = company
        cfg["license_verifier_url"] = data.get("verifier_url", "")
        cfg["license_glow_color"] = data.get("glow_color", "#7ab8e0")
        logo = data.get("logo", "")
        if logo and logo.startswith("data:image"):
            cfg["license_logo"] = logo
        # Lizenz-ID generieren wenn noch keine existiert oder Firma geändert
        if company and not cfg.get("license_id"):
            import string, random
            digits = ''.join(random.choices(string.digits, k=4))
            alphanum = ''.join(random.choices(string.ascii_letters + string.digits, k=28))
            cfg["license_id"] = f"Shin_Perso{digits}{alphanum}"
        elif not company:
            cfg.pop("license_id", None)
        save_config(cfg)
        nexus_log(f"✅ Lizenz-Config gespeichert: {company or 'LEER'}", "green")
        self._send_json({"ok": True, "license_id": cfg.get("license_id", "")})

    def _handle_migrate_export(self):
        """POST /api/migrate/export — Migrations-String erzeugen (Source-Seite).

        Der String enthaelt KEINE User-Daten — nur Zugangsdaten zu DIESEM Nexus.
        Der Ziel-Nexus ruft dann mit Token+Transport-Key das eigentliche Bundle
        ueber /api/migrate/bundle ab. Transport-Key verschluesselt das Bundle
        zusaetzlich zu HTTPS (PQ-Private-Keys duerfen nicht im Klartext durch Proxies).

        Optional: target_url — wenn angegeben, wird der Ziel-Nexus gegen die lokale
        Whitelist geprüft (Chain-Info abrufen, Hash+TXID gegen eigene Liste matchen).
        Wenn Ziel nicht vertrauenswürdig → 403, Migration abgelehnt.
        """
        session = self._require_auth()
        if not session:
            return
        sid = session.get("shinpai_id", "")
        name = session.get("name", "")
        data = self._parse_json() or {}
        target_url = (data.get("target_url") or "").strip().rstrip("/")
        # Owner-Migration: nur nach 30-Tage-Countdown erlaubt
        if _identity and sid == _identity.get("shinpai_id"):
            cfg_mig = load_config()
            mig_start = cfg_mig.get("owner_migrate_started", 0)
            if not mig_start:
                self._send_json({
                    "error": "Owner-Migration erst über den 30-Tage-Countdown starten (Sicherheits-Tab).",
                }, 403)
                return
            elapsed = time.time() - mig_start
            if elapsed < 30 * 86400:
                days_left = int((30 * 86400 - elapsed) / 86400) + 1
                self._send_json({
                    "error": f"Owner-Migration: Noch {days_left} Tage Wartezeit.",
                }, 403)
                return
            # 30 Tage abgelaufen → Owner darf migrieren!
        if name not in _users:
            self._send_json({"error": "User nicht gefunden"}, 404)
            return
        # Bereits migriert?
        if _users[name].get("migrated_to"):
            self._send_json({
                "error": f"Account wurde bereits migriert nach {_users[name]['migrated_to']}",
            }, 409)
            return
        # Whitelist-Gatekeeping: Ziel-Nexus muss on-chain-vertrauenswürdig sein
        if target_url:
            trusted, remote_info, reasons = _whitelist_check_remote_nexus(target_url)
            if not trusted:
                self._send_json({
                    "error": "Ziel-Nexus nicht vertrauenswürdig: " + "; ".join(reasons),
                    "target_url": target_url,
                    "remote_version": remote_info.get("version", ""),
                    "remote_hash": remote_info.get("code_hash", ""),
                    "remote_txid": remote_info.get("txid", ""),
                    "remote_company": remote_info.get("company", ""),
                    "whitelist_reject": True,
                }, 403)
                return

        # 30-Tage-Migration-Cooldown: Wenn User erst kürzlich hier angekommen,
        # KEINE Weiter-Migration (weder zurück noch woanders hin). Reflexionszeit.
        arrived = int(_users[name].get("migrated_at_target") or 0)
        if arrived:
            age = int(time.time()) - arrived
            if age < 30 * 86400:
                days_left = (30 * 86400 - age) // 86400 + 1
                self._send_json({
                    "error": f"Migration gesperrt — du bist erst vor {age // 86400} Tagen hier angekommen. Nächste Migration möglich in {days_left} Tagen.",
                }, 403)
                return

        token = secrets.token_urlsafe(48)
        transport_key = secrets.token_urlsafe(32)
        expires = int(time.time()) + 3600
        if not hasattr(type(self), '_migration_tokens'):
            type(self)._migration_tokens = {}
        type(self)._migration_tokens[token] = {
            "shinpai_id": sid,
            "name": name,
            "transport_key": transport_key,
            "created": int(time.time()),
            "expires": expires,
            "target_url": target_url,  # leer wenn nicht angegeben
        }
        cfg = load_config()
        source_url = (cfg.get("public_url") or "").rstrip("/")
        if not source_url:
            port = cfg.get("port", DEFAULT_PORT)
            proto = "https" if _tls_active else "http"
            source_url = f"{proto}://localhost:{port}"
        payload = {
            "source_url": source_url,
            "token": token,
            "transport_key": transport_key,
            "shinpai_id": sid,
            "name": name,
            "expires": expires,
        }
        migration_string = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).decode("utf-8").rstrip("=")
        nexus_log(f"📤 Migrations-String erzeugt fuer {name} ({sid}) - 1h gueltig", "yellow")
        self._send_json({
            "ok": True,
            "migration_string": migration_string,
            "expires": expires,
            "source_url": source_url,
        })

    def _handle_migrate_bundle(self):
        """POST /api/migrate/bundle — Source liefert User-Bundle an Ziel-Nexus.

        Kein Session-Auth — Auth ist der Migrations-Token + Transport-Key.
        Body: {token, transport_key}
        Response: {encrypted_bundle_b64, nonce_b64, signature_hex, public_key_hex, algo}
        """
        data = self._parse_json()
        token = (data.get("token") or "").strip()
        transport_key = (data.get("transport_key") or "").strip()
        if not token or not transport_key:
            self._send_json({"error": "token und transport_key erforderlich"}, 400)
            return
        tokens = getattr(type(self), '_migration_tokens', {})
        entry = tokens.get(token)
        if not entry or entry.get("transport_key") != transport_key:
            self._send_json({"error": "Ungueltiger Token"}, 403)
            return
        if time.time() > entry.get("expires", 0):
            tokens.pop(token, None)
            self._send_json({"error": "Token abgelaufen"}, 410)
            return
        name = entry.get("name", "")
        sid = entry.get("shinpai_id", "")
        # Owner oder normaler User?
        if _identity and _identity.get("shinpai_id") == sid:
            user = _identity
        else:
            user = _users.get(name)
        if not user or user.get("shinpai_id") != sid:
            self._send_json({"error": "User nicht mehr vorhanden"}, 404)
            return
        # Bundle aufbauen — nur die echten User-Daten, keine fremden Referenzen
        bundle = {
            "version": 1,
            "user": {
                "name": user["name"],
                "email": user.get("email", ""),
                "shinpai_id": user["shinpai_id"],
                "password_hash": user.get("password_hash", ""),
                "password_salt": user.get("password_salt", ""),
                "totp_secret": user.get("totp_secret", ""),
                "totp_confirmed": user.get("totp_confirmed", False),
                "email_verified": user.get("email_verified", False),
                "recovery_seed_hash": user.get("recovery_seed_hash", ""),
                "pq_keys": user.get("pq_keys", {}),
                "created": user.get("created", int(time.time())),
            },
            "hives": _user_hives.get(name, []),
            "friends": _friends_data.get(sid, {
                "friends": [], "pending_in": [], "pending_out": [], "blocked": [],
            }),
            "source_nexus": (_identity.get("name") if _identity else "?"),
            "exported_at": int(time.time()),
        }
        bundle_json = json.dumps(bundle, sort_keys=True).encode("utf-8")
        # Signatur mit Source-Nexus-PQ-Key (Authenticity-Stempel)
        try:
            signature = _sign_data(bundle_json)
            public_key = (_pq_keys or {}).get("sig_pk", "")
        except Exception as e:
            self._send_json({"error": f"Signatur fehlgeschlagen: {e}"}, 500)
            return
        # AES-256-GCM mit transport_key als Shared-Secret
        # Key-Derivation: SHA256(transport_key) -> 32 Byte
        key32 = hashlib.sha256(transport_key.encode("utf-8")).digest()
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(key32).encrypt(nonce, bundle_json, b"migrate-bundle-v1")
        nexus_log(f"📤 Migrations-Bundle geliefert fuer {name} ({sid})", "yellow")
        self._send_json({
            "ok": True,
            "encrypted_bundle": base64.b64encode(encrypted).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "signature": signature,
            "public_key": public_key,
            "algo": "AES-256-GCM|ML-DSA-65",
            "aad": "migrate-bundle-v1",
        })

    def _handle_migrate_confirm(self):
        """POST /api/migrate/confirm — Source markiert User als migriert.

        Nur der Ziel-Nexus (mit demselben Token + Transport-Key) darf das triggern.
        Body: {token, transport_key, target_url}
        """
        data = self._parse_json()
        token = (data.get("token") or "").strip()
        transport_key = (data.get("transport_key") or "").strip()
        target_url = (data.get("target_url") or "").strip().rstrip("/")
        if not token or not transport_key or not target_url:
            self._send_json({"error": "token, transport_key, target_url erforderlich"}, 400)
            return
        tokens = getattr(type(self), '_migration_tokens', {})
        entry = tokens.get(token)
        if not entry or entry.get("transport_key") != transport_key:
            self._send_json({"error": "Ungueltiger Token"}, 403)
            return
        if time.time() > entry.get("expires", 0):
            tokens.pop(token, None)
            self._send_json({"error": "Token abgelaufen"}, 410)
            return
        name = entry.get("name", "")
        sid = entry.get("shinpai_id", "")
        # Owner-Migration?
        is_owner_migrate = _identity and _identity.get("shinpai_id") == sid
        if not is_owner_migrate and name not in _users:
            self._send_json({"error": "User nicht vorhanden"}, 404)
            return
        if is_owner_migrate:
            # Owner migriert → Nexus auflösen!
            nexus_log(f"🔴 OWNER-MIGRATION CONFIRMED → Nexus wird aufgelöst! → {target_url}", "red")
            _nexus_dissolve(target_url)
        else:
            # Normaler User: Soft-Lock
            _users[name]["migrated_to"] = target_url
            _users[name]["migrated_at"] = int(time.time())
            _save_users()
        tokens.pop(token, None)
        nexus_log(f"✅ {'OWNER' if is_owner_migrate else 'User'} {name} ({sid}) migriert nach {target_url}", "green")
        self._send_json({"ok": True, "migrated": name, "target": target_url, "dissolved": is_owner_migrate})

    def _handle_migrate_import(self):
        """POST /api/migrate/import — Ziel-Nexus empfaengt Migration (KEIN Auth noetig!).
        Bei ownerless Nexus: owner_password + owner_totp → migrierter User wird Owner.

        Body: {migration_string: "base64-JSON"}
        Flow:
          1. Parse migration_string -> source_url, token, transport_key, sid, name
          2. HTTP-Call zu source_url/api/migrate/bundle -> verschluesseltes Bundle
          3. Decrypt mit transport_key, Signatur pruefen
          4. User in _users, _user_hives, _friends_data anlegen
          5. source_url/api/migrate/confirm rufen damit Source-Account gesperrt wird
        """
        global _identity, _pq_keys
        # Rate-Limit: max 3 Import-Versuche/min/IP (zaehlt NICHT als Abuse-Fail)
        ip = self._client_ip()
        now = time.time()
        rc = getattr(type(self), '_migrate_import_counts', {})
        if not hasattr(type(self), '_migrate_import_counts'):
            type(self)._migrate_import_counts = {}
            rc = type(self)._migrate_import_counts
        entry = rc.get(ip, {"count": 0, "window_start": now})
        if now - entry["window_start"] > 60:
            entry = {"count": 0, "window_start": now}
        if entry["count"] >= 5:
            self._send_json({"error": "Rate limit - max 5/min"}, 429)
            return
        entry["count"] += 1
        rc[ip] = entry

        # Abuse-Check: Wer aktuell gesperrt ist, kommt gar nicht erst durch
        allowed, abuse_msg, retry = _migrate_abuse_check(ip)
        if not allowed:
            self._send_json({"error": abuse_msg, "retry_after": retry}, 423)
            return

        def _fail(reason: str, code: int = 400):
            """Send error + Abuse-Counter bei echten Fehlern (keine 409/503/429)."""
            self._send_json({"error": reason}, code)
            if code not in (409, 503, 429):
                _migrate_abuse_register_fail(ip, reason=reason[:60])

        # Owner-Migration? Wenn kein Owner existiert UND PW+2FA mitgeschickt → auto_owner!
        auto_owner = _identity is None
        if not auto_owner and not vault_is_unlocked():
            self._send_json({
                "error": "Nexus gerade gebootet! Owner muss erst freigeben!",
            }, 503)
            return
        data = self._parse_json()
        mstr = (data.get("migration_string") or "").strip()
        if not mstr:
            _fail("migration_string erforderlich", 400)
            return
        # Base64-Decode mit Padding-Toleranz
        try:
            padded = mstr + "=" * (-len(mstr) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except Exception as e:
            _fail(f"migration_string korrupt: {e}", 400)
            return
        source_url = (payload.get("source_url") or "").strip().rstrip("/")
        token = payload.get("token", "")
        transport_key = payload.get("transport_key", "")
        sid = payload.get("shinpai_id", "")
        name = payload.get("name", "")
        if not (source_url and token and transport_key and sid and name):
            _fail("migration_string unvollstaendig", 400)
            return
        # Target hat schon einen gleichnamigen/gleich-ID User? (409 → KEIN Abuse)
        if name in _users:
            self._send_json({"error": f"User {name} existiert bereits auf diesem Nexus"}, 409)
            return
        if _identity and _identity.get("shinpai_id") == sid:
            self._send_json({"error": "Shinpai-ID ist Owner dieses Nexus"}, 409)
            return
        for u in _users.values():
            if u.get("shinpai_id") == sid:
                self._send_json({"error": "Shinpai-ID existiert bereits auf diesem Nexus"}, 409)
                return
        # Selbst-Migration verhindern (source_url == mein public_url)
        cfg = load_config()
        my_url = (cfg.get("public_url") or "").rstrip("/")
        if my_url and source_url.rstrip("/") == my_url:
            _fail("Quelle und Ziel sind derselbe Nexus", 400)
            return
        # 1. Bundle vom Source abholen
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            body = json.dumps({"token": token, "transport_key": transport_key}).encode("utf-8")
            req = urllib.request.Request(
                source_url + "/api/migrate/bundle",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                bundle_resp = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as he:
            try:
                err = json.loads(he.read().decode("utf-8")).get("error", str(he))
            except Exception:
                err = str(he)
            # Source lehnt ab → Token ungueltig → Abuse-Indikator
            _fail(f"Source lehnt ab: {err}", 502)
            return
        except Exception as e:
            # Netzwerkfehler — KEIN Abuse (nicht Clients Schuld)
            self._send_json({"error": f"Source nicht erreichbar: {e}"}, 502)
            return
        if not bundle_resp.get("ok"):
            _fail(bundle_resp.get("error", "Bundle-Fehler"), 502)
            return
        # 2. Entschluesseln
        try:
            enc = base64.b64decode(bundle_resp["encrypted_bundle"])
            nonce = base64.b64decode(bundle_resp["nonce"])
            aad = bundle_resp.get("aad", "migrate-bundle-v1").encode("utf-8")
            key32 = hashlib.sha256(transport_key.encode("utf-8")).digest()
            bundle_json = AESGCM(key32).decrypt(nonce, enc, aad)
        except Exception as e:
            _fail(f"Bundle-Entschluesselung fehlgeschlagen: {e}", 400)
            return
        # 3. Signatur pruefen (Authenticity-Stempel des Source-Nexus)
        try:
            sig_ok = _verify_signature(
                bundle_json,
                bundle_resp.get("signature", ""),
                bundle_resp.get("public_key", ""),
            )
            if not sig_ok:
                _fail("Bundle-Signatur ungueltig", 403)
                return
        except Exception as e:
            _fail(f"Signatur-Pruefung fehlgeschlagen: {e}", 400)
            return
        bundle = json.loads(bundle_json.decode("utf-8"))
        # 4. User anlegen
        user = bundle.get("user", {})
        if user.get("shinpai_id") != sid or user.get("name") != name:
            _fail("Bundle passt nicht zu Migration-Token", 400)
            return

        if auto_owner:
            # Owner-Migration: PW + 2FA gegen Bundle-Daten verifizieren
            owner_pw = data.get("owner_password", "")
            owner_totp = data.get("owner_totp", "")
            if not owner_pw or not owner_totp:
                _fail("Passwort + 2FA-Code erforderlich für Owner-Migration", 400)
                return
            # PW prüfen
            pw_hash = user.get("password_hash", "")
            pw_salt = user.get("password_salt", "")
            if not _verify_password(owner_pw, pw_hash, pw_salt):
                _fail("Falsches Passwort", 401)
                return
            # 2FA prüfen
            totp_secret = user.get("totp_secret", "")
            if not totp_verify(totp_secret, owner_totp):
                _fail("Falscher 2FA-Code", 401)
                return
            # Vault + Identity erstellen (1:1 wie Kneipe-Provisioning!)
            vault_unlock(owner_pw)
            pq_keys = user.get("pq_keys") or _generate_user_keypair()
            _identity = {
                "name": user["name"],
                "email": user.get("email", ""),
                "shinpai_id": user["shinpai_id"],
                "password_hash": pw_hash,
                "password_salt": pw_salt,
                "totp_secret": totp_secret,
                "totp_confirmed": user.get("totp_confirmed", True),
                "email_verified": user.get("email_verified", False),
                "recovery_seed_hash": user.get("recovery_seed_hash", ""),
                "pq_keys": pq_keys,
                "created": user.get("created", int(time.time())),
                "migrated_from": source_url,
                "migrated_at_target": int(time.time()),
            }
            _pq_keys = pq_keys
            _save_identity()
            _save_recovery_data(owner_pw, "")  # Kein neuer Seed — alter bleibt gültig
            cfg2 = load_config()
            cfg2["name"] = user["name"]
            cfg2["email"] = user.get("email", "")
            cfg2["shinpai_id"] = user["shinpai_id"]
            cfg2["mode"] = "server"
            save_config(cfg2)
            _igni_init(cfg2)
            if cfg2.get("owner_vault_mode", "standard") == "standard":
                igni_save(owner_pw)
            system_vault_init(cfg2, owner_password=owner_pw)
            _placeholder_dismiss()
            nexus_log(f"👑 OWNER-MIGRATION: {name} ({sid}) von {source_url}", "green")
        else:
            # Normaler User-Import
            _users[name] = {
                "name": user["name"],
                "email": user.get("email", ""),
                "shinpai_id": user["shinpai_id"],
                "password_hash": user.get("password_hash", ""),
                "password_salt": user.get("password_salt", ""),
                "totp_secret": user.get("totp_secret", ""),
                "totp_confirmed": user.get("totp_confirmed", False),
                "email_verified": user.get("email_verified", False),
                "recovery_seed_hash": user.get("recovery_seed_hash", ""),
                "pq_keys": user.get("pq_keys", {}),
                "created": user.get("created", int(time.time())),
                "migrated_from": source_url,
                "migrated_at_target": int(time.time()),
            }
            _save_users()
        _user_hives[name] = bundle.get("hives", []) or []
        _friends_data[sid] = bundle.get("friends", {
            "friends": [], "pending_in": [], "pending_out": [], "blocked": [],
        })
        # 5. Source-Confirm triggern (Source sperrt alten Account)
        try:
            my_port = cfg.get("port", DEFAULT_PORT)
            my_proto = "https" if _tls_active else "http"
            my_url_for_source = my_url or f"{my_proto}://localhost:{my_port}"
            body2 = json.dumps({
                "token": token,
                "transport_key": transport_key,
                "target_url": my_url_for_source,
            }).encode("utf-8")
            req2 = urllib.request.Request(
                source_url + "/api/migrate/confirm",
                data=body2,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=10, context=ctx) as resp2:
                confirm_resp = json.loads(resp2.read().decode("utf-8"))
        except Exception as e:
            # User ist angelegt, aber Source nicht confirm — trotzdem OK, Source-Token laeuft ohnehin in 1h ab
            confirm_resp = {"ok": False, "warning": f"Source-Confirm fehlgeschlagen: {e}"}
        nexus_log(f"📥 Migration ok: {name} ({sid}) von {source_url}", "green")
        self._send_json({
            "ok": True,
            "migrated": name,
            "shinpai_id": sid,
            "source": source_url,
            "source_confirm": confirm_resp,
        })

    def _handle_owner_migrate_start(self):
        """POST /api/migrate/owner-start — Owner-Migration starten (30 Tage Countdown)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner darf Owner-Migration starten"}, 403)
            return
        cfg = load_config()
        if cfg.get("owner_migrate_started"):
            remaining = cfg["owner_migrate_started"] + 30*86400 - time.time()
            if remaining > 0:
                days = int(remaining / 86400)
                self._send_json({"error": f"Countdown läuft bereits! Noch {days} Tage."}, 400)
                return
        cfg["owner_migrate_started"] = int(time.time())
        save_config(cfg)
        nexus_log("⚠️ OWNER-MIGRATION gestartet! 30-Tage-Countdown!", "red")
        # Email an alle User senden (nutzt send_nexus_email mit Vault-Passwort)
        company = cfg.get("license_company", "ShinNexus")
        nexus_url = cfg.get('public_url', '').rstrip('/') or f"https://{cfg.get('domain', 'localhost')}:{cfg.get('port', 12345)}"
        # Mobiler Nexus? IP-basierte Erkennung: öffentliche IP = statisch, private IP = mobil
        import ipaddress as _ipamod
        _is_mobile = True  # Default: mobil (sicher)
        try:
            import socket
            _own_ip = socket.gethostbyname(socket.gethostname())
            _is_mobile = _ipamod.ip_address(_own_ip).is_private
        except Exception:
            pass
        _mobile_hint = ""
        if _is_mobile:
            _mobile_hint = """
                    <div style="background:#1a1400;border:1px solid #554400;border-radius:8px;padding:12px 15px;margin:15px 0;text-align:left;">
                      <div style="font-size:12px;color:#d4a850;">&#9888; Mobiler Nexus</div>
                      <div style="font-size:12px;color:#998866;margin-top:5px;">Dieser Nexus hat keine feste Adresse. Wende dich direkt an deinen Betreiber f&uuml;r Unterst&uuml;tzung bei der Migration.</div>
                    </div>"""
        # Logo als Base64 (offline-sicher, kein Server n&ouml;tig)
        _logo_b64 = ""
        _logo_path = BASE / "ShinNexus-Logo.webp"
        if _logo_path.exists():
            import base64 as _b64mod
            _logo_b64 = _b64mod.b64encode(_logo_path.read_bytes()).decode()
        try:
            for uname, udata in _users.items():
                email = udata.get("email", "")
                if not email:
                    continue
                _logo_tag = f'<img src="data:image/webp;base64,{_logo_b64}" alt="ShinNexus" style="width:120px;height:120px;border-radius:50%;box-shadow:0 0 25px rgba(255,255,255,0.3);margin-bottom:15px;">' if _logo_b64 else '<div style="font-size:42px;margin-bottom:15px;">&#128737;</div>'
                html = f"""
                <div style="background:#0a0a0a;color:#e0d8c8;font-family:Georgia,serif;padding:40px;max-width:520px;margin:0 auto;border:1px solid #1a1a1a;border-radius:12px;">
                  <div style="text-align:center;">
                    {_logo_tag}
                    <h1 style="color:#7ab8e0;margin:0 0 5px 0;font-size:22px;">ShinNexus</h1>
                    <div style="color:#556677;font-size:11px;letter-spacing:2px;margin-bottom:25px;">SAME KNOWLEDGE. YOUR OWNERSHIP.</div>
                    <div style="background:linear-gradient(135deg,#1a0a0a,#0a0a1a);border:1px solid #5a2a2a;border-radius:10px;padding:25px;margin:20px 0;">
                      <div style="font-size:18px;color:#e55;margin-bottom:12px;">&#9888;&#65039; Account-Migration</div>
                      <div style="font-size:14px;color:#e0d8c8;line-height:1.6;">Der Betreiber <strong style="color:#d4a850;">{company}</strong> hat eine Migration gestartet.</div>
                      <div style="font-size:15px;color:#e55;margin-top:12px;font-weight:bold;">Dein Account wird in 30 Tagen gel&ouml;scht.</div>
                    </div>
                    <div style="background:#0d1117;border-left:3px solid #7ab8e0;padding:15px;margin:20px 0;text-align:left;border-radius:0 8px 8px 0;">
                      <div style="font-size:11px;color:#7ab8e0;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Dein Account</div>
                      <div style="font-size:14px;color:#e0d8c8;">Benutzername: <strong style="color:#7ab8e0;">{uname}</strong></div>
                    </div>
                    <div style="background:#0d1117;border-left:3px solid #d4a850;padding:15px;margin:20px 0;text-align:left;border-radius:0 8px 8px 0;">
                      <div style="font-size:11px;color:#d4a850;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Nexus-Standort</div>
                      <div style="font-size:13px;color:#e0d8c8;">Betreiber: <strong style="color:#d4a850;">{company}</strong></div>
                      <div style="font-size:12px;color:#887755;margin-top:4px;">{nexus_url}</div>
                    </div>{_mobile_hint}
                    <div style="background:#0d1117;border-left:3px solid #3a5a7a;padding:15px;margin:20px 0;text-align:left;border-radius:0 8px 8px 0;">
                      <div style="font-size:11px;color:#3a5a7a;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Was tun?</div>
                      <div style="font-size:13px;color:#998866;line-height:1.7;">
                        1. Melde dich bei einem anderen ShinNexus an<br>
                        2. Gehe in die Einstellungen<br>
                        3. Klicke auf &quot;Migrieren&quot;<br>
                        4. Generiere einen Migrations-Token<br>
                        5. Gib den Token beim neuen ShinNexus ein<br><br>
                        <span style="color:#7ab8e0;">Deine Daten wandern sicher zum neuen Nexus.</span>
                      </div>
                    </div>
                    <hr style="border:none;border-top:1px solid #1a1a1a;margin:25px 0;">
                    <div style="font-size:11px;color:#334455;">Shinpai-AI &mdash; Same Knowledge. Your Ownership.<br><span style="color:#556677;">Ist einfach passiert. &#128009;</span></div>
                  </div>
                </div>"""
                send_nexus_email(email, f"ShinNexus Migration — {company} — 30 Tage Frist", html, cfg)
        except Exception as e:
            nexus_log(f"❌ Email-Versand Fehler: {e}", "red")
        self._send_json({"ok": True, "countdown_days": 30})

    def _handle_public_url_save(self):
        """POST /api/public-url/save — Public URL speichern (Owner only).
        Leerstring = Auto-Detect-Modus. Sonst wird die URL zunächst 2-Stage-getestet.
        """
        if not self._owner_only_session():
            return
        data = self._parse_json()
        url = (data.get("url") or "").strip().rstrip("/")
        cfg = load_config()
        if url:
            if not (url.startswith("http://") or url.startswith("https://")):
                self._send_json({"error": "URL muss mit http:// oder https:// beginnen"}, 400)
                return
            reachable, method = _check_external_reachable(url)
            cfg["public_url"] = url
            save_config(cfg)
            # Network-State refreshen damit Frontend direkt neue Daten sieht
            run_network_check(cfg)
            nexus_log(f"✅ Public URL gespeichert: {url} (reachable: {reachable}/{method})", "green")
            self._send_json({"ok": True, "url": url, "reachable": reachable, "method": method})
        else:
            # Leer = Auto-Detect aktivieren
            cfg["public_url"] = ""
            save_config(cfg)
            state = run_network_check(cfg)
            nexus_log("🧭 Public URL gelöscht — Auto-Detect aktiv", "cyan")
            self._send_json({"ok": True, "url": "", "state": state})

    def _handle_public_url_status(self):
        """GET /api/public-url/status — Network-State + Config.
        Owner bekommt alle Details, Visitor nur minimal (best_url + Flag).
        """
        cfg = load_config()
        with _network_state_lock:
            state = dict(_network_state)
        # Auth optional — für Owner-Detail
        session = None
        token = self.headers.get("X-Session-Token", "")
        if not token:
            token = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        if token:
            session = validate_auth_session(token)
        is_owner = bool(session and _identity and session.get("shinpai_id") == _identity.get("shinpai_id"))
        manual = (cfg.get("public_url") or "").rstrip("/")
        if is_owner:
            self._send_json({
                "public_url_manual": manual,
                "autocheck_enabled": bool(cfg.get("autocheck_enabled", True)),
                "autocheck_interval_sec": int(cfg.get("autocheck_interval_sec", 1800)),
                "state": state,
            })
        else:
            # Öffentlich: minimaler Snapshot (kein local_ips-Leak!)
            self._send_json({
                "public_url_manual": manual,
                "state": {
                    "best_url": state.get("best_url"),
                    "reachable_external": state.get("reachable_external", False),
                    "last_check": state.get("last_check", 0),
                },
            })

    def _handle_public_url_check(self):
        """POST /api/public-url/check — Full-Check oder URL-specific (Owner only).
        Body: {} → run_network_check()
        Body: {url: "..."} → 2-Stage-Check nur für diese URL, KEINE Speicherung.
        """
        if not self._owner_only_session():
            return
        data = self._parse_json()
        url = (data.get("url") or "").strip().rstrip("/")
        if url:
            if not (url.startswith("http://") or url.startswith("https://")):
                self._send_json({"error": "URL muss mit http:// oder https:// beginnen"}, 400)
                return
            reachable, method = _check_external_reachable(url)
            self._send_json({
                "ok": reachable,
                "url": url,
                "method": method,
                "note": "Erreichbar!" if reachable else "Nicht erreichbar…",
            })
        else:
            state = run_network_check()
            self._send_json({"ok": True, "state": state})

    def _handle_public_url_config(self):
        """POST /api/public-url/config — Watchdog-Settings (Owner only)."""
        if not self._owner_only_session():
            return
        data = self._parse_json()
        cfg = load_config()
        if "autocheck_enabled" in data:
            cfg["autocheck_enabled"] = bool(data["autocheck_enabled"])
        if "autocheck_interval_sec" in data:
            try:
                ival = int(data["autocheck_interval_sec"])
                # Clamp auf [60, 86400]
                cfg["autocheck_interval_sec"] = max(60, min(86400, ival))
            except (TypeError, ValueError):
                self._send_json({"error": "autocheck_interval_sec muss Zahl sein"}, 400)
                return
        save_config(cfg)
        self._send_json({
            "ok": True,
            "autocheck_enabled": bool(cfg.get("autocheck_enabled", True)),
            "autocheck_interval_sec": int(cfg.get("autocheck_interval_sec", 1800)),
        })

    def _handle_veriff_price_save(self):
        """POST /api/veriff/price — Veriff-Preis in Euro setzen (Owner only)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner"}, 403)
            return
        data = self._parse_json()
        try:
            price = float(data.get("price_eur", 3.0))
        except (TypeError, ValueError):
            self._send_json({"error": "Preis muss eine Zahl sein"}, 400)
            return
        if price < 0 or price > 100:
            self._send_json({"error": "Preis 0-100 Euro erlaubt"}, 400)
            return
        cfg = load_config()
        cfg["veriff_price_eur"] = price
        save_config(cfg)
        self._send_json({"ok": True, "price_eur": price})

    def _handle_veriff_toggle(self):
        """POST /api/veriff/toggle — Veriff ein/ausschalten (Owner only).
        Body: {enabled: true/false}"""
        if not self._owner_only_session():
            return
        data = self._parse_json() or {}
        enabled = bool(data.get("enabled", False))
        cfg = load_config()
        cfg["veriff_enabled"] = enabled
        save_config(cfg)
        nexus_log(f"🪪 Veriff {'aktiviert' if enabled else 'deaktiviert'}", "green" if enabled else "yellow")
        self._send_json({"ok": True, "veriff_enabled": enabled})

    def _handle_veriff_config(self):
        """POST /api/veriff/config — Veriff API-Key konfigurieren (Owner only)."""
        session = self._require_auth()
        if not session:
            return
        if not _identity or session.get("shinpai_id") != _identity.get("shinpai_id"):
            self._send_json({"error": "Nur Owner darf Veriff konfigurieren"}, 403)
            return

        data = self._parse_json()
        key = data.get("veriff_api_key", "")
        secret = data.get("veriff_shared_secret", "")

        if not key:
            self._send_json({"error": "veriff_api_key erforderlich"}, 400)
            return

        cfg = load_config()
        cfg["veriff_api_key"] = key
        if secret:
            cfg["veriff_shared_secret"] = secret
        save_config(cfg)
        nexus_log("✅ Veriff API-Key konfiguriert", "green")
        self._send_json({"ok": True, "veriff_configured": True})

    # ── Handler: Landing Page ─────────────────────────────────────
    def _handle_landing(self):
        """Landing Page — Login-Form für Remote, Dashboard nach Auth."""
        try:
            return self._handle_landing_inner()
        except Exception as _landing_err:
            import traceback
            nexus_log(f"🚨 LANDING CRASH: {_landing_err}", "red")
            nexus_log(traceback.format_exc(), "red")
            self._send_json({"error": f"Internal: {_landing_err}"}, 500)

    def _handle_landing_inner(self):
        is_local = self._is_localhost()
        is_owner_session = False  # Default — wird im Dashboard-Branch ggf. überschrieben
        has_account = _identity is not None

        # Verifiziert-durch Text (für Login-Seite, vor allen Branches berechnen!)
        _lcfg = load_config()
        _veriff_on = bool(_lcfg.get("veriff_enabled", True) and _lcfg.get("veriff_api_key"))
        _member_count = sum(1 for u in _users.values() if u.get("id_verified")) + (1 if _identity and _identity.get("id_verified") else 0)
        _lcompany = _lcfg.get("license_company", "")
        _lglow = _lcfg.get("license_glow_color", "#7ab8e0")
        _llogo = _lcfg.get("license_logo", "")
        if _lcompany:
            logo_img = f'<img src="{_llogo}" style="width:28px;height:28px;border-radius:50%;vertical-align:middle;margin-left:8px;box-shadow:0 0 8px {_lglow};">' if _llogo else ''
            verified_html = f'<p style="text-align:center;font-size:10px;margin-top:15px;margin-bottom:20px;"><span style="color:{_lglow};text-shadow:0 0 8px {_lglow}50;">🦋 Verifiziert durch {_lcompany}{logo_img}</span></p>'
        else:
            verified_html = ''

        # Owner-Migration Status berechnen
        _mcfg = load_config()
        _mstart = _mcfg.get("owner_migrate_started", 0)
        if _mstart:
            _msecs = max(0, int(_mstart + 30*86400 - time.time()))
            _md = _msecs // 86400
            _mh = (_msecs % 86400) // 3600
            _mm = (_msecs % 3600) // 60
            _mready = _msecs == 0
            owner_migrate_html = f'<p style="font-size:10px;color:#f90;margin-bottom:8px;">⏰ Owner-Migration läuft! Noch {_md}T {_mh}h {_mm}min</p><button onclick="doMigrateExport()" class="btn" style="font-size:12px;background:#2a4a2a;" {"" if _mready else "disabled"}>📤 Token generieren {"(bereit!)" if _mready else "(gesperrt)"}</button>'
        else:
            owner_migrate_html = '<p style="font-size:10px;color:#e55;margin-bottom:8px;">⚠️ Owner-Migration: 30 Tage Wartefrist! Alle User werden per Email benachrichtigt.</p><button onclick="doOwnerMigrateStart()" class="btn" style="font-size:12px;background:#4a2a2a;">🔄 Owner-Migration starten (30 Tage)</button>'

        # Session-Cookie prüfen
        session = None
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("nexus_session="):
                token = part.split("=", 1)[1]
                session = validate_auth_session(token)
                break

        # Logout-Parameter? → Login-Seite erzwingen
        from urllib.parse import urlparse, parse_qs
        _qs = parse_qs(urlparse(self.path).query)
        force_logout = 'logout' in _qs

        # ── Content bestimmen ──
        if not force_logout and (is_local or session) and has_account:
            # Eingeloggt (lokal ODER authentifiziert) → Dashboard
            # Wer ist eingeloggt? Owner (lokal) oder Session-User?
            if session and session.get("shinpai_id") != (_identity or {}).get("shinpai_id"):
                # Non-Owner-User via Session
                dash_name = session.get("name", "?")
                dash_id = session.get("shinpai_id", "?")
                dash_extra = ''
            else:
                dash_name = _identity['name']
                dash_id = _identity['shinpai_id']
                dash_extra = ''
            is_owner_session = not session or (session and session.get("shinpai_id") == (_identity or {}).get("shinpai_id"))
            email_verified = '✅' if (_identity or {}).get('email_verified') else '❌'
            smtp_ok = '✅' if smtp_configured() else '❌'
            session_html = '<p class="dim" style="margin-top:10px;color:#888;">🌐 Web-Session aktiv</p>' if session else ''
            logout_html = '<button onclick="doLogout()" class="btn btn-danger" style="font-size:12px;margin:3px;">Abmelden</button>'
            # Logout-Symbol oben rechts schwebend (klein, rot, süß) — IMMER im Dashboard
            logout_corner_html = '<div onclick="doLogout()" style="position:fixed;top:15px;right:15px;cursor:pointer;text-align:center;padding:6px 10px;border:1px solid #5a2a2a;border-radius:8px;background:rgba(40,10,10,0.7);backdrop-filter:blur(8px);transition:all 0.2s;z-index:1000;box-shadow:0 4px 12px rgba(0,0,0,0.4);" onmouseover="this.style.background=\'rgba(80,20,20,0.85)\';this.style.transform=\'scale(1.05)\'" onmouseout="this.style.background=\'rgba(40,10,10,0.7)\';this.style.transform=\'scale(1)\'" title="Abmelden"><div style="font-size:18px;color:#e44;line-height:1;">⏻</div><div style="font-size:8px;color:#e44;font-weight:bold;margin-top:2px;letter-spacing:0.5px;">Logout</div></div>'
            delete_html = ''  # Redundanter matter Button entfernt — neue schöne Lösch-Box übernimmt (siehe Sicherheits-Tab)
            smtp_html = """<button onclick="showSection('smtp-section')" class="btn" style="font-size:12px;margin:3px;background:#1a2a1a;">📧 SMTP</button>""" if is_owner_session else ''
            stripe_html = """<button onclick="showSection('stripe-section')" class="btn" style="font-size:12px;margin:3px;background:#2a1a3a;">💳 Stripe</button>""" if is_owner_session else ''
            _veriff_on = bool(_lcfg.get("veriff_enabled", True) and _lcfg.get("veriff_api_key"))
            veriff_html = """<button onclick="showSection('veriff-section')" class="btn" style="font-size:12px;margin:3px;background:#1a2a2a;">🪪 Veriff</button>""" if is_owner_session else ''
            license_html = """<button onclick="showSection('license-section')" class="btn" style="font-size:12px;margin:3px;background:#1a1a0d;">🦋 Lizenz</button>""" if is_owner_session else ''
            migrate_html = """<button onclick="showSection('migrate-section')" class="btn" style="font-size:12px;margin:3px;background:#0d0d1a;">🔄 Migration</button>"""
            # Migration-Inhalt für Sicherheit-Tab vorberechnen (kein f-string-bruch!)
            _mig_btn_style = 'background:rgba(170,120,255,0.15);border:1px solid rgba(170,120,255,0.4);color:#aa78ff;'
            if is_owner_session:
                migrate_inner_html = owner_migrate_html
            else:
                migrate_inner_html = f'<button onclick="doMigrateExport()" class="btn" style="font-size:12px;width:100%;{_mig_btn_style}">📤 Migrations-Token generieren</button>'

            # Verifiziert-durch Banner über den Tabs (im Dashboard)
            if _lcompany:
                _logo_box = f'<img src="{_llogo}" style="width:24px;height:24px;border-radius:50%;vertical-align:middle;margin-left:8px;box-shadow:0 0 8px {_lglow};">' if _llogo else ''
                dashboard_verified_banner = f'<div style="text-align:center;margin-top:18px;margin-bottom:-8px;"><span style="font-size:11px;color:{_lglow};text-shadow:0 0 8px {_lglow}50;">🦋 Verifiziert durch {_lcompany}</span>{_logo_box}</div>'
            else:
                dashboard_verified_banner = ''

            # Whitelist-Tab nur für Owner sichtbar (vertrauenswürdige Versionen)
            if is_owner_session:
                whitelist_tab_btn = """<button onclick="showDashTab('whitelist')" class="dash-tab" data-tab="whitelist" id="dtab-whitelist" style="font-size:11px;padding:8px 14px;background:none;border:1px solid transparent;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#665540;cursor:pointer;position:relative;z-index:1;">🦋 Whitelist</button>"""
                whitelist_tab_content = """
              <div id="dash-whitelist" class="dash-tab-content" style="display:none;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:15px;">
                <div style="font-size:12px;color:#998866;line-height:1.55;margin-bottom:14px;padding:10px;background:rgba(122,184,224,0.06);border-left:3px solid rgba(122,184,224,0.4);border-radius:4px;">
                  Liste vertrauenswürdiger ShinNexus-Versionen. Jeder Eintrag: <strong>Version + Code-Hash + Bitcoin-TXID</strong>. Drei Felder = eindeutiger Fingerabdruck einer on-chain verifizierten Version. URL ist egal — der Code zählt.<br><br>
                  <span style="color:#7ab8e0;">💡 Tipp:</span> Einfach den Footer einer vertrauten ShinNexus-Seite anklicken (kopiert Fingerabdruck) und unten einfügen.
                </div>
                <!-- Add-Formular: Smart-Paste -->
                <div style="background:linear-gradient(135deg,rgba(90,200,140,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:14px;border:1px solid rgba(90,200,140,0.25);">
                  <div style="font-size:12px;color:#5ac88c;font-weight:bold;margin-bottom:8px;">➕ Neuen Eintrag hinzufügen</div>
                  <input type="text" id="wl-paste" placeholder="Fingerabdruck hier einfügen" oninput="doWhitelistParsePreview()" style="width:100%;margin-bottom:5px;font-size:11px;padding:8px;box-sizing:border-box;">
                  <div id="wl-parse-preview" style="display:none;font-size:10px;color:#887755;margin-bottom:6px;padding:6px 8px;background:rgba(10,15,25,0.6);border-radius:4px;border:1px solid rgba(122,184,224,0.15);font-family:monospace;line-height:1.6;"></div>
                  <input type="text" id="wl-label" placeholder="Label (optional, z.B. Shinpai-AI Official)" maxlength="64" style="margin-bottom:8px;font-size:12px;padding:7px;">
                  <button onclick="doWhitelistAdd()" class="btn" style="font-size:12px;width:100%;background:rgba(90,200,140,0.15);border:1px solid rgba(90,200,140,0.45);color:#5ac88c;">🦋 Hinzufügen</button>
                  <div id="wl-add-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- Import von fremdem Nexus -->
                <div style="background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:14px;border:1px solid rgba(122,184,224,0.25);">
                  <div style="font-size:12px;color:#7ab8e0;font-weight:bold;margin-bottom:8px;">🔗 Whitelist importieren</div>
                  <input type="text" id="wl-import-url" placeholder="URL eines vertrauten Nexus (z.B. https://nexus.shinpai.de)" style="width:100%;margin-bottom:6px;font-size:11px;padding:7px;box-sizing:border-box;">
                  <button onclick="doWhitelistImport()" class="btn" style="font-size:12px;width:100%;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.45);color:#7ab8e0;">🔗 Importieren</button>
                  <div id="wl-import-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- Liste -->
                <div style="font-size:11px;color:#7ab8e0;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">📜 Vertrauenswürdige Versionen</div>
                <div id="wl-list" style="font-size:11px;color:#887755;">Lade…</div>
              </div>
"""
                server_tab_btn = """<button onclick="showDashTab('server')" class="dash-tab" data-tab="server" id="dtab-server" style="font-size:11px;padding:8px 14px;background:none;border:1px solid transparent;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#665540;cursor:pointer;position:relative;z-index:1;">⚙️ Server</button>"""
                server_tab_content = """
              <div id="dash-server" class="dash-tab-content" style="display:none;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:15px;">
                <!-- Bot-Quote (edel bronze-gold, sauber strukturiert) -->
                <div id="bot-quota-tile" style="background:linear-gradient(135deg,#1a1208,#0d0804);padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(212,168,80,0.35);box-shadow:inset 0 0 24px rgba(212,168,80,0.05);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <div style="font-size:12px;color:#d4a850;font-weight:bold;letter-spacing:1px;text-shadow:0 0 6px rgba(212,168,80,0.3);">Bot-Quote</div>
                    <select id="bot-quota-select" style="font-size:12px;padding:4px 10px;background:#0d0804;color:#e8c464;border:1px solid rgba(212,168,80,0.4);border-radius:5px;">
                      <option value="0">0</option>
                      <option value="20" selected>20</option>
                      <option value="50">50</option>
                      <option value="100">100</option>
                      <option value="200">200</option>
                      <option value="1000">1000</option>
                    </select>
                  </div>
                  <input type="password" id="bot-quota-pw" placeholder="aktuelles Passwort" autocomplete="current-password" style="width:100%;box-sizing:border-box;font-size:11px;padding:8px;margin-bottom:6px;background:#0d0804;color:#e8c464;border:1px solid rgba(212,168,80,0.35);border-radius:8px;text-align:center;">
                  <input type="text" id="bot-quota-totp" placeholder="2FA-Code" maxlength="6" inputmode="numeric" style="width:100%;box-sizing:border-box;font-size:11px;padding:8px;margin-bottom:8px;background:#0d0804;color:#e8c464;border:1px solid rgba(212,168,80,0.35);border-radius:8px;text-align:center;letter-spacing:4px;">
                  <button onclick="doBotQuotaSave()" class="btn" style="width:100%;font-size:11px;padding:8px;background:linear-gradient(135deg,#1a1208,#0d0804);border:1px solid rgba(212,168,80,0.6);color:#e8c464;">Ändern</button>
                  <div id="bot-quota-current" style="font-size:10px;color:#8b6f47;margin-top:6px;text-align:center;">…</div>
                  <div id="bot-quota-counter" style="font-size:10px;color:#d4a850;margin-top:4px;text-align:center;"></div>
                  <div id="bot-quota-label" style="display:none;font-size:9px;color:#8b6f47;opacity:0.5;font-style:italic;letter-spacing:0.5px;margin-top:4px;text-align:center;"></div>
                </div>
                <!-- Igni — Haus­schlüssel (schwarz mit Lichtfarben) -->
                <div id="igni-tile" style="display:none;background:linear-gradient(135deg,#050508,#0b0b12);padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(180,220,255,0.2);box-shadow:inset 0 0 24px rgba(180,220,255,0.05);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-size:12px;color:#dfe9ff;font-weight:bold;letter-spacing:1px;">🔑 Haus­schlüssel (Igni)</div>
                    <div id="igni-status" style="font-size:10px;color:#7a8aa0;">…</div>
                  </div>
                  <p style="font-size:10px;color:#8a9ab0;margin:0 0 10px;line-height:1.55;">
                    Maschinengebunden. Im Standard-Modus entsperrt der Server sich beim Start automatisch —
                    der Haus­schlüssel funktioniert <b>nur</b> auf dieser Maschine. Im Paranoid-Modus verlangt
                    jeder Neustart Passwort&nbsp;+&nbsp;2FA.
                  </p>
                  <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;">
                    <label for="igni-mode" style="font-size:11px;color:#bfd0e8;">Modus</label>
                    <select id="igni-mode" style="flex:1;font-size:12px;padding:6px 8px;background:#000;color:#dfe9ff;border:1px solid rgba(180,220,255,0.3);border-radius:5px;">
                      <option value="standard">Standard — Auto-Unlock (Igni aktiv)</option>
                      <option value="paranoid">Paranoid — kein Igni, jeder Start fragt</option>
                    </select>
                  </div>
                  <input type="password" id="igni-pw" placeholder="Aktuelles Passwort" autocomplete="current-password" style="background:#000;color:#dfe9ff;border:1px solid rgba(180,220,255,0.3);margin-bottom:5px;font-size:12px;padding:8px;">
                  <input type="text" id="igni-totp" placeholder="2FA Code" maxlength="6" inputmode="numeric" style="background:#000;color:#dfe9ff;border:1px solid rgba(180,220,255,0.3);margin-bottom:8px;font-size:12px;padding:8px;text-align:center;letter-spacing:6px;">
                  <div style="display:flex;gap:6px;">
                    <button onclick="doIgniSave()" class="btn" style="flex:2;font-size:12px;background:linear-gradient(135deg,#0a1020,#050510);border:1px solid rgba(180,220,255,0.5);color:#dfe9ff;">💾 Modus speichern</button>
                    <button onclick="doIgniExport()" id="igni-export-btn" class="btn" style="flex:1;font-size:12px;background:#000;border:1px solid rgba(180,220,255,0.35);color:#9fbce0;" title="Igni-Ordner als ZIP herunterladen (USB-Kopie für Support/Zweitschlüssel)">📦 USB-Export</button>
                  </div>
                  <div id="igni-msg" style="font-size:11px;margin-top:6px;text-align:center;color:#8a9ab0;"></div>
                </div>
                <!-- Public URL / Verfügbarkeit (Hellblau, analog Kneipe mit Status-Info) -->
                <div style="background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(122,184,224,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-size:12px;color:#7ab8e0;font-weight:bold;">🌐 Öffentliche URL &amp; Verfügbarkeit</div>
                    <div id="srv-public-status" style="font-size:10px;color:#665540;">Lade…</div>
                  </div>
                  <!-- Status-Panel (nur wenn NICHT manuell gesetzt) -->
                  <div id="pu-status-panel" style="display:none;background:rgba(0,0,0,0.25);padding:10px;border-radius:6px;margin-bottom:10px;font-family:monospace;font-size:11px;line-height:1.6;color:#aac0d8;">
                    <div id="pu-status-lines"></div>
                  </div>
                  <!-- Info-Hint bei manueller URL -->
                  <div id="pu-manual-hint" style="display:none;font-size:10px;color:#7ab8e0;margin-bottom:8px;line-height:1.5;">
                    🔗 Manuelle URL ist gesetzt — kein Sniffing nötig. Zum Auto-Detect-Modus: Feld leeren + Speichern.
                  </div>
                  <p style="font-size:10px;color:#665540;margin-bottom:6px;line-height:1.55;">
                    Manuelle URL (Domain/Reverse-Proxy) eintragen, oder leer lassen für Auto-Detect.
                    Der Check testet 2-stufig: erst Self-Request, dann externen Dienst (isitup.org) gegen NAT-Loopback.
                  </p>
                  <input type="text" id="public-url" placeholder="https://nexus.deine-domain.de" style="margin-bottom:6px;font-size:11px;padding:7px;">
                  <div style="display:flex;gap:6px;margin-bottom:6px;">
                    <button onclick="doPublicUrlSave()" class="btn" style="flex:2;font-size:11px;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.4);color:#7ab8e0;">💾 Testen &amp; Speichern</button>
                    <button onclick="doPublicUrlCheckNow()" class="btn" style="flex:1;font-size:11px;background:rgba(122,184,224,0.08);border:1px solid rgba(122,184,224,0.3);color:#9fc8e8;" title="Netzwerk-Check jetzt wiederholen">🔄 Jetzt prüfen</button>
                  </div>
                  <!-- Auto-Check Config (auto-save bei Change) -->
                  <div style="display:flex;gap:6px;align-items:center;margin-bottom:4px;padding:6px 8px;background:rgba(0,0,0,0.2);border-radius:5px;">
                    <label style="font-size:10px;color:#8ba5c0;flex:0 0 auto;">
                      <input type="checkbox" id="pu-autocheck-enabled" onchange="doPublicUrlConfigSave()" style="vertical-align:middle;"> Auto-Check
                    </label>
                    <select id="pu-autocheck-interval" onchange="doPublicUrlConfigSave()" style="flex:1;font-size:10px;padding:3px 6px;background:#0a0f18;color:#aac0d8;border:1px solid rgba(122,184,224,0.25);border-radius:4px;">
                      <option value="300">alle 5 Min</option>
                      <option value="900">alle 15 Min</option>
                      <option value="1800" selected>alle 30 Min</option>
                      <option value="3600">alle 1 h</option>
                      <option value="21600">alle 6 h</option>
                    </select>
                  </div>
                  <div id="public-url-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- SMTP (Hellgrün) -->
                <div style="background:linear-gradient(135deg,rgba(90,200,140,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(90,200,140,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-size:12px;color:#5ac88c;font-weight:bold;">📧 SMTP</div>
                    <div id="srv-smtp-status" style="font-size:10px;color:#665540;">Lade...</div>
                  </div>
                  <div id="srv-smtp-info" style="font-size:10px;color:#887755;line-height:1.6;margin-bottom:8px;"></div>
                  <button onclick="toggleServerEdit('smtp')" class="btn" style="font-size:11px;width:100%;background:rgba(90,200,140,0.15);border:1px solid rgba(90,200,140,0.4);color:#5ac88c;">Bearbeiten</button>
                  <div id="srv-smtp-edit" style="display:none;margin-top:10px;">
                    <input type="text" id="smtp-host" placeholder="SMTP Host (z.B. smtp.migadu.com)" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="text" id="smtp-port" placeholder="Port" value="587" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="text" id="smtp-user" placeholder="SMTP User" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="password" id="smtp-pass" placeholder="SMTP Passwort" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="text" id="smtp-from" placeholder="Absender (optional)" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="email" id="smtp-test" placeholder="Test-Mail an (optional)" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <button onclick="doSmtpSave()" class="btn" style="font-size:11px;width:100%;background:rgba(90,200,140,0.15);border:1px solid rgba(90,200,140,0.4);color:#5ac88c;">💾 Speichern</button>
                    <div id="smtp-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                  </div>
                </div>
                <!-- Stripe (Helllila) -->
                <div style="background:linear-gradient(135deg,rgba(170,120,255,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(170,120,255,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-size:12px;color:#aa78ff;font-weight:bold;">💳 Stripe</div>
                    <div id="srv-stripe-status" style="font-size:10px;color:#665540;">Lade...</div>
                  </div>
                  <div id="srv-stripe-info" style="font-size:10px;color:#887755;line-height:1.6;margin-bottom:8px;"></div>
                  <button onclick="toggleServerEdit('stripe')" class="btn" style="font-size:11px;width:100%;background:rgba(170,120,255,0.15);border:1px solid rgba(170,120,255,0.4);color:#aa78ff;">Bearbeiten</button>
                  <div id="srv-stripe-edit" style="display:none;margin-top:10px;">
                    <input type="password" id="stripe-sk" placeholder="Secret Key (sk_...)" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="text" id="stripe-pk" placeholder="Publishable Key (pk_...)" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <button onclick="doStripeSave()" class="btn" style="font-size:11px;width:100%;background:rgba(170,120,255,0.15);border:1px solid rgba(170,120,255,0.4);color:#aa78ff;">💾 Speichern</button>
                    <div id="stripe-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                  </div>
                </div>
                <!-- Veriff (Helltürkis) -->
                <div style="background:linear-gradient(135deg,rgba(100,220,220,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(100,220,220,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="display:flex;align-items:center;gap:8px;">
                      <div style="font-size:12px;color:#64dcdc;font-weight:bold;">🪪 Veriff</div>
                      """ + (f"""<label style="position:relative;width:32px;height:18px;cursor:pointer;" title="Veriff {'aktiv' if _veriff_on else 'deaktiviert'}">
                        <input type="checkbox" id="veriff-toggle" onchange="doVeriffToggle(this.checked)" {'checked' if _veriff_on else ''} style="opacity:0;width:0;height:0;position:absolute;">
                        <span style="position:absolute;top:0;left:0;right:0;bottom:0;background:{'#4caf50' if _veriff_on else '#e44'};border-radius:9px;transition:background 0.3s;"></span>
                        <span style="position:absolute;top:2px;left:{'16px' if _veriff_on else '2px'};width:14px;height:14px;background:#fff;border-radius:50%;transition:left 0.3s;box-shadow:0 1px 3px rgba(0,0,0,0.3);"></span>
                      </label>""" if is_owner_session else "") + """
                    </div>
                    <div id="srv-veriff-status" style="font-size:10px;color:#665540;">Lade...</div>
                  </div>
                  <div id="srv-veriff-info" style="font-size:10px;color:#887755;line-height:1.6;margin-bottom:8px;"></div>
                  <button onclick="toggleServerEdit('veriff')" class="btn" style="font-size:11px;width:100%;background:rgba(100,220,220,0.15);border:1px solid rgba(100,220,220,0.4);color:#64dcdc;">Bearbeiten</button>
                  <div id="srv-veriff-edit" style="display:none;margin-top:10px;">
                    <input type="password" id="veriff-key" placeholder="API Key" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <input type="text" id="veriff-secret" placeholder="Shared Secret (optional)" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <label style="font-size:10px;color:#665540;">Preis pro Verifikation (Euro)</label>
                    <input type="number" id="veriff-price" step="0.1" min="0" placeholder="3.0" style="margin-bottom:4px;font-size:11px;padding:7px;">
                    <button onclick="doVeriffSave()" class="btn" style="font-size:11px;width:100%;background:rgba(100,220,220,0.15);border:1px solid rgba(100,220,220,0.4);color:#64dcdc;">💾 Speichern</button>
                    <div id="veriff-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                  </div>
                </div>
                <!-- Bitcoin Wallet (Hellorange) — Chain of Trust -->
                <div style="background:linear-gradient(135deg,rgba(245,158,11,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(245,158,11,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-size:12px;color:#f59e0b;font-weight:bold;">₿ Bitcoin Wallet</div>
                    <div id="srv-btc-status" style="font-size:10px;color:#665540;">Lade...</div>
                  </div>
                  <p style="font-size:10px;color:#665540;margin-bottom:10px;line-height:1.5;">
                    Nur für Versionierungs-Updates: Falls du deinen eigenen ShinNexus autark weiterentwickelst,
                    kannst du jeden Release per Code-Hash in der Bitcoin-Blockchain verankern.<br>
                    <span style="color:#887755;">Jeder kann dann prüfen, dass dein Nexus exakt diesen Code ausführt.</span>
                  </p>
                  <div id="btc-wallet-info" style="display:none;margin-bottom:10px;">
                    <div style="background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:10px;margin-bottom:8px;">
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div style="font-size:10px;color:#887755;">Adresse</div>
                        <button onclick="toggleBtcSeed()" id="btc-seed-toggle" style="font-size:10px;padding:2px 8px;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.3);border-radius:4px;color:#f59e0b;cursor:pointer;" title="Seed-Wörter anzeigen">ℹ️ Seed</button>
                      </div>
                      <code id="btc-address" style="color:#f59e0b;font-size:11px;word-break:break-all;"></code>
                    </div>
                    <div id="btc-seed-box" style="display:none;background:rgba(255,85,85,0.06);border:2px solid rgba(255,85,85,0.3);border-radius:8px;padding:12px;margin-bottom:8px;">
                      <div style="font-size:10px;color:#ff5555;font-weight:bold;text-align:center;margin-bottom:6px;">⚠️ SEED — SICHER AUFBEWAHREN!</div>
                      <code id="btc-seed-words" style="color:#ffd700;font-size:12px;line-height:1.8;word-break:break-word;display:block;text-align:center;"></code>
                      <div style="font-size:9px;color:#665540;text-align:center;margin-top:6px;">Mit diesen Wörtern kann das Wallet in jeder BIP84-kompatiblen App wiederhergestellt werden.</div>
                    </div>
                    <div style="display:flex;gap:8px;margin-bottom:8px;">
                      <div style="flex:1;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:10px;text-align:center;">
                        <div style="font-size:10px;color:#887755;margin-bottom:4px;">Balance</div>
                        <span id="btc-balance" style="color:#f59e0b;font-size:13px;font-weight:bold;">—</span>
                      </div>
                      <div style="flex:1;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:10px;text-align:center;">
                        <div style="font-size:10px;color:#887755;margin-bottom:4px;">Anchors</div>
                        <span id="btc-anchors" style="color:#f59e0b;font-size:13px;font-weight:bold;">0</span>
                      </div>
                    </div>
                    <div style="background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:10px;margin-bottom:8px;">
                      <div style="font-size:10px;color:#887755;margin-bottom:4px;">Aktueller Code-Hash</div>
                      <code id="btc-code-hash" style="color:#7ecfff;font-size:10px;word-break:break-all;"></code>
                    </div>
                    <button onclick="doBtcAnchorPreview()" id="btc-anchor-btn" class="btn" style="font-size:11px;width:100%;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.4);color:#f59e0b;">⚓ Code-Hash verankern</button>
                    <div id="btc-anchor-preview" style="display:none;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:10px;margin-top:8px;text-align:center;">
                      <div style="font-size:11px;color:#f59e0b;margin-bottom:6px;">Kosten-Vorschau</div>
                      <div id="btc-preview-fee" style="font-size:13px;color:#ffd700;font-weight:bold;"></div>
                      <div id="btc-preview-hash" style="font-size:9px;color:#665540;margin:4px 0;word-break:break-all;"></div>
                      <div id="btc-preview-dup" style="font-size:10px;color:#e55;display:none;margin:4px 0;"></div>
                      <div style="display:flex;gap:6px;margin-top:8px;">
                        <button onclick="doBtcAnchorConfirm()" id="btc-confirm-btn" class="btn" style="flex:1;font-size:11px;background:rgba(245,158,11,0.2);border:1px solid rgba(245,158,11,0.5);color:#f59e0b;">Verankern!</button>
                        <button onclick="document.getElementById('btc-anchor-preview').style.display='none'" class="btn" style="flex:1;font-size:11px;background:rgba(100,100,100,0.1);border:1px solid #333;color:#888;">Abbrechen</button>
                      </div>
                    </div>
                    <div id="btc-anchor-progress" style="display:none;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:12px;margin-top:8px;text-align:center;">
                      <div style="font-size:11px;color:#f59e0b;margin-bottom:6px;">⏳ Warte auf Bestätigung...</div>
                      <div id="btc-progress-timer" style="font-size:20px;color:#ffd700;font-weight:bold;font-family:monospace;"></div>
                      <div id="btc-progress-status" style="font-size:10px;color:#887755;margin-top:4px;"></div>
                      <div id="btc-progress-cycle" style="font-size:10px;color:#665540;margin-top:2px;"></div>
                    </div>
                    <div id="btc-anchor-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                    <div style="margin-top:8px;">
                      <button onclick="doBtcRevokePreview()" id="btc-revoke-btn" style="display:none;font-size:10px;padding:4px 10px;background:rgba(255,85,85,0.1);border:1px solid rgba(255,85,85,0.3);border-radius:4px;color:#ff5555;cursor:pointer;">🔴 Version widerrufen</button>
                      <div id="btc-revoke-dialog" style="display:none;background:rgba(255,85,85,0.06);border:1px solid rgba(255,85,85,0.2);border-radius:6px;padding:10px;margin-top:6px;">
                        <div style="font-size:11px;color:#ff5555;font-weight:bold;margin-bottom:6px;">⚠️ Widerruf ist ENDGÜLTIG!</div>
                        <div id="btc-revoke-fee" style="font-size:13px;color:#ff5555;font-weight:bold;text-align:center;margin-bottom:4px;"></div>
                        <div id="btc-revoke-info" style="font-size:9px;color:#665540;text-align:center;margin-bottom:8px;word-break:break-all;"></div>
                        <input type="text" id="btc-revoke-totp" placeholder="2FA-Code eingeben" maxlength="6" inputmode="numeric" style="font-size:14px;text-align:center;letter-spacing:4px;padding:8px;">
                        <button onclick="doBtcRevokeConfirm()" id="btc-revoke-confirm-btn" class="btn" style="font-size:11px;width:100%;margin-top:4px;background:rgba(255,85,85,0.15);border:1px solid rgba(255,85,85,0.4);color:#ff5555;">Unwiderruflich widerrufen</button>
                        <button onclick="document.getElementById('btc-revoke-dialog').style.display='none'" class="btn" style="font-size:11px;width:100%;margin-top:4px;background:rgba(100,100,100,0.1);border:1px solid #333;color:#888;">Abbrechen</button>
                        <div id="btc-revoke-msg" style="font-size:10px;margin-top:4px;text-align:center;"></div>
                      </div>
                      <div id="btc-revoke-progress" style="display:none;background:rgba(255,85,85,0.06);border:1px solid rgba(255,85,85,0.15);border-radius:6px;padding:12px;margin-top:8px;text-align:center;">
                        <div style="font-size:11px;color:#ff5555;margin-bottom:6px;">⏳ Warte auf Widerruf-Bestätigung...</div>
                        <div id="btc-revoke-timer" style="font-size:20px;color:#ff5555;font-weight:bold;font-family:monospace;"></div>
                        <div id="btc-revoke-progress-status" style="font-size:10px;color:#887755;margin-top:4px;"></div>
                      </div>
                    </div>
                    <div id="btc-entries" style="margin-top:10px;"></div>
                  </div>
                  <div id="btc-no-wallet" style="text-align:center;">
                    <button onclick="doBtcCreate()" class="btn" style="font-size:11px;width:100%;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.4);color:#f59e0b;">₿ Neues Wallet erstellen</button>
                    <div style="font-size:10px;color:#665540;margin:10px 0 6px;border-top:1px solid rgba(245,158,11,0.15);padding-top:10px;">oder bestehendes Wallet importieren:</div>
                    <textarea id="btc-import-seed" placeholder="12 oder 24 Seed-Wörter (z.B. aus BlueWallet)" rows="3" style="width:100%;font-size:11px;padding:7px;background:#151520;border:1px solid #333;border-radius:8px;color:#e0e0e0;resize:none;"></textarea>
                    <button onclick="doBtcImportSeed()" class="btn" style="font-size:11px;width:100%;margin-top:4px;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.25);color:#f59e0b;">🔑 Seed importieren</button>
                    <details style="margin-top:8px;text-align:left;">
                      <summary style="font-size:10px;color:#665540;cursor:pointer;">WIF direkt eingeben</summary>
                      <input type="text" id="btc-import-wif" placeholder="WIF Private Key (K... oder L...)" style="font-size:11px;padding:7px;margin-top:4px;">
                      <button onclick="doBtcImport()" class="btn" style="font-size:11px;width:100%;margin-top:4px;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.15);color:#887755;">WIF importieren</button>
                    </details>
                  </div>
                  <div id="btc-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- Amt-Listen (Hellgold) — Federation, nur ab Stufe 2 sichtbar -->
                <div id="srv-amt-lists-box" style="display:none;background:linear-gradient(135deg,rgba(212,168,80,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(212,168,80,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-size:12px;color:#d4a850;font-weight:bold;">🏛️ Amt-Listen (Federation)</div>
                    <button onclick="doAmtListsRefresh()" class="btn" style="font-size:10px;padding:4px 10px;background:rgba(212,168,80,0.15);border:1px solid rgba(212,168,80,0.4);color:#d4a850;">🔄 Alle aktualisieren</button>
                  </div>
                  <p style="font-size:10px;color:#665540;margin-bottom:8px;">Abonniere externe JSON-Listen mit Ämtern (wie AdBlock-Filter). Einfach die Domain eingeben — Nexus holt automatisch <code style="color:#d4a850;">/amt-list.json</code>. Jeder kann eigene Listen hosten.</p>
                  <input type="text" id="amt-list-url" placeholder="lab.shinpai.de" style="width:100%;font-size:11px;padding:7px;margin-bottom:6px;">
                  <button onclick="doAmtListSubscribe()" class="btn" style="font-size:11px;padding:7px 14px;background:rgba(212,168,80,0.15);border:1px solid rgba(212,168,80,0.4);color:#d4a850;width:100%;">Abonnieren</button>
                  <div id="amt-list-msg" style="font-size:11px;margin-top:6px;margin-bottom:8px;text-align:center;"></div>
                  <div id="amt-list-table" style="font-size:10px;color:#887755;"></div>
                </div>
                <!-- Member-Liste (ganz unten, rotes destructive Design, Perso-geschützt) -->
                <div style="background:linear-gradient(135deg,rgba(228,68,68,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-top:24px;border:1px solid rgba(228,68,68,0.35);box-shadow:inset 0 0 20px rgba(228,68,68,0.04);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <div style="font-size:12px;color:#e44;font-weight:bold;letter-spacing:1px;">⚠️ Nexus-Member (destructive)</div>
                    <span onclick="loadOwnerMembers()" style="cursor:pointer;font-size:14px;color:#e44;opacity:0.6;transition:opacity 0.2s;" onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.6'" title="Aktualisieren">🔄</span>
                  </div>
                  <p style="font-size:10px;color:#887755;line-height:1.55;margin-bottom:10px;">
                    Nur Shinpai-IDs (DSGVO). Perso-verifizierte Accounts kann nur der User selbst löschen — Owner hat keinen Zugriff (Anti-Veriff-Farm-Schutz).
                    Farbpunkt: <span style="color:#4caf50;">●</span> grün = Perso verifiziert, <span style="color:#d4a850;">●</span> bronze = nur KK, <span style="color:#555;">●</span> grau = keine Belege.
                  </p>
                  <div id="owner-members-list" style="max-height:360px;overflow-y:auto;background:rgba(0,0,0,0.25);border-radius:5px;padding:4px 0;"></div>
                </div>
              </div>"""
            else:
                server_tab_btn = ""
                server_tab_content = ""
                whitelist_tab_btn = ""
                whitelist_tab_content = ""

            body_content = f"""
            <div id="dashboard">
              {logout_corner_html}
              <!-- Reset-Mode-Hinweis (dezent, nur sichtbar wenn pw_reset_pending=true) -->
              <div id="pw-reset-banner" style="display:none;background:linear-gradient(135deg,rgba(212,168,80,0.12),rgba(26,18,8,0.7));border:1px solid rgba(212,168,80,0.4);border-radius:8px;padding:10px 14px;margin-bottom:14px;text-align:center;">
                <div style="font-size:12px;color:#d4a850;letter-spacing:0.5px;">
                  🔑 Reset-Modus aktiv — du kannst Passwort, 2FA oder Email ändern. <span id="pw-reset-days-left-text" style="color:#887755;font-size:11px;"></span>
                  <br><a href="#" onclick="showDashTab('sicherheit');return false;" style="color:#e8c464;text-decoration:underline;font-size:11px;">Sicherheits-Tab öffnen</a>
                </div>
              </div>
              <div style="display:flex;align-items:center;justify-content:center;gap:15px;margin-bottom:10px;">
                <!-- Account-Typ-Icon (links vom Name) — versteckt bei Erwachsener, Klick = Switch -->
                <div id="profile-type-icon" style="display:none;cursor:pointer;" onclick="doAccountTypeSwitch()" title="Klick für Typ-Wechsel"></div>
                <div style="text-align:left;">
                  <h2 style="margin:0;color:#7ab8e0;">{dash_name}</h2>
                  <p class="id" style="margin:2px 0 0;font-size:11px;color:#665540;">{dash_id}</p>
                </div>
                <div id="profile-shield" style="text-align:center;cursor:pointer;padding:15px;overflow:visible;" onclick="smartShieldClick()">
                  <img src="/ShinNexus-Shield.png" id="profile-shield-img" data-basis-ok="{1 if (_identity or {}).get('email_verified') and (_identity or {}).get('totp_confirmed') else 0}" style="width:80px;height:80px;filter:grayscale(100%);transition:filter 0.4s;display:block;margin:0 auto;" title="Klick für Verifikations-Status">
                  <div style="font-size:10px;font-weight:bold;color:#665540;margin-top:4px;" id="profile-shield-label">ShinNexus</div>
                </div>
              </div>
              {dash_extra}

              {dashboard_verified_banner}

              <!-- Share-Banner (analog Kneipe, Hellblau-Style): zeigt aktuelle Nexus-Adresse wenn keine manuelle URL gesetzt -->
              <div id="share-banner-dash" style="display:none;max-width:420px;margin:12px auto 8px;font-size:12px;color:#556677;text-align:center;">
                <div style="margin-bottom:3px;font-style:italic;">Deine Nexus-Adresse:</div>
                <div style="display:flex;gap:6px;align-items:center;justify-content:center;">
                  <span id="share-url-dash" style="font-family:monospace;color:#7ab8e0;font-size:13px;letter-spacing:0.3px;"></span>
                  <button id="btn-copy-share-dash" title="Kopieren" style="background:transparent;border:0;color:#7ab8e0;cursor:pointer;padding:2px 4px;display:inline-flex;align-items:center;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  </button>
                </div>
                <div id="share-hint-dash" style="font-size:10px;color:#556677;margin-top:2px;"></div>
              </div>

              <div id="dash-tabs" style="display:flex;gap:0;margin-top:25px;position:relative;justify-content:center;flex-wrap:wrap;">
                <button onclick="showDashTab('info')" class="dash-tab" data-tab="info" id="dtab-info" style="font-size:11px;padding:8px 14px;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#7ab8e0;cursor:pointer;font-weight:bold;position:relative;z-index:2;">ℹ️ Info</button>
                <button onclick="showDashTab('sicherheit')" class="dash-tab" data-tab="sicherheit" id="dtab-sicherheit" style="font-size:11px;padding:8px 14px;background:none;border:1px solid transparent;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#665540;cursor:pointer;position:relative;z-index:1;">🔐 Sicherheit</button>
                <button onclick="showDashTab('verifikation')" class="dash-tab" data-tab="verifikation" id="dtab-verifikation" style="font-size:11px;padding:8px 14px;background:none;border:1px solid transparent;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#665540;cursor:pointer;position:relative;z-index:1;">🛡️ Verifikation</button>
                <button onclick="showDashTab('lizenzen')" class="dash-tab" data-tab="lizenzen" id="dtab-lizenzen" style="font-size:11px;padding:8px 14px;background:none;border:1px solid transparent;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#665540;cursor:pointer;position:relative;z-index:1;">🦋 Lizenzen</button>
                <button onclick="showDashTab('amt')" class="dash-tab" data-tab="amt" id="dtab-amt" style="font-size:11px;padding:8px 14px;background:none;border:1px solid transparent;border-bottom:1px solid #2a2a3a;border-radius:6px 6px 0 0;margin-bottom:-1px;color:#665540;cursor:pointer;position:relative;z-index:1;">🏛️ Ämter</button>
                {whitelist_tab_btn}
                {server_tab_btn}
              </div>

              <div id="dash-info" class="dash-tab-content" style="background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:20px;">
                <div style="text-align:center;margin-bottom:18px;padding:14px 0;">
                  <img src="/ShinNexus-Logo.webp" style="width:64px;height:64px;border-radius:50%;box-shadow:0 0 20px rgba(122,184,224,0.3);" onerror="this.outerHTML='<div style=font-size:48px>🛡️</div>'">
                  <div style="font-size:14px;color:#7ab8e0;font-weight:bold;margin-top:14px;">ShinNexus</div>
                  <div style="font-size:10px;color:#665540;letter-spacing:2px;margin-top:14px;">SAME KNOWLEDGE. YOUR OWNERSHIP.</div>
                </div>
                <!-- Wer und Warum -->
                <div style="background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(122,184,224,0.25);">
                  <div style="font-size:11px;color:#7ab8e0;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">📜 Wer und Warum</div>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0;">
                    ShinNexus ist Teil von <strong style="color:#7ab8e0;">Shinpai-AI</strong> — einem dezentralen Ökosystem ohne Konzern, ohne Datenkrake, ohne Tracking. Jeder kann seinen eigenen Nexus betreiben. Deine Identität bleibt bei dir, nicht bei Google oder Facebook.
                  </p>
                </div>
                <!-- Philosophie -->
                <div style="background:linear-gradient(135deg,rgba(170,120,255,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(170,120,255,0.25);">
                  <div style="font-size:11px;color:#aa78ff;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">💜 Philosophie</div>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0 0 8px 0;">
                    <em>Wissen ist universell — Identität ist persönlich.</em>
                  </p>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0;">
                    Du besitzt was du bist. Deine Daten, dein Vault, deine Schlüssel. Niemand kann sie dir wegnehmen — nicht mal wir. Same Knowledge. Your Ownership. Genau das.
                  </p>
                </div>
                <!-- Deine Daten -->
                <div style="background:linear-gradient(135deg,rgba(90,200,140,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(90,200,140,0.25);">
                  <div style="font-size:11px;color:#5ac88c;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">🔒 Deine Daten — Keine Angst</div>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0 0 8px 0;">
                    Wir speichern keine personenbezogenen Daten. Kein Name, kein Geburtsdatum, keine Adresse — nur anonyme Hashes die selbst wir nicht entschlüsseln können.
                  </p>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0 0 8px 0;">
                    Falls du jemals alles verlierst — Passwort, Seed, 2FA, Email — kein Stress. Das System räumt alle <strong style="color:#5ac88c;">3 Jahre</strong> inaktive Accounts automatisch auf, inklusive Perso-Hashes. Danach ist alles weg als wärst du nie hier gewesen. Neuanfang immer möglich.
                  </p>
                  <p style="font-size:10px;color:#776655;line-height:1.5;margin:0;font-style:italic;">
                    Und falls du innerhalb der 3 Jahre bei genau diesem Nexus nochmal von vorne anfangen willst, aber wirklich gar nichts mehr hast? Dann, mein Lieber… fang halt nochmal klein an. Ganz klein. Buchstäblich. Nicht jeder Start muss ein großer sein — manchmal reicht auch ein zweiter erster Schritt.
                  </p>
                </div>
                <!-- Der Schmetterling -->
                <div style="background:linear-gradient(135deg,rgba(212,168,80,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(212,168,80,0.25);">
                  <div style="font-size:11px;color:#d4a850;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">🦋 Der Schmetterling</div>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0 0 8px 0;">
                    Der lebende Schmetterling über jedem ShinNexus ist sein Wasserzeichen. Seine Flugbahn entsteht aus dem SHA-256 Hash des Quellcodes — wird der Code verändert, fliegt ein anderer Schmetterling.
                  </p>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0 0 8px 0;">
                    <strong style="color:#d4a850;">Gerätespezifisch identisch:</strong> Auf jedem PC fliegt er gleich, auf jedem Handy fliegt er gleich. PC und Handy fliegen unterschiedlich — die Flugbahn passt sich dem Bildschirm an, nicht der Zeit.
                  </p>
                  <p style="font-size:11px;color:#998866;line-height:1.6;margin:0;">
                    Kryptographisch unfälschbar. Lebendig. Schön.
                  </p>
                </div>
                <p style="font-size:9px;color:#445566;text-align:center;margin-top:14px;">Ist einfach passiert. 🐉</p>
                <!-- Titel-Register (unsichtbar bis erster Titel) -->
                <div id="titel-register" style="display:none;margin-top:14px;">
                  <div style="background:linear-gradient(135deg,rgba(245,158,11,0.08),rgba(10,15,25,0.6));padding:14px;border-radius:8px;border:1px solid rgba(245,158,11,0.25);">
                    <div style="font-size:11px;color:#f59e0b;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">🏅 Titel-Register</div>
                    <div id="titel-earned" style="margin-bottom:8px;"></div>
                    <div id="titel-progress"></div>
                  </div>
                </div>
              </div>

              <div id="dash-sicherheit" class="dash-tab-content" style="display:none;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:15px;">
                <!-- Email anzeigen + ändern (Warmweiß) -->
                <div id="email-card" style="background:linear-gradient(135deg,rgba(232,232,232,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(232,232,232,0.25);">
                  <div style="font-size:12px;color:#e8e8e8;margin-bottom:8px;font-weight:bold;">📧 Email</div>
                  <div id="current-email-row" style="font-size:12px;color:#c8c8c8;margin-bottom:10px;padding:6px 10px;background:rgba(0,0,0,0.25);border-radius:4px;display:flex;align-items:center;justify-content:space-between;gap:8px;">
                    <span id="current-email-value" style="font-family:monospace;word-break:break-all;">—</span>
                    <span id="current-email-badge" style="font-size:10px;padding:2px 6px;border-radius:3px;white-space:nowrap;"></span>
                  </div>
                  <input type="email" id="new-email" placeholder="Neue Email-Adresse" autocomplete="email" style="margin-bottom:5px;font-size:12px;padding:8px;">
                  <input type="password" id="email-change-pw" placeholder="Aktuelles Passwort" autocomplete="current-password" style="margin-bottom:5px;font-size:12px;padding:8px;">
                  <input type="text" id="email-change-totp" placeholder="2FA Code" maxlength="6" inputmode="numeric" style="margin-bottom:8px;font-size:12px;padding:8px;text-align:center;letter-spacing:6px;">
                  <button onclick="doChangeEmail()" class="btn" style="font-size:12px;width:100%;background:rgba(232,232,232,0.12);border:1px solid rgba(232,232,232,0.4);color:#e8e8e8;">Ändern</button>
                  <div id="email-change-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                  <!-- Code-Verifikation (nur sichtbar wenn Email unverifiziert) -->
                  <div id="email-verify-box" style="display:none;margin-top:10px;padding:10px;background:rgba(0,0,0,0.25);border:1px dashed rgba(232,232,232,0.25);border-radius:6px;">
                    <div style="font-size:11px;color:#e8e8e8;text-align:center;margin-bottom:8px;">📬 6-stelliger Code aus der Mail</div>
                    <input type="text" id="verify-code-input" placeholder="000000" maxlength="6" inputmode="numeric" pattern="[0-9]*" style="text-align:center;font-size:22px;letter-spacing:10px;font-family:monospace;padding:8px;margin-bottom:6px;background:#000;color:#e8e8e8;border:1px solid rgba(232,232,232,0.35);">
                    <button onclick="doVerifyCode()" class="btn" style="font-size:12px;width:100%;background:rgba(76,175,80,0.15);border:1px solid rgba(76,175,80,0.45);color:#8ad89a;">✅ Verifizieren</button>
                    <div id="verify-code-msg" style="font-size:11px;margin-top:6px;text-align:center;color:#887755;">
                      Kein Code bekommen? <a href="#" onclick="resendVerifyMail();return false;" style="color:#e8e8e8;">Neu senden</a> (10 Min gültig)
                    </div>
                  </div>
                </div>
                <!-- PW-Reset-Modus (rot, nur sichtbar wenn pw_reset_pending=true) -->
                <div id="pw-reset-card" style="display:none;background:linear-gradient(135deg,rgba(228,68,68,0.12),rgba(60,0,0,0.6));padding:14px;border-radius:8px;margin-bottom:10px;border:2px solid rgba(228,68,68,0.5);box-shadow:0 0 20px rgba(228,68,68,0.15);">
                  <div style="font-size:13px;color:#ffdada;margin-bottom:8px;font-weight:bold;">🔑 Neues Passwort setzen (Reset-Modus)</div>
                  <p style="font-size:10px;color:#ffcaca;margin-bottom:8px;line-height:1.5;">Kein altes Passwort nötig — Seed-Phrase war der Beweis. Wenn du Owner bist, Seed-Phrase nochmal hier eingeben (Vault-Re-Encrypt).</p>
                  <input type="password" id="reset-new-pw" placeholder="Neues Passwort (min 6 Zeichen)" autocomplete="new-password" style="margin-bottom:5px;font-size:12px;padding:8px;background:#1a0505;border:1px solid rgba(228,68,68,0.4);color:#ffdada;">
                  <input type="password" id="reset-new-pw2" placeholder="Neues Passwort wiederholen" autocomplete="new-password" style="margin-bottom:5px;font-size:12px;padding:8px;background:#1a0505;border:1px solid rgba(228,68,68,0.4);color:#ffdada;">
                  <textarea id="reset-owner-seed" placeholder="NUR Owner: Seed-Phrase nochmal (24 Wörter)" rows="2" style="margin-bottom:8px;font-size:11px;padding:8px;background:#1a0505;border:1px solid rgba(228,68,68,0.4);color:#ffdada;font-family:monospace;resize:vertical;width:100%;"></textarea>
                  <button onclick="doPwResetSet()" class="btn" style="font-size:12px;width:100%;background:rgba(228,68,68,0.2);border:1px solid rgba(228,68,68,0.6);color:#ffdada;">🔑 Passwort setzen</button>
                  <div id="reset-pw-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                  <div style="margin-top:10px;padding:10px;background:rgba(212,168,80,0.06);border:1px dashed rgba(212,168,80,0.25);border-radius:6px;">
                    <p style="font-size:10px;color:#d4a850;line-height:1.6;margin:0;text-align:center;">Keine Angst, junger Padawan! Passwort muss zuerst erneuert werden, damit alles andere sauber greifen kann. 2FA und Email kannst du danach in aller Ruhe anpassen. Eins nach dem anderen, die Macht ist mit dir.</p>
                  </div>
                </div>
                <!-- Passwort ändern (Hellblau, normaler Modus) -->
                <div id="normal-pw-card" style="background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(122,184,224,0.25);">
                  <div style="font-size:12px;color:#7ab8e0;margin-bottom:8px;font-weight:bold;">🔑 Passwort ändern</div>
                  <input type="password" id="old-pw" placeholder="Aktuelles Passwort" autocomplete="current-password" style="margin-bottom:5px;font-size:12px;padding:8px;">
                  <input type="password" id="new-pw" placeholder="Neues Passwort" autocomplete="new-password" style="margin-bottom:5px;font-size:12px;padding:8px;">
                  <input type="password" id="new-pw2" placeholder="Neues Passwort wiederholen" autocomplete="new-password" style="margin-bottom:5px;font-size:12px;padding:8px;">
                  <input type="text" id="pw-totp" placeholder="2FA Code" maxlength="6" inputmode="numeric" style="margin-bottom:8px;font-size:12px;padding:8px;text-align:center;letter-spacing:6px;">
                  <button onclick="doChangePassword()" class="btn" style="font-size:12px;width:100%;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.4);color:#7ab8e0;">Ändern</button>
                  <div id="pw-change-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- 2FA neu (Hellorange) -->
                <div id="twofa-card" style="background:linear-gradient(135deg,rgba(255,165,80,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(255,165,80,0.25);">
                  <div style="font-size:12px;color:#ffa550;margin-bottom:8px;font-weight:bold;">🔐 2FA neu einrichten</div>
                  <p style="font-size:10px;color:#665540;margin-bottom:8px;">Neuer QR-Code wird per E-Mail gesendet. 2 Minuten Zeit zum Scannen.</p>
                  <button onclick="do2faRefresh()" class="btn" style="font-size:12px;width:100%;margin-bottom:6px;background:rgba(255,165,80,0.15);border:1px solid rgba(255,165,80,0.4);color:#ffa550;">Neuen QR anfordern</button>
                  <div id="2fa-refresh-msg" style="font-size:11px;margin:8px 0;text-align:center;"></div>
                  <div id="2fa-refresh-confirm" style="display:none;margin-top:8px;">
                    <input type="text" id="2fa-new-code" placeholder="Neuer 2FA Code" maxlength="6" inputmode="numeric" style="font-size:14px;padding:8px;text-align:center;letter-spacing:6px;margin-bottom:6px;">
                    <button onclick="do2faConfirm()" class="btn" style="font-size:12px;width:100%;background:rgba(255,165,80,0.15);border:1px solid rgba(255,165,80,0.4);color:#ffa550;">Bestätigen</button>
                    <div id="2fa-timer" style="font-size:11px;color:#e08040;margin-top:4px;text-align:center;"></div>
                  </div>
                </div>
                <!-- Seed erneuern (Terracotta — warm rötlich, aber nicht Alarm-Rot) -->
                <div id="seed-refresh-card" style="background:linear-gradient(135deg,rgba(200,116,84,0.10),rgba(30,12,8,0.6));padding:12px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(200,116,84,0.35);">
                  <div style="font-size:12px;color:#c87454;margin-bottom:8px;font-weight:bold;">🌱 Recovery-Seed erneuern</div>
                  <p style="font-size:10px;color:#998866;margin-bottom:8px;line-height:1.5;">Ersetzt deinen 24-Wort-Seed durch einen neuen. Alter Seed wird sofort ungültig. Erfordert Passwort + 2FA + verifizierte Email (höchste Sicherheitsstufe).</p>
                  <input type="password" id="seed-refresh-pw" placeholder="Aktuelles Passwort" autocomplete="current-password" style="margin-bottom:5px;font-size:12px;padding:8px;background:#1a100a;border:1px solid rgba(200,116,84,0.3);color:#e8d4c8;">
                  <input type="text" id="seed-refresh-totp" placeholder="2FA Code" maxlength="6" inputmode="numeric" style="margin-bottom:8px;font-size:12px;padding:8px;text-align:center;letter-spacing:6px;background:#1a100a;border:1px solid rgba(200,116,84,0.3);color:#e8d4c8;">
                  <button onclick="doSeedRefresh()" class="btn" style="font-size:12px;width:100%;background:rgba(200,116,84,0.15);border:1px solid rgba(200,116,84,0.5);color:#c87454;">🌱 Neuen Seed generieren</button>
                  <div id="seed-refresh-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                  <div id="seed-refresh-display" style="display:none;margin-top:10px;padding:12px;background:#0d1a0d;border:1px solid rgba(90,200,140,0.35);border-radius:6px;">
                    <div style="color:#5ac88c;font-size:11px;font-weight:bold;margin-bottom:8px;text-align:center;">🌱 Dein neuer Recovery-Seed (JETZT aufschreiben!)</div>
                    <div id="seed-refresh-value" style="font-family:monospace;font-size:11px;color:#9d9;line-height:1.8;text-align:center;word-spacing:4px;background:#000;padding:10px;border-radius:4px;"></div>
                    <div style="font-size:10px;color:#887755;margin-top:8px;text-align:center;font-style:italic;">Wird nur EINMAL gezeigt. Papier, Passwort-Manager, safe deposit box — dein Ding.</div>
                  </div>
                </div>
                <!-- Migration (Helllila) -->
                <div id="migrate-card" style="background:linear-gradient(135deg,rgba(170,120,255,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(170,120,255,0.25);">
                  <div style="font-size:12px;color:#aa78ff;margin-bottom:8px;font-weight:bold;">🔄 Migration</div>
                  <p style="font-size:10px;color:#665540;margin-bottom:8px;">Umzug zu einem anderen ShinNexus. Trag unten die URL des <b>Ziel-Nexus</b> ein (wohin du umziehen willst) — dein Nexus prüft den Fremden gegen deine Whitelist bevor er Daten freigibt.</p>
                  <label style="font-size:10px;color:#aa78ff;display:block;margin-bottom:3px;">Wohin willst du umziehen?</label>
                  <input type="text" id="migrate-target-url" placeholder="https://fremder-nexus.beispiel.de" style="width:100%;margin-bottom:6px;font-size:11px;padding:8px;box-sizing:border-box;">
                  <div id="migrate-target-reject" style="display:none;background:rgba(228,68,68,0.08);border:1px solid rgba(228,68,68,0.35);border-radius:6px;padding:10px;margin-bottom:8px;font-size:10px;color:#e8a0a0;line-height:1.6;"></div>
                  {migrate_inner_html}
                  <div id="migrate-token" style="display:none;margin-top:8px;">
                    <code id="migrate-token-value" style="font-size:10px;color:#d4a850;word-break:break-all;background:#0a0a0a;padding:8px;border-radius:4px;display:block;margin:5px 0;"></code>
                    <button onclick="copyMigrateToken()" class="btn" style="font-size:11px;width:100%;background:rgba(170,120,255,0.15);border:1px solid rgba(170,120,255,0.4);color:#aa78ff;">📋 Token kopieren</button>
                    <p style="font-size:9px;color:#665540;margin-top:6px;">Token ist 1 Stunde gültig.</p>
                  </div>
                  <div id="migrate-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- Account löschen (nur Nicht-Owner) -->
                {'<div style="background:linear-gradient(135deg,rgba(228,68,68,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:10px;border:1px solid rgba(228,68,68,0.35);"><div style="font-size:12px;color:#e44;margin-bottom:8px;font-weight:bold;">🗑️ Account löschen</div><p style="font-size:10px;color:#887755;line-height:1.55;margin-bottom:8px;">Unwiderruflich. PW + 2FA erforderlich. Bei Perso-Verifikation: Perso-Hash wird 90 Tage gesperrt, danach Neuanfang möglich.</p><button onclick="doAccountDeleteSelf()" class="btn" style="font-size:12px;width:100%;background:rgba(228,68,68,0.15);border:1px solid rgba(228,68,68,0.5);color:#e44;">🗑️ Mein Account löschen</button></div>' if not is_owner_session else ''}
                <div style="text-align:center;margin-top:10px;">
                  {delete_html}
                </div>
              </div>

              <div id="dash-verifikation" class="dash-tab-content" style="display:none;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:15px;">
                <div id="verify-status" style="font-size:12px;color:#888;margin-bottom:8px;text-align:center;">Lade Status...</div>
                <!-- Kreditkarten-Info oben, immer sichtbar wenn hinterlegt (Klick = Karte ändern) -->
                <div id="verify-card-top" style="display:none;font-size:11px;margin-bottom:14px;padding:8px 12px;background:rgba(122,184,224,0.08);border:1px solid rgba(122,184,224,0.25);border-radius:6px;text-align:center;cursor:pointer;" onclick="doVerifyCardChange()" title="Klick zum Kartentausch"></div>
                <div id="verify-stripe-row" style="background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:8px;border:1px solid rgba(122,184,224,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <div style="font-size:13px;color:#7ab8e0;">💳 Stufe 1 — Kreditkarte (18+)</div>
                    <div style="font-size:11px;color:#4caf50;font-weight:bold;">0,00 €</div>
                  </div>
                  <p style="font-size:10px;color:#665540;margin-bottom:8px;">Beweist 18+ ohne Daten zu speichern. Nur Prüfung, keine Abbuchung.</p>
                  <div id="verify-card-info" style="display:none;font-size:11px;color:#7ab8e0;background:rgba(10,20,40,0.5);padding:8px 10px;border-radius:6px;margin-bottom:8px;border:1px solid rgba(122,184,224,0.2);"></div>
                  <button onclick="doVerifyStart()" class="btn" id="verify-btn" style="font-size:12px;width:100%;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.4);color:#7ab8e0;display:none;">🔐 Jetzt verifizieren</button>
                  <div id="stripe-card" style="display:none;margin-top:10px;background:#111;padding:15px;border-radius:8px;border:1px solid #333;">
                    <div id="stripe-element" style="background:#1a1a2a;padding:12px;border-radius:6px;border:1px solid #333;min-height:44px;"></div>
                    <button onclick="doStripeConfirm()" class="btn" id="stripe-btn" style="font-size:12px;margin-top:8px;width:100%;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.4);color:#7ab8e0;">✅ Karte bestätigen</button>
                    <div id="stripe-msg" style="font-size:11px;margin-top:6px;"></div>
                  </div>
                </div>
                <!-- Perso-Info oben, immer sichtbar wenn hinterlegt (Klick = Perso ändern) -->
                <div id="verify-perso-top" style="display:none;font-size:11px;margin-bottom:14px;padding:8px 12px;background:rgba(90,200,140,0.08);border:1px solid rgba(90,200,140,0.25);border-radius:6px;text-align:center;cursor:pointer;" onclick="doVerifyPersoChange()" title="Klick zum Perso-Tausch"></div>
                <div id="verify-veriff-row" style="background:linear-gradient(135deg,rgba(90,200,140,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:8px;border:1px solid rgba(90,200,140,0.25);">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <div style="font-size:13px;color:#5ac88c;">🪪 Stufe 2 — Identität bestätigen (Veriff)</div>
                    <div id="veriff-price-display" style="font-size:11px;color:#d4a850;font-weight:bold;">–</div>
                  </div>
                  <p style="font-size:10px;color:#665540;margin-bottom:6px;">Personalausweis-Scan + Gesichtsabgleich. Parallel zu Stufe 1 möglich — Kinder können Perso ohne KK hinterlegen.</p>
                  <p style="font-size:10px;color:#e44;margin-bottom:8px;font-weight:bold;">⚠️ Bezahlung erfolgt sofort beim Start. Keine Erstattung bei Fehlschlag.</p>
                  <p style="font-size:9px;color:#887755;margin-bottom:8px;line-height:1.5;font-style:italic;">📜 Dein Perso und Account werden maximal 3 Jahre ohne Login aufbewahrt. Danach wird alles gelöscht — aus so vielen guten Gründen, dass das Universum zwei Mal neu entstehen würde, bevor wir sie alle aufzählen könnten. Also: ab und zu mal vorbeischauen, junger Padawan!</p>
                  <div id="verify-perso-info" style="display:none;font-size:11px;color:#5ac88c;background:rgba(10,40,25,0.5);padding:8px 10px;border-radius:6px;margin-bottom:8px;border:1px solid rgba(90,200,140,0.2);"></div>
                  <button onclick="doVeriffStart()" class="btn" id="veriff-start-btn" style="font-size:12px;width:100%;background:rgba(90,200,140,0.15);border:1px solid rgba(90,200,140,0.4);color:#5ac88c;">🪪 Identität verifizieren</button>
                </div>
                <!-- Stufe 3 — Amtliche Bestätigung (flache Liste nach Kategorie gruppiert) -->
                <div id="verify-amt-row" style="background:linear-gradient(135deg,rgba(212,168,80,0.08),rgba(10,15,25,0.6));padding:12px;border-radius:8px;margin-bottom:8px;border:1px solid rgba(212,168,80,0.25);opacity:0.5;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <div style="font-size:13px;color:#d4a850;">🏛️ Stufe 3 — Amtlich bestätigt</div>
                    <div id="verify-amt-status" style="font-size:10px;color:#665540;">gesperrt</div>
                  </div>
                  <p style="font-size:10px;color:#665540;margin-bottom:10px;">Die Ämter die du im Ämter Tab abonnierst erscheinen hier. Klick auf Beantragen stellt den Antrag an das Amt.</p>
                  <div id="verify-amt-list" style="font-size:11px;color:#887755;"></div>
                </div>

                <button onclick="doVerifyAusweis()" class="btn" id="ausweis-btn" style="font-size:12px;margin-top:8px;width:100%;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.4);color:#7ab8e0;display:none;">📜 Nexus-Ausweis anzeigen</button>
                <button onclick="doVerifyReset()" class="btn" id="verify-reset-btn" style="font-size:11px;margin-top:8px;width:100%;background:rgba(228,68,68,0.10);border:1px solid rgba(228,68,68,0.35);color:#e44;display:none;">🔄 Verifikation zurücksetzen</button>
                <div id="verify-msg" style="font-size:11px;margin-top:6px;"></div>
                <div id="ausweis-display" style="display:none;margin-top:10px;background:#0a1a2a;padding:15px;border-radius:8px;border:1px solid #1a3a5a;">
                  <pre id="ausweis-data" style="font-size:10px;color:#7ab8e0;white-space:pre-wrap;word-break:break-all;"></pre>
                </div>
              </div>

              <div id="dash-lizenzen" class="dash-tab-content" style="display:none;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:15px;">
                <!-- Meine Lizenz: Edit + Anzeige in einem (NUR OWNER) -->
                <div id="my-license-edit-box" style="display:{'block' if is_owner_session else 'none'};background:#0a0a14;padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid #2a2a1a;">
                  <div style="font-size:11px;color:#d4a850;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;text-align:center;">📜 Meine Lizenz</div>
                  <div style="display:flex;gap:12px;align-items:flex-start;">
                    <div style="flex:1;">
                      <label style="font-size:10px;color:#665540;">Firmenname (3-12 Zeichen)</label>
                      <input type="text" id="license-company" placeholder="z.B. Shinpai-AI" maxlength="12" style="margin-top:3px;font-size:13px;padding:8px;width:100%;">
                      <label style="font-size:10px;color:#665540;margin-top:8px;display:block;">Glow-Farbe</label>
                      <select id="license-glow" style="margin-top:3px;font-size:12px;padding:8px;width:100%;">
                        <option value="#7ab8e0">Hellblau</option>
                        <option value="#d4a850">Gold</option>
                        <option value="#e44">Rot</option>
                        <option value="#4a4">Grün</option>
                        <option value="#fff">Weiß</option>
                        <option value="#f90">Orange</option>
                        <option value="#a6f">Lila</option>
                      </select>
                      <label style="font-size:10px;color:#665540;margin-top:8px;display:block;">Prüf-Nexus URL</label>
                      <input type="text" id="license-verifier" placeholder="https://nexus.shinpai.de" style="margin-top:3px;font-size:12px;padding:8px;width:100%;">
                    </div>
                    <div style="text-align:center;width:128px;">
                      <div id="license-logo-box" style="width:96px;height:96px;border-radius:50%;background:#1a1a2a;border:2px dashed #3a3a4a;margin:0 auto;display:flex;align-items:center;justify-content:center;font-size:30px;color:#3a3a4a;">📷</div>
                      <input type="file" id="license-logo" accept="image/*" style="display:none;" onchange="openCrop(this)">
                      <button onclick="document.getElementById('license-logo').click()" class="btn" style="font-size:10px;margin-top:6px;width:100%;padding:6px;">Bild ändern</button>
                    </div>
                  </div>
                  <div id="license-id-display" style="font-size:10px;color:#665540;margin-top:10px;text-align:center;display:none;"></div>
                  <div id="license-code-hash" style="font-size:9px;color:#445566;margin-top:4px;text-align:center;font-family:monospace;"></div>
                  <div style="text-align:center;margin-top:14px;">
                    <button onclick="doLicenseSave()" id="license-save-btn" style="background:none;border:none;cursor:pointer;padding:0;" title="Schmetterling klicken zum Speichern und Verifizieren">
                      <div style="font-size:34px;">🦋</div>
                      <div style="font-size:10px;color:#d4a850;font-weight:bold;margin-top:4px;">Speichern &amp; Verifizieren</div>
                    </button>
                  </div>
                  <div id="license-msg" style="font-size:11px;margin-top:6px;text-align:center;"></div>
                </div>
                <!-- Crop-Area (popup) -->
                <div id="crop-area" style="display:none;background:#0d0d1a;padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid #3a3a5a;text-align:center;">
                  <div style="font-size:11px;color:#7ab8e0;margin-bottom:8px;">Bild zuschneiden (ziehen + scrollen zum zoomen)</div>
                  <div style="position:relative;width:150px;height:150px;margin:0 auto;overflow:hidden;border-radius:50%;border:2px solid #d4a850;">
                    <canvas id="crop-canvas" width="150" height="150" style="cursor:move;"></canvas>
                  </div>
                  <button onclick="confirmCrop()" class="btn" style="font-size:11px;margin-top:10px;">✅ Übernehmen</button>
                  <button onclick="cancelCrop()" class="btn btn-danger" style="font-size:11px;margin-top:10px;margin-left:6px;">Abbrechen</button>
                </div>
                <!-- Erhaltene Lizenzen -->
                <div style="background:#0a0a14;padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid #1a2a3a;">
                  <div style="font-size:11px;color:#7ab8e0;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">🛡️ Verifizierungen erhalten</div>
                  <div id="received-licenses" style="font-size:11px;color:#665540;">Noch keine Verifizierungen. Sobald ein anderer Nexus dich verifiziert, erscheint die Lizenz hier.</div>
                </div>
                <!-- Abgelaufene Lizenzen -->
                <div id="expired-licenses-box" style="display:none;background:#0a0a14;padding:14px;border-radius:8px;margin-bottom:10px;border:1px solid #2a1a1a;">
                  <div style="font-size:11px;color:#f59e0b;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">⌛ Abgelaufen</div>
                  <div id="expired-licenses" style="font-size:11px;color:#665540;"></div>
                </div>
                <!-- Als Prüfstelle ausgestellt -->
                <div style="background:#0a0a14;padding:14px;border-radius:8px;border:1px solid #2a1a2a;">
                  <div style="font-size:11px;color:#a06ad0;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">🪶 Als Prüfstelle ausgestellt</div>
                  <div id="issued-licenses" style="font-size:11px;color:#665540;">Du hast noch keine anderen Nexus verifiziert. Bedingung: Selbst verifiziert sein.</div>
                </div>
                <p style="font-size:9px;color:#445566;text-align:center;margin-top:12px;">Challenge-Response Verifikation kommt mit dem Wasserzeichen-Update.</p>
              </div>

              <!-- Ämter-Tab (Lizenzmodell Phase 1, Drill-Down Navigation: Kategorie → Subklasse → Ämter) -->
              <div id="dash-amt" class="dash-tab-content" style="display:none;background:rgba(20,20,30,0.6);border:1px solid #2a2a3a;border-top:1px solid #2a2a3a;border-radius:0 8px 8px 8px;padding:18px;">

                <!-- Suchleiste (algorithmische Synonym-Suche) -->
                <div style="background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:12px 14px;border-radius:8px;margin-bottom:14px;border:1px solid rgba(122,184,224,0.25);">
                  <input type="text" id="amt-search-input" placeholder="🔍 Tipp ein was du brauchst: Führerschein, bin krank, Bonität..." oninput="amtSearch(this.value)" style="width:100%;font-size:12px;padding:9px 12px;">
                  <div id="amt-search-results" style="margin-top:8px;font-size:10px;color:#665540;"></div>
                </div>

                <!-- Breadcrumb -->
                <div id="amt-breadcrumb" style="font-size:11px;color:#665540;margin-bottom:14px;min-height:16px;">
                  <span onclick="amtGoLevel(1)" style="cursor:pointer;color:#7ab8e0;">🏛️ Ämter</span>
                  <span id="amt-bc-cat" style="display:none;"> › <span onclick="amtGoLevel(2)" style="cursor:pointer;" id="amt-bc-cat-name"></span></span>
                  <span id="amt-bc-sub" style="display:none;"> › <span id="amt-bc-sub-name"></span></span>
                </div>

                <!-- LEVEL 1: Kategorie-Auswahl -->
                <div id="amt-level-1">
                  <div style="text-align:center;margin-bottom:16px;">
                    <div style="font-size:13px;color:#7ab8e0;font-weight:bold;">Wähle eine Kategorie</div>
                    <div style="font-size:10px;color:#665540;margin-top:3px;">Fünf Oberkategorien, jede mit fünf Unterkategorien. Klick auf eine Karte zum Öffnen.</div>
                  </div>

                  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;">

                    <div onclick="amtOpenCat('identity')" style="cursor:pointer;background:linear-gradient(135deg,rgba(228,68,68,0.08),rgba(10,15,25,0.6));padding:16px;border-radius:8px;border:1px solid rgba(228,68,68,0.25);text-align:center;transition:transform 0.15s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                      <div style="font-size:26px;margin-bottom:6px;">🆔</div>
                      <div style="font-size:12px;color:#e44;font-weight:bold;letter-spacing:0.5px;">IDENTITÄT</div>
                      <div style="font-size:9px;color:#887755;margin-top:4px;">5 Subklassen</div>
                    </div>

                    <div onclick="amtOpenCat('finance')" style="cursor:pointer;background:linear-gradient(135deg,rgba(212,168,80,0.08),rgba(10,15,25,0.6));padding:16px;border-radius:8px;border:1px solid rgba(212,168,80,0.25);text-align:center;transition:transform 0.15s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                      <div style="font-size:26px;margin-bottom:6px;">💰</div>
                      <div style="font-size:12px;color:#d4a850;font-weight:bold;letter-spacing:0.5px;">FINANZEN</div>
                      <div style="font-size:9px;color:#887755;margin-top:4px;">5 Subklassen</div>
                    </div>

                    <div onclick="amtOpenCat('health')" style="cursor:pointer;background:linear-gradient(135deg,rgba(68,170,68,0.08),rgba(10,15,25,0.6));padding:16px;border-radius:8px;border:1px solid rgba(68,170,68,0.25);text-align:center;transition:transform 0.15s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                      <div style="font-size:26px;margin-bottom:6px;">🌿</div>
                      <div style="font-size:12px;color:#4a4;font-weight:bold;letter-spacing:0.5px;">GESUNDHEIT</div>
                      <div style="font-size:9px;color:#887755;margin-top:4px;">5 Subklassen</div>
                    </div>

                    <div onclick="amtOpenCat('authority')" style="cursor:pointer;background:linear-gradient(135deg,rgba(122,184,224,0.08),rgba(10,15,25,0.6));padding:16px;border-radius:8px;border:1px solid rgba(122,184,224,0.25);text-align:center;transition:transform 0.15s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                      <div style="font-size:26px;margin-bottom:6px;">⚙️</div>
                      <div style="font-size:12px;color:#7ab8e0;font-weight:bold;letter-spacing:0.5px;">BEFUGNIS</div>
                      <div style="font-size:9px;color:#887755;margin-top:4px;">5 Subklassen</div>
                    </div>

                    <div onclick="amtOpenCat('affiliation')" style="cursor:pointer;background:linear-gradient(135deg,rgba(170,120,255,0.08),rgba(10,15,25,0.6));padding:16px;border-radius:8px;border:1px solid rgba(170,120,255,0.25);text-align:center;transition:transform 0.15s;" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                      <div style="font-size:26px;margin-bottom:6px;">🌍</div>
                      <div style="font-size:12px;color:#aa78ff;font-weight:bold;letter-spacing:0.5px;">ZUGEHÖRIGKEIT</div>
                      <div style="font-size:9px;color:#887755;margin-top:4px;">5 Subklassen</div>
                    </div>
                  </div>

                  <div style="background:rgba(20,30,50,0.4);padding:14px;border-radius:8px;margin-top:16px;border:1px solid rgba(122,184,224,0.2);">
                    <div style="font-size:11px;color:#7ab8e0;font-weight:bold;margin-bottom:6px;">💡 So funktioniert es</div>
                    <div style="font-size:10px;color:#887755;line-height:1.6;">
                      Klick auf eine Kategorie → du siehst die fünf Unterkategorien. Klick auf eine Unterkategorie → du siehst die registrierten Ämter die das anbieten. Wählst du ein Amt aus → wandert es in deinen Verifikations-Tab und du kannst dort einen Antrag stellen.
                    </div>
                  </div>
                </div>

                <!-- LEVEL 2: Subklassen einer Kategorie -->
                <div id="amt-level-2" style="display:none;">
                  <div id="amt-level-2-header" style="text-align:center;margin-bottom:16px;">
                    <div id="amt-cat-icon" style="font-size:32px;"></div>
                    <div id="amt-cat-title" style="font-size:14px;font-weight:bold;margin-top:4px;"></div>
                    <div style="font-size:10px;color:#665540;margin-top:3px;">Wähle eine Unterkategorie.</div>
                  </div>
                  <div id="amt-subclass-list" style="display:flex;flex-direction:column;gap:8px;"></div>
                </div>

                <!-- LEVEL 3: Ämter einer Subklasse -->
                <div id="amt-level-3" style="display:none;">
                  <div id="amt-level-3-header" style="text-align:center;margin-bottom:16px;">
                    <div id="amt-sub-title" style="font-size:14px;font-weight:bold;"></div>
                    <div style="font-size:10px;color:#665540;margin-top:3px;">Ämter die diese Subklasse ausstellen (aus deinen abonnierten Listen).</div>
                  </div>
                  <div id="amt-registry-list" style="display:flex;flex-direction:column;gap:8px;"></div>
                </div>

              </div>

              <script>
                // Ämter-Tab Drill-Down Navigation (Lizenzmodell Phase 1 UI)
                // Reihenfolge innerhalb jeder Kategorie: häufig/alltäglich → speziell/selten
                const AMT_CATEGORIES = {{
                  identity:    {{ label: 'Identität',    icon: '🆔', color: '#e44', subs: [['birth_certificate','Geburtsurkunde'],['personal_id','Personalausweis'],['passport','Reisepass'],['registration_certificate','Meldebescheinigung'],['residence_permit','Aufenthaltstitel']] }},
                  finance:     {{ label: 'Finanzen',     icon: '💰', color: '#d4a850', subs: [['creditworthiness','Bonität'],['tax_certificate','Steuerbescheinigung'],['income_proof','Einkommensnachweis'],['payment_capability','Zahlungsfähigkeit'],['wealth_proof','Vermögensnachweis']] }},
                  health:      {{ label: 'Gesundheit',   icon: '🌿', color: '#4a4',  subs: [['vaccination_record','Impfpass'],['medical_certificate','Ärztliche Bescheinigung'],['lab_result','Laborergebnis'],['psychological_assessment','Psychologisches Gutachten'],['disability_certificate','Behinderungsnachweis']] }},
                  authority:   {{ label: 'Befugnis',     icon: '⚙️', color: '#7ab8e0', subs: [['drivers_license','Führerschein'],['professional_license','Berufserlaubnis'],['craftsman_register','Handwerksrolle'],['weapons_license','Waffenschein'],['pilot_license','Pilotenschein']] }},
                  affiliation: {{ label: 'Zugehörigkeit', icon: '🌍', color: '#aa78ff', subs: [['club_membership','Vereinsmitgliedschaft'],['religious_affiliation','Religionszugehörigkeit'],['union_membership','Gewerkschaftsmitgliedschaft'],['party_membership','Parteimitgliedschaft'],['nationality','Nationalität']] }}
                }};

                // Lichtfarben pro Subklasse (25 Farben, 5 Stufen pro Kategorie, hell bis dunkel)
                // Sättigung hoch für Glow-Effekt, Lightness variiert für Unterscheidbarkeit
                const AMT_SUBCLASS_COLORS = {{
                  identity: {{
                    birth_certificate:        '#ff9090',  // hellrot
                    personal_id:              '#ff6060',
                    passport:                 '#ee4040',
                    registration_certificate: '#c82828',
                    residence_permit:         '#8e1818',  // dunkelrot
                  }},
                  finance: {{
                    creditworthiness:   '#ffe488',  // hellgold
                    tax_certificate:    '#f5c858',
                    income_proof:       '#d4a850',
                    payment_capability: '#a6822c',
                    wealth_proof:       '#6e5410',  // dunkelgold
                  }},
                  health: {{
                    vaccination_record:       '#88e896',  // hellgrün
                    medical_certificate:      '#5bc870',
                    lab_result:               '#4caf50',
                    psychological_assessment: '#358a3a',
                    disability_certificate:   '#1b5e20',  // dunkelgrün
                  }},
                  authority: {{
                    drivers_license:      '#9ed4f0',  // hellblau
                    professional_license: '#7ab8e0',
                    craftsman_register:   '#5a9ed0',
                    weapons_license:      '#3a7cbf',
                    pilot_license:        '#1a5a9f',  // dunkelblau
                  }},
                  affiliation: {{
                    club_membership:  '#d0a0ff',  // helllila
                    religious_affiliation:'#b082ff',
                    union_membership: '#aa78ff',
                    party_membership: '#7e4ad0',
                    nationality:      '#4e1c88',  // dunkellila
                  }},
                }};

                // Helfer: Farbe für (category, subclass)
                function amtSubColor(cat, sub) {{
                  return (AMT_SUBCLASS_COLORS[cat] || {{}})[sub] || '#888888';
                }}
                // Helfer: "nicht verifiziert" Farbe (Weiß)
                const AMT_NOT_VERIFIED_COLOR = '#ffffff';

                let amtCurrentCat = null;
                let amtCurrentSub = null;

                function amtGoLevel(lvl) {{
                  document.getElementById('amt-level-1').style.display = (lvl === 1) ? 'block' : 'none';
                  document.getElementById('amt-level-2').style.display = (lvl === 2) ? 'block' : 'none';
                  document.getElementById('amt-level-3').style.display = (lvl === 3) ? 'block' : 'none';
                  document.getElementById('amt-bc-cat').style.display = (lvl >= 2) ? 'inline' : 'none';
                  document.getElementById('amt-bc-sub').style.display = (lvl >= 3) ? 'inline' : 'none';
                }}

                function amtOpenCat(catKey) {{
                  const cat = AMT_CATEGORIES[catKey];
                  if (!cat) return;
                  amtCurrentCat = catKey;
                  document.getElementById('amt-cat-icon').textContent = cat.icon;
                  document.getElementById('amt-cat-title').textContent = cat.label;
                  document.getElementById('amt-cat-title').style.color = cat.color;
                  document.getElementById('amt-bc-cat-name').textContent = cat.label;
                  document.getElementById('amt-bc-cat-name').style.color = cat.color;

                  const list = document.getElementById('amt-subclass-list');
                  list.innerHTML = '';
                  cat.subs.forEach(function(pair) {{
                    const key = pair[0], label = pair[1];
                    const subColor = amtSubColor(catKey, key);
                    const row = document.createElement('div');
                    row.style.cssText = 'cursor:pointer;background:linear-gradient(90deg,' + subColor + '22 0%, rgba(20,20,30,0.6) 40%);padding:14px 16px;border-radius:6px;border:1px solid ' + subColor + '80;border-left:4px solid ' + subColor + ';display:flex;justify-content:space-between;align-items:center;transition:all 0.15s;box-shadow:0 0 8px ' + subColor + '15;';
                    row.onmouseover = function() {{ this.style.background = 'linear-gradient(90deg,' + subColor + '44 0%, rgba(30,30,45,0.8) 40%)'; this.style.boxShadow = '0 0 14px ' + subColor + '35'; }};
                    row.onmouseout = function() {{ this.style.background = 'linear-gradient(90deg,' + subColor + '22 0%, rgba(20,20,30,0.6) 40%)'; this.style.boxShadow = '0 0 8px ' + subColor + '15'; }};
                    row.onclick = function() {{ amtOpenSub(key, label); }};
                    row.innerHTML = '<div style="font-size:12px;color:' + subColor + ';font-weight:bold;">' + label + '</div><div style="font-size:10px;color:#887755;">→</div>';
                    list.appendChild(row);
                  }});

                  amtGoLevel(2);
                }}

                function amtOpenSub(subKey, subLabel) {{
                  amtCurrentSub = subKey;
                  document.getElementById('amt-sub-title').textContent = subLabel;
                  const cat = AMT_CATEGORIES[amtCurrentCat];
                  document.getElementById('amt-sub-title').style.color = cat ? cat.color : '#cfd8e4';
                  document.getElementById('amt-bc-sub-name').textContent = subLabel;
                  amtLoadRegistry(amtCurrentCat, subKey);
                  amtGoLevel(3);
                }}

                // Lädt die Ämter einer Subklasse aus dem Federation-Cache
                async function amtLoadRegistry(category, subclass) {{
                  const list = document.getElementById('amt-registry-list');
                  list.innerHTML = '<div style="text-align:center;color:#665540;font-size:10px;padding:12px;">Lade Ämter...</div>';
                  try {{
                    const r = await fetch('/api/amt-directory/browse?category=' + encodeURIComponent(category) + '&subclass=' + encodeURIComponent(subclass));
                    const d = await r.json();
                    amtRenderAmter(list, d.amter || [], false);
                  }} catch (e) {{
                    list.innerHTML = '<div style="color:#e55;font-size:10px;padding:12px;">Fehler beim Laden: ' + e + '</div>';
                  }}
                }}

                // Rendert eine Amt-Liste in einen Container
                function amtRenderAmter(container, amter, showWhy) {{
                  if (!amter || amter.length === 0) {{
                    container.innerHTML = '<div style="background:rgba(20,30,50,0.4);padding:20px;border-radius:8px;text-align:center;color:#665540;font-size:11px;border:1px dashed #2a3a4a;">Keine Ämter in dieser Unterkategorie.<br><br><em style="color:#445566;">Abonniere mehr Amt-Listen im Server Tab, um die Auswahl zu erweitern.</em></div>';
                    return;
                  }}
                  let rows = '';
                  for (const amt of amter) {{
                    const name = (amt.name || amt.shinpai_id || 'Unbekannt').replace(/</g, '&lt;');
                    const city = (amt.city || '').replace(/</g, '&lt;');
                    const country = (amt.country || '').replace(/</g, '&lt;');
                    const lang = (amt.language || '').replace(/</g, '&lt;');
                    const trust = amt.trust_level || 1;
                    const endpoint = (amt.endpoint || '').replace(/</g, '&lt;');
                    const source = (amt._source_list || '').replace(/</g, '&lt;');
                    const sid = (amt.shinpai_id || '').replace(/</g, '&lt;');
                    const trustIcon = trust >= 5 ? '👑' : trust >= 4 ? '🏅' : trust >= 3 ? '✓✓✓' : trust >= 2 ? '✓' : '⚠️';
                    const cityLine = [city, country, lang].filter(x => x).join(' · ');
                    const watchlisted = amtWatchlist.has(sid);
                    const btnLabel = watchlisted ? '✓ Abonniert' : '⭐ Abonnieren';
                    const btnBg = watchlisted ? 'rgba(76,175,80,0.2)' : 'rgba(212,168,80,0.15)';
                    const btnBorder = watchlisted ? 'rgba(76,175,80,0.5)' : 'rgba(212,168,80,0.4)';
                    const btnColor = watchlisted ? '#4caf50' : '#d4a850';
                    rows += '<div style="padding:12px 14px;background:rgba(10,15,25,0.5);border-radius:8px;border:1px solid rgba(212,168,80,0.15);">' +
                              '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">' +
                                '<div style="color:#d4a850;font-weight:bold;font-size:13px;line-height:1.4;">' + name + '</div>' +
                                '<div style="font-size:11px;color:#887755;margin-left:8px;">' + trustIcon + '</div>' +
                              '</div>' +
                              (cityLine ? '<div style="font-size:11px;color:#887755;margin-bottom:4px;">' + cityLine + '</div>' : '') +
                              (source ? '<div style="font-size:9px;color:#556677;margin-bottom:6px;">Quelle: ' + source + '</div>' : '') +
                              '<button onclick="amtToggleWatch(\\'' + sid + '\\',\\'' + name.replace(/'/g,"\\\\'") + '\\')" class="btn" style="width:100%;font-size:11px;padding:8px 12px;background:' + btnBg + ';border:1px solid ' + btnBorder + ';color:' + btnColor + ';">' + btnLabel + '</button>' +
                            '</div>';
                  }}
                  container.innerHTML = rows;
                }}

                // Suchleiste: tippt User → algorithmische Semantik-Suche
                let amtSearchTimer = null;
                function amtSearch(query) {{
                  clearTimeout(amtSearchTimer);
                  const out = document.getElementById('amt-search-results');
                  if (!query || query.trim().length < 2) {{
                    out.innerHTML = '';
                    out.style.display = 'none';
                    return;
                  }}
                  amtSearchTimer = setTimeout(async function() {{
                    try {{
                      const r = await fetch('/api/amt-directory/search?q=' + encodeURIComponent(query));
                      const d = await r.json();
                      amtRenderSearchResults(d.results || []);
                    }} catch (e) {{
                      out.innerHTML = '<div style="color:#e55;">Suchfehler: ' + e + '</div>';
                      out.style.display = 'block';
                    }}
                  }}, 200);
                }}

                function amtRenderSearchResults(results) {{
                  const out = document.getElementById('amt-search-results');
                  out.style.display = 'block';
                  if (!results || results.length === 0) {{
                    out.innerHTML = '<div style="color:#665540;padding:6px 0;">Keine Treffer. Tipp anders, z.B. Arzt, Führerschein, Bonität.</div>';
                    return;
                  }}
                  let rows = '<div style="color:#7ab8e0;font-weight:bold;padding:4px 0 8px 0;">Treffer:</div>';
                  for (const r of results) {{
                    const cat = AMT_CATEGORIES[r.category];
                    if (!cat) continue;
                    const subLabel = (cat.subs.find(s => s[0] === r.subclass) || [r.subclass, r.subclass])[1];
                    const countStr = r.amter_count > 0 ? r.amter_count + ' Amt' + (r.amter_count === 1 ? '' : 'er') : 'kein Amt abonniert';
                    rows += '<div onclick="amtJumpTo(\\'' + r.category + '\\',\\'' + r.subclass + '\\',\\'' + subLabel.replace(/'/g,"\\\\'") + '\\')" style="cursor:pointer;padding:8px 10px;background:rgba(20,20,30,0.5);border-radius:6px;margin-bottom:4px;border:1px solid ' + cat.color + '30;transition:background 0.15s;" onmouseover="this.style.background=\\'rgba(30,30,45,0.8)\\'" onmouseout="this.style.background=\\'rgba(20,20,30,0.5)\\'">' +
                              '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                                '<div><span style="color:' + cat.color + ';font-weight:bold;">' + cat.icon + ' ' + cat.label + '</span> <span style="color:#cfd8e4;">› ' + subLabel + '</span></div>' +
                                '<div style="font-size:10px;color:#887755;">' + countStr + ' →</div>' +
                              '</div>' +
                            '</div>';
                  }}
                  out.innerHTML = rows;
                }}

                function amtJumpTo(category, subclass, subLabel) {{
                  amtCurrentCat = category;
                  const cat = AMT_CATEGORIES[category];
                  if (cat) {{
                    document.getElementById('amt-cat-icon').textContent = cat.icon;
                    document.getElementById('amt-cat-title').textContent = cat.label;
                    document.getElementById('amt-cat-title').style.color = cat.color;
                    document.getElementById('amt-bc-cat-name').textContent = cat.label;
                    document.getElementById('amt-bc-cat-name').style.color = cat.color;
                  }}
                  amtOpenSub(subclass, subLabel);
                }}

                // Watchlist (vorgemerkte Ämter für Stufe-3-Verifikation)
                let amtWatchlist = new Set();

                async function amtLoadWatchlist() {{
                  try {{
                    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
                    const r = await fetch('/api/amt-watchlist', {{headers:{{'X-Session-Token':token}}}});
                    const d = await r.json();
                    amtWatchlist = new Set((d.items || []).map(i => i.shinpai_id));
                  }} catch (e) {{
                    amtWatchlist = new Set();
                  }}
                }}

                async function amtToggleWatch(shinpaiId, name) {{
                  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
                  const isOn = amtWatchlist.has(shinpaiId);
                  const url = isOn ? '/api/amt-watchlist/remove' : '/api/amt-watchlist/add';
                  try {{
                    const r = await fetch(url, {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{shinpai_id:shinpaiId, name:name, category:amtCurrentCat, subclass:amtCurrentSub}})}});
                    const d = await r.json();
                    if (d.ok) {{
                      if (isOn) amtWatchlist.delete(shinpaiId);
                      else amtWatchlist.add(shinpaiId);
                      if (amtCurrentSub) amtLoadRegistry(amtCurrentCat, amtCurrentSub);
                    }} else if (d.conflict) {{
                      const existing = d.existing || {{}};
                      alert('Für diese Unterkategorie ist bereits "' + (existing.name || existing.shinpai_id) + '" abonniert. Nur ein Amt pro Unterkategorie erlaubt. Entferne das alte zuerst.');
                    }} else if (d.error) {{
                      alert(d.error);
                    }}
                  }} catch (e) {{}}
                }}
              </script>

              {whitelist_tab_content}

              {server_tab_content}

            </div>
            """
        elif has_account:
            # Remote + nicht eingeloggt → Login + Register Tabs
            # Nexus-Status-Banner für alle User (Korrupt/Shutdown)
            _nexus_warn_banner = ""
            if _identity and _identity.get("nexus_shutdown"):
                _nexus_warn_banner = """
                <div style="background:linear-gradient(135deg,rgba(228,68,68,0.15),rgba(60,0,0,0.7));border:2px solid rgba(228,68,68,0.6);border-radius:8px;padding:12px 14px;margin:10px auto 14px;max-width:320px;text-align:center;">
                  <div style="font-size:13px;color:#ffdada;font-weight:bold;">🔒 Nexus geschlossen</div>
                  <div style="font-size:11px;color:#ffcaca;margin-top:4px;line-height:1.5;">Der Owner hat 30 Tage nichts unternommen. Dieser Nexus nimmt keine neuen Aktionen an. Bitte siedle um.</div>
                </div>"""
            elif _identity and _identity.get("nexus_corrupt"):
                _nexus_warn_banner = """
                <div style="background:linear-gradient(135deg,rgba(212,168,80,0.12),rgba(26,18,8,0.7));border:2px solid rgba(212,168,80,0.5);border-radius:8px;padding:12px 14px;margin:10px auto 14px;max-width:320px;text-align:center;">
                  <div style="font-size:13px;color:#e8c464;font-weight:bold;">⚠️ Nexus möglicherweise kompromittiert</div>
                  <div style="font-size:11px;color:#d4a850;margin-top:4px;line-height:1.5;">Der Owner hat einen Passwort-Reset ausgelöst und seit 24h nichts geändert. Empfehlung: Daten sichern und umsiedeln.</div>
                </div>"""
            body_content = _nexus_warn_banner + """
            <div style="text-align:center;margin:20px 0 8px;">
              <img src="/ShinNexus-Logo.webp" style="max-width:140px;border-radius:50%;animation:float 3s ease-in-out infinite;box-shadow:0 8px 30px rgba(122,184,224,0.15);" onerror="this.outerHTML='<div style=font-size:4em>🛡️</div>'">
            </div>
            <!-- Share-Banner (analog Kneipe, Hellblau-Style): zeigt aktuelle Nexus-Adresse wenn keine manuelle URL gesetzt -->
            <div id="share-banner" style="display:none;max-width:420px;margin:8px auto;font-size:12px;color:#556677;text-align:center;">
              <div style="margin-bottom:3px;font-style:italic;">Deine Nexus-Adresse:</div>
              <div style="display:flex;gap:6px;align-items:center;justify-content:center;">
                <span id="share-url" style="font-family:monospace;color:#7ab8e0;font-size:13px;letter-spacing:0.3px;"></span>
                <button id="btn-copy-share" title="Kopieren" style="background:transparent;border:0;color:#7ab8e0;cursor:pointer;padding:2px 4px;display:inline-flex;align-items:center;">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
              </div>
              <div id="share-hint" style="font-size:10px;color:#556677;margin-top:2px;"></div>
            </div>
            """ + verified_html + """
            <!-- Perso-LED (links) + Member-Count (mitte) + Bot-Icon (rechts): dezent über den Auth-Tabs -->
            <div style="max-width:320px;margin:0 auto 4px;display:flex;align-items:center;padding:0 2px;">
              <div style="flex:1;display:flex;align-items:center;gap:5px;">
                <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:transparent;border:2px solid """ + ('#4caf50' if _veriff_on else '#e44') + """;box-shadow:0 0 4px """ + ('#4caf50' if _veriff_on else '#e44') + """, 0 0 10px """ + ('#4caf50' if _veriff_on else '#e44') + """, inset 0 0 4px """ + ('#4caf50' if _veriff_on else '#e44') + """;"></span>
                <span style="font-size:12px;color:#a8873d;letter-spacing:0.8px;font-family:'Georgia',serif;font-style:italic;text-shadow:0 0 5px rgba(140,105,40,0.2);">Verifikation</span>
              </div>
              <div style="flex:1;text-align:center;">
                <span style="font-size:12px;font-family:'Georgia',serif;color:#a8873d;letter-spacing:1.2px;text-shadow:0 0 5px rgba(140,105,40,0.2);">""" + f"{_member_count}" + """<span style="color:#8b6f47;font-size:10px;">/200</span></span>
              </div>
              <div style="flex:1;display:flex;align-items:center;gap:4px;justify-content:flex-end;">
              <svg id="login-bot-svg" width="18" height="18" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style="filter:drop-shadow(0 0 4px rgba(212,168,80,0.4));">
                <line x1="32" y1="6" x2="32" y2="14" stroke="#d4a850" stroke-width="3"/>
                <circle cx="32" cy="5" r="3" fill="#e8c464"/>
                <rect x="14" y="16" width="36" height="30" rx="5" fill="rgba(212,168,80,0.08)" stroke="#d4a850" stroke-width="3"/>
                <circle cx="24" cy="30" r="4" fill="#e8c464"/>
                <circle cx="40" cy="30" r="4" fill="#e8c464"/>
                <line x1="22" y1="38" x2="42" y2="38" stroke="#d4a850" stroke-width="2.5"/>
                <line x1="20" y1="46" x2="20" y2="54" stroke="#d4a850" stroke-width="3"/>
                <line x1="44" y1="46" x2="44" y2="54" stroke="#d4a850" stroke-width="3"/>
              </svg>
              <span id="login-bot-quota" style="font-size:12px;color:#d4a850;letter-spacing:1px;text-shadow:0 0 5px rgba(212,168,80,0.35);">…</span>
              </div>
            </div>
            <div id="auth-tabs" style="display:flex;justify-content:center;gap:4px;margin-bottom:4px;max-width:320px;margin-left:auto;margin-right:auto;">
              <button onclick="showTab('login')" class="tab-btn active" id="tab-login" style="flex:1;font-size:11px;padding:6px 0;">Anmelden</button>
              <button onclick="showTab('register')" class="tab-btn" id="tab-register" style="flex:1;font-size:11px;padding:6px 0;">Registrieren</button>
              <button onclick="showTab('migrate')" class="tab-btn" id="tab-migrate" style="flex:1;font-size:11px;padding:6px 0;">Migrieren</button>
            </div>
            <!-- Bot-Spruch: mittig unter den Tabs, dezent leuchtend Bronze -->
            <div id="login-bot-label" style="text-align:center;font-size:10px;color:#d4a850;opacity:0.7;font-style:italic;letter-spacing:0.4px;margin:8px auto 10px;text-shadow:0 0 6px rgba(212,168,80,0.25);">&nbsp;</div>

            <!-- MIGRATE -->
            <div id="migrate-box" style="display:none;">
              <p style="font-size:11px;color:#888;margin-bottom:10px;">Account von einem anderen ShinNexus hierher übertragen.</p>
              <input type="text" id="migrate-token-input" placeholder="Migrations-Token einfügen" class="input" style="margin-bottom:8px;">
              <button onclick="doPublicMigrate()" class="btn" style="width:100%;">📥 Migration starten</button>
              <div id="migrate-pub-msg" style="font-size:11px;margin-top:6px;"></div>
            </div>

            <!-- LOGIN -->
            <div id="login-box">
              <div id="login-error" class="error" style="display:none;"></div>
              <div id="login-step1">
                <input type="text" id="username" placeholder="Username" autocomplete="username" maxlength="12">
                <input type="password" id="password" placeholder="Passwort" autocomplete="current-password">
                <button onclick="doLogin()" class="btn" id="login-btn">Anmelden</button>
                <p style="text-align:center;margin-top:8px;"><a href="#" onclick="showSection('forgot-box');return false;" style="color:#556677;font-size:11px;">Passwort vergessen?</a></p>
                <!-- Seed-basierter Reset: Step 1 (Email+Username validieren) -->
                <div id="forgot-box" style="display:none;margin-top:10px;">
                  <p style="font-size:11px;color:#887755;margin-bottom:8px;">Email + Username eingeben. Danach brauchst du deine Seed-Phrase (24 Wörter vom Register).</p>
                  <input type="email" id="forgot-email" placeholder="Deine Email" autocomplete="email">
                  <input type="text" id="forgot-username" placeholder="Username" autocomplete="username" maxlength="12">
                  <button onclick="doForgot()" class="btn" style="font-size:12px;">Weiter zur Seed-Eingabe</button>
                  <div id="forgot-msg" style="font-size:11px;margin-top:6px;"></div>
                </div>
                <!-- Seed-basierter Reset: Step 2 (Seed-Phrase prüfen) -->
                <div id="seed-unlock-box" style="display:none;margin-top:10px;padding:12px;background:rgba(212,168,80,0.08);border:1px solid rgba(212,168,80,0.3);border-radius:8px;">
                  <div style="font-size:12px;color:#d4a850;font-weight:bold;margin-bottom:6px;">🔑 Seed-Phrase eingeben</div>
                  <p style="font-size:11px;color:#887755;margin-bottom:8px;">Alle Wörter in richtiger Reihenfolge, Leerzeichen getrennt, keine Nummern.</p>
                  <textarea id="seed-input" placeholder="wort1 wort2 wort3 ..." rows="3" style="width:100%;padding:8px;background:#111;border:1px solid #333;border-radius:6px;color:#e0d8c8;font-family:monospace;font-size:12px;"></textarea>
                  <button onclick="doSeedUnlock()" class="btn" style="font-size:12px;width:100%;margin-top:6px;background:rgba(212,168,80,0.15);border:1px solid rgba(212,168,80,0.4);color:#d4a850;">🔓 Prüfen</button>
                  <div id="seed-msg" style="font-size:11px;margin-top:6px;"></div>
                </div>
              </div>
              <div id="login-step2fa" style="display:none;">
                <p class="dim" style="text-align:center;margin-bottom:10px;">2FA-Code eingeben:</p>
                <input type="text" id="totp" placeholder="000000" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
                <button onclick="doLogin2FA()" class="btn">Bestätigen</button>
              </div>
            </div>

            <!-- REGISTER -->
            <div id="register-box" style="display:none;max-width:320px;margin:0 auto;">
              <div id="reg-error" class="error" style="display:none;"></div>
              <div id="reg-step1">
                <input type="text" id="reg-username" placeholder="Username (3-12 Zeichen)" maxlength="12">
                <input type="email" id="reg-email" placeholder="E-Mail">
                <input type="password" id="reg-password" placeholder="Passwort" autocomplete="new-password">
                <input type="password" id="reg-password2" placeholder="Passwort wiederholen" autocomplete="new-password">
                <button onclick="doRegister()" class="btn" id="reg-btn">Registrieren</button>
              </div>
              <div id="reg-step2" style="display:none;">
                <p class="dim" style="text-align:center;margin-bottom:10px;">2FA einrichten:</p>
                <div id="reg-totp-info" style="text-align:center;margin:10px 0;"></div>
                <input type="text" id="reg-totp" placeholder="6-stelliger Code" maxlength="6" inputmode="numeric">
                <button onclick="doRegConfirm()" class="btn">2FA bestätigen</button>
              </div>
              <div id="reg-done" style="display:none;text-align:center;">
                <p style="color:#7ecfff;font-size:1.2em;margin:20px 0;">✅ Account erstellt!</p>
                <p class="dim">Du kannst dich jetzt anmelden.</p>
                <button onclick="showTab('login')" class="btn" style="margin-top:15px;">Zum Login</button>
              </div>
            </div>
            """
        else:
            body_content = """
            <div style="text-align:center;margin:20px 0 20px;">
              <img src="/ShinNexus-Logo.webp" style="max-width:180px;border-radius:50%;animation:float 3s ease-in-out infinite;box-shadow:0 8px 30px rgba(122,184,224,0.15);" onerror="this.outerHTML='<div style=font-size:5em>🛡️</div>'">
            </div>

            <div id="claim-box" style="max-width:320px;margin:0 auto;">
              <div id="claim-step1">
                <div id="share-banner-claim" style="display:none;max-width:320px;margin:0 auto 10px;font-size:12px;color:#556677;text-align:center;">
                  <div style="margin-bottom:3px;font-style:italic;">Deine Nexus-Adresse:</div>
                  <div style="display:flex;gap:6px;align-items:center;justify-content:center;">
                    <span id="share-url-claim" style="font-family:monospace;color:#7ab8e0;font-size:13px;letter-spacing:0.3px;"></span>
                    <button id="btn-copy-claim" title="Kopieren" style="background:transparent;border:0;color:#7ab8e0;cursor:pointer;padding:2px 4px;display:inline-flex;align-items:center;">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </button>
                  </div>
                  <div id="share-hint-claim" style="font-size:10px;color:#556677;margin-top:2px;"></div>
                </div>
                <p style="text-align:center;color:#7ecfff;font-size:14px;font-weight:bold;margin-bottom:15px;">Kein Owner — Besitz beanspruchen!</p>
                <input type="text" id="claim-name" placeholder="Username (3-12 Zeichen)" maxlength="12" class="input">
                <input type="email" id="claim-email" placeholder="E-Mail" class="input">
                <input type="password" id="claim-pw" placeholder="Passwort (min. 6 Zeichen)" class="input">
                <input type="password" id="claim-pw2" placeholder="Passwort wiederholen" class="input">
                <button onclick="doClaim()" class="btn" style="width:100%;margin-top:8px;font-size:15px;">👑 Besitz beanspruchen!</button>
                <div style="text-align:center;margin-top:14px;padding-top:14px;border-top:1px solid #2a2a3a;">
                  <button onclick="document.getElementById('claim-step1').style.display='none';document.getElementById('claim-migrate').style.display='block';" style="background:none;border:none;color:#aa78ff;font-size:11px;cursor:pointer;text-decoration:underline;">Bestehenden Account migrieren</button>
                </div>
                <div id="claim-msg" style="font-size:12px;margin-top:8px;text-align:center;"></div>
              </div>
              <div id="claim-migrate" style="display:none;">
                <div id="share-banner-migrate" style="display:none;max-width:320px;margin:0 auto 10px;font-size:12px;color:#556677;text-align:center;">
                  <div style="margin-bottom:3px;font-style:italic;">Adresse dieses Nexus (als Ziel eintragen):</div>
                  <div style="display:flex;gap:6px;align-items:center;justify-content:center;">
                    <span id="share-url-migrate" style="font-family:monospace;color:#7ab8e0;font-size:13px;letter-spacing:0.3px;"></span>
                    <button id="btn-copy-migrate" title="Kopieren" style="background:transparent;border:0;color:#7ab8e0;cursor:pointer;padding:2px 4px;display:inline-flex;align-items:center;">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </button>
                  </div>
                  <div id="share-hint-migrate" style="font-size:10px;color:#556677;margin-top:2px;"></div>
                </div>
                <p style="text-align:center;color:#aa78ff;font-size:14px;font-weight:bold;margin-bottom:6px;">Account migrieren</p>
                <p style="text-align:center;color:#665540;font-size:10px;margin-bottom:8px;line-height:1.5;">Übernimm deinen bestehenden Account von einem anderen ShinNexus als Owner.</p>
                <input type="text" id="claim-mig-token" placeholder="Migrations-Token einfügen" class="input" style="width:100%;box-sizing:border-box;font-size:11px;">
                <input type="password" id="claim-mig-pw" placeholder="Dein bestehendes Passwort" class="input" style="margin-top:4px;">
                <input type="text" id="claim-mig-totp" placeholder="2FA-Code" maxlength="6" inputmode="numeric" class="input" style="margin-top:4px;font-size:18px;text-align:center;letter-spacing:6px;">
                <button onclick="doClaimMigrate()" class="btn" style="width:100%;margin-top:8px;font-size:14px;background:rgba(170,120,255,0.15);border:1px solid rgba(170,120,255,0.4);color:#aa78ff;">Als Owner migrieren</button>
                <div style="text-align:center;margin-top:10px;">
                  <button onclick="document.getElementById('claim-migrate').style.display='none';document.getElementById('claim-step1').style.display='block';" style="background:none;border:none;color:#665540;font-size:11px;cursor:pointer;text-decoration:underline;">← Zurück zur Owner-Einrichtung</button>
                </div>
                <div id="claim-mig-msg" style="font-size:12px;margin-top:8px;text-align:center;"></div>
              </div>
              <div id="claim-step2" style="display:none;text-align:center;">
                <p style="color:#7ab8e0;font-size:14px;margin-bottom:10px;">🔐 2FA einrichten</p>
                <div id="claim-qr" style="margin:10px 0;"></div>
                <div id="claim-secret" style="font-size:10px;color:#887755;margin:8px 0;"></div>
                <div id="claim-seed" style="background:#1a0a0a;border:2px solid #ff5555;border-radius:10px;padding:16px;margin:16px 0;text-align:left;display:none;">
                  <p style="color:#ff5555;font-size:13px;font-weight:bold;text-align:center;margin-bottom:10px;">⚠️ RECOVERY-SEED — AUFSCHREIBEN!</p>
                  <code id="claim-seed-words" style="color:#ffd700;font-size:13px;line-height:1.8;word-break:break-word;display:block;text-align:center;"></code>
                </div>
                <input type="text" id="claim-totp" placeholder="6-stelliger Code" maxlength="6" inputmode="numeric" class="input" style="font-size:20px;text-align:center;letter-spacing:8px;">
                <button onclick="doClaimConfirm()" class="btn" style="width:100%;margin-top:8px;">✅ Bestätigen</button>
                <div id="claim-msg2" style="font-size:12px;margin-top:8px;"></div>
              </div>
            </div>
            """

        # Code-Hash als Seed für den Schmetterling (Wasserzeichen)
        try:
            _self_path = os.path.abspath(__file__)
            with open(_self_path, 'rb') as _sf:
                code_seed = int(hashlib.sha256(_sf.read()).hexdigest()[:8], 16)
        except Exception:
            code_seed = 42

        # Chain of Trust Footer-Daten
        _anchor = _btc_read_anchor_json()
        try:
            with open(__file__, "rb") as _hf:
                _cur_hash = hashlib.sha256(_hf.read()).hexdigest()
        except Exception:
            _cur_hash = ""
        _short_hash = _cur_hash[:16] if _cur_hash else "—"
        # Click-to-Copy: Version + voller Hash (+ TXID wenn verankert und nicht widerrufen)
        # für direkten Smart-Paste in die Whitelist
        _copy_text = f"ShinNexus v{VERSION} · {_cur_hash}" if _cur_hash else f"ShinNexus v{VERSION}"
        if _anchor.get("txid") and not _anchor.get("revoked"):
            _copy_text = f"{_copy_text} · {_anchor.get('txid')}"
        _footer_common = f'onclick="doChainCopy(this)" data-copy="{_copy_text}" style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;transition:opacity 0.2s;" title="Klick zum Kopieren für Whitelist-Check"'

        if _anchor.get("txid"):
            _hash_match = _cur_hash == _anchor.get("code_hash", "")
            _anchor_date = time.strftime("%d.%m.%Y %H:%M", time.localtime(_anchor.get("timestamp", 0)))
            _short_tx = _anchor.get("txid", "")[:12]
            _live_status = _anchor.get("live_verify_status", "")
            if not _hash_match:
                # Code geändert seit Anker — nicht verankert
                if _anchor.get("revoked"):
                    _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #1a1a2a;transition:opacity 0.2s;"><span style="color:#f59e0b;">⚠️ v{VERSION} · Neuer Code, nicht verankert</span><br><span style="color:#665540;font-size:9px;">Hash: {_short_hash}… · Vorgänger v{_anchor.get("version","?")} wurde widerrufen</span></div>'
                else:
                    _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #2a2a1a;transition:opacity 0.2s;"><span style="color:#f59e0b;">⚠️ v{VERSION} · Nicht verankert</span><br><span style="color:#665540;font-size:9px;">Hash: {_short_hash}… · Letzte Verankerung: v{_anchor.get("version","?")}</span></div>'
            elif _anchor.get("revoked"):
                # Gleicher Code aber widerrufen → Update erforderlich!
                _revoke_date = time.strftime("%d.%m.%Y", time.localtime(_anchor.get("revoked_at", _anchor.get("timestamp", 0))))
                _chain_footer = f'<div {_footer_common} data-border="#2a1a1a"><span style="color:#ff5555;">🔴 v{_anchor.get("version","?")} — WIDERRUFEN ({_revoke_date})</span><br><span style="color:#553333;font-size:9px;">Update erforderlich!</span></div>'
            elif _live_status == "mismatch":
                _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #4a1010;transition:opacity 0.2s;"><span style="color:#ff5555;">🚨 v{_anchor.get("version","?")} · Hash stimmt nicht mit Anker überein!</span><br><span style="color:#553333;font-size:9px;">Tampering-Verdacht · {_short_hash}… · <a href="https://mempool.space/tx/{_anchor.get("txid","")}" target="_blank" onclick="event.stopPropagation()" style="color:#7ab8e0;text-decoration:none;">TX ↗</a></span></div>'
            elif _live_status == "match":
                _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #1a2a1a;transition:opacity 0.2s;"><span style="color:#4caf50;">⚓ v{_anchor.get("version","?")} · On-chain verifiziert</span><br><span style="color:#665540;font-size:9px;">{_anchor_date} · {_short_hash}… · <a href="https://mempool.space/tx/{_anchor.get("txid","")}" target="_blank" onclick="event.stopPropagation()" style="color:#7ab8e0;text-decoration:none;">TX {_short_tx}… ↗</a></span></div>'
            elif _live_status in ("network_error", "bad_format"):
                _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #2a2415;transition:opacity 0.2s;"><span style="color:#e8c464;">⚓ v{_anchor.get("version","?")} · Anker vorhanden · Check offline</span><br><span style="color:#665540;font-size:9px;">{_short_hash}… · <a href="https://mempool.space/tx/{_anchor.get("txid","")}" target="_blank" onclick="event.stopPropagation()" style="color:#7ab8e0;text-decoration:none;">TX {_short_tx}… ↗</a></span></div>'
            else:
                _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #1a2a1a;transition:opacity 0.2s;"><span style="color:#4caf50;">⚓ v{_anchor.get("version","?")} · Verankert</span><br><span style="color:#665540;font-size:9px;">{_anchor_date} · {_short_hash}… · <a href="https://mempool.space/tx/{_anchor.get("txid","")}" target="_blank" onclick="event.stopPropagation()" style="color:#7ab8e0;text-decoration:none;">TX {_short_tx}… ↗</a></span></div>'
        else:
            _chain_footer = f'<div {_footer_common} style="cursor:pointer;text-align:center;padding:12px;margin-top:20px;font-size:10px;border-top:1px solid #1a1a2a;transition:opacity 0.2s;"><span style="color:#665540;">ShinNexus v{VERSION}</span><br><span style="color:#445566;font-size:9px;">Hash: {_short_hash}… · Keine Verankerung</span></div>'

        html = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShinNexus</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0a0a0f; color: #e0e0e0; padding: 20px; max-width: 480px; margin: 0 auto; }}
h1 {{ text-align: center; color: #7ecfff; margin: 30px 0 5px; font-size: 1.8em; }}
.subtitle {{ text-align: center; color: #888; margin-bottom: 30px; }}
h2 {{ color: #7ecfff; margin: 15px 0 10px; }}
.id {{ font-family: monospace; color: #ffd700; font-size: 0.9em; }}
.dim {{ color: #666; font-size: 0.85em; margin: 5px 0; }}
.status {{ color: #4caf50; font-weight: bold; }}
hr {{ border: none; border-top: 1px solid #222; margin: 15px 0; }}
.shield {{ text-align: center; font-size: 4em; margin: 40px 0 20px; }}
@keyframes float {{ 0%,100% {{ transform: translateY(0); }} 50% {{ transform: translateY(-10px); }} }}
@keyframes shieldRainbow {{
  0%   {{ filter: drop-shadow(0 0 18px #d4a850) drop-shadow(0 0 10px #7ab8e0) drop-shadow(0 0 28px #e0c060); }}
  25%  {{ filter: drop-shadow(0 0 18px #7ab8e0) drop-shadow(0 0 10px #4caf50) drop-shadow(0 0 28px #aa78ff); }}
  50%  {{ filter: drop-shadow(0 0 18px #e44)    drop-shadow(0 0 10px #d4a850) drop-shadow(0 0 28px #7ab8e0); }}
  75%  {{ filter: drop-shadow(0 0 18px #4caf50) drop-shadow(0 0 10px #aa78ff) drop-shadow(0 0 28px #d4a850); }}
  100% {{ filter: drop-shadow(0 0 18px #d4a850) drop-shadow(0 0 10px #7ab8e0) drop-shadow(0 0 28px #e0c060); }}
}}
.error {{ color: #ff5555; text-align: center; margin: 10px 0; font-size: 0.9em; }}
#login-box {{ max-width: 320px; margin: 0 auto; }}
input[type="text"], input[type="password"], input[type="email"] {{
  width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #333;
  border-radius: 8px; background: #151520; color: #e0e0e0; font-size: 1em;
  outline: none; transition: border-color 0.2s;
}}
input:focus {{ border-color: #7ecfff; }}
.btn {{
  width: 100%; padding: 12px; margin: 12px 0 0; border: none; border-radius: 8px;
  background: #7ecfff; color: #0a0a0f; font-size: 1em; font-weight: bold;
  cursor: pointer; transition: background 0.2s;
}}
.btn:hover {{ background: #5bb8f0; }}
.btn:disabled {{ background: #333; color: #666; cursor: not-allowed; }}
.btn-danger {{ background: #ff5555; color: #fff; }}
.btn-danger:hover {{ background: #cc4444; }}
.tab-btn {{ padding: 8px 20px; border: 1px solid #333; border-radius: 8px; background: transparent;
  color: #888; cursor: pointer; font-size: 0.9em; transition: all 0.2s; }}
.tab-btn.active {{ background: #7ecfff; color: #0a0a0f; border-color: #7ecfff; font-weight: bold; }}
.tab-btn:hover {{ border-color: #7ecfff; }}
.totp-secret {{ font-family: monospace; background: #151520; padding: 8px 12px; border-radius: 6px;
  border: 1px solid #333; color: #ffd700; word-break: break-all; font-size: 0.85em; margin: 8px 0; }}
.seed-box {{ background: #1a0a0a; border: 2px solid #ff5555; border-radius: 10px; padding: 16px;
  margin: 12px 0; }}
.seed-box h3 {{ color: #ff5555; text-align: center; margin: 0 0 12px; font-size: 1em; }}
.seed-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; }}
.seed-word {{ font-family: monospace; background: #151520; border: 1px solid #ff5555;
  border-radius: 6px; padding: 6px 8px; font-size: 0.9em; text-align: center; }}
.seed-num {{ color: #666; font-size: 0.75em; }}
.seed-val {{ color: #ffd700; font-weight: bold; }}
@keyframes dlpulse {{
  0%, 100% {{ opacity: 0.9; }}
  50%      {{ opacity: 0.65; }}
}}
.dl-crystal {{ animation: dlpulse 2.4s ease-in-out infinite; }}
</style>
</head>
<body>
<!-- Download-Button oben links (Kristall, ShinNexus-Hellblau, Glow) — linkt auf GitHub-Releases -->
<div onclick="window.open('https://github.com/Shinpai-AI/ShinNexus','_blank')" style="position:fixed;top:15px;left:15px;cursor:pointer;text-align:center;padding:6px 10px;border:1px solid rgba(122,184,224,0.45);border-radius:8px;background:rgba(10,20,40,0.7);backdrop-filter:blur(8px);transition:all 0.2s;z-index:1000;box-shadow:0 4px 12px rgba(0,0,0,0.4);" onmouseover="this.style.background='rgba(20,40,80,0.85)';this.style.transform='scale(1.05)'" onmouseout="this.style.background='rgba(10,20,40,0.7)';this.style.transform='scale(1)'" title="ShinNexus Downloads auf GitHub">
  <svg width="26" height="26" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style="filter:drop-shadow(0 0 6px rgba(122,184,224,0.45));display:block;margin:0 auto;">
    <defs><linearGradient id="crystalDl" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#e0eaff" stop-opacity="0.6"/><stop offset="100%" stop-color="#7ab8e0" stop-opacity="0.2"/></linearGradient></defs>
    <path d="M 32 8 L 48 22 L 44 42 L 32 52 L 20 42 L 16 22 Z" fill="url(#crystalDl)" stroke="#7ab8e0" stroke-width="2" class="dl-crystal"/>
    <path d="M 32 8 L 32 52" stroke="#9fc8e8" stroke-width="1" opacity="0.6"/>
    <path d="M 16 22 L 48 22" stroke="#9fc8e8" stroke-width="1" opacity="0.6"/>
    <path d="M 20 42 L 44 42" stroke="#9fc8e8" stroke-width="1" opacity="0.6"/>
    <path d="M 26 24 L 32 34 L 38 24" fill="none" stroke="#e0eaff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
  <div style="font-size:8px;color:#7ab8e0;font-weight:bold;margin-top:2px;letter-spacing:0.5px;">Download</div>
</div>
<h1>ShinNexus</h1>
<p class="subtitle">Same Knowledge. Your Ownership.</p>
{body_content}
<p class="dim" style="text-align:center; margin-top:40px;"></p>
<script>
const _isOwner = {'true' if is_owner_session else 'false'};
let _pw = '';
async function doLogin() {{
  const el = document.getElementById.bind(document);
  const user = el('username').value.trim();
  const pw = el('password').value;
  const err = el('login-error');
  const btn = el('login-btn');
  if (!user || !pw) {{ err.textContent = 'Username und Passwort eingeben!'; err.style.display = 'block'; return; }}
  btn.disabled = true; btn.textContent = '...';
  try {{
    const r = await fetch('/api/auth/login', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: user, password: pw, source: 'web'}})
    }});
    const d = await r.json();
    if (d.step === '2fa') {{
      _pw = pw;
      el('login-step1').style.display = 'none';
      el('login-step2fa').style.display = 'block';
      err.style.display = 'none';
      setTimeout(() => el('totp').focus(), 100);
    }} else if (d.authenticated) {{
      document.cookie = 'nexus_session=' + d.session_token + '; path=/; SameSite=Strict; Secure';
      location.href = '/';
    }} else {{
      err.textContent = d.error || 'Login fehlgeschlagen'; err.style.display = 'block';
      btn.disabled = false; btn.textContent = 'Anmelden';
    }}
  }} catch(e) {{
    err.textContent = 'Verbindungsfehler'; err.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Anmelden';
  }}
}}
async function doLogin2FA() {{
  const el = document.getElementById.bind(document);
  const user = el('username').value.trim();
  const totp = el('totp').value.trim();
  const err = el('login-error');
  if (!totp || totp.length !== 6) {{ err.textContent = '6-stelligen Code eingeben!'; err.style.display = 'block'; return; }}
  try {{
    const r = await fetch('/api/auth/login', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: user, password: _pw, totp_code: totp, source: 'web'}})
    }});
    const d = await r.json();
    if (d.authenticated) {{
      document.cookie = 'nexus_session=' + d.session_token + '; path=/; SameSite=Strict; Secure';
      location.href = '/';
    }} else {{
      err.textContent = d.error || '2FA fehlgeschlagen'; err.style.display = 'block';
    }}
  }} catch(e) {{
    err.textContent = 'Verbindungsfehler'; err.style.display = 'block';
  }}
}}
function doLogout() {{
  document.cookie = 'nexus_session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  location.href = '/?logout=1';
}}
function showSection(id) {{
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}
function showDashTab(tab) {{
  document.querySelectorAll('.dash-tab-content').forEach(el => el.style.display = 'none');
  const target = document.getElementById('dash-' + tab);
  if (target) target.style.display = 'block';
  if (tab === 'lizenzen') loadMyLicense();
  if (tab === 'info') {{ loadTitles(); }}
  if (tab === 'server') {{ loadServerStatus(); loadAmtLists(); loadBtcWallet(); loadIgniStatus(); loadPublicUrlSection(); loadBotQuota(); loadOwnerMembers(); }}
  if (tab === 'info') loadAccountType();
  if (tab === 'amt') amtLoadWatchlist();
  if (tab === 'sicherheit') {{ loadCurrentEmail(); }}
  if (tab === 'whitelist') {{ doWhitelistLoad(); }}
  // Karteikasten-Optik: aktiver Tab verschmilzt mit Inhalt
  document.querySelectorAll('.dash-tab').forEach(btn => {{
    const active = btn.dataset.tab === tab;
    if (active) {{
      btn.style.background = 'rgba(20,20,30,0.6)';
      btn.style.borderColor = '#2a2a3a';
      btn.style.borderBottomColor = 'transparent';
      btn.style.color = '#7ab8e0';
      btn.style.fontWeight = 'bold';
      btn.style.zIndex = '2';
    }} else {{
      btn.style.background = 'none';
      btn.style.borderColor = 'transparent';
      btn.style.borderBottomColor = '#2a2a3a';
      btn.style.color = '#665540';
      btn.style.fontWeight = 'normal';
      btn.style.zIndex = '1';
    }}
  }});
}}
async function loadServerStatus() {{
  try {{
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/server/status', {{headers: {{'X-Session-Token': token}}}});
    const d = await r.json();
    // SMTP
    const smtpStat = document.getElementById('srv-smtp-status');
    const smtpInfo = document.getElementById('srv-smtp-info');
    if (smtpStat) smtpStat.innerHTML = d.smtp.configured ? '<span style="color:#4caf50;">✅ Aktiv</span>' : '<span style="color:#665540;">⚪ Nicht eingerichtet</span>';
    if (smtpInfo && d.smtp.configured) {{
      smtpInfo.innerHTML = 'Host: <strong>' + (d.smtp.host || '–') + '</strong>:' + (d.smtp.port || '–') + '<br>User: <strong>' + (d.smtp.user || '–') + '</strong><br>Absender: ' + (d.smtp.from_addr || '–') + '<br>Passwort: ' + (d.smtp.password_set ? 'gesetzt' : 'fehlt');
    }} else if (smtpInfo) {{
      smtpInfo.textContent = 'Noch nicht konfiguriert.';
    }}
    // Stripe
    const stripeStat = document.getElementById('srv-stripe-status');
    const stripeInfo = document.getElementById('srv-stripe-info');
    if (stripeStat) stripeStat.innerHTML = d.stripe.configured ? '<span style="color:#4caf50;">✅ Aktiv</span>' : '<span style="color:#665540;">⚪ Nicht eingerichtet</span>';
    if (stripeInfo && d.stripe.configured) {{
      stripeInfo.innerHTML = 'Publishable: <code style="word-break:break-all;font-size:9px;">' + (d.stripe.publishable_key || '–') + '</code><br>Secret: <code style="word-break:break-all;font-size:9px;">' + (d.stripe.secret_key_masked || '–') + '</code>';
    }} else if (stripeInfo) {{
      stripeInfo.textContent = 'Noch nicht konfiguriert.';
    }}
    // Veriff
    const veriffStat = document.getElementById('srv-veriff-status');
    const veriffInfo = document.getElementById('srv-veriff-info');
    if (veriffStat) veriffStat.innerHTML = d.veriff.configured ? '<span style="color:#4caf50;">✅ Aktiv</span>' : '<span style="color:#665540;">⚪ Nicht eingerichtet</span>';
    if (veriffInfo && d.veriff.configured) {{
      veriffInfo.innerHTML = 'API Key: <code>' + (d.veriff.api_key_masked || '–') + '</code><br>Shared Secret: ' + (d.veriff.secret_set ? 'gesetzt' : 'nicht gesetzt') + '<br>Preis: <strong>' + (d.veriff.price_eur || 3) + ' Euro</strong>';
    }} else if (veriffInfo) {{
      veriffInfo.textContent = 'Noch nicht konfiguriert.';
    }}
    // Veriff Preis im Edit-Feld vorausfüllen
    const veriffPriceInput = document.getElementById('veriff-price');
    if (veriffPriceInput && d.veriff.price_eur) veriffPriceInput.value = d.veriff.price_eur;
    // Public URL
    const pubUrl = document.getElementById('public-url');
    const pubStatus = document.getElementById('srv-public-status');
    if (pubUrl && d.public && d.public.url) pubUrl.value = d.public.url;
    if (pubStatus) {{
      if (d.public && d.public.url) {{
        pubStatus.innerHTML = '<span style="color:#4caf50;">✅ Gesetzt</span>';
      }} else {{
        pubStatus.innerHTML = '<span style="color:#665540;">⚪ Nicht gesetzt</span>';
      }}
    }}
  }} catch (e) {{}}
}}
function _fmtAgo(ts) {{
  if (!ts) return 'nie';
  const s = Math.max(0, Math.floor(Date.now()/1000 - ts));
  if (s < 60) return s + 's her';
  if (s < 3600) return Math.floor(s/60) + 'm her';
  if (s < 86400) return Math.floor(s/3600) + 'h her';
  return Math.floor(s/86400) + 'd her';
}}
// Whitelist — Liste vertrauenswürdiger Versionen (Owner-only)
async function doWhitelistLoad() {{
  const list = document.getElementById('wl-list');
  if (!list) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/whitelist', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) {{ list.innerHTML = '<span style="color:#e55;">' + d.error + '</span>'; return; }}
    const items = d.items || [];
    if (!items.length) {{
      list.innerHTML = '<div style="color:#665540;font-style:italic;padding:10px;">Keine Einträge — füg oben deinen ersten vertrauenswürdigen Hash hinzu.</div>';
      return;
    }}
    list.innerHTML = items.map(it => {{
      const dt = new Date((it.added_at||0)*1000).toLocaleDateString('de-DE');
      const label = it.label ? `<div style="color:#7ab8e0;font-size:11px;margin-bottom:3px;">${{it.label}}</div>` : '';
      return `<div style="background:rgba(0,0,0,0.25);padding:10px;border-radius:6px;margin-bottom:6px;border:1px solid rgba(122,184,224,0.15);">
        ${{label}}
        <div style="color:#9fc8e8;font-weight:bold;margin-bottom:4px;">v${{it.version}} <span style="color:#665540;font-size:10px;font-weight:normal;">· ${{dt}}</span></div>
        <div style="color:#887755;font-size:10px;font-family:monospace;word-break:break-all;">Hash: ${{it.hash}}</div>
        <div style="color:#887755;font-size:10px;font-family:monospace;word-break:break-all;">TX: <a href="https://mempool.space/tx/${{it.txid}}" target="_blank" style="color:#7ab8e0;">${{it.txid}} ↗</a></div>
        <button onclick="doWhitelistDelete('${{it.hash}}')" style="margin-top:6px;font-size:10px;padding:3px 8px;background:rgba(228,68,68,0.1);border:1px solid rgba(228,68,68,0.4);color:#e44;border-radius:4px;cursor:pointer;">🗑️ Entfernen</button>
      </div>`;
    }}).join('');
  }} catch (e) {{ list.innerHTML = '<span style="color:#e55;">Fehler beim Laden</span>'; }}
}}
// Parser: "ShinNexus vX.Y.Z · <hash> · <txid>" → {{version, hash, txid}}
function parseWhitelistPaste(raw) {{
  if (!raw) return null;
  const txt = raw.trim();
  // Version per Regex (robust gegen "ShinNexus v1.0.0", "v1.0.0", "1.0.0")
  const vMatch = txt.match(/v?(\\d+\\.\\d+\\.\\d+)/i);
  // 64-hex Sequenzen finden (Hash + TXID sind beide SHA-256-Länge)
  const hexes = (txt.match(/\\b[a-fA-F0-9]{{64}}\\b/g) || []).map(s => s.toLowerCase());
  if (!vMatch || hexes.length < 2) return null;
  return {{version: vMatch[1], hash: hexes[0], txid: hexes[1]}};
}}
function doWhitelistParsePreview() {{
  const raw = document.getElementById('wl-paste')?.value || '';
  const prev = document.getElementById('wl-parse-preview');
  if (!prev) return;
  if (!raw.trim()) {{ prev.style.display = 'none'; return; }}
  const parsed = parseWhitelistPaste(raw);
  if (!parsed) {{
    prev.style.display = 'block';
    prev.style.color = '#e55';
    prev.textContent = '⚠️ Konnte nicht parsen — brauche Version + Hash + TXID';
    return;
  }}
  prev.style.display = 'block';
  prev.style.color = '#5ac88c';
  prev.innerHTML = 'Version: <b>' + parsed.version + '</b><br>Hash: ' + parsed.hash.slice(0,16) + '…<br>TXID: ' + parsed.txid.slice(0,16) + '…';
}}
async function doWhitelistAdd() {{
  const raw = document.getElementById('wl-paste')?.value?.trim();
  const label = document.getElementById('wl-label')?.value?.trim();
  const msg = document.getElementById('wl-add-msg');
  if (!raw) {{ msg.textContent = 'Fingerabdruck einfügen!'; msg.style.color = '#e55'; return; }}
  const parsed = parseWhitelistPaste(raw);
  if (!parsed) {{ msg.textContent = '❌ Parse fehlgeschlagen — brauche Version + Hash + TXID'; msg.style.color = '#e55'; return; }}
  const {{version, hash, txid}} = parsed;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ Speichere…'; msg.style.color = '#888';
  try {{
    const r = await fetch('/api/whitelist/add', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{version,hash,txid,label}})}});
    const d = await r.json();
    if (d.error) {{ msg.textContent = '❌ ' + d.error; msg.style.color = '#e55'; return; }}
    msg.textContent = '✅ Hinzugefügt!'; msg.style.color = '#5ac88c';
    document.getElementById('wl-paste').value = '';
    document.getElementById('wl-label').value = '';
    document.getElementById('wl-parse-preview').style.display = 'none';
    doWhitelistLoad();
  }} catch (e) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
}}
async function doWhitelistDelete(hash) {{
  if (!confirm('Diesen Whitelist-Eintrag wirklich entfernen?')) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/whitelist/delete', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{hash}})}});
    const d = await r.json();
    if (d.error) {{ alert(d.error); return; }}
    doWhitelistLoad();
  }} catch (e) {{ alert('Netzwerkfehler'); }}
}}

function startRevokePoll() {{
  const prog = document.getElementById('btc-revoke-progress');
  const timer = document.getElementById('btc-revoke-timer');
  const status = document.getElementById('btc-revoke-progress-status');
  const revokeBtn = document.getElementById('btc-revoke-btn');
  if (prog) prog.style.display = 'block';
  if (revokeBtn) revokeBtn.style.display = 'none';
  let startTime = Date.now();
  const tick = () => {{
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(elapsed / 60);
    const s = elapsed % 60;
    if (timer) timer.textContent = m + ':' + (s < 10 ? '0' : '') + s;
  }};
  tick();
  const timerInterval = setInterval(tick, 1000);
  const poll = async () => {{
    try {{
      const r = await fetch('/api/btc/revoke/status', {{headers: {{'X-Session-Token': _btcToken()}}}});
      const d = await r.json();
      if (d.status === 'confirmed') {{
        clearInterval(timerInterval);
        if (prog) prog.style.display = 'none';
        if (revokeBtn) revokeBtn.style.display = 'block';
        const msg = document.getElementById('btc-revoke-msg');
        if (msg) {{ msg.innerHTML = '🔴 Widerruf bestätigt! Block #' + d.block_height + ' · <a href="https://mempool.space/tx/' + d.txid + '" target="_blank" style="color:#ff5555;">TX↗</a>'; msg.style.color = '#ff5555'; }}
        loadBtcWallet();
        return;
      }} else if (d.status === 'pending') {{
        if (status) status.textContent = 'TX im Mempool… Zyklus ' + d.cycle + '/4';
      }}
    }} catch (e) {{
      if (status) status.textContent = 'Netzwerkfehler — versuche erneut…';
    }}
    setTimeout(poll, 15000);
  }};
  setTimeout(poll, 10000);
}}

async function doWhitelistImport() {{
  const url = (document.getElementById('wl-import-url')?.value || '').trim();
  const msg = document.getElementById('wl-import-msg');
  if (!url) {{ msg.textContent = 'URL eingeben!'; msg.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ Importiere…'; msg.style.color = '#888';
  try {{
    const r = await fetch('/api/whitelist/import', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{url}})}});
    const d = await r.json();
    if (d.error) {{ msg.textContent = '❌ ' + d.error; msg.style.color = '#e55'; return; }}
    msg.textContent = '✅ ' + d.added + ' neue Einträge importiert (gesamt: ' + d.total + ')'; msg.style.color = '#5ac88c';
    document.getElementById('wl-import-url').value = '';
    doWhitelistLoad();
  }} catch (e) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
}}

// Footer Click-to-Copy: Version + Hash für Whitelist-Gegencheck
async function doChainCopy(el) {{
  const txt = el.getAttribute('data-copy');
  if (!txt) return;
  try {{ await navigator.clipboard.writeText(txt); }} catch (e) {{ prompt('Kopieren:', txt); return; }}
  const orig = el.innerHTML;
  el.innerHTML = '<span style="color:#4caf50;font-size:11px;">✓ Kopiert! Version + Hash im Zwischenspeicher</span>';
  setTimeout(() => {{ el.innerHTML = orig; }}, 1800);
}}

// Share-Banner (analog Kneipe): zeigt aktuelle Nexus-Adresse wenn keine manuelle URL gesetzt
const _COPY_ICON_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
const _COPY_ICON_OK = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4caf50" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
function _flashCopy(btn) {{
  const orig = btn.innerHTML;
  btn.innerHTML = _COPY_ICON_OK;
  setTimeout(() => {{ btn.innerHTML = orig; }}, 1200);
}}
async function _doShareCopy(btnId, urlElId) {{
  const btn = document.getElementById(btnId);
  const urlEl = document.getElementById(urlElId);
  if (!btn || !urlEl) return;
  const url = urlEl.dataset.url || urlEl.textContent;
  if (!url) return;
  try {{
    await navigator.clipboard.writeText(url);
    _flashCopy(btn);
  }} catch (e) {{
    prompt('Kopieren:', url);
  }}
}}
async function updateShareBanner() {{
  // Alle Banner gleichzeitig updaten — identische Daten
  const banner1 = document.getElementById('share-banner');
  const banner2 = document.getElementById('share-banner-dash');
  const banner3 = document.getElementById('share-banner-claim');
  const banner4 = document.getElementById('share-banner-migrate');
  const allBanners = [banner1, banner2, banner3, banner4].filter(Boolean);
  if (!allBanners.length) return;
  try {{
    const r = await fetch('/api/public-url/status', {{headers:{{'X-Session-Token': document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || ''}}}});
    const d = await r.json();
    if (d.error || !d.state) {{
      allBanners.forEach(b => b.style.display = 'none');
      return;
    }}
    // Manuelle URL gesetzt → Banner komplett aus (User kennt seine Domain)
    if (d.public_url_manual) {{
      allBanners.forEach(b => b.style.display = 'none');
      return;
    }}
    const s = d.state;
    let url = '';
    let hint = '';
    if (s.best_url && s.best_url.indexOf('127.0.0.1') === -1 && s.best_url.indexOf('localhost') === -1) {{
      url = s.best_url;
      hint = s.reachable_external ? '— weltweit erreichbar' : (s.reachable_local ? '— nur im lokalen Netz' : '');
    }} else if (s.local_ips && s.local_ips.length) {{
      // Fallback: erste LAN-IP
      const proto = location.protocol.replace(':', '');
      const port = location.port || (proto === 'https' ? '443' : '80');
      url = `${{proto}}://${{s.local_ips[0]}}:${{port}}`;
      hint = '— nur im lokalen Netz';
    }} else {{
      // Letzte Rettung: best_url (auch wenn localhost)
      url = s.best_url || '';
      hint = url ? '— nur für dich lokal' : '';
    }}
    if (!url) {{
      allBanners.forEach(b => b.style.display = 'none');
      return;
    }}
    // Banner 1 (Login)
    if (banner1) {{
      const urlEl = document.getElementById('share-url');
      const hintEl = document.getElementById('share-hint');
      if (urlEl) {{ urlEl.textContent = url; urlEl.dataset.url = url; }}
      if (hintEl) hintEl.textContent = hint;
      banner1.style.display = 'block';
    }}
    // Banner 2 (Dashboard)
    if (banner2) {{
      const urlEl = document.getElementById('share-url-dash');
      const hintEl = document.getElementById('share-hint-dash');
      if (urlEl) {{ urlEl.textContent = url; urlEl.dataset.url = url; }}
      if (hintEl) hintEl.textContent = hint;
      banner2.style.display = 'block';
    }}
    // Banner 3 (Claim — Owner-Einrichtung)
    if (banner3) {{
      const urlEl = document.getElementById('share-url-claim');
      const hintEl = document.getElementById('share-hint-claim');
      if (urlEl) {{ urlEl.textContent = url; urlEl.dataset.url = url; }}
      if (hintEl) hintEl.textContent = hint;
      banner3.style.display = 'block';
    }}
    // Banner 4 (Claim-Migration)
    if (banner4) {{
      const urlEl = document.getElementById('share-url-migrate');
      const hintEl = document.getElementById('share-hint-migrate');
      if (urlEl) {{ urlEl.textContent = url; urlEl.dataset.url = url; }}
      if (hintEl) hintEl.textContent = hint;
      banner4.style.display = 'block';
    }}
  }} catch (e) {{
    allBanners.forEach(b => b.style.display = 'none');
  }}
}}
// Copy-Handler für beide Banner (onclick im DOM nachträglich binden, da IDs je nach View)
function _bindShareCopyHandlers() {{
  const btn1 = document.getElementById('btn-copy-share');
  const btn2 = document.getElementById('btn-copy-share-dash');
  if (btn1 && !btn1._bound) {{
    btn1.onclick = () => _doShareCopy('btn-copy-share', 'share-url');
    btn1._bound = true;
  }}
  if (btn2 && !btn2._bound) {{
    btn2.onclick = () => _doShareCopy('btn-copy-share-dash', 'share-url-dash');
    btn2._bound = true;
  }}
  const btn3 = document.getElementById('btn-copy-claim');
  if (btn3 && !btn3._bound) {{
    btn3.onclick = () => _doShareCopy('btn-copy-claim', 'share-url-claim');
    btn3._bound = true;
  }}
  const btn4 = document.getElementById('btn-copy-migrate');
  if (btn4 && !btn4._bound) {{
    btn4.onclick = () => _doShareCopy('btn-copy-migrate', 'share-url-migrate');
    btn4._bound = true;
  }}
}}
// Init: beim Page-Load + alle 30s
document.addEventListener('DOMContentLoaded', () => {{
  _bindShareCopyHandlers();
  updateShareBanner();
  setInterval(updateShareBanner, 30000);
}});

async function loadPublicUrlSection() {{
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const input = document.getElementById('public-url');
  const panel = document.getElementById('pu-status-panel');
  const lines = document.getElementById('pu-status-lines');
  const hint = document.getElementById('pu-manual-hint');
  const stat = document.getElementById('srv-public-status');
  const chk = document.getElementById('pu-autocheck-enabled');
  const sel = document.getElementById('pu-autocheck-interval');
  if (!input || !panel || !lines) return;
  try {{
    const r = await fetch('/api/public-url/status', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) return;
    const manual = d.public_url_manual || '';
    input.value = manual;
    if (chk) chk.checked = !!d.autocheck_enabled;
    if (sel && d.autocheck_interval_sec) sel.value = String(d.autocheck_interval_sec);
    const s = d.state || {{}};
    // Status-Badge oben rechts
    if (stat) {{
      if (manual) {{ stat.innerHTML = '<span style="color:#7ab8e0;">🔗 Manuell</span>'; }}
      else if (s.reachable_external) {{ stat.innerHTML = '<span style="color:#4caf50;">✅ Erreichbar</span>'; }}
      else if (s.reachable_local) {{ stat.innerHTML = '<span style="color:#e0a850;">🏠 Nur LAN</span>'; }}
      else {{ stat.innerHTML = '<span style="color:#888;">💤 Unbekannt</span>'; }}
    }}
    // Status-Panel nur zeigen wenn KEINE manuelle URL (wenn Owner sie kennt, nicht nerven)
    if (manual) {{
      panel.style.display = 'none';
      if (hint) hint.style.display = 'block';
    }} else {{
      panel.style.display = 'block';
      if (hint) hint.style.display = 'none';
      const rows = [];
      if (s.external_ip) rows.push(`Externe IP:&nbsp;<span style="color:#e8f0ff;">${{s.external_ip}}</span> ${{s.reachable_external ? '✅' : '❌'}}`);
      else rows.push('Externe IP: <span style="color:#888;">nicht ermittelbar</span>');
      if (s.local_ips && s.local_ips.length) rows.push(`Lokal:&nbsp;<span style="color:#e8f0ff;">${{s.local_ips.join(', ')}}</span> ${{s.reachable_local ? '✅' : '❌'}}`);
      if (s.best_url) rows.push(`Beste URL:&nbsp;<span style="color:#7ab8e0;">${{s.best_url}}</span>`);
      if (s.reachable_via) rows.push(`Methode: <span style="color:#aac0d8;">${{s.reachable_via === 'self' ? 'Self-Check' : 'Extern (isitup.org)'}}</span>`);
      rows.push(`Letzter Check: <span style="color:#888;">${{_fmtAgo(s.last_check)}}</span>`);
      lines.innerHTML = rows.join('<br>');
    }}
  }} catch (e) {{
    if (stat) stat.innerHTML = '<span style="color:#e55;">⚠️ Fehler</span>';
  }}
}}
async function doPublicUrlSave() {{
  const url = (document.getElementById('public-url')?.value || '').trim();
  const msg = document.getElementById('public-url-msg');
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = url ? '⏳ Teste & speichere…' : '⏳ Auto-Detect aktivieren…';
  msg.style.color = '#888';
  try {{
    const r = await fetch('/api/public-url/save', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify(url ? {{url:url}} : {{url:''}})
    }});
    const d = await r.json();
    if (!d.ok) {{ msg.textContent = '❌ ' + (d.error || 'Fehler'); msg.style.color = '#e55'; return; }}
    if (url) {{
      msg.textContent = d.reachable ? ('✅ Gespeichert & erreichbar (' + d.method + ')') : '⚠️ Gespeichert, aber nicht erreichbar!';
      msg.style.color = d.reachable ? '#4caf50' : '#f90';
    }} else {{
      msg.textContent = '✅ Auto-Detect aktiv';
      msg.style.color = '#7ab8e0';
    }}
    loadPublicUrlSection();
    loadServerStatus();
  }} catch (e) {{
    msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function doPublicUrlCheckNow() {{
  const url = (document.getElementById('public-url')?.value || '').trim();
  const msg = document.getElementById('public-url-msg');
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ Prüfe…'; msg.style.color = '#888';
  try {{
    const r = await fetch('/api/public-url/check', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify(url ? {{url:url}} : {{}})
    }});
    const d = await r.json();
    if (d.error) {{ msg.textContent = '❌ ' + d.error; msg.style.color = '#e55'; return; }}
    if (url) {{
      msg.textContent = d.ok ? ('✅ ' + (d.note || 'OK') + ' (' + (d.method || '?') + ')') : ('❌ ' + (d.note || 'Nicht erreichbar'));
      msg.style.color = d.ok ? '#4caf50' : '#f90';
    }} else {{
      msg.textContent = '✅ Full-Check fertig';
      msg.style.color = '#7ab8e0';
    }}
    loadPublicUrlSection();
  }} catch (e) {{
    msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function doPublicUrlConfigSave() {{
  const enabled = document.getElementById('pu-autocheck-enabled')?.checked || false;
  const interval = parseInt(document.getElementById('pu-autocheck-interval')?.value || '1800');
  const msg = document.getElementById('public-url-msg');
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/public-url/config', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify({{autocheck_enabled:enabled, autocheck_interval_sec:interval}})
    }});
    const d = await r.json();
    if (d.ok) {{ msg.textContent = '✅ Auto-Check: ' + (enabled ? 'an' : 'aus') + ' / ' + Math.round(interval/60) + ' Min'; msg.style.color = '#7ab8e0'; }}
    else {{ msg.textContent = '❌ ' + (d.error || 'Fehler'); msg.style.color = '#e55'; }}
  }} catch (e) {{
    msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
function toggleServerEdit(name) {{
  const el = document.getElementById('srv-' + name + '-edit');
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}
// Stufe 3 — Flache Liste, gruppiert nach Oberkategorie, Status-Button pro Amt.
// Nutzt AMT_CATEGORIES und AMT_SUBCLASS_COLORS aus dem Ämter-Tab-Script.
const VERIFY_STATUS_LABELS = {{
  pending:     {{ label: '📮 Beantragen',        bg:'rgba(212,168,80,0.18)', color:'#d4a850', clickable:true  }},
  requested:   {{ label: '⏳ Antrag gesendet',   bg:'rgba(122,184,224,0.18)', color:'#7ab8e0', clickable:false }},
  received:    {{ label: '📨 Eingegangen',       bg:'rgba(122,184,224,0.18)', color:'#7ab8e0', clickable:false }},
  in_progress: {{ label: '⚙️ In Bearbeitung',    bg:'rgba(255,165,80,0.18)',  color:'#ffa550', clickable:false }},
  confirmed:   {{ label: '✅ Bestätigt',          bg:'rgba(76,175,80,0.22)',   color:'#4caf50', clickable:false }},
  rejected:    {{ label: '❌ Abgelehnt',          bg:'rgba(228,68,68,0.22)',   color:'#e55',    clickable:false }},
}};

async function loadVerifyStufe3() {{
  const container = document.getElementById('verify-amt-list');
  if (!container) return;
  try {{
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/amt-watchlist', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    const items = d.items || [];
    renderVerifyStufe3(container, items);
  }} catch (e) {{
    container.innerHTML = '<div style="color:#e55;">Ladefehler: ' + e + '</div>';
  }}
}}

function renderVerifyStufe3(container, items) {{
  // Gruppieren nach Kategorie
  const grouped = {{ identity:[], finance:[], health:[], authority:[], affiliation:[] }};
  for (const item of items) {{
    const cat = item.category || 'identity';
    if (grouped[cat]) grouped[cat].push(item);
  }}
  let html = '';
  for (const catKey of ['identity','finance','health','authority','affiliation']) {{
    const cat = AMT_CATEGORIES[catKey];
    if (!cat) continue;
    const catItems = grouped[catKey];
    const count = catItems.length;
    // Kategorie-Überschrift (immer sichtbar, auch bei 0)
    html += '<div style="margin-top:18px;padding:10px 12px;background:linear-gradient(90deg,' + cat.color + '22 0%, rgba(10,15,25,0.5) 60%);border-radius:6px;border-left:4px solid ' + cat.color + ';display:flex;justify-content:space-between;align-items:center;">' +
              '<div style="color:' + cat.color + ';font-weight:bold;font-size:13px;letter-spacing:0.5px;">' + cat.icon + ' ' + cat.label.toUpperCase() + '</div>' +
              '<div style="font-size:10px;color:#887755;">' + count + ' ' + (count === 1 ? 'Amt' : 'Ämter') + '</div>' +
            '</div>';
    if (count === 0) {{
      html += '<div style="padding:10px 14px;color:#556677;font-size:10px;font-style:italic;text-align:center;">Kein Amt abonniert. Im Ämter Tab suchen und abonnieren.</div>';
      continue;
    }}
    for (const item of catItems) {{
      const sid = (item.shinpai_id || '').replace(/</g, '&lt;');
      const name = (item.name || sid).replace(/</g, '&lt;');
      const subKey = item.subclass || '';
      const subLabel = (cat.subs.find(s => s[0] === subKey) || [subKey, subKey])[1];
      const subColor = amtSubColor(catKey, subKey);
      const trust = item.trust_level || 1;
      const trustIcon = trust >= 5 ? '👑' : trust >= 4 ? '🏅' : trust >= 3 ? '✓✓✓' : trust >= 2 ? '✓' : '⚠️';
      const trustLabel = trust >= 5 ? 'Shinpai geprüft' : trust >= 4 ? 'Behörden-Register' : trust >= 3 ? 'Peer verifiziert' : trust >= 2 ? 'Domain verifiziert' : 'Unbekannt';
      const trustColor = trust >= 4 ? '#d4a850' : trust >= 2 ? '#4caf50' : '#e55';
      const st = VERIFY_STATUS_LABELS[item.status] || VERIFY_STATUS_LABELS.pending;
      const cursor = st.clickable ? 'pointer' : 'default';
      const onclickAttr = st.clickable ? 'onclick="verifyRequestAmt(\\'' + sid + '\\')"' : '';
      const statusTs = item.status_updated_at ? new Date(item.status_updated_at * 1000).toLocaleString('de-DE', {{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}}) : '';
      // Nachfrage/Beschwerde-Logik
      const inquiries = Array.isArray(item.inquiries) ? item.inquiries : [];
      const complaints = Array.isArray(item.complaints) ? item.complaints : [];
      const processingDays = parseInt(item.processing_time_days || 7, 10);
      const requestedAt = item.requested_at || item.added_at || 0;
      const lastActionTs = inquiries.length > 0 ? inquiries[inquiries.length - 1] : requestedAt;
      const nowSec = Math.floor(Date.now() / 1000);
      const cooldownRemaining = Math.max(0, (lastActionTs + processingDays * 86400) - nowSec);
      const inquiryAvailable = item.status !== 'pending' && item.status !== 'confirmed' && item.status !== 'rejected' && cooldownRemaining === 0;
      // Status-Label kann um Counter ergänzt werden
      const inquiryCount = inquiries.length;
      const displayStatus = (item.status === 'requested' || item.status === 'received' || item.status === 'in_progress') && inquiryCount > 0
        ? (inquiryCount === 1 ? 'einmal nachgefragt' : inquiryCount === 2 ? 'zweimal nachgefragt' : inquiryCount === 3 ? 'dreimal nachgefragt' : inquiryCount + ' Nachfragen')
        : null;
      // Beschwerde nach 3 Nachfragen seit letzter Beschwerde
      const sinceComplaint = complaints.length > 0 ? complaints[complaints.length - 1] : 0;
      const inquiriesSinceComplaint = inquiries.filter(t => t > sinceComplaint).length;
      const complaintAvailable = inquiriesSinceComplaint >= 3 && item.status !== 'pending' && item.status !== 'confirmed' && item.status !== 'rejected';
      const complaintCount = complaints.length;
      // Karteikarten-Layout: Name groß oben, Subklasse + Kategorie Icon, Trust-Badge, großer Beantragen-Button mittig unten
      html += '<div style="padding:18px 16px 16px 16px;margin-top:10px;background:linear-gradient(180deg,' + subColor + '15 0%, rgba(10,15,25,0.6) 100%);border-radius:10px;border:1px solid ' + subColor + '55;box-shadow:0 0 18px ' + subColor + '20;">' +
                // Oben: Trust-Badge rechts, Kategorie-Icon links
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">' +
                  '<div style="font-size:18px;">' + cat.icon + '</div>' +
                  '<div style="display:flex;align-items:center;gap:6px;padding:4px 10px;background:' + trustColor + '22;border:1px solid ' + trustColor + '66;border-radius:20px;">' +
                    '<span style="font-size:12px;">' + trustIcon + '</span>' +
                    '<span style="font-size:9px;color:' + trustColor + ';font-weight:bold;">' + trustLabel + '</span>' +
                  '</div>' +
                '</div>' +
                // Name zentriert groß
                '<div style="text-align:center;margin-bottom:6px;">' +
                  '<div style="color:' + subColor + ';font-weight:bold;font-size:16px;line-height:1.3;letter-spacing:0.3px;">' + name + '</div>' +
                '</div>' +
                // Subklasse + Kategorie + Kosten als Untertitel
                '<div style="text-align:center;margin-bottom:14px;">' +
                  '<div style="font-size:11px;color:#887755;">' + subLabel + '</div>' +
                  '<div style="font-size:9px;color:#556677;margin-top:2px;">' + cat.label + (typeof item.fee_eur !== 'undefined' ? ' &nbsp;·&nbsp; ' + (item.fee_eur > 0 ? '<span style="color:#d4a850;font-weight:bold;">' + item.fee_eur.toFixed(2).replace('.', ',') + ' Euro</span>' : '<span style="color:#4caf50;">kostenfrei</span>') : '') + '</div>' +
                '</div>' +
                // Großer breiter Status/Beantragen-Button mittig
                '<button ' + onclickAttr + ' class="btn" style="cursor:' + cursor + ';width:100%;font-size:13px;padding:12px 16px;font-weight:bold;background:' + st.bg + ';border:1px solid ' + st.color + '88;color:' + st.color + ';border-radius:8px;">' + st.label + (displayStatus ? ' · ' + displayStatus : '') + '</button>' +
                // Zeitstempel unter dem Button (wenn Status != pending)
                (statusTs && item.status !== 'pending' ? '<div style="text-align:center;font-size:9px;color:#556677;margin-top:6px;">' + statusTs + '</div>' : '') +
                // Links-Bar: Beschwerde links unten, Nachfrage rechts unten
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;min-height:14px;">' +
                  // Beschwerde-Link links
                  (complaintAvailable
                    ? '<a href="#" onclick="verifyComplaint(\\'' + sid + '\\');return false;" style="font-size:10px;color:#e55;text-decoration:underline;">' + (complaintCount >= 1 ? 'Eskalation' : 'Beschwerde einreichen') + '</a>'
                    : '<span></span>') +
                  // Nachfrage-Link rechts
                  (item.status !== 'pending' && item.status !== 'confirmed' && item.status !== 'rejected'
                    ? (inquiryAvailable
                        ? '<a href="#" onclick="verifyInquiry(\\'' + sid + '\\');return false;" style="font-size:10px;color:#7ab8e0;text-decoration:underline;">Nachfrage senden</a>'
                        : '<span style="font-size:9px;color:#556677;">Nachfrage in ' + Math.ceil(cooldownRemaining / 86400) + ' Tagen möglich</span>')
                    : '<span></span>') +
                '</div>';
      // Infobox bei Rückmeldung
      if (item.response_hint) {{
        const hint = item.response_hint.replace(/</g, '&lt;');
        const link = item.response_link ? '<a href="' + item.response_link.replace(/"/g, '&quot;') + '" target="_blank" style="color:#7ab8e0;">Mehr Infos →</a>' : '';
        html += '<div style="margin-top:10px;padding:10px 12px;background:rgba(0,0,0,0.35);border-radius:6px;font-size:10px;color:#887755;line-height:1.5;">' + hint + ' ' + link + '</div>';
      }}
      html += '</div>';
    }}
  }}
  container.innerHTML = html;
}}

async function verifyRequestAmt(shinpaiId) {{
  // Echter Antrag: ruft das Amt über /api/amt-watchlist/submit an,
  // das kontaktiert den Amt-Endpoint und erzeugt bei Erfolg eine signierte Lizenz.
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/amt-watchlist/submit', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{shinpai_id:shinpaiId}})}});
    const d = await r.json();
    if (d.ok) {{
      loadVerifyStufe3();
    }} else if (d.error) {{
      alert(d.error);
    }}
  }} catch (e) {{ alert('Netzwerkfehler: ' + e); }}
}}

async function verifyInquiry(shinpaiId) {{
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/amt-watchlist/inquire', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{shinpai_id:shinpaiId}})}});
    const d = await r.json();
    if (d.ok) {{
      loadVerifyStufe3();
    }} else if (d.error) {{
      alert(d.error);
    }}
  }} catch (e) {{}}
}}

async function verifyComplaint(shinpaiId) {{
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/amt-watchlist/complaint', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{shinpai_id:shinpaiId}})}});
    const d = await r.json();
    if (d.ok) {{
      let msg = 'Beschwerde eingereicht. Template: ' + (d.template || '');
      if (d.escalation_ready) {{
        msg += '\\n\\nZweite Beschwerde — bei weiterer Nichtreaktion Eskalation zum Listen-Owner (kommt in Phase 2).';
      }}
      alert(msg);
      loadVerifyStufe3();
    }} else if (d.error) {{
      alert(d.error);
    }}
  }} catch (e) {{}}
}}
// Veraltet: loadVerifyAmtWatchlistPreview — wird jetzt von loadVerifyStufe3 erledigt.
function loadVerifyAmtWatchlistPreview() {{
  loadVerifyStufe3();
}}
function _amtListsToken() {{
  return document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
}}
async function loadAmtLists() {{
  const table = document.getElementById('amt-list-table');
  if (!table) return;
  try {{
    const token = _amtListsToken();
    const r = await fetch('/api/amt-lists', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    const subs = d.subscriptions || [];
    if (subs.length === 0) {{
      table.innerHTML = '<div style="text-align:center;padding:10px;color:#665540;">Noch keine Listen abonniert.</div>';
      return;
    }}
    let rows = '';
    for (const s of subs) {{
      const status = s.last_status === 'ok' ? '<span style="color:#4caf50;">✅ ok</span>' : '<span style="color:#e55;">❌ ' + (s.last_status || '–') + '</span>';
      const lastFetched = s.last_fetched ? new Date(s.last_fetched * 1000).toLocaleString('de-DE') : '–';
      const name = (s.name || s.url).replace(/</g, '&lt;');
      const url = s.url.replace(/</g, '&lt;');
      rows += '<div style="padding:12px 14px;background:rgba(10,15,25,0.4);border-radius:8px;margin-bottom:10px;border:1px solid rgba(212,168,80,0.15);">' +
              '<div style="color:#d4a850;font-weight:bold;font-size:13px;line-height:1.5;margin-bottom:4px;">' + name + '</div>' +
              '<div style="font-size:11px;color:#665540;word-break:break-all;line-height:1.6;margin-bottom:6px;">' + url + '</div>' +
              '<div style="font-size:11px;color:#887755;line-height:1.8;">Status: ' + status + ' &nbsp;·&nbsp; Ämter: <strong style="color:#d4a850;">' + (s.last_count || 0) + '</strong></div>' +
              '<div style="font-size:10px;color:#665540;line-height:1.6;margin-bottom:10px;">Geholt: ' + lastFetched + '</div>' +
              '<div style="display:flex;gap:8px;">' +
                '<button onclick="doAmtListRefresh(\\'' + s.id + '\\')" class="btn" style="flex:1;font-size:11px;padding:8px 12px;background:rgba(122,184,224,0.15);border:1px solid rgba(122,184,224,0.4);color:#7ab8e0;">🔄 Aktualisieren</button>' +
                '<button onclick="doAmtListRemove(\\'' + s.id + '\\')" class="btn" style="flex:1;font-size:11px;padding:8px 12px;background:rgba(220,80,80,0.15);border:1px solid rgba(220,80,80,0.4);color:#e55;">🗑️ Entfernen</button>' +
              '</div>' +
            '</div>';
    }}
    table.innerHTML = rows;
  }} catch (e) {{
    table.innerHTML = '<div style="color:#e55;">Ladefehler: ' + e + '</div>';
  }}
}}
async function doAmtListSubscribe() {{
  const url = document.getElementById('amt-list-url')?.value?.trim();
  const msg = document.getElementById('amt-list-msg');
  if (!url) {{ msg.textContent = 'URL eingeben!'; msg.style.color = '#e55'; return; }}
  const token = _amtListsToken();
  msg.textContent = 'Hole Liste...'; msg.style.color = '#888';
  try {{
    const r = await fetch('/api/amt-lists/subscribe', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{url:url}})}});
    const d = await r.json();
    if (d.ok) {{
      const s = d.subscription || {{}};
      if (s.last_status === 'ok') {{
        msg.textContent = '✅ Abonniert! ' + (s.last_count || 0) + ' Ämter geladen.';
        msg.style.color = '#4caf50';
      }} else {{
        msg.textContent = '⚠️ Abo angelegt, aber Fetch schlug fehl: ' + s.last_status;
        msg.style.color = '#f90';
      }}
      document.getElementById('amt-list-url').value = '';
      loadAmtLists();
    }} else {{
      msg.textContent = d.error || 'Fehler';
      msg.style.color = '#e55';
    }}
  }} catch (e) {{
    msg.textContent = 'Netzwerkfehler: ' + e;
    msg.style.color = '#e55';
  }}
}}
async function doAmtListRemove(id) {{
  if (!confirm('Diese Liste wirklich entfernen?')) return;
  const token = _amtListsToken();
  try {{
    const r = await fetch('/api/amt-lists/remove', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{id:id}})}});
    const d = await r.json();
    if (d.ok) loadAmtLists();
    else alert(d.error || 'Fehler');
  }} catch (e) {{
    alert('Netzwerkfehler: ' + e);
  }}
}}
async function doAmtListRefresh(id) {{
  const token = _amtListsToken();
  const msg = document.getElementById('amt-list-msg');
  if (msg) {{ msg.textContent = 'Aktualisiere...'; msg.style.color = '#888'; }}
  try {{
    const r = await fetch('/api/amt-lists/refresh', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{id:id}})}});
    const d = await r.json();
    if (d.ok) {{
      if (msg) {{ msg.textContent = '✅ Aktualisiert.'; msg.style.color = '#4caf50'; }}
      loadAmtLists();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler: ' + e; msg.style.color = '#e55'; }}
  }}
}}
async function doAmtListsRefresh() {{
  const token = _amtListsToken();
  const msg = document.getElementById('amt-list-msg');
  if (msg) {{ msg.textContent = 'Aktualisiere alle...'; msg.style.color = '#888'; }}
  try {{
    const r = await fetch('/api/amt-lists/refresh', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{}})}});
    const d = await r.json();
    if (d.ok) {{
      if (msg) {{ msg.textContent = '✅ ' + (d.refreshed?.length || 0) + ' Liste(n) aktualisiert.'; msg.style.color = '#4caf50'; }}
      loadAmtLists();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler: ' + e; msg.style.color = '#e55'; }}
  }}
}}
// ── Titel-Register ──
async function loadTitles() {{
  try {{
    const r = await fetch('/api/titles', {{headers: {{'X-Session-Token': _btcToken()}}}});
    const d = await r.json();
    const reg = document.getElementById('titel-register');
    const earnedBox = document.getElementById('titel-earned');
    const progBox = document.getElementById('titel-progress');
    if (!reg || (!d.earned?.length && !d.progress?.length)) return;
    reg.style.display = 'block';
    // Verdiente Titel
    if (earnedBox && d.earned?.length) {{
      earnedBox.innerHTML = d.earned.map(t =>
        '<div style="display:flex;align-items:center;gap:10px;background:rgba(245,158,11,0.06);border:1px solid ' + t.badge_color + '40;border-radius:8px;padding:10px;margin-bottom:6px;">' +
          '<div style="font-size:28px;filter:drop-shadow(0 0 6px ' + t.badge_color + ');">' + t.badge_emoji + '</div>' +
          '<div style="flex:1;">' +
            '<div style="font-size:12px;color:' + t.badge_color + ';font-weight:bold;">' + t.name + '</div>' +
            '<div style="font-size:10px;color:#887755;">' + t.description + '</div>' +
            '<div style="font-size:9px;color:#665540;margin-top:2px;">' + t.grade + ' · ' + t._source_list + '</div>' +
          '</div>' +
          '<div style="font-size:10px;color:#4caf50;font-weight:bold;">✅</div>' +
        '</div>'
      ).join('');
    }}
    // Fortschritt (noch nicht verdient, aber teilweise erfüllt)
    if (progBox && d.progress?.length) {{
      const relevant = d.progress.filter(t => t.fulfilled > 0);
      if (relevant.length) {{
        progBox.innerHTML = '<div style="font-size:10px;color:#665540;margin-bottom:6px;">Fortschritt:</div>' +
          relevant.map(t => {{
            const pct = Math.round((t.fulfilled / t.total) * 100);
            return '<div style="background:rgba(40,40,50,0.4);border:1px solid #2a2a3a;border-radius:6px;padding:8px;margin-bottom:4px;">' +
              '<div style="display:flex;align-items:center;gap:8px;">' +
                '<span style="font-size:18px;opacity:0.4;">' + t.badge_emoji + '</span>' +
                '<div style="flex:1;">' +
                  '<div style="font-size:11px;color:#887755;">' + t.name + '</div>' +
                  '<div style="background:#1a1a2a;border-radius:3px;height:6px;margin-top:4px;overflow:hidden;">' +
                    '<div style="background:' + t.badge_color + ';height:100%;width:' + pct + '%;border-radius:3px;"></div>' +
                  '</div>' +
                  '<div style="font-size:9px;color:#665540;margin-top:2px;">' + t.fulfilled + '/' + t.total + ' Bedingungen' +
                    (t.cycles_needed > 0 ? ' · ' + t.cycles_current + '/' + t.cycles_needed + ' Zyklen' : '') +
                  '</div>' +
                '</div>' +
              '</div>' +
            '</div>';
          }}).join('');
      }}
    }}
  }} catch (e) {{}}
}}
// ── Bitcoin Wallet ──
function toggleBtcSeed() {{
  const box = document.getElementById('btc-seed-box');
  if (box) box.style.display = box.style.display === 'none' ? 'block' : 'none';
}}
function _btcToken() {{ return document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || ''; }}
let _btcPollInterval = null;
let _btcPollStart = 0;
async function loadBtcWallet() {{
  try {{
    const r = await fetch('/api/btc/wallet', {{headers: {{'X-Session-Token': _btcToken()}}}});
    const d = await r.json();
    const info = document.getElementById('btc-wallet-info');
    const noWallet = document.getElementById('btc-no-wallet');
    const status = document.getElementById('srv-btc-status');
    if (d.address) {{
      if (info) info.style.display = 'block';
      if (noWallet) noWallet.style.display = 'none';
      if (status) status.innerHTML = '<span style="color:#4caf50;">✅ Aktiv</span>';
      document.getElementById('btc-address').textContent = d.address;
      document.getElementById('btc-anchors').textContent = (d.entries || []).filter(e => e.status === 'confirmed').length;
      document.getElementById('btc-code-hash').textContent = d.code_hash || '—';
      const seedWords = document.getElementById('btc-seed-words');
      const seedToggle = document.getElementById('btc-seed-toggle');
      if (seedWords && d.mnemonic) {{ seedWords.textContent = d.mnemonic; }}
      if (seedToggle && !d.mnemonic) {{ seedToggle.style.display = 'none'; }}
      // Revoke-Button zeigen wenn Verankerung existiert
      const revokeBtn = document.getElementById('btc-revoke-btn');
      if (revokeBtn) {{
        const hasConfirmed = (d.entries || []).some(e => e.status === 'confirmed');
        revokeBtn.style.display = hasConfirmed ? 'inline-block' : 'none';
      }}
      loadBtcBalance(d.address);
      // Einträge anzeigen (alle: confirmed + revoked + pending)
      const box = document.getElementById('btc-entries');
      const allEntries = (d.entries || []).filter(e => e.status);
      if (box && allEntries.length > 0) {{
        const active = allEntries.filter(e => e.status === 'confirmed' && !e.revoked).length;
        const revoked = allEntries.filter(e => e.revoked).length;
        const pending = allEntries.filter(e => e.status === 'pending').length;
        let header = '<div style="font-size:10px;color:#887755;margin-bottom:6px;font-weight:bold;">Verankerungen: ' + active + ' aktiv';
        if (revoked) header += ' · <span style="color:#ff5555;">' + revoked + ' widerrufen</span>';
        if (pending) header += ' · <span style="color:#f59e0b;">' + pending + ' pending</span>';
        header += '</div>';
        box.innerHTML = header + allEntries.map(e => {{
          const isRevoked = e.revoked;
          const isPending = e.status === 'pending';
          const border = isRevoked ? 'rgba(255,85,85,0.2)' : isPending ? 'rgba(245,158,11,0.3)' : 'rgba(245,158,11,0.1)';
          const bg = isRevoked ? 'rgba(255,85,85,0.06)' : 'rgba(245,158,11,0.06)';
          const vColor = isRevoked ? '#ff5555' : '#f59e0b';
          const badge = isRevoked ? ' <span style="color:#ff5555;font-weight:bold;">🔴 WIDERRUFEN</span>' : isPending ? ' <span style="color:#f59e0b;">⏳ pending</span>' : ' <span style="color:#4caf50;">✅</span>';
          return '<div style="background:' + bg + ';border:1px solid ' + border + ';border-radius:4px;padding:6px;margin-bottom:4px;font-size:10px;">' +
            '<span style="color:' + vColor + ';">v' + (e.version || '?') + '</span>' + badge + ' — ' +
            '<code style="color:#7ecfff;font-size:9px;">' + (e.code_hash || '').substring(0, 16) + '…</code>' +
            (e.txid ? ' — <a href="https://mempool.space/tx/' + e.txid + '" target="_blank" style="color:#887755;">TX↗</a>' : '') +
            (isRevoked && e.revoke_txid ? ' · <a href="https://mempool.space/tx/' + e.revoke_txid + '" target="_blank" style="color:#ff5555;font-size:9px;">Revoke-TX↗</a>' : '') +
            '<br><span style="color:#665540;">' + new Date((e.timestamp || 0) * 1000).toLocaleString('de-DE') + '</span>' +
          '</div>';
        }}).join('');
      }}
      // Pending Anchor? Poll starten
      if ((d.entries || []).some(e => e.status === 'pending')) {{ startAnchorPoll(); }}
      // Pending Revoke? Poll starten
      if (d.pending_revoke) {{ startRevokePoll(); }}
    }} else {{
      if (info) info.style.display = 'none';
      if (noWallet) noWallet.style.display = 'block';
      if (status) status.innerHTML = '<span style="color:#665540;">⚪ Kein Wallet</span>';
    }}
  }} catch (e) {{}}
}}
async function loadBtcBalance(addr) {{
  try {{
    const r = await fetch('https://mempool.space/api/address/' + addr);
    const d = await r.json();
    const confirmed = (d.chain_stats?.funded_txo_sum || 0) - (d.chain_stats?.spent_txo_sum || 0);
    const unconfirmed = (d.mempool_stats?.funded_txo_sum || 0) - (d.mempool_stats?.spent_txo_sum || 0);
    const total = confirmed + unconfirmed;
    const el = document.getElementById('btc-balance');
    if (el) el.textContent = (total / 100000000).toFixed(8) + ' BTC';
  }} catch (e) {{
    const el = document.getElementById('btc-balance');
    if (el) el.textContent = '—';
  }}
}}
async function doBtcCreate() {{
  const msg = document.getElementById('btc-msg');
  if (msg) {{ msg.textContent = '⏳ Erstelle Wallet...'; msg.style.color = '#f59e0b'; }}
  try {{
    const r = await fetch('/api/btc/wallet/create', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':_btcToken()}}, body:'{{}}'}});
    const d = await r.json();
    if (d.address) {{
      if (msg) {{ msg.textContent = '✅ Wallet erstellt!'; msg.style.color = '#4caf50'; }}
      loadBtcWallet();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
  }}
}}
async function doBtcImport() {{
  const wif = document.getElementById('btc-import-wif')?.value?.trim();
  const msg = document.getElementById('btc-msg');
  if (!wif) {{ if (msg) {{ msg.textContent = 'WIF eingeben!'; msg.style.color = '#e55'; }} return; }}
  if (msg) {{ msg.textContent = '⏳ Importiere...'; msg.style.color = '#f59e0b'; }}
  try {{
    const r = await fetch('/api/btc/wallet/import', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':_btcToken()}}, body:JSON.stringify({{wif:wif}})}});
    const d = await r.json();
    if (d.address) {{
      if (msg) {{ msg.textContent = '✅ Wallet importiert!'; msg.style.color = '#4caf50'; }}
      loadBtcWallet();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
  }}
}}
async function doBtcImportSeed() {{
  const seed = document.getElementById('btc-import-seed')?.value?.trim();
  const msg = document.getElementById('btc-msg');
  if (!seed) {{ if (msg) {{ msg.textContent = 'Seed-Wörter eingeben!'; msg.style.color = '#e55'; }} return; }}
  const words = seed.split(/\s+/).length;
  if (words !== 12 && words !== 24) {{ if (msg) {{ msg.textContent = 'Bitte 12 oder 24 Wörter eingeben (du hast ' + words + ')'; msg.style.color = '#e55'; }} return; }}
  if (msg) {{ msg.textContent = '⏳ Importiere aus Seed...'; msg.style.color = '#f59e0b'; }}
  try {{
    const r = await fetch('/api/btc/wallet/import', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':_btcToken()}}, body:JSON.stringify({{seed:seed}})}});
    const d = await r.json();
    if (d.address) {{
      if (msg) {{ msg.textContent = '✅ Wallet importiert!'; msg.style.color = '#4caf50'; }}
      loadBtcWallet();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
  }}
}}
// ── Anchor Flow: Preview → Confirm → Poll ──
async function doBtcAnchorPreview() {{
  const preview = document.getElementById('btc-anchor-preview');
  const fee = document.getElementById('btc-preview-fee');
  const hash = document.getElementById('btc-preview-hash');
  const dup = document.getElementById('btc-preview-dup');
  const confirm = document.getElementById('btc-confirm-btn');
  fee.textContent = '⏳ Berechne...';
  preview.style.display = 'block';
  try {{
    const r = await fetch('/api/btc/anchor/preview', {{headers: {{'X-Session-Token': _btcToken()}}}});
    const d = await r.json();
    fee.textContent = d.fee_sats + ' Sats (~' + d.fee_eur + '€)';
    hash.textContent = 'v' + d.version + ' · ' + d.code_hash;
    if (d.already_anchored) {{
      dup.style.display = 'block';
      dup.textContent = '⚠️ Dieser Code-Hash ist bereits verankert!';
      confirm.disabled = true;
    }} else if (d.license_complete === false) {{
      const miss = (d.license_missing || []).join(', ');
      dup.style.display = 'block';
      dup.innerHTML = '⚠️ Lizenz unvollständig: <b>' + miss + '</b><br><a href="#" onclick="showDashTab(\\'lizenzen\\');return false;" style="color:#7ab8e0;text-decoration:underline;">→ Erst im Lizenzen-Tab eintragen!</a>';
      confirm.disabled = true;
    }} else {{
      dup.style.display = 'none';
      confirm.disabled = false;
    }}
  }} catch (e) {{
    fee.textContent = 'Fehler beim Laden';
  }}
}}
async function doBtcAnchorConfirm() {{
  const btn = document.getElementById('btc-confirm-btn');
  const msg = document.getElementById('btc-anchor-msg');
  const preview = document.getElementById('btc-anchor-preview');
  btn.disabled = true; btn.textContent = '⏳ Sende TX...';
  try {{
    const r = await fetch('/api/btc/anchor', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':_btcToken()}}, body:'{{}}'}});
    const d = await r.json();
    if (d.ok) {{
      preview.style.display = 'none';
      if (msg) {{ msg.innerHTML = '✅ TX gesendet! <a href="https://mempool.space/tx/' + d.entry.txid + '" target="_blank" style="color:#f59e0b;">TX↗</a>'; msg.style.color = '#4caf50'; }}
      startAnchorPoll();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
      btn.disabled = false; btn.textContent = 'Verankern!';
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
    btn.disabled = false; btn.textContent = 'Verankern!';
  }}
}}
function startAnchorPoll() {{
  if (_btcPollInterval) return;
  _btcPollStart = Date.now();
  const prog = document.getElementById('btc-anchor-progress');
  if (prog) prog.style.display = 'block';
  document.getElementById('btc-anchor-btn').style.display = 'none';
  _btcPollInterval = setInterval(pollAnchorStatus, 10000);
  pollAnchorStatus();
}}
async function pollAnchorStatus() {{
  const timer = document.getElementById('btc-progress-timer');
  const status = document.getElementById('btc-progress-status');
  const cycle = document.getElementById('btc-progress-cycle');
  const elapsed = Math.floor((Date.now() - _btcPollStart) / 1000);
  const min = Math.floor(elapsed / 60);
  const sec = elapsed % 60;
  if (timer) timer.textContent = min.toString().padStart(2,'0') + ':' + sec.toString().padStart(2,'0');
  try {{
    const r = await fetch('/api/btc/anchor/status', {{headers: {{'X-Session-Token': _btcToken()}}}});
    const d = await r.json();
    if (d.status === 'confirmed') {{
      clearInterval(_btcPollInterval); _btcPollInterval = null;
      const prog = document.getElementById('btc-anchor-progress');
      if (prog) prog.style.display = 'none';
      document.getElementById('btc-anchor-btn').style.display = 'block';
      const msg = document.getElementById('btc-anchor-msg');
      if (msg) {{ msg.innerHTML = '✅ Verankerung bestätigt! Block #' + d.block_height + ' — <a href="https://mempool.space/tx/' + d.txid + '" target="_blank" style="color:#f59e0b;">TX↗</a>'; msg.style.color = '#4caf50'; }}
      loadBtcWallet();
    }} else if (d.status === 'pending') {{
      if (status) status.textContent = 'TX: ' + (d.txid || '').substring(0, 20) + '…';
      if (d.cycle >= 4) {{
        if (cycle) cycle.innerHTML = '⚠️ Verankerung dauert länger als erwartet!<br><button onclick="clearInterval(_btcPollInterval);_btcPollInterval=null;" style="color:#f59e0b;background:none;border:1px solid #f59e0b;border-radius:4px;padding:2px 8px;margin-top:4px;cursor:pointer;font-size:10px;">Warten beenden</button>';
      }} else {{
        if (cycle) cycle.textContent = 'Zyklus ' + d.cycle + '/3 · Nächste Prüfung in 10s';
      }}
    }} else {{
      if (status) status.textContent = 'Kein pending Anchor';
      clearInterval(_btcPollInterval); _btcPollInterval = null;
      document.getElementById('btc-anchor-progress').style.display = 'none';
      document.getElementById('btc-anchor-btn').style.display = 'block';
    }}
  }} catch (e) {{}}
}}
// ── Revocation ──
async function doBtcRevokePreview() {{
  const dialog = document.getElementById('btc-revoke-dialog');
  const fee = document.getElementById('btc-revoke-fee');
  const info = document.getElementById('btc-revoke-info');
  const msg = document.getElementById('btc-revoke-msg');
  if (fee) fee.textContent = '⏳ Berechne Kosten...';
  if (info) info.innerHTML = '';
  if (dialog) dialog.style.display = 'block';
  try {{
    const r = await fetch('/api/btc/revoke/preview', {{headers: {{'X-Session-Token': _btcToken()}}}});
    const d = await r.json();
    if (d.error) {{
      if (fee) fee.textContent = d.error;
      return;
    }}
    if (fee) fee.textContent = d.fee_sats + ' Sats (~' + d.fee_eur + '€)';
    // Dropdown mit aktiven Versionen
    const versions = d.active_versions || [];
    if (versions.length === 0) {{
      if (info) info.textContent = 'Keine aktiven Versionen zum Widerrufen.';
      return;
    }}
    let opts = versions.map(v => {{
      const dt = new Date(v.timestamp * 1000).toLocaleDateString('de-DE');
      return '<option value="' + v.code_hash + '">v' + v.version + ' (' + dt + ') · ' + v.code_hash.slice(0,12) + '…</option>';
    }}).join('');
    if (info) info.innerHTML = '<label style="color:#ff8888;font-size:10px;display:block;margin-bottom:3px;">Welche Version widerrufen?</label><select id="btc-revoke-select" style="width:100%;font-size:11px;padding:6px;background:#1a0a0a;color:#ff5555;border:1px solid rgba(255,85,85,0.3);border-radius:4px;">' + opts + '</select>';
  }} catch (e) {{
    if (fee) fee.textContent = 'Fehler beim Laden';
  }}
}}
async function doBtcRevokeConfirm() {{
  const code = document.getElementById('btc-revoke-totp')?.value?.trim();
  const sel = document.getElementById('btc-revoke-select');
  const hash = sel ? sel.value : '';
  const msg = document.getElementById('btc-revoke-msg');
  const btn = document.getElementById('btc-revoke-confirm-btn');
  if (!hash) {{ if (msg) {{ msg.textContent = 'Version auswählen!'; msg.style.color = '#e55'; }} return; }}
  if (!code || code.length !== 6) {{ if (msg) {{ msg.textContent = '6-stelligen 2FA-Code eingeben!'; msg.style.color = '#e55'; }} return; }}
  if (btn) {{ btn.disabled = true; btn.textContent = '⏳ Sende Widerruf...'; }}
  if (msg) {{ msg.textContent = ''; }}
  try {{
    const r = await fetch('/api/btc/revoke', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':_btcToken()}}, body:JSON.stringify({{totp_code:code, code_hash:hash}})}});
    const d = await r.json();
    if (d.ok) {{
      document.getElementById('btc-revoke-dialog').style.display = 'none';
      if (msg) {{ msg.innerHTML = '🔴 v' + (d.version||'?') + ' TX gesendet! <a href="https://mempool.space/tx/' + d.revoke_txid + '" target="_blank" style="color:#ff5555;">TX↗</a>'; msg.style.color = '#ff5555'; }}
      startRevokePoll();
    }} else {{
      if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
      if (btn) {{ btn.disabled = false; btn.textContent = 'Unwiderruflich widerrufen'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55'; }}
    if (btn) {{ btn.disabled = false; btn.textContent = 'Unwiderruflich widerrufen'; }}
  }}
}}

async function loadMyLicense() {{
  try {{
    const r = await fetch('/api/license/info');
    const d = await r.json();
    const company = document.getElementById('license-company');
    const verifier = document.getElementById('license-verifier');
    const glow = document.getElementById('license-glow');
    const idDisp = document.getElementById('license-id-display');
    const hashDisp = document.getElementById('license-code-hash');
    const logoBox = document.getElementById('license-logo-box');
    if (company && d.company) company.value = d.company;
    if (verifier && d.verifier_url) verifier.value = d.verifier_url;
    if (glow && d.glow_color) glow.value = d.glow_color;
    if (idDisp && d.license_id) {{ idDisp.style.display = 'block'; idDisp.textContent = 'Lizenz-ID: ' + d.license_id; }}
    if (hashDisp && d.code_hash) hashDisp.textContent = 'Code-Hash: ' + d.code_hash.substring(0, 16) + '...';
    if (logoBox && d.logo) logoBox.innerHTML = '<img src="' + d.logo + '" style="width:96px;height:96px;border-radius:50%;object-fit:cover;">';
  }} catch (e) {{}}
  // Erhaltene Lizenzen laden (L9)
  loadReceivedLicenses();
  loadIssuedLicenses();
}}

async function loadReceivedLicenses() {{
  const box = document.getElementById('received-licenses');
  const expBox = document.getElementById('expired-licenses');
  const expContainer = document.getElementById('expired-licenses-box');
  if (!box) return;
  try {{
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/licenses/received', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    const lics = d.licenses || [];
    if (lics.length === 0) {{
      box.innerHTML = '<div style="color:#665540;">Noch keine Verifizierungen. Sobald du Stufe 1 oder höher durchläufst, erscheint die Lizenz hier.</div>';
      return;
    }}
    let html = '';
    let expHtml = '';
    const nowSec = Math.floor(Date.now() / 1000);
    for (const lic of lics) {{
      const issuedD = new Date((lic.issued_at || 0) * 1000);
      const validD = new Date((lic.valid_until || 0) * 1000);
      const issued = issuedD.toLocaleDateString('de-DE', {{day:'2-digit',month:'2-digit',year:'numeric'}}) + ' um ' + issuedD.toLocaleTimeString('de-DE', {{hour:'2-digit',minute:'2-digit'}}) + ' Uhr';
      const validUntil = validD.toLocaleDateString('de-DE', {{day:'2-digit',month:'2-digit',year:'numeric'}}) + ' um ' + validD.toLocaleTimeString('de-DE', {{hour:'2-digit',minute:'2-digit'}}) + ' Uhr';
      const isExpired = !lic.is_valid;
      const graceUntil = lic.grace_until || 0;
      const inGrace = isExpired && graceUntil > nowSec;
      const daysRemain = inGrace ? Math.ceil((graceUntil - nowSec) / 86400) : 0;
      let statusIcon, statusColor, statusLabel;
      if (lic.revoked) {{
        statusIcon = '🚫'; statusColor = '#e55'; statusLabel = 'widerrufen';
      }} else if (lic.is_valid) {{
        statusIcon = '✅'; statusColor = '#4caf50'; statusLabel = 'gültig';
      }} else if (inGrace) {{
        statusIcon = '⌛'; statusColor = '#f90'; statusLabel = 'abgelaufen, Löschung in ' + daysRemain + ' Tag' + (daysRemain === 1 ? '' : 'en');
      }} else {{
        statusIcon = '⌛'; statusColor = '#e55'; statusLabel = 'abgelaufen';
      }}
      const notes = (lic.notes || lic.realized_by || '').replace(/</g, '&lt;');
      const issuer = (lic.issuer_name || '—').replace(/</g, '&lt;');
      const realizedBy = (lic.realized_by || '').replace(/</g, '&lt;');
      const licId = (lic.license_id || '').replace(/</g, '&lt;');
      const sigShort = (lic.signature_short || '').replace(/</g, '&lt;');
      const hint = (lic.response_hint || '').replace(/</g, '&lt;');
      const link = (lic.response_link || '').replace(/"/g, '&quot;');
      const card = '<div style="padding:12px 14px;background:rgba(10,15,25,0.5);border-radius:8px;border:1px solid ' + (isExpired ? 'rgba(245,158,11,0.2)' : 'rgba(122,184,224,0.2)') + ';margin-bottom:10px;">' +
                '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">' +
                  '<div style="color:' + (isExpired ? '#f59e0b' : '#7ab8e0') + ';font-weight:bold;font-size:12px;">' + notes + '</div>' +
                  '<div style="font-size:10px;color:' + statusColor + ';">' + statusIcon + ' ' + statusLabel + '</div>' +
                '</div>' +
                '<div style="font-size:10px;color:#887755;margin-bottom:4px;">Ausgestellt durch: <strong>' + issuer + '</strong></div>' +
                '<div style="font-size:10px;color:#887755;margin-bottom:2px;white-space:nowrap;">Ausstellung: ' + issued + '</div>' +
                '<div style="font-size:10px;color:#887755;margin-bottom:4px;white-space:nowrap;">Gültig bis: ' + validUntil + '</div>' +
                (lic.needs_paid_refresh ? '<div style="font-size:10px;color:#f59e0b;margin-bottom:4px;">💰 Erneuerung: ' + lic.fee_eur + '€</div>' : '') +
                (hint ? '<div style="font-size:10px;color:#665540;margin-bottom:4px;font-style:italic;">' + hint + (link ? ' &nbsp;<a href="' + link + '" target="_blank" style="color:#7ab8e0;">mehr Infos →</a>' : '') + '</div>' : '') +
                '<div style="font-size:9px;color:#556677;font-family:monospace;word-break:break-all;margin-top:6px;">ID: ' + licId + '</div>' +
                '<div style="font-size:9px;color:#556677;font-family:monospace;margin-top:2px;">Signatur: ' + sigShort + '…</div>' +
                '<button onclick="copyLicenseId(\\'' + licId + '\\')" class="btn" style="font-size:9px;margin-top:8px;padding:4px 8px;background:rgba(122,184,224,0.12);border:1px solid rgba(122,184,224,0.3);color:#7ab8e0;">📋 ID kopieren</button>' +
              '</div>';
      if (isExpired) {{
        expHtml += card;
      }} else {{
        html += card;
      }}
    }}
    box.innerHTML = html || '<div style="color:#665540;">Keine aktiven Verifizierungen.</div>';
    if (expBox && expHtml) {{
      expBox.innerHTML = expHtml;
      if (expContainer) expContainer.style.display = 'block';
    }} else if (expContainer) {{
      expContainer.style.display = 'none';
    }}
  }} catch (e) {{
    box.innerHTML = '<div style="color:#e55;">Ladefehler: ' + e + '</div>';
  }}
}}

async function loadIssuedLicenses() {{
  const box = document.getElementById('issued-licenses');
  if (!box) return;
  try {{
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/licenses/issued', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) {{ box.innerHTML = '<div style="color:#556677;font-size:10px;">' + d.error + '</div>'; return; }}
    const lics = d.licenses || [];
    if (lics.length === 0) {{
      box.innerHTML = '<div style="color:#665540;">Du hast noch keine Lizenzen ausgestellt.</div>';
      return;
    }}
    let html = '';
    for (const lic of lics) {{
      const issued = new Date((lic.issued_at || 0) * 1000).toLocaleString('de-DE', {{day:'2-digit',month:'2-digit',year:'numeric'}});
      const statusIcon = lic.is_valid ? '✅' : '⌛';
      const name = (lic.subject_name || lic.subject_shinpai_id || '').replace(/</g, '&lt;');
      html += '<div style="padding:8px 12px;background:rgba(10,15,25,0.5);border-radius:6px;border:1px solid rgba(170,120,255,0.15);margin-bottom:6px;">' +
                '<div style="color:#aa78ff;font-weight:bold;font-size:11px;">' + statusIcon + ' ' + name + '</div>' +
                '<div style="font-size:9px;color:#887755;">' + issued + ' &nbsp;·&nbsp; ' + (lic.realized_by || '') + '</div>' +
              '</div>';
    }}
    box.innerHTML = html;
  }} catch (e) {{}}
}}

function copyLicenseId(id) {{
  navigator.clipboard.writeText(id).then(() => {{
    alert('Lizenz-ID kopiert: ' + id);
  }});
}}
function confirmCrop() {{
  const logoBox = document.getElementById('license-logo-box');
  if (logoBox) {{
    const cropped = getCroppedB64();
    logoBox.innerHTML = '<img src="' + cropped + '" style="width:96px;height:96px;border-radius:50%;object-fit:cover;">';
  }}
  document.getElementById('crop-area').style.display = 'none';
}}
function cancelCrop() {{
  document.getElementById('crop-area').style.display = 'none';
  _cropImg = null;
}}
function copyMigrateToken() {{
  const el = document.getElementById('migrate-token-value');
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {{
    const msg = document.getElementById('migrate-msg');
    if (msg) {{ msg.textContent = '✅ Token kopiert!'; msg.style.color = '#4caf50'; setTimeout(() => msg.textContent = '', 2000); }}
  }});
}}
function smartShieldClick() {{
  // Smart-Click: führt zum richtigen Tab je nach was fehlt
  const shieldImg = document.getElementById('profile-shield-img');
  if (!shieldImg) return;
  const basisOk = shieldImg.dataset.basisOk === '1';
  if (!basisOk) {{
    showDashTab('sicherheit');
  }} else {{
    showDashTab('verifikation');
  }}
}}
async function doChangePassword() {{
  const oldPw = document.getElementById('old-pw')?.value;
  const newPw = document.getElementById('new-pw')?.value;
  const newPw2 = document.getElementById('new-pw2')?.value;
  const totp = document.getElementById('pw-totp')?.value || '';
  const msg = document.getElementById('pw-change-msg');
  if (!oldPw) {{ msg.textContent = 'Aktuelles Passwort eingeben!'; msg.style.color = '#e55'; return; }}
  if (!newPw) {{ msg.textContent = 'Neues Passwort eingeben!'; msg.style.color = '#e55'; return; }}
  if (newPw !== newPw2) {{ msg.textContent = 'Passwörter stimmen nicht überein!'; msg.style.color = '#e55'; return; }}
  if (newPw.length < 6) {{ msg.textContent = 'Min. 6 Zeichen!'; msg.style.color = '#e55'; return; }}
  if (!totp) {{ msg.textContent = '2FA Code nötig!'; msg.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const r = await fetch('/api/auth/password', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{old_password:oldPw, new_password:newPw, totp_code:totp}})}});
  const d = await r.json();
  if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; }}
  else {{
    msg.textContent = '✅ Passwort geändert!'; msg.style.color = '#4a4';
    document.getElementById('old-pw').value = '';
    document.getElementById('new-pw').value = '';
    document.getElementById('new-pw2').value = '';
    document.getElementById('pw-totp').value = '';
  }}
}}
async function loadBotQuota() {{
  // Public endpoint — kein Token nötig
  const sel = document.getElementById('bot-quota-select');
  const cur = document.getElementById('bot-quota-current');
  if (!sel || !cur) return;
  try {{
    const r = await fetch('/api/public/bot-policy');
    const d = await r.json();
    if (d.error) return;
    sel.value = String(d.quota);
    cur.textContent = `${{d.current}}/${{d.quota}}`;
    // Bot-Counter: Perso × Quote = Max, actual vs max
    const counter = document.getElementById('bot-quota-counter');
    if (counter) {{
      const persoCount = d.perso_count || 0;
      const maxBots = persoCount * d.quota;
      const actualBots = d.bot_count || 0;
      if (maxBots > 0) {{
        counter.textContent = `${{actualBots}} / ${{maxBots}} Bots (${{persoCount}} Perso × ${{d.quota}})`;
      }} else {{
        counter.textContent = persoCount > 0 ? 'Quote: 0 — keine Bots erlaubt' : 'Keine Perso-Lizenzen';
      }}
    }}
    // Easter-Egg Label IMMER versteckt bis User speichert — nicht initial zeigen!
  }} catch (e) {{}}
}}
async function doBotQuotaSave() {{
  const sel = document.getElementById('bot-quota-select');
  const pwEl = document.getElementById('bot-quota-pw');
  const totpEl = document.getElementById('bot-quota-totp');
  const cur = document.getElementById('bot-quota-current');
  const lbl = document.getElementById('bot-quota-label');
  const quota = parseInt(sel.value);
  const pw = pwEl.value;
  const totp = (totpEl.value || '').trim();
  if (!pw) {{ cur.textContent = 'PW?'; cur.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  cur.textContent = '⏳'; cur.style.color = '#8b6f47';
  try {{
    const r = await fetch('/api/owner/bot-quota', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify({{quota:quota, password:pw, totp_code:totp}})
    }});
    const d = await r.json();
    if (d.ok) {{
      cur.textContent = `${{d.current}}/${{d.quota}}`; cur.style.color = '#8b6f47';
      pwEl.value = ''; totpEl.value = '';
      // Easter-Egg: Label FADE-IN nach erfolgreichem Save
      if (lbl && d.label) {{
        lbl.textContent = '» ' + d.label;
        lbl.style.display = 'block';
        lbl.style.opacity = '0';
        setTimeout(() => {{ lbl.style.transition = 'opacity 1.2s ease'; lbl.style.opacity = '0.5'; }}, 50);
      }}
    }} else {{
      cur.textContent = d.error || 'Fehler'; cur.style.color = '#e55';
    }}
  }} catch (e) {{
    cur.textContent = 'Netzwerk-Fehler'; cur.style.color = '#e55';
  }}
}}
async function loadIgniStatus() {{
  const tile = document.getElementById('igni-tile');
  const statusEl = document.getElementById('igni-status');
  const modeSel = document.getElementById('igni-mode');
  const exportBtn = document.getElementById('igni-export-btn');
  if (!tile) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/owner/igni', {{headers:{{'X-Session-Token':token}}}});
    if (r.status === 403) {{ tile.style.display = 'none'; return; }}
    const d = await r.json();
    if (d.error) {{ tile.style.display = 'none'; return; }}
    tile.style.display = 'block';
    if (modeSel) modeSel.value = d.mode || 'standard';
    if (statusEl) {{
      if (d.active) {{ statusEl.textContent = '● aktiv'; statusEl.style.color = '#9ad0ff'; }}
      else {{ statusEl.textContent = '○ inaktiv (Paranoid)'; statusEl.style.color = '#8a9ab0'; }}
    }}
    if (exportBtn) exportBtn.disabled = !d.active;
    if (exportBtn) exportBtn.style.opacity = d.active ? '1' : '0.4';
  }} catch (e) {{
    tile.style.display = 'none';
  }}
}}
async function doIgniSave() {{
  const mode = document.getElementById('igni-mode').value;
  const pw = document.getElementById('igni-pw').value;
  const totp = document.getElementById('igni-totp').value || '';
  const msg = document.getElementById('igni-msg');
  if (!pw) {{ msg.textContent = '❌ Passwort erforderlich'; msg.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ speichere…'; msg.style.color = '#8a9ab0';
  try {{
    const r = await fetch('/api/owner/igni', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify({{mode:mode, password:pw, totp_code:totp}})
    }});
    const d = await r.json();
    if (d.error) {{ msg.textContent = '❌ ' + d.error; msg.style.color = '#e55'; return; }}
    msg.textContent = '✅ ' + (d.message || 'Gespeichert'); msg.style.color = '#9ad0ff';
    document.getElementById('igni-pw').value = '';
    document.getElementById('igni-totp').value = '';
    loadIgniStatus();
  }} catch (e) {{
    msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function doIgniExport() {{
  const msg = document.getElementById('igni-msg');
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ lade Igni…'; msg.style.color = '#8a9ab0';
  try {{
    const r = await fetch('/api/owner/igni/export', {{headers:{{'X-Session-Token':token}}}});
    if (!r.ok) {{
      let err = 'Export fehlgeschlagen';
      try {{ const d = await r.json(); err = d.error || err; }} catch(_) {{}}
      msg.textContent = '❌ ' + err; msg.style.color = '#e55'; return;
    }}
    const blob = await r.blob();
    const cd = r.headers.get('Content-Disposition') || '';
    const fn = (cd.match(/filename="([^"]+)"/) || [,'ShinNexus-Igni.zip'])[1];
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = fn;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    msg.textContent = '✅ Haus­schlüssel exportiert — nur auf dieser Maschine gültig.';
    msg.style.color = '#9ad0ff';
  }} catch (e) {{
    msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
window._currentEmail = '';
async function loadCurrentEmail() {{
  const valEl = document.getElementById('current-email-value');
  const badgeEl = document.getElementById('current-email-badge');
  const verifyBox = document.getElementById('email-verify-box');
  if (!valEl || !badgeEl) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/auth/email', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) {{ valEl.textContent = '(Fehler: ' + d.error + ')'; badgeEl.textContent = ''; badgeEl.onclick = null; badgeEl.style.cursor = ''; badgeEl.title = ''; if (verifyBox) verifyBox.style.display='none'; return; }}
    valEl.textContent = d.email || '(keine hinterlegt)';
    window._currentEmail = d.email || '';
    badgeEl.onclick = null; badgeEl.style.cursor = ''; badgeEl.title = '';
    if (!d.email) {{
      badgeEl.textContent = '⚠️ fehlt'; badgeEl.style.background = 'rgba(224,128,64,0.2)'; badgeEl.style.color = '#e08040';
      if (verifyBox) verifyBox.style.display = 'none';
    }} else if (d.email_verified) {{
      badgeEl.textContent = '✅ verifiziert'; badgeEl.style.background = 'rgba(76,175,80,0.2)'; badgeEl.style.color = '#4caf50';
      if (verifyBox) verifyBox.style.display = 'none';
    }} else {{
      badgeEl.textContent = '⚠️ unverifiziert';
      badgeEl.style.background = 'rgba(224,168,80,0.2)'; badgeEl.style.color = '#e0a850';
      badgeEl.style.cursor = 'pointer';
      badgeEl.title = 'Klick: Code per Mail anfordern';
      badgeEl.onclick = resendVerifyMail;
      // Code-Eingabe-Box einblenden
      if (verifyBox) verifyBox.style.display = 'block';
    }}
  }} catch (e) {{
    valEl.textContent = '(Netzwerkfehler)'; badgeEl.textContent = '';
    if (verifyBox) verifyBox.style.display = 'none';
  }}
}}
async function doVerifyCode() {{
  const codeEl = document.getElementById('verify-code-input');
  const msg = document.getElementById('verify-code-msg');
  const code = (codeEl?.value || '').trim();
  const email = window._currentEmail || '';
  if (!/^\\d{{6}}$/.test(code)) {{
    msg.innerHTML = '❌ 6 Ziffern eingeben'; msg.style.color = '#e55'; return;
  }}
  if (!email) {{
    msg.innerHTML = '❌ Keine Email bekannt'; msg.style.color = '#e55'; return;
  }}
  msg.innerHTML = '⏳ Prüfe…'; msg.style.color = '#887755';
  try {{
    const r = await fetch('/api/email/verify-code', {{
      method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{email:email, code:code}})
    }});
    const d = await r.json();
    if (d.ok) {{
      msg.innerHTML = '✅ ' + (d.message || 'Verifiziert!');
      msg.style.color = '#4caf50';
      codeEl.value = '';
      setTimeout(() => loadCurrentEmail(), 600);
    }} else {{
      msg.innerHTML = '❌ ' + (d.error || 'Fehler');
      msg.style.color = '#e55';
    }}
  }} catch (e) {{
    msg.innerHTML = '❌ Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function resendVerifyMail() {{
  const badgeEl = document.getElementById('current-email-badge');
  const msg = document.getElementById('email-change-msg');
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const origText = badgeEl.textContent;
  badgeEl.textContent = '⏳ sende…'; badgeEl.onclick = null; badgeEl.style.cursor = 'wait';
  try {{
    const r = await fetch('/api/email/send-verify', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:'{{}}'}});
    const d = await r.json();
    if (d.error) {{
      if (msg) {{ msg.textContent = '❌ ' + d.error; msg.style.color = '#e55'; }}
      badgeEl.textContent = origText; badgeEl.style.cursor = 'pointer'; badgeEl.onclick = resendVerifyMail;
    }} else {{
      if (msg) {{ msg.textContent = '✅ ' + (d.message || 'Mail gesendet!'); msg.style.color = '#4a4'; }}
      badgeEl.textContent = '📬 gesendet — Postfach prüfen';
      badgeEl.style.background = 'rgba(76,175,80,0.2)'; badgeEl.style.color = '#4caf50';
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55'; }}
    badgeEl.textContent = origText; badgeEl.style.cursor = 'pointer'; badgeEl.onclick = resendVerifyMail;
  }}
}}
async function doChangeEmail() {{
  const newEmail = document.getElementById('new-email')?.value?.trim()?.toLowerCase();
  const pw = document.getElementById('email-change-pw')?.value;
  const totp = document.getElementById('email-change-totp')?.value || '';
  const msg = document.getElementById('email-change-msg');
  if (!newEmail || !newEmail.includes('@') || !newEmail.includes('.')) {{ msg.textContent = 'Gültige Email eingeben!'; msg.style.color = '#e55'; return; }}
  if (!pw) {{ msg.textContent = 'Aktuelles Passwort eingeben!'; msg.style.color = '#e55'; return; }}
  if (!totp) {{ msg.textContent = '2FA Code nötig!'; msg.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const r = await fetch('/api/auth/email', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{new_email:newEmail, password:pw, totp_code:totp}})}});
  const d = await r.json();
  if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; }}
  else {{
    msg.textContent = '✅ ' + (d.message || 'Email geändert!'); msg.style.color = '#4a4';
    document.getElementById('new-email').value = '';
    document.getElementById('email-change-pw').value = '';
    document.getElementById('email-change-totp').value = '';
    await loadCurrentEmail();
    // Direkt Verify-Mail an neue Adresse senden (gleicher Flow wie Ersteinrichtung)
    await resendVerifyMail();
  }}
}}
async function doSeedRefresh() {{
  const pw = document.getElementById('seed-refresh-pw')?.value;
  const totp = document.getElementById('seed-refresh-totp')?.value?.trim();
  const msg = document.getElementById('seed-refresh-msg');
  const display = document.getElementById('seed-refresh-display');
  const valueEl = document.getElementById('seed-refresh-value');
  if (!pw) {{ msg.textContent = 'Passwort eingeben!'; msg.style.color = '#e55'; return; }}
  if (!/^\\d{{6}}$/.test(totp||'')) {{ msg.textContent = '6-stelligen 2FA-Code eingeben!'; msg.style.color = '#e55'; return; }}
  if (!confirm('Alter Seed wird SOFORT ungültig. Neuen Seed aufschreiben = PFLICHT! Wirklich erneuern?')) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ Generiere…'; msg.style.color = '#887755';
  try {{
    const r = await fetch('/api/auth/seed-refresh', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{password:pw, totp_code:totp}})}});
    const d = await r.json();
    if (d.ok && d.recovery_seed) {{
      document.getElementById('seed-refresh-pw').value = '';
      document.getElementById('seed-refresh-totp').value = '';
      valueEl.textContent = d.recovery_seed;
      display.style.display = 'block';
      msg.textContent = '✅ Neuer Seed generiert — UNBEDINGT aufschreiben!';
      msg.style.color = '#5ac88c';
    }} else {{
      msg.textContent = '❌ ' + (d.error || 'Fehler');
      msg.style.color = '#e55';
    }}
  }} catch (e) {{
    msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function do2faRefresh() {{
  const msg = document.getElementById('2fa-refresh-msg');
  msg.textContent = '📧 Sende Email...'; msg.style.color = '#e08040';
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const r = await fetch('/api/auth/2fa-refresh', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:'{{}}'}});
  const d = await r.json();
  if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; return; }}
  msg.textContent = d.message; msg.style.color = '#4a4';
  document.getElementById('2fa-refresh-confirm').style.display = 'block';
  // 2min Countdown
  let remaining = 120;
  const timer = document.getElementById('2fa-timer');
  const countdown = setInterval(() => {{
    remaining--;
    timer.textContent = `⏱️ ${{Math.floor(remaining/60)}}:${{String(remaining%60).padStart(2,'0')}}`;
    if (remaining <= 0) {{
      clearInterval(countdown);
      timer.textContent = '⏱️ Abgelaufen!';
      document.getElementById('2fa-refresh-confirm').style.display = 'none';
      msg.textContent = 'Zeit abgelaufen. Nochmal anfordern.'; msg.style.color = '#e55';
    }}
  }}, 1000);
}}
async function do2faConfirm() {{
  const code = document.getElementById('2fa-new-code')?.value?.trim();
  const msg = document.getElementById('2fa-refresh-msg');
  if (!code || code.length < 6) {{ msg.textContent = '6-stelligen Code eingeben!'; msg.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const r = await fetch('/api/auth/2fa-refresh-confirm', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{totp_code:code}})}});
  const d = await r.json();
  if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; }}
  else {{ msg.textContent = '✅ ' + d.message; msg.style.color = '#4a4'; document.getElementById('2fa-refresh-confirm').style.display = 'none'; }}
}}
async function doForgot() {{
  const email = document.getElementById('forgot-email')?.value?.trim()?.toLowerCase();
  const username = document.getElementById('forgot-username')?.value?.trim();
  const msg = document.getElementById('forgot-msg');
  if (!email || !username) {{ msg.textContent = 'Email UND Username eingeben!'; msg.style.color = '#e55'; return; }}
  msg.textContent = '⏳ Prüfe…'; msg.style.color = '#888';
  try {{
    const r = await fetch('/api/auth/forgot', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{email, username}})}});
    const d = await r.json();
    if (d.ok) {{
      msg.textContent = '✅ Weiter zur Seed-Phrase ↓';
      msg.style.color = '#4a4';
      // Seed-Input-Box einblenden, Username + Email fixieren
      const seedBox = document.getElementById('seed-unlock-box');
      if (seedBox) seedBox.style.display = 'block';
      // Username für den nächsten Request merken
      window._forgotUsername = username;
    }} else {{
      msg.textContent = d.message || d.error || 'Unbekannter Fehler';
      msg.style.color = '#e55';
    }}
  }} catch (e) {{
    msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function doPwResetSet() {{
  const pw = document.getElementById('reset-new-pw')?.value;
  const pw2 = document.getElementById('reset-new-pw2')?.value;
  const seed = document.getElementById('reset-owner-seed')?.value?.trim()?.toLowerCase();
  const msg = document.getElementById('reset-pw-msg');
  if (!pw || pw.length < 6) {{ msg.textContent = 'Min. 6 Zeichen!'; msg.style.color = '#e55'; return; }}
  if (pw !== pw2) {{ msg.textContent = 'Passwörter stimmen nicht überein!'; msg.style.color = '#e55'; return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  msg.textContent = '⏳ Setze Passwort…'; msg.style.color = '#888';
  const body = {{new_password:pw, confirm_password:pw2}};
  if (seed) body.seed_phrase = seed;
  try {{
    const r = await fetch('/api/auth/pw-reset-set', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify(body)}});
    const d = await r.json();
    if (d.ok) {{
      msg.innerHTML = '✅ ' + (d.message || 'Passwort gesetzt') + ' — lade neu…';
      msg.style.color = '#4a4';
      setTimeout(() => location.reload(), 1400);
    }} else {{
      msg.textContent = '❌ ' + (d.error || 'Fehler'); msg.style.color = '#e55';
    }}
  }} catch (e) {{
    msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
async function doSeedUnlock() {{
  const seed = document.getElementById('seed-input')?.value?.trim()?.toLowerCase();
  const username = window._forgotUsername || '';
  const msg = document.getElementById('seed-msg');
  if (!seed) {{ msg.textContent = 'Seed-Phrase eingeben!'; msg.style.color = '#e55'; return; }}
  if (!username) {{ msg.textContent = 'Username fehlt — bitte Formular oben erneut absenden.'; msg.style.color = '#e55'; return; }}
  msg.textContent = '⏳ Prüfe Seed…'; msg.style.color = '#888';
  try {{
    const r = await fetch('/api/auth/seed-unlock', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{username, seed_phrase:seed}})}});
    const d = await r.json();
    if (d.ok && d.session_token) {{
      document.cookie = 'nexus_session=' + d.session_token + '; path=/; SameSite=Strict; Secure';
      msg.innerHTML = '✅ Seed akzeptiert — leite zum Reset-Dashboard weiter…';
      msg.style.color = '#4a4';
      setTimeout(() => {{ location.href = '/'; }}, 1200);
    }} else {{
      msg.textContent = '❌ ' + (d.error || d.message || 'Fehler');
      msg.style.color = '#e55';
    }}
  }} catch (e) {{
    msg.textContent = 'Netzwerkfehler'; msg.style.color = '#e55';
  }}
}}
// Tab-Switch
function showTab(tab) {{
  const lb = document.getElementById('login-box');
  const rb = document.getElementById('register-box');
  const mb = document.getElementById('migrate-box');
  const tl = document.getElementById('tab-login');
  const tr = document.getElementById('tab-register');
  const tm = document.getElementById('tab-migrate');
  if (!lb || !rb) return;
  lb.style.display = 'none'; rb.style.display = 'none'; if(mb) mb.style.display = 'none';
  tl?.classList.remove('active'); tr?.classList.remove('active'); tm?.classList.remove('active');
  if (tab === 'register') {{
    rb.style.display = 'block'; tr?.classList.add('active');
  }} else if (tab === 'migrate') {{
    if(mb) mb.style.display = 'block'; tm?.classList.add('active');
  }} else {{
    lb.style.display = 'block'; tl?.classList.add('active');
  }}
}}

// Register Step 1
let _regUser = '';
async function doRegister() {{
  const el = document.getElementById.bind(document);
  const user = el('reg-username').value.trim();
  const email = el('reg-email').value.trim();
  const pw = el('reg-password').value;
  const pw2 = el('reg-password2').value;
  const err = el('reg-error');
  if (!user || !email || !pw) {{ err.textContent = 'Alle Felder ausfüllen!'; err.style.display = 'block'; return; }}
  if (pw !== pw2) {{ err.textContent = 'Passwörter stimmen nicht überein!'; err.style.display = 'block'; return; }}
  if (pw.length < 6) {{ err.textContent = 'Passwort mindestens 6 Zeichen!'; err.style.display = 'block'; return; }}
  const btn = el('reg-btn');
  btn.disabled = true; btn.textContent = '...';
  try {{
    const r = await fetch('/api/auth/register', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: user, email: email, password: pw}})
    }});
    const d = await r.json();
    if (d.step === '2fa_setup') {{
      _regUser = user;
      el('reg-step1').style.display = 'none';
      el('reg-step2').style.display = 'block';
      err.style.display = 'none';
      let qrHtml = d.totp_qr ? '<img src="' + d.totp_qr + '" style="width:200px;height:200px;margin:10px auto;display:block;border-radius:8px;" alt="QR Code">' : '';
      el('reg-totp-info').innerHTML =
        '<div class="seed-box"><h3>🔑 Recovery-Seed — JETZT aufschreiben!</h3><code style="color:#ffd700;font-size:13px;line-height:1.8;word-break:break-word;display:block;text-align:center;">' + d.recovery_seed + '</code></div>' +
        '<p class="dim" style="margin-top:15px;">QR-Code mit Authenticator-App scannen:</p>' +
        qrHtml +
        '<p class="dim" style="margin-top:5px;font-size:0.8em;">Oder manuell: <span style="color:#7ecfff;">' + d.totp_secret + '</span></p>' +
        '<p class="dim" style="margin-top:8px;">Shinpai-ID: <span style="color:#ffd700;">' + d.shinpai_id + '</span></p>';
      setTimeout(() => el('reg-totp').focus(), 100);
    }} else {{
      err.textContent = d.error || 'Registration fehlgeschlagen'; err.style.display = 'block';
      btn.disabled = false; btn.textContent = 'Registrieren';
    }}
  }} catch(e) {{
    err.textContent = 'Verbindungsfehler'; err.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Registrieren';
  }}
}}

// Register Step 2: TOTP bestätigen
async function doRegConfirm() {{
  const el = document.getElementById.bind(document);
  const code = el('reg-totp').value.trim();
  const err = el('reg-error');
  if (!code || code.length !== 6) {{ err.textContent = '6-stelligen Code eingeben!'; err.style.display = 'block'; return; }}
  try {{
    const r = await fetch('/api/auth/register', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: _regUser, totp_code: code}})
    }});
    const d = await r.json();
    if (d.step === 'done') {{
      el('reg-step2').style.display = 'none';
      el('reg-done').style.display = 'block';
      err.style.display = 'none';
    }} else {{
      err.textContent = d.error || '2FA-Bestätigung fehlgeschlagen'; err.style.display = 'block';
    }}
  }} catch(e) {{
    err.textContent = 'Verbindungsfehler'; err.style.display = 'block';
  }}
}}

// Account-Typ-Icon im Profil-Header (Kind/Bot leuchtet, Erwachsener unsichtbar)
const _BOT_SVG_48 = '<svg width="48" height="48" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style="filter:drop-shadow(0 0 10px rgba(212,168,80,0.5));"><line x1="32" y1="6" x2="32" y2="14" stroke="#d4a850" stroke-width="3"/><circle cx="32" cy="5" r="3" fill="#e8c464"/><rect x="14" y="16" width="36" height="30" rx="5" fill="rgba(212,168,80,0.08)" stroke="#d4a850" stroke-width="3"/><circle cx="24" cy="30" r="4" fill="#e8c464"/><circle cx="40" cy="30" r="4" fill="#e8c464"/><line x1="22" y1="38" x2="42" y2="38" stroke="#d4a850" stroke-width="2.5"/><line x1="20" y1="46" x2="20" y2="54" stroke="#d4a850" stroke-width="3"/><line x1="44" y1="46" x2="44" y2="54" stroke="#d4a850" stroke-width="3"/></svg>';
const _KIND_SVG_48 = '<svg width="48" height="48" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" style="filter:drop-shadow(0 0 10px rgba(212,168,80,0.5));"><path d="M 28 12 Q 32 4 36 12" fill="none" stroke="#d4a850" stroke-width="3"/><circle cx="32" cy="30" r="18" fill="rgba(212,168,80,0.08)" stroke="#d4a850" stroke-width="3"/><path d="M 22 28 Q 25 26 28 28" stroke="#d4a850" stroke-width="2.5" fill="none"/><path d="M 36 28 Q 39 26 42 28" stroke="#d4a850" stroke-width="2.5" fill="none"/><ellipse cx="32" cy="38" rx="4" ry="2.5" fill="rgba(232,196,100,0.3)" stroke="#e8c464" stroke-width="2"/><rect x="30" y="40" width="4" height="5" rx="1" fill="#e8c464"/><circle cx="32" cy="46" r="2.5" fill="rgba(212,168,80,0.2)" stroke="#d4a850" stroke-width="1.5"/><circle cx="22" cy="34" r="1.8" fill="#d4a850" fill-opacity="0.6"/><circle cx="42" cy="34" r="1.8" fill="#d4a850" fill-opacity="0.6"/></svg>';
window._accountTypeInfo = null;
async function loadAccountType() {{
  const box = document.getElementById('profile-type-icon');
  if (!box) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/account/type', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) {{ box.style.display='none'; return; }}
    window._accountTypeInfo = d;

    // PW-Reset-Banner (informativ, kein Zwang!)
    const banner = document.getElementById('pw-reset-banner');
    const daysLeftText = document.getElementById('pw-reset-days-left-text');
    const resetCard = document.getElementById('pw-reset-card');
    if (d.pw_reset_pending) {{
      if (banner) banner.style.display = 'block';
      if (daysLeftText && d.pw_reset_triggered_at) {{
        const maxDays = d.is_owner ? 30 : 7;
        const passed = (Date.now()/1000) - d.pw_reset_triggered_at;
        const remaining = Math.max(0, Math.ceil((maxDays*86400 - passed)/86400));
        if (d.is_owner) {{
          daysLeftText.textContent = 'Owner: ' + remaining + ' Tage bis Nexus-Schließung wenn nichts geändert wird.';
        }} else {{
          daysLeftText.textContent = remaining + ' Tage verbleibend — danach wird der Account gelöscht.';
        }}
      }}
      // Reset-Mode: NUR rote PW-Box, alles andere versteckt (erst PW, dann Rest)
      if (resetCard) resetCard.style.display = 'block';
      ['normal-pw-card','email-card','twofa-card','seed-refresh-card','migrate-card'].forEach(id => {{
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      }});
    }} else {{
      if (banner) banner.style.display = 'none';
      if (resetCard) resetCard.style.display = 'none';
      ['normal-pw-card','email-card','twofa-card','seed-refresh-card','migrate-card'].forEach(id => {{
        const el = document.getElementById(id);
        if (el) el.style.display = 'block';
      }});
    }}
    if (d.type === 'erwachsener') {{
      box.style.display = 'none';  // kein Icon für Erwachsene
      return;
    }}
    // Kind oder Bot → Icon anzeigen
    box.innerHTML = d.type === 'bot' ? _BOT_SVG_48 : _KIND_SVG_48;
    box.style.display = 'block';
    box.title = d.is_secondary
      ? ('Klick zum Wechseln — aktuell: ' + d.type)
      : (d.type === 'kind' ? 'Kind-Account (Perso fehlt oder keine KK)' : 'Bot-Account');
    box.style.cursor = d.is_secondary ? 'pointer' : 'default';
  }} catch (e) {{
    box.style.display = 'none';
  }}
}}
async function doAccountTypeSwitch() {{
  const info = window._accountTypeInfo;
  if (!info || !info.is_secondary) return;
  const currentType = info.type;
  const target = currentType === 'bot' ? 'kind' : 'bot';
  if (target === 'bot' && !info.can_switch_to_bot) {{
    alert('Für Bot-Status brauchst du eine eigene Kreditkarte (verified_stripe).');
    return;
  }}
  const pw = prompt('Wechsel zu ' + target.toUpperCase() + ' — Passwort eingeben:');
  if (!pw) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/account/type-switch', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify({{target_type:target, password:pw}})
    }});
    const d = await r.json();
    if (d.ok) {{
      if (d.message) alert(d.message);
      loadAccountType();
    }} else {{
      alert('Fehler: ' + (d.error || 'unbekannt'));
    }}
  }} catch (e) {{
    alert('Netzwerkfehler');
  }}
}}
async function doAccountDeleteSelf() {{
  if (!confirm('⚠️ Wirklich Account LÖSCHEN? Das ist UNWIDERRUFLICH!')) return;
  const pw = prompt('Passwort bestätigen:');
  if (!pw) return;
  const totp = prompt('2FA-Code (wenn aktiv):') || '';
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/account/delete-self', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify({{password:pw, totp_code:totp}})
    }});
    const d = await r.json();
    if (d.ok) {{
      alert('✅ Account gelöscht.');
      document.cookie = 'nexus_session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      location.href = '/?logout=1';
    }} else {{
      alert('Fehler: ' + (d.error || 'unbekannt'));
    }}
  }} catch (e) {{
    alert('Netzwerkfehler');
  }}
}}
async function loadOwnerMembers() {{
  const box = document.getElementById('owner-members-list');
  if (!box) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/owner/members', {{headers:{{'X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) {{ box.innerHTML = '<div style="color:#e55;font-size:11px;">' + d.error + '</div>'; return; }}
    if (!d.members || !d.members.length) {{
      box.innerHTML = '<div style="color:#665;font-size:11px;font-style:italic;text-align:center;padding:12px;">Keine Member registriert</div>';
      return;
    }}
    // Sortierung: 1. nicht verifiziert → 2. nur KK → 3. nur Perso → 4. KK+Perso → 5. Bots ganz unten
    const sorted = [...d.members].sort((a, b) => {{
      const rank = m => {{
        const isBot = (m.type || '').toLowerCase().includes('bot');
        if (isBot) return 5;
        if (m.has_perso && m.has_kk) return 4;
        if (m.has_perso) return 3;
        if (m.has_kk) return 2;
        return 1;
      }};
      return rank(a) - rank(b);
    }});
    const persoCount = d.members.filter(m => m.has_perso).length;
    const rows = sorted.map(m => {{
      const persoColor = m.has_perso ? '#4caf50' : (m.has_kk ? '#d4a850' : '#555');
      const persoLabel = m.has_perso ? 'Perso ✅' : (m.has_kk ? 'nur KK' : '—');
      const deleteBtn = m.perso_protected
        ? '<span title="Perso-geschützt" style="color:#555;cursor:not-allowed;padding:3px 8px;">🔒</span>'
        : `<button onclick="doOwnerMemberDelete('${{m.shinpai_id}}')" style="background:none;border:1px solid rgba(228,68,68,0.45);color:#e44;padding:3px 9px;border-radius:4px;cursor:pointer;font-size:11px;">✕</button>`;
      return `<div style="display:flex;align-items:center;gap:10px;padding:6px 8px;border-bottom:1px solid rgba(228,68,68,0.08);font-size:11px;">
        <code style="flex:1;color:#c9a;font-family:monospace;">${{m.shinpai_id}}</code>
        <span style="color:${{persoColor}};text-shadow:0 0 4px ${{persoColor}};font-size:10px;font-weight:bold;letter-spacing:0.5px;">●</span>
        <span style="color:#887;font-size:10px;min-width:60px;">${{persoLabel}}</span>
        <span style="color:#776;font-size:10px;min-width:70px;">${{m.type}}</span>
        ${{deleteBtn}}
      </div>`;
    }}).join('');
    box.innerHTML = `<div style="color:#e44;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;text-align:center;">${{d.count}} Member · <span style="color:#4caf50;">${{persoCount}} / 200 verifiziert</span></div>${{rows}}`;
  }} catch (e) {{
    box.innerHTML = '<div style="color:#e55;font-size:11px;">Netzwerkfehler</div>';
  }}
}}
async function doOwnerMemberDelete(sid) {{
  if (!confirm('Member ' + sid + ' wirklich löschen?')) return;
  const pw = prompt('Owner-Passwort:');
  if (!pw) return;
  const totp = prompt('2FA-Code (wenn aktiv):') || '';
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/owner/members/delete', {{
      method:'POST',
      headers:{{'Content-Type':'application/json','X-Session-Token':token}},
      body: JSON.stringify({{shinpai_id:sid, password:pw, totp_code:totp}})
    }});
    const d = await r.json();
    if (d.ok) {{ alert('✅ Member gelöscht'); loadOwnerMembers(); }}
    else {{ alert('Fehler: ' + (d.error || 'unbekannt')); }}
  }} catch (e) {{
    alert('Netzwerkfehler');
  }}
}}

// Dashboard-Load: Account-Typ-Icon initial anzeigen
(async function() {{
  if (document.getElementById('profile-type-icon')) {{
    loadAccountType();
  }}
}})();

// Service-Config Handler (SMTP/Stripe/Veriff) — GLOBAL (nicht in IIFE!) damit onclick immer greift
async function doSmtpSave() {{
  const host = document.getElementById('smtp-host')?.value?.trim();
  const port = document.getElementById('smtp-port')?.value?.trim() || '587';
  const user = document.getElementById('smtp-user')?.value?.trim();
  const pass = document.getElementById('smtp-pass')?.value;
  const from_ = document.getElementById('smtp-from')?.value?.trim() || user;
  const test = document.getElementById('smtp-test')?.value?.trim();
  const msg = document.getElementById('smtp-msg');
  if (!host || !user || !pass) {{ if (msg) {{ msg.textContent = 'Host, User und Passwort nötig!'; msg.style.color = '#e55'; }} return; }}
  const body = {{host, port:parseInt(port), user, password:pass, from:from_}};
  if (test) body.test_email = test;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/smtp/config', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify(body)}});
    const d = await r.json();
    if (msg) {{
      if (d.ok) {{ msg.textContent = '✅ ' + (d.message || 'Gespeichert!'); msg.style.color = '#4a4'; }}
      else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = '❌ Netzwerkfehler'; msg.style.color = '#e55'; }}
  }}
}}
async function doStripeSave() {{
  const sk = document.getElementById('stripe-sk')?.value?.trim();
  const pk = document.getElementById('stripe-pk')?.value?.trim();
  const msg = document.getElementById('stripe-msg');
  if (!sk) {{ if (msg) {{ msg.textContent = 'Secret Key nötig!'; msg.style.color = '#e55'; }} return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  if (msg) {{ msg.textContent = '⏳ Speichere…'; msg.style.color = '#888'; }}
  try {{
    const r = await fetch('/api/stripe/config', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{stripe_secret_key:sk, stripe_publishable_key:pk}})}});
    const d = await r.json();
    if (msg) {{
      if (d.ok) {{ msg.textContent = '✅ Stripe konfiguriert!'; msg.style.color = '#4a4'; setTimeout(() => location.reload(), 1500); }}
      else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
    }}
  }} catch (e) {{
    if (msg) {{ msg.textContent = '❌ Netzwerkfehler: ' + e.message; msg.style.color = '#e55'; }}
  }}
}}
async function doVeriffToggle(enabled) {{
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/veriff/toggle', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{enabled}})}});
    const d = await r.json();
    if (d.ok) {{
      const label = document.querySelector('#veriff-toggle')?.parentElement;
      if (label) {{
        const bg = label.querySelectorAll('span')[0];
        const dot = label.querySelectorAll('span')[1];
        if (bg) bg.style.background = enabled ? '#4caf50' : '#e44';
        if (dot) dot.style.left = enabled ? '16px' : '2px';
        label.title = enabled ? 'Veriff aktiv' : 'Veriff deaktiviert';
      }}
    }}
  }} catch (e) {{}}
}}
async function doVeriffSave() {{
  const key = document.getElementById('veriff-key')?.value?.trim();
  const secret = document.getElementById('veriff-secret')?.value?.trim();
  const priceRaw = document.getElementById('veriff-price')?.value;
  const msg = document.getElementById('veriff-msg');
  if (!key) {{ if (msg) {{ msg.textContent = 'API Key nötig!'; msg.style.color = '#e55'; }} return; }}
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  if (msg) {{ msg.textContent = '⏳ Speichere…'; msg.style.color = '#888'; }}
  try {{
    const r = await fetch('/api/veriff/config', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{veriff_api_key:key, veriff_shared_secret:secret}})}});
    const d = await r.json();
    if (!d.ok) {{ if (msg) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }} return; }}
    if (priceRaw) {{
      const pr = await fetch('/api/veriff/price', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{price_eur:parseFloat(priceRaw)}})}});
      const pd = await pr.json();
      if (!pd.ok) {{ if (msg) {{ msg.textContent = pd.error || 'Preis-Fehler'; msg.style.color = '#e55'; }} return; }}
    }}
    if (msg) {{ msg.textContent = '✅ Veriff konfiguriert!'; msg.style.color = '#4a4'; }}
    if (typeof loadServerStatus === 'function') loadServerStatus();
  }} catch (e) {{
    if (msg) {{ msg.textContent = '❌ Netzwerkfehler: ' + e.message; msg.style.color = '#e55'; }}
  }}
}}

// Login-Seite: Bot-Politik-Anzeige initial füllen (öffentlicher Endpoint)
(async function() {{
  const q = document.getElementById('login-bot-quota');
  const l = document.getElementById('login-bot-label');
  if (!q) return;  // nicht auf Login-Seite
  try {{
    const r = await fetch('/api/public/bot-policy');
    const d = await r.json();
    if (d.quota !== undefined) {{
      // Nur die Zahl neben dem SVG-Icon — kein Emoji-Duplikat
      q.textContent = String(d.quota);
      if (l) {{
        l.textContent = d.label || '\u00a0';
      }}
    }}
  }} catch (e) {{}}
}})();

// Enter-Keys
document.addEventListener('keydown', e => {{
  if (e.key === 'Enter') {{
    const regStep2 = document.getElementById('reg-step2');
    const regStep1 = document.getElementById('reg-step1');
    const loginStep2fa = document.getElementById('login-step2fa');
    if (regStep2?.style.display !== 'none') doRegConfirm();
    else if (regStep1?.style.display !== 'none' && document.getElementById('register-box')?.style.display !== 'none') doRegister();
    else if (loginStep2fa?.style.display !== 'none') doLogin2FA();
    else if (document.getElementById('login-step1')) doLogin();
  }}
}});

// URL-Parameter Check: ?reset=TOKEN → Reset-Formular zeigen
(function() {{
  const params = new URLSearchParams(window.location.search);
  const resetToken = params.get('reset');
  if (resetToken) {{
    // Login/Register/Dashboard verstecken, Reset-Form zeigen
    // Alles verstecken
    document.querySelectorAll('#dashboard, #login-box, #register-box, #auth-tabs, .shield').forEach(el => {{
      if (el) el.style.display = 'none';
    }});

    const resetDiv = document.createElement('div');
    resetDiv.style.cssText = 'max-width:320px;margin:40px auto;text-align:center;';
    resetDiv.innerHTML = `
      <div style="font-size:36px;">🔑</div>
      <h2 style="color:#7ab8e0;">Neues Passwort setzen</h2>
      <input type="password" id="reset-pw" placeholder="Neues Passwort" style="width:100%;padding:12px;margin:6px 0;background:#111;border:1px solid #333;border-radius:6px;color:#e0d8c8;font-size:14px;">
      <input type="password" id="reset-pw2" placeholder="Wiederholen" style="width:100%;padding:12px;margin:6px 0;background:#111;border:1px solid #333;border-radius:6px;color:#e0d8c8;font-size:14px;">
      <label style="display:flex;align-items:center;gap:8px;margin:10px 0;font-size:12px;color:#e08040;cursor:pointer;">
        <input type="checkbox" id="reset-2fa" style="cursor:pointer;">
        🔐 2FA auch zurücksetzen (Authenticator verloren?)
      </label>
      <button onclick="doReset()" class="btn" style="width:100%;margin-top:8px;">Zurücksetzen</button>
      <div id="reset-msg" style="font-size:12px;margin-top:8px;"></div>
    `;
    document.body.appendChild(resetDiv);

    window.doReset = async function() {{
      const pw = document.getElementById('reset-pw').value;
      const pw2 = document.getElementById('reset-pw2').value;
      const msg = document.getElementById('reset-msg');
      if (!pw || pw.length < 6) {{ msg.textContent = 'Min. 6 Zeichen!'; msg.style.color = '#e55'; return; }}
      if (pw !== pw2) {{ msg.textContent = 'Stimmen nicht überein!'; msg.style.color = '#e55'; return; }}
      const reset2fa = document.getElementById('reset-2fa')?.checked || false;
      const r = await fetch('/api/auth/reset-password', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{token:resetToken, password:pw, reset_2fa:reset2fa}})}});
      const d = await r.json();
      if (d.ok) {{
        msg.textContent = '✅ ' + d.message;
        msg.style.color = '#4a4';
        setTimeout(() => {{ window.location.href = '/'; }}, 2000);
      }} else {{
        msg.textContent = d.error || 'Fehler';
        msg.style.color = '#e55';
      }}
    }};
  }}

  // ── SMTP CONFIG ──
  window.doSmtpSave = async function() {{
    const host = document.getElementById('smtp-host')?.value?.trim();
    const port = document.getElementById('smtp-port')?.value?.trim() || '587';
    const user = document.getElementById('smtp-user')?.value?.trim();
    const pass = document.getElementById('smtp-pass')?.value;
    const from_ = document.getElementById('smtp-from')?.value?.trim() || user;
    const test = document.getElementById('smtp-test')?.value?.trim();
    const msg = document.getElementById('smtp-msg');
    if (!host || !user || !pass) {{ msg.textContent = 'Host, User und Passwort nötig!'; msg.style.color = '#e55'; return; }}
    const body = {{host, port:parseInt(port), user, password:pass, from:from_}};
    if (test) body.test_email = test;
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/smtp/config', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify(body)}});
    const d = await r.json();
    if (d.ok) {{ msg.textContent = '✅ ' + (d.message || 'Gespeichert!'); msg.style.color = '#4a4'; }}
    else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};

  window.doStripeSave = async function() {{
    const sk = document.getElementById('stripe-sk')?.value?.trim();
    const pk = document.getElementById('stripe-pk')?.value?.trim();
    const msg = document.getElementById('stripe-msg');
    if (!sk) {{ msg.textContent = 'Secret Key nötig!'; msg.style.color = '#e55'; return; }}
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/stripe/config', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{stripe_secret_key:sk, stripe_publishable_key:pk}})}});
    const d = await r.json();
    if (d.ok) {{ msg.textContent = '✅ Stripe konfiguriert!'; msg.style.color = '#4a4'; setTimeout(() => location.reload(), 1500); }}
    else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};

  // Crop-System (wie Kneipe)
  let _cropImg = null, _cropOffX = 0, _cropOffY = 0, _cropScale = 1, _cropDrag = false, _cropStartX = 0, _cropStartY = 0;
  window.openCrop = function(input) {{
    const file = input.files?.[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {{
      _cropImg = new Image();
      _cropImg.onload = function() {{
        const cw = 150, ch = 150;
        _cropScale = Math.max(cw / _cropImg.width, ch / _cropImg.height) * 1.2;
        _cropOffX = (cw - _cropImg.width * _cropScale) / 2;
        _cropOffY = (ch - _cropImg.height * _cropScale) / 2;
        document.getElementById('crop-area').style.display = 'block';
        drawCrop();
      }};
      _cropImg.src = e.target.result;
    }};
    reader.readAsDataURL(file);
  }};
  function drawCrop() {{
    const cvs = document.getElementById('crop-canvas'); if (!cvs || !_cropImg) return;
    const ctx = cvs.getContext('2d');
    ctx.clearRect(0, 0, 150, 150);
    ctx.drawImage(_cropImg, _cropOffX, _cropOffY, _cropImg.width * _cropScale, _cropImg.height * _cropScale);
  }}
  const _cc = document.getElementById('crop-canvas');
  if (_cc) {{
    _cc.addEventListener('mousedown', function(e) {{ _cropDrag = true; _cropStartX = e.clientX - _cropOffX; _cropStartY = e.clientY - _cropOffY; }});
    _cc.addEventListener('mousemove', function(e) {{ if (!_cropDrag) return; _cropOffX = e.clientX - _cropStartX; _cropOffY = e.clientY - _cropStartY; drawCrop(); }});
    _cc.addEventListener('mouseup', function() {{ _cropDrag = false; }});
    _cc.addEventListener('mouseleave', function() {{ _cropDrag = false; }});
    _cc.addEventListener('touchstart', function(e) {{ e.preventDefault(); const t = e.touches[0]; _cropDrag = true; _cropStartX = t.clientX - _cropOffX; _cropStartY = t.clientY - _cropOffY; }});
    _cc.addEventListener('touchmove', function(e) {{ e.preventDefault(); if (!_cropDrag) return; const t = e.touches[0]; _cropOffX = t.clientX - _cropStartX; _cropOffY = t.clientY - _cropStartY; drawCrop(); }});
    _cc.addEventListener('touchend', function() {{ _cropDrag = false; }});
    _cc.addEventListener('wheel', function(e) {{ e.preventDefault(); const d = e.deltaY > 0 ? 0.95 : 1.05; const old = _cropScale; _cropScale = Math.max(0.1, Math.min(5, _cropScale * d)); _cropOffX = 75 - (75 - _cropOffX) * (_cropScale / old); _cropOffY = 75 - (75 - _cropOffY) * (_cropScale / old); drawCrop(); }});
  }}

  function getCroppedB64() {{
    const cvs = document.getElementById('crop-canvas'); if (!cvs) return '';
    const r = document.createElement('canvas'); r.width = 128; r.height = 128;
    r.getContext('2d').drawImage(cvs, 0, 0, 150, 150, 0, 0, 128, 128);
    return r.toDataURL('image/jpeg', 0.7);
  }}

  window.doLicenseSave = async function() {{
    const company = document.getElementById('license-company')?.value?.trim();
    const verifier = document.getElementById('license-verifier')?.value?.trim();
    const glow = document.getElementById('license-glow')?.value;
    const msg = document.getElementById('license-msg');
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    // Logo: bevorzugt frisch gecropt, fallback aus aktueller Box
    let logo = '';
    if (_cropImg) {{
      logo = getCroppedB64();
    }} else {{
      const img = document.querySelector('#license-logo-box img');
      if (img && img.src.startsWith('data:')) logo = img.src;
    }}
    const r = await fetch('/api/license/save', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{company:company, verifier_url:verifier, glow_color:glow, logo:logo}})}});
    const d = await r.json();
    if (d.ok) {{ msg.textContent = '🦋 Lizenz gespeichert!'; msg.style.color = '#d4a850'; setTimeout(() => location.reload(), 1500); }}
    else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};

  window.doOwnerMigrateStart = async function() {{
    if (!confirm('⚠️ WARNUNG: Owner-Migration startet einen 30-Tage-Countdown!\\n\\nAlle User werden per Email benachrichtigt.\\nNach 30 Tagen wird ein Migrations-Token generiert (1h gültig).\\n\\nFortfahren?')) return;
    const msg = document.getElementById('migrate-msg');
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    const r = await fetch('/api/migrate/owner-start', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}}});
    const d = await r.json();
    if (d.ok) {{ msg.textContent = '⏰ 30-Tage-Countdown gestartet! User werden benachrichtigt.'; msg.style.color = '#d4a850'; }}
    else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};

  window.doMigrateExport = async function() {{
    const msg = document.getElementById('migrate-msg');
    const reject = document.getElementById('migrate-target-reject');
    const target = (document.getElementById('migrate-target-url')?.value || '').trim();
    if (reject) reject.style.display = 'none';
    if (!target) {{
      if (msg) {{ msg.textContent = 'Ziel-Nexus URL eintragen!'; msg.style.color = '#e55'; }}
      return;
    }}
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    if (msg) {{ msg.textContent = '⏳ Prüfe Ziel gegen Whitelist...'; msg.style.color = '#888'; }}
    const r = await fetch('/api/migrate/export', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{target_url:target}})}});
    const d = await r.json();
    if (d.migration_string) {{
      document.getElementById('migrate-token').style.display = 'block';
      const el = document.getElementById('migrate-token-value');
      el.textContent = d.migration_string;
      el.style.wordBreak = 'break-all';
      el.style.userSelect = 'all';
      msg.innerHTML = '✅ Ziel vertrauenswürdig · Migrations-String erzeugt (1 h gültig). Kopier ihn auf <b>' + target + '</b>:<br><span style="font-size:10px;color:#998;">Quelle: ' + (d.source_url || '?') + '</span>';
      msg.style.color = '#4a4';
    }} else if (d.whitelist_reject && reject) {{
      const hash = (d.remote_hash || '').slice(0,16);
      const tx = (d.remote_txid || '').slice(0,16);
      const comp = d.remote_company ? (' ("' + d.remote_company + '")') : '';
      const pasteStr = 'ShinNexus v' + (d.remote_version || '?') + ' · ' + (d.remote_hash || '') + (d.remote_txid ? (' · ' + d.remote_txid) : '');
      reject.innerHTML = '❌ <b>Ziel nicht in deiner Whitelist</b>' + comp + '<br>' +
        'Version: ' + (d.remote_version || '?') + '<br>' +
        'Hash: ' + hash + '…<br>' +
        (tx ? ('TXID: ' + tx + '…<br>') : '<span style="color:#e8c464;">⚠️ Ziel nicht on-chain verankert</span><br>') +
        (_isOwner ? '<button onclick="addRemoteToWhitelist(' + JSON.stringify(pasteStr).replace(/"/g,'&quot;') + ')" style="margin-top:6px;font-size:11px;padding:5px 10px;background:rgba(90,200,140,0.15);border:1px solid rgba(90,200,140,0.45);color:#5ac88c;border-radius:4px;cursor:pointer;">🦋 Zur Whitelist hinzufügen</button>' : '<span style="color:#887755;font-size:10px;">Bitte den Owner kontaktieren um dieses Ziel freizuschalten.</span>');
      reject.style.display = 'block';
      msg.textContent = 'Migration abgelehnt — Ziel zuerst verifizieren.';
      msg.style.color = '#e55';
    }} else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};
  window.addRemoteToWhitelist = function(pasteStr) {{
    // Hopp in den Whitelist-Tab, vorfüllen, fokussieren — der Owner tippt nur noch das Label
    if (typeof showDashTab === 'function') {{ showDashTab('whitelist'); }}
    const box = document.getElementById('wl-paste');
    if (box) {{
      box.value = pasteStr;
      if (typeof doWhitelistParsePreview === 'function') doWhitelistParsePreview();
      box.focus();
    }}
  }};

  window.doPublicMigrate = async function() {{
    const mstr = document.getElementById('migrate-token-input')?.value?.trim();
    const msg = document.getElementById('migrate-pub-msg');
    if (!mstr) {{ msg.textContent = 'Migrations-String einfügen!'; msg.style.color = '#e55'; return; }}
    msg.textContent = '⏳ Hole Daten vom Quell-Nexus…'; msg.style.color = '#888';
    const r = await fetch('/api/migrate/import', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{migration_string:mstr}})}});
    const d = await r.json();
    if (d.ok) {{ msg.innerHTML = '✅ Migriert: <b>' + d.migrated + '</b> — Login jetzt mit deinem bestehenden Passwort.'; msg.style.color = '#4a4'; }}
    else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};

  window.doMigrateImport = async function() {{
    const mstr = document.getElementById('migrate-import-token')?.value?.trim();
    const msg = document.getElementById('migrate-msg');
    if (!mstr) {{ msg.textContent = 'Migrations-String einfügen!'; msg.style.color = '#e55'; return; }}
    msg.textContent = '⏳ Hole Daten vom Quell-Nexus…'; msg.style.color = '#888';
    const r = await fetch('/api/migrate/import', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{migration_string:mstr}})}});
    const d = await r.json();
    if (d.ok) {{ msg.innerHTML = '✅ Migriert: <b>' + d.migrated + '</b> — jetzt einloggen mit bestehendem Passwort.'; msg.style.color = '#4a4'; }}
    else {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; }}
  }};

  window.doVeriffSave = async function() {{
    const key = document.getElementById('veriff-key')?.value?.trim();
    const secret = document.getElementById('veriff-secret')?.value?.trim();
    const priceRaw = document.getElementById('veriff-price')?.value;
    const msg = document.getElementById('veriff-msg');
    if (!key) {{ msg.textContent = 'API Key nötig!'; msg.style.color = '#e55'; return; }}
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    // 1. API-Keys speichern
    const r = await fetch('/api/veriff/config', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{veriff_api_key:key, veriff_shared_secret:secret}})}});
    const d = await r.json();
    if (!d.ok) {{ msg.textContent = d.error || 'Fehler'; msg.style.color = '#e55'; return; }}
    // 2. Preis speichern (wenn eingetragen)
    if (priceRaw) {{
      const pr = await fetch('/api/veriff/price', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}, body:JSON.stringify({{price_eur:parseFloat(priceRaw)}})}});
      const pd = await pr.json();
      if (!pd.ok) {{ msg.textContent = pd.error || 'Preis-Fehler'; msg.style.color = '#e55'; return; }}
    }}
    msg.textContent = '✅ Veriff konfiguriert!';
    msg.style.color = '#4a4';
    loadServerStatus();
  }};

  // ── CLAIM OWNERSHIP ──
  let claimData = {{}};
  window.doClaim = async function() {{
    const name = document.getElementById('claim-name')?.value?.trim();
    const email = document.getElementById('claim-email')?.value?.trim();
    const pw = document.getElementById('claim-pw')?.value;
    const pw2 = document.getElementById('claim-pw2')?.value;
    const msg = document.getElementById('claim-msg');
    if (!name || name.length < 3) {{ msg.textContent = 'Username: min 3 Zeichen!'; msg.style.color = '#e55'; return; }}
    if (!email) {{ msg.textContent = 'Email nötig!'; msg.style.color = '#e55'; return; }}
    if (!pw || pw.length < 6) {{ msg.textContent = 'Passwort: min 6 Zeichen!'; msg.style.color = '#e55'; return; }}
    if (pw !== pw2) {{ msg.textContent = 'Passwörter stimmen nicht überein!'; msg.style.color = '#e55'; return; }}
    msg.textContent = '⏳ Erstelle Owner...'; msg.style.color = '#7ab8e0';
    const r = await fetch('/api/auth/register', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{username:name, email:email, password:pw}})}});
    const d = await r.json();
    if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; return; }}
    if (d.step === '2fa_setup') {{
      claimData = {{name, email, pw}};
      document.getElementById('claim-step1').style.display = 'none';
      document.getElementById('claim-step2').style.display = 'block';
      if (d.totp_qr) document.getElementById('claim-qr').innerHTML = '<img src="' + d.totp_qr + '" style="width:280px;max-width:100%;background:#fff;padding:12px;border-radius:12px;box-shadow:0 4px 20px rgba(126,207,255,0.15);">';
      if (d.totp_secret) document.getElementById('claim-secret').innerHTML = '<span style="color:#7ecfff;font-weight:bold;">Secret:</span> <code style="color:#ffd700;font-size:12px;letter-spacing:1px;">' + d.totp_secret + '</code>';
      if (d.recovery_seed) {{
        document.getElementById('claim-seed').style.display = 'block';
        document.getElementById('claim-seed-words').textContent = d.recovery_seed;
      }}
    }} else if (d.step === 'done') {{
      msg.textContent = '✅ Owner erstellt!'; msg.style.color = '#4a4';
      setTimeout(() => location.reload(), 2000);
    }}
  }};
  window.doClaimConfirm = async function() {{
    const code = document.getElementById('claim-totp')?.value?.trim();
    const msg = document.getElementById('claim-msg2');
    if (!code || code.length < 6) {{ msg.textContent = '6-stelligen Code eingeben!'; msg.style.color = '#e55'; return; }}
    const r = await fetch('/api/auth/register', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{username:claimData.name, totp_code:code}})}});
    const d = await r.json();
    if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; return; }}
    if (d.step === 'done') {{
      msg.textContent = '✅ Owner erstellt + 2FA aktiv!'; msg.style.color = '#4a4';
      if (d.session_token) document.cookie = 'nexus_session=' + d.session_token + '; path=/; SameSite=Strict; Secure';
      setTimeout(() => location.reload(), 2000);
    }}
  }};

  window.doClaimMigrate = async function() {{
    const mstr = (document.getElementById('claim-mig-token')?.value || '').trim();
    const pw = document.getElementById('claim-mig-pw')?.value || '';
    const totp = (document.getElementById('claim-mig-totp')?.value || '').trim();
    const msg = document.getElementById('claim-mig-msg');
    if (!mstr) {{ msg.textContent = 'Migrations-Token einfügen!'; msg.style.color = '#e55'; return; }}
    if (!pw) {{ msg.textContent = 'Passwort eingeben!'; msg.style.color = '#e55'; return; }}
    if (!totp || totp.length < 6) {{ msg.textContent = '6-stelligen 2FA-Code eingeben!'; msg.style.color = '#e55'; return; }}
    msg.textContent = '⏳ Migriere als Owner…'; msg.style.color = '#aa78ff';
    try {{
      const r = await fetch('/api/migrate/import', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{migration_string:mstr, owner_password:pw, owner_totp:totp}})}});
      const d = await r.json();
      if (d.ok) {{
        msg.innerHTML = '✅ Migriert als Owner! <b>' + (d.migrated || '') + '</b>';
        msg.style.color = '#4a4';
        setTimeout(() => location.reload(), 2000);
      }} else {{
        msg.textContent = d.error || 'Fehler';
        msg.style.color = '#e55';
      }}
    }} catch (e) {{
      msg.textContent = 'Netzwerkfehler';
      msg.style.color = '#e55';
    }}
  }};

  // ?verified=1 → URL aufräumen
  if (params.get('verified')) {{
    window.history.replaceState({{}}, '', '/');
  }}

  // Titel-Register beim Start laden
  loadTitles();

  // ── Verification UI ──────────────────────────────────────────
  const verifyStatus = document.getElementById('verify-status');
  const verifyBtn = document.getElementById('verify-btn');
  const ausweisBtn = document.getElementById('ausweis-btn');
  if (verifyStatus || document.getElementById('profile-shield-img')) {{
    const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
    fetch('/api/verify/status', {{headers: {{'X-Session-Token': token}}}})
      .then(r => r.json())
      .then(d => {{
        // effective_level berücksichtigt card_pending_replacement (während Austausch = 0)
        const lvl = (typeof d.effective_level !== 'undefined') ? d.effective_level : (d.verification_level || 0);
        const labels = ['❌ Nicht verifiziert', '✅ Stufe 1 (Kreditkarte)', '✅ Stufe 2 (Perso)', '✅ Stufe 3 (Amtlich)'];
        if (verifyStatus) verifyStatus.innerHTML = '🛡️ ' + (labels[lvl] || labels[0]);
        // Profil-Schild aktualisieren (Farbe + Status-Text)
        const shieldImg = document.getElementById('profile-shield-img');
        const shieldLabel = document.getElementById('profile-shield-label');
        const profVerified = document.getElementById('profile-verified');
        if (shieldImg) {{
          const basisOk = shieldImg.dataset.basisOk === '1';
          if (lvl >= 3) {{
            // Stufe 3: Amt-bestätigt — edler Schild mit dynamischem 25-Slot-Glow
            shieldImg.src = '/ShinNexus-Shield-edel.png?v=4';
            shieldImg.style.animation = '';
            if (shieldLabel) {{ shieldLabel.style.color = '#d4a850'; shieldLabel.textContent = 'Amtlich bestätigt'; }}
            // 25-Slot Shield-Glow: Farbe pro Subklasse, schwarz wenn nicht bestätigt
            const _glowSlots = [
              ['identity','birth_certificate','#ff9090'],['identity','personal_id','#ff6060'],
              ['identity','passport','#ee4040'],['identity','registration_certificate','#c82828'],
              ['identity','residence_permit','#8e1818'],
              ['finance','creditworthiness','#ffe488'],['finance','tax_certificate','#f5c858'],
              ['finance','income_proof','#d4a850'],['finance','payment_capability','#a6822c'],
              ['finance','wealth_proof','#6e5410'],
              ['health','vaccination_record','#88e896'],['health','medical_certificate','#5bc870'],
              ['health','lab_result','#4caf50'],['health','psychological_assessment','#358a3a'],
              ['health','disability_certificate','#1b5e20'],
              ['authority','drivers_license','#9ed4f0'],['authority','professional_license','#7ab8e0'],
              ['authority','craftsman_register','#5a9ed0'],['authority','weapons_license','#3a7cbf'],
              ['authority','pilot_license','#1a5a9f'],
              ['affiliation','club_membership','#d0a0ff'],['affiliation','religious_affiliation','#b082ff'],
              ['affiliation','union_membership','#aa78ff'],['affiliation','party_membership','#7e4ad0'],
              ['affiliation','nationality','#4e1c88'],
            ];
            const _activeSubs = new Set(d.active_subclasses || []);
            const _glowColors = _glowSlots.map(s => _activeSubs.has(s[0]+'/'+s[1]) ? s[2] : '#000000');
            let _glowIdx = 0;
            if (window._shieldGlowTimer) clearInterval(window._shieldGlowTimer);
            window._shieldGlowTimer = setInterval(() => {{
              const c = _glowColors[_glowIdx % 25];
              const c2 = _glowColors[(_glowIdx+1) % 25];
              shieldImg.style.filter = 'drop-shadow(0 0 18px '+c+') drop-shadow(0 0 10px '+c2+') drop-shadow(0 0 28px '+c+')';
              _glowIdx = (_glowIdx + 1) % 25;
            }}, 320);
          }} else if (lvl >= 2) {{
            shieldImg.src = '/ShinNexus-Shield.png';
            shieldImg.style.filter = 'drop-shadow(0 0 12px #d4a850) drop-shadow(0 0 6px #d4a850)';
            shieldImg.style.animation = '';
            if (shieldLabel) {{ shieldLabel.style.color = '#d4a850'; shieldLabel.textContent = 'Identität bestätigt'; }}
          }} else if (lvl >= 1) {{
            shieldImg.src = '/ShinNexus-Shield.png';
            shieldImg.style.filter = 'drop-shadow(0 0 12px #e44) drop-shadow(0 0 6px #e44)';
            shieldImg.style.animation = '';
            if (shieldLabel) {{ shieldLabel.style.color = '#e44'; shieldLabel.textContent = '18+'; }}
          }} else if (basisOk) {{
            shieldImg.src = '/ShinNexus-Shield.png';
            shieldImg.style.filter = 'drop-shadow(0 0 12px #fff) drop-shadow(0 0 6px #fff)';
            shieldImg.style.animation = '';
            if (shieldLabel) {{ shieldLabel.style.color = '#4caf50'; shieldLabel.textContent = 'Verbunden'; }}
          }} else {{
            shieldImg.src = '/ShinNexus-Shield.png';
            shieldImg.style.filter = 'grayscale(100%)';
            shieldImg.style.animation = '';
            if (shieldLabel) {{ shieldLabel.style.color = '#665540'; shieldLabel.textContent = 'ShinNexus'; }}
          }}
        }}
        if (lvl > 0 && ausweisBtn) ausweisBtn.style.display = 'inline-block';
        const resetBtn = document.getElementById('verify-reset-btn');
        if (lvl > 0 && resetBtn) resetBtn.style.display = 'inline-block';
        // Karten-Info anzeigen wenn vorhanden (live von Stripe)
        const cardBox = document.getElementById('verify-card-info');
        if (cardBox && d.card && d.card.brand) {{
          const brand = d.card.brand.charAt(0).toUpperCase() + d.card.brand.slice(1);
          const exp = String(d.card.exp_month).padStart(2,'0') + '/' + String(d.card.exp_year).slice(-2);
          cardBox.innerHTML = '✅ <b>' + brand + '</b> •••• ' + d.card.last4 + ' &nbsp;<span style="color:#665540;">läuft ' + exp + '</span>';
          cardBox.style.display = 'block';
        }}
        // Karten-Info oben, IMMER sichtbar wenn Karte hinterlegt (unabhängig von Progressive Disclosure)
        const cardTop = document.getElementById('verify-card-top');
        if (cardTop && d.card && d.card.brand) {{
          const brandTop = d.card.brand.charAt(0).toUpperCase() + d.card.brand.slice(1);
          const expTop = String(d.card.exp_month).padStart(2,'0') + '/' + String(d.card.exp_year).slice(-2);
          cardTop.innerHTML = '💳 Hinterlegt: <b style="color:#7ab8e0;">' + brandTop + '</b> •••• ' + d.card.last4 + ' &nbsp;·&nbsp; <span style="color:#887755;">läuft ' + expTop + '</span> &nbsp;·&nbsp; <span style="color:#d4a850;text-decoration:underline;">Karte tauschen</span>';
          cardTop.style.display = 'block';
        }} else if (cardTop) {{
          cardTop.style.display = 'none';
        }}
        // Flag-basiert statt Level-basiert — Stripe und Veriff sind UNABHÄNGIG (Kinder brauchen Perso ohne KK)
        const hasKK = !!d.verified_stripe;
        const hasPerso = !!d.id_verified;
        const veriffRow = document.getElementById('verify-veriff-row');
        const veriffStartBtn = document.getElementById('veriff-start-btn');
        const stripeRow = document.getElementById('verify-stripe-row');
        const amtRow = document.getElementById('verify-amt-row');
        const amtStatus = document.getElementById('verify-amt-status');
        const persoInfo = document.getElementById('verify-perso-info');
        const persoTop = document.getElementById('verify-perso-top');

        // Stripe-Row: sichtbar wenn KK noch NICHT hinterlegt (sonst läuft alles über verify-card-top oben)
        const stripeAvail = (d.available_providers || []).find(p => p.name === 'stripe');
        if (stripeRow) stripeRow.style.display = hasKK ? 'none' : 'block';
        if (verifyBtn) {{
          if (hasKK) {{
            verifyBtn.style.display = 'none';
          }} else if (stripeAvail && stripeAvail.available) {{
            verifyBtn.style.display = 'inline-block';
            verifyBtn.disabled = false;
            verifyBtn.textContent = '🔐 Jetzt verifizieren';
          }} else {{
            verifyBtn.style.display = 'inline-block';
            verifyBtn.disabled = true;
            verifyBtn.textContent = '⚠️ Stripe nicht konfiguriert';
          }}
        }}

        // Veriff-Row: sichtbar wenn Perso NICHT hinterlegt (sonst läuft alles über verify-perso-top oben)
        const veriffAvail = (d.available_providers || []).find(p => p.name === 'veriff');
        if (veriffRow) veriffRow.style.display = hasPerso ? 'none' : 'block';
        if (veriffStartBtn) {{
          if (!veriffAvail || !veriffAvail.available) {{
            veriffStartBtn.disabled = true;
            veriffStartBtn.textContent = '⚠️ Veriff nicht konfiguriert';
          }} else if (hasPerso) {{
            veriffStartBtn.style.display = 'none';
          }} else {{
            veriffStartBtn.style.display = 'inline-block';
            veriffStartBtn.disabled = false;
            veriffStartBtn.textContent = '🪪 Identität verifizieren';
          }}
        }}
        // Perso-Info oben (analog verify-card-top)
        if (persoTop) {{
          if (hasPerso) {{
            const dt = d.perso_verified_at ? new Date(d.perso_verified_at * 1000).toLocaleDateString('de-DE') : '';
            persoTop.innerHTML = '🪪 Perso verifiziert: <b style="color:#5ac88c;">✅</b> &nbsp;·&nbsp; <span style="color:#887755;">seit ' + dt + '</span> &nbsp;·&nbsp; <span style="color:#d4a850;text-decoration:underline;">Perso tauschen</span>';
            persoTop.style.display = 'block';
          }} else {{
            persoTop.style.display = 'none';
          }}
        }}
        // Amt-Row: sichtbar ab Perso (Stufe 2 erreicht)
        if (amtRow) {{
          if (hasPerso) {{
            amtRow.style.display = 'block';
            amtRow.style.opacity = '1';
            if (amtStatus) {{ amtStatus.textContent = lvl >= 3 ? 'aktiv' : 'verfügbar'; amtStatus.style.color = lvl >= 3 ? '#4caf50' : '#d4a850'; }}
          }} else {{
            amtRow.style.display = 'none';
          }}
        }}
        // Ämter-Tab-Button: nur ab Stufe 2 sichtbar
        const amtTabBtn = document.getElementById('dtab-amt');
        if (amtTabBtn) amtTabBtn.style.display = lvl >= 2 ? 'inline-block' : 'none';
        // Server-Tab Amt-Listen-Box: nur ab Stufe 2 sichtbar
        const srvAmtBox = document.getElementById('srv-amt-lists-box');
        if (srvAmtBox) srvAmtBox.style.display = lvl >= 2 ? 'block' : 'none';
        // Watchlist-Preview unter den Kategorie-Buttons
        loadVerifyAmtWatchlistPreview();
        // Pending-Status anzeigen (wenn Veriff-Session läuft)
        const pendingVeriff = (d.pending || []).find(p => p.provider === 'veriff');
        if (pendingVeriff && veriffStartBtn) {{
          const mins = Math.floor(pendingVeriff.age_seconds / 60);
          const secs = pendingVeriff.age_seconds % 60;
          const ageStr = mins > 0 ? mins + ' Min ' + secs + ' Sek' : secs + ' Sek';
          veriffStartBtn.disabled = true;
          veriffStartBtn.innerHTML = '⏳ Verifikation läuft... (' + ageStr + ')';
          veriffStartBtn.style.background = 'rgba(255,165,80,0.15)';
          veriffStartBtn.style.borderColor = 'rgba(255,165,80,0.4)';
          veriffStartBtn.style.color = '#ffa550';
          // Client-Side Counter hochzählen (statt Server-Poll)
          if (!window._pendingVeriffStart) window._pendingVeriffStart = Date.now() - (pendingVeriff.age_seconds * 1000);
          if (!window._verifyCounterInterval) {{
            window._verifyCounterInterval = setInterval(() => {{
              const btn = document.getElementById('veriff-start-btn');
              if (!btn) return;
              const age = Math.floor((Date.now() - window._pendingVeriffStart) / 1000);
              const m = Math.floor(age / 60);
              const s = age % 60;
              btn.innerHTML = '⏳ Verifikation läuft... (' + (m > 0 ? m + ' Min ' + s + ' Sek' : s + ' Sek') + ')';
            }}, 1000);
          }}
          // Server-Poll nur alle 30 Sekunden um auf Webhook zu reagieren
          if (!window._verifyServerPollInterval) {{
            window._verifyServerPollInterval = setInterval(() => {{
              const tk = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
              fetch('/api/verify/status', {{headers: {{'X-Session-Token': tk}}}}).then(rr => rr.json()).then(sd => {{
                if (sd.verification_level >= 2) {{
                  clearInterval(window._verifyCounterInterval); window._verifyCounterInterval = null;
                  clearInterval(window._verifyServerPollInterval); window._verifyServerPollInterval = null;
                  window._pendingVeriffStart = null;
                  location.reload();
                }}
              }}).catch(() => {{}});
            }}, 30000);
          }}
        }} else if (window._verifyCounterInterval) {{
          clearInterval(window._verifyCounterInterval); window._verifyCounterInterval = null;
          clearInterval(window._verifyServerPollInterval); window._verifyServerPollInterval = null;
          window._pendingVeriffStart = null;
        }}
        // Veriff Preis aus Server-Status laden
        const vPriceDisplay = document.getElementById('veriff-price-display');
        if (vPriceDisplay) {{
          fetch('/api/server/status', {{headers: {{'X-Session-Token': token}}}})
            .then(rr => rr.json())
            .then(sd => {{
              if (sd.veriff && sd.veriff.price_eur != null) vPriceDisplay.textContent = sd.veriff.price_eur.toFixed(2).replace('.',',') + ' €';
              else vPriceDisplay.textContent = '3,00 €';
            }})
            .catch(() => {{ vPriceDisplay.textContent = '3,00 €'; }});
        }}
      }})
      .catch(() => {{ verifyStatus.textContent = '⚠️ Status nicht abrufbar'; }});
  }}

  let _verifySessionId = '';
  let _stripeClientSecret = '';
  let _stripeObj = null;
  let _stripeElements = null;
  let _stripeCard = null;
}})();

// Verification Functions (außerhalb IIFE für onclick)
async function doVerifyStart() {{
  const msg = document.getElementById('verify-msg');
  const btn = document.getElementById('verify-btn');
  const card = document.getElementById('stripe-card');
  btn.disabled = true; btn.textContent = '⏳ Lade...';
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/verify/start', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json', 'X-Session-Token': token}},
      body: JSON.stringify({{provider: 'stripe'}})
    }});
    const d = await r.json();
    if (d.error) {{
      msg.textContent = d.error; msg.style.color = '#e55';
      btn.disabled = false; btn.textContent = '🔐 Jetzt verifizieren';
      return;
    }}
    _verifySessionId = d.session_id;
    _stripeClientSecret = d.client_secret;
    card.style.display = 'block';
    btn.style.display = 'none';
    msg.textContent = '💳 Kreditkartendaten eingeben (keine Abbuchung!)';
    msg.style.color = '#d4a850';
    // Stripe.js laden falls nötig
    if (!window.Stripe) {{
      const s = document.createElement('script');
      s.src = 'https://js.stripe.com/v3/';
      s.onload = () => initStripeElement();
      document.head.appendChild(s);
    }} else {{
      initStripeElement();
    }}
  }} catch(e) {{
    msg.textContent = 'Verbindungsfehler'; msg.style.color = '#e55';
    btn.disabled = false; btn.textContent = '🔐 Jetzt verifizieren';
  }}
}}

function initStripeElement() {{
  // PK aus Meta-Tag oder Config holen
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  fetch('/api/verify/providers', {{headers: {{'X-Session-Token': token}}}})
    .then(r => r.json())
    .then(d => {{
      // Stripe PK wird über Config bereitgestellt
      fetch('/api/status').then(r => r.json()).then(s => {{
        const pk = s.stripe_publishable_key;
        if (!pk) {{
          document.getElementById('stripe-msg').textContent = '⚠️ Stripe Publishable Key fehlt in Config';
          document.getElementById('stripe-msg').style.color = '#e55';
          return;
        }}
        _stripeObj = Stripe(pk);
        _stripeElements = _stripeObj.elements();
        _stripeCard = _stripeElements.create('card', {{
          style: {{
            base: {{ color: '#e0e0e0', fontSize: '14px', '::placeholder': {{ color: '#666' }} }},
            invalid: {{ color: '#ff5555' }}
          }}
        }});
        _stripeCard.mount('#stripe-element');
      }});
    }});
}}

// Erkennt mobile Geräte anhand User-Agent oder Viewport-Breite
function isMobileDevice() {{
  const ua = navigator.userAgent || '';
  const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile/i.test(ua);
  const isSmallViewport = window.innerWidth <= 768;
  return isMobileUA || isSmallViewport;
}}

async function doVeriffStart() {{
  const msg = document.getElementById('verify-msg');
  msg.textContent = '⏳ Veriff wird gestartet...'; msg.style.color = '#d4a850';
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/verify/start', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json', 'X-Session-Token': token}},
      body: JSON.stringify({{provider: 'veriff'}})
    }});
    const d = await r.json();
    if (d.error) {{ msg.textContent = d.error; msg.style.color = '#e55'; return; }}
    if (d.redirect_url) {{
      if (isMobileDevice()) {{
        // Mobile: Direkt im gleichen Tab weiterleiten (kein QR Code, kein neuer Tab)
        msg.textContent = '🪪 Weiterleitung zu Veriff...'; msg.style.color = '#4a4';
        window.location.href = d.redirect_url;
      }} else {{
        // Desktop: Neuer Tab wie bisher (oder QR-Code-Flow)
        msg.textContent = '🪪 Veriff Tab öffnet...'; msg.style.color = '#4a4';
        window.open(d.redirect_url, '_blank');
      }}
    }} else {{
      msg.textContent = 'Keine Veriff-URL erhalten'; msg.style.color = '#e55';
    }}
  }} catch(e) {{ msg.textContent = 'Fehler: ' + e.message; msg.style.color = '#e55'; }}
}}

async function doStripeConfirm() {{
  const msg = document.getElementById('stripe-msg');
  const btn = document.getElementById('stripe-btn');
  if (!_stripeObj || !_stripeCard || !_stripeClientSecret) {{
    msg.textContent = 'Stripe nicht initialisiert'; msg.style.color = '#e55';
    return;
  }}
  btn.disabled = true; btn.textContent = '⏳ Prüfe...';
  const result = await _stripeObj.confirmCardSetup(_stripeClientSecret, {{
    payment_method: {{ card: _stripeCard }}
  }});
  if (result.error) {{
    msg.textContent = result.error.message; msg.style.color = '#e55';
    btn.disabled = false; btn.textContent = '✅ Karte bestätigen';
    return;
  }}
  // Callback an Nexus
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const r = await fetch('/api/verify/callback', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json', 'X-Session-Token': token}},
    body: JSON.stringify({{session_id: _verifySessionId}})
  }});
  const d = await r.json();
  if (d.verified) {{
    msg.textContent = '✅ Verifiziert! Stufe 1 freigeschaltet!'; msg.style.color = '#4a4';
    setTimeout(() => location.reload(), 2000);
  }} else {{
    msg.textContent = d.error || 'Verifikation fehlgeschlagen'; msg.style.color = '#e55';
    btn.disabled = false; btn.textContent = '✅ Karte bestätigen';
  }}
}}

async function doVerifyAusweis() {{
  const display = document.getElementById('ausweis-display');
  const data = document.getElementById('ausweis-data');
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  const r = await fetch('/api/verify/ausweis', {{headers: {{'X-Session-Token': token}}}});
  const d = await r.json();
  if (d.error) {{ data.textContent = d.error; }}
  else {{ data.textContent = JSON.stringify(d, null, 2); }}
  display.style.display = display.style.display === 'none' ? 'block' : 'none';
}}

async function doVerifyCardChange() {{
  if (!confirm('Karte tauschen?\\n\\nDeine höheren Stufen bleiben erhalten. Du durchläufst nur den Stripe Flow neu mit der neuen Karte. Sobald die neue Karte akzeptiert ist, sind alle Stufen wieder aktiv.')) return;
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/verify/card-replace', {{method:'POST', headers:{{'Content-Type':'application/json','X-Session-Token':token}}}});
    const d = await r.json();
    if (d.error) {{ alert(d.error); return; }}
    location.reload();
  }} catch (e) {{ alert('Fehler: ' + e); }}
}}

async function doVerifyPersoChange() {{
  const price = document.getElementById('veriff-price-display')?.textContent || '?';
  if (!confirm('Perso tauschen?\\n\\n⚠️ Bezahlung erfolgt sofort beim Start (' + price + '). Keine Erstattung bei Fehlschlag.\\n\\nDeine alte Perso-Verifikation bleibt gültig bis die neue akzeptiert ist.')) return;
  // Einfach den normalen Veriff-Flow neu starten — der existierende Flow ueberschreibt bei Erfolg
  doVeriffStart();
}}

async function doVerifyReset() {{
  if (!confirm('Verifikation komplett zurücksetzen?\\n\\nAlle Stufen werden auf 0 gesetzt, Stripe-Customer entfernt und laufende Pre-Auths gecancelt. Du musst danach komplett neu verifizieren.')) return;
  const msg = document.getElementById('verify-msg');
  const btn = document.getElementById('verify-reset-btn');
  btn.disabled = true; btn.textContent = '⏳ Setze zurück...';
  const token = document.cookie.split(';').find(c => c.trim().startsWith('nexus_session='))?.split('=')[1] || '';
  try {{
    const r = await fetch('/api/verify/reset', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json', 'X-Session-Token': token}}
    }});
    const d = await r.json();
    if (d.error) {{
      msg.textContent = d.error; msg.style.color = '#e55';
      btn.disabled = false; btn.textContent = '🔄 Verifikation zurücksetzen';
      return;
    }}
    msg.textContent = '✅ Reset erfolgreich. ' + (d.cancelled_payments > 0 ? d.cancelled_payments + ' Pre-Auth(s) gecancelt. ' : '') + (d.licenses_removed > 0 ? d.licenses_removed + ' Lizenz(en) entfernt. ' : '') + (d.amt_subscriptions_removed > 0 ? d.amt_subscriptions_removed + ' Amt-Abo(s) entfernt. ' : '') + 'Lade neu...';
    msg.style.color = '#4a4';
    setTimeout(() => location.reload(), 1500);
  }} catch(e) {{
    msg.textContent = 'Fehler: ' + e.message; msg.style.color = '#e55';
    btn.disabled = false; btn.textContent = '🔄 Verifikation zurücksetzen';
  }}
}}
</script>
<div style="text-align:center;margin-top:30px;padding:10px;font-size:9px;color:#3a3a4a;"></div>
<canvas id="butterfly-canvas" style="position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:9999;"></canvas>
<script>
// 🦋 ShinNexus Wasserzeichen — Schmetterling V12
// Fliegt NUR wenn Lizenz aktiv (license_company gesetzt)
var _hasLicense = {str(bool(_lcompany)).lower()};
if (!_hasLicense) {{ document.getElementById('butterfly-canvas').style.display = 'none'; }}
(function(){{
  const cvs=document.getElementById('butterfly-canvas');if(!cvs)return;
  const ctx=cvs.getContext('2d');
  cvs.width=window.innerWidth;cvs.height=window.innerHeight;
  window.onresize=()=>{{cvs.width=window.innerWidth;cvs.height=window.innerHeight;}};
  // Seed aus Code-Hash (vom Server injiziert)
  let _rs={code_seed};function sR(){{_rs=(_rs*9301+49297)%233280;return _rs/233280;}}
  // Prozentuale Koordinaten → gleicher Flug auf jedem Gerät
  function randEdge(){{const e=Math.floor(sR()*4);switch(e){{case 0:return{{x:sR(),y:-0.03}};case 1:return{{x:1.03,y:sR()}};case 2:return{{x:sR(),y:1.03}};default:return{{x:-0.03,y:sR()}};}}}}
  let startX,startY,endX,endY,swA,swF,swP,fStart=0,pEnd=0;const trail=[];let _lastCycle=-1;
  function newF(){{const s=randEdge();let e=randEdge();startX=s.x;startY=s.y;endX=e.x;endY=e.y;swA=0.04+sR()*0.08;swF=1.5+sR()*2;swP=sR()*Math.PI*2;fStart=Date.now();pEnd=0;}}
  newF();
  // Alles in Prozent (0-1), erst beim Zeichnen auf Pixel skalieren
  function getP(t){{const ea=0.5-0.5*Math.cos(t*Math.PI);const bx=startX+(endX-startX)*ea;const by=startY+(endY-startY)*ea;const dx=endX-startX,dy=endY-startY,ln=Math.sqrt(dx*dx+dy*dy)||1;const nx=-dy/ln,ny=dx/ln;const mf=Math.sin(t*Math.PI);const sw=Math.sin(ea*Math.PI*swF+swP)*swA*mf;return{{x:bx+nx*sw,y:by+ny*sw}};}}
  function drawB(x,y,wa,sz){{ctx.save();ctx.translate(x,y);const w=wa*1.2,S=sz*1.3;
    function wing(side,top){{const s=side==='L'?-1:1;ctx.save();ctx.scale(s,1);if(top){{const wI=w*0.3,wO=w*1.0,mx=S*0.5,my=-S*0.45+wI*S*0.12,tx=S*0.95,ty=my-S*0.25+wO*S*0.2;ctx.beginPath();ctx.moveTo(0,-S*0.05);ctx.bezierCurveTo(S*0.2,-S*0.4+wI*S*0.05,S*0.35,my-S*0.2,mx,my-S*0.05);ctx.bezierCurveTo(S*0.65,my-S*0.15+wO*S*0.05,S*0.85,ty-S*0.05,tx,ty);ctx.quadraticCurveTo(tx+S*0.02,ty+S*0.12,tx-S*0.1,ty+S*0.18);ctx.bezierCurveTo(S*0.7,my+S*0.25+wO*S*0.08,S*0.55,my+S*0.3,mx-S*0.05,my+S*0.25);ctx.bezierCurveTo(S*0.3,my+S*0.2,S*0.15,S*0.05,0,S*0.1);ctx.closePath();const g=ctx.createRadialGradient(mx,my,S*0.05,mx,my,S*0.55);g.addColorStop(0,'hsla(280,80%,55%,0.85)');g.addColorStop(0.45,'hsla(320,75%,50%,0.75)');g.addColorStop(1,'hsla(25,85%,55%,0.65)');ctx.fillStyle=g;ctx.fill();ctx.strokeStyle='hsla(280,55%,65%,0.5)';ctx.lineWidth=0.8;ctx.stroke();ctx.beginPath();ctx.arc(S*0.65,(my+ty)/2+S*0.05,S*0.08,0,Math.PI*2);ctx.fillStyle='hsla(40,80%,65%,0.5)';ctx.fill();ctx.beginPath();ctx.arc(S*0.65,(my+ty)/2+S*0.05,S*0.04,0,Math.PI*2);ctx.fillStyle='hsla(0,0%,95%,0.6)';ctx.fill();}}else{{const wL=w*0.4;ctx.beginPath();ctx.moveTo(0,S*0.02);ctx.bezierCurveTo(S*0.2,S*0.08,S*0.6,S*(0.2+wL*0.1),S*0.6,S*(0.4+wL*0.08));ctx.bezierCurveTo(S*0.55,S*(0.55+wL*0.05),S*0.3,S*0.5,S*0.15,S*0.35);ctx.bezierCurveTo(S*0.05,S*0.15,0,S*0.08,0,S*0.02);const g2=ctx.createRadialGradient(S*0.25,S*0.2,S*0.02,S*0.3,S*0.25,S*0.3);g2.addColorStop(0,'hsla(25,85%,55%,0.8)');g2.addColorStop(1,'hsla(340,75%,45%,0.65)');ctx.fillStyle=g2;ctx.fill();ctx.strokeStyle='hsla(280,60%,70%,0.5)';ctx.lineWidth=0.6;ctx.stroke();}}ctx.restore();}}
    wing('L',false);wing('R',false);wing('L',true);wing('R',true);
    for(let i=0;i<5;i++){{const cy=-S*0.08+i*S*0.05,r=S*(0.028-i*0.002);ctx.beginPath();ctx.ellipse(0,cy,r,r*1.3,0,0,Math.PI*2);ctx.fillStyle=`hsla(280,30%,${{20+i*3}}%,0.95)`;ctx.fill();}}
    ctx.beginPath();ctx.arc(0,-S*0.12,S*0.035,0,Math.PI*2);ctx.fillStyle='hsla(280,35%,25%,0.95)';ctx.fill();
    ctx.lineWidth=0.8;ctx.strokeStyle='hsla(280,40%,45%,0.8)';ctx.beginPath();ctx.moveTo(-S*0.01,-S*0.15);ctx.bezierCurveTo(-S*0.08,-S*0.3,-S*0.18,-S*0.38,-S*0.12,-S*0.42);ctx.stroke();ctx.beginPath();ctx.arc(-S*0.12,-S*0.42,S*0.015,0,Math.PI*2);ctx.fillStyle='hsla(280,50%,55%,0.9)';ctx.fill();ctx.beginPath();ctx.moveTo(S*0.01,-S*0.15);ctx.bezierCurveTo(S*0.08,-S*0.3,S*0.18,-S*0.38,S*0.12,-S*0.42);ctx.stroke();ctx.beginPath();ctx.arc(S*0.12,-S*0.42,S*0.015,0,Math.PI*2);ctx.fillStyle='hsla(280,50%,55%,0.9)';ctx.fill();ctx.restore();}}
  function anim(){{ctx.clearRect(0,0,cvs.width,cvs.height);const now=Date.now();
    // Absolute Zeit: 13s Zyklus (8s Flug + 5s Pause), synchron auf allen Geräten
    const cycle=13000;
    const phase=now%cycle;
    if(phase>=8000){{ctx.clearRect(0,0,cvs.width,cvs.height);requestAnimationFrame(anim);return;}}
    // Neuen Flug berechnen basierend auf Zyklus-Nummer (deterministisch!)
    const cycleNum=Math.floor(now/cycle);
    if(cycleNum!==_lastCycle){{_lastCycle=cycleNum;_rs={code_seed};for(let i=0;i<cycleNum%50;i++)sR();newF();trail.length=0;}}
    const t=phase/8000,pt=getP(t),wa=Math.sin(now*0.004)*1.0;
    const px=pt.x*cvs.width,py=pt.y*cvs.height;
    trail.push({{x:px,y:py,age:0}});if(trail.length>25)trail.shift();
    trail.forEach(p=>{{p.age++;const a=Math.max(0,1-p.age/25)*0.25;ctx.beginPath();ctx.arc(p.x,p.y,1.5,0,Math.PI*2);ctx.fillStyle=`hsla(280,70%,60%,${{a}})`;ctx.fill();}});
    drawB(px,py,wa,12);requestAnimationFrame(anim);}}
  anim();
}})();
</script>
{_chain_footer}
</body>
</html>"""
        body_bytes = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


# ══════════════════════════════════════════════════════════════════════
#  SERVER START
# ══════════════════════════════════════════════════════════════════════

_server_running = False

def start_server(cfg: dict):
    """HTTP(S) Server starten."""
    global _tls_active, _server_running
    if _server_running:
        return  # Schon gestartet (z.B. im Setup-Thread)
    _server_running = True
    import socket as _socket

    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", DEFAULT_PORT)

    NexusHandler.config = cfg

    # TLS Setup — Let's Encrypt > Self-Signed > Off
    ssl_ctx = None
    tls_mode = cfg.get("tls", {}).get("mode", "auto")
    domain = cfg.get("domain", "")

    if tls_mode in ("auto", "letsencrypt", "self"):
        cert, key = None, None

        # 1. ACME-Cert versuchen wenn Domain gesetzt (5 Provider Fallback!)
        if domain and tls_mode in ("auto", "letsencrypt"):
            acme_email = cfg.get("acme_email", "")
            cert, key = _obtain_acme_cert(domain, acme_email)
            if cert and key:
                tls_source = "ACME (Trusted)"

        # 2. Fallback: Self-Signed
        if not cert:
            cert, key = _ensure_self_signed_cert()
            tls_source = "Self-Signed"

        if cert and key:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(str(cert), str(key))
            _tls_active = True
            nexus_log(f"TLS aktiviert ({tls_source})", "green")
        else:
            nexus_log("TLS-Cert Fehler — starte OHNE TLS!", "red")
            nexus_log("WARNUNG: Sensitive Endpoints nur von localhost erreichbar!", "red")
    elif tls_mode == "off":
        nexus_log("TLS deaktiviert (manuell)", "yellow")
        nexus_log("WARNUNG: Sensitive Endpoints nur von localhost erreichbar!", "yellow")

    srv = ThreadedServer((host, port), NexusHandler)
    srv.socket.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    if ssl_ctx:
        srv.socket = ssl_ctx.wrap_socket(srv.socket, server_side=True)

    proto = "https" if _tls_active else "http"
    public_url = cfg.get("public_url", "")
    nexus_log(f"ShinNexus v{VERSION} gestartet: {proto}://{host}:{port}", "cyan")
    if public_url:
        nexus_log(f"Öffentlich: {public_url}", "cyan")
    nexus_log(f"Lokal: {proto}://localhost:{port}/", "cyan")

    if not _tls_active:
        nexus_log("Sensitive API-Calls (vault/unlock, account/create) nur von localhost!", "yellow")

    # Firemail Cleanup Thread
    def _fm_cleanup_loop():
        while True:
            time.sleep(60)
            _firemail_cleanup()
    threading.Thread(target=_fm_cleanup_loop, daemon=True).start()
    nexus_log("🔥 Firemail-Cleanup Thread gestartet", "cyan")

    # Lizenz-Expiry Thread (Phase 1 L13):
    # Prüft alle 60 Sekunden, ob Lizenzen abgelaufen sind. Markiert sie als expired,
    # triggert Auto-Refresh bei Amt-Lizenzen, respektiert Grace Period (7 Tage)
    # und löscht danach automatisch.
    def _license_expiry_loop():
        while True:
            time.sleep(60)
            try:
                _license_expiry_tick()
            except Exception as _le:
                nexus_log(f"⚠️ License-Expiry-Loop Fehler: {_le}", "yellow")
    threading.Thread(target=_license_expiry_loop, daemon=True).start()
    nexus_log("📜 License-Expiry Thread gestartet", "cyan")

    # Chain of Trust: Integrity Check (inkl. Live-Blockchain-Verifikation)
    _btc_startup_integrity_check()

    # Live-Anker-Check alle 6h — erkennt auch on-chain-Revokes zuverlässig
    def _btc_live_verify_loop():
        while True:
            time.sleep(6 * 3600)
            try:
                _btc_live_verify_and_persist()
            except Exception as _be:
                nexus_log(f"⚠️ Live-Anker-Check Fehler: {_be}", "yellow")
    threading.Thread(target=_btc_live_verify_loop, daemon=True).start()
    nexus_log("⚓ Live-Anker-Check Thread gestartet (6h)", "cyan")

    # Network-Check Watchdog — alle N Sekunden Self-Test + isitup
    def _network_check_loop():
        # Erst-Check nach 5s Delay (Server muss Socket binden)
        time.sleep(5)
        try:
            run_network_check()
        except Exception as _ne:
            nexus_log(f"⚠️ Initial Network-Check Fehler: {_ne}", "yellow")
        while True:
            c = load_config()
            if not c.get("autocheck_enabled", True):
                time.sleep(60)
                continue
            interval = int(c.get("autocheck_interval_sec", 1800))
            time.sleep(max(60, interval))
            try:
                run_network_check(c)
            except Exception as _ne:
                nexus_log(f"⚠️ Network-Check Fehler: {_ne}", "yellow")
    threading.Thread(target=_network_check_loop, daemon=True).start()
    nexus_log("🌐 Network-Check Watchdog gestartet", "cyan")

    # Account-Lifecycle-Tick — alle 30 Minuten
    def _account_lifecycle_loop():
        time.sleep(60)  # Initial-Delay
        while True:
            try:
                _account_lifecycle_tick()
            except Exception as _ae:
                nexus_log(f"⚠️ Lifecycle-Cleanup Fehler: {_ae}", "yellow")
            time.sleep(30 * 60)
    threading.Thread(target=_account_lifecycle_loop, daemon=True).start()
    nexus_log("🧹 Account-Lifecycle Thread gestartet (90d/scheduled)", "cyan")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        nexus_log("Server gestoppt", "yellow")
        srv.shutdown()


# ══════════════════════════════════════════════════════════════════════
#  CLI ONBOARDING
# ══════════════════════════════════════════════════════════════════════

def _print_qr_terminal(uri: str):
    """QR-Code im Terminal anzeigen (segno)."""
    if not HAS_SEGNO:
        return False
    try:
        qr = segno.make(uri)
        # Unicode-Block-Ausgabe fürs Terminal
        import io
        buf = io.StringIO()
        qr.terminal(out=buf, compact=True)
        print(buf.getvalue())
        return True
    except Exception:
        return False


def _nexus_request(url: str, data: dict = None, method: str = "GET") -> dict | None:
    """HTTP-Request an einen ShinNexus-Server (für Client-Modus)."""
    import urllib.request
    try:
        # SSL-Context: Self-Signed akzeptieren
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if data is not None:
            body = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(url, data=body, method=method or "POST")
            req.add_header("Content-Type", "application/json")
        else:
            req = urllib.request.Request(url, method=method)

        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        nexus_log(f"Nexus-Request fehlgeschlagen: {e}", "red")
        return None


def cli_client_connect(cfg: dict) -> bool:
    """Client-Modus: Mit bestehendem ShinNexus-Server verbinden."""
    print()
    print("╔══════════════════════════════════════╗")
    print("║   🔗 Mit ShinNexus-Server verbinden  ║")
    print("╚══════════════════════════════════════╝")
    print()

    # Server-URL abfragen
    print("  Gib die URL deines ShinNexus-Servers ein:")
    print("  (z.B. https://nexus.shidow.de:12345)")
    print()
    while True:
        server_url = input("  Server-URL: ").strip().rstrip("/")
        if not server_url:
            print("  ❌ URL darf nicht leer sein!")
            continue
        if not server_url.startswith("http"):
            server_url = f"https://{server_url}"

        # Ping testen
        print(f"  ⏳ Teste Verbindung zu {server_url}...")
        ping = _nexus_request(f"{server_url}/api/ping")
        if ping and ping.get("status") == "online":
            print(f"  ✅ Server erreichbar! ({ping.get('app')} v{ping.get('version')})")
            break
        else:
            print(f"  ❌ Server nicht erreichbar! Nochmal versuchen.")
            retry = input("  [Enter] Nochmal / [q] Abbrechen: ").strip()
            if retry.lower() == "q":
                return False

    # Login: Username
    print()
    print("  Anmelden:")
    while True:
        username = input("  Username: ").strip()
        name_err = validate_username(username)
        if name_err:
            print(f"  ❌ {name_err}")
            continue
        break

    # Login: Passwort
    password = getpass.getpass("  Passwort: ")

    # 3-Step Auth gegen den Server
    print("  ⏳ Authentifiziere...")
    login_data = {"username": username, "password": password, "source": "shinnexus-client"}
    auth_result = _nexus_request(f"{server_url}/api/auth/login", login_data)

    if not auth_result:
        print("  ❌ Verbindung fehlgeschlagen!")
        return False

    if auth_result.get("error"):
        print(f"  ❌ {auth_result['error']}")
        return False

    # 2FA erforderlich?
    if auth_result.get("totp_required") or auth_result.get("step") == "2fa":
        print()
        code = input("  🔐 2FA-Code: ").strip()
        login_data["totp_code"] = code
        auth_result = _nexus_request(f"{server_url}/api/auth/login", login_data)
        if not auth_result or auth_result.get("error"):
            print(f"  ❌ {auth_result.get('error', 'Auth fehlgeschlagen')}")
            return False

    # Session-Token erhalten?
    session_token = auth_result.get("session_token")
    if not session_token and auth_result.get("step") == "done":
        session_token = auth_result.get("session_token")

    if not session_token:
        print(f"  ❌ Kein Session-Token erhalten!")
        return False

    # Identity vom Server holen
    print("  ⏳ Lade Identity...")
    identity = _nexus_request(f"{server_url}/api/identity")
    if not identity or identity.get("error"):
        print("  ❌ Identity konnte nicht geladen werden!")
        return False

    # Config speichern
    cfg["mode"] = "client"
    cfg["server_url"] = server_url
    cfg["name"] = identity.get("name", username)
    cfg["email"] = identity.get("email", "")
    cfg["shinpai_id"] = identity.get("shinpai_id", "")
    cfg["public_key"] = identity.get("public_key", "")
    cfg["kem_public_key"] = identity.get("kem_public_key", "")
    cfg["session_token"] = session_token
    save_config(cfg)

    # Lokale Identity-Kopie speichern (für Offline-Zugriff)
    global _identity
    _identity = {
        "name": identity.get("name", username),
        "email": identity.get("email", ""),
        "shinpai_id": identity.get("shinpai_id", ""),
        "server_url": server_url,
        "connected": int(time.time()),
        "mode": "client",
    }

    print()
    print(f"  ✅ Verbunden mit {server_url}")
    print(f"  👤 {_identity['name']}")
    print(f"  🆔 {_identity['shinpai_id']}")
    print(f"  🔗 Modus: CLIENT (Fernbedienung)")
    print()
    return True


def cli_onboarding(cfg: dict):
    """Terminal-basiertes Onboarding — SERVER-Modus: Neuen Account erstellen."""
    cfg["mode"] = "server"
    print()
    print("╔══════════════════════════════════════╗")
    print("║       🔮 ShinNexus — Setup           ║")
    print("║   Dein digitaler Personalausweis     ║")
    print("╚══════════════════════════════════════╝")
    print()

    # Vault-Passwort setzen
    print("Schritt 1/5: Vault-Passwort festlegen")
    print("  (Verschlüsselt deine Identität lokal)")
    print()
    while True:
        pw1 = getpass.getpass("  Passwort: ")
        pw2 = getpass.getpass("  Wiederholen: ")
        if pw1 != pw2:
            print("  ❌ Passwörter stimmen nicht überein!")
            continue
        if len(pw1) < 6:
            print("  ❌ Mindestens 6 Zeichen!")
            continue
        break

    vault_password = pw1
    vault_unlock(pw1)
    print("  ✅ Vault erstellt!")
    print()

    # Account
    print("Schritt 2/5: Account erstellen")
    print("  Username: 3-12 Zeichen, nur A-Z, a-z, 0-9 (case-sensitive!)")
    while True:
        name = input("  Username: ").strip()
        name_err = validate_username(name)
        if name_err:
            print(f"  ❌ {name_err}")
            continue
        break
    email = input("  Email: ").strip()

    if not email:
        print("  ❌ Email ist Pflicht!")
        return

    result = create_account(name, email, vault_password=vault_password)

    # Keypair + Kürzel für Igni-Ordner
    _ensure_keypair(cfg)
    cfg["name"] = name
    cfg["shinpai_name_hash"] = result["shinpai_id"].split("-")[0]
    cfg["email"] = email
    cfg["shinpai_id"] = result["shinpai_id"]
    save_config(cfg)

    print()
    print("╔══════════════════════════════════════╗")
    print("║  ⚠️  RECOVERY-SEED — AUFSCHREIBEN!   ║")
    print("╠══════════════════════════════════════╣")
    words = result["recovery_seed"].split()
    for i in range(0, len(words), 2):
        w1 = f"{i+1:2d}. {words[i]}"
        w2 = f"{i+2:2d}. {words[i+1]}" if i+1 < len(words) else ""
        print(f"║  {w1:<18s} {w2:<17s}║")
    print("╠══════════════════════════════════════╣")
    print("║  Damit kannst du deinen Account      ║")
    print("║  wiederherstellen! NIEMALS teilen!    ║")
    print("╚══════════════════════════════════════╝")
    print()
    input("  [Enter] Hab ich aufgeschrieben! → ")

    # 2FA Setup
    print()
    print("Schritt 3/5: 2FA einrichten (TOTP)")
    if HAS_TOTP and result.get("totp_secret"):
        totp_uri = result.get("totp_uri", "")
        # QR-Code im Terminal
        if totp_uri and HAS_SEGNO:
            print()
            print("  Scanne den QR-Code mit deiner Authenticator-App:")
            print()
            _print_qr_terminal(totp_uri)
            print()
        else:
            print(f"  Secret: {result['totp_secret']}")
            print(f"  URI:    {totp_uri}")
        print()
        print("  (Google Authenticator, Authy, Microsoft Authenticator...)")
        print(f"  Manueller Key: {result['totp_secret']}")
        print()
        while True:
            code = input("  6-stelliger Code aus der App: ").strip()
            if totp_verify(result["totp_secret"], code):
                _identity["totp_confirmed"] = True
                _save_identity()
                print("  ✅ 2FA aktiviert!")
                break
            else:
                print("  ❌ Falscher Code — nochmal!")
    else:
        print("  ⚠️ pyotp nicht installiert — 2FA übersprungen!")
        print("  (pip install pyotp für 2FA-Support)")

    # Schritt 4: Öffentliche Erreichbarkeit
    print()
    print("Schritt 4/5: Öffentliche Erreichbarkeit")
    print("  Wie ist dieser Server erreichbar?")
    print()
    print("  [1] Eigene Domain / IP (VPS, Root-Server, feste IP)")
    print("      Du hast eine Domain oder öffentliche IP.")
    print()
    print("  [2] frps-Tunnel (Lokaler Rechner hinter NAT)")
    print("      Dein Server läuft lokal, frps tunnelt nach außen.")
    print()
    print("  [3] Cloudflare Quick Tunnel (Hobby/Test, GRATIS)")
    print("      Temporäre URL, ändert sich bei Neustart.")
    print()
    print("  [4] Nur lokal (kein öffentlicher Zugang)")
    print("      Kann später aktiviert werden.")
    print()
    choice = input("  Wahl [1/2/3/4]: ").strip()

    if choice == "1":
        # Eigene Domain / IP
        print()
        print("  Gib deine Domain oder IP ein:")
        print("  (z.B. nexus.shidow.de oder 185.123.45.67)")
        print()
        domain = input("  Domain/IP: ").strip()
        if domain:
            port = cfg.get("port", DEFAULT_PORT)
            # Protokoll bestimmen
            if domain.startswith("http"):
                public_url = domain.rstrip("/")
            else:
                public_url = f"https://{domain}:{port}"
            cfg["public_url"] = public_url
            # Domain OHNE Port! (Port kommt separat)
            cfg["domain"] = domain.split(":")[0] if ":" in domain and not domain.startswith("http") else domain
            save_config(cfg)
            print(f"  ✅ Öffentliche Adresse: {public_url}")
            print()
            # ACME-Email = Owner-Email (aus Schritt 2)
            cfg["acme_email"] = email
            save_config(cfg)
            print("  🔒 TLS-Zertifikat (ACME — 5 Provider automatisch!):")
            print("    Let's Encrypt → ZeroSSL → Buypass → SSL.com → Google")
            print(f"    E-Mail: {email} (deine Account-Email)")
            print("    Braucht: certbot installiert + Port 80 offen")
            print()
            print("  ⚠️ Stelle sicher dass:")
            print(f"    - DNS '{domain}' auf diese Server-IP zeigt")
            print(f"    - Port {port} in der Firewall offen ist")
            print(f"    - Port 80 offen für Zertifikat-Beantragung")
            print("    Zertifikat wird beim Start automatisch beantragt!")
        else:
            print("  ❌ Keine Domain angegeben — übersprungen.")

    elif choice == "2":
        # frps-Tunnel
        print()
        print("  frps-Server konfigurieren:")
        print()
        frps_server = input("  frps-Server (z.B. mein-vps.de): ").strip()
        frps_port = input("  frps-Port [7000]: ").strip() or "7000"
        frps_token = input("  frps-Token: ").strip()
        frps_domain = input("  Domain (z.B. shidow.de): ").strip()
        frps_subdomain = input("  Subdomain [nexus]: ").strip() or "nexus"

        if frps_server and frps_token:
            tunnel_cfg = cfg.get("tunnel", {})
            tunnel_cfg["enabled"] = True
            tunnel_cfg["server"] = frps_server
            tunnel_cfg["server_port"] = int(frps_port)
            tunnel_cfg["token"] = frps_token
            tunnel_cfg["domain"] = frps_domain
            tunnel_cfg["subdomain"] = frps_subdomain
            cfg["tunnel"] = tunnel_cfg

            public_url = f"https://{frps_subdomain}.{frps_domain}" if frps_domain else ""
            if public_url:
                cfg["public_url"] = public_url
            save_config(cfg)
            print(f"  ✅ frps-Tunnel konfiguriert!")
            if public_url:
                print(f"  🌐 Adresse: {public_url}")
            print("  Tunnel startet automatisch nach dem Setup.")
        else:
            print("  ❌ Server und Token sind Pflicht — übersprungen.")

    elif choice == "3":
        # Cloudflare Quick Tunnel
        print()
        port = cfg.get("port", DEFAULT_PORT)
        ok = start_cloudflare_tunnel(port)
        if ok:
            print("  ⏳ Warte auf öffentliche URL...")
            for _ in range(30):
                if _public_url:
                    break
                time.sleep(0.5)
            if _public_url:
                cfg["public_url"] = _public_url
                cfg["tunnel_mode"] = "cloudflare"
                save_config(cfg)
                print(f"  ✅ Temporäre URL: {_public_url}")
                print("  ⚠️ URL ändert sich bei jedem Neustart!")
            else:
                print("  ⚠️ Tunnel gestartet, URL wird noch ermittelt...")
        else:
            print("  ❌ Tunnel fehlgeschlagen — kann später aktiviert werden")
    else:
        print("  → Nur lokal. Aktiviere später über die Einstellungen.")

    # System-Vault initialisieren (machine-bound, automatisch)
    system_vault_init(cfg, owner_password=vault_password)
    system_vault_save({
        "installed": int(time.time()),
        "owner_shinpai_id": result["shinpai_id"],
    })
    print("  ✅ System-Vault bereit (maschinengebunden)")

    # Schritt 6: SMTP einrichten (PFLICHT!) — mit Retry-Loop!
    smtp_ok = False
    while not smtp_ok:
        print()
        print("Schritt 6/7: SMTP einrichten (PFLICHT!)")
        print("  Ohne SMTP: Keine Email-Verifizierung, keine User-Registrierung!")
        print()
        smtp_host = input("  SMTP Host (z.B. smtp.migadu.com): ").strip()
        smtp_port = input("  SMTP Port (587=STARTTLS, 465=SSL) [587]: ").strip() or "587"
        smtp_user = input("  SMTP User (z.B. info@shinpai.de): ").strip()
        smtp_pass = getpass.getpass("  SMTP Passwort: ")
        smtp_from = input(f"  Absender [{smtp_user}]: ").strip() or smtp_user

        if not smtp_host or not smtp_user or not smtp_pass:
            print("  ❌ Host, User und Passwort sind Pflicht!")
            continue

        cfg["smtp"] = {
            "host": smtp_host,
            "port": int(smtp_port),
            "user": smtp_user,
            "password": smtp_pass,
            "from": smtp_from,
        }
        save_config(cfg)
        print("  ✅ SMTP gespeichert! Teste Verbindung...")

        # Verifizierungs-Mail senden als Test
        print(f"  📧 Sende Verifizierungs-Mail an {email}...")
        ok = send_verify_email(email, name, result["shinpai_id"], cfg=cfg)
        if ok:
            print(f"  ✅ Verifizierungs-Mail gesendet an {email}!")
            smtp_ok = True
        else:
            print(f"  ❌ Mail fehlgeschlagen! SMTP-Daten falsch?")
            print()
            retry = input("  Nochmal eingeben? [J/n]: ").strip().lower()
            if retry == 'n':
                print("  → Kann später über /api/smtp/config konfiguriert werden.")
                break

    # Schritt 7: Email verifizieren
    # Server muss VORHER laufen, sonst ist der Verify-Link nicht erreichbar!
    print()
    print("Schritt 7/7: Email verifizieren")
    if smtp_ok:
        print("  🌐 Starte Server im Hintergrund für Verify-Link...")
        _setup_server_thread = threading.Thread(target=start_server, args=(cfg,), daemon=True)
        _setup_server_thread.start()
        time.sleep(2)  # Server kurz hochfahren lassen
        print("  ✅ Server läuft!")
        print()
        print(f"  📧 Check dein Postfach: {email}")
        print("  Klick den Link in der Mail um deine Identität zu bestätigen!")
        print()
        print("  Warte auf Verifizierung... (Ctrl+C zum Überspringen)")
        try:
            for i in range(120):  # Max 10 Minuten warten
                time.sleep(5)
                if _identity and _identity.get("email_verified"):
                    print(f"\n  ✅ Email verifiziert! {email}")
                    break
                if i % 6 == 0 and i > 0:
                    print(f"  ⏳ Warte... ({i*5}s)")
            else:
                print("\n  ⏳ Timeout — kann später verifiziert werden.")
                print("  → POST /api/email/send-verify")
        except KeyboardInterrupt:
            print("\n  → Übersprungen. Kann später verifiziert werden.")
    else:
        print("  ⚠️ Ohne SMTP keine Verifizierung möglich.")

    # Schritt 8: Igni-Key (Auto-Unlock) oder Paranoid-Modus
    print()
    print("Schritt 8: Haus­schlüssel-Modus wählen")
    print("  [1] Standard — Igni-Key erstellen (Auto-Unlock bei nächstem Start)")
    print("  [2] Paranoid — kein Igni, jeder Start fragt nach Passwort + 2FA")
    igni_choice = input("  Wahl [1]: ").strip() or "1"
    _igni_init(cfg)
    if igni_choice == "2":
        cfg["owner_vault_mode"] = "paranoid"
        save_config(cfg)
        print("  🔒 Paranoid-Modus — kein Igni. Owner muss bei jedem Start einloggen.")
        # Platzhalter verwerfen — echter Owner steht
        _placeholder_dismiss()
    else:
        cfg["owner_vault_mode"] = "standard"
        save_config(cfg)
        igni_save(vault_password)
        print("  ✅ Igni-Key erstellt (maschinengebunden, USB-exportierbar).")
        _placeholder_dismiss()

    print()
    print("╔══════════════════════════════════════╗")
    print("║       ✅ Setup abgeschlossen!         ║")
    print("╠══════════════════════════════════════╣")
    print(f"║  👤 {name:<33s}║")
    print(f"║  🆔 {result['shinpai_id']:<33s}║")
    print(f"║  🔑 ML-DSA-65 + ML-KEM-768          ║")
    ev = '✅' if _identity and _identity.get('email_verified') else '❌'
    sm = '✅' if smtp_configured(cfg) else '❌'
    print(f"║  🔐 2FA: {'Aktiv' if _identity.get('totp_confirmed') else 'Aus':<24s}║")
    print(f"║  📧 Email: {ev:<23s}║")
    print(f"║  📧 SMTP: {sm:<24s}║")
    print(f"║  🛡️ Vault: {sv_mode.upper():<22s}║")
    print(f"║  🔑 Igni: ✅ Auto-Unlock              ║")
    url_display = cfg.get('public_url') or _public_url or 'Nur lokal'
    print(f"║  🌐 {url_display:<33s}║")
    print("╚══════════════════════════════════════╝")
    print()


def cli_recovery(cfg: dict) -> bool:
    """Account wiederherstellen via Recovery-Seed."""
    print()
    print("╔══════════════════════════════════════╗")
    print("║   🔄 Account-Wiederherstellung       ║")
    print("╚══════════════════════════════════════╝")
    print()

    if not RECOVERY_HASH_FILE.exists():
        print("  ❌ Keine Recovery-Daten gefunden!")
        print("  (Wurde der Account auf diesem Gerät erstellt?)")
        return False

    print("  Gib deine 12 Recovery-Wörter ein (durch Leerzeichen getrennt):")
    print()
    seed = input("  Seed: ").strip().lower()
    words = seed.split()
    if len(words) != 12:
        print(f"  ❌ Erwartet: 24 Wörter, bekommen: {len(words)}")
        return False

    # Vault-Passwort über Seed wiederherstellen
    old_password = _recover_vault_password(seed)
    if not old_password:
        print("  ❌ Recovery-Seed falsch!")
        return False

    print("  ✅ Seed verifiziert!")
    print()

    # Neues Passwort setzen
    print("  Neues Vault-Passwort festlegen:")
    while True:
        pw1 = getpass.getpass("  Neues Passwort: ")
        pw2 = getpass.getpass("  Wiederholen: ")
        if pw1 != pw2:
            print("  ❌ Stimmen nicht überein!")
            continue
        if len(pw1) < 6:
            print("  ❌ Mindestens 6 Zeichen!")
            continue
        break

    # Vault mit neuem Passwort re-verschlüsseln
    if not _vault_change_password(old_password, pw1):
        print("  ❌ Passwort-Änderung fehlgeschlagen!")
        return False

    # Recovery-Daten mit neuem Passwort aktualisieren
    _save_recovery_data(pw1, seed)

    # Vault öffnen und Identity laden
    _load_identity()
    _load_hives()
    _load_friends()
    _load_agents()
    _load_users()
    _load_user_hives()
    _load_migrate_abuse()
    _load_type_switch_abuse()
    if _identity:
        _ensure_keypair(cfg)
        save_config(cfg)
        print()
        print(f"  ✅ Account wiederhergestellt!")
        print(f"  👤 Willkommen zurück, {_identity['name']}!")
        return True
    return False


def cli_unlock(cfg: dict) -> str | None:
    """Vault im Terminal entsperren (Passwort + 2FA).
    Gibt das Klartext-Passwort bei Erfolg zurück (für Igni-Save), None bei Fail.
    """
    print()
    pw = getpass.getpass("🔒 Vault-Passwort: ")
    if not vault_unlock(pw):
        print("  ❌ Falsches Passwort!")
        return None
    _load_identity()
    _load_hives()
    _load_friends()
    _load_agents()
    _load_users()
    # 2FA prüfen wenn aktiviert
    if _identity and _identity.get("totp_confirmed"):
        attempts = 0
        while attempts < 3:
            code = input("  🔐 2FA-Code: ").strip()
            if totp_verify(_identity.get("totp_secret", ""), code):
                break
            attempts += 1
            print(f"  ❌ Falscher Code! ({3 - attempts} Versuche übrig)")
        else:
            print("  ❌ 2FA fehlgeschlagen!")
            vault_lock()
            return None
    if _identity:
        _ensure_keypair(cfg)
        save_config(cfg)
        print(f"  ✅ Willkommen zurück, {_identity['name']}!")
    return pw


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    cfg = load_config()

    print()
    print(f"  🔮 ShinNexus v{VERSION}")
    print(f"  📁 {BASE}")
    print()

    existing_mode = cfg.get("mode", "")

    if not IDENTITY_VAULT.exists() and existing_mode != "client":
        # ── Erster Start: Was soll ShinNexus sein? ──
        print("  Willkommen bei ShinNexus!")
        print()
        # Headless? → Kein Menü, direkt Provisioning-Modus!
        if not sys.stdin.isatty():
            print("  ⏳ Headless — Provisioning-Modus (erster API-Account wird Owner)")
        else:
            print("  Was möchtest du tun?")
            print()
            print("  [1] 🖥️  SERVER einrichten (VPS/eigener Server)")
            print("  [2] 📱 VERBINDEN (Handy/Laptop/zweites Gerät)")
            print("  [3] 🔄 WIEDERHERSTELLEN (Recovery-Seed)")
            print()
            choice = input("  Wahl [1/2/3]: ").strip()

            if choice == "2":
                if not cli_client_connect(cfg):
                    print("  ❌ Verbindung fehlgeschlagen.")
                    sys.exit(1)
            elif choice == "3":
                if not cli_recovery(cfg):
                    print("  Wiederherstellung fehlgeschlagen.")
                    sys.exit(1)
            else:
                cli_onboarding(cfg)

    elif existing_mode == "client":
        # ── Client-Modus: Reconnect zum Server ──
        server_url = cfg.get("server_url", "")
        print(f"  🔗 Client-Modus: {server_url}")
        print()
        print("  [1] Verbinden (Session erneuern)")
        print("  [2] Server wechseln")
        print("  [3] Zu Server-Modus wechseln")
        print()
        choice = input("  Wahl [1/2/3]: ").strip()

        if choice == "2" or choice == "3":
            if choice == "3":
                # Zu Server wechseln
                cfg["mode"] = ""
                cfg["server_url"] = ""
                save_config(cfg)
                cli_onboarding(cfg)
            else:
                cfg["mode"] = ""
                save_config(cfg)
                if not cli_client_connect(cfg):
                    sys.exit(1)
        else:
            # Reconnect
            print(f"  ⏳ Verbinde zu {server_url}...")
            ping = _nexus_request(f"{server_url}/api/ping")
            if ping and ping.get("status") == "online":
                print(f"  ✅ Server erreichbar!")
                # Identity laden
                identity = _nexus_request(f"{server_url}/api/identity")
                if identity and not identity.get("error"):
                    global _identity
                    _identity = {
                        "name": identity.get("name", cfg.get("name", "")),
                        "email": identity.get("email", ""),
                        "shinpai_id": identity.get("shinpai_id", ""),
                        "server_url": server_url,
                        "mode": "client",
                    }
                    print(f"  👤 {_identity['name']} ({_identity['shinpai_id']})")
                else:
                    # Server da aber Identity gesperrt → Login nötig
                    if not cli_client_connect(cfg):
                        sys.exit(1)
            else:
                print(f"  ❌ Server nicht erreichbar: {server_url}")
                print("  Offline-Modus mit letzten bekannten Daten...")
                _identity = {
                    "name": cfg.get("name", "?"),
                    "shinpai_id": cfg.get("shinpai_id", "?"),
                    "mode": "client",
                    "offline": True,
                }

    else:
        # ── Server-Modus: Account vorhanden → Igni oder Login ──
        _igni_init(cfg)
        igni_pw = igni_load()
        if igni_pw:
            # Igni Auto-Unlock!
            print("  🔑 Igni-Key gefunden — Auto-Unlock...")
            if vault_unlock(igni_pw):
                _load_identity()
                _load_hives()
                _load_friends()
                _load_agents()
                _load_users()
                if _identity:
                    _ensure_keypair(cfg)
                    save_config(cfg)
                    print(f"  ✅ Auto-Login: {_identity['name']}!")
                else:
                    print("  ❌ Igni-Unlock OK aber keine Identity!")
                    sys.exit(1)
            else:
                print("  ❌ Igni-Key ungültig (Passwort geändert?) — manueller Login:")
                igni_delete()
                if not cli_unlock(cfg):
                    sys.exit(1)
        else:
            # Kein Igni → Interaktiver Login
            print("  🖥️ Server-Modus — Account gefunden.")
            print()
            print("  [1] Anmelden (Vault entsperren)")
            print("  [2] Passwort vergessen (Recovery-Seed)")
            print()
            choice = input("  Wahl [1/2]: ").strip()

            if choice == "2":
                if not cli_recovery(cfg):
                    sys.exit(1)
            else:
                attempts = 0
                unlock_pw: str | None = None
                while attempts < 3:
                    unlock_pw = cli_unlock(cfg)
                    if unlock_pw:
                        break
                    attempts += 1
                else:
                    print("  ❌ 3 Fehlversuche — beende.")
                    print("  Tipp: Starte neu und wähle 'Passwort vergessen'")
                    sys.exit(1)
                # Nach erfolgreichem Login: Igni nur erstellen wenn owner_vault_mode=standard
                # und noch kein Igni existiert (Paranoid = nie Igni)
                owner_mode = cfg.get("owner_vault_mode", "standard")
                if owner_mode == "standard" and unlock_pw and not _VAULT_BOOTSTRAP.exists():
                    print()
                    print("  🔑 Igni-Key wird erstellt (Auto-Unlock für nächsten Start)...")
                    try:
                        igni_save(unlock_pw)
                        print("  ✅ Igni-Key erstellt!")
                    except Exception as e:
                        print(f"  ⚠️  Igni konnte nicht erstellt werden: {e}")

    if not _identity:
        # System First-Start — Platzhalter im RAM aufziehen (nicht abrufbar!)
        _placeholder_activate()
        print("  ⏳ Kein Owner — Server startet im Provisioning-Modus!")
        print("  → Erster Account via /api/auth/register wird automatisch Owner.")
        print("  → Platzhalter existiert NUR im RAM, nirgends in DB/Config/Logs.")
        print()

    # ── Ab hier: Server ODER Client läuft ──
    is_server = cfg.get("mode") == "server" or (cfg.get("mode") != "client")
    is_client = cfg.get("mode") == "client"

    if is_server and _identity:
        # System Vault initialisieren (nur wenn Owner existiert!)
        if not system_vault_is_unlocked():
            if not system_vault_init(cfg):
                nexus_log("System Vault konnte nicht geöffnet werden!", "red")

        # Tunnel starten (wenn konfiguriert)
        if cfg.get("tunnel", {}).get("enabled"):
            start_tunnel(cfg)
    elif is_server and not _identity:
        # Sicherstellen dass der Platzhalter nach allen Setup-Pfaden lebt
        _placeholder_activate()
        nexus_log("Provisioning-Modus — warte auf ersten Account via API", "yellow")

    # Server starten (beide Modi — Server served API, Client served als lokaler Proxy)
    print()

    def _shutdown(signum, frame):
        nexus_log("Shutdown Signal empfangen", "yellow")
        if is_server:
            stop_tunnel()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if is_client:
        nexus_log(f"Client-Modus: Verbunden mit {cfg.get('server_url', '?')}", "cyan")

    if _server_running:
        # Server läuft schon (aus Setup Schritt 7) — am Leben halten
        nexus_log("Server läuft bereits (aus Setup) — halte Prozess am Leben", "cyan")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            nexus_log("Server gestoppt", "yellow")
    else:
        start_server(cfg)


if __name__ == "__main__":
    main()
