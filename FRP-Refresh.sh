#!/bin/bash
# FRP-Refresh.sh — Token-Refresh + frps-Restart auf dem SAI VPS
# Ausführung: bash FRP-Refresh.sh
# Sudo wird interaktiv abgefragt (kein NOPASSWD nötig)
# Stand: 2026-05-01 — Hasi-Diktat im Kneipe-Tisch r1_t1227

set -e

SERVICE="frps.service"

# Config-Pfad aus systemd-Service auslesen (robust gegen beliebige Installationen)
CONFIG=""
EXEC_LINE=$(systemctl cat "$SERVICE" 2>/dev/null | grep -E '^ExecStart=' | head -1)
if [ -n "$EXEC_LINE" ]; then
    # ExecStart=/path/to/frps -c /path/to/frps.toml → -c-Parameter extrahieren
    CONFIG=$(echo "$EXEC_LINE" | sed -n 's/.*-c[[:space:]]\+\([^[:space:]]\+\).*/\1/p')
fi

# Fallback auf bekannte Standard-Pfade falls Service-Auslese fehlschlägt
[ -f "$CONFIG" ] || CONFIG="/etc/frp/frps.toml"
[ -f "$CONFIG" ] || CONFIG="/opt/frp/frps.toml"
[ -f "$CONFIG" ] || CONFIG="$HOME/frp/frps.toml"
[ -f "$CONFIG" ] || CONFIG="$HOME/Projekt-SAI/ShinShare/frps.toml"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   📡 FRP Refresh — frps Restart       ║"
echo "  ║   Sudo wird interaktiv abgefragt!    ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# 1. Status vorher
echo "  → Status vor Restart:"
systemctl status "$SERVICE" --no-pager 2>&1 | head -5 | sed 's/^/    /'
echo ""

# 2. Config existiert?
if [ ! -f "$CONFIG" ]; then
    echo "  ⚠️  frps.toml nicht gefunden — Pfad-Liste durchgegangen, nichts da"
    echo "     Geprüft: /etc/frp/, /opt/frp/, \$HOME/frp/"
    echo "     Setze CONFIG manuell oder lege Pfad in dieses Skript ein."
    exit 1
fi
echo "  → frps.toml: $CONFIG"

# 3. Token aus frps.toml lesen (für Verify)
TOKEN_LINE=$(grep -E '^[[:space:]]*auth\.token[[:space:]]*=' "$CONFIG" | head -1)
if [ -n "$TOKEN_LINE" ]; then
    echo "  → Aktuelle Token-Zeile gefunden: $(echo "$TOKEN_LINE" | sed 's/.*auth\.token[[:space:]]*=[[:space:]]*"\([^"]*\)".*/Token: \1/')"
fi
echo ""

# 4. Restart mit interaktiver sudo-Abfrage
echo "  → frps wird neugestartet (sudo-Passwort wird gleich abgefragt)..."
echo ""
sudo systemctl restart "$SERVICE"

# 5. Status nachher
echo ""
echo "  → Status nach Restart:"
sleep 1
systemctl status "$SERVICE" --no-pager 2>&1 | head -7 | sed 's/^/    /'

# 6. Schluss-Check
echo ""
if systemctl is-active --quiet "$SERVICE"; then
    echo "  ✅ frps läuft — neuer Token ist aktiv"
    echo ""
    exit 0
else
    echo "  ❌ frps läuft NICHT! Prüfe journalctl -u $SERVICE -n 50"
    echo ""
    exit 2
fi
