#!/bin/bash
# ShinNexus — Identity Service
# Shinpai-AI | Ist einfach passiert.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "$0")"
PID_FILE="$SCRIPT_DIR/.nexus.pid"
PORT=12345
PYTHON="$SCRIPT_DIR/env/bin/python3"
MAIN="ShinNexus.py"

show_intro() {
  echo ""
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║                                      ║"
  echo "  ║  🛡️  ShinNexus — Identity Service  🛡️ ║"
  echo "  ║                                      ║"
  echo "  ║  Same Knowledge. Your Ownership.     ║"
  echo "  ║  Port $PORT                           ║"
  echo "  ║                                      ║"
  echo "  ║  🐉 Ist einfach passiert.            ║"
  echo "  ║                                      ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
}

setup_env() {
  local fresh=0
  if [ ! -d "$SCRIPT_DIR/env" ]; then
    echo "  📦 Erstelle venv..."
    python3 -m venv "$SCRIPT_DIR/env"
    "$PYTHON" -m pip install --upgrade pip -q
    fresh=1
  fi
  # Requirements.txt immer syncen — idempotent, holt fehlende Dependencies nach
  if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    REQ_HASH_FILE="$SCRIPT_DIR/env/.requirements.sha1"
    NEW_HASH=$(sha1sum "$SCRIPT_DIR/requirements.txt" | awk '{print $1}')
    OLD_HASH=$(cat "$REQ_HASH_FILE" 2>/dev/null || echo "")
    if [ "$fresh" = "1" ] || [ "$NEW_HASH" != "$OLD_HASH" ]; then
      echo "  📦 Synce requirements.txt..."
      "$PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt" -q && echo "$NEW_HASH" > "$REQ_HASH_FILE"
    fi
  fi
  [ "$fresh" = "1" ] && echo "  ✅ venv erstellt"
}

wait_port_free() {
  for i in $(seq 1 10); do
    PIDS=$(lsof -t -i :$PORT 2>/dev/null || ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+')
    [ -z "$PIDS" ] && return 0
    [ "$i" -eq 5 ] && kill -9 $PIDS 2>/dev/null
    sleep 1
  done
}

# Prozess + seine gesamte Prozess-Gruppe killen (für setsid-gestartete Main + Kinder).
# Fallback: wenn PGID nicht ermittelbar oder == 0, nur den PID selbst killen.
kill_pgid() {
  local pid="$1"
  local sig="${2:-TERM}"
  [ -z "$pid" ] && return 1
  kill -0 "$pid" 2>/dev/null || return 0   # Prozess bereits tot — nichts zu tun
  local pgid
  pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
  if [ -n "$pgid" ] && [ "$pgid" != "0" ]; then
    kill "-$sig" -- "-$pgid" 2>/dev/null
  else
    kill "-$sig" "$pid" 2>/dev/null
  fi
}

# Sauberer Stop: SIGTERM für Gruppe → kurz warten → SIGKILL wenn nötig.
graceful_stop_pid() {
  local pid="$1"
  [ -z "$pid" ] && return 0
  kill -0 "$pid" 2>/dev/null || return 0
  kill_pgid "$pid" TERM
  # Graceful-Window: bis zu 3s warten (6x 500ms)
  for i in 1 2 3 4 5 6; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.5
  done
  # Immer noch am leben → hart
  kill_pgid "$pid" KILL
}

case "${1:-start}" in
  start)
    # Hasi-Diktat: start = auto-replace. Alte Instanz wird sauber gestoppt + neu gestartet.
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      OLD_PID=$(cat "$PID_FILE")
      echo "  🔄 Alte Instanz läuft (PID $OLD_PID) — stoppe sauber + restarte..."
      graceful_stop_pid "$OLD_PID"
      rm -f "$PID_FILE"
    fi
    # Fremder Prozess auf Port? → wegräumen (Zombies aus Trash-Ordnern etc.)
    FOREIGN_PIDS=$(lsof -t -i :$PORT 2>/dev/null)
    if [ -n "$FOREIGN_PIDS" ]; then
      echo "  ⚠️  Port $PORT belegt von fremdem Prozess (PID $FOREIGN_PIDS) — räume auf..."
      for p in $FOREIGN_PIDS; do graceful_stop_pid "$p"; done
      wait_port_free
    fi
    setup_env
    show_intro
    mkdir -p "$SCRIPT_DIR/logs"
    cd "$SCRIPT_DIR"

    # Hasi-Diktat 2026-05-05: Wenn keine Igni-Datei vorhanden ist, fragt
    # ShinNexus beim Start interaktiv nach Owner-PW + 2FA. start.sh holt
    # die Eingaben ab und pipet sie in den Hintergrund-Prozess, damit auch
    # ohne Igni ein headless-Start möglich ist.
    HAS_IGNI=0
    for igni_dir in "$SCRIPT_DIR"/ShinNexus-Igni*; do
      if [ -f "$igni_dir/vault_bootstrap.enc" ]; then HAS_IGNI=1; break; fi
    done

    if [ "$HAS_IGNI" -eq 0 ]; then
      echo "  🔑 Kein Igni gefunden — Owner-Login einmalig nötig"
      echo ""
      read -p "    Wahl [1=Anmelden, 2=Recovery-Seed, ENTER=1]: " CHOICE
      CHOICE="${CHOICE:-1}"
      if [ "$CHOICE" = "2" ]; then
        echo ""
        echo "  ⚠️  Recovery-Seed-Pfad ist interaktiv mehrstufig — bitte direkt starten:"
        echo "      $PYTHON $MAIN"
        echo ""
        exit 1
      fi
      read -srp "    Owner-Passwort: " PW
      echo ""
      read -rp "    2FA-Code (leer wenn deaktiviert): " TOTP
      echo ""
      echo "  🛡️ Starte ShinNexus (Erst-Login via Pipe)..."
      START_LOG="$SCRIPT_DIR/logs/start-headless.log"
      # Pipe Wahl + PW + TOTP an stdin des Hintergrund-Prozesses.
      # Output landet in start-headless.log statt /dev/null damit Crashes sichtbar sind.
      printf '%s\n%s\n%s\n' "$CHOICE" "$PW" "$TOTP" \
        | setsid "$PYTHON" "$MAIN" > "$START_LOG" 2>&1 &
      unset PW TOTP
    else
      echo "  🛡️ Starte ShinNexus..."
      setsid "$PYTHON" "$MAIN" > /dev/null 2>&1 &
    fi
    echo $! > "$PID_FILE"
    for i in $(seq 1 5); do
      sleep 1
      lsof -i :$PORT &>/dev/null && break
    done
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null && lsof -i :$PORT &>/dev/null; then
      echo ""
      echo "  ╔══════════════════════════════════════╗"
      echo "  ║  ✅ ShinNexus etabliert              ║"
      echo "  ║  🌐 https://localhost:$PORT           ║"
      echo "  ║  📋 Logs: logs/nexus.log             ║"
      echo "  ║  Terminal kann geschlossen werden.   ║"
      echo "  ╚══════════════════════════════════════╝"
      echo ""
    else
      echo "  ❌ Start fehlgeschlagen! Check logs/start-headless.log oder logs/"
      rm -f "$PID_FILE"
    fi
    exit 0
    ;;
  stop)
    # 1. Eigene Instanz aus PID-File sauber herunterfahren (inkl. Prozess-Gruppe)
    if [ -f "$PID_FILE" ]; then
      MAIN_PID=$(cat "$PID_FILE")
      graceful_stop_pid "$MAIN_PID"
      rm -f "$PID_FILE"
    fi
    # 2. Zombies/Fremdprozesse auf Port (andere Instanzen, Papierkorb-Reste etc.)
    PIDS=$(lsof -t -i :$PORT 2>/dev/null)
    for p in $PIDS; do
      graceful_stop_pid "$p"
    done
    # 3. Letztes Safety-Net falls Prozess-Gruppen-Kill was nicht erwischt hat
    wait_port_free
    echo "🛑 ShinNexus gestoppt"
    ;;
  restart)
    "$SCRIPT_PATH" stop
    wait_port_free
    "$SCRIPT_PATH" start
    ;;
  status)
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "🛡️ Läuft (PID $(cat "$PID_FILE"))"
    else
      echo "💤 Nicht aktiv"
      rm -f "$PID_FILE" 2>/dev/null
    fi
    ;;
  logs) tail -f "$SCRIPT_DIR/logs/nexus.log" ;;
  *) echo "Usage: $0 {start|stop|restart|status|logs}"; exit 1 ;;
esac
