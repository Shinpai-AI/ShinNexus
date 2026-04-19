#!/bin/bash
DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"
cd "$DIR"
if [ ! -f "$DIR/env/bin/python3" ]; then
  python3 -m venv "$DIR/env"
  "$DIR/env/bin/pip" install --upgrade pip -q
  "$DIR/env/bin/pip" install -r "$DIR/requirements.txt" -q
fi
"$DIR/env/bin/python3" "$DIR/ShinNexus.py" &
SERVER_PID=$!
for i in $(seq 1 30); do
  sleep 1
  curl -sk -o /dev/null "https://localhost:12345" 2>/dev/null && break
done
open "https://localhost:12345"
wait $SERVER_PID
