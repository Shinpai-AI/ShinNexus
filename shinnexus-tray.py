#!/usr/bin/env python3
"""ShinNexus System-Tray Icon."""
import os, sys, signal, subprocess, threading, time, webbrowser, tempfile, ssl
from pathlib import Path
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')
from gi.repository import Gtk, AppIndicator3, GLib
from PIL import Image

SCRIPT_DIR = Path(__file__).resolve().parent
PORT = 12345
URL = f"https://localhost:{PORT}"
server_proc = None
status = "starting"
indicator = None

def _prepare_logo_icon():
    icon_dir = Path(tempfile.gettempdir()) / "shinnexus-icons"
    icon_dir.mkdir(exist_ok=True)
    icon_name = "shinnexus-logo"
    path = icon_dir / f"{icon_name}.png"
    if not path.exists():
        logo_path = SCRIPT_DIR / "shinnexus.png"
        if logo_path.exists():
            img = Image.open(str(logo_path)).resize((64, 64), Image.LANCZOS)
            img.save(str(path))
        else:
            from PIL import ImageDraw
            img = Image.new("RGBA", (64, 64), (0, 100, 200, 255))
            img.save(str(path))
    return str(icon_dir), icon_name

ICON_DIR, ICON_NAME = _prepare_logo_icon()

def kill_old_servers():
    try:
        result = subprocess.run(["lsof", "-t", "-i", f":{PORT}"],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            for pid in result.stdout.strip().split("\n"):
                try: os.kill(int(pid), signal.SIGTERM)
                except: pass
            time.sleep(2)
    except: pass

def update_icon(new_status):
    global status
    status = new_status
    GLib.idle_add(indicator.set_icon_full, ICON_NAME, f"ShinNexus - {new_status}")

def start_server():
    global server_proc
    kill_old_servers()
    venv_python = SCRIPT_DIR / "env" / "bin" / "python3"
    server_py = SCRIPT_DIR / "ShinNexus.py"
    if not venv_python.exists():
        update_icon("error"); return
    server_proc = subprocess.Popen(
        [str(venv_python), str(server_py)],
        cwd=str(SCRIPT_DIR),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(30):
        time.sleep(1)
        if server_proc.poll() is not None:
            update_icon("error"); return
        try:
            urllib.request.urlopen(URL, timeout=2, context=ctx)
            update_icon("running")
            webbrowser.open(URL)
            return
        except: pass
    update_icon("error")

def monitor_server():
    while True:
        time.sleep(5)
        if server_proc and server_proc.poll() is not None:
            if status != "error": update_icon("error")

def on_open(_): webbrowser.open(URL)
def on_status(_):
    msgs = {"running": f"Server läuft auf Port {PORT}",
            "starting": "Server startet...",
            "error": "Server-Fehler! Logs prüfen."}
    d = Gtk.MessageDialog(message_type=Gtk.MessageType.INFO,
                          buttons=Gtk.ButtonsType.OK,
                          text="ShinNexus", secondary_text=msgs.get(status, "Unbekannt"))
    d.run(); d.destroy()
def on_quit(_):
    if server_proc:
        server_proc.terminate()
        try: server_proc.wait(timeout=5)
        except: server_proc.kill()
    Gtk.main_quit()

def main():
    global indicator
    indicator = AppIndicator3.Indicator.new(
        "shinnexus-tray", ICON_NAME,
        AppIndicator3.IndicatorCategory.APPLICATION_STATUS)
    indicator.set_icon_theme_path(ICON_DIR)
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
    menu = Gtk.Menu()
    for label, handler in [("ShinNexus öffnen", on_open), ("Status", on_status)]:
        item = Gtk.MenuItem(label=label)
        item.connect("activate", handler)
        menu.append(item)
    menu.append(Gtk.SeparatorMenuItem())
    item = Gtk.MenuItem(label="Beenden")
    item.connect("activate", on_quit)
    menu.append(item)
    menu.show_all()
    indicator.set_menu(menu)
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=monitor_server, daemon=True).start()
    Gtk.main()

if __name__ == "__main__":
    main()
