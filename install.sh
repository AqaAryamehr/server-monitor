#!/usr/bin/env bash
# Server Monitor - one-line installer
#   curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/install.sh | sudo bash
# Extra arguments are passed to server_monitor.py, e.g.:  ... | sudo bash -s -- --port 9090
set -euo pipefail

RAW_URL="${SM_RAW_URL:-https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main}"
INSTALL_DIR="${SM_DIR:-/opt/server-monitor}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root, e.g.:  curl -fsSL <url>/install.sh | sudo bash" >&2
  exit 1
fi

# 1) Python 3
if ! command -v python3 >/dev/null 2>&1; then
  echo "Installing python3 ..."
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y python3
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y python3
  elif command -v yum     >/dev/null 2>&1; then yum install -y python3
  else echo "Could not install python3 automatically. Please install it and run again." >&2; exit 1
  fi
fi

# 2) Download the program
mkdir -p "$INSTALL_DIR"
echo "Downloading Server Monitor to $INSTALL_DIR ..."
if   command -v curl >/dev/null 2>&1; then curl -fsSL "$RAW_URL/server_monitor.py" -o "$INSTALL_DIR/server_monitor.py"
elif command -v wget >/dev/null 2>&1; then wget -q "$RAW_URL/server_monitor.py" -O "$INSTALL_DIR/server_monitor.py"
else echo "Neither curl nor wget is installed." >&2; exit 1
fi
chmod 755 "$INSTALL_DIR/server_monitor.py"

# 3) First run: asks for a username and password, then prints the panel link.
#    When this script is piped from curl, stdin is not a terminal, so reattach the real one.
if [ ! -t 0 ] && ( : < /dev/tty ) 2>/dev/null; then
  exec python3 "$INSTALL_DIR/server_monitor.py" "$@" < /dev/tty
fi
exec python3 "$INSTALL_DIR/server_monitor.py" "$@"
