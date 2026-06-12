#!/bin/bash
# Pi Security Monitor — install script
# Run as root: sudo bash install.sh
set -e

APP_DIR="/opt/pi-security-monitor"

echo "=== Pi Security Monitor Installer ==="
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "[!] This script must be run as root (sudo bash install.sh)"
  exit 1
fi

echo "[*] Updating package list..."
apt-get update -q

echo "[*] Installing Python3 + venv..."
apt-get install -y -q python3 python3-pip python3-venv

echo "[*] Copying files to $APP_DIR..."
mkdir -p "$APP_DIR"
cp -r . "$APP_DIR/"
cd "$APP_DIR"

echo "[*] Creating Python virtual environment..."
python3 -m venv venv

echo "[*] Installing Python dependencies..."
venv/bin/pip install --quiet --upgrade pip
venv/bin/pip install --quiet -r requirements.txt

echo "[*] Installing systemd service..."
cp pi_security_monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable pi_security_monitor
systemctl restart pi_security_monitor

echo ""
echo "=== Installation complete! ==="
echo ""
echo "  Web UI: http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "  Status:  systemctl status pi_security_monitor"
echo "  Logs:    journalctl -u pi_security_monitor -f"
echo "  Stop:    systemctl stop pi_security_monitor"
echo ""

# Memory check
TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
PIHOLE_MB=$(ps aux | grep pihole | awk '{sum+=$6} END {printf "%d", sum/1024}')
echo "[*] Pi RAM: ${TOTAL_MB}MB total"
echo "[*] Pi-hole ~${PIHOLE_MB}MB in use"
echo "[*] Security Monitor RAM cap: 450MB"
echo ""
