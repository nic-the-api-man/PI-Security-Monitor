# Pi Security Monitor

A lightweight, self-hosted security monitoring dashboard for Raspberry Pi. Runs alongside Pi-hole with a low resource footprint, accessible from any browser on your local network.

---

## Features

| Area | What it shows |
|---|---|
| **Dashboard** | CPU, memory, disk, temperature, load, uptime, recent auth and syslog events |
| **SSH Alerts** | Live feed of login attempts — successes, failures, invalid users, source IPs |
| **Logs** | Tail and filter auth, syslog, kernel, daemon, DPKG, Fail2ban, UFW |
| **Processes** | Full process list sortable by CPU, memory, PID, name, or user |
| **Network** | Active connections with status filter, interface I/O statistics |
| **Services** | All systemd services — filter by active/inactive/failed |
| **Integrity** | SHA-256 hashes of critical system files, baseline comparison |
| **Packages** | Full installed package list with versions and sizes |
| **Investigate** | Cron jobs (all sources) and autostart items |
| **Snapshots** | Point-in-time capture of everything above, stored as JSON, browsable in-dashboard |

---

## Requirements

- Raspberry Pi running Raspberry Pi OS (Debian-based)
- Python 3.9+
- Run as root (required for process, network, and log access)

---

## Installation

```bash
git clone https://github.com/nic-the-api-man/PI-Security-Monitor.git
cd PI-Security-Monitor
sudo bash install.sh
```

The installer will:
- Install Python 3 and create a virtual environment
- Install Flask and psutil
- Copy the app to `/opt/pi-security-monitor/`
- Install and enable a systemd service
- Install a 30-day log rotation policy

**Set your password before use:**

```bash
echo "MONITOR_PASSWORD=your-secure-password" | sudo tee /opt/pi-security-monitor/.env
sudo chmod 600 /opt/pi-security-monitor/.env
sudo systemctl restart pi_security_monitor
```

Then open `http://<your-pi-ip>:5000` in a browser.

---

## Manual Run (no systemd)

```bash
git clone https://github.com/nic-the-api-man/PI-Security-Monitor.git
cd PI-Security-Monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export MONITOR_PASSWORD=your-secure-password
sudo python3 app.py
```

---

## Updating

```bash
cd /opt/pi-security-monitor
sudo git pull origin main
sudo systemctl restart pi_security_monitor
```

---

## Log Files

The dashboard reads standard syslog files (`auth.log`, `syslog`, `kern.log`, etc.). These require `rsyslog` to be installed:

```bash
sudo apt install rsyslog -y
sudo systemctl enable --now rsyslog
```

Without rsyslog, log tabs will show "file not available" but all other features work normally.

---

## Snapshots

Clicking **Take Snapshot** captures the full system state at that moment — processes, network, services, logs, packages, integrity hashes, SSH events, cron jobs — and saves it as a JSON file in `/opt/pi-security-monitor/snapshots/`. Snapshots can be browsed in full from the dashboard.

---

## Service Management

```bash
# Status
systemctl status pi_security_monitor

# Live logs
journalctl -u pi_security_monitor -f

# Restart
sudo systemctl restart pi_security_monitor

# Stop
sudo systemctl stop pi_security_monitor
```

---

## Security Considerations

**Authentication**
- Set a strong `MONITOR_PASSWORD` before use. A missing or weak password gives anyone on your network full visibility into processes, connections, SSH history, and system logs.
- The `.env` file stores your password in plaintext. Keep it root-only: `chmod 600 /opt/pi-security-monitor/.env`

**Network Exposure**
- The dashboard binds to `0.0.0.0:5000` and is reachable by every device on your local network. **Do not expose port 5000 to the internet.**
- For remote access, use an SSH tunnel rather than opening the port: `ssh -L 5000:localhost:5000 pi@<pi-ip>` then browse to `localhost:5000`.
- There is no HTTPS. Credentials travel as plaintext over the local network.

**Running as Root**
- Root is required to read shadow files, network connections, and system logs. Keep dependencies updated: `cd /opt/pi-security-monitor && venv/bin/pip install --upgrade flask psutil`

**Snapshot Files**
- Snapshots contain sensitive system data. Restrict the directory: `chmod 700 /opt/pi-security-monitor/snapshots`
- Do not share snapshot files without reviewing their contents.

**Limitations**
- This tool monitors and records — it does not block attacks or alert in real time.
- File integrity checking detects changes after the fact; it does not prevent tampering.
- SSH event parsing depends on log files being present and unaltered.

---

## Stack

- **Backend:** Python 3, Flask
- **System data:** psutil, subprocess (systemctl, journalctl, tail)
- **Frontend:** Vanilla HTML/CSS/JS — no build step, no npm, no frameworks
- **Auth:** Flask sessions with a persisted secret key
- **Storage:** JSON files for snapshots, no database

---

## License

MIT
