#!/usr/bin/env python3
"""
Pi Security Monitor — lightweight security monitoring for Raspberry Pi 3B+
Run as root. Designed for <500MB RAM, ARM Cortex-A53, alongside Pi-hole.
"""
from flask import Flask, render_template, jsonify, request
import psutil, subprocess, os, hashlib, threading, time, json
from datetime import datetime

app = Flask(__name__)

# ── CONFIG ──────────────────────────────────────────────────────────────────
PORT = 5000

LOG_FILES = {
    'auth':    '/var/log/auth.log',
    'syslog':  '/var/log/syslog',
    'kern':    '/var/log/kern.log',
    'daemon':  '/var/log/daemon.log',
    'dpkg':    '/var/log/dpkg.log',
    'fail2ban':'/var/log/fail2ban.log',
    'ufw':     '/var/log/ufw.log',
}

INTEGRITY_FILES = [
    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
    '/etc/hosts', '/etc/hostname', '/etc/fstab',
    '/etc/ssh/sshd_config', '/etc/ssh/ssh_config',
    '/etc/crontab', '/etc/rc.local',
    '/bin/bash', '/usr/bin/sudo', '/usr/bin/passwd',
    '/boot/cmdline.txt', '/boot/config.txt',
]

# ── TTL CACHE (thread-safe, no deps) ────────────────────────────────────────
_cache: dict = {}
_lock = threading.Lock()

def cached(key: str, ttl: float, fn, *args, **kw):
    now = time.monotonic()
    with _lock:
        entry = _cache.get(key)
        if entry and now - entry[1] < ttl:
            return entry[0]
    val = fn(*args, **kw)
    with _lock:
        _cache[key] = (val, now)
    return val

def invalidate(key: str):
    with _lock:
        _cache.pop(key, None)

# ── COLLECTORS ───────────────────────────────────────────────────────────────

def _tail(path: str, n: int) -> list[str]:
    if not os.path.exists(path):
        return [f'[file not found: {path}]']
    try:
        r = subprocess.run(['tail', '-n', str(n), path],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.splitlines() if r.returncode == 0 else [f'[tail error: {r.stderr.strip()}]']
    except Exception as e:
        return [f'[error: {e}]']


def _sysinfo() -> dict:
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    temp = None
    # vcgencmd (Pi-native)
    try:
        r = subprocess.run(['vcgencmd', 'measure_temp'],
                           capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            temp = float(r.stdout.strip().replace("temp=","").replace("'C",""))
    except Exception:
        pass
    if temp is None:
        try:
            temps = psutil.sensors_temperatures()
            for key in ('cpu_thermal','cpu-thermal','coretemp'):
                if key in temps and temps[key]:
                    temp = round(temps[key][0].current, 1)
                    break
        except Exception:
            pass

    load = [0.0, 0.0, 0.0]
    try:
        load = list(os.getloadavg())
    except Exception:
        pass

    return {
        'cpu': cpu,
        'cpu_count': psutil.cpu_count(),
        'mem_total': mem.total, 'mem_used': mem.used,
        'mem_free': mem.available, 'mem_pct': mem.percent,
        'disk_total': disk.total, 'disk_used': disk.used, 'disk_pct': disk.percent,
        'temp': temp,
        'load': [round(x, 2) for x in load],
        'uptime': int(time.time() - psutil.boot_time()),
        'ts': datetime.now().strftime('%H:%M:%S'),
    }


def _processes() -> list[dict]:
    procs = []
    attrs = ['pid','ppid','name','username','cpu_percent','memory_percent','status','cmdline']
    for p in psutil.process_iter(attrs):
        try:
            i = p.info
            cmd = (' '.join(i.get('cmdline') or []))[:120] or (i.get('name') or '?')
            procs.append({
                'pid':  i['pid'],
                'ppid': i.get('ppid') or 0,
                'name': (i.get('name') or '?')[:30],
                'user': ((i.get('username') or 'N/A'))[:16],
                'cpu':  round(i.get('cpu_percent') or 0, 1),
                'mem':  round(i.get('memory_percent') or 0, 2),
                'status': i.get('status','?'),
                'cmd':  cmd,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    procs.sort(key=lambda x: x['cpu'], reverse=True)
    return procs[:150]


def _network() -> dict:
    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            try:
                conns.append({
                    'proto':  'TCP' if c.type.value == 1 else 'UDP',
                    'laddr':  f'{c.laddr.ip}:{c.laddr.port}' if c.laddr else '',
                    'raddr':  f'{c.raddr.ip}:{c.raddr.port}' if c.raddr else '',
                    'status': c.status or '',
                    'pid':    c.pid or 0,
                })
            except Exception:
                pass
    except Exception:
        pass

    ifaces = {}
    try:
        for name, s in psutil.net_io_counters(pernic=True).items():
            ifaces[name] = {
                'sent': s.bytes_sent, 'recv': s.bytes_recv,
                'errin': s.errin, 'errout': s.errout,
                'dropin': s.dropin, 'dropout': s.dropout,
            }
    except Exception:
        pass

    return {'connections': conns[:300], 'total': len(conns), 'interfaces': ifaces}


def _services() -> list[dict]:
    try:
        r = subprocess.run(
            ['systemctl','list-units','--type=service','--all',
             '--no-pager','--no-legend','--plain'],
            capture_output=True, text=True, timeout=15)
        out = []
        for line in r.stdout.splitlines():
            p = line.split(None, 4)
            if len(p) >= 4:
                out.append({'name': p[0], 'load': p[1], 'active': p[2],
                            'sub': p[3], 'desc': p[4].strip() if len(p) > 4 else ''})
        return out
    except Exception:
        return []


def _list_files(d: str) -> list[str]:
    try:
        return [os.path.join(d, f) for f in os.listdir(d)
                if os.path.isfile(os.path.join(d, f))]
    except Exception:
        return []


def _cronjobs() -> list[dict]:
    crons = []
    sources = ['/etc/crontab'] + _list_files('/etc/cron.d')
    for src in sources:
        try:
            with open(src) as f:
                for line in f:
                    l = line.strip()
                    if l and not l.startswith('#'):
                        crons.append({'source': src, 'entry': l})
        except PermissionError:
            crons.append({'source': src, 'entry': '[permission denied]'})
        except Exception:
            pass

    for d, label in [('/etc/cron.hourly','hourly'),('/etc/cron.daily','daily'),
                     ('/etc/cron.weekly','weekly'),('/etc/cron.monthly','monthly')]:
        for f in _list_files(d):
            crons.append({'source': f'@{label}', 'entry': os.path.basename(f)})

    try:
        r = subprocess.run(['crontab','-l'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                l = line.strip()
                if l and not l.startswith('#'):
                    crons.append({'source': f'user:{os.environ.get("USER","root")}', 'entry': l})
    except Exception:
        pass

    return crons


def _autostart() -> list[dict]:
    items = []
    try:
        r = subprocess.run(
            ['systemctl','list-unit-files','--type=service','--state=enabled',
             '--no-pager','--no-legend'],
            capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            p = line.split()
            if p:
                items.append({'type':'systemd', 'name': p[0],
                              'state': p[1] if len(p) > 1 else 'enabled', 'notes':''})
    except Exception:
        pass

    if os.path.exists('/etc/rc.local'):
        try:
            with open('/etc/rc.local') as f:
                content = f.read(800)
            items.append({'type':'rc.local','name':'/etc/rc.local','state':'exists','notes': content[:120]})
        except Exception:
            items.append({'type':'rc.local','name':'/etc/rc.local','state':'exists','notes':''})

    for f in _list_files('/etc/init.d'):
        items.append({'type':'init.d','name':os.path.basename(f),'state':'present','notes':''})

    for d in ['/etc/xdg/autostart', os.path.expanduser('~/.config/autostart')]:
        for f in _list_files(d):
            items.append({'type':'xdg','name':os.path.basename(f),'state':'present','notes':''})

    return items


def _packages() -> list[dict]:
    try:
        r = subprocess.run(
            ['dpkg-query','-W','-f=${Package}\t${Version}\t${Installed-Size}\n'],
            capture_output=True, text=True, timeout=30)
        pkgs = []
        for line in r.stdout.splitlines():
            p = line.split('\t')
            if len(p) >= 2:
                try:
                    size = int(p[2]) if len(p) > 2 and p[2].strip().isdigit() else 0
                except ValueError:
                    size = 0
                pkgs.append({'name': p[0], 'version': p[1], 'size': size})
        pkgs.sort(key=lambda x: x['size'], reverse=True)
        return pkgs[:600]
    except Exception:
        return []


def _hash(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()[:20]
    except PermissionError:
        return 'PERM_DENIED'
    except FileNotFoundError:
        return 'NOT_FOUND'
    except Exception as e:
        return f'ERR:{str(e)[:20]}'


_baseline: dict[str, str] = {}

def _integrity() -> list[dict]:
    results = []
    for path in INTEGRITY_FILES:
        cur = _hash(path)
        base = _baseline.get(path)
        if base is None:
            status = 'no-baseline'
        elif cur in ('PERM_DENIED','NOT_FOUND') or cur.startswith('ERR'):
            status = 'error'
        elif cur == base:
            status = 'ok'
        else:
            status = 'CHANGED'

        mtime = ''
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M')
        except Exception:
            pass

        results.append({
            'path': path, 'hash': cur, 'baseline': base or '',
            'status': status, 'mtime': mtime,
        })
    return results


# ── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/sysinfo')
def api_sysinfo():
    return jsonify(cached('sysinfo', 3, _sysinfo))

@app.route('/api/logs/<log_type>')
def api_logs(log_type):
    if log_type not in LOG_FILES:
        return jsonify({'error': 'unknown'}), 400
    n = min(int(request.args.get('n', 100)), 500)
    path = LOG_FILES[log_type]
    lines = cached(f'log:{log_type}:{n}', 8, _tail, path, n)
    return jsonify({'lines': lines, 'file': path, 'available': os.path.exists(path)})

@app.route('/api/processes')
def api_processes():
    return jsonify({'processes': cached('procs', 3, _processes)})

@app.route('/api/network')
def api_network():
    return jsonify(cached('net', 3, _network))

@app.route('/api/services')
def api_services():
    return jsonify({'services': cached('svcs', 8, _services)})

@app.route('/api/cronjobs')
def api_cronjobs():
    return jsonify({'crons': cached('crons', 30, _cronjobs)})

@app.route('/api/autostart')
def api_autostart():
    return jsonify({'autostart': cached('autostart', 30, _autostart)})

@app.route('/api/packages')
def api_packages():
    return jsonify({'packages': cached('pkgs', 60, _packages)})

@app.route('/api/integrity')
def api_integrity():
    return jsonify({'files': cached('integrity', 20, _integrity)})

@app.route('/api/integrity/baseline', methods=['POST'])
def api_set_baseline():
    global _baseline
    count = 0
    for path in INTEGRITY_FILES:
        h = _hash(path)
        if h not in ('PERM_DENIED','NOT_FOUND') and not h.startswith('ERR'):
            _baseline[path] = h
            count += 1
    invalidate('integrity')
    return jsonify({'ok': True, 'baselined': count})


if __name__ == '__main__':
    print(f'[*] Pi Security Monitor — http://0.0.0.0:{PORT}')
    print(f'[*] Monitoring {len(INTEGRITY_FILES)} integrity files')
    # Auto-baseline readable files on startup
    for p in INTEGRITY_FILES:
        h = _hash(p)
        if h not in ('PERM_DENIED','NOT_FOUND') and not h.startswith('ERR'):
            _baseline[p] = h
    print(f'[*] Baseline set for {len(_baseline)} files')
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
