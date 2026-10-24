#!/usr/bin/env python3
"""
server_monitor.py - live monitoring panel for Linux servers: network traffic, CPU, RAM and disk (every second),
24-hour history, Telegram alerts, and multi-server support (add other servers as "nodes").

No external dependencies (Python 3.7+, Linux).

Main panel:   python3 server_monitor.py
              -> first run asks for a username and password for the web panel, then prints the panel link.
Add a server: open the panel -> Settings -> Add server, and run the command it shows on the other server.
              (manually: python3 server_monitor.py --node http://MAIN-PANEL:8080 --token TOKEN)
Change login: python3 server_monitor.py --reset
Options:      --host 0.0.0.0  --port N  --cert cert.pem --key key.pem (HTTPS)   (the port is asked during setup)
"""
import argparse
import bisect
import collections
import getpass
import gzip
import hashlib
import html as _html
import hmac
import http.client
import http.cookies
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from array import array
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

VERSION = "1.2.0"
LAUNCHER = "/usr/local/bin/server-monitor"  # the `server-monitor update|uninstall|status|restart` command
UNIT_DIR = "/etc/systemd/system"
UNITS = ("server-monitor", "server-monitor-node")  # panel service, node service
try:
    with open(os.path.abspath(__file__), "rb") as _f:
        SCRIPT_HASH = hashlib.sha256(_f.read()).hexdigest()[:12]  # identifies this exact version of the file
except OSError:
    SCRIPT_HASH = ""

RECENT_SAMPLES = 300    # latest complete samples kept for the live view
DAY_SECONDS = 86400     # history kept on disk
SEG = 30                # history granularity in seconds: one file / one chart point base per 30 s
SESSION_TTL = 7 * 24 * 3600
LOCAL_ID = "local"      # id of the server that runs the panel
ARGS = None
CRED = None  # saved login: user + salted PBKDF2 hash (the password itself is never stored)

lock = threading.Lock()
REVOKED = set()  # tokens logged out since start
FAILS = {}       # key (ip) -> (failed attempts, window start)


# ---------------------------------------------------------------- data collection
def read_cpu():
    out = {}
    with open("/proc/stat") as f:
        for line in f:
            if not line.startswith("cpu"):
                break
            p = line.split()
            v = [int(x) for x in p[1:9]]
            out[p[0]] = (sum(v), v[3] + v[4])  # total, idle+iowait
    return out


def read_net():
    out = {}
    with open("/proc/net/dev") as f:
        for line in list(f)[2:]:
            name, data = line.split(":", 1)
            c = data.split()
            out[name.strip()] = (int(c[0]), int(c[8]))  # rx, tx bytes
    return out


def read_mem():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            m[k] = int(v.split()[0]) * 1024
    total = m["MemTotal"]
    avail = m.get("MemAvailable", m["MemFree"])
    return {
        "total": total,
        "used": total - avail,
        "swap_total": m.get("SwapTotal", 0),
        "swap_used": m.get("SwapTotal", 0) - m.get("SwapFree", 0),
    }


def read_disk(path="/"):
    """Usage of the root filesystem, computed like `df` (percentage = used / (used + available))."""
    try:
        st = os.statvfs(path)
    except OSError:
        return {"total": 0, "used": 0}
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    return {"total": used + st.f_bavail * st.f_frsize, "used": used}


class Collector:
    """Produces one sample per call; rates are computed from the previous call."""

    def __init__(self):
        self.prev_cpu, self.prev_net, self.prev_t = read_cpu(), read_net(), time.time()

    def wait(self):
        time.sleep(max(0.05, 1 - (time.time() - self.prev_t) % 1))

    def sample(self):
        now = time.time()
        dt = max(now - self.prev_t, 0.001)
        cpu, net = read_cpu(), read_net()

        pct = {}
        for k, (t, i) in cpu.items():
            pt, pi = self.prev_cpu.get(k, (t, i))
            dtot = t - pt
            pct[k] = round(100 * (1 - (i - pi) / dtot), 1) if dtot > 0 else 0.0

        rates = {}
        for k, (rx, tx) in net.items():
            prx, ptx = self.prev_net.get(k, (rx, tx))
            rates[k] = [round(max(0, (rx - prx) / dt)), round(max(0, (tx - ptx) / dt))]

        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])

        self.prev_cpu, self.prev_net, self.prev_t = cpu, net, now
        return {
            "t": int(now * 1000),
            "cpu": pct.get("cpu", 0.0),
            "cores": [pct[k] for k in sorted((k for k in pct if k != "cpu"), key=lambda s: int(s[3:]))],
            "mem": read_mem(),
            "net": rates,
            "load": list(os.getloadavg()),
            "uptime": int(uptime),
            "disk": read_disk(),
        }


def local_sampler(src):
    c = Collector()
    while True:
        c.wait()
        try:
            src.add(c.sample())
        except Exception as e:  # never let the sampler thread die
            print(f"sampler error: {e}", file=sys.stderr)
            time.sleep(1)


# ---------------------------------------------------------------- sessions / login
def _load_secret(path):
    try:
        with open(path, "rb") as f:
            k = f.read()
        if len(k) >= 32:
            return k
    except OSError:
        pass
    k = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k)
    except OSError:
        pass  # fall back to a per-run secret
    return k


KEY = b""  # set in main(); derived from a random secret + the saved login


def _sig(exp_s):
    return hmac.new(KEY, exp_s.encode(), "sha256").hexdigest()


def new_session():
    exp = str(int(time.time()) + SESSION_TTL)
    return exp + "." + _sig(exp)


def auth_state(tok):
    """'ok' or the reason the session is not accepted."""
    if not tok:
        return "no_cookie"
    with lock:
        if tok in REVOKED:
            return "logged_out"
    exp_s, _, sig = tok.partition(".")
    if not exp_s.isdigit() or not hmac.compare_digest(sig, _sig(exp_s)):
        return "bad_token"
    if int(exp_s) < time.time():
        return "expired"
    return "ok"


def login_blocked(ip):
    with lock:
        c, t = FAILS.get(ip, (0, 0))
        if time.time() - t > 300:
            FAILS.pop(ip, None)
            return False
        return c >= 5


def record_fail(ip):
    with lock:
        c, t = FAILS.get(ip, (0, time.time()))
        if time.time() - t > 300:
            c, t = 0, time.time()
        FAILS[ip] = (c + 1, t)


def _line_t(line):
    try:
        return int(line[1:line.index(",")])
    except ValueError:
        return 0  # damaged line: treat it as old so it gets removed


class Store:
    """History on disk: one small file per 30 seconds, one JSON line per second.
    It keeps exactly the newest 24 hours: every second, the one second that has just become older than 24 hours
    is deleted from the oldest file (a file disappears when it is empty), so the disk usage stays constant."""

    def __init__(self, directory):
        self.dir, self.fh, self.cur, self.ok = directory, None, None, True
        self.files = []  # indexes of the .seg files, oldest first
        try:
            os.makedirs(directory, exist_ok=True)
            self.files = sorted(int(n[:-4]) for n in os.listdir(directory) if n[:-4].isdigit() and n[-4:] == ".seg")
        except OSError as e:
            self._fail(e)

    def _fail(self, e):
        if self.ok:
            print(f"WARNING: history is not being saved to disk ({e}).", file=sys.stderr)
        self.ok = False

    def write(self, s):
        if not self.ok:
            return
        try:
            k = s["t"] // (SEG * 1000)
            if k != self.cur:
                if self.fh:
                    self.fh.close()
                self.fh = open(os.path.join(self.dir, f"{k}.seg"), "a")
                self.cur = k
                if k not in self.files:
                    self.files.append(k)
                    self.files.sort()
                self.prune_legacy(k)
            net = {n: v for n, v in s["net"].items() if v[0] or v[1]}  # idle interfaces are omitted
            d = s.get("disk") or {}
            self.fh.write(json.dumps([s["t"], s["cpu"], s["mem"]["used"], net, s["mem"]["total"], d.get("used", 0), d.get("total", 0)], separators=(",", ":")) + "\n")
            self.fh.flush()
            self.trim(s["t"])
        except OSError as e:
            self._fail(e)

    def trim(self, now_ms):
        """Remove everything older than 24 hours before now_ms (normally exactly one second of the oldest file)."""
        cutoff = now_ms - DAY_SECONDS * 1000
        while self.files:
            k = self.files[0]
            if k == self.cur:
                return
            path = os.path.join(self.dir, f"{k}.seg")
            if (k + 1) * SEG * 1000 <= cutoff:  # the whole file is older than the window
                _remove(path)
                del self.files[0]
                continue
            if k * SEG * 1000 >= cutoff:        # the whole file is inside the window
                return
            try:
                with open(path) as f:
                    lines = f.readlines()
            except OSError:
                del self.files[0]
                continue
            keep = [ln for ln in lines if _line_t(ln) >= cutoff]
            if len(keep) == len(lines):
                return
            if keep:
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    f.writelines(keep)
                os.replace(tmp, path)
                return
            _remove(path)
            del self.files[0]

    def prune_legacy(self, k):
        """Files of older program versions (one file per minute)."""
        keep_from_ms = (k - DAY_SECONDS // SEG + 1) * SEG * 1000
        for name in os.listdir(self.dir):
            if name[-4:] == ".min" and name[:-4].isdigit() and (int(name[:-4]) + 1) * 60000 <= keep_from_ms:
                _remove(os.path.join(self.dir, name))


# ---------------------------------------------------------------- servers (the local one and connected nodes)
SOURCES = {}  # server id -> Source
SOURCES_LOCK = threading.RLock()
SETTINGS_LOCK = threading.RLock()
NODES_LOCK = threading.RLock()
DATA_DIR = ""
SETTINGS_PATH = ""
NODES_PATH = ""
NODE_ID_RE = re.compile(r"^n[0-9a-f]{8}$")


def save_json(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _pct(used, total):
    return round(100 * used / total, 1) if total else 0.0


U32 = 0xFFFFFFFF
MAX_IFACES = 16  # busier interfaces get their own column; the rest are summed into "other"


class Series:
    """The last 24 hours, one entry per second, stored compactly in arrays (a few MB per server)."""

    def __init__(self):
        self.t = array("q")                    # timestamps in ms
        self.cpu = array("H")                  # CPU % x 10
        self.mu = array("I")                   # memory used, MB
        self.du = array("I")                   # disk used, MB
        self.net = {}                          # interface -> [rx, tx] arrays in bytes/s
        self.all = [array("I"), array("I")]    # traffic of all interfaces except lo
        self.mt = self.dt = 0                  # memory / disk totals in bytes (latest)

    def _cols(self):
        yield from (self.t, self.cpu, self.mu, self.du, self.all[0], self.all[1])
        for rx, tx in self.net.values():
            yield rx
            yield tx

    @staticmethod
    def _zeros(n):
        a = array("I")
        a.frombytes(bytes(a.itemsize * n))
        return a

    def append(self, t, cpu, mem_used, mem_total, disk_used, disk_total, net):
        n = len(self.t)
        if n and t <= self.t[-1]:
            return False
        self.t.append(int(t))
        self.cpu.append(min(int(cpu * 10), 65535))
        self.mu.append(min(int(mem_used) >> 20, U32))
        self.du.append(min(int(disk_used) >> 20, U32))
        self.mt = int(mem_total) or self.mt
        self.dt = int(disk_total) or self.dt
        vals, allrx, alltx, newcols = {}, 0, 0, 0
        for name, v in net.items():
            rx, tx = int(v[0]), int(v[1])
            if name != "lo":
                allrx += rx
                alltx += tx
            if not (rx or tx) and name not in self.net:
                continue  # idle interfaces get no column until they carry traffic
            if name not in self.net and name not in vals:
                if len(self.net) + newcols >= MAX_IFACES:
                    name = "other"
                else:
                    newcols += 1
            a = vals.setdefault(name, [0, 0])
            a[0] += rx
            a[1] += tx
        for name, (rx, tx) in vals.items():
            if name not in self.net:
                self.net[name] = [self._zeros(n), self._zeros(n)]  # zeros for the seconds before it appeared
            self.net[name][0].append(min(rx, U32))
            self.net[name][1].append(min(tx, U32))
        for name, col in self.net.items():
            if name not in vals:
                col[0].append(0)
                col[1].append(0)
        self.all[0].append(min(allrx, U32))
        self.all[1].append(min(alltx, U32))
        cut = int(t) - DAY_SECONDS * 1000
        if self.t[0] < cut - 60_000:  # drop what is older than 24 h, in batches
            k = bisect.bisect_left(self.t, cut)
            for col in self._cols():
                del col[:k]
        return True


class Source:
    """All data of one monitored server: the last 24 hours (one value per second), the latest samples,
    the disk store and the alert state."""

    def __init__(self, sid, name, directory, local=False):
        self.id, self.name, self.dir, self.local = sid, name, directory, local
        self.history = collections.deque(maxlen=RECENT_SAMPLES)
        self.series = Series()
        self.lock = threading.RLock()
        self.store = Store(directory)
        self.last_rx = 0.0  # wall-clock time the last sample arrived
        self.meta = {"host": socket.gethostname() if local else "", "cores": os.cpu_count() if local else 0}
        self.alerts = Alerts(self)

    # ---- ingest
    def add(self, s):
        with self.lock:
            if self.history and s["t"] <= self.history[-1]["t"]:
                return False
            self.history.append(s)
            d = s.get("disk") or {}
            self.series.append(s["t"], s["cpu"], s["mem"]["used"], s["mem"]["total"], d.get("used", 0), d.get("total", 0), s["net"])
            self.last_rx = time.time()
            self.store.write(s)
        self.alerts.feed(s)
        return True

    # ---- queries
    def poll(self, since):
        with self.lock:
            if since:
                return [x for x in self.history if x["t"] > since][-120:]
            return list(self.history)[-1:]

    def series_json(self, window, iface, since=0):
        """One value per second for the last `window` seconds (or only the seconds after `since`), as columns."""
        window = max(10, min(DAY_SECONDS, window))
        cutoff = int(time.time() * 1000) - window * 1000
        with self.lock:
            sr = self.series
            i = bisect.bisect_left(sr.t, cutoff)
            if since:
                i = max(i, bisect.bisect_right(sr.t, since))
            n = len(sr.t) - i
            if n <= 0:
                return {"n": 0}
            tl = sr.t[i:].tolist()
            rx, tx = sr.all if iface == "__all__" else (sr.net.get(iface) or (None, None))
            return {"n": n, "t": [tl[0]] + [tl[j] - tl[j - 1] for j in range(1, n)],  # first value absolute, then deltas (ms)
                    "cpu": sr.cpu[i:].tolist(), "mu": sr.mu[i:].tolist(), "du": sr.du[i:].tolist(),
                    "mt": sr.mt, "dt": sr.dt,
                    "rx": [(v + 62) // 125 for v in rx[i:]] if rx is not None else [0] * n,  # units of 125 B/s (1 kbit/s)
                    "tx": [(v + 62) // 125 for v in tx[i:]] if tx is not None else [0] * n}

    def online(self):
        return self.local or (self.last_rx > 0 and time.time() - self.last_rx < 10)

    def info(self):
        with self.lock:
            s = self.history[-1] if self.history else None
        out = {"id": self.id, "name": self.name, "host": self.meta.get("host", ""), "cores": self.meta.get("cores", 0),
               "local": self.local, "online": self.online(), "last_seen": s["t"] if s else 0, "auth": True,
               "version": self.meta.get("ver") or (VERSION if self.local else ""),
               "outdated": (not self.local) and bool(self.meta.get("host")) and self.meta.get("hash", "") != SCRIPT_HASH}
        if s:
            d = s.get("disk") or {}
            out.update(cpu=s["cpu"], ram=_pct(s["mem"]["used"], s["mem"]["total"]), disk=_pct(d.get("used", 0), d.get("total", 0)))
        return out

    # ---- restore from disk (so charts survive restarts)
    def load(self):
        try:
            entries = sorted((int(n[:-4]) * (SEG if n[-4:] == ".seg" else 60), n) for n in os.listdir(self.dir)
                             if n[:-4].isdigit() and n[-4:] in (".seg", ".min"))
        except OSError:
            return 0
        cutoff = int(time.time() * 1000) - DAY_SECONDS * 1000
        fallback_total = read_mem()["total"] if self.local else 0
        recent, count = collections.deque(maxlen=RECENT_SAMPLES), 0
        for _, name in entries:
            try:
                with open(os.path.join(self.dir, name)) as f:
                    for line in f:
                        try:
                            p = json.loads(line)
                            t, cpu, mu, net = int(p[0]), float(p[1]), int(p[2]), p[3]
                            mt = int(p[4]) if len(p) > 4 else fallback_total
                            du, dtot = (int(p[5]), int(p[6])) if len(p) > 6 else (0, 0)
                            if t >= cutoff and isinstance(net, dict) and self.series.append(t, cpu, mu, mt, du, dtot, net):
                                count += 1
                                recent.append({"t": t, "cpu": cpu, "cores": [], "load": [0, 0, 0], "uptime": 0, "net": net,
                                               "mem": {"total": mt, "used": mu, "swap_total": 0, "swap_used": 0},
                                               "disk": {"total": dtot, "used": du}})
                        except (ValueError, TypeError, IndexError):
                            continue
            except OSError:
                continue
        self.history.extend(recent)
        return count


# ---------------------------------------------------------------- settings and Telegram alerts
DEFAULT_TG = {"enabled": False, "offline": True, "token": "", "chat_id": "", "threshold": 80, "proxy": "",
              "api_base": "https://api.telegram.org"}
SETTINGS = {"local_name": "", "telegram": dict(DEFAULT_TG)}
TG_STATUS = {"ok": None, "msg": "", "time": 0}


def load_settings():
    d = load_json(SETTINGS_PATH, {}) or {}
    with SETTINGS_LOCK:
        SETTINGS["local_name"] = str(d.get("local_name", ""))[:40]
        SETTINGS["telegram"] = dict(DEFAULT_TG, **{k: v for k, v in (d.get("telegram") or {}).items() if k in DEFAULT_TG})


def local_name():
    with SETTINGS_LOCK:
        return SETTINGS["local_name"] or socket.gethostname()


def public_settings():
    with SETTINGS_LOCK:
        tg = dict(SETTINGS["telegram"])
        token = tg.pop("token")
        tg["token_set"] = bool(token)
        tg["token_hint"] = "…" + token[-4:] if token else ""
        return {"local_name": SETTINGS["local_name"], "telegram": tg, "tg_status": dict(TG_STATUS), "bot": dict(BOT_STATUS)}


def update_settings(data):
    """Validate and store settings. Returns an error message or '' on success."""
    if not isinstance(data, dict):
        return "Bad request"
    with SETTINGS_LOCK:
        new = {"local_name": SETTINGS["local_name"], "telegram": dict(SETTINGS["telegram"])}
        if "local_name" in data:
            new["local_name"] = str(data["local_name"]).strip()[:40]
        t = data.get("telegram")
        if isinstance(t, dict):
            g = new["telegram"]
            if "enabled" in t:
                g["enabled"] = bool(t["enabled"])
            if "offline" in t:
                g["offline"] = bool(t["offline"])
            if t.get("token"):
                tok = str(t["token"]).strip()
                if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,80}", tok):
                    return "That does not look like a bot token (expected 123456789:ABC...)."
                g["token"] = tok
            if "chat_id" in t:
                cid = str(t["chat_id"]).strip()
                if cid and not re.fullmatch(r"-?\d{3,20}|@[A-Za-z0-9_]{4,64}", cid):
                    return "Chat ID must be a number (for example 123456789) or @channelname."
                g["chat_id"] = cid
            if "threshold" in t:
                try:
                    th = int(t["threshold"])
                except (TypeError, ValueError):
                    return "The limit must be a number between 1 and 100."
                if not 1 <= th <= 100:
                    return "The limit must be a number between 1 and 100."
                g["threshold"] = th
            if "proxy" in t:
                px = str(t["proxy"]).strip()
                if px and not re.fullmatch(r"https?://[^\s/]+(:\d+)?/?", px):
                    return "Proxy must look like http://host:port"
                g["proxy"] = px.rstrip("/")
            if "api_base" in t:
                base = str(t["api_base"]).strip() or DEFAULT_TG["api_base"]
                if not re.fullmatch(r"https?://[^\s]+", base):
                    return "API base URL must start with http:// or https://"
                g["api_base"] = base.rstrip("/")
            if g["enabled"] and not (g["token"] and g["chat_id"]):
                return "Enter the bot token and the chat ID before turning alerts on."
        SETTINGS.update(new)
        save_json(SETTINGS_PATH, SETTINGS)
    with SOURCES_LOCK:
        if LOCAL_ID in SOURCES:
            SOURCES[LOCAL_ID].name = local_name()
    return ""


def _gb(b):
    return f"{b / 1073741824:.1f} GB"


class TgError(Exception):
    def __init__(self, msg, retry=False, wait=0):
        super().__init__(msg)
        self.retry, self.wait = retry, wait


def tg_api(method, payload=None, timeout=15):
    """Call one Telegram Bot API method with the saved token/proxy/address. Returns the result or raises TgError."""
    with SETTINGS_LOCK:
        tg = dict(SETTINGS["telegram"])
    if not tg["token"]:
        raise TgError("Bot token is not set.")
    req = urllib.request.Request(f"{tg['api_base']}/bot{tg['token']}/{method}", json.dumps(payload or {}).encode(),
                                 {"Content-Type": "application/json"})
    opener = urllib.request.build_opener(*([urllib.request.ProxyHandler({"http": tg["proxy"], "https": tg["proxy"]})]
                                           if tg["proxy"] else []))
    try:
        with opener.open(req, timeout=timeout) as r:
            body = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            d = json.loads(e.read().decode())
        except Exception:
            d = {}
        raise TgError(f"Telegram answered {e.code}: {d.get('description') or e.reason}",
                      retry=(e.code == 429 or e.code >= 500), wait=(d.get("parameters") or {}).get("retry_after", 0))
    except Exception as e:
        raise TgError(f"Cannot reach Telegram ({str(e).replace(tg['token'], '***')}). If this server cannot open "
                      "api.telegram.org, set an HTTP proxy or a custom API base URL under Advanced.", retry=True)
    if not body.get("ok"):
        raise TgError(str(body.get("description", "Unknown Telegram error")))
    return body.get("result")


def _chat_id():
    with SETTINGS_LOCK:
        return SETTINGS["telegram"]["chat_id"]


def send_telegram(text, markup=None):
    """One attempt to send a message to the admin chat. Returns (ok, message) and remembers the result."""
    try:
        payload = {"chat_id": _chat_id(), "text": text, "parse_mode": "HTML"}
        if markup:
            payload["reply_markup"] = markup
        tg_api("sendMessage", payload)
        ok, msg = True, "Message sent."
    except TgError as e:
        ok, msg = False, str(e)
    TG_STATUS.update(ok=ok, msg=msg, time=int(time.time() * 1000))
    return ok, msg


RETRY_DELAYS = (2, 5, 15, 30, 60)  # an alert is retried for about two minutes if Telegram cannot be reached


def deliver(text, markup=None):
    """Send an alert and keep trying (network errors, Telegram overload) so that it is not lost."""
    for i in range(len(RETRY_DELAYS) + 1):
        try:
            payload = {"chat_id": _chat_id(), "text": text, "parse_mode": "HTML"}
            if markup:
                payload["reply_markup"] = markup
            tg_api("sendMessage", payload)
            TG_STATUS.update(ok=True, msg="Message sent.", time=int(time.time() * 1000))
            return True
        except TgError as e:
            TG_STATUS.update(ok=False, msg=str(e), time=int(time.time() * 1000))
            if not e.retry or i == len(RETRY_DELAYS):
                return False
            time.sleep(max(RETRY_DELAYS[i], e.wait))
    return False


def fmt_size(b):
    u = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while b >= 1024 and i < len(u) - 1:
        b /= 1024
        i += 1
    return f"{b:.{2 if i > 2 else 0}f} {u[i]}"


def fmt_rate(bps):
    v, u, i = bps * 8, ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"], 0
    while v >= 1000 and i < len(u) - 1:
        v /= 1000
        i += 1
    return f"{v:.0f} {u[i]}" if i == 0 else f"{v:.1f} {u[i]}" if v >= 100 else f"{v:.2f} {u[i]}"


def _clock(ms):
    return time.strftime("%H:%M:%S", time.localtime(ms / 1000))


class Alerts:
    """Telegram alerts for one server. Checked every second: the first second CPU, RAM or disk is at or above the
    limit an alert is sent at once. It is not repeated while the value stays high (a reminder follows after 30 minutes);
    when the value has been clearly below the limit for 30 seconds a 'back to normal' message is sent."""
    LABEL = {"cpu": "CPU", "ram": "RAM", "disk": "Disk"}
    COOLDOWN = 1800      # reminder while a value stays high
    RECOVER_AFTER = 30   # seconds clearly below the limit before 'back to normal'

    def __init__(self, src):
        self.src = src
        self.st = {m: {"active": False, "sent": 0.0, "ok_since": None} for m in self.LABEL}

    def _values(self, s):
        mem, d = s["mem"], s.get("disk") or {}
        return {"cpu": s["cpu"], "ram": _pct(mem["used"], mem["total"]), "disk": _pct(d.get("used", 0), d.get("total", 0))}

    def _detail(self, m, s):
        mem, d = s["mem"], s.get("disk") or {}
        if m == "ram":
            return f"Used {_gb(mem['used'])} of {_gb(mem['total'])}"
        if m == "disk":
            return f"Used {_gb(d.get('used', 0))} of {_gb(d.get('total', 0))}"
        return f"Load average {s['load'][0]:.2f}"

    def feed(self, s, now=None):
        with SETTINGS_LOCK:
            tg = SETTINGS["telegram"]
            enabled, limit = bool(tg["enabled"] and tg["token"] and tg["chat_id"]), tg["threshold"]
        if not enabled:
            return
        now = time.time() if now is None else now
        margin = min(5, limit * 0.1)
        name = _html.escape(self.src.name)
        for m, v in self._values(s).items():
            st = self.st[m]
            if v >= limit:
                st["ok_since"] = None
                if not st["active"] or now - st["sent"] >= self.COOLDOWN:
                    again = st["active"]
                    st["active"], st["sent"] = True, now
                    self._send(f"\U0001f6a8 <b>{name}</b>: {self.LABEL[m]} {'is still high' if again else 'is high'}\n"
                               f"<b>{self.LABEL[m]}: {v:.1f}%</b>  (limit {limit}%)\n{self._detail(m, s)}\n"
                               f"\U0001f552 {_clock(s['t'])}")
            elif st["active"]:
                if v < limit - margin:
                    if st["ok_since"] is None:
                        st["ok_since"] = now
                    if now - st["ok_since"] >= self.RECOVER_AFTER:
                        st["active"], st["ok_since"] = False, None
                        self._send(f"\u2705 <b>{name}</b>: {self.LABEL[m]} is back to normal ({v:.1f}%)\n\U0001f552 {_clock(s['t'])}")
                else:
                    st["ok_since"] = None

    def _send(self, text):
        send_alert(text, self.src.id)


# ---------------------------------------------------------------- offline alerts (a server stops reporting)
OFFLINE_AFTER = 15   # seconds without data before a server counts as offline
OFFLINE_GRACE = 60   # a server that has not reported since the panel (re)started gets this long to reconnect
OFFLINE_REMIND = 1800


def send_alert(text, sid):
    """Send an alert message with a Details button for that server (in the background, with retries)."""
    markup = {"inline_keyboard": [[{"text": "\U0001f4ca Details", "callback_data": "snap:" + sid}]]}
    threading.Thread(target=deliver, args=(text, markup), daemon=True).start()


def fmt_dur(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    if sec < 86400:
        return f"{sec // 3600}h {sec % 3600 // 60}m"
    return f"{sec // 86400}d {sec % 86400 // 3600}h"


def offline_check(state, started, now):
    """One pass over all nodes: alert when one went silent, when it stays offline, and when it is back."""
    with SETTINGS_LOCK:
        tg = SETTINGS["telegram"]
        on = bool(tg["enabled"] and tg["token"] and tg["chat_id"] and tg.get("offline", True))
    with SOURCES_LOCK:
        nodes = [x for x in SOURCES.values() if not x.local]
    for src in nodes:
        st = state.setdefault(src.id, {"alerted": False, "since": 0.0, "sent": 0.0})
        ref, limit = (src.last_rx, OFFLINE_AFTER) if src.last_rx else (started, OFFLINE_GRACE)
        name = _html.escape(src.name)
        if now - ref >= limit:  # offline
            if not on:
                continue
            with src.lock:
                last = src.history[-1] if src.history else None
            if not st["alerted"]:
                st.update(alerted=True, since=ref, sent=now)
                detail = (f"Last data {_clock(last['t'])}: CPU {last['cpu']:.0f}% \u00b7 RAM "
                          f"{_pct(last['mem']['used'], last['mem']['total']):.0f}%") if last else "It has not reported since the panel started."
                send_alert(f"\U0001f534 <b>{name}</b> is offline\nNo data for {fmt_dur(now - ref)}.\n{detail}\n"
                           f"\U0001f552 {time.strftime('%H:%M:%S', time.localtime(now))}", src.id)
            elif now - st["sent"] >= OFFLINE_REMIND:
                st["sent"] = now
                send_alert(f"\U0001f534 <b>{name}</b> is still offline (for {fmt_dur(now - st['since'])})", src.id)
        elif st["alerted"]:  # data is flowing again
            st["alerted"] = False
            if on:
                send_alert(f"\U0001f7e2 <b>{name}</b> is back online (was offline for {fmt_dur(now - st['since'])})\n"
                           f"\U0001f552 {time.strftime('%H:%M:%S', time.localtime(now))}", src.id)
    for sid in [k for k in state if k not in {x.id for x in nodes}]:  # removed servers
        del state[sid]


def offline_watch():
    state, started = {}, time.time()
    while True:
        time.sleep(1)
        try:
            offline_check(state, started, time.time())
        except Exception as e:
            print(f"offline watch error: {e}", file=sys.stderr)


# ---------------------------------------------------------------- Telegram bot menu (/start -> servers -> live details)
BOT_STATUS = {"ok": None, "msg": "", "time": 0}


def snapshot_text(src):
    info = src.info()
    with src.lock:
        s = src.history[-1] if src.history else None
    name = _html.escape(info["name"])
    if not s:
        return f"\U0001f534 <b>{name}</b>\nNo data yet."
    mem, d = s["mem"], s.get("disk") or {}
    rx = sum(v[0] for n, v in s["net"].items() if n != "lo")
    tx = sum(v[1] for n, v in s["net"].items() if n != "lo")
    up = s.get("uptime", 0)
    state = "\U0001f7e2 online" if info["online"] else "\U0001f534 offline (last data " + _clock(s["t"]) + ")"
    rows = [f"CPU   {s['cpu']:5.1f} %   {info.get('cores') or len(s['cores']) or '?'} cores, load {s['load'][0]:.2f}",
            f"RAM   {_pct(mem['used'], mem['total']):5.1f} %   {fmt_size(mem['used'])} / {fmt_size(mem['total'])}",
            f"Disk  {_pct(d.get('used', 0), d.get('total', 0)):5.1f} %   {fmt_size(d.get('used', 0))} / {fmt_size(d.get('total', 0))}",
            f"In    {fmt_rate(rx)}", f"Out   {fmt_rate(tx)}",
            f"Up    {up // 86400}d {up % 86400 // 3600}h {up % 3600 // 60}m"]
    return (f"<b>{name}</b>  {state}\n\U0001f552 {_clock(s['t'])}\n<pre>" + _html.escape("\n".join(rows)) + "</pre>")


def bot_list_view():
    servers = server_list()
    lines, buttons = ["<b>Your servers</b> - tap one for its live status:\n"], []
    for x in servers:
        dot = "\U0001f7e2" if x["online"] else "\U0001f534"
        extra = f" \u00b7 CPU {x['cpu']:.0f}% \u00b7 RAM {x['ram']:.0f}% \u00b7 Disk {x['disk']:.0f}%" if x["online"] and "cpu" in x else " \u00b7 offline"
        lines.append(f"{dot} {_html.escape(x['name'])}{extra}")
        buttons.append([{"text": f"{dot} {x['name']}", "callback_data": "srv:" + x["id"]}])
    buttons.append([{"text": "\U0001f504 Refresh list", "callback_data": "list"}])
    return "\n".join(lines), {"inline_keyboard": buttons}


def bot_server_view(sid):
    with SOURCES_LOCK:
        src = SOURCES.get(sid)
    if not src:
        return "That server was removed.", {"inline_keyboard": [[{"text": "\u2b05\ufe0f Servers", "callback_data": "list"}]]}
    return snapshot_text(src), {"inline_keyboard": [[{"text": "\U0001f504 Refresh", "callback_data": "srv:" + sid},
                                                     {"text": "\u2b05\ufe0f Servers", "callback_data": "list"}]]}


def _edit(chat, mid, text, markup):
    try:
        tg_api("editMessageText", {"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML", "reply_markup": markup})
    except TgError as e:
        if "not modified" not in str(e):
            raise


def bot_handle(u):
    admin = _chat_id()
    cb, msg = u.get("callback_query"), u.get("message")
    if cb:
        m = cb.get("message") or {}
        chat = (m.get("chat") or {}).get("id")
        if str(chat) != admin:
            tg_api("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Not allowed.", "show_alert": True})
            return
        tg_api("answerCallbackQuery", {"callback_query_id": cb["id"]})
        data = cb.get("data") or ""
        if data == "list":
            _edit(chat, m["message_id"], *bot_list_view())
        elif data.startswith("srv:"):
            _edit(chat, m["message_id"], *bot_server_view(data[4:]))
        elif data.startswith("snap:"):  # from an alert: keep the alert, send the details as a new message
            text, markup = bot_server_view(data[5:])
            tg_api("sendMessage", {"chat_id": chat, "text": text, "parse_mode": "HTML", "reply_markup": markup})
    elif msg and isinstance(msg.get("text"), str) and msg["text"].startswith("/"):
        chat = (msg.get("chat") or {}).get("id")
        if str(chat) != admin:
            tg_api("sendMessage", {"chat_id": chat, "text": "This bot is private."})
            return
        if msg["text"].split()[0].split("@")[0].lower() in ("/start", "/servers", "/menu", "/help", "/status"):
            text, markup = bot_list_view()
            tg_api("sendMessage", {"chat_id": chat, "text": text, "parse_mode": "HTML", "reply_markup": markup})


def bot_loop():
    offset, ready, backoff = 0, None, 1
    while True:
        with SETTINGS_LOCK:
            tg = dict(SETTINGS["telegram"])
        if not (tg["token"] and tg["chat_id"]):
            BOT_STATUS.update(ok=None, msg="Save the bot token and chat ID to turn the bot menu on.")
            time.sleep(3)
            continue
        key = (tg["token"], tg["api_base"], tg["proxy"])
        try:
            if ready != key:
                me = tg_api("getMe")
                try:
                    tg_api("deleteWebhook")
                except TgError:
                    pass
                tg_api("setMyCommands", {"commands": [{"command": "start", "description": "Show my servers"},
                                                      {"command": "servers", "description": "Show my servers"}]})
                ready, offset, backoff = key, 0, 1
                BOT_STATUS.update(ok=True, msg=f"Bot menu is on: send /start to @{me.get('username', 'your bot')}", time=int(time.time() * 1000))
            for u in tg_api("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]}, timeout=40) or []:
                offset = u["update_id"] + 1
                try:
                    bot_handle(u)
                except Exception as e:
                    print(f"bot error: {e}", file=sys.stderr)
            backoff = 1
        except TgError as e:
            ready = None
            BOT_STATUS.update(ok=False, msg=f"Bot menu is off: {e}", time=int(time.time() * 1000))
            time.sleep(min(backoff, 30))
            backoff *= 2
        except Exception as e:
            ready = None
            BOT_STATUS.update(ok=False, msg=f"Bot menu is off: {e}", time=int(time.time() * 1000))
            time.sleep(min(backoff, 30))
            backoff *= 2


# ---------------------------------------------------------------- nodes (other servers reporting to this panel)
NODES = []  # [{"id", "name", "token_hash", "created"}]


def _hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


def register_node(rec_):
    src = Source(rec_["id"], rec_["name"], os.path.join(DATA_DIR, "nodes", rec_["id"]))
    src.load()
    with SOURCES_LOCK:
        SOURCES[rec_["id"]] = src


def load_nodes():
    with NODES_LOCK:
        NODES[:] = [r for r in (load_json(NODES_PATH, []) or []) if isinstance(r, dict) and NODE_ID_RE.match(str(r.get("id", "")))]
        for r in NODES:
            register_node(r)


def create_node(name):
    token = "sm_" + secrets.token_urlsafe(24)
    r = {"id": "n" + secrets.token_hex(4), "name": name, "token_hash": _hash_token(token), "created": int(time.time())}
    with NODES_LOCK:
        NODES.append(r)
        save_json(NODES_PATH, NODES)
    register_node(r)
    return r["id"], token


def delete_node(nid):
    if not NODE_ID_RE.match(nid or ""):
        return False
    with NODES_LOCK:
        r = next((x for x in NODES if x["id"] == nid), None)
        if not r:
            return False
        NODES.remove(r)
        save_json(NODES_PATH, NODES)
    with SOURCES_LOCK:
        src = SOURCES.pop(nid, None)
    if src:
        with src.lock:
            if src.store.fh:
                src.store.fh.close()
            src.store.ok = False
        shutil.rmtree(src.dir, ignore_errors=True)
    return True


def node_by_token(token):
    if not token:
        return None
    h = _hash_token(token)
    with NODES_LOCK:
        for r in NODES:
            if hmac.compare_digest(h, r["token_hash"]):
                return r["id"]
    return None


def server_list():
    with SOURCES_LOCK:
        order = [LOCAL_ID] + [r["id"] for r in NODES]
        return [SOURCES[i].info() for i in order if i in SOURCES]


def clean_sample(d):
    """Validate and normalise a sample received from a node (raises on malformed data)."""
    mem = d["mem"]
    net = {str(k)[:40]: [int(v[0]), int(v[1])] for k, v in list(d["net"].items())[:64]}
    load = [float(x) for x in d.get("load", [])][:3]
    load += [0.0] * (3 - len(load))
    dk = d.get("disk") or {}
    return {"t": int(d["t"]), "cpu": float(d["cpu"]), "cores": [float(x) for x in d.get("cores", [])][:512],
            "mem": {k: int(mem.get(k, 0)) for k in ("total", "used", "swap_total", "swap_used")},
            "net": net, "load": load, "uptime": int(d.get("uptime", 0)),
            "disk": {"total": int(dk.get("total", 0)), "used": int(dk.get("used", 0))}}


NODE_INSTALLER = r"""#!/usr/bin/env bash
# Server Monitor - node installer (generated by your main panel)
set -euo pipefail
MASTER="@MASTER@"
TOKEN="@TOKEN@"
DIR="/opt/server-monitor"
if [ "$(id -u)" -ne 0 ]; then echo "Please run as root (use sudo)." >&2; exit 1; fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Installing python3 ..."
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y python3
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y python3
  elif command -v yum     >/dev/null 2>&1; then yum install -y python3
  else echo "Please install python3 first." >&2; exit 1; fi
fi
mkdir -p "$DIR"
echo "Downloading Server Monitor from $MASTER ..."
if   command -v curl >/dev/null 2>&1; then curl -fsSL "$MASTER/node.py?token=$TOKEN" -o "$DIR/server_monitor.py"
elif command -v wget >/dev/null 2>&1; then wget -q "$MASTER/node.py?token=$TOKEN" -O "$DIR/server_monitor.py"
else echo "curl or wget is required." >&2; exit 1; fi
chmod 755 "$DIR/server_monitor.py"
exec python3 "$DIR/server_monitor.py" --node "$MASTER" --token "$TOKEN" --install-service
"""


# ---------------------------------------------------------------- node mode (this server reports to a main panel)
NODE_CFG_DEFAULT = os.path.join(os.path.expanduser("~"), ".server_monitor_node.json")
NODE_SERVICE_NAME = "server-monitor-node"
NODE_SERVICE_PATH = "/etc/systemd/system/server-monitor-node.service"


def node_pusher(cfg, buf):
    u = urllib.parse.urlsplit(cfg["url"])
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = u.path.rstrip("/") + "/api/node/push"
    ctx = ssl._create_unverified_context() if cfg.get("insecure") else None
    meta = {"host": socket.gethostname(), "cores": os.cpu_count(), "ver": VERSION, "hash": SCRIPT_HASH}
    conn, backoff, connected, last_log = None, 1, None, 0.0

    def log(msg):
        nonlocal last_log
        if time.time() - last_log > 60 or msg.startswith("Connected"):
            print(msg, flush=True)
            last_log = time.time()

    while True:
        if not buf:
            time.sleep(0.2)
            continue
        batch = list(buf)[:120]
        body = json.dumps({"now": int(time.time() * 1000), "meta": meta, "samples": batch}).encode()
        try:
            if conn is None:
                conn = (http.client.HTTPSConnection(u.hostname, port, timeout=10, context=ctx) if https
                        else http.client.HTTPConnection(u.hostname, port, timeout=10))
            conn.request("POST", path, body, {"Authorization": "Bearer " + cfg["token"], "Content-Type": "application/json"})
            r = conn.getresponse()
            r.read()
            if r.status == 200:
                last = batch[-1]["t"]
                while buf and buf[0]["t"] <= last:
                    buf.popleft()
                backoff = 1
                if connected is not True:
                    connected = True
                    log("Connected to the main panel - sending metrics.")
                continue
            conn.close()
            conn = None
            log(f"The main panel refused the data (HTTP {r.status}). Check the token. Retrying...")
            time.sleep(30 if r.status in (401, 403) else min(backoff, 30))
        except Exception as e:
            try:
                conn and conn.close()
            except Exception:
                pass
            conn = None
            connected = False
            log(f"Cannot reach the main panel ({e}). Retrying...")
            time.sleep(min(backoff, 30))
            backoff *= 2


def run_node(cfg):
    print(f"Server Monitor node: sending metrics to {cfg['url']}  (Ctrl+C to stop)", flush=True)
    buf = collections.deque(maxlen=3600)  # unsent samples while the main panel is unreachable
    threading.Thread(target=node_pusher, args=(cfg, buf), daemon=True).start()
    c = Collector()
    try:
        while True:
            c.wait()
            try:
                buf.append(c.sample())
            except Exception as e:
                print(f"sampler error: {e}", file=sys.stderr)
                time.sleep(1)
    except KeyboardInterrupt:
        pass


def node_service_unit(cfg_path):
    cmd = [sys.executable, os.path.abspath(__file__), "--node-config", cfg_path]
    return ("[Unit]\nDescription=Server Monitor node\nAfter=network-online.target\n\n[Service]\n"
            "ExecStart=" + " ".join(shlex.quote(c) for c in cmd) + "\nRestart=always\nRestartSec=5\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def install_node_service(cfg_path, unit_path=NODE_SERVICE_PATH, run=subprocess.run, launcher=LAUNCHER):
    with open(unit_path, "w") as f:
        f.write(node_service_unit(cfg_path))
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", NODE_SERVICE_NAME], check=True)
    run(["systemctl", "restart", NODE_SERVICE_NAME], check=True)
    install_launcher(launcher)


# ---------------------------------------------------------------- login storage / first-run setup
DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".server_monitor.json")
ITERS = 200_000
SERVICE_NAME = "server-monitor"
SERVICE_PATH = "/etc/systemd/system/server-monitor.service"


def make_cred(user, password, port=None):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERS)
    c = {"user": user, "salt": salt.hex(), "hash": h.hex(), "iters": ITERS}
    if port:
        c["port"] = int(port)
    return c


def verify_cred(cred, user, password):
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(cred["salt"]), cred["iters"])
    ok_h = hmac.compare_digest(h.hex(), cred["hash"])
    ok_u = hmac.compare_digest(user.encode(), cred["user"].encode())
    return ok_h and ok_u


def load_cred(path):
    try:
        with open(path) as f:
            d = json.load(f)
        if all(k in d for k in ("user", "salt", "hash", "iters")):
            return d
    except (OSError, ValueError):
        pass
    return None


def save_cred(path, cred):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cred, f)
    os.chmod(path, 0o600)


def check_username(u):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u))


def check_password(p):
    return len(p) >= 6


def port_free(port):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.bind((ARGS.host, port))
        return True
    except OSError:
        return False
    finally:
        sk.close()


def ask_port(default, current=0):
    while True:
        raw = input(f"  Panel port [{default}]: ").strip() or str(default)
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            print("  Enter a number between 1 and 65535.")
            continue
        p = int(raw)
        if p != current and not port_free(p):
            print(f"  Port {p} is already in use (or not allowed). Choose another one.")
            continue
        return p


def ask_setup(port=None, current=0):
    """Interactive first-run questions, in this order: port, username, password."""
    print("\n  Server Monitor - first-time setup")
    print("  Choose the port and the login for your monitoring panel.\n")
    if port is None:
        port = ask_port(current or 8080, current)
    while True:
        user = input("  Username: ").strip()
        if check_username(user):
            break
        print("  Use 3-32 characters: letters, digits, '_', '-' or '.'.")
    while True:
        pw = getpass.getpass("  Password (min 6 characters, hidden): ")
        if not check_password(pw):
            print("  That password is too short.")
            continue
        if getpass.getpass("  Repeat password: ") != pw:
            print("  The passwords do not match, try again.")
            continue
        return port, user, pw


def ask_yes_no(question, default=True):
    try:
        a = input(f"  {question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return default if not a else a in ("y", "yes")


def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return True


def detect_ip():
    """Best guess of the address people should use to reach this server."""
    ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packet is sent; just picks the outgoing interface
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    if not ip or _is_private(ip):  # behind NAT: ask a public "what is my IP" service
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    cand = r.read(64).decode().strip()
                if not _is_private(cand):
                    return cand
            except Exception:
                pass
    return ip or "127.0.0.1"


def panel_url(scheme):
    host = ARGS.host
    if host in ("0.0.0.0", "::", ""):
        host = detect_ip()
    return f"{scheme}://{host}:{ARGS.port}"


def print_success(url, user, password):
    ok = "\u2714" if "utf" in (getattr(sys.stdout, "encoding", "") or "").lower() else "[OK]"
    line = "=" * 58
    print(f"\n{line}\n  {ok}  Server Monitor was installed successfully!\n{line}")
    print(f"  Username   : {user}")
    print(f"  Password   : {password if password else '(the one you provided)'}")
    print(f"  Panel link : {url}\n{line}")
    if url.startswith("http://"):
        print("  Note: the panel uses plain HTTP. For HTTPS run with --cert and --key.\n")


def service_unit():
    cmd = [sys.executable, os.path.abspath(__file__), "--host", ARGS.host, "--port", str(ARGS.port),
           "--config", ARGS.config]
    if ARGS.cert:
        cmd += ["--cert", os.path.abspath(ARGS.cert), "--key", os.path.abspath(ARGS.key)]
    return ("[Unit]\nDescription=Server Monitor\nAfter=network-online.target\n\n[Service]\n"
            "ExecStart=" + " ".join(shlex.quote(c) for c in cmd) + "\nRestart=always\nRestartSec=3\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def can_install_service():
    return (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
            and os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None
            and "INVOCATION_ID" not in os.environ)


def install_service(unit_path=SERVICE_PATH, run=subprocess.run, launcher=LAUNCHER):
    with open(unit_path, "w") as f:
        f.write(service_unit())
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", SERVICE_NAME], check=True)
    run(["systemctl", "restart", SERVICE_NAME], check=True)
    install_launcher(launcher)


# ---------------------------------------------------------------- web server
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, *a):
        pass

    # helpers
    def _token(self):
        c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return c["session"].value if "session" in c else None

    def _authed(self):
        return auth_state(self._token()) == "ok"

    def _is_https(self):
        return bool(ARGS.cert) or self.headers.get("X-Forwarded-Proto", "") == "https"

    def _send(self, code, body, ctype, headers=None):
        if isinstance(body, str):
            body = body.encode()
        gz = len(body) > 800 and "gzip" in self.headers.get("Accept-Encoding", "")
        if gz:
            body = gzip.compress(body, 5)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Vary", "Accept-Encoding")
        if gz:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj, separators=(",", ":")), "application/json", headers)

    def _cookie(self, value, max_age):
        parts = [f"session={value}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={max_age}"]
        if self._is_https():
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def _body(self, limit=65536):
        if len(self._raw) > limit:
            raise ValueError("too large")
        return json.loads(self._raw or b"{}")

    def _origin(self):
        host = self.headers.get("Host") or f"{detect_ip()}:{ARGS.port}"
        return f"{'https' if self._is_https() else 'http'}://{host}"

    def _source(self, q):
        sid = (q.get("s") or [LOCAL_ID])[0]
        with SOURCES_LOCK:
            return SOURCES.get(sid)

    def _unauthorized(self):
        self._json(401, {"error": "unauthorized", "reason": auth_state(self._token())})

    # routes
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        path, q = u.path, parse_qs(u.query)
        if path in ("/", "/login"):
            self._send(200, PAGE if self._authed() else LOGIN_PAGE, "text/html; charset=utf-8")
            return
        if path in ("/node-install.sh", "/node.py"):  # downloaded by a new server; protected by its node token
            token = (q.get("token") or [""])[0]
            if not node_by_token(token):
                self._send(403, "Invalid token\n", "text/plain; charset=utf-8")
            elif path == "/node.py":
                with open(os.path.abspath(__file__), encoding="utf-8") as f:
                    self._send(200, f.read(), "text/x-python; charset=utf-8")
            else:
                self._send(200, NODE_INSTALLER.replace("@MASTER@", self._origin()).replace("@TOKEN@", token),
                           "text/x-shellscript; charset=utf-8")
            return
        if not self._authed():
            self._unauthorized()
            return
        if path == "/api/servers":
            self._json(200, server_list())
        elif path == "/api/settings":
            self._json(200, public_settings())
        elif path in ("/api/stats", "/api/series", "/api/poll"):
            src = self._source(q)
            if not src:
                self._json(404, {"error": "unknown server"})
            elif path == "/api/stats":
                s = src.poll(0)
                self._json(200, s[0] if s else {})
            elif path == "/api/series":
                try:
                    w = int((q.get("w") or ["3600"])[0])
                    since = int((q.get("since") or ["0"])[0])
                except ValueError:
                    w, since = 3600, 0
                out = src.series_json(w, (q.get("iface") or ["__all__"])[0][:40], since)
                out["meta"] = src.info()
                self._json(200, out)
            else:
                try:
                    since = int((q.get("since") or ["0"])[0])
                except ValueError:
                    since = 0
                self._json(200, {"meta": src.info(), "samples": src.poll(since)})
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
            if not 0 <= n <= 2_000_000:
                raise ValueError
        except ValueError:
            self.close_connection = True
            self._json(400, {"error": "bad request"})
            return
        self._raw = self.rfile.read(n) if n else b""  # always consume the body (keeps keep-alive connections in sync)
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            ip = self.client_address[0]
            if login_blocked(ip):
                self._json(429, {"error": "Too many attempts. Try again in a few minutes."})
                return
            try:
                d = self._body(4096)
                u, p = str(d.get("username", "")), str(d.get("password", ""))
            except Exception:
                self._json(400, {"error": "Bad request"})
                return
            if verify_cred(CRED, u, p):
                self._json(200, {"ok": True}, [self._cookie(new_session(), SESSION_TTL)])
            else:
                record_fail(ip)
                time.sleep(0.6)
                self._json(401, {"error": "Invalid username or password"})
        elif path == "/logout":
            tok = self._token()
            if tok:
                with lock:
                    REVOKED.add(tok)
            self._json(200, {"ok": True}, [self._cookie("", 0)])
        elif path == "/api/node/push":
            self._push()
        elif not self._authed():
            self._unauthorized()
        elif path == "/api/settings":
            try:
                err = update_settings(self._body())
            except Exception:
                err = "Bad request"
            self._json(400 if err else 200, {"error": err} if err else public_settings())
        elif path == "/api/telegram/test":
            ok, msg = send_telegram(f"\u2705 Test message from Server Monitor ({_html.escape(local_name())}). Alerts are working.\nSend /start to this bot to see your servers.")
            self._json(200, {"ok": ok, "msg": msg})
        elif path == "/api/nodes":
            try:
                name = str(self._body().get("name", "")).strip()[:40]
            except Exception:
                name = ""
            if not name:
                self._json(400, {"error": "Enter a name for the server."})
            else:
                nid, token = create_node(name)
                self._json(200, {"id": nid, "name": name, "token": token})
        elif path == "/api/nodes/delete":
            try:
                ok = delete_node(str(self._body().get("id", "")))
            except Exception:
                ok = False
            self._json(200 if ok else 404, {"ok": ok})
        else:
            self.send_error(404)

    def _push(self):
        ip = "push:" + self.client_address[0]
        auth = self.headers.get("Authorization", "")
        nid = node_by_token(auth[7:].strip() if auth.startswith("Bearer ") else "")
        if not nid:  # a valid token always works; only wrong guesses are rate-limited
            if login_blocked(ip):
                self._json(429, {"error": "too many attempts"})
            else:
                record_fail(ip)
                self._json(401, {"error": "invalid token"})
            return
        try:
            d = self._body(2_000_000)
            skew = int(time.time() * 1000) - int(d["now"])
            samples = sorted((clean_sample(x) for x in d["samples"][:600]), key=lambda s: s["t"])
            meta = d.get("meta") or {}
            host, cores = str(meta.get("host", ""))[:60], int(meta.get("cores") or 0)
            ver, nhash = str(meta.get("ver", ""))[:20], str(meta.get("hash", ""))[:16]
        except (KeyError, TypeError, ValueError, AttributeError, IndexError):
            self._json(400, {"error": "bad data"})
            return
        if abs(skew) > 5000:  # the node's clock is off: align its timestamps with ours
            for s in samples:
                s["t"] += skew
        with SOURCES_LOCK:
            src = SOURCES.get(nid)
        if not src:
            self._json(404, {"error": "server was removed"})
            return
        src.meta = {"host": host, "cores": cores, "ver": ver, "hash": nhash}
        self._json(200, {"ok": True, "accepted": sum(1 for s in samples if src.add(s))})


# ---------------------------------------------------------------- login page
LOGIN_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Server Monitor - Log in</title>
<style>
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:#0a1120;color:#e8edf5;
  font:15px/1.5 Roboto,"Segoe UI",system-ui,-apple-system,sans-serif;
  display:flex;align-items:center;justify-content:center;padding:20px;position:relative;overflow:hidden}
.wave{position:fixed;left:0;right:0;bottom:0;width:100%;height:56vh;z-index:0}
.card{position:relative;z-index:1;width:100%;max-width:450px;background:#161f33;
  border-radius:30px;padding:34px 48px 44px;box-shadow:0 24px 60px rgba(0,0,0,.35)}
h1{margin:14px 0 34px;text-align:center;font-size:28px;font-weight:700;color:#d9dfeb}
.field{position:relative;margin-bottom:16px}
.field svg.ico{position:absolute;left:20px;top:50%;transform:translateY(-50%);
  width:18px;height:18px;stroke:#9aa7bd;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
input{width:100%;height:56px;border-radius:28px;border:1px solid #243049;background:#1b263d;
  color:#e8edf5;font:inherit;padding:0 52px 0 50px;outline:none;transition:border-color .2s,background .2s}
input::placeholder{color:#6f7d95}
input:focus{background:#12404a;border-color:#0f766e}
.eye{position:absolute;right:14px;top:50%;transform:translateY(-50%);width:32px;height:32px;border:0;
  background:none;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0}
.eye svg{width:18px;height:18px;stroke:#9aa7bd;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
button.go{width:100%;height:56px;margin-top:16px;border-radius:28px;border:1px solid #0f7a6e;
  background:#0a5a52;color:#fff;font:inherit;font-weight:600;cursor:pointer;transition:background .2s}
button.go:hover{background:#0c6d63}
button.go:disabled{opacity:.6;cursor:default}
#err{min-height:22px;margin-top:14px;text-align:center;color:#ff7b7b;font-size:14px}
:focus-visible{outline:2px solid #3cc8b4;outline-offset:2px}
@media(max-width:480px){.card{padding:28px 24px 34px}}
</style>
</head>
<body>
<svg class="wave" viewBox="0 0 1440 320" preserveAspectRatio="none" aria-hidden="true">
  <path fill="#1a2336" d="M0,200 C260,130 500,250 760,205 C1020,160 1230,90 1440,175 L1440,320 L0,320Z"/>
  <path fill="#222d45" d="M0,245 C300,200 540,275 840,242 C1090,214 1270,180 1440,222 L1440,320 L0,320Z"/>
</svg>
<main class="card">
  <h1>Welcome</h1>
  <form id="f" autocomplete="on">
    <div class="field">
      <svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>
      <input id="u" name="username" placeholder="Username" autocomplete="username" autocapitalize="none" required autofocus>
    </div>
    <div class="field">
      <svg class="ico" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
      <input id="p" name="password" type="password" placeholder="Password" autocomplete="current-password" required>
      <button type="button" class="eye" id="eye" aria-label="Show password">
        <svg viewBox="0 0 24 24"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>
      </button>
    </div>
    <button class="go" id="btn" type="submit">Log In</button>
    <div id="err" role="alert"></div>
  </form>
</main>
<script>
const $ = id => document.getElementById(id);
$('eye').onclick = () => {
  const hide = $('p').type === 'password';
  $('p').type = hide ? 'text' : 'password';
  $('eye').setAttribute('aria-label', hide ? 'Hide password' : 'Show password');
};
$('f').addEventListener('submit', async e => {
  e.preventDefault(); $('btn').disabled = true; $('err').textContent = '';
  try {
    const r = await fetch('login', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: $('u').value, password: $('p').value})});
    if (r.ok){ location.href = './'; return; }
    const j = await r.json().catch(() => ({}));
    $('err').textContent = j.error || 'Login failed';
  } catch (_) { $('err').textContent = 'Cannot reach the server'; }
  $('btn').disabled = false;
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- dashboard page
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0a1120">
<title>Server Monitor</title>
<style>
:root{--bg:#0a1120;--p1:#131e33;--p2:#0f1829;--line:#1f2d47;--text:#e8eef7;--muted:#8195b0;
  --rx:#2dd4bf;--tx:#fbbf24;--cpu:#60a5fa;--ram:#c084fc;--bad:#fb7185;--warn:#facc15;--disk:#f472b6}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--text);background:
  radial-gradient(900px 520px at 12% -8%,rgba(45,212,191,.11),transparent 60%),
  radial-gradient(800px 520px at 100% 0,rgba(192,132,252,.10),transparent 55%),var(--bg);
  font:15px/1.5 Roboto,"Segoe UI",system-ui,-apple-system,sans-serif}
header{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:center;justify-content:space-between;padding:14px 18px}
h1{font-size:19px;margin:0;font-weight:700}
h1 small{color:var(--muted);font-weight:400;font-size:14px;margin-left:6px}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.seg{display:flex;background:var(--p2);border:1px solid var(--line);border-radius:999px;padding:3px}
.seg button{border:0;background:none;color:var(--muted);padding:5px 13px;border-radius:999px;font:inherit;font-size:13px;cursor:pointer}
.seg button.on{background:#1d2c49;color:var(--text);box-shadow:0 0 0 1px #2a3d63 inset}
select,button.out{background:var(--p2);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font:inherit;font-size:13px}
button.out{cursor:pointer;display:none}
#status{font-size:13px;color:var(--muted);display:flex;align-items:center;gap:6px}
#status::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--bad)}
#status.live::before{background:var(--rx);box-shadow:0 0 8px var(--rx)}
main{padding:4px 18px 24px;max-width:1180px;margin:auto;display:grid;gap:14px}
.panel{background:linear-gradient(180deg,var(--p1),var(--p2));border:1px solid var(--line);border-radius:18px;
  padding:14px 16px;box-shadow:0 12px 32px rgba(0,0,0,.28)}
.nums{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.g3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.g3 .gauge{padding:10px 4px}.g3 .gname{font-size:12px}.g3 .gsub{font-size:11px;line-height:1.3;padding:0 2px}
.gauge{--c:var(--col);padding:12px 8px;text-align:center}
.gauge.warn{--c:var(--warn)}
.gauge.hot{--c:var(--bad)}
.gname{font-size:13px;color:var(--muted);font-weight:500}
.gauge svg{width:100%;max-width:250px;display:block;margin:2px auto 0}
.track{fill:none;stroke:rgba(255,255,255,.07);stroke-width:10;stroke-linecap:round}
.fill{fill:none;stroke:var(--c);stroke-width:10;stroke-linecap:round;stroke-dasharray:100 100;stroke-dashoffset:100}
.tick{stroke:rgba(255,255,255,.28);stroke-width:1.4;stroke-linecap:round}
.tick.maj{stroke:rgba(255,255,255,.5);stroke-width:2}
.needle path{fill:var(--c)}
.hub{fill:#0f1829;stroke:var(--c);stroke-width:2.5}.hubin{fill:var(--c)}
.num{fill:#fff;font:600 28px Roboto,system-ui,sans-serif;font-variant-numeric:tabular-nums}
.unit{fill:var(--muted);font:500 11px system-ui,sans-serif}
.mn,.mx{fill:var(--muted);font:10px system-ui,sans-serif}
.gsub{font-size:12px;color:var(--muted);margin-top:2px}
.plain{display:flex;flex-direction:column;align-items:center;justify-content:center;border-top:3px solid var(--c)}
.plain .num{display:block;fill:none;color:var(--c);font:700 40px/1.1 Roboto,system-ui,sans-serif;margin-top:10px}
.plain .unit{display:block;fill:none;color:var(--muted);font:500 13px system-ui,sans-serif;margin:2px 0 8px}
.ph{display:flex;flex-wrap:wrap;gap:6px 14px;justify-content:space-between;align-items:center;margin-bottom:6px}
.ph h2 small{color:var(--muted);font-weight:400;font-size:12px;margin-left:8px}
.ph h2{font-size:15px;margin:0;font-weight:600}
.chips{display:flex;gap:12px;flex-wrap:wrap;font-size:13px;color:var(--muted)}
.chips i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.chips b{color:var(--text);font-weight:600;font-variant-numeric:tabular-nums}
.cw{position:relative;height:240px;min-width:0;overflow:hidden}
.cw canvas{position:absolute;left:0;top:0;width:100%;height:100%;display:block;touch-action:pan-y}
main>*,.panel{min-width:0}
.two{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}
#cores{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px 14px}
.core{font-size:12px;color:var(--muted)}
.core div{height:6px;background:rgba(255,255,255,.07);border-radius:3px;overflow:hidden;margin-top:4px}
.core div i{display:block;height:100%;border-radius:3px;background:var(--cpu);transition:width .5s}
.foot{display:flex;gap:8px;flex-wrap:wrap;color:var(--muted);font-size:13px}
.foot span{background:var(--p2);border:1px solid var(--line);border-radius:999px;padding:3px 12px}

.btn{background:var(--p2);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:6px 14px;font:inherit;font-size:13px;cursor:pointer}
.btn:hover{border-color:#2a5d8a}.btn.pri{background:#0a5a52;border-color:#0f7a6e;color:#fff}.btn.danger{color:var(--bad)}
.servers{display:flex;gap:8px;overflow-x:auto;padding:0 18px 12px;max-width:1180px;margin:0 auto;scrollbar-width:none}
.servers::-webkit-scrollbar{display:none}
.sv{flex:none;display:flex;align-items:center;gap:8px;background:var(--p2);border:1px solid var(--line);border-radius:999px;
  padding:6px 14px;color:var(--text);font:inherit;font-size:13px;cursor:pointer}
.sv.on{background:#16294a;border-color:#2f6fa8}.sv.add{color:var(--muted);border-style:dashed}
.sv small{color:var(--muted);font-size:12px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted)}
.dot.on{background:var(--rx);box-shadow:0 0 6px var(--rx)}.dot.off{background:var(--bad)}
.modal{position:fixed;inset:0;background:rgba(4,9,20,.72);display:flex;align-items:flex-start;justify-content:center;
  padding:18px;overflow-y:auto;z-index:10}
.modal[hidden]{display:none}
.sheet{width:100%;max-width:540px;background:linear-gradient(180deg,var(--p1),var(--p2));border:1px solid var(--line);
  border-radius:20px;padding:18px 18px 22px;box-shadow:0 24px 60px rgba(0,0,0,.5)}
.sh-head{display:flex;justify-content:space-between;align-items:center}
.sheet h2{font-size:18px;margin:0}.sheet h3{font-size:14px;margin:20px 0 8px;color:var(--text)}
.x{background:none;border:0;color:var(--muted);font-size:26px;line-height:1;cursor:pointer}
.sheet input[type=text],.sheet input[type=password],.sheet input[type=number],.sheet textarea{width:100%;background:var(--bg);color:var(--text);
  border:1px solid var(--line);border-radius:12px;padding:10px 12px;font:inherit;font-size:14px;margin-bottom:8px}
.sheet textarea{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;resize:none}
.sheet input:focus,.sheet textarea:focus{outline:none;border-color:#0f766e}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.row input{flex:1;min-width:140px;margin-bottom:0!important}
.chk{display:flex;gap:10px;align-items:flex-start;font-size:14px;margin-bottom:10px}.chk input{margin-top:3px}
.note{font-size:13px;color:var(--muted);margin:8px 0 0}.note.ok{color:var(--rx)}.note.err{color:var(--bad)}
.nodes{display:grid;gap:6px;margin-bottom:10px}
.node{display:flex;align-items:center;gap:10px;background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:8px 12px}
.node span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
details summary{cursor:pointer;color:var(--muted);font-size:13px;margin:6px 0 8px}
label.f{display:block;font-size:13px;color:var(--muted);margin:2px 0 4px}
.tag{background:#3b2f0b;color:var(--warn);border-radius:999px;padding:1px 9px;font-size:11px;white-space:nowrap}
</style>
</head>
<body>
<header>
  <h1>Server Monitor<small id="host"></small></h1>
  <div class="controls">
    <div class="seg" id="win">
      <button data-w="3600" class="on">1 hour</button><button data-w="43200">12 hours</button><button data-w="86400">24 hours</button>
    </div>
    <select id="iface" title="Network interface"></select>
    <select id="unit" title="Unit"><option value="bit">Mbit/s</option><option value="byte">MB/s</option></select>
    <span id="status">Connecting…</span>
    <button class="btn" id="settingsBtn">Settings</button>
    <button class="out" id="logout">Log out</button>
  </div>
</header>
<nav class="servers" id="servers"></nav>
<main>
  <section class="nums" id="nums"></section>
  <section class="g3" id="gauges"></section>
  <section class="panel">
    <div class="ph"><h2>Network traffic<small id="netNote"></small></h2><div class="chips">
      <span><i style="background:var(--rx)"></i>In <b id="lgRx">-</b></span>
      <span><i style="background:var(--tx)"></i>Out <b id="lgTx">-</b></span></div></div>
    <div class="cw" style="height:270px"><canvas id="cNet"></canvas></div>
  </section>
  <section class="two">
    <div class="panel"><div class="ph"><h2>CPU usage</h2><div class="chips"><span><i style="background:var(--cpu)"></i><b id="lgCpu">-</b></span></div></div><div class="cw"><canvas id="cCpu"></canvas></div></div>
    <div class="panel"><div class="ph"><h2>RAM usage</h2><div class="chips"><span><i style="background:var(--ram)"></i><b id="lgRam">-</b></span></div></div><div class="cw"><canvas id="cRam"></canvas></div></div>
  </section>
  <section class="panel"><div class="ph"><h2>Disk usage</h2><div class="chips"><span><i style="background:var(--disk)"></i><b id="lgDisk">-</b></span></div></div><div class="cw"><canvas id="cDisk"></canvas></div></section>
  <section class="panel"><div class="ph"><h2>CPU cores</h2></div><div id="cores"></div></section>
  <div class="foot"><span id="fLoad"></span><span id="fSwap"></span><span id="fUp"></span></div>
</main>

<div class="modal" id="modal" hidden>
  <div class="sheet" role="dialog" aria-label="Settings">
    <div class="sh-head"><h2>Settings</h2><button class="x" id="mClose" aria-label="Close">&times;</button></div>

    <h3>Servers</h3>
    <div class="nodes" id="nodeList"></div>
    <p class="note">Update a server by running <b>server-monitor update</b> on it (update this panel first, then the others).</p>
    <label class="f" for="nodeAddr">Panel address and port the new server will connect to</label>
    <input type="text" id="nodeAddr" placeholder="203.0.113.10:8080" autocomplete="off" autocapitalize="none">
    <div class="row"><input type="text" id="nodeName" placeholder="Name of the new server, e.g. Web 1" maxlength="40"><button class="btn pri" id="nodeAdd">Add server</button></div>
    <p class="note err" id="nodeErr" hidden></p>
    <div id="nodeResult" hidden>
      <p class="note">Run this command as <b>root</b> on the new server. It installs the monitor and connects it to this panel:</p>
      <textarea id="nodeCmd" readonly rows="3"></textarea>
      <button class="btn" id="nodeCopy">Copy command</button>
      <p class="note">The new server must be able to reach this panel&rsquo;s address and port. You can change the port above at any time and the command updates.</p>
    </div>

    <h3>This server</h3>
    <label class="f" for="localName">Display name</label>
    <input type="text" id="localName" maxlength="40" placeholder="Name shown in the server list">

    <h3>Telegram bot and alerts</h3>
    <label class="chk"><input type="checkbox" id="tgOn"><span>Send an alert the moment CPU, RAM or disk usage of any server reaches the limit (checked every second)</span></label>
    <label class="chk"><input type="checkbox" id="tgOff"><span>Also alert when a server goes offline, and when it is back online</span></label>
    <input type="password" id="tgToken" autocomplete="off" placeholder="Bot token (from @BotFather)">
    <input type="text" id="tgChat" autocomplete="off" placeholder="Your chat ID">
    <label class="f" for="tgLimit">Limit (%)</label>
    <input type="number" id="tgLimit" min="1" max="100" value="80">
    <details><summary>Advanced: if this server cannot reach Telegram</summary>
      <label class="f" for="tgProxy">HTTP proxy</label>
      <input type="text" id="tgProxy" placeholder="http://host:port">
      <label class="f" for="tgBase">Telegram API address</label>
      <input type="text" id="tgBase" placeholder="https://api.telegram.org">
    </details>
    <div class="row"><button class="btn pri" id="tgSave">Save</button><button class="btn" id="tgTest">Send test message</button></div>
    <p class="note" id="tgMsg"></p>
    <p class="note" id="botMsg"></p>
    <p class="note">The bot menu works as soon as the token and chat ID are saved: open your bot in Telegram and send /start to see your servers.</p>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const WLABEL = {3600: '1 hour', 43200: '12 hours', 86400: '24 hours'};
const emptySeries = () => ({t: [], cpu: [], mem: [], disk: [], rx: [], tx: []});  // one entry per second, as columns
const GAP_MS = 5000;
let live = null, S = emptySeries(), rawBuf = [], meta = {}, WIN = 3600, SID = 'local';
try { SID = sessionStorage.getItem('sid') || 'local'; } catch (_) {}
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
let reload = true, gapSince = 0, histBusy = false, raf = 0;
const hover = {};
let pend = 0;
const soon = () => { if (!pend) pend = requestAnimationFrame(() => { pend = 0; try { render(); } catch (e) { console.error(e); } }); };

/* ---------- formatting ---------- */
function rateParts(b, unit){
  let v = unit === 'bit' ? b * 8 : b; const base = 1000;
  const u = unit === 'bit' ? ['bit/s','Kbit/s','Mbit/s','Gbit/s','Tbit/s'] : ['B/s','KB/s','MB/s','GB/s','TB/s'];
  let i = 0; while (v >= base && i < u.length - 1){ v /= base; i++; }
  return [(i === 0 ? v.toFixed(0) : v >= 100 ? v.toFixed(1) : v.toFixed(2)), u[i]];
}
const fmtRate = (b, unit) => rateParts(b, unit).join(' ');
function fmtBytes(b){
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1){ b /= 1024; i++; }
  return b.toFixed(i > 2 ? 2 : 0) + ' ' + u[i];
}
function niceMax(v){
  const e = Math.pow(10, Math.floor(Math.log10(v))), m = v / e;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 3 ? 3 : m <= 4 ? 4 : m <= 5 ? 5 : m <= 6 ? 6 : m <= 8 ? 8 : 10) * e;
}
function niceRate(b, unit){
  let v = unit === 'bit' ? b * 8 : b; const base = 1000; let i = 0;
  while (v >= base){ v /= base; i++; }
  const n = niceMax(Math.max(v, 1e-9)) * Math.pow(base, i);
  return unit === 'bit' ? n / 8 : n;
}
function rateAxis(maxB, unit){
  const base = 1000;
  const names = unit === 'bit' ? ['bit/s','Kbit/s','Mbit/s','Gbit/s','Tbit/s'] : ['B/s','KB/s','MB/s','GB/s','TB/s'];
  let v = unit === 'bit' ? maxB * 8 : maxB, i = 0;
  while (v >= base && i < names.length - 1){ v /= base; i++; }
  const div = Math.pow(base, i) / (unit === 'bit' ? 8 : 1);
  return {unit: names[i], fmt: b => { const n = b / div; return String(+(n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2))); }};
}
const pad = n => String(n).padStart(2, '0');
function tl(t, secs){ const d = new Date(t); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + (secs ? ':' + pad(d.getSeconds()) : ''); }

/* ---------- gauges ---------- */
const CX = 100, CY = 96, R = 72, G = {};
const pol = (a, r) => [CX + r * Math.cos(a * Math.PI / 180), CY + r * Math.sin(a * Math.PI / 180)];
function buildGauges(){
  const [x0, y0] = pol(135, R), [x1, y1] = pol(405, R);
  const d = `M${x0.toFixed(2)} ${y0.toFixed(2)} A${R} ${R} 0 1 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
  let ticks = '';
  for (let i = 0; i <= 10; i++){
    const a = 135 + 27 * i, p = pol(a, 63), q = pol(a, i % 5 ? 58.5 : 55);
    ticks += `<line class="tick${i % 5 ? '' : ' maj'}" x1="${p[0].toFixed(1)}" y1="${p[1].toFixed(1)}" x2="${q[0].toFixed(1)}" y2="${q[1].toFixed(1)}"/>`;
  }
  const defs = [['rx','In','--rx',1],['tx','Out','--tx',1],['cpu','CPU','--cpu',0],['ram','RAM','--ram',0],['disk','Disk','--disk',0]];
  const card = ([k, name, col, plain]) => plain ? `
    <div class="panel gauge plain" id="g-${k}" style="--col:var(${col})"><div class="gname">${name}</div>
    <span class="num">-</span><span class="unit"></span><div class="gsub"></div></div>` : `
    <div class="panel gauge" id="g-${k}" style="--col:var(${col})"><div class="gname">${name}</div>
    <svg viewBox="0 0 200 174" aria-hidden="true"><path class="track" d="${d}"/><path class="fill" d="${d}" pathLength="100"/>${ticks}
    <g class="needle"><path d="M-9 -3.2 L54 0 L-9 3.2Z"/></g><circle class="hub" cx="100" cy="96" r="8"/><circle class="hubin" cx="100" cy="96" r="3"/>
    <text class="num" x="100" y="141" text-anchor="middle">-</text><text class="unit" x="100" y="158" text-anchor="middle"></text>
    <text class="mn" x="48" y="169" text-anchor="middle">0</text><text class="mx" x="152" y="169" text-anchor="middle"></text></svg>
    <div class="gsub"></div></div>`;
  $('nums').innerHTML = defs.filter(x => x[3]).map(card).join('');
  $('gauges').innerHTML = defs.filter(x => !x[3]).map(card).join('');
  defs.forEach(([k]) => { const e = $('g-' + k), q = s => e.querySelector(s);
    G[k] = {e, cur: 0, target: 0, fill: q('.fill'), needle: q('.needle'), num: q('.num'), unit: q('.unit'), mx: q('.mx'), sub: q('.gsub')}; });
  tick();
}
const level = pct => pct >= 80 ? 2 : pct >= 50 ? 1 : 0;
function setGauge(k, frac, num, unit, mx, sub, lvl){
  const g = G[k]; g.target = clamp(frac, 0, 1);
  g.num.textContent = num; g.unit.textContent = unit; g.sub.textContent = sub;
  if (g.mx) g.mx.textContent = mx;
  g.e.classList.toggle('warn', lvl === 1); g.e.classList.toggle('hot', lvl === 2);
  if (g.fill && !raf) raf = requestAnimationFrame(tick);
}
function tick(){
  let busy = false;
  for (const g of Object.values(G)){
    if (!g.fill) continue;
    const d = g.target - g.cur;
    if (Math.abs(d) > .0008){ g.cur += d * .14; busy = true; } else g.cur = g.target;
    g.fill.style.strokeDashoffset = 100 * (1 - g.cur);
    g.fill.style.opacity = g.cur < .004 ? 0 : 1;
    g.needle.setAttribute('transform', `translate(${CX} ${CY}) rotate(${135 + 270 * g.cur})`);
  }
  raf = busy ? requestAnimationFrame(tick) : 0;
}

/* ---------- charts ---------- */
function monotone(P){
  const n = P.length, dx = [], m = [], t = new Array(n).fill(0);
  for (let i = 0; i < n - 1; i++){ dx[i] = P[i+1][0] - P[i][0]; m[i] = dx[i] ? (P[i+1][1] - P[i][1]) / dx[i] : 0; }
  t[0] = m[0]; t[n-1] = m[n-2];
  for (let i = 1; i < n - 1; i++) t[i] = m[i-1] * m[i] <= 0 ? 0 : (m[i-1] + m[i]) / 2;
  for (let i = 0; i < n - 1; i++){
    if (m[i] === 0){ t[i] = 0; t[i+1] = 0; continue; }
    const a = t[i] / m[i], b = t[i+1] / m[i], s = a * a + b * b;
    if (s > 9){ const k = 3 / Math.sqrt(s); t[i] = k * a * m[i]; t[i+1] = k * b * m[i]; }
  }
  return {dx, t};
}
function trace(c, P){
  c.moveTo(P[0][0], P[0][1]);
  if (P.length < 3){ for (let i = 1; i < P.length; i++) c.lineTo(P[i][0], P[i][1]); return; }
  const {dx, t} = monotone(P);
  for (let i = 0; i < P.length - 1; i++)
    c.bezierCurveTo(P[i][0] + dx[i]/3, P[i][1] + t[i]*dx[i]/3, P[i+1][0] - dx[i]/3, P[i+1][1] - t[i+1]*dx[i]/3, P[i+1][0], P[i+1][1]);
}
function rr(c, x, y, w, h, r){
  c.beginPath(); c.moveTo(x + r, y); c.arcTo(x + w, y, x + w, y + h, r); c.arcTo(x + w, y + h, x, y + h, r);
  c.arcTo(x, y + h, x, y, r); c.arcTo(x, y, x + w, y, r); c.closePath();
}
function lowerBound(a, x){ let lo = 0, hi = a.length; while (lo < hi){ const m = (lo + hi) >> 1; if (a[m] < x) lo = m + 1; else hi = m; } return lo; }
const dcache = new Map();
/* Chart points for a series: the highest value of every bw-millisecond bucket. Buckets are aligned to absolute time and
   cached, so each second only the newest bucket is touched (no re-scan of the 86 400 seconds of a day). */
function bucketsFor(key, T, V, bw, t0, span){
  let c = dcache.get(key);
  if (!c || c.T !== T || c.bw !== bw){ c = {T, bw, ids: [], vs: [], ts: [], last: 0}; dcache.set(key, c); }
  for (let i = lowerBound(T, c.last + 1); i < T.length; i++){
    const id = Math.floor(T[i] / bw), n = c.ids.length - 1;
    if (n >= 0 && c.ids[n] === id){ if (V[i] > c.vs[n]){ c.vs[n] = V[i]; c.ts[n] = T[i]; } }
    else { c.ids.push(id); c.vs.push(V[i]); c.ts.push(T[i]); }
    c.last = T[i];
  }
  const lo = Math.floor((t0 - span * .02) / bw); let k = 0;
  while (k < c.ids.length && c.ids[k] < lo) k++;
  if (k > 8){ c.ids.splice(0, k); c.vs.splice(0, k); c.ts.splice(0, k); }  // old buckets are dropped in batches
  return c;
}
function drawChart(cv, o){
  const box = cv.parentElement, dpr = Math.min(window.devicePixelRatio || 1, 3), w = box.clientWidth, h = box.clientHeight;
  if (!w || !h || w > 3000 || h > 1000) return;
  const W = Math.round(w * dpr), H = Math.round(h * dpr);
  if (cv.width !== W || cv.height !== H){ cv.width = W; cv.height = H; }
  const c = cv.getContext('2d'); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, w, h);
  c.font = '11px system-ui,-apple-system,sans-serif'; c.lineWidth = 1;
  const labels = [0, 1, 2, 3, 4].map(i => (o.axis || o.fmt)(o.max * (4 - i) / 4));
  const L = Math.max(44, Math.ceil(Math.max(...labels.map(t => c.measureText(t).width))) + 20);
  const Rm = 14, T = 12, B = 26, pw = w - L - Rm, ph = h - T - B, span = WIN * 1000, t0 = o.tEnd - span;
  const X = t => L + pw * (t - t0) / span, Y = v => T + ph - ph * clamp(v / o.max, 0, 1), muted = css('--muted');
  for (let i = 0; i <= 4; i++){
    const y = Math.round(T + ph * i / 4) + .5;
    c.setLineDash(i === 4 ? [] : [3, 5]); c.strokeStyle = i === 4 ? 'rgba(255,255,255,.16)' : 'rgba(255,255,255,.07)';
    c.beginPath(); c.moveTo(L, y); c.lineTo(L + pw, y); c.stroke();
    c.fillStyle = muted; c.textAlign = 'right'; c.textBaseline = 'middle'; c.fillText(labels[i], L - 8, y);
  }
  if (o.unitText){ c.textAlign = 'left'; c.textBaseline = 'top'; c.fillStyle = muted; c.fillText(o.unitText, L + 6, T + 4); }
  c.setLineDash([]); c.textBaseline = 'top';
  for (let i = 0; i <= 4; i++){
    c.textAlign = i === 0 ? 'left' : i === 4 ? 'right' : 'center';
    c.fillText(tl(t0 + span * i / 4, false), L + pw * i / 4 + (i === 0 ? -4 : i === 4 ? 4 : 0), h - B + 8);
  }
  c.save(); c.beginPath(); c.rect(L - 1, T - 6, pw + 2, ph + 12); c.clip();
  o.series.forEach(s => {
    const bw = Math.max(1000, Math.ceil(span / pw / 1000) * 1000), bk = bucketsFor(cv.id + ':' + s.name, s.T, s.V, bw, t0, span), P = [], pts = [];
    for (let i = 0; i < bk.ids.length; i++){
      if ((bk.ids[i] + 1) * bw < t0) continue;
      P.push([X(Math.min((bk.ids[i] + .5) * bw, o.tEnd)), Y(bk.vs[i])]); pts.push([bk.ts[i], bk.vs[i]]);
    }
    s.pts = pts; s.P = P;
    if (!P.length) return;
    const gapPx = Math.max(2.5, (o.gap || GAP_MS) / span * pw), segs = []; let cur = [];
    P.forEach((p, i) => { if (i && p[0] - P[i-1][0] > gapPx){ segs.push(cur); cur = []; } cur.push(p); }); if (cur.length) segs.push(cur);
    const g = c.createLinearGradient(0, T, 0, T + ph);
    g.addColorStop(0, s.color + (o.series.length > 1 ? '40' : '55')); g.addColorStop(1, s.color + '00');
    segs.forEach(Q => {
      if (Q.length < 2){ c.fillStyle = s.color; c.beginPath(); c.arc(Q[0][0], Q[0][1], 2, 0, 6.283); c.fill(); return; }
      c.beginPath(); trace(c, Q); c.lineTo(Q[Q.length-1][0], T + ph); c.lineTo(Q[0][0], T + ph); c.closePath(); c.fillStyle = g; c.fill();
      c.beginPath(); trace(c, Q); c.strokeStyle = s.color; c.lineWidth = 2.2; c.lineJoin = 'round'; c.stroke();
    });
  });
  c.restore();
  o.series.forEach(s => { const P = s.P; if (!P || !P.length) return; const p = P[P.length - 1];
    c.fillStyle = s.color + '33'; c.beginPath(); c.arc(p[0], p[1], 7, 0, 6.283); c.fill();
    c.fillStyle = s.color; c.beginPath(); c.arc(p[0], p[1], 3.5, 0, 6.283); c.fill(); });
  const hx = hover[cv.id];
  if (hx == null || hx < L || hx > L + pw) return;
  const tt = t0 + (hx - L) / pw * span, rows = [];
  o.series.forEach(s => { let best = null, bd = 1e18;
    s.pts.forEach(p => { const d = Math.abs(p[0] - tt); if (d < bd){ bd = d; best = p; } });
    if (best && bd < span * .06) rows.push([s, best]); });
  if (!rows.length) return;
  const ts = rows[0][1][0], x = clamp(X(ts), L, L + pw);
  c.strokeStyle = 'rgba(255,255,255,.35)'; c.lineWidth = 1; c.setLineDash([4, 4]);
  c.beginPath(); c.moveTo(x, T); c.lineTo(x, T + ph); c.stroke(); c.setLineDash([]);
  rows.forEach(([s, p]) => { c.fillStyle = '#0b1220'; c.strokeStyle = s.color; c.lineWidth = 2;
    c.beginPath(); c.arc(x, Y(p[1]), 4.5, 0, 6.283); c.fill(); c.stroke(); });
  c.font = '12px system-ui,-apple-system,sans-serif';
  const head = WIN <= 3600 ? tl(ts, true) : (pad(new Date(ts).getMonth() + 1) + '/' + pad(new Date(ts).getDate()) + ' ' + tl(ts, false)), lines = rows.map(([s, p]) => s.name + '  ' + (o.tip || o.fmt)(p[1]));
  const tw = Math.max(c.measureText(head).width, ...lines.map(l => c.measureText(l).width + 14)) + 22, th = 24 + lines.length * 18;
  let bx = x + 12; if (bx + tw > w - 4) bx = x - 12 - tw; bx = Math.max(4, bx);
  const by = T + 4;
  c.fillStyle = 'rgba(8,14,26,.95)'; c.strokeStyle = 'rgba(255,255,255,.14)'; rr(c, bx, by, tw, th, 8); c.fill(); c.stroke();
  c.textAlign = 'left'; c.textBaseline = 'middle'; c.fillStyle = muted; c.fillText(head, bx + 10, by + 13);
  rows.forEach(([s], i) => { const yy = by + 32 + i * 18;
    c.fillStyle = s.color; c.beginPath(); c.arc(bx + 14, yy, 4, 0, 6.283); c.fill();
    c.fillStyle = '#fff'; c.fillText(lines[i], bx + 24, yy); });
}

/* ---------- render ---------- */
function rates(s){
  const sel = $('iface').value; let rx = 0, tx = 0;
  for (const [k, v] of Object.entries(s.net)) if (sel === '__all__' ? k !== 'lo' : k === sel){ rx += v[0]; tx += v[1]; }
  return [rx, tx];
}
function syncIfaces(s){
  const names = Object.keys(s.net).sort(), sel = $('iface');
  if (['__all__', ...names].join('|') === [...sel.options].map(o => o.value).join('|')) return;
  const cur = sel.value || '__all__';
  sel.innerHTML = '<option value="__all__">All interfaces</option>' + names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
  sel.value = names.includes(cur) ? cur : '__all__';
}
function render(){
  if (!live) return;
  syncIfaces(live);
  const unit = $('unit').value, tot = live.mem.total || 1;
  const [rx, tx] = rates(live);
  let pkRx = rx, pkTx = tx;
  for (let i = 0; i < S.rx.length; i++){ if (S.rx[i] > pkRx) pkRx = S.rx[i]; if (S.tx[i] > pkTx) pkTx = S.tx[i]; }
  const lineMax = Math.max(pkRx, pkTx), wl = WLABEL[WIN];
  const top = niceRate(Math.max(lineMax, 125000) * 1.05, unit);
  const a = rateParts(rx, unit), b = rateParts(tx, unit), mx = fmtRate(top, unit);
  setGauge('rx', rx / top, a[0], a[1], mx, `Peak ${fmtRate(pkRx, unit)} (${wl})`);
  setGauge('tx', tx / top, b[0], b[1], mx, `Peak ${fmtRate(pkTx, unit)} (${wl})`);
  const mp = 100 * live.mem.used / tot;
  setGauge('cpu', live.cpu / 100, live.cpu.toFixed(1), '%', '100', `${meta.cores || live.cores.length} cores · load ${live.load[0].toFixed(2)}`, level(live.cpu));
  setGauge('ram', mp / 100, mp.toFixed(1), '%', '100', `${fmtBytes(live.mem.used)} / ${fmtBytes(tot)}`, level(mp));
  const dk = live.disk || {total: 0, used: 0}, dp = dk.total ? 100 * dk.used / dk.total : 0;
  setGauge('disk', dp / 100, dp.toFixed(1), '%', '100', dk.total ? `${fmtBytes(dk.used)} / ${fmtBytes(dk.total)}` : 'n/a', level(dp));
  $('lgDisk').textContent = dk.total ? dp.toFixed(1) + '%' : 'n/a';
  $('lgRx').textContent = fmtRate(rx, unit); $('lgTx').textContent = fmtRate(tx, unit);
  $('lgCpu').textContent = live.cpu.toFixed(1) + '%'; $('lgRam').textContent = mp.toFixed(1) + '%';
  const tEnd = S.t.length ? S.t[S.t.length - 1] : live.t, ser = (name, color, V) => ({name, color: css(color), T: S.t, V});
  const ntop = niceRate(Math.max(lineMax, 125000) * 1.05, unit), ax = rateAxis(ntop, unit);
  $('netNote').textContent = '· highest value per 1 s';
  const pct = {fmt: v => v.toFixed(0) + '%', tip: v => v.toFixed(1) + '%'};
  drawChart($('cNet'), {tEnd, max: ntop, fmt: v => fmtRate(v, unit), axis: ax.fmt, unitText: ax.unit, series: [ser('In', '--rx', S.rx), ser('Out', '--tx', S.tx)]});
  drawChart($('cCpu'), Object.assign({tEnd, max: 100, series: [ser('CPU', '--cpu', S.cpu)]}, pct));
  drawChart($('cRam'), Object.assign({tEnd, max: 100, series: [ser('RAM', '--ram', S.mem)]}, pct));
  drawChart($('cDisk'), Object.assign({tEnd, max: 100, series: [ser('Disk', '--disk', S.disk)]}, pct));
  $('cores').innerHTML = live.cores.map((p, i) => `<div class="core">CPU${i} · ${p.toFixed(0)}%<div><i style="width:${p}%"></i></div></div>`).join('');
  $('fLoad').textContent = 'Load ' + live.load.map(x => x.toFixed(2)).join(' / ');
  $('fSwap').textContent = live.mem.swap_total ? `Swap ${fmtBytes(live.mem.swap_used)} / ${fmtBytes(live.mem.swap_total)}` : 'Swap off';
  const s = live.uptime; $('fUp').textContent = `Uptime ${Math.floor(s / 86400)}d ${Math.floor(s % 86400 / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
}

/* ---------- data: small polling requests (works through VPNs and proxies) ---------- */
function setLive(on, txt){ $('status').textContent = txt; $('status').className = on ? 'live' : ''; }
async function getJSON(url, ms){
  const ac = new AbortController(), timer = setTimeout(() => ac.abort(), ms || 6000);
  try {
    const r = await fetch(url, {cache: 'no-store', signal: ac.signal});
    if (r.status === 401){
      const j = await r.json().catch(() => ({}));
      try { const n = Date.now(), l = +sessionStorage.getItem('rl') || 0; if (n - l > 10000){ sessionStorage.setItem('rl', n); location.reload(); } } catch (_) {}
      throw new Error('unauthorized (' + (j.reason || '?') + ')');
    }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  } finally { clearTimeout(timer); }
}
async function postJSON(url, body){
  const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
const api = (name, extra) => `api/${name}?s=${encodeURIComponent(SID)}` + (extra || '');
function applyMeta(m){
  if (!m) return; meta = m;
  const n = m.name || m.host || '';
  $('host').textContent = n; document.title = 'Monitor · ' + n;
  $('logout').style.display = m.auth ? 'inline-block' : 'none';
}

/* ---------- servers ---------- */
let servers = [], lastSrv = 0, srvBusy = false;
function renderServers(){
  $('servers').innerHTML = servers.map(s => `<button class="sv${s.id === SID ? ' on' : ''}" data-id="${esc(s.id)}" title="${esc(s.host || '')}">
    <i class="dot ${s.online ? 'on' : 'off'}"></i>${esc(s.name)}<small>${s.online ? (s.cpu != null ? s.cpu.toFixed(0) + '%' : '') : 'offline'}</small></button>`).join('')
    + '<button class="sv add" id="svAdd">+ Add server</button>';
}
function resetView(){
  for (const g of Object.values(G)){ g.target = 0; g.num.textContent = '-'; g.unit.textContent = ''; g.sub.textContent = ''; g.e.classList.remove('warn', 'hot'); }
  if (!raf) raf = requestAnimationFrame(tick);
  for (const id of ['cNet', 'cCpu', 'cRam', 'cDisk']){ const cv = $(id); cv.getContext('2d').clearRect(0, 0, cv.width, cv.height); hover[id] = null; }
  for (const id of ['lgRx', 'lgTx', 'lgCpu', 'lgRam', 'lgDisk']) $(id).textContent = '-';
  $('cores').innerHTML = ''; $('netNote').textContent = ''; $('iface').innerHTML = '';
}
function selectServer(id){
  if (id === SID) return;
  SID = id; try { sessionStorage.setItem('sid', id); } catch (_) {}
  live = null; S = emptySeries(); rawBuf = []; meta = {}; reload = true; gapSince = 0;
  resetView(); renderServers(); setLive(false, 'Loading…');
}
function refreshServers(){
  if (srvBusy) return; srvBusy = true; lastSrv = Date.now();
  getJSON('api/servers').then(l => {
    servers = l;
    if (!servers.some(s => s.id === SID)) selectServer('local');
    renderServers();
  }).catch(() => {}).finally(() => { srvBusy = false; });
}

/* Every chart point is one second. The whole day is downloaded once (columns, gzip); after that each second only the
   new sample is appended, and a short gap (tab in the background, lost connection) is filled with just the missing seconds. */
function appendSample(x){
  const n = S.t.length; if (n && x.t <= S.t[n - 1]) return;
  const m = x.mem, d = x.disk || {used: 0, total: 0}, [a, b] = rates(x);
  S.t.push(x.t); S.cpu.push(x.cpu); S.mem.push(m.total ? 100 * m.used / m.total : 0);
  S.disk.push(d.total ? 100 * d.used / d.total : 0); S.rx.push(a); S.tx.push(b);
}
function trimSeries(){
  const n = S.t.length; if (!n) return;
  const cut = S.t[n - 1] - WIN * 1000 - 60000;
  if (S.t[0] >= cut - 30000) return;  // trimmed in batches
  const k = lowerBound(S.t, cut);
  for (const key in S) S[key].splice(0, k);
}
function decodeSeries(j, append){
  const n = j.n || 0, mt = j.mt || 1, dtot = j.dt || 0, last = append && S.t.length ? S.t[S.t.length - 1] : 0;
  if (!append) S = emptySeries();
  let t = 0;
  for (let i = 0; i < n; i++){
    t += j.t[i]; if (t <= last) continue;
    S.t.push(t); S.cpu.push(j.cpu[i] / 10); S.mem.push(100 * j.mu[i] * 1048576 / mt);
    S.disk.push(dtot ? 100 * j.du[i] * 1048576 / dtot : 0); S.rx.push(j.rx[i] * 125); S.tx.push(j.tx[i] * 125);
  }
}
function loadSeries(since){
  histBusy = true; const w = WIN, sid = SID, ifc = $('iface').value || '__all__';
  getJSON(api('series', '&w=' + w + '&iface=' + encodeURIComponent(ifc) + (since ? '&since=' + since : '')), 60000).then(j => {
    if (w !== WIN || sid !== SID || ifc !== ($('iface').value || '__all__')) { reload = true; return; }
    applyMeta(j.meta); decodeSeries(j, !!since);
    for (const x of rawBuf) appendSample(x);  // seconds that arrived while the download was running
    trimSeries(); render();
  }).catch(() => { reload = true; }).finally(() => { histBusy = false; });
}
async function loop(){
  for (;;){
    if (document.hidden){ await new Promise(r => setTimeout(r, 1000)); continue; }  // save battery and data in the background
    const t0 = Date.now(), sid = SID;
    let ok = false;
    try {
      if (Date.now() - lastSrv > 3000) refreshServers();
      if (!histBusy && (reload || gapSince)){ const g = reload ? 0 : gapSince; reload = false; gapSince = 0; loadSeries(g); }
      const d = await getJSON(api('poll', live ? '&since=' + live.t : ''));
      if (sid === SID){
        applyMeta(d.meta);
        if (d.samples.length){
          if (live && S.t.length && !reload && d.samples[0].t - live.t > GAP_MS) gapSince = S.t[S.t.length - 1];  // missed seconds: fetch them
          const hold = histBusy || reload || gapSince;  // while a download is pending, new seconds wait in rawBuf
          for (const x of d.samples){ rawBuf.push(x); if (!hold) appendSample(x); }
          if (rawBuf.length > 130) rawBuf.splice(0, rawBuf.length - 130);
          trimSeries();
          live = d.samples[d.samples.length - 1];
        }
        ok = true;
      }
    } catch (e) {
      setLive(false, 'Disconnected: ' + (e.name === 'AbortError' ? 'timeout' : String(e.message || e).slice(0, 60)));
    }
    if (ok){
      try {
        render();
        if (meta.online === false) setLive(false, 'Offline · last seen ' + (meta.last_seen ? tl(meta.last_seen, true) : 'never'));
        else setLive(true, 'Live');
      } catch (e) { console.error(e); setLive(false, 'Display error: ' + String(e.message || e).slice(0, 50)); }
    }
    await new Promise(r => setTimeout(r, Math.max(200, 1000 - (Date.now() - t0))));
  }
}

/* ---------- settings: servers + Telegram ---------- */
function say(id, text, cls){ const e = $(id); e.textContent = text; e.className = 'note' + (cls ? ' ' + cls : ''); e.hidden = !text; }
function renderNodeList(list){
  $('nodeList').innerHTML = list.filter(x => !x.local).map(x => `<div class="node"><i class="dot ${x.online ? 'on' : 'off'}"></i>
    <span>${esc(x.name)}</span><small style="color:var(--muted)">${x.online ? 'online' : 'offline'}${x.version ? ' · v' + esc(x.version) : ''}</small>${x.outdated ? '<small class="tag" title="Run on that server: server-monitor update">update available</small>' : ''}
    <button class="btn danger" data-del="${esc(x.id)}">Remove</button></div>`).join('')
    || '<p class="note">No other servers yet. Add one below to monitor it from this panel.</p>';
}
async function loadSettings(){
  const [s, list] = await Promise.all([getJSON('api/settings'), getJSON('api/servers')]);
  const t = s.telegram;
  $('localName').value = s.local_name || '';
  $('tgOn').checked = !!t.enabled; $('tgOff').checked = t.offline !== false; $('tgToken').value = '';
  $('tgToken').placeholder = t.token_set ? `Saved (${t.token_hint}) - leave empty to keep it` : 'Bot token (from @BotFather)';
  $('tgChat').value = t.chat_id || ''; $('tgLimit').value = t.threshold; $('tgProxy').value = t.proxy || '';
  $('tgBase').value = t.api_base || '';
  const st = s.tg_status;
  say('tgMsg', st && st.msg ? `Last Telegram result: ${st.msg}` : '', st && st.ok === false ? 'err' : (st && st.ok ? 'ok' : ''));
  const bt = s.bot; say('botMsg', bt && bt.msg ? bt.msg : '', bt && bt.ok === false ? 'err' : (bt && bt.ok ? 'ok' : ''));
  renderNodeList(list);
}
let nodeToken = '';
const nodeOrigin = () => {
  const a = ($('nodeAddr').value.trim() || location.host).replace(/[^A-Za-z0-9.:\[\]\/_-]/g, '').replace(/\/+$/, '');
  return /^https?:\/\//.test(a) ? a : location.protocol + '//' + a;
};
const showNodeCmd = () => { if (nodeToken) $('nodeCmd').value = `curl -fsSL "${nodeOrigin()}/node-install.sh?token=${nodeToken}" | sudo bash`; };
async function openSettings(focusAdd){
  $('modal').hidden = false; $('nodeResult').hidden = true; say('nodeErr', '');
  if (!$('nodeAddr').value) $('nodeAddr').value = location.host;
  try { await loadSettings(); } catch (e) { say('tgMsg', 'Could not load settings: ' + e.message, 'err'); }
  if (focusAdd) $('nodeName').focus();
}
const closeSettings = () => { $('modal').hidden = true; };
function tgBody(){
  const t = {enabled: $('tgOn').checked, offline: $('tgOff').checked, chat_id: $('tgChat').value, threshold: $('tgLimit').value, proxy: $('tgProxy').value, api_base: $('tgBase').value};
  if ($('tgToken').value) t.token = $('tgToken').value;
  return {local_name: $('localName').value, telegram: t};
}
async function saveTelegram(){
  try { await postJSON('api/settings', tgBody()); await loadSettings(); say('tgMsg', 'Saved.', 'ok'); refreshServers(); return true; }
  catch (e) { say('tgMsg', e.message, 'err'); return false; }
}
$('tgSave').onclick = saveTelegram;
$('tgTest').onclick = async () => {
  if (!await saveTelegram()) return;
  say('tgMsg', 'Sending…');
  try { const j = await postJSON('api/telegram/test'); say('tgMsg', j.msg, j.ok ? 'ok' : 'err'); } catch (e) { say('tgMsg', e.message, 'err'); }
};
$('nodeAdd').onclick = async () => {
  say('nodeErr', '');
  try {
    const j = await postJSON('api/nodes', {name: $('nodeName').value});
    nodeToken = j.token; showNodeCmd();
    $('nodeResult').hidden = false; $('nodeName').value = '';
    renderNodeList(await getJSON('api/servers')); refreshServers();
  } catch (e) { say('nodeErr', e.message, 'err'); }
};
$('nodeAddr').oninput = showNodeCmd;
$('nodeCopy').onclick = () => {
  const t = $('nodeCmd'); t.select();
  try { (navigator.clipboard ? navigator.clipboard.writeText(t.value) : Promise.reject()).catch(() => document.execCommand('copy')); } catch (_) { document.execCommand('copy'); }
  $('nodeCopy').textContent = 'Copied';
  setTimeout(() => { $('nodeCopy').textContent = 'Copy command'; }, 1500);
};
$('nodeList').onclick = async e => {
  const b = e.target.closest('button[data-del]'); if (!b) return;
  if (!confirm('Remove this server and its saved history?')) return;
  try { await postJSON('api/nodes/delete', {id: b.dataset.del}); renderNodeList(await getJSON('api/servers')); refreshServers(); }
  catch (er) { say('nodeErr', er.message, 'err'); }
};

/* ---------- events ---------- */
$('win').onclick = e => {
  const b = e.target.closest('button'); if (!b) return;
  WIN = +b.dataset.w; [...$('win').children].forEach(x => x.classList.toggle('on', x === b));
  S = emptySeries(); rawBuf.length = 0; reload = true; gapSince = 0; soon();
};
$('unit').onchange = soon;
$('iface').onchange = () => { S = emptySeries(); rawBuf.length = 0; reload = true; gapSince = 0; soon(); };
$('logout').onclick = () => fetch('logout', {method: 'POST'}).then(() => location.reload());
$('settingsBtn').onclick = () => openSettings(false);
$('mClose').onclick = closeSettings;
$('modal').onclick = e => { if (e.target === $('modal')) closeSettings(); };
addEventListener('keydown', e => { if (e.key === 'Escape') closeSettings(); });
$('servers').onclick = e => {
  const b = e.target.closest('button'); if (!b) return;
  if (b.id === 'svAdd') openSettings(true); else selectServer(b.dataset.id);
};
['cNet', 'cCpu', 'cRam', 'cDisk'].forEach(id => {
  const cv = $(id), set = e => { hover[id] = e.clientX - cv.getBoundingClientRect().left; soon(); }, clr = () => { hover[id] = null; soon(); };
  cv.addEventListener('pointermove', set); cv.addEventListener('pointerdown', set);
  cv.addEventListener('pointerleave', clr); cv.addEventListener('pointercancel', clr);
});
addEventListener('resize', soon);
addEventListener('error', ev => setLive(false, 'Script error: ' + String(ev.message).slice(0, 50)));
buildGauges(); refreshServers(); loop();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- maintenance commands: update / uninstall / status / restart
def install_launcher(path=LAUNCHER):
    """Create the `server-monitor` command (update, uninstall, status, restart)."""
    try:
        with open(path, "w") as f:
            f.write('#!/bin/sh\nexec %s %s "$@"\n' % (shlex.quote(sys.executable), shlex.quote(os.path.abspath(__file__))))
        os.chmod(path, 0o755)
    except OSError as e:
        print(f"  (could not create the {path} command: {e})")


def ensure_launcher():
    """Services installed by an older version get the command the first time they start with a newer one."""
    try:
        if "INVOCATION_ID" in os.environ and os.geteuid() == 0 and not os.path.exists(LAUNCHER):
            install_launcher()
    except Exception:
        pass


def fetch_bytes(url, insecure=False):
    ctx = ssl._create_unverified_context() if insecure else None
    req = urllib.request.Request(url, headers={"User-Agent": "server-monitor-updater"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return r.read(8_000_000)


def unit_file(name):
    return os.path.join(UNIT_DIR, name + ".service")


def installed_units():
    return [n for n in UNITS if os.path.exists(unit_file(n))]


def unit_args(name):
    """Command line of an installed service (so custom --config / --data-dir paths are honoured)."""
    try:
        with open(unit_file(name)) as f:
            for line in f:
                if line.startswith("ExecStart="):
                    return shlex.split(line[len("ExecStart="):].strip())
    except (OSError, ValueError):
        pass
    return []


def arg_value(args, flag):
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(flag + "="):
            return a[len(flag) + 1:]
    return ""


def systemctl(*a):
    return subprocess.run(["systemctl", *a], capture_output=True, text=True)


def node_cfg_path():
    return os.path.abspath(os.path.expanduser(ARGS.node_config or NODE_CFG_DEFAULT))


def update_source():
    """Where to download the new version from: --url > saved address > the main panel (for nodes)."""
    node = load_json(node_cfg_path()) or {}
    cred = load_cred(ARGS.config) or {}
    if ARGS.url:
        return ARGS.url, bool(ARGS.insecure)
    if node.get("update_url"):
        return node["update_url"], bool(node.get("insecure"))
    if cred.get("update_url"):
        return cred["update_url"], False
    if node.get("url") and node.get("token"):
        return node["url"].rstrip("/") + "/node.py?token=" + urllib.parse.quote(node["token"], safe=""), bool(node.get("insecure"))
    return "", False


def save_update_url(url):
    cred = load_cred(ARGS.config)
    node = load_json(node_cfg_path())
    if cred:
        cred["update_url"] = url
        save_cred(ARGS.config, cred)
    elif node:
        node["update_url"] = url
        save_json(node_cfg_path(), node)


def cmd_update():
    url, insecure = update_source()
    if not url:
        print("No update source is known for this server.\n"
              "  - On the main panel run once:  server-monitor update --url https://raw.githubusercontent.com/USER/REPO/main/server_monitor.py\n"
              "    (the address is remembered for the next time)\n"
              "  - A node updates itself from its main panel, so update the main panel first.", file=sys.stderr)
        return 2
    target = os.path.abspath(__file__)
    print(f"Downloading the latest version from {re.sub(r'token=[^&]+', 'token=...', url)} ...")
    try:
        data = fetch_bytes(url, insecure)
        text = data.decode("utf-8")
        compile(text, "server_monitor.py", "exec")
        if "def main()" not in text or "SCRIPT_HASH" not in text:
            raise ValueError("this is not a Server Monitor script")
    except Exception as e:
        print(f"Update failed, nothing was changed: {e}", file=sys.stderr)
        return 1
    new_hash = hashlib.sha256(data).hexdigest()[:12]
    m = re.search(r'^VERSION = "([^"]+)"', text, re.M)
    new_ver = m.group(1) if m else "?"
    if ARGS.url:
        save_update_url(ARGS.url)
    if new_hash == SCRIPT_HASH and not ARGS.force:
        print(f"Already up to date (version {VERSION}).")
        return 0
    try:
        shutil.copy2(target, target + ".bak")
        tmp = target + ".new"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, os.stat(target).st_mode & 0o777)
        os.replace(tmp, target)
    except OSError as e:
        print(f"Cannot write {target}: {e}", file=sys.stderr)
        return 1
    print(f"Updated: {VERSION} -> {new_ver}")
    units = installed_units()
    if not units or not shutil.which("systemctl"):
        print("Restart the program to start using the new version.")
        return 0
    for n in units:
        systemctl("restart", n)
    time.sleep(4)
    bad = [n for n in units if systemctl("is-active", n).stdout.strip() != "active"]
    if bad:
        shutil.copy2(target + ".bak", target)
        for n in units:
            systemctl("restart", n)
        print(f"The new version did not start ({', '.join(bad)}). The previous version was restored.", file=sys.stderr)
        return 1
    print("Restarted: " + ", ".join(units) + "  -  the new version is running.")
    return 0


def cmd_restart():
    units = installed_units()
    if not units or not shutil.which("systemctl"):
        print("No Server Monitor service is installed on this server.", file=sys.stderr)
        return 1
    for n in units:
        r = systemctl("restart", n)
        print(f"  {n}: " + ("restarted" if r.returncode == 0 else "failed - " + (r.stderr or "").strip()))
    return 0


def cmd_status():
    print(f"Server Monitor {VERSION}   ({os.path.abspath(__file__)})")
    units = installed_units()
    if not units:
        print("  No service is installed here (the program may be running in a terminal).")
    for n in units:
        st = (systemctl("is-active", n).stdout.strip() if shutil.which("systemctl") else "") or "unknown"
        args = unit_args(n)
        if n == "server-monitor":
            cfg = os.path.abspath(os.path.expanduser(arg_value(args, "--config") or ARGS.config))
            port = (load_cred(cfg) or {}).get("port") or arg_value(args, "--port") or 8080
            extra = f"panel port {port}"
        else:
            node = load_json(os.path.abspath(os.path.expanduser(arg_value(args, "--node-config") or NODE_CFG_DEFAULT))) or {}
            extra = f"reports to {node.get('url', '?')}"
        print(f"  {n:<22} {st:<10} {extra}")
    print("  Update: server-monitor update     Uninstall: server-monitor uninstall")
    return 0


def _remove(path):
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def _remove_history(directory):
    """Delete only the files this program creates in a history directory."""
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for n in names:
        p = os.path.join(directory, n)
        if re.fullmatch(r"\d+\.(seg|min)", n):
            _remove(p)
        elif n == "nodes" and os.path.isdir(p):
            for sub in os.listdir(p):
                if NODE_ID_RE.match(sub):
                    shutil.rmtree(os.path.join(p, sub), ignore_errors=True)
            try:
                os.rmdir(p)
            except OSError:
                pass
    try:
        os.rmdir(directory)
    except OSError:
        pass


def cmd_uninstall():
    units = installed_units()
    script = os.path.abspath(__file__)
    cfgs, node_cfgs, data_dirs = {ARGS.config}, {node_cfg_path()}, set()
    for n in units:
        a = unit_args(n)
        if arg_value(a, "--config"):
            cfgs.add(os.path.abspath(os.path.expanduser(arg_value(a, "--config"))))
        if arg_value(a, "--node-config"):
            node_cfgs.add(os.path.abspath(os.path.expanduser(arg_value(a, "--node-config"))))
        if arg_value(a, "--data-dir"):
            data_dirs.add(os.path.abspath(os.path.expanduser(arg_value(a, "--data-dir"))))
    if ARGS.data_dir:
        data_dirs.add(os.path.abspath(os.path.expanduser(ARGS.data_dir)))
    for c in cfgs:
        data_dirs.add(os.path.join(os.path.dirname(c), ".server_monitor_data"))
    was_panel = "server-monitor" in units or any(load_cred(c) for c in cfgs)

    print("This will remove Server Monitor from this server:")
    for n in units:
        print(f"  - the '{n}' service")
    if os.path.exists(LAUNCHER):
        print(f"  - the command {LAUNCHER}")
    print(f"  - the program file {script}")
    if not ARGS.yes:
        if not sys.stdin.isatty():
            print("Add --yes to confirm.", file=sys.stderr)
            return 2
        if not ask_yes_no("Continue?", default=False):
            print("Cancelled. Nothing was removed.")
            return 1
    purge = ARGS.purge
    if not purge and not ARGS.yes and sys.stdin.isatty():
        purge = ask_yes_no("Also delete the saved login, settings and history of this server?", default=False)

    have_systemctl = shutil.which("systemctl") is not None
    for n in units:
        if have_systemctl:
            systemctl("disable", "--now", n)
        _remove(unit_file(n))
    if units and have_systemctl:
        systemctl("daemon-reload")
    try:
        with open(LAUNCHER) as f:
            if "server_monitor.py" in f.read():
                _remove(LAUNCHER)
    except OSError:
        pass
    if purge:
        for c in cfgs:
            if load_cred(c):
                d = os.path.dirname(c)
                for name in (os.path.basename(c), ".server_monitor_secret", ".server_monitor_settings.json", ".server_monitor_nodes.json"):
                    _remove(os.path.join(d, name))
        for nc in node_cfgs:
            if (load_json(nc) or {}).get("token"):
                _remove(nc)
        for dd in data_dirs:
            _remove_history(dd)
    for suffix in ("", ".bak", ".new"):
        _remove(script + suffix)
    try:
        if os.path.basename(os.path.dirname(script)) == "server-monitor":
            os.rmdir(os.path.dirname(script))
    except OSError:
        pass
    print("\nServer Monitor was removed from this server." + ("" if purge else "\nYour saved login, settings and history were kept (add --purge to delete them)."))
    if was_panel:
        print("Servers connected to this panel keep running; remove them too with:  server-monitor uninstall")
    print("If the program is still running in a terminal, stop it with Ctrl+C.")
    return 0


def node_main(ap):
    path = os.path.abspath(os.path.expanduser(ARGS.node_config or NODE_CFG_DEFAULT))
    if ARGS.node:
        url = ARGS.node.strip().rstrip("/")
        if not re.fullmatch(r"https?://[^/\s]+(/\S*)?", url):
            ap.error("--node must look like http://HOST:PORT")
        if not ARGS.token:
            ap.error("--token is required with --node (create it in the panel: Settings -> Add server)")
        cfg = {"url": url, "token": ARGS.token.strip(), "insecure": bool(ARGS.insecure)}
        save_json(path, cfg)
    else:
        cfg = load_json(path)
        if not cfg or not cfg.get("url") or not cfg.get("token"):
            print(f"Node settings not found in {path}.", file=sys.stderr)
            return 2
    if ARGS.install_service:
        if can_install_service():
            try:
                install_node_service(path)
                ok = "\u2714" if "utf" in (getattr(sys.stdout, "encoding", "") or "").lower() else "[OK]"
                print(f"\n{ok} Server Monitor node installed. It reports to {cfg['url']} and will appear in the panel.")
                print(f"  Manage it with:  systemctl status|restart|stop {NODE_SERVICE_NAME}\n")
                return 0
            except Exception as e:
                print(f"Could not install the service ({e}). Running in the foreground instead.", file=sys.stderr)
        else:
            print("systemd is not available here (or you are not root). Running in the foreground instead.", file=sys.stderr)
    run_node(cfg)
    return 0


def main():
    global ARGS, CRED, KEY, DATA_DIR, SETTINGS_PATH, NODES_PATH
    ap = argparse.ArgumentParser(description="Live network / CPU / RAM / disk monitor with a login-protected web panel "
                                             "and support for multiple servers",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="commands (also available as `server-monitor <command>` after installation):\n"
                                        "  update      download and install the newest version, then restart the service\n"
                                        "  uninstall   remove the service, the command and the program (asks before deleting data)\n"
                                        "  status      show the version and the state of the service\n"
                                        "  restart     restart the service")
    ap.add_argument("command", nargs="?", choices=("update", "uninstall", "status", "restart"), help="maintenance command (see below)")
    ap.add_argument("--version", action="version", version=f"server_monitor {VERSION}")
    ap.add_argument("--url", default="", help="(update) address of the newest server_monitor.py; remembered for next time")
    ap.add_argument("--force", action="store_true", help="(update) reinstall even if the version is the same")
    ap.add_argument("--yes", action="store_true", help="(uninstall) do not ask for confirmation")
    ap.add_argument("--purge", action="store_true", help="(uninstall) also delete the saved login, settings and history")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0 = all interfaces)")
    ap.add_argument("--port", type=int, default=None, help="panel port (default: the port chosen at setup, or 8080)")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="where the login is saved (default: ~/.server_monitor.json)")
    ap.add_argument("--reset", action="store_true", help="choose a new username and password")
    ap.add_argument("--data-dir", default="", help="where the 24 h history is saved (default: next to the config file)")
    ap.add_argument("--user", default=os.environ.get("MONITOR_USER", ""), help="set the username without prompting")
    ap.add_argument("--password", default=os.environ.get("MONITOR_PASS", ""), help="set the password without prompting")
    ap.add_argument("--cert", default="", help="TLS certificate file (enables HTTPS)")
    ap.add_argument("--key", default="", help="TLS private key file")
    ap.add_argument("--node", default="", help="run as a node: send this server's metrics to the main panel at this URL")
    ap.add_argument("--token", default="", help="node token created in the main panel (with --node)")
    ap.add_argument("--node-config", default="", help="node settings file (default: ~/.server_monitor_node.json)")
    ap.add_argument("--install-service", action="store_true", help="(node mode) install and start a systemd service")
    ap.add_argument("--insecure", action="store_true", help="(node mode) do not verify the HTTPS certificate of the main panel")
    ARGS = ap.parse_args()
    ARGS.config = os.path.abspath(os.path.expanduser(ARGS.config))
    if ARGS.command:
        return {"update": cmd_update, "uninstall": cmd_uninstall, "status": cmd_status, "restart": cmd_restart}[ARGS.command]()
    ensure_launcher()
    if ARGS.node or ARGS.node_config:
        return node_main(ap)

    ARGS.config = os.path.abspath(os.path.expanduser(ARGS.config))
    if ARGS.port is not None and not 1 <= ARGS.port <= 65535:
        ap.error("--port must be between 1 and 65535")
    if bool(ARGS.cert) != bool(ARGS.key):
        ap.error("--cert and --key must be used together")
    given = bool(ARGS.user or ARGS.password)
    if given and not (ARGS.user and ARGS.password):
        ap.error("--user and --password must be used together")
    if given and not (check_username(ARGS.user) and check_password(ARGS.password)):
        ap.error("username: 3-32 letters/digits/_-. ; password: at least 6 characters")

    stored = load_cred(ARGS.config)
    saved_port = int((stored or {}).get("port") or 0)
    cred, fresh, plain_pw = stored, False, None
    if given and stored and not ARGS.reset and verify_cred(stored, ARGS.user, ARGS.password):
        pass  # same login as already saved: keep it (sessions stay valid across restarts)
    elif given or ARGS.reset or stored is None:
        if given:
            user, pw, port = ARGS.user, ARGS.password, ARGS.port or saved_port or 8080
        elif sys.stdin.isatty():
            try:
                port, user, pw = ask_setup(ARGS.port, saved_port)
            except (EOFError, KeyboardInterrupt):
                print("\nSetup cancelled.")
                return 1
        else:
            print("No login has been set up yet.\nRun this script once in an interactive terminal "
                  "(or pass --user and --password).", file=sys.stderr)
            return 2
        cred = make_cred(user, pw, port)
        save_cred(ARGS.config, cred)
        fresh, plain_pw = True, pw
        ARGS.port = port
    ARGS.port = ARGS.port or int(cred.get("port") or 0) or 8080  # --port > port chosen at setup > 8080
    upd = ARGS.url or os.environ.get("SM_UPDATE_URL", "")  # set by install.sh: where `server-monitor update` downloads from
    if upd and (fresh or not cred.get("update_url")) and cred.get("update_url") != upd:
        cred["update_url"] = upd
        save_cred(ARGS.config, cred)
    CRED = cred
    cfg_dir = os.path.dirname(ARGS.config)
    KEY = _load_secret(os.path.join(cfg_dir, ".server_monitor_secret")) + bytes.fromhex(cred["hash"])

    scheme = "https" if ARGS.cert else "http"
    interactive = sys.stdout.isatty()
    url = panel_url(scheme) if (fresh or interactive) else f"{scheme}://{ARGS.host}:{ARGS.port}"
    if fresh:
        print_success(url, cred["user"], plain_pw if interactive else None)
        print(f"  If the link does not open, allow TCP port {ARGS.port} in your firewall (for example: ufw allow {ARGS.port}/tcp).\n")
        if interactive and sys.stdin.isatty() and can_install_service():
            if ask_yes_no("Keep it running in the background (survives closing the terminal and reboots)?"):
                try:
                    install_service()
                    print(f"\n  Done. The panel is running as the '{SERVICE_NAME}' service.")
                    print(f"  Manage it with:  systemctl status|restart|stop {SERVICE_NAME}")
                    print("  To monitor more servers, open the panel -> Settings -> Add server.\n")
                    return 0
                except Exception as e:
                    print(f"  Could not install the service ({e}). Running in the foreground instead.")
    else:
        print(f"Server monitor: {url}   (user: {cred['user']}; run with --reset to change the login)")

    DATA_DIR = os.path.abspath(os.path.expanduser(ARGS.data_dir)) if ARGS.data_dir else os.path.join(cfg_dir, ".server_monitor_data")
    SETTINGS_PATH = os.path.join(cfg_dir, ".server_monitor_settings.json")
    NODES_PATH = os.path.join(cfg_dir, ".server_monitor_nodes.json")
    load_settings()
    local = Source(LOCAL_ID, local_name(), DATA_DIR, local=True)
    local.load()
    with SOURCES_LOCK:
        SOURCES[LOCAL_ID] = local
    load_nodes()
    threading.Thread(target=local_sampler, args=(local,), daemon=True).start()
    threading.Thread(target=bot_loop, daemon=True).start()
    threading.Thread(target=offline_watch, daemon=True).start()
    try:
        srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    except OSError as e:
        print(f"Cannot listen on {ARGS.host}:{ARGS.port} ({e.strerror}). Is Server Monitor already running?\n"
              f"If it runs as a service, apply a new login with: systemctl restart {SERVICE_NAME}", file=sys.stderr)
        return 1
    srv.daemon_threads = True
    if ARGS.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ARGS.cert, ARGS.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
