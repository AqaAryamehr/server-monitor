# Server Monitor

A lightweight, single-file web panel for Linux servers. It shows **network traffic (in/out), CPU, RAM and disk**
live, every second, keeps a 24-hour history, sends **Telegram alerts**, and can monitor **many servers from one
dashboard** (like a tiny Netdata).

- Live numbers for traffic In / Out, gauges for CPU, RAM and Disk (yellow from 50 %, red from 80 %)
- History charts for traffic, CPU, RAM and disk over **1 hour, 12 hours and 24 hours**, with **one data point per second**
  (where the screen has fewer pixels than seconds, every pixel shows the highest second it covers, so no spike is lost;
  hover or touch for the exact second and value)
- Charts update **every second**: the day is downloaded once (about 0.7 MB, compressed), then only the newest second per update
- Every second is saved to disk and survives restarts; exactly the last 24 hours are kept
  (every second, the second that just became 24 hours old is deleted, so disk usage stays constant: about 8-12 MB per server)
- **Multi-server**: install the panel on one server, connect other servers as nodes, click a server to monitor it
- **Telegram alerts** when CPU, RAM or disk of any server reaches the limit (default 80 %)
- Login-protected panel with a modern login page
- No dependencies: just Python 3 on Linux

## Install the panel (one line)

Run on the server that will host the panel (as root, or with `sudo`):

```bash
curl -fsSL https://raw.githubusercontent.com/AqaAryamehr/server-monitor/main/install.sh | sudo bash
```

The script asks you to choose the **port** of the panel, then a **username** and a **password**, and prints the panel link, for example
`http://203.0.113.10:8080` (with the port you chose). If systemd is available it offers to keep the panel running in the background.

Prefer to look at the code first?

```bash
curl -fsSL -o server_monitor.py https://raw.githubusercontent.com/AqaAryamehr/server-monitor/main/server_monitor.py
python3 server_monitor.py
```

> Open the port you chose (suggested: `8080`) in your firewall, e.g. `ufw allow 8080/tcp`.

## Monitor more servers

1. Open the panel -> **Settings** -> **Add server**, type a name and press the button.
2. Check the **address and port** field (it starts with the address you use in the browser; change the port or host if the new server must connect another way) and copy the command it shows. Run it **as root on the other server**:
   `curl -fsSL "http://PANEL:8080/node-install.sh?token=..." | sudo bash`
3. The new server appears in the bar under the header. Click a server to see its dashboard.

The node only sends metrics to the panel (it opens no port). It needs to reach the panel's address and port.
If the node cannot reach the panel for a while, it keeps its data and sends it when the connection returns.
Remove a server from the same Settings window. Manual alternative:
`python3 server_monitor.py --node http://PANEL:8080 --token TOKEN`.

## Telegram bot and alerts

1. In Telegram open **@BotFather**, send `/newbot` and copy the **bot token**.
2. Open your new bot and press **Start**, then get your **chat ID** (for example from **@userinfobot**).
3. Panel -> **Settings** -> **Telegram bot and alerts**: enter token and chat ID, choose the limit, tick the alert box,
   press **Save**, then **Send test message**.

**Bot menu:** as soon as the token and chat ID are saved, send `/start` to your bot. It lists all servers of the panel
(with a green/red dot and their CPU, RAM and disk). Tap a server to get its live status (CPU, RAM, disk, traffic in/out,
load, uptime), then **Refresh** or go **back to the list**. Only your chat can use the bot; everybody else gets
"This bot is private".

**Alerts:** CPU, RAM and disk of every server are checked every second. The moment one reaches the limit (default 80 %)
you get a message with the value and the time, and a **Details** button that shows the live status. It is not repeated
while the value stays high (a reminder follows after 30 minutes). When the value has been clearly below the limit for
30 seconds you get a "back to normal" message. If Telegram cannot be reached the alert is retried for about two minutes.

**Offline alerts:** if a server connected as a node stops sending data for 15 seconds you get a "server is offline" message
(with the time of its last data and a **Details** button), a reminder every 30 minutes while it stays offline, and a
"back online" message with the downtime when it returns. A node that has not reconnected 60 seconds after the panel started is
reported too. The checkbox *Also alert when a server goes offline* in Settings turns this on or off.

If the server cannot reach `api.telegram.org`, use *Advanced* to set an HTTP proxy or another API address.

## Update

One command on every server (update the **main panel first**, then the nodes):

```bash
sudo server-monitor update
```

- The main panel downloads the newest `server_monitor.py` from the address it was installed from (the installer
  remembers it; to set or change it: `server-monitor update --url https://raw.githubusercontent.com/AqaAryamehr/server-monitor/main/server_monitor.py`).
- A node downloads the version of its main panel, so all servers always run the same version.
- The new file is checked before it replaces the old one, the old one is kept as `server_monitor.py.bak`,
  the service restarts automatically, and if the new version does not start the previous one is restored.
- Nodes that run an older version show an **update available** tag in the panel (Settings -> Servers).
- Installations from before this command existed: replace `server_monitor.py` once and restart the service
  (`systemctl restart server-monitor`); on a node you can fetch the file from the panel with its own token:

```bash
M=$(python3 -c "import json;print(json.load(open('/root/.server_monitor_node.json'))['url'])")
T=$(python3 -c "import json;print(json.load(open('/root/.server_monitor_node.json'))['token'])")
curl -fsSL "$M/node.py?token=$T" -o /opt/server-monitor/server_monitor.py && systemctl restart server-monitor-node
```

## Commands

| Command | What it does |
| --- | --- |
| `server-monitor update` | Install the newest version and restart the service |
| `server-monitor status` | Show the version and the state of the service |
| `server-monitor restart` | Restart the service |
| `server-monitor uninstall` | Remove the service, the command and the program (asks before deleting data) |

## Usage

```bash
python3 server_monitor.py                 # first run asks for username/password; later runs reuse them
python3 server_monitor.py --reset         # choose a new username/password
python3 server_monitor.py --port 9090     # another port
python3 server_monitor.py --cert cert.pem --key key.pem   # HTTPS (recommended when nodes connect over the internet)
```

| Option | Meaning |
| --- | --- |
| `--host` | Bind address (default `0.0.0.0`) |
| `--port` | Panel port (default: the one chosen during setup, or `8080`) |
| `--reset` | Ask for a new username and password |
| `--user`, `--password` | Set the login without prompting (for automation) |
| `--cert`, `--key` | Enable HTTPS with your certificate |
| `--config` | Where the login is stored (default `~/.server_monitor.json`) |
| `--data-dir` | Where the 24 h history is stored (default `~/.server_monitor_data`) |
| `--node`, `--token` | Run as a node of another panel |
| `--insecure` | (node) accept a self-signed HTTPS certificate of the panel |

## Where things are stored

- `~/.server_monitor.json` - username and a salted PBKDF2 hash of the password (never the password itself), mode `600`
- `~/.server_monitor_secret` - random key used to sign login sessions
- `~/.server_monitor_settings.json` - Telegram settings and display name (mode `600`)
- `~/.server_monitor_nodes.json` - connected servers (only hashes of their tokens)
- `~/.server_monitor_data/` - the 24-hour history of this server (`nodes/` holds the other servers)
- On a node: `~/.server_monitor_node.json` - panel address and token (mode `600`)

## Security notes

- The panel uses plain HTTP unless you pass `--cert` and `--key` (or put it behind an HTTPS reverse proxy).
  Passwords and node tokens travel unencrypted over plain HTTP: use a strong password and prefer HTTPS.
- After 5 failed logins an IP is blocked for 5 minutes. A valid node token is never blocked.
- Node tokens are long random secrets; removing a server in Settings revokes its token immediately.

## Run as a service manually

```ini
# /etc/systemd/system/server-monitor.service
[Unit]
Description=Server Monitor
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/server-monitor/server_monitor.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now server-monitor
```

## Uninstall

```bash
sudo server-monitor uninstall           # asks for confirmation; your login, settings and history are kept unless you agree
sudo server-monitor uninstall --purge   # also delete the saved login, settings and history
sudo server-monitor uninstall --yes     # no questions
```

Run it on every server you installed (the main panel and each node). Removing the panel does not stop the nodes.

## License

Add a `LICENSE` file of your choice (for example MIT) to the repository.
