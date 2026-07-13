# Pentest-Agent v3 — Unleash Guide

Full-power usage against HTB machines (or any authorized target).

---

## 1. Infrastructure (one-time setup)

### Docker Compose (recommended)

This repo now includes a compose stack that runs:
- `db` (PostgreSQL 16)
- `kali-agent` (Pentest Agent in a Kali container)

```bash
# One-line setup + Agent REPL (builds image if needed, then opens agent REPL in Kali)
MODEL=gemma4:12b docker compose run --rm kali-agent

# With Gemini API (remote LLM, no Ollama needed):
GEMINI_API_KEY="your-key" MODEL=gemini-2.5-flash docker compose run --rm kali-agent
```

If you also want PostgreSQL memory persistence, start DB separately:

```bash
docker compose up -d db
docker compose run --rm kali-agent python3 -m pentest_agent db migrate
```

The compose file sets:
- `PENTEST_DB_URL=postgresql+asyncpg://pentest:pentest@db:5432/pentest_agent`
- `PENTEST_DB_SYNC_URL=postgresql+psycopg2://pentest:pentest@db:5432/pentest_agent`
- `OLLAMA_BASE_URL=http://host.docker.internal:11434`

When you enter the container session, you land directly in `python3 -m pentest_agent agent-repl` with your chosen `MODEL`.

> Keep Ollama running on the host (`ollama serve`) so the Kali container can reach it.
>
> **No Ollama? Use Gemini instead.** Set `GEMINI_API_KEY` and pass a `gemini-*` model name.
> The factory auto-detects the provider from the model prefix (`gemini-*` → Gemini, `gpt-*` → OpenAI, `claude-*` → Anthropic).

---

### PostgreSQL — Memory & Learning Brain

```bash
docker run -d --name pg-pentest \
  -e POSTGRES_PASSWORD=pentest \
  -e POSTGRES_DB=pentest_agent \
  -p 5432:5432 \
  postgres:16

# Create all 8 tables
python -m pentest_agent db migrate
```

### Ollama — LLM Brain

```bash
ollama serve &
ollama pull gemma4:12b        # Best: tool use, 256K context
# Low VRAM alternative:
ollama pull qwen2.5-coder:7b  # Good at command syntax
```

### Docker Sandbox — Safe Exploit Execution

```bash
docker build -t pentest-sandbox:latest -f - . <<'EOF'
FROM kalilinux/kali-rolling:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip netcat-openbsd curl wget nmap whatweb \
    metasploit-framework exploitdb git openssh-client \
    impacket-scripts crackmapexec sqlmap hydra john hashcat \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages \
    requests impacket pwntools pycryptodome paramiko
RUN useradd -m pentest && mkdir -p /exploits /output && chown -R pentest:pentest /exploits /output
USER pentest
WORKDIR /exploits
EOF
```

### API Keys (optional but powerful)

```bash
export NVD_API_KEY="your-nvd-key"       # 50 req/30s instead of 5
export GITHUB_TOKEN="your-gh-token"     # GitHub PoC search (higher rate limit)
export ANTHROPIC_API_KEY="your-key"     # If using Claude instead of Ollama
export OPENAI_API_KEY="your-key"        # If using GPT instead of Ollama
export GEMINI_API_KEY="your-key"        # If using Gemini instead of Ollama (free tier available)
export PENTEST_DB_URL="postgresql+asyncpg://pentest:pentest@localhost:5432/pentest_agent"
```

If you set both `GEMINI_API_KEY` and have Ollama running, the provider is chosen
from the `--model` prefix: `gemini-*` → Gemini, `gpt-*` → OpenAI, `claude-*` → Anthropic.
To force a provider regardless of model name, set `PENTEST_LLM_PROVIDER=gemini`.

### /etc/hosts (if HTB box uses a hostname)

```bash
# Many HTB boxes redirect to a domain. Add it:
echo "10.129.x.x  target.htb subdomain.target.htb" | sudo tee -a /etc/hosts
```

---

## 2. Pre-Flight Intel

```bash
# If you have SharpHound/BloodHound output, seed the graph with AD attack paths:
python3 -c "
from pentest_agent.bloodhound import BloodHoundImporter
from pentest_agent.graph.pathfinding import AttackPathfinder

g = BloodHoundImporter().import_json('20240709123145_sharphound.json')
pf = AttackPathfinder(g)

# Show known paths to Domain Admin
for path in pf.k_shortest('attacker_start', 'objective_root', k=3):
    print(path.summary())
"

# Pre-enrich known service versions so the graph is primed:
python -m pentest_agent enrich --service "Apache httpd" --version "2.4.49" --check-poc
python -m pentest_agent enrich --service "OpenSSH" --version "8.2p1" --check-poc
python -m pentest_agent enrich --service "Samba" --version "4.15.0" --check-poc
```

---

## 3. Launch — Full Power

### The Main Command

```bash
# With Ollama (local):
python -m pentest_agent run \
  --target 10.129.x.x \
  --objective "Capture user.txt and root.txt. Escalate to SYSTEM/root." \
  --mode deep \
  --model gemma4:12b \
  --iterations 50 \
  --stealth \
  --export htb_engagement.json

# With Gemini (remote, no Ollama needed):
GEMINI_API_KEY="your-key" python -m pentest_agent run \
  --target 10.129.x.x \
  --model gemini-2.5-flash \
  --iterations 50
```

### What Each Flag Does

| Flag | Effect |
|---|---|
| `--target` | IP, CIDR range, or hostname of the target |
| `--objective` | What the agent is trying to achieve (shown in prompts) |
| `--mode deep` | Full `-p-` port scan + `-sC` scripts. Use `quick` for top 100 ports only |
| `--model gemma4:12b` | LLM model for decision-making. Prefix auto-selects provider: `gemini-*` → Gemini, `gpt-*` → OpenAI, `claude-*` → Anthropic. Also respects `PENTEST_LLM_PROVIDER` env var. |
| `--iterations 50` | Max turns per agent (more = deeper testing) |
| `--stealth` | Uses evasion-aware pathfinding — prefers low-detection-risk edges (SSH keys over PSExec, token manip over LSASS dump) |
| `--export` | Saves the attack graph as JSON for later analysis |

### Agent Behavior

The agent runs autonomously through these phases:

1. **Recon** — nmap all ports → gobuster on HTTP → nuclei vuln scan
2. **Enrich** — Every service version → NVD CVEs → EPSS scores → CISA KEV check → MITRE ATT&CK mapping
3. **Rank** — Exploitable frontier sorted by `(11-CVSS) × (1-EPSS) × KEV_multiplier × PoC_multiplier`
4. **Exploit** — KEV vulns first → search Metasploit → ExploitDB → GitHub PoCs → execute in Docker sandbox
5. **Post-Exploit** — On shell: id, sudo -l, SUID find, linpeas/winpeas, SSH keys, /etc/shadow, LSASS dump
6. **Lateral** — Found creds → test against all known hosts → SSH/PSExec/WinRM pivot
7. **Privesc** — User → root/SYSTEM via kernel exploits, SUID, token manipulation
8. **Repeat** — New host discovered → back to step 1

---

## 4. During the Run — Human-in-the-Loop

### Agent REPL (interactive terminal)

```bash
python -m pentest_agent agent-repl --target 10.129.x.x --model gemma4:12b
```

Once inside the REPL:

| Command | What It Does |
|---|---|
| `/step [n]` | Run n agent iterations (default 1) |
| `/status` | Show agent tree status summary |
| `/tree` | Show detailed agent hierarchy |
| `/info` | Show LLM provider/model, target, objective, agent counts, graph stats, debug/plan mode |
| `/target <ip>` | Switch to a new target (resets graph, agents, and conversation) |
| `/debug` | Toggle detailed debug output (agent errors, graph stats, conversation size) |
| `/plan` | Toggle approval gate — confirm dangerous actions before execution |
| `/checkpoint` | Save session state to disk for later resume |
| `/help` | Show this command reference |
| `/quit` | Exit the REPL |
| *any other text* | Send as instruction to the root agent |

When debug mode is on (`/debug`), the feedback pane also shows agent errors, graph node counts, agent pool stats, and conversation log length.

### Legacy Pause & Inject (Ctrl+C during `run`)


```
⏸️  PAUSED at iteration 12
  AttackGraph: 5 nodes, 4 edges | 1 hosts, 2 vulns (1 KEV)
  🎯 Top target: CVE-2021-41773 pri=0.0234

  Commands: CVE-XXXX | gobuster | hydra | nmap | enrich | exploit | resume | quit
  >>>
```

### Available Injections

| Command | What It Does |
|---|---|
| `CVE-2021-41773` | Immediately download and run the exploit for this CVE |
| `gobuster` | Force directory brute-force on discovered HTTP services |
| `hydra` or `hydra ssh` | Launch SSH brute-force with default wordlists |
| `nmap` | Re-run deep port scan |
| `nmap -p- --min-rate 5000 -A` | Custom nmap with your own flags |
| `enrich` | Re-run CVE enrichment on all discovered services |
| `exploit` | Force exploitation of the top-priority vulnerability |
| `resume` | Let the agent continue autonomously |
| `quit` | Stop the engagement (can resume later from DB) |

### Dashboard (separate terminal)

```bash
python -m pentest_agent dashboard --port 9999 --api-key htb2024
# Open: http://localhost:9999
# Set header: X-API-Key: htb2024
```

The dashboard shows:
- **Live attack graph** — Cytoscape.js visualization of hosts/services/vulns/creds/privs
- **Agent tree** — Which agents are running, waiting, completed
- **Decision log** — Every LLM decision with reasoning
- **Stats** — Hosts found, CVEs identified, exploits attempted, flags captured

---

## 5. After the Run — Learn & Analyze

```bash
# See everything the agent learned:
python -m pentest_agent memory "10.129"
python -m pentest_agent memory "CVE-2021"
python -m pentest_agent memory "apache"

# Database stats:
python -m pentest_agent db stats
# Output:
#   Engagements: 3
#   Learned Patterns: 12
#   Memory Facts: 47

# Attack graph operations:
python -m pentest_agent graph --frontier     # Ranked exploit targets
python -m pentest_agent graph --path objective_root  # Optimal path to objective

# Export for Neo4j / BloodHound analysis:
python3 -c "
from pentest_agent.cypher_exporter import CypherExporter
from pentest_agent.graph.models import AttackGraph
import json

# Rebuild graph from saved JSON
data = json.load(open('htb_engagement.json'))
g = AttackGraph(name='htb_analysis')
for n in data['nodes']:
    from pentest_agent.graph.models import Node, NodeType
    g.add_node(Node(**{k:v for k,v in n.items() if k != 'type'}, type=NodeType(n['type'])))
for e in data['edges']:
    from pentest_agent.graph.models import Edge, EdgeRelation
    g.add_edge(Edge(**{k:v for k,v in e.items() if k != 'relation'}, relation=EdgeRelation(e['relation'])))

CypherExporter(g).export_to_file('htb_attack.cypher')
print('Load into Neo4j: cypher-shell -f htb_attack.cypher')
print('Then run BloodHound-style: MATCH p=shortestPath((a:Attacker)-[*..15]->(o:Objective)) RETURN p')
"
```

---

## 6. Resume if Interrupted

```bash
# List past engagements:
python3 -c "
import asyncio
from pentest_agent.db import init_db, get_repository
async def main():
    await init_db()
    repo = get_repository()
    async with repo.session() as s:
        engs = await repo.list_engagements(s)
        for e in engs:
            print(f'{e.id[:8]}  {e.target:20s}  {e.status:12s}  {e.started_at}')
asyncio.run(main())
"

# Resume from DB:
python -m pentest_agent resume <session-id>
```

---

## 7. Python API — Advanced Usage

```python
"""Custom HTB engagement script."""
import asyncio
from pentest_agent.agent.coordinator import AgentCoordinator
from pentest_agent.graph.models import AttackGraph
from pentest_agent.llm import LLMFactory
from pentest_agent.db import init_db, get_repository

async def main():
    # Init DB
    await init_db()
    repo = get_repository()

    # Smart LLM
    llm = LLMFactory.create(model="gemma4:12b")

    # Fresh graph
    graph = AttackGraph(name="htb_custom")

    # Coordinator with all settings
    coord = AgentCoordinator(
        graph=graph,
        target="10.129.x.x",
        objective="Capture all flags. Full compromise.",
        llm=llm,
        repository=repo,
        max_agents=15,  # More parallel agents
    )

    # Start — spawns root + recon agents
    await coord.start()

    # Optionally spawn extra specialists immediately
    coord.spawn_agent(AgentConfig(
        name="web_specialist",
        role="web_specialist",
        skills=["web_recon", "web_exploit", "vuln_scan"],
        max_iterations=20,
    ))

    print("Agent tree:")
    print(coord.get_agent_tree())

    # Run to completion
    summary = await coord.run(max_iterations=50)

    # Results
    print(f"\nFinal graph: {graph.summary()}")

    # Best attack path
    from pentest_agent.graph.pathfinding import AttackPathfinder
    pf = AttackPathfinder(graph)

    # Standard shortest path
    path = pf.dijkstra("attacker_start", "objective_root")
    if path:
        print(f"\nOptimal path (cost={path.total_cost}):")
        print(path.summary())

    # Evasive alternative
    stealth = pf.evasive("attacker_start", "objective_root")
    if stealth:
        print(f"\nStealth path (risk={stealth.total_risk}):")
        print(stealth.summary())

    # All discovered attack paths
    paths = pf.k_shortest("attacker_start", "objective_root", k=5)
    print(f"\n{len(paths)} attack paths discovered")

    # Check what the agent learned for next time
    async with repo.session() as session:
        # What CVEs worked?
        from pentest_agent.db.models import ExploitAttempt
        from sqlalchemy import select
        r = await session.execute(
            select(ExploitAttempt).where(ExploitAttempt.success == True)
        )
        for ea in r.scalars().all():
            print(f"  ✓ {ea.cve_id} on {ea.target_host} via {ea.exploit_source}")

asyncio.run(main())
```

---

## 8. Full Automation Script

```bash
#!/bin/bash
# unleash.sh — Fully automated HTB pentest
set -e

TARGET="${1:?Usage: $0 <HTB_IP> [hostname]}"
HOSTNAME="${2:-}"
SESSION="htb_$(date +%Y%m%d_%H%M%S)"

echo "=== Pentest-Agent v3 — Unleash ==="
echo "Target: $TARGET"
echo "Session: $SESSION"
echo ""

# Add hostname to /etc/hosts
[ -n "$HOSTNAME" ] && echo "$TARGET  $HOSTNAME" | sudo tee -a /etc/hosts

# Ensure PostgreSQL
docker ps --format '{{.Names}}' | grep -q pg-pentest || {
  echo "[*] Starting PostgreSQL..."
  docker run -d --name pg-pentest \
    -e POSTGRES_PASSWORD=pentest \
    -e POSTGRES_DB=pentest_agent \
    -p 5432:5432 postgres:16
  sleep 3
}
python -m pentest_agent db migrate

# Ensure Ollama
curl -s http://localhost:11434/api/tags >/dev/null 2>&1 || {
  echo "[*] Starting Ollama..."
  ollama serve &
  sleep 3
}
ollama list | grep -q gemma4:12b || {
  echo "[*] Pulling gemma4:12b..."
  ollama pull gemma4:12b
}

# Ensure Docker sandbox
docker image inspect pentest-sandbox:latest >/dev/null 2>&1 || {
  echo "[*] Building sandbox image..."
  docker build -t pentest-sandbox:latest -f - . <<'DOCKERFILE'
FROM kalilinux/kali-rolling:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip netcat-openbsd curl wget nmap whatweb \
    metasploit-framework exploitdb git openssh-client \
    impacket-scripts crackmapexec sqlmap hydra john hashcat \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages \
    requests impacket pwntools pycryptodome paramiko
RUN useradd -m pentest && mkdir -p /exploits /output && chown -R pentest:pentest /exploits /output
USER pentest
WORKDIR /exploits
DOCKERFILE
}

echo "[*] Launching agent..."
echo ""

# LAUNCH — full power
python -m pentest_agent run \
  --target "$TARGET" \
  --objective "Capture all flags (user.txt, root.txt, proof.txt). Escalate to root/SYSTEM." \
  --mode deep \
  --model gemma4:12b \
  --iterations 50 \
  --stealth \
  --export "${SESSION}_graph.json" \
  2>&1 | tee "${SESSION}.log"

echo ""
echo "=== Engagement Complete ==="
echo "Log: ${SESSION}.log"
echo "Graph: ${SESSION}_graph.json"
echo ""

# Post-engagement analysis
python -m pentest_agent memory "$TARGET"
```

```bash
chmod +x unleash.sh
./unleash.sh 10.129.244.146 target.htb
```

---

## 9. MCP Mode — Control via Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "pentest-agent": {
      "command": "python3",
      "args": ["-m", "pentest_agent.mcp"],
      "env": {
        "NVD_API_KEY": "${NVD_API_KEY}",
        "PENTEST_DB_URL": "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest_agent"
      }
    }
  }
}
```

Then in Claude Code you can say:

> "Scan 10.129.x.x with nmap and enrich any services found"

Claude will call the pentest tools via MCP protocol and the attack graph persists across calls.

---

## 10. Quick Reference

| Command | Purpose |
|---|---|
| `python -m pentest_agent run --target <IP>` | Full autonomous pentest |
| `python -m pentest_agent demo` | Demo with mock targets, no LLM needed |
| `python -m pentest_agent enrich --cpe <CPE>` | CVE enrichment for a service |
| `python -m pentest_agent tools --tool nmap --target <IP>` | Run a single tool |
| `python -m pentest_agent graph --frontier` | Show ranked exploit targets |
| `python -m pentest_agent graph --path objective_root` | Show optimal attack path |
| `python -m pentest_agent memory <query>` | Search past learnings |
| `python -m pentest_agent resume <id>` | Resume interrupted engagement |
| `python -m pentest_agent dashboard` | Web UI on port 9999 |
| `python -m pentest_agent mcp` | MCP server for Claude Code |
| `python -m pentest_agent db migrate` | Create PostgreSQL tables |
| `python -m pentest_agent db stats` | Engagement statistics |
| `Ctrl+C` during run | Pause and inject commands |
