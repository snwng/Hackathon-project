# Pentest Agent — Graph-Driven Autonomous Penetration Testing

**MITRE ATT&CK-integrated, CVE-aware, graph-based autonomous pentesting agent.**

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [The Attack Graph](#the-attack-graph)
4. [CVE Enrichment Pipeline](#cve-enrichment-pipeline)
5. [Agent Loop (ReAct)](#agent-loop-react)
6. [MCP Tool Interface](#mcp-tool-interface)
7. [How to Implement](#how-to-implement)
8. [Project Structure](#project-structure)
9. [Usage](#usage)
10. [Why a Graph, Not a Tree](#why-a-graph-not-a-tree)
11. [Data Structures & Algorithms](#data-structures--algorithms)
12. [Production Roadmap](#production-roadmap)

---

## Overview

This is an autonomous penetration testing agent that:

1. **Discovers** attack surface via security tools (nmap, gobuster, nuclei, searchsploit)
2. **Enriches** every finding with real-time CVE data (NVD), exploitation probability (EPSS), active-exploitation status (CISA KEV), and MITRE ATT&CK technique mappings
3. **Models** the entire engagement as a **weighted directed attack graph** — not a tree
4. **Plans** optimal exploitation paths using Dijkstra/A\* over the graph
5. **Ranks** the exploitable frontier with a priority queue (CVSS × EPSS × KEV)
6. **Executes** via a ReAct agent loop where an LLM observes graph state, decides actions, calls tools, and updates the graph incrementally

The graph **is** the agent's state. No separate database, no scattered JSON — every host, service, vulnerability, credential, and privilege is a typed node with weighted edges capturing the pre/post-condition relationships.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PENTEST AGENT                                   │
│                                                                          │
│  ┌──────────┐    ┌──────────────┐    ┌──────────┐    ┌──────────────┐  │
│  │  RECON   │    │  ENRICHMENT  │    │  AGENT   │    │     MCP      │  │
│  │  LAYER   │───▶│  PIPELINE    │───▶│   LOOP   │◀──▶│   SERVER     │  │
│  │          │    │              │    │          │    │              │  │
│  │ nmap     │    │ NVD API 2.0  │    │ Observe  │    │ tool defs    │  │
│  │ gobuster │    │ EPSS (FIRST) │    │  Think   │    │ invoke       │  │
│  │ nuclei   │    │ CISA KEV     │    │   Act    │    │ results      │  │
│  │ srchsplt │    │ CWE→ATT&CK   │    │  Update  │    │              │  │
│  └────┬─────┘    └──────┬───────┘    └────┬─────┘    └──────────────┘  │
│       │                 │                 │                              │
│       │          ┌──────▼─────────────────▼──────┐                      │
│       │          │                              │                      │
│       └─────────▶│      ATTACK GRAPH             │                      │
│                  │   (networkx.DiGraph)          │                      │
│                  │                              │                      │
│                  │  Nodes:  Host, Service,       │                      │
│                  │  Vuln, Credential,            │                      │
│                  │  Privilege, Objective         │                      │
│                  │                              │                      │
│                  │  Edges:  has_service,         │                      │
│                  │  has_vuln, exploits,          │                      │
│                  │  can_auth, can_lateral,       │                      │
│                  │  credential_discovery, …      │                      │
│                  │                              │                      │
│                  │  ┌─────────────────────┐     │                      │
│                  │  │ frontier (min-heap) │     │                      │
│                  │  │ path (Dijkstra/A*)  │     │                      │
│                  │  └─────────────────────┘     │                      │
│                  └──────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
1. nmap 10.10.10.10
   → Finding(host="10.10.10.10", port=443, service="http", version="Apache 2.4.49")
   → graph.add_node(Host("10.10.10.10"))
   → graph.add_node(Service("Apache httpd 2.4.49", port=443))
   → graph.add_edge(host → service, "has_service")

2. enrich_service("Apache httpd", "2.4.49", cpe="cpe:2.3:a:apache:http_server:2.4.49")
   → NVD API returns [CVE-2021-41773 (CVSS 7.5), CVE-2021-42013 (CVSS 9.8), …]
   → EPSS API returns {CVE-2021-41773: 0.96, CVE-2021-42013: 0.97}
   → KEV check: CVE-2021-41773 IS in KEV (actively exploited)
   → CWE-22 → ATT&CK T1190 (Exploit Public-Facing Application, initial-access)
   → graph.add_node(Vuln(CVE-2021-41773, cvss=7.5, epss=0.96, kev=True, mitre=T1190))
   → graph.add_edge(service → vuln, "has_vuln")

3. get_frontier()
   → heap returns: [CVE-2021-41773 (priority=0.02), CVE-2021-42013 (priority=0.03), …]
   → LLM picks CVE-2021-41773 (KEV + highest EPSS * CVSS score)

4. exploit(CVE-2021-41773)
   → runs Metasploit/http-poc against 10.10.10.10:443
   → success → graph.add_node(Privilege("root@10.10.10.10"))
   → graph.add_edge(vuln → privilege, "exploits", weight=2.0, mitre=T1190)

5. replan → Dijkstra(attacker_start → Domain Admin)
   → finds: web01 → CVE-2021-41773 → root@web01 → SSH key → ws01 → LSASS → dc01 → Domain Admin
```

---

## The Attack Graph

### Node Types

| Type | Shape (in viz) | Example | What it represents |
|---|---|---|---|
| `attacker` | 🔺 Triangle | `Attacker (Kali)` | Starting position |
| `host` | ⬡ Hexagon | `10.10.10.10 (Ubuntu 20.04)` | A machine on the network |
| `service` | ▭ Rounded rect | `Apache httpd 2.4.49:443` | Something listening on a port |
| `vulnerability` | ◆ Diamond | `CVE-2021-41773` | A weakness (CVE) with CVSS/EPSS/KEV |
| `credential` | 🏷 Tag | `SSH key from /var/www/.ssh` | Found secrets, hashes, tickets |
| `privilege` | ★ Star | `root@web01` | Access level obtained on a host |
| `objective` | ★ Gold star | `Domain Admin` | The goal |

### Edge Types (Relations)

| Edge | Meaning | MITRE Tactic | Example |
|---|---|---|---|
| `has_service` | Host runs this service | Recon | `web01 → Apache:443` |
| `has_vuln` | Service has this CVE | — | `Apache:443 → CVE-2021-41773` |
| `exploits` | Triggering vuln → privilege | Execution | `CVE-2021-41773 → root@web01` |
| `network_access` | Attacker can reach this host | Initial Access | `Attacker → web01` |
| `credential_discovery` | Post-exploit: found creds | Credential Access | `root@web01 → SSH key` |
| `credential_dumping` | Dump LSASS/SAM | Credential Access | `user@ws01 → cached DA hash` |
| `can_auth` | Cred → access on target host | Lateral Movement | `SSH key → user@ws01` |
| `can_lateral` | Privilege → move to another host | Lateral Movement | `admin@ws01 → dc01` |
| `can_escalate` | Low priv → high priv (same host) | Priv Escalation | `user@ws01 → SYSTEM@ws01` |
| `objective_achieved` | Privilege meets the goal | — | `DA@dc01 → Domain Admin` |

### Edge Weights

Each edge has a **weight** (lower = more attractive path). Weights are composite:

```
weight = base_cost × detection_risk_multiplier

Where base_cost depends on the relation:
  - has_service / has_vuln / network_access → 0.0 (passive discovery, no risk)
  - exploits (KEV + PoC available) → 0.5–2.0
  - exploits (no known PoC) → 4.0–8.0
  - credential_discovery → 1.5 (medium risk)
  - credential_dumping → 2.0–3.0 (high risk, touches LSASS)
  - can_auth (SSH key) → 1.0 (stealthy)
  - can_auth (pass-the-hash) → 2.5 (noisy)
  - can_lateral (WinRM) → 4.0 (very noisy)
```

### Priority Score (Exploit Ranking)

The heap ranks vulnerabilities by:

```python
priority = (11 - cvss_score) × (1 - epss_score) × kev_multiplier × poc_multiplier

# kev_multiplier  = 0.3 if in CISA KEV, else 1.0
# poc_multiplier  = 0.5 if public PoC exists, else 1.5
```

Lower priority = **attack this first**. A KEV-listed CVE with high CVSS, high EPSS, and a public PoC gets a priority near **0.01**. An obscure CVE with no PoC gets **5.0+**.

---

## CVE Enrichment Pipeline

```
Service (name + version + CPE)
   │
   ├─ 1. NVD REST API 2.0 ──────────────► CVE list + CVSS + CWE
   │      GET /rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:http_server:2.4.49
   │      Rate limit: 5 req/30s (no key) or 50 req/30s (with API key)
   │
   ├─ 2. FIRST.org EPSS API ─────────────► Exploitation probability [0, 1]
   │      GET /data/v1/epss?cve=CVE-2021-41773,...
   │      "Probability of exploitation in the wild within 30 days"
   │
   ├─ 3. CISA KEV Catalog ───────────────► Actively exploited? (bool)
   │      GET known_exploited_vulnerabilities.json
   │      Single highest-signal field — if it's in KEV, exploit it NOW
   │
   ├─ 4. CWE → ATT&CK Mapping ───────────► MITRE technique + tactic
   │      Static mapping table (Center for Threat-Informed Defense)
   │      CWE-22 (Path Traversal) → T1190 (initial-access)
   │      CWE-78 (Command Injection) → T1059 (execution)
   │      CWE-502 (Deserialization) → T1059 (execution)
   │
   └─ 5. PoC/Exploit Check ──────────────► Is there a public exploit?
          ExploitDB, Metasploit module DB, nomi-sec/PoC-in-GitHub
```

### Mapping Chain

```
CVE → CWE → CAPEC → MITRE ATT&CK Technique

Example:
  CVE-2021-41773
    → CWE-22 (Path Traversal)
      → CAPEC-126 (Path Traversal)
        → T1190 (Exploit Public-Facing Application)
          Tactic: initial-access
```

The mapping is a curated lookup table from the [Center for Threat-Informed Defense](https://ctid.io) mappings project. Gaps are filled via LLM inference on CVE descriptions.

### API Requirements

| Source | URL | Rate Limit | Key Required? |
|---|---|---|---|
| NVD 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 5/30s (no key), 50/30s (key) | Optional but recommended |
| EPSS | `api.first.org/data/v1/epss` | Generous | No |
| CISA KEV | `cisa.gov/…known_exploited_vulnerabilities.json` | Single file download | No |
| ExploitDB | Local `searchsploit` CLI | Local | No |

---

## Agent Loop (ReAct)

### The Pattern

```
┌──────────────────────────────────────────────────────────┐
│                     REACT LOOP                            │
│                                                           │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐      │
│   │ OBSERVE  │─────▶│  THINK   │─────▶│   ACT    │      │
│   │          │      │          │      │          │      │
│   │ Read     │      │ LLM      │      │ Execute  │      │
│   │ graph    │      │ decides  │      │ tool     │      │
│   │ state    │      │ action   │      │ call     │      │
│   └──────────┘      └──────────┘      └──────────┘      │
│        ▲                                  │              │
│        │                                  │              │
│        └────────── UPDATE ◀──────────────┘              │
│                  (mutate graph)                          │
└──────────────────────────────────────────────────────────┘
```

### Each Iteration

**Step 1: OBSERVE** — Read graph state into LLM context

```python
def _format_observation(frontier, privileges):
    return f"""
    Graph: {graph.summary()}
    Exploitable frontier (top 5):
      1. CVE-2021-41773 (CVSS=7.5, EPSS=96%, KEV=True) priority=0.02
      2. CVE-2021-42287 (CVSS=8.8, EPSS=91%, KEV=True) priority=0.03
    Privileges held: root@web01
    """
```

**Step 2: THINK** — LLM receives context + decides

```
SYSTEM: You are a penetration testing agent.
Goal: Domain Admin on dc01.corp.local.
Available tools: nmap, gobuster, nuclei, searchsploit, enrich_service,
                 get_frontier, find_attack_path, add_to_graph.

USER: [current graph state]

Respond:
  ACTION: <recon|enrich|exploit|lateral|done>
  TOOL: <tool_name>
  TARGET: <ip/hostname>
  REASONING: <one sentence>
```

**Step 3: ACT** — Execute

```python
if action.type == "recon":
    findings = run_tool("nmap", target=action.target)
elif action.type == "enrich":
    cves = pipeline.enrich_cpe(cpe, max_cves=10)
elif action.type == "exploit":
    result = metasploit.run(cve_id, target)
```

**Step 4: UPDATE** — Mutate graph

```python
# Ingest recon findings → new host + service nodes
for finding in result["findings"]:
    graph.add_node(Host(...))
    graph.add_node(Service(...))
    graph.add_edge(host → service, "has_service")

# Ingest enrichment → vulnerability nodes
for cve in result["cves"]:
    graph.add_node(Vuln(cve_id, cvss, epss, kev, mitre_technique))
    graph.add_edge(service → vuln, "has_vuln")

# Ingest successful exploit → privilege node
if exploit_success:
    graph.add_node(Privilege("root@web01"))
    graph.add_edge(vuln → privilege, "exploits", mitre=T1190)
```

### Decision Heuristics (for the LLM)

The system prompt encodes these rules:

1. **Always scan before exploiting** — nmap first, then nuclei, then exploit
2. **Always enrich every service version** — call `enrich_service()` after nmap finds versions
3. **Prioritize KEV** — actively exploited vulnerabilities override raw CVSS ranking
4. **Credentials are pivot points** — when you find creds, immediately check for lateral movement
5. **Every action should move toward the objective** — if it doesn't, the LLM should justify why

### How the LLM Plugs In

The orchestrator takes **any callable** with signature `(system_prompt: str, user_prompt: str) -> str`:

```python
# Claude (Anthropic)
import anthropic

def claude_llm(system: str, user: str) -> str:
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=500,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return resp.content[0].text


# OpenAI
def openai_llm(system: str, user: str) -> str:
    import openai
    resp = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return resp.choices[0].message.content


# Ollama (local)
def ollama_llm(system: str, user: str) -> str:
    import requests
    resp = requests.post("http://localhost:11434/api/generate", json={
        "model": "llama3",
        "system": system,
        "prompt": user,
        "stream": False,
    })
    return resp.json()["response"]


# Wire it up
agent = PentestOrchestrator(
    graph=graph,
    llm_call=claude_llm,  # ← plug any LLM here
    target="10.10.10.0/24",
    objective="Domain Admin on dc01.corp.local",
)
agent.run(max_iterations=30)
```

---

## MCP Tool Interface

### What the LLM Sees

The MCP server exposes these tools to the LLM:

| Tool | Description | When to Call |
|---|---|---|
| `nmap(target)` | Port scan, returns open ports + services + versions | First action on any new host |
| `gobuster(target)` | Directory enumeration on web servers | After finding HTTP/HTTPS |
| `nuclei(target)` | Vulnerability scanner (template-based) | After service discovery |
| `searchsploit(query)` | Search ExploitDB for PoCs | After finding service + version |
| `enrich_service(host_id, service_name, version, cpe)` | NVD + EPSS + KEV + ATT&CK lookup | After every service discovery |
| `get_frontier()` | Ranked exploitable vulnerabilities | Beginning of each agent turn |
| `find_attack_path(src, dst)` | Optimal path (Dijkstra) | Planning the full chain |
| `get_graph_summary()` | Graph state summary | Beginning of each agent turn |
| `add_to_graph(action, data)` | Add nodes/edges | After every finding |

### Tool Contract

Every security tool returns **structured `Finding` objects** — not raw text:

```python
@dataclass
class Finding:
    tool: str                    # "nmap"
    host: str                    # "10.10.10.10"
    port: Optional[int]          # 443
    service: Optional[str]       # "http"
    version: Optional[str]       # "Apache httpd 2.4.49"
    cpe: Optional[str]           # "cpe:2.3:a:apache:http_server:2.4.49"
    vuln_name: Optional[str]     # "CVE-2021-41773: Apache Path Traversal"
    cve_id: Optional[str]        # "CVE-2021-41773"
    severity: Optional[str]      # "critical"
```

This normalization is what makes the graph work — every tool feeds the same data model.

### MCP Server Implementation

The `MCPServer` class provides:

```python
mcp = MCPServer()

# List all tool definitions (what the LLM can call)
tools = mcp.list_tools()

# Invoke a tool (when the LLM calls it)
result = mcp.invoke("nmap", {"target": "10.10.10.10"}, graph=graph)

# Every tool call returns structured JSON:
{
    "success": True,
    "findings": [Finding.to_dict(), ...],
    "count": N,
}
```

For production, replace the class with a real MCP transport (stdio or SSE) using the Anthropic MCP SDK or FastMCP.

---

## How to Implement

### Phase 1: Foundation (what's built)

- [x] Attack graph data model (`Node`, `Edge`, `AttackGraph`)
- [x] Dijkstra shortest path + Yen's k-shortest paths
- [x] Priority queue frontier ranking (min-heap)
- [x] NVD REST API 2.0 client
- [x] EPSS batch-fetch from FIRST.org
- [x] CISA KEV catalog loader
- [x] CWE → ATT&CK static mapping table
- [x] nmap, gobuster, nuclei, searchsploit wrappers
- [x] MCP tool definitions + invoke handler
- [x] ReAct agent loop (observe → think → act → update)
- [x] Mock LLM for testing (deterministic, follows kill chain)
- [x] CLI (`demo`, `enrich`, `tools`, `graph`)
- [x] Interactive graph visualizer (Cytoscape.js)

### Phase 2: Real Exploitation

- [ ] Metasploit RPC integration (`msfrpcd` → `MetasploitTool`)
- [ ] ExploitDB PoC runner (auto-download + execute PoC scripts)
- [ ] C2 framework integration (Sliver, Havoc, Mythic)
- [ ] Shell session management (persist shells in graph as privilege nodes)

### Phase 3: Better Intelligence

- [ ] Full MITRE ATT&CK STIX loader (`mitreattack-python`)
- [ ] CTID mapping dataset loader (CVE → CWE → CAPEC → ATT&CK, complete)
- [ ] Live CVE feed subscription (NVD incremental updates via webhook/poll)
- [ ] BloodHound/SharpHound integration (import AD attack paths)
- [ ] Hybrid retrieval for CVE search: BM25 (exact CVE-ID) + HNSW vector index (semantic search on descriptions)

### Phase 4: Production Hardening

- [ ] Neo4j backend (Cypher queries, replaces `networkx` for large graphs)
- [ ] Real MCP transport (stdio/SSE) for Claude Code integration
- [ ] Multi-agent: separate agent instances per target host, coordinator agent orchestrates
- [ ] Evasion-aware planning: add EDR/AV presence to edge weights
- [ ] Session persistence (save/restore graph to disk)
- [ ] Web dashboard (live graph visualization + agent step log)

### Phase 5: Advanced Planning

- [ ] A\* with admissible heuristic (ATT&CK kill-chain stage distance to objective)
- [ ] MCTS for stochastic planning (when exploit success is probabilistic)
- [ ] Multi-objective optimization (stealth vs. speed Pareto frontier)
- [ ] Reinforcement learning from past engagements (which exploit chains actually worked?)

---

## Project Structure

```
pentest-agent/
│
├── graph_demo.py                  # Standalone demo: builds scenario, runs Dijkstra
├── graph_viewer.html              # Interactive Cytoscape.js visualization
├── graph_data.json                # Exported attack graph (auto-generated)
├── requirements.txt               # networkx, requests
│
├── README.md                      # ← this file
│
└── pentest_agent/                 # Main Python package
    │
    ├── __init__.py                # Package metadata
    ├── __main__.py                # Enables `python -m pentest_agent`
    ├── cli.py                     # CLI: demo, enrich, tools, graph
    │
    ├── graph/
    │   ├── __init__.py
    │   └── models.py             # Node, Edge, AttackGraph
    │       ├── Node               # Dataclass: id, type, label, cvss, epss, kev, …
    │       ├── Edge               # Dataclass: src, dst, relation, weight, mitre
    │       ├── AttackGraph        # networkx.DiGraph wrapper
    │       │   ├── find_path()        # Dijkstra shortest path
    │       │   ├── find_paths()       # Yen's k-shortest paths
    │       │   ├── reachable_vulns()  # Frontier (min-heap ranked)
    │       │   ├── reachable_privileges()
    │       │   ├── export_json()      # For visualization
    │       │   └── summary()          # Human-readable state
    │       └── NodeType, EdgeRelation # Enums
    │
    ├── enrichment/
    │   └── __init__.py            # CVE Enrichment Pipeline
    │       ├── fetch_cves_by_cpe()    # NVD REST API 2.0
    │       ├── fetch_cve_detail()     # Single CVE lookup
    │       ├── fetch_epss_batch()     # FIRST.org batch EPSS
    │       ├── fetch_kev_catalog()    # CISA KEV JSON
    │       ├── map_cwe_to_attack()    # CWE → ATT&CK lookup
    │       ├── map_capec_to_attack()  # CAPEC → ATT&CK lookup
    │       └── EnrichmentPipeline     # Orchestrates the full chain
    │
    ├── tools/
    │   ├── __init__.py            # Security tool wrappers
    │   │   ├── Finding             # Normalized tool output dataclass
    │   │   ├── BaseTool            # Abstract tool interface
    │   │   ├── NmapTool            # nmap wrapper + output parser
    │   │   ├── GobusterTool        # gobuster wrapper
    │   │   ├── NucleiTool          # nuclei wrapper
    │   │   ├── SearchsploitTool    # searchsploit wrapper
    │   │   └── run_tool()          # Execute by name
    │   │
    │   └── mcp_server.py          # MCP Server
    │       └── MCPServer
    │           ├── list_tools()        # Tool definitions for LLM
    │           └── invoke()            # Execute tool, return structured result
    │
    └── agent/
        ├── __init__.py
        ├── prompts.py              # LLM prompt templates
        │   ├── SYSTEM_PROMPT       # Agent persona + rules
        │   ├── OBSERVE_PROMPT      # Format graph state for LLM
        │   ├── DECISION_PROMPT     # Ask LLM to pick next action
        │   └── REFLECTION_PROMPT   # Post-action analysis
        │
        └── orchestrator.py         # ReAct Agent Loop
            ├── AgentAction         # Parsed LLM decision
            ├── AgentStep           # One iteration's record
            └── PentestOrchestrator
                ├── run()               # Full ReAct loop
                ├── _initialize_graph() # Set up attacker + objective nodes
                ├── _run_one_iteration()# Observe → Think → Act → Update
                ├── _format_observation() # Graph state → LLM context
                ├── _ask_llm()          # Query LLM for next action
                ├── _execute_action()   # Run tool / exploit / lateral
                ├── _update_graph()     # Ingest findings into graph
                └── session_report()    # Markdown report
```

---

## Usage

### CLI Commands

```bash
# Full demo (mock LLM, no API key needed)
python -m pentest_agent demo --iterations 8
python -m pentest_agent demo --export my_graph.json

# Enrichment pipeline (hits real NVD + EPSS + KEV APIs)
python -m pentest_agent enrich --cpe "cpe:2.3:a:apache:http_server:2.4.49"
python -m pentest_agent enrich --cpe "cpe:2.3:a:samba:samba:4.15.0" --limit 20

# Run a security tool
python -m pentest_agent tools --list
python -m pentest_agent tools --tool nmap --target 10.10.10.10

# Graph operations
python -m pentest_agent graph                    # Show summary
python -m pentest_agent graph --frontier         # What to exploit first
python -m pentest_agent graph --path objective_da # Optimal path to DA
python -m pentest_agent graph --export out.json  # Export for viz
python -m pentest_agent graph --view             # Start web visualizer
```

### Python API

```python
from pentest_agent.graph.models import AttackGraph, Node, Edge, NodeType, EdgeRelation
from pentest_agent.enrichment import EnrichmentPipeline
from pentest_agent.tools import run_tool
from pentest_agent.agent.orchestrator import PentestOrchestrator

# 1. Build a graph
graph = AttackGraph(name="engagement_2026_07_09")
graph.add_node(Node("attacker_start", NodeType.ATTACKER, "Kali"))

# 2. Run enrichment on a finding
pipeline = EnrichmentPipeline()
results = pipeline.enrich_cpe("cpe:2.3:a:apache:http_server:2.4.49")
for r in results:
    print(f"{r.cve_id}: CVSS={r.cvss_score}, EPSS={r.epss_score}, KEV={r.kev}")
    print(f"  ATT&CK: {r.attack_techniques}")

# 3. Run the agent with a real LLM
def my_llm(system, user):
    # Call Claude / GPT / Ollama / …
    return "ACTION: recon\nTOOL: nmap\nTARGET: 10.10.10.10\n..."

agent = PentestOrchestrator(
    graph=graph,
    llm_call=my_llm,
    target="10.10.10.0/24",
    objective="Domain Admin",
)
steps = agent.run(max_iterations=30)

# 4. Get results
print(agent.session_report())
print(graph.find_path("attacker_start", "objective_root"))
```

### Graph Visualizer

```bash
python -m pentest_agent graph --view
# Open: http://localhost:8765/Projects/pentest-agent/graph_viewer.html
```

Interactive features:
- **Click nodes** → see CVE/CVSS/EPSS/KEV data
- **Click edges** → see relation, MITRE technique, weight
- **Click gold bar** → animate optimal attack path
- **Scroll** to zoom, **drag** to pan
- **Red glow** = CISA KEV (actively exploited)
- Color-coded by node type

---

## Why a Graph, Not a Tree

Real attack surfaces are **not trees**. Here's why:

### Convergence

Multiple exploitation vectors lead to the same target:

```
                    ┌─ CVE-2021-41773 → root@web01 ─┐
                    │                                │
  Attacker ─► web01 ─┼─ SSH brute force → root@web01 ─┼─► SSH key ─► ws01
                    │                                │
                    └─ Weak MySQL → root@db01 ───────┘
                                          │
                                          └─ (also reaches ws01 via shared creds)
```

In a tree, `ws01` would be duplicated under each incoming path. In a graph, it's one node with two inbound edges. Dijkstra naturally picks the cheapest.

### Cycles

Lateral movement creates cycles:

```
  user@ws01 ──► DA hash ──► dc01 ──► DA@dc01
      ▲                         │
      └────── new creds ────────┘  (found on dc01, used to re-auth to ws01 as admin)
```

The graph handles cycles natively; Dijkstra ignores them.

### Multi-parent nodes

A `cached DA hash` node has two inbound edges:

```
  user@ws01 ──► LSASS dump ──► cached DA hash  ◄── LSASS dump ── admin@ws01
```

The hash is the same node regardless of how you got it. In a tree, you'd duplicate it.

### What IS a tree?

Only the static **MITRE ATT&CK taxonomy** itself:
- Tactics → Techniques → Sub-techniques (strict hierarchy)
- This lives as a trie/hashmap for fast lookup, not the attack graph

---

## Data Structures & Algorithms

| Problem | Data Structure | Why |
|---|---|---|
| **Attack graph storage** | `networkx.DiGraph` (adjacency list) | O(V+E) traversal, native pathfinding |
| **ATT&CK technique lookup** | Hashmap (dict) | O(1) by technique ID (~800 total) |
| **Sub-technique prefix query** (`T1059.*`) | Trie | Only if you need prefix search; hashmap otherwise |
| **Exploit frontier ranking** | Binary min-heap | O(log n) insert, O(1) peek-min |
| **Shortest path to objective** | Dijkstra | O((V+E) log V), edge weights are non-negative |
| **Path with admissible heuristic** | A\* | Dijkstra + kill-chain-stage distance heuristic |
| **Stochastic planning** | MCTS / UCB | When exploit success is probabilistic (v2) |
| **CVE semantic search** | BM25 + HNSW | Exact ID match + semantic description matching |
| **K-shortest paths** | Yen's algorithm | Attacker wants options, not just the single best path |
| **Graph export for viz** | Cytoscape.js JSON | Browser-native graph rendering |

### Why Dijkstra First (not MCTS)

Dijkstra is the right v1 choice because:

1. **Deterministic**: Given the graph, the optimal path is always the same — useful for operator review
2. **Debuggable**: You can trace every edge weight decision
3. **Fast**: O((V+E) log V) is fine for graphs with <10,000 nodes
4. **Low cognitive load**: The LLM doesn't need to model uncertainty yet

Move to MCTS when:
- Exploit success rates are probabilistic (40% chance, might trigger EDR)
- You need explore/exploit trade-offs across multiple attempts
- The graph is large enough that exhaustive pathfinding is too slow

---

## Production Roadmap

### v0.1 — Research & Demo (current)
- Attack graph data model + Dijkstra pathfinding
- CVE enrichment pipeline (NVD + EPSS + KEV + ATT&CK)
- ReAct agent loop with mock LLM
- Tool wrappers (nmap, gobuster, nuclei, searchsploit)
- Interactive graph visualization

### v0.2 — Real Exploitation
- Metasploit RPC integration
- Actual PoC execution
- Shell session management

### v0.3 — Live Intelligence
- Real-time CVE feed subscription
- Full MITRE ATT&CK STIX data
- BloodHound data import

### v1.0 — Production
- Neo4j backend
- Real MCP transport
- Web dashboard
- Multi-agent coordination
- Session persistence

### v2.0 — Advanced
- A\* + MCTS hybrid planner
- Evasion-aware edge weights
- RL from past engagements
- Automated report generation

---

## Key Design Decisions

1. **Graph is state** — no separate database, no scattered JSON. The graph nodes capture everything.
2. **Typed nodes, not generic** — `Host`, `Service`, `Vulnerability`, `Credential`, `Privilege` are distinct types with type-specific fields. This enables type-safe graph traversal.
3. **Weighted edges, not binary** — every edge has a cost. The planner minimizes cost, not hop count. This naturally prefers stealthy KEV exploits over noisy brute force.
4. **LLM is the strategist, not the executor** — the LLM decides what to do; tools execute; the graph tracks everything. The LLM never touches raw nmap output.
5. **MCP for tool decoupling** — the orchestrator doesn't import nmap. It calls `mcp.invoke("nmap", …)`. Swap tools without touching agent code.
6. **Enrichment is a pipeline, not a lookup** — NVD → EPSS → KEV → ATT&CK is a chain of API calls, each enriching the previous output. The pipeline caches aggressively.
7. **Priority, not severity** — CVSS measures impact. Priority = impact × exploitability × urgency (KEV). The heap ranks by priority, not raw CVSS.

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTI (STIX data)](https://github.com/mitre/cti)
- [Center for Threat-Informed Defense](https://ctid.io) — CVE→ATT&CK mappings
- [NVD REST API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [FIRST.org EPSS](https://www.first.org/epss)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) — graph-based AD attack path analysis
- [MulVAL](https://github.com/risesecurity/mulval) — academic attack graph generator (Datalog)
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) — Python STIX loader
- [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) — PoC dataset

---

## License

MIT — for authorized security testing only. This tool is designed for CTF competitions, bug bounty programs, and authorized penetration testing engagements.
