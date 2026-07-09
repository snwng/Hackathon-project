# Strix vs. Pentest-Agent — Gap Analysis

> Analysis of [Strix](https://github.com/usestrix/strix) (v1.0.4, 39.1k ★, Apache 2.0)
> vs. our pentest-agent architecture.
> July 2026

---

## TL;DR

**Strix** and **pentest-agent** attack the same problem from opposite angles:

- **Strix** = multi-agent web-app pentester with sandboxed tool execution, CI/CD integration, and auto-fix generation. Agent tree. No MITRE, no attack-path planning.
- **Pentest-agent** = graph-based network/AD pentester with CVE enrichment, MITRE ATT&CK mapping, and optimal-path planning. Single agent loop. No sandbox, no multi-agent coordination.

They're **complementary** — the ideal system combines both.

---

## Architecture Comparison

| Dimension | Strix | Pentest-Agent | Winner |
|---|---|---|---|
| **Agent model** | Multi-agent tree (root → children → grandchildren) | Single ReAct agent loop | Strix |
| **Agent graph** | Tree of agents (orchestration structure) | Directed graph of the TARGET (hosts/services/vulns) | Pentest-agent |
| **Communication** | Agent inbox: `send_message_to_agent`, `wait_for_message` | None (single agent, no inter-agent comms) | Strix |
| **State management** | Coordinator object tracks agent statuses + inboxes | Attack graph IS the state (nodes capture everything) | Tie — different purposes |
| **Execution model** | Docker sandbox per agent | Direct process execution (operator's machine) | Strix |
| **LLM integration** | LiteLLM (multi-provider abstraction) | Pluggable callable — Claude, OpenAI, Ollama | Strix |
| **Tool interface** | FunctionTool + CustomTool (SDK-native) | MCP protocol (stdio JSON-RPC) | Pentest-agent |
| **Tool decoupling** | Tightly coupled to SDK | MCP server — swap tools without touching agent code | Pentest-agent |
| **Skills system** | `load_skill` — modular, hot-loadable agent capabilities | None — tools are hardcoded | Strix |

---

## Feature Comparison

### What Strix Has That We Don't

| Feature | Strix Implementation | Priority to Add | Effort |
|---|---|---|---|
| **Multi-agent orchestration** | Root spawns child agents; children spawn grandchildren; inbox-based comms | HIGH | Medium |
| **Docker sandbox** | Agents run in isolated containers; safe PoC execution | HIGH | Low |
| **Browser automation** | Playwright for XSS, CSRF, auth bypass, clickjacking | MEDIUM | Medium |
| **HTTP proxy** | Caido for request/response inspection + manipulation | MEDIUM | Low |
| **CI/CD integration** | `--non-interactive`, `--scope-mode diff`, GitHub Actions | MEDIUM | Low |
| **Skills system** | Hot-loadable agent capabilities via `load_skill` | MEDIUM | Medium |
| **Interactive TUI** | Textual-based terminal UI for live sessions | LOW | Medium |
| **Auto-fix PRs** | AI-generated patches as ready-to-merge GitHub PRs | LOW | High |
| **Compliance reports** | SOC 2, ISO 27001, PCI DSS formatted reports | LOW | Medium |
| **Agent lifecycle** | Statuses: running, waiting, completed, crashed, stopped | MEDIUM | Low |
| **SAST capability** | Static analysis of source code repositories | LOW | High |
| **Inter-agent messaging** | Structured inbox with priority levels + message types | HIGH | Medium |
| **Diff-scoped scanning** | Only scan changed lines in PRs | LOW | Low |
| **Continuous pentesting** | Always-on, runs against deployments automatically | LOW | High |
| **Perplexity search** | Web search integration for OSINT | MEDIUM | Low |

### What We Have That Strix Doesn't

| Feature | Pentest-Agent Implementation | Why It Matters |
|---|---|---|
| **MITRE ATT&CK integration** | Full technique lookup, CWE→ATT&CK mapping, tactic tracking | Every edge in the attack graph maps to a MITRE technique. Essential for blue team handoff and threat-informed defense. |
| **CVE enrichment pipeline** | NVD API 2.0 → EPSS → CISA KEV → ATT&CK (chained) | Every service version gets real-time CVE data with exploitation probability. Strix has CVSS scoring but no live CVE feeds. |
| **Attack graph (target)** | Directed weighted graph: Host → Service → Vuln → Exploit → Privilege → Credential → Lateral | Models the TARGET's infrastructure, not the agent hierarchy. Enables pathfinding. |
| **Priority queue exploit ranking** | Binary min-heap: `f(CVSS, EPSS, KEV, PoC availability)` | Ranks what to exploit first based on impact × exploitability × urgency. |
| **Dijkstra/A\* pathfinding** | Optimal attack chain from attacker to Domain Admin | BloodHound-style "shortest path to DA" — Strix has no pathfinding across the target. |
| **Neo4j/BloodHound export** | Full Cypher generation with indexes, relationships, query library | Scales to enterprise networks. Same pattern as BloodHound. |
| **MCP protocol** | Stdio JSON-RPC transport, 13 tool definitions, graph operations as tools | Decouples orchestrator from tools. Claude Code can call pentest tools directly. |
| **Lateral movement modeling** | `can_auth`, `can_lateral`, `credential_dumping` edge types | Models pass-the-hash, SSH pivoting, WinRM lateral movement — core to network pentesting. |
| **AD attack paths** | Domain Admin chaining via LSASS dump → PTH → noPAC → DA | BloodHound-style attack-path modeling for Active Directory. |
| **Tool normalization** | All tools return structured `Finding` objects → unified graph ingestion | nmap, nuclei, gobuster all feed the same data model. |
| **Offline ATT&CK data** | 26 techniques, 13 tactics built-in; trie for sub-technique prefix search | Works without internet. Full STIX loader when online. |

---

## Architecture Diagrams

### Strix Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    STRIX                                 │
│                                                          │
│  ┌──────────┐  spawns   ┌──────────┐  spawns  ┌───────┐ │
│  │ ROOT     │──────────▶│ CHILD    │─────────▶│LEAF   │ │
│  │ AGENT    │           │ AGENT    │          │AGENT  │ │
│  │          │◀──────────│          │◀─────────│       │ │
│  │ skills:  │  inbox    │ skills:  │  inbox   │skills │ │
│  │ - proxy  │  msgs     │ - nuclei │  msgs    │-shell │ │
│  │ - browser│           │ - xss    │          │       │ │
│  │ - web    │           │          │          │       │ │
│  └──────────┘           └──────────┘          └───────┘ │
│       │                      │                     │     │
│       └──────────────────────┼─────────────────────┘     │
│                              │                           │
│                    ┌─────────▼─────────┐                 │
│                    │   COORDINATOR     │                 │
│                    │  (agent tree +    │                 │
│                    │   inbox state)    │                 │
│                    └───────────────────┘                 │
│                                                          │
│  Tools: proxy, browser, shell, nuclei, web_search,      │
│         notes, todo, apply_patch, report                 │
│                                                          │
│  Target: source code repo, live URL, or PR diff          │
│  Output: findings + PoCs + auto-fix PRs + compliance     │
└─────────────────────────────────────────────────────────┘
```

### Pentest-Agent Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  PENTEST-AGENT                            │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │              REACT AGENT LOOP                      │   │
│  │                                                    │   │
│  │  OBSERVE ──▶ THINK ──▶ ACT ──▶ UPDATE             │   │
│  │  (graph    (LLM     (tool    (mutate               │   │
│  │   state)   decides)  call)    graph)               │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                                │
│         ┌───────────────┼───────────────┐               │
│         ▼               ▼               ▼               │
│  ┌──────────┐   ┌──────────────┐  ┌──────────┐        │
│  │   MCP    │   │  ENRICHMENT  │  │ MITRE    │        │
│  │  SERVER  │   │  PIPELINE    │  │ ATT&CK   │        │
│  │          │   │              │  │ LOADER   │        │
│  │ nmap     │   │ NVD API 2.0  │  │          │        │
│  │ gobuster │   │ EPSS (FIRST) │  │ 650+     │        │
│  │ nuclei   │   │ CISA KEV     │  │ techniques│       │
│  │ srchsplt │   │ CWE→ATT&CK   │  │ trie      │        │
│  └────┬─────┘   └──────┬───────┘  └────┬─────┘        │
│       │                │               │               │
│       └────────────────┼───────────────┘               │
│                        ▼                                │
│  ┌──────────────────────────────────────────────────┐   │
│  │              ATTACK GRAPH                          │   │
│  │           (networkx.DiGraph)                       │   │
│  │                                                    │   │
│  │  attacker ──▶ host ──▶ service ──▶ vuln ──▶ priv  │   │
│  │                                  │         │       │   │
│  │                                  ▼         ▼       │   │
│  │                               cred ──▶ lateral ──▶ │   │
│  │                                                    │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │   │
│  │  │ frontier │  │ Dijkstra │  │ Cypher   │        │   │
│  │  │ (heap)   │  │ (path)   │  │ (Neo4j)  │        │   │
│  │  └──────────┘  └──────────┘  └──────────┘        │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  Target: network range, IP list, AD domain               │
│  Output: attack paths + exploit plan + graph viz         │
└─────────────────────────────────────────────────────────┘
```

---

## Gaps to Close — What We Should Build Next

### 1. Multi-Agent Orchestration (HIGH PRIORITY)

Strix's strongest feature. We should adopt their pattern:

```python
# What we need to add:
class AgentCoordinator:
    """Manages a tree of agents with inbox-based communication."""
    agents: dict[str, Agent]
    agent_tree: DiGraph          # parent → child relationships
    inboxes: dict[str, list]     # agent_id → [messages]

    def create_agent(self, name, task, skills) -> str
    def send_message(self, from_agent, to_agent, msg_type, content)
    def wait_for_message(self, agent_id, timeout)
    def stop_agent(self, agent_id, cascade)
    def view_agent_graph(self) -> str  # ASCII tree of agents
```

**Why:** A single ReAct agent can't parallelize. For a real engagement you want:
- One agent running nmap on all hosts in parallel
- Another enriching CVEs as results come in
- A third attempting low-risk exploits on KEV vulns
- A coordinator merging findings into the attack graph

### 2. Docker Sandbox (HIGH PRIORITY)

Strix runs every agent in a Docker container. We should at minimum sandbox exploit execution:

```python
class SandboxedExploitRunner:
    """Run PoC exploits in Docker containers."""
    def run_in_sandbox(self, exploit_path, target, image="pentest-sandbox"):
        # docker run --rm --network host -v exploit:/exploit pentest-sandbox
```

### 3. Agent Inbox System (HIGH PRIORITY)

Replace our single `AgentStep` log with real inter-agent messaging:

```python
@dataclass
class AgentMessage:
    sender_id: str
    recipient_id: str
    msg_type: str       # "query", "instruction", "information", "finding"
    priority: str       # "low", "normal", "high", "urgent"
    content: str
    timestamp: str

class AgentInbox:
    """Per-agent inbox with priority queuing."""
    def deliver(self, message: AgentMessage)
    def await_message(self, timeout: float) -> AgentMessage
```

### 4. Skills System (MEDIUM PRIORITY)

Strix's `load_skill` pattern lets agents acquire capabilities dynamically:

```python
# What we need:
SKILL_REGISTRY = {
    "web_recon": WebReconSkill(nuclei, gobuster),
    "network_scan": NetworkScanSkill(nmap, masscan),
    "ad_enum": ADEnumSkill(bloodhound, ldapsearch),
    "exploit_web": WebExploitSkill(metasploit, nuclei),
    "lateral_move": LateralMovementSkill(psexec, wmiexec, ssh),
}

# Agent loads: load_skill("web_recon")
# Now agent can call: nmap, gobuster, nuclei, whatweb
```

### 5. Web Search Integration (MEDIUM PRIORITY)

Strix uses Perplexity for OSINT. We should add web search to our enrichment pipeline:

```python
# In enrichment pipeline:
def search_exploit_web(cve_id: str) -> list[str]:
    """Search the web for PoCs, writeups, exploitation guides."""
    # Use Perplexity API or Google/Bing search
```

### 6. Agent Status Lifecycle (MEDIUM PRIORITY)

```python
class AgentStatus(Enum):
    RUNNING = "running"
    WAITING = "waiting"        # waiting for a message
    COMPLETED = "completed"    # finished successfully
    CRASHED = "crashed"        # terminal error
    STOPPED = "stopped"        # stopped by parent
```

### 7. CI/CD / Non-Interactive Mode (MEDIUM PRIORITY)

```python
# What we need:
python -m pentest_agent run --target 10.10.10.0/24 --non-interactive --output-dir ./run_2026-07-09/
```

### 8. Browser Automation (LOW PRIORITY — scope dependent)

If we expand to web app testing, add Playwright integration:

```python
class BrowserTool(BaseTool):
    """Automated browser for XSS, CSRF, auth testing."""
    name = "browser"
    def run(self, target_url: str, action: str) -> list[Finding]
```

---

## What NOT to Adopt from Strix

1. **Tight SDK coupling** — Strix tools are tightly coupled to their SDK's `FunctionTool`. Our MCP approach is more portable (works with any MCP client, not just one SDK).
2. **Agent tree vs. attack graph** — Strix's agent tree models the ORCHESTRATION. Our attack graph models the TARGET. We need BOTH, not one or the other.
3. **No ATT&CK mapping** — This is our strongest differentiator. Don't drop it.
4. **No pathfinding** — Strix has no Dijkstra/A\* over the target. Keep this.
5. **Web-only focus** — Strix is primarily web-app pentesting. Keep our network/AD focus.

---

## The Combined Architecture (v2 Target)

```
┌──────────────────────────────────────────────────────────────────┐
│                    PENTEST-AGENT v2                               │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              AGENT COORDINATOR (Strix pattern)            │    │
│  │                                                           │    │
│  │  ROOT AGENT                                               │    │
│  │  ├── RECON AGENT (nmap all hosts in parallel)             │    │
│  │  ├── WEB AGENT (gobuster + nuclei on HTTP services)       │    │
│  │  ├── ENRICH AGENT (NVD+EPSS+KEV for every service)        │    │
│  │  ├── EXPLOIT AGENT (run exploits on KEV vulns)            │    │
│  │  └── LATERAL AGENT (pivot with found creds)               │    │
│  │                                                           │    │
│  │  Communication: inbox messages (findings flow upward)     │    │
│  │  Lifecycle: running → waiting → completed/crashed         │    │
│  └──────────────────────────────────────────────────────────┘    │
│                              │                                    │
│                              ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              ATTACK GRAPH (our pattern)                   │    │
│  │                                                           │    │
│  │  All agents write to the SAME graph.                      │    │
│  │  Graph is the shared state between all agents.            │    │
│  │  Frontier ranking + pathfinding works off merged data.    │    │
│  └──────────────────────────────────────────────────────────┘    │
│                              │                                    │
│                              ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              EXECUTION ENGINE                              │    │
│  │                                                           │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐               │    │
│  │  │ Docker   │  │ MCP      │  │ Skills   │               │    │
│  │  │ Sandbox  │  │ Server   │  │ Registry │               │    │
│  │  └──────────┘  └──────────┘  └──────────┘               │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

The combined system has:
- **Strix's** multi-agent tree for orchestrating parallel work
- **Our** attack graph as the shared state between agents
- **Our** MCP server for tool decoupling
- **Our** enrichment pipeline + MITRE mapping
- **Strix's** Docker sandbox for safe execution
- **Strix's** inter-agent inbox for coordination
- **Strix's** skills system for modular capabilities

---

## Summary

| Area | Strix | Pentest-Agent | Combined |
|---|---|---|---|
| Multi-agent orchestration | ✅ | ❌ | ✅ **adopt** |
| Docker sandbox | ✅ | ❌ | ✅ **adopt** |
| Skills system | ✅ | ❌ | ✅ **adopt** |
| Inter-agent messaging | ✅ | ❌ | ✅ **adopt** |
| MITRE ATT&CK mapping | ❌ | ✅ | ✅ **keep** |
| Attack graph (target) | ❌ | ✅ | ✅ **keep** |
| CVE enrichment pipeline | ❌ | ✅ | ✅ **keep** |
| Priority queue ranking | ❌ | ✅ | ✅ **keep** |
| Dijkstra/A* pathfinding | ❌ | ✅ | ✅ **keep** |
| MCP protocol | ❌ | ✅ | ✅ **keep** |
| Neo4j/BloodHound export | ❌ | ✅ | ✅ **keep** |
| Browser automation | ✅ | ❌ | 🔶 **scope-dependent** |
| CI/CD integration | ✅ | ❌ | 🔶 **add later** |
| Auto-fix PRs | ✅ | ❌ | 🔶 **add later** |
| Compliance reports | ✅ | ❌ | 🔶 **add later** |

**Immediate next builds (next session):**
1. Multi-agent coordinator with inbox system
2. Docker sandbox for exploit execution
3. Skills registry for hot-loadable agent capabilities
4. Web search integration for OSINT/enrichment
