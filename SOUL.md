# Pentest Agent — Project SOUL

## Purpose
An AI-driven penetration testing assistant. The agent receives a target IP/hostname and autonomously discovers services, finds vulnerabilities, attempts exploitation, and chains privileges/credentials — all while the user can watch, intervene, and ask questions conversationally.

The project exists to:
1. Automate the boring/scripted parts of pentesting (scanning, service discovery, exploit lookup)
2. Augment human judgment with AI reasoning about attack paths
3. Keep the human in the loop — the agent explains what it's doing and why

## Architecture (high-level)

```
User (REPL) ──INSTRUCTION──→ Coordinator ──system+observation──→ LLM
                                  │                                    │
                                  │ ←── AgentDecision (JSON) ──────────│
                                  │
                                  ├──→ tools (nmap, gobuster, nuclei, searchsploit)
                                  ├──→ AttackGraph (data model)
                                  └──→ Skills registry (capabilities)
```

### Key components
- **REPL** (`agent_repl.py`): Terminal UI. User types instructions (`/step`, `/target`, or free text).
- **Coordinator** (`agent/coordinator.py`): Central brain. Manages agents, messages, conversation history, and the decision loop.
- **LLM Client** (`llm/`): Abstraction over Gemini / OpenAI / deterministic fallback. Parses JSON responses into `AgentDecision`.
- **Attack Graph** (`graph/`): NetworkX-based directed graph tracking hosts, services, vulnerabilities, credentials, privileges.
- **Tools** (`tools/`): Wrappers around nmap, gobuster, nuclei, searchsploit. Each returns `list[Finding]`.
- **Skills** (`skills/`): Registry of agent capabilities (recon, exploit, brute-force, etc.).

### Data flow
1. User sends instruction (or just `/step` to auto-pilot)
2. Coordinator picks up pending agent with inbox messages
3. Builds `observation` (graph state + frontier + conversation history)
4. Sends `system_prompt` + `observation` to LLM
5. LLM returns `AgentDecision` (JSON with action/tool/target/args/response)
6. If `response` is non-empty, agent answered a question — show it
7. Otherwise execute the decision: run the tool, parse findings, update graph
8. Repeat

## Quick start
```bash
pip install -e .
pentest-agent --target 10.10.10.10 --model gemini
```

## LLM output format
Every LLM response must be valid JSON with these fields:
- `action`: recon | enrich | exploit | lateral | privesc | bruteforce | search | done
- `tool`: nmap | gobuster | nuclei | searchsploit | ...
- `target`: IP, hostname, or URL
- `args`: key-value dict of tool parameters
- `reasoning`: one-sentence explanation
- `response`: direct answer to the user (empty if running a tool)
