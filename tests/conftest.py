"""Shared test fixtures for Pentest Agent v3."""

import pytest
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pentest_agent.graph.models import AttackGraph, Node, Edge, NodeType, EdgeRelation


@pytest.fixture
def empty_graph():
    """An empty attack graph with just attacker + objective."""
    g = AttackGraph(name="test")
    g.add_node(Node("attacker_start", NodeType.ATTACKER, "Attacker"))
    g.add_node(Node("objective_root", NodeType.OBJECTIVE, "Domain Admin"))
    return g


@pytest.fixture
def demo_graph():
    """A realistic attack graph with hosts, services, vulns, creds, and privs."""
    g = AttackGraph(name="demo")

    # Attacker and objective
    g.add_node(Node("attacker_start", NodeType.ATTACKER, "Attacker"))
    g.add_node(Node("objective_root", NodeType.OBJECTIVE, "Domain Admin"))

    # Host: web01 (10.10.10.10)
    g.add_node(Node("host_web01", NodeType.HOST, "10.10.10.10",
                    host_ip="10.10.10.10", host_os="Ubuntu 20.04"))
    g.add_edge(Edge("attacker_start", "host_web01",
                    EdgeRelation.NETWORK_ACCESS, 0.0, "network_reachable"))

    # Service: Apache 2.4.49 on port 443
    g.add_node(Node("svc_apache", NodeType.SERVICE, "Apache httpd 2.4.49:443",
                    service_port=443, service_version="2.4.49",
                    service_cpe="cpe:2.3:a:apache:http_server:2.4.49"))
    g.add_edge(Edge("host_web01", "svc_apache",
                    EdgeRelation.HAS_SERVICE, 0.0, "service_discovered"))

    # Vulnerability: CVE-2021-41773 (KEV, high EPSS)
    g.add_node(Node("vuln_CVE-2021-41773", NodeType.VULNERABILITY,
                    "CVE-2021-41773: Apache Path Traversal",
                    cve_id="CVE-2021-41773", cvss_score=7.5, epss_score=0.96,
                    kev=True, cwe_id="CWE-22",
                    mitre_technique="T1190", mitre_tactic="initial-access"))
    g.add_edge(Edge("svc_apache", "vuln_CVE-2021-41773",
                    EdgeRelation.HAS_VULN, 0.5, "vulnerability_identified"))

    # Privilege: root@web01 via CVE-2021-41773
    g.add_node(Node("priv_root_web01", NodeType.PRIVILEGE,
                    "root@10.10.10.10", privilege_level="root",
                    privilege_host="10.10.10.10"))
    g.add_edge(Edge("vuln_CVE-2021-41773", "priv_root_web01",
                    EdgeRelation.EXPLOITS, 2.0, "remote_code_execution",
                    mitre_technique="T1190", detection_risk=0.4))

    # Credential: SSH key found on web01
    g.add_node(Node("cred_ssh_key", NodeType.CREDENTIAL,
                    "SSH key from /var/www/.ssh",
                    credential_type="ssh_key"))
    g.add_edge(Edge("priv_root_web01", "cred_ssh_key",
                    EdgeRelation.CREDENTIAL_DISCOVERY, 1.5, "unsecured_creds",
                    mitre_technique="T1552"))

    # Host: dc01 (10.10.10.30)
    g.add_node(Node("host_dc01", NodeType.HOST, "10.10.10.30",
                    host_ip="10.10.10.30", host_os="Windows Server 2019"))

    # Lateral movement via SSH key → dc01
    g.add_edge(Edge("cred_ssh_key", "host_dc01",
                    EdgeRelation.CAN_AUTH, 2.0, "ssh_lateral",
                    mitre_technique="T1021.004", detection_risk=0.3))

    # Connect dc01 to objective
    g.add_edge(Edge("host_dc01", "objective_root",
                    EdgeRelation.OBJECTIVE_ACHIEVED, 0.0, "domain_admin_access"))

    return g
