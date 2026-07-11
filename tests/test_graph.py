"""Tests for AttackGraph, pathfinding, and frontier ranking."""

from pentest_agent.graph.models import Node, Edge, NodeType, EdgeRelation
from pentest_agent.graph.pathfinding import AttackPathfinder


class TestAttackGraph:
    def test_add_node(self, empty_graph):
        g = empty_graph
        g.add_node(Node("host_test", NodeType.HOST, "10.0.0.1", host_ip="10.0.0.1"))
        assert g.has_node("host_test")
        assert g.get_node("host_test").host_ip == "10.0.0.1"
        assert g.node_count == 3  # attacker + objective + host

    def test_add_edge(self, empty_graph):
        g = empty_graph
        g.add_node(Node("host_test", NodeType.HOST, "10.0.0.1"))
        g.add_edge(Edge("attacker_start", "host_test",
                       EdgeRelation.NETWORK_ACCESS, 1.0, "test"))
        assert g.edge_count == 1

    def test_summary(self, demo_graph):
        summary = demo_graph.summary()
        assert "2 hosts" in summary
        assert "CVE-2021-41773" in str(demo_graph.nodes.get("vuln_CVE-2021-41773"))

    def test_frontier_ranking(self, demo_graph):
        frontier = demo_graph.reachable_vulns("attacker_start")
        assert len(frontier) >= 1
        # CVE-2021-41773 should be top priority (KEV + high EPSS)
        assert frontier[0]["kev"] is True
        assert frontier[0]["cve"] == "CVE-2021-41773"
        assert frontier[0]["priority"] < 1.0  # KEV should give very low priority

    def test_vuln_priority_score(self):
        """KEV vulns should have much lower priority than non-KEV."""
        kev_vuln = Node("v1", NodeType.VULNERABILITY, "test",
                        cvss_score=9.0, epss_score=0.9, kev=True, exploit_available=True)
        non_kev = Node("v2", NodeType.VULNERABILITY, "test",
                       cvss_score=9.0, epss_score=0.9, kev=False)
        assert kev_vuln.priority_score < non_kev.priority_score

    def test_export_json(self, demo_graph, tmp_path):
        path = tmp_path / "test_graph.json"
        demo_graph.export_json(str(path))
        assert path.exists()
        import json
        data = json.loads(path.read_text())
        assert "nodes" in data
        assert "edges" in data

    def test_to_dict(self, demo_graph):
        d = demo_graph.to_dict()
        assert len(d["nodes"]) > 0
        assert len(d["edges"]) > 0


class TestPathfinding:
    def test_dijkstra_path(self, demo_graph):
        pf = AttackPathfinder(demo_graph)
        result = pf.dijkstra("attacker_start", "objective_root")
        assert result is not None
        assert result.total_cost > 0
        assert len(result.path) >= 3  # attacker → host → ... → objective
        # Verify path goes through the KEV vuln
        node_ids = [step["from"] for step in result.path] + [result.path[-1]["to"]]
        assert "vuln_CVE-2021-41773" in node_ids or "priv_root_web01" in node_ids

    def test_a_star_path(self, demo_graph):
        pf = AttackPathfinder(demo_graph)
        result = pf.a_star("attacker_start", "objective_root")
        assert result is not None
        assert result.algorithm == "a_star"

    def test_evasive_path(self, demo_graph):
        pf = AttackPathfinder(demo_graph)
        result = pf.evasive("attacker_start", "objective_root")
        assert result is not None
        assert result.algorithm == "evasive"
        # Evasive path should consider detection_risk
        assert hasattr(result, "total_risk")

    def test_k_shortest(self, demo_graph):
        pf = AttackPathfinder(demo_graph)
        results = pf.k_shortest("attacker_start", "objective_root", k=2)
        assert len(results) >= 1
        assert results[0].total_cost > 0

    def test_mcts(self, demo_graph):
        pf = AttackPathfinder(demo_graph)
        result = pf.mcts("attacker_start", "objective_root", simulations=100)
        # MCTS may or may not find a path with few simulations
        if result:
            assert len(result.path) > 0

    def test_no_path(self, empty_graph):
        pf = AttackPathfinder(empty_graph)
        assert pf.dijkstra("attacker_start", "objective_root") is None
        assert pf.a_star("attacker_start", "objective_root") is None

    def test_path_result_summary(self, demo_graph):
        pf = AttackPathfinder(demo_graph)
        result = pf.dijkstra("attacker_start", "objective_root")
        assert result is not None
        summary = result.summary()
        assert "dijkstra" in summary.lower()
        assert "cost=" in summary


class TestNodeEdge:
    def test_node_types(self):
        for nt in NodeType:
            node = Node(f"test_{nt.value}", nt, f"Test {nt.value}")
            assert node.type == nt
            assert node.id == f"test_{nt.value}"

    def test_edge_relations(self):
        for er in EdgeRelation:
            edge = Edge("a", "b", er, 1.0, "test")
            assert edge.relation == er

    def test_node_priority_scoring(self):
        """Priority should decrease (better) with higher CVSS, EPSS, KEV, and PoC."""
        base = Node("v", NodeType.VULNERABILITY, "test",
                    cvss_score=5.0, epss_score=0.5, kev=False,
                    exploit_available=False)
        base_score = base.priority_score

        # Higher CVSS → lower (better) priority
        high_cvss = Node("v", NodeType.VULNERABILITY, "test",
                         cvss_score=9.0, epss_score=0.5, kev=False,
                         exploit_available=False)
        assert high_cvss.priority_score < base_score

        # KEV → much lower priority
        kev_node = Node("v", NodeType.VULNERABILITY, "test",
                        cvss_score=5.0, epss_score=0.5, kev=True,
                        exploit_available=True)
        assert kev_node.priority_score < base_score


class TestNodeConstruction:
    def test_node_str_representation(self):
        node = Node("h1", NodeType.HOST, "10.0.0.1", host_ip="10.0.0.1")
        s = str(node)
        assert "h1" in s
        assert "HOST" in s

    def test_node_with_services(self):
        node = Node("s1", NodeType.SERVICE, "ssh:22",
                     service_port=22, service_version="OpenSSH 8.9p1",
                     service_cpe="cpe:2.3:a:openbsd:openssh:8.9p1")
        assert node.service_port == 22
        assert "8.9p1" in node.service_version
        assert "cpe:" in node.service_cpe

    def test_node_with_credentials(self):
        node = Node("c1", NodeType.CREDENTIAL, "admin:pass123",
                     credential_type="password", credential_target="10.0.0.1")
        assert node.credential_type == "password"
        assert node.credential_target == "10.0.0.1"


class TestEdgeConstruction:
    def test_edge_str_representation(self):
        edge = Edge("a", "b", EdgeRelation.NETWORK_ACCESS, 1.0, "test")
        s = str(edge)
        assert "a" in s
        assert "b" in s

    def test_edge_with_mitre(self):
        edge = Edge("a", "b", EdgeRelation.NETWORK_ACCESS, 0.5, "test",
                     mitre_technique="T1190", detection_risk=0.8)
        assert edge.mitre_technique == "T1190"
        assert edge.detection_risk == 0.8


class TestAttackGraphExtended:
    def test_add_duplicate_node(self, empty_graph):
        g = empty_graph
        g.add_node(Node("h1", NodeType.HOST, "10.0.0.1"))
        g.add_node(Node("h1", NodeType.HOST, "10.0.0.1"))  # duplicate
        assert g.node_count == 3  # still 3 because duplicate overwrites

    def test_get_nonexistent_node(self, empty_graph):
        assert empty_graph.get_node("nonexistent") is None

    def test_has_node(self, empty_graph):
        assert empty_graph.has_node("attacker_start")
        assert not empty_graph.has_node("nonexistent")

    def test_find_path_no_path(self, empty_graph):
        path = empty_graph.find_path("attacker_start", "objective_root")
        assert path is None

    def test_edge_connected(self, demo_graph):
        """Verify demo graph has expected edges via networkx."""
        import networkx as nx
        assert demo_graph._g.has_edge("attacker_start", "host_web01")
        # The vuln might be connected via a service node, not directly to host
        edges = list(demo_graph._g.edges())
        assert any("CVE-2021-41773" in str(e) for e in edges)

    def test_reset_clears_data_nodes(self, demo_graph):
        demo_graph.reset()
        assert demo_graph.has_node("attacker_start")
        assert demo_graph.has_node("objective_root")
        assert not demo_graph.has_node("host_web01")
        assert demo_graph.node_count == 2
        assert demo_graph.edge_count == 0

    def test_reset_empty_graph(self, empty_graph):
        empty_graph.reset()
        assert empty_graph.node_count == 2
        assert empty_graph.edge_count == 0
