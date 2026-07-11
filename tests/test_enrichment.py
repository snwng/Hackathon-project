"""Tests for CVE enrichment pipeline, CPE matching, and CWE→ATT&CK mapping."""

from pentest_agent.enrichment import (
    map_cwe_to_attack,
    map_capec_to_attack,
    CWE_TO_ATTACK,
)


class TestCWEMapping:
    def test_cwe_22_path_traversal(self):
        """CWE-22 should map to T1190 (initial-access)."""
        results = map_cwe_to_attack("CWE-22")
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1190"
        assert results[0]["tactic"] == "initial-access"

    def test_cwe_78_command_injection(self):
        """CWE-78 should map to T1059 (execution)."""
        results = map_cwe_to_attack("CWE-78")
        assert results[0]["technique_id"] == "T1059"

    def test_cwe_89_sql_injection(self):
        """CWE-89 maps to T1190 and T1505."""
        results = map_cwe_to_attack("CWE-89")
        assert len(results) == 2
        assert any(r["technique_id"] == "T1190" for r in results)

    def test_cwe_502_deserialization(self):
        """CWE-502 maps to T1059 (execution)."""
        results = map_cwe_to_attack("CWE-502")
        assert results[0]["technique_id"] == "T1059"

    def test_unknown_cwe(self):
        """Unknown CWE returns empty list."""
        results = map_cwe_to_attack("CWE-99999")
        assert results == []

    def test_all_cwes_have_valid_tactics(self):
        """Every CWE mapping must use valid MITRE tactics."""
        valid_tactics = {
            "initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement",
            "collection", "command-and-control", "exfiltration", "impact",
            "reconnaissance",
        }
        for cwe, techs in CWE_TO_ATTACK.items():
            for tid, tactic in techs:
                assert tactic in valid_tactics, f"{cwe} → {tactic} is invalid"

    def test_all_techniques_start_with_t(self):
        """Every technique ID must start with T."""
        for cwe, techs in CWE_TO_ATTACK.items():
            for tid, _ in techs:
                assert tid.startswith("T"), f"{cwe} → {tid} doesn't start with T"


class TestCAPECMapping:
    def test_capec_126_path_traversal(self):
        results = map_capec_to_attack("CAPEC-126")
        assert results[0]["technique_id"] == "T1059"

    def test_capec_233_privesc(self):
        results = map_capec_to_attack("CAPEC-233")
        assert results[0]["tactic"] == "privilege-escalation"

    def test_unknown_capec(self):
        assert map_capec_to_attack("CAPEC-99999") == []


class TestCPEBuilding:
    def test_cpe_map(self):
        """Test CPE vendor mapping."""
        from pentest_agent.agent_pro import CPE_VENDOR_MAP
        assert "apache" in CPE_VENDOR_MAP
        assert CPE_VENDOR_MAP["apache"] == ("http_server", "apache")
        assert CPE_VENDOR_MAP["openssh"] == ("openssh", "openbsd")
