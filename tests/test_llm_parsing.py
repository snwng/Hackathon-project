"""Tests for LLM decision parsing with Pydantic validation."""

import pytest
from pentest_agent.llm.parsing import DecisionParser, AgentDecision, ActionType


class TestDecisionParser:
    def setup_method(self):
        self.parser = DecisionParser()

    def test_parse_pure_json(self):
        response = '{"action": "recon", "tool": "nmap", "target": "10.10.10.10", "args": {"fast": true}, "reasoning": "Initial scan"}'
        decision = self.parser.parse(response)
        assert decision.action == ActionType.RECON
        assert decision.tool == "nmap"
        assert decision.target == "10.10.10.10"
        assert decision.args == {"fast": True}
        assert "Initial scan" in decision.reasoning

    def test_parse_json_block(self):
        response = """
        Here is my decision:
        ```json
        {"action": "exploit", "tool": "download_exploit", "target": "CVE-2021-41773", "args": {"cve_id": "CVE-2021-41773"}, "reasoning": "KEV vuln — exploit first"}
        ```
        """
        decision = self.parser.parse(response)
        assert decision.action == ActionType.EXPLOIT
        assert decision.tool == "download_exploit"
        assert "CVE-2021-41773" in decision.target

    def test_parse_key_value_legacy(self):
        response = """
        ACTION: enrich
        TOOL: enrich_service
        TARGET: Apache 2.4.49
        ARGS: {"service_name": "Apache", "service_version": "2.4.49"}
        REASONING: Need CVE data for this service
        """
        decision = self.parser.parse(response)
        assert decision.action == ActionType.ENRICH
        assert decision.tool == "enrich_service"
        assert decision.reasoning == "Need CVE data for this service"

    def test_parse_minimal(self):
        """Minimal valid response should default gracefully."""
        response = '{"action": "done", "reasoning": "Objective achieved"}'
        decision = self.parser.parse(response)
        assert decision.action == ActionType.DONE
        assert decision.tool == "nmap"  # default

    def test_parse_malformed_json_with_block(self):
        """Malformed outer text but valid JSON block inside."""
        response = """
        I think the best action is:
        ```json
        {"action": "lateral", "tool": "ssh", "target": "10.10.10.30", "args": {}, "reasoning": "Use SSH key"}
        ```
        That should give us access.
        """
        decision = self.parser.parse(response)
        assert decision.action == ActionType.LATERAL
        assert decision.tool == "ssh"

    def test_parse_raises_on_total_failure(self):
        with pytest.raises(ValueError):
            self.parser.parse("no json here at all just plain text without any colons or braces")

    def test_agent_decision_from_dict_normalizes_keys(self):
        """Should handle uppercase and alternative keys."""
        result = AgentDecision.from_dict({
            "ACTION": "exploit",
            "TOOL": "metasploit",
            "TARGET": "10.10.10.10",
            "REASONING": "Testing",
        })
        assert result.action == ActionType.EXPLOIT
        assert result.tool == "metasploit"

    def test_json_extraction_from_braces(self):
        text = 'some text { "action": "search", "tool": "web_search", "target": "orion.htb", "args": {}, "reasoning": "Search for writeup" } more text'
        decision = self.parser.parse(text)
        assert decision.action == ActionType.SEARCH
        assert decision.tool == "web_search"


class TestActionType:
    def test_all_actions_parseable(self):
        for at in ActionType:
            response = f'{{"action": "{at.value}", "tool": "test", "target": "", "reasoning": ""}}'
            parser = DecisionParser()
            decision = parser.parse(response)
            assert decision.action == at
