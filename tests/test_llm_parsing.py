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


class TestAgentDecisionResponse:
    def test_response_field_defaults_empty(self):
        d = AgentDecision(action=ActionType.RECON, tool="nmap", target="10.10.10.10")
        assert d.response == ""

    def test_from_dict_parses_response(self):
        d = AgentDecision.from_dict({
            "action": "done",
            "response": "The scan found Apache 2.4.49 on port 80.",
        })
        assert d.response == "The scan found Apache 2.4.49 on port 80."

    def test_from_dict_parses_answer_alias(self):
        d = AgentDecision.from_dict({
            "action": "done",
            "answer": "Yes, port 80 is open.",
        })
        assert d.response == "Yes, port 80 is open."

    def test_from_dict_empty_response(self):
        d = AgentDecision.from_dict({
            "action": "recon",
            "tool": "nmap",
            "target": "10.10.10.10",
        })
        assert d.response == ""

    def test_json_output_instruction_mentions_response(self):
        from pentest_agent.llm.parsing import JSON_OUTPUT_INSTRUCTION
        assert "response" in JSON_OUTPUT_INSTRUCTION
        assert "direct answer" in JSON_OUTPUT_INSTRUCTION


class TestConversationHistory:
    """Test the coordinator's conversation tracking methods."""

    def test_add_and_get_messages(self):
        from pentest_agent.agent.coordinator import AgentCoordinator
        c = AgentCoordinator()
        c.add_user_message("What ports are open?")
        c.add_agent_response("I found ports 22 and 80.")
        summary = c.get_conversation_summary()
        assert "What ports are open?" in summary
        assert "I found ports 22 and 80." in summary

    def test_conversation_summary_respects_max_entries(self):
        from pentest_agent.agent.coordinator import AgentCoordinator
        c = AgentCoordinator()
        for i in range(10):
            c.add_user_message(f"msg{i}")
            c.add_agent_response(f"resp{i}")
        summary = c.get_conversation_summary(max_entries=4)
        # Should only contain the last 4 messages (2 user + 2 agent)
        assert "msg0" not in summary
        assert "msg9" in summary

    def test_conversation_empty_summary(self):
        from pentest_agent.agent.coordinator import AgentCoordinator
        c = AgentCoordinator()
        summary = c.get_conversation_summary()
        assert "(no prior conversation)" not in summary
        assert summary == ""


class TestCoordinatorReset:
    """Test that /target command resets agent states properly."""

    def test_target_reset_clears_last_response(self):
        from pentest_agent.agent.coordinator import AgentCoordinator, AgentState, AgentConfig, AgentStatus
        c = AgentCoordinator()
        state = AgentState(agent_id="test", config=AgentConfig(name="test"))
        state.last_response = "Some old response"
        state.last_decision = "nmap"
        state.last_reasoning = "because"
        c._agents["test"] = state
        # Simulate /target reset logic
        for s in c._agents.values():
            s.status = AgentStatus.RUNNING
            s.last_decision = None
            s.last_reasoning = None
            s.last_response = ""
        assert state.last_response == ""
        assert state.last_decision is None
        assert state.last_reasoning is None
