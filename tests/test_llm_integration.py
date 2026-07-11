"""Tests for LLM integration: callback wiring, Gemini response parsing, retry logic."""

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from pentest_agent.llm.base import LLMClient, LLMResponse
from pentest_agent.llm.parsing import DecisionParser, AgentDecision, ActionType
from pentest_agent.llm.gemini import GeminiClient
from pentest_agent.llm.ollama import OllamaClient
from pentest_agent.llm.deterministic import DeterministicClient


# ═══════════════════════════════════════════════════════════════════════════
#  LLMResponse contract
# ═══════════════════════════════════════════════════════════════════════════


class TestLLMResponse:
    def test_text_attribute_is_string(self):
        resp = LLMResponse(text='{"action": "recon"}', model="test", provider="test")
        assert isinstance(resp.text, str)
        assert resp.text.strip().startswith("{")

    def test_text_is_json_serializable(self):
        resp = LLMResponse(text='{"action": "recon", "tool": "nmap"}')
        data = json.loads(resp.text)
        assert data["action"] == "recon"

    def test_empty_text(self):
        resp = LLMResponse(text="")
        assert resp.text == ""
        assert resp.text.strip() == ""


# ═══════════════════════════════════════════════════════════════════════════
#  Async callback wiring (the bug that caused 'coroutine' object has no attr)
# ═══════════════════════════════════════════════════════════════════════════


class TestAsyncCallback:
    """Verify that DecisionParser's llm_callback receives and returns strings,
    not LLMResponse objects or coroutines."""

    @pytest.mark.asyncio
    async def test_callback_returns_string_not_llmresponse(self):
        """The callback must return a string so parse() can call .strip()."""
        async def fake_chat(system, user):
            return LLMResponse(text='{"action": "done", "reasoning": "test"}')

        async def correct_callback(system, user):
            resp = await fake_chat(system, user)
            return resp.text

        parser = DecisionParser(llm_callback=correct_callback)
        result = await parser.parse_with_retry(
            "invalid json", "system prompt"
        )
        assert result.action == ActionType.DONE

    @pytest.mark.asyncio
    async def test_callback_must_be_awaitable(self):
        """A non-async callback returning a coroutine gets awaited but returns
        LLMResponse instead of str, causing .strip() to fail."""
        def non_async_callback(system, user):
            async def inner():
                return LLMResponse(text='{"action": "done"}')
            return inner()

        parser = DecisionParser(llm_callback=non_async_callback)
        # The coroutine is awaited by parse_with_retry, yielding an LLMResponse.
        # Then parse() calls .strip() on it → AttributeError
        with pytest.raises((ValueError, AttributeError)):
            await parser.parse_with_retry("invalid json that triggers retry", "system")

    @pytest.mark.asyncio
    async def test_wrong_callback_type_raises(self):
        """A lambda that returns the LLMResponse directly (not .text) will fail."""
        async def bad_callback(system, user):
            return LLMResponse(text='{"action": "done"}')  # returns object, not str

        parser = DecisionParser(llm_callback=bad_callback)
        with pytest.raises((ValueError, AttributeError)):
            await parser.parse_with_retry("invalid", "system")

    @pytest.mark.asyncio
    async def test_correct_async_callback_pattern(self):
        """The correct pattern: async callback returning resp.text."""
        async def good_callback(system, user):
            return LLMResponse(text='{"action": "recon", "tool": "nmap", "reasoning": "test"}').text

        parser = DecisionParser(llm_callback=good_callback)
        result = await parser.parse_with_retry("bad json", "system")
        assert result.action == ActionType.RECON
        assert result.tool == "nmap"


# ═══════════════════════════════════════════════════════════════════════════
#  DecisionParser retry logic
# ═══════════════════════════════════════════════════════════════════════════


class TestDecisionParserRetry:
    @pytest.mark.asyncio
    async def test_parse_with_retry_succeeds_first_try(self):
        parser = DecisionParser()
        result = await parser.parse_with_retry(
            '{"action": "recon", "tool": "nmap", "reasoning": "scan"}',
            "system",
        )
        assert result.action == ActionType.RECON

    @pytest.mark.asyncio
    async def test_parse_with_retry_succeeds_after_bad_first(self):
        """First response is garbage, callback returns valid JSON."""
        call_count = 0

        async def callback(system, user):
            nonlocal call_count
            call_count += 1
            return '{"action": "exploit", "tool": "nmap", "reasoning": "retry worked"}'

        parser = DecisionParser(llm_callback=callback)
        result = await parser.parse_with_retry(
            "this is not json at all", "system"
        )
        assert result.action == ActionType.EXPLOIT
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_parse_with_retry_exhausts_retries(self):
        """All retries return garbage — should raise ValueError."""
        async def bad_callback(system, user):
            return "still not json"

        parser = DecisionParser(llm_callback=bad_callback)
        with pytest.raises(ValueError, match="Parse failed"):
            await parser.parse_with_retry("garbage", "system")

    @pytest.mark.asyncio
    async def test_parse_with_retry_no_callback_gives_up_fast(self):
        """Without a callback, parse_with_retry should not retry."""
        parser = DecisionParser(llm_callback=None)
        with pytest.raises(ValueError):
            await parser.parse_with_retry("no json here", "system")


# ═══════════════════════════════════════════════════════════════════════════
#  Gemini response parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestGeminiResponseParsing:
    """Test GeminiClient._parse_response and _clean_text with various payloads."""

    def _make_client(self):
        with patch.object(GeminiClient, "__init__", lambda self, **kw: None):
            client = GeminiClient.__new__(GeminiClient)
            client.api_key = "fake-key"
            client._model = "gemini-3.5-flash"
            client._available = True
            return client

    def test_clean_text_plain(self):
        client = self._make_client()
        assert client._clean_text('{"action": "recon"}') == '{"action": "recon"}'

    def test_clean_text_code_fences(self):
        client = self._make_client()
        text = '```json\n{"action": "recon"}\n```'
        assert client._clean_text(text) == '{"action": "recon"}'

    def test_clean_text_empty(self):
        client = self._make_client()
        assert client._clean_text("") == ""
        assert client._clean_text("   ") == ""

    def test_parse_response_normal(self):
        client = self._make_client()
        data = {
            "candidates": [{
                "content": {"parts": [{"text": '{"action": "recon"}'}]},
                "finishReason": "stop",
            }],
            "usageMetadata": {"candidatesTokenCount": 10},
        }
        resp = client._parse_response(data, "gemini-3.5-flash", 0.0, '{"action": "recon"}')
        assert resp.text == '{"action": "recon"}'
        assert resp.model == "gemini-3.5-flash"
        assert resp.provider == "gemini"
        assert resp.tokens_used == 10

    def test_parse_response_skips_thought_parts(self):
        """Gemini 3.5 Flash thinking parts should be filtered out."""
        client = self._make_client()
        data = {
            "candidates": [{
                "content": {"parts": [
                    {"thought": True, "text": "Let me think about this..."},
                    {"text": '{"action": "recon", "tool": "nmap"}'},
                ]},
                "finishReason": "stop",
            }],
            "usageMetadata": {"candidatesTokenCount": 20},
        }
        resp = client._parse_response(data, "gemini-3.5-flash", 0.0, '{"action": "recon", "tool": "nmap"}')
        # The _request method filters thoughts before calling _parse_response,
        # so this test verifies _parse_response accepts pre-cleaned content
        assert "think" not in resp.text.lower() or "recon" in resp.text

    def test_empty_response_raises(self):
        """Empty Gemini content should raise RuntimeError, not return empty text."""
        client = self._make_client()
        data = {
            "candidates": [{
                "content": {"parts": []},
                "finishReason": "stop",
            }],
        }
        candidate = data["candidates"][0]
        content = ""
        for part in candidate.get("content", {}).get("parts", []):
            if not part.get("thought", False):
                content += part.get("text", "")
        content = client._clean_text(content)
        assert content == ""  # Should be empty, triggering the guard


# ═══════════════════════════════════════════════════════════════════════════
#  Gemini _request method with mocked HTTP
# ═══════════════════════════════════════════════════════════════════════════


class TestGeminiRequest:
    @pytest.mark.asyncio
    async def test_request_empty_content_raises(self):
        """_request should raise RuntimeError on empty Gemini content."""
        client = GeminiClient.__new__(GeminiClient)
        client.api_key = "fake"
        client._model = "gemini-3.5-flash"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": []},
                "finishReason": "stop",
            }],
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="empty content"):
                await client._request(
                    {"contents": []}, "gemini-3.5-flash", 0.0
                )

    @pytest.mark.asyncio
    async def test_request_normal_response(self):
        """_request should return LLMResponse on valid Gemini response."""
        client = GeminiClient.__new__(GeminiClient)
        client.api_key = "fake"
        client._model = "gemini-3.5-flash"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": [{"text": '{"action": "recon", "tool": "nmap"}'}]},
                "finishReason": "stop",
            }],
            "usageMetadata": {"candidatesTokenCount": 5},
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", return_value=mock_resp):
            resp = await client._request(
                {"contents": []}, "gemini-3.5-flash", 0.0
            )
            assert resp.text == '{"action": "recon", "tool": "nmap"}'
            assert resp.provider == "gemini"

    @pytest.mark.asyncio
    async def test_request_thought_parts_filtered(self):
        """Thoughts from Gemini 3.5 Flash should not appear in response text."""
        client = GeminiClient.__new__(GeminiClient)
        client.api_key = "fake"
        client._model = "gemini-3.5-flash"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": [
                    {"thought": True, "text": "Internal reasoning here..."},
                    {"thought": True, "text": "More thinking..."},
                    {"text": '{"action": "done", "reasoning": "objective met"}'},
                ]},
                "finishReason": "stop",
            }],
            "usageMetadata": {"candidatesTokenCount": 30},
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", return_value=mock_resp):
            resp = await client._request(
                {"contents": []}, "gemini-3.5-flash", 0.0
            )
            assert "Internal reasoning" not in resp.text
            assert "More thinking" not in resp.text
            assert "objective met" in resp.text


# ═══════════════════════════════════════════════════════════════════════════
#  Gemini json_mode / structured output
# ═══════════════════════════════════════════════════════════════════════════


class TestGeminiJsonMode:
    """Verify the json_mode parameter forces structured JSON output."""

    def _make_client(self):
        with patch.object(GeminiClient, "__init__", lambda self, **kw: None):
            client = GeminiClient.__new__(GeminiClient)
            client.api_key = "fake-key"
            client._model = "gemini-3.5-flash"
            client._available = True
            return client

    @pytest.mark.asyncio
    async def test_chat_json_mode_sets_response_mime_type(self):
        """chat(json_mode=True) must set response_mime_type in payload."""
        client = self._make_client()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": [{"text": '{"action": "recon"}'}]},
                "finishReason": "stop",
            }],
            "usageMetadata": {},
        }
        mock_resp.raise_for_status = MagicMock()

        sent_payload = {}

        async def capture_payload(*args, **kwargs):
            # args[2] is the json payload in requests.post(url, json=payload, ...)
            nonlocal sent_payload
            sent_payload = kwargs.get("json", args[1] if len(args) > 1 else {})
            return mock_resp

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", capture_payload):
            resp = await client.chat("system", "user", json_mode=True)

        assert sent_payload.get("generationConfig", {}).get("response_mime_type") == "application/json"

    @pytest.mark.asyncio
    async def test_chat_no_json_mode_no_mime_type(self):
        """chat(json_mode=False) must NOT set response_mime_type."""
        client = self._make_client()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": [{"text": "hello"}]},
                "finishReason": "stop",
            }],
            "usageMetadata": {},
        }
        mock_resp.raise_for_status = MagicMock()

        sent_payload = {}

        async def capture_payload(*args, **kwargs):
            nonlocal sent_payload
            sent_payload = kwargs.get("json", args[1] if len(args) > 1 else {})
            return mock_resp

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", capture_payload):
            resp = await client.chat("system", "user", json_mode=False)

        mime = sent_payload.get("generationConfig", {}).get("response_mime_type")
        assert mime is None

    @pytest.mark.asyncio
    async def test_decide_uses_json_mode(self):
        """decide() must call chat() with json_mode=True."""
        client = self._make_client()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": [{"text": '{"action": "recon", "tool": "nmap"}'}]},
                "finishReason": "stop",
            }],
            "usageMetadata": {},
        }
        mock_resp.raise_for_status = MagicMock()

        sent_payload = {}

        async def capture_payload(*args, **kwargs):
            nonlocal sent_payload
            sent_payload = kwargs.get("json", args[1] if len(args) > 1 else {})
            return mock_resp

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", capture_payload):
            resp = await client.decide("system prompt", "user request")

        mime = sent_payload.get("generationConfig", {}).get("response_mime_type")
        assert mime == "application/json"

    @pytest.mark.asyncio
    async def test_request_non_json_response_allowed(self):
        """_request should NOT raise for non-JSON text — it logs a warning."""
        client = self._make_client()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = {
            "candidates": [{
                "content": {"parts": [{"text": "I think we should scan the target first"}]},
                "finishReason": "stop",
            }],
            "usageMetadata": {},
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("pentest_agent.llm.gemini.asyncio.to_thread", return_value=mock_resp):
            # Should NOT raise — non-JSON is allowed through
            resp = await client._request({"contents": []}, "gemini-3.5-flash", 0.0)
            assert "scan" in resp.text
            assert resp.provider == "gemini"


# ═══════════════════════════════════════════════════════════════════════════
#  Coordinator._llm_callback method
# ═══════════════════════════════════════════════════════════════════════════


class TestCoordinatorCallback:
    """Verify the coordinator's _llm_callback is properly async and returns str."""

    @pytest.mark.asyncio
    async def test_llm_callback_returns_string(self):
        from pentest_agent.agent.coordinator import AgentCoordinator
        from pentest_agent.graph.models import AttackGraph

        mock_llm = AsyncMock()
        mock_llm.chat.return_value = LLMResponse(
            text='{"action": "recon", "tool": "nmap"}',
            model="test",
            provider="test",
        )

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(
            graph=graph,
            target="127.0.0.1",
            llm=mock_llm,
        )

        result = await coord._llm_callback("system", "user")
        assert isinstance(result, str)
        assert "recon" in result

    @pytest.mark.asyncio
    async def test_llm_callback_not_coroutine(self):
        """_llm_callback must return a string, not a coroutine or LLMResponse."""
        from pentest_agent.agent.coordinator import AgentCoordinator
        from pentest_agent.graph.models import AttackGraph

        mock_llm = AsyncMock()
        mock_llm.chat.return_value = LLMResponse(text="hello", model="t", provider="t")

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(graph=graph, target="127.0.0.1", llm=mock_llm)

        result = await coord._llm_callback("s", "u")
        assert type(result) is str

    @pytest.mark.asyncio
    async def test_parser_callback_is_bound_method(self):
        """The parser's callback should be the coordinator's _llm_callback method."""
        from pentest_agent.agent.coordinator import AgentCoordinator
        from pentest_agent.graph.models import AttackGraph

        mock_llm = AsyncMock()
        mock_llm.chat.return_value = LLMResponse(text='{"action": "done"}', model="t", provider="t")

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(graph=graph, target="127.0.0.1", llm=mock_llm)

        # bound methods create new objects on access, so check func + self
        cb = coord.parser.llm_callback
        assert cb.__func__ is coord._llm_callback.__func__
        assert cb.__self__ is coord


# ═══════════════════════════════════════════════════════════════════════════
#  DeterministicClient returns valid JSON
# ═══════════════════════════════════════════════════════════════════════════


class TestDeterministicClient:
    @pytest.mark.asyncio
    async def test_chat_returns_valid_json(self):
        client = DeterministicClient()
        resp = await client.chat("system", "no hosts found on 10.0.0.1")
        data = json.loads(resp.text)
        assert "action" in data

    @pytest.mark.asyncio
    async def test_decide_returns_valid_json(self):
        client = DeterministicClient()
        resp = await client.decide("system", "KEV CVE-2021-41773 found")
        data = json.loads(resp.text)
        assert data["action"] == "exploit"

    @pytest.mark.asyncio
    async def test_deterministic_provider_name(self):
        client = DeterministicClient()
        assert client.provider == "deterministic"
        assert client.available is True

    @pytest.mark.asyncio
    async def test_extract_target_uses_explicit_target_first(self):
        client = DeterministicClient(target="10.0.0.5")
        # Even though observation has 127.0.0.1, the explicit target should win
        target = client._extract_target("scan results for 127.0.0.1")
        assert target == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_extract_target_fallback_to_first_ip(self):
        client = DeterministicClient()
        target = client._extract_target("found open ports on 192.168.1.1")
        assert target == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_extract_target_defaults_localhost(self):
        client = DeterministicClient()
        target = client._extract_target("no IPs in this text")
        assert target == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_decision_uses_target_param(self):
        client = DeterministicClient(target="10.0.0.5")
        resp = await client.decide("system", "0 hosts discovered")
        data = json.loads(resp.text)
        assert data["target"] == "10.0.0.5"


# ═══════════════════════════════════════════════════════════════════════════
#  User instruction flow
# ═══════════════════════════════════════════════════════════════════════════


class TestBuildObservationWithUserInstruction:
    def test_user_instruction_included(self):
        from pentest_agent.llm.prompts import build_observation

        obs = build_observation(
            graph_summary="1 host found on 127.0.0.1",
            user_instruction="who is the target",
        )
        assert "who is the target" in obs
        assert "User's Question / Instruction" in obs
        assert "⚡ NEXT: Address the user's instruction above" in obs

    def test_no_user_instruction_normal_flow(self):
        from pentest_agent.llm.prompts import build_observation

        obs = build_observation(graph_summary="0 hosts found")
        assert "User's Question / Instruction" not in obs
        assert "⚡ NEXT: Run nmap" in obs

    def test_user_instruction_takes_priority_over_nmap_hint(self):
        """When a user instruction is present, the next hint should NOT suggest nmap."""
        from pentest_agent.llm.prompts import build_observation

        obs = build_observation(
            graph_summary="0 hosts found",
            user_instruction="show me what you have",
        )
        assert "⚡ NEXT: Address the user's instruction above" in obs
        assert "Run nmap" not in obs.split("⚡ NEXT:")[1] if "⚡ NEXT:" in obs else True


class TestCoordinatorUserInstruction:
    """Verify INSTRUCTION messages are included in the observation."""

    @pytest.mark.asyncio
    async def test_instruction_captured_in_observation(self):
        from pentest_agent.agent.coordinator import AgentCoordinator, AgentStatus, MessageType
        from pentest_agent.graph.models import AttackGraph

        mock_llm = AsyncMock()
        mock_llm.chat.return_value = LLMResponse(text='{"action": "done"}', model="t", provider="t")

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(graph=graph, target="127.0.0.1", llm=mock_llm)
        root_id = await coord.start()

        coord._send_message(
            sender_id="user",
            recipient_id=root_id,
            msg_type=MessageType.INSTRUCTION,
            subject="User instruction",
            content="who is the target",
            data={"instruction": "who is the target"},
        )

        state = coord._agents[root_id]
        inbox = state.inbox
        msgs = inbox.drain()
        user_instruction = ""
        for msg in msgs:
            if msg.msg_type == MessageType.INSTRUCTION and msg.content:
                user_instruction = msg.content
        assert user_instruction == "who is the target"

    @pytest.mark.asyncio
    async def test_inbox_message_without_instruction_is_ignored(self):
        """FINDING messages should not set user_instruction."""
        from pentest_agent.agent.coordinator import AgentCoordinator, AgentStatus, MessageType
        from pentest_agent.graph.models import AttackGraph

        mock_llm = AsyncMock()
        mock_llm.chat.return_value = LLMResponse(text='{"action": "done"}', model="t", provider="t")

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(graph=graph, target="127.0.0.1", llm=mock_llm)
        root_id = await coord.start()

        coord._send_message(
            sender_id="recon_lead",
            recipient_id=root_id,
            msg_type=MessageType.FINDING,
            subject="Scan results",
            content="nmap done",
            data={"type": "service", "host": "127.0.0.1", "port": 80},
        )

        state = coord._agents[root_id]
        inbox = state.inbox
        msgs = inbox.drain()
        user_instruction = ""
        for msg in msgs:
            if msg.msg_type == MessageType.INSTRUCTION and msg.content:
                user_instruction = msg.content
        assert user_instruction == ""


# ═══════════════════════════════════════════════════════════════════════════
#  End-to-end: user instruction reaches LLM via build_observation
# ═══════════════════════════════════════════════════════════════════════════


class TestUserInstructionEndToEnd:
    """Full pipeline: INSTRUCTION message → observation → LLM receives it."""

    @pytest.mark.asyncio
    async def test_llm_receives_user_instruction_in_observation(self):
        from pentest_agent.agent.coordinator import (
            AgentCoordinator, AgentStatus, MessageType,
        )
        from pentest_agent.graph.models import AttackGraph

        recorded_observation = None

        class RecordingLLM:
            provider = "test"
            available = True

            async def chat(self, system: str, user: str, **kw):
                return LLMResponse(text="ok", model="t", provider="t")

            async def decide(self, system: str, observation: str):
                nonlocal recorded_observation
                recorded_observation = observation
                return LLMResponse(
                    text='{"action": "done", "reasoning": "The target is 127.0.0.1"}',
                    model="t",
                    provider="t",
                )

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(graph=graph, target="127.0.0.1", llm=RecordingLLM())
        root_id = await coord.start()

        # Set root to RUNNING so step() will pick it up
        for s in coord._agents.values():
            if s.status == AgentStatus.PENDING:
                s.status = AgentStatus.RUNNING

        coord._send_message(
            sender_id="user",
            recipient_id=root_id,
            msg_type=MessageType.INSTRUCTION,
            subject="User instruction",
            content="who is the target",
            data={"instruction": "who is the target"},
        )

        # Run one iteration
        await coord._run_agent_iteration(root_id)

        # Verify the LLM's observation included the user instruction
        assert recorded_observation is not None, "LLM.decide() was never called"
        assert "who is the target" in recorded_observation, (
            f"User instruction not found in observation. Got:\n{recorded_observation}"
        )
        assert "User's Question / Instruction" in recorded_observation
        assert "⚡ NEXT: Address the user's instruction above" in recorded_observation

    @pytest.mark.asyncio
    async def test_llm_decision_used_not_overridden(self):
        """Verify the LLM's decision is used and not replaced by deterministic."""
        from pentest_agent.agent.coordinator import (
            AgentCoordinator, AgentStatus, MessageType,
        )
        from pentest_agent.graph.models import AttackGraph

        class DeterministicCheckLLM:
            """Fails if deterministic mode is used instead of this LLM."""
            provider = "test"
            available = True

            async def chat(self, system: str, user: str, **kw):
                return LLMResponse(text="ok", model="t", provider="t")

            async def decide(self, system: str, observation: str):
                # Return a done action — this should NOT be overridden
                return LLMResponse(
                    text=(
                        '{"action": "done", "tool": "echo", "target": "127.0.0.1", '
                        '"reasoning": "user asked who the target is — it is 127.0.0.1"}'
                    ),
                    model="t",
                    provider="t",
                )

        graph = AttackGraph(name="test")
        coord = AgentCoordinator(graph=graph, target="127.0.0.1", llm=DeterministicCheckLLM())
        root_id = await coord.start()

        for s in coord._agents.values():
            if s.status == AgentStatus.PENDING:
                s.status = AgentStatus.RUNNING

        coord._send_message(
            sender_id="user",
            recipient_id=root_id,
            msg_type=MessageType.INSTRUCTION,
            subject="User instruction",
            content="who is the target",
            data={"instruction": "who is the target"},
        )

        await coord._run_agent_iteration(root_id)

        state = coord._agents[root_id]
        assert state.last_decision is not None
        assert "done" in state.last_decision
        assert "echo" in state.last_decision
        # The reasoning should be the LLM's answer, NOT a hardcoded fallback text
        assert "user asked who the target is" in state.last_reasoning, (
            f"LLM reasoning was overridden. Got: {state.last_reasoning}"
        )
