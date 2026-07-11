"""Tests for LLM factory module and client providers."""

import pytest
from pentest_agent.llm.factory import create_llm, check_ollama, _SyncOllamaClient
from pentest_agent.llm.base import LLMClient, LLMResponse, LLMFactory


class TestSyncOllamaClient:
    def test_init(self):
        client = _SyncOllamaClient(model="test-model")
        assert client.model_name == "test-model"

    def test_init_default_model(self):
        client = _SyncOllamaClient()
        assert isinstance(client.model_name, str)
        assert client.model_name != ""


class TestCreateLLM:
    def test_returns_none_when_prefer_local_false(self):
        result = create_llm(prefer_local=False)
        assert result is None

    def test_returns_callable_when_model_specified(self):
        result = create_llm(model="test-model", prefer_local=True)
        # May return None if Ollama is unavailable — that's OK
        if result is not None:
            assert callable(result)


class TestCheckOllama:
    def test_returns_dict(self):
        result = check_ollama()
        assert isinstance(result, dict)
        assert "available" in result


class TestLLMFactory:
    def test_provider_from_model_gemini(self):
        assert LLMFactory._provider_from_model("gemini-3.5-flash") == "gemini"

    def test_provider_from_model_gpt(self):
        assert LLMFactory._provider_from_model("gpt-4") == "openai"

    def test_provider_from_model_claude(self):
        assert LLMFactory._provider_from_model("claude-3-opus") == "anthropic"

    def test_provider_from_model_o1(self):
        assert LLMFactory._provider_from_model("o1-preview") == "openai"

    def test_provider_from_model_unknown(self):
        assert LLMFactory._provider_from_model("llama-3") == ""

    def test_create_returns_client(self):
        client = LLMFactory.create(provider="deterministic")
        assert client is not None
        assert client.provider == "deterministic"


class TestLLMClientABC:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            LLMClient()

    def test_llm_response_dataclass(self):
        r = LLMResponse(text="hello", model="test", provider="test")
        assert r.text == "hello"
        assert r.model == "test"
        assert r.provider == "test"


class TestDeterministicClient:
    def test_import(self):
        from pentest_agent.llm.deterministic import DeterministicClient
        assert DeterministicClient is not None


class TestOpenAIClient:
    def test_import(self):
        from pentest_agent.llm.openai import OpenAIClient
        assert OpenAIClient is not None


class TestAnthropicClient:
    def test_import(self):
        from pentest_agent.llm.anthropic import AnthropicClient
        assert AnthropicClient is not None
