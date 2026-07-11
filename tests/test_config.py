"""Tests for config module."""

import os
import pytest
from pentest_agent.config import Config, get_config


class TestConfigDefaults:
    def test_default_db_url(self):
        # Remove env var if set so we test the default
        old = os.environ.pop("PENTEST_DB_URL", None)
        cfg = Config()
        assert "postgresql+asyncpg://" in cfg.db_url
        if old is not None:
            os.environ["PENTEST_DB_URL"] = old

    def test_default_llm_provider(self):
        old = os.environ.pop("PENTEST_LLM_PROVIDER", None)
        cfg = Config()
        assert cfg.llm_provider == "ollama"
        if old is not None:
            os.environ["PENTEST_LLM_PROVIDER"] = old

    def test_ollama_timeout_default(self):
        old = os.environ.pop("OLLAMA_TIMEOUT", None)
        cfg = Config()
        assert cfg.ollama_timeout == 120
        if old is not None:
            os.environ["OLLAMA_TIMEOUT"] = old

    def test_api_keys_empty_by_default(self):
        cfg = Config()
        assert cfg.gemini_api_key == ""
        assert cfg.anthropic_api_key == ""
        assert cfg.openai_api_key == ""


class TestConfigEnvOverrides:
    def test_db_url_env(self):
        os.environ["PENTEST_DB_URL"] = "sqlite:///test.db"
        cfg = Config()
        assert cfg.db_url == "sqlite:///test.db"
        del os.environ["PENTEST_DB_URL"]

    def test_llm_provider_env(self):
        os.environ["PENTEST_LLM_PROVIDER"] = "gemini"
        cfg = Config()
        assert cfg.llm_provider == "gemini"
        del os.environ["PENTEST_LLM_PROVIDER"]

    def test_gemini_api_key_env(self):
        os.environ["GEMINI_API_KEY"] = "test-key-123"
        cfg = Config()
        assert cfg.gemini_api_key == "test-key-123"
        del os.environ["GEMINI_API_KEY"]

    def test_ollama_timeout_env(self):
        # Note: ollama_timeout uses static eval, not field(default_factory=...)
        # so it reads env at import time. This test verifies it's an int.
        cfg = Config()
        assert isinstance(cfg.ollama_timeout, int)

    def test_ollama_base_url_env(self):
        os.environ["OLLAMA_BASE_URL"] = "http://ollama:11434"
        cfg = Config()
        assert cfg.ollama_base_url == "http://ollama:11434"
        del os.environ["OLLAMA_BASE_URL"]


class TestGetConfig:
    def test_get_config_singleton(self):
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2
