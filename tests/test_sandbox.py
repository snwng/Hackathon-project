"""Tests for sandbox module: DockerSandbox, DryRunSandbox, SandboxResult."""

import pytest
from pentest_agent.sandbox import (
    SandboxResult, DryRunSandbox, create_sandbox,
    SandboxProfile, NetworkMode, PROFILE_CONFIGS,
)


class TestSandboxResult:
    def test_default_construction(self):
        r = SandboxResult(success=True, exit_code=0, stdout="ok", stderr="", command="ls")
        assert r.success is True
        assert r.exit_code == 0
        assert r.stdout == "ok"
        assert r.shell_obtained is False

    def test_output_truncated_short(self):
        r = SandboxResult(success=True, exit_code=0, stdout="hello", stderr="", command="echo")
        assert r.output_truncated == "hello"

    def test_output_truncated_long(self):
        long_out = "x" * 3000
        r = SandboxResult(success=True, exit_code=0, stdout=long_out, stderr="", command="cat")
        truncated = r.output_truncated
        assert len(truncated) < 3000
        assert "more bytes" in truncated

    def test_to_dict(self):
        r = SandboxResult(success=True, exit_code=0, stdout="ok", stderr="", command="ls",
                           network_mode="nat", duration=1.5, shell_obtained=True)
        d = r.to_dict()
        assert d["success"] is True
        assert d["shell_obtained"] is True


class TestDryRunSandbox:
    def test_run_returns_result(self):
        sandbox = DryRunSandbox()
        result = sandbox.run("echo hello")
        assert isinstance(result, SandboxResult)
        assert result.command == "echo hello"
        assert result.success is True

    def test_run_with_profile(self):
        sandbox = DryRunSandbox()
        result = sandbox.run("nmap -sV 127.0.0.1")
        # DryRunSandbox uses network_mode="local"
        assert isinstance(result.network_mode, str)


class TestSandboxProfiles:
    def test_network_mode_enum(self):
        assert NetworkMode.NONE.value == "none"
        assert NetworkMode.NAT.value == "nat"
        assert NetworkMode.HOST.value == "host"
        assert NetworkMode.CUSTOM.value == "custom"

    def test_sandbox_profile_enum(self):
        assert SandboxProfile.SAFE.value == "safe"
        assert SandboxProfile.PENTEST.value == "pentest"
        assert SandboxProfile.AGGRESSIVE.value == "aggressive"
        assert SandboxProfile.STEALTH.value == "stealth"

    def test_profile_configs_have_required_keys(self):
        for profile in SandboxProfile:
            config = PROFILE_CONFIGS[profile]
            assert "network" in config
            assert "memory_limit" in config

    def test_safe_profile_no_network(self):
        config = PROFILE_CONFIGS[SandboxProfile.SAFE]
        assert config["network"] == NetworkMode.NONE
        assert config["read_only"] is True


class TestCreateSandbox:
    def test_create_dry_run(self):
        sandbox = create_sandbox(use_docker=False)
        assert isinstance(sandbox, DryRunSandbox)
