"""Tests for skills module: Skill, ToolBinding, SkillsRegistry."""

import pytest
from pentest_agent.skills import (
    Skill, ToolBinding, SkillDomain, SkillLevel,
    SkillsRegistry, get_skills_registry,
)


class TestSkillDomain:
    def test_enum_values(self):
        assert SkillDomain.RECONNAISSANCE.value == "reconnaissance"
        assert SkillDomain.EXPLOITATION.value == "exploitation"
        assert SkillDomain.REPORTING.value == "reporting"


class TestSkillLevel:
    def test_enum_values(self):
        assert SkillLevel.PASSIVE.value == "passive"
        assert SkillLevel.ACTIVE.value == "active"
        assert SkillLevel.AGGRESSIVE.value == "aggressive"
        assert SkillLevel.STEALTH.value == "stealth"


class TestToolBinding:
    def test_defaults(self):
        tb = ToolBinding(name="nmap", description="Port scanner")
        assert tb.name == "nmap"
        assert tb.required is True
        assert tb.sandbox_required is False
        assert tb.default_args == {}

    def test_custom_args(self):
        tb = ToolBinding(name="nmap", description="Quick scan",
                          default_args={"fast": True, "ports": "top-1000"},
                          sandbox_required=True)
        assert tb.default_args["fast"] is True
        assert tb.sandbox_required is True


class TestSkill:
    def test_minimal_skill(self):
        s = Skill(
            name="port_scan",
            display_name="Port Scanner",
            domain=SkillDomain.RECONNAISSANCE,
            level=SkillLevel.ACTIVE,
            description="Scan for open ports",
            tools=[ToolBinding(name="nmap", description="Port scanner")],
        )
        assert s.name == "port_scan"
        assert len(s.tools) == 1
        assert s.level == SkillLevel.ACTIVE

    def test_skill_with_prompt_fragment(self):
        s = Skill(
            name="web_recon",
            display_name="Web Recon",
            domain=SkillDomain.RECONNAISSANCE,
            level=SkillLevel.ACTIVE,
            description="Web application recon",
            tools=[],
            system_prompt_fragment="Scan web apps thoroughly",
        )
        assert s.system_prompt_fragment == "Scan web apps thoroughly"

    def test_skill_with_dependencies(self):
        s = Skill(
            name="full_recon",
            display_name="Full Recon",
            domain=SkillDomain.RECONNAISSANCE,
            level=SkillLevel.ACTIVE,
            description="Full recon suite",
            tools=[],
            requires=["port_scan", "web_recon"],
        )
        assert s.requires == ["port_scan", "web_recon"]

    def test_to_dict(self):
        s = Skill(
            name="test_skill",
            display_name="Test Skill",
            domain=SkillDomain.GENERAL,
            level=SkillLevel.PASSIVE,
            description="A test",
            tools=[ToolBinding(name="echo", description="Echo")],
        )
        d = s.to_dict()
        assert d["name"] == "test_skill"
        assert d["domain"] == "general"

    def test_validate_valid(self):
        s = Skill(name="valid_skill", display_name="Valid",
                   domain=SkillDomain.GENERAL, level=SkillLevel.PASSIVE,
                   description="OK",
                   tools=[ToolBinding(name="echo", description="Echo")])
        assert s.validate() == []

    def test_validate_missing_name(self):
        s = Skill(name="", display_name="Bad",
                   domain=SkillDomain.GENERAL, level=SkillLevel.PASSIVE,
                   description="No name")
        issues = s.validate()
        assert len(issues) > 0


class TestSkillsRegistry:
    def test_get_skill_exists(self):
        registry = get_skills_registry()
        skill = registry.get("network_scan")
        assert skill is not None
        assert skill.name == "network_scan"
        assert skill.domain == SkillDomain.RECONNAISSANCE

    def test_get_skill_not_found(self):
        registry = SkillsRegistry()
        skill = registry.get("nonexistent")
        assert skill is None

    def test_list_all(self):
        registry = get_skills_registry()
        skills = registry.list_all()
        assert len(skills) > 0
        names = [s.name for s in skills]
        assert "network_scan" in names
        assert "web_recon" in names

    def test_list_by_domain(self):
        registry = get_skills_registry()
        recon = registry.list_by_domain(SkillDomain.RECONNAISSANCE)
        assert len(recon) > 0
        assert all(s.domain == SkillDomain.RECONNAISSANCE for s in recon)

    def test_singleton(self):
        r1 = get_skills_registry()
        r2 = get_skills_registry()
        assert r1 is r2

    def test_register_custom_skill(self):
        registry = SkillsRegistry()
        skill = Skill(
            name="custom_test",
            display_name="Custom Test",
            domain=SkillDomain.GENERAL,
            level=SkillLevel.PASSIVE,
            description="Test skill",
            tools=[],
        )
        issues = registry.register(skill)
        assert registry.get("custom_test") is skill

    def test_unregister_skill(self):
        registry = SkillsRegistry()
        skill = Skill(name="temp", display_name="Temp",
                       domain=SkillDomain.GENERAL, level=SkillLevel.PASSIVE,
                       description="Temporary")
        registry.register(skill)
        assert registry.get("temp") is skill
        assert registry.unregister("temp") is True
        assert registry.get("temp") is None

    def test_resolve_skills(self):
        registry = get_skills_registry()
        loaded, issues = registry.resolve(["network_scan"])
        assert len(loaded) > 0
        assert loaded[0].name == "network_scan"
