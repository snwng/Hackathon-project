"""Tests for tools module: Finding, BaseTool, NmapTool, GobusterTool, run_tool."""

import pytest
from pentest_agent.tools import Finding, BaseTool, NmapTool, run_tool, TOOLS


class TestFinding:
    def test_default_construction(self):
        f = Finding(tool="nmap", host="127.0.0.1")
        assert f.tool == "nmap"
        assert f.host == "127.0.0.1"
        assert f.port is None

    def test_to_dict_basic(self):
        f = Finding(tool="nmap", host="127.0.0.1", port=80, service="http",
                     version="Apache 2.4.49")
        d = f.to_dict()
        assert d["tool"] == "nmap"
        assert d["host"] == "127.0.0.1"
        assert d["port"] == 80
        assert d["service"] == "http"

    def test_to_dict_omits_empty(self):
        f = Finding(tool="nmap", host="127.0.0.1")
        d = f.to_dict()
        assert "port" not in d

    def test_vulnerability_fields(self):
        f = Finding(tool="nuclei", host="127.0.0.1", port=443,
                     vuln_name="CVE-2021-41773: Apache Path Traversal",
                     cve_id="CVE-2021-41773", severity="critical")
        d = f.to_dict()
        assert d["cve_id"] == "CVE-2021-41773"

    def test_http_fields(self):
        f = Finding(tool="gobuster", host="127.0.0.1", port=80,
                     url="http://127.0.0.1/admin", status_code=200,
                     webserver="Apache/2.4.49",
                     technologies=["PHP", "WordPress"])
        d = f.to_dict()
        assert d["url"] == "http://127.0.0.1/admin"
        assert d["status_code"] == 200


class TestBaseTool:
    def test_to_mcp_tool_def(self):
        class TestTool(BaseTool):
            name = "test_tool"
            description = "A test tool"

            def run(self, target, **kwargs):
                return []

        tool = TestTool()
        tdef = tool.to_mcp_tool_def()
        assert tdef["name"] == "test_tool"
        assert tdef["description"] == "A test tool"
        assert "target" in tdef["inputSchema"]["properties"]


class TestNmapTool:
    def test_parse_nmap_output(self):
        nmap = NmapTool()
        fake_output = """
Nmap scan report for 127.0.0.1
Host is up (0.0010s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu
80/tcp   open  http       Apache httpd 2.4.49
443/tcp  open  https      Apache httpd 2.4.49
3306/tcp open  mysql      MySQL 8.0.32
        """
        findings = nmap._parse_nmap(fake_output, "127.0.0.1")
        assert len(findings) >= 1
        ports_found = {f.port for f in findings if f.port}
        assert 22 in ports_found
        assert 80 in ports_found
        assert 443 in ports_found
        assert 3306 in ports_found


class TestRunTool:
    def test_run_tool_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            run_tool("nonexistent_tool", "127.0.0.1")

    def test_tools_registry_has_nmap(self):
        assert "nmap" in TOOLS
        tool = TOOLS["nmap"]
        assert isinstance(tool, NmapTool)
