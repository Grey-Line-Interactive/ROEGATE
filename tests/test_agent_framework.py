"""Tests for the multi-vendor agent framework."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from src.agents.base import AgentConfig, AgentProvider, ToolRouter


class TestAgentConfig(unittest.TestCase):
    """Tests for AgentConfig dataclass."""

    def test_creation_with_defaults(self):
        """AgentConfig should have sensible defaults for optional fields."""
        config = AgentConfig(provider="anthropic", model="claude-sonnet-4-6")
        self.assertEqual(config.provider, "anthropic")
        self.assertEqual(config.model, "claude-sonnet-4-6")
        self.assertEqual(config.api_key_env, "")
        self.assertEqual(config.base_url, "")
        self.assertEqual(config.max_turns, 50)
        self.assertEqual(config.temperature, 0.1)
        self.assertEqual(config.system_prompt, "")
        self.assertEqual(config.extra, {})

    def test_creation_with_all_fields(self):
        """AgentConfig should accept all fields."""
        config = AgentConfig(
            provider="openai",
            model="gpt-4o",
            api_key_env="MY_KEY",
            base_url="https://custom.endpoint.com/v1",
            max_turns=100,
            temperature=0.5,
            system_prompt="Custom prompt",
            extra={"stream": True},
        )
        self.assertEqual(config.provider, "openai")
        self.assertEqual(config.model, "gpt-4o")
        self.assertEqual(config.api_key_env, "MY_KEY")
        self.assertEqual(config.base_url, "https://custom.endpoint.com/v1")
        self.assertEqual(config.max_turns, 100)
        self.assertEqual(config.temperature, 0.5)
        self.assertEqual(config.system_prompt, "Custom prompt")
        self.assertEqual(config.extra, {"stream": True})


class TestToolRouter(unittest.TestCase):
    """Tests for ToolRouter intent building and command building."""

    def setUp(self):
        """Create a ToolRouter with a mocked GateServiceClient."""
        with patch("src.service.gate_client.GateServiceClient"):
            self.router = ToolRouter(
                gate_url="http://127.0.0.1:19990",
                session_id="test-session-123",
                engagement_id="ACME-2024-001",
            )

    def test_build_intent_nmap_scan(self):
        """_build_intent should create valid intent for roe_nmap_scan."""
        intent = self.router._build_intent("roe_nmap_scan", {
            "target": "10.0.0.1",
            "ports": "1-1000",
            "scan_type": "tcp_connect",
            "justification": "Initial recon",
        })
        self.assertEqual(intent["action"]["tool"], "nmap_scan")
        self.assertEqual(intent["action"]["category"], "reconnaissance")
        self.assertEqual(intent["target"]["host"], "10.0.0.1")
        self.assertEqual(intent["agent_session"], "test-session-123")
        self.assertEqual(intent["engagement_id"], "ACME-2024-001")
        self.assertEqual(intent["agent_justification"], "Initial recon")
        # justification should NOT be in parameters
        self.assertNotIn("justification", intent["parameters"])
        # But ports should be
        self.assertIn("ports", intent["parameters"])

    def test_build_intent_http_request(self):
        """_build_intent should create valid intent for roe_http_request."""
        intent = self.router._build_intent("roe_http_request", {
            "url": "https://app.acme.com/login",
            "method": "POST",
            "data": "user=admin&pass=test",
            "justification": "Testing login form",
        })
        self.assertEqual(intent["action"]["tool"], "http_request")
        self.assertEqual(intent["action"]["category"], "web_application_testing")
        self.assertEqual(intent["target"]["host"], "app.acme.com")
        self.assertEqual(intent["agent_justification"], "Testing login form")

    def test_build_intent_extracts_host_from_url(self):
        """_build_intent should extract hostname from url parameter."""
        intent = self.router._build_intent("roe_directory_scan", {
            "url": "http://192.168.1.100:8080/api",
            "wordlist": "common",
        })
        self.assertEqual(intent["target"]["host"], "192.168.1.100")

    def test_build_intent_dns_lookup(self):
        """_build_intent should use domain for dns_lookup target."""
        intent = self.router._build_intent("roe_dns_lookup", {
            "domain": "acme.com",
            "record_type": "MX",
        })
        self.assertEqual(intent["target"]["host"], "acme.com")
        self.assertEqual(intent["action"]["category"], "reconnaissance")

    def test_build_intent_service_probe(self):
        """_build_intent should set host and port for service_probe."""
        intent = self.router._build_intent("roe_service_probe", {
            "host": "10.0.0.5",
            "port": 443,
        })
        self.assertEqual(intent["target"]["host"], "10.0.0.5")
        self.assertEqual(intent["target"]["port"], 443)

    def test_build_command_nmap(self):
        """_build_command should create correct nmap command."""
        cmd, args = self.router._build_command("roe_nmap_scan", {
            "target": "10.0.0.1",
            "ports": "80,443",
            "scan_type": "syn",
        })
        self.assertEqual(cmd, "nmap")
        self.assertIn("-sS", args)
        self.assertIn("-p", args)
        self.assertIn("80,443", args)
        self.assertIn("10.0.0.1", args)

    def test_build_command_curl(self):
        """_build_command should create correct curl command."""
        cmd, args = self.router._build_command("roe_http_request", {
            "url": "https://app.acme.com/api",
            "method": "POST",
            "data": '{"test": 1}',
        })
        self.assertEqual(cmd, "curl")
        self.assertIn("-s", args)
        self.assertIn("-S", args)
        self.assertIn("-X", args)
        self.assertIn("POST", args)
        self.assertIn("-d", args)
        self.assertIn('{"test": 1}', args)
        self.assertIn("https://app.acme.com/api", args)

    def test_build_command_dig(self):
        """_build_command should create correct dig command."""
        cmd, args = self.router._build_command("roe_dns_lookup", {
            "domain": "acme.com",
            "record_type": "MX",
        })
        self.assertEqual(cmd, "dig")
        self.assertEqual(args, ["acme.com", "MX"])

    def test_build_command_sqlmap(self):
        """_build_command should create correct sqlmap command."""
        cmd, args = self.router._build_command("roe_sql_injection_test", {
            "url": "http://app.acme.com/search",
            "parameter": "q",
            "method": "POST",
        })
        self.assertEqual(cmd, "sqlmap")
        self.assertIn("-u", args)
        self.assertIn("http://app.acme.com/search", args)
        self.assertIn("-p", args)
        self.assertIn("q", args)
        self.assertIn("--batch", args)
        self.assertIn("--method=POST", args)

    def test_build_command_shell(self):
        """_build_command should split shell command correctly."""
        cmd, args = self.router._build_command("roe_shell_command", {
            "command": "nikto -h 10.0.0.1 -p 80",
        })
        self.assertEqual(cmd, "nikto")
        self.assertEqual(args, ["-h", "10.0.0.1", "-p", "80"])

    def test_build_command_gobuster(self):
        """_build_command should create correct gobuster command."""
        cmd, args = self.router._build_command("roe_directory_scan", {
            "url": "http://app.acme.com",
            "wordlist": "big",
        })
        self.assertEqual(cmd, "gobuster")
        self.assertIn("dir", args)
        self.assertIn("-u", args)
        self.assertIn("http://app.acme.com", args)
        self.assertIn("-w", args)
        self.assertIn("/usr/share/wordlists/big.txt", args)

    def test_build_command_service_probe(self):
        """_build_command should create correct nmap service probe command."""
        cmd, args = self.router._build_command("roe_service_probe", {
            "host": "10.0.0.5",
            "port": 8080,
        })
        self.assertEqual(cmd, "nmap")
        self.assertIn("-sV", args)
        self.assertIn("-p", args)
        self.assertIn("8080", args)
        self.assertIn("10.0.0.5", args)


class TestAgentProviderStatics(unittest.TestCase):
    """Tests for AgentProvider static methods."""

    def test_get_default_system_prompt_includes_roe_summary(self):
        """get_default_system_prompt should include the ROE summary."""
        summary = "Engagement: ACME-2024\nClient: Acme Corp"
        prompt = AgentProvider.get_default_system_prompt(summary)
        self.assertIn("ACME-2024", prompt)
        self.assertIn("Acme Corp", prompt)
        self.assertIn("roe_nmap_scan", prompt)
        self.assertIn("authorized security assessment", prompt)

    def test_get_tool_definitions_returns_7_tools(self):
        """get_tool_definitions should return exactly 7 tools."""
        tools = AgentProvider.get_tool_definitions()
        self.assertEqual(len(tools), 7)

    def test_get_tool_definitions_tool_names(self):
        """get_tool_definitions should return tools with correct names."""
        tools = AgentProvider.get_tool_definitions()
        names = [t["name"] for t in tools]
        expected = [
            "roe_nmap_scan",
            "roe_http_request",
            "roe_dns_lookup",
            "roe_service_probe",
            "roe_directory_scan",
            "roe_sql_injection_test",
            "roe_shell_command",
        ]
        self.assertEqual(names, expected)

    def test_get_tool_definitions_have_required_keys(self):
        """Each tool definition should have name, description, parameters."""
        tools = AgentProvider.get_tool_definitions()
        for tool in tools:
            self.assertIn("name", tool)
            self.assertIn("description", tool)
            self.assertIn("parameters", tool)
            self.assertEqual(tool["parameters"]["type"], "object")
            self.assertIn("properties", tool["parameters"])
            self.assertIn("required", tool["parameters"])


class TestROEGateConfig(unittest.TestCase):
    """Tests for ROEGateConfig YAML parsing."""

    def test_from_yaml_parses_example_config(self):
        """ROEGateConfig.from_yaml should parse the example config."""
        from src.agents.config import ROEGateConfig
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "roe_gate_config.yaml"
        )
        config = ROEGateConfig.from_yaml(config_path)

        self.assertEqual(config.tester.provider, "claude-code")
        self.assertEqual(config.tester.model, "claude-sonnet-4-6")
        self.assertEqual(config.tester.api_key_env, "ANTHROPIC_API_KEY")
        self.assertEqual(config.tester.max_turns, 50)
        self.assertEqual(config.tester.temperature, 0.1)

        self.assertEqual(config.judge.provider, "claude-code")
        self.assertEqual(config.judge.model, "claude-sonnet-4-6")
        self.assertEqual(config.judge.api_key_env, "ANTHROPIC_API_KEY")

        self.assertEqual(config.gate.roe, "examples/local_corp_roe.yaml")
        self.assertEqual(config.gate.port, 19990)
        self.assertEqual(config.gate.signing, "ed25519")
        self.assertTrue(config.gate.hitl)

        self.assertIn("penetration test", config.objective)

    def test_from_yaml_with_minimal_config(self):
        """ROEGateConfig.from_yaml should handle minimal YAML."""
        from src.agents.config import ROEGateConfig
        minimal_yaml = "tester:\n  provider: openai\n  model: gpt-4o\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(minimal_yaml)
            f.flush()
            config = ROEGateConfig.from_yaml(f.name)
        os.unlink(f.name)

        self.assertEqual(config.tester.provider, "openai")
        self.assertEqual(config.tester.model, "gpt-4o")
        # Defaults
        self.assertEqual(config.judge.provider, "mock")
        self.assertEqual(config.gate.port, 19990)

    def test_to_yaml_roundtrip(self):
        """to_yaml output should be parseable back into a config."""
        from src.agents.config import ROEGateConfig, GateConfig, JudgeConfig
        import yaml

        original = ROEGateConfig(
            tester=AgentConfig(provider="anthropic", model="claude-sonnet-4-6"),
            judge=JudgeConfig(provider="mock"),
            gate=GateConfig(port=19991),
            objective="Test the app",
        )
        yaml_str = original.to_yaml()
        data = yaml.safe_load(yaml_str)
        self.assertEqual(data["tester"]["provider"], "anthropic")
        self.assertEqual(data["gate"]["port"], 19991)
        self.assertEqual(data["objective"], "Test the app")


class TestAnthropicAgentToolFormat(unittest.TestCase):
    """Tests for AnthropicAPIAgent tool format conversion."""

    def test_convert_tools_to_anthropic_format(self):
        """Anthropic format should use input_schema instead of parameters."""
        os.environ["ANTHROPIC_API_KEY"] = "test-key-for-unit-test"
        try:
            from src.agents.anthropic_agent import AnthropicAPIAgent
            config = AgentConfig(provider="anthropic", model="claude-sonnet-4-6")
            agent = AnthropicAPIAgent(config)
            tools = agent._convert_tools_to_anthropic_format()

            self.assertEqual(len(tools), 7)
            for tool in tools:
                self.assertIn("name", tool)
                self.assertIn("description", tool)
                self.assertIn("input_schema", tool)
                self.assertNotIn("parameters", tool)
                self.assertEqual(tool["input_schema"]["type"], "object")
        finally:
            del os.environ["ANTHROPIC_API_KEY"]


class TestOpenAIAgentToolFormat(unittest.TestCase):
    """Tests for OpenAIAPIAgent tool format conversion."""

    def test_convert_tools_to_openai_format(self):
        """OpenAI format should wrap tools in type: function + function: {...}."""
        os.environ["OPENAI_API_KEY"] = "test-key-for-unit-test"
        try:
            from src.agents.openai_agent import OpenAIAPIAgent
            config = AgentConfig(provider="openai", model="gpt-4o")
            agent = OpenAIAPIAgent(config)
            tools = agent._convert_tools_to_openai_format()

            self.assertEqual(len(tools), 7)
            for tool in tools:
                self.assertEqual(tool["type"], "function")
                self.assertIn("function", tool)
                func = tool["function"]
                self.assertIn("name", func)
                self.assertIn("description", func)
                self.assertIn("parameters", func)
        finally:
            del os.environ["OPENAI_API_KEY"]


class TestToolRouterExecute(unittest.TestCase):
    """Tests for ToolRouter.execute_tool with mocked gate client."""

    def test_execute_tool_allowed(self):
        """execute_tool should return success when gate allows."""
        with patch("src.service.gate_client.GateServiceClient") as MockClient:
            mock_instance = MockClient.return_value
            mock_instance.evaluate.return_value = {
                "decision": "ALLOW",
                "token": {"signed": "test-token"},
            }
            mock_instance.execute.return_value = {
                "stdout": "PORT   STATE SERVICE\n80/tcp open  http\n",
                "stderr": "",
            }

            router = ToolRouter("http://127.0.0.1:19990", "sess-1", "eng-1")
            result = router.execute_tool("roe_nmap_scan", {
                "target": "10.0.0.1",
                "ports": "80",
            })

            self.assertTrue(result["success"])
            self.assertEqual(result["decision"], "ALLOW")
            self.assertIn("80/tcp", result["output"])

    def test_execute_tool_denied(self):
        """execute_tool should return failure when gate denies."""
        with patch("src.service.gate_client.GateServiceClient") as MockClient:
            mock_instance = MockClient.return_value
            mock_instance.evaluate.return_value = {
                "decision": "DENY",
                "reasoning": "Target 192.168.1.1 is out of scope",
            }

            router = ToolRouter("http://127.0.0.1:19990", "sess-1", "eng-1")
            result = router.execute_tool("roe_nmap_scan", {
                "target": "192.168.1.1",
            })

            self.assertFalse(result["success"])
            self.assertEqual(result["decision"], "DENY")
            self.assertIn("out of scope", result["output"])


if __name__ == "__main__":
    unittest.main()
