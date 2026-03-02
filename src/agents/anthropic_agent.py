"""Raw Anthropic API pentesting agent.

Uses the Anthropic Messages API directly with tool_use. This is the most
secure agent configuration because:
- We control the entire tool execution loop
- The agent has NO direct shell/subprocess access
- ALL operations go through the Gate Service evaluate+execute pipeline
- There is no 'Bash escape' to worry about
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request

from src.agents.base import AgentProvider, AgentConfig, ToolRouter

logger = logging.getLogger(__name__)


class AnthropicAPIAgent(AgentProvider):
    """Pentesting agent using the Anthropic Messages API directly."""

    def __init__(self, config: AgentConfig, gate_url: str = "http://127.0.0.1:19990"):
        super().__init__(config, gate_url)
        self.api_key = os.environ.get(config.api_key_env or "ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key not found in env var: %s" % (config.api_key_env or "ANTHROPIC_API_KEY")
            )
        self.base_url = config.base_url or "https://api.anthropic.com"

    def run(self, objective: str, roe_summary: str) -> str:
        import uuid
        session_id = "anthropic-%s" % uuid.uuid4().hex[:8]

        # Get engagement_id from gate health
        try:
            health_resp = urllib.request.urlopen("%s/api/v1/health" % self.gate_url)
            health = json.loads(health_resp.read())
            engagement_id = health.get("engagement_id", "unknown")
        except Exception:
            engagement_id = "unknown"

        router = ToolRouter(self.gate_url, session_id, engagement_id)
        system_prompt = self.config.system_prompt or self.get_default_system_prompt(roe_summary)
        tools = self._convert_tools_to_anthropic_format()

        messages = [{"role": "user", "content": objective}]
        final_report = ""

        for turn in range(self.config.max_turns):
            # Call Anthropic API
            response = self._call_api(system_prompt, messages, tools)

            if response is None:
                logger.error("API call failed on turn %d", turn)
                break

            # Process response
            assistant_content = response.get("content", [])
            messages.append({"role": "assistant", "content": assistant_content})

            # Check if done
            stop_reason = response.get("stop_reason")
            if stop_reason == "end_turn":
                # Extract final text
                for block in assistant_content:
                    if block.get("type") == "text":
                        final_report += block["text"]
                break

            # Process tool uses
            if stop_reason == "tool_use":
                tool_results = []
                for block in assistant_content:
                    if block.get("type") == "tool_use":
                        tool_name = block["name"]
                        tool_input = block["input"]
                        tool_id = block["id"]

                        logger.info(
                            "Turn %d: Tool call %s(%s)",
                            turn, tool_name, json.dumps(tool_input)[:100],
                        )

                        # Route through Gate
                        result = router.execute_tool(tool_name, tool_input)

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": result["output"],
                            "is_error": not result["success"]
                        })

                messages.append({"role": "user", "content": tool_results})
            else:
                # Unexpected stop reason
                for block in assistant_content:
                    if block.get("type") == "text":
                        final_report += block["text"]
                break

        return final_report

    def _call_api(self, system: str, messages: list, tools: list) -> dict:
        """Call the Anthropic Messages API."""
        url = "%s/v1/messages" % self.base_url
        payload = {
            "model": self.config.model,
            "max_tokens": 4096,
            "system": system,
            "messages": messages,
            "tools": tools,
            "temperature": self.config.temperature,
        }

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2024-10-22",
        }

        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            logger.error("Anthropic API error: %s", exc)
            return None

    def _convert_tools_to_anthropic_format(self) -> list:
        """Convert neutral tool definitions to Anthropic's format."""
        tools = self.get_tool_definitions()
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["parameters"]
            }
            for t in tools
        ]
