"""OpenAI API pentesting agent.

Uses the OpenAI Chat Completions API with function calling.
Also works with any OpenAI-compatible endpoint (Together, Groq, vLLM, etc.)
by setting base_url in the config.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request

from src.agents.base import AgentProvider, AgentConfig, ToolRouter

logger = logging.getLogger(__name__)


class OpenAIAPIAgent(AgentProvider):
    """Pentesting agent using the OpenAI Chat Completions API."""

    def __init__(self, config: AgentConfig, gate_url: str = "http://127.0.0.1:19990"):
        super().__init__(config, gate_url)
        self.api_key = os.environ.get(config.api_key_env or "OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key not found: %s" % (config.api_key_env or "OPENAI_API_KEY")
            )
        self.base_url = (config.base_url or "https://api.openai.com/v1").rstrip("/")

    def run(self, objective: str, roe_summary: str) -> str:
        import uuid
        session_id = "openai-%s" % uuid.uuid4().hex[:8]

        try:
            health_resp = urllib.request.urlopen("%s/api/v1/health" % self.gate_url)
            health = json.loads(health_resp.read())
            engagement_id = health.get("engagement_id", "unknown")
        except Exception:
            engagement_id = "unknown"

        router = ToolRouter(self.gate_url, session_id, engagement_id)
        system_prompt = self.config.system_prompt or self.get_default_system_prompt(roe_summary)
        tools = self._convert_tools_to_openai_format()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": objective}
        ]
        final_report = ""

        for turn in range(self.config.max_turns):
            response = self._call_api(messages, tools)
            if response is None:
                break

            choice = response["choices"][0]
            message = choice["message"]
            messages.append(message)

            if choice["finish_reason"] == "stop":
                final_report = message.get("content", "")
                break

            if choice["finish_reason"] == "tool_calls":
                for tc in message.get("tool_calls", []):
                    func = tc["function"]
                    tool_name = func["name"]
                    tool_input = json.loads(func["arguments"])

                    logger.info("Turn %d: Tool call %s", turn, tool_name)
                    result = router.execute_tool(tool_name, tool_input)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result["output"]
                    })

        return final_report

    def _call_api(self, messages: list, tools: list) -> dict:
        url = "%s/chat/completions" % self.base_url
        payload = {
            "model": self.config.model,
            "messages": messages,
            "tools": tools,
            "temperature": self.config.temperature,
            "max_tokens": 4096,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.api_key,
        }
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            logger.error("OpenAI API error: %s", exc)
            return None

    def _convert_tools_to_openai_format(self) -> list:
        tools = self.get_tool_definitions()
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["parameters"]
                }
            }
            for t in tools
        ]
