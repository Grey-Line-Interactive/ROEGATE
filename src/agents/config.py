"""Unified configuration for ROE Gate agent + judge + gate settings."""
from __future__ import annotations

import yaml
from dataclasses import dataclass
from pathlib import Path
from src.agents.base import AgentConfig


@dataclass
class GateConfig:
    """Gate Service configuration."""
    roe: str = "examples/acme_corp_roe.yaml"
    port: int = 19990
    host: str = "127.0.0.1"
    signing: str = "hmac"  # "hmac" or "ed25519"
    hitl: bool = False
    dry_run: bool = False
    log_dir: str = ""


@dataclass
class JudgeConfig:
    """Judge LLM configuration."""
    provider: str = "mock"  # "mock", "anthropic", "openai", "gemini", "ollama", "bedrock", etc.
    model: str = ""
    api_key_env: str = ""
    base_url: str = ""


@dataclass
class ROEGateConfig:
    """Complete ROE Gate configuration."""
    tester: AgentConfig
    judge: JudgeConfig
    gate: GateConfig
    objective: str = ""

    @classmethod
    def from_yaml(cls, path: str) -> "ROEGateConfig":
        """Load configuration from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        tester_data = data.get("tester", {})
        tester = AgentConfig(
            provider=tester_data.get("provider", "anthropic"),
            model=tester_data.get("model", "claude-sonnet-4-6"),
            api_key_env=tester_data.get("api_key_env", ""),
            base_url=tester_data.get("base_url", ""),
            max_turns=tester_data.get("max_turns", 50),
            temperature=tester_data.get("temperature", 0.1),
            system_prompt=tester_data.get("system_prompt", ""),
            extra=tester_data.get("extra", {}),
        )

        judge_data = data.get("judge", {})
        judge = JudgeConfig(
            provider=judge_data.get("provider", "mock"),
            model=judge_data.get("model", ""),
            api_key_env=judge_data.get("api_key_env", ""),
            base_url=judge_data.get("base_url", ""),
        )

        gate_data = data.get("gate", {})
        gate = GateConfig(
            roe=gate_data.get("roe", "examples/acme_corp_roe.yaml"),
            port=gate_data.get("port", 19990),
            host=gate_data.get("host", "127.0.0.1"),
            signing=gate_data.get("signing", "hmac"),
            hitl=gate_data.get("hitl", False),
            dry_run=gate_data.get("dry_run", False),
            log_dir=gate_data.get("log_dir", ""),
        )

        return cls(
            tester=tester,
            judge=judge,
            gate=gate,
            objective=data.get("objective", ""),
        )

    def to_yaml(self) -> str:
        """Serialize config to YAML string."""
        data = {
            "tester": {
                "provider": self.tester.provider,
                "model": self.tester.model,
                "api_key_env": self.tester.api_key_env,
                "base_url": self.tester.base_url,
                "max_turns": self.tester.max_turns,
                "temperature": self.tester.temperature,
                "system_prompt": self.tester.system_prompt,
                "extra": self.tester.extra,
            },
            "judge": {
                "provider": self.judge.provider,
                "model": self.judge.model,
                "api_key_env": self.judge.api_key_env,
                "base_url": self.judge.base_url,
            },
            "gate": {
                "roe": self.gate.roe,
                "port": self.gate.port,
                "host": self.gate.host,
                "signing": self.gate.signing,
                "hitl": self.gate.hitl,
                "dry_run": self.gate.dry_run,
                "log_dir": self.gate.log_dir,
            },
            "objective": self.objective,
        }
        return yaml.dump(data, default_flow_style=False)
