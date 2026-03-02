"""
LLM Providers for the Judge

These implement the LLMProvider protocol for different backends.
The key design constraint: every call is STATELESS. No conversation memory.
The Judge evaluates each action independently.

LOCAL MODEL STRATEGY:
The Judge's task is narrow — evaluate one action against one policy, return
structured JSON. This is a classification/evaluation task, not creative writing.
Small models (3-7B parameters) can handle this reliably when:
  1. The prompt is structured and explicit
  2. The output format is constrained (JSON mode)
  3. Confidence thresholding catches uncertain verdicts (auto-escalate)

The deterministic Rule Engine handles ~70-80% of decisions with zero LLM.
The Judge only sees the ambiguous remainder. Even if the local model gets
some of those wrong, the confidence threshold escalates uncertain verdicts
to a human operator. The system fails SAFE, not OPEN.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("roe_gate.providers")


# ─── HuggingFace Transformers Provider (Primary Local Option) ────────────────
# Loads models directly from safetensors via the transformers library.
# Supports any model on HuggingFace Hub or local paths.
# Can use bitsandbytes for 4-bit/8-bit quantization.

class TransformersProvider:
    """Local LLM provider using HuggingFace transformers.

    Loads a model directly from safetensors — either from the HuggingFace Hub
    (downloaded on first use) or from a local directory. No server needed.

    Recommended models for the Judge (in order of preference):
      - "Qwen/Qwen2.5-7B-Instruct"    — Best structured output, strong reasoning
      - "microsoft/Phi-3.5-mini-instruct" — Excellent reasoning for 3.8B params
      - "meta-llama/Llama-3.1-8B-Instruct" — Strong general reasoning
      - "Qwen/Qwen2.5-3B-Instruct"    — Best 3B model for structured tasks
      - "meta-llama/Llama-3.2-3B-Instruct" — Fastest, good for constrained systems
      - "meta-llama/Llama-Guard-3-1B"  — Purpose-built for policy classification

    Quantization options (via bitsandbytes — pip install bitsandbytes):
      - load_in_4bit=True:  ~2x memory reduction, minimal quality loss
      - load_in_8bit=True:  ~1.5x memory reduction, near-lossless quality

    Memory requirements (4-bit quantized):
      - 3B model: ~2.5 GB
      - 7B model: ~5 GB
      - 8B model: ~6 GB
    """

    def __init__(
        self,
        model_id: str = "Qwen/Qwen2.5-7B-Instruct",
        device: str | None = None,
        load_in_4bit: bool = False,
        load_in_8bit: bool = False,
        torch_dtype: str = "auto",
        max_new_tokens: int = 1024,
        temperature: float = 0.1,
        trust_remote_code: bool = False,
    ) -> None:
        """Initialize the Transformers provider.

        Args:
            model_id: HuggingFace model ID or local path to a model directory.
            device: Device to load on ("cpu", "cuda", "mps", or None for auto).
            load_in_4bit: Use bitsandbytes 4-bit quantization (needs bitsandbytes).
            load_in_8bit: Use bitsandbytes 8-bit quantization (needs bitsandbytes).
            torch_dtype: Torch dtype ("auto", "float16", "bfloat16", "float32").
            max_new_tokens: Maximum tokens to generate per evaluation.
            temperature: Low temperature for consistent, conservative evaluation.
            trust_remote_code: Whether to trust remote code in model repos.
        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError:
            raise ImportError(
                "transformers and torch are required.\n"
                "Install with: pip install transformers torch\n"
                "For quantization: pip install bitsandbytes"
            )

        self.model_id = model_id
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature

        # Resolve device
        if device is None:
            if torch.cuda.is_available():
                device = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                device = "mps"
            else:
                device = "cpu"

        self._device = device
        logger.info("Loading model %s on device %s", model_id, device)

        # Build quantization config if requested
        model_kwargs: dict[str, Any] = {
            "trust_remote_code": trust_remote_code,
        }

        if load_in_4bit or load_in_8bit:
            try:
                from transformers import BitsAndBytesConfig
                quant_config = BitsAndBytesConfig(
                    load_in_4bit=load_in_4bit,
                    load_in_8bit=load_in_8bit,
                    bnb_4bit_compute_dtype=torch.float16 if load_in_4bit else None,
                    bnb_4bit_use_double_quant=load_in_4bit,
                )
                model_kwargs["quantization_config"] = quant_config
                model_kwargs["device_map"] = "auto"
            except ImportError:
                logger.warning(
                    "bitsandbytes not installed — loading without quantization.\n"
                    "Install with: pip install bitsandbytes"
                )
                model_kwargs["device_map"] = device
        else:
            # Resolve torch_dtype
            dtype_map = {
                "auto": "auto",
                "float16": torch.float16,
                "bfloat16": torch.bfloat16,
                "float32": torch.float32,
            }
            resolved_dtype = dtype_map.get(torch_dtype, "auto")
            model_kwargs["torch_dtype"] = resolved_dtype
            model_kwargs["device_map"] = device

        # Load tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            trust_remote_code=trust_remote_code,
        )
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

        # Load model
        self._model = AutoModelForCausalLM.from_pretrained(
            model_id,
            **model_kwargs,
        )
        self._model.eval()

        logger.info("Model loaded: %s", model_id)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a stateless completion request to the local model.

        Constructs a chat-formatted prompt using the tokenizer's chat template,
        generates a response, and extracts just the assistant's reply.
        """
        import torch

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            # Use the model's chat template for proper formatting
            input_text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

            inputs = self._tokenizer(
                input_text,
                return_tensors="pt",
                truncation=True,
                max_length=4096,
            )
            # Move inputs to the model's device
            device = next(self._model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self._model.generate(
                    **inputs,
                    max_new_tokens=self.max_new_tokens,
                    temperature=self.temperature if self.temperature > 0 else None,
                    do_sample=self.temperature > 0,
                    pad_token_id=self._tokenizer.pad_token_id,
                )

            # Decode only the newly generated tokens (skip the input)
            input_length = inputs["input_ids"].shape[1]
            generated_tokens = outputs[0][input_length:]
            response = self._tokenizer.decode(
                generated_tokens,
                skip_special_tokens=True,
            ).strip()

            # Try to extract JSON from the response
            response = self._extract_json(response)
            return response

        except Exception as e:
            logger.error("Transformers inference failed: %s", e)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM error: {e}. Escalating to human.",
                "roe_clauses_cited": [],
            })

    @staticmethod
    def _extract_json(text: str) -> str:
        """Extract JSON from model output, handling common formatting issues.

        Models sometimes wrap JSON in markdown code blocks or add extra text.
        """
        # Strip markdown code fences
        if "```" in text:
            lines = text.split("\n")
            json_lines = []
            in_block = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("```") and not in_block:
                    in_block = True
                    continue
                elif stripped.startswith("```") and in_block:
                    break
                elif in_block:
                    json_lines.append(line)
            if json_lines:
                text = "\n".join(json_lines)

        # Try to find a JSON object in the text
        text = text.strip()
        if not text.startswith("{"):
            start = text.find("{")
            if start >= 0:
                # Find matching closing brace
                depth = 0
                for i, ch in enumerate(text[start:], start):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            text = text[start:i + 1]
                            break

        return text


# ─── llama.cpp Provider (Alternative Local Option) ───────────────────────────
# For GGUF model files. More portable, less memory overhead.

class LlamaCppProvider:
    """Local LLM provider using llama-cpp-python.

    Loads GGUF model files directly. Lower memory overhead than transformers.
    Supports constrained decoding via GBNF grammars for guaranteed valid JSON.

    Install: pip install llama-cpp-python
    """

    def __init__(
        self,
        model_path: str,
        n_ctx: int = 4096,
        n_threads: int | None = None,
        n_gpu_layers: int = 0,
        temperature: float = 0.1,
    ) -> None:
        try:
            from llama_cpp import Llama
        except ImportError:
            raise ImportError(
                "llama-cpp-python is required.\n"
                "Install with: pip install llama-cpp-python"
            )

        self.temperature = temperature
        self._llm = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_threads=n_threads or 0,
            n_gpu_layers=n_gpu_layers,
            verbose=False,
        )

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self._llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.temperature,
                max_tokens=1024,
                response_format={"type": "json_object"},
            )
            return response["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error("llama.cpp inference failed: %s", e)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM error: {e}. Escalating to human.",
                "roe_clauses_cited": [],
            })


# ─── API Providers (Cloud Options) ───────────────────────────────────────────

class AnthropicProvider:
    """Cloud provider using the Anthropic API (Claude).

    Authentication:
        Pass ``api_key`` directly, or set the ``ANTHROPIC_API_KEY`` environment
        variable.  The constructor reads from the environment when no key is
        provided explicitly.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-5-20250929",
        max_tokens: int = 1024,
    ) -> None:
        import os

        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key is required. Either pass api_key= or set "
                "the ANTHROPIC_API_KEY environment variable."
            )
        self.model = model
        self.max_tokens = max_tokens

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import urllib.request

        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                    "anthropic-version": "2024-10-22",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["content"][0]["text"]
        except Exception as e:
            logger.error("Anthropic API failed: %s", e)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM unavailable: {e}. Escalating to human.",
                "roe_clauses_cited": [],
            })


class OpenAIProvider:
    """Cloud provider using OpenAI-compatible APIs (GPT, vLLM, LM Studio, etc.).

    Works with any OpenAI-compatible endpoint by setting ``base_url``:
      - OpenAI:     https://api.openai.com/v1 (default)
      - Together:   https://api.together.xyz/v1
      - Groq:       https://api.groq.com/openai/v1
      - Azure:      https://<resource>.openai.azure.com/openai/deployments/<model>/v1
      - vLLM:       http://localhost:8000/v1
      - LM Studio:  http://localhost:1234/v1

    Authentication:
        Pass ``api_key`` directly, or set the ``OPENAI_API_KEY`` environment
        variable.  The constructor reads from the environment when no key is
        provided explicitly.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        max_tokens: int = 1024,
    ) -> None:
        import os

        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "OpenAI API key is required. Either pass api_key= or set "
                "the OPENAI_API_KEY environment variable."
            )
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_tokens = max_tokens

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import urllib.request

        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error("OpenAI API failed: %s", e)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM unavailable: {e}. Escalating to human.",
                "roe_clauses_cited": [],
            })


# ─── Google Gemini Provider ───────────────────────────────────────────────────

class GeminiProvider:
    """Cloud provider using the Google Generative Language API (Gemini).

    Authentication:
        Pass ``api_key`` directly, or set the ``GOOGLE_API_KEY`` environment
        variable.  The constructor reads from the environment when no key is
        provided explicitly.
    """

    def __init__(
        self,
        model: str = "gemini-2.0-flash",
        api_key: str | None = None,
    ) -> None:
        import os

        self.model = model
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Google API key is required. Either pass api_key= or set "
                "the GOOGLE_API_KEY environment variable."
            )

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import urllib.request

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1024},
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as exc:
            logger.error("Gemini API failed: %s", exc)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM unavailable (GeminiProvider): {exc}",
                "roe_clauses_cited": [],
                "recommended_action": "Request human review",
            })


# ─── Ollama Provider (Local) ─────────────────────────────────────────────────

class OllamaProvider:
    """Local model provider using Ollama.

    Connects to a running Ollama instance. No API key needed.
    Default endpoint: http://localhost:11434

    Install Ollama: https://ollama.com
    Pull a model:   ollama pull llama3.1:8b
    """

    def __init__(
        self,
        model: str = "llama3.1:8b",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import urllib.request

        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["message"]["content"]
        except Exception as exc:
            logger.error("Ollama API failed: %s", exc)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM unavailable (OllamaProvider): {exc}",
                "roe_clauses_cited": [],
                "recommended_action": "Request human review",
            })


# ─── AWS Bedrock Provider ────────────────────────────────────────────────────

class BedrockProvider:
    """Cloud provider using the AWS Bedrock Converse API.

    Supports Claude, Llama, Mistral, and other models hosted on Bedrock.
    Requires ``boto3`` and valid AWS credentials (env vars, profile, or IAM role).

    Install: pip install boto3
    """

    def __init__(
        self,
        model_id: str = "anthropic.claude-3-haiku-20240307-v1:0",
        region: str = "us-east-1",
    ) -> None:
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "AWS Bedrock provider requires boto3.\n"
                "Install with: pip install boto3"
            )
        self.model_id = model_id
        self.client = boto3.client("bedrock-runtime", region_name=region)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self.client.converse(
                modelId=self.model_id,
                system=[{"text": system_prompt}],
                messages=[
                    {"role": "user", "content": [{"text": user_prompt}]},
                ],
                inferenceConfig={"temperature": 0.1, "maxTokens": 1024},
            )
            return response["output"]["message"]["content"][0]["text"]
        except Exception as exc:
            logger.error("Bedrock API failed: %s", exc)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM unavailable (BedrockProvider): {exc}",
                "roe_clauses_cited": [],
                "recommended_action": "Request human review",
            })


# ─── Hybrid Provider ─────────────────────────────────────────────────────────

class HybridProvider:
    """Uses a local model first, falls back to cloud for low-confidence results.

    Recommended production config:
    1. Local model evaluates first (fast, private, no API cost)
    2. If confidence < threshold, re-evaluate with cloud model
    3. If cloud unavailable, escalate to human
    """

    def __init__(
        self,
        local_provider: Any,
        cloud_provider: Any | None = None,
        local_confidence_threshold: float = 0.7,
    ) -> None:
        self.local = local_provider
        self.cloud = cloud_provider
        self.threshold = local_confidence_threshold
        self._local_calls = 0
        self._cloud_fallbacks = 0

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self._local_calls += 1
        local_response = self.local.complete(system_prompt, user_prompt)

        try:
            parsed = json.loads(local_response)
            confidence = float(parsed.get("confidence", 0.0))

            if confidence >= self.threshold:
                return local_response

            if self.cloud:
                self._cloud_fallbacks += 1
                logger.info(
                    "Local confidence %.2f < threshold %.2f, falling back to cloud",
                    confidence, self.threshold,
                )
                return self.cloud.complete(system_prompt, user_prompt)

            return local_response
        except (json.JSONDecodeError, ValueError):
            if self.cloud:
                self._cloud_fallbacks += 1
                return self.cloud.complete(system_prompt, user_prompt)
            return local_response

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_local_calls": self._local_calls,
            "cloud_fallbacks": self._cloud_fallbacks,
            "local_hit_rate": (
                (self._local_calls - self._cloud_fallbacks) / self._local_calls
                if self._local_calls > 0 else 0.0
            ),
        }


# ─── Claude Agent SDK Provider ──────────────────────────────────────────────
# Uses the Claude Agent SDK (claude_agent_sdk) to evaluate actions by sending
# prompts to Claude Code programmatically.
# Authentication: Set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN env var.

class ClaudeAgentSDKProvider:
    """Cloud provider using the Claude Agent SDK.

    Evaluates actions by sending prompts through the Claude Agent SDK,
    which communicates with Claude Code programmatically. This provider
    streams the response and collects the text output for judge evaluation.

    Authentication is handled via environment variables:
      - ANTHROPIC_API_KEY: Standard Anthropic API key
      - CLAUDE_CODE_OAUTH_TOKEN: OAuth token from ``claude setup-token``

    Install: pip install claude-agent-sdk
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        max_turns: int = 1,
    ) -> None:
        """Initialize the Claude Agent SDK provider.

        Args:
            model: The Claude model to use for evaluation.
            max_turns: Maximum conversation turns (1 for single evaluation).
        """
        try:
            import claude_agent_sdk  # noqa: F401
        except ImportError:
            raise ImportError(
                "claude_agent_sdk is required.\n"
                "Install with: pip install claude-agent-sdk\n"
                "Authentication: set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN env var."
            )

        self.model = model
        self.max_turns = max_turns

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a stateless evaluation request via the Claude Agent SDK.

        Uses asyncio.run() to drive the async SDK from synchronous code.
        Falls back to the existing event loop if one is already running
        (e.g. inside Jupyter or an async framework).

        Args:
            system_prompt: The judge system prompt with policy context.
            user_prompt: The action description to evaluate.

        Returns:
            The text response from Claude, or ESCALATE JSON on failure.
        """
        import asyncio
        from claude_agent_sdk import query, ClaudeAgentOptions

        async def _run() -> str:
            result_text = ""
            async for message in query(
                prompt=user_prompt,
                options=ClaudeAgentOptions(
                    model=self.model,
                    allowed_tools=[],
                    system_prompt=system_prompt,
                    max_turns=self.max_turns,
                    permission_mode="bypassPermissions",
                ),
            ):
                if hasattr(message, "content"):
                    for block in message.content:
                        if hasattr(block, "text"):
                            result_text += block.text
            return result_text

        try:
            # Prefer asyncio.run() for a clean event loop.  If a loop is
            # already running (Jupyter, async framework, etc.), fall back
            # to run_until_complete on the existing loop.
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                result = loop.run_until_complete(_run())
            else:
                result = asyncio.run(_run())

            return result

        except Exception as e:
            logger.error("Claude Agent SDK evaluation failed: %s", e)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge LLM error (Claude Agent SDK): {e}. Escalating to human.",
                "roe_clauses_cited": [],
            })


# --- Claude CLI Provider (Subscription-based) ------------------------------------
# Uses the `claude` CLI tool directly via `claude -p`. Requires Claude Code to be
# installed and authenticated (subscription). No API keys needed.

class ClaudeCLIProvider:
    """Judge provider using the ``claude`` CLI with the user's subscription.

    Calls ``claude -p`` as a subprocess for each evaluation. This uses the
    user's existing Claude Code authentication -- no API keys or OAuth tokens
    are needed.

    The ``claude`` binary must be on ``$PATH`` and authenticated (run
    ``claude auth`` if needed).
    """

    def __init__(self, model: str = "haiku") -> None:
        import shutil

        self._claude_path = shutil.which("claude")
        if self._claude_path is None:
            raise FileNotFoundError(
                "The 'claude' CLI was not found on $PATH.\n"
                "Install Claude Code: https://docs.anthropic.com/en/docs/claude-code\n"
                "Then authenticate with: claude auth"
            )
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        import subprocess

        try:
            result = subprocess.run(
                [
                    self._claude_path,
                    "-p", user_prompt,
                    "--system-prompt", system_prompt,
                    "--model", self.model,
                    "--output-format", "text",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                logger.error("claude CLI exited %d: %s", result.returncode, stderr)
                return json.dumps({
                    "verdict": "ESCALATE",
                    "confidence": 0.0,
                    "reasoning": f"Judge CLI error (exit {result.returncode}): {stderr}. Escalating.",
                    "roe_clauses_cited": [],
                })

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            logger.error("claude CLI timed out after 120s")
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": "Judge CLI timed out. Escalating to human.",
                "roe_clauses_cited": [],
            })
        except Exception as e:
            logger.error("claude CLI failed: %s", e)
            return json.dumps({
                "verdict": "ESCALATE",
                "confidence": 0.0,
                "reasoning": f"Judge CLI error: {e}. Escalating to human.",
                "roe_clauses_cited": [],
            })
