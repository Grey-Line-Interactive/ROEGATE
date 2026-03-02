"""Tests for new judge LLM providers: Gemini, Ollama, Bedrock, and OpenAI base_url."""

import io
import json
import unittest
from unittest.mock import MagicMock, patch

from src.core.providers import (
    BedrockProvider,
    GeminiProvider,
    OllamaProvider,
    OpenAIProvider,
)


# ─── OpenAI base_url tests ──────────────────────────────────────────────────

class TestOpenAIProviderBaseURL(unittest.TestCase):
    """Tests for OpenAIProvider configurable base_url."""

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    def test_default_base_url(self):
        provider = OpenAIProvider()
        self.assertEqual(provider.base_url, "https://api.openai.com/v1")

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    def test_custom_base_url(self):
        provider = OpenAIProvider(base_url="https://api.together.xyz/v1")
        self.assertEqual(provider.base_url, "https://api.together.xyz/v1")

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    def test_custom_base_url_strips_trailing_slash(self):
        provider = OpenAIProvider(base_url="https://api.groq.com/openai/v1/")
        self.assertEqual(provider.base_url, "https://api.groq.com/openai/v1")

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"})
    def test_constructs_correct_url_with_custom_base(self):
        provider = OpenAIProvider(base_url="http://localhost:8000/v1")
        # Mock urlopen to capture the request
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": '{"verdict":"ALLOW"}'}}]
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            provider.complete("system", "user")
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.full_url, "http://localhost:8000/v1/chat/completions")


# ─── GeminiProvider tests ───────────────────────────────────────────────────

class TestGeminiProvider(unittest.TestCase):
    """Tests for GeminiProvider."""

    def test_requires_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            # Ensure GOOGLE_API_KEY is not set
            with self.assertRaises(ValueError) as ctx:
                GeminiProvider(api_key=None)
            self.assertIn("GOOGLE_API_KEY", str(ctx.exception))

    @patch.dict("os.environ", {"GOOGLE_API_KEY": "test-gemini-key"})
    def test_constructs_correct_url(self):
        provider = GeminiProvider(model="gemini-2.0-flash")
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "candidates": [{"content": {"parts": [{"text": '{"verdict":"ALLOW"}'}]}}]
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            provider.complete("system", "user")
            req = mock_urlopen.call_args[0][0]
            self.assertIn("generativelanguage.googleapis.com", req.full_url)
            self.assertIn("gemini-2.0-flash", req.full_url)
            self.assertIn("key=test-gemini-key", req.full_url)

    @patch.dict("os.environ", {"GOOGLE_API_KEY": "test-gemini-key"})
    def test_returns_escalate_on_network_error(self):
        provider = GeminiProvider()
        with patch("urllib.request.urlopen", side_effect=ConnectionError("Network down")):
            result = provider.complete("system", "user")
            parsed = json.loads(result)
            self.assertEqual(parsed["verdict"], "ESCALATE")
            self.assertEqual(parsed["confidence"], 0.0)
            self.assertIn("GeminiProvider", parsed["reasoning"])
            self.assertEqual(parsed["recommended_action"], "Request human review")


# ─── OllamaProvider tests ───────────────────────────────────────────────────

class TestOllamaProvider(unittest.TestCase):
    """Tests for OllamaProvider."""

    def test_default_base_url(self):
        provider = OllamaProvider()
        self.assertEqual(provider.base_url, "http://localhost:11434")

    def test_custom_base_url(self):
        provider = OllamaProvider(base_url="http://192.168.1.100:11434/")
        self.assertEqual(provider.base_url, "http://192.168.1.100:11434")

    def test_default_model(self):
        provider = OllamaProvider()
        self.assertEqual(provider.model, "llama3.1:8b")

    def test_returns_escalate_when_not_running(self):
        provider = OllamaProvider()
        with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError("Connection refused")):
            result = provider.complete("system", "user")
            parsed = json.loads(result)
            self.assertEqual(parsed["verdict"], "ESCALATE")
            self.assertEqual(parsed["confidence"], 0.0)
            self.assertIn("OllamaProvider", parsed["reasoning"])

    def test_successful_completion(self):
        provider = OllamaProvider()
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "message": {"content": '{"verdict":"DENY","confidence":0.95}'}
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = provider.complete("system", "user")
            self.assertIn("DENY", result)


# ─── BedrockProvider tests ──────────────────────────────────────────────────

class TestBedrockProvider(unittest.TestCase):
    """Tests for BedrockProvider."""

    def test_requires_boto3(self):
        with patch.dict("sys.modules", {"boto3": None}):
            with self.assertRaises(ImportError) as ctx:
                BedrockProvider()
            self.assertIn("boto3", str(ctx.exception))

    def test_creates_client_with_correct_region(self):
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            # Re-import to pick up mock
            import importlib
            import src.core.providers as pmod
            importlib.reload(pmod)
            provider = pmod.BedrockProvider(region="eu-west-1")
            mock_boto3.client.assert_called_with("bedrock-runtime", region_name="eu-west-1")

    def test_returns_escalate_on_error(self):
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.converse.side_effect = Exception("Access denied")
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            import importlib
            import src.core.providers as pmod
            importlib.reload(pmod)
            provider = pmod.BedrockProvider()
            result = provider.complete("system", "user")
            parsed = json.loads(result)
            self.assertEqual(parsed["verdict"], "ESCALATE")
            self.assertEqual(parsed["confidence"], 0.0)
            self.assertIn("BedrockProvider", parsed["reasoning"])


# ─── Cross-provider error JSON validity ─────────────────────────────────────

class TestAllNewProvidersErrorJSON(unittest.TestCase):
    """Verify all new providers return valid JSON on error."""

    @patch.dict("os.environ", {"GOOGLE_API_KEY": "k"})
    def test_all_providers_return_valid_json_on_error(self):
        providers = []

        # Gemini
        providers.append(GeminiProvider())

        # Ollama
        providers.append(OllamaProvider())

        # Bedrock
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.converse.side_effect = Exception("fail")
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            import importlib
            import src.core.providers as pmod
            importlib.reload(pmod)
            providers.append(pmod.BedrockProvider())

        for provider in providers:
            with patch("urllib.request.urlopen", side_effect=Exception("fail")):
                result = provider.complete("system", "user")
                parsed = json.loads(result)
                self.assertIn("verdict", parsed, f"{type(provider).__name__} missing verdict")
                self.assertIn("confidence", parsed, f"{type(provider).__name__} missing confidence")
                self.assertIn("reasoning", parsed, f"{type(provider).__name__} missing reasoning")
                self.assertIn("roe_clauses_cited", parsed, f"{type(provider).__name__} missing roe_clauses_cited")


if __name__ == "__main__":
    unittest.main()
