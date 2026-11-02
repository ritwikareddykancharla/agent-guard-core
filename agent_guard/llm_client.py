"""
Real Multi-Provider Guarded LLM Client
======================================

Wraps live LLM API calls (Anthropic `claude-opus-5-5`, OpenAI `gpt-4o-mini`,
Google Gemini `gemini-2.5-flash`, Amazon Bedrock, and deterministic local gateway
fallback) in the full AgentGuard & ContextCore zero-trust security and memory pipeline:

1. Pre-Context PII Redaction & Prompt-Injection Firewall (`PIIFirewall.inspect_and_sanitize`)
   ensuring raw SSNs, AWS keys, credit cards, MRNs, emails, and phones never leave
   the security boundary or enter the LLM context window.
2. 3-Tier Hierarchical Memory Context Injection (`HierarchicalMemoryMCPServer.retrieve_context`)
   hydrating relevant Tier 1 Working, Tier 2 Episodic, and Tier 3 Semantic facts.
3. Multi-Model Gateway Governance (`MultiModelGateway.invoke`) enforcing semantic caching,
   token-bucket rate limits, runaway loop breakers, and USD cost kill-switches.
4. Zero-Trust Capability Token Enforcement & Selective Tool PII Re-Hydration
   (`ZeroTrustPolicyEngine.authorize_and_execute` + `PIIFirewall.rehydrate_for_tool`).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Callable, Optional
import urllib.error
import urllib.request

from .identity_delegation import (
    PolicyDecision,
    SignedCapabilityToken,
    ZeroTrustPolicyEngine,
)
from .memory_mcp import (
    HierarchicalMemoryMCPServer,
    RetrievedContextPackage,
)
from .model_gateway import (
    GatewayRequest,
    GatewayResponse,
    ModelTier,
    MultiModelGateway,
)
from .pii_firewall import (
    FirewallInspectionResult,
    PIIFirewall,
    RehydrationResult,
)


def load_dotenv_local() -> dict[str, str]:
    """
    Load environment variables from `.env.local` in current or parent directories
    without hardcoding any secrets in source code.
    """
    candidates = [
        Path.cwd() / ".env.local",
        Path.cwd().parent / ".env.local",
        Path.cwd().parent.parent / ".env.local",
        *[p / ".env.local" for p in Path(__file__).resolve().parents],
    ]
    loaded: dict[str, str] = {}
    for path in candidates:
        if path.is_file():
            try:
                for raw_line in path.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    key = k.strip()
                    val = v.strip().strip("'").strip('"')
                    if key and key not in loaded:
                        loaded[key] = val
            except OSError:
                continue
    return loaded


def _get_env_or_dotenv(key: str, dotenv_vars: dict[str, str], default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(key) or dotenv_vars.get(key) or default


@dataclass(frozen=True)
class GuardedCompletionResult:
    """End-to-end result from GuardedLLMClient.complete()."""

    provider: str
    model_id: str
    response_text: str
    sanitized_prompt: str
    firewall_inspection: FirewallInspectionResult
    memory_context: RetrievedContextPackage
    gateway_response: GatewayResponse
    tool_decision: Optional[PolicyDecision] = None
    rehydrated_tool_arguments: Optional[dict[str, Any]] = None


class GuardedLLMClient:
    """
    Production multi-provider LLM client using Python standard library `urllib.request`
    (plus optional `boto3` for Amazon Bedrock) wrapped with AgentGuard & ContextCore.

    Supported providers:
    - `"anthropic"` (reads `ANTHROPIC_API_KEY`, default model `"claude-opus-5-5"`, header `anthropic-version: 2026-10-21`)
    - `"openai"`    (reads `OPENAI_API_KEY`, default model `"gpt-4o-mini"`)
    - `"gemini"`    (reads `GEMINI_API_KEY`, default model `"gemini-2.5-flash"`)
    - `"bedrock"`   (uses `boto3` `bedrock-runtime` `converse` API)
    - `"gateway"`   (deterministic local MultiModelGateway execution, zero external keys required)
    """

    DEFAULT_MODELS: dict[str, str] = {
        "anthropic": "claude-opus-5-5",
        "openai": "gpt-4o-mini",
        "gemini": "gemini-2.5-flash",
        "bedrock": "us.amazon.nova-micro-v1:0",
        "gateway": MultiModelGateway.FAST_MODEL_ID,
    }

    def __init__(
        self,
        *,
        provider: str = "auto",
        api_key: Optional[str] = None,
        model_id: Optional[str] = None,
        anthropic_version: Optional[str] = None,
        aws_region: Optional[str] = None,
        policy_engine: Optional[ZeroTrustPolicyEngine] = None,
        pii_firewall: Optional[PIIFirewall] = None,
        memory_server: Optional[HierarchicalMemoryMCPServer] = None,
        model_gateway: Optional[MultiModelGateway] = None,
        http_transport: Optional[Callable[[urllib.request.Request, float], bytes]] = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.policy_engine = policy_engine or ZeroTrustPolicyEngine(
            signing_secret="agent-guard-default-signing-secret-key-2026"
        )
        self.pii_firewall = pii_firewall or PIIFirewall()
        self.memory_server = memory_server or HierarchicalMemoryMCPServer()
        self.model_gateway = model_gateway or MultiModelGateway()
        self.timeout_seconds = timeout_seconds
        self._http_transport = http_transport
        self._dotenv = load_dotenv_local()
        self.aws_region = aws_region or _get_env_or_dotenv("AWS_REGION", self._dotenv, "us-east-1") or "us-east-1"
        self.anthropic_version = (
            anthropic_version
            or _get_env_or_dotenv("ANTHROPIC_VERSION", self._dotenv, "2026-10-21")
            or "2026-10-21"
        )

        resolved_provider, resolved_key = self._resolve_provider_and_key(provider, api_key, self._dotenv)
        self.provider = resolved_provider
        self._api_key = resolved_key

        if model_id:
            self.model_id = model_id
        elif self.provider == "anthropic":
            self.model_id = _get_env_or_dotenv("ANTHROPIC_MODEL", self._dotenv, "claude-opus-5-5") or "claude-opus-5-5"
        elif self.provider == "openai":
            self.model_id = _get_env_or_dotenv("OPENAI_MODEL", self._dotenv, "gpt-4o-mini") or "gpt-4o-mini"
        else:
            self.model_id = self.DEFAULT_MODELS.get(self.provider, "gemini-2.5-flash")

    @staticmethod
    def _resolve_provider_and_key(
        provider: str,
        explicit_key: Optional[str],
        dotenv_vars: dict[str, str],
    ) -> tuple[str, Optional[str]]:
        norm = provider.strip().lower()
        if norm == "auto":
            if explicit_key:
                return "gemini", explicit_key
            if _get_env_or_dotenv("GEMINI_API_KEY", dotenv_vars):
                return "gemini", _get_env_or_dotenv("GEMINI_API_KEY", dotenv_vars)
            if _get_env_or_dotenv("ANTHROPIC_API_KEY", dotenv_vars):
                return "anthropic", _get_env_or_dotenv("ANTHROPIC_API_KEY", dotenv_vars)
            if _get_env_or_dotenv("OPENAI_API_KEY", dotenv_vars):
                return "openai", _get_env_or_dotenv("OPENAI_API_KEY", dotenv_vars)
            return "gateway", None

        if norm == "gemini":
            return "gemini", explicit_key or _get_env_or_dotenv("GEMINI_API_KEY", dotenv_vars)
        if norm == "openai":
            return "openai", explicit_key or _get_env_or_dotenv("OPENAI_API_KEY", dotenv_vars)
        if norm == "anthropic":
            return "anthropic", explicit_key or _get_env_or_dotenv("ANTHROPIC_API_KEY", dotenv_vars)
        if norm in ("bedrock", "gateway"):
            return norm, explicit_key
        raise ValueError(f"Unsupported LLM provider '{provider}'. Expected gemini, openai, anthropic, bedrock, or gateway.")

    def _execute_http_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        if self._http_transport is not None:
            raw_bytes = self._http_transport(req, self.timeout_seconds)
        else:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw_bytes = resp.read()
        return json.loads(raw_bytes.decode("utf-8"))

    def _call_gemini(self, system_prompt: str, assembled_user_prompt: str) -> str:
        if not self._api_key:
            raise PermissionError("GEMINI_API_KEY is required for live Gemini calls")
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_id}:generateContent?key={self._api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": assembled_user_prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 400},
        }
        data = self._execute_http_json(
            url,
            headers={"Content-Type": "application/json"},
            payload=payload,
        )
        candidates = data.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(str(p.get("text", "")) for p in parts)

    def _call_openai(self, system_prompt: str, assembled_user_prompt: str) -> str:
        if not self._api_key:
            raise PermissionError("OPENAI_API_KEY is required for live OpenAI calls")
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": assembled_user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 350,
        }
        data = self._execute_http_json(
            url,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            payload=payload,
        )
        choices = data.get("choices", [])
        if not choices:
            return ""
        return str(choices[0].get("message", {}).get("content", ""))

    def _call_anthropic(self, system_prompt: str, assembled_user_prompt: str) -> str:
        if not self._api_key:
            raise PermissionError("ANTHROPIC_API_KEY is required for live Anthropic calls")
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.model_id,
            "max_tokens": 600,
            "system": system_prompt,
            "messages": [{"role": "user", "content": assembled_user_prompt}],
        }
        data = self._execute_http_json(
            url,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": self.anthropic_version,
                "User-Agent": "curl/8.7.1",
            },
            payload=payload,
        )
        content_blocks = data.get("content", [])
        return "".join(str(b.get("text", "")) for b in content_blocks if b.get("type") == "text")

    def _call_bedrock(self, system_prompt: str, assembled_user_prompt: str) -> str:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise RuntimeError("boto3 is required for provider='bedrock'") from exc

        client = boto3.client("bedrock-runtime", region_name=self.aws_region)
        response = client.converse(
            modelId=self.model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": assembled_user_prompt}]}],
            inferenceConfig={"maxTokens": 350, "temperature": 0.2},
        )
        blocks = response.get("output", {}).get("message", {}).get("content", [])
        return "".join(str(b.get("text", "")) for b in blocks if "text" in b)

    def complete(
        self,
        *,
        prompt: str,
        tenant_id: str = "tenant-default",
        agent_id: str = "agent:orchestrator",
        system_prompt: str = "You are a Zero-Trust enterprise AI assistant. Preserve all <PII:...> tokens and cite memory provenance.",
        capability_token: Optional[SignedCapabilityToken] = None,
        proposed_tool_call: Optional[tuple[str, str, dict[str, Any]]] = None,
        tool_fn: Optional[Callable[[dict[str, Any]], Any]] = None,
        jit_request_id: Optional[str] = None,
        raise_on_injection: bool = True,
        bypass_gateway_cache: bool = False,
        now: Optional[float] = None,
    ) -> GuardedCompletionResult:
        """
        Execute a guarded LLM completion + optional tool authorization cycle:

        1. Inspects and sanitizes `prompt` through `PIIFirewall` (blocking prompt injections
           and replacing sensitive PII with `<PII:...>` tokens).
        2. Appends the sanitized turn to `HierarchicalMemoryMCPServer` and retrieves
           hydrated Tier 1 + Tier 2 + Tier 3 context.
        3. Evaluates `MultiModelGateway` (rate limits, loop breaker, cost kill-switch,
           and semantic cache). On cache miss with a live provider configured, invokes
           the upstream provider (`anthropic`, `openai`, `gemini`, or `bedrock`).
        4. If `proposed_tool_call=(tool_name, resource_arn, tool_args)` is provided,
           authorizes execution via `ZeroTrustPolicyEngine.authorize_and_execute` and
           selectively re-hydrates permitted PII categories for that tool.
        """
        # Step 1: Pre-context PII redaction & prompt-injection firewall
        inspection = self.pii_firewall.inspect_and_sanitize(
            prompt,
            source="user_prompt",
            raise_on_block=raise_on_injection,
        )
        sanitized_prompt = inspection.sanitized_text

        # Step 2: Update 3-tier memory and retrieve hydrated context package
        self.memory_server.append_turn(
            role="user",
            content=sanitized_prompt,
            now=now,
        )
        memory_pkg = self.memory_server.retrieve_context(sanitized_prompt, now=now)

        # Step 3: Route through MultiModelGateway (rate limit, semantic cache, loop/cost guards)
        gw_tool_tuple: Optional[tuple[str, dict[str, Any]]] = None
        if proposed_tool_call is not None:
            gw_tool_tuple = (proposed_tool_call[0], proposed_tool_call[2])

        gw_req = GatewayRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            prompt=sanitized_prompt,
            system_prompt=system_prompt,
            proposed_tool_call=gw_tool_tuple,
            force_tier=ModelTier.FAST_TIER if bypass_gateway_cache else None,
        )
        gw_resp = self.model_gateway.invoke(gw_req, now=now)

        # Dispatch to live provider if configured and not served from semantic cache
        composed_input = f"{memory_pkg.assembled_prompt}\n\n### Current User Query\n{sanitized_prompt}"
        if (gw_resp.cache_hit and not bypass_gateway_cache) or self.provider == "gateway":
            final_text = gw_resp.content
            active_model = gw_resp.model_id
        elif self.provider == "gemini":
            final_text = self._call_gemini(system_prompt, composed_input)
            active_model = self.model_id
        elif self.provider == "openai":
            final_text = self._call_openai(system_prompt, composed_input)
            active_model = self.model_id
        elif self.provider == "anthropic":
            final_text = self._call_anthropic(system_prompt, composed_input)
            active_model = self.model_id
        elif self.provider == "bedrock":
            final_text = self._call_bedrock(system_prompt, composed_input)
            active_model = self.model_id
        else:
            final_text = gw_resp.content
            active_model = gw_resp.model_id

        self.memory_server.append_turn(
            role="assistant",
            content=final_text,
            now=now,
        )

        # Step 4: Enforce capability token scope & selective PII re-hydration on tool calls
        tool_decision: Optional[PolicyDecision] = None
        rehydrated_args: Optional[dict[str, Any]] = None

        if proposed_tool_call is not None:
            if capability_token is None:
                raise PermissionError("capability_token is required when executing a proposed_tool_call")
            tool_name, resource_arn, raw_tool_args = proposed_tool_call

            sanitized_args: dict[str, Any] = {}
            for k, v in raw_tool_args.items():
                if isinstance(v, str):
                    sanitized_args[k] = self.pii_firewall.redact_text(v).redacted_text
                else:
                    sanitized_args[k] = v

            rehyd: RehydrationResult = self.pii_firewall.rehydrate_for_tool(
                sanitized_args,
                tool_name=tool_name,
            )
            rehydrated_args = rehyd.rehydrated_payload

            tool_decision = self.policy_engine.authorize_and_execute(
                token=capability_token,
                tool_name=tool_name,
                resource_arn=resource_arn,
                arguments=rehydrated_args,
                tool_fn=tool_fn,
                jit_request_id=jit_request_id,
                now=now,
            )

        return GuardedCompletionResult(
            provider=self.provider,
            model_id=active_model,
            response_text=final_text,
            sanitized_prompt=sanitized_prompt,
            firewall_inspection=inspection,
            memory_context=memory_pkg,
            gateway_response=gw_resp,
            tool_decision=tool_decision,
            rehydrated_tool_arguments=rehydrated_args,
        )
