"""
Reversible Pre-Context PII Redaction Proxy & Prompt-Injection Firewall
=======================================================================

Implements:
1. Deterministic pre-context PII detection and tokenization across 6 core entity classes:
   - SSN            -> <PII:SSN_001>
   - AWS_ACCESS_KEY -> <PII:AWS_KEY_001>
   - CREDIT_CARD    -> <PII:CREDIT_CARD_001>
   - EMAIL          -> <PII:EMAIL_001>
   - PHONE          -> <PII:PHONE_001>
   - PATIENT_MRN    -> <PII:PATIENT_MRN_001>
2. Selective downstream re-hydration governed by per-tool capability allowlists,
   preventing unauthorized tools or LLM context windows from viewing raw secrets.
3. Multi-layer Cross-Agent Indirect Prompt-Injection & Tool-Schema Fuzzer Firewall
   detecting instruction overrides, ChatML/XML role-spoofing delimiters, markdown/URL
   data exfiltration beacons, base64-obfuscated payloads, and tool parameter smuggling.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import re
from typing import Any, Optional


class PIICategory(str, Enum):
    """Supported sensitive entity types for deterministic tokenization."""

    SSN = "SSN"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PATIENT_MRN = "PATIENT_MRN"

    @property
    def token_prefix(self) -> str:
        if self is PIICategory.AWS_ACCESS_KEY:
            return "AWS_KEY"
        return self.value


class PromptInjectionError(PermissionError):
    """Raised when strict firewall mode blocks an indirect prompt injection payload."""


@dataclass(frozen=True)
class PIIMatch:
    """Single detected sensitive entity span and its assigned deterministic placeholder."""

    category: PIICategory
    placeholder: str
    start: int
    end: int
    value_hmac: str


@dataclass(frozen=True)
class RedactionResult:
    """Output of redacting sensitive PII from text prior to LLM context ingestion."""

    original_length: int
    redacted_text: str
    matches: tuple[PIIMatch, ...]
    counts_by_category: dict[str, int]

    @property
    def total_redactions(self) -> int:
        return len(self.matches)


@dataclass(frozen=True)
class RehydrationResult:
    """Output of selectively re-hydrating authorized PII tokens for a downstream tool."""

    tool_name: str
    rehydrated_payload: Any
    rehydrated_tokens: tuple[str, ...]
    blocked_tokens: tuple[str, ...]


@dataclass(frozen=True)
class FirewallInspectionResult:
    """Comprehensive security inspection result combining injection defense and PII redaction."""

    source: str
    is_blocked: bool
    risk_score: float
    matched_rules: tuple[str, ...]
    sanitized_text: str
    redaction_result: RedactionResult


# Ordered from most specific structural formats to broader numeric patterns
_PII_PATTERNS: list[tuple[PIICategory, re.Pattern[str]]] = [
    (
        PIICategory.AWS_ACCESS_KEY,
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ),
    (
        PIICategory.PATIENT_MRN,
        re.compile(r"\bMRN(?:-|: ?)[0-9]{6,10}\b", re.IGNORECASE),
    ),
    (
        PIICategory.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        PIICategory.CREDIT_CARD,
        re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b"),
    ),
    (
        PIICategory.SSN,
        re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ),
    (
        PIICategory.PHONE,
        re.compile(
            r"(?:(?:\+?1[-.\s]?)?\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4})"
            r"|(?:(?:\+1[-.\s]?)\d{3}[-.\s]\d{3}[-.\s]\d{4})"
            r"|(?:\b\d{3}-\d{3}-\d{4}\b)"
        ),
    ),
]

_PLACEHOLDER_PATTERN = re.compile(r"<PII:([A-Z_]+)_(\d{3,})>")

# Multi-layer Indirect Prompt Injection & Tool-Schema Fuzzer signatures
_INJECTION_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    (
        "INSTRUCTION_OVERRIDE",
        0.92,
        re.compile(
            r"(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:all\s+)?(?:previous|prior|above|system|earlier|safety)\s+"
            r"(?:instructions|prompts|rules|constraints|guardrails|directives)",
            re.IGNORECASE,
        ),
    ),
    (
        "SYSTEM_PROMPT_HIJACK",
        0.90,
        re.compile(
            r"(?:new\s+system\s+prompt|system\s+override|you\s+are\s+now\s+in\s+developer\s+mode"
            r"|act\s+as\s+an\s+unrestricted|jailbreak\s+mode|do\s+anything\s+now"
            r"|important\s+new\s+instructions\s+from\s+admin)",
            re.IGNORECASE,
        ),
    ),
    (
        "ROLE_SPOOFING_DELIMITER",
        0.95,
        re.compile(
            r"(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"
            r"|</tool_output>\s*<system>|<system_instructions>|</context>\s*<system>"
            r"|(?:^|\n)\s*(?:System|Assistant|Developer)\s*:\s*(?:You\s+must|Ignore|Execute|Call))",
            re.IGNORECASE,
        ),
    ),
    (
        "COVERT_EXFILTRATION_URL",
        0.94,
        re.compile(
            r"(?:!\[[^\]]*\]\(https?://[^\)]+(?:\?(?:token|secret|key|ssn|data|exfil|pii)=|webhook\.site|ngrok|burpcollaborator|requestbin|evil|attacker)[^\)]*\))"
            r"|(?:https?://(?:[^\s/]*\.)?(?:webhook\.site|ngrok\.io|ngrok-free\.app|requestbin\.com|burpcollaborator\.net|attacker\.|evil\.)[^\s\"']*)"
            r"|(?:https?://[^\s\"']+\?(?:exfil|leak|stolen_token|aws_key|ssn)=[^\s\"']+)",
            re.IGNORECASE,
        ),
    ),
    (
        "TOOL_CALL_SMUGGLING",
        0.88,
        re.compile(
            r"(?:\{\s*\"(?:tool| tool_name|function_call|action)\"\s*:\s*\"(?:WIRE_TRANSFER|IAM_MUTATE|PROD_DEPLOY|DELETE|bash|exec)\")"
            r"|(?:call_tool\s*\(\s*['\"](?:WIRE_TRANSFER|IAM_MUTATE|PROD_DEPLOY|DELETE))",
            re.IGNORECASE,
        ),
    ),
    (
        "SCHEMA_FUZZER_TRAVERSAL_OR_INJECTION",
        0.89,
        re.compile(
            r"(?:\.\./\.\./(?:etc/passwd|etc/shadow|root|proc/self))"
            r"|(?:;\s*(?:rm\s+-rf|curl\s+http|wget\s+http|nc\s+-e|/bin/sh))"
            r"|(?:'\s*OR\s+'1'\s*=\s*'1|\bUNION\s+SELECT\b.*?\bFROM\b|\bDROP\s+TABLE\b)",
            re.IGNORECASE,
        ),
    ),
]

_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


class PIIFirewall:
    """
    Reversible Pre-Context PII Redaction Proxy & Indirect Prompt-Injection Firewall.

    Maintains a deterministic bidirectional vault mapping raw PII values to typed
    placeholders (`<PII:SSN_001>`, `<PII:AWS_KEY_001>`, etc.) so that multi-turn
    reasoning preserves entity identity without leaking sensitive values into the
    LLM context window or unauthorized downstream tools.
    """

    def __init__(
        self,
        *,
        vault_secret: str | bytes = "agent-guard-default-vault-hmac-key-2026",
        tool_rehydration_policy: Optional[dict[str, set[PIICategory | str]]] = None,
        block_threshold: float = 0.75,
    ) -> None:
        if isinstance(vault_secret, str):
            vault_secret = vault_secret.encode("utf-8")
        self._vault_secret = vault_secret
        self.block_threshold = block_threshold

        # Normalize tool rehydration policy: tool_pattern -> set[PIICategory]
        self._tool_policies: dict[str, set[PIICategory]] = {}
        if tool_rehydration_policy:
            for tool_name, categories in tool_rehydration_policy.items():
                normalized_cats: set[PIICategory] = set()
                for cat in categories:
                    normalized_cats.add(cat if isinstance(cat, PIICategory) else PIICategory(cat))
                self._tool_policies[tool_name] = normalized_cats

        # Deterministic bidirectional vault
        self._value_to_placeholder: dict[tuple[PIICategory, str], str] = {}
        self._placeholder_to_entry: dict[str, tuple[PIICategory, str]] = {}
        self._category_counters: dict[PIICategory, int] = {cat: 0 for cat in PIICategory}

    def register_tool_policy(
        self,
        tool_name: str,
        allowed_categories: set[PIICategory | str] | list[PIICategory | str],
    ) -> None:
        """Grant a downstream tool permission to re-hydrate specific PII categories."""
        self._tool_policies[tool_name] = {
            c if isinstance(c, PIICategory) else PIICategory(c) for c in allowed_categories
        }

    def _get_or_create_placeholder(self, category: PIICategory, raw_value: str) -> str:
        key = (category, raw_value)
        existing = self._value_to_placeholder.get(key)
        if existing is not None:
            return existing

        self._category_counters[category] += 1
        index = self._category_counters[category]
        placeholder = f"<PII:{category.token_prefix}_{index:03d}>"
        self._value_to_placeholder[key] = placeholder
        self._placeholder_to_entry[placeholder] = (category, raw_value)
        return placeholder

    def _compute_value_hmac(self, raw_value: str) -> str:
        return hmac.new(self._vault_secret, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def redact_text(self, text: str) -> RedactionResult:
        """
        Scan `text` for sensitive PII entities and replace them with deterministic
        placeholders (`<PII:SSN_001>`, `<PII:AWS_KEY_001>`, etc.).
        """
        if not text:
            return RedactionResult(
                original_length=0,
                redacted_text="",
                matches=(),
                counts_by_category={},
            )

        # Collect non-overlapping candidate spans prioritized by pattern specificity
        occupied: list[tuple[int, int]] = []
        raw_detections: list[tuple[int, int, PIICategory, str]] = []

        for category, pattern in _PII_PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                # Skip if overlapping with an already claimed higher-priority span
                if any(not (end <= occ_start or start >= occ_end) for occ_start, occ_end in occupied):
                    continue
                occupied.append((start, end))
                raw_detections.append((start, end, category, match.group(0)))

        raw_detections.sort(key=lambda item: item[0])

        out_parts: list[str] = []
        cursor = 0
        pii_matches: list[PIIMatch] = []
        counts: dict[str, int] = {}

        for start, end, category, raw_val in raw_detections:
            out_parts.append(text[cursor:start])
            placeholder = self._get_or_create_placeholder(category, raw_val)
            out_parts.append(placeholder)
            cursor = end

            counts[category.value] = counts.get(category.value, 0) + 1
            pii_matches.append(
                PIIMatch(
                    category=category,
                    placeholder=placeholder,
                    start=start,
                    end=end,
                    value_hmac=self._compute_value_hmac(raw_val),
                )
            )

        out_parts.append(text[cursor:])
        return RedactionResult(
            original_length=len(text),
            redacted_text="".join(out_parts),
            matches=tuple(pii_matches),
            counts_by_category=counts,
        )

    def _is_category_allowed_for_tool(self, tool_name: str, category: PIICategory) -> bool:
        if tool_name in self._tool_policies:
            return category in self._tool_policies[tool_name]
        # Support wildcard prefix policies like "billing:*"
        for pat, allowed_cats in self._tool_policies.items():
            if pat.endswith("*") and tool_name.startswith(pat[:-1]):
                return category in allowed_cats
        return False

    def rehydrate_for_tool(
        self,
        payload: Any,
        *,
        tool_name: str,
    ) -> RehydrationResult:
        """
        Selectively re-hydrate PII placeholders inside `payload` (str, dict, list)
        only for categories explicitly authorized for `tool_name`.
        Unauthorized placeholders remain tokenized in the output.
        """
        rehydrated_tokens: list[str] = []
        blocked_tokens: list[str] = []

        def _transform(node: Any) -> Any:
            if isinstance(node, str):
                def _replace_match(m: re.Match[str]) -> str:
                    token = m.group(0)
                    vault_entry = self._placeholder_to_entry.get(token)
                    if vault_entry is None:
                        return token
                    category, raw_val = vault_entry
                    if self._is_category_allowed_for_tool(tool_name, category):
                        if token not in rehydrated_tokens:
                            rehydrated_tokens.append(token)
                        return raw_val
                    else:
                        if token not in blocked_tokens:
                            blocked_tokens.append(token)
                        return token

                return _PLACEHOLDER_PATTERN.sub(_replace_match, node)
            if isinstance(node, dict):
                return {k: _transform(v) for k, v in node.items()}
            if isinstance(node, list):
                return [_transform(item) for item in node]
            if isinstance(node, tuple):
                return tuple(_transform(item) for item in node)
            return node

        transformed = _transform(payload)
        return RehydrationResult(
            tool_name=tool_name,
            rehydrated_payload=transformed,
            rehydrated_tokens=tuple(rehydrated_tokens),
            blocked_tokens=tuple(blocked_tokens),
        )

    def _detect_base64_smuggling(self, text: str) -> list[str]:
        """Check base64-encoded segments for hidden prompt injection instructions."""
        hits: list[str] = []
        for match in _BASE64_CANDIDATE_RE.finditer(text):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if len(decoded) < 12:
                continue
            for rule_name, _, pattern in _INJECTION_RULES:
                if pattern.search(decoded):
                    hits.append(f"BASE64_SMUGGLED_{rule_name}")
        return hits

    def inspect_and_sanitize(
        self,
        content: str,
        *,
        source: str = "tool_output",
        raise_on_block: bool = False,
    ) -> FirewallInspectionResult:
        """
        Inspect untrusted content (retrieved documents, tool outputs, A2A messages,
        or user inputs) for indirect prompt injection, tool-schema fuzzing, and PII.

        1. Evaluates multi-layer prompt injection & fuzzer rules (including Base64 decoding).
        2. Sanitizes malicious instruction blocks and neutralizes exfiltration beacons.
        3. Runs pre-context PII redaction on the remaining text.
        """
        matched_rules: list[str] = []
        max_score = 0.0
        working_text = content

        for rule_name, weight, pattern in _INJECTION_RULES:
            if pattern.search(working_text):
                matched_rules.append(rule_name)
                max_score = max(max_score, weight)
                working_text = pattern.sub(f"[FIREWALL_QUARANTINED:{rule_name}]", working_text)

        b64_hits = self._detect_base64_smuggling(content)
        if b64_hits:
            matched_rules.extend(b64_hits)
            max_score = max(max_score, 0.93)
            working_text = _BASE64_CANDIDATE_RE.sub("[FIREWALL_QUARANTINED:BASE64_PAYLOAD]", working_text)

        # Combine multiple distinct rule hits into a boosted risk score capped at 1.0
        if len(matched_rules) > 1:
            risk_score = min(1.0, round(max_score + 0.03 * (len(matched_rules) - 1), 4))
        else:
            risk_score = round(max_score, 4)

        is_blocked = risk_score >= self.block_threshold
        redaction = self.redact_text(working_text)

        result = FirewallInspectionResult(
            source=source,
            is_blocked=is_blocked,
            risk_score=risk_score,
            matched_rules=tuple(matched_rules),
            sanitized_text=redaction.redacted_text,
            redaction_result=redaction,
        )
        if is_blocked and raise_on_block:
            raise PromptInjectionError(
                f"Blocked untrusted content from '{source}' (risk_score={risk_score}, rules={matched_rules})"
            )
        return result
