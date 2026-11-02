"""
Cryptographic Agent Identity, Scoped A2A Delegation & JIT Approval Proxy
=========================================================================

Implements:
1. HMAC-SHA256 Signed Capability Tokens binding human principal, agent identity,
   parent agent lineage (A2A handoffs), allowed tools, resource ARN patterns,
   cost ceiling, and expiration timestamps.
2. Strict Scope Attenuation on Agent-to-Agent (A2A) handoffs guaranteeing that
   sub-agents can never escalate tool, resource, budget, or TTL privileges.
3. Just-In-Time (JIT) Approval state machine for high-risk actions
   (DELETE, IAM_MUTATE, WIRE_TRANSFER, PROD_DEPLOY) requiring cryptographic
   human-in-the-loop sign-off before execution.
4. Tamper-evident SHA-256 hash-chained attribution audit log recording
   human_actor, delegated_agent_actor, parent_agent_actor, and approver_actor.
"""

from __future__ import annotations

import base64
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
import fnmatch
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Callable, Optional


class TokenVerificationError(PermissionError):
    """Raised when a capability token fails cryptographic verification or is expired."""


class ScopeEscalationError(PermissionError):
    """Raised when an A2A delegation or tool invocation attempts privilege escalation."""


class JITApprovalStatus( str, Enum):
    """Lifecycle states for Just-In-Time (JIT) human approval workflows."""

    PENDING_JIT_APPROVAL = "PENDING_JIT_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"


HIGH_RISK_TOOL_MARKERS: tuple[str, ...] = (
    "DELETE",
    "IAM_MUTATE",
    "WIRE_TRANSFER",
    "PROD_DEPLOY",
)


def _canonical_json(data: dict[str, Any]) -> bytes:
    """Deterministic JSON serialization for cryptographic signing and hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def is_glob_subsumed(child_pattern: str, parent_patterns: tuple[str, ...]) -> bool:
    """
    Verify that `child_pattern` is strictly subsumed by at least one pattern in
    `parent_patterns` without introducing broader wildcards.

    By replacing wildcards in `child_pattern` with literal sentinel tokens and
    testing `fnmatchcase` against each `parent_pattern`, a child pattern containing
    `*` or `?` can only match a parent pattern that also permits arbitrary characters
    at that exact position.
    """
    if not child_pattern or not parent_patterns:
        return False
    # Reject character-range brackets in child patterns unless identical to parent
    has_brackets = "[" in child_pattern or "]" in child_pattern
    sentinel_child = (
        child_pattern.replace("*", "__AG_STAR_SENTINEL__")
        .replace("?", "__AG_QMARK_SENTINEL__")
    )
    for parent in parent_patterns:
        if child_pattern == parent:
            return True
        if has_brackets:
            continue
        if fnmatch.fnmatchcase(sentinel_child, parent):
            return True
    return False


@dataclass(frozen=True)
class DelegationClaims:
    """Immutable claims bound into a cryptographic agent capability token."""

    token_id: str
    human_principal_id: str
    agent_id: str
    parent_agent_id: Optional[str]
    allowed_tools: tuple[str, ...]
    resource_arn_patterns: tuple[str, ...]
    max_cost_usd: float
    issued_at: float
    expires_at: float
    delegation_depth: int = 0
    chain_of_custody: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "human_principal_id": self.human_principal_id,
            "agent_id": self.agent_id,
            "parent_agent_id": self.parent_agent_id,
            "allowed_tools": list(self.allowed_tools),
            "resource_arn_patterns": list(self.resource_arn_patterns),
            "max_cost_usd": round(float(self.max_cost_usd), 6),
            "issued_at": round(float(self.issued_at), 6),
            "expires_at": round(float(self.expires_at), 6),
            "delegation_depth": int(self.delegation_depth),
            "chain_of_custody": list(self.chain_of_custody),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> DelegationClaims:
        return cls(
            token_id=str(payload["token_id"]),
            human_principal_id=str(payload["human_principal_id"]),
            agent_id=str(payload["agent_id"]),
            parent_agent_id=payload.get("parent_agent_id"),
            allowed_tools=tuple(payload["allowed_tools"]),
            resource_arn_patterns=tuple(payload["resource_arn_patterns"]),
            max_cost_usd=float(payload["max_cost_usd"]),
            issued_at=float(payload["issued_at"]),
            expires_at=float(payload["expires_at"]),
            delegation_depth=int(payload.get("delegation_depth", 0)),
            chain_of_custody=tuple(payload.get("chain_of_custody", ())),
        )


@dataclass(frozen=True)
class SignedCapabilityToken:
    """HMAC-SHA256 signed capability token supporting compact serialization."""

    claims: DelegationClaims
    signature: str
    algorithm: str = "HMAC-SHA256"

    def to_compact(self) -> str:
        """Encode as URL-safe compact token: header.payload.signature."""
        header = {"alg": self.algorithm, "typ": "AGY-CAP+JWT"}
        header_b64 = base64.urlsafe_b64encode(_canonical_json(header)).decode("ascii").rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(_canonical_json(self.claims.to_dict())).decode("ascii").rstrip("=")
        return f"{header_b64}.{payload_b64}.{self.signature}"

    @classmethod
    def from_compact(cls, compact_token: str) -> SignedCapabilityToken:
        """Deserialize a compact capability token (must still be verified before use)."""
        parts = compact_token.split(".")
        if len(parts) != 3:
            raise TokenVerificationError("Malformed compact capability token structure")
        header_b64, payload_b64, signature = parts
        try:
            header_pad = header_b64 + "=" * (-len(header_b64) % 4)
            payload_pad = payload_b64 + "=" * (-len(payload_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_pad.encode("ascii")))
            payload = json.loads(base64.urlsafe_b64decode(payload_pad.encode("ascii")))
        except Exception as exc:
            raise TokenVerificationError(f"Failed to decode compact token payload: {exc}") from exc

        if header.get("alg") != "HMAC-SHA256":
            raise TokenVerificationError(f"Unsupported token algorithm: {header.get('alg')}")
        return cls(
            claims=DelegationClaims.from_dict(payload),
            signature=signature,
            algorithm="HMAC-SHA256",
        )


@dataclass(frozen=True)
class AuditLogEntry:
    """Single immutable record in the SHA-256 hash-chained attribution log."""

    entry_id: str
    sequence_no: int
    timestamp: float
    event_type: str
    human_actor: str
    delegated_agent_actor: str
    parent_agent_actor: Optional[str]
    approver_actor: Optional[str]
    chain_of_custody: tuple[str, ...]
    tool_name: str
    resource_arn: str
    decision: str
    reason: str
    metadata: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def compute_expected_hash(self) -> str:
        payload = {
            "entry_id": self.entry_id,
            "sequence_no": self.sequence_no,
            "timestamp": round(self.timestamp, 6),
            "event_type": self.event_type,
            "human_actor": self.human_actor,
            "delegated_agent_actor": self.delegated_agent_actor,
            "parent_agent_actor": self.parent_agent_actor,
            "approver_actor": self.approver_actor,
            "chain_of_custody": list(self.chain_of_custody),
            "tool_name": self.tool_name,
            "resource_arn": self.resource_arn,
            "decision": self.decision,
            "reason": self.reason,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


class TamperEvidentAuditLog:
    """
    Append-only, SHA-256 hash-chained audit log that provides cryptographic proof
    of attribution across human principals, delegated agents, and JIT approvers.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._entries: list[AuditLogEntry] = []

    @property
    def entries(self) -> list[AuditLogEntry]:
        return list(self._entries)

    def append(
        self,
        *,
        event_type: str,
        human_actor: str,
        delegated_agent_actor: str,
        parent_agent_actor: Optional[str],
        approver_actor: Optional[str],
        chain_of_custody: tuple[str, ...],
        tool_name: str,
        resource_arn: str,
        decision: str,
        reason: str,
        metadata: Optional[dict[str, Any]] = None,
        now: Optional[float] = None,
    ) -> AuditLogEntry:
        seq_no = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        ts = round(now if now is not None else time.time(), 6)
        entry_id = f"audit-{seq_no:05d}-{uuid.uuid4().hex[:8]}"
        meta = dict(metadata) if metadata else {}

        provisional = AuditLogEntry(
            entry_id=entry_id,
            sequence_no=seq_no,
            timestamp=ts,
            event_type=event_type,
            human_actor=human_actor,
            delegated_agent_actor=delegated_agent_actor,
            parent_agent_actor=parent_agent_actor,
            approver_actor=approver_actor,
            chain_of_custody=tuple(chain_of_custody),
            tool_name=tool_name,
            resource_arn=resource_arn,
            decision=decision,
            reason=reason,
            metadata=meta,
            prev_hash=prev_hash,
            entry_hash="",
        )
        computed_hash = provisional.compute_expected_hash()
        final_entry = dataclasses.replace(provisional, entry_hash=computed_hash)
        self._entries.append(final_entry)
        return final_entry

    def verify_integrity(self) -> tuple[bool, Optional[int], str]:
        """
        Verify the cryptographic hash chain from genesis to head.
        Returns (is_valid, failed_sequence_no, diagnostic_message).
        """
        expected_prev = self.GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.sequence_no != idx:
                return False, idx, f"Sequence number mismatch at index {idx}"
            if entry.prev_hash != expected_prev:
                return False, idx, f"Broken prev_hash link at entry {entry.entry_id}"
            recomputed = entry.compute_expected_hash()
            if not hmac.compare_digest(entry.entry_hash, recomputed):
                return False, idx, f"Entry hash tampering detected at entry {entry.entry_id}"
            expected_prev = entry.entry_hash
        return True, None, f"Verified {len(self._entries)} hash-chained entries"


@dataclass
class JITApprovalRequest:
    """State record for a high-risk tool invocation suspended for human sign-off."""

    request_id: str
    token_id: str
    human_principal_id: str
    agent_id: str
    parent_agent_id: Optional[str]
    chain_of_custody: tuple[str, ...]
    tool_name: str
    resource_arn: str
    arguments: dict[str, Any]
    estimated_cost_usd: float
    status: JITApprovalStatus
    created_at: float
    expires_at: float
    approver_principal_id: Optional[str] = None
    approver_signature: Optional[str] = None
    approval_reason: Optional[str] = None
    decided_at: Optional[float] = None


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating a tool execution request through ZeroTrustPolicyEngine."""

    allowed: bool
    status: str
    reason: str
    token_id: str
    human_actor: str
    delegated_agent_actor: str
    parent_agent_actor: Optional[str]
    approver_actor: Optional[str]
    jit_request_id: Optional[str] = None
    audit_entry_hash: Optional[str] = None
    execution_output: Any = None


class ZeroTrustPolicyEngine:
    """
    Zero-Trust Identity & Access Governance engine for autonomous AI agents.

    Enforces:
    - HMAC-SHA256 capability token issuance and constant-time verification
    - Monotonic scope attenuation across multi-hop Agent-to-Agent (A2A) handoffs
    - Automatic JIT suspension for high-risk actions (DELETE, IAM_MUTATE, WIRE_TRANSFER, PROD_DEPLOY)
    - Cryptographically signed human approver release and tamper-evident audit logging
    """

    def __init__(
        self,
        signing_secret: str | bytes,
        *,
        max_delegation_depth: int = 4,
        high_risk_markers: tuple[str, ...] = HIGH_RISK_TOOL_MARKERS,
        jit_ttl_seconds: float = 900.0,
    ) -> None:
        if isinstance(signing_secret, str):
            signing_secret = signing_secret.encode("utf-8")
        if len(signing_secret) < 16:
            raise ValueError("signing_secret must be at least 16 bytes for HMAC-SHA256")
        self._secret: bytes = signing_secret
        self.max_delegation_depth = max_delegation_depth
        self.high_risk_markers = tuple(m.upper() for m in high_risk_markers)
        self.jit_ttl_seconds = jit_ttl_seconds
        self.audit_log = TamperEvidentAuditLog()
        self._jit_requests: dict[str, JITApprovalRequest] = {}
        self._revoked_token_ids: set[str] = set()
        self._spent_by_token: dict[str, float] = {}

    def _compute_signature(self, claims: DelegationClaims) -> str:
        return hmac.new(
            self._secret,
            _canonical_json(claims.to_dict()),
            hashlib.sha256,
        ).hexdigest()

    def _compute_jit_approval_signature(
        self,
        request_id: str,
        approver_id: str,
        status: JITApprovalStatus,
        reason: str,
        decided_at: float,
    ) -> str:
        payload = {
            "request_id": request_id,
            "approver_id": approver_id,
            "status": status.value,
            "reason": reason,
            "decided_at": round(decided_at, 6),
        }
        return hmac.new(
            self._secret,
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

    def issue_root_token(
        self,
        *,
        human_principal_id: str,
        agent_id: str,
        allowed_tools: list[str] | tuple[str, ...],
        resource_arn_patterns: list[str] | tuple[str, ...],
        max_cost_usd: float,
        ttl_seconds: float = 3600.0,
        now: Optional[float] = None,
    ) -> SignedCapabilityToken:
        """Issue a root capability token from a human principal to a primary agent."""
        if not human_principal_id or not agent_id:
            raise ValueError("human_principal_id and agent_id are required")
        if max_cost_usd <= 0:
            raise ValueError("max_cost_usd must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        ts = round(now if now is not None else time.time(), 6)
        claims = DelegationClaims(
            token_id=f"cap-{uuid.uuid4().hex[:12]}",
            human_principal_id=human_principal_id,
            agent_id=agent_id,
            parent_agent_id=None,
            allowed_tools=tuple(allowed_tools),
            resource_arn_patterns=tuple(resource_arn_patterns),
            max_cost_usd=round(float(max_cost_usd), 6),
            issued_at=ts,
            expires_at=round(ts + ttl_seconds, 6),
            delegation_depth=0,
            chain_of_custody=(human_principal_id, agent_id),
        )
        sig = self._compute_signature(claims)
        token = SignedCapabilityToken(claims=claims, signature=sig)

        self.audit_log.append(
            event_type="ISSUE_ROOT_TOKEN",
            human_actor=human_principal_id,
            delegated_agent_actor=agent_id,
            parent_agent_actor=None,
            approver_actor=None,
            chain_of_custody=claims.chain_of_custody,
            tool_name="sts:issue_root_token",
            resource_arn=",".join(claims.resource_arn_patterns),
            decision="ALLOW",
            reason=f"Issued root capability token {claims.token_id}",
            metadata={"max_cost_usd": claims.max_cost_usd, "expires_at": claims.expires_at},
            now=ts,
        )
        return token

    def verify_token(
        self,
        token: SignedCapabilityToken,
        *,
        now: Optional[float] = None,
    ) -> DelegationClaims:
        """
        Cryptographically verify HMAC-SHA256 signature, revocation state, and TTL.
        Raises TokenVerificationError if tampered, revoked, or expired.
        """
        if token.claims.token_id in self._revoked_token_ids:
            raise TokenVerificationError(f"Token {token.claims.token_id} has been revoked")

        expected_sig = self._compute_signature(token.claims)
        if not hmac.compare_digest(token.signature, expected_sig):
            raise TokenVerificationError(
                f"Cryptographic HMAC-SHA256 signature verification failed for token {token.claims.token_id}"
            )

        current_time = now if now is not None else time.time()
        if current_time > token.claims.expires_at:
            raise TokenVerificationError(
                f"Token {token.claims.token_id} expired at {token.claims.expires_at} (now={current_time})"
            )

        if token.claims.delegation_depth > self.max_delegation_depth:
            raise TokenVerificationError(
                f"Token delegation_depth {token.claims.delegation_depth} exceeds max {self.max_delegation_depth}"
            )

        return token.claims

    def revoke_token(self, token_id: str) -> None:
        """Immediately revoke a capability token ID."""
        self._revoked_token_ids.add(token_id)

    def delegate_a2a(
        self,
        *,
        parent_token: SignedCapabilityToken,
        child_agent_id: str,
        requested_tools: list[str] | tuple[str, ...],
        requested_resource_arn_patterns: list[str] | tuple[str, ...],
        requested_max_cost_usd: float,
        requested_ttl_seconds: Optional[float] = None,
        now: Optional[float] = None,
    ) -> SignedCapabilityToken:
        """
        Mint an attenuated sub-agent capability token for an Agent-to-Agent (A2A) handoff.

        Enforces strict monotonic scope attenuation:
        - Every requested tool pattern must be subsumed by `parent_token.claims.allowed_tools`
        - Every requested resource ARN pattern must be subsumed by `parent_token.claims.resource_arn_patterns`
        - `requested_max_cost_usd` cannot exceed parent's remaining cost budget
        - Expiration cannot exceed parent's `expires_at`
        - Delegation depth cannot exceed `max_delegation_depth`
        """
        ts = round(now if now is not None else time.time(), 6)
        parent_claims = self.verify_token(parent_token, now=ts)

        next_depth = parent_claims.delegation_depth + 1
        if next_depth > self.max_delegation_depth:
            self._log_escalation_attempt(
                parent_claims,
                child_agent_id,
                f"A2A delegation depth {next_depth} exceeds max limit {self.max_delegation_depth}",
                ts,
            )
            raise ScopeEscalationError(
                f"A2A delegation depth {next_depth} exceeds maximum {self.max_delegation_depth}"
            )

        if not requested_tools:
            raise ScopeEscalationError("Child delegation must specify at least one allowed tool")
        if not requested_resource_arn_patterns:
            raise ScopeEscalationError("Child delegation must specify at least one resource ARN pattern")

        # 1. Verify strict tool scope attenuation
        for tool_pat in requested_tools:
            if not is_glob_subsumed(tool_pat, parent_claims.allowed_tools):
                reason = (
                    f"A2A tool privilege escalation blocked: child '{child_agent_id}' requested "
                    f"tool '{tool_pat}' outside parent '{parent_claims.agent_id}' scope {parent_claims.allowed_tools}"
                )
                self._log_escalation_attempt(parent_claims, child_agent_id, reason, ts)
                raise ScopeEscalationError(reason)

        # 2. Verify strict resource ARN scope attenuation
        for arn_pat in requested_resource_arn_patterns:
            if not is_glob_subsumed(arn_pat, parent_claims.resource_arn_patterns):
                reason = (
                    f"A2A resource privilege escalation blocked: child '{child_agent_id}' requested "
                    f"ARN '{arn_pat}' outside parent '{parent_claims.agent_id}' scope {parent_claims.resource_arn_patterns}"
                )
                self._log_escalation_attempt(parent_claims, child_agent_id, reason, ts)
                raise ScopeEscalationError(reason)

        # 3. Verify cost budget attenuation
        parent_spent = self._spent_by_token.get(parent_claims.token_id, 0.0)
        parent_remaining = round(parent_claims.max_cost_usd - parent_spent, 6)
        if requested_max_cost_usd <= 0 or requested_max_cost_usd > parent_remaining + 1e-9:
            reason = (
                f"A2A budget escalation blocked: child '{child_agent_id}' requested "
                f"${requested_max_cost_usd:.4f} > parent remaining budget ${parent_remaining:.4f}"
            )
            self._log_escalation_attempt(parent_claims, child_agent_id, reason, ts)
            raise ScopeEscalationError(reason)

        # 4. Verify expiration attenuation
        child_expires_at = (
            round(ts + requested_ttl_seconds, 6)
            if requested_ttl_seconds is not None
            else parent_claims.expires_at
        )
        if child_expires_at > parent_claims.expires_at + 1e-6:
            reason = (
                f"A2A TTL escalation blocked: child expires_at {child_expires_at} "
                f"exceeds parent expires_at {parent_claims.expires_at}"
            )
            self._log_escalation_attempt(parent_claims, child_agent_id, reason, ts)
            raise ScopeEscalationError(reason)

        child_claims = DelegationClaims(
            token_id=f"cap-{uuid.uuid4().hex[:12]}",
            human_principal_id=parent_claims.human_principal_id,
            agent_id=child_agent_id,
            parent_agent_id=parent_claims.agent_id,
            allowed_tools=tuple(requested_tools),
            resource_arn_patterns=tuple(requested_resource_arn_patterns),
            max_cost_usd=round(float(requested_max_cost_usd), 6),
            issued_at=ts,
            expires_at=child_expires_at,
            delegation_depth=next_depth,
            chain_of_custody=parent_claims.chain_of_custody + (child_agent_id,),
        )
        sig = self._compute_signature(child_claims)
        child_token = SignedCapabilityToken(claims=child_claims, signature=sig)

        self.audit_log.append(
            event_type="DELEGATE_A2A_TOKEN",
            human_actor=child_claims.human_principal_id,
            delegated_agent_actor=child_agent_id,
            parent_agent_actor=parent_claims.agent_id,
            approver_actor=None,
            chain_of_custody=child_claims.chain_of_custody,
            tool_name="sts:delegate_a2a",
            resource_arn=",".join(child_claims.resource_arn_patterns),
            decision="ALLOW",
            reason=(
                f"Attenuated A2A handoff {parent_claims.agent_id} -> {child_agent_id} "
                f"(depth={next_depth}, max_cost=${child_claims.max_cost_usd:.2f})"
            ),
            metadata={"parent_token_id": parent_claims.token_id, "child_token_id": child_claims.token_id},
            now=ts,
        )
        return child_token

    def _log_escalation_attempt(
        self,
        parent_claims: DelegationClaims,
        child_agent_id: str,
        reason: str,
        ts: float,
    ) -> None:
        self.audit_log.append(
            event_type="A2A_ESCALATION_BLOCKED",
            human_actor=parent_claims.human_principal_id,
            delegated_agent_actor=child_agent_id,
            parent_agent_actor=parent_claims.agent_id,
            approver_actor=None,
            chain_of_custody=parent_claims.chain_of_custody + (child_agent_id,),
            tool_name="sts:delegate_a2a",
            resource_arn="*",
            decision="DENY",
            reason=reason,
            now=ts,
        )

    def is_high_risk_tool(self, tool_name: str) -> bool:
        """Check whether a tool name matches any high-risk operation marker."""
        normalized = tool_name.upper().replace("-", "_")
        return any(marker in normalized for marker in self.high_risk_markers)

    def authorize_and_execute(
        self,
        *,
        token: SignedCapabilityToken,
        tool_name: str,
        resource_arn: str,
        arguments: Optional[dict[str, Any]] = None,
        estimated_cost_usd: float = 0.01,
        tool_fn: Optional[Callable[[dict[str, Any]], Any]] = None,
        jit_request_id: Optional[str] = None,
        now: Optional[float] = None,
    ) -> PolicyDecision:
        """
        Authorize a tool invocation under Zero-Trust capability rules and execute if permitted.

        High-risk tools (DELETE, IAM_MUTATE, WIRE_TRANSFER, PROD_DEPLOY) automatically
        suspend into `PENDING_JIT_APPROVAL` unless a valid `APPROVED` `jit_request_id`
        signed by an authorized human approver is presented.
        """
        ts = round(now if now is not None else time.time(), 6)
        args = dict(arguments) if arguments else {}

        try:
            claims = self.verify_token(token, now=ts)
        except TokenVerificationError as exc:
            entry = self.audit_log.append(
                event_type="TOKEN_VERIFICATION_FAILED",
                human_actor=token.claims.human_principal_id,
                delegated_agent_actor=token.claims.agent_id,
                parent_agent_actor=token.claims.parent_agent_id,
                approver_actor=None,
                chain_of_custody=token.claims.chain_of_custody,
                tool_name=tool_name,
                resource_arn=resource_arn,
                decision="DENY",
                reason=str(exc),
                now=ts,
            )
            return PolicyDecision(
                allowed=False,
                status="DENIED_INVALID_TOKEN",
                reason=str(exc),
                token_id=token.claims.token_id,
                human_actor=token.claims.human_principal_id,
                delegated_agent_actor=token.claims.agent_id,
                parent_agent_actor=token.claims.parent_agent_id,
                approver_actor=None,
                audit_entry_hash=entry.entry_hash,
            )

        # Check tool permission
        if not any(fnmatch.fnmatchcase(tool_name, pat) for pat in claims.allowed_tools):
            reason = f"Tool '{tool_name}' is not authorized by token scope {claims.allowed_tools}"
            entry = self.audit_log.append(
                event_type="TOOL_SCOPE_VIOLATION",
                human_actor=claims.human_principal_id,
                delegated_agent_actor=claims.agent_id,
                parent_agent_actor=claims.parent_agent_id,
                approver_actor=None,
                chain_of_custody=claims.chain_of_custody,
                tool_name=tool_name,
                resource_arn=resource_arn,
                decision="DENY",
                reason=reason,
                now=ts,
            )
            return PolicyDecision(
                allowed=False,
                status="DENIED_TOOL_SCOPE",
                reason=reason,
                token_id=claims.token_id,
                human_actor=claims.human_principal_id,
                delegated_agent_actor=claims.agent_id,
                parent_agent_actor=claims.parent_agent_id,
                approver_actor=None,
                audit_entry_hash=entry.entry_hash,
            )

        # Check resource ARN permission
        if not any(fnmatch.fnmatchcase(resource_arn, pat) for pat in claims.resource_arn_patterns):
            reason = f"Resource '{resource_arn}' is not authorized by ARN scope {claims.resource_arn_patterns}"
            entry = self.audit_log.append(
                event_type="RESOURCE_SCOPE_VIOLATION",
                human_actor=claims.human_principal_id,
                delegated_agent_actor=claims.agent_id,
                parent_agent_actor=claims.parent_agent_id,
                approver_actor=None,
                chain_of_custody=claims.chain_of_custody,
                tool_name=tool_name,
                resource_arn=resource_arn,
                decision="DENY",
                reason=reason,
                now=ts,
            )
            return PolicyDecision(
                allowed=False,
                status="DENIED_RESOURCE_SCOPE",
                reason=reason,
                token_id=claims.token_id,
                human_actor=claims.human_principal_id,
                delegated_agent_actor=claims.agent_id,
                parent_agent_actor=claims.parent_agent_id,
                approver_actor=None,
                audit_entry_hash=entry.entry_hash,
            )

        # Check cost budget
        current_spent = self._spent_by_token.get(claims.token_id, 0.0)
        if current_spent + estimated_cost_usd > claims.max_cost_usd + 1e-9:
            reason = (
                f"Estimated cost ${estimated_cost_usd:.4f} exceeds remaining token budget "
                f"${claims.max_cost_usd - current_spent:.4f}"
            )
            entry = self.audit_log.append(
                event_type="BUDGET_EXCEEDED",
                human_actor=claims.human_principal_id,
                delegated_agent_actor=claims.agent_id,
                parent_agent_actor=claims.parent_agent_id,
                approver_actor=None,
                chain_of_custody=claims.chain_of_custody,
                tool_name=tool_name,
                resource_arn=resource_arn,
                decision="DENY",
                reason=reason,
                now=ts,
            )
            return PolicyDecision(
                allowed=False,
                status="DENIED_BUDGET_EXCEEDED",
                reason=reason,
                token_id=claims.token_id,
                human_actor=claims.human_principal_id,
                delegated_agent_actor=claims.agent_id,
                parent_agent_actor=claims.parent_agent_id,
                approver_actor=None,
                audit_entry_hash=entry.entry_hash,
            )

        # Evaluate Just-In-Time (JIT) approval gate for high-risk tools
        approver_actor: Optional[str] = None
        if self.is_high_risk_tool(tool_name):
            if jit_request_id is None:
                req_id = f"jit-{uuid.uuid4().hex[:10]}"
                jit_req = JITApprovalRequest(
                    request_id=req_id,
                    token_id=claims.token_id,
                    human_principal_id=claims.human_principal_id,
                    agent_id=claims.agent_id,
                    parent_agent_id=claims.parent_agent_id,
                    chain_of_custody=claims.chain_of_custody,
                    tool_name=tool_name,
                    resource_arn=resource_arn,
                    arguments=args,
                    estimated_cost_usd=estimated_cost_usd,
                    status=JITApprovalStatus.PENDING_JIT_APPROVAL,
                    created_at=ts,
                    expires_at=round(ts + self.jit_ttl_seconds, 6),
                )
                self._jit_requests[req_id] = jit_req
                reason = (
                    f"High-risk tool '{tool_name}' suspended into {JITApprovalStatus.PENDING_JIT_APPROVAL.value} "
                    f"(request_id={req_id})"
                )
                entry = self.audit_log.append(
                    event_type="JIT_APPROVAL_SUSPENDED",
                    human_actor=claims.human_principal_id,
                    delegated_agent_actor=claims.agent_id,
                    parent_agent_actor=claims.parent_agent_id,
                    approver_actor=None,
                    chain_of_custody=claims.chain_of_custody,
                    tool_name=tool_name,
                    resource_arn=resource_arn,
                    decision=JITApprovalStatus.PENDING_JIT_APPROVAL.value,
                    reason=reason,
                    metadata={"jit_request_id": req_id, "arguments": args},
                    now=ts,
                )
                return PolicyDecision(
                    allowed=False,
                    status=JITApprovalStatus.PENDING_JIT_APPROVAL.value,
                    reason=reason,
                    token_id=claims.token_id,
                    human_actor=claims.human_principal_id,
                    delegated_agent_actor=claims.agent_id,
                    parent_agent_actor=claims.parent_agent_id,
                    approver_actor=None,
                    jit_request_id=req_id,
                    audit_entry_hash=entry.entry_hash,
                )

            # Verify existing JIT request
            jit_req = self._jit_requests.get(jit_request_id)
            if jit_req is None:
                raise PermissionError(f"Unknown JIT approval request_id: {jit_request_id}")

            if ts > jit_req.expires_at:
                jit_req.status = JITApprovalStatus.EXPIRED
                entry = self.audit_log.append(
                    event_type="JIT_APPROVAL_EXPIRED",
                    human_actor=claims.human_principal_id,
                    delegated_agent_actor=claims.agent_id,
                    parent_agent_actor=claims.parent_agent_id,
                    approver_actor=jit_req.approver_principal_id,
                    chain_of_custody=claims.chain_of_custody,
                    tool_name=tool_name,
                    resource_arn=resource_arn,
                    decision="DENY",
                    reason=f"JIT request {jit_request_id} expired",
                    now=ts,
                )
                return PolicyDecision(
                    allowed=False,
                    status=JITApprovalStatus.EXPIRED.value,
                    reason=f"JIT request {jit_request_id} expired",
                    token_id=claims.token_id,
                    human_actor=claims.human_principal_id,
                    delegated_agent_actor=claims.agent_id,
                    parent_agent_actor=claims.parent_agent_id,
                    approver_actor=jit_req.approver_principal_id,
                    jit_request_id=jit_request_id,
                    audit_entry_hash=entry.entry_hash,
                )

            if jit_req.status != JITApprovalStatus.APPROVED:
                entry = self.audit_log.append(
                    event_type="JIT_NOT_APPROVED",
                    human_actor=claims.human_principal_id,
                    delegated_agent_actor=claims.agent_id,
                    parent_agent_actor=claims.parent_agent_id,
                    approver_actor=jit_req.approver_principal_id,
                    chain_of_custody=claims.chain_of_custody,
                    tool_name=tool_name,
                    resource_arn=resource_arn,
                    decision="DENY",
                    reason=f"JIT request {jit_request_id} is in state {jit_req.status.value}",
                    now=ts,
                )
                return PolicyDecision(
                    allowed=False,
                    status=jit_req.status.value,
                    reason=f"JIT request {jit_request_id} is in state {jit_req.status.value}",
                    token_id=claims.token_id,
                    human_actor=claims.human_principal_id,
                    delegated_agent_actor=claims.agent_id,
                    parent_agent_actor=claims.parent_agent_id,
                    approver_actor=jit_req.approver_principal_id,
                    jit_request_id=jit_request_id,
                    audit_entry_hash=entry.entry_hash,
                )

            if (
                jit_req.token_id != claims.token_id
                or jit_req.tool_name != tool_name
                or jit_req.resource_arn != resource_arn
            ):
                raise ScopeEscalationError(
                    "JIT approval parameter mismatch: tool, resource, or token differs from approved request"
                )

            # Verify cryptographic signature of the human approver
            expected_jit_sig = self._compute_jit_approval_signature(
                jit_req.request_id,
                jit_req.approver_principal_id or "",
                JITApprovalStatus.APPROVED,
                jit_req.approval_reason or "",
                jit_req.decided_at or 0.0,
            )
            if not jit_req.approver_signature or not hmac.compare_digest(
                jit_req.approver_signature, expected_jit_sig
            ):
                raise TokenVerificationError("JIT approval signature verification failed")

            approver_actor = jit_req.approver_principal_id
            jit_req.status = JITApprovalStatus.EXECUTED

        # Record spend and execute tool
        self._spent_by_token[claims.token_id] = round(current_spent + estimated_cost_usd, 6)
        output = tool_fn(args) if tool_fn is not None else {"status": "ok", "tool": tool_name}

        entry = self.audit_log.append(
            event_type="TOOL_EXECUTED",
            human_actor=claims.human_principal_id,
            delegated_agent_actor=claims.agent_id,
            parent_agent_actor=claims.parent_agent_id,
            approver_actor=approver_actor,
            chain_of_custody=claims.chain_of_custody,
            tool_name=tool_name,
            resource_arn=resource_arn,
            decision="ALLOW",
            reason=(
                f"Executed with JIT approval {jit_request_id} by {approver_actor}"
                if approver_actor
                else "Executed within delegated capability scope"
            ),
            metadata={"cost_usd": estimated_cost_usd, "jit_request_id": jit_request_id},
            now=ts,
        )
        return PolicyDecision(
            allowed=True,
            status=JITApprovalStatus.EXECUTED.value if approver_actor else "EXECUTED",
            reason=entry.reason,
            token_id=claims.token_id,
            human_actor=claims.human_principal_id,
            delegated_agent_actor=claims.agent_id,
            parent_agent_actor=claims.parent_agent_id,
            approver_actor=approver_actor,
            jit_request_id=jit_request_id,
            audit_entry_hash=entry.entry_hash,
            execution_output=output,
        )

    def approve_jit_request(
        self,
        *,
        request_id: str,
        approver_principal_id: str,
        reason: str,
        now: Optional[float] = None,
    ) -> JITApprovalRequest:
        """Cryptographically sign and approve a pending JIT high-risk action request."""
        jit_req = self._jit_requests.get(request_id)
        if jit_req is None:
            raise KeyError(f"Unknown JIT request_id: {request_id}")
        if jit_req.status != JITApprovalStatus.PENDING_JIT_APPROVAL:
            raise ValueError(f"JIT request {request_id} cannot be approved from state {jit_req.status.value}")

        ts = round(now if now is not None else time.time(), 6)
        if ts > jit_req.expires_at:
            jit_req.status = JITApprovalStatus.EXPIRED
            raise TokenVerificationError(f"JIT request {request_id} has expired")

        sig = self._compute_jit_approval_signature(
            request_id=request_id,
            approver_id=approver_principal_id,
            status=JITApprovalStatus.APPROVED,
            reason=reason,
            decided_at=ts,
        )
        jit_req.status = JITApprovalStatus.APPROVED
        jit_req.approver_principal_id = approver_principal_id
        jit_req.approver_signature = sig
        jit_req.approval_reason = reason
        jit_req.decided_at = ts

        self.audit_log.append(
            event_type="JIT_APPROVAL_GRANTED",
            human_actor=jit_req.human_principal_id,
            delegated_agent_actor=jit_req.agent_id,
            parent_agent_actor=jit_req.parent_agent_id,
            approver_actor=approver_principal_id,
            chain_of_custody=jit_req.chain_of_custody,
            tool_name=jit_req.tool_name,
            resource_arn=jit_req.resource_arn,
            decision=JITApprovalStatus.APPROVED.value,
            reason=reason,
            metadata={"jit_request_id": request_id, "approver_signature": sig[:16] + "..."},
            now=ts,
        )
        return jit_req

    def deny_jit_request(
        self,
        *,
        request_id: str,
        approver_principal_id: str,
        reason: str,
        now: Optional[float] = None,
    ) -> JITApprovalRequest:
        """Deny a pending JIT high-risk action request and log attribution."""
        jit_req = self._jit_requests.get(request_id)
        if jit_req is None:
            raise KeyError(f"Unknown JIT request_id: {request_id}")
        if jit_req.status != JITApprovalStatus.PENDING_JIT_APPROVAL:
            raise ValueError(f"JIT request {request_id} cannot be denied from state {jit_req.status.value}")

        ts = round(now if now is not None else time.time(), 6)
        sig = self._compute_jit_approval_signature(
            request_id=request_id,
            approver_id=approver_principal_id,
            status=JITApprovalStatus.DENIED,
            reason=reason,
            decided_at=ts,
        )
        jit_req.status = JITApprovalStatus.DENIED
        jit_req.approver_principal_id = approver_principal_id
        jit_req.approver_signature = sig
        jit_req.approval_reason = reason
        jit_req.decided_at = ts

        self.audit_log.append(
            event_type="JIT_APPROVAL_DENIED",
            human_actor=jit_req.human_principal_id,
            delegated_agent_actor=jit_req.agent_id,
            parent_agent_actor=jit_req.parent_agent_id,
            approver_actor=approver_principal_id,
            chain_of_custody=jit_req.chain_of_custody,
            tool_name=jit_req.tool_name,
            resource_arn=jit_req.resource_arn,
            decision=JITApprovalStatus.DENIED.value,
            reason=reason,
            metadata={"jit_request_id": request_id},
            now=ts,
        )
        return jit_req

    def get_jit_request(self, request_id: str) -> JITApprovalRequest:
        if request_id not in self._jit_requests:
            raise KeyError(f"Unknown JIT request_id: {request_id}")
        return self._jit_requests[request_id]
