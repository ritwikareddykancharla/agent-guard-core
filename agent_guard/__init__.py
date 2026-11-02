"""
AgentGuard & ContextCore
========================

Production-grade Zero-Trust AI Agent Identity, Scoped A2A Delegation,
Just-In-Time (JIT) Approval Proxy, Reversible Pre-Context PII Firewall,
3-Tier Hierarchical Memory MCP Server, and Multi-Provider Model Gateway.
"""

from .identity_delegation import (
    AuditLogEntry,
    DelegationClaims,
    JITApprovalRequest,
    JITApprovalStatus,
    PolicyDecision,
    ScopeEscalationError,
    SignedCapabilityToken,
    TamperEvidentAuditLog,
    TokenVerificationError,
    ZeroTrustPolicyEngine,
)
from .memory_mcp import (
    EpisodicSegment,
    EvictionBenchmarkResult,
    HierarchicalMemoryMCPServer,
    MemoryTurn,
    SemanticFact,
)
from .model_gateway import (
    CostKillSwitchError,
    GatewayRequest,
    GatewayResponse,
    ModelTier,
    MultiModelGateway,
    RateLimitExceededError,
    RunawayLoopError,
    SemanticCache,
)
from .pii_firewall import (
    FirewallInspectionResult,
    PIICategory,
    PIIFirewall,
    PIIMatch,
    PromptInjectionError,
    RedactionResult,
    RehydrationResult,
)

__version__ = "1.0.0"

__all__ = [
    "AuditLogEntry",
    "CostKillSwitchError",
    "DelegationClaims",
    "EpisodicSegment",
    "EvictionBenchmarkResult",
    "FirewallInspectionResult",
    "GatewayRequest",
    "GatewayResponse",
    "HierarchicalMemoryMCPServer",
    "JITApprovalRequest",
    "JITApprovalStatus",
    "MemoryTurn",
    "ModelTier",
    "MultiModelGateway",
    "PIICategory",
    "PIIFirewall",
    "PIIMatch",
    "PolicyDecision",
    "PromptInjectionError",
    "RateLimitExceededError",
    "RedactionResult",
    "RehydrationResult",
    "RunawayLoopError",
    "ScopeEscalationError",
    "SemanticCache",
    "SemanticFact",
    "SignedCapabilityToken",
    "TamperEvidentAuditLog",
    "TokenVerificationError",
    "ZeroTrustPolicyEngine",
]
