"""
3-Tier Hierarchical Agent Memory MCP Server (Working -> Episodic -> Semantic)
=============================================================================

Implements an MCP-compliant hierarchical memory architecture for long-horizon
autonomous agents:
- Tier 1 (Working Memory): Token-budgeted sliding window with priority pinning
  for system instructions, guardrails, and active tool schemas.
- Tier 2 (Episodic Memory): Automatic compaction/summarization of evicted
  conversational turns with exponential temporal decay and access reinforcement.
- Tier 3 (Semantic Memory): Hybrid TF-IDF + entity overlap cosine-similarity
  vector store for durable cross-session facts with cryptographic/turn provenance.
- Context Window Eviction Stress Harness: Plants enterprise "needle" facts
  (SLA constraints, security exceptions, ADRs, compliance rules) across 50+
  turns of distractor noise and benchmarks Recall@K, Token Compression Ratio,
  and Zero-Loss Eviction Accuracy against naive FIFO sliding windows.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import math
import re
import time
import uuid
from typing import Any, Optional


_WORD_RE = re.compile(r"[a-zA-Z0-9_.\-%$]+")
_ENTITY_RE = re.compile(
    r"\b(?:ADR-\d+|SEC-EXC-\d+|SLA-\d+|CVE-\d{4}-\d+|FIPS-\d+-\d+"
    r"|eu-central-1|us-east-1|us-west-2|ap-northeast-1"
    r"|\d+(?:\.\d+)?%|\$\d[\d,]*(?:\.\d+)?"
    r"|\d[\d,]*\s*(?:WCU|RCU|ms|minutes|req/s|GB|TB))\b",
    re.IGNORECASE,
)
_SALIENCE_KEYWORDS: frozenset[str] = frozenset(
    {
        "sla",
        "rto",
        "rpo",
        "uptime",
        "exception",
        "sec-exc",
        "adr",
        "mandate",
        "mandates",
        "compliance",
        "gdpr",
        "hipaa",
        "residency",
        "provisioned",
        "wcu",
        "threshold",
        "limit",
        "ceiling",
        "encryption",
        "kms",
        "hmac-sha256",
        "wire_transfer",
        "approval",
        "policy",
        "retention",
        "critical",
        "constraint",
    }
)
_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "or",
        "to",
        "of",
        "in",
        "on",
        "for",
        "with",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "this",
        "that",
        "it",
        "as",
        "at",
        "by",
        "from",
        "we",
        "our",
        "what",
        "which",
        "who",
        "how",
        "can",
        "will",
        "just",
        "now",
    }
)


def estimate_tokens(text: str) -> int:
    """Deterministic token count estimator (~0.75 words per token + punctuation)."""
    if not text:
        return 0
    words = text.split()
    return max(1, int(math.ceil(len(words) * 1.3)))


def tokenize_terms(text: str) -> list[str]:
    """Normalize text into alphanumeric/domain terms excluding stopwords."""
    raw = [t.lower().strip(".,;:!?()[]{}\"'") for t in _WORD_RE.findall(text)]
    return [t for t in raw if len(t) > 1 and t not in _STOPWORDS]


def extract_entities(text: str) -> tuple[str, ...]:
    """Extract structured technical entities, IDs, regions, percentages, and dollar caps."""
    found: list[str] = []
    for match in _ENTITY_RE.finditer(text):
        val = match.group(0)
        if val not in found:
            found.append(val)
    return tuple(found)


@dataclass
class MemoryTurn:
    """Single conversational or tool turn stored in Tier 1 Working Memory."""

    turn_id: str
    turn_index: int
    role: str
    content: str
    token_count: int
    timestamp: float
    pinned: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EpisodicSegment:
    """Compacted conversational segment stored in Tier 2 Episodic Memory."""

    segment_id: str
    source_turn_ids: tuple[str, ...]
    start_turn_index: int
    end_turn_index: int
    summary: str
    key_entities: tuple[str, ...]
    token_count: int
    created_at: float
    last_accessed_at: float
    access_count: int = 0

    def compute_temporal_score(
        self,
        *,
        base_similarity: float,
        current_turn_index: int,
        decay_lambda: float = 0.012,
        reinforcement_alpha: float = 0.08,
    ) -> float:
        """
        Compute temporally decayed relevance score with access reinforcement:
        score = similarity * exp(-lambda * age_in_turns) + alpha * ln(1 + access_count)
        """
        age_turns = max(0, current_turn_index - self.end_turn_index)
        temporal_factor = math.exp(-decay_lambda * age_turns)
        reinforcement = reinforcement_alpha * math.log1p(self.access_count)
        return round(base_similarity * temporal_factor + (reinforcement if base_similarity > 0.05 else 0.0), 6)


@dataclass(frozen=True)
class SemanticFact:
    """Durable cross-session knowledge record in Tier 3 Semantic Memory with provenance."""

    fact_id: str
    statement: str
    category: str
    entities: tuple[str, ...]
    source_turn_id: str
    source_turn_index: int
    session_id: str
    confidence: float
    created_at: float


@dataclass(frozen=True)
class RetrievedContextPackage:
    """Hydrated context package combining Tier 1, Tier 2, and Tier 3 memories."""

    query: str
    working_turns: tuple[MemoryTurn, ...]
    episodic_segments: tuple[tuple[EpisodicSegment, float], ...]
    semantic_facts: tuple[tuple[SemanticFact, float], ...]
    assembled_prompt: str
    assembled_token_count: int
    total_historical_tokens: int

    @property
    def compression_ratio(self) -> float:
        if self.assembled_token_count <= 0:
            return 1.0
        return round(self.total_historical_tokens / self.assembled_token_count, 3)


@dataclass(frozen=True)
class EvictionBenchmarkResult:
    """Metrics produced by the Context Window Eviction Stress Harness."""

    total_turns_ingested: int
    planted_needles_count: int
    working_token_budget: int
    total_raw_tokens: int
    assembled_context_tokens: int
    token_compression_ratio: float
    hierarchical_recall_at_k: float
    naive_window_recall_at_k: float
    zero_loss_eviction_accuracy: float
    evictions_triggered: int
    tier1_working_count: int
    tier2_episodic_count: int
    tier3_semantic_count: int
    per_needle_results: tuple[dict[str, Any], ...]


class HybridTFIDFIndex:
    """
    Lightweight standard-library TF-IDF + Entity Boost vector index for Tier 2 & Tier 3 retrieval.
    """

    def __init__(self) -> None:
        self._doc_terms: dict[str, Counter[str]] = {}
        self._doc_entities: dict[str, set[str]] = {}
        self._df: Counter[str] = Counter()

    def upsert(self, doc_id: str, text: str, entities: tuple[str, ...] = ()) -> None:
        if doc_id in self._doc_terms:
            for term in self._doc_terms[doc_id]:
                self._df[term] = max(0, self._df[term] - 1)
        terms = tokenize_terms(text)
        counts = Counter(terms)
        self._doc_terms[doc_id] = counts
        self._doc_entities[doc_id] = {e.lower() for e in entities} | {
            e.lower() for e in extract_entities(text)
        }
        for term in counts:
            self._df[term] += 1

    def score(self, query: str, doc_id: str) -> float:
        if doc_id not in self._doc_terms:
            return 0.0
        q_terms = Counter(tokenize_terms(query))
        if not q_terms:
            return 0.0
        d_terms = self._doc_terms[doc_id]
        if not d_terms:
            return 0.0

        num_docs = max(1, len(self._doc_terms))
        dot = 0.0
        q_norm_sq = 0.0
        d_norm_sq = 0.0

        for term, q_tf in q_terms.items():
            idf = math.log(1.0 + num_docs / (1.0 + self._df.get(term, 0)))
            q_w = (1.0 + math.log(q_tf)) * idf
            q_norm_sq += q_w * q_w
            if term in d_terms:
                d_w = (1.0 + math.log(d_terms[term])) * idf
                dot += q_w * d_w

        for term, d_tf in d_terms.items():
            idf = math.log(1.0 + num_docs / (1.0 + self._df.get(term, 0)))
            d_w = (1.0 + math.log(d_tf)) * idf
            d_norm_sq += d_w * d_w

        denom = math.sqrt(q_norm_sq) * math.sqrt(d_norm_sq)
        cosine = (dot / denom) if denom > 0 else 0.0

        # Boost exact entity matches (e.g. ADR-014, SEC-EXC-4092, eu-central-1)
        q_entities = {e.lower() for e in extract_entities(query)}
        q_words = set(q_terms.keys())
        doc_ents = self._doc_entities.get(doc_id, set())
        entity_overlap = len((q_entities | q_words) & doc_ents)
        entity_boost = min(0.35, 0.15 * entity_overlap)

        return min(1.0, round(cosine + entity_boost, 6))


class HierarchicalMemoryMCPServer:
    """
    3-Tier Hierarchical Agent Memory MCP Server (`Working -> Episodic -> Semantic`).

    Exposes both a direct Python API and Model Context Protocol (MCP) tool schemas
    (`list_tools`, `call_tool`) for seamless integration with agent orchestrators.
    """

    def __init__(
        self,
        *,
        session_id: str = "session-default",
        working_token_budget: int = 320,
        episodic_compaction_batch_size: int = 3,
        temporal_decay_lambda: float = 0.01,
    ) -> None:
        if working_token_budget < 40:
            raise ValueError("working_token_budget must be at least 40 tokens")
        self.session_id = session_id
        self.working_token_budget = working_token_budget
        self.episodic_compaction_batch_size = max(1, episodic_compaction_batch_size)
        self.temporal_decay_lambda = temporal_decay_lambda

        # Tier 1: Working Memory
        self._working_turns: list[MemoryTurn] = []
        self._eviction_buffer: list[MemoryTurn] = []

        # Tier 2: Episodic Memory
        self._episodic_segments: dict[str, EpisodicSegment] = {}
        self._episodic_index = HybridTFIDFIndex()

        # Tier 3: Semantic Memory
        self._semantic_facts: dict[str, SemanticFact] = {}
        self._semantic_index = HybridTFIDFIndex()

        # Telemetry
        self._turn_counter = 0
        self._total_historical_tokens = 0
        self._evictions_triggered = 0

    @property
    def working_turns(self) -> list[MemoryTurn]:
        return list(self._working_turns)

    @property
    def episodic_segments(self) -> list[EpisodicSegment]:
        return list(self._episodic_segments.values())

    @property
    def semantic_facts(self) -> list[SemanticFact]:
        return list(self._semantic_facts.values())

    def current_working_tokens(self) -> int:
        return sum(t.token_count for t in self._working_turns)

    def pin_system_instruction(
        self,
        content: str,
        *,
        role: str = "system",
        metadata: Optional[dict[str, Any]] = None,
    ) -> MemoryTurn:
        """Pin a system prompt or active tool schema in Tier 1 so it is never evicted."""
        return self.append_turn(
            role=role,
            content=content,
            pinned=True,
            metadata=metadata or {"pinned_reason": "system_or_tool_schema"},
        )

    def append_turn(
        self,
        *,
        role: str,
        content: str,
        pinned: bool = False,
        metadata: Optional[dict[str, Any]] = None,
        now: Optional[float] = None,
    ) -> MemoryTurn:
        """
        Append a turn to Tier 1 Working Memory. If total working tokens exceed
        `working_token_budget`, automatically evicts oldest unpinned turns into
        Tier 2 (Episodic) and extracts durable facts into Tier 3 (Semantic).
        """
        ts = round(now if now is not None else time.time(), 6)
        self._turn_counter += 1
        tok_count = estimate_tokens(content)
        self._total_historical_tokens += tok_count

        turn = MemoryTurn(
            turn_id=f"turn-{self._turn_counter:04d}",
            turn_index=self._turn_counter,
            role=role,
            content=content,
            token_count=tok_count,
            timestamp=ts,
            pinned=pinned,
            metadata=dict(metadata) if metadata else {},
        )
        self._working_turns.append(turn)
        self._enforce_working_budget(now=ts)
        return turn

    def _is_salient_turn(self, turn: MemoryTurn) -> tuple[bool, str]:
        """Determine whether an evicted turn contains durable enterprise facts for Tier 3."""
        if turn.metadata.get("salient_fact") or turn.metadata.get("category"):
            return True, str(turn.metadata.get("category", "enterprise_policy"))

        entities = extract_entities(turn.content)
        terms = set(tokenize_terms(turn.content))
        keyword_hits = terms & _SALIENCE_KEYWORDS

        if entities and keyword_hits:
            return True, "domain_constraint"
        if len(keyword_hits) >= 2:
            return True, "architectural_or_policy_fact"
        if any(e.upper().startswith(("ADR-", "SEC-EXC-", "SLA-", "CVE-")) for e in entities):
            return True, "governance_record"
        return False, ""

    def _enforce_working_budget(self, *, now: float) -> None:
        """Evict oldest unpinned turns when Tier 1 exceeds `working_token_budget`."""
        while self.current_working_tokens() > self.working_token_budget:
            evict_idx: Optional[int] = None
            for idx, candidate in enumerate(self._working_turns):
                if not candidate.pinned:
                    evict_idx = idx
                    break
            if evict_idx is None:
                # Only pinned turns remain; cannot evict pinned turns
                break

            evicted = self._working_turns.pop(evict_idx)
            self._evictions_triggered += 1
            self._eviction_buffer.append(evicted)

            # Promote salient facts to Tier 3 Semantic Memory before compaction
            is_salient, category = self._is_salient_turn(evicted)
            if is_salient:
                self.store_semantic_fact(
                    statement=evicted.content,
                    category=category,
                    source_turn_id=evicted.turn_id,
                    source_turn_index=evicted.turn_index,
                    confidence=0.95,
                    now=now,
                )

            if len(self._eviction_buffer) >= self.episodic_compaction_batch_size:
                self._flush_eviction_buffer_to_episodic(now=now)

        # Ensure any remaining evicted turns are also searchable in Tier 2
        if self._eviction_buffer:
            self._flush_eviction_buffer_to_episodic(now=now)

    def _flush_eviction_buffer_to_episodic(self, *, now: float) -> Optional[EpisodicSegment]:
        if not self._eviction_buffer:
            return None

        batch = list(self._eviction_buffer)
        self._eviction_buffer.clear()

        # Compaction: preserve high-density clauses and entities while stripping filler phrases
        compacted_lines: list[str] = []
        all_entities: list[str] = []
        for t in batch:
            ents = extract_entities(t.content)
            for e in ents:
                if e not in all_entities:
                    all_entities.append(e)
            is_salient, _ = self._is_salient_turn(t)
            if is_salient or ents:
                compacted_lines.append(f"[{t.turn_id}] {t.content.strip()}")
            else:
                # Extractive compression of routine chatter to first 12 words
                words = t.content.strip().split()
                snippet = " ".join(words[:12]) + ("..." if len(words) > 12 else "")
                compacted_lines.append(f"[{t.turn_id}] {snippet}")

        summary_text = " | ".join(compacted_lines)
        seg_id = f"epi-{batch[0].turn_index:04d}-{batch[-1].turn_index:04d}-{uuid.uuid4().hex[:6]}"
        segment = EpisodicSegment(
            segment_id=seg_id,
            source_turn_ids=tuple(t.turn_id for t in batch),
            start_turn_index=batch[0].turn_index,
            end_turn_index=batch[-1].turn_index,
            summary=summary_text,
            key_entities=tuple(all_entities),
            token_count=estimate_tokens(summary_text),
            created_at=now,
            last_accessed_at=now,
            access_count=0,
        )
        self._episodic_segments[seg_id] = segment
        self._episodic_index.upsert(seg_id, summary_text, segment.key_entities)
        return segment

    def store_semantic_fact(
        self,
        *,
        statement: str,
        category: str = "general_fact",
        source_turn_id: str = "manual",
        source_turn_index: int = 0,
        confidence: float = 0.95,
        now: Optional[float] = None,
    ) -> SemanticFact:
        """Explicitly or automatically store a durable fact in Tier 3 Semantic Memory."""
        ts = round(now if now is not None else time.time(), 6)
        entities = extract_entities(statement)
        fact_id = f"sem-{len(self._semantic_facts) + 1:04d}-{uuid.uuid4().hex[:6]}"
        fact = SemanticFact(
            fact_id=fact_id,
            statement=statement.strip(),
            category=category,
            entities=entities,
            source_turn_id=source_turn_id,
            source_turn_index=source_turn_index,
            session_id=self.session_id,
            confidence=round(float(confidence), 4),
            created_at=ts,
        )
        self._semantic_facts[fact_id] = fact
        self._semantic_index.upsert(fact_id, fact.statement, fact.entities)
        return fact

    def retrieve_context(
        self,
        query: str,
        *,
        top_k_semantic: int = 4,
        top_k_episodic: int = 3,
        now: Optional[float] = None,
    ) -> RetrievedContextPackage:
        """
        Query across all 3 memory tiers (Tier 1 Working + Tier 2 Episodic + Tier 3 Semantic)
        and assemble a token-efficient context package with provenance citations.
        """
        ts = round(now if now is not None else time.time(), 6)

        # Score Tier 3 Semantic Facts
        scored_semantic: list[tuple[SemanticFact, float]] = []
        for fact_id, fact in self._semantic_facts.items():
            sim = self._semantic_index.score(query, fact_id)
            if sim > 0.0:
                scored_semantic.append((fact, round(sim * fact.confidence, 6)))
        scored_semantic.sort(key=lambda item: item[1], reverse=True)
        top_semantic = tuple(scored_semantic[:top_k_semantic])

        # Score Tier 2 Episodic Segments with Temporal Decay
        scored_episodic: list[tuple[EpisodicSegment, float]] = []
        for seg_id, seg in self._episodic_segments.items():
            raw_sim = self._episodic_index.score(query, seg_id)
            if raw_sim > 0.0:
                decayed = seg.compute_temporal_score(
                    base_similarity=raw_sim,
                    current_turn_index=self._turn_counter,
                    decay_lambda=self.temporal_decay_lambda,
                )
                scored_episodic.append((seg, decayed))
        scored_episodic.sort(key=lambda item: item[1], reverse=True)
        top_episodic = tuple(scored_episodic[:top_k_episodic])

        # Update access stats for retrieved episodic segments
        for seg, _ in top_episodic:
            seg.access_count += 1
            seg.last_accessed_at = ts

        # Assemble structured context window
        sections: list[str] = []
        if top_semantic:
            sem_lines = [
                f"- [{f.fact_id} | src={f.source_turn_id} | cat={f.category}] {f.statement}"
                for f, _ in top_semantic
            ]
            sections.append("### Tier 3: Durable Semantic Facts (Provenance Indexed)\n" + "\n".join(sem_lines))

        if top_episodic:
            epi_lines = [
                f"- [{s.segment_id} | turns={s.start_turn_index}..{s.end_turn_index} | score={sc:.3f}] {s.summary}"
                for s, sc in top_episodic
            ]
            sections.append("### Tier 2: Compacted Episodic Memory\n" + "\n".join(epi_lines))

        working_lines = [
            f"- [{'PINNED' if t.pinned else t.turn_id} | {t.role}] {t.content}"
            for t in self._working_turns
        ]
        sections.append("### Tier 1: Active Working Memory Window\n" + "\n".join(working_lines))

        assembled_prompt = "\n\n".join(sections)
        assembled_tokens = estimate_tokens(assembled_prompt)

        return RetrievedContextPackage(
            query=query,
            working_turns=tuple(self._working_turns),
            episodic_segments=top_episodic,
            semantic_facts=top_semantic,
            assembled_prompt=assembled_prompt,
            assembled_token_count=assembled_tokens,
            total_historical_tokens=max(1, self._total_historical_tokens),
        )

    # -------------------------------------------------------------------------
    # MCP (Model Context Protocol) Server Interface
    # -------------------------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP-compliant tool definitions exposed by this memory server."""
        return [
            {
                "name": "memory_append_turn",
                "description": "Append a conversational or tool turn to Tier 1 Working Memory with optional priority pinning.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "enum": ["system", "user", "assistant", "tool"]},
                        "content": {"type": "string"},
                        "pinned": {"type": "boolean", "default": False},
                    },
                    "required": ["role", "content"],
                },
            },
            {
                "name": "memory_query_context",
                "description": "Retrieve hybrid context across Tier 1 Working, Tier 2 Episodic, and Tier 3 Semantic memory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "top_k_semantic": {"type": "integer", "default": 4},
                        "top_k_episodic": {"type": "integer", "default": 3},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "memory_store_semantic_fact",
                "description": "Store a durable cross-session fact with provenance in Tier 3 Semantic Memory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "string"},
                        "category": {"type": "string", "default": "enterprise_fact"},
                        "source_turn_id": {"type": "string", "default": "mcp_call"},
                    },
                    "required": ["statement"],
                },
            },
            {
                "name": "memory_inspect_tiers",
                "description": "Return token utilization and record counts across all 3 memory tiers.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def call_tool(self, name: str, arguments: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Execute an MCP tool call against the 3-Tier Hierarchical Memory server."""
        args = arguments or {}
        if name == "memory_append_turn":
            turn = self.append_turn(
                role=str(args["role"]),
                content=str(args["content"]),
                pinned=bool(args.get("pinned", False)),
            )
            return {
                "turn_id": turn.turn_id,
                "token_count": turn.token_count,
                "pinned": turn.pinned,
                "working_tokens": self.current_working_tokens(),
                "evictions_triggered": self._evictions_triggered,
            }
        if name == "memory_query_context":
            pkg = self.retrieve_context(
                query=str(args["query"]),
                top_k_semantic=int(args.get("top_k_semantic", 4)),
                top_k_episodic=int(args.get("top_k_episodic", 3)),
            )
            return {
                "assembled_prompt": pkg.assembled_prompt,
                "assembled_token_count": pkg.assembled_token_count,
                "compression_ratio": pkg.compression_ratio,
                "semantic_hits": [
                    {"fact_id": f.fact_id, "statement": f.statement, "source_turn_id": f.source_turn_id, "score": sc}
                    for f, sc in pkg.semantic_facts
                ],
                "episodic_hits": [
                    {"segment_id": s.segment_id, "summary": s.summary, "score": sc}
                    for s, sc in pkg.episodic_segments
                ],
            }
        if name == "memory_store_semantic_fact":
            fact = self.store_semantic_fact(
                statement=str(args["statement"]),
                category=str(args.get("category", "enterprise_fact")),
                source_turn_id=str(args.get("source_turn_id", "mcp_call")),
            )
            return {"fact_id": fact.fact_id, "entities": list(fact.entities), "category": fact.category}
        if name == "memory_inspect_tiers":
            return {
                "session_id": self.session_id,
                "working_token_budget": self.working_token_budget,
                "current_working_tokens": self.current_working_tokens(),
                "total_historical_tokens": self._total_historical_tokens,
                "evictions_triggered": self._evictions_triggered,
                "tier1_working_turns": len(self._working_turns),
                "tier2_episodic_segments": len(self._episodic_segments),
                "tier3_semantic_facts": len(self._semantic_facts),
            }
        raise ValueError(f"Unknown MCP memory tool: {name}")


def run_eviction_stress_test(
    *,
    num_distractor_turns: int = 56,
    working_token_budget: int = 220,
    top_k: int = 4,
) -> EvictionBenchmarkResult:
    """
    Context Window Eviction Stress Harness.

    Injects `num_distractor_turns` (default 56, yielding 65+ total turns including
    pinned instructions and 8 planted enterprise "needle" facts) through a tight
    token-budgeted working window. Compares 3-Tier Hierarchical Memory against a
    naive FIFO sliding window of identical token budget.
    """
    server = HierarchicalMemoryMCPServer(
        session_id="stress-bench-session",
        working_token_budget=working_token_budget,
        episodic_compaction_batch_size=3,
    )

    # Pin core system instructions and active tool schemas in Tier 1
    server.pin_system_instruction(
        "SYSTEM GUARDRAIL: Enforce Zero-Trust HMAC-SHA256 capability tokens, redact PII prior to LLM context, and cite turn provenance for all policy decisions."
    )

    planted_needles: list[dict[str, Any]] = [
        {
            "inject_at_distractor": 2,
            "category": "sla_constraint",
            "statement": "Customer SLA-9001 mandates 99.995% availability uptime and a strict 15 minutes P1 RTO ceiling for Tier-0 payment APIs.",
            "query": "What is the Customer SLA-9001 availability uptime and P1 RTO requirement?",
            "expected_marker": "99.995%",
        },
        {
            "inject_at_distractor": 8,
            "category": "security_exception",
            "statement": "Security exception SEC-EXC-4092 grants temporary FIPS-140-3 legacy HSM bridge access expiring on 2026-12-31.",
            "query": "Which security exception governs the FIPS-140-3 legacy HSM bridge and when does it expire?",
            "expected_marker": "SEC-EXC-4092",
        },
        {
            "inject_at_distractor": 15,
            "category": "architectural_decision",
            "statement": "Architecture decision ADR-014 mandates HMAC-SHA256 scoped capability tokens with monotonic privilege attenuation on A2A handoffs.",
            "query": "What does architecture decision ADR-014 mandate for A2A handoffs?",
            "expected_marker": "ADR-014",
        },
        {
            "inject_at_distractor": 22,
            "category": "compliance_residency",
            "statement": "EU-GDPR data residency policy locks all German healthcare telemetry shards exclusively to region eu-central-1.",
            "query": "Which region is mandated by the EU-GDPR data residency policy for German healthcare shards?",
            "expected_marker": "eu-central-1",
        },
        {
            "inject_at_distractor": 29,
            "category": "capacity_limit",
            "statement": "DynamoDB OrdersLedger table is provisioned with a hard ceiling of 4,500 WCU to prevent downstream throttling.",
            "query": "What is the DynamoDB OrdersLedger provisioned WCU ceiling?",
            "expected_marker": "4,500 WCU",
        },
        {
            "inject_at_distractor": 36,
            "category": "financial_guardrail",
            "statement": "Autonomous treasury agents have a pre-approved WIRE_TRANSFER limit of $2,500; any higher amount suspends for JIT human approval.",
            "query": "What is the autonomous WIRE_TRANSFER dollar threshold before JIT approval is required?",
            "expected_marker": "$2,500",
        },
        {
            "inject_at_distractor": 43,
            "category": "kms_rotation",
            "statement": "Envelope encryption policy requires automatic CMK key rotation every 90 days across us-east-1 and us-west-2 vaults.",
            "query": "How often does the envelope encryption policy require CMK key rotation across us-east-1 and us-west-2?",
            "expected_marker": "90 days",
        },
        {
            "inject_at_distractor": 49,
            "category": "incident_escalation",
            "statement": "Sev-1 latency anomalies exceeding 850ms at p99 for 5 minutes trigger automatic canary rollback in CodeDeploy.",
            "query": "What p99 latency threshold in ms triggers automatic canary rollback for Sev-1 anomalies?",
            "expected_marker": "850ms",
        },
    ]
    needle_by_step = {item["inject_at_distractor"]: item for item in planted_needles}

    # Maintain a naive FIFO sliding window with the exact same token budget for comparison
    naive_window: list[MemoryTurn] = list(server.working_turns)

    def _append_naive(turn: MemoryTurn) -> None:
        naive_window.append(turn)
        while sum(t.token_count for t in naive_window) > working_token_budget and len(naive_window) > 1:
            naive_window.pop(0)

    for step in range(1, num_distractor_turns + 1):
        if step in needle_by_step:
            needle = needle_by_step[step]
            t = server.append_turn(
                role="user",
                content=needle["statement"],
                metadata={"salient_fact": True, "category": needle["category"]},
            )
            needle["turn_id"] = t.turn_id
            _append_naive(t)

        distractor_text = (
            f"Routine telemetry heartbeat #{step:03d}: worker pod node-{step % 12:02d} reported normal CPU "
            f"utilization at {32 + (step % 25)}%, queue depth nominal, no active alerts in staging cluster."
        )
        dt = server.append_turn(role="assistant", content=distractor_text)
        _append_naive(dt)

    # Evaluate recall@K and eviction preservation across all planted needles
    naive_corpus = "\n".join(t.content for t in naive_window)
    hierarchical_hits = 0
    naive_hits = 0
    preserved_in_tiers = 0
    per_needle_records: list[dict[str, Any]] = []
    total_assembled_tokens = 0

    all_tier2_3_text = " ".join(f.statement for f in server.semantic_facts) + " " + " ".join(
        s.summary for s in server.episodic_segments
    )

    for needle in planted_needles:
        marker = needle["expected_marker"]
        if marker in all_tier2_3_text:
            preserved_in_tiers += 1

        pkg = server.retrieve_context(
            needle["query"],
            top_k_semantic=top_k,
            top_k_episodic=2,
        )
        total_assembled_tokens += pkg.assembled_token_count

        hier_found = marker in pkg.assembled_prompt
        naive_found = marker in naive_corpus
        if hier_found:
            hierarchical_hits += 1
        if naive_found:
            naive_hits += 1

        per_needle_records.append(
            {
                "category": needle["category"],
                "expected_marker": marker,
                "source_turn_id": needle.get("turn_id", ""),
                "hierarchical_recalled": hier_found,
                "naive_window_recalled": naive_found,
                "assembled_tokens": pkg.assembled_token_count,
            }
        )

    n_needles = len(planted_needles)
    avg_assembled_tokens = max(1, round(total_assembled_tokens / n_needles))
    total_raw_tokens = server._total_historical_tokens

    return EvictionBenchmarkResult(
        total_turns_ingested=server._turn_counter,
        planted_needles_count=n_needles,
        working_token_budget=working_token_budget,
        total_raw_tokens=total_raw_tokens,
        assembled_context_tokens=avg_assembled_tokens,
        token_compression_ratio=round(total_raw_tokens / avg_assembled_tokens, 2),
        hierarchical_recall_at_k=round(hierarchical_hits / n_needles, 4),
        naive_window_recall_at_k=round(naive_hits / n_needles, 4),
        zero_loss_eviction_accuracy=round(preserved_in_tiers / n_needles, 4),
        evictions_triggered=server._evictions_triggered,
        tier1_working_count=len(server.working_turns),
        tier2_episodic_count=len(server.episodic_segments),
        tier3_semantic_count=len(server.semantic_facts),
        per_needle_results=tuple(per_needle_records),
    )
