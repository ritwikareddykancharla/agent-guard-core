# AgentGuard — Zero-Trust AI Security Firewall, Scoped A2A Auth & Bedrock Posture Auto-Patcher

**Live Production App (Amazon CloudFront + Private S3 OAC + Bedrock Nova):** https://d3bfhuibgzllcf.cloudfront.net  
**CloudFront Distribution ID:** `E3PN6VHSQN4P1T` (`us-west-2` `/api/*` Origin + Private S3 OAC `agentguard-web-796330847946-us-west-2`)  
**Live Health Check:** `https://d3bfhuibgzllcf.cloudfront.net/api/health`

**AgentGuard** is a Zero-Trust AI Security Control Plane sitting between enterprise applications, delegated autonomous sub-agents, and external/cloud foundation models (**Amazon Bedrock `us.amazon.nova-lite-v1:0`**):
1. **Reversible Pre-Context VPC PII Vault (`agent_guard/pii_firewall.py`)**: Replaces `SSN`, `AWS_ACCESS_KEY`, `CREDIT_CARD`, `EMAIL`, `PHONE`, and `PATIENT_MRN` spans inside the VPC boundary (`[PII_SSN_1]` / `<PII:SSN_001>`) before prompts ever reach an LLM, selectively re-hydrating only authorized fields per downstream tool ACL (**360 / 360** spans redacted, **0** leaks).
2. **Multi-Signature Indirect Prompt-Injection Firewall (`agent_guard/pii_firewall.py`)**: Screens untrusted retrieved RAG documents and tool outputs for instruction overrides, ChatML/XML role-delimiter spoofing, covert exfiltration URLs, Base64 smuggling, and schema fuzzing (**40 / 40** attacks quarantined pre-LLM at **0.0%** false-positive rate).
3. **Cryptographic Scoped A2A Capability Tokens & Human JIT Gate (`agent_guard/identity_delegation.py`)**: Binds human principal, parent-to-child chain of custody, allowed tool patterns, pinned AWS resource ARNs, USD budget caps, and TTLs into `HMAC-SHA256` tokens — rejecting **23 / 23** confused-deputy privilege escalations, holding destructive/financial tools (`WIRE_TRANSFER`, `IAM_MUTATE`, `DELETE`, `PROD_DEPLOY`) in `PENDING_JIT_APPROVAL`, and recording a tamper-evident **SHA-256 hash-chained audit log**.
4. **Service Security Posture Auditor & Auto-Patcher (`agent_guard/web_api.py` + Bedrock Nova)**: Scans agent microservice manifests across **6 Zero-Trust controls** (wildcard IAM actions/ARNs, unpinned tool scopes, missing VPC PII egress filters, unscreened RAG ingestion, missing human JIT gates, and unbounded session budgets) and synthesizes a ready-to-apply unified security patch + blast-radius briefing via **Amazon Bedrock (`us.amazon.nova-lite-v1:0`)**.
5. **Tenant-Isolated Semantic Cache & Model Gateway (`agent_guard/model_gateway.py`, `agent_guard/memory_mcp.py`)**: Serves semantically equivalent repeat queries in `<2 ms` (`920.0 ms -> 86.8 ms` mean latency, **-89.6%** inference spend) while compacting 65-turn sessions at **100%** key-fact recall (**-80.7%** context tokens).

![AgentGuard CloudFront Architecture](docs/architecture.svg)

---

## Measured Benchmark Results (`benchmarks/latest_results.json`)

| Subsystem | Metric | Measured Result | Baseline / Notes |
| :--- | :--- | :---: | :--- |
| **VPC PII & Secret Redaction** | Regulated Spans Redacted Prior to Model Call | **360 / 360 (100.0%)** | `SSN`, `AWS_KEY`, `CARD`, `EMAIL`, `PHONE`, `MRN` |
| **Indirect Prompt-Injection Firewall** | Malicious Payloads Blocked / Benign FPR | **40 / 40 (100.0%)** / **0.0% FPR** | Role spoofing, exfil beacons, Base64 smuggling |
| **Scoped Sub-Agent A2A Auth** | Confused-Deputy Escalation Vectors Blocked | **23 / 23 (100.0%)** | Tool widening, ARN escape, budget/TTL & signature tampering |
| **Human JIT Gate & Audit Chain** | High-Risk Writes Gated & Hash Links Verified | **4 / 4 gated** · **100% SHA-256 valid** | `DELETE`, `IAM_MUTATE`, `WIRE_TRANSFER`, `PROD_DEPLOY` |
| **Session Memory Compaction** | Key-Fact Recall@4 Across 65 Turns (`58` Evictions) | **100.0%** (`8/8` facts) | vs. **0.0%** naive FIFO window (**5.17x** token compression) |
| **Semantic Cache & Router** | Gateway Spend & Mean Latency Reduction | **-89.6% spend** / **-90.6% latency** | `920.0 ms -> 86.8 ms` (**84.0%** semantic cache hit rate) |

---

## What You Can Do Live in the Web App

1. **Workflow 1 — Clean Customer Billing Support + Semantic Cache Hit**: Watch customer `SSN`, `EMAIL`, and `AWS_ACCESS_KEY` get tokenized inside the VPC (`[PII_SSN_1]`, `[PII_EMAIL_1]`, `[PII_AWS_KEY_1]`) before dispatching to **Amazon Bedrock (`us.amazon.nova-lite-v1:0`)**, inspect selective PII re-hydration for `billing:lookup_invoice`, and click **Repeat Request** to prove a live `<2 ms` Semantic Cache HIT at `$0.0000` model spend.
2. **Workflow 2 — Indirect Prompt Injection in Retrieved Document**: Trigger an untrusted RAG snippet containing `IGNORE ALL PREVIOUS INSTRUCTIONS` + a webhook exfiltration URL and watch Gate 2 quarantine all matched threat signatures before a single token reaches Bedrock.
3. **Workflow 3 — Confused-Deputy Sub-Agent Privilege Escalation**: Inspect a sub-agent holding an attenuated `read:orders` `HMAC-SHA256` token attempting `iam:CreateAccessKey` or `refund:issue_wire` — cryptographically rejected and logged to the SHA-256 hash chain. Also trigger `refund:WIRE_TRANSFER` under the root coordinator token to sign a live **Human JIT Approval**.
4. **Workflow 4 — Service Security Posture Audit & Bedrock Auto-Patcher**: Scan vulnerable agent microservice manifests (`24/100 CRITICAL`), generate a live **Amazon Bedrock Nova** remediation brief + colorized unified diff, and click **Apply Security Auto-Patch** to verify **`100/100`** hardened compliance.

---

## Run Locally & Deploy to Amazon CloudFront

```bash
# 1. Run all 25 unit, security, and API tests
python3 -m unittest discover -s tests -v

# 2. Run reproducible security & gateway benchmarks
python3 -m agent_guard.cli

# 3. Start the interactive Security Control Plane locally
python3 -m agent_guard.web_api
# -> Open http://localhost:3096

# 4. Deploy to Amazon CloudFront + Private S3 (OAC) + /api/* + Amazon Bedrock (us-west-2)
chmod +x infra/deploy_cloudfront.sh
./infra/deploy_cloudfront.sh
```
