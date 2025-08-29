
# Project Guardian 2.0 — Deployment Strategy (Mohammed Yunus)

## TL;DR
Deploy a **zero‑copy streaming PII filter** at the **ingress/egress edge** using an **NGINX Ingress Controller plugin** (Lua + OpenResty) that calls a **local sidecar redaction service** (our Python detector, compiled with uv/pyoxidizer if needed). Mirror traffic to **Kafka** for async analytics and coverage, and add **log sinks** (Fluent Bit filters) that redact before persistence. This gives **single digit‑ms latency**, **horizontal scalability**, and **one control point** for all apps.

---

## Where it lives
1. **Kubernetes Ingress Layer (Primary Enforcement)**
   - **NGINX Ingress Controller** with a **streaming body filter** (Lua).  
   - For each HTTP request/response, the filter chunks the payload and sends to a **localhost gRPC sidecar** for PII detection/redaction.  
   - Only mutates bodies for content types likely to carry PII (JSON, text, form-data), skips binaries.

2. **Service Mesh / Sidecar (Detector)**
   - A **sidecar container** runs `pii-detector` (Python script packaged as a single binary via PyInstaller), exposing a **gRPC / unix-socket** API:
     - `DetectAndRedact(stream<bytes>) -> stream<bytes>, pii_found`
   - Stateless; scales 1:1 with ingress pods. Warm pools keep regex/NER models in memory.

3. **Logging & Observability Layer**
   - **Fluent Bit** DaemonSet with a **redaction filter** that invokes the same sidecar before shipping logs to S3/ELK.  
   - **Sampling + metrics** (PII hit rates, top fields) go to Prometheus/Grafana; spikes trigger alerts.

4. **Kafka (Async Safety Net)**
   - **Ingress mirror** (NGINX tee module) publishes a copy of selected topics to Kafka.  
   - Downstream consumers (risk, security) run **batch re‑scans** with stricter models and maintain **hash registries** of redacted tokens for forensics without storing raw PII.

5. **Developer Tooling / Internal Apps**
   - **Node/Express middleware** for internal tools (admin panels) to sanitize server‑rendered templates.  
   - A **UI guard** (Browser extension for staff browsers) that hides PII rendered accidentally by legacy apps using a lightweight DOM scrubber.

---

## Why this placement
- **Latency:** Running the detector **co‑located** with ingress (same node & socket) avoids network hops; regex‑first + optional NER gives **sub‑10ms** median for typical payloads (<128 KB).  
- **Blast radius:** One control plane for **all external traffic** and **all logs** blocks leaks even when unowned services misbehave.  
- **Scalability:** Purely horizontal—scale ingress replicas; sidecars scale with them. Kafka path is async and does not affect P99.  
- **Cost:** Reuses existing ingress and logging stacks; CPU spikes only on text/JSON payloads; binaries bypass.  
- **Ease of integration:** No app changes; toggle per‑route via Ingress annotations.

---

## Data Flow (Request & Response)
```
Client ⇄ Edge (NGINX/Lua) ⇄ Sidecar (gRPC) ⇄ Upstream Service
            │                         │
            └── metrics/logs ─────────┘
            └── mirror to Kafka (tee) ─▶ async analytics
```

**Streaming**: The Lua filter and gRPC both stream chunks; no full‑buffer to avoid head‑of‑line blocking. Chunk boundaries are respected for SSE and long‑poll.

---

## Detection/Redaction Policy
- **Policy-as-code** (OPA/Rego) to decide *when* to redact (e.g., `route=/api/logs` or `header=x-internal:true`).  
- **Regex-first** for high‑precision structured fields (phones, Aadhaar, UPI, passports).  
- **Combinatorial logic** (>=2 of {name, email, address, device/ip}) to avoid false positives.  
- Optional **NER** model (SpaCy) enabled **only** on specific paths or body sizes to keep latency bounded.  
- **Field-aware** JSON walker when content-type is JSON; otherwise **best‑effort text sanitizer**.

---

## Operational Controls
- **Per‑route annotations**: `pii.guardian/enabled=true`, `pii.guardian/mode=block|mask|observe`, `pii.guardian/max-body=1MB`.  
- **Circuit breakers**: If sidecar is unhealthy or latency > budget, ingress falls back to **pass‑through** but emits **critical alerts**.  
- **Versioned dictionaries** for provider lists (UPI handles, phone prefixes), distributed via ConfigMap + Hot reload.  
- **Redaction formats** standardized (e.g., phone `98XXXXXX10`).

---

## Failure Modes & Safeguards
- **Double‑scrub**: Logs are **always redacted** before leaving the node, independent of edge success.  
- **Shadow mode**: Start in observe‑only; compare redacted vs original via Kafka mirrors to tune false positives.  
- **PII Vault**: No raw PII is stored. Hashes (HMAC‑salted) allow correlation without reversibility.

---

## Rollout Plan
1. **Stage** on non‑critical routes; enable `observe`.  
2. **Ramp** to critical API paths with per‑service SLOs; tune thresholds.  
3. **Flip** high‑risk log sinks to mandatory redaction.  
4. **Audit** quarterly using seeded canaries and synthetic payloads.

---

## Rough Sizing
- 1 vCPU sidecar handles ~2–3K small requests/sec with regex‑only mode.  
- Memory: 100–200 MB (regex + small caches).  
- Add NER only on flagged routes (adds 20–40 ms, 300–500 MB per pod); keep disabled by default.

---

## Security Notes
- Sidecar exposes **unix domain socket** only.  
- All configs and allowlists are **code‑reviewed**; changes require 2‑person approval.  
- Extensive unit+fuzz tests for the sanitizer to prevent bypass (e.g., Unicode confusables, zero‑width spaces).

---

## Alternatives Considered
- **API Gateway plugin only**: simplest but doesn’t cover **logs**.  
- **DaemonSet eBPF scrubber**: powerful but harder to do **content‑aware** redaction.  
- **Pure library in apps**: fastest in‑process but inconsistent adoption across teams.

**Chosen hybrid** combines edge enforcement + log redaction + async mirror for best coverage vs. latency and cost.
