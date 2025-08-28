# Project Guardian 2.0 — PII Detection/Redaction Deployment Strategy

## Goals
- Intercept and redact PII in near real-time across ingress, service-to-service traffic, and logs.
- Minimize latency, be cost‑effective, and easy to integrate without rewrites.

## Recommended Pattern: Sidecar at App Tier + Gateway Plugin at Edge

1) API Gateway Plugin (Edge)
- Where: NGINX/Envoy/ Kong/ API Gateway plugin on the ingress controller.
- Why: Catches third‑party callbacks and partner traffic before they hit apps.
- How: Lua/WASM filter that:
  - Applies streaming regex/DFAs for fast matches to common PII (phone, aadhar, passport, UPI).
  - Truncates/obfuscates PII and removes PII from headers.
  - Emits PII-alert metrics (Prometheus) and drops payload copies in a quarantine bucket for forensic review.
- Latency: O(bytes) streaming pass; <2ms typical for JSON <32KB.

2) App Pod Sidecar (Kubernetes)
- Where: Daemon sidecar container injected into pods that handle customer data.
- Why: Prevent PII leakage to logs and outbound HTTP; no code change in app.
- How:
  - eBPF/iptables redirect app’s stdout/stderr and HTTP egress through sidecar.
  - Sidecar (this Python service packaged as a small FastAPI/uvicorn) performs:
    - JSON-aware redaction (hybrid: regex + heuristics),
    - Structured log enrichment (add pii_found=true),
    - Sink to log collector (Fluent Bit) post-redaction.
  - Provide a local Unix socket for apps that optionally call redact(text) for inline scrubbing.
- Latency: intra-pod localhost; p99 <3ms for <64KB events.

3) Log Pipeline Guardrail
- Fluent Bit/Vector processor plugin inserts the redactor as a filter for any remaining PII.
- Ensures legacy services and batch jobs cannot bypass redaction.

## Operations & Scale
- Autoscale sidecars with pod HPAs; edge plugin is horizontally scaled with ingress replicas.
- Caching of compiled regex; pre-compile patterns at startup.
- Backpressure: if redactor CPU spikes, fall back to coarse masking (replace digits with X) and raise an alert.
- Observability: Prometheus metrics (pii_detected_total, pii_masked_bytes), Grafana dashboards, SLO alerts.

## Security
- All quarantine samples encrypted with KMS; access gated by break-glass policy.
- Sidecar and plugin images are distroless; SBOM + signing (Cosign), admission policy enforced.
- Config-as-code via ConfigMaps; secrets via External Secrets.

## Rollout Plan
- Phase 1: Mirror mode at edge (detect-only) for 1 week; tune rules to reduce false positives.
- Phase 2: Enable redact at edge for external integrations; enable sidecar for top 5 PIIs apps.
- Phase 3: Extend to all namespaces; enforce log-pipeline filter globally.

## Why This Placement
- Edge plugin: protects against third-party leaks with minimal app coupling.
- Sidecar: maximal coverage for internal paths and logs, with isolated blast radius and low latency.
- Log pipeline: guarantees defense‑in‑depth for legacy paths.

## Interfaces
- REST: POST /redact (body text/JSON), returns redacted content & flags.
- gRPC optional for high-throughput services.
- Local library shim for synchronous use in latency-sensitive handlers.

## Capacity & Cost
- CPU: ~0.2 vCPU per 1k req/s (typical payloads), memory 128–256MB per sidecar.
- Horizontal scale at ingress; per‑service sidecars scale with app pods.

## Compliance
- Masking policies versioned; audit logs retained 90 days.
- Periodic re-evaluation with synthetic PII corpora; monthly drift reports.

---
This strategy balances speed (edge), coverage (sidecar), and safety (log filter) while keeping integration friction low and costs predictable.
