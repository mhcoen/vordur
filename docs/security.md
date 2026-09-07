# Security Architecture

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

Vörður uses a defense-in-depth security pipeline designed to harden MCP servers and MCP clients against prompt injection, data exfiltration, replay attacks, and trust-boundary violations from unknown-provenance content sources such as web search results, emails, documents, calendar data, and other untrusted inputs.

## Defense Layers

| Layer | Name | Purpose | Primary Module |
|---|---|---|---|
| L0 | Input Sanitization | Strip hidden HTML, dangerous attributes/comments, invisible Unicode, and normalize content before further processing | `vordur.security.sanitizer` |
| L1 | Content Isolation | Wrap untrusted input in `<untrusted_content ...>` tags with source attribution | `vordur.security.isolation` |
| L2 | Source Gate | Enforce provenance-based KG extraction policies (`allow`, `quarantine`, `block`) | `vordur.security.source_gate` |
| L3 | Outbound DLP | Block high-overlap egress, secret-like patterns, hex decode-then-scan entropy detection, and deobfuscated variants (reversed text, spelled-out characters) | `vordur.security.outbound_dlp` |
| L4 | Provenance Tracking | Track untrusted spans and block suspicious reuse across trust boundaries, including deobfuscated content variants | `vordur.security.provenance` |
| L5 | Canary Detection | Provision and remember a session canary, then block if that exact private value appears at egress | `vordur.security.canary` |
| L6 | Rate Limiting | Per-context action throttling for abuse resistance | `vordur.security.rate_limiter` |
| L7 | Error Sanitization | Sanitize error payloads before returning to clients | `vordur.security.error_sanitizer` |
| L8 | OAuth Scope Resolution | Scope narrowing/escalation policy between auth/session states | Host application responsibility |
| L9 | Tool Firewall | Authorize tools by policy + explicit authorization events | `vordur.security.policy_engine` |
| L10 | Validation | Validate tool arguments before dispatch | `vordur.security.validation` |
| L11 | Request Binding | Bind tool execution to message hash + args hash + TTL | `vordur.security.request_binding` |
| L12 | Action Gate | Optional interactive confirmation gate for sensitive actions, with G6 commitment verification | `vordur.security.action_gate` |
| - | Audit Logging | Structured security event logging for analysis and incident response (cross-cutting observer) | `vordur.security.audit` |

Note: Layer numbers are stable control identifiers, not a total execution order. L8 is documented for completeness but remains outside the library boundary.

## Guard API Coverage (Current)

This section is the source of truth for what is wired through `vordur.Guard` today.

| Layer | Status | Guard API Surface |
|---|---|---|
| L0 Input Sanitization | Implemented | `process_inbound(...)` |
| L1 Content Isolation | Implemented | `process_inbound(...)` |
| L2 Source Gate | Implemented | `vordur.security.source_gate.check_extraction_allowed(...)` |
| L3 Outbound DLP | Implemented | `check_outbound(...)` |
| L4 Provenance Tracking | Implemented | `process_inbound(...)`, `check_outbound(...)` |
| L5 Canary Detection | Implemented | `Guard(canary_session_id=...)`, `guard.canary_token`, and inbound/outbound checks |
| L6 Rate Limiting | Implemented | `check_tool_call(...)`, `check_outbound(...)`, `guard_tool_call(...)` |
| L7 Error Sanitization | Implemented | `sanitize_exception(...)` |
| L8 OAuth Scope Resolution | Not implemented in library | Host application responsibility |
| L9 Tool Firewall | Implemented | `check_tool_call(...)`, `guard_tool_call(...)` |
| L10 Validation | Implemented | `validate_tool_args(...)`, `guard_tool_call(validate=True)` |
| L11 Request Binding | Implemented | `bind_request(...)`, `check_tool_call(...)`, `guard_tool_call(...)` |
| L12 Action Gate | Implemented | `confirm_action(...)`, `guard_tool_call(..., require_confirmation=True)` |
| Audit Logging | Implemented | `Guard(audit_logger=AuditLogger(log_path=..., stream=...))` emits security events as JSON lines to a file, a stream, or both |

## Unified Pipeline

The central orchestrator is `vordur.security.pipeline.SecurityPipeline`, exposed through the high-level `Guard` API.

Inbound path:
1. TR39 confusable normalization (homoglyph characters mapped to ASCII within mixed-script runs; legitimate single-script international text is preserved)
2. Prompt-injection signal pass
3. Sanitize untrusted input (L0), including HTML, Unicode, and encoded-payload handling
4. Isolate by trust level (L1)
5. Ingest for outbound DLP comparisons (L3 data prep)
6. Record provenance spans (L4)
7. Check canary presence in inbound payloads (L5)

Compound ingress (`process_inbound_compound`):
- Accepts a list of (content, SecurityContext) spans representing a single message with mixed provenance (e.g., a trusted envelope wrapping a forwarded untrusted payload).
- Each span is processed independently through the pipeline above. Session state (contamination, DLP buffers, provenance) accumulates across all spans.
- Core invariant: a trusted transport does not upgrade embedded untrusted content. Forwarding cannot launder untrusted content into trusted extraction.
- If any span has `source_trust == UNTRUSTED`, the session contamination flag is set, widening downstream egress and tool-call checks for the entire session.

L0 encoded payload handling:
- Base64 and URL-encoded segments are decoded and scored with the prompt-injection detector.
- This avoids relying only on fixed suspicious keyword lists.

Tool-call path:
1. Tool authorization/firewall checks (L9)
2. Rate limiting (L6)
3. Optional request binding verification (L11)
4. Optional L12 confirmation gate with G6 commitment verification: the action gate captures a canonical snapshot of tool args before the confirmation handler is called. After confirmation, `verify_commitment` checks that the args have not been mutated. If args changed between confirmation and execution, the call is rejected (prevents TOCTOU attacks on the confirmation flow).

Outbound path:
1. TR39 confusable normalization (homoglyph characters mapped to ASCII within mixed-script runs; legitimate single-script international text is preserved)
2. Remembered-canary leakage detection (L5), before generic heuristics so the strongest known-value signal retains attribution
3. DLP overlap/secret checks (L3), including deobfuscated variants (reversed text, spelled-out characters) and hex decode-then-scan for entropy detection
4. Provenance reuse guard (L4), including deobfuscated variants
5. Rate limiting (L6)

Threshold tuning:
- L3 and L4 overlap thresholds are configurable per context via `PolicyConfig`
  (`dlp_verbatim_lcs_min`, `dlp_ngram_overlap_min`,
  `provenance_verbatim_lcs_min`, `provenance_ngram_overlap_min`).
- DLP defaults: `dlp_verbatim_lcs_min=14`, `dlp_sensitive_lcs_min=12`, `dlp_ngram_overlap_min=0.40`.
- Provenance defaults: `provenance_verbatim_lcs_min=50`, `provenance_ngram_overlap_min=0.30`.

## Unknown-Provenance Source Handling

Vörður supports explicit security contexts for:
- MCP server responses (`context_mcp_server`)
- MCP client requests (`context_mcp_client`)
- Documents (`context_document`)
- Web results (`context_web`)

You can also define custom `SecurityContext` values for sources like:
- `email_content`
- `calendar_content`
- `tool_output`
- `rag_content`

These source types integrate directly with source-gate and provenance behavior.

## Default Security Posture

- Both trust axes default to `UNTRUSTED`: `source_trust` (per-content) and `principal_trust` (per-session caller) each default to `TrustLevel.UNTRUSTED`.
- Destructive tool calls are blocked unless explicitly enabled via `PolicyConfig(enable_destructive=True)`.
- Destructive tool calls require authorization events in client mode.
- Request binding is optional but recommended for all write-capable actions. In addition, the policy engine binds authorizations to the current user message (a mismatching message hash is denied as replay); `PolicyConfig.require_message_binding` (`"destructive"` / `"all"`) makes a missing current hash fail closed.
- Server mode allows non-destructive tools by default when `capability_scopes` is unset; set `PolicyConfig.server_default_deny=True` to fail closed instead.
- Client mode allows non-destructive tools that carry no authorization event by default when `tool_allowlist` is unset (`None`); set `tool_allowlist` explicitly (an empty dict `{}` denies all tools) to fail closed.
- `contaminated_tool_policy` defaults to `allow`, so untrusted-ingest contamination does not by itself tighten tool authorization; set it to `require_auth` or `deny` to fail closed. These three defaults are listed under "Documented compatibility exceptions" in `SECURITY.md`.
- OAuth/OIDC integration is supported via host-side scope-to-policy mapping (see `docs/oauth_integration.md`).

## Session Risk Signals

> Illustrated: [01 What the Guard Remembers](mechanisms/01-session-risk.html) follows a
> contamination mark from ingest to the tool gate that reads it, and
> [02 A Marker Only the Model Sees](mechanisms/02-canary.html) follows the escalation
> signal in the other direction.

The pipeline carries two independent, monotonic, logical-session risk signals that tighten tool authorization. Both are cleared by `reset()`; a canary-enabled host passes a new canary session ID when that reset also starts a new logical session.

- **Contamination (forward propagation)** - `_context_contaminated` is set in `process_inbound` when untrusted content enters the session. `check_tool_execution` then applies `PolicyConfig.contaminated_tool_policy` (default `allow`).
- **Egress feedback escalation (backward propagation)** - implemented. `_session_escalated` is set in `check_outbound` when a high-confidence exfiltration block fires: an L3/DLP hard block or a match against the remembered session canary. `check_tool_execution` then applies `PolicyConfig.escalated_tool_policy` (default `require_auth`). This closes the gap where an outbound exfiltration block left no trace and a subsequent tool call proceeded normally.

The two signals are independent: either can tighten tool policy on its own. When both fire, the **strictest** policy wins (`deny` > `require_auth` > `allow`), and the denial reason names each contributing trigger with its policy so the deciding signal is unambiguous (e.g. `Tool call denied: session contaminated=deny; egress escalated=require_auth`). Escalation only tightens tool authorization; it does not change `check_outbound` behavior on later calls. It never mutates `principal_trust`, which is immutable after construction.

**Trigger scope (high-confidence exfiltration).** DLP hard blocks and remembered-canary matches escalate. Provenance and rate-limit blocks do not. A remembered canary is a session-scoped value registered as private material, so it receives primary attribution even when generic entropy would also match it. Provenance blocks remain excluded to avoid escalating on lexical-overlap false positives; the tradeoff is narrower coverage when a real cross-boundary copy is caught only by provenance.

> **Host contract - canary provisioning and `reset()`.** When `canary_session_id` is supplied, trusted host code reads `guard.canary_token` and places that value in private model context; Vörður remembers the expected value outside the model. Calling `reset()` clears both risk signals but retains the same logical session and canary. Calling `reset(canary_session_id="new-id")` atomically clears risk and rotates an already-enabled canary for a new logical session. Never reset reactively in response to processed content or on a fixed schedule, because that would clear accumulated session risk.

Verification: unit tests in `tests/security/test_egress_escalation.py` cover DLP and canary triggers, canary precedence, non-triggering provenance/rate/echo paths, policy options, monotonicity, reset and rotation, independence from contamination, and strictest-wins ordering.

## Concurrency and Thread Safety

A `SecurityPipeline` (and the `Guard` that wraps it) mutates session-scoped state without internal synchronization: the remembered canary, contamination and escalation flags, DLP buffers, provenance tracking, and rate counters are updated in place as inbound, outbound, and tool-execution calls run. The contract is **one pipeline per session, driven sequentially**. A host that issues concurrent operations against a single pipeline (async tasks or OS threads) must serialize them itself; the library does not defend against concurrent mutation, and interleaved calls can corrupt session state or race the session-risk signals. Use a separate `Guard` per session, or hold a lock around the pipeline, whenever one session may be driven concurrently.

Two operations are internally synchronized, and they cover only themselves. The rate limiter's confirmation finalize (`check_and_record`, used by `guard_tool_call` after confirmation) serializes its check-and-record under a lock, so concurrent confirmed tool calls cannot collectively exceed the limit even under real thread concurrency. The privacy vault holds a lock around token issuance, seeding, and clearing, so two calls cannot issue two tokens for one value. All other session-state mutation, including the vault's own scans and lookups, is still the host's responsibility to serialize.

## Threats Covered

- Hidden-instruction prompt injection in HTML/text payloads
- Unicode obfuscation attacks (zero-width/bidi controls, TR39 homoglyph substitution)
- Exfiltration by copying untrusted spans into outbound content
- Obfuscated exfiltration via reversed text or spelled-out characters (e.g. `s-t-r-i-p-e`)
- Hex-encoded secret exfiltration (decoded and entropy-scanned)
- Replay/deferred tool execution after conversation state changes
- Over-privileged tool invocation and destructive action abuse

## Operational Boundaries

Vörður is an application-layer hardening library. It does not replace:
- network segmentation
- host/container isolation
- secret management systems
- transport-layer authN/authZ
- OAuth/OIDC token issuance, validation, and lifecycle management

Use Vörður as one layer in a full security architecture.
