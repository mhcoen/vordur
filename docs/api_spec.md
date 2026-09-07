# API Specification (Exhaustive)

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

<!-- toc:start -->
<details markdown="1">
<summary>On this page</summary>

- [Scope and Stability](#scope-and-stability)
- [Session Lifetime and Concurrency](#session-lifetime-and-concurrency)
- [Public Export](#public-export)
- [Guard Class](#guard-class)
  - [Constructor](#constructor)
  - [Property: `canary_token`](#property-canary_token)
  - [Method: `reset`](#method-reset)
  - [Static Method: `hash_message`](#static-method-hash_message)
  - [Static Method: `authorize`](#static-method-authorize)
  - [Static Method: `bind_request`](#static-method-bind_request)
  - [Static Method: `context_mcp_server`](#static-method-context_mcp_server)
  - [Static Method: `context_mcp_client`](#static-method-context_mcp_client)
  - [Static Method: `context_document`](#static-method-context_document)
  - [Static Method: `context_web`](#static-method-context_web)
  - [Static Method: `context_internal_sensitive`](#static-method-context_internal_sensitive)
  - [Method: `process_inbound`](#method-process_inbound)
  - [Method: `process_inbound_compound`](#method-process_inbound_compound)
  - [Method: `check_tool_call`](#method-check_tool_call)
  - [Method: `check_outbound`](#method-check_outbound)
  - [Method: `check_outbound_content`](#method-check_outbound_content)
  - [Method: `validate_tool_args`](#method-validate_tool_args)
  - [Method: `sanitize_exception`](#method-sanitize_exception)
  - [Method: `seed_private_values`](#method-seed_private_values)
  - [Method: `deidentify`](#method-deidentify)
  - [Method: `reidentify`](#method-reidentify)
  - [Method: `prepare_tool_call`](#method-prepare_tool_call)
  - [Method: `carry_session_risk`](#method-carry_session_risk)
  - [Method: `persist_vault`](#method-persist_vault)
  - [Async Method: `confirm_action`](#async-method-confirm_action)
  - [Async Method: `guard_tool_call`](#async-method-guard_tool_call)
- [Type Specification](#type-specification)
  - [Enum: `TrustLevel`](#enum-trustlevel)
  - [Enum: `ContentType`](#enum-contenttype)
  - [Dataclass: `AuthorizationEvent` (frozen)](#dataclass-authorizationevent-frozen)
  - [Dataclass: `PolicyConfig`](#dataclass-policyconfig)
  - [Protocol Class: `ConfirmationHandler`](#protocol-class-confirmationhandler)
  - [Dataclass: `SecurityContext`](#dataclass-securitycontext)
  - [Dataclass: `SanitizationResult`](#dataclass-sanitizationresult)
  - [Dataclass: `ProcessedContent`](#dataclass-processedcontent)
  - [Dataclass: `GateResult`](#dataclass-gateresult)
  - [Dataclass: `OutboundResult`](#dataclass-outboundresult)
  - [Dataclass: `RateLimitResult`](#dataclass-ratelimitresult)
  - [Dataclass: `ValidationResult`](#dataclass-validationresult)
  - [Dataclass: `Binding`](#dataclass-binding)
  - [Dataclass: `AuditEvent`](#dataclass-auditevent)
- [Validation Contract (`validate_tool_args`)](#validation-contract-validate_tool_args)
- [Error Sanitization Contract (`sanitize_exception`)](#error-sanitization-contract-sanitize_exception)
- [Audit Logger Contract](#audit-logger-contract)

</details>
<!-- toc:end -->

This document is the complete public API contract for Vörður (`vordur`) as implemented in:
- `src/vordur/__init__.py`
- `src/vordur/api.py`
- `src/vordur/security/types.py`

## Scope and Stability

- Public package export surface: `vordur.Guard`
- Stability target: `Guard` methods and the data types referenced below.
- Internal modules under `vordur.security.*` are implementation details unless explicitly referenced in this spec.
- The privacy types are public and exported from the package root as well as from `vordur.security.types`: `PrivacyConfig`, `PIIClass`, `ClassPolicy`, `Destination`, `PIIFinding`, `Detector`, `DetectedSpan`, `DeidentifyResult`, `ReidentifyResult`, `PreparedCall`. So are `ConfirmationHandler`, `AuditLogger`, `SanitizationResult`, `RateLimitResult`, and `ExtractionPolicy`.
- This document is authoritative. [api.md](api.md) is the overview; where the two differ, this one wins.
- Four supported modules sit outside the `Guard` facade: `vordur.config` (policy files), `vordur.policy` (Rego), `vordur.support` (diagnostic bundles), and `vordur.security.vault_store` (vault persistence: the `VaultStore` protocol, `EncryptedFileVaultStore`, `MemoryVaultStore`, `VaultSnapshot`, `VaultEntry`, `VaultStoreError`, `generate_key`, and `VAULT_SNAPSHOT_VERSION`). Each has its own page under [docs](README.md). `vordur.api` also exports `joined_call_payload(args)`, a tool call's string *values* concatenated in traversal order with field names excluded: `prepare_tool_call` and the gateway check it as one outbound payload after checking each field, so a secret, canary, or copied passage cut across two fields is seen. It does not reach a split whose field ordering keeps the halves apart, nor one spread across separate calls or turns; that needs cross-request accumulation.

## Session Lifetime and Concurrency

A `Guard` holds the state of one logical session: the contamination and escalation flags, provenance spans, DLP buffers, rate counters, action-gate commitments, the remembered canary, and the privacy vault. Nothing in that state is keyed by user or principal.

- **One `Guard` per session, and per principal.** A `Guard` shared across users lets one user's untrusted ingest tighten another's tool calls, one user's sensitive content block another's egress, and, with `privacy`, one user re-identify another's tokens. Construct one per session, or call `reset()` only at a genuine session boundary; `reset()` mid-session discards the evidence the session has accumulated.
- **`principal_trust` is fixed at construction.** Every `SecurityContext` passed to `process_inbound`, `process_inbound_compound`, `check_tool_call`, `guard_tool_call`, `check_outbound`, or `check_outbound_content` must carry the `principal_trust` the `Guard` was built with. A mismatch raises `ValueError("principal_trust mismatch: context has ..., pipeline was constructed with ...")` before any check runs. The context builders take `principal_trust` as a keyword for this reason and default it to `UNTRUSTED`, matching the constructor default.
- **Sequential, not concurrent.** Session state is mutated without internal synchronization. Drive one `Guard` from one thread or one asyncio task at a time; a host that runs calls concurrently must serialize them. Two operations are locked internally, the rate limiter's confirmation finalize and the vault's token issuance, and each covers only itself. See [security.md](security.md#concurrency-and-thread-safety).

## Public Export

```python
from vordur import Guard
```

`src/vordur/__init__.py` exports the names below. `Guard` is the facade; the
rest are the types its methods accept and return, so they are public because
callers need them for annotations and construction:

- `AuditEvent`
- `AuditLogger`
- `AuthorizationEvent`
- `Binding`
- `ClassPolicy`
- `ConfirmationHandler`
- `ContentType`
- `DeidentifyResult`
- `Destination`
- `DetectedSpan`
- `Detector`
- `ExtractionPolicy`
- `GateResult`
- `Guard`
- `OutboundResult`
- `PIIClass`
- `PIIFinding`
- `PolicyConfig`
- `PreparedCall`
- `PrivacyConfig`
- `ProcessedContent`
- `RateLimitResult`
- `ReidentifyResult`
- `SanitizationResult`
- `SecurityContext`
- `SensitivityLevel`
- `TrustLevel`
- `ValidationResult`

## Guard Class

### Constructor

```python
Guard(*, canary_session_id: str | None = None, audit_logger: object | None = None, principal_trust: TrustLevel = TrustLevel.UNTRUSTED, privacy: PrivacyConfig | None = None, vault_store: VaultStore | None = None)
```

Parameters:
- `canary_session_id`: optional session identifier used to generate a canary token for exfiltration detection checks.
- `audit_logger`: optional logger object. If it has `.log(event)` it receives `AuditEvent` records emitted by Guard methods.
- `principal_trust`: session-level caller trust (default `UNTRUSTED`). Accepts `TRUSTED`, `SEMI_TRUSTED`, or `UNTRUSTED`.
- `privacy`: optional `PrivacyConfig`. Constructs the pseudonymization vault. Omitted, none of the four privacy methods below runs and no other verdict changes.
- `vault_store`: optional `VaultStore`. Attaches persistence to the privacy vault: the stored snapshot is loaded at construction, and `persist_vault()` writes it back. Omitted, the vault is session state and nothing reaches disk. **Raises `ValueError` when given without `privacy`**, rather than building no vault and reporting nothing, because persistence configured but never happening looks healthy until a restart comes up empty.

Behavior:
- Initializes security pipeline and action gate.
- Does not raise under normal construction.

### Property: `canary_token`

```python
guard.canary_token -> str | None
```

Behavior:
- Returns the remembered token when the Guard was constructed with `canary_session_id`.
- Returns `None` when canary protection is disabled.
- Trusted host code places this value in private model context. Vörður does not assemble the host's system prompt.

### Method: `reset`

```python
guard.reset(*, canary_session_id: str | None = None) -> None
```

Behavior:
- Clears contamination, escalation, provenance, DLP, rate, and action-gate state.
- With no new ID, retains the current logical session and canary.
- With a new non-empty ID, rotates an already-enabled canary atomically with the reset.
- Raises `ValueError` if a new ID is supplied to a Guard constructed without canary protection, or if the supplied ID is empty.

### Static Method: `hash_message`

```python
Guard.hash_message(message: str) -> str
```

Behavior:
- Returns SHA-256 hex digest of `message`.

### Static Method: `authorize`

```python
Guard.authorize(
    action: str,
    scope: dict,
    *,
    source: str = "api",
    user_message: str | None = None,
    message_hash: str | None = None,
    session_id: str | None = None,
    timestamp: float | None = None,
) -> AuthorizationEvent
```

Required input rule:
- Must provide either `user_message` or `message_hash`.

Error behavior:
- Raises `ValueError("Provide either user_message or message_hash")` if neither yields a usable hash.

Behavior:
- If `message_hash` not provided and `user_message` provided, hashes message via `Guard.hash_message`.
- Uses `time.time()` when `timestamp` is not supplied.

### Static Method: `bind_request`

```python
Guard.bind_request(
    tool: str,
    args: dict,
    *,
    authorization: AuthorizationEvent | None = None,
    user_message: str | None = None,
    message_hash: str | None = None,
    ttl: float = 120.0,
) -> Binding
```

Behavior:
- Creates anti-replay binding for `(tool, args, message_hash)`.
- Message hash precedence:
1. `authorization.message_hash` (if authorization provided)
2. explicit `message_hash`
3. hash of `user_message` (if provided)
4. empty string if none provided

Notes:
- Method itself does not raise for missing hash.
- Verification stage can reject if hash context mismatches later.

### Static Method: `context_mcp_server`

```python
Guard.context_mcp_server(
    server_id: str,
    *,
    source_trust: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="mcp_server"`
- `source_id=server_id`
- `source_trust`, `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`
- `principal_trust` as passed/defaulted; it must equal the `Guard`'s own (see [Session Lifetime and Concurrency](#session-lifetime-and-concurrency))

### Static Method: `context_mcp_client`

```python
Guard.context_mcp_client(
    client_id: str,
    *,
    source_trust: TrustLevel = TrustLevel.UNTRUSTED,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    principal_id: str | None = None,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="server"`
- `source_type="mcp_client"`
- `source_id=client_id`
- `source_trust`, `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`
- `principal_trust` as passed/defaulted; it must equal the `Guard`'s own (see [Session Lifetime and Concurrency](#session-lifetime-and-concurrency))
- `principal_id` as passed (default `None`); the only profile that sets it, and the only identity `check_outbound(egress_to_principal_id=...)` will exempt

### Static Method: `context_document`

```python
Guard.context_document(
    document_id: str,
    *,
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="rag_content"`
- `source_id=document_id`
- `source_trust=TrustLevel.UNTRUSTED`
- `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`
- `principal_trust` as passed/defaulted; it must equal the `Guard`'s own (see [Session Lifetime and Concurrency](#session-lifetime-and-concurrency))

### Static Method: `context_web`

```python
Guard.context_web(
    *,
    source_id: str = "web",
    content_type: ContentType = ContentType.HTML,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext
```

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="web_content"`
- `source_id=source_id`
- `source_trust=TrustLevel.UNTRUSTED`
- `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`
- `principal_trust` as passed/defaulted; it must equal the `Guard`'s own (see [Session Lifetime and Concurrency](#session-lifetime-and-concurrency))

### Static Method: `context_internal_sensitive`

```python
Guard.context_internal_sensitive(
    *,
    source_id: str = "internal",
    content_type: ContentType = ContentType.PLAINTEXT,
    policy: PolicyConfig | None = None,
    principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
) -> SecurityContext
```

For content the host trusts but must not let out: credentials, customer records, internal documents. Ingesting it through `process_inbound` registers it as a sensitive span, so a later `check_outbound` refuses to copy it regardless of contamination.

Returns `SecurityContext` with:
- `mode="client"`
- `source_type="internal"`
- `source_id=source_id`
- `source_trust=TrustLevel.TRUSTED`
- `sensitivity=SensitivityLevel.SENSITIVE`
- `content_type` as passed/defaulted
- `policy=policy or PolicyConfig()`
- `principal_trust` as passed/defaulted; it must equal the `Guard`'s own (see [Session Lifetime and Concurrency](#session-lifetime-and-concurrency))

### Method: `process_inbound`

```python
guard.process_inbound(content: str, context: SecurityContext) -> ProcessedContent
```

Pipeline behavior:
- Sanitizes inbound content.
- Wraps untrusted content in `<untrusted_content ...>` tags.
- Tracks provenance and warnings.
- Emits audit event `inbound_processed` if audit logger is configured.
- Raises `ValueError` when `context.principal_trust` differs from the `Guard`'s `principal_trust`.
- **Bounded, and refuses rather than truncates.** Content over `MAX_INBOUND_CHARS` (1,000,000 characters, `vordur.security.pipeline`), or that would push the session past what its provenance tracker retains (`MAX_PROVENANCE_SPANS` 10,000 spans or `MAX_PROVENANCE_CHARS` 2,000,000 normalized characters, `vordur.security.provenance`), returns `ProcessedContent(blocked=True)` with `content="[inbound refused: content withheld]"` and a warning naming the bound. Nothing is recorded: contamination, DLP, and provenance are unchanged. The tracker never evicts, because evicting the oldest span would let a flood of junk flush a sensitive span out of the no-copy check; a session that reaches the budget is at a boundary the host has to `reset()` deliberately.

### Method: `process_inbound_compound`

```python
guard.process_inbound_compound(
    spans: list[tuple[str, SecurityContext]],
    compound_id: str | None = None,
) -> list[ProcessedContent]
```

Pipeline behavior:
- Processes each span independently through the existing `process_inbound` path.
- Session state (contamination, DLP buffers, provenance) accumulates across all spans.
- If any span has `source_trust == UNTRUSTED`, the session contamination flag is set, widening downstream egress checks for the entire session.
- Each span keeps its own trust label, so a trusted envelope does not upgrade an untrusted forwarded payload. This path does not consult the source gate; `SecurityPipeline.check_kg_extraction` is a separate call.
- `compound_id` links spans for provenance and audit. If `None`, generated from a hash of all span contents (16-char hex prefix).
- Emits per-span `inbound_processed` audit events plus one `compound_inbound_processed` summary event with the `compound_id` as `request_id`.

### Method: `check_tool_call`

```python
guard.check_tool_call(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    authorization: AuthorizationEvent | None = None,
    binding: Binding | None = None,
    user_message: str | None = None,
    message_hash: str | None = None,
    recipient: str | None = None,
    validate: bool = True,
    record_rate_limit: bool = True,
) -> GateResult
```

Behavior:
- Runs policy check, rate-limit check, and optional binding verification.
- If `message_hash` absent and `user_message` provided, computes hash from `user_message`.
- Anti-replay message binding: when an `authorization` is present and a current message hash is available (from `message_hash`/`user_message`), a mismatch against `authorization.message_hash` is denied as a possible replay. `PolicyConfig.require_message_binding` additionally fails closed on a missing current hash.
- `recipient` (optional) feeds novel-recipient rate-limit anomaly detection; surfaced non-blocking on `GateResult.anomalies` and recorded in the audit event.
- `validate` (default `True`): validate arguments before the authorization decision; pass `False` only when the caller already validated (as `guard_tool_call` does).
- `record_rate_limit` (default `True`): a permitted call is the terminal decision and is recorded against the rate limiter. The rate-limit *check* always runs; only the *record* is gated. `guard_tool_call` passes `False` when a confirmation still follows, so a denied confirmation does not consume quota (see `guard_tool_call` below).
- Runs the session-risk gate before the policy check: contamination and escalation flags, under `contaminated_tool_policy` and `escalated_tool_policy`, deny with `"Tool call denied: ..."` or demand an authorization with `"Authorization required: ..."`, naming each trigger.
- An `authorization` older than 300 seconds is denied as expired, as is one with a non-finite or future `timestamp`. The window is the policy engine's default and is not configurable through `Guard` or `PolicyConfig`.
- Emits audit event `tool_call_checked` if audit logger is configured.
- Raises `ValueError` when `context.principal_trust` differs from the `Guard`'s `principal_trust`.

### Method: `check_outbound`

```python
guard.check_outbound(
    content: str,
    context: SecurityContext,
    *,
    has_quoting_directive: bool = False,
    recipient: str | None = None,
    egress_to_principal_id: str | None = None,
) -> OutboundResult
```

Behavior:
- Checks the remembered canary first, then runs outbound DLP, provenance, and rate checks.
- A canary match blocks even with a quoting directive, sets `OutboundResult.canary_detected`, and escalates the logical session.
- `recipient` (optional) feeds novel-recipient rate-limit anomaly detection; surfaced non-blocking on `OutboundResult.anomalies` and recorded in the audit event.
- `egress_to_principal_id` (optional): untrusted spans whose `principal_id` equals this value are exempt from the no-copy check, so a principal can be handed back their own words. Both values must be truthy to match. Sensitive spans, the remembered canary, and the secret scan are never exempt.
- Emits one facade-owned `outbound_checked` audit event if audit logging is configured. Its DLP payload includes `canary_detected` and the post-check escalation state, never the canary value or raw outbound content.
- Raises `ValueError` when `context.principal_trust` differs from the `Guard`'s `principal_trust`.

### Method: `check_outbound_content`

```python
guard.check_outbound_content(
    content: str,
    context: SecurityContext,
    *,
    has_quoting_directive: bool = False,
) -> OutboundResult
```

Behavior:
- L5 (remembered canary), L3 (DLP) and L4 (provenance) only. **No L6 quota or action accounting.**
- For a caller inspecting several pieces of one outbound action, which is the shape a tool call has: many argument leaves, one send. `check_outbound` records an outbound action every time it is called, so looping it over the leaves charges that single action once per string and exhausts the hourly quota inside one request.
- Escalation is preserved: a canary block or a high-confidence DLP block still sets session escalation, so a leak found in an argument still tightens later tool calls.
- `prepare_tool_call` and the gateway's tool-argument check both use this rather than `check_outbound`.
- Raises `ValueError` when `context.principal_trust` differs from the `Guard`'s `principal_trust`.

### Method: `validate_tool_args`

```python
guard.validate_tool_args(tool: str, args: dict, *, policy: PolicyConfig | None = None) -> ValidationResult
```

Behavior:
- Validates known argument names against built-in size/pattern limits.
- `policy` supplies `PolicyConfig.argument_limits`, merged over the built-in limits by argument name. Optional so a host with no context in hand still gets the safety checks; `check_tool_call` and `guard_tool_call` pass the active context's policy themselves.
- Applies universal safety checks (path traversal, null byte) to every argument including unknown ones and strings nested in containers; unknown fields get no size/pattern limits but are not exempt from these safety checks.
- Emits audit event `tool_args_validated` if audit logger is configured.

### Method: `sanitize_exception`

```python
guard.sanitize_exception(exception: Exception, retry_after: int | None = None) -> dict
```

Behavior:
- Maps internal exception to outward-safe error payload.
- Emits audit event `error_sanitized` if audit logger is configured.

Return payload shape:

```python
{"error": {"code": str, "message": str}}
```

### Method: `seed_private_values`

```python
guard.seed_private_values(values: dict[str, PIIClass]) -> None
```

Parameters:
- `values`: a mapping from a literal value to the class it belongs to, taken from a session the host has already authenticated.

Behavior:
- Registers values for exact detection. Nothing is inferred, so precision here is a property of the host's own authentication rather than of a detector.
- Raises `ValueError` when the guard was constructed without `privacy`.

### Method: `deidentify`

```python
guard.deidentify(content: str) -> DeidentifyResult
```

Behavior:
- Replaces detected personal data with opaque tokens before the content reaches a model provider.
- Detection runs two tiers that do not infer: declared values seeded above, and deterministic patterns (email, phone, SSN, credit card by Luhn, IBAN, routing number, passport, driver's licence, national identity number, medical record number, date of birth). A third tier is reachable through the `Detector` protocol.
- Sets `DeidentifyResult.detection_incomplete` when the vault knows its own coverage was partial. It cannot report what nothing looked for.
- Refuses rather than partially tokenizing when a bound is exceeded: `vault_max_entries`, `max_arg_depth`, `max_arg_nodes`.
- Raises `ValueError` when the guard was constructed without `privacy`.

### Method: `reidentify`

```python
guard.reidentify(
    content: str,
    *,
    destination: Destination,
    allowed_classes: frozenset[PIIClass] | None = None,
) -> ReidentifyResult
```

Parameters:
- `destination`: the destination whose `destination_policy` entry decides which classes may be restored. A destination with no rule restores nothing.
- `allowed_classes`: optional further restriction. It **intersects** with `destination_policy` and never replaces it, so it can only narrow. Passing a class the destination does not permit does not restore it.

Behavior:
- Deny-by-default. Restores only classes permitted by both the destination policy and, when given, `allowed_classes`.
- Raises `ValueError` when the guard was constructed without `privacy`.

### Method: `prepare_tool_call`

```python
guard.prepare_tool_call(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    has_quoting_directive: bool = False,
) -> PreparedCall
```

Behavior:
- Resolves tokens in tool arguments under `restore_policy`, which is keyed by tool and field path. A field with no rule restores nothing.
- **Ordering requirement.** Call this before building the `AuthorizationEvent` and `Binding`. Both bind exact bytes, so a scope authorized over a token fails against the restored value and the binding hash mismatches.
- Fails closed. An unresolvable token, a token whose framing the model damaged, an unresolvable count past `max_unresolvable`, or an argument tree past `max_arg_depth` or `max_arg_nodes` refuses the call rather than dispatching a partially resolved one.
- Unlike the three above, this does **not** raise without `privacy`. It passes the arguments through with `reason="privacy disabled"`, so a host can call it unconditionally in its dispatch path.

### Method: `carry_session_risk`

```python
guard.carry_session_risk(*, contaminated: bool = False, escalated: bool = False) -> None
```

Behavior:
- Raises the session-risk flags on a rebuilt guard. For a host reconstructing a session whose guard it no longer holds; the gateway uses it when an evicted session id returns.
- **Monotonic.** It can raise these flags and never lower them. A setter that could clear them would be a way to launder a contaminated session back to clean, which is the failure it exists to prevent.
- Only the flags travel. DLP buffers and provenance spans are not reconstructible from two booleans, so overlap detection against content ingested before the rebuild does not come back; the tool gate, which the flags drive, does.

### Method: `persist_vault`

```python
guard.persist_vault() -> None
```

Behavior:
- Writes the privacy vault's current state to the `vault_store` the guard was constructed with.
- Explicit, and never called from issuance: writing on every token would put an fsync on the path of every prompt, and a token lost to a crash before the next write is unresolvable afterwards, which fails the call rather than resolving to the wrong person.
- Raises `ValueError` without `privacy`, and `VaultStoreError` with `privacy` but no `vault_store`. Persistence configured but never happening is the failure that looks fine until a restart.

### Async Method: `confirm_action`

```python
await guard.confirm_action(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    summary: str,
    proposal_context: dict | None = None,
    heightened_scrutiny: bool = False,
    context_has_web_derived: bool = False,
) -> bool
```

Behavior:
- Delegates to `context.confirmation_handler.confirm(...)` when handler exists.
- If no confirmation handler is configured, fails closed (`False`) and emits `action_gate_unavailable` with `user_confirmed=None`: no user was consulted, so the audit trail does not record a decision nobody made.
- Otherwise emits `action_gate_confirmed` with the handler's answer in `user_confirmed`, if audit logger is configured.

### Async Method: `guard_tool_call`

```python
await guard.guard_tool_call(
    tool: str,
    args: dict,
    context: SecurityContext,
    *,
    summary: str | None = None,
    proposal_context: dict | None = None,
    authorization: AuthorizationEvent | None = None,
    binding: Binding | None = None,
    user_message: str | None = None,
    message_hash: str | None = None,
    context_has_web_derived: bool = False,
    require_confirmation: bool = False,
    heightened_scrutiny: bool = False,
    validate: bool = True,
    recipient: str | None = None,
) -> GateResult
```

Execution order:
1. Confirmation escalation: `require_confirmation` is forced to `True` when policy demands it, even if the caller passed `False`. This fires for a destructive tool under `auto_confirm_destructive`, for web-derived context (`context_has_web_derived=True`) under `escalation_gate_enabled`, and for a principal at or below `confirm_all_below`. Escalation fails closed: if confirmation is required and no handler is configured, the call is denied.
2. Optional validation (`validate=True` by default)
3. Tool policy/rate/binding checks (`check_tool_call`). When a confirmation follows (`require_confirmation=True`), this call passes `record_rate_limit=False`: the rate-limit *check* runs but the slot is not consumed yet, so a call denied at confirmation leaves no rate-limit trace.
4. Optional/escalated confirmation (`require_confirmation=True`)
5. G6 commitment verification: after confirmation, verifies that tool args have not been mutated since the confirmation handler was called. If args changed, the call is rejected with `"Commitment verification failed"`. This prevents TOCTOU attacks where args are swapped between confirmation and execution.
6. Rate-limit finalize (confirmation path only): once the call has cleared confirmation and G6, the rate-limit slot is re-checked and recorded atomically. Re-checking here (not just recording) closes a race where two concurrent confirmations both pass the step-3 check before either records; the check and record run with no intervening `await`, so at most `limit` confirmed calls are admitted. If the limit is now reached, the call is denied with the rate-limit reason.

`recipient` (optional) is forwarded to `check_tool_call` for novel-recipient anomaly detection.

Return behavior:
- Validation failure: `GateResult(allowed=False, reason="Validation failed: ...", confidence="none")`
- Gate failure: returns gate denial from `check_tool_call`
- Confirmation denied: `GateResult(allowed=False, reason="User denied confirmation", confidence="none")`
- Confirmation required with no handler configured: `GateResult(allowed=False, reason="Confirmation unavailable: no confirmation handler configured", confidence="none")`, with an `action_gate_unavailable` audit event
- G6 commitment mismatch: `GateResult(allowed=False, reason="Commitment verification failed: ...", confidence="none")`
- Rate-limit reached at finalize (concurrent confirmed calls): `GateResult(allowed=False, reason="Hourly limit exceeded ...", confidence="none")`
- Success: returns gate result from `check_tool_call`

## Type Specification

All types below are from `vordur.security.types`.

### Enum: `TrustLevel`

- `TrustLevel.TRUSTED` -> `"trusted"`
- `TrustLevel.SEMI_TRUSTED` -> `"semi_trusted"` (valid only for `principal_trust`, not `source_trust`)
- `TrustLevel.UNTRUSTED` -> `"untrusted"`

Note: `SEMI_TRUSTED` is only valid on the `principal_trust` axis. Setting `source_trust=TrustLevel.SEMI_TRUSTED` on a `SecurityContext` raises `ValueError`.

### Enum: `ContentType`

- `ContentType.HTML` -> `"html"`
- `ContentType.PLAINTEXT` -> `"plaintext"`
- `ContentType.STRUCTURED` -> `"structured"`

### Dataclass: `AuthorizationEvent` (frozen)

Fields:
- `action: str`
- `scope: dict`
- `message_hash: str`
- `timestamp: float`
- `source: str`
- `session_id: str | None = None`

Method:
- `binding_hash() -> str`

### Dataclass: `PolicyConfig`

Fields:
- `tool_allowlist: dict[tuple, Any] | None = None` (`None` = no allowlist, fall through; `{}` = deny all tools)
- `directive_patterns: dict[str, Any] = {}` (reserved / not yet wired; not consulted by the policy engine today, retained for forward compatibility)
- `enable_destructive: bool = False`
- `destructive_tools: frozenset[str] | None = None` (keyword-only; `None` keeps the built-in set; a frozenset replaces it, including an empty set. Gates `enable_destructive`, the authorization requirement, `require_message_binding="destructive"`, and `auto_confirm_destructive`; does not feed the session-risk gate)
- `capability_scopes: dict[str, Any] | None = None` (`None` = no allowlist; `{}` = deny all tools)
- `client_id: str | None = None`
- `server_default_deny: bool = False` (server mode: when `True`, a missing `capability_scopes` denies all tools instead of allowing by default)
- `rate_limits: dict[str, Any] = {}`
- `argument_limits: dict[str, Any] = {}`
- `escalation_gate_enabled: bool = True`
- `contaminated_action: str = "block"`
- `dlp_verbatim_lcs_min: int = 14`
- `dlp_ngram_overlap_min: float = 0.40`
- `dlp_sensitive_lcs_min: int = 12`
- `provenance_verbatim_lcs_min: int = 50`
- `provenance_ngram_overlap_min: float = 0.30`
- `source_gate_overrides: dict[tuple[str, TrustLevel], ExtractionPolicy] = {}`
- `untrusted_deny_tools: frozenset[str] = frozenset()`
- `untrusted_require_auth: bool = False`
- `confirm_all_below: TrustLevel | None = None`
- `rate_limit_overrides: dict[TrustLevel, dict[str, int]] = {}`
- `contaminated_tool_policy: str = "allow"` (`"allow"` | `"require_auth"` | `"deny"`; tool gating when untrusted content has entered the session)
- `escalated_tool_policy: str = "require_auth"` (`"allow"` | `"require_auth"` | `"deny"`; tool gating once a high-confidence DLP or remembered-canary block has fired this logical session)
- `auto_confirm_destructive: bool = False`
- `require_source_id_for: frozenset[str] = frozenset()`
- `require_message_binding: str = "off"` (`"off"` | `"destructive"` | `"all"`; anti-replay message binding)

### Protocol Class: `ConfirmationHandler`

Required async method:

```python
async def confirm(self, tool: str, args: dict, context: dict) -> bool
```

### Dataclass: `SecurityContext`

Fields:
- `mode: str` (`"client"` or `"server"`; any other value raises `ValueError` at construction)
- `source_type: str`
- `source_id: str`
- `source_trust: TrustLevel = TrustLevel.UNTRUSTED` (per-content trust; `TRUSTED` or `UNTRUSTED` only)
- `principal_trust: TrustLevel = TrustLevel.UNTRUSTED` (per-session caller trust; `TRUSTED`, `SEMI_TRUSTED`, or `UNTRUSTED`; must equal the `Guard`'s own)
- `principal_id: str | None = None` (keyword-only; authenticated author identity for the egress-recipient exemption, never inferred from `source_id`; only `context_mcp_client` exposes it among the profiles; leave unset on tool/server output)
- `sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC`
- `content_type: ContentType = ContentType.PLAINTEXT`
- `policy: PolicyConfig = PolicyConfig()`
- `confirmation_handler: ConfirmationHandler | None = None`

### Dataclass: `SanitizationResult`

Fields:
- `cleaned_text: str`
- `warnings: list[str] = []`
- `sanitization_summary: str | None = None`
- `chars_stripped: int = 0`
- `class_hiding_possible: bool = False`
- `encoded_detected: bool = False`
- `mixed_script_words: list[str] = []`

### Dataclass: `ProcessedContent`

Fields:
- `content: str`
- `sanitization: SanitizationResult | None = None`
- `isolated: bool = False`
- `source_type: str = ""`
- `source_id: str = ""`
- `warnings: list[str] = []`

### Dataclass: `GateResult`

Fields:
- `allowed: bool`
- `reason: str`
- `matched_directive: str | None = None`
- `confidence: str = "none"` (`"explicit" | "implicit" | "none"` by convention)
- `anomalies: list[str] = []` (non-blocking rate-limit signals: burst, novel recipient)

### Dataclass: `OutboundResult`

Fields:
- `allowed: bool`
- `reason: str`
- `overlap_pct: float = 0.0`
- `secrets_found: list[str] = []`
- `provenance_blocked: bool = False`
- `contamination_triggered: bool = False`
- `echo_detected: bool = False`
- `echo_lcs: int = 0`
- `anomalies: list[str] = []` (non-blocking rate-limit signals: burst, novel recipient)
- `canary_detected: bool = False` (the primary block matched the remembered session canary)

### Dataclass: `RateLimitResult`

Fields:
- `allowed: bool`
- `reason: str`
- `anomalies: list[str] = []`
- `remaining: int | None = None`
- `retry_after: int | None = None`

### Dataclass: `ValidationResult`

Fields:
- `valid: bool`
- `errors: list[str] = []`
- `field_name: str | None = None`

### Dataclass: `Binding`

Fields:
- `tool_name: str`
- `args_hash: str`
- `message_hash: str`
- `binding_hash: str`
- `created_at: float`
- `ttl: float = 120.0`

Computed property:
- `expired: bool`

### Dataclass: `AuditEvent`

Fields:
- `event_type: str`
- `tool_name: str | None = None`
- `action_summary: str | None = None`
- `content_hash: str | None = None`
- `user_confirmed: bool | None = None`
- `firewall_result: dict[str, Any] | None = None`
- `dlp_result: dict[str, Any] | None = None`
- `provenance_result: dict[str, Any] | None = None`
- `rate_limit_result: dict[str, Any] | None = None`
- `binding_result: dict[str, Any] | None = None`
- `warnings: list[str] | None = None`
- `session_id: str | None = None`
- `timestamp: float | None = None`
- `request_id: str | None = None`

## Validation Contract (`validate_tool_args`)

Known argument limits currently enforced:

- `message`: max chars `50_000`
- `content`: max chars `500_000`
- `query`: max chars `1_000`
- `source_name`: max chars `200`, regex `^[\w\-. /]+$`
- `thread_handle`: max chars `100`, regex `^[A-Za-z0-9_\-]+$`
- `provenance`: max fields `10`, max string value chars `500`

Universal safety checks (every argument, known or unknown):
- path traversal sequence `".."` is rejected
- null byte (`\x00`) is rejected
- these run on strings nested in lists/dicts (including dict keys); recursion is depth-bounded and over-deep or cyclic input is rejected

Unknown argument names:
- no size/pattern limits are applied, but the universal safety checks above still apply, so a traversal or null-byte payload in an unknown field is rejected

## Error Sanitization Contract (`sanitize_exception`)

Supported mappings:
- `RateLimitError` -> `{"code": "rate_limited", "message": "...retry after Xs"}`
- `InvalidParamsError` -> `{"code": "invalid_params", "message": "Invalid parameters: <field>"}`
- `UnauthorizedError` -> `{"code": "unauthorized", "message": "Invalid or expired token"}`
- `PermissionDeniedError` -> `{"code": "permission_denied", "message": "Tool not available"}`
- `InvalidHandleError` -> `{"code": "invalid_handle", "message": "Invalid or expired thread handle"}`
- `sqlite3.OperationalError` -> `{"code": "internal_error", "message": "Request could not be processed"}`
- `FileNotFoundError` -> `{"code": "internal_error", "message": "Request could not be processed"}`
- uncaught/other exceptions -> `{"code": "internal_error", "message": "Request could not be processed"}`

## Audit Logger Contract

If `Guard(..., audit_logger=logger)` is provided:
- logger must either be:
1. an instance of `vordur.security.audit.AuditLogger`, or
2. any object with method `log(event)`

`event` is an `AuditEvent` instance. `event_type` is one of:

- `action_gate_confirmed`
- `action_gate_unavailable`
- `compound_inbound_processed`
- `deidentified`
- `error_sanitized`
- `inbound_processed`
- `outbound_checked`
- `outbound_content_checked`
- `reidentified`
- `tool_args_validated`
- `tool_call_checked`
- `tool_call_prepare_denied`
