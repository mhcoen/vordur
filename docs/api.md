# API Reference

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

Vörður exposes a stable facade: `vordur.Guard`.

This page is the overview. [api_spec.md](api_spec.md) is the authoritative contract, with full signatures, defaults, return types, and error semantics; where the two differ, the specification wins.

## Core Class

```python
from vordur import Guard
```

Constructor:
- `Guard(*, canary_session_id: str | None = None, audit_logger: object | None = None, principal_trust: TrustLevel = TrustLevel.UNTRUSTED, privacy: PrivacyConfig | None = None, vault_store: VaultStore | None = None)`

All arguments are keyword-only. `privacy` is what constructs the vault; without it nothing in the privacy section below runs and no existing verdict changes. `vault_store` attaches persistence to that vault and raises `ValueError` when given without `privacy`, since there is no vault to persist.

Canary provisioning and lifecycle:
- `guard.canary_token -> str | None`: read-only token for trusted host code to place in private model context.
- `guard.reset(canary_session_id=None)`: clear transient state while retaining the current logical session and canary; pass a new ID to rotate an already-enabled canary for a new logical session.

## Session Lifetime

A `Guard` is the state of one logical session, and none of that state is keyed by user:

- **One `Guard` per session and per principal.** Shared across users, one user's untrusted ingest tightens another's tool calls and, with `privacy`, one user can re-identify another's tokens. Construct one per session, or call `reset()` only at a genuine session boundary.
- **`principal_trust` is fixed at construction.** Every context passed to a check must carry the same value, or the call raises `ValueError("principal_trust mismatch: ...")`. The context builders take it as a keyword and default it to `UNTRUSTED`, matching the constructor.
- **Sequential, not concurrent.** Drive a `Guard` from one thread or one asyncio task at a time. See [security.md](security.md#concurrency-and-thread-safety).

## Context Builders

Use these to declare trust boundaries explicitly:
- `Guard.context_mcp_server(server_id, source_trust=..., content_type=..., policy=..., principal_trust=...)`
- `Guard.context_mcp_client(client_id, source_trust=..., content_type=..., policy=..., principal_trust=..., principal_id=...)`
- `Guard.context_document(document_id, content_type=..., policy=..., principal_trust=...)`
- `Guard.context_web(source_id="web", content_type=..., policy=..., principal_trust=...)`
- `Guard.context_internal_sensitive(source_id="internal", content_type=..., policy=..., principal_trust=...)`: trusted but sensitive internal content such as credentials or customer records, labelled `SENSITIVE` so outbound checks refuse to copy it.

Every builder takes `principal_trust`, which must equal the `Guard`'s own (see [Session Lifetime](#session-lifetime)). Only `context_mcp_client` takes `principal_id`, the one identity `check_outbound(egress_to_principal_id=...)` will exempt from the no-copy check.

For additional source types (for example `email_content`, `calendar_content`), construct `SecurityContext` directly.

## Authorization and Binding

- `Guard.hash_message(message) -> str`
- `Guard.authorize(action, scope, source="api", user_message=..., message_hash=..., session_id=..., timestamp=...) -> AuthorizationEvent`
- `Guard.bind_request(tool, args, authorization=..., user_message=..., message_hash=..., ttl=120.0) -> Binding`

Recommended pattern for write-capable tools:
1. Create authorization event from explicit user intent.
2. Create binding from tool + args + message hash.
3. Check tool call with authorization + binding.

## Runtime Checks

- `guard.process_inbound(content, context) -> ProcessedContent`
- `guard.check_tool_call(tool, args, context, authorization=..., binding=..., user_message=..., message_hash=..., recipient=...) -> GateResult`
- `guard.check_outbound(content, context, has_quoting_directive=False, recipient=..., egress_to_principal_id=...) -> OutboundResult`
- `guard.validate_tool_args(tool, args) -> ValidationResult`
- `await guard.confirm_action(tool, args, context, summary=..., ...) -> bool`
- `await guard.guard_tool_call(tool, args, context, ...) -> GateResult`
- `guard.sanitize_exception(exception, retry_after=None) -> dict`

### Manual Gating (L12) Behavior

- `confirm_action(...)` and `guard_tool_call(..., require_confirmation=True)` rely on `context.confirmation_handler`.
- If no handler is configured, confirmation fails closed: `confirm_action` returns `False`, `guard_tool_call` denies with `reason="Confirmation unavailable: no confirmation handler configured"`, and the audit event is `action_gate_unavailable` with `user_confirmed=None`, because no user was asked. `"User denied confirmation"` and `user_confirmed=False` are reserved for a handler that actually answered no.
- For heightened scrutiny, pass `context_has_web_derived=True` to include the hardcoded warning context in the confirmation payload.
- `guard_tool_call` escalates to confirmation automatically (even without `require_confirmation=True`) when policy requires it: `auto_confirm_destructive` for destructive tools, `context_has_web_derived=True` under `escalation_gate_enabled`, or a principal at or below `confirm_all_below`. Escalation fails closed with no handler.

## Privacy Vault (opt-in)

Available only when the guard was constructed with `privacy=PrivacyConfig(...)`. The types these methods take and return (`PrivacyConfig`, `PIIClass`, `Destination`, `ClassPolicy`, `DeidentifyResult`, `ReidentifyResult`, `PreparedCall`, `PIIFinding`, `Detector`, `DetectedSpan`) are exported from the package root. The first three raise `ValueError` without it rather than returning something that looks like a result; `prepare_tool_call` instead passes the arguments through with `reason="privacy disabled"`, so a host can call it unconditionally in its dispatch path.

- `guard.seed_private_values(values: dict[str, PIIClass]) -> None`: declare values from a session the host has already authenticated. Exact by construction, since nothing is inferred.
- `guard.deidentify(content: str) -> DeidentifyResult`: replace personal data with opaque tokens before the content reaches a model provider.
- `guard.reidentify(content: str, *, destination: Destination, allowed_classes: frozenset[PIIClass] | None = None) -> ReidentifyResult`: restore real values for one destination. `allowed_classes` **narrows** and never widens: it intersects with `destination_policy` rather than replacing it.
- `guard.prepare_tool_call(tool: str, args: dict, context: SecurityContext, *, has_quoting_directive: bool = False) -> PreparedCall`: resolve tokens in tool arguments under `restore_policy`. Call it **before** building the authorization event and binding, because both bind exact bytes and a scope authorized over a token fails against the restored value.

- `guard.check_outbound_content(content, context, *, has_quoting_directive=False) -> OutboundResult`: L5/L3/L4 with no L6 quota accounting, for a caller checking several pieces of one outbound action. `check_outbound` records an action every call, so looping it over a tool call's argument leaves spends that call's quota once per string.
- `guard.carry_session_risk(*, contaminated=False, escalated=False) -> None`: re-raise session-risk flags on a rebuilt guard, for a host reconstructing a session it no longer holds. Monotonic: it never lowers them, since clearing would launder a contaminated session back to clean.
- `guard.persist_vault() -> None`: write the vault to the store the guard was constructed with (`Guard(..., vault_store=...)`). Raises without a store rather than doing nothing, since persistence configured but never happening is the failure that looks fine until a restart.

Both restore paths are deny-by-default: a field or destination with no rule restores nothing. See [privacy.md](privacy.md).

## Beyond the Guard Facade

`Guard` is the stable facade, and these are the other supported entry points.

- **Policy files.** `vordur.config.load_policy(path)` and `parse_policy(text)` build a `PolicyConfig` from YAML, for a deployment with nowhere to put a Python object. Needs the `yaml` extra. Refuses unknown keys and wrong types rather than falling back to a default. Optional `version:` key, `POLICY_FILE_VERSION == 1`. See [configuration.md](configuration.md).
- **Rego policies.** `vordur.policy.RegoPolicy(path)`, `build_input(...)`, `decide(...)`, and `POLICY_INPUT_VERSION`. Evaluated in process through wasmtime, with no network. A Vörður deny is final and the policy is never consulted; Rego only ever narrows. Needs the `rego` extra. See [rego.md](rego.md).
- **Diagnostics.** `vordur.support.build_bundle(...)`, `render_bundle(...)`, `write_bundle(path, ...)`, and `python -m vordur.support`. Raises `UnsafeBundleError` rather than writing a bundle holding credential material it cannot remove exactly. See [support.md](support.md).
- **Gateway.** `python -m vordur.gateway` presents an OpenAI-compatible endpoint that runs the checks itself, so an application changes only its `base_url`. See [gateway.md](gateway.md).
- **Vault persistence.** `vordur.security.vault_store.VaultStore` is a three-method protocol (`load`, `save`, `purge`); `EncryptedFileVaultStore(path, key=...)` and `.from_env(path)` are the local implementation, AES-256-GCM under a key you supply, and `MemoryVaultStore` is the in-process one. `generate_key()` returns a key for a secret manager and nothing here writes one. Needs the `vault` extra. There is no unencrypted fallback: without it the store refuses to write. See [privacy.md](privacy.md).
- **Audit sinks.** `AuditLogger(log_path=..., stream=...)`. `stream=sys.stdout` is the intended argument in a container, and is flushed per event.

## Return Objects

- `ProcessedContent`: sanitized content, warnings, source metadata.
- `GateResult`: allow/deny decision and reason for tool execution, plus non-blocking rate-limit `anomalies` (burst, novel recipient).
- `OutboundResult`: allow/deny decision and exfiltration/provenance indicators, `canary_detected`, plus non-blocking rate-limit `anomalies`.
- `ValidationResult`: argument validation pass/fail with field-level details.
- `DeidentifyResult`: tokenized `content`, the `findings` behind it, `denied` classes, `allowed`, `reason`, and `detection_incomplete` when coverage was known to be partial.
- `ReidentifyResult`: restored content and what was withheld.
- `PreparedCall`: the arguments with tokens resolved, `allowed`, and `reason`. Fails closed: an unresolvable or damaged token refuses the call rather than dispatching a partially resolved one.

## Minimal End-to-End Example

```python
from vordur import Guard
from vordur.security.types import PolicyConfig

guard = Guard(canary_session_id="session-1")
assert guard.canary_token is not None
# Trusted host code places guard.canary_token in private system context.
ctx = Guard.context_mcp_server(
    server_id="mcp-mail",
    policy=PolicyConfig(
        enable_destructive=True,
        dlp_verbatim_lcs_min=100,
        dlp_ngram_overlap_min=0.40,
        provenance_verbatim_lcs_min=50,
        provenance_ngram_overlap_min=0.30,
    ),
)

tool = "gmail_send_email"
args = {"to": "alice@example.com"}
msg = "send email to alice@example.com"

auth = Guard.authorize(action=tool, scope={"to": "alice@example.com"}, user_message=msg)
binding = Guard.bind_request(tool=tool, args=args, authorization=auth)

gate = guard.check_tool_call(
    tool=tool,
    args=args,
    context=ctx,
    authorization=auth,
    binding=binding,
    user_message=msg,
)

if gate.allowed:
    # execute tool here
    pass
```
