# Configuration and Policy

<!-- nav:start -->
[Docs index](README.md)
<!-- nav:end -->

Vörður is policy-driven via `PolicyConfig` and `SecurityContext`.

## Policy from a file

A deployment behind a process boundary has nowhere to put a Python dataclass,
so `PolicyConfig` can be read from YAML. Needs PyYAML, which is not in the core
install: `pip install 'vordur[yaml]'`.

```python
from vordur.config import load_policy

policy = load_policy("policy.yaml")
ctx = Guard.context_mcp_server(server_id="mail", policy=policy)
```

```yaml
version: 1          # optional; absent means 1
policy:
  enable_destructive: false
  server_default_deny: true
  tool_allowlist: [search_knowledge, read_file]
  untrusted_deny_tools: [send_email]
  confirm_all_below: semi_trusted
  contaminated_tool_policy: deny
  capability_scopes:
    search_knowledge: {scope: read}
  rate_limit_overrides:
    untrusted: {emails_per_hour: 10}
  source_gate_overrides:
    - source_type: web
      source_trust: untrusted
      policy: quarantine
```

The loader refuses rather than guesses, because a setting that is silently not
in force is worse than one you cannot write:

- **An unknown key is an error**, with a suggestion. `enable_destrucive: true`
  does not leave destructive tools disabled while you believe otherwise.
- **A value of the wrong type is an error.** YAML reads `off` and `no` as
  false, but `"false"` is a non-empty string and therefore truthy, so
  `enable_destructive: "false"` is refused rather than coerced.
- **Absent is not empty.** `tool_allowlist:` unset means no allowlist;
  `tool_allowlist: []` denies every tool. Same for `capability_scopes`.
- **`directive_patterns` is refused**, because the policy engine does not read
  it and a file should not be able to express a rule that does nothing.

The optional `version` key exists because a deployment runs a release for years
and cannot be forced forward, so this format is a long-lived interface. Within a
version settings are only ever added; none is removed, renamed, or given a new
meaning. An absent version means 1, so no file needs the boilerplate. A version
this build does not know is refused, and the message distinguishes the two
directions because the remedies are opposite: a newer file needs a newer
Vörður, while a retired version needs the file migrating. Without that, an old
build reading a new file would reject its settings as unknown keys and report a
typo, when the truth is that the operator's policy is not being enforced.

Only `PolicyConfig` is loadable. `PrivacyConfig` holds detector instances and
class-to-policy mappings that a file cannot name, so it stays a Python object.

## PolicyConfig

`PolicyConfig` fields:
- `tool_allowlist`: client-mode allowlist map for tool authorization policy (`None` = no allowlist, fall through; `{}` = deny all tools; `{tool: ...}` = allow listed tools only).
- `directive_patterns`: **reserved / not yet wired.** Accepted for forward compatibility but not consulted by the policy engine today. The library validates an `AuthorizationEvent`'s contents, not its origin; ensuring only trusted adapters can construct events is a host obligation (see A-AS8 in `docs/threat_model.md`). Its disposition (deprecate vs. wire as a source-string consistency check) is undecided; retained as a constructor field to avoid a breaking change post-2.0.0.
- `enable_destructive`: enable destructive tools (default `False`).
- `destructive_tools`: the tools this deployment treats as destructive, as a
  list of names. Absent keeps the library's built-in set, which names gmail,
  calendar, slack, file and shell tools; a list **replaces** that set rather
  than extending it, so `[]` means nothing is destructive. Set this if your
  dangerous action is not one the library ships a name for. It gates
  `enable_destructive`, the authorization requirement,
  `require_message_binding: destructive`, and automatic confirmation under
  `auto_confirm_destructive`. The Python constructor accepts this field by
  keyword only, preserving the existing positional arguments. It does **not**
  feed the session-risk gate, which refuses a declared and an undeclared tool alike under
  `contaminated_tool_policy: deny`.
- `capability_scopes`: server-mode allowed tool scope mapping (`None` = no allowlist; `{}` = deny all tools).
- `client_id`: optional logical client identity.
Both `rate_limits` and `argument_limits` are validated by `PolicyConfig` at construction: an unknown key, a wrong type, or a `pattern` that does not compile is refused there rather than raising from the middle of whichever tool call happens to carry that argument.

- `rate_limits`: base rate limits for this context, merged over the defaults (`emails_per_hour`, `burst_threshold`, `burst_window_seconds`, `novel_recipient_flag`). A key you omit keeps its default rather than being unset. `rate_limit_overrides` still wins over this for the matching principal trust level.
- `argument_limits`: per-argument constraints (`max_chars`, `pattern`, and for `provenance`, `max_fields` / `max_value_chars`), merged over the defaults by argument name. A partial override keeps the sibling settings of that argument, and a name the defaults do not know is added.
- `escalation_gate_enabled`: enable heightened confirmation behavior in action gate.
- `contaminated_action`: action when contaminated context detected (default `"block"`).
- `dlp_verbatim_lcs_min`: untrusted-echo LCS threshold (default `14` chars).
- `dlp_ngram_overlap_min`: outbound DLP n-gram overlap block threshold (default `0.40`).
- `dlp_sensitive_lcs_min`: sensitive-leak LCS threshold (default `12` chars).
- `provenance_verbatim_lcs_min`: provenance verbatim overlap block threshold (default `50` chars).
- `provenance_ngram_overlap_min`: provenance n-gram overlap block threshold (default `0.30`).
- `source_gate_overrides`: override source gate policy keyed by `(source_type, source_trust)`.
- `untrusted_deny_tools`: tools denied when `principal_trust == UNTRUSTED`.
- `untrusted_require_auth`: require auth event when `principal_trust == UNTRUSTED` (default `False`).
- `confirm_all_below`: require confirmation for all tools when `principal_trust` is at or below this level.
- `rate_limit_overrides`: per-`principal_trust` rate limit overrides, merged over defaults.
- `contaminated_tool_policy`: tool gating when context is contaminated (untrusted content ingested this session) (`"allow"`, `"require_auth"`, or `"deny"`; default `"allow"`).
- `escalated_tool_policy`: tool gating once a high-confidence egress DLP or remembered-canary block has fired in the logical session (the backward-propagating complement of contamination) (`"allow"`, `"require_auth"`, or `"deny"`; default `"require_auth"`). Contamination and escalation are independent; when both fire the strictest policy wins. See "Session Risk Signals" in `docs/security.md`.
- `auto_confirm_destructive`: auto-require confirmation for destructive tool calls (default `False`). Production deployments should set to `True`.
- `require_source_id_for`: source types that require non-empty `source_id` (default empty frozenset). Blocks KG extraction when violated.
- `server_default_deny`: server-mode fail-closed (default `False`). When `True`, a missing `capability_scopes` (`None`) denies all tools instead of allowing non-destructive tools by default. Set to `True` in production so a forgotten scope config does not silently allow tools.
- `require_message_binding`: anti-replay message binding for client-mode authorizations (`"off"`, `"destructive"`, or `"all"`; default `"off"`). A current message hash that mismatches the authorized message is always denied as replay; this flag additionally controls whether a *missing* current hash fails closed: `"destructive"` requires it for destructive tools, `"all"` for every authorized tool call.

## SecurityContext

`SecurityContext` controls evaluation for each data flow:
- `mode`: `"client"` or `"server"`
- `source_type`: provenance label (`mcp_server`, `mcp_client`, `web_content`, `email_content`, etc.)
- `source_id`: source identifier for traceability
- `source_trust`: per-content trust (`TRUSTED` or `UNTRUSTED` only; `SEMI_TRUSTED` is not valid on this axis)
- `principal_trust`: per-session caller identity (`TRUSTED`, `SEMI_TRUSTED`, or `UNTRUSTED`)
- `sensitivity`: data sensitivity level (`PUBLIC`, `INTERNAL`, or `SENSITIVE`)
- `content_type`: plaintext/html/structured
- `policy`: `PolicyConfig`

## Recommended Defaults

- Keep `enable_destructive=False` unless explicitly required.
- Use `UNTRUSTED` for any external or mixed-provenance source.
- Require both authorization and binding for all write-capable tools.
- Set `server_default_deny=True` (server mode) so a missing `capability_scopes` fails closed.
- Set `require_message_binding="destructive"` (or `"all"`) and pass the current `user_message`/`message_hash` so authorizations cannot be replayed across messages.
- Preserve and monitor warnings from `process_inbound`.

## Deployment Guidance

- Run inbound checks at every trust boundary (server ingress, retrieval ingress, webhook ingress).
- Run tool gating immediately before execution (not earlier in the request lifecycle).
- Run outbound checks on final generated/tool-return content.
- Version and review your policy configuration as code.
