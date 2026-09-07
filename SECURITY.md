# Security Policy

Vörður is a security library. We take vulnerability reports seriously and aim to respond quickly.

## Supported Versions

Only the most recent minor release line of Vörður receives security fixes.

| Version | Supported |
|--------:|:---------:|
| 3.0.x   | Yes       |
| < 3.0   | No        |

The version is declared in `pyproject.toml`. Older versions on PyPI will not be patched; users on older releases should upgrade.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security problems.

Send a private report to **mhcoen@gmail.com** with:

- A description of the vulnerability and the affected component (sanitizer, policy engine, request binding, outbound DLP, etc.)
- A minimal reproduction (input that triggers the issue, version of Vörður, Python version)
- Your assessment of impact (information disclosure, authorization bypass, prompt-injection bypass, panic/DoS, etc.)
- Whether you intend to disclose publicly, and on what timeline

You should receive an acknowledgement within **3 business days**. We aim to triage within **7 days** and produce a patch release for confirmed high-severity issues within **30 days**, sooner for actively exploited problems.

If you do not get an acknowledgement within a week, please follow up: mail can get lost.

## Coordinated Disclosure

We follow a 90-day coordinated disclosure window by default. We are happy to negotiate a different timeline for complex fixes or downstream coordination. We will credit reporters in the CHANGELOG unless you ask to remain anonymous.

## In Scope

The following are in scope for vulnerability reports against Vörður itself:

- **Sanitizer bypass**: input that escapes `<untrusted_content>` isolation, smuggles instructions past HTML/CSS/whitespace normalization, or evades the prompt-injection detector with no obfuscation cost
- **Authorization bypass**: tool calls that pass `Guard.authorize` / `Guard.check_tool_call` despite policy denying them
- **Request-binding bypass**: tampered parameters that verify against an unrelated binding, or replays that succeed past the anti-replay window
- **Outbound DLP bypass**: untrusted-provenance content copied into outbound payloads without detection
- **Error-channel disclosure**: `Guard.sanitize_exception` leaking internal paths, secrets, or stack frames
- **Canary handling**: canary tokens accepted as untainted, or canary-bearing content silently passing outbound checks
- **Crashes or DoS** in any pipeline path on small, malformed inputs (memory exhaustion, regex catastrophic backtracking, infinite loops)
- **Supply-chain issues** in this repository's dependencies or build pipeline

## Out of Scope

Vörður is one layer of defense; it does not replace other controls. The following are not Vörður vulnerabilities:

- LLM behavior outside of Vörður's pipeline (e.g. the model ignoring `<untrusted_content>` framing when the application strips it before sending to the model)
- Application-layer policy choices: e.g. an empty allowlist is intentionally deny-by-default, and a misconfigured allowlist that admits a destructive tool is the operator's responsibility
- Attacks requiring a privileged local attacker (e.g. someone who can write the application's policy config)
- Performance reports that are not crash-class (general latency regressions belong in regular issues)
- Reports limited to benchmark numbers in `benchmarks/results.md` (those are reproducibility/methodology discussions, not vulnerabilities)

## Test Datasets

The benchmark datasets under `benchmarks/` are part of Vörður's evaluation methodology. Changes to those datasets are governed by `benchmarks/methodology.md` and reviewed separately from security fixes. A flaw in a *dataset case* is not a Vörður vulnerability; a flaw in *how the pipeline handles a class of input* is.

## Hardening Posture

Vörður ships with safe-by-default settings:

- Empty allowlist denies (does not allow-all)
- Destructive tools are disabled by default, and enabling one in client mode still
  requires an `AuthorizationEvent` whose scope covers every dispatched argument.
  In server mode a destructive tool that is enabled and listed in
  `capability_scopes` is permitted without an authorization event, which is the
  server capability contract rather than an exception to it.
- Inbound content is wrapped with source and trust metadata even when no warnings fire
- Outbound checks compare against the provenance and DLP state the session has
  actually recorded. They do not fail closed on unknown provenance: content a
  session never ingested returns `allowed=True, reason="clean"`. Registering
  untrusted input through `process_inbound` is what gives egress something to
  match against, which is the host obligation the tool-feedback demo covers.

If you find a default that does not match this posture, that itself is a reportable issue.

### Documented compatibility exceptions

Three shipped defaults are deliberately permissive for backward compatibility and do not match the safe-by-default posture above. They are known, documented choices, each with a named fail-closed opt-in, and are slated for a consolidated safe-by-default review at the next major version:

- **Server mode with `capability_scopes` unset** implicitly allows non-destructive tools rather than denying. Opt into fail-closed with `PolicyConfig(server_default_deny=True)`.
- **`contaminated_tool_policy` defaults to `allow`**, so untrusted-ingest contamination does not by itself tighten tool authorization. Set it explicitly to `require_auth` or `deny` to fail closed.
- **Client mode with `tool_allowlist` unset (`None`)** implicitly allows non-destructive tools that carry no authorization event, rather than denying. Opt into fail-closed by setting `tool_allowlist` explicitly: an empty dict (`{}`) denies all tools, and a populated allowlist denies anything not listed.

Reports about these three specific defaults are expected and tracked, not treated as new posture violations, until that review lands. A default outside this list that fails the posture is still in scope.
