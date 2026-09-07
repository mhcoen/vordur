# Vörður Documentation

This directory contains architecture and integration documentation for using Vörður to harden MCP servers, MCP clients, and unknown-provenance input sources (web search, email, documents, calendar data, and other untrusted content).

## Where to start

In order of how much time each takes, shortest first.

1. [Watch an attack get stopped](https://mhcoen.github.io/vordur/demo/vordur_demos.html): every value on the page is real output from the library.
2. [The visual mechanism guide](https://mhcoen.github.io/vordur/docs/mechanisms/): six strips, one mechanism each, for a reader meeting the architecture for the first time.
3. [quick_start.md](quick_start.md), then [tutorial 01](../tutorials/01_web_search_sanitization.md), which is a page to read and a script to run.
4. [threat_model.md](threat_model.md): the assumptions each control rests on, and what each one costs when false.
5. [production_checklist.md](production_checklist.md) before any deployment, since several defaults are deliberately permissive for compatibility.

## Documents

**Architecture**

- [security.md](security.md): defense-in-depth architecture and layer-by-layer controls.
- [threat_model.md](threat_model.md): adversaries, trust boundaries, threats, and the assumptions each mitigation rests on.
- [privacy.md](privacy.md): pseudonymization at the model boundary, and the two policies that decide where a real value may be restored.

**API**

- [api.md](api.md): stable public API (`Guard`) and usage contract.
- [api_spec.md](api_spec.md): exhaustive API contract (full signatures, defaults, return types, and error semantics).

**Integration**

- [quick_start.md](quick_start.md): simple, interaction-focused setup for first integration.
- [integration.md](integration.md): practical integration patterns for MCP server/client systems.
- [integration_templates.md](integration_templates.md): copy-paste templates for MCP server/client and untrusted-input ingestion.
- [oauth_integration.md](oauth_integration.md): mapping OAuth scopes to Guard policy and tool-gating decisions.

**Policy and deployment**

- [configuration.md](configuration.md): policy controls and deployment guidance.
- [policy_tuning.md](policy_tuning.md): guidance for safely tuning policy strictness.
- [rego.md](rego.md): writing an access policy in Rego against the session facts Vörður computes, evaluated locally.
- [gateway.md](gateway.md): the OpenAI-compatible proxy that runs the checks itself, so an application changes only its `base_url`.
- [production_checklist.md](production_checklist.md): deployment checklist for production hardening and operations.

**Operations**

- [troubleshooting.md](troubleshooting.md): common failure modes, fixes, and FAQ.
- [support.md](support.md): the diagnostic bundle a customer-hosted deployment produces for a support ticket, and what it refuses to carry.

## Visual mechanism guide

Six illustrated explanations, one mechanism each, for readers meeting the
architecture for the first time. They are normative about mechanism and carry no
measurements: the Markdown documents above remain the authoritative specification.

- [All six strips](https://mhcoen.github.io/vordur/docs/mechanisms/), with a map of how they interlock.
- [01 What the Guard Remembers](https://mhcoen.github.io/vordur/docs/mechanisms/01-session-risk.html): a fact recorded at
  ingest denies a tool call two turns later once `contaminated_tool_policy` is set to
  `require_auth` or `deny`, and why four point tools cannot.
- [02 A Marker Only the Model Sees](https://mhcoen.github.io/vordur/docs/mechanisms/02-canary.html): canary tokens, and
  what a match proves.
- [03 The Call That Came Back Changed](https://mhcoen.github.io/vordur/docs/mechanisms/03-request-binding.html): request binding
  and deferred-execution replay.
- [04 What the Provider Sees Instead](https://mhcoen.github.io/vordur/docs/mechanisms/04-privacy-vault.html): substitution at the
  model boundary, what a default configuration does not detect, and the two gates on the way
  back.
- [05 The Path Around the Guard](https://mhcoen.github.io/vordur/docs/mechanisms/05-mediated-paths.html): why installed is
  not the same as in the way, and what the gateway does about it.
- [06 One Call, Two Questions](https://mhcoen.github.io/vordur/docs/mechanisms/06-two-questions.html): the tool gate rules
  on the action, egress rules on the bytes, and passing one is not passing the other.

The source for each strip is in [mechanisms/](mechanisms/).

## Runnable material

- [Executable demos](../demo/README.md): self-contained pages generated from the
  shipped library. Every displayed result carries the metadata that produced it
  and names the exact test that reproduces it. Start at the
  [system map](https://mhcoen.github.io/vordur/demo/vordur_surface_map.html).
- [Tutorials](../tutorials/README.md): step-by-step end-to-end integrations, each
  with a script you can run from the repo root.
- [Benchmarks](../benchmarks/methodology.md): evaluation methodology,
  [results](../benchmarks/results.md), and the [reproduction guide](../REPRODUCE.md)
  for re-running them from a clone.

## Framework integrations

See the [integrations index](integrations/README.md), or go directly to:

- [integrations/fastapi.md](integrations/fastapi.md)
- [integrations/mcp_sdk.md](integrations/mcp_sdk.md)
- [integrations/langchain_llamaindex.md](integrations/langchain_llamaindex.md)
