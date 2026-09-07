# Contributing to Vörður

Vörður is a security library, so contributions are reviewed with that lens. The goal is to keep the threat model coherent, the pipeline auditable, and the public API stable for downstream applications.

This guide covers practical contribution steps. For security reporting, see [SECURITY.md](SECURITY.md). For project background, see [README.md](README.md).

## Where Contributions Are Most Welcome

- **New vulnerability classes**: a missed prompt-injection technique, an outbound-channel exfiltration pattern, or a tool-call abuse path. A reproduction in a test case is more valuable than a one-line fix.
- **Adapters for new ingress surfaces**: connectors for additional MCP servers, document loaders, or search APIs.
- **Integration patterns**: clean example wiring for popular frameworks (LangGraph, LangChain, LlamaIndex, Pydantic AI, Semantic Kernel, etc.) in `examples/`.
- **Hardening improvements** to the sanitizer, normalizer, or detector that close gaps without large false-positive cost. Show the FP/TP tradeoff with numbers.
- **Documentation**: clearer threat-model framing, more honest production-checklist items, better troubleshooting recipes.

## Where Contributions Need Care

- **Sanitizer / detector heuristic changes**: these change the false-positive and false-negative profile. Include benchmark deltas (`benchmarks/run_benchmarks.py`) so reviewers can see the tradeoff.
- **Public API changes** (anything exported from `vordur` or `vordur.security`): require a deprecation path and a CHANGELOG entry. A breaking change needs a major version bump, and a changed default that alters a verdict counts as breaking: 2.0.0 was cut for `escalated_tool_policy` alone.
- **Benchmark dataset changes**: governed separately. See `benchmarks/methodology.md`. Do not modify dataset files (`CSE-8000`, `CBX-1200`, etc.) as part of a feature PR.
- **The paper** (`paper/`): off-limits for contributor PRs. Open an issue if you find an error.

## Development Setup

```bash
git clone https://github.com/mhcoen/vordur.git
cd vordur
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

Optional extras:

```bash
pip install -e '.[benchmarks]'    # to run benchmark comparisons
pip install -e '.[examples]'      # to run the local-LLM demo
pip install -e '.[gpu]'           # to run GPU baselines locally
```

## Running Tests

```bash
pytest                            # full suite
pytest tests/security/            # security-focused unit tests
pytest tests/integration/         # documented-flow integration tests
pytest -x --tb=short              # stop on first failure (debugging)
```

The security unit tests in `tests/security/` are the most load-bearing: they pin the contract of each primitive (sanitizer, prompt-injection detector, request binding, outbound DLP, etc.). Adding a new vulnerability class without a test is not enough.

## Running Benchmarks

```bash
python benchmarks/run_benchmarks.py
python benchmarks/compare_mitigations.py
```

If you change anything that could shift detection numbers, include the before/after table in the PR description. Use the canonical checkpoint to verify you haven't drifted:

```bash
python benchmarks/run_benchmarks.py \
  --checkpoint benchmarks/checkpoints/official-baseline.json \
  --allow-extra-suites
```

## Style

- Python 3.10+ (matches `pyproject.toml`).
- Ruff for linting (see `[tool.ruff]` in `pyproject.toml`). Run `ruff check .` before pushing.
- Type hints on public functions and dataclasses. We ship a `py.typed` marker; downstream users rely on the types being honest.
- Prefer dataclasses over loose dicts for cross-module data.
- No new runtime dependencies unless there is a clear case. There are three: `beautifulsoup4`, `soupsieve` (pinned to the patched release for GHSA-2wc2-fm75-p42x), and `confusables`. Keep the list this short if possible.

## Commit and PR Conventions

- Short, imperative commit subjects, prefixed by area: `feat:`, `fix:`, `refactor:`, `docs:`, `benchmarks:`, `ci:`, `deps:`.
- One logical change per commit where feasible. A failing test plus its fix can share a commit; unrelated refactors should not ride along.
- PR description should include:
  - What changed and why
  - Threat-model relevance (if any)
  - Benchmark / test impact (numbers, not just "tests pass")
  - Backwards-compatibility notes if any public API moved

## Reviewing Security-Sensitive PRs

If you are reviewing a PR that touches the sanitizer, detector, policy engine, request binding, or outbound DLP, look for:

1. Does the change preserve the existing contract for the safe path (no new way for untrusted content to lose its label)?
2. Does it add or update the corresponding unit test?
3. Does it include benchmark delta, and is the FP/FN tradeoff acceptable?
4. Are new heuristics deterministic and side-effect-free (no network, no model calls, no file I/O on the hot path)?

## License

By contributing, you agree that your contributions are licensed under the project's MIT License.
