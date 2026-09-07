# Reproducing Paper Results

<!-- nav:start -->
[Home](README.md) / [Docs index](docs/README.md)
<!-- nav:end -->

<!-- toc:start -->
<details markdown="1">
<summary>On this page</summary>

- [Prerequisites](#prerequisites)
  - [Optional dependency groups](#optional-dependency-groups)
  - [Pinned dependency versions (for exact reproduction of Tier 4 baselines)](#pinned-dependency-versions-for-exact-reproduction-of-tier-4-baselines)
- [Tier 1: Unit Tests and Regression Suite (no API keys, no GPU)](#tier-1-unit-tests-and-regression-suite-no-api-keys-no-gpu)
  - [Run the full test suite](#run-the-full-test-suite)
  - [Run benchmark regression with checkpoint validation](#run-benchmark-regression-with-checkpoint-validation)
  - [Run the eval suite (non-injection controls)](#run-the-eval-suite-non-injection-controls)
- [How Benchmark Data Is Organized](#how-benchmark-data-is-organized)
  - [Upstream provenance](#upstream-provenance)
- [CSE-8000: Control Surface Evaluation (no API keys)](#cse-8000-control-surface-evaluation-no-api-keys)
  - [Run the evaluation](#run-the-evaluation)
  - [Run the baseline evaluation](#run-the-baseline-evaluation)
  - [Verify oracle independence](#verify-oracle-independence)
  - [Mutation tests](#mutation-tests)
- [Tier 2: Cross-Boundary Exfiltration Evaluation (no API keys)](#tier-2-cross-boundary-exfiltration-evaluation-no-api-keys)
  - [External data requirements](#external-data-requirements)
  - [Generate CBX-1000](#generate-cbx-1000)
  - [Evaluate CBX-1000](#evaluate-cbx-1000)
  - [Build pool files for invariance suites](#build-pool-files-for-invariance-suites)
  - [Generate and evaluate invariance suites](#generate-and-evaluate-invariance-suites)
  - [Generate and evaluate benign library (false-positive measurement)](#generate-and-evaluate-benign-library-false-positive-measurement)
- [Tier 3: Deterministic Dataset Rebuild and ROC/PR Curves (no API keys)](#tier-3-deterministic-dataset-rebuild-and-rocpr-curves-no-api-keys)
  - [Rebuild the canonical dataset](#rebuild-the-canonical-dataset)
  - [Run ROC/PR experiments (Vörður-only, local)](#run-rocpr-experiments-vörður-only-local)
  - [Generate ROC and PR figures](#generate-roc-and-pr-figures)
- [Tier 4: Local Competitor Comparison (no API keys)](#tier-4-local-competitor-comparison-no-api-keys)
  - [Run Vörður vs. baselines on all cases](#run-vörður-vs-baselines-on-all-cases)
  - [Surface control results (Table 5 claims)](#surface-control-results-table-5-claims)
- [Tier 5: Vendor API Comparisons (requires API keys)](#tier-5-vendor-api-comparisons-requires-api-keys)
  - [OpenAI and Anthropic](#openai-and-anthropic)
  - [Azure Prompt Shields](#azure-prompt-shields)
  - [AWS Bedrock Guardrails](#aws-bedrock-guardrails)
  - [Full comparison with all vendors](#full-comparison-with-all-vendors)
- [Tier 6: GPU Competitors](#tier-6-gpu-competitors)
  - [ProtectAI DeBERTa](#protectai-deberta)
  - [Meta Llama Guard 4 (12B)](#meta-llama-guard-4-12b)
  - [DataFilter + GPT-4o (contaminated-context exfiltration)](#datafilter--gpt-4o-contaminated-context-exfiltration)
- [Local LLM Demo (no API keys, ~6 GB model download)](#local-llm-demo-no-api-keys-6-gb-model-download)
- [Verifying Specific Paper Claims](#verifying-specific-paper-claims)
  - [Claim: CSE-8000 F1=1.000 across all 8 control kinds](#claim-cse-8000-f11000-across-all-8-control-kinds)
  - [Claim: CBX-1000 attack detection (500/500, 0 FP)](#claim-cbx-1000-attack-detection-500500-0-fp)
  - [Claim: Invariance across text sources](#claim-invariance-across-text-sources)
  - [Claim: 0.75% false positive rate on real email text](#claim-075-false-positive-rate-on-real-email-text)
  - [Claim: Vörður processes inbound content in under 0.1ms](#claim-vörður-processes-inbound-content-in-under-01ms)
  - [Claim: F1 = 85.46 on text-scope injection detection (3,823 records)](#claim-f1--8546-on-text-scope-injection-detection-3823-records)
  - [Claim: 100% on surface controls](#claim-100-on-surface-controls)
  - [Claim: ~10,000x faster than neural-based alternatives](#claim-10000x-faster-than-neural-based-alternatives)
  - [Claim: ROC/PR curves with dev/test split](#claim-rocpr-curves-with-devtest-split)
- [Dataset Provenance](#dataset-provenance)
- [Git Tags](#git-tags)
- [Output Directory Structure](#output-directory-structure)
- [Further Documentation](#further-documentation)

</details>
<!-- toc:end -->

This guide provides step-by-step instructions for reproducing every claim in the paper. Commands are organized into tiers by resource requirements.

## Prerequisites

```bash
git clone https://github.com/mhcoen/Vörður.git
cd Vörður
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

- Python 3.10 or later (CI covers 3.10, 3.11, 3.12, 3.13)
- Reference platform: Mac M3 Max with 128 GB unified memory (all timings in Tiers 1-5 are from this machine unless noted otherwise)
- GPU platform: Linux with NVIDIA A100 80 GB (Tier 6 GPU competitor timings are from this machine)
- Core dependency: `beautifulsoup4>=4.12` (installed automatically)
- No external API keys or GPU required for Tiers 1 through 3
- See [README.md](README.md) for general project overview and API documentation

### Optional dependency groups

Install only the groups you need:

```bash
pip install -e '.[dev]'             # Tier 1: unit tests and regression suite
pip install -e '.[dev,benchmarks]'  # Tiers 2-4: dataset generation and competitor comparison
pip install -e '.[dev,gpu]'         # Tier 6: GPU-based competitors (Llama Guard 4, DeBERTa)
pip install -e '.[examples]'        # Local LLM demo
```

### Pinned dependency versions (for exact reproduction of Tier 4 baselines)

The surface baseline strategies (Tier 4) depend on optional packages. For exact reproduction of the reported numbers, pin these versions:

```
beautifulsoup4==4.14.3
casbin==1.43.0
jsonschema==4.23.0
pydantic==2.12.5
```

If `jsonschema` is not installed, the `schema_jsonschema` strategy cannot run actual validation and falls back to permissive defaults, producing different (lower) pass counts. These packages are installed by `pip install -e '.[benchmarks]'`.

## Tier 1: Unit Tests and Regression Suite (no API keys, no GPU)

### Run the full test suite

```bash
pytest -q
```

Expected: all collected tests pass. No count is published here. A numeric expectation drifts on every commit that adds a test, and the last one quoted here was wrong by more than six thousand.

### Run benchmark regression with checkpoint validation

```bash
python benchmarks/run_benchmarks.py \
  --checkpoint benchmarks/checkpoints/official-baseline.json
```

This evaluates all 12 control surface kinds across native and upstream-derived cases. The checkpoint enforces that pass/fail counts match the baseline exactly (modulo known-failed cases listed in the checkpoint file).

Expected output: checkpoint comparison passes. If optional suites (e.g. wainjectbench) are locally imported, use `--allow-extra-suites` to accept them without checkpoint mismatch.

### Run the eval suite (non-injection controls)

```bash
pytest tests/ -k eval_suite --tb=short
```

This parametrizes each non-`inbound_sanitize` benchmark case as an individual pytest test, covering tool gating, authorization, validation, error sanitization, binding replay, action gating, source gating, rate limiting, canary detection, outbound checks, and contaminated-context exfiltration.

## How Benchmark Data Is Organized

Benchmark cases come from two sources, both committed in the repository:

1. **Native fixtures** in `benchmarks/cases/*.jsonl` (751 cases across 14 files): hand-authored threat patterns covering prompt injection, tool abuse, secrets exfiltration, unicode evasion, cross-boundary exfiltration, error sanitization, and more.

2. **Upstream-derived snapshots** in `benchmarks/upstream/<suite>/<version>/mapped_cases.jsonl` (up to 10,064 cases across 9 suites): imported from pinned commits of external benchmark repositories (PINT, BIPIA, AgentDojo, JailbreakBench, HarmBench, InjecAgent, MCPBench, mcp-bench, WAInjectBench).

All upstream snapshots are committed and available after `git clone`. No separate download or build step is needed to run Tier 1 or Tier 4 benchmarks.

The scripts `run_benchmarks.py` and `compare_mitigations.py` load cases directly from these two locations. The `build_dataset.py` script (Tier 3) assembles them into a single canonical dataset package for the ROC/PR experiments, which require a unified `cases.jsonl` with provenance metadata.

### Upstream provenance

Each upstream suite is pinned to a specific commit SHA in `benchmarks/upstream/manifest.json`. To verify provenance or re-import from upstream:

```bash
# View pinned refs and case counts
python -c "
import json; m = json.load(open('benchmarks/upstream/manifest.json'))
for s in m['sources']:
    print(f\"{s['suite']:20s} ref={s['ref'][:12]} mapped={s['mapped_cases']}\")
"
```

One suite (`wainjectbench`) has no upstream license signal and is **not included** in the repository. To use it, fetch the data from the upstream repository and import locally:

```bash
# wainjectbench (WAInjectBench @ 4a5b7a5d)
git clone https://github.com/Norrrrrrr-lyn/WAInjectBench /tmp/wainjectbench
cd /tmp/wainjectbench && git checkout 4a5b7a5d
cd /path/to/Vörður
python benchmarks/import_official_exports.py \
  --suite wainjectbench \
  --input /tmp/wainjectbench \
  --ref 4a5b7a5d4e393983d7105aed3485014b7206d205
```

This suite is optional. All benchmark results, the eval suite, and the comparison tables work without it. See `benchmarks/DATASET_REPRO.md` for the full acquisition and verification protocol.

## CSE-8000: Control Surface Evaluation (no API keys)

The CSE-8000 evaluation tests all 8 security control kinds against an independent oracle with 1,000 cases per kind (500 attack, 500 benign). The oracle is in `devel/` and has zero imports from `src/vordur/`.

> **Not runnable from a clone.** The evaluator, the baselines, the oracle, and the case file this section invokes live under `devel/`, which is not tracked in this repository. Until they are published, the CSE-8000 figures below are reported rather than reproducible, and the tracked surface evidence in `benchmarks/published/` is the verifiable record for the control surfaces.

### Run the evaluation

```bash
python devel/cse_eval_guardllm.py
```

Expected: 8,000/8,000 agreement (F1=1.000, Precision=1.000, Recall=1.000). Per-kind breakdown: 500 TP, 0 FP, 0 FN, 500 TN for each of: source_gate, validation, tool_gate, rate_limit, action_gate, binding_replay, outbound_dlp, tool_gate_auth.

### Run the baseline evaluation

```bash
python devel/cse_eval_baselines.py
```

Expected: surface_stack baseline F1=0.712, Precision=0.903, Recall=0.588. The baseline collapses on cross-stage controls (F1=0.477) because surface_stack has no binding replay, no outbound DLP, and weak contamination-aware gating.

### Verify oracle independence

The oracle labels in `devel/cse_oracle_cases_1k.jsonl` are generated by `devel/cse_oracle.py` and `devel/cse_generate_cases_1k.py`. Neither file imports from `src/vordur/`. To verify:

```bash
grep -r "from vordur\|import vordur" devel/cse_oracle.py devel/cse_generate_cases_1k.py
```

Expected: no output (zero matches). The oracle reimplements decision logic independently from the specification documents (`devel/cse_security_spec.md` v2.0, `devel/cse_conformance_profile.md` v1.0).

### Mutation tests

Three targeted mutations prove the evaluation is sensitive to real code changes. Each mutation should collapse exactly the targeted control kind.

**Mutation 1: Disable binding verification**

In `src/vordur/security/request_binding.py`, replace the body of `verify_binding()` (lines 80-101) with a single line: `return True, "Binding verified"`. Then rerun the evaluation:

```bash
python devel/cse_eval_guardllm.py
```

Expected for binding_replay: TP=229, FP=0, FN=271, TN=500 (recall collapses from 1.000 to 0.458). Revert the file after checking.

**Mutation 2: Disable auth expiry check**

In `src/vordur/security/policy_engine.py`, comment out or remove the TTL verification block (the `elapsed = time.time() - auth_event.timestamp` / `if elapsed > self._auth_ttl` check near the end of `_check_client`). Then rerun:

```bash
python devel/cse_eval_guardllm.py
```

Expected for tool_gate_auth: TP=372, FP=0, FN=128, TN=500 (recall collapses from 1.000 to 0.744). Side effect: binding_replay also shows 126 FN because some binding cases depend on auth expiry at stage 2. Revert the file after checking.

**Mutation 3: Disable outbound DLP**

In `src/vordur/security/outbound_dlp.py`, insert `return OutboundResult(allowed=True, reason="disabled")` as the first line of `OutboundDLP.check()`. Then rerun:

```bash
python devel/cse_eval_guardllm.py
```

Expected for outbound_dlp: TP=0, FP=0, FN=500, TN=500 (complete collapse, recall 0.000). Revert the file after checking.

**Mutation summary:**

| Mutation | Target Kind | Before (TP/FP/FN/TN) | After (TP/FP/FN/TN) | Recall |
|----------|-------------|----------------------|---------------------|--------|
| 1: binding always True | binding_replay | 500/0/0/500 | 229/0/271/500 | 0.458 |
| 2: skip auth expiry | tool_gate_auth | 500/0/0/500 | 372/0/128/500 | 0.744 |
| 3: DLP always allow | outbound_dlp | 500/0/0/500 | 0/0/500/500 | 0.000 |

## Tier 2: Cross-Boundary Exfiltration Evaluation (no API keys)

These datasets evaluate the contaminated-context egress gate, the paper's primary
contribution. They require cloning external repos to build pool files but no API
keys or GPU.

### External data requirements

**EnronSent Corpus v1.0** (public domain, ~25 MB):

```bash
mkdir -p /tmp/enron && cd /tmp/enron
curl -LO http://wstyler.ucsd.edu/files/enronsentv1.tar.gz
tar xzf enronsentv1.tar.gz
```

Source: William Styler, UC Colorado. Public domain preparation of the Enron
Sent Corpus. URL: `http://wstyler.ucsd.edu/files/enronsentv1.tar.gz`

The extraction script reads all `.txt` files under the extracted directory,
deduplicates email bodies, filters to lines with 40+ characters and 40%+
alphabetic content, and truncates each to 2000 characters.

Expected pool: 15,371 lines.
SHA-256: `5f393c58297a6fb84bfa4d6b5d64540ac0f8098dec8663f95d14f190ea64d717`

**OWASP CRS and PayloadsAllTheThings** (cloned automatically by `sources_owasp.py`):

| repo | commit | license |
|---|---|---|
| `coreruleset/coreruleset` | `5486e697bd336cedca4a0d4cece16722a6088235` | Apache-2.0 |
| `swisskyrepo/PayloadsAllTheThings` | `10d41d2e7de0de20c424c90ceb118a5993110081` | MIT |

**LLM injection repos** (cloned automatically by `scripts/gen_cbx1000.py` and `sources_llm.py`):

| repo | commit | license |
|---|---|---|
| `uiuc-kang-lab/InjecAgent` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT |
| `ethz-spylab/agentdojo` | `462c88ddf596cb745882702f9999c8aeb5fe467f` | MIT |
| `lakeraai/pint-benchmark` | `0aa0d6415d6ce3108c6cbd8fb630b2ffaa6ee9f8` | MIT |
| `Giskard-AI/prompt-injections` | `ce50a549dadc46b48c931250d2dd71d5f003c0c2` | MIT |

### Generate CBX-1000

```bash
python scripts/gen_cbx1000.py
```

Output: `artifacts/cbx1000/cbx_1000_v1_seed20260222.jsonl` (1000 cases) and
manifest with repo commit SHAs and source file hashes.

Distribution: 500 expected BLOCK, 350 expected ALLOW, 150 REPORT_LIMITATION.

### Evaluate CBX-1000

```bash
python benchmarks/eval_cbx1000.py
```

Expected: 500/500 expected-BLOCK cases blocked, 0 false negatives, 0 false positives.

### Build pool files for invariance suites

```bash
python scripts/gen_suites/sources_llm.py --cache_dir artifacts/suites/cache
python scripts/gen_suites/sources_owasp.py --cache_dir artifacts/suites/cache
```

The benign pool must be built from the EnronSent download above. Place the
processed file at `artifacts/suites/cache/benign_noise.txt`.

Expected pool sizes:
- `llm_injection.txt`: 219 lines
- `owasp_payload.txt`: 7,191 lines
- `benign_noise.txt`: 15,371 lines

### Generate and evaluate invariance suites

```bash
python scripts/gen_suites/gen_attack_suites.py \
  --outdir artifacts/suites --seed 20260222 \
  --cache_dir artifacts/suites/cache

python benchmarks/eval_invariance_suites.py
```

Expected: all three suites produce identical results (500/500 blocked, 0 FN,
0 FP). This proves detection is mechanism-driven, not corpus-tuned.

### Generate and evaluate benign library (false-positive measurement)

```bash
python scripts/gen_suites/gen_benign_library.py \
  --outdir artifacts/suites --seed 20260222 \
  --benign_pool artifacts/suites/cache/benign_noise.txt --N 2000

python benchmarks/eval_benign_library.py
```

All 2000 cases are expected ALLOW. Any block is a false positive.

Expected FP rate: 0.75% (15/2000). Breakdown:
- 4 from high-entropy tokens in real Enron email text (secret scanner)
- 11 from provenance overlap (genuinely similar email pairs at LCS >= 50)
- 0 from DLP

## Tier 3: Deterministic Dataset Rebuild and ROC/PR Curves (no API keys)

### Rebuild the canonical dataset

```bash
SOURCE_DATE_EPOCH=0 python benchmarks/build_dataset.py --dataset-id canonical-v1
```

Output: `benchmarks/datasets/canonical-v1/` containing `cases.jsonl`, `case_manifest.json`, and `METADATA.json`.

Verify determinism by running the command twice and comparing SHA-256 hashes:

```bash
shasum -a 256 benchmarks/datasets/canonical-v1/cases.jsonl
```

The hash should match `METADATA.json`'s `dataset_hash_sha256` field.

### Run ROC/PR experiments (Vörður-only, local)

```bash
python benchmarks/roc_pr_experiments.py \
  --run-id rocpr-canonical-local \
  --dataset-id canonical-v1
```

This produces dev/test split analysis with threshold selection on dev and frozen evaluation on test. All curves are dev-sourced. 95% Wilson confidence intervals are computed for recall, precision, and FPR.

Output: `benchmarks/runs/rocpr-canonical-local/roc_pr_experiments.json` and `.md`

### Generate ROC and PR figures

```bash
python benchmarks/plot_roc_pr.py --run-id rocpr-canonical-local
```

Output: `benchmarks/runs/rocpr-canonical-local/roc_curve.svg` and `pr_curve.svg`

## Tier 4: Local Competitor Comparison (no API keys)

### Run Vörður vs. baselines on all cases

This loads cases directly from the committed fixture files (see "How Benchmark Data Is Organized" above). `--dataset-id ""` selects that path; without it the tool defaults to `--dataset-id canonical-v1`, which requires the Tier 3 build step above and fails on a fresh clone because `benchmarks/datasets/` is gitignored.

```bash
python benchmarks/compare_mitigations.py --dataset-id "" --run-id comparison-local
```

This evaluates `vordur`, `isolation_only`, `source_gate_only`, `regex_rule_based`, and `no_defense` strategies on all benchmark cases. No external API calls are made.

Output: `benchmarks/runs/comparison-local/comparison.json` and `comparison.md`

### Surface control results (Table 5 claims)

The comparison report includes a surface controls section. Key claims to verify:
- Vörður: 100% on surface controls
- `surface_stack` (OPA + Redis + Casbin + JSON Schema composed): 65.98% on surface controls
- `no_defense_surface`: 12.5% on surface controls

Both figures are the published ones in `benchmarks/published/surface_controls.md`, which records the run id, commit, and dataset hash behind them.

Optional surface-stack dependencies (included in `pip install -e '.[benchmarks]'`):

```bash
# If not using the benchmarks extras group, install individually:
pip install casbin pydantic jsonschema
# OPA: download from https://www.openpolicyagent.org/docs/latest/#running-opa
# Redis: install via package manager (brew install redis, apt install redis-server)
```

## Tier 5: Vendor API Comparisons (requires API keys)

### OpenAI and Anthropic

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-vendors \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-4.1-mini" \
  --anthropic-api-key "$ANTHROPIC_API_KEY" \
  --anthropic-model "claude-3-5-haiku-latest"
```

### Azure Prompt Shields

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-azure \
  --azure-endpoint "https://<name>.cognitiveservices.azure.com" \
  --azure-key "$AZURE_KEY"
```

### AWS Bedrock Guardrails

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-bedrock \
  --bedrock-guardrail-id "$BEDROCK_GUARDRAIL_ID" \
  --bedrock-guardrail-version "$BEDROCK_GUARDRAIL_VERSION" \
  --bedrock-profile "bedrockbench" \
  --bedrock-region "us-east-1"
```

### Full comparison with all vendors

```bash
python benchmarks/compare_mitigations.py \
  --run-id comparison-full \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-4.1-mini" \
  --anthropic-api-key "$ANTHROPIC_API_KEY" \
  --anthropic-model "claude-3-5-haiku-latest" \
  --azure-endpoint "https://<name>.cognitiveservices.azure.com" \
  --azure-key "$AZURE_KEY" \
  --bedrock-guardrail-id "$BEDROCK_GUARDRAIL_ID" \
  --bedrock-guardrail-version "$BEDROCK_GUARDRAIL_VERSION" \
  --bedrock-profile "bedrockbench" \
  --bedrock-region "us-east-1"
```

## Tier 6: GPU Competitors

DeBERTa timings were collected on Mac M3 Max (MPS acceleration). Llama Guard 4 timings were collected on Linux with an NVIDIA A100 80 GB.

### ProtectAI DeBERTa

```bash
pip install -e '.[gpu]'  # or: pip install transformers torch
python benchmarks/compare_mitigations.py \
  --run-id comparison-deberta \
  --open-source-model-id "protectai/deberta-v3-base-prompt-injection-v2"
```

Runs on CPU (slower) or GPU (automatic detection via PyTorch). Paper numbers (27ms avg latency) were collected on Mac M3 Max using MPS (Metal Performance Shaders) acceleration. On CUDA GPUs, latency will be similar or faster. On CPU, expect ~100-200ms per inference.

### Meta Llama Guard 4 (12B)

Requires a GPU with sufficient VRAM (A100 80 GB recommended). Paper results
(178ms avg latency) were collected on Linux with an NVIDIA A100 80 GB.

**HuggingFace access request required.** Llama Guard 4 is a gated model. Before
running, visit the model page on HuggingFace
(`meta-llama/Llama-Guard-4-12B`) and request access. Once approved:

```bash
pip install -e '.[gpu]'  # or: pip install torch transformers huggingface_hub accelerate
huggingface-cli login   # paste your HF token when prompted
python benchmarks/eval_llama_guard4.py --run-id llama-guard4-v1
```

Merge Llama Guard 4 results into the comparison table:

```bash
python benchmarks/compare_mitigations.py \
  --llama-guard-results benchmarks/runs/llama-guard4-v1/llama_guard4_eval/results.json \
  --run-id comparison-with-lg4
```

### DataFilter + GPT-4o (contaminated-context exfiltration)

```bash
python local/eval_datafilter_gpt4o_contaminated_context.py \
  --run-id datafilter-gpt4o-cc \
  --openai-api-key "$OPENAI_API_KEY"
```

## Local LLM Demo (no API keys, ~6 GB model download)

The demo runs a real LLM (Qwen2.5-3B-Instruct) through the pipeline twice: once without Vörður (injection succeeds, account number exfiltrated), once with Vörður (hidden div stripped, injection flagged, egress gate blocks exfiltration).

```bash
pip install -e '.[examples]'  # or: pip install transformers torch accelerate
python examples/demo_local_llm.py
```

Runtime: under 5 minutes on the reference platform (excluding first-time model download). See `examples/README.md` for details.

## Verifying Specific Paper Claims

### Claim: CSE-8000 F1=1.000 across all 8 control kinds

Run the CSE-8000 evaluation (see "CSE-8000: Control Surface Evaluation" above).
Expected: 8,000/8,000 agreement. To verify this is not trivial agreement, run
the three mutation tests; each collapses the targeted kind's recall.

### Claim: CBX-1000 attack detection (500/500, 0 FP)

Run Tier 2 (`eval_cbx1000.py`). Expected: 500 expected-BLOCK cases all blocked,
350 expected-ALLOW cases all allowed, 0 false negatives, 0 false positives.

### Claim: Invariance across text sources

Run Tier 2 (`eval_invariance_suites.py`). The three suites use different
untrusted text sources (LLM injections, OWASP payloads, benign Enron emails)
but produce identical blocked/FN/FP counts: 500/0/0.

### Claim: 0.75% false positive rate on real email text

Run Tier 2 (`eval_benign_library.py`). The 2000-case benign library drawn from
real Enron email text yields 15 false positives (0.75%). Zero of these come
from the DLP layer; 11 are provenance overlap between genuinely similar email
pairs, 4 are high-entropy tokens in real email text.

### Claim: Vörður processes inbound content in under 0.1ms

This is measured by the benchmark harness latency column. Run Tier 4 and check the `avg_latency_ms` field for `vordur` in `comparison.json`.

### Claim: F1 = 85.46 on text-scope injection detection (3,823 records)

Run Tier 4 or Tier 5. The text-scope comparison section of `comparison.md` shows F1, precision, recall, and latency for all strategies. Record count (3,823) is the `injection`-scope text projection from the canonical dataset (1,021 attacks, 2,802 benign).

### Claim: 100% on surface controls

Run Tier 4. The surface comparison section shows Vörður at 100% across all surface control kinds.

### Claim: ~10,000x faster than neural-based alternatives

Compare Vörður's avg latency (0.07ms) against vendor latencies in the comparison table. The ratio against typical neural classifiers (27ms for DeBERTa, 178ms for Llama Guard 4, 600-750ms for API-based) ranges from ~400x to ~10,000x.

### Claim: ROC/PR curves with dev/test split

Run Tier 3. The methodology uses deterministic stratified dev/test split (seed=1337, dev_fraction=0.30, dev_max_records=700). Threshold selection on dev only; frozen thresholds evaluated once on test with 95% Wilson intervals.

## Dataset Provenance

The canonical dataset (`canonical-v1`) is built from:
- 14 native fixture files in `benchmarks/cases/` (751 cases)
- 9 upstream-derived snapshots in `benchmarks/upstream/` (up to 10,064 cases)

All upstream sources are pinned by commit SHA in `benchmarks/upstream/manifest.json`. Two suites (`mcp_bench`, `wainjectbench`) have unclear upstream licensing and must be fetched directly from their source repositories.

Full dataset provenance protocol: `benchmarks/DATASET_REPRO.md`
Upstream acquisition matrix: `benchmarks/upstream/manifest.json`

## Git Tags

For pinning specific paper versions, tag the submission commit:

```bash
git tag -a cacm-submission -m "CACM paper submission"
git push origin cacm-submission
```

## Output Directory Structure

All benchmark outputs are written to `benchmarks/runs/<run_id>/`:
- `latest.json`: core benchmark results
- `comparison.json` / `comparison.md`: competitor comparison
- `roc_pr_experiments.json` / `.md`: ROC/PR analysis
- `roc_curve.svg` / `pr_curve.svg`: figures
- `METADATA.json`: dataset provenance (when built with `--run-id`)

## Further Documentation

- Benchmark methodology and metric definitions: `benchmarks/methodology.md`
- Dataset rebuild protocol: `benchmarks/DATASET_REPRO.md`
- Auditor verification checklist: `benchmarks/VERIFICATION.md`
- Canonical result pointers: `benchmarks/results.md`
- Security architecture: `docs/security.md`
