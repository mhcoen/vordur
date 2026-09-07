# Benchmark Methodology

<!-- nav:start -->
[Home](../README.md) / [Benchmarks](README.md)
<!-- nav:end -->

This file is the protocol contract for benchmark metrics and figures.

## Dataset And Unit Of Evaluation

- Unit: one benchmark case record.
- Case loading:
  - fixture + upstream snapshots: `benchmarks/run_benchmarks.py` (`load_cases` without `--dataset-id`)
  - prebuilt dataset package: `benchmarks/run_benchmarks.py` (`load_cases` with `--dataset-id`)
- Canonical dataset package writer: `benchmarks/build_dataset.py`.

## Labeling And Text Projection

- Text record derivation and attack labeling are implemented in `benchmarks/compare_mitigations.py` (`build_text_records`).
- Injection-only scope uses fixed suite allowlist `TEXT_SCOPE_INCLUDED_SUITES` in `benchmarks/compare_mitigations.py`.

## Split Protocol

- Deterministic stratified dev/test split by `(suite, label_attack)` in `benchmarks/roc_pr_experiments.py` (`_stratified_split_indices`).
- Duplicate texts (case-folded, with whitespace collapsed) form global groups, even across suites or labels. Each group uses its first record's stratum and stays whole through both the initial split and development-cap pruning. The cap is an upper bound, not a promise of an exact development count; a group too large to fit stays entirely in test. Corrected cap pruning can change split membership, so recompute operating points when changing splitter versions.
- Defaults:
  - `split_seed=1337`
  - `dev_fraction=0.30`
  - `dev_max_records=700`

## Curve And AUC Policy

- ROC/PR points and AUC are computed from dev split only in `benchmarks/roc_pr_experiments.py`.
- All methods report `curve_source: "dev"` in the run JSON payload.
- Non-tunable methods are single-point frontiers.

## Operating Point Policy

- Threshold selection is done on dev only:
  - objective: maximize recall subject to budget
  - tie-breaks: lower FP then higher precision
- Frozen thresholds are evaluated once on test.
- Budget fields are split by evaluation split:
  - `meets_budget_dev`
  - `meets_budget_test`

## Precision Convention

- Precision is defined as `1.0` when `TP + FP == 0`.
- This convention is encoded in `benchmarks/roc_pr_experiments.py` confusion-metric logic.

## Uncertainty Intervals

- 95% Wilson intervals are computed for:
  - recall
  - precision
  - FPR
- Intervals are attached to default and budget-selected frozen test operating points.

## Output Layout

- Dataset packages: `benchmarks/datasets/<dataset_id>/`
- Benchmark runs: `benchmarks/runs/<run_id>/`
- Caches: `benchmarks/cache/`
- `benchmarks/runs/LATEST.txt` points to the latest run id.

## Local-Only Reproducibility Mode

- All benchmark scripts support local execution without vendor APIs by passing empty API keys.
- `roc_pr_experiments.py` can run against a built dataset package via `--dataset-id`.
