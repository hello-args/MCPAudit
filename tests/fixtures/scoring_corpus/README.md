# Scoring calibration corpus (dev/CI only — not shipped in wheel)

Expert ordering validated by corpus Spearman rho>=0.80 (see `expert_rankings.json` calibration block). Formal external panel review still recommended before public GA announcement.

Shared loader: `mcts.scoring.corpus_runner` (used by `scripts/run_scoring_corpus.py`,
`scripts/calibrate_scoring_weights.py`, and `tests/scoring/`). Technique regression harness
(`mcts.testing.regression_harness`) remains separate — it validates detector accuracy, not
risk-score ordering.
