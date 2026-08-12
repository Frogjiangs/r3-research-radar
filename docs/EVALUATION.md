# Evaluation

R3 separates software correctness, onboarding determinism, historical output,
recommendation quality, and product usefulness. Passing one layer must not be
reported as passing another.

## Current evidence

| Evidence layer | Current status | What it supports | What it does not support |
|---|---|---|---|
| Engineering regression | Read the generated `r3/verification-receipt/v1` CI artifact for the exact command, count, result and source manifest | The behaviors covered by that exact command and source manifest | Scientific relevance, live-provider reliability, or market demand |
| Deterministic demo | Bundled alpha path | Installation, command discovery, stable fixture ingestion, and result rendering without paid APIs | Live recall, model reasoning quality, or source freshness |
| Bounded focus run | 15 admitted items completed under one recorded current-policy run | That run can acquire, analyze, cite, and render real papers/repositories with recorded provenance | General recommendation quality, external recall, or future-run reliability |
| Human relevance benchmark | Not yet completed | Nothing yet | Precision, recall, ranking quality, decision impact, and time saved |

The generated engineering result is scoped to its command and source-manifest
hash. It is not a percentage of product completion or a recommendation-quality
score. Static documentation intentionally omits the changing test count.

## Reproduce the engineering checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q r3radar
.\.venv\Scripts\python.exe scripts\generate_verification_receipt.py --output verification-receipt.json -- .\.venv\Scripts\python.exe -m unittest discover -s tests -p test_*.py
```

The unit suite is expected to be deterministic. A test that intentionally
exercises pause or interruption may print a paused receipt while still passing;
the final test-run status is authoritative.

## Human and external relevance evidence

`/gold-review` is a server-enforced blind y0 workflow. All 70 y0 judgments
must be saved and locked before any AI-assistance stage. Operational failure
and semantic relevance are separate, and `unjudged` is not counted as a
negative label. A novice review remains a user judgment, not universal truth.

External known-answer evaluation requires an independently sourced, frozen
20–35 item set. Use `known-answer-validate` and `known-answer-evaluate`; the
receipt rejects self-sourced pools and reports missing identities, unknown
denominators and baseline comparisons explicitly.

## Deterministic demo contract

`r3radar demo` is intended to:

- require no live network, API key, or paid model;
- use redistributable, fixed fixtures;
- create an isolated demo workspace;
- exercise one synthetic paper and one synthetic repository result;
- expose evidence, compact decision summaries, feedback, decisions, and exports;
- be safe to rerun without changing the user’s production database.

Module fallback:

```powershell
.\.venv\Scripts\python.exe -m r3radar demo
```

Demo success is an onboarding acceptance check only.
Exclusion, historical-policy, unavailable-content, and failure rendering remain
covered by engineering tests and real-workspace validation; the two-item demo
does not pretend to exercise those states.

## Required prospective relevance benchmark

A credible relevance claim requires a human-labeled candidate set collected from
real research periods. The minimum useful design is:

1. Freeze two or more candidate pools before deep reading.
2. Label each candidate as must-read, useful background, defer, or irrelevant.
3. Record the reason and whether it changed a research decision.
4. Preserve the profile, query plan, provider observations, timestamps, and
   exclusions.
5. Evaluate at a bounded decision surface, such as the top 3, 5, or 10.
6. Compare against simple baselines: keyword matching, recency, citation/star
   count, and unpersonalized ranking.

Recommended metrics:

- Precision@K and Recall@K;
- nDCG@K for graded usefulness;
- must-read miss rate;
- false-positive review burden;
- evidence-anchor verification rate;
- elapsed time, model calls, input/output tokens, and cache reuse;
- human minutes spent verifying a recommendation;
- decisions changed and later judged useful.

The benchmark must report disagreements and missing labels. An LLM judge may be a
secondary diagnostic, not the sole ground truth for personal research value.

## Performance evaluation

Historical invocation totals include older policies, retries, and exhaustive
repository reads. They are not a clean benchmark of the current selected-corpus
and controlled-concurrency policy.

A valid before/after performance experiment should hold candidate content and
model policy constant while varying only one factor, such as corpus selection,
chunk batch size, or concurrency. Report wall time, provider time, calls, tokens,
cache reuse, evidence pass rate, retry count, and a blinded human quality review.

## Reporting rule

Every public result should identify:

- repository version or commit;
- configuration and profile hash;
- dataset or run ID;
- provider, model, and reasoning policy;
- test or benchmark command;
- timestamp and environment;
- missing evidence and known limitations.
