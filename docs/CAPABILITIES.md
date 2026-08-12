# Capabilities and boundaries

This document describes the `v0.2.0-alpha.1` preparation, not a future roadmap
presented as finished behavior.

## Available core

| Area | Current behavior |
|---|---|
| Research profile | JSON profile defines the question, scope, sources, budgets, gates, analysis policy, and output paths |
| Paper discovery | OpenAlex and arXiv official paths with source observations and reproducible query records |
| Repository discovery | GitHub official API metadata and static official repository archives |
| Hosted supplement | Bounded Codex-hosted discovery followed by official verification before admission |
| Content | PDF parsing and static repository text acquisition with size, archive, and disk guards |
| Repository selection | Core plus bounded auxiliary corpus selection, with complete manifest, exclusion reasons, and offline dry-run reprojection for cached ZIPs |
| Deep reading | Structured chunk analysis, hierarchical reduction, final synthesis, receipts, and evidence checks |
| Providers | Codex CLI primary path and explicit llama.cpp fallback path |
| Recovery | SQLite leases, retry/backoff, `not_before`, budget pause, interrupt cleanup, and explicit retry commands |
| Decision support | Ranking, compact decision slice, four-level feedback, report and citation/reproduction exports |
| UI | Loopback-only dashboard with progress, state, model usage, evidence, and historical/current distinctions |
| Security | Public-address checks, redirect validation, throttling, response/archive limits, static code handling, and secret-safe logs |

## Alpha onboarding surface

The public alpha uses:

```powershell
r3radar doctor
r3radar demo
r3radar create-profile
```

Each command also supports `python -m r3radar ...`. `demo` is deterministic and
isolated; `doctor` diagnoses prerequisites; `create-profile` creates a user-owned
profile without modifying the bundled examples.

## Important boundaries

- The complete hardened path is Windows 10/11 with CPython 3.10.
- The package is not claimed to be published on PyPI.
- Linux and Docker are not claimed as supported deployment paths.
- The dashboard is not designed for remote exposure or multiple users.
- R3 does not provide institutional full-text access or bypass paywalls.
- A metadata-only record cannot become a completed deep read.
- Hosted discovery alone cannot become an admitted recommendation.
- Repository code is inspected statically and is not executed or benchmarked.
- Codex analysis sends selected content to a remote provider; local-first is not
  equivalent to fully offline.
- llama.cpp is an explicit fallback and its results retain provider/fallback
  labels.
- Four-level feedback is stored, but adaptive personalized ranking has not yet
  been validated with real feedback volume.
- The current implementation is not a PRISMA-compliant systematic-review product.
- It does not claim autonomous scientific truth, publication-ready writing, or
  replacement of human paper/code reading.

## Historical versus current evidence

The existing focus workspace contains 15 admitted items with historical deep-read
results. They remain useful and visible, but they are not evidence that the
current model and prompt policy has completed the same set. The UI must continue
to show that distinction.

## Extension points

Good bounded contributions include:

- official-source adapters with documented quotas and terms;
- parsers that preserve content identity and location;
- deterministic profile templates;
- evidence validators;
- ranking baselines and human-labeled evaluation tooling;
- citation/export formats;
- accessibility and compact-triage improvements;
- provider adapters that preserve receipts, budgets, and fallback identity.

New remote deployment modes, account systems, collaboration roles, billing,
permission models, and cross-repository execution are architectural expansions
and require explicit design and threat review.
