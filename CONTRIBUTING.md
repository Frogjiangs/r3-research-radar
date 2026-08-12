# Contributing to R3 Research Radar

R3 is an evidence-oriented research tool. A change is useful only when its
behavior, inputs, outputs, and limits remain inspectable.

## Before opening a change

1. Search existing issues and describe the concrete research workflow or defect.
2. Keep the change narrow. New providers, deployment modes, permission models,
   storage models, and external services require design discussion first.
3. Never include API keys, tokens, private papers, local databases, model
   receipts, user profiles, or generated research output in a commit.
4. Do not add scraping behavior that bypasses access controls, CAPTCHAs, quotas,
   `robots` policies, or provider terms.

## Development setup

The complete hardened development path is currently Windows 10/11 with
CPython 3.10.

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

For the exact locked environment used by the project:

```powershell
.\scripts\SETUP.ps1
```

The editable install is convenient for development. The locked script is the
current supply-chain-controlled path.

## Verification

Run the narrowest relevant test while developing. Before requesting review for a
shared-core or release-facing change, run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q r3radar
```

Tests must be deterministic by default. Live network and paid-model checks belong
in explicitly invoked integration paths and must not silently run in the unit
suite.

## Evidence and data rules

- A discovery hit must not be presented as a recommendation.
- Preserve source observations, content revisions, hashes, coverage, provider
  identity, policy identity, and decision history.
- A failed, blocked, deferred, rejected, incomplete, historical, or fallback
  result must remain distinguishable from current-policy success.
- Fixtures must be synthetic, redistributable, or explicitly licensed for the
  repository.
- Do not hand-edit generated metrics to make a test or benchmark pass.
- Any benchmark claim must identify the dataset, configuration, model/provider,
  date, scoring method, and known missing evidence.

## Pull request checklist

- [ ] The change closes a specific user-visible or evidence-visible gap.
- [ ] No secret, private input, generated database, or local absolute path was
      added.
- [ ] Relevant tests and compilation pass.
- [ ] Public behavior and boundaries are documented.
- [ ] New dependencies are necessary, pinned where required, and reviewed for
      license and supply-chain impact.
- [ ] Network behavior remains rate-limited, attributable, and recoverable.
- [ ] Historical records are not silently rewritten.

## Community conduct and security

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Do not disclose a vulnerability, credential, or private research artifact in a
public issue. Request a private maintainer contact without including sensitive
details if a private reporting channel is not yet visible.
