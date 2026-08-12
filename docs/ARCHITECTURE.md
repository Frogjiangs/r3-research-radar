# Architecture

R3 Research Radar is a local, stateful research pipeline. Its central design
choice is to preserve the difference between discovery, verified content,
analysis, and a human research decision.

## System flow

```text
Research profile
  -> query planning
  -> source-specific retrieval
  -> official verification and deduplication
  -> objective admission gates
  -> paper/repository content acquisition
  -> immutable content revision and manifest
  -> chunk or selected-corpus analysis
  -> hierarchical synthesis
  -> ranking and decision slice
  -> feedback, exports, and reproducibility handoff
```

## Main components

| Component | Responsibility |
|---|---|
| `config.py`, `models.py` | Parse the research profile and typed runtime settings |
| `sources.py`, `http_client.py` | Retrieve source records with provider attribution, throttling, retry, and budgets |
| `verification.py` | Verify hosted discoveries against official source metadata |
| `content.py`, `pdf_parser.py` | Acquire and normalize static paper/repository content |
| `document_policy.py` | Select a research-relevant repository corpus and record exclusions |
| `evidence.py` | Preserve chunks, anchors, hashes, and coverage checks |
| `codex_worker.py`, `llama_worker.py` | Execute provider-specific structured analysis |
| `pipeline.py`, `recovery.py`, `continuity.py` | Coordinate leases, budgets, pausing, resumption, and cleanup |
| `ranking.py`, `decision.py`, `report.py` | Produce bounded recommendations, frozen decisions, and exports |
| `storage.py`, `reproduction.py` | Persist append-oriented facts and create reproducibility evidence |
| `web.py`, `static/` | Serve the loopback-only triage and audit interface |

## Evidence invariants

1. A source hit is not a recommendation.
2. Hosted discovery cannot bypass official verification.
3. Content identity is attached to a revision and hash.
4. Analysis identity includes provider, model, policy, prompt, and content
   revision.
5. Coverage must account for included chunks without hidden gaps or duplicates.
6. Repository selection must retain the complete file manifest and exclusion
   reasons.
7. Current-policy and historical results must remain distinguishable.
8. Failure, fallback, pause, block, rejection, and incomplete coverage are
   first-class visible states.
9. Re-fetching content must not rewrite an older analysis retrospectively.
10. A published decision slice identifies the run from which it was produced.

## State and recovery

SQLite is the authoritative coordination and provenance store. Work leases prevent
two workers from claiming the same unit. Long provider waits become `not_before`
state rather than holding the entire process open. Budget exhaustion pauses work
without converting it to a content or model failure.

An interrupt releases query, verification, content, analysis, and run leases in
one cleanup path and persists a paused terminal receipt. On Windows, the hardened
Codex path uses a Job Object so child processes do not survive an interrupted
foreground run.

## Trust boundaries

### Network

Requests reject URL userinfo, HTTPS downgrade, and destinations that resolve to
private, loopback, link-local, or otherwise non-public addresses. Redirects are
checked again. Per-host reservations, response budgets, `Retry-After`, backoff,
and circuit breakers are shared through SQLite.

### Retrieved content

Papers, archives, and repository files are untrusted data. Archive paths,
compression ratios, file sizes, total text, and download volume are bounded.
Repository code, dependencies, Git hooks, binaries, and Actions are not executed.

### Models

Selected content may be sent to the configured model provider. Structured output
is validated against schemas and evidence anchors are checked against the exact
content revision. A local fallback is labeled as a fallback and cannot impersonate
the primary provider.

### User interface

The dashboard listens on loopback, applies a content security policy, and rejects
non-local feedback origins. It is not currently a multi-user or remotely exposed
application.

## Deployment boundary

The fully hardened and tested path is Windows 10/11 with CPython 3.10. The alpha
metadata supports editable installation, but no Linux, Docker, PyPI, server, or
hosted-service guarantee is made.
