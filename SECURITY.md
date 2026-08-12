# Security Policy

## Supported scope

R3 Research Radar is currently a local, single-user research tool. The dashboard
is intentionally restricted to the loopback interface (`127.0.0.1`,
`localhost`, or `::1`). It is not a production web service and must not be
exposed directly to the public internet.

The current codebase does not provide:

- user authentication or authorization;
- tenant isolation;
- TLS termination;
- per-user quotas or billing controls;
- a hosted secret vault;
- a production service-level agreement.

Changing the listen address, placing the dashboard behind a public tunnel, or
forwarding its port does not add these controls and is not a supported
deployment.

## Supported versions

Security fixes are applied to the current development line. Historical local
snapshots and acceptance artifacts are not maintained as independent releases.

| Version | Supported |
| --- | --- |
| Current development line | Yes |
| Historical snapshots | No |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow in the repository's
**Security** tab when it is available. Include:

- the affected version or commit;
- the smallest safe reproduction;
- expected and observed behavior;
- the security impact;
- whether credentials or user data may have been exposed.

Do not include live credentials, private research documents, exploit payloads,
or personal data in a public issue. If private vulnerability reporting is not
available, open a public issue containing no sensitive detail and ask the
maintainer to establish a private contact channel.

## Secret handling

R3 reads provider credentials from environment variables or from the
provider's own authenticated client. Never commit API keys, access tokens,
Codex authentication caches, `.env` files, databases, model receipts, or local
research corpora.

Treat `~/.codex/auth.json` and equivalent OS credential-store entries as
passwords. A commercial or shared deployment must not reuse one person's
ChatGPT/Codex login for other users.

If a credential may have been exposed:

1. revoke or rotate it at the provider;
2. remove it from the working tree and release artifacts;
3. inspect Git history and published packages;
4. review provider usage and billing;
5. document the incident without reproducing the credential.

## Untrusted content boundary

Papers, PDFs, repository archives, metadata, prompts, and model output are
untrusted input. Keep the existing download limits, SSRF and redirect checks,
archive validation, PDF isolation, structured-output validation, and evidence
gates enabled.

R3 statically reads external repositories. It must not execute downloaded
scripts, hooks, notebooks, package installers, tests, or binaries as part of
research ingestion.

## Remote-model boundary

Codex and other remote model providers receive the selected content needed for
analysis. This can include research questions, metadata, extracted paper text,
and selected repository files. A user must not send confidential, unpublished,
licensed, personal, regulated, or otherwise restricted material unless the
user has authority to do so and accepts the provider's current data terms.

For more detail, see [docs/PRIVACY.md](docs/PRIVACY.md).
