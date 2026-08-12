# Small-Scale Commercial Use

## Recommended initial model

The current codebase is suitable for a very small commercial pilot only when
the local single-user boundary is preserved. The recommended offers are:

- paid installation and environment verification;
- research-profile and query-pack design;
- relevance and evidence-policy tuning;
- migration, training, and limited support;
- a dedicated single-tenant deployment using the customer's credentials.

This model sells deployment expertise and research-workflow quality rather than
reselling model-account access.

## Recommended pilot boundary

A pilot should use:

- one user or customer per machine or isolated instance;
- a separate database, content directory, output directory, and credential set
  for every customer;
- customer-owned API keys or an explicitly agreed project key;
- model charges that are metered separately or paid directly by the customer;
- loopback access for local installs;
- a documented content-license and retention policy;
- a small, named user group rather than public sign-up.

No deployment should promise unlimited deep reads before a clean production
benchmark establishes wall time, provider usage, retry cost, and evidence
quality.

## Not currently implemented

R3 does not currently implement the controls required for a shared
multi-tenant service:

- user registration, authentication, or password recovery;
- role-based access control or administrative roles;
- tenant-scoped database queries and object storage;
- hosted secret storage and rotation;
- TLS termination and production reverse-proxy policy;
- per-user queues, quotas, abuse controls, or cost ceilings;
- subscriptions, invoicing, refunds, or tax handling;
- tenant backup, export, deletion, and disaster recovery;
- service monitoring, incident response, or an SLA;
- legal consent records or a data processing agreement.

Do not make the current dashboard public by changing its bind address, opening
the firewall, using a public tunnel, or forwarding its port. That does not
create authentication or tenant isolation.

## Model-provider rules

- Do not share a maintainer's personal ChatGPT/Codex login with paying users.
- Prefer customer BYO credentials or a dedicated provider project for each
  controlled deployment.
- Keep credentials server-side and outside the repository.
- Show which provider, model, endpoint, and data boundary apply before a run.
- Record usage for cost accounting without recording credentials.
- Offer local llama.cpp only with an explicit quality boundary; local output
  must not silently inherit the publication status of a separately calibrated
  remote model.

## Content and copyright rules

Central metadata, identifiers, scores, and links are different from a central
full-text library.

For a commercial pilot:

1. store descriptive metadata only where provider terms permit it;
2. process user-provided or explicitly licensed full text;
3. record the source, version, license, and content hash;
4. use temporary full-text storage with an enforceable deletion deadline;
5. do not serve original PDFs, archives, extracted full text, or substantial
   quotations to other customers;
6. send users to the authoritative source for the original work;
7. retain evidence sufficient to audit a conclusion without redistributing the
   underlying work.

arXiv's API terms expressly support discovery and notification tools, but most
e-prints cannot be stored and served by a third-party central service without
permission. GitHub repository contents remain subject to each repository's
license.

## Minimum gate before charging a pilot customer

- the software distribution has an accepted project-license decision;
- third-party licenses and a release-time SBOM have been reviewed;
- the release artifact contains no credentials, local paths, user database,
  paper corpus, repository archive, or model receipts;
- the customer's provider account, cost responsibility, and data policy are
  written down;
- retention and deletion are executable and tested for that deployment;
- backups do not silently extend the promised retention period;
- the customer can identify every remote data recipient;
- support and security-reporting channels are documented;
- claims describe the product as research assistance, not a guarantee of
  completeness, correctness, novelty, or systematic-review compliance.

## Expansion requiring a separate decision

Shared hosting, public registration, multi-tenancy, SSO, centralized billing,
mobile clients, long-tail integrations, and enterprise compliance are separate
product expansions. They should not be added merely to make the local project
look commercially complete.

Before any such expansion, define its users, legal jurisdiction, data flow,
operating cost, threat model, and observable acceptance criteria.
