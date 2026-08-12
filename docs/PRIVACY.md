# Privacy and Data-Handling Boundary

## Current product boundary

R3 Research Radar is currently a local, single-user tool. It has no hosted R3
account service and no multi-tenant data plane. The dashboard is loopback-only.
This does not mean that every configured analysis path is offline.

## What R3 stores locally

Depending on the configured sources and run mode, R3 may store:

- research profiles, queries, candidate metadata, scores, and decisions;
- downloaded paper PDFs and extracted text;
- downloaded repository archives, file inventories, and selected source text;
- content hashes, evidence anchors, model invocation receipts, and usage data;
- feedback, run events, reports, and exported research artifacts.

These files can contain copyrighted material, unpublished research context,
local paths, repository content, and model output. Protect the R3 data,
literature, and output directories with the same care as the underlying
research materials.

The current local product does not provide a universal retention scheduler or
a complete deletion UI. Operators are responsible for defining retention,
backups, access controls, and verified deletion for their local artifact
directories and database.

## When data leaves the machine

### Codex CLI

Codex analysis sends the selected analysis input to OpenAI. The input may
include the research question, paper metadata, extracted paper text, repository
inventory, selected repository files, and the instructions required to produce
structured evidence.

Codex authentication can use a ChatGPT login or an API key. Those methods can
have different workspace, billing, training, and retention policies. Review the
current OpenAI terms and data controls for the account actually used.

R3 limits the child-process environment and scrubs common credential patterns
from recorded process text, but that is not a substitute for checking the
content sent in the prompt.

### Other remote providers

If an OpenAI-compatible endpoint points to a remote host, the selected content
is sent to that operator. The endpoint operator's privacy, retention, security,
and training policies apply.

### Local llama.cpp

The provided fallback configuration targets a loopback llama.cpp endpoint. In
that configuration, model prompts remain on the local machine. Users must
verify the configured endpoint before relying on this property. Changing the
base URL to a remote service changes the privacy boundary.

### Retrieval providers

OpenAlex, arXiv, GitHub, and other configured sources receive the search and
retrieval requests required to provide their services. Their access logs and
account policies apply. R3 credentials must remain in environment variables or
provider-managed credential storage, not in committed configuration files.

## BYO credentials

Bring-your-own-key mode means the credential owner is responsible for:

- provider terms and account eligibility;
- usage charges and rate limits;
- key permissions, rotation, and revocation;
- deciding whether the submitted material may be processed by that provider;
- configuring provider data controls appropriate to the material.

Do not share one user's personal API key or ChatGPT/Codex session with other
users.

## Papers and repository content

Public availability does not imply permission to redistribute or commercially
process every full text.

arXiv descriptive metadata is available under CC0, but most arXiv e-prints are
not licensed for redistribution. A central service must not retain or serve
paper PDFs, source files, or extracted full text unless the copyright holder
or the work's license permits that use.

Repository content remains subject to each repository's license. A missing
license does not grant permission to copy, redistribute, or create derivative
works. R3's summaries and evidence exports must preserve provenance and avoid
republishing substantial source content.

For a hosted deployment, prefer:

- metadata and links in central storage;
- user-provided documents or explicitly licensed full text;
- purpose-limited temporary processing;
- recorded license and provenance;
- an enforceable deletion deadline;
- no redistribution of the original content by default.

## Sensitive material

Do not use a remote provider for confidential, unpublished, personal,
regulated, export-controlled, or contract-restricted material without explicit
authority and an appropriate provider agreement. When that authority is
uncertain, use an approved local model or do not process the material.

## Current limitations

R3 does not currently provide user accounts, consent records, data-subject
request workflows, tenant-level export/deletion, regional data residency, or a
data processing agreement. Those controls are required before operating a
shared hosted service.
