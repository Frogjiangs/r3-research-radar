# Third-Party Notices

This file records the direct runtime dependencies declared by the current R3
Research Radar source tree. R3's own source code is licensed under the MIT
License in `LICENSE`; this notice is not a substitute for the complete license
texts or for a release-time software bill of materials.

## Python direct dependencies

| Component | Pinned version | License | Upstream |
| --- | ---: | --- | --- |
| httpx | 0.28.1 | BSD-3-Clause | https://github.com/encode/httpx |
| pypdf | 6.14.2 | BSD-3-Clause | https://github.com/py-pdf/pypdf |
| typing_extensions | 4.16.0 | PSF-2.0 | https://github.com/python/typing_extensions |

## Node.js direct dependency

| Component | Pinned version | License | Upstream |
| --- | ---: | --- | --- |
| @openai/codex | 0.145.0 | Apache-2.0 | https://github.com/openai/codex |

## Optional external runtimes and services

llama.cpp, locally downloaded model weights, OpenAI services, OpenAlex, arXiv,
GitHub, and other configured retrieval or model providers are not relicensed by
this project. Their software licenses, model licenses, API terms, content
licenses, rate limits, and data policies apply independently.

## Release verification requirement

Before every public binary, container, package, or commercial deployment:

1. regenerate the dependency lock and CycloneDX SBOM from the release source;
2. verify direct and transitive package versions and licenses;
3. run the existing vulnerability and provenance checks;
4. include all license texts, notices, attribution, and source-offer obligations
   required by the actual distributed components;
5. review optional model weights and bundled native binaries separately;
6. block the release when a dependency license is missing, incompatible, or
   materially different from this record.

The lock file and generated SBOM are authoritative for the dependency set of a
specific release. This notice is a human-readable index and must be updated
when declared direct dependencies change.
