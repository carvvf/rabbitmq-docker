# AGENTS.md

## Purpose and scope

This repository rebuilds the official Docker Library RabbitMQ management recipe
for `linux/amd64`, using current patches within reviewed release lines. It is an
image-packaging repository, not a fork of RabbitMQ server. The image is intended
for public distribution as `ghcr.io/carvvf/rabbitmq-docker`.

## Language and communication

1. Chat with the user in Italian. Repository content must be English, including
   code, comments, documentation, diagnostics, test names, and commit messages.
2. Use numbered lists for individually reviewable findings and decisions.
3. Classify proposed fixes as exactly one of REAL SOLUTION, PARTIAL SOLUTION,
   WORKAROUND, or UNCONFIRMED / HYPOTHESIS. Explain root causes and evidence.
4. Architectural workarounds require an ADR-lite, trade-offs, and explicit user
   confirmation before implementation. Never mask errors or weaken security
   checks to make a candidate pass.

## Release and compatibility policy

1. Automatic selection is limited to stable releases of the RabbitMQ, OpenSSL
   and Erlang/OTP lines pinned as `RABBITMQ_SERIES`, `OPENSSL_SERIES` and
   `OTP_SERIES` in `tools/build_inputs.py`, the only copy of each (OTP
   including four-part patch releases), at or above the floors there, and to
   the Ubuntu release of the vendored recipe. The renderer and the official
   image signal derive the RabbitMQ line from `RABBITMQ_SERIES`. Renovate lists
   a new line on the Dependency Dashboard, OpenSSL LTS lines only, and opens its
   pull request only once approved; that approval is the confirmation rule 2
   asks for.
2. A change to a release line, floor, runtime dependency policy, recipe revision,
   implementation version, schema, or externally visible behavior requires an
   explanation of compatibility, tests, consumers, rollout, and migration, then
   explicit user confirmation before implementation. No opportunistic bumps.
3. Keep the upstream recipe checksum-locked. Update its original snapshot and
   attribution together. Generate Dockerfile changes through the reviewed
   renderer; do not edit the generated Dockerfile alone.
4. Preserve the official entrypoint and command, UID/GID `999:999`, default root
   startup and privilege drop, data volume `/var/lib/rabbitmq`, configuration
   handling, management and Prometheus defaults, and the Erlang/OpenSSL paths
   under `/opt`. Qualify non-root startup and read-only plugin overrides too.
5. Publish only `<rabbitmq-version>-custom.<N>` and `latest`. Never overwrite an
   existing custom tag. Advance `latest` only after the exact candidate has
   passed scan, runtime tests, publication verification, and registry rescan.
6. Record `schema_version` and `producer_version` in generated input manifests.
   Fail explicitly on unsupported schemas. The initial internal input schema is
   1 and tooling producer version is `0.1.0`; these are not RabbitMQ versions.

## Security and supply chain

1. Build OpenSSL and OTP from verified sources and install the verified official
   RabbitMQ generic release. Retain upstream signature checks and published
   SHA-256 checksums. Never silently fall back after resolution failure.
2. Resolve inputs once per operation and record source revisions, recipe commit,
   base and official-image digests, component versions, and checksums. Do not
   substitute inputs between qualification and publication.
3. Refresh Ubuntu packages on each build, invalidating the relevant build cache.
   An unchanged Ubuntu tag digest does not mean apt security updates are absent.
4. Block on Trivy HIGH/CRITICAL OS or library findings with a listed fixed
   version, even when release-line policies prevent adopting it automatically.
   Findings without a listed fix allow publication with explicit GitHub warnings
   naming the CVE, package, installed version, and target, plus summary details.
   Initial scans validate evidence without warnings before remediation. Scanner
   failures and missing, malformed, or incomplete reports remain errors. Apply
   the same gate to candidates, registry rescans, and manual entrypoints. Keep
   scan reports, SBOM and provenance; explain scanner coverage limitations,
   especially source-built and embedded components. See docs/ci-security-policy.md.
5. Serialize publication and retention cleanup. Build once and promote the same
   OCI artifact. Never introduce deliberate notification failures or ignore
   vulnerabilities. Retention may delete versions older than 60 days, preserving
   latest, the ten newest custom releases, and all referenced OCI manifests.
   Support dry runs and never upload registry credentials as artifacts.
6. Preserve Docker Library's MIT attribution and component-specific license
   files. The repository license does not relicense shipped dependencies.

## Verification and environment

1. Reuse shared resolver and pipeline functions for local and CI behavior.
   Keep core selection logic, integrations, and test utilities separate.
2. Do not automatically run test suites, integration tests, or image builds
   immediately after edits. First report changes, reason, exact recommended
   commands, interpreter/environment, and dependency-update requirements.
3. Run tests only after an explicit user request or readiness confirmation.
   Resolver tests use system Python's standard library. Runtime tests use
   disposable Docker resources and the hash-pinned Pika test client; they do not
   install packages into a developer or application virtual environment.
4. Never bypass installed environments with PYTHONPATH changes or import-path
   manipulation. If an environment needs updating, state the minimal update
   steps and wait for the user before testing.
5. Scan added text for English-only compliance. Use mode `775` for directories
   and executable files with a shebang; use `664` for other files. Never grant
   write permission to others. Keep generated reports out of version control.

## Git and delivery

1. Before Git history or remote operations, inspect `git status` and
   `git branch --show-current`. Work on a dedicated feature branch, never
   directly on `master`, `main`, or another integration head.
2. The user performs commits. Provide English one-line commit messages. Do not
   commit, push, rewrite history, merge PRs, or change remote state without exact
   explicit authorization naming the operation, branch, remote, and refs.
3. Use feature branch, user commits, feature-branch push, PR, and user-controlled
   merge. Force pushes require separate explicit authorization and recovery plan.
4. Do not change `ragtime-rag-orch`, persisted installation profiles, or live
   clusters as part of image work. The suite deploys
   `ghcr.io/carvvf/rabbitmq-docker:latest` and qualifies only images whose
   labels report RabbitMQ `4.4.x`, Erlang/OTP `29.1.x`, and OpenSSL `3.5.x`
   (`src/ragtime_rag_orch/rabbitmq_image_identity.py` in `ragtime-rag-orch`).
   A change of any of these lines makes the suite refuse the image, so it
   needs a coordinated change in `ragtime-rag-orch`, reviewed and released
   together with this repository's change.
5. Report what changed, why, verification actually performed, remaining limits,
   and the operator actions needed to publish and consume the image. Do not
   claim publication or cluster compatibility without the corresponding evidence.
