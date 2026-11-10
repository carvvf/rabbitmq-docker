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

1. Automatic selection is limited to stable RabbitMQ `4.4.x`, OpenSSL `3.5.x`,
   Erlang/OTP `29.1.x` (including four-part patch releases), and Ubuntu `26.04`.
   Floors are RabbitMQ `4.4.0`, OpenSSL `3.5.9`, and OTP `29.1.2`.
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
4. Block on every Trivy HIGH/CRITICAL OS or library finding, including findings
   without fixes. Keep scan reports, SBOM and provenance; explain scanner coverage
   limitations, especially source-built and embedded components.
5. Serialize publishers. Build once and promote the same OCI artifact. No
   deliberate notification failures, ignored vulnerabilities, or automatic image
   deletion. Never upload registry credentials as artifacts.
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
   clusters as part of image work. The current suite rejects this repository
   and its custom/latest tags; integration needs separate coordinated changes.
5. Report what changed, why, verification actually performed, remaining limits,
   and the operator actions needed to publish and consume the image. Do not
   claim publication or cluster compatibility without the corresponding evidence.

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

1. Automatic selection is limited to stable RabbitMQ `4.4.x`, OpenSSL `3.5.x`,
   Erlang/OTP `29.1.x` (including four-part patch releases), and Ubuntu `26.04`.
   Floors are RabbitMQ `4.4.0`, OpenSSL `3.5.9`, and OTP `29.1.2`.
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
4. Block on every Trivy HIGH/CRITICAL OS or library finding, including findings
   without fixes. Keep scan reports, SBOM and provenance; explain scanner coverage
   limitations, especially source-built and embedded components.
5. Serialize publishers. Build once and promote the same OCI artifact. No
   deliberate notification failures, ignored vulnerabilities, or automatic image
   deletion. Never upload registry credentials as artifacts.
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
   clusters as part of image work. The current suite rejects this repository
   and its custom/latest tags; integration needs separate coordinated changes.
5. Report what changed, why, verification actually performed, remaining limits,
   and the operator actions needed to publish and consume the image. Do not
   claim publication or cluster compatibility without the corresponding evidence.
