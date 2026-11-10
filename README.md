# RabbitMQ custom image

> [!NOTE]
> **Written with AI assistance.** This document was generated with the help of an AI
> assistant and may contain inaccuracies. Verify anything critical against the source code.

This repository prepares a `linux/amd64` management image derived from the
official Docker Library RabbitMQ recipe. It compiles patched OpenSSL and
Erlang/OTP, installs the official RabbitMQ generic release, refreshes Ubuntu
packages, and qualifies the image before publication to
`ghcr.io/carvvf/rabbitmq-docker`. This is an image-packaging repository, not a
RabbitMQ source fork or a deployment tool. Implementation is not evidence of
a successful build, public GHCR access, or acceptance on a live cluster.

## Reviewed release policy

| Input | Automatic selection | Initial floor |
| --- | --- | --- |
| RabbitMQ | Stable `4.4.x` | `4.4.0` |
| OpenSSL | Stable `3.5.x` | `3.5.9` |
| Erlang/OTP | Stable `29.1.x`, including four-part patches | `29.1.2` |
| Ubuntu | Current `ubuntu:26.04` digest | Same release only |
| rabbitmqadmin | Pinned official recipe | `2.35.0` |
| Trivy | Stable `0.76.x` container | `0.76.1` |

New release lines and recipe changes require review. The shared resolver
enumerates every upstream release page and selects numerically, excluding
drafts and prereleases. Archives and signatures require published SHA-256
metadata. The build retains upstream OpenSSL and RabbitMQ PGP verification;
OpenSSL keys are retrieved through `hkps://keyserver.ubuntu.com:443`, using
TLS and the upstream full signing-key fingerprint. OTP uses the archive
checksum, as in the official recipe. Any resolution,
checksum, signature, registry, or scanner error stops the operation.

The official `rabbitmq:4.4-management` digest is an additional rebuild signal,
not a runtime dependency or the only update source. Independent OpenSSL and
OTP resolution acquires patches without waiting for an official image rebuild.

`upstream.json` locks the Docker Library commit and each original file under
`vendor/docker-library-rabbitmq/`. The renderer produces the root Dockerfile
with checked substitutions. Its management stage extends the runtime just
compiled. The original snapshot is retained unchanged for review and attribution.

Ubuntu stages that install packages also upgrade installed packages.
`CACHEBUST`, unique to a build attempt, invalidates their cache even with an
unchanged base digest. Apt cannot update the privately compiled OpenSSL and
OTP copies under `/opt`; those updates require recompilation.

## Runtime and image identity

Preserved upstream behavior includes entrypoint, `rabbitmq-server` command,
UID/GID `999:999`, `/var/lib/rabbitmq` data volume, configuration conventions,
management and default Prometheus plugins, root startup with privilege drop,
and direct non-root startup. External read-only plugin configuration uses
`RABBITMQ_ENABLED_PLUGINS_FILE`.

Published tags are:

1. `<rabbitmq-version>-custom.<N>`, for example `4.4.0-custom.1`: immutable,
   allocated using all existing package-version pages with collision checks.
2. `latest`: the most recently qualified image in the reviewed RabbitMQ line.

`org.opencontainers.image.version` identifies the custom rebuild;
`io.github.carvvf.rabbitmq-docker.rabbitmq.version` identifies RabbitMQ itself.
Other labels record component/repository revisions, recipe commit, input
fingerprint, and base/official digests. The full inventory is installed at
`/usr/share/rabbitmq-build/inputs.json`, with internal `schema_version: 1`
and tooling `producer_version: 0.1.0`, independently of RabbitMQ versions.

Retain versioned tags and digests for controlled deployments. Preserve data,
node identity, cookies and credentials. Image availability does not establish
cluster upgrade or rollback safety.

## Local preparation and checks

Requirements: system Python 3 with its standard library, Bash, Git, Docker
with Buildx and a running Linux daemon, OpenSSL CLI, GNU `timeout`, and outbound HTTPS.
Publication also needs `gh`. API authentication uses `GH_TOKEN`, then
`GITHUB_TOKEN`, then an existing `gh` login for `github.com`. CLI credentials
are read once per process into memory and never printed or written to files.
The authorization header is sent only to `api.github.com`. Without credentials,
public resolution uses GitHub's smaller anonymous quota. Authenticate locally
with `gh auth login --hostname github.com` to avoid exhausting that quota on
repeated builds. Rate-limit errors report the authentication source and reset
time; they do not silently use stale inputs. No developer venv is needed.

Offline validation commands, from this repository:

```bash
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
/usr/bin/python3 -m tools.render_recipe --check
bash -n tests/test-image.sh
shellcheck tests/test-image.sh scripts/trivy/resolve-version.sh
hadolint Dockerfile
actionlint -shellcheck= -pyflakes=
```

Follow AGENTS.md: after edits, report commands, environment, and dependency
requirements before tests, and wait for the user's test request or readiness
confirmation. Do not change another project's venv or PYTHONPATH.

An intentional full local build, scan, and runtime qualification is:

```bash
/usr/bin/python3 -m tools.pipeline check
```

It never publishes. It resolves inputs once, builds an OCI candidate with
SBOM/provenance, converts it for Trivy and Docker, and tests that same candidate.
Generated inputs, reports, and large archives remain in ignored `build/` and
`.cache/` until the operator removes them. To regenerate the Dockerfile after
a reviewed renderer change, use `/usr/bin/python3 -m tools.render_recipe`.

Runtime tests build a disposable `python:3.14-slim` client with hash-pinned
Pika `1.4.4`. This installs nothing in the broker or a developer environment.
Tests use an internal network, temporary volume and certificates, and no host
ports. They cover exact component versions, crypto linkage, diagnostics,
management authentication, verified TLS, AMQP publisher confirms, quorum-queue
persistence after restart, and non-root execution with all capabilities dropped
and management-only plugins mounted read-only. These are single-node image
checks, not cluster rollout acceptance.

## CI and promotion

### VS Code tasks

The task picker follows the PostgreSQL/Qdrant repository layout:

1. `Docker: build and qualify local image` is the default build task. It runs
   `python3 -m tools.pipeline check`, including build, CVE scan, and runtime tests.
2. `Trivy: scan CVE` rescans the existing `build/candidate.tar` using the same
   scanner resolver and HIGH/CRITICAL gate as CI. It does not rebuild or publish.
3. `Test: all` is the default test task. It runs offline tests, recipe consistency,
   Dockerfile/shell/workflow lint, and RabbitMQ runtime tests in sequence.
   Runtime tests require the previously built `rabbitmq-docker:candidate` image
   and its matching `build/inputs.json`; this task does not build them implicitly.

Individual test and lint tasks are hidden from the main picker but remain
available as dependencies. Python tasks use `/usr/bin/python3` with its standard
library; lint tasks run Hadolint, ShellCheck, and Actionlint in Docker. No venv
update is required. Tasks run only when explicitly invoked and never publish.

### Workflow lifecycle

Pull requests run offline checks and candidate qualification without publishing.
Pushes to `master`, daily runs at `02:17 UTC` (03:17 CET / 04:17 CEST), and
manual dispatch use the same resolver and pipeline. Only trusted `master`
workflows in `carvvf/rabbitmq-docker` may publish. Publishers share one concurrency
group without nested workflow locks.

New inputs, repository commit, official-image digest, missing active image,
HIGH/CRITICAL findings, or manual `force_rebuild` trigger a rebuild. A current
clean image completes successfully without rebuilding.

1. Resolve inputs once and scan the existing active image.
2. Build one OCI candidate with BuildKit SBOM and provenance; retain the original
   attestation statements as separate evidence.
3. Convert that candidate for Trivy and runtime qualification without rebuilding.
4. Reject all HIGH/CRITICAL OS or library findings, including findings without fixes.
5. Check collisions and publish the immutable tag from the original OCI archive.
6. Verify its `linux/amd64` platform and OCI index digest, and scan its immutable
   registry digest before promoting `latest` to that exact index.
7. Verify that `latest` references the same digest and report normal success.

Failures before promotion leave the previous `latest` intact. Failures after
writing `latest` may leave it advanced; verification reports that failure without
an unqualified automatic rollback. A rejected registry rescan may leave an
immutable tag present, but it does not promote it. There are no intentional
notification failures or automatic image deletions.

Input inventory, build metadata, SBOM, provenance, scan JSON, and runtime logs
are retained as CI artifacts for 14 days. Credentials and image archives are
excluded from artifact uploads.

## Security coverage

The motivating advisory is [CVE-2026-109518](https://ubuntu.com/security/CVE-2026-109518),
fixed in Ubuntu 26.04 by `3.2.1ubuntu0.1`. Confirm built-package versions and
scan results: a rebuild alone does not prove remediation. APT is outside normal
AMQP processing, but package installation during build still affects exposure.

Trivy scans OS and recognized language-library packages. Compiled OTP, private
OpenSSL, BEAM applications, Rust dependencies embedded in rabbitmqadmin, and
static components may not all be identified or matched against advisories.
SBOM and inventories improve evidence without guaranteeing coverage. A clean
report means no matching HIGH/CRITICAL findings for the detected inventory,
not that every dependency is vulnerability-free. Never hide findings or fabricate
package metadata to force a scanner result.

## First publication and integration

The GitHub repository is public; GHCR visibility is a separate setting. The
user reviews and commits the feature branch, pushes it, and controls integration
into `master`. After the first successful trusted CI run creates the package,
set it to public and verify anonymous registry access without mounted credentials:

```bash
docker run --rm quay.io/skopeo/stable:v1.22.3 inspect docker://ghcr.io/carvvf/rabbitmq-docker:latest
```

No publication or anonymous access is claimed until verified. The current
Ragtime suite selects official `4.4.x-management` tags and validates the official
repository identity; it rejects this repository and its custom/latest tags.
Integration requires separate changes to selection, qualification, tests, and
installation compatibility. This repository does not change the suite or clusters.

## License and third-party components

Repository content uses MIT; see LICENSE. Derived recipe and entrypoint content
retains Docker, Inc.'s original MIT notice under `vendor/`. Original additions
are attributed separately to carvvf; `upstream.json` records the source revision.

This does not relicense image components. `/licenses` retains OpenSSL and OTP
Apache-2.0 texts from their source archives, RabbitMQ MPL/Apache texts from its
resolved source commit, and rabbitmqadmin MIT/Apache texts from its pinned source
revision. Other dependencies retain upstream notices and licenses; review the
distributions and generated SBOM for the shipped set.

Primary references: [Docker Library recipe](https://github.com/docker-library/rabbitmq),
[Erlang compatibility](https://www.rabbitmq.com/docs/which-erlang),
[RabbitMQ upgrades](https://www.rabbitmq.com/docs/upgrade).
