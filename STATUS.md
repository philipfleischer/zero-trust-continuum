# Status

What is implemented right now. Updated in every branch that moves something forward.

Legend: ✅ implemented and tested · 🟡 works, known gaps · 🔴 not started

## Milestones

| Milestone | Content | Status |
| --- | --- | --- |
| M0 Foundation | repo hygiene, Go service skeleton, CI | ✅ |
| M1 Decision chain | policy, trust, PDP, tokens, PEP | ✅ first end-to-end decision, `make demo`, tag `v0.1.0` |
| M2 Fog, IDS and demo | telemetry, edge devices, fog node, IDS, audit, e2e demo | 🔴 |
| M3 Distributed systems | clocks, Raft, SWIM, Chord | 🔴 |
| M4 Offloading and containers | load balancing, Docker, Compose, monitoring, Kubernetes | 🔴 |
| M5 Industrial security | threat model, zones, Modbus/GOOSE, IDS service, mTLS | 🔴 |
| M6 Simulation and evaluation | C++ core, OMNeT++, migration, analytics | 🔴 |
| M7 Infrastructure and career | Terraform, Ansible, Cisco, thesis skeleton | 🔴 |

## Components

| Part | Path | Status | Notes |
| --- | --- | --- | --- |
| Go services | `services/` | 🟡 | libraries `model`, `config`, `httpx`, `observability`, `svc`, `policy`, `trust`, `pdp`, `token`, `pep`; services `ztc-pdp`, `ztc-ca`, `ztc-pep`; CLI `ztcctl` |
| C++ simulation core | `sim/core/` | 🔴 | |
| OMNeT++ model | `sim/omnetpp/` | 🔴 | |
| Analytics | `analytics/` | 🔴 | |
| Deployment | `deploy/` | 🟡 | `policies/substation.json`, the canonical default policy; `pep/routes.json`, example PEP routes |
| CI/CD | `.github/workflows/` | ✅ | build, race tests with coverage, golangci-lint, actionlint, e2e demo, Dependabot |
| Docs | `Docs/` | 🟡 | `adr/`: 0001 fail closed, 0002 PDP write token, 0003 standard library only; `architecture/`: overview and trust boundaries, request flows, trust algorithm; `diagrams/`: target architecture and design per milestone (17 diagrams.net files with rationale); `go-style.md` |

## Go packages

| Package | Status | Notes |
| --- | --- | --- |
| `internal/model` | ✅ | layers, device classes, access request and decision (fail closed) |
| `internal/policy` | ✅ | ABAC engine, deny-overrides with default deny, lock-free install, default substation policy, strict JSON loading |
| `internal/trust` | ✅ | decaying trust score with hand-computed test vectors, concurrent store with injectable clock |
| `internal/pdp` | ✅ | policy plus trust, PDP-owned time, trust and emergency, HTTP API with write token, remote client, chain, placement, decision cache |
| `internal/config` | ✅ | `ZTC_` env vars, invalid values reported through `Err()` |
| `internal/httpx` | ✅ | strict JSON decoding, server timeouts, graceful shutdown |
| `internal/observability` | ✅ | Prometheus exposition, `/healthz`, `/readyz`, RED metrics, JSON logs |
| `internal/svc` | ✅ | shared start-up: config, logger, metrics, fail-fast serve |
| `cmd/ztc-pdp` | ✅ | decision API, policy from `ZTC_POLICY_FILE`, writes behind `ZTC_PDP_TOKEN`, readiness checks the policy |
| `cmd/ztc-ca` | ✅ | v1: tokens for registered clients (`POST /v1/token`), signing key as JWK set (`GET /v1/keys`); X.509 in M5 |
| `cmd/ztc-pep` | ✅ | routes from `ZTC_PEP_ROUTES_FILE`, source zone from configuration, keys from `ztc-ca`, placement `cloud` or `hierarchical`; readiness checks keys and PDP |
| `cmd/ztcctl` | ✅ | `policy`, `decide`, `signal`, `keys gen`, `token issue`/`verify`, `cap rootkey`/`mint`/`attenuate`/`show` |
| `internal/token` | ✅ | Ed25519-signed tokens with strict verification, attenuable HMAC capabilities, revocation list with epoch and snapshots, PEM key files, JWK set |
| `internal/pep` | ✅ | route table without dot segments, token and capability authentication, fail-closed middleware, reverse proxy that strips client `X-ZTC-*` headers, obligations, placement, key refresh from the CA |

## Repository basics

| Item | Status |
| --- | --- |
| `.gitignore` (Go, Python, C++, OMNeT++, Terraform, OS, editors) | ✅ |
| `LICENSE` (MIT), `.editorconfig` | ✅ |
| `STATUS.md`, `CLAUDE.md` | ✅ |
| `Makefile`, `.golangci.yml`, CI workflow, Dependabot | ✅ |
| `scripts/demo.sh` (`make demo`), also the `e2e` CI job | ✅ |
