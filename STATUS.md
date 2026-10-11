# Status

What is implemented right now. Updated in every branch that moves something forward.

Legend: ✅ implemented and tested · 🟡 works, known gaps · 🔴 not started

## Milestones

| Milestone | Content | Status |
| --- | --- | --- |
| M0 Foundation | repo hygiene, Go service skeleton, CI | ✅ |
| M1 Decision chain | policy, trust, PDP, tokens, PEP | 🟡 Policy engine, trust score and PDP done |
| M2 Fog, IDS and demo | telemetry, edge devices, fog node, IDS, audit, e2e demo | 🔴 |
| M3 Distributed systems | clocks, Raft, SWIM, Chord | 🔴 |
| M4 Offloading and containers | load balancing, Docker, Compose, monitoring, Kubernetes | 🔴 |
| M5 Industrial security | threat model, zones, Modbus/GOOSE, IDS service, mTLS | 🔴 |
| M6 Simulation and evaluation | C++ core, OMNeT++, migration, analytics | 🔴 |
| M7 Infrastructure and career | Terraform, Ansible, Cisco, thesis skeleton | 🔴 |

## Components

| Part | Path | Status | Notes |
| --- | --- | --- | --- |
| Go services | `services/` | 🟡 | libraries: `model`, `config`, `httpx`, `observability`, `svc`, `trust`, `pdp`; service `ztc-pdp`; CLI `ztcctl` |
| C++ simulation core | `sim/core/` | 🔴 | |
| OMNeT++ model | `sim/omnetpp/` | 🔴 | |
| Analytics | `analytics/` | 🔴 | |
| Deployment | `deploy/` | 🟡 | `policies/substation.json`, the canonical default policy |
| CI/CD | `.github/workflows/` | ✅ | build, race tests with coverage, golangci-lint, actionlint, Dependabot |
| Docs | `Docs/` | 🟡 | `adr/`: 0001 fail closed, 0002 PDP write token; `architecture/`: trust algorithm; `diagrams/`: target architecture and design per milestone (17 diagrams.net files with rationale) |

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
| `cmd/ztc-pdp` | 🟡 | runs; decision API comes in M1 |

## Repository basics

| Item | Status |
| --- | --- |
| `.gitignore` (Go, Python, C++, OMNeT++, Terraform, OS, editors) | ✅ |
| `LICENSE` (MIT), `.editorconfig` | ✅ |
| `STATUS.md`, `CLAUDE.md` | ✅ |
| `Makefile`, `.golangci.yml`, CI workflow, Dependabot | ✅ |
