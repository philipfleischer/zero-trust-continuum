# CLAUDE.md

Project context for Claude Code sessions. Keep it short and current; details belong in STATUS.md and Docs/.

## Project

ZTC (Zero-Trust Continuum): a zero-trust architecture (NIST SP 800-207) for the edge-fog-cloud continuum, applied to a digital substation (IEC 61850 / IEC 62443). Built incrementally as a portfolio project, as practice for the UiO courses IN5700, IN5020, and TEK5520, and as a possible master's thesis testbed.
Research questions: RQ1 PDP placement, RQ2 credential model, RQ3 secure migration, RQ4 continuous verification. See README.md.

Current state: see STATUS.md. Most components do not exist yet; do not assume a file exists without checking.

## Planned layout

| Path | What | Tooling |
|---|---|---|
| `services/` | Go microservices (`cmd/`) and libraries (`internal/`) | Go, standard library only |
| `sim/core/` | Simulator-independent C++ models | C++17, CMake |
| `sim/omnetpp/` | OMNeT++ model for the evaluation | OMNeT++ 6.x, no INET |
| `analytics/` | Result parsing, anomaly detection, figures | Python 3, stdlib core |
| `deploy/` | Docker, Compose, Kubernetes, Helm, Terraform, Ansible, network configs | |
| `Docs/` | Architecture, ADRs, security, course maps | Markdown |

## Conventions

- Code, comments and repository docs are in English.
- Every file starts with a header comment; every exported function has a doc comment saying what it must do.
- Unfinished functions keep their doc comment, contain `// TODO(ztc): <what>` and return zero values, so everything compiles.
- Go: standard library only, gofmt, go vet, table-driven tests next to the code, config from `ZTC_`-prefixed env vars, `/healthz`, `/readyz` and `/metrics` on every service.
- Go code reads like text (full rules in `Docs/go-style.md`): variables, parameters, receivers and fields are whole words
  (`signer`, `request`, `decision`, `func (store *Store)`), never `s`, `req`, `d`; only `err`, `ctx`, `ok`, `t` and a plain index `i` stay short.
  Booleans read as statements (`isExpired`, `found`). Name the parts of a long condition before testing them. Comments say why, not what.
- The same concept means the same thing in Go and C++ (e.g. the trust formula); change both together.
- Git: short-lived branches (`feat/`, `fix/`, `refactor/`, `build/`, `ci/`, `deploy/`, `sim/`, `docs/`, `chore/`),
  Conventional Commits, merge commits (no squash), every merge to `main` keeps build, tests and demo green.
