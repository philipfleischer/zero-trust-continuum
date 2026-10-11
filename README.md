# ZTC — Zero-Trust Continuum

[![ci](https://github.com/philipfleischer/zero-trust-continuum/actions/workflows/ci.yml/badge.svg)](https://github.com/philipfleischer/zero-trust-continuum/actions/workflows/ci.yml)

A zero-trust security architecture for the edge-fog-cloud continuum, applied to critical energy infrastructure (smart-grid substations).

**Project page:** [philipfleischer.github.io/projects/zero-trust-continuum](https://philipfleischer.github.io/projects/zero-trust-continuum/) explains the architecture, the design decisions and the research questions in more depth, with the diagrams. More projects: [philipfleischer.github.io](https://philipfleischer.github.io/).

ZTC is a long-running research and engineering project by Philip Elias Fleischer (MSc Informatics: Programming and System Architecture, UiO). It serves three purposes at once:

1. **Master's thesis testbed.** A design, a reference implementation and an OMNeT++ simulation for the thesis directions discussed with potential supervisors: zero-trust architecture for the fog-cloud continuum, access control / IAM across the continuum, and secure service migration.
2. **Course companion.** Applies as much as possible of the curriculum from IN5700 (Fog and Cloud Computing), IN5020 (Distributed Systems) and TEK5520 (Cybersecurity in Industrial Systems), with an eye toward IN5031 and IN5410 next semester.
3. **Portfolio project.** Shows the tools and practices that job ads for cloud/security/network roles ask for: Go microservices, C++, Python data pipelines, Docker, Kubernetes, GitHub Actions CI/CD, infrastructure as code (Terraform/Ansible), Prometheus/Grafana, Cisco network configuration, IEC 62443 and NIST SP 800-207.

## The problem, briefly

Zero trust ("never trust, always verify") is well established in the cloud, but it assumes a stable, well-connected, centrally managed infrastructure. Fog computing breaks those assumptions: devices join and leave, links are slow or partitioned, nodes may be owned by different parties, and tasks move between edge, fog and cloud at run time. Each move changes who can see or touch the data, so the trust boundary has to be redrawn. In critical infrastructure such as the power grid, getting this wrong causes a blackout, and adding too much latency means a protection function reacts too late. ZTC asks where decisions should be made, which credentials should be used, and how trust should follow a migrating service, and measures the resulting security, latency and availability trade-offs.

## Scenario: a digital substation on the edge-fog-cloud continuum

```
CLOUD  (control centre / TSO / DSO)
  ztc-ca (identity, short-lived certs)   ztc-pdp x3 (Raft-replicated policy decision point)
  ztc-ingest (telemetry pipeline)        analytics (Python, anomaly detection)   Prometheus / Grafana
                         ^
                         | WAN (4G/5G, fiber, MPLS), can be slow or partitioned
                         v
FOG  (substation / DMZ)
  ztc-fog  (task execution, offloading, gossip membership, local decision cache, migration)
  ztc-pep  (mTLS gateway, per-request authorization, microsegmentation)
  ztc-ids  (ICS intrusion detection: Modbus/TCP, IEC 61850 GOOSE rules + anomaly scores)
                         ^
                         | Field bus / process bus / LAN (fast, but untrusted)
                         v
EDGE  (field devices)
  ztc-edge (simulated IEDs, PMUs, RTUs, smart meters, EV chargers): telemetry, Modbus, GOOSE-like events
```

Every arrow crosses a trust boundary. No component trusts another because of its network location. Every request carries a verifiable identity (SPIFFE-style ID in a short-lived X.509 certificate), is authorized by a policy decision (ABAC plus a continuously updated trust score), and is enforced at a policy enforcement point. Zones and conduits follow IEC 62443. Network segmentation is expressed at three layers: Cisco VLANs/ACLs, Docker networks, and Kubernetes NetworkPolicies, so the same model is verified three different ways.

## Architecture diagrams

![Target architecture](Docs/diagrams/svg/00-system-overview-1.svg)

The target architecture and the design of every milestone, as editable [diagrams.net](https://app.diagrams.net) files with the reasoning behind each decision: NIST SP 800-207 mapping, the decision chain, credential models and the trust algorithm, PDP placement, the continuous-verification loop, Raft/SWIM/Chord, IEC 62443 zones, the STRIDE threat model, secure migration and the evaluation plan. Start at [Docs/diagrams](Docs/diagrams/README.md), or read the walkthrough on the [project page](https://philipfleischer.github.io/projects/zero-trust-continuum/).

## Research questions (thesis)

| # | Question |
|---|---|
| RQ1 | Where should the policy decision point live? Cloud-only vs. fog-replicated vs. hierarchical (cloud authority with a fog cache). What does each cost in decision latency, availability during a WAN partition, and staleness of revocations? |
| RQ2 | Which credential model fits a dynamic continuum? Bearer tokens (JWT-like), certificates (mTLS), capabilities (macaroon-like, attenuable). Overhead, revocation latency and delegation along an offloading chain. |
| RQ3 | How does trust follow a migrating service? Full re-authentication vs. pre-authentication vs. token handover. Migration downtime vs. exposure window. |
| RQ4 | Does continuous verification detect a compromised device fast enough? Trust-score decay and IDS signals vs. lateral movement. |

## Status

This project is a work in progress. The structure below is the plan for what the repository will contain as the different parts get built out.

## Repository layout

Planned parts of the system:

| Part | Language / tool |
|---|---|
| Reference implementation: microservices for identity, policy, trust, PDP, PEP, Raft, gossip, Chord, offloading, migration, ICS protocols, IDS, telemetry and audit log | Go, standard library only |
| Simulator-independent C++ models (trust, policy, credentials, decision cache, crypto cost, migration), unit tested | C++17, CMake |
| The OMNeT++ project used for the thesis evaluation | OMNeT++ 6.x, C++17, NED |
| Data pipeline and analysis: result parsing, telemetry features, anomaly detection, plots | Python |
| Container images and a full local deployment with segmented networks | Docker, Compose |
| Kubernetes manifests and Helm chart, default-deny NetworkPolicies | Kubernetes |
| Infrastructure as code: cloud VMs, fog-node provisioning | Terraform, Ansible |
| Purdue-model network design: Cisco IOS configs, containerlab topology | Cisco IOS, containerlab |
| Prometheus scrape config, alert rules, Grafana dashboard | Prometheus, Grafana |
| LaTeX skeleton of the master's thesis | LaTeX |
| Architecture notes, ADRs, threat model, course maps, career material, runbooks | Markdown |

## Design principles

* **Standard library first.** The Go services avoid third-party dependencies, so the cryptography, the Raft log and the HTTP APIs stay readable end to end. Production-grade libraries are noted as the industry equivalent where relevant.
* **One model, two worlds.** The same concepts (trust score, policy rule, credential, decision cache, migration protocol) exist in the Go implementation and in the C++ simulation core, kept in sync on purpose.
* **Everything measurable.** Every service exposes metrics and health endpoints, and every simulation module records signals that feed the thesis figures.
* **Documented for the next session.** Files and functions carry short, honest comments about what they are for, even while a function body is still unfinished, so the project stays easy to pick back up.

## License

MIT for the code. Any third-party course material kept alongside the project belongs to its original authors and is used only for personal study.
