# Architecture diagrams

System design and architecture of ZTC (Zero-Trust Continuum), from the complete target system down to each building block.
Every diagram is a `.drawio` file that opens and edits directly in [diagrams.net](https://app.diagrams.net) or the draw.io desktop app.
Each one has a Markdown file next to it that explains what it shows, which design choices it captures, which alternatives were considered and why they were rejected.

## Reading order

Start with the target architecture, then follow the milestones in the order they are built. Each milestone adds one layer, and together they add up to the target architecture.

| # | Diagram | Pages | What it answers |
|---|---|---|---|
| 00 | [System overview](00-system-overview.md) | 2 | The architecture at a glance, then the finished system end to end |
| 01 | [Architecture evolution](01-architecture-evolution.md) | 2 | How M0 → M7 add up to the target architecture |
| 02 | [NIST SP 800-207 mapping](02-nist-zta-mapping.md) | 1 | Which ZTC part plays which zero-trust role |
| 03 | [M0 Service foundation](03-m0-service-foundation.md) | 2 | What every service has in common; how the Go packages are layered |
| 04 | [M1 Decision chain](04-m1-decision-chain.md) | 3 | How one request is authenticated, decided and enforced |
| 05 | [M1 Credentials and trust](05-m1-credentials-and-trust.md) | 3 | Tokens vs capabilities vs certificates; the trust score; cache invalidation |
| 06 | [RQ1 PDP placement](06-rq1-pdp-placement.md) | 1 | Where decisions are made: cloud, hierarchical or fog |
| 07 | [M2 Fog, telemetry and IDS](07-m2-fog-telemetry-ids.md) | 3 | The data pipeline, the anomaly → lock-out loop, the audit log |
| 08 | [M3 Distributed systems](08-m3-distributed-systems.md) | 4 | Raft-replicated PDP, SWIM membership, Chord placement, logical clocks |
| 09 | [M4 Offloading and containers](09-m4-offloading-containers.md) | 3 | Trust-aware offloading, Docker Compose zones, Kubernetes |
| 10 | [M5 IEC 62443 zones](10-m5-iec62443-zones.md) | 2 | Zones, conduits, security levels; one model exported to four layers |
| 11 | [M5 Threat model](11-m5-threat-model.md) | 2 | Data-flow diagram, trust boundaries, STRIDE; defence in depth |
| 12 | [M5 Identity and mTLS](12-m5-identity-mtls.md) | 2 | SPIFFE identities, the CA, a request over mutual TLS |
| 13 | [M6 Secure migration](13-m6-secure-migration.md) | 2 | How trust follows a service that moves between fog nodes (RQ3) |
| 14 | [M6 Simulation and evaluation](14-m6-simulation-evaluation.md) | 3 | Go and OMNeT++ sharing one model; the evaluation plan for RQ1–RQ4 |
| 15 | [M7 Infrastructure and network](15-m7-infrastructure-network.md) | 2 | Cisco network design; Terraform → Ansible → Kubernetes |
| 16 | [DevSecOps pipeline](16-devsecops-pipeline.md) | 1 | From commit to signed image, with security gates |

Short on time? Read 00, 02, 04, 07 and 11. Those five show the zero-trust core, the continuous verification loop and the security analysis.

## Visual language

The same conventions are used in every diagram, so a colour or line style always means the same thing.

| Element | Meaning |
|---|---|
| Blue | cloud / control centre (Purdue L4–5) |
| Green | fog / substation (Purdue L3) |
| Orange | edge / field devices (Purdue L0–2) |
| Purple | OT-DMZ and WAN (Purdue L3.5) |
| Red fill | threat actor, security-critical control or known limitation |
| Yellow note | design rationale |
| Solid black arrow | request or data path |
| Dashed red arrow | trust signal (continuous verification) |
| Dashed blue arrow | control traffic: revocation epoch, policy, replication |
| Thick green arrow | telemetry aggregates |
| Dotted grey arrow | copy of traffic for inspection |
| Numbered circle | a step of the zero-trust cycle, on every part of its path |
| Thick dashed red line | trust boundary (TB1–TB6, defined in [11](11-m5-threat-model.md)) |

## Editing

- Open a `.drawio` file in diagrams.net (*File → Open from → Device*), in the draw.io desktop app, or with the draw.io VS Code extension. Pages are the tabs at the bottom.
- Containers (zones, groups) carry their children, so moving a zone moves everything inside it.
- The previews in [`svg/`](svg/) are exports of each page (`<file>-<page>.svg`), used by the Markdown files. After editing a page, export it again with *File → Export as → SVG* (border 20, "include a copy of my diagram" off) and overwrite the matching file. If an SVG falls behind, the `.drawio` file is the source of truth.
- Names in the diagrams (services, packages, endpoints, environment variables, policy rules) match the code and the milestone plan. Change them together.

## Standards and sources used

- NIST SP 800-207 *Zero Trust Architecture*: PE / PA / PEP model, the seven tenets, trust algorithm.
- IEC 62443-3-2 / 3-3: zones, conduits, security levels, foundational requirements FR1–FR7.
- IEC 61850 (GOOSE, MMS) and the Purdue reference model for the substation scenario.
- MITRE ATT&CK for ICS for IDS rules and the attack-path walk-through.
- STRIDE for the threat model.
- SPIFFE for workload identity; RFC 5869 (HKDF), RFC 7748 (X25519) for migration sealing.
- Raft (Ongaro and Ousterhout 2014), SWIM (Das et al. 2002), Chord (Stoica et al. 2001), hybrid logical clocks (Kulkarni et al. 2014).
