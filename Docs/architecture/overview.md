# Architecture overview

What runs after M1, what each part trusts, and what is still missing. The target architecture for all milestones is in
[Docs/diagrams](../diagrams/README.md); this page describes the code as it is.

## Components

```
                ztc-ca :8090
   POST /v1/token ▲   ▲ GET /v1/keys (at start, then every 5 min)
                  │   │
 PMU ─────────────┘   │
  │                   │
  └── Bearer token ──► ztc-pep :8080 ── POST /v1/decide, /v1/signals ──► ztc-pdp :8181
                         │                                               policy + trust
                         │ only on allow, with X-ZTC-Subject and X-ZTC-Rule
                         ▼
                     upstream (the protected service)

 operator ── ztcctl: keys, tokens, capabilities, decide, signal
```

| Component | Role in NIST SP 800-207 | What it does |
| --- | --- | --- |
| `ztc-pep` | Policy Enforcement Point | Finds the route, authenticates the token or capability, reports the authentication, asks the PDP, carries out the obligations and proxies the request, or answers 401, 403 or 503 |
| `ztc-pdp` | Policy Decision Point (policy engine and trust algorithm) | Combines the ABAC policy with the subject's trust score; sets time, trust and emergency mode itself |
| `ztc-ca` | Identity provider for tokens | Issues short-lived Ed25519 tokens to registered clients and publishes its key as a JWK set |
| `ztcctl` | Operator tooling | Keys, tokens and capabilities from files and standard input; decisions and trust signals against the PDP |

Every service has `/healthz`, `/readyz` and `/metrics`, takes its configuration from `ZTC_*` variables, and refuses to start on
a configuration it cannot use (ADR [0001](../adr/0001-fail-closed.md)).

## Trust boundaries

What each part believes, and why. "Trusted" here always means trusted for one thing, never in general.

| Who | Trusts | For | Never trusts |
| --- | --- | --- | --- |
| `ztc-pep` | the CA's key set | that a token's subject, roles and zone are real | anything the client says in headers: source zone, emergency, task, `X-ZTC-*` |
| `ztc-pep` | its own configuration | routes, the resource behind a path, the source zone of its clients | the path itself when it has empty, `.` or `..` segments |
| `ztc-pdp` | the PEP's access request | subject, action and resource | the request's time, trust score and emergency flag, which it sets itself |
| `ztc-pdp` | holders of `ZTC_PDP_TOKEN` | trust signals, policy changes, emergency mode (ADR [0002](../adr/0002-pdp-write-token.md)) | anyone else writing |
| `ztc-ca` | holders of a registered client secret | who that client is | the subject, scope, roles and zone a request asks for |
| upstream | `X-ZTC-Subject` and `X-ZTC-Rule` | who was allowed, by which rule | nothing else; the PEP removes every other `X-ZTC-*` header |

The upstream's trust in `X-ZTC-Subject` holds only if the upstream can be reached through the PEP alone. In M1 that is an
assumption: the demo upstream listens on localhost. The zone model and mutual TLS in M5 make it a property of the network.

## Placement (RQ1)

`ZTC_PLACEMENT` chooses where the PEP gets decisions:

| Placement | Decider | Fresh | Works while the cloud is unreachable |
| --- | --- | --- | --- |
| `cloud` (default) | `pdp.RemoteClient` | every decision | no: 503 |
| `hierarchical` | `pdp.Cache` in front of the cloud PDP | allows can be up to the rule's TTL old | for cached allows |
| `fog` | needs a PDP replica | | refused until Raft in M3 |

The cache drops a subject's allows when the PDP denies it anything, and drops everything on a newer policy version or revocation
epoch. A subject whose trust has just fallen keeps its cached allows until one of those happens or the TTL runs out; measuring
that window is part of RQ1 and RQ4.

## Known gaps after M1

| Gap | Consequence | Closed in |
| --- | --- | --- |
| No TLS between the services | tokens and decisions cross the network in clear text | M5, mutual TLS |
| One shared `ZTC_PDP_TOKEN` | a PEP that may send signals may also replace the policy | M5, SPIFFE IDs per service |
| `POST /v1/decide` and the reads are open | anyone on the network can learn how the policy treats a request | M5 |
| The PDP serves no revocation list | a stolen token is valid until it expires (at most 5 min) | with the fog node in M2 |
| Capabilities authenticate, but no rule allows `capability:*` subjects | capabilities are verified but always denied | with offloading in M2 and M4 |
| Audit records are log lines | they can be changed or deleted | M2, hash-chained audit log |
| A token authentication gives trust 0.475 | enough to write telemetry, not to read it (0.5) or operate a breaker (0.8) | M5, mTLS and attestation |
