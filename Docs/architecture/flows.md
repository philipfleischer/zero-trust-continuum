# Request flows

How one request moves through ZTC after M1, step by step, with the code that does each step. `scripts/demo.sh` runs these
flows on localhost and checks the status codes.

## 1. A PMU gets a token

```
PMU                                    ztc-ca
 │  POST /v1/token                       │
 │  Authorization: Bearer <client secret>│
 │──────────────────────────────────────►│ SHA-256 of the secret → registered client
 │                                       │ claims from the clients file: sub, aud, scope, roles, zone
 │                                       │ exp = now + 5 min, jti = 128 random bits, signed with Ed25519
 │◄──────────────────────────────────────│
 │  {"token": "eyJ…", "expiresAt": "…"}  │
```

The request body is never read, so a client cannot ask for another subject or more scope
(`cmd/ztc-ca`, `TestClientCannotChooseItsIdentity`).

## 2. The PMU writes telemetry

```
PMU                    ztc-pep                           ztc-pdp                 upstream
 │ POST /bay-1/telemetry/pmu-1                             │                        │
 │ Authorization: Bearer eyJ…                              │                        │
 │───────────────────────►│                                │                        │
 │                        │ 1 route  /bay-1/telemetry/     │                        │
 │                        │   → telemetry, zone bay-1      │                        │
 │                        │ 2 action POST → write          │                        │
 │                        │ 3 token  signature, exp, aud   │                        │
 │                        │   → subject pmu/1, edge, bay-1 │                        │
 │                        │ 4 signal authentication 0.5 ──►│ trust 0.475            │
 │                        │ 5 decide ─────────────────────►│ time, trust, emergency │
 │                        │                                │ set by the PDP         │
 │                        │◄──── allow, edge-write-telemetry                        │
 │                        │ 6 obligations: none            │                        │
 │                        │ 7 proxy, without Authorization and the client's X-ZTC-*  │
 │                        │   with X-ZTC-Subject, X-ZTC-Rule ──────────────────────►│
 │◄─────────────────────────────────────────────────────────────── 200 stored ──────│
```

| Step | Code | Rejects with |
| --- | --- | --- |
| 1 route | `pep.RouteTable.Match`: longest prefix, whole segments, no `.` or `..` | 404 |
| 2 action | `pep.ActionFor`: GET read, POST write, POST to a breaker operate | 405 |
| 3 credential | `pep.Authenticator`: `token.Verifier` with the CA's keys from `pep.RemoteKeys` | 401 |
| 4 signal | `Enforcer.reportAuthentication`: before the decision, at most once a minute per subject | never; a failed signal is logged |
| 5 decision | `Enforcer.BuildRequest` and the decider of the placement | 403 on deny, 503 on any error |
| 6 obligations | `fulfilObligations`: `log`, `alert:<target>`, `reverify:<duration>`, all checked first | 403 |
| 7 proxy | `pep.NewProxy` with `httputil.ReverseProxy` | 502 if the upstream is down |

The client sees only the status code and a short word. Why a request was rejected, which rule decided and how trusted the subject
was, are in the PEP's JSON log, so an attacker learns neither the policy nor why a credential failed.

## 3. The IDS reports the PMU

```
IDS (ztcctl in M1) ── POST /v1/signals {behaviour, 0.95} ──► ztc-pdp: 0.95 ≥ 0.9 → compromised, trust 0

PMU ── same valid token ──► ztc-pep ── decide ──► ztc-pdp: deny-untrusted (trust 0 < 0.3) ──► 403
```

The token is still valid: authentication succeeds and authorization fails. That is the difference between checking a credential
and zero trust, which keeps asking whether the holder should still be trusted.

## 4. The PDP is unreachable

```
PMU ── valid token ──► ztc-pep ── decide ──✗ connection refused ──► 503, the upstream is not called
```

An error from the decider wins over any decision that came with it, so even a decider that answers "allow" together with an
error gives 503 (`TestMiddlewareRejects`). With `ZTC_PLACEMENT=hierarchical`, cached allows keep working until their TTL runs out.
