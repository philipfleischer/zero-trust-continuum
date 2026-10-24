# 0003: The Go services use only the standard library

- **Status:** accepted
- **Date:** 2026-10-24
- **Issue:** #15

## Context

The Go services need HTTP, JSON, metrics, structured logs and, from M1 on, signed tokens. The usual choices are third-party modules: prometheus/client_golang for metrics, and golang-jwt/jwt or go-jose for tokens. Each brings its own dependencies, releases and vulnerabilities into a system that decides who may operate a breaker.

Token libraries in particular have a history of flaws in how they verify, not in the cryptography:

- CVE-2015-9235 (jsonwebtoken for Node.js): a token with `"alg": "none"` was accepted without a signature.
- Algorithm confusion (several libraries, 2015-2016): a token with `"alg": "HS256"` was verified with the RSA public key as the HMAC secret, so anyone who knew the public key could sign tokens.
- CVE-2020-26160 (dgrijalva/jwt-go): an empty `aud` list turned the audience check into a check against `""`, which passed.

The library was no longer maintained, and the fix came in a community fork, golang-jwt/jwt.

All three come from letting the token decide how it is checked, or from flexibility the system does not need.

## Decision

- `services/go.mod` has no `require` lines. Every Go service uses only the standard library.
- Cryptography comes from the standard library (`crypto/ed25519`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`, `crypto/x509`). ZTC writes formats and checks around it, never cryptographic primitives.
- The token format (`services/internal/token`) is JWT-shaped but deliberately not JWT: one algorithm (EdDSA), one type (`ZTC`), required `sub`, `aud`, `exp` and `jti`. The verifier fixes the algorithm; the token never chooses it.
- Each of the flaws above has a negative test in `verify_test.go`, and a test was only accepted after it failed when the check it guards was removed.

## Consequences

- No third-party code runs in the services, so there is no dependency to update, audit or lose to an abandoned project. `govulncheck` (M5) only has the Go toolchain to check.
- The services must be maintained by the project: about 1 000 lines for metrics, tokens and capabilities that a library would have provided. Every check is visible and tested, which is also what the thesis needs for RQ2.
- ZTC tokens do not interoperate with JWT tooling: jwt.io and JWT libraries will not accept `typ: ZTC`. That is intended; a ZTC token should not be accepted by a service that expects some other JWT.
- If ZTC has to accept tokens from an external identity provider (OpenID Connect), this decision is revisited. The likely answer is go-jose, confined to one package at the edge of the system.
