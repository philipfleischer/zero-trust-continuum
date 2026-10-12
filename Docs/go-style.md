# Go style: code that reads like text

ZTC's Go code should be readable top to bottom, like pseudocode, without
having to remember what a one-letter name stood for twenty lines earlier.
These rules come on top of gofmt, go vet and golangci-lint, and they apply to
every new or changed `.go` file.

## 1. Names are words

Local variables, parameters, receivers, struct fields and type parameters are
whole words that say what the value **is**.

| Instead of | Write |
|---|---|
| `s`, `v`, `c`, `d`, `p`, `e` | `signer`, `verifier`, `claims`, `decision`, `policy`, `environment` |
| `req`, `resp`, `srv`, `buf`, `msg`, `sig` | `request`, `response`, `server`, `buffer`, `message`, `signature` |
| `def`, `exp`, `cfg`, `tc`, `kv` | `defaultValue`, `expiresAt`, `settings`, `testCase`, `signalKind` |
| `func (s *Store)` | `func (store *Store)` |
| `parse[T any]` | `parse[Value any]` |

Only these short names are allowed, because every Go programmer reads them as words:

- `err` for an error, `ctx` for a `context.Context`, `ok` for the second value of a comma-ok
- `t` for `*testing.T`
- `i` for a plain integer index, and only when the loop has nothing better to call it

Acronyms from the domain stay acronyms: `ID`, `URL`, `HTTP`, `JSON`, `TTL`,
`PDP`, `PEP`, `SPIFFE`, `HMAC`, `IED`.

## 2. The name says which one

When there is more than one of a kind, or a name would hide a package, add
the word that tells them apart: `loadedPolicy`, `trustStore`,
`accessRequest` next to an `httpRequest`, `cloudPDP` and `fogCache`.

- HTTP handlers use `writer http.ResponseWriter, request *http.Request`. If an
  access request is also in scope, call that one `accessRequest`.
- A value of type `config.Env` is `environment`.

## 3. Booleans read as a statement

`isExpired`, `hasScope`, `found`, `allowed`, `wantError`, not `exp`, `b` or `flag`.

## 4. One step per line

When a condition combines several checks or calls, give the parts names
first and test the names. The names replace a comment.

```go
// Hard to follow
if prefix, ok := strings.CutSuffix(g, "*"); ok && strings.HasSuffix(prefix, ":") && strings.HasPrefix(s, prefix) {

// Reads as text
prefix, isWildcard := strings.CutSuffix(granted, "*")
coversWholeGroup := isWildcard && strings.HasSuffix(prefix, ":")
if coversWholeGroup && strings.HasPrefix(wanted, prefix) {
```

The short form `if err := f(); err != nil` is fine; it is one step.

## 5. Tests

- A table row is a `testCase`, with fields such as `name`, `input` and `want`;
  the result is `got`.
- Helpers are named for what they build: `newTestSigner`, `pmuClaims`,
  `forgeToken`.

## 6. Comments say why

The code should say **what** happens; comments say **why**: the attack a
check stops, the standard a format follows, the flaw in the original that a
line fixes. Every file still has a header comment and every exported name a
doc comment.
