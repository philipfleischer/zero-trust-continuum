# Architecture Decision Records

Each record explains one decision that shapes the architecture: the context, what was decided, and what it costs.
The format is taken from Michael Nygard's template (Status, Context, Decision, Consequences).

Rules:

- A new decision gets the next number. The numbers follow the order in which decisions were made.
- A record is never deleted or rewritten. Any changes in decisions down the line gets a new record, and the old ADR is marked `superseded by ...`.
- A record is added in the same branch as the code it describes.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-fail-closed.md) | Fail closed when no decision is available | accepted |
| [0002](0002-pdp-write-token.md) | A shared bearer token protects writes to the PDP until mTLS | accepted, superseded in M5 |
| [0003](0003-go-standard-library-only.md) | The Go services use only the standard library | accepted |
