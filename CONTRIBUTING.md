# Contributing

## Development

1. Install a current stable Rust toolchain.
2. Make changes in small, reviewable commits.
3. Run:

```bash
cargo fmt
cargo check
cargo test
```

## Design expectations

- Scope checks must fail closed.
- Header injection must validate names and values before send.
- Rate limiting changes must preserve automatic `429` backoff behavior.
- New behavior should ship with tests, especially for matching and edge cases.

## Pull requests

- Update examples or docs when the public API changes.
- Keep the integration story simple for downstream CLI authors.
- Prefer additive config changes over breaking existing TOML layouts.
