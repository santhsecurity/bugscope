# bugscope

Drop-in scope enforcement, authorization, and compliance helpers for security CLI tools. It wraps HTTP clients to guarantee requests stay within allowed domains, attach required headers, and honor program rate limits.

```rust
use bugscope::{ScopeConfig, ScopeGuard};
use reqwest::{Client, Method};

let scope = ScopeConfig {
    in_scope: vec!["*.example.com".to_string(), "192.0.2.0/24".to_string()],
    out_of_scope: vec!["admin.example.com".to_string()],
};

let client = Client::new();
let guard = ScopeGuard::new(client, scope);

let result = guard.request(Method::GET, "https://admin.example.com");
assert!(result.is_err()); // Blocked before the request is built
```

## Why this exists

Every security scanner needs to respect bounty scope, inject authorization headers, and honor program rate limits. Writing this logic repeatedly leads to bugs where a scanner accidentally hits an out-of-scope domain or gets blocked for ignoring a `429 Too Many Requests` header. `bugscope` centralizes these rules at the network edge.

## Engagement management

Load program scope, credentials, and rate limits from TOML files.

```toml
program_name = "acme"
platform = "hackerone"

[scope]
in_scope = ["example.com", "*.example.com"]
out_of_scope = ["admin.example.com"]

[credentials]
handle = "alice"
token = "secret"

[rate_limits]
default_requests_per_second = 2.0
```

```rust
use bugscope::EngagementStore;

let store = EngagementStore::discover().unwrap();
let engagement = store.load("acme").unwrap();
println!("Loaded scope for {}", engagement.program_name);
```

## Rate limiting

The rate limiter handles standard bucket refills, burst limits, and automatic backoff when encountering `429 Too Many Requests` responses.

```toml
default_requests_per_second = 1.5
max_retries = 4

[[rules]]
pattern = "*.example.com"
requests_per_second = 0.5
burst = 2
retry_after_cap = "10s"
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/bugscope.svg)](https://crates.io/crates/bugscope)
[![docs.rs](https://docs.rs/bugscope/badge.svg)](https://docs.rs/bugscope)