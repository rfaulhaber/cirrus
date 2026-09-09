# cirrus

A family of Rust crates for the Salesforce platform. Not affiliated with Salesforce.

## Crates

| Crate                                       | Description                                                                                                                   |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| [`cirrus`](crates/cirrus/)                  | HTTP client for the Salesforce REST API — sObject CRUD, SOQL/SOSL, Bulk 2.0, composite, Tooling, Apex REST, Event Monitoring. |
| [`cirrus-auth`](crates/cirrus-auth/)        | Salesforce OAuth 2.0 flows (JWT, Refresh, Client Credentials, Web Server PKCE, Token Exchange) + the `AuthSession` trait.     |
| [`cirrus-metadata`](crates/cirrus-metadata) | Client for the Salesforce Metadata API (SOAP).                                                                                |

Each crate ships and versions independently. They share a workspace so dependency versions, lint config, and tooling stay consistent.

`cirrus-auth` is re-exported as `cirrus::auth`, so users of `cirrus` don't need an explicit `cirrus-auth` dependency — `cirrus = "..."` is enough. Other Cirrus sibling crates (e.g. `cirrus-metadata`) depend on `cirrus-auth` directly so they don't pull in the REST client.

## Development

The repo is a Nix flake and ships an `.envrc`. With [direnv](https://direnv.net) installed, run `direnv allow` once and `cd`ing in loads the dev shell from then on; otherwise run `nix develop`. The shell provides stable `rustc`/`cargo`, `clippy`, `rust-analyzer`, `cargo-nextest`, and `cargo-release`.

You do not need to use Nix to contribute to this repository. The Nix developer environment is provided for convenience.

```bash
cargo build --workspace                          # build all crates
cargo nextest run --workspace                    # run all tests (no network)
cargo clippy --all-targets --workspace           # workspace-wide lints
cargo fmt --all                                  # format every crate
```

Per-crate READMEs and crate-specific commands live alongside each crate.

## License

MIT. See [`LICENSE`](LICENSE).
