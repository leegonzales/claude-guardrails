//! Entry point that actually compiles the integration tests.
//!
//! `tests/integration/` is a subdirectory, and cargo only builds `tests/*.rs` as
//! test crates. Without this file the 60+ tests under it were never compiled and
//! never run — `cargo test` reported green on the unit tests alone.

#[path = "integration/mod.rs"]
mod integration;
