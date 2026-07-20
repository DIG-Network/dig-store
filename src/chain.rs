//! The on-chain read boundary (SPEC §7, NC-9).
//!
//! `dig-store` is network-free at its core (inherited from `dig-merkle`, INV-1): it never dials the
//! chain itself. On-chain getters take a [`ChainSource`] the caller supplies — the user's own
//! verified node, or a trusted/threshold provider set — and prove every chain-anchored value against
//! it before returning (NC-9). A single untrusted remote MUST NOT back a custody-grade read
//! (NC-9 F1); the caller owns that trust decision.
//!
//! The trait is the ONE canonical [`dig_chainsource_interface::ChainSource`] shared across the whole
//! ecosystem — never a per-crate copy — re-exported here so a consumer reaching for the store getters
//! finds the boundary in one place. Its `coin_spend(coin_id)` fail-closed lookup (`Ok(None)` = the
//! coin is unspent/unknown; `Err(_)` = the source could not answer) is the primitive the store's
//! lineage walk composes.

pub use dig_chainsource_interface::ChainSource;
