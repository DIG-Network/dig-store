//! The on-chain read boundary (SPEC §7, NC-9).
//!
//! `dig-store` is network-free at its core (inherited from `dig-merkle`, INV-1): it never dials the
//! chain itself. On-chain getters take a [`ChainSource`] the caller supplies — the user's own
//! verified node, or a trusted/threshold provider set — and prove every chain-anchored value against
//! it before returning (NC-9). A single untrusted remote MUST NOT back a custody-grade read
//! (NC-9 F1); the caller owns that trust decision.
//!
//! ## Compose-pass note
//!
//! This trait is a placeholder that mirrors the shape of the canonical
//! `dig_chainsource_interface::ChainSource`. On the compose pass (SPEC §11) it is replaced by that
//! published trait so the ecosystem shares ONE chain-source abstraction; getters keep the same
//! `<C: ChainSource>` signatures.

use crate::error::DigStoreResult;
use crate::types::Bytes32;

/// A source of confirmed on-chain coin spends, used to prove a store's state against the chain.
///
/// The minimal surface a store read needs: fetch the confirmed spend of a coin by id. Lineage walks
/// (owner discovery, root history) are expressed as repeated [`coin_spend`](Self::coin_spend)
/// lookups, exactly as `dig-merkle`'s `resolve_owner_did` does.
pub trait ChainSource {
    /// The confirmed spend of the coin with the given id, or `None` if the coin has not been spent
    /// (or does not exist) — fail-closed.
    ///
    /// The returned bytes MUST come from a source the caller trusts for custody-grade reads (NC-9).
    ///
    /// # Errors
    ///
    /// Returns a [`DigStoreResult`] error if the source itself fails (network/backend error), as
    /// distinct from an absent coin (`Ok(None)`).
    fn coin_spend(&self, coin_id: Bytes32) -> DigStoreResult<Option<CoinSpendBytes>>;
}

/// The raw bytes of a confirmed coin spend (coin id + puzzle reveal + solution).
///
/// A placeholder for `chia_protocol::CoinSpend`; on the compose pass it becomes a re-export of the
/// SDK type so no re-parsing is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinSpendBytes {
    /// The id of the coin that was spent.
    pub coin_id: Bytes32,
    /// The revealed puzzle bytes.
    pub puzzle_reveal: Vec<u8>,
    /// The solution bytes.
    pub solution: Vec<u8>,
}
