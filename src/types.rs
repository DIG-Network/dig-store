//! The shared identifier + value types of the store surface.
//!
//! The coin/identity types are re-exported VERBATIM from `dig-merkle` (which re-exports the
//! `chia-wallet-sdk` byte-source-of-truth) so a consumer depends on ONE canonical shape and never a
//! shadow copy that could byte-drift:
//!
//! - [`Bytes32`] — a 32-byte identifier (a `store_id` / `launcher_id`, a merkle root, a DID id);
//! - [`Coin`] / [`CoinSpend`] — the Chia coin + confirmed spend;
//! - [`DataStore`] / [`DigDataStoreMetadata`] — the hydrated DataLayer coin + its on-chain metadata;
//! - [`DidRef`] — a reference to an owning DID by its launcher id;
//! - [`MerkleCoinSpend`] — the unsigned result of a lifecycle operation (coin spends + child store).
//!
//! [`RootHistory`] is the one `dig-store`-owned view type: the ordered list of merkle roots a store
//! has anchored across its generations, produced by the on-chain lineage walk (SPEC §5).

pub use dig_merkle::{
    Bytes32, Coin, CoinSpend, DataStore, DidRef, DigDataStoreMetadata, MerkleCoinSpend,
};

/// The ordered history of merkle roots a store has anchored, oldest first.
///
/// Each entry is proven on chain by walking the singleton's lineage from the launcher forward (NC-9,
/// SPEC §5). The last element is the latest root. A live store is never empty (the mint anchors
/// generation 0); a fully-melted store's history still lists every root it anchored while live.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootHistory {
    /// The anchored roots, oldest → newest.
    pub roots: Vec<Bytes32>,
}

impl RootHistory {
    /// The most recently anchored root, if any.
    pub fn latest(&self) -> Option<Bytes32> {
        self.roots.last().copied()
    }

    /// The number of generations (root anchorings) the store has had.
    pub fn generation_count(&self) -> usize {
        self.roots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Bytes32 {
        Bytes32::new([b; 32])
    }

    #[test]
    fn root_history_reports_latest_and_generation_count() {
        let empty = RootHistory::default();
        assert_eq!(empty.latest(), None);
        assert_eq!(empty.generation_count(), 0);

        let history = RootHistory {
            roots: vec![id(1), id(2), id(3)],
        };
        assert_eq!(history.latest(), Some(id(3)));
        assert_eq!(history.generation_count(), 3);
    }
}
