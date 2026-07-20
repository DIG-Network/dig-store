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
//! Two `dig-store`-owned view types are added here:
//!
//! - [`RootHistory`] — the ordered list of merkle roots a store has anchored across its generations,
//!   produced by the on-chain lineage walk (SPEC §5);
//! - [`CapsuleIdentity`] — the `(store_id, root_hash)` a capsule declares, recovered OFF-CHAIN from a
//!   compiled `.dig` module's bytes (SPEC §5/§11). It is the `dig-store`-native view (canonical
//!   [`Bytes32`]) of a `dig_capsule::capsule::Capsule`, so the whole store surface speaks ONE byte
//!   type rather than exposing `dig-capsule`'s separate `Bytes32`.

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

/// The identity a capsule declares: one immutable store generation, the pair `(store_id, root_hash)`.
///
/// Recovered OFF-CHAIN from a compiled `.dig` module's bytes by [`crate::get_capsule_identity`] /
/// [`crate::open_capsule`] (SPEC §5/§11). This is `dig-store`'s canonical-[`Bytes32`] view of a
/// `dig_capsule::capsule::Capsule`.
///
/// # `store_id` is NOT self-verified
///
/// `root_hash` is proven internally consistent by the reader (it recomputes the merkle root from the
/// module's committed leaves and rejects a forged one). `store_id`, however, is the store's on-chain
/// Chia launcher id, baked into the module at compile time and NOT self-verifiable from the module
/// bytes alone — nothing in the bytes binds them to that launcher. Treat a `store_id` from
/// [`crate::get_capsule_identity`] as a CLAIM until cross-checked against a trusted anchor (the URN you
/// resolved, the on-chain singleton, or a verified `ChainSource`). [`crate::open_capsule`] performs
/// that cross-check for you.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapsuleIdentity {
    /// The store's on-chain launcher id (a CLAIM until cross-checked — see the type docs).
    pub store_id: Bytes32,
    /// The merkle root of this capsule generation, proven internally consistent by the reader.
    pub root_hash: Bytes32,
}

impl CapsuleIdentity {
    /// The capsule URN `urn:dig:chia:<store_id>:<root_hash>` pinning this exact generation.
    pub fn capsule_urn(&self) -> String {
        crate::urn::capsule_urn(self.store_id, self.root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Bytes32 {
        Bytes32::new([b; 32])
    }

    #[test]
    fn capsule_identity_formats_its_pinning_urn() {
        let identity = CapsuleIdentity {
            store_id: id(0xaa),
            root_hash: id(0xbb),
        };
        assert_eq!(
            identity.capsule_urn(),
            format!("urn:dig:chia:{}:{}", "aa".repeat(32), "bb".repeat(32))
        );
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
