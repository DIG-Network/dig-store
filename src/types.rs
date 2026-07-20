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
//! - [`MerkleCoinSpend`] — the unsigned result of a lifecycle operation (coin spends + child store);
//! - [`Proof`] / [`LineageProof`] — a singleton's eve-or-lineage proof and the lineage proof a child
//!   spend must carry (see [`crate::child_lineage_proof`]);
//! - [`DelegatedPuzzle`] — an admin/writer/oracle delegated puzzle a store may carry (SPEC §5).
//!
//! Two `dig-store`-owned view types are added here:
//!
//! - [`RootHistory`] — the ordered list of merkle roots a store has anchored across its generations,
//!   produced by the on-chain lineage walk (SPEC §5);
//! - [`CapsuleIdentity`] — the `(store_id, root_hash)` a capsule declares, recovered OFF-CHAIN from a
//!   compiled `.dig` module's bytes (SPEC §5/§11). It is the `dig-store`-native view (canonical
//!   [`Bytes32`]) of a `dig_capsule::capsule::Capsule`, so the whole store surface speaks ONE byte
//!   type rather than exposing `dig-capsule`'s separate `Bytes32`.

use serde::{Deserialize, Serialize};

pub use dig_merkle::{
    Bytes32, Coin, CoinSpend, DataStore, DelegatedPuzzle, DidRef, DigDataStoreMetadata,
    LineageProof, MerkleCoinSpend, Proof,
};

/// The lifecycle state of a store as seen on chain (SPEC §5).
///
/// The three outcomes of the single lineage walk that backs [`crate::get_store_status`]:
///
/// - [`Live`](StoreStatusKind::Live) — the launcher resolved and the walk reached an UNSPENT tip;
/// - [`Melted`](StoreStatusKind::Melted) — the launcher resolved but the lineage ends in a terminal
///   melt (no live tip); the store still has a root history but no current content;
/// - [`NotFound`](StoreStatusKind::NotFound) — no launcher spend exists on chain for this store id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreStatusKind {
    /// The store is live: its singleton has an unspent tip anchoring the current root.
    Live,
    /// The store has been melted: its lineage ends in a terminal melt, no live tip remains.
    Melted,
    /// No store with this id exists on chain (no launcher spend found).
    NotFound,
}

/// How deeply the live tip is buried under the current chain peak (SPEC §5).
///
/// `have` is the number of blocks between the tip's confirming height and the current peak
/// (`peak.saturating_sub(confirmed_height)`); `target` is the caller-chosen confirmation depth at
/// which the tip is considered settled (see [`crate::DEFAULT_CONFIRMATION_TARGET`]). Present only when
/// the chain source exposed BOTH a peak height and the tip's confirmed height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmations {
    /// The confirmation depth observed (`peak_height - tip_confirmed_height`).
    pub have: u32,
    /// The confirmation depth the caller treats as settled.
    pub target: u32,
}

/// The aggregate on-chain status of a store, produced by [`crate::get_store_status`] from ONE
/// consistent lineage walk plus a single supplementary read on the resolved tip (SPEC §5, NC-9).
///
/// Every identifier field is a bare lowercase-hex string byte-identical to the URN body form (so
/// `store_id` equals the id in the store's `urn:dig:chia:<store_id>`), making the whole snapshot
/// directly JSON-serializable for a CLI/RPC surface without leaking a chia byte type across serde.
///
/// # Field availability by [`status`](StoreStatus::status)
///
/// - `NotFound` — every optional field is `None`, `verified` is `false`, `generation_count` is 0.
/// - `Melted`  — identity fields (`owner_puzzle_hash`/`live_root`/`program_hash`/`coin_id`) and
///   `confirmations` are `None`, `verified` is `false`; `generation_count` still counts every root
///   the store anchored while live.
/// - `Live`    — `live_root`/`owner_puzzle_hash`/`coin_id` are always present; `program_hash`,
///   `confirmations`, and `verified` reflect what the metadata + supplementary tip read carried.
///
/// `head_signature` is ALWAYS `None`: a per-coin BLS head signature is structurally unavailable
/// through the [`ChainSource`](crate::ChainSource) surface (it yields `CoinSpend` — coin/puzzle/
/// solution — with no signature). The field ships present-but-`None` for forward-compat; a routed
/// follow-up sources it out-of-band (SPEC §5/§7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreStatus {
    /// The store's lifecycle state on chain.
    pub status: StoreStatusKind,
    /// The store's launcher id as bare lowercase hex (the URN body form).
    pub store_id: String,
    /// The live tip's confirmation depth vs the chain peak, when both heights are known.
    pub confirmations: Option<Confirmations>,
    /// The live tip's owner puzzle hash as bare lowercase hex, when live.
    pub owner_puzzle_hash: Option<String>,
    /// The latest anchored merkle root as bare lowercase hex, when live.
    pub live_root: Option<String>,
    /// The store's on-chain program hash as bare lowercase hex, when live and set.
    pub program_hash: Option<String>,
    /// The live tip's head BLS signature — always `None` (structurally unavailable, see type docs).
    pub head_signature: Option<String>,
    /// The live tip coin's id as bare lowercase hex, when live.
    pub coin_id: Option<String>,
    /// Whether the resolved tip's coin record confirms it is unspent (never self-asserted; `false`
    /// when no coin record was available). Cross-checked against the walk (NC-9 fail-closed).
    pub verified: bool,
    /// The number of generations (root anchorings) the store has had across its whole lineage.
    pub generation_count: usize,
}

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
