//! The store LIFECYCLE (SPEC §3): a store is a coin that gets SPENT.
//!
//! A DIG store is a CHIP-0035 DataLayer singleton. Three operations span its life, each a spend of
//! that coin:
//!
//! - [`create_store`] — launch the store coin from a DID-authorized parent, anchoring the first root
//!   + its size bucket + optional metadata.
//! - [`modify_store`] — spend the tip coin to recreate the store with a NEW root (a new generation).
//! - [`melt_store`] — terminally spend the coin, closing the store with no successor.
//!
//! Every operation returns an UNSIGNED [`StoreSpend`] (inherited boundary INV-2/INV-3 from
//! `dig-merkle`): `dig-store` never holds a key, never signs, never broadcasts. The wallet-backend /
//! node signs the reported messages, assembles the `SpendBundle`, and submits it. The on-chain
//! encoding is minimal (NC-8) — delegated wholesale to `dig-merkle`, which owns the byte layout.
//!
//! SCAFFOLD: the bodies are `todo!()` gated on `dig-merkle 0.3.0` + `dig-capsule` publishing to
//! crates.io (SPEC §11). The SIGNATURES are final — this is the shape consumers build against.

use crate::error::DigStoreResult;
use crate::size::SizeBucket;
use crate::types::{Bytes32, DidRef};

/// A store owner authority for a spend.
///
/// A placeholder for `dig_merkle::Owner`; on the compose pass it becomes a re-export. `Standard`
/// carries the owner's public key (bytes); `Custom` is the escape hatch for a pre-built inner spend
/// (a DID-authorized delegated puzzle, a multisig, a vault).
#[derive(Debug, Clone)]
pub enum StoreOwner {
    /// The standard single-key p2 puzzle, owned by the given public key bytes.
    Standard(Vec<u8>),
    /// A fully pre-built inner spend for a custom p2 puzzle, passed through unchanged.
    Custom(Vec<u8>),
}

/// The unsigned result of a lifecycle operation.
///
/// A placeholder for `dig_merkle::MerkleCoinSpend`; on the compose pass it becomes a re-export
/// carrying the real `CoinSpend`s + the recreated child `DataStore`. Consumers then sign the reported
/// messages, assemble the `SpendBundle`, and broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSpend {
    /// The unsigned coin-spend bytes composing this operation.
    pub coin_spends: Vec<Vec<u8>>,
    /// The store id (`launcher_id`) the operation targets or creates.
    pub store_id: Option<Bytes32>,
}

/// The parameters that describe a store's on-chain metadata at creation (SPEC §3.1).
///
/// Every field but `root_hash` and `size` is optional and omitted-when-absent on chain (NC-8).
#[derive(Debug, Clone)]
pub struct CreateStoreParams {
    /// The first anchored merkle root (the `.dig` root of generation 0).
    pub root_hash: Bytes32,
    /// The store's size, anchored as a power-of-2 bucket so clients can gate downloads (SPEC §4).
    pub size: SizeBucket,
    /// An optional human label.
    pub label: Option<String>,
    /// An optional human description.
    pub description: Option<String>,
    /// An optional CLVM tree-hash of a program/puzzle associated with the store (`dig-merkle` `"p"`).
    pub program_hash: Option<Bytes32>,
    /// The reserve fee (mojos) to attach to the launch spend.
    pub fee: u64,
}

/// Launches a new store coin from a DID-authorized parent, anchoring the first root (SPEC §3.1).
///
/// The `parent_coin_id` funds + parents the launcher (so `launcher_id == store_id` derives from it).
/// The store is rooted in a DID by passing the DID-authorized coin as parent with a
/// [`StoreOwner::Custom`] inner spend that satisfies the DID puzzle — owner discovery then resolves
/// the DID via `dig-merkle` (`resolve_owner_did`, NC-9). Returns the UNSIGNED launch spend.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the spend cannot be constructed (invalid metadata / size /
/// delegated-puzzle set).
pub fn create_store(
    _parent_coin_id: Bytes32,
    _owner: StoreOwner,
    _params: CreateStoreParams,
) -> DigStoreResult<StoreSpend> {
    todo!("gated on dig-merkle 0.3.0 + dig-capsule single-crate publish (SPEC §11)")
}

/// Spends the store's tip coin to recreate it anchoring `new_root` — a new generation (SPEC §3.2).
///
/// `store_tip` is the current confirmed tip (from [`crate::get_store_singleton_tip`]); the spend
/// consumes it and recreates the singleton with the new root, preserving `store_id`. Returns the
/// UNSIGNED spend.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the spend cannot be constructed.
pub fn modify_store(
    _store_tip: crate::types::StoreTip,
    _owner: StoreOwner,
    _new_root: Bytes32,
    _fee: u64,
) -> DigStoreResult<StoreSpend> {
    todo!("gated on dig-merkle 0.3.0 publish (SPEC §11)")
}

/// Terminally spends (melts) the store's tip coin, leaving no successor (SPEC §3.3).
///
/// Closes the store: the singleton is spent with no recreation, so no future generation can be
/// anchored. Returns the UNSIGNED melt spend.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the spend cannot be constructed.
pub fn melt_store(
    _store_tip: crate::types::StoreTip,
    _owner: StoreOwner,
    _fee: u64,
) -> DigStoreResult<StoreSpend> {
    todo!("gated on dig-merkle 0.3.0 publish (SPEC §11)")
}

/// The DID that authorized a store's creation, if any (SPEC §3.1) — a convenience re-shape used by
/// [`create_store`] callers that build the parent DID spend. Returns the resolved owner reference.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the owner cannot be resolved.
pub fn resolve_owner(_owner: &StoreOwner) -> DigStoreResult<Option<DidRef>> {
    todo!("gated on dig-merkle 0.3.0 publish (SPEC §11)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Bytes32 {
        Bytes32([b; 32])
    }

    fn params() -> CreateStoreParams {
        CreateStoreParams {
            root_hash: id(1),
            size: SizeBucket::from_exponent(7).unwrap(),
            label: Some("docs".into()),
            description: None,
            program_hash: None,
            fee: 0,
        }
    }

    #[test]
    #[ignore = "gated on dig-merkle 0.3.0 + dig-capsule publish (SPEC §11)"]
    fn create_store_builds_launch_spend() {
        let _ = create_store(id(9), StoreOwner::Standard(vec![0u8; 48]), params());
    }

    #[test]
    #[ignore = "gated on dig-merkle 0.3.0 publish (SPEC §11)"]
    fn modify_store_recreates_with_new_root() {
        let tip = crate::types::StoreTip {
            store_id: id(9),
            coin_id: id(10),
            root_hash: id(1),
        };
        let _ = modify_store(tip, StoreOwner::Standard(vec![0u8; 48]), id(2), 0);
    }

    #[test]
    #[ignore = "gated on dig-merkle 0.3.0 publish (SPEC §11)"]
    fn melt_store_closes_the_store() {
        let tip = crate::types::StoreTip {
            store_id: id(9),
            coin_id: id(10),
            root_hash: id(1),
        };
        let _ = melt_store(tip, StoreOwner::Standard(vec![0u8; 48]), 0);
    }
}
