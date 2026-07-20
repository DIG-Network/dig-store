//! The comprehensive GETTER surface (SPEC §5/§7): every on-chain and off-chain store property.
//!
//! Getters split by plane:
//!
//! - **On-chain** getters read the DataLayer singleton through a [`ChainSource`] and prove every
//!   value against the chain (NC-9). They are generic over `C: ChainSource` and network-free at the
//!   crate boundary — the caller supplies the (trusted) chain source.
//! - **URN** getters format the canonical `urn:dig:chia:…` scheme; the rootless store URN needs no
//!   chain read (buildable now), the latest-root URN reads the tip first.
//! - **Off-chain** getters open the `.dig` capsule via `dig-capsule` and read its manifest/visibility/
//!   resource properties.
//!
//! SCAFFOLD: the on-chain + off-chain bodies are `todo!()` gated on `dig-merkle 0.3.0` +
//! `dig-capsule` publishing (SPEC §11). [`get_store_urn`] is fully implemented now. The SIGNATURES
//! are final.

use crate::chain::ChainSource;
use crate::error::DigStoreResult;
use crate::size::SizeBucket;
use crate::types::{Bytes32, DidRef, RootHistory, StoreTip};

// ---------------------------------------------------------------------------
// URN getters — the rootless store URN needs no chain (implemented now).
// ---------------------------------------------------------------------------

/// The ROOTLESS store URN `urn:dig:chia:<store_id>` — the stable handle across all generations.
///
/// Needs no chain read: a store id fully determines its store URN. See [`crate::urn::store_urn`].
pub fn get_store_urn(store_id: Bytes32) -> String {
    crate::urn::store_urn(store_id)
}

/// The capsule URN `urn:dig:chia:<store_id>:<latest_root>` pinning the store's latest generation.
///
/// Reads the latest root from chain first (NC-9), then formats. See [`get_latest_root`].
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the on-chain read/proof fails.
pub fn get_latest_root_urn<C: ChainSource>(chain: &C, store_id: Bytes32) -> DigStoreResult<String> {
    let root = get_latest_root(chain, store_id)?;
    Ok(crate::urn::capsule_urn(store_id, root))
}

// ---------------------------------------------------------------------------
// On-chain getters — proven against the chain (NC-9), gated on dig-merkle publish.
// ---------------------------------------------------------------------------

/// The DID that owns the store, resolved by walking the launcher's parent spend on chain (NC-9).
///
/// Returns `None` for a store minted from an ordinary (non-DID) coin. Fail-closed at every missing
/// lineage step (SPEC §3.7).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails.
pub fn get_store_did_owner<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<Option<DidRef>> {
    todo!("gated on dig-merkle 0.3.0 resolve_owner_did (SPEC §11)")
}

/// The current confirmed tip of the store singleton — the coin a `modify`/`melt` must consume.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent or the chain source fails.
pub fn get_store_singleton_tip<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<StoreTip> {
    todo!("gated on dig-merkle 0.3.0 read/hydrate (SPEC §11)")
}

/// The ordered history of every merkle root the store has anchored (oldest → newest), proven by
/// walking the singleton's lineage on chain (NC-9).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails or a lineage step does not verify.
pub fn get_root_history<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<RootHistory> {
    todo!("gated on dig-merkle 0.3.0 lineage walk (SPEC §11)")
}

/// The latest anchored merkle root (the root at the current tip), proven on chain (NC-9).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent or the chain source fails.
pub fn get_latest_root<C: ChainSource>(chain: &C, store_id: Bytes32) -> DigStoreResult<Bytes32> {
    Ok(get_store_singleton_tip(chain, store_id)?.root_hash)
}

/// The store's on-chain human label (`dig-merkle` metadata `"l"`), if set.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails.
pub fn get_store_label<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<Option<String>> {
    todo!("gated on dig-merkle 0.3.0 metadata read (SPEC §11)")
}

/// The store's on-chain human description (`dig-merkle` metadata `"d"`), if set.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails.
pub fn get_store_description<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<Option<String>> {
    todo!("gated on dig-merkle 0.3.0 metadata read (SPEC §11)")
}

/// The store's on-chain size bucket (`dig-merkle` metadata `"sz"`) — the value the SIZE PROOF checks
/// a download against (SPEC §4).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails.
pub fn get_store_size_bucket<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<Option<SizeBucket>> {
    todo!("gated on dig-merkle 0.3.0 metadata read (SPEC §11)")
}

/// The store's on-chain program hash (`dig-merkle` metadata `"p"`), if set.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails.
pub fn get_store_program_hash<C: ChainSource>(
    _chain: &C,
    _store_id: Bytes32,
) -> DigStoreResult<Option<Bytes32>> {
    todo!("gated on dig-merkle 0.3.0 metadata read (SPEC §11)")
}

// ---------------------------------------------------------------------------
// Off-chain getters — the .dig capsule (dig-capsule), gated on capsule publish.
// ---------------------------------------------------------------------------

/// An opened `.dig` capsule — the off-chain data plane handle over which capsule getters read.
///
/// A placeholder for `dig_capsule::capsule::Capsule` + its reader; on the compose pass it becomes a
/// thin wrapper over the `dig-capsule` facade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCapsule {
    /// The `(store_id, root_hash)` the capsule pins.
    pub store_id: Bytes32,
    /// The anchored merkle root of this capsule generation.
    pub root_hash: Bytes32,
}

/// Opens a `.dig` capsule from raw artifact bytes, verifying its self-consistency (SPEC §5).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the bytes are not a valid `.dig`.
pub fn open_capsule(_dig_bytes: &[u8]) -> DigStoreResult<OpenCapsule> {
    todo!("gated on dig-capsule single-crate publish (SPEC §11)")
}

/// The `(store_id, root_hash)` a capsule pins — its capsule identity.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the capsule cannot be read.
pub fn get_capsule_identity(_capsule: &OpenCapsule) -> DigStoreResult<(Bytes32, Bytes32)> {
    todo!("gated on dig-capsule single-crate publish (SPEC §11)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Bytes32 {
        Bytes32([b; 32])
    }

    #[test]
    fn get_store_urn_is_rootless_and_needs_no_chain() {
        assert_eq!(
            get_store_urn(id(0xaa)),
            format!("urn:dig:chia:{}", "aa".repeat(32))
        );
    }
}
