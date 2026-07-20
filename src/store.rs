//! The comprehensive on-chain GETTER surface (SPEC §5/§7): every chain-anchored store property.
//!
//! Getters split by concern:
//!
//! - **URN** getters format the canonical `urn:dig:chia:…` scheme; the rootless store URN needs no
//!   chain read ([`get_store_urn`], buildable now), the latest-root URN reads the tip first.
//! - **On-chain** getters read the DataLayer singleton through a [`ChainSource`] and prove every
//!   value against the chain (NC-9). They are generic over `C: ChainSource` and network-free at the
//!   crate boundary — the caller supplies the (trusted) chain source.
//!
//! The on-chain reads share ONE lineage walk ([`walk_lineage`]): starting from the launcher spend
//! (`coin_spend(store_id)`), it hydrates each generation with `dig-merkle` and follows the singleton
//! forward — `coin_spend(tip_coin) == None` marks the live tip; a `MissingLineage` hydration marks a
//! melt. This yields both the ordered root history and the tip in a single pass, fail-closed at every
//! missing hop.
//!
//! The OFF-CHAIN `.dig` capsule getters (`open_capsule` / `get_capsule_identity`) are DEFERRED: as of
//! `dig-capsule 0.4.0` there is no lightweight `bytes → (store_id, root_hash)` capsule reader (the
//! only path is the full wasmtime serve runtime), so a `Capsule::from_module_bytes` reader is being
//! added to `dig-capsule` release-first and the capsule getters land in a follow-up unit (SPEC §11).
//! The download-gating SIZE PROOF (SPEC §4) needs no capsule open and ships here now.

use dig_merkle::{hydrate, resolve_owner_did, MerkleError};

use crate::chain::ChainSource;
use crate::error::{DigStoreError, DigStoreResult};
use crate::size::SizeBucket;
use crate::types::{Bytes32, DataStore, DidRef, DigDataStoreMetadata, RootHistory};

// ---------------------------------------------------------------------------
// URN getters.
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
// On-chain getters — proven against the chain via the shared lineage walk (NC-9).
// ---------------------------------------------------------------------------

/// The DID that owns the store, resolved by walking the launcher's parent spend on chain (NC-9).
///
/// Returns `None` for a store minted from an ordinary (non-DID) coin. Fail-closed at every missing
/// lineage step (SPEC §3.7). Delegated to [`dig_merkle::resolve_owner_did`].
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the chain source fails.
pub fn get_store_did_owner<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<Option<DidRef>> {
    resolve_owner_did(store_id, chain)
        .map_err(|error| DigStoreError::Proof(format!("owner-DID discovery: {error}")))
}

/// The current confirmed tip of the store singleton — the coin a `modify`/`melt` must consume, fully
/// hydrated (coin + lineage proof + metadata + owner) so it can be passed straight to
/// [`crate::modify_store`] / [`crate::melt_store`].
///
/// # Errors
///
/// Returns [`DigStoreError::Proof`] if the store is absent, has been melted (no live tip), or the
/// chain source fails.
pub fn get_store_singleton_tip<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<DataStore<DigDataStoreMetadata>> {
    walk_lineage(chain, store_id)?.tip.ok_or_else(|| {
        DigStoreError::Proof(format!("store {store_id} has been melted (no live tip)"))
    })
}

/// The ordered history of every merkle root the store has anchored (oldest → newest), proven by
/// walking the singleton's lineage on chain (NC-9). A melted store still reports every root it
/// anchored while live.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent, the chain source fails, or a lineage
/// step does not verify.
pub fn get_root_history<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<RootHistory> {
    Ok(RootHistory {
        roots: walk_lineage(chain, store_id)?.roots,
    })
}

/// The latest anchored merkle root (the root at the current tip), proven on chain (NC-9).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent/melted or the chain source fails.
pub fn get_latest_root<C: ChainSource>(chain: &C, store_id: Bytes32) -> DigStoreResult<Bytes32> {
    Ok(get_store_singleton_tip(chain, store_id)?
        .info
        .metadata
        .root_hash)
}

/// The store's on-chain human label (`dig-merkle` metadata `"l"`), if set.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent/melted or the chain source fails.
pub fn get_store_label<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<Option<String>> {
    Ok(get_store_singleton_tip(chain, store_id)?
        .info
        .metadata
        .label)
}

/// The store's on-chain human description (`dig-merkle` metadata `"d"`), if set.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent/melted or the chain source fails.
pub fn get_store_description<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<Option<String>> {
    Ok(get_store_singleton_tip(chain, store_id)?
        .info
        .metadata
        .description)
}

/// The store's on-chain size bucket (`dig-merkle` metadata `"sz"`) — the value the SIZE PROOF checks
/// a download against (SPEC §4).
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent/melted or the chain source fails.
pub fn get_store_size_bucket<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<Option<SizeBucket>> {
    Ok(get_store_singleton_tip(chain, store_id)?
        .info
        .metadata
        .size_bucket)
}

/// The store's on-chain program hash (`dig-merkle` metadata `"p"`), if set.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the store is absent/melted or the chain source fails.
pub fn get_store_program_hash<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
) -> DigStoreResult<Option<Bytes32>> {
    Ok(get_store_singleton_tip(chain, store_id)?
        .info
        .metadata
        .program_hash)
}

// ---------------------------------------------------------------------------
// The shared lineage walk.
// ---------------------------------------------------------------------------

/// The result of walking a store's singleton lineage from the launcher forward.
struct Lineage {
    /// Every anchored merkle root, oldest → newest.
    roots: Vec<Bytes32>,
    /// The live tip DataStore, or `None` if the store has been melted (its lineage ends in a melt).
    tip: Option<DataStore<DigDataStoreMetadata>>,
}

/// Walks the store singleton from its launcher spend forward to the tip (or melt), collecting each
/// generation's anchored root in order.
///
/// The walk hydrates the eve store from `coin_spend(store_id)` (the launcher spend), then follows the
/// singleton: `coin_spend(current_coin)` is the spend that recreated it. `None` means `current` is
/// the unspent live tip; a `MissingLineage` hydration means that spend was a terminal melt. Every
/// missing/failed hop fails closed (NC-9).
fn walk_lineage<C: ChainSource>(chain: &C, store_id: Bytes32) -> DigStoreResult<Lineage> {
    let launcher_spend = read_coin_spend(chain, store_id)?.ok_or_else(|| {
        DigStoreError::Proof(format!("store {store_id} launcher not found on chain"))
    })?;
    let mut current = hydrate(&launcher_spend).map_err(|error| {
        DigStoreError::Proof(format!("hydrate launcher of {store_id}: {error}"))
    })?;

    let mut roots = Vec::new();
    loop {
        roots.push(current.info.metadata.root_hash);

        match read_coin_spend(chain, current.coin.coin_id())? {
            // The current coin is unspent — it is the live tip.
            None => {
                return Ok(Lineage {
                    roots,
                    tip: Some(current),
                })
            }
            Some(spend) => match hydrate(&spend) {
                // The spend recreated the singleton — advance to the next generation.
                Ok(child) => current = child,
                // A terminal melt recreated no successor — the store is closed, no live tip.
                Err(MerkleError::MissingLineage) => return Ok(Lineage { roots, tip: None }),
                Err(error) => {
                    return Err(DigStoreError::Proof(format!(
                        "hydrate generation of {store_id}: {error}"
                    )))
                }
            },
        }
    }
}

/// Reads the spend that spent `coin_id`, mapping the source's own error into [`DigStoreError::Proof`]
/// so the crate's error surface never leaks the generic `ChainSource::Error` type parameter.
fn read_coin_spend<C: ChainSource>(
    chain: &C,
    coin_id: Bytes32,
) -> DigStoreResult<Option<crate::types::CoinSpend>> {
    chain
        .coin_spend(coin_id)
        .map_err(|error| DigStoreError::Proof(format!("chain read for {coin_id}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Bytes32 {
        Bytes32::new([b; 32])
    }

    #[test]
    fn get_store_urn_is_rootless_and_needs_no_chain() {
        assert_eq!(
            get_store_urn(id(0xaa)),
            format!("urn:dig:chia:{}", "aa".repeat(32))
        );
    }
}
