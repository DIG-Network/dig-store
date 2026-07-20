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
//! The OFF-CHAIN `.dig` capsule getters (`open_capsule` / `get_capsule_identity`) live in
//! [`crate::capsule`] — they read a capsule's declared identity from compiled `.dig` module bytes via
//! `dig-capsule`'s lightweight, wasmtime-free reader (SPEC §5/§11), independent of any chain read.

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

/// The hard ceiling on the number of generations the lineage walk will follow.
///
/// A well-behaved chain source returns a finite recreation chain, but a hostile or buggy one could
/// return an endless stream of valid-looking recreation spends, hanging the walk (a DoS). The cap
/// bounds the walk and fails closed past it. It is deliberately far above any real store's generation
/// count (a store recreates once per content update).
const MAX_LINEAGE_GENERATIONS: usize = 100_000;

/// Walks the store singleton from its launcher spend forward to the tip (or melt), collecting each
/// generation's anchored root in order. See [`walk_lineage_bounded`] for the walk contract; this is
/// the production entry with the [`MAX_LINEAGE_GENERATIONS`] cap.
fn walk_lineage<C: ChainSource>(chain: &C, store_id: Bytes32) -> DigStoreResult<Lineage> {
    walk_lineage_bounded(chain, store_id, MAX_LINEAGE_GENERATIONS)
}

/// Walks the store singleton from its launcher spend forward to the tip (or melt), collecting each
/// generation's anchored root in order — the identity-checked, bounded core of the on-chain reads.
///
/// The walk hydrates the eve store from `coin_spend(store_id)` (the launcher spend), then follows the
/// singleton: `coin_spend(current_coin)` is the spend that recreated it. `None` means `current` is
/// the unspent live tip; a `MissingLineage` hydration means that spend was a terminal melt.
///
/// # Identity proof against the chain (NC-9) — never trust the source blindly
///
/// A `ChainSource` is caller-supplied and, in real deployments, attacker-influenceable (the §5.3
/// ladder includes the public `rpc.dig.net` gateway). A hostile or buggy source could return a
/// DIFFERENT store's valid-looking spend for a coin id we asked about; without a check the getters
/// would then return the WRONG store's root/owner instead of failing closed. So every hop is proven:
///
/// - the returned spend's `coin.coin_id()` MUST equal the coin id we requested (a spend for a
///   different coin is rejected), and
/// - the hydrated launcher's `launcher_id` MUST equal `store_id` (the store we were asked to read).
///
/// Every missing / mismatched / failed hop fails closed with [`DigStoreError::Proof`], and the walk
/// is bounded by `max_generations` (a hostile endless-recreation stream is rejected, not followed).
fn walk_lineage_bounded<C: ChainSource>(
    chain: &C,
    store_id: Bytes32,
    max_generations: usize,
) -> DigStoreResult<Lineage> {
    let launcher_spend = read_verified_spend(chain, store_id)?.ok_or_else(|| {
        DigStoreError::Proof(format!("store {store_id} launcher not found on chain"))
    })?;
    let mut current = hydrate(&launcher_spend).map_err(|error| {
        DigStoreError::Proof(format!("hydrate launcher of {store_id}: {error}"))
    })?;

    // The hydrated launcher MUST actually be the store we were asked about — otherwise a source that
    // returned another store's launcher spend would silently answer for the wrong store (NC-9).
    if current.info.launcher_id != store_id {
        return Err(DigStoreError::Proof(format!(
            "launcher mismatch: coin_spend({store_id}) hydrated store {}, not the requested store",
            current.info.launcher_id
        )));
    }

    let mut roots = Vec::new();
    loop {
        if roots.len() >= max_generations {
            return Err(DigStoreError::Proof(format!(
                "store {store_id} lineage exceeds the {max_generations}-generation cap; \
                 refusing to follow further (possible hostile chain source)"
            )));
        }
        roots.push(current.info.metadata.root_hash);

        match read_verified_spend(chain, current.coin.coin_id())? {
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

/// Reads the spend that spent `coin_id` and PROVES the returned spend actually spent that coin.
///
/// `ChainSource::coin_spend(coin_id)` is contracted to return the spend of `coin_id`, but a hostile or
/// buggy source could return an unrelated spend. This asserts `spend.coin.coin_id() == coin_id` so the
/// lineage walk can never be steered onto a different coin/store (NC-9). The source's own read error
/// is mapped into [`DigStoreError::Proof`] so the crate's surface never leaks the generic
/// `ChainSource::Error` type parameter.
fn read_verified_spend<C: ChainSource>(
    chain: &C,
    coin_id: Bytes32,
) -> DigStoreResult<Option<crate::types::CoinSpend>> {
    let spend = chain
        .coin_spend(coin_id)
        .map_err(|error| DigStoreError::Proof(format!("chain read for {coin_id}: {error}")))?;

    if let Some(spend) = &spend {
        let returned = spend.coin.coin_id();
        if returned != coin_id {
            return Err(DigStoreError::Proof(format!(
                "chain source returned a spend for coin {returned} when asked for {coin_id}"
            )));
        }
    }
    Ok(spend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{create_store, modify_store, CreateStoreParams, StoreOwner};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::test::Simulator;
    use dig_chainsource_interface::MockChainSource;

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

    /// The spend of `coin_id` within a set of built coin spends.
    fn spend_of(
        coin_spends: &[crate::types::CoinSpend],
        coin_id: Bytes32,
    ) -> crate::types::CoinSpend {
        coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == coin_id)
            .expect("spend present")
            .clone()
    }

    /// Builds a real TWO-generation store (mint → one modify) on the simulator and returns its
    /// `store_id` plus a chain source loaded with the launcher + modify spends.
    fn two_generation_store() -> anyhow::Result<(Bytes32, MockChainSource)> {
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let mint = create_store(
            owner.coin,
            StoreOwner::Standard(owner.pk),
            owner_ph,
            CreateStoreParams {
                root_hash: id(0x5a),
                size: SizeBucket::from_exponent(0).unwrap(),
                label: None,
                description: None,
                program_hash: None,
                fee: 0,
            },
        )?;
        sim.spend_coins(mint.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let eve = mint.child.clone().expect("mint yields a child");
        let store_id = eve.info.launcher_id;

        let modified = modify_store(&eve, StoreOwner::Standard(owner.pk), id(0x77))?;
        sim.spend_coins(
            modified.coin_spends.clone(),
            std::slice::from_ref(&owner.sk),
        )?;

        let chain = MockChainSource::new()
            .with_spend(store_id, spend_of(&mint.coin_spends, store_id))
            .with_spend(
                eve.coin.coin_id(),
                spend_of(&modified.coin_spends, eve.coin.coin_id()),
            );
        Ok((store_id, chain))
    }

    /// A generous cap follows the whole two-generation lineage: both roots, live tip.
    #[test]
    fn bounded_walk_follows_lineage_under_the_cap() -> anyhow::Result<()> {
        let (store_id, chain) = two_generation_store()?;
        let lineage = walk_lineage_bounded(&chain, store_id, 10)?;
        assert_eq!(lineage.roots, vec![id(0x5a), id(0x77)]);
        assert!(lineage.tip.is_some());
        Ok(())
    }

    /// A cap below the real generation count fails closed — the walk refuses to follow a lineage past
    /// the cap (the guard against a hostile endless-recreation chain source). Non-vacuous: the SAME
    /// lineage succeeds above the cap (see `bounded_walk_follows_lineage_under_the_cap`).
    #[test]
    fn bounded_walk_rejects_lineage_over_the_cap() -> anyhow::Result<()> {
        let (store_id, chain) = two_generation_store()?;
        assert!(
            matches!(
                walk_lineage_bounded(&chain, store_id, 1),
                Err(DigStoreError::Proof(_))
            ),
            "a lineage longer than the cap must fail closed"
        );
        Ok(())
    }
}
