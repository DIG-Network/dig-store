//! The store LIFECYCLE (SPEC §3): a store is a coin that gets SPENT.
//!
//! A DIG store is a CHIP-0035 DataLayer singleton. Three operations span its life, each a spend of
//! that coin, composed directly over `dig-merkle` (the byte-source-of-truth for every DataLayer
//! spend, INV-4):
//!
//! - [`create_store`] — launch the store coin from a funding parent, anchoring the first root + its
//!   size bucket + optional metadata (→ [`dig_merkle::mint_datastore_with_kind`]).
//! - [`modify_store`] — spend the tip coin to recreate the store with a NEW root, preserving the rest
//!   of the anchored metadata (→ [`dig_merkle::update_root`]).
//! - [`melt_store`] — terminally spend the coin, closing the store with no successor
//!   (→ [`dig_merkle::melt`]).
//!
//! Every operation returns an UNSIGNED [`MerkleCoinSpend`] (inherited boundary INV-2/INV-3 from
//! `dig-merkle`): `dig-store` never holds a key, never signs, never broadcasts. The wallet-backend /
//! node feeds the reported spends to `dig_merkle::required_signatures`, signs, assembles the
//! `SpendBundle`, and submits it. The on-chain encoding is minimal (NC-8) — delegated wholesale to
//! `dig-merkle`, which owns the byte layout.
//!
//! `modify_store` / `melt_store` take the already-hydrated tip [`DataStore`] (from
//! [`crate::get_store_singleton_tip`], which does the single chain read) rather than a chain source,
//! so these builders stay pure transforms of their inputs (INV-1).

use dig_merkle::{melt, mint_datastore_with_kind, update_root, StoreKind};

use crate::error::DigStoreResult;
use crate::size::SizeBucket;
use crate::types::{Bytes32, Coin, DataStore, DigDataStoreMetadata, MerkleCoinSpend};

/// Who is authorized to spend a store coin — the p2 ("inner") puzzle that guards it.
///
/// Re-exported verbatim from [`dig_merkle::Owner`] so a caller uses ONE owner type across the whole
/// DataLayer surface: [`StoreOwner::Standard`] is the common single-key case (dig-merkle builds the
/// standard layer; the spend requires one `AGG_SIG_ME` over the key), and [`StoreOwner::Custom`] is
/// the escape hatch for a pre-built inner spend (a DID-authorized delegated puzzle, a multisig, a
/// vault).
pub use dig_merkle::Owner as StoreOwner;

/// The parameters that describe a store's on-chain metadata at creation (SPEC §3.1).
///
/// `root_hash` and `size` are required — every store anchors its size so the SIZE PROOF (SPEC §4) can
/// gate downloads. Every other field is optional and omitted-when-absent on chain (NC-8).
#[derive(Debug, Clone)]
pub struct CreateStoreParams {
    /// The first anchored merkle root (the `.dig` root of generation 0).
    pub root_hash: Bytes32,
    /// The store's size, anchored as a power-of-2 bucket so clients can gate downloads (SPEC §4).
    pub size: SizeBucket,
    /// An optional human label (`dig-merkle` metadata `"l"`).
    pub label: Option<String>,
    /// An optional human description (`dig-merkle` metadata `"d"`).
    pub description: Option<String>,
    /// An optional CLVM tree-hash of a program/puzzle associated with the store (`dig-merkle` `"p"`).
    pub program_hash: Option<Bytes32>,
    /// The reserve fee (mojos) to attach to the launch spend.
    pub fee: u64,
}

/// Launches a new store coin from a funding parent, anchoring the first root (SPEC §3.1).
///
/// `parent_coin` funds + parents the launcher, so `launcher_id == store_id` derives from its
/// `coin_id`. `owner` authorizes the parent spend; `owner_puzzle_hash` is the store owner recorded in
/// the singleton (and the target of the owner-discovery hint + any change). `params` carries the
/// first root, the required size bucket, and optional metadata. The store is minted with the file
/// launcher discriminator ([`StoreKind::File`]), byte-identical to existing on-chain DIG stores.
///
/// To root a store in a DID, pass the DID-authorized coin as `parent_coin` with a
/// [`StoreOwner::Custom`] inner spend satisfying the DID puzzle — owner discovery
/// ([`crate::get_store_did_owner`]) then resolves the DID via `dig-merkle`. Returns the UNSIGNED
/// launch spend.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the spend cannot be constructed (invalid metadata / size /
/// fee overflow).
pub fn create_store(
    parent_coin: Coin,
    owner: StoreOwner,
    owner_puzzle_hash: Bytes32,
    params: CreateStoreParams,
) -> DigStoreResult<MerkleCoinSpend> {
    Ok(mint_datastore_with_kind(
        StoreKind::File,
        parent_coin,
        owner,
        params.root_hash,
        params.label,
        params.description,
        None, // size_proof: superseded by the size bucket (NC-8), never emitted by dig-store.
        params.program_hash,
        Some(params.size),
        owner_puzzle_hash,
        Vec::new(), // delegated puzzles: added additively in a later unit (SPEC §3).
        params.fee,
    )?)
}

/// Spends the store's tip coin to recreate it anchoring `new_root` — a new generation (SPEC §3.2).
///
/// `store` is the current confirmed tip (from [`crate::get_store_singleton_tip`]); the spend consumes
/// it and recreates the singleton with `new_root`, PRESERVING every other anchored metadata field
/// (label, description, size bucket, program hash) and the store identity (`store_id`, owner,
/// delegation set). Returns the UNSIGNED spend.
///
/// Note: attaching a reserve fee to a modify spend is a `dig-merkle` future unit (its `fee` module is
/// a documented stub); this builder recreates the coin at its current amount.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the spend cannot be constructed.
pub fn modify_store(
    store: &DataStore<DigDataStoreMetadata>,
    owner: StoreOwner,
    new_root: Bytes32,
) -> DigStoreResult<MerkleCoinSpend> {
    let new_metadata = DigDataStoreMetadata {
        root_hash: new_root,
        ..store.info.metadata.clone()
    };
    Ok(update_root(store, owner, new_metadata)?)
}

/// Terminally spends (melts) the store's tip coin, leaving no successor (SPEC §3.3).
///
/// Closes the store: the singleton is spent with no recreation, so no future generation can be
/// anchored. `store` is the current tip (from [`crate::get_store_singleton_tip`]). Returns the
/// UNSIGNED melt spend.
///
/// # Errors
///
/// Returns a [`DigStoreResult`] error if the spend cannot be constructed.
pub fn melt_store(
    store: &DataStore<DigDataStoreMetadata>,
    owner: StoreOwner,
) -> DigStoreResult<MerkleCoinSpend> {
    Ok(melt(store, owner)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::test::Simulator;

    /// Mints a store on the simulator and returns the owner keypair + the settled eve DataStore, so
    /// lifecycle tests start from a real on-chain store.
    fn minted_store(
        sim: &mut Simulator,
        size: SizeBucket,
    ) -> anyhow::Result<(
        chia_wallet_sdk::test::BlsPairWithCoin,
        DataStore<DigDataStoreMetadata>,
    )> {
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let built = create_store(
            owner.coin,
            StoreOwner::Standard(owner.pk),
            owner_ph,
            CreateStoreParams {
                root_hash: Bytes32::new([0x5a; 32]),
                size,
                label: Some("docs".into()),
                description: None,
                program_hash: None,
                fee: 0,
            },
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok((owner, built.child.expect("mint yields a child")))
    }

    /// create_store anchors the first root + size bucket and validates on the simulator; the eve
    /// store hydrates back with both preserved.
    #[test]
    fn create_store_anchors_root_and_size() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let size = SizeBucket::from_exponent(7).unwrap();
        let (_owner, store) = minted_store(&mut sim, size)?;

        assert_eq!(store.info.metadata.root_hash, Bytes32::new([0x5a; 32]));
        assert_eq!(store.info.metadata.size_bucket, Some(size));
        assert_eq!(store.info.metadata.label, Some("docs".into()));
        Ok(())
    }

    /// modify_store recreates the store with a NEW root, PRESERVES the anchored size bucket + label
    /// (wholesale-replacement carry-forward), keeps the store id, and validates on the simulator.
    #[test]
    fn modify_store_updates_root_and_preserves_metadata() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let size = SizeBucket::from_exponent(5).unwrap();
        let (owner, store) = minted_store(&mut sim, size)?;

        let new_root = Bytes32::new([0x77; 32]);
        let built = modify_store(&store, StoreOwner::Standard(owner.pk), new_root)?;
        let child = built.child.clone().expect("modify yields a child");

        assert_eq!(child.info.metadata.root_hash, new_root);
        assert_eq!(
            child.info.metadata.size_bucket,
            Some(size),
            "the anchored size bucket is preserved across a modify"
        );
        assert_eq!(child.info.metadata.label, Some("docs".into()));
        assert_eq!(child.info.launcher_id, store.info.launcher_id);

        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// melt_store yields no successor and the melt validates on the simulator: the store is closed.
    #[test]
    fn melt_store_closes_the_store() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let size = SizeBucket::from_exponent(3).unwrap();
        let (owner, store) = minted_store(&mut sim, size)?;

        let built = melt_store(&store, StoreOwner::Standard(owner.pk))?;
        assert!(built.child.is_none(), "a melt leaves no successor");

        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        Ok(())
    }

    /// The unsigned create spend requires exactly one `AGG_SIG_ME` over the owner's key — the custody
    /// contract inherited from dig-merkle (a compromised dig-store cannot move funds, INV-2).
    #[test]
    fn create_store_requires_a_single_owner_signature() -> anyhow::Result<()> {
        use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
        use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};

        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let built = create_store(
            owner.coin,
            StoreOwner::Standard(owner.pk),
            owner_ph,
            CreateStoreParams {
                root_hash: Bytes32::new([0x01; 32]),
                size: SizeBucket::from_exponent(0).unwrap(),
                label: None,
                description: None,
                program_hash: None,
                fee: 0,
            },
        )?;

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = dig_merkle::required_signatures(&built.coin_spends, &constants)?;
        assert_eq!(required.len(), 1, "one AGG_SIG_ME expected");
        match &required[0] {
            RequiredSignature::Bls(bls) => assert_eq!(bls.public_key, owner.pk),
            RequiredSignature::Secp(_) => panic!("standard owner uses a BLS key"),
        }
        Ok(())
    }
}
