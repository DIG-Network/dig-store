//! On-chain getter integration tests (SPEC §5/§7): build a real store lineage on the CHIP-0035
//! simulator, load its coin spends into an in-memory [`MockChainSource`], and exercise the shared
//! lineage walk — tip, ordered root history, metadata, owner discovery, melt, and the fail-closed
//! paths. Never broadcasts: the simulator validates every spend locally.

use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::test::Simulator;
use dig_chainsource_interface::{ChainSourceError, MockChainSource};
use dig_store::{
    capsule_urn, create_store, get_latest_root, get_latest_root_urn, get_root_history,
    get_store_description, get_store_did_owner, get_store_label, get_store_program_hash,
    get_store_singleton_tip, get_store_size_bucket, melt_store, modify_store, Bytes32, CoinSpend,
    CreateStoreParams, DataStore, DigDataStoreMetadata, MerkleCoinSpend, SizeBucket, StoreOwner,
};

/// The `CoinSpend` in `built` that spent the coin with id `coin_id`.
fn spend_of(built: &MerkleCoinSpend, coin_id: Bytes32) -> CoinSpend {
    built
        .coin_spends
        .iter()
        .find(|s| s.coin.coin_id() == coin_id)
        .expect("spend present")
        .clone()
}

/// Mints a store (root `0x5a`, label "docs", the given size) on `sim`, settles it, and returns the
/// owner keypair, the eve DataStore, and the launcher/owner spends needed to seed a chain source.
fn minted(
    sim: &mut Simulator,
    size: SizeBucket,
) -> anyhow::Result<(
    chia_wallet_sdk::test::BlsPairWithCoin,
    DataStore<DigDataStoreMetadata>,
    MerkleCoinSpend,
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
    let eve = built.child.clone().expect("mint yields a child");
    Ok((owner, eve, built))
}

/// A two-generation store (mint → modify) reports both roots in order, the tip carries the latest
/// root + preserved metadata, and the latest-root URN pins the newest generation.
#[test]
fn walk_reports_ordered_history_tip_and_metadata() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let size = SizeBucket::from_exponent(7).unwrap();
    let (owner, eve, mint) = minted(&mut sim, size)?;
    let store_id = eve.info.launcher_id;

    let new_root = Bytes32::new([0x77; 32]);
    let modified = modify_store(&eve, StoreOwner::Standard(owner.pk), new_root)?;
    sim.spend_coins(
        modified.coin_spends.clone(),
        std::slice::from_ref(&owner.sk),
    )?;

    let chain = MockChainSource::new()
        .with_spend(store_id, spend_of(&mint, store_id))
        .with_spend(eve.coin.coin_id(), spend_of(&modified, eve.coin.coin_id()));

    // Ordered root history: generation 0 then generation 1.
    let history = get_root_history(&chain, store_id)?;
    assert_eq!(history.roots, vec![Bytes32::new([0x5a; 32]), new_root]);
    assert_eq!(history.generation_count(), 2);
    assert_eq!(history.latest(), Some(new_root));

    // Tip + latest root.
    let tip = get_store_singleton_tip(&chain, store_id)?;
    assert_eq!(tip.info.metadata.root_hash, new_root);
    assert_eq!(get_latest_root(&chain, store_id)?, new_root);

    // Metadata read off the tip: size bucket + label are preserved across the modify.
    assert_eq!(get_store_size_bucket(&chain, store_id)?, Some(size));
    assert_eq!(get_store_label(&chain, store_id)?, Some("docs".into()));
    assert_eq!(get_store_description(&chain, store_id)?, None);
    assert_eq!(get_store_program_hash(&chain, store_id)?, None);

    // The latest-root URN pins the newest generation.
    assert_eq!(
        get_latest_root_urn(&chain, store_id)?,
        capsule_urn(store_id, new_root)
    );
    Ok(())
}

/// A freshly minted, never-updated store: the eve coin is the live tip and history is one root.
#[test]
fn walk_of_single_generation_store() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let (_owner, eve, mint) = minted(&mut sim, SizeBucket::from_exponent(0).unwrap())?;
    let store_id = eve.info.launcher_id;

    let chain = MockChainSource::new().with_spend(store_id, spend_of(&mint, store_id));

    assert_eq!(
        get_root_history(&chain, store_id)?.roots,
        vec![Bytes32::new([0x5a; 32])]
    );
    assert_eq!(
        get_store_singleton_tip(&chain, store_id)?.coin.coin_id(),
        eve.coin.coin_id()
    );
    Ok(())
}

/// A melted store has no live tip (the tip getter fails closed) but still reports the roots it
/// anchored while live.
#[test]
fn melted_store_has_no_tip_but_keeps_history() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let (owner, eve, mint) = minted(&mut sim, SizeBucket::from_exponent(2).unwrap())?;
    let store_id = eve.info.launcher_id;

    let melted = melt_store(&eve, StoreOwner::Standard(owner.pk))?;
    sim.spend_coins(melted.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;

    let chain = MockChainSource::new()
        .with_spend(store_id, spend_of(&mint, store_id))
        .with_spend(eve.coin.coin_id(), spend_of(&melted, eve.coin.coin_id()));

    assert_eq!(
        get_root_history(&chain, store_id)?.roots,
        vec![Bytes32::new([0x5a; 32])]
    );
    assert!(
        get_store_singleton_tip(&chain, store_id).is_err(),
        "a melted store exposes no live tip"
    );
    Ok(())
}

/// A plainly-minted (non-DID) store resolves to no owning DID — fail-closed to `None`, never an
/// error. The walk reads the launcher spend and its creator (the owner coin's standard spend).
#[test]
fn plain_store_has_no_owning_did() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let (owner, eve, mint) = minted(&mut sim, SizeBucket::from_exponent(1).unwrap())?;
    let store_id = eve.info.launcher_id;

    let launcher_spend = spend_of(&mint, store_id);
    let creator_id = launcher_spend.coin.parent_coin_info;

    let chain = MockChainSource::new()
        .with_spend(store_id, launcher_spend)
        .with_spend(creator_id, spend_of(&mint, owner.coin.coin_id()));

    assert_eq!(get_store_did_owner(&chain, store_id)?, None);
    Ok(())
}

/// An unknown store id fails closed: the launcher spend is absent, so the walk errors rather than
/// fabricating a tip.
#[test]
fn absent_store_fails_closed() {
    let chain = MockChainSource::new();
    assert!(get_store_singleton_tip(&chain, Bytes32::new([0xee; 32])).is_err());
    assert!(get_root_history(&chain, Bytes32::new([0xee; 32])).is_err());
}

/// A chain-source read error surfaces as an error (never degraded to an absence): the getters fail
/// closed on an unreliable source (NC-9).
#[test]
fn chain_read_error_fails_closed() {
    let chain = MockChainSource::new().fail_with(ChainSourceError::Timeout);
    assert!(get_store_singleton_tip(&chain, Bytes32::new([0x01; 32])).is_err());
    assert!(get_store_did_owner(&chain, Bytes32::new([0x01; 32])).is_err());
}
