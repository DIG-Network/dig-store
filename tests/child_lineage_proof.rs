//! Regression test for the `child_lineage_proof` consensus fix (dig-merkle #1332), proven at
//! `dig-store`'s OWN re-exported surface.
//!
//! `dig-store` re-exposes [`dig_store::child_lineage_proof`] as its lineage-getter surface: given a
//! hydrated store, it derives the [`dig_store::LineageProof`] a child singleton spend must carry to
//! be recreated. Before the fix, that proof's `parent_inner_puzzle_hash` was derived via the SDK's
//! NFT-default metadata-updater path, so it did NOT match a real on-chain DataLayer coin and a child
//! spend built against it was consensus-rejected (`AssertMyParentIdFailed`). dig-merkle 0.4.3 derives
//! it via the DataLayer updater path; this test proves the corrected behavior flows through
//! `dig-store` and guards against a future dig-merkle downgrade.
//!
//! Simulator-first: every spend is validated locally by the in-process CHIP-0035 simulator and is
//! NEVER broadcast.
//!
//! Scope — the EMPTY-delegation case only: `dig-store`'s [`dig_store::create_store`] surface mints a
//! store with NO delegated puzzles (delegated minting is a deferred `dig-store` unit, SPEC §3), so a
//! delegated store is not producible through `dig-store`'s surface. The delegated branch of
//! `child_lineage_proof` is covered by dig-merkle's own suite.

use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::test::{BlsPairWithCoin, Simulator};

use dig_store::{
    child_lineage_proof, create_store, modify_store, Bytes32, CreateStoreParams, DataStore,
    DigDataStoreMetadata, Proof, SizeBucket, StoreOwner,
};

/// Mints a store on the simulator through `dig-store`'s `create_store` surface and settles the eve
/// store on chain, so the test starts from a real DataLayer coin.
fn minted_store(
    sim: &mut Simulator,
) -> anyhow::Result<(BlsPairWithCoin, DataStore<DigDataStoreMetadata>)> {
    let owner = sim.bls(1_000_000);
    let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
    let built = create_store(
        owner.coin,
        StoreOwner::Standard(owner.pk),
        owner_ph,
        CreateStoreParams {
            root_hash: Bytes32::new([0x5a; 32]),
            size: SizeBucket::from_exponent(7).unwrap(),
            label: Some("docs".into()),
            description: None,
            program_hash: None,
            fee: 0,
        },
    )?;
    sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
    Ok((owner, built.child.expect("mint yields a child (eve store)")))
}

/// GROUND TRUTH (#1332): the proof [`child_lineage_proof`] derives for a child of `store1` must equal
/// the proof the SDK sets by PARSING `store1`'s real on-chain puzzle when it hydrates the child of a
/// `modify_store` spend. A mismatched `parent_inner_puzzle_hash` is exactly the pre-fix defect.
#[test]
fn dig_store_child_lineage_proof_matches_the_parsed_on_chain_proof() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let (owner, store1) = minted_store(&mut sim)?;

    let standalone = child_lineage_proof(&store1)?;

    // The parsed byte-source-of-truth: a modify recreates store1; the child's proof is set by
    // parsing store1's actual singleton layer.
    let built2 = modify_store(
        &store1,
        StoreOwner::Standard(owner.pk),
        Bytes32::new([0x77; 32]),
    )?;
    let store2 = built2.child.clone().expect("modify yields a child");
    let parsed = match store2.proof {
        Proof::Lineage(lp) => lp,
        Proof::Eve(_) => panic!("store2 is not an eve coin"),
    };

    assert_eq!(
        standalone.parent_inner_puzzle_hash, parsed.parent_inner_puzzle_hash,
        "dig-store child_lineage_proof's parent_inner_puzzle_hash must equal the parsed on-chain value"
    );
    assert_eq!(
        standalone.parent_parent_coin_info,
        parsed.parent_parent_coin_info
    );
    assert_eq!(standalone.parent_amount, parsed.parent_amount);
    Ok(())
}

/// GROUND TRUTH (#1332), consensus edition: a child spend whose lineage proof is supplied SOLELY by
/// [`child_lineage_proof`] — the exact path a lineage-walker takes to build the next spend against a
/// store returned by the walk — must be accepted by the simulator. If the derived
/// `parent_inner_puzzle_hash` were wrong, singleton consensus would reject it with
/// `AssertMyParentIdFailed`.
#[test]
fn dig_store_child_lineage_proof_produces_a_consensus_valid_child_spend() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let (owner, store1) = minted_store(&mut sim)?;

    // Put store2 on chain so it is a spendable coin (store2's parent is store1).
    let built2 = modify_store(
        &store1,
        StoreOwner::Standard(owner.pk),
        Bytes32::new([0x77; 32]),
    )?;
    sim.spend_coins(built2.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
    let store2 = built2.child.expect("modify yields a child");

    // Reconstruct store2 with its proof supplied SOLELY by child_lineage_proof(store1) — never the
    // parsed proof — so the spend below stands or falls on the derived proof alone.
    let store2_via_clp = DataStore::new(
        store2.coin,
        Proof::Lineage(child_lineage_proof(&store1)?),
        store2.info.clone(),
    );

    // Spend store2 using ONLY the child_lineage_proof-derived proof; the simulator enforces real
    // singleton consensus.
    let built3 = modify_store(
        &store2_via_clp,
        StoreOwner::Standard(owner.pk),
        Bytes32::new([0x88; 32]),
    )?;
    sim.spend_coins(built3.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
    Ok(())
}
