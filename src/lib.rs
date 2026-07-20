//! # dig-store — the DIG Network DataLayer store manager
//!
//! A **store** is the composition of two planes:
//!
//! - an **on-chain anchor** — a CHIP-0035 DataLayer singleton (owned by
//!   [`dig-merkle`](https://github.com/DIG-Network/dig-merkle)) whose metadata carries the `.dig`
//!   merkle root plus its label / description / size bucket / program hash; and
//! - an **off-chain data plane** — the `.dig` capsule format (owned by
//!   [`dig-capsule`](https://github.com/DIG-Network/dig-capsule)).
//!
//! `dig-store` composes the two into ONE curated abstraction, with three concerns:
//!
//! 1. **Lifecycle** — a store is a coin that gets SPENT: [`create_store`], [`modify_store`],
//!    [`melt_store`]. Each returns an UNSIGNED [`MerkleCoinSpend`]; the wallet-backend / node signs +
//!    broadcasts. `dig-store` never holds a key, never signs, never dials the network.
//! 2. **Size proof** — a store anchors its `.dig` SIZE on chain as a power-of-2 [`SizeBucket`]
//!    (1 MB..1 GB, NC-8 minimal encoding). Before keeping a downloaded `.dig`, a client runs
//!    [`SizeProof::verify`]: a real size that does not match the anchored bucket is
//!    [`SizeVerdict::Discard`]ed — a dig-node MUST NOT store or serve a size-mismatched capsule.
//! 3. **Getters** — a comprehensive read surface over both planes:
//!    - **on-chain** (chain-proven, NC-9): [`get_store_did_owner`], [`get_store_singleton_tip`],
//!      [`get_root_history`], [`get_latest_root`], [`get_latest_root_urn`], [`get_store_urn`], and the
//!      label / description / size / program-hash getters;
//!    - **off-chain** (from a compiled `.dig` module's bytes, wasmtime-free): [`get_capsule_identity`]
//!      recovers a capsule's declared `(store_id, root_hash)`, and [`open_capsule`] additionally
//!      cross-checks the declared `store_id` against a trusted anchor (fail-closed).
//!
//! The coin/identity types ([`Bytes32`], [`Coin`], [`CoinSpend`], [`DataStore`], [`DidRef`],
//! [`DigDataStoreMetadata`], [`MerkleCoinSpend`]) and the owner type ([`StoreOwner`]) are re-exported
//! VERBATIM from `dig-merkle`, and [`ChainSource`] from `dig-chainsource-interface`, so a consumer
//! depends on ONE canonical shape across the whole DataLayer surface.
//!
//! ## Invariants
//!
//! - **INV-1 — No network.** `dig-store` performs no chain I/O itself; on-chain getters take a
//!   [`ChainSource`] the caller supplies (the user's verified node or a trusted provider set, NC-9),
//!   and lifecycle operations are pure transforms of their inputs.
//! - **INV-2 — No keys, unsigned output.** Lifecycle operations return unsigned spends; signing is
//!   always the caller's responsibility (inherited from `dig-merkle`).
//! - **INV-3 — Minimal on-chain encoding (NC-8).** The store's on-chain footprint is delegated
//!   wholesale to `dig-merkle`, which owns the minimal byte layout; the size is a single-byte bucket.
//! - **INV-4 — On-chain proof always (NC-9).** Every getter that returns chain-anchored data proves
//!   it against the chain; trust never comes from a self-declared field or an unverified peer.
//! - **INV-5 — `.dig` back-compat (§5.1).** The capsule surface reads every older `.dig` format
//!   identically (inherited from `dig-capsule`'s reader, which dispatches on the DIGS blob version); the
//!   public API is extended additively, never broken.
//!
//! ## The `store_id` trust boundary (off-chain capsule getters)
//!
//! [`get_capsule_identity`] recovers a capsule's DECLARED `store_id` from module bytes. That id is the
//! store's on-chain launcher id and is NOT self-verifiable from the bytes alone — treat it as a CLAIM
//! until cross-checked against a trusted anchor. [`open_capsule`] does that cross-check against a
//! caller-supplied anchor and fails closed on mismatch. The `root_hash` is always proven internally
//! consistent by the reader (it recomputes the merkle root and rejects a forged one).

// Public modules.
pub mod capsule;
pub mod chain;
pub mod error;
pub mod lifecycle;
pub mod size;
pub mod store;
pub mod types;
pub mod urn;

// The curated public surface — consumers depend on these paths, not the module layout.
pub use capsule::{get_capsule_identity, open_capsule};
pub use chain::ChainSource;
pub use error::{DigStoreError, DigStoreResult};
pub use lifecycle::{create_store, melt_store, modify_store, CreateStoreParams, StoreOwner};
pub use size::{SizeBucket, SizeProof, SizeVerdict};
pub use store::{
    get_latest_root, get_latest_root_urn, get_root_history, get_store_description,
    get_store_did_owner, get_store_label, get_store_program_hash, get_store_singleton_tip,
    get_store_size_bucket, get_store_urn,
};
pub use types::{
    Bytes32, CapsuleIdentity, Coin, CoinSpend, DataStore, DidRef, DigDataStoreMetadata,
    MerkleCoinSpend, RootHistory,
};
pub use urn::{capsule_urn, retrieval_key, store_urn, URN_PREFIX};
