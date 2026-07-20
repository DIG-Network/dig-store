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
//!    [`melt_store`]. Each returns an UNSIGNED [`StoreSpend`]; the wallet-backend / node signs +
//!    broadcasts. `dig-store` never holds a key, never signs, never dials the network.
//! 2. **Size proof** — a store anchors its `.dig` SIZE on chain as a power-of-2 [`SizeBucket`]
//!    (1 MB..1 GB, NC-8 minimal encoding). Before keeping a downloaded `.dig`, a client runs
//!    [`SizeProof::verify`]: a real size that does not match the anchored bucket is
//!    [`SizeVerdict::Discard`]ed — a dig-node MUST NOT store or serve a size-mismatched capsule.
//! 3. **Getters** — a comprehensive, chain-proven (NC-9) read surface over every on-chain and
//!    off-chain property ([`get_store_did_owner`], [`get_store_singleton_tip`], [`get_root_history`],
//!    [`get_latest_root`], [`get_latest_root_urn`], [`get_store_urn`], and the label / description /
//!    size / program-hash + capsule getters).
//!
//! ## Invariants
//!
//! - **INV-1 — No network.** `dig-store` performs no chain I/O itself; on-chain getters take a
//!   [`ChainSource`] the caller supplies (the user's verified node or a trusted provider set, NC-9).
//! - **INV-2 — No keys, unsigned output.** Lifecycle operations return unsigned spends; signing is
//!   always the caller's responsibility (inherited from `dig-merkle`).
//! - **INV-3 — Minimal on-chain encoding (NC-8).** The store's on-chain footprint is delegated
//!   wholesale to `dig-merkle`, which owns the minimal byte layout; the size is a single-byte bucket.
//! - **INV-4 — On-chain proof always (NC-9).** Every getter that returns chain-anchored data proves
//!   it against the chain; trust never comes from a self-declared field or an unverified peer.
//! - **INV-5 — `.dig` back-compat (§5.1).** The capsule surface reads every older `.dig` format
//!   identically; the public API is extended additively, never broken.
//!
//! ## Scaffold status (issue #1247)
//!
//! This is a DESIGN-FIRST scaffold. `dig-merkle 0.3.0` (the `size_bucket` line) and the single-crate
//! `dig-capsule` are not yet on crates.io, and the `no git deps` rule (CLAUDE.md §3.6) forbids
//! wiring them before they publish. So the composition surface (lifecycle + on-chain / off-chain
//! getters) is scaffolded with `todo!()` bodies whose SIGNATURES are final, while the PURE,
//! self-contained logic is fully implemented + tested now:
//!
//! - the [`size`] module — the [`SizeBucket`] ladder + the [`SizeProof`] discard check;
//! - the [`urn`] module — the `urn:dig:chia:…` store / capsule URN formatting + retrieval key;
//! - the [`error`] taxonomy and the [`types`] identifier surface.
//!
//! The compose pass adds the `dig-merkle` / `dig-capsule` / `chia-*` dependencies and fills the
//! `todo!()`s; see the repo `SPEC.md` §11 for the exact plan and the upstream APIs it consumes.

// Public modules.
pub mod chain;
pub mod error;
pub mod lifecycle;
pub mod size;
pub mod store;
pub mod types;
pub mod urn;

// The curated public surface — consumers depend on these paths, not the module layout.
pub use chain::{ChainSource, CoinSpendBytes};
pub use error::{DigStoreError, DigStoreResult};
pub use lifecycle::{
    create_store, melt_store, modify_store, resolve_owner, CreateStoreParams, StoreOwner,
    StoreSpend,
};
pub use size::{SizeBucket, SizeProof, SizeVerdict};
pub use store::{
    get_capsule_identity, get_latest_root, get_latest_root_urn, get_root_history,
    get_store_description, get_store_did_owner, get_store_label, get_store_program_hash,
    get_store_singleton_tip, get_store_size_bucket, get_store_urn, open_capsule, OpenCapsule,
};
pub use types::{Bytes32, DidRef, RootHistory, StoreTip};
pub use urn::{capsule_urn, retrieval_key, store_urn, URN_PREFIX};
