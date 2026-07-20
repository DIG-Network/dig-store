//! The `dig-store` error taxonomy (SPEC §6).
//!
//! Every fallible operation returns [`DigStoreResult`]. The variants are deliberately coarse and
//! stable — a consumer matches on the kind, not on a message string — and each carries a
//! human-readable detail for logs. New variants are added additively; existing ones never change
//! meaning (CLAUDE.md §5.1 back-compat discipline applies to the public error surface too).

use thiserror::Error;

/// The result type every `dig-store` operation returns.
pub type DigStoreResult<T> = Result<T, DigStoreError>;

/// Everything that can go wrong composing, spending, or reading a DIG store.
#[derive(Debug, Error)]
pub enum DigStoreError {
    /// A size value is outside the valid ladder (`k ∈ 0..=10`, i.e. 1 MB..1 GB) — see
    /// [`crate::SizeBucket`]. Mirrors `dig_merkle::MerkleError::InvalidSize`.
    #[error("invalid store size: {0}")]
    InvalidSize(String),

    /// A downloaded `.dig`'s real size does not match the size the store anchored on chain, so it
    /// MUST be discarded rather than stored or served (SPEC §4, NC-9). Carries the anchored bucket
    /// and the observed byte length for diagnostics.
    #[error("size-proof mismatch: .dig is {actual_bytes} bytes (bucket {actual_k}) but the store anchored bucket {anchored_k}; discarding")]
    SizeProofMismatch {
        /// The power-of-2 exponent the store anchored on chain.
        anchored_k: u8,
        /// The power-of-2 exponent the downloaded `.dig`'s real byte length falls into.
        actual_k: u8,
        /// The downloaded `.dig`'s real byte length.
        actual_bytes: u64,
    },

    /// A URN string could not be parsed or a store id / root hash was malformed.
    #[error("invalid URN or identifier: {0}")]
    InvalidUrn(String),

    /// An on-chain read could not prove the store's integrity/validity against the chain (NC-9):
    /// the coin was absent, the lineage did not verify, or the chain source failed.
    #[error("on-chain proof failed: {0}")]
    Proof(String),

    /// The underlying `.dig` capsule (`dig-capsule`) could not be opened, parsed, or read.
    #[error("capsule error: {0}")]
    Capsule(String),

    /// A spend could not be constructed by the on-chain anchor (`dig-merkle`).
    #[error("spend-build error: {0}")]
    Spend(String),
}
