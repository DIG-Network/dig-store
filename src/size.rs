//! The store SIZE and the SIZE PROOF (SPEC §4) — the download-gating core of this crate.
//!
//! A store anchors its `.dig` SIZE on chain so a client can decide, BEFORE downloading, whether the
//! artifact is worth fetching. The anchored size is a coarse **power-of-2 bucket**, not an exact byte
//! count — the smallest representation that still conveys magnitude (NC-8, minimal on-chain
//! encoding): a single exponent `k ∈ 0..=10` mapping to `2^k MB`, 1 MB..1 GB.
//!
//! [`SizeBucket`] is re-exported VERBATIM from [`dig_merkle::SizeBucket`] — the ONE canonical owner
//! of the ladder AND the byte→bucket mapping ([`SizeBucket::for_byte_len`]) — so the encoding lives
//! in a single place and the on-chain (`dig-merkle` metadata `"sz"`) and client-side (this proof)
//! views can never drift.
//!
//! The SIZE PROOF is the client-side check: given the bucket the store anchored on chain (NC-9) and
//! the real byte length of a downloaded `.dig`, [`SizeProof::verify`] decides ACCEPT or DISCARD. A
//! `.dig` whose real size does not fall in the anchored bucket is rejected — a dig-node MUST NOT
//! store or serve it (SPEC §4, the discard rule).

pub use dig_merkle::SizeBucket;

use crate::error::{DigStoreError, DigStoreResult};

/// The largest bucket exponent (`k = 10`, i.e. 1 GB). A byte length above the ceiling has no bucket;
/// the discard diagnostics report `MAX_EXPONENT + 1` in that case to stay well-formed.
const MAX_EXPONENT: u8 = 10;

/// The verdict of a [`SizeProof::verify`] check: whether a downloaded `.dig` may be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeVerdict {
    /// The `.dig`'s real size falls in the store's on-chain-anchored bucket — keep it.
    Accept,
    /// The `.dig`'s real size does NOT match the anchored bucket — a dig-node MUST discard it.
    Discard,
}

/// The client-side SIZE PROOF check (SPEC §4).
///
/// A `.dig`'s real size is trusted ONLY when it matches the size the store anchored on chain. The
/// anchored bucket is obtained via an on-chain read (NC-9, `dig-merkle`); the real byte length is
/// measured from the downloaded artifact.
pub struct SizeProof;

impl SizeProof {
    /// Decides whether a downloaded `.dig` of `actual_bytes` bytes may be kept, given the
    /// `anchored` bucket the store recorded on chain.
    ///
    /// The `.dig` is ACCEPTED iff its real byte length falls into the SAME bucket the store anchored
    /// (`SizeBucket::for_byte_len(actual_bytes) == anchored`). Any other size — larger OR smaller —
    /// yields [`SizeVerdict::Discard`]: a wrong-size artifact is never what the store committed to,
    /// so it must not be cached or served.
    ///
    /// A byte length above the 1 GiB ceiling has no bucket and therefore can never match; it is
    /// discarded rather than erroring, since a caller checking untrusted downloaded bytes wants a
    /// verdict, not a failure.
    pub fn verify(anchored: SizeBucket, actual_bytes: u64) -> SizeVerdict {
        match SizeBucket::for_byte_len(actual_bytes) {
            Ok(actual) if actual == anchored => SizeVerdict::Accept,
            _ => SizeVerdict::Discard,
        }
    }

    /// Like [`verify`](Self::verify) but returns an error carrying the mismatch detail instead of a
    /// verdict — convenient when a caller wants `?`-propagation on the discard path.
    ///
    /// # Errors
    ///
    /// Returns [`DigStoreError::SizeProofMismatch`] when the `.dig` would be discarded.
    pub fn require(anchored: SizeBucket, actual_bytes: u64) -> DigStoreResult<()> {
        match Self::verify(anchored, actual_bytes) {
            SizeVerdict::Accept => Ok(()),
            SizeVerdict::Discard => {
                // Report the observed bucket where one exists; a byte length over the ceiling has no
                // bucket, so report `MAX_EXPONENT + 1` to keep the message well-formed.
                let actual_k = SizeBucket::for_byte_len(actual_bytes)
                    .map(|bucket| bucket.exponent())
                    .unwrap_or(MAX_EXPONENT + 1);
                Err(DigStoreError::SizeProofMismatch {
                    anchored_k: anchored.exponent(),
                    actual_k,
                    actual_bytes,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    /// A `.dig` whose real size lands in the anchored bucket is accepted.
    #[test]
    fn size_proof_accepts_matching_bucket() {
        let anchored = SizeBucket::from_exponent(7).unwrap(); // 128 MB
                                                              // Any byte length in (64 MiB, 128 MiB] maps to bucket 7.
        assert_eq!(SizeProof::verify(anchored, 100 * MIB), SizeVerdict::Accept);
        assert_eq!(SizeProof::verify(anchored, 128 * MIB), SizeVerdict::Accept);
    }

    /// A `.dig` that is too LARGE for the anchored bucket is discarded.
    #[test]
    fn size_proof_discards_oversize() {
        let anchored = SizeBucket::from_exponent(7).unwrap(); // 128 MB
        assert_eq!(
            SizeProof::verify(anchored, 128 * MIB + 1),
            SizeVerdict::Discard
        );
    }

    /// A `.dig` that is too SMALL for the anchored bucket is also discarded — a store commits to an
    /// exact bucket, not a maximum.
    #[test]
    fn size_proof_discards_undersize() {
        let anchored = SizeBucket::from_exponent(7).unwrap(); // 128 MB, i.e. (64 MiB, 128 MiB]
        assert_eq!(SizeProof::verify(anchored, 64 * MIB), SizeVerdict::Discard);
    }

    /// A `.dig` larger than the whole ladder can never match and is discarded, not errored.
    #[test]
    fn size_proof_discards_over_ceiling() {
        let anchored = SizeBucket::from_exponent(10).unwrap();
        assert_eq!(SizeProof::verify(anchored, GIB + 1), SizeVerdict::Discard);
    }

    /// `require` surfaces the discard as a structured error carrying the anchored + observed buckets.
    #[test]
    fn require_reports_mismatch_detail() {
        let anchored = SizeBucket::from_exponent(7).unwrap();
        let err = SizeProof::require(anchored, 64 * MIB).unwrap_err();
        match err {
            DigStoreError::SizeProofMismatch {
                anchored_k,
                actual_k,
                actual_bytes,
            } => {
                assert_eq!(anchored_k, 7);
                assert_eq!(actual_k, 6); // 64 MiB fits bucket 6
                assert_eq!(actual_bytes, 64 * MIB);
            }
            other => panic!("expected SizeProofMismatch, got {other:?}"),
        }
    }

    /// The over-ceiling discard path reports `MAX_EXPONENT + 1` as the observed bucket (no real
    /// bucket exists) rather than erroring on the lookup.
    #[test]
    fn require_over_ceiling_reports_synthetic_bucket() {
        let anchored = SizeBucket::from_exponent(10).unwrap();
        let err = SizeProof::require(anchored, GIB + 1).unwrap_err();
        match err {
            DigStoreError::SizeProofMismatch { actual_k, .. } => assert_eq!(actual_k, 11),
            other => panic!("expected SizeProofMismatch, got {other:?}"),
        }
    }

    /// The accept path of `require` is a plain `Ok`.
    #[test]
    fn require_accepts_matching() {
        let anchored = SizeBucket::from_exponent(7).unwrap();
        assert!(SizeProof::require(anchored, 100 * MIB).is_ok());
    }

    /// The re-exported ladder is the canonical `dig_merkle::SizeBucket`: `k = 10` is a full 1 GB and
    /// `byte_len()` is `2^(k+20)`, so the on-chain and client-side size views cannot drift.
    #[test]
    fn re_exported_ladder_is_canonical() {
        assert_eq!(SizeBucket::from_exponent(10).unwrap().megabytes(), 1024);
        assert_eq!(SizeBucket::from_exponent(10).unwrap().byte_len(), GIB);
        assert_eq!(SizeBucket::for_byte_len(MIB).unwrap().exponent(), 0);
        assert_eq!(SizeBucket::for_byte_len(MIB + 1).unwrap().exponent(), 1);
    }
}
