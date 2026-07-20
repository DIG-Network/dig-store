//! The store SIZE and the SIZE PROOF (SPEC §4) — the net-new core of this crate.
//!
//! A store anchors its `.dig` SIZE on chain so a client can decide, BEFORE downloading, whether the
//! artifact is worth fetching. The anchored size is a coarse **power-of-2 bucket**, not an exact byte
//! count — the smallest representation that still conveys magnitude (NC-8, minimal on-chain
//! encoding): a single exponent `k ∈ 0..=10` mapping to `2^k MB`, 1 MB..1 GB.
//!
//! The SIZE PROOF is the client-side check: given the bucket the store anchored on chain (NC-9) and
//! the real byte length of a downloaded `.dig`, [`SizeProof::verify`] decides ACCEPT or DISCARD. A
//! `.dig` whose real size does not fall in the anchored bucket is rejected — a dig-node MUST NOT
//! store or serve it (SPEC §4, the discard rule).
//!
//! ## Canonical ladder
//!
//! `1 MB = 1 MiB = 2^20 bytes` (the canonical unit contract, shared byte-for-byte with
//! `dig_merkle::SizeBucket`).
//!
//! | k | size |     | k | size |
//! |---|------|-----|---|------|
//! | 0 | 1 MB | | 6 | 64 MB |
//! | 1 | 2 MB | | 7 | 128 MB |
//! | 2 | 4 MB | | 8 | 256 MB |
//! | 3 | 8 MB | | 9 | 512 MB |
//! | 4 | 16 MB | | 10 | 1024 MB = 1 GB |
//! | 5 | 32 MB |
//!
//! ## Compose-pass note
//!
//! [`SizeBucket`] mirrors `dig_merkle::SizeBucket` exactly. On the compose pass (SPEC §11) this type
//! becomes a re-export of the canonical one so the ladder lives in ONE place and cannot drift; the
//! `ladder_matches_dig_merkle` golden test pins the values until then.

use crate::error::{DigStoreError, DigStoreResult};

/// The largest bucket exponent: `k = 10` is `2^10 MiB = 1024 MB = 1 GB`, the ceiling a store size is
/// quantised into. A byte length above `2^30` (1 GiB) has no bucket and is rejected.
const MAX_EXPONENT: u8 = 10;

/// One megabyte, defined as one mebibyte (`2^20` bytes) — the canonical unit of the ladder.
const BYTES_PER_MB: u64 = 1 << 20;

/// A store size quantised to a power-of-2 bucket: exponent `k ∈ 0..=10` ↔ `2^k MiB` (1 MB..1 GB).
///
/// A `SizeBucket` is always valid by construction — every constructor rejects an out-of-range value
/// — so [`exponent`](Self::exponent) is guaranteed to be in `0..=10`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SizeBucket {
    /// The validated bucket exponent, always in `0..=10`.
    k: u8,
}

impl SizeBucket {
    /// Builds a bucket from its exponent `k`, rejecting `k > 10` (the ladder ceiling).
    ///
    /// # Errors
    ///
    /// Returns [`DigStoreError::InvalidSize`] if `k > 10` — there is no bucket larger than 1 GB.
    pub fn from_exponent(k: u8) -> DigStoreResult<Self> {
        if k > MAX_EXPONENT {
            return Err(DigStoreError::InvalidSize(format!(
                "size-bucket exponent {k} exceeds the maximum {MAX_EXPONENT} (1 GB)"
            )));
        }
        Ok(Self { k })
    }

    /// The validated bucket exponent, always in `0..=10`.
    pub fn exponent(&self) -> u8 {
        self.k
    }

    /// The bucket size in megabytes (`2^k`, with 1 MB = 1 MiB): 1, 2, 4, … 1024.
    pub fn megabytes(&self) -> u32 {
        1u32 << self.k
    }

    /// The exact byte capacity of this bucket (`2^(k+20)`).
    pub fn byte_len(&self) -> u64 {
        BYTES_PER_MB << self.k
    }

    /// The canonical byte length → bucket mapping: the SMALLEST `k` whose bucket (`2^(k+20)` bytes)
    /// is at least `bytes`. 0 or 1 byte → `k = 0`; exactly 1 MiB → `k = 0`; 1 MiB + 1 → `k = 1`;
    /// exactly 1 GiB → `k = 10`.
    ///
    /// # Errors
    ///
    /// Returns [`DigStoreError::InvalidSize`] if `bytes > 2^30` (1 GiB) — beyond the ladder ceiling.
    pub fn for_byte_len(bytes: u64) -> DigStoreResult<Self> {
        for k in 0..=MAX_EXPONENT {
            if bytes <= (BYTES_PER_MB << k) {
                return Ok(Self { k });
            }
        }
        Err(DigStoreError::InvalidSize(format!(
            "size {bytes} bytes exceeds the maximum bucket 2^30 (1 GiB)"
        )))
    }
}

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
                // bucket, so report the ceiling exponent to keep the message well-formed.
                let actual_k = SizeBucket::for_byte_len(actual_bytes)
                    .map(|b| b.exponent())
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

    /// The exponent→megabytes ladder is exactly the powers of two 1..1024, `k = 10` is 1 GB, and
    /// `byte_len()` is `2^(k+20)` for every bucket. Pins byte-for-byte parity with
    /// `dig_merkle::SizeBucket` until the compose pass replaces this type with a re-export.
    #[test]
    fn ladder_matches_dig_merkle() {
        let expected_mb = [1u32, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
        for (k, &mb) in expected_mb.iter().enumerate() {
            let bucket = SizeBucket::from_exponent(k as u8).expect("k in range");
            assert_eq!(bucket.megabytes(), mb, "k={k} megabytes");
            assert_eq!(bucket.exponent(), k as u8, "k={k} exponent round-trips");
            assert_eq!(bucket.byte_len(), MIB << k, "k={k} byte_len");
        }
        assert_eq!(SizeBucket::from_exponent(10).unwrap().megabytes(), 1024);
        assert_eq!(SizeBucket::from_exponent(10).unwrap().byte_len(), GIB);
    }

    #[test]
    fn from_exponent_rejects_out_of_range() {
        assert!(matches!(
            SizeBucket::from_exponent(11),
            Err(DigStoreError::InvalidSize(_))
        ));
        assert!(matches!(
            SizeBucket::from_exponent(255),
            Err(DigStoreError::InvalidSize(_))
        ));
    }

    /// The canonical byte→bucket boundaries: the smallest bucket that fits, edges landing where
    /// dig-merkle fixes them, and anything over 1 GiB rejected.
    #[test]
    fn for_byte_len_boundaries() {
        let expect = |bytes: u64, k: u8| {
            assert_eq!(
                SizeBucket::for_byte_len(bytes)
                    .expect("in range")
                    .exponent(),
                k,
                "for_byte_len({bytes}) should be k={k}"
            );
        };
        expect(0, 0);
        expect(1, 0);
        expect(MIB, 0);
        expect(MIB + 1, 1);
        expect(512 * MIB, 9);
        expect(512 * MIB + 1, 10);
        expect(GIB, 10);
        assert!(matches!(
            SizeBucket::for_byte_len(GIB + 1),
            Err(DigStoreError::InvalidSize(_))
        ));
    }

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

    /// The accept path of `require` is a plain `Ok`.
    #[test]
    fn require_accepts_matching() {
        let anchored = SizeBucket::from_exponent(7).unwrap();
        assert!(SizeProof::require(anchored, 100 * MIB).is_ok());
    }
}
