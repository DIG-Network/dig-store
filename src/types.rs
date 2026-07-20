//! The shared identifier + value types of the store surface.
//!
//! These are self-contained now so the crate compiles and the API shape is final. On the compose
//! pass (SPEC §11) [`Bytes32`] becomes a re-export of `chia_protocol::Bytes32` and [`DidRef`] a
//! re-export of `dig_merkle::DidRef`; both are byte-identical 32-byte identifiers, so the swap is
//! source-compatible for consumers that use these paths.

use crate::error::{DigStoreError, DigStoreResult};

/// A 32-byte identifier — a store id (`launcher_id`), a merkle root, or a DID launcher id.
///
/// Rendered as lowercase hex in URNs and logs. On the compose pass this becomes a re-export of
/// `chia_protocol::Bytes32`, which has the identical 32-byte representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    /// Wraps 32 raw bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The lowercase-hex rendering (64 chars, no `0x` prefix) used in URNs.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 64-char lowercase-or-uppercase hex string into a `Bytes32`.
    ///
    /// # Errors
    ///
    /// Returns [`DigStoreError::InvalidUrn`] if the input is not exactly 32 hex-encoded bytes.
    pub fn from_hex(s: &str) -> DigStoreResult<Self> {
        let raw =
            hex::decode(s).map_err(|e| DigStoreError::InvalidUrn(format!("bad hex '{s}': {e}")))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| DigStoreError::InvalidUrn(format!("expected 32 bytes, got '{s}'")))?;
        Ok(Self(bytes))
    }
}

/// A reference to a store's owning DID — its permanent on-chain launcher id.
///
/// On the compose pass this becomes a re-export of `dig_merkle::DidRef`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DidRef {
    /// The DID's launcher id — its permanent on-chain identity.
    pub launcher_id: Bytes32,
}

/// The current confirmed tip of a store singleton: the coin the next spend must consume.
///
/// Composition of the on-chain read (`dig-merkle`) — a fully-resolved, chain-proven snapshot of the
/// store's live coin. Fields land on the compose pass; the shape is fixed now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreTip {
    /// The store id (`launcher_id`) — permanent across the store's whole lifetime.
    pub store_id: Bytes32,
    /// The current (tip) coin id that a `modify`/`melt` spend must consume.
    pub coin_id: Bytes32,
    /// The merkle root anchored at this tip.
    pub root_hash: Bytes32,
}

/// The ordered history of merkle roots a store has anchored, oldest first.
///
/// Each entry is proven on chain by walking the singleton's lineage (NC-9). The last element is the
/// latest root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootHistory {
    /// The anchored roots, oldest → newest. Never empty for a live store (the mint anchors root 0).
    pub roots: Vec<Bytes32>,
}

impl RootHistory {
    /// The most recently anchored root, if any.
    pub fn latest(&self) -> Option<Bytes32> {
        self.roots.last().copied()
    }

    /// The number of generations (root anchorings) the store has had.
    pub fn generation_count(&self) -> usize {
        self.roots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Bytes32 {
        Bytes32::new([b; 32])
    }

    #[test]
    fn bytes32_hex_round_trips() {
        let original = id(0x3c);
        assert_eq!(original.to_hex(), "3c".repeat(32));
        assert_eq!(Bytes32::from_hex(&original.to_hex()).unwrap(), original);
    }

    #[test]
    fn bytes32_from_hex_rejects_wrong_length_and_bad_chars() {
        assert!(matches!(
            Bytes32::from_hex("abcd"),
            Err(DigStoreError::InvalidUrn(_))
        ));
        assert!(matches!(
            Bytes32::from_hex(&"zz".repeat(32)),
            Err(DigStoreError::InvalidUrn(_))
        ));
    }

    #[test]
    fn root_history_reports_latest_and_generation_count() {
        let empty = RootHistory::default();
        assert_eq!(empty.latest(), None);
        assert_eq!(empty.generation_count(), 0);

        let history = RootHistory {
            roots: vec![id(1), id(2), id(3)],
        };
        assert_eq!(history.latest(), Some(id(3)));
        assert_eq!(history.generation_count(), 3);
    }
}
