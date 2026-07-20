//! Store + capsule URN formatting (SPEC §5).
//!
//! The DIG content URN scheme is `urn:dig:chia:<store_id>[:<root_hash>]`:
//!
//! - the **store URN** (`urn:dig:chia:<store_id>`) is ROOTLESS — it names the store across all its
//!   generations, the stable handle a resolver uses to find the latest content;
//! - the **capsule / root URN** (`urn:dig:chia:<store_id>:<root_hash>`) PINS one immutable
//!   generation — the pair `(store_id, root_hash)` is exactly a capsule.
//!
//! The scheme, canonical form, and retrieval-key derivation are owned by the canonical
//! [`dig_urn_protocol`] crate (the ONE ecosystem definition, re-exported through the `dig-capsule`
//! `urn` facade). `dig-store` delegates every URN operation to it so the scheme lives in a single
//! place and cannot drift, converting only between the re-exported [`Bytes32`] and the protocol's own
//! 32-byte identifier at the boundary.

use dig_urn_protocol::{Bytes32 as UrnBytes32, DigUrn, CANONICAL_CHAIN};

use crate::error::{DigStoreError, DigStoreResult};
use crate::types::Bytes32;

/// The fixed URN prefix for the Chia-anchored DIG content scheme (`urn:dig:` + the canonical `chia`
/// chain label). Pinned against the protocol's own prefix + chain by
/// [`tests::prefix_matches_protocol`].
pub const URN_PREFIX: &str = "urn:dig:chia:";

/// Converts a store/root [`Bytes32`] into the protocol crate's own 32-byte identifier at the URN
/// boundary — both are the identical 32 raw bytes.
fn to_urn_bytes(value: Bytes32) -> UrnBytes32 {
    let mut raw = [0u8; 32];
    raw.copy_from_slice(value.as_ref());
    UrnBytes32(raw)
}

/// The ROOTLESS store URN: `urn:dig:chia:<store_id>`.
///
/// Names the store across every generation — the stable handle for "the latest content of this
/// store". Use [`capsule_urn`] to pin a specific root.
pub fn store_urn(store_id: Bytes32) -> String {
    DigUrn {
        chain: CANONICAL_CHAIN.to_string(),
        store_id: to_urn_bytes(store_id),
        root_hash: None,
        resource_key: None,
    }
    .canonical()
}

/// The capsule / root URN: `urn:dig:chia:<store_id>:<root_hash>`.
///
/// Pins the immutable generation `(store_id, root_hash)` — the on-wire name of one capsule.
pub fn capsule_urn(store_id: Bytes32, root_hash: Bytes32) -> String {
    DigUrn {
        chain: CANONICAL_CHAIN.to_string(),
        store_id: to_urn_bytes(store_id),
        root_hash: Some(to_urn_bytes(root_hash)),
        resource_key: None,
    }
    .canonical()
}

/// The retrieval key of a URN: `SHA-256(canonical(urn))`.
///
/// This is the URN-identity key that PINS the content — byte-identical to
/// [`DigUrn::retrieval_key`] and to the browser verifier. A rootless store URN and a rooted capsule
/// URN therefore have DISTINCT retrieval keys (the root is part of the canonical string), which is
/// why a client fetching a pinned generation keys on the capsule URN.
///
/// # Errors
///
/// Returns [`DigStoreError::InvalidUrn`] if `urn` is not a parseable DIG URN.
pub fn retrieval_key(urn: &str) -> DigStoreResult<Bytes32> {
    let parsed =
        DigUrn::parse(urn).map_err(|error| DigStoreError::InvalidUrn(format!("{urn}: {error}")))?;
    Ok(Bytes32::new(parsed.retrieval_key().0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Bytes32 {
        Bytes32::new([byte; 32])
    }

    #[test]
    fn prefix_matches_protocol() {
        assert_eq!(
            URN_PREFIX,
            format!("{}{CANONICAL_CHAIN}:", dig_urn_protocol::URN_PREFIX)
        );
    }

    #[test]
    fn store_urn_is_rootless() {
        let urn = store_urn(id(0xab));
        assert_eq!(urn, format!("urn:dig:chia:{}", "ab".repeat(32)));
        assert!(!urn.trim_start_matches(URN_PREFIX).contains(':'));
    }

    #[test]
    fn capsule_urn_pins_the_root() {
        let urn = capsule_urn(id(0x11), id(0x22));
        assert_eq!(
            urn,
            format!("urn:dig:chia:{}:{}", "11".repeat(32), "22".repeat(32))
        );
    }

    #[test]
    fn retrieval_key_matches_dig_urn_protocol() {
        let urn = store_urn(id(0x01));
        let expected = DigUrn::parse(&urn).unwrap().retrieval_key();
        assert_eq!(retrieval_key(&urn).unwrap(), Bytes32::new(expected.0));
    }

    #[test]
    fn store_and_capsule_urns_have_distinct_retrieval_keys() {
        let store = store_urn(id(0x05));
        let capsule = capsule_urn(id(0x05), id(0x06));
        assert_ne!(
            retrieval_key(&store).unwrap(),
            retrieval_key(&capsule).unwrap()
        );
    }

    #[test]
    fn retrieval_key_rejects_a_non_urn() {
        assert!(matches!(
            retrieval_key("not-a-urn"),
            Err(DigStoreError::InvalidUrn(_))
        ));
    }
}
