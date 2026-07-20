//! Store + capsule URN formatting (SPEC §5).
//!
//! The DIG content URN scheme is `urn:dig:chia:<store_id>[:<root_hash>]`:
//!
//! - the **store URN** (`urn:dig:chia:<store_id>`) is ROOTLESS — it names the store across all its
//!   generations, the stable handle a resolver uses to find the latest content;
//! - the **capsule / root URN** (`urn:dig:chia:<store_id>:<root_hash>`) PINS one immutable
//!   generation — the pair `(store_id, root_hash)` is exactly a capsule.
//!
//! Both `store_id` and `root_hash` are rendered lowercase hex. This mirrors the canonical
//! `dig-urn-protocol` scheme byte-for-byte; on the compose pass (SPEC §11) [`store_urn`] /
//! [`capsule_urn`] delegate to `dig_capsule::urn::DigUrn` so the scheme lives in ONE place.

use crate::types::Bytes32;
use sha2::{Digest, Sha256};

/// The fixed URN prefix for the Chia-anchored DIG content scheme.
pub const URN_PREFIX: &str = "urn:dig:chia:";

/// The ROOTLESS store URN: `urn:dig:chia:<store_id>`.
///
/// Names the store across every generation — the stable handle for "the latest content of this
/// store". Use [`capsule_urn`] to pin a specific root.
pub fn store_urn(store_id: Bytes32) -> String {
    format!("{URN_PREFIX}{}", store_id.to_hex())
}

/// The capsule / root URN: `urn:dig:chia:<store_id>:<root_hash>`.
///
/// Pins the immutable generation `(store_id, root_hash)` — the on-wire name of one capsule.
pub fn capsule_urn(store_id: Bytes32, root_hash: Bytes32) -> String {
    format!("{URN_PREFIX}{}:{}", store_id.to_hex(), root_hash.to_hex())
}

/// The retrieval key of a URN: `SHA-256(urn)` over its canonical (lowercase) string.
///
/// This is the URN-identity key that PINS the content — byte-identical to
/// `dig_urn_protocol::DigUrn::retrieval_key` and to the browser verifier. A rootless store URN and a
/// rooted capsule URN therefore have DISTINCT retrieval keys (the root is part of the canonical
/// string), which is why a client fetching a pinned generation keys on the capsule URN.
pub fn retrieval_key(urn: &str) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(urn.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Bytes32(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Bytes32 {
        Bytes32([byte; 32])
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
    fn retrieval_key_is_sha256_of_the_urn_string() {
        let urn = store_urn(id(0x01));
        let expected = {
            let mut h = Sha256::new();
            h.update(urn.as_bytes());
            let d = h.finalize();
            let mut o = [0u8; 32];
            o.copy_from_slice(&d);
            Bytes32(o)
        };
        assert_eq!(retrieval_key(&urn), expected);
    }

    #[test]
    fn store_and_capsule_urns_have_distinct_retrieval_keys() {
        let store = store_urn(id(0x05));
        let capsule = capsule_urn(id(0x05), id(0x06));
        assert_ne!(retrieval_key(&store), retrieval_key(&capsule));
    }

    #[test]
    fn store_id_round_trips_through_hex() {
        let original = id(0x7f);
        let urn = store_urn(original);
        let hex = urn.trim_start_matches(URN_PREFIX);
        assert_eq!(Bytes32::from_hex(hex).unwrap(), original);
    }
}
