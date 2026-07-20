//! The OFF-CHAIN `.dig` capsule getters (SPEC §5/§11): recover a capsule's declared identity from a
//! compiled `.dig` module's bytes, WITHOUT the on-chain suite and WITHOUT the full wasmtime serve
//! runtime.
//!
//! Both getters compose `dig-capsule`'s lightweight, wasmtime-free `reader`
//! ([`dig_capsule::capsule::Capsule::from_module_bytes`]): it parses the module's embedded DIGS data
//! section, reads the `StoreId` + `CurrentRoot`, and — FAIL-CLOSED — recomputes the merkle root from
//! the committed `MerkleNodes` leaves and rejects a forged `CurrentRoot`. So the `root_hash` a getter
//! returns is always internally consistent with the module's committed content; a tampered module
//! surfaces as [`DigStoreError::Capsule`] rather than a wrong-but-plausible root.
//!
//! # Caller-supplied bytes — never a fetch
//!
//! `dig-store` is network-free (INV-1): these getters take the module bytes the CALLER already holds
//! (a downloaded `.dig`, a module read from disk, a chunk assembled by the node). They never dial the
//! network or read a store — fetching the bytes is the caller's job.
//!
//! # The `store_id` trust boundary
//!
//! A capsule's `store_id` is its on-chain launcher id, baked in at compile time and NOT self-verifiable
//! from the module bytes alone (SPEC §8, and the `dig-capsule` reader docs). The two getters differ
//! ONLY in how they treat that:
//!
//! - [`get_capsule_identity`] returns the declared `store_id` as a CLAIM — the caller MUST cross-check
//!   it against a trusted anchor before trusting it.
//! - [`open_capsule`] takes the trusted `store_id` the caller already holds (from the URN it resolved
//!   or the on-chain singleton) and cross-checks the module's declared id against it, failing closed on
//!   mismatch — so a returned [`CapsuleIdentity`] is bound to that anchor.

use dig_capsule::capsule::Capsule as CapsuleReader;

use crate::error::{DigStoreError, DigStoreResult};
use crate::types::{Bytes32, CapsuleIdentity};

/// Recover a capsule's declared identity `(store_id, root_hash)` from a compiled `.dig` module's bytes
/// — the lightweight, wasmtime-free read (SPEC §5/§11).
///
/// The `root_hash` is proven internally consistent (the reader recomputes the merkle root and rejects a
/// forged one). The `store_id` is the module's DECLARED on-chain launcher id and is NOT self-verified;
/// the caller MUST cross-check it against a trusted anchor before trusting it (use [`open_capsule`] to
/// have that cross-check done here). See [`CapsuleIdentity`].
///
/// # Errors
///
/// Returns [`DigStoreError::Capsule`] if the bytes are not a parseable `.dig` module, carry no DIGS
/// data section, are missing a required section, or fail the fail-closed merkle-root check.
pub fn get_capsule_identity(module_bytes: &[u8]) -> DigStoreResult<CapsuleIdentity> {
    let capsule = CapsuleReader::from_module_bytes(module_bytes)
        .map_err(|error| DigStoreError::Capsule(error.to_string()))?;

    Ok(CapsuleIdentity {
        store_id: Bytes32::new(capsule.store_id.0),
        root_hash: Bytes32::new(capsule.root_hash.0),
    })
}

/// OPEN a compiled `.dig` module against the trusted `store_id` the caller already holds: recover its
/// declared identity and cross-check the declared `store_id` against `expected_store_id`, failing
/// closed on mismatch (SPEC §5/§8/§11).
///
/// This is the SAFE entry point when the caller has a trusted store anchor (the URN it resolved, the
/// on-chain singleton it verified): the returned [`CapsuleIdentity`]'s `store_id` is guaranteed to
/// equal `expected_store_id`, so it is bound to that anchor rather than a self-declared claim. The
/// `root_hash` remains the module's internally-consistent committed root — this cross-check does not
/// assert the root is the publisher's LATEST authorized root (the chain is the authority for that).
///
/// # Errors
///
/// Returns [`DigStoreError::Capsule`] if the module cannot be read (see [`get_capsule_identity`]) or if
/// its declared `store_id` does not equal `expected_store_id`.
pub fn open_capsule(
    module_bytes: &[u8],
    expected_store_id: Bytes32,
) -> DigStoreResult<CapsuleIdentity> {
    let identity = get_capsule_identity(module_bytes)?;

    if identity.store_id != expected_store_id {
        return Err(DigStoreError::Capsule(format!(
            "capsule store_id mismatch: module declares {} but the trusted anchor is {expected_store_id}",
            identity.store_id
        )));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frozen golden `.dig` module fixture: a real compiled wasm module carrying a self-consistent
    /// DIGS blob with `store_id = [0xAB; 32]` and `CurrentRoot` = the merkle root of leaves
    /// `[0x33; 32], [0x44; 32]`. Generated once from `dig-capsule`'s `compile` path; this crate reads
    /// it with the lightweight `reader` only. §5.1 lock: the reader must decode it forever.
    fn golden_module() -> Vec<u8> {
        let hex = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/golden_capsule_module.hex"
        ))
        .trim();
        hex_decode(hex)
    }

    /// The `store_id` the golden fixture declares.
    fn golden_store_id() -> Bytes32 {
        Bytes32::new([0xAB; 32])
    }

    /// The `root_hash` (merkle root of the golden leaves) the golden fixture commits to.
    const GOLDEN_ROOT_HEX: &str =
        "da2b3372876ec1d3dd9b846f22cb6a9afcb2dadbf579f2930f8e5efe81b0905a";

    /// A tiny dependency-free hex decoder for the fixture (the crate needs no `hex` at runtime).
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex length must be even");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// GOLDEN: a real compiled `.dig` module reads back its exact declared `(store_id, root_hash)`.
    #[test]
    fn get_capsule_identity_recovers_the_declared_pair() {
        let identity = get_capsule_identity(&golden_module()).expect("golden module reads");
        assert_eq!(identity.store_id, golden_store_id());
        assert_eq!(identity.root_hash, Bytes32::new(hex_to_32(GOLDEN_ROOT_HEX)));
    }

    /// `open_capsule` returns the identity when the declared id matches the trusted anchor.
    #[test]
    fn open_capsule_accepts_a_matching_anchor() {
        let identity =
            open_capsule(&golden_module(), golden_store_id()).expect("matching anchor opens");
        assert_eq!(identity.store_id, golden_store_id());
    }

    /// FAIL-CLOSED: `open_capsule` rejects a module whose declared id differs from the trusted anchor —
    /// an attacker cannot pass off a different store's module under the caller's anchor.
    #[test]
    fn open_capsule_rejects_a_mismatched_anchor() {
        let wrong_anchor = Bytes32::new([0x01; 32]);
        assert!(
            matches!(
                open_capsule(&golden_module(), wrong_anchor),
                Err(DigStoreError::Capsule(_))
            ),
            "a store_id that does not match the trusted anchor must fail closed"
        );
    }

    /// FAIL-CLOSED: non-module garbage surfaces as a capsule error, never a panic or a bogus identity.
    #[test]
    fn get_capsule_identity_rejects_non_module_bytes() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        assert!(matches!(
            get_capsule_identity(&garbage),
            Err(DigStoreError::Capsule(_))
        ));
    }

    /// FAIL-CLOSED: a tampered module (one flipped byte) does not read as a valid capsule — the reader's
    /// merkle-root check (or wasm parse) rejects it, surfaced as [`DigStoreError::Capsule`].
    #[test]
    fn get_capsule_identity_rejects_a_tampered_module() {
        let mut module = golden_module();
        let last = module.len() - 1;
        module[last] ^= 0xFF;
        assert!(matches!(
            get_capsule_identity(&module),
            Err(DigStoreError::Capsule(_))
        ));
    }

    /// Decode a 64-char hex string into a 32-byte array.
    fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = hex_decode(s);
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}
