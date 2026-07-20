# dig-store — normative specification

`dig-store` is the DIG Network **DataLayer store manager**: the crate that composes the on-chain
anchor (`dig-merkle`) and the off-chain `.dig` data plane (`dig-capsule`) into ONE store abstraction.
This document is the normative contract an independent reimplementation can be built against. The
voice is normative (IS / MUST / SHOULD); it describes the current contract, not history or roadmap.

Cross-references: the ecosystem interaction map (`SYSTEM.md`), the `dig-store-format` skill (the
`.dig` / DIGS layout + build prereqs), `dig-merkle` `SPEC.md` (the on-chain byte layout), and
`dig-capsule` `SPEC.md` (the `.dig` format). NC-8 / NC-9 are the ecosystem MUST-DO items on minimal
on-chain encoding and on-chain proof (the `normative-contract` skill).

## 1. Scope + invariants

A **store** is the pair of:

- an **on-chain anchor** — a CHIP-0035 DataLayer singleton whose `launcher_id` IS the `store_id` and
  whose metadata carries the current `.dig` merkle root plus `label` / `description` / `size_bucket`
  / `program_hash`. Owned by `dig-merkle`.
- an **off-chain data plane** — the `.dig` capsule (`(store_id, root_hash)`). Owned by `dig-capsule`.

`dig-store` composes the two; it MUST NOT re-implement either plane's bytes. The following invariants
hold across the whole crate:

- **INV-1 — No network.** `dig-store` performs NO chain or network I/O itself. On-chain reads take a
  caller-supplied [`ChainSource`] (§7); lifecycle operations are pure transforms of their inputs.
- **INV-2 — No keys, unsigned output.** `dig-store` never accepts, holds, derives, or logs a secret
  key. Every lifecycle operation returns an UNSIGNED spend; signing + broadcasting are the caller's.
- **INV-3 — Minimal on-chain encoding (NC-8).** The store's on-chain footprint is delegated wholesale
  to `dig-merkle`, which owns the minimal byte layout. `dig-store` MUST NOT add its own on-chain
  fields; the size is a single-byte power-of-2 bucket (§4).
- **INV-4 — On-chain proof always (NC-9).** Every getter that returns chain-anchored data MUST prove
  it against the chain via the `ChainSource`. Trust MUST NOT come from a self-declared field, a cached
  value, a curried id, or an unverified peer. A `ChainSource` used for custody-grade reads MUST be a
  trusted source (the user's own verified node or a trusted/threshold provider set), never a single
  untrusted remote (NC-9 F1).
- **INV-5 — `.dig` back-compat (CLAUDE.md §5.1).** The capsule surface MUST read every older `.dig`
  format identically. The public API is extended additively; an existing item's meaning never changes.

## 2. Identifiers

- `store_id`: the DataLayer singleton `launcher_id`, a 32-byte value, permanent for the store's life.
- `root_hash`: the anchored `.dig` merkle root, a 32-byte value; changes each generation.
- A `(store_id, root_hash)` pair IS a **capsule** — one immutable generation.
- `Bytes32` is a 32-byte identifier rendered as 64 lowercase hex characters in URNs and logs.

## 3. Lifecycle — a store is a coin that gets spent

Three operations span a store's life; each is a spend of the singleton and returns an UNSIGNED
`MerkleCoinSpend` (INV-2, re-exported verbatim from `dig-merkle`: the coin spends + the recreated
child `DataStore`). The on-chain encoding is `dig-merkle`'s (INV-3). `StoreOwner` is a re-export of
`dig_merkle::Owner` (`Standard(PublicKey)` | `Custom(Spend)`).

### 3.1 `create_store(parent_coin, owner, owner_puzzle_hash, params) -> MerkleCoinSpend`

Launches a new store coin. `parent_coin` (a full `Coin`) funds + parents the launcher, so
`launcher_id == store_id` derives from its `coin_id`. `owner` authorizes the parent spend;
`owner_puzzle_hash` is the store owner recorded in the singleton. `params` (`CreateStoreParams`)
carries the first `root_hash`, the `size` bucket (§4, REQUIRED — every store anchors its size), and
optional `label` / `description` / `program_hash`, plus the launch `fee`. The store is minted with the
`StoreKind::File` launcher discriminator, byte-identical to existing on-chain DIG stores. Composes
`dig_merkle::mint_datastore_with_kind`.

To root a store in a DID, the caller passes the DID-authorized coin as `parent_coin` with a
`StoreOwner::Custom` inner spend satisfying the DID puzzle; owner discovery (§7) then resolves the
DID via `dig-merkle`. `create_store` MUST anchor `size` in the on-chain metadata so §4 can be checked.

### 3.2 `modify_store(store, owner, new_root) -> MerkleCoinSpend`

Spends the current tip coin to recreate the singleton anchoring `new_root` — a new generation.
`store` is the already-hydrated tip `DataStore` (from §7's `get_store_singleton_tip`), so this builder
stays a pure transform (INV-1). `store_id`, owner, and delegation set are preserved, and every OTHER
anchored metadata field (label, description, size bucket, program hash) is carried forward unchanged
(`dig-merkle` replaces metadata wholesale, so `modify_store` re-sends the existing fields with only
`root_hash` updated). Composes `dig_merkle::update_root`. Attaching a reserve fee to a modify is a
`dig-merkle` future unit (its `fee` module is a stub); the coin is recreated at its current amount.

### 3.3 `melt_store(store, owner) -> MerkleCoinSpend`

Terminally spends the tip `DataStore` with no successor (`child == None`), closing the store. No
future generation can be anchored after a melt. Composes `dig_merkle::melt`.

## 4. Size + size proof (the net-new contract)

A store anchors its `.dig` SIZE on chain so a client can decide, BEFORE downloading, whether to fetch
the artifact.

- **Encoding.** The size is a power-of-2 **bucket**, not an exact byte count (NC-8 minimal encoding):
  an exponent `k ∈ 0..=10` mapping to `2^k MB`, where `1 MB = 1 MiB = 2^20 bytes`. The ladder is
  therefore 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 MB (1 GB is the ceiling). This is `SizeBucket`
  and MUST be byte-identical to `dig_merkle::SizeBucket` (CLVM metadata key `"sz"`).
- **byte → bucket.** `SizeBucket::for_byte_len(n)` MUST return the SMALLEST `k` whose bucket
  (`2^(k+20)` bytes) is ≥ `n`. `n = 0` or `1` → `k = 0`; exactly 1 MiB → `k = 0`; 1 MiB + 1 → `k = 1`;
  exactly 1 GiB → `k = 10`; `n > 2^30` → error (no bucket).
- **Size proof.** `SizeProof::verify(anchored, actual_bytes)` returns `Accept` iff
  `SizeBucket::for_byte_len(actual_bytes) == anchored`, else `Discard`. A `.dig` whose real size does
  not fall in the store's anchored bucket — larger OR smaller — MUST be discarded. A byte length above
  the ceiling can never match and is `Discard`ed (not errored). `SizeProof::require` returns
  `DigStoreError::SizeProofMismatch` on the discard path for `?`-propagation.
- **dig-node enforcement (sibling, dig-node repo).** A dig-node MUST run the size proof against the
  on-chain-anchored bucket (read with NC-9 proof) for every downloaded `.dig` and MUST NOT store or
  serve a capsule whose real size does not match. A size-mismatched capsule is rejected, never cached.

## 5. Getters + URNs

The getter surface is comprehensive over both planes. On-chain getters (§7) prove every value against
the chain (INV-4).

- URN (no chain read for the rootless form). The scheme, canonical form, and key derivation are owned
  by the canonical `dig-urn-protocol` crate (re-exported through the `dig-capsule` `urn` facade);
  `dig-store` delegates to it so the scheme lives in one place:
  - `get_store_urn(store_id) -> String` — the ROOTLESS `urn:dig:chia:<store_id>`; the stable handle
    across all generations.
  - `get_latest_root_urn(chain, store_id) -> String` — `urn:dig:chia:<store_id>:<latest_root>`, the
    capsule URN pinning the latest generation (reads the tip first).
  - `store_urn` / `capsule_urn` format the canonical scheme; `retrieval_key(urn) -> Result<Bytes32>` =
    `SHA-256(canonical(urn))`, byte-identical to `dig-urn-protocol` (fails closed on a non-URN input).
- On-chain (NC-9), all generic over the canonical `dig_chainsource_interface::ChainSource` (§7). The
  reads share ONE lineage walk (launcher spend → hydrate each generation → follow the singleton to the
  unspent tip; a `MissingLineage` hydration marks a melt), fail-closed at every missing hop:
  - `get_store_did_owner(chain, store_id) -> Option<DidRef>` — the owning DID, resolved by walking the
    launcher's parent spend (`dig_merkle::resolve_owner_did`); `None` for a non-DID mint.
  - `get_store_singleton_tip(chain, store_id) -> DataStore<DigDataStoreMetadata>` — the current
    confirmed tip, fully hydrated so it feeds `modify_store` / `melt_store` directly; errors if the
    store is absent or melted (no live tip).
  - `get_root_history(chain, store_id) -> RootHistory` — every anchored root, oldest → newest (a
    melted store still reports the roots it anchored while live).
  - `get_latest_root(chain, store_id) -> Bytes32` — the root at the tip.
  - `get_store_label` / `get_store_description` / `get_store_size_bucket` / `get_store_program_hash` —
    the corresponding on-chain metadata field read off the tip (`Option`, omitted-when-absent).
- Lineage proof (no chain read). `child_lineage_proof(store) -> LineageProof` (re-exported verbatim
  from `dig-merkle`, INV-4) derives the `LineageProof` a child singleton spend must carry to be
  recreated from a hydrated store — so a consumer builds the next spend against a store the walk
  returned. The `parent_inner_puzzle_hash` is derived via the DataLayer metadata-updater path (currying
  `DL_METADATA_UPDATER_PUZZLE_HASH`), byte-matching a real on-chain DataLayer coin, so the resulting
  child spend is consensus-valid (no `AssertMyParentIdFailed`) for both the empty- and delegated-inner
  cases. `dig-store` pins `dig-merkle >= 0.4.3`, the version that first derives it this way.
- Off-chain (`.dig` via `dig-capsule`) — read a capsule's declared identity from a compiled `.dig`
  module's bytes the caller supplies, wasmtime-free, WITHOUT any chain read (§11). Both compose
  `dig_capsule::capsule::Capsule::from_module_bytes` (the `reader` feature): it recomputes the merkle
  root from the module's committed leaves and rejects a forged `CurrentRoot` fail-closed, so the
  returned `root_hash` is always internally consistent. A read failure surfaces as
  `DigStoreError::Capsule`.
  - `get_capsule_identity(module_bytes) -> CapsuleIdentity` — the DECLARED `(store_id, root_hash)`. The
    `store_id` is the on-chain launcher id and is NOT self-verifiable from the bytes; the caller MUST
    cross-check it against a trusted anchor before trusting it (§8).
  - `open_capsule(module_bytes, expected_store_id) -> CapsuleIdentity` — recovers the identity and
    cross-checks the declared `store_id` against the caller's trusted anchor, failing closed
    (`DigStoreError::Capsule`) on mismatch. The returned identity is thus bound to that anchor.

## 6. Errors

`DigStoreResult<T> = Result<T, DigStoreError>`. Variants: `InvalidSize`, `SizeProofMismatch
{ anchored_k, actual_k, actual_bytes }`, `InvalidUrn`, `Proof`, `Capsule`, `Spend`. Variants are
added additively; an existing variant's meaning never changes.

## 7. The `ChainSource` boundary

On-chain getters are generic over `C: ChainSource` — the ONE canonical
`dig_chainsource_interface::ChainSource` (re-exported at `dig_store::ChainSource`), a caller-supplied
reads-only source of confirmed chain state. The store surface uses its `coin_spend(coin_id) ->
Result<Option<CoinSpend>, C::Error>` fail-closed lookup (`Ok(None)` = the coin is unspent/unknown;
`Err(_)` = the source could not answer, mapped into `DigStoreError::Proof`). Lineage walks (owner
discovery, root history, tip) are repeated `coin_spend` lookups composed with `dig-merkle`'s
`hydrate`. The source MUST be trusted for custody-grade reads (INV-4 / NC-9 F1).

## 8. Security properties

- Unsigned output only (INV-2): a compromised `dig-store` cannot move funds; it emits spends the
  caller must still authorize.
- On-chain proof (INV-4): a value returned by a getter reflects the chain, not an attacker-chosen
  field. The proof is only as sound as the `ChainSource`; a payment-routing / custody read MUST use a
  trusted source (NC-9 F1).
- Size proof (§4): a size-mismatched `.dig` is discarded, so an attacker cannot make a node cache or
  serve content the store did not commit to.

## 9. Conformance

- The size ladder + byte→bucket mapping are the re-exported `dig_merkle::SizeBucket`, so they cannot
  drift from the on-chain encoding (test `size::tests::re_exported_ladder_is_canonical`).
- The URN scheme + retrieval key are the re-exported `dig-urn-protocol` definition (delegated, so they
  match the browser verifier by construction; test `urn::tests::retrieval_key_matches_dig_urn_protocol`).
- Golden `.dig` fixtures decode byte-identically forever (INV-5 / CLAUDE.md §5.1): the frozen
  `tests/fixtures/golden_capsule_module.hex` (a real compiled `.dig` module whose `store_id` is
  `[0xAB; 32]` and whose `CurrentRoot` is the merkle root of leaves `[0x33; 32], [0x44; 32]`) MUST keep
  reading through `get_capsule_identity` (test `capsule::tests::get_capsule_identity_recovers_the_declared_pair`).
  Older `.dig` blob versions read via the version-dispatching `dig-capsule` reader (inherited back-compat).

## 10. Crate hierarchy + publishing

`dig-store` depends on `dig-merkle` + `dig-capsule` (both level `10-primitives`) and
`dig-chainsource-interface` + `dig-urn-protocol` (level `00-foundation`). Depending on two
`10-primitives` crates, it sits ABOVE them at level **`20-domain`** in the crate hierarchy
(reference-DOWN-only). It is consumed by `dig-wallet-backend`, which sits above it. It publishes to
crates.io (no git deps); consumers depend on the crates.io version.

## 11. Composition (issues #1247, #1313)

`dig-store` wires the live crates.io dependencies (`dig-merkle 0.4`, `dig-capsule 0.5` `reader`,
`dig-chainsource-interface 0.1`, `dig-urn-protocol 0.1`) and fills every lifecycle, on-chain-getter, and
off-chain capsule-getter body:

- **`dig-merkle 0.4`** — `mint_datastore_with_kind` (create), `update_root` (modify), `melt` (melt),
  `hydrate` + `resolve_owner_did` (the on-chain read walk), and the re-exported `SizeBucket` / `Owner`
  / `Bytes32` / `Coin` / `CoinSpend` / `DataStore` / `DidRef` / `DigDataStoreMetadata` /
  `MerkleCoinSpend` types (so the ladder + coin shapes live in ONE place).
- **`dig-chainsource-interface 0.1`** — the canonical `ChainSource` every on-chain getter is generic
  over (its associated `Error` is mapped into `DigStoreError::Proof`).
- **`dig-urn-protocol 0.1`** — the canonical `DigUrn` the URN helpers delegate to (the same definition
  `dig-capsule` re-exports at `dig_capsule::urn`; `dig-store` depends on the foundation owner directly so
  URN formatting needs no `dig-capsule` feature).
- **`dig-capsule 0.5` (`reader` only)** — the lightweight, wasmtime-free `Capsule::from_module_bytes`
  the off-chain capsule getters compose (see below). `default-features = false` + `features =
  ["reader"]` keeps `dig-capsule`'s heavy serve/compile stack (wasmtime, chia-bls) out of the tree.

### The off-chain `.dig` capsule getters

`get_capsule_identity` / `open_capsule` compose `dig-capsule 0.5`'s `reader` feature — the lightweight,
wasmtime-free `dig_capsule::capsule::Capsule::from_module_bytes(&[u8]) -> Result<Capsule,
reader::ModuleReadError>`. The reader parses the module's embedded DIGS data section, reads `StoreId` +
`CurrentRoot`, and FAIL-CLOSED recomputes the merkle root from the committed `MerkleNodes` leaves,
rejecting a forged `CurrentRoot`. It pulls only `wasmparser` — no wasmtime, no chia-bls, no store — and
carries NO chia-sdk dependency, so `dig-store`'s single `chia-wallet-sdk` tree stays owned by
`dig-merkle` (verified: one `chia-wallet-sdk v0.30.0` in the tree).

`dig-capsule`'s own `Capsule` uses its own `Bytes32`; `dig-store` returns [`CapsuleIdentity`] built on
the canonical (`dig-merkle`) `Bytes32`, so the whole store surface speaks ONE byte type. A
`ModuleReadError` maps to `DigStoreError::Capsule`.

**`store_id` trust boundary (§8).** `from_module_bytes` returns `store_id` = the on-chain launcher id,
which is NOT self-verifiable from the module bytes alone. `get_capsule_identity` therefore returns it as
a CLAIM the caller MUST cross-check; `open_capsule` performs that cross-check against a caller-supplied
trusted anchor and fails closed on mismatch. Neither getter over-claims that `root_hash` is the
publisher's LATEST authorized root — the chain remains the authority for that (an on-chain getter is
used to learn the latest root).

`dig-store` is network-free (INV-1): both getters take CALLER-PROVIDED module bytes — they never fetch a
store or dial the network.
