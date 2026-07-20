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
`StoreSpend` (INV-2). The on-chain encoding is `dig-merkle`'s (INV-3).

### 3.1 `create_store(parent_coin_id, owner, params) -> StoreSpend`

Launches a new store coin. `parent_coin_id` funds + parents the launcher, so `launcher_id ==
store_id` derives from it. `params` (`CreateStoreParams`) carries the first `root_hash`, the `size`
bucket (§4, REQUIRED — every store anchors its size), and optional `label` / `description` /
`program_hash`, plus the launch `fee`.

To root a store in a DID, the caller passes the DID-authorized coin as parent with an
`StoreOwner::Custom` inner spend satisfying the DID puzzle; owner discovery (§7) then resolves the
DID via `dig-merkle`. `create_store` MUST anchor `size` in the on-chain metadata so §4 can be checked.

### 3.2 `modify_store(store_tip, owner, new_root, fee) -> StoreSpend`

Spends the current tip coin (`store_tip`, from §7) to recreate the singleton anchoring `new_root` — a
new generation. `store_id` is preserved. The size bucket MAY be re-anchored when the new generation's
size changes bucket; a `modify` that changes the `.dig` size to a different bucket MUST update the
anchored `size_bucket` so §4 stays truthful.

### 3.3 `melt_store(store_tip, owner, fee) -> StoreSpend`

Terminally spends the tip coin with no successor, closing the store. No future generation can be
anchored after a melt.

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

- URN (no chain read for the rootless form):
  - `get_store_urn(store_id) -> String` — the ROOTLESS `urn:dig:chia:<store_id>`; the stable handle
    across all generations.
  - `get_latest_root_urn(chain, store_id) -> String` — `urn:dig:chia:<store_id>:<latest_root>`, the
    capsule URN pinning the latest generation (reads the tip first).
  - `store_urn` / `capsule_urn` / `retrieval_key` format the canonical scheme; `retrieval_key(urn) =
    SHA-256(urn)`, byte-identical to `dig-urn-protocol`.
- On-chain (NC-9):
  - `get_store_did_owner(chain, store_id) -> Option<DidRef>` — the owning DID, resolved by walking the
    launcher's parent spend; `None` for a non-DID mint.
  - `get_store_singleton_tip(chain, store_id) -> StoreTip` — the current confirmed tip coin.
  - `get_root_history(chain, store_id) -> RootHistory` — every anchored root, oldest → newest.
  - `get_latest_root(chain, store_id) -> Bytes32` — the root at the tip.
  - `get_store_label` / `get_store_description` / `get_store_size_bucket` / `get_store_program_hash` —
    the corresponding on-chain metadata field (`Option`, omitted-when-absent).
- Off-chain (`.dig` via `dig-capsule`):
  - `open_capsule(dig_bytes) -> OpenCapsule` — open + self-verify a `.dig`.
  - `get_capsule_identity(capsule) -> (store_id, root_hash)` — the capsule's pinned pair.
  - Further `.dig` properties (manifest, visibility, generation, resource list) are read through the
    `dig-capsule` facade; they are added additively (INV-5).

## 6. Errors

`DigStoreResult<T> = Result<T, DigStoreError>`. Variants: `InvalidSize`, `SizeProofMismatch
{ anchored_k, actual_k, actual_bytes }`, `InvalidUrn`, `Proof`, `Capsule`, `Spend`. Variants are
added additively; an existing variant's meaning never changes.

## 7. The `ChainSource` boundary

On-chain getters are generic over `C: ChainSource`, a caller-supplied source of confirmed coin
spends (`coin_spend(coin_id) -> Option<CoinSpendBytes>`, fail-closed). Lineage walks (owner
discovery, root history) are repeated `coin_spend` lookups. The source MUST be trusted for
custody-grade reads (INV-4 / NC-9 F1). On the compose pass this trait is replaced by the published
`dig_chainsource_interface::ChainSource`.

## 8. Security properties

- Unsigned output only (INV-2): a compromised `dig-store` cannot move funds; it emits spends the
  caller must still authorize.
- On-chain proof (INV-4): a value returned by a getter reflects the chain, not an attacker-chosen
  field. The proof is only as sound as the `ChainSource`; a payment-routing / custody read MUST use a
  trusted source (NC-9 F1).
- Size proof (§4): a size-mismatched `.dig` is discarded, so an attacker cannot make a node cache or
  serve content the store did not commit to.

## 9. Conformance

- The size ladder + byte→bucket mapping match `dig_merkle::SizeBucket` byte-for-byte (test
  `size::tests::ladder_matches_dig_merkle`).
- The URN scheme + retrieval key match `dig-urn-protocol` / the browser verifier.
- Golden `.dig` fixtures of each released format version decode byte-identically (added on the compose
  pass with the `dig-capsule` dependency; INV-5 / CLAUDE.md §5.1).

## 10. Crate hierarchy + publishing

`dig-store` depends on `dig-merkle` + `dig-capsule` (both level `00-foundation`) → it sits ABOVE them
in the crate hierarchy (proposed level `10-primitives`, reference-down-only). It is consumed by
`dig-wallet-backend`, which sits above it. It publishes to crates.io (no git deps); consumers depend
on the crates.io version.

## 11. Scaffold status + compose pass (issue #1247)

This crate is a DESIGN-FIRST scaffold. `dig-merkle 0.3.0` (the `size_bucket` line) and the
single-crate `dig-capsule` (post-#1270 collapse) are NOT yet on crates.io; the `no git deps` rule
(CLAUDE.md §3.6) forbids wiring them before they publish. Therefore:

- **Implemented + tested now:** the `size` ladder + size proof (§4), the `urn` formatting (§5), the
  `error` taxonomy (§6), and the `types` identifier surface. `get_store_urn` is live.
- **Scaffolded (`todo!()`, signatures final):** the lifecycle (§3) and the on-chain / off-chain
  getters (§5/§7). Their dep-gated tests are `#[ignore]`d with the gate reason.

The **compose pass** adds the dependencies and fills the `todo!()`s:

- `dig-merkle = "0.3"` — `mint_datastore`, the `update` / `melt` / `read` / `lineage` operations,
  `resolve_owner_did`, `DigDataStoreMetadata`, `DidRef`, and `SizeBucket` (re-export, replacing the
  local mirror so the ladder lives in ONE place).
- `dig-capsule = "0.3"` — the `capsule` / `format` / `metadata` reader for `open_capsule` + the
  off-chain getters.
- `dig-chainsource-interface` — the canonical `ChainSource` (replaces the local placeholder trait).
- `chia-wallet-sdk` (chip-0035) + `chia-protocol` — `Coin` / `CoinSpend` / `Bytes32` / `SpendBundle`.

### Required upstream APIs (routed to the dig-wallet-backend family)

These must exist on the published deps for the compose pass; some are `dig-merkle` future units:

- `dig_merkle::update::*` — recreate the coin with a new root (SPEC §3.2 there) — for `modify_store`.
- `dig_merkle::melt::*` — terminal spend — for `melt_store`.
- `dig_merkle::read` / `hydrate` / `lineage` — parse tip state + walk lineage — for
  `get_store_singleton_tip` / `get_root_history` / `get_latest_root` / the metadata getters.
- `dig_merkle::read::resolve_owner_did<C: ChainSource>(store_id, chain)` — the DID owner walk
  (currently a `PENDING dig-chainsource-interface` stub in `dig-merkle`) — for `get_store_did_owner`.
- `dig-merkle 0.3.0` published to crates.io with `SizeBucket` exported (currently 0.2.0 is live).
- `dig-capsule` single-crate facade published to crates.io with the `capsule` / `metadata` read
  surface.
