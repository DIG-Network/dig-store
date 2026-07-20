# dig-store

The DIG Network **DataLayer store manager**. A *store* is the composition of two planes:

- an **on-chain anchor** — a CHIP-0035 DataLayer singleton (owned by
  [`dig-merkle`](https://github.com/DIG-Network/dig-merkle)) whose metadata carries the `.dig` merkle
  root plus label / description / size bucket / program hash; and
- an **off-chain data plane** — the `.dig` capsule format (owned by
  [`dig-capsule`](https://github.com/DIG-Network/dig-capsule)).

`dig-store` composes the two into ONE curated abstraction with three concerns:

1. **Lifecycle** — a store is a coin that gets SPENT: `create_store`, `modify_store`, `melt_store`.
   Each returns an UNSIGNED spend; the wallet-backend / node signs + broadcasts. `dig-store` never
   holds a key, never signs, never dials the network.
2. **Size proof** — a store anchors its `.dig` SIZE on chain as a power-of-2 `SizeBucket`
   (1 MB..1 GB). Before keeping a downloaded `.dig`, a client runs `SizeProof::verify`; a real size
   that does not match the anchored bucket is **discarded** — a dig-node must not store or serve a
   size-mismatched capsule.
3. **Getters** — a comprehensive, chain-proven read surface over every on-chain property (tip, ordered
   root history, latest root, owner DID, and the label / description / size / program-hash metadata).

The lifecycle + getters compose `dig-merkle` (the CHIP-0035 DataLayer coin expert) over the canonical
`dig-chainsource-interface` chain reader; the URN scheme delegates to `dig-urn-protocol`. dig-store
adds no on-chain bytes and re-exports the coin/identity types verbatim, so a consumer depends on ONE
canonical shape.

See [`SPEC.md`](./SPEC.md) for the normative contract.

## Off-chain capsule getters — deferred (issue #1247)

`open_capsule` / `get_capsule_identity` are not in this version: `dig-capsule 0.4.0` exposes no
lightweight `bytes → (store_id, root_hash)` reader (the only path is the full wasmtime serve runtime).
They land once `dig-capsule` ships a `Capsule::from_module_bytes` reader (release-first). The
download-gating size proof needs no capsule open and is complete now. See SPEC §11.

## Install

```toml
[dependencies]
dig-store = "0.2"
```

## License

Licensed under either of Apache-2.0 or MIT at your option.
