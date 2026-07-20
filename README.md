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
3. **Getters** — a comprehensive, chain-proven read surface over every on-chain and off-chain
   property.

See [`SPEC.md`](./SPEC.md) for the normative contract.

## Status — design-first scaffold (issue #1247)

`dig-merkle 0.3.0` and the single-crate `dig-capsule` are not yet on crates.io, and the DIG Network
`no git deps` rule forbids wiring them before they publish. So the composition surface (lifecycle +
getters) is scaffolded with `todo!()` bodies whose **signatures are final**, while the pure,
self-contained logic is fully implemented + tested now:

- the **size ladder + size proof** (`dig_store::size`);
- the **URN formatting** (`dig_store::urn`);
- the **error taxonomy + identifier types**.

The compose pass adds the `dig-merkle` / `dig-capsule` / `chia-*` dependencies and fills the
`todo!()`s — see SPEC §11.

## Install

```toml
[dependencies]
dig-store = "0.1"
```

## License

Licensed under either of Apache-2.0 or MIT at your option.
