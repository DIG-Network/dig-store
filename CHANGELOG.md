# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.5.0] - 2026-07-20

### Features
- **dig-store:** Aggregate on-chain `get_store_status() -> StoreStatus` from a single consistent
  lineage walk (NC-9 chain-read surface, #1336). Adds `StoreStatus` / `StoreStatusKind` /
  `Confirmations` (Serialize + Deserialize) and `DEFAULT_CONFIRMATION_TARGET`. `confirmations` +
  `verified` derive from ONE supplementary read on the already-resolved tip (never a second walk);
  a walk-Live-vs-coin-record-spent contradiction fails closed. `head_signature` ships present-but-
  `None` (structurally unavailable through `ChainSource`; a routed follow-up sources it out-of-band).
  Additive: the internal lineage walk was refactored to a `WalkOutcome` enum with every existing
  getter behavior-preserved.

## [0.4.0] - 2026-07-20

### Chores
- **deps:** Bump dig-merkle 0.4 -> 0.4.3 (child_lineage_proof consensus fix, #1332) (#3)

## [0.3.0] - 2026-07-20

### Features
- **dig-store:** Off-chain capsule getters (open_capsule / get_capsule_identity) (#2)

## [0.2.0] - 2026-07-20

### Features
- Scaffold the dig-store DataLayer store manager (create/modify/melt + size proof) (#1)

### Chores
- Initialize dig-store repo


