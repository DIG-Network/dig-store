# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-20

### Bug Fixes
- **deps:** Bump dig-merkle 0.4 -> 0.4.3 so the re-exposed lineage getter inherits the
  child_lineage_proof consensus fix (consensus-valid child spend, no AssertMyParentIdFailed) (#1332)

### Features
- **types:** Expose the lineage-getter surface — `child_lineage_proof`, `LineageProof`, `Proof`,
  `DelegatedPuzzle` — so a consumer builds the next spend against a walked store without a separate
  dig-merkle dependency

## [0.3.0] - 2026-07-20

### Features
- **dig-store:** Off-chain capsule getters (open_capsule / get_capsule_identity) (#2)

## [0.2.0] - 2026-07-20

### Features
- Scaffold the dig-store DataLayer store manager (create/modify/melt + size proof) (#1)

### Chores
- Initialize dig-store repo
