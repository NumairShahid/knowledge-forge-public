# P4-P1-P1-P3-P6 — Same-descriptor, bounded binary identity and dependency hints

**REVIEW ONLY — NOT NATIVE HOST TEST AUTHORIZATION.** No Claude/Codex launches, interpreter execution, host hooks, model calls, package-manager invocation, credential or configuration reads, external network, tool grants, or deployment.

## Why this separate cut exists

P3-P1's 256 MiB (268,435,456-byte) full-file SHA-256 limit refused the TNG Codex candidate (292,309,256 bytes). That original P3-P1 policy and file remain **untouched**. P3-P2 and P3-P3 captured bounded metadata and ELF hints but could not bind them to a complete Codex digest. P3-P4 recorded all nine native-runtime gates unverified; P3-P5 named P6 as the next offline evidence gate.

P6 introduces a **distinct 320 MiB (335,544,320-byte) snapshot-only full-hash policy** for the first PATH candidate. It never removes or relaxes the prior 256 MiB limit. Its Python module reads the candidate executable with an `O_NOFOLLOW` final file descriptor, in 1 MiB or smaller chunks, refuses unsafe mode, oversized/nonregular/empty files, and checks device/inode/size/ownership/mode/ctime/mtime before and after hashing. It uses the previously reviewed bounded P3-P3 ELF parser on **the same file descriptor** to record `DT_NEEDED` **name hints**. ELF reads have an additional 98,304-byte bound. No dynamic loader, `ldd`, `readelf`, host binary, package manager, or network program runs.

Before and after reading, the module observes bounded PATH candidate, direct executable-link destination, resolved path and path-component `lstat` metadata (up to 48 components and 16 direct symlinks). An observed `current` symlink is reported as a symlink, **not** a `0777` directory-write permission. Directory group/world write *mode bits* are merely hints: effective access and ACLs are unverified. Metadata checks reduce accidental mismatch but are **not an atomic freeze, dirfd-based secure walker, immutable inode lease, or defense against deliberate same-metadata races**. A successfully hashed file may change immediately afterward or be replaced by a new PATH or symlink target.

## Evidence versus missing proof

- `PASSIVE_P6_DIGEST_AND_ELF_SNAPSHOT_NOT_ATTESTATION` means a complete-file SHA-256 and bounded ELF hints were captured from one observed file descriptor. It **does not** verify supply-chain signer, official installer, signature, file immutability after observation, full runtime dependency closure, interpreter/library mapping, `dlopen` dependencies, model/non-tool behavior, host hook selection, or native sandbox enforcement.
- `BLOCKED_P6_IDENTITY_NOT_PROVEN` is a refusal and carries no digest, private paths or raw exception strings. `UNRESOLVED_NO_EXECUTION` means the command was not found.
- ELF `DT_NEEDED` entries, even if observed, do not identify exact loader-selected versions or transitive dependencies. `NO_DT_NEEDED_OBSERVED` is **not proof of no dependencies or static linkage**. Claude's earlier `DYNSTR_BOUND_OR_ADDRESS_REFUSED` must not be silently upgraded to successful parsing.
- A hash is evidence for an executable snapshot only, not authentication or installation provenance. No nine-gate native proof is automatically promoted. The P7 hermetic fixture, P8 hook trust, P9 explicit approval packet, and P10 separately authorized actual-native test remain ahead.

Run the exact review cut on TNG with the delivered `.sh` wrapper. The module itself also supports:

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_portable_native_binary_dossier
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_binary_dossier --host claude-code --mode DOSSIER_ONLY
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m knowledge_forge.portable_native_binary_dossier --host codex-cli --mode DOSSIER_ONLY
```

**Laws:** `VALIDATED != PROMOTED`; `REVIEWED != AUTHENTICATED`; `KNOWLEDGE != AUTHORITY`.
