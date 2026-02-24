# ETP Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     ENTANGLEMENT TRANSFER PROTOCOL                      │
│                                                                         │
│  ┌──────────┐    512 bytes     ┌──────────┐                            │
│  │  SENDER  │ ──────────────── │ RECEIVER │                            │
│  │          │  entanglement    │          │                            │
│  └────┬─────┘      key        └────┬─────┘                            │
│       │                             │                                   │
│       │ COMMIT                      │ MATERIALIZE                       │
│       │ (shards)                    │ (fetch k-of-n)                    │
│       ▼                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    COMMITMENT LAYER                              │   │
│  │                                                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │              COMMITMENT LOG (Append-Only)                  │  │   │
│  │  │                                                            │  │   │
│  │  │  Record 1 ← Record 2 ← Record 3 ← ... ← Record N        │  │   │
│  │  │  (cryptographic chain — each record references previous)   │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  │                                                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │              COMMITMENT NODES (Shard Storage)              │  │   │
│  │  │                                                            │  │   │
│  │  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐          │  │   │
│  │  │  │ N1  │  │ N2  │  │ N3  │  │ N4  │  │ N5  │  ...     │  │   │
│  │  │  │     │  │     │  │     │  │     │  │     │          │  │   │
│  │  │  │ s1  │  │ s2  │  │ s1  │  │ s3  │  │ s2  │          │  │   │
│  │  │  │ s4  │  │ s5  │  │ s3  │  │ s6  │  │ s4  │          │  │   │
│  │  │  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘          │  │   │
│  │  │       (shards distributed via consistent hashing)        │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Entity Engine

The Entity Engine is the sender-side component that prepares entities for commitment.

```
┌─────────────────────────────────────────────┐
│              ENTITY ENGINE                    │
│                                               │
│  ┌─────────────┐    ┌──────────────────┐    │
│  │   Content    │    │   Shape Analyzer  │    │
│  │   Ingester   │───▶│   (schema detect) │    │
│  └─────────────┘    └────────┬─────────┘    │
│                               │               │
│                    ┌──────────▼─────────┐    │
│                    │  Identity Computer  │    │
│                    │  H(content||shape|| │    │
│                    │    time||pubkey)    │    │
│                    └──────────┬─────────┘    │
│                               │               │
│                    ┌──────────▼─────────┐    │
│                    │  Erasure Encoder   │    │
│                    │  (n shards, k min) │    │
│                    └──────────┬─────────┘    │
│                               │               │
│                    ┌──────────▼─────────┐    │
│                    │  Shard Distributor │    │
│                    │  (consistent hash) │    │
│                    └──────────┬─────────┘    │
│                               │               │
│                    ┌──────────▼─────────┐    │
│                    │  Commitment Writer │    │
│                    │  (append to log)   │    │
│                    └───────────────────-┘    │
└─────────────────────────────────────────────┘
```

### 2. Entanglement Key Generator

After commitment, the sender produces the entanglement key for the receiver.

```
┌──────────────────────────────────────────────────────┐
│           ENTANGLEMENT KEY GENERATOR                   │
│                                                        │
│  Inputs:                                               │
│  ├── entity_id (from commitment)                       │
│  ├── commitment_log_ref (pointer to record)            │
│  ├── receiver_pubkey (destination identity)             │
│  └── access_policy (rules for materialization)          │
│                                                        │
│  Process:                                              │
│  1. Generate ephemeral X25519 keypair                   │
│  2. Derive shared secret with receiver_pubkey           │
│  3. Encrypt decryption material with shared secret      │
│  4. Pack: entity_id + log_ref + encrypted_material      │
│  5. Sign with sender's Ed25519 key                      │
│                                                        │
│  Output:                                               │
│  └── EntanglementKey (256-512 bytes, sealed)            │
└──────────────────────────────────────────────────────┘
```

### 3. Materialization Engine

The receiver-side component that reconstructs entities.

```
┌─────────────────────────────────────────────────────────────┐
│                 MATERIALIZATION ENGINE                        │
│                                                               │
│  ┌────────────────┐   ┌──────────────────────┐              │
│  │ Key Decryptor   │──▶│ Commitment Verifier   │              │
│  │ (unseal key,    │   │ (fetch & verify       │              │
│  │  extract refs)  │   │  commitment record)   │              │
│  └────────────────┘   └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Shard Locator        │              │
│                        │  (compute locations   │              │
│                        │   via consistent hash) │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Parallel Fetcher     │              │
│                        │  (fetch k-of-n from   │              │
│                        │   nearest nodes)       │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│           ┌───────────────────────┼───────────────┐          │
│           ▼            ▼          ▼         ▼     ▼          │
│        [shard1]    [shard2]   [shard3]  [shard4] ...         │
│           │            │          │         │                 │
│           └───────────────────────┼───────────────┘          │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Shard Verifier       │              │
│                        │  (verify each shard   │              │
│                        │   against ShardID)    │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Erasure Decoder      │              │
│                        │  (reconstruct from    │              │
│                        │   k verified shards)  │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Entity Verifier      │              │
│                        │  (H(entity) ==        │              │
│                        │   entity_id?)         │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                                   ▼                           │
│                           ✓ ENTITY MATERIALIZED              │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Commitment Network Topology

```
                    ┌─────────────────────┐
                    │   COMMITMENT LOG    │
                    │   (Global, Shared,  │
                    │    Append-Only)     │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
         │ Region  │   │ Region  │   │ Region  │
         │   A     │   │   B     │   │   C     │
         │(US-East)│   │(EU-West)│   │(AP-East)│
         └────┬────┘   └────┬────┘   └────┬────┘
              │              │              │
        ┌─────┼─────┐  ┌────┼────┐   ┌────┼────┐
        │     │     │  │    │    │   │    │    │
       ┌▼┐  ┌▼┐  ┌▼┐ ┌▼┐  ┌▼┐ ┌▼┐ ┌▼┐  ┌▼┐ ┌▼┐
       │N│  │N│  │N│ │N│  │N│ │N│ │N│  │N│ │N│
       │1│  │2│  │3│ │4│  │5│ │6│ │7│  │8│ │9│
       └─┘  └─┘  └─┘ └─┘  └─┘ └─┘ └─┘  └─┘ └─┘

       Commitment nodes store shards and replicate
       within and across regions. Receivers fetch
       from nearest nodes.
```

---

## 5. Transfer Flow (Sequence)

```
 Sender                    Commitment Layer              Receiver
   │                             │                          │
   │  1. Compute EntityID        │                          │
   │  2. Erasure encode → shards │                          │
   │  3. Distribute shards ─────▶│                          │
   │                             │  (shards stored on       │
   │  4. Write commitment ──────▶│   commitment nodes)      │
   │     record to log           │                          │
   │                             │  (record appended        │
   │  5. Generate entanglement   │   to immutable log)      │
   │     key for receiver        │                          │
   │                             │                          │
   │  6. Send entanglement key ──────────────────────────▶ │
   │     (~512 bytes)            │                          │
   │                             │                          │
   │  ✓ Sender done.             │          7. Unseal key   │
   │    Can go offline.          │          8. Fetch record  │
   │                             │◀──────── 9. Verify record│
   │                             │                          │
   │                             │◀────── 10. Fetch k shards│
   │                             │──────▶   (parallel,      │
   │                             │           nearest nodes)  │
   │                             │                          │
   │                             │       11. Verify shards   │
   │                             │       12. Erasure decode  │
   │                             │       13. Verify entity   │
   │                             │                          │
   │                             │       ✓ ENTITY            │
   │                             │         MATERIALIZED      │
```

---

## 6. Security Layers

```
┌──────────────────────────────────────────────────┐
│                 SECURITY STACK                     │
│                                                    │
│  Layer 5: ACCESS POLICY                            │
│  ├── One-time materialization                      │
│  ├── Time-bounded access                           │
│  ├── Delegatable permissions                       │
│  └── Revocable entanglement                        │
│                                                    │
│  Layer 4: ZERO-KNOWLEDGE (Optional)                │
│  ├── ZK-proofs on commitment records               │
│  ├── Encrypted shards (nodes can't read)           │
│  └── Verifiable computation on hidden data         │
│                                                    │
│  Layer 3: FORWARD SECRECY                          │
│  ├── Ephemeral X25519 key agreement                │
│  ├── Per-transfer encryption keys                  │
│  └── No long-term key compromise exposure          │
│                                                    │
│  Layer 2: CRYPTOGRAPHIC INTEGRITY                  │
│  ├── Content-addressed entities (BLAKE3)           │
│  ├── Content-addressed shards (BLAKE3)             │
│  ├── Ed25519 signatures on commitments             │
│  └── Merkle tree over shard set                    │
│                                                    │
│  Layer 1: INFORMATION-THEORETIC SECURITY           │
│  ├── Erasure coding (k-of-n threshold)             │
│  ├── Shard compromise < k reveals nothing          │
│  └── Distributed across independent nodes          │
│                                                    │
└──────────────────────────────────────────────────┘
```

---

## 7. Data Flow Summary

| Stage | Data Size | Who Performs | Network Cost |
|-------|-----------|-------------|-------------|
| Entity → Shards | O(entity) | Sender | None (local) |
| Shards → Nodes | O(entity × replication) | Sender → Network | Amortized, async |
| Commitment Record | O(1) ~1KB | Sender → Log | Minimal |
| Entanglement Key | O(1) ~512B | Sender → Receiver | **Near zero** |
| Shards → Entity | O(entity) | Network → Receiver | Local fetches |

**Critical insight**: The sender-to-receiver path carries O(1) data. The O(entity) work
happens between sender↔network and network↔receiver, where "network" means **nearby nodes**.

---

## 8. Technology Choices

| Component | Recommended | Rationale |
|-----------|------------|-----------|
| Hash function | BLAKE3 | Fast, secure, parallelizable, ZK-friendly |
| Signatures | Ed25519 / Dilithium | Ed25519 for speed; Dilithium for post-quantum |
| Key exchange | X25519 | Proven, fast ephemeral key agreement |
| Erasure coding | Reed-Solomon GF(2^8) | Well-understood, deterministic, efficient |
| Commitment log | Merkle DAG / append-only ledger | Immutable, verifiable, decentralizable |
| Shard placement | Consistent hashing (jump hash) | Deterministic, balanced, minimal disruption |
| Shard encryption | XChaCha20-Poly1305 | AEAD, fast, nonce-misuse resistant |
