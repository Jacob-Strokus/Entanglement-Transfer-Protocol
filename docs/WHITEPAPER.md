# ETP: Entanglement Transfer Protocol — Whitepaper

**Version:** 0.1.0-draft  
**Date:** 2026-02-24  
**Status:** Exploratory Design

---

## Abstract

We propose a data transfer protocol in which no data payload is transmitted between sender and
receiver. Instead, the sender **commits** an immutable, content-addressed representation of the
entity to a distributed commitment layer, transmits a minimal cryptographic **entanglement key**
to the receiver, and the receiver **materializes** the entity through deterministic reconstruction
from distributed shards. The protocol achieves:

- **Sub-latency transfer** — the entanglement key is orders of magnitude smaller than the entity
- **Immutability by design** — every transfer is a permanent, auditable commitment
- **Security without trust** — verification is mathematical, not institutional
- **Geography-independence** — materialization draws from the nearest available shards

---

## 1. The Ontology of Data Transfer

### 1.1 What Is an "Entity"?

In ETP, we do not transfer "files," "packets," or "messages." We transfer **entities**. An entity
is any discrete, self-contained unit of state:

- A document
- A database row
- A video frame sequence
- A machine learning model
- An application state snapshot
- A human identity credential

An entity has three properties:
1. **Content** — the raw information
2. **Shape** — the schema/structure that gives content meaning
3. **Identity** — a unique, deterministic fingerprint derived from content + shape

### 1.2 The Entity Identity Function

Every entity has a deterministic identity:

```
EntityID = H(content || shape || timestamp || sender_pubkey)
```

Where:
- `H` is a collision-resistant hash function (e.g., BLAKE3 or Poseidon for ZK-friendliness)
- `||` denotes concatenation
- `timestamp` is the commitment time (logical clock, not wall clock)
- `sender_pubkey` is the sender's public key, binding identity to origin

This identity is **permanent**. The same content committed by the same sender at the same
logical moment always produces the same identity. Different moment = different entity. This
is not a bug — it is the immutability guarantee.

---

## 2. The Three Phases of Transfer

### Phase 1: COMMIT

The sender does not prepare the entity for transmission. Instead, the sender **commits** the
entity to a distributed commitment layer.

#### 2.1.1 Deterministic Sharding

The entity is decomposed into `n` shards using deterministic erasure coding:

```
shards = ErasureEncode(entity, n, k)
```

Where:
- `n` = total number of shards produced
- `k` = minimum number of shards needed to reconstruct (k < n)
- The encoding is deterministic: same input always produces same shards
- Each shard is content-addressed: `ShardID = H(shard_content || entity_id || shard_index)`

#### 2.1.2 Distributed Shard Placement

Shards are placed across a distributed network of **commitment nodes**. Placement follows a
deterministic algorithm based on the EntityID:

```
placement(shard_i) = ConsistentHash(EntityID || shard_index) → node_set
```

This means:
- Both sender and receiver can independently compute where shards live
- No central registry or lookup service is needed
- Shards are replicated across geographically diverse nodes
- The receiver will materialize from the **nearest** available shards

#### 2.1.3 The Commitment Record

Once shards are distributed, the sender publishes a **commitment record** to an append-only
commitment log (this can be a blockchain, a Merkle DAG, or any immutable append-only structure):

```json
{
  "entity_id": "blake3:7f3a8b...",
  "sender": "ed25519:pubkey...",
  "shard_map_root": "blake3:merkle_root_of_shard_ids",
  "encoding_params": { "n": 64, "k": 32, "algorithm": "reed-solomon-gf256" },
  "shape_hash": "blake3:schema_hash...",
  "timestamp": 1740422400,
  "signature": "ed25519:sig..."
}
```

This record is the **proof that the entity exists and was committed**. It is small (< 1 KB),
immutable, and independently verifiable.

### Phase 2: ENTANGLE

The sender transmits a minimal **entanglement key** to the receiver. This is the only data
that traverses the sender → receiver path directly.

#### 2.2.1 The Entanglement Key

```
EntanglementKey = {
  entity_id,
  commitment_log_reference,
  receiver_decryption_material,
  access_policy
}
```

The entanglement key is:
- **Tiny** — typically 256-512 bytes regardless of entity size
- **Encrypted** — sealed to the receiver's public key
- **Self-authenticating** — contains the commitment reference for verification
- **Policy-bound** — includes access rules (one-time, time-limited, delegatable, etc.)

#### 2.2.2 Key Properties of Entanglement

The entanglement key is **not the data**. It is the **proof of right to reconstruct**. This
creates several remarkable properties:

1. **Size invariance**: Transferring 1 KB and transferring 1 TB produce the same size
   entanglement key (~512 bytes). The "transfer" takes the same time regardless of entity size.

2. **Interception resistance**: An attacker who captures the entanglement key cannot reconstruct
   the entity without also compromising k-of-n commitment nodes AND possessing the receiver's
   private key.

3. **Non-repudiation**: The commitment record on the append-only log proves the sender committed
   the entity. The entanglement key proves the sender authorized the receiver. Both are
   cryptographically signed.

4. **Forward secrecy**: Each entanglement key can use ephemeral key agreement (X25519), so
   compromising long-term keys doesn't expose historical transfers.

### Phase 3: MATERIALIZE

The receiver uses the entanglement key to **reconstruct** the entity from the commitment layer.

#### 2.3.1 Reconstruction Process

```
1. Parse entanglement key → extract entity_id, commitment reference
2. Fetch commitment record from the append-only log
3. Verify commitment record signature (sender authenticity)
4. Compute shard locations: ConsistentHash(entity_id || shard_index) for each shard
5. Fetch k-of-n shards from nearest available commitment nodes (parallel)
6. Verify each shard: ShardID == H(shard_content || entity_id || shard_index)
7. ErasureDecode(shards, k) → entity
8. Verify: H(entity_content || shape || timestamp || sender_pubkey) == entity_id
9. Decrypt entity content using receiver_decryption_material
10. Entity materialized. Transfer complete.
```

#### 2.3.2 Why This Is Fast

Traditional transfer: **move all the data across one path (sender → receiver)**

ETP materialization: **pull k shards in parallel from the nearest nodes in the commitment network**

```
Traditional:    S ═══════════════════════════════════> R
                       (entire payload, one path)

ETP:            S ──(512 bytes)──> R
                                   R <── shard from Node nearby
                                   R <── shard from Node nearby
                                   R <── shard from Node nearby
                                   R <── shard from Node nearby
                                   ...k shards, parallel, nearest-first
```

The bottleneck is no longer the sender's upload speed or the sender-receiver distance.
The bottleneck is the receiver's ability to pull shards from the **nearest commitment nodes**,
which can be geographically local.

---

## 3. Security Model

### 3.1 Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| Man-in-the-middle intercepts entanglement key | Key is encrypted to receiver's public key; useless without private key |
| Attacker compromises commitment nodes | Need k-of-n shards; compromise of < k nodes reveals nothing (information-theoretic security) |
| Sender denies transfer occurred | Commitment record is on immutable append-only log with sender's signature |
| Receiver claims different data was sent | Entity ID is deterministic hash of content; both parties can verify |
| Replay attack (re-use entanglement key) | Access policy can enforce one-time materialization; commitment nodes track access |
| Quantum computing threat | Use post-quantum hash (BLAKE3) and post-quantum signatures (Dilithium); erasure coding is information-theoretic |

### 3.2 Zero-Knowledge Transfer Mode

For maximum privacy, ETP supports a zero-knowledge variant where:

1. The commitment record is encrypted; only the entity_id is public
2. Shard content is encrypted with a key derived from the entity_id + sender's secret
3. The receiver's entanglement key includes the decryption material
4. Commitment nodes store shards but **cannot read them**
5. A ZK-proof accompanies the commitment record proving the entity satisfies certain properties
   (e.g., "this is a valid JSON document" or "this number is in range [0, 1000]") without
   revealing the content

```
CommitmentRecord + ZK-Proof: "I committed a valid entity. Here's the proof. You can verify
without seeing the data."
```

---

## 4. Immutability Guarantees

### 4.1 Why Immutability Is Inherent

ETP doesn't "add" immutability as a feature. Immutability is a **consequence of the design**:

1. **Entity IDs are content-addressed**: Changing one bit changes the EntityID. There is no way
   to modify an entity and keep the same identity.

2. **Commitment records are append-only**: Once published, a commitment cannot be altered or
   deleted. The log is cryptographically chained.

3. **Shards are content-addressed**: A commitment node cannot alter a shard without invalidating
   its ShardID, which would be detected at reconstruction.

4. **Entanglement keys reference specific commitments**: The receiver always materializes the
   exact entity the sender committed. There is no opportunity for mutation in transit.

### 4.2 Versioning vs. Mutation

If a sender wants to "update" an entity, they commit a **new entity** with a reference to the
previous one:

```json
{
  "entity_id": "blake3:new_hash...",
  "predecessor": "blake3:old_hash...",
  "version": 2,
  ...
}
```

This creates an immutable **version chain**. Every version exists permanently. "Updating" is
actually "appending a new version." The full history is always auditable.

---

## 5. Breaking the Constraints

### 5.1 Latency

**Traditional**: Latency = f(distance, hops, payload_size)  
**ETP**: Latency = f(entanglement_key_transmission) + f(nearest_shard_fetch)

Since the entanglement key is ~512 bytes, its transmission is near-instantaneous on any network.
Shard fetching is parallelized from the nearest nodes. Effective latency approaches the **local
network latency** of the commitment network, regardless of where the sender is.

### 5.2 Geographic Distance

**Traditional**: New York → Tokyo = ~200ms minimum (speed of light through fiber)  
**ETP**: If commitment nodes exist near Tokyo, shards are fetched locally. The sender in New York
transmits only a 512-byte entanglement key. The receiver in Tokyo materializes from local shards.

The geographic cost is paid **once** when shards are distributed to the commitment network (and
this happens asynchronously). Subsequent transfers to any receiver anywhere effectively have
**local latency**.

### 5.3 Computing Power

**Traditional**: Sender must serialize, compress, encrypt, and transmit. Receiver must receive,
decrypt, decompress, and deserialize. Both need sufficient compute.  
**ETP**: The heavy work (erasure encoding, shard distribution) is done once at commit time and
can be offloaded to the commitment network. Materialization (erasure decoding from k shards) is
computationally lightweight and highly parallelizable.

---

## 6. Comparison with Existing Approaches

| Property | TCP/IP | IPFS | Blockchain | BitTorrent | **ETP** |
|----------|--------|------|-----------|------------|---------|
| Payload travels sender→receiver | Yes | Partial | No (ledger only) | Partial | **No** |
| Content-addressed | No | Yes | Yes | Partial | **Yes** |
| Immutable | No | Yes | Yes | No | **Yes** |
| Size-invariant transfer | No | No | N/A | No | **Yes** |
| Built-in access control | No | No | Partial | No | **Yes** |
| Forward secrecy | TLS layer | No | No | No | **Yes** |
| ZK privacy mode | No | No | Some chains | No | **Yes** |
| Survives sender going offline | No | If pinned | Yes | If seeded | **Yes** |
| Receiver proximity optimization | No | Partial | N/A | Partial | **Yes** |

---

## 7. Use Cases

### 7.1 Instant Large File Transfer
A 50 GB dataset is committed once. Any number of receivers can materialize it instantly by
receiving a 512-byte entanglement key. The "transfer" time for each receiver is dominated by
local shard fetching, not by the sender's bandwidth.

### 7.2 Immutable Audit Trail
Every data transfer is permanently recorded. A compliance system can verify: "Entity X was
committed by Sender A at time T and entangled with Receiver B." No party can deny or alter this.

### 7.3 Secure Messaging
A message is committed and entangled. The entanglement key is the message notification. The
content never traverses the public internet as a readable payload. Even if intercepted, the
entanglement key alone is useless.

### 7.4 State Synchronization
Two distributed systems synchronize state by exchanging entanglement keys. Each system materializes
the other's state from the commitment network. This is faster than traditional replication because
shards are fetched locally, and only the delta (new entity) needs materialization.

### 7.5 Cross-Planetary Data Transfer
On a Mars colony with 4-24 minute light delay to Earth: commitment nodes on Mars cache shards.
A sender on Earth commits an entity. The 512-byte entanglement key crosses the void once. The
receiver on Mars materializes from Mars-local commitment nodes (which replicate shards during
off-peak periods). Effective perceived transfer time: near-instantaneous.

---

## 8. Open Questions

1. **Commitment network economics**: How are commitment nodes incentivized to store and serve shards?
2. **Shard eviction**: When can shards be garbage collected? (Never? After TTL? After all authorized
   receivers materialize?)
3. **Commitment log consensus**: What consensus mechanism secures the append-only log? (Does it need
   full BFT, or is a lighter mechanism sufficient?)
4. **Bandwidth for initial shard distribution**: The commit phase still requires distributing n 
   shards. Can this be amortized or pipelined?
5. **Real-time streaming**: Can ETP support continuous entity streams (video, telemetry), or is it
   inherently batch-oriented?

---

## 9. Conclusion

ETP inverts the data transfer paradigm. Rather than asking "how do I send this data to you," it
asks "how do I prove this data exists, and give you the right to reconstruct it near you."

The result is a protocol where:
- **Transfer size is constant** regardless of entity size
- **Transfer is immutable** by mathematical construction, not policy
- **Security is cryptographic** not perimeter-based
- **Geography is irrelevant** because materialization is local
- **The sender can go offline** after commitment without affecting the transfer

Data doesn't move. Proof moves. Truth materializes.

---

*ETP v0.1.0-draft — Entanglement Transfer Protocol*
