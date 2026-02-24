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

- **Decoupled transfer** — the sender→receiver path carries only a ~1,300-byte sealed key (ML-KEM-768), independent of entity size. Total system bandwidth is O(entity × replication), but the direct-path bottleneck is eliminated.
- **Immutability by design** — every transfer is a permanent, auditable commitment
- **Security without trust** — verification is mathematical, not institutional
- **Geography-optimized materialization** — the receiver fetches shards from the nearest available nodes, converting a long-haul transfer into parallel local fetches

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

The entity is decomposed into `n` shards using deterministic erasure coding,
then each shard is encrypted with a random Content Encryption Key (CEK):

```
plaintext_shards = ErasureEncode(entity, n, k)
CEK = random(256 bits)
encrypted_shards = [AEAD_Encrypt(CEK, shard, nonce=index) for index, shard in enumerate(plaintext_shards)]
```

Where:
- `n` = total number of shards produced
- `k` = minimum number of shards needed to reconstruct (k < n)
- The encoding is deterministic: same input always produces same shards
- `CEK` = a random 256-bit Content Encryption Key, unique per entity
- Each shard is encrypted with AEAD (authenticated encryption) before distribution
- Commitment nodes store **only ciphertext** — they cannot read shard content
- Each encrypted shard is integrity-checked: `ShardHash = H(encrypted_shard || entity_id || shard_index)`

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
  "sender": "ml-dsa-65:verification_key...",
  "shard_map_root": "blake3:merkle_root_of_encrypted_shard_hashes",
  "encoding_params": { "n": 64, "k": 32, "algorithm": "reed-solomon-gf256" },
  "shape_hash": "blake3:schema_hash...",
  "timestamp": 1740422400,
  "signature": "ml-dsa-65:sig...  (3,309 bytes, quantum-resistant)"
}
```

Critical security property: the commitment record contains **no individual shard IDs**.
Only a Merkle root of hashes of **encrypted** shards is stored. This reveals nothing
about the plaintext content — they are hashes of ciphertext.

The record is the **proof that the entity exists and was committed**. It is small (< 1 KB),
immutable, and independently verifiable.

### Phase 2: ENTANGLE

The sender transmits a minimal **entanglement key** to the receiver. This is the only data
that traverses the sender → receiver path directly.

#### 2.2.1 The Entanglement Key

The entanglement key contains exactly **three secrets** and a policy:

```
EntanglementKey = {
  entity_id,              // 32 bytes — which entity to materialize
  content_encryption_key, // 32 bytes — CEK to decrypt shards
  commitment_ref,         // 32 bytes — hash of commitment record
  access_policy           // ~20-50 bytes — materialization rules
}
```

Critically, the key does **NOT** contain:
- `shard_ids` — receiver derives shard locations from `entity_id` via consistent hashing
- `encoding_params` — receiver reads these from the commitment record
- `sender_id` — receiver reads this from the commitment record

The entire key is **sealed** via ML-KEM-768 (FIPS 203) key encapsulation. Each seal
operation generates a fresh encapsulation, providing forward secrecy per transfer.

The entanglement key is:
- **Minimal** — ~160 bytes inner payload, ~1,300 bytes sealed, regardless of entity size
- **Sealed** — ML-KEM encapsulated to the receiver's encapsulation key (quantum-resistant)
- **Self-authenticating** — contains the commitment reference for verification
- **Policy-bound** — includes access rules (one-time, time-limited, delegatable, etc.)
- **Opaque** — an interceptor sees only random bytes (no metadata leaks)
- **Post-quantum** — ML-KEM-768 resists both classical and quantum adversaries

#### 2.2.2 Key Properties of Entanglement

The entanglement key is **not the data**. It is the **proof of right to reconstruct**. This
creates several remarkable properties:

1. **Sender→receiver decoupling**: Transferring 1 KB and transferring 1 TB produce the same
   size sealed entanglement key (~1,300 bytes). The sender→receiver direct transmission is O(1).
   Note: total system bandwidth is O(entity × replication) across the commit and materialize
   phases. The advantage is not bandwidth elimination — it is *bottleneck relocation*: the
   sender-receiver path (often the slowest link) is reduced to a constant, and the O(entity)
   work shifts to the receiver↔network path, which can be geographically optimized.

2. **Three-layer interception resistance**: An attacker faces three independent barriers:
   - **Layer 1 (Sealed envelope)**: The key is encrypted to the receiver's public key;
     intercepting it yields opaque ciphertext with no metadata
   - **Layer 2 (Encrypted shards)**: Even if an attacker queries the commitment network
     directly, all shards are AEAD-encrypted; without the CEK, they are useless
   - **Layer 3 (Minimal log)**: The commitment log contains only a Merkle root of
     ciphertext hashes — no individual shard IDs, no content, no CEK

3. **Non-repudiation**: The commitment record on the append-only log proves the sender committed
   the entity. The entanglement key proves the sender authorized the receiver. Both are
   cryptographically signed.

4. **Forward secrecy**: Each entanglement key uses a fresh ML-KEM-768 encapsulation, producing
   a unique (shared_secret, ciphertext) pair per seal. The shared_secret is used once for AEAD
   encryption and then immediately zeroized. Compromising the receiver's decapsulation key
   after the shared_secret has been destroyed does not expose historical transfers.

   **Forward secrecy lifecycle:**
   1. `seal()` calls ML-KEM.Encaps(receiver_ek) → fresh (ss, kem_ct)
   2. ss is used as the AEAD key for the payload, then zeroized in memory
   3. kem_ct is embedded in the sealed output
   4. Only the holder of dk can recover ss from kem_ct (Module-LWE hardness)
   5. After the receiver processes the sealed key and zeroizes ss, the shared
      secret is unrecoverable — even if dk is later compromised
   6. For defense-in-depth, receivers SHOULD rotate ek/dk periodically;
      old dk values MUST be securely destroyed after rotation

### Phase 3: MATERIALIZE

The receiver uses the entanglement key to **reconstruct** the entity from the commitment layer.

#### 2.3.1 Reconstruction Process

```
1. Unseal entanglement key with receiver's private key → extract entity_id, CEK, commitment_ref
2. Fetch commitment record from append-only log using entity_id
3. Verify commitment record: H(record) == commitment_ref (integrity check)
4. Verify commitment record signature (sender authenticity)
5. Read encoding params (n, k) from commitment record
6. Derive shard locations: ConsistentHash(entity_id || shard_index) for index in 0..n-1
7. Fetch k-of-n ENCRYPTED shards from nearest available commitment nodes (parallel)
8. Decrypt each shard: AEAD_Decrypt(CEK, encrypted_shard, nonce=shard_index)
   — AEAD authentication tag is verified BEFORE decryption (tamper detection)
9. ErasureDecode(decrypted_shards, k) → entity content
10. Verify: H(entity_content || shape || timestamp || sender_pubkey) == entity_id
11. Entity materialized. Transfer complete.
```

#### 2.3.2 Why This Is Fast

Traditional transfer: **move all the data across one path (sender → receiver)**

ETP materialization: **pull k shards in parallel from the nearest nodes in the commitment network**

```
Traditional:    S ════════════════(entire payload)════════════════> R
                  Bottleneck: sender upload × distance to receiver

ETP:            S ──(~1,300B sealed key)──> R
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          ...k shards, parallel, nearest-first
```

**Important nuance:** The total bytes moved across the system is *greater* than direct
transfer — the commit phase uploads O(entity × replication_factor) to the network, and the
materialize phase downloads O(entity) from it. ETP does not eliminate bandwidth; it
**relocates the bottleneck**:

- The sender→receiver path (often the slowest, highest-latency link) shrinks to O(1)
- The O(entity) work shifts to receiver↔nearby-nodes, which can be geographically local
- The commit-phase bandwidth is amortized: committed once, materialized by many receivers

The win is not "less bandwidth" — it is **faster perceived transfer** via parallelism,
geographic locality, and sender-independence. For fan-out scenarios (one sender, many
receivers), the amortized cost approaches O(entity) total regardless of receiver count,
whereas direct transfer costs O(entity × receiver_count).

---

## 3. Security Model

### 3.1 Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| Man-in-the-middle intercepts entanglement key | Entire key is sealed (envelope-encrypted) to receiver's public key; interceptor sees opaque ciphertext with zero metadata |
| Attacker scrapes commitment log | Log contains only Merkle root of encrypted shard hashes — no shard IDs, no content, no CEK |
| Attacker fetches shards from nodes | Shards are AEAD-encrypted with CEK; without CEK, ciphertext is computationally useless |
| Attacker compromises < k nodes | Information-theoretic security: < k shards (even decrypted) reveal zero information about the entity |
| Sender denies transfer occurred | Commitment record is on immutable append-only log with sender's signature |
| Receiver claims different data was sent | Entity ID is deterministic hash of content; both parties can verify |
| Replay attack (re-use entanglement key) | Access policy can enforce one-time materialization; commitment nodes track access |
| Quantum computing threat | **Full post-quantum security**: ML-KEM-768 (FIPS 203) for key encapsulation, ML-DSA-65 (FIPS 204) for signatures, BLAKE2b/BLAKE3 for hashing (quantum-resistant), erasure coding is information-theoretic (quantum-immune). No X25519 or Ed25519 in the protocol. |

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
**ETP**: Latency = f(key_transmission) + f(nearest_shard_fetch)

The sealed entanglement key is ~1,300 bytes (increased from ~240 bytes pre-quantum due to
ML-KEM-768 ciphertext overhead — the honest cost of quantum resistance). Its transmission
is near-instantaneous on any network. Shard fetching is parallelized from the nearest nodes.

**What this means precisely:**
- The sender→receiver latency is reduced to O(1) (the key is constant-size)
- The materialization latency depends on the receiver's proximity to commitment nodes
- If commitment nodes exist near the receiver, effective latency approaches local RTT
- If no nearby nodes exist, shard fetching still incurs geographic latency

**What this does NOT mean:** Total time is not "near-instantaneous" for large entities.
The receiver still downloads O(entity) bytes of encrypted shards. The advantage is that
this download is from *nearby nodes* in parallel, not from a distant sender over a single
path.

### 5.2 Geographic Distance

**Traditional**: New York → Tokyo = ~200ms RTT minimum (speed of light through fiber).  
For a 1 GB file at 100 Mbps effective throughput: ~80 seconds, bottlenecked by the single path.

**ETP**: The sender in New York transmits a ~1,300-byte sealed key to the receiver in Tokyo
(one round trip, ~200ms). The receiver then fetches k encrypted shards in parallel from
Tokyo-local commitment nodes (~5-10ms RTT each). Materialization time is dominated by
*local bandwidth*, not transoceanic latency.

The geographic cost is paid **once** when shards are distributed to the commitment network
during the commit phase (this happens asynchronously, before any receiver is involved).
Subsequent materializations by any receiver anywhere draw from *nearby nodes*.

**Honest tradeoff:** The commit phase requires distributing O(entity × replication) bytes
across the global network. For a single sender → single receiver transfer, total system
bandwidth is higher than direct transfer. The advantage appears in:
- **Fan-out:** one commit, many receivers — amortized cost per receiver approaches zero
- **Latency:** receiver-local fetches vs. sender-distance fetches
- **Sender-independence:** sender can go offline after commit

### 5.3 Computing Power

**Traditional**: Sender must serialize, compress, encrypt, and transmit. Receiver must receive,
decrypt, decompress, and deserialize. Both need sufficient compute.  
**ETP**: The heavy work (erasure encoding, shard distribution) is done once at commit time and
can be offloaded to the commitment network. Materialization (erasure decoding from k shards) is
computationally lightweight and highly parallelizable.

### 5.4 Formal Cost Model

Let:
- $D$ = entity size in bytes
- $n$ = total shards, $k$ = reconstruction threshold
- $r$ = replication factor per shard
- $N$ = number of receivers
- $L_{SR}$ = latency between sender and receiver
- $L_{RN}$ = latency between receiver and nearest commitment node

**Bandwidth costs:**

| Metric | Direct Transfer | ETP |
|--------|----------------|-----|
| Sender upload (per transfer) | $D$ | — (already committed) |
| Sender upload (commit, once) | — | $D \cdot r$ |
| Sender→receiver direct | $D$ | $O(1)$ (~1,300 bytes) |
| Receiver download | $D$ | $D$ (k shards × $D/k$) |
| **Total system, 1 receiver** | $D$ | $D \cdot r + D \approx D(r+1)$ |
| **Total system, N receivers** | $D \cdot N$ | $D \cdot r + D \cdot N$ |
| **Amortized per receiver (N large)** | $D$ | $\approx D$ |

**Key formula — total system bandwidth:**

$$B_{ETP}(N) = D \cdot r + D \cdot N$$
$$B_{direct}(N) = D \cdot N$$

For $N = 1$: $B_{ETP} = D(r+1) > D = B_{direct}$. **ETP is strictly worse for single-transfer bandwidth.**

For $N > r$: $B_{ETP} \approx D \cdot N \approx B_{direct}$. **ETP amortizes to parity.**

For large $N$: The commit cost $D \cdot r$ becomes negligible. Each additional receiver costs only
$D$ (local shard fetches) + ~1,300 bytes (sealed key). Sender bandwidth is constant after commit.

**Latency costs:**

$$T_{direct} = L_{SR} + \frac{D}{\text{bandwidth}_{SR}}$$

$$T_{ETP} = \underbrace{\frac{1300}{\text{bandwidth}_{SR}}}_{\text{key (negligible)}} + \underbrace{\frac{D/k}{\text{bandwidth}_{RN}}}_{\text{k parallel shard fetches}}$$

When $\text{bandwidth}_{RN} \gg \text{bandwidth}_{SR}$ (receiver is near commitment nodes but far from
sender), $T_{ETP} \ll T_{direct}$. This is the latency advantage.

When $\text{bandwidth}_{RN} \approx \text{bandwidth}_{SR}$ (everything is equidistant), $T_{ETP} \approx T_{direct}$
but with the sender free to go offline.

**Where ETP wins honestly:**
1. Fan-out: $N$ receivers for near-constant sender cost
2. Latency: receiver-local fetches vs. sender-distance fetches
3. Sender-independence: sender contributes zero bandwidth after commit
4. Availability: shards survive sender going offline

**Where ETP loses honestly:**
1. Single-transfer bandwidth: $r+1$ times worse than direct
2. Storage: the commitment network stores $D \cdot r$ bytes persistently
3. Complexity: three-phase protocol vs. one-phase direct send

---

## 6. Comparison with Existing Approaches

| Property | TCP/IP | IPFS | BitTorrent | Tahoe-LAFS | Storj | **ETP** |
|----------|--------|------|-----------|------------|-------|---------|
| Payload travels sender→receiver | Yes | Partial | Partial | No | No | **No** |
| Content-addressed | No | Yes | Partial | Yes | Yes | **Yes** |
| Immutable | No | Yes | No | Yes | Yes | **Yes** |
| Client-side encryption | TLS layer | No | No | **Yes** | **Yes** | **Yes** |
| Shards encrypted at rest | N/A | No | No | **Yes** | **Yes** | **Yes** |
| Erasure-coded redundancy | No | No | No | **Yes** | **Yes** | **Yes** |
| Sender→receiver path O(1) | No | No | No | No | No | **Yes** |
| Capability-based access control | No | No | No | **Yes** | **Yes** | **Yes** |
| Capability bound to receiver identity | No | No | No | No | No | **Yes (ML-KEM)** |
| Forward secrecy (PQ) | TLS layer | No | No | No | No | **Yes (ML-KEM)** |
| PQ signatures on commitments | No | No | No | No | No | **Yes (ML-DSA)** |
| ZK privacy mode | No | No | No | No | No | **Yes** |
| Survives sender going offline | No | If pinned | If seeded | **Yes** | **Yes** | **Yes** |
| Receiver proximity optimization | No | Partial | Partial | No | Partial | **Yes** |
| Deterministic shard placement | No | DHT | DHT peers | Server-assigned | Server-assigned | **Consistent hash** |
| Append-only audit log | No | No | No | No | No | **Yes** |

**Reading guide:** ETP's unique cells (only ETP has "Yes") are: O(1) sender→receiver path,
receiver-bound capabilities, per-message PQ forward secrecy, PQ-signed append-only audit log,
and ZK privacy mode. The encrypted storage, erasure coding, and capability-based access that
ETP shares with Tahoe-LAFS and Storj are acknowledged as prior art — see Section 7.

---

## 7. Related Work and Prior Art

ETP is not built in a vacuum. Its design draws from, recombines, and extends ideas pioneered by
decades of work in distributed systems, cryptography, and peer-to-peer networking. This section
honestly acknowledges the lineage and articulates what — if anything — ETP contributes beyond
its predecessors.

### 7.1 Content-Addressed Storage

**IPFS (InterPlanetary File System, 2015)** [1] introduced content-addressed, Merkle-DAG-based
storage to mainstream distributed systems. In IPFS, files are split into blocks, each identified
by a cryptographic hash (CID), and retrieved by requesting the CID from the network. Peers who
have fetched a block can re-serve it, creating BitTorrent-like swarming.

**Git (2005)** [2] pioneered the idea that a repository's entire history could be addressed by
content hashes (SHA-1, now SHA-256). Every commit, tree, and blob is content-addressed, making
the history immutable and independently verifiable.

**What ETP borrows:** Content-addressing as the identity function (`EntityID = H(content || ...)`).
This is not novel — it is a direct application of the same principle.

**Where ETP diverges:** In IPFS, any peer with the CID can fetch the content; there is no built-in
access control. In ETP, knowing the `entity_id` is insufficient — the receiver also needs the
Content Encryption Key (CEK), which is sealed inside the entanglement key. IPFS retrieval is
*permissionless*; ETP materialization is *capability-gated*. Additionally, ETP encrypts all shards
at rest (AEAD with CEK), whereas IPFS blocks are stored and served in plaintext by default.

### 7.2 Erasure-Coded Distributed Storage

**Tahoe-LAFS (Least-Authority File Store, 2007)** [3] was among the first systems to combine
erasure coding with capability-based access control for untrusted storage. Files are encrypted
client-side, erasure-coded into shares, and distributed to storage servers. Capabilities (read-caps,
write-caps) are unforgeable tokens that grant specific access rights. Tahoe-LAFS coined the
principle: *"the server doesn't learn anything about the data."*

**Storj (2018)** [4] applies Reed-Solomon erasure coding over a decentralized network of storage
nodes. Files are encrypted client-side, split into 80 pieces (of which any 29 can reconstruct),
and distributed to independent operators. Access grants (serialized macaroons) authorize retrieval.

**Filecoin (2020)** [5] extends IPFS with cryptoeconomic guarantees: storage providers submit
Proofs of Replication and Proofs of Spacetime to demonstrate that data is physically stored.
This addresses the data availability problem that ETP's Section 8 (Open Questions) leaves open.

**What ETP borrows:** Erasure coding for redundancy and threshold reconstruction (k-of-n); client-side
encryption before distribution; the property that storage nodes cannot read content.

**Where ETP diverges:** Tahoe-LAFS, Storj, and Filecoin are *storage systems* — they address "how
do I store data durably on untrusted nodes?" ETP frames the same infrastructure as a *transfer
protocol* — the question is "how does entity X get from sender A to receiver B," with the storage
layer as an intermediate step rather than the end goal. The distinction is one of framing and
protocol-level abstraction: ETP's three-phase model (commit → entangle → materialize) treats
the distributed storage as a side-effect of the commit phase, not as the primary interface.

Whether this framing is a meaningful contribution or merely a relabeling is a fair question.
We argue the value lies in the protocol-level UX: the sender thinks in terms of "commit and
entangle," not "upload to storage provider and share access grant." The operational semantics
differ even if the underlying mechanisms are similar.

### 7.3 Append-Only Commitment Logs

**Bitcoin (2008)** [6] introduced the hash-chained, proof-of-work append-only ledger. Each block
references the hash of the previous block, making history tamper-evident.

**Certificate Transparency (2013)** [7] applies Merkle-tree append-only logs to TLS certificate
issuance. CAs must publish certificates to public logs, and anyone can verify that a certificate
was (or was not) logged. CT logs are simpler than blockchain — they require only a trusted log
operator (or multiple operators for cross-verification) rather than decentralized consensus.

**Hyperledger Fabric (2018)** [8] demonstrates that append-only commitment logs need not be
permissionless blockchains — permissioned channels with endorsement policies can achieve
immutability with lower latency and without proof-of-work.

**What ETP borrows:** The commitment log is a direct application of these ideas. The whitepaper
deliberately does not specify a consensus mechanism (Section 8, Open Question 3) — it could be
a blockchain, a CT-style Merkle log, or a permissioned ledger. The immutability guarantee
(Section 4) relies only on the append-only property and hash chaining, not on a specific
consensus protocol.

**Where ETP diverges:** ETP's commitment log is minimal by design: it stores only a Merkle root
of encrypted shard hashes, the entity_id, encoding params, and an ML-DSA signature. No shard
IDs, no content, no CEK. This is a tighter interface than most blockchain-based systems, which
tend to store more metadata. The log's purpose is *attestation* ("this entity was committed by
this sender at this time"), not general-purpose state management.

### 7.4 Capability-Based Security

**Dennis & Van Horn (1966)** [9] introduced the capability model: an unforgeable token that
simultaneously designates a resource and authorizes access to it. The holder of a capability
can access the resource; without it, the resource is unreachable. Capabilities are the
*minimum viable authorization* — no identity checks, no ACLs, just possession of proof.

**Macaroons (2014)** [10] extended capabilities with *caveats* — conditions that can be added
by any party in the delegation chain (e.g., "valid until 2026-03-24," "only from IP range X").
Storj uses serialized macaroons as its access grant format.

**SPIFFE/SPIRE (2017+)** [11] provides workload identity in distributed systems via short-lived
X.509 certificates (SVIDs), enabling zero-trust service-to-service authentication.

**What ETP borrows:** The entanglement key is a capability. It designates a resource (the
committed entity) and authorizes a specific receiver to materialize it. The `access_policy`
field (one-time, time-bounded, delegatable) is directly inspired by macaroon caveats.

**Where ETP diverges:** The entanglement key combines capability semantics with envelope
encryption (ML-KEM). A Storj access grant can be used by anyone who possesses it; an ETP
entanglement key is sealed to a specific receiver's encapsulation key and is useless to anyone
else. This binds the capability to a cryptographic identity, not just to possession.

### 7.5 Peer-to-Peer Content Distribution

**BitTorrent (2001)** [12] demonstrated that large-file distribution could be decentralized:
the original seeder uploads once, and peers exchange pieces among themselves. The more popular
a file becomes, the faster it distributes (unlike client-server, where popularity causes
congestion). BitTorrent's piece model (splitting content into fixed-size chunks distributed
across peers) is an ancestor of ETP's shard model.

**NDN (Named Data Networking, 2009+)** [13] proposes replacing IP's host-centric architecture
with data-centric networking: consumers request data by name, and any node that has a cached
copy can serve it. The network layer itself becomes content-addressed. NDN's "fetch from
wherever is closest" philosophy directly parallels ETP's receiver-side materialization from
nearest commitment nodes.

**What ETP borrows:** Parallel multi-source fetching (from BitTorrent/NDN), the principle that
the first upload is the expensive operation and subsequent retrievals amortize the cost, and
the idea that content should flow from where it is cached rather than from a fixed origin.

**Where ETP diverges:** BitTorrent has no built-in encryption or access control — torrents are
public by default. NDN's data-centric model operates at the network layer, while ETP is an
application-layer protocol. ETP's commitment phase is a one-time sender operation (not a
continuous seeding obligation), and the commitment network serves encrypted shards without
needing to understand or index the content.

### 7.6 Hybrid and Convergent Systems

Several systems have independently converged on similar combinations:

**Tahoe-LAFS + Capability Model** arguably comes closest to ETP's design: encrypted erasure-coded
storage with capability-based access. ETP's main departure is the protocol framing (transfer vs.
storage), the ML-KEM sealed envelope (binding capabilities to a specific receiver), and the
explicit three-phase model with an append-only commitment log.

**Keybase (2014-2020)** [14] combined KBFS (an encrypted, content-addressed filesystem) with
public-key identity and Merkle-tree-based audit logs. Users could share files by name, with
client-side encryption and server-side ignorance — similar to ETP's "nodes store ciphertext."

**Secure Scuttlebutt (SSB, 2014+)** [15] uses append-only logs per identity, with content-
addressed messages and capability-based private groups. SSB's offline-first design (gossip
replication, no central server) parallels ETP's sender-independence property.

### 7.7 What ETP Contributes

Given the depth of prior art, the honest answer is: **ETP's individual components are not novel.
Its contribution is the protocol-level synthesis.**

Specifically:

1. **The three-phase model (commit → entangle → materialize) as a transfer primitive.** Prior
   systems treat content-addressed storage + capabilities as *storage with sharing*. ETP treats
   the combination as *a data transfer protocol* — an alternative to sending payloads. This is
   primarily a conceptual contribution. Whether it proves practically valuable depends on
   whether the abstraction enables workflows that existing tools make awkward.

2. **The sealed entanglement key as a constant-size, receiver-bound, post-quantum transfer
   token.** Unlike Storj access grants (bearer tokens, anyone who holds them can use them),
   the entanglement key is cryptographically bound to a specific receiver via ML-KEM-768.
   Unlike Tahoe-LAFS read-caps (static, no expiry built-in), the entanglement key includes
   inline access policy (one-time, time-bounded, delegatable) and uses per-seal forward
   secrecy. The combination of capability + receiver binding + per-message forward secrecy +
   inline policy in a constant-size token is, to our knowledge, not present in prior systems.

3. **Deterministic receiver-side location derivation.** In IPFS and Storj, the provider/sharer
   must communicate block CIDs or shard locations to the receiver explicitly. In ETP, the
   receiver computes shard locations from the entity_id via consistent hashing — no lookup
   service, no external metadata. This eliminates one round-trip and one point of failure.

4. **Post-quantum security as a default, not an upgrade path.** ML-KEM-768 for key encapsulation
   and ML-DSA-65 for signatures are the *default* primitives, not optional add-ons. Most
   existing distributed storage systems use X25519/Ed25519 and mention post-quantum as future
   work.

We make no claim that these contributions are individually groundbreaking. The question for the
reader is whether the synthesis, and the mental model it enables ("don't move the data — transfer
the proof"), justifies a dedicated protocol specification. We believe it does, but acknowledge
that reasonable reviewers may disagree.

### References

[1] J. Benet, "IPFS — Content Addressed, Versioned, P2P File System," arXiv:1407.3561, 2014.

[2] L. Torvalds, "Git: A distributed version control system," 2005. https://git-scm.com/

[3] Z. Wilcox-O'Hearn, "Tahoe — The Least-Authority Filesystem," ACM CCS StorageSS Workshop, 2008.

[4] Storj Labs, "Storj: A Decentralized Cloud Storage Network Framework," Storj Whitepaper v3, 2018.

[5] Protocol Labs, "Filecoin: A Decentralized Storage Network," Filecoin Whitepaper, 2017 (mainnet 2020).

[6] S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.

[7] B. Laurie, A. Langley, E. Kasper, "Certificate Transparency," RFC 6962, 2013.

[8] E. Androulaki et al., "Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains," EuroSys, 2018.

[9] J. B. Dennis and E. C. Van Horn, "Programming Semantics for Multiprogrammed Computations," Communications of the ACM, 9(3), 1966.

[10] A. Birgisson, J. G. Politz, U. Erlingsson, A. Taly, M. Vrable, M. Lentczner, "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud," NDSS, 2014.

[11] CNCF, "SPIFFE: Secure Production Identity Framework for Everyone," https://spiffe.io/, 2017.

[12] B. Cohen, "Incentives Build Robustness in BitTorrent," Workshop on Economics of P2P Systems, 2003.

[13] L. Zhang et al., "Named Data Networking," ACM SIGCOMM CCR, 2014. (NDN project started 2009.)

[14] Keybase, Inc., "Keybase filesystem (KBFS)," https://book.keybase.io/docs/files, 2014-2020.

[15] D. Tarr et al., "Secure Scuttlebutt: An Identity-Centric Protocol for Subjective and Decentralized Applications," IFIP, 2019.

---

## 8. Use Cases

### 8.1 Large File Fan-Out
A 50 GB dataset is committed once. Any number of receivers can materialize it by each receiving
a ~1,300-byte sealed entanglement key (ML-KEM-768). Each receiver's materialization time is
dominated by local shard fetching from nearby nodes — not by the sender's bandwidth or
availability. For N receivers, direct transfer costs O(50GB × N). ETP costs O(50GB ×
replication) for the commit plus O(~1,300B × N) for the keys — amortized cost per receiver
approaches zero as N grows.

### 8.2 Immutable Audit Trail
Every data transfer is permanently recorded. A compliance system can verify: "Entity X was
committed by Sender A at time T and entangled with Receiver B." No party can deny or alter this.

### 8.3 Secure Messaging
A message is committed and entangled. The entanglement key is the message notification. The
content never traverses the public internet as a readable payload. Even if intercepted, the
entanglement key alone is useless.

### 8.4 State Synchronization
Two distributed systems synchronize state by exchanging entanglement keys. Each system materializes
the other's state from the commitment network. This is faster than traditional replication because
shards are fetched locally, and only the delta (new entity) needs materialization.

### 8.5 Cross-Planetary Data Transfer
On a Mars colony with 4-24 minute light delay to Earth: commitment nodes on Mars cache shards.
A sender on Earth commits an entity. The ~1,300-byte sealed entanglement key crosses the void
once (4-24 minutes). The receiver on Mars materializes from Mars-local commitment nodes (which
replicate shards during off-peak periods). Materialization time is bounded by Mars-local network
speed, not Earth-Mars light delay. Note: initial shard replication to Mars nodes still incurs
the light-delay cost — the advantage is that this is amortized across all Mars-side receivers
and can happen asynchronously before any specific transfer.

---

## 9. Open Questions

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

## 10. Conclusion

ETP inverts the data transfer paradigm. Rather than asking "how do I send this data to you," it
asks "how do I prove this data exists, and give you the right to reconstruct it near you."

The result is a protocol where:
- **The sender→receiver path is O(1)** — a constant-size sealed key (~1,300B), regardless of entity size
- **Total system bandwidth is higher than direct transfer** — but the bottleneck shifts from
  the sender-receiver link to receiver-local fetches, with amortized fan-out
- **Transfer is immutable** by mathematical construction, not policy
- **Security is cryptographic** not perimeter-based
- **Geography is optimized** because materialization pulls from nearby nodes
- **The sender can go offline** after commitment without affecting the transfer

Data doesn't move. Proof moves. Truth materializes.
Bandwidth doesn't disappear. It redistributes to where it's cheapest.

---

*ETP v0.1.0-draft — Entanglement Transfer Protocol*
