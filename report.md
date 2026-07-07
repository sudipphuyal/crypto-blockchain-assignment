# Exercise 1 — Hash Functions

## Objective

The objective was to explore SHA-256, Keccak-256, avalanche behaviour,
simplified Proof-of-Work, Bitcoin-style double SHA-256, and the Bitcoin
genesis block.

## SHA-256 Results

The strings "Vinho do Porto", "vinho do porto", and the empty string
produced three completely different 256-bit hashes. This demonstrates
determinism, fixed-length output, and sensitivity to input changes.

## Avalanche Effect

Changing one character from "Vinho do Porto" to "Vinho do Portu" changed
138 of 256 hash bits (53.91%). This is consistent with the avalanche
property expected from a secure cryptographic hash function.

## Proof-of-Work

A nonce was searched until the SHA-256 hash of a fixed block header began
with 1, 2, and 3 hexadecimal zeroes. The number of attempts increased as
the difficulty increased. Verification remains efficient because another
node only needs to hash the final candidate once.

## Bitcoin Double SHA-256

A simulated serialised transaction was hashed twice with SHA-256. The final
digest was also displayed in Bitcoin-style reversed byte order. Double hashing
provides additional separation from the internal state of the first hash and
is part of Bitcoin's protocol design.

## Ethereum Keccak-256

An Ethereum-style address was derived from the final 20 bytes of
Keccak-256(public_key_body). The public key used in this exercise was
illustrative only; a valid secp256k1 key pair will be generated in Exercise 2.

## Bitcoin Genesis Block

The calculated Bitcoin genesis block hash was:
000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f

Its header contains version, previous-block hash, Merkle root, timestamp,
difficulty target (nBits), and nonce. The previous hash is zero because it
is the first block.

# Exercise 2 — ECC, Bitcoin Addresses, and Ethereum Addresses

## Objective

The objective was to generate a test-only secp256k1 key pair, derive a Bitcoin
P2PKH address and an Ethereum address, encode the private key in WIF format,
and examine the computational cost of short vanity addresses.

## Key Generation

A random 256-bit private key was generated on the secp256k1 curve. The public
key was calculated through elliptic-curve point multiplication:

K = k × G

The uncompressed public-key body was 64 bytes, while the compressed public key
was 33 bytes. Compression stores the x-coordinate and one parity bit indicating
which valid y-coordinate must be reconstructed.

## Bitcoin Address

A Bitcoin P2PKH address was generated using:

RIPEMD-160(SHA-256(compressed public key))

The resulting hash was prefixed with the mainnet version byte, protected with a
four-byte double-SHA-256 checksum, and encoded using Base58Check.

## Ethereum Address

An Ethereum-style address was derived by applying Keccak-256 to the 64-byte
uncompressed public-key body and taking the final 20 bytes. The key derivation
excluded the 0x04 uncompressed-key prefix.

## WIF

The private key was encoded as a compressed mainnet WIF using Base58Check.
The WIF was displayed only locally for a generated test key and was not stored
in the repository or report.

## Discrete Logarithm Problem

Calculating a public key from a private key is computationally practical.
However, recovering the private key from a public key is computationally
infeasible because of the elliptic-curve discrete-logarithm problem. This
one-way property protects wallet private keys.

## Vanity Address Experiment

The expected number of generated P2PKH keys for a prefix beginning with `1A`
is approximately 58. For `1ABC`, the approximate expectation is 58³ =
195,112 attempts. Therefore, every additional requested Base58 character
increases the expected computation substantially.

# Exercise 3 — ECDSA Signatures and Nonce Reuse

## Objective

The objective was to sign a blockchain-style transaction using ECDSA over
secp256k1, verify the signature with the sender’s public key, prove that a
modified transaction fails verification, and demonstrate the security impact
of reusing an ECDSA nonce.

## Signing and Verification

Alice signed the message:

`Alice sends 1 BTC to Bob | nonce: 12345 | timestamp: 2026-01-01`

The signature was encoded in DER format and verified successfully using
Alice's public key. When the transaction amount was changed from 1 BTC to
2 BTC, verification failed. This demonstrates transaction integrity: even a
small change to signed transaction data invalidates the signature.

## Non-Repudiation

A valid ECDSA signature demonstrates that the holder of Alice's private key
authorised the signed message. Nodes can verify this using Alice's public key
without receiving the private key itself.

## Nonce Reuse Vulnerability

A controlled test reused the same ECDSA nonce `k` to sign two different
messages with a newly generated test key. Both signatures had the same `r`
component. Using the two public signatures and message hashes, the nonce and
then the private key were recovered mathematically.

The formulas used were:

`k = (z1 - z2) × (s1 - s2)^(-1) mod n`

`privateKey = (s1 × k - z1) × r^(-1) mod n`

The recovered private key generated the same public key as Alice's original
key. Therefore, nonce reuse completely compromises an ECDSA private key.

## Mitigation

Real systems must generate a fresh unpredictable nonce for every ECDSA
signature or use deterministic nonce generation, such as RFC 6979. The fixed
nonce in this exercise was used only for a controlled demonstration and must
never be used in a real wallet or signing system.

## ECDSA, EdDSA, and Schnorr

ECDSA is widely used in Bitcoin and Ethereum-related systems. EdDSA, such as
Ed25519, uses a different curve/signature construction and has deterministic
nonce derivation by design. Schnorr signatures provide simpler algebraic
properties and enable efficient signature aggregation; Bitcoin introduced
Schnorr signatures through Taproot.

# Exercise 4 — Merkle Trees and SPV Inclusion Proofs

## Objective

The objective was to construct a Merkle tree from four blockchain-style
transactions, calculate the Merkle root, demonstrate tamper detection, and
generate and verify an SPV inclusion proof.

## Merkle Tree Construction

The following transactions were used:

1. Alice -> Bob
2. Carol -> Dave
3. Eve -> Frank
4. Grace -> Harry

Each transaction was first hashed with SHA-256. Pairs of hashes were then
concatenated and hashed to create parent nodes until a single Merkle root
was produced.

## Tamper Detection

The second transaction was changed from `Carol -> Dave` to
`Carol -> Mallory`. This produced a completely different Merkle root.
Therefore, any transaction modification is detectable because it changes
the leaf hash, its parent hashes, and finally the root.

## SPV Inclusion Proof

A Merkle proof was generated for `Eve -> Frank`. The proof contained:

- H4, the sibling hash for `Grace -> Harry`
- H12, the combined hash of the first two transactions

Starting with H3, the verifier calculated H34 and then the final Merkle root.
The reconstructed root matched the original root, so the inclusion proof was
valid. When the transaction text was changed, verification failed.

## Scale

For a block containing 1,000,000 transactions, an inclusion proof requires
approximately ceil(log2(1,000,000)) = 20 sibling hashes. At 32 bytes per
SHA-256 hash, the hash payload is approximately 640 bytes, plus direction
metadata. This is why SPV clients can verify inclusion without downloading
the complete block.

## Ethereum Patricia Merkle Trie

Bitcoin commonly uses a binary Merkle tree to commit a list of transactions.
Ethereum uses Merkle Patricia Tries because it requires authenticated key-value
storage for account state, transactions, and receipts. Ethereum block headers
include `stateRoot`, `transactionsRoot`, and `receiptsRoot`.

# Exercise 5 — Zero-Knowledge Proofs and Schnorr Identification

## Objective

The objective was to understand completeness, soundness, and zero knowledge;
simulate the Alibaba cave protocol; implement the Schnorr identification
protocol; and compare major zero-knowledge technologies used in blockchain.

## The Three ZKP Properties

- **Completeness:** An honest prover who knows the secret should be accepted
  by the verifier.
- **Soundness:** A dishonest prover who does not know the secret should have
  only a very small probability of being accepted.
- **Zero knowledge:** The verifier learns that the prover knows the secret,
  but does not learn the secret itself.

## Alibaba Cave Simulation

In the Alibaba cave analogy, a prover who knows the secret door mechanism can
always exit through the side requested by the verifier. A dishonest prover must
guess the requested side in advance and has a 1/2 chance of passing each round.

After 10 rounds, the theoretical probability of a dishonest prover passing all
rounds is:

`(1/2)^10 = 1/1024 ≈ 0.09765625%`

After 30 rounds, the probability becomes:

`(1/2)^30 = 1/1,073,741,824 ≈ 0.000000093132%`

Repeated rounds therefore make successful cheating increasingly improbable.

## Schnorr Identification Protocol

A toy Schnorr protocol was implemented using a small educational group.

1. The prover has private secret `x`.
2. The public key is `Y = g^x mod p`.
3. The prover selects random `r` and sends `t = g^r mod p`.
4. The verifier sends challenge `c`.
5. The prover sends `s = r + c*x mod q`.
6. The verifier checks:

`g^s mod p = t * Y^c mod p`

The equality held, demonstrating completeness. The toy values were deliberately
small and are not secure for real cryptographic use.

## Soundness Illustration

A fake prover attempted to provide a random response without knowing the
secret. The verification equation normally failed. This illustrates that a
valid response depends on knowledge of the secret, although formal soundness
requires cryptographically large parameters and repeated or large challenges.

## Conceptual Shielded Transaction

A conceptual shielded transaction demonstrated the relation:

`input = output + fee`

A real privacy-focused system can prove this relation in zero knowledge without
revealing amounts or identities. Production systems such as Zcash additionally
use commitments, nullifiers, encryption, and zk-SNARK proofs. These components
were not implemented in this educational script.

## Technology Comparison

- **zk-SNARKs:** compact proofs and fast verification; some systems require a
  trusted setup.
- **zk-STARKs:** commonly avoid trusted setup and use hash-based methods, but
  proofs are generally larger.
- **zkRollups:** aggregate Layer-2 transactions and submit a validity proof to
  a Layer-1 blockchain.
- **Bulletproofs:** avoid trusted setup and support efficient range proofs.

# Exercise 6 — HD Wallets, BIP32, BIP39, and Address Derivation

## Objective

The objective was to generate a test-only BIP39 mnemonic, derive its seed and
BIP32 master material, derive Bitcoin and Ethereum BIP44 addresses, demonstrate
determinism, and analyse HD-wallet security.

## BIP39 Mnemonic and Seed

A fresh 12-word test mnemonic was generated. The mnemonic itself was not saved
in the public repository. The mnemonic was converted into a 512-bit seed using
PBKDF2-HMAC-SHA512 with 2048 iterations and an empty passphrase.

The generated seed was then used to derive BIP32 master material:

`I = HMAC-SHA512(key="Bitcoin seed", data=seed)`

The left 32 bytes of `I` form the master private-key material and the right
32 bytes form the master chain code.

## BIP44 Address Derivation

The first five external Bitcoin addresses were derived using:

`m/44'/0'/0'/0/index`

The first five external Ethereum addresses were derived using:

`m/44'/60'/0'/0/index`

The same seed produced the same five addresses when derivation was repeated.
This demonstrates deterministic wallet behaviour.

## Entropy

A 12-word mnemonic uses 128 bits of entropy and a 4-bit checksum. Although
there are `2048^12 = 2^132` possible sequences of twelve words, only `2^128`
represent valid BIP39 entropy values because the final bits are checksum bits.

At an unrealistic brute-force speed of `10^12` attempts per second, a full
2^128 search would still require approximately 10^19 years. A 24-word mnemonic
uses 256 bits of entropy and is vastly stronger.

## Extended Public Keys

An extended public key, commonly represented as an xpub, contains public-key
and chain-code information. It can derive non-hardened descendant public keys
and receiving addresses without allowing spending. Therefore, an exchange can
use an xpub on an online receiving system to generate a unique deposit address
per customer while keeping private keys offline.

However, an xpub should still be treated as privacy-sensitive because it can
reveal the linked public address hierarchy.

## Hardened and Non-Hardened Derivation

An apostrophe in a derivation path indicates hardened derivation. For example:

`m/44'/0'/0'`

Hardened derivation cannot be performed from an xpub alone. Non-hardened
derivation, such as the external address chain `m/44'/0'/0'/0/index`, can be
performed from the corresponding extended public key.

## Security Note

All mnemonic, seed, master-key, and xpub values used in this exercise were
temporary educational values. Sensitive values were intentionally hidden from
the public repository and report. No real wallet seed phrase or funded wallet
was used.

# Exercise 7 — Cryptographic Attacks and Defences

## Objective

The objective was to simulate a birthday collision with a deliberately weak
16-bit hash, model the economic calculation behind a majority-hashrate attack,
demonstrate conceptual replay protection using a chain identifier, and implement
a commit-reveal mechanism against front-running.

## Birthday Collision Demonstration

A mini hash function was created by taking the first 16 bits of SHA-256. Since
there are only 2^16 = 65,536 possible outputs, a collision can be found with
roughly the square root of the output space rather than by testing all outputs.

The rough birthday-bound scale is:

`sqrt(65536) = 256`

The actual number of attempts varied because the inputs were random. The script
successfully found two different inputs with the same 16-bit hash. This shows
why cryptographic hashes such as SHA-256 use a much larger 256-bit output:
a generic collision attack against SHA-256 would require approximately 2^128
work, which is infeasible.

## Majority Hashrate Attack

A majority-hashrate attack in a Proof-of-Work network may allow an attacker to
reorganise recent history or double-spend its own transactions. It does not give
the attacker the private keys of other users or allow arbitrary theft.

The script implements a transparent economic estimate:

`required hash rate = 0.51 × network hash rate`

`hourly cost = required TH/s × rental price per TH/s/day ÷ 24`

Current hash-rate and rental-price inputs must be collected from dated public
sources and cited in the final report. The implementation performs no network
interaction or mining activity.

## Replay Attack and Chain ID

A conceptual legacy transaction without a chain identifier was signed and
verified in two scenarios, representing two chains. Because the signed payload
was identical, the signature remained valid in both scenarios.

A chain-bound payload included a Chain ID. A signature created for chain ID 1
verified for that chain but failed for chain ID 61. This models the purpose of
EIP-155: binding a transaction signature to a particular chain to reduce
cross-chain replay risk.

The Python demonstration uses deterministic JSON and SHA-256 for clarity. Real
Ethereum uses RLP transaction encoding, Keccak-256, and EIP-155 signature rules.

## Commit-Reveal

A commit-reveal protocol was implemented as:

`commitment = SHA-256(action || salt)`

The user first publishes only the commitment. Later, the user reveals the
original action and secret salt. The contract verifies the reveal by recomputing
the hash. A modified action fails verification.

Commit-reveal can reduce front-running because the action is hidden during the
commit phase. Practical systems should also include deadlines, penalties or
refund rules for non-reveal, and a high-entropy secret salt.

## Quantum and MEV Discussion

Public mempools may expose pending transactions to MEV and front-running.
Commit-reveal is one mitigation, although it is not sufficient for every
application. Future large-scale fault-tolerant quantum computers could threaten
ECC-based signatures, so post-quantum cryptography is important for long-term
blockchain security.
