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
