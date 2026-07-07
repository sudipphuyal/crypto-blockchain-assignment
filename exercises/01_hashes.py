from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

from Crypto.Hash import keccak


def sha256_bytes(data: bytes) -> bytes:
    """Return SHA-256 digest bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(text: str) -> str:
    """Hash a UTF-8 text string using SHA-256."""
    return sha256_bytes(text.encode("utf-8")).hex()


def double_sha256(data: bytes) -> bytes:
    """Bitcoin-style SHA-256(SHA-256(data))."""
    return sha256_bytes(sha256_bytes(data))


def hamming_distance(hash_a: str, hash_b: str) -> int:
    """
    Count how many bits differ between two hexadecimal hashes.
    This measures the avalanche effect.
    """
    xor_value = int(hash_a, 16) ^ int(hash_b, 16)
    return bin(xor_value).count("1")


def mine_proof_of_work(block_header: str, difficulty: int) -> dict:
    """
    Simplified Proof-of-Work:
    Find a nonce so SHA-256(block_header | nonce) begins with N hex zeroes.
    """
    if difficulty < 1 or difficulty > 6:
        raise ValueError(
            "Difficulty must be between 1 and 6 for this classroom demo.")

    prefix = "0" * difficulty
    nonce = 0
    attempts = 0
    started = time.perf_counter()

    while True:
        candidate = f"{block_header}|nonce={nonce}".encode("utf-8")
        digest = sha256_bytes(candidate).hex()
        attempts += 1

        if digest.startswith(prefix):
            elapsed = time.perf_counter() - started
            return {
                "difficulty": difficulty,
                "nonce": nonce,
                "attempts": attempts,
                "hash": digest,
                "seconds": elapsed,
            }

        nonce += 1


def keccak_256(data: bytes) -> bytes:
    """
    Ethereum-style Keccak-256.
    This is intentionally not hashlib.sha3_256().
    """
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def ethereum_address_from_public_key(public_key_body: bytes) -> str:
    """
    Ethereum address = last 20 bytes of Keccak-256(public key body).

    public_key_body must be 64 bytes: x-coordinate || y-coordinate.
    It does not include the 0x04 uncompressed-key prefix.
    """
    if len(public_key_body) != 64:
        raise ValueError("Ethereum public-key body must be exactly 64 bytes.")

    return "0x" + keccak_256(public_key_body)[-20:].hex()


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    # ------------------------------------------------------------
    # Exercise 1.1: SHA-256 properties
    # ------------------------------------------------------------
    print_section("Exercise 1.1 — SHA-256 outputs")

    inputs = ["Vinho do Porto", "vinho do porto", ""]

    for text in inputs:
        print(f"Input: {text!r}")
        print(f"SHA-256: {sha256_hex(text)}\n")

    # ------------------------------------------------------------
    # Avalanche effect
    # ------------------------------------------------------------
    print_section("Avalanche effect")

    original = "Vinho do Porto"
    modified = "Vinho do Portu"  # only one character changes: o -> u

    original_hash = sha256_hex(original)
    modified_hash = sha256_hex(modified)
    changed_bits = hamming_distance(original_hash, modified_hash)

    print(f"Original text: {original!r}")
    print(f"Modified text: {modified!r}")
    print(f"Original hash: {original_hash}")
    print(f"Modified hash: {modified_hash}")
    print(f"Different bits: {changed_bits} / 256")
    print(f"Difference: {(changed_bits / 256) * 100:.2f}%")

    # ------------------------------------------------------------
    # Exercise 1.2: simplified Proof-of-Work
    # ------------------------------------------------------------
    print_section("Exercise 1.2 — Simplified Proof-of-Work")

    block_header = (
        "version=1|"
        "previous_hash=0000000000000000|"
        "merkle_root=demo-merkle-root|"
        "timestamp=2026-07-07T00:00:00Z"
    )

    for difficulty in [1, 2, 3]:
        result = mine_proof_of_work(block_header, difficulty)

        print(f"Difficulty: {result['difficulty']} leading hex zero(es)")
        print(f"Nonce found: {result['nonce']}")
        print(f"Attempts: {result['attempts']}")
        print(f"Hash: {result['hash']}")
        print(f"Elapsed time: {result['seconds']:.6f} seconds\n")

    # ------------------------------------------------------------
    # Exercise 1.3: Bitcoin-style transaction identifier
    # ------------------------------------------------------------
    print_section("Exercise 1.3 — Bitcoin-style double SHA-256")

    serialized_transaction = (
        b"Alice pays Bob 1 BTC | nonce=12345 | timestamp=2026-01-01"
    )

    tx_hash_raw = double_sha256(serialized_transaction)
    txid_display_order = tx_hash_raw[::-1].hex()

    print("Serialized transaction bytes:")
    print(serialized_transaction)
    print(f"\nDouble SHA-256, raw byte order: {tx_hash_raw.hex()}")
    print(f"Bitcoin-style display TXID:     {txid_display_order}")

    # ------------------------------------------------------------
    # Exercise 1.4: Ethereum Keccak-256 address derivation
    # ------------------------------------------------------------
    print_section("Exercise 1.4 — Ethereum Keccak-256")

    # Educational fixed 64-byte public-key body.
    # This is only for demonstrating the address derivation formula.
    # Exercise 2 will generate a real secp256k1 public key.
    simulated_public_key_body = bytes.fromhex("11" * 64)

    public_key_hash = keccak_256(simulated_public_key_body).hex()
    ethereum_address = ethereum_address_from_public_key(
        simulated_public_key_body)

    print(
        f"Simulated public-key body length: {len(simulated_public_key_body)} bytes")
    print(f"Keccak-256(public key): {public_key_hash}")
    print(f"Ethereum-style address: {ethereum_address}")

    # ------------------------------------------------------------
    # Part C: Bitcoin Genesis Block
    # ------------------------------------------------------------
    print_section("Part C — Bitcoin Genesis Block")

    # Serialized Bitcoin genesis-block header.
    genesis_header_hex = (
        "01000000"
        + "00" * 32
        + "3ba3edfd7a7b12b27ac72c3e67768f"
          "617fc81bc3888a51323a9fb8aa4b1e5e4a"
        + "29ab5f49"
        + "ffff001d"
        + "1dac2b7c"
    )

    genesis_header = bytes.fromhex(genesis_header_hex)
    genesis_raw_hash = double_sha256(genesis_header)
    genesis_display_hash = genesis_raw_hash[::-1].hex()

    print(f"Genesis block hash: {genesis_display_hash}")
    print("Version: 1")
    print("Previous block hash: 64 zeroes (there was no earlier block)")
    print("Merkle root, human-readable display order:")
    print("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
    print("Timestamp: 1231006505 = 2009-01-03 18:15:05 UTC")
    print("Difficulty bits: 0x1d00ffff")
    print("Nonce: 2083236893")
    print(f"Current UTC run time: {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()
