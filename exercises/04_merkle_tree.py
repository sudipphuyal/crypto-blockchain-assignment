from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass


def sha256(data: bytes) -> bytes:
    """Return raw SHA-256 digest bytes."""
    return hashlib.sha256(data).digest()


def hash_transaction(transaction: str) -> bytes:
    """Hash one transaction using UTF-8 and SHA-256."""
    return sha256(transaction.encode("utf-8"))


def hash_pair(left_hash: bytes, right_hash: bytes) -> bytes:
    """
    Hash two child hashes to create a Merkle parent.

    Both children are raw 32-byte SHA-256 digests.
    """
    return sha256(left_hash + right_hash)


@dataclass(frozen=True)
class ProofStep:
    """
    One sibling hash needed for a Merkle inclusion proof.

    position:
    - "left": sibling must be concatenated before current hash
    - "right": sibling must be concatenated after current hash
    """

    position: str
    sibling_hash: bytes


class MerkleTree:
    def __init__(self, transactions: list[str]) -> None:
        if not transactions:
            raise ValueError(
                "A Merkle tree requires at least one transaction.")

        self.transactions = transactions
        self.levels = self._build_tree()

    def _build_tree(self) -> list[list[bytes]]:
        """
        Build the tree from leaf level to root.

        Rule for odd number of hashes:
        duplicate the final hash before producing parent hashes.
        """
        current_level = [hash_transaction(tx) for tx in self.transactions]
        levels = [current_level]

        while len(current_level) > 1:
            working_level = current_level[:]

            if len(working_level) % 2 == 1:
                working_level.append(working_level[-1])

            next_level = []

            for index in range(0, len(working_level), 2):
                parent_hash = hash_pair(
                    working_level[index],
                    working_level[index + 1],
                )
                next_level.append(parent_hash)

            levels.append(next_level)
            current_level = next_level

        return levels

    @property
    def merkle_root(self) -> bytes:
        """Return the root hash of the tree."""
        return self.levels[-1][0]

    def get_proof(self, transaction_index: int) -> list[ProofStep]:
        """
        Return the sibling hashes needed to prove inclusion of one transaction.
        """
        if transaction_index < 0 or transaction_index >= len(self.transactions):
            raise IndexError("Transaction index is outside the tree.")

        proof: list[ProofStep] = []
        current_index = transaction_index

        for level in self.levels[:-1]:
            working_level = level[:]

            if len(working_level) % 2 == 1:
                working_level.append(working_level[-1])

            if current_index % 2 == 0:
                sibling_index = current_index + 1
                sibling_position = "right"
            else:
                sibling_index = current_index - 1
                sibling_position = "left"

            proof.append(
                ProofStep(
                    position=sibling_position,
                    sibling_hash=working_level[sibling_index],
                )
            )

            current_index //= 2

        return proof


def verify_proof(
    transaction: str,
    proof: list[ProofStep],
    expected_root: bytes,
) -> bool:
    """
    Verify that a transaction belongs to the Merkle tree represented by root.
    """
    current_hash = hash_transaction(transaction)

    for step in proof:
        if step.position == "left":
            current_hash = hash_pair(step.sibling_hash, current_hash)
        elif step.position == "right":
            current_hash = hash_pair(current_hash, step.sibling_hash)
        else:
            raise ValueError(f"Unknown proof position: {step.position}")

    return current_hash == expected_root


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def print_tree_for_four_transactions(tree: MerkleTree) -> None:
    """
    Clear ASCII view for the required four-transaction example.
    """
    leaves = tree.levels[0]
    parents = tree.levels[1]
    root = tree.levels[2][0]

    print(f"Merkle Root: {root.hex()}")
    print(f"├── H12: {parents[0].hex()}")
    print(f"│   ├── H1: {leaves[0].hex()}  ({tree.transactions[0]})")
    print(f"│   └── H2: {leaves[1].hex()}  ({tree.transactions[1]})")
    print(f"└── H34: {parents[1].hex()}")
    print(f"    ├── H3: {leaves[2].hex()}  ({tree.transactions[2]})")
    print(f"    └── H4: {leaves[3].hex()}  ({tree.transactions[3]})")


def print_proof(proof: list[ProofStep]) -> None:
    for step_number, step in enumerate(proof, start=1):
        print(
            f"Step {step_number}: sibling on the {step.position} -> "
            f"{step.sibling_hash.hex()}"
        )


def main() -> None:
    transactions = [
        "Alice -> Bob",
        "Carol -> Dave",
        "Eve -> Frank",
        "Grace -> Harry",
    ]

    # ------------------------------------------------------------
    # Exercise 4.1 — Build Merkle tree
    # ------------------------------------------------------------
    print_section("Exercise 4.1 — Merkle Tree Construction")

    tree = MerkleTree(transactions)

    print("Transactions:")
    for index, transaction in enumerate(transactions, start=1):
        print(f"Tx{index}: {transaction}")

    print("\nASCII Merkle Tree:")
    print_tree_for_four_transactions(tree)

    print("\nMerkle Root:")
    print(tree.merkle_root.hex())

    # ------------------------------------------------------------
    # Tampering demonstration
    # ------------------------------------------------------------
    print_section("Tampering Demonstration")

    tampered_transactions = transactions[:]
    tampered_transactions[1] = "Carol -> Mallory"

    tampered_tree = MerkleTree(tampered_transactions)

    print("Original Tx2:", transactions[1])
    print("Tampered Tx2:", tampered_transactions[1])

    print("\nOriginal Merkle Root:")
    print(tree.merkle_root.hex())

    print("\nTampered Merkle Root:")
    print(tampered_tree.merkle_root.hex())

    roots_are_different = tree.merkle_root != tampered_tree.merkle_root

    print("\nRoots are different:", roots_are_different)

    assert roots_are_different is True
    print("Tampering detection check: PASSED")

    # ------------------------------------------------------------
    # Exercise 4.2 — SPV / Merkle inclusion proof
    # ------------------------------------------------------------
    print_section("Exercise 4.2 — SPV Inclusion Proof for Tx3")

    tx3_index = 2
    tx3 = transactions[tx3_index]

    proof = tree.get_proof(tx3_index)
    proof_is_valid = verify_proof(tx3, proof, tree.merkle_root)

    print("Transaction to prove:")
    print(tx3)

    print("\nProof components:")
    print_proof(proof)

    print("\nExpected Merkle Root:")
    print(tree.merkle_root.hex())

    print("\nProof verification result:", proof_is_valid)

    assert proof_is_valid is True
    print("SPV inclusion proof check: PASSED")

    # Negative proof test
    incorrect_transaction = "Eve -> Mallory"
    incorrect_proof_result = verify_proof(
        incorrect_transaction,
        proof,
        tree.merkle_root,
    )

    print("\nVerification using altered transaction:", incorrect_proof_result)

    assert incorrect_proof_result is False
    print("Altered transaction rejection check: PASSED")

    # ------------------------------------------------------------
    # Exercise 4.2 scale calculation
    # ------------------------------------------------------------
    print_section("Merkle Proof Scale Calculation")

    transaction_count = 1_000_000
    required_hashes = math.ceil(math.log2(transaction_count))
    proof_size_bytes = required_hashes * 32

    print(f"Transactions in block: {transaction_count:,}")
    print(f"Approximate sibling hashes needed: {required_hashes}")
    print(f"Approximate proof hash payload: {proof_size_bytes} bytes")
    print("Direction metadata is also needed for each proof step.")

    # ------------------------------------------------------------
    # Exercise 4.3 conceptual notes
    # ------------------------------------------------------------
    print_section("Exercise 4.3 — Ethereum Patricia Merkle Trie")

    print(
        "Bitcoin commonly uses a binary Merkle tree to commit transactions "
        "inside a block."
    )
    print(
        "Ethereum uses Merkle Patricia Tries for state, transactions, and "
        "receipts because it needs authenticated key-value storage, not only "
        "a transaction-list commitment."
    )
    print(
        "The three major Ethereum block-header roots are stateRoot, "
        "transactionsRoot, and receiptsRoot."
    )


if __name__ == "__main__":
    main()
