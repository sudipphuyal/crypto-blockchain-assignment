from __future__ import annotations

from blockchain import Blockchain, MerkleTree, Transaction, Wallet


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    print_section("Secure Mini Blockchain — Final Demonstration")

    # ------------------------------------------------------------
    # Step 1: Create educational wallets
    # ------------------------------------------------------------
    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()

    print("Alice address:", alice.address)
    print("Bob address:  ", bob.address)
    print("Miner address:", miner.address)

    # ------------------------------------------------------------
    # Step 2: Genesis allocation
    # ------------------------------------------------------------
    print_section("Step 1 — Genesis Block")

    blockchain = Blockchain(
        genesis_recipient=alice.address,
        initial_balance=100,
        mining_reward=5,
        difficulty=3,
    )

    genesis_block = blockchain.chain[0]

    print("Genesis block hash:", genesis_block.hash)
    print("Genesis nonce:", genesis_block.nonce)
    print("Alice initial balance:", blockchain.get_balance(alice.address))
    print("Chain valid after genesis:", blockchain.is_chain_valid())

    assert blockchain.get_balance(alice.address) == 100
    assert blockchain.is_chain_valid() is True

    # ------------------------------------------------------------
    # Step 3: Alice sends Bob 10 units
    # ------------------------------------------------------------
    print_section("Step 2 — Alice Sends 10 Units to Bob")

    alice_to_bob = Transaction.create_transfer(
        sender_wallet=alice,
        recipient=bob.address,
        amount=10,
    )

    blockchain.add_transaction(alice_to_bob)

    print("Transaction ID:", alice_to_bob.txid)
    print("Transaction signature valid:", alice_to_bob.is_valid())
    print("Pending transactions:", len(blockchain.pending_transactions))

    assert alice_to_bob.is_valid() is True

    # ------------------------------------------------------------
    # Step 4: Bob sends Alice 3 units
    # ------------------------------------------------------------
    print_section("Step 3 — Bob Sends 3 Units Back to Alice")

    bob_to_alice = Transaction.create_transfer(
        sender_wallet=bob,
        recipient=alice.address,
        amount=3,
    )

    blockchain.add_transaction(bob_to_alice)

    print("Transaction ID:", bob_to_alice.txid)
    print("Transaction signature valid:", bob_to_alice.is_valid())
    print("Pending transactions:", len(blockchain.pending_transactions))

    assert bob_to_alice.is_valid() is True

    # ------------------------------------------------------------
    # Step 5: Mine pending transactions
    # ------------------------------------------------------------
    print_section("Step 4 — Miner Mines Pending Transactions")

    mined_block = blockchain.mine_pending(miner.address)

    print("Block index:", mined_block.index)
    print("Previous block hash:", mined_block.previous_hash)
    print("Merkle root:", mined_block.merkle_root)
    print("Nonce:", mined_block.nonce)
    print("Mined block hash:", mined_block.hash)
    print("Proof-of-Work valid:", mined_block.hash.startswith("000"))
    print("Block valid:", mined_block.is_valid(blockchain.difficulty))

    assert mined_block.hash.startswith("000")
    assert mined_block.is_valid(blockchain.difficulty) is True

    # ------------------------------------------------------------
    # Step 6: Confirm balances and chain validity
    # ------------------------------------------------------------
    print_section("Step 5 — Confirmed Balances and Chain Validity")

    alice_balance = blockchain.get_balance(alice.address)
    bob_balance = blockchain.get_balance(bob.address)
    miner_balance = blockchain.get_balance(miner.address)

    print("Alice balance:", alice_balance)
    print("Bob balance:  ", bob_balance)
    print("Miner balance:", miner_balance)
    print("Complete chain valid:", blockchain.is_chain_valid())

    assert alice_balance == 93
    assert bob_balance == 7
    assert miner_balance == 5
    assert blockchain.is_chain_valid() is True

    # ------------------------------------------------------------
    # Step 7: Generate and verify SPV proof
    # ------------------------------------------------------------
    print_section("Step 6 — SPV / Merkle Inclusion Proof")

    proof_data = blockchain.generate_spv_proof(alice_to_bob.txid)

    print("Transaction ID being verified:", alice_to_bob.txid)
    print("Block index:", proof_data["block_index"])
    print("Transaction index:", proof_data["transaction_index"])
    print("Merkle root:", proof_data["merkle_root"])
    print("\nProof steps:")

    for step_number, step in enumerate(proof_data["proof"], start=1):
        print(
            f"Step {step_number}: sibling on the {step.position} -> "
            f"{step.sibling_hash.hex()}"
        )

    proof_valid = MerkleTree.verify_proof(
        alice_to_bob.txid,
        proof_data["proof"],
        proof_data["merkle_root"],
    )

    print("\nSPV proof valid:", proof_valid)

    assert proof_valid is True

    # ------------------------------------------------------------
    # Step 8: Tamper demonstration
    # ------------------------------------------------------------
    print_section("Step 7 — Tampering Demonstration")

    original_amount = blockchain.chain[1].transactions[1].amount

    print("Original Alice-to-Bob amount:", original_amount)

    blockchain.chain[1].transactions[1].amount = 999

    print("Tampered Alice-to-Bob amount:",
          blockchain.chain[1].transactions[1].amount)
    print("Chain valid after tampering:", blockchain.is_chain_valid())

    assert blockchain.is_chain_valid() is False

    print_section("Final Result")
    print("All required demonstrations completed successfully.")
    print("The final tampering check intentionally leaves the in-memory chain invalid.")


if __name__ == "__main__":
    main()
