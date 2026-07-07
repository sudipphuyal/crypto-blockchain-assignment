from blockchain import Block, Blockchain, MerkleTree, Transaction, Wallet


def test_wallet_creates_bitcoin_style_address() -> None:
    wallet = Wallet.create()

    assert wallet.address.startswith("1")
    assert len(wallet.public_key_hex) == 128


def test_valid_signed_transaction() -> None:
    alice = Wallet.create()
    bob = Wallet.create()

    transaction = Transaction.create_transfer(
        sender_wallet=alice,
        recipient=bob.address,
        amount=10,
    )

    assert transaction.is_valid() is True
    assert len(transaction.txid) == 64


def test_modified_transaction_signature_fails() -> None:
    alice = Wallet.create()
    bob = Wallet.create()

    transaction = Transaction.create_transfer(
        sender_wallet=alice,
        recipient=bob.address,
        amount=10,
    )

    transaction.amount = 99

    assert transaction.is_valid() is False


def test_sender_address_must_match_public_key() -> None:
    alice = Wallet.create()
    bob = Wallet.create()
    mallory = Wallet.create()

    transaction = Transaction.create_transfer(
        sender_wallet=alice,
        recipient=bob.address,
        amount=10,
    )

    transaction.sender = mallory.address

    assert transaction.is_valid() is False


def create_test_transactions() -> list[Transaction]:
    alice = Wallet.create()
    bob = Wallet.create()
    charlie = Wallet.create()

    return [
        Transaction.create_transfer(alice, bob.address, 10),
        Transaction.create_transfer(bob, charlie.address, 5),
        Transaction.create_transfer(charlie, alice.address, 2),
    ]


def test_merkle_proof_is_valid() -> None:
    transactions = create_test_transactions()
    tree = MerkleTree(transactions)

    proof = tree.get_proof(1)

    assert MerkleTree.verify_proof(
        transactions[1].txid,
        proof,
        tree.merkle_root,
    ) is True


def test_wrong_merkle_proof_fails() -> None:
    transactions = create_test_transactions()
    tree = MerkleTree(transactions)

    proof = tree.get_proof(1)

    assert MerkleTree.verify_proof(
        transactions[0].txid,
        proof,
        tree.merkle_root,
    ) is False


def test_merkle_root_changes_when_transaction_is_altered() -> None:
    transactions = create_test_transactions()
    original_tree = MerkleTree(transactions)

    transactions[1].amount = 999
    altered_tree = MerkleTree(transactions)

    assert original_tree.merkle_root != altered_tree.merkle_root


def test_odd_number_of_transactions_supports_proof() -> None:
    transactions = create_test_transactions()
    tree = MerkleTree(transactions)

    proof = tree.get_proof(2)

    assert len(proof) == 2
    assert MerkleTree.verify_proof(
        transactions[2].txid,
        proof,
        tree.merkle_root,
    ) is True


def test_mined_block_is_valid() -> None:
    transactions = create_test_transactions()

    block = Block.create(
        index=1,
        previous_hash="0" * 64,
        transactions=transactions,
    )

    block.mine(difficulty=2)

    assert block.hash.startswith("00")
    assert block.is_valid(difficulty=2) is True


def test_tampered_block_transaction_is_invalid() -> None:
    transactions = create_test_transactions()

    block = Block.create(
        index=1,
        previous_hash="0" * 64,
        transactions=transactions,
    )

    block.mine(difficulty=2)

    block.transactions[0].amount = 999

    assert block.is_valid(difficulty=2) is False


def test_changed_nonce_makes_block_invalid() -> None:
    transactions = create_test_transactions()

    block = Block.create(
        index=1,
        previous_hash="0" * 64,
        transactions=transactions,
    )

    block.mine(difficulty=2)

    block.nonce += 1

    assert block.is_valid(difficulty=2) is False


def test_wrong_previous_hash_makes_block_invalid() -> None:
    transactions = create_test_transactions()

    block = Block.create(
        index=1,
        previous_hash="0" * 64,
        transactions=transactions,
    )

    block.mine(difficulty=2)

    block.previous_hash = "f" * 64

    assert block.is_valid(difficulty=2) is False


def test_chain_is_valid_after_genesis_block() -> None:
    alice = Wallet.create()

    blockchain = Blockchain(
        genesis_recipient=alice.address,
        initial_balance=100,
        mining_reward=5,
        difficulty=1,
    )

    assert blockchain.get_balance(alice.address) == 100
    assert blockchain.is_chain_valid() is True


def test_pending_transaction_order_allows_bob_to_send_back_funds() -> None:
    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()

    blockchain = Blockchain(
        genesis_recipient=alice.address,
        initial_balance=100,
        mining_reward=5,
        difficulty=1,
    )

    alice_to_bob = Transaction.create_transfer(
        alice,
        bob.address,
        10,
    )

    bob_to_alice = Transaction.create_transfer(
        bob,
        alice.address,
        3,
    )

    blockchain.add_transaction(alice_to_bob)
    blockchain.add_transaction(bob_to_alice)

    mined_block = blockchain.mine_pending(miner.address)

    assert mined_block.is_valid(difficulty=1) is True
    assert blockchain.get_balance(alice.address) == 93
    assert blockchain.get_balance(bob.address) == 7
    assert blockchain.get_balance(miner.address) == 5
    assert blockchain.is_chain_valid() is True


def test_insufficient_balance_is_rejected() -> None:
    alice = Wallet.create()
    bob = Wallet.create()

    blockchain = Blockchain(
        genesis_recipient=alice.address,
        initial_balance=100,
        difficulty=1,
    )

    invalid_transfer = Transaction.create_transfer(
        bob,
        alice.address,
        1,
    )

    try:
        blockchain.add_transaction(invalid_transfer)
        assert False, "Expected insufficient balance error."
    except ValueError as error:
        assert "Insufficient available balance" in str(error)


def test_tampered_chain_is_invalid() -> None:
    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()

    blockchain = Blockchain(
        genesis_recipient=alice.address,
        initial_balance=100,
        mining_reward=5,
        difficulty=1,
    )

    transaction = Transaction.create_transfer(
        alice,
        bob.address,
        10,
    )

    blockchain.add_transaction(transaction)
    blockchain.mine_pending(miner.address)

    blockchain.chain[1].transactions[1].amount = 999

    assert blockchain.is_chain_valid() is False


def test_confirmed_transaction_has_valid_spv_proof() -> None:
    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()

    blockchain = Blockchain(
        genesis_recipient=alice.address,
        initial_balance=100,
        mining_reward=5,
        difficulty=1,
    )

    transaction = Transaction.create_transfer(
        alice,
        bob.address,
        10,
    )

    blockchain.add_transaction(transaction)
    blockchain.mine_pending(miner.address)

    proof_data = blockchain.generate_spv_proof(transaction.txid)

    assert MerkleTree.verify_proof(
        transaction.txid,
        proof_data["proof"],
        proof_data["merkle_root"],
    ) is True
