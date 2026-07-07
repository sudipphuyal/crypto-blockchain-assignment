from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ecdsa import BadSignatureError, SECP256k1, SigningKey, VerifyingKey, util


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def canonical_json(data: dict[str, Any]) -> bytes:
    """Return deterministic JSON bytes for hashing and signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def base58_encode(data: bytes) -> str:
    """Encode bytes in Bitcoin Base58."""
    number = int.from_bytes(data, byteorder="big")
    encoded = ""

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + encoded


def base58check_encode(payload: bytes) -> str:
    """Encode payload with a four-byte double-SHA-256 checksum."""
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def hash160(data: bytes) -> bytes:
    """Bitcoin HASH160 = RIPEMD160(SHA256(data))."""
    sha_hash = sha256(data)

    try:
        return hashlib.new("ripemd160", sha_hash).digest()
    except ValueError:
        from Crypto.Hash import RIPEMD160

        digest = RIPEMD160.new()
        digest.update(sha_hash)
        return digest.digest()


def compress_public_key(raw_public_key: bytes) -> bytes:
    """
    Convert a 64-byte secp256k1 public-key body x || y into compressed SEC form.
    """
    if len(raw_public_key) != 64:
        raise ValueError("A secp256k1 public-key body must be 64 bytes.")

    x_coordinate = raw_public_key[:32]
    y_coordinate = int.from_bytes(raw_public_key[32:], byteorder="big")

    prefix = b"\x03" if y_coordinate % 2 else b"\x02"
    return prefix + x_coordinate


def bitcoin_address_from_public_key_hex(public_key_hex: str) -> str:
    """Derive a Bitcoin P2PKH-style address from a raw 64-byte public key."""
    raw_public_key = bytes.fromhex(public_key_hex)
    compressed_key = compress_public_key(raw_public_key)

    payload = b"\x00" + hash160(compressed_key)
    return base58check_encode(payload)


def utc_timestamp() -> str:
    """Produce a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


class Wallet:
    """
    Educational secp256k1 wallet.

    It creates a test key pair, derives a Bitcoin-style address, and signs
    messages. It must never be used for real funds.
    """

    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key
        self._verifying_key = signing_key.get_verifying_key()

    @classmethod
    def create(cls) -> "Wallet":
        return cls(SigningKey.generate(curve=SECP256k1))

    @property
    def public_key_hex(self) -> str:
        """Raw uncompressed secp256k1 public-key body: x || y, 64 bytes."""
        return self._verifying_key.to_string().hex()

    @property
    def address(self) -> str:
        """Bitcoin P2PKH-style address derived from this wallet's public key."""
        return bitcoin_address_from_public_key_hex(self.public_key_hex)

    def sign(self, message: bytes) -> str:
        """
        Create a deterministic DER-encoded ECDSA signature.

        Deterministic signing follows the same principle as RFC 6979: it avoids
        accidental random nonce failures in this educational implementation.
        """
        signature = self._signing_key.sign_deterministic(
            message,
            hashfunc=hashlib.sha256,
            sigencode=util.sigencode_der,
        )
        return signature.hex()

    @staticmethod
    def verify(
        public_key_hex: str,
        message: bytes,
        signature_hex: str,
    ) -> bool:
        """Verify a DER-encoded ECDSA signature against a public key."""
        try:
            verifying_key = VerifyingKey.from_string(
                bytes.fromhex(public_key_hex),
                curve=SECP256k1,
            )
            return verifying_key.verify(
                bytes.fromhex(signature_hex),
                message,
                hashfunc=hashlib.sha256,
                sigdecode=util.sigdecode_der,
            )
        except (BadSignatureError, ValueError, TypeError):
            return False


@dataclass
class Transaction:
    """
    One signed transfer in the educational blockchain.

    Amounts are integer units, not floating-point currency values.
    """

    sender: str
    recipient: str
    amount: int
    timestamp: str
    nonce: str
    sender_public_key: str
    signature: str | None = None
    kind: str = "TRANSFER"

    @classmethod
    def create_transfer(
        cls,
        sender_wallet: Wallet,
        recipient: str,
        amount: int,
    ) -> "Transaction":
        """Create and sign a transfer transaction."""
        transaction = cls(
            sender=sender_wallet.address,
            recipient=recipient,
            amount=amount,
            timestamp=utc_timestamp(),
            nonce=secrets.token_hex(16),
            sender_public_key=sender_wallet.public_key_hex,
        )

        transaction.signature = sender_wallet.sign(transaction.signing_bytes())
        return transaction

    def signing_payload(self) -> dict[str, Any]:
        """
        Return exactly the fields protected by the signature.

        The signature itself is excluded to avoid circular hashing.
        """
        return {
            "kind": self.kind,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "sender_public_key": self.sender_public_key,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(self.signing_payload())

    @property
    def txid(self) -> str:
        """Transaction identifier commits to the signed payload and signature."""
        complete_data = {
            **self.signing_payload(),
            "signature": self.signature,
        }
        return sha256(canonical_json(complete_data)).hex()

    def is_valid(self) -> bool:
        """Validate transaction structure, address binding, and signature."""
        if self.kind == "COINBASE":
            return (
                self.sender == "SYSTEM"
                and bool(self.recipient)
                and type(self.amount) is int
                and self.amount > 0
                and bool(self.timestamp)
                and bool(self.nonce)
                and self.sender_public_key == ""
                and self.signature is None
            )

        if self.kind != "TRANSFER":
            return False

        if not self.sender or not self.recipient:
            return False

        if type(self.amount) is not int or self.amount <= 0:
            return False

        if not self.timestamp or not self.nonce:
            return False

        if not self.sender_public_key or not self.signature:
            return False

        try:
            derived_sender_address = bitcoin_address_from_public_key_hex(
                self.sender_public_key
            )
        except (ValueError, TypeError):
            return False

        if derived_sender_address != self.sender:
            return False

        return Wallet.verify(
            self.sender_public_key,
            self.signing_bytes(),
            self.signature,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a serialisable transaction view."""
        return {
            **self.signing_payload(),
            "signature": self.signature,
            "txid": self.txid,
        }

    @classmethod
    def create_coinbase(
        cls,
        recipient: str,
        amount: int,
    ) -> "Transaction":
        """
        Create a system-issued transaction for genesis allocation or mining reward.

        This is allowed only when Blockchain validates its position and amount.
        """
        return cls(
            sender="SYSTEM",
            recipient=recipient,
            amount=amount,
            timestamp=utc_timestamp(),
            nonce=secrets.token_hex(16),
            sender_public_key="",
            signature=None,
            kind="COINBASE",
        )


@dataclass(frozen=True)
class MerkleProofStep:
    """
    One sibling hash used to reconstruct a Merkle root.

    position:
    - "left": sibling hash is concatenated before the current hash
    - "right": sibling hash is concatenated after the current hash
    """

    position: str
    sibling_hash: bytes


class MerkleTree:
    """
    Educational binary Merkle tree.

    Leaves are transaction IDs. Parent nodes are calculated as:

        SHA256(left_child_hash || right_child_hash)

    For an odd number of leaves, the final hash is duplicated.
    """

    def __init__(self, transactions: list[Transaction]) -> None:
        if not transactions:
            raise ValueError(
                "A Merkle tree requires at least one transaction.")

        self.transactions = list(transactions)
        self.levels = self._build_levels()

    @staticmethod
    def _hash_pair(left_hash: bytes, right_hash: bytes) -> bytes:
        return sha256(left_hash + right_hash)

    def _build_levels(self) -> list[list[bytes]]:
        """
        Build levels from transaction-ID leaves to a single Merkle root.
        """
        current_level = [
            bytes.fromhex(transaction.txid)
            for transaction in self.transactions
        ]

        levels = [current_level]

        while len(current_level) > 1:
            working_level = current_level[:]

            # Standard classroom rule for an odd number of nodes:
            # duplicate the final node before calculating parents.
            if len(working_level) % 2 == 1:
                working_level.append(working_level[-1])

            next_level = []

            for index in range(0, len(working_level), 2):
                parent = self._hash_pair(
                    working_level[index],
                    working_level[index + 1],
                )
                next_level.append(parent)

            levels.append(next_level)
            current_level = next_level

        return levels

    @property
    def merkle_root(self) -> str:
        """Return the final Merkle root as hexadecimal text."""
        return self.levels[-1][0].hex()

    def get_proof(self, transaction_index: int) -> list[MerkleProofStep]:
        """
        Build an SPV-style inclusion proof for one transaction index.
        """
        if transaction_index < 0 or transaction_index >= len(self.transactions):
            raise IndexError("Transaction index is outside the Merkle tree.")

        proof: list[MerkleProofStep] = []
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
                MerkleProofStep(
                    position=sibling_position,
                    sibling_hash=working_level[sibling_index],
                )
            )

            current_index //= 2

        return proof

    @staticmethod
    def verify_proof(
        transaction_id: str,
        proof: list[MerkleProofStep],
        expected_root: str,
    ) -> bool:
        """
        Verify that a transaction ID belongs to a tree with expected_root.
        """
        try:
            current_hash = bytes.fromhex(transaction_id)
            expected_root_bytes = bytes.fromhex(expected_root)
        except ValueError:
            return False

        if len(current_hash) != 32 or len(expected_root_bytes) != 32:
            return False

        for step in proof:
            if step.position == "left":
                current_hash = MerkleTree._hash_pair(
                    step.sibling_hash,
                    current_hash,
                )
            elif step.position == "right":
                current_hash = MerkleTree._hash_pair(
                    current_hash,
                    step.sibling_hash,
                )
            else:
                return False

        return current_hash == expected_root_bytes


@dataclass
class Block:
    """
    Educational block containing signed transactions and a Merkle root.

    The block hash commits to:
    - index
    - previous block hash
    - timestamp
    - Merkle root
    - nonce

    Transaction contents are committed indirectly through the Merkle root.
    """

    index: int
    previous_hash: str
    timestamp: str
    transactions: list[Transaction]
    nonce: int
    merkle_root: str
    hash: str

    @classmethod
    def create(
        cls,
        index: int,
        previous_hash: str,
        transactions: list[Transaction],
    ) -> "Block":
        """Create an unmined block from one or more transactions."""
        if not transactions:
            raise ValueError("A block requires at least one transaction.")

        merkle_tree = MerkleTree(transactions)

        block = cls(
            index=index,
            previous_hash=previous_hash,
            timestamp=utc_timestamp(),
            transactions=list(transactions),
            nonce=0,
            merkle_root=merkle_tree.merkle_root,
            hash="",
        )

        block.hash = block.calculate_hash()
        return block

    def header_payload(self) -> dict[str, Any]:
        """Return deterministic block-header fields used for hashing."""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
        }

    def calculate_hash(self) -> str:
        """Calculate SHA-256 of the deterministic block header."""
        return sha256(canonical_json(self.header_payload())).hex()

    def mine(self, difficulty: int) -> str:
        """
        Mine the block by searching for a hash with N leading hexadecimal zeroes.
        """
        if type(difficulty) is not int or difficulty < 1 or difficulty > 6:
            raise ValueError("Difficulty must be an integer between 1 and 6.")

        if not all(transaction.is_valid() for transaction in self.transactions):
            raise ValueError(
                "Cannot mine a block containing invalid transactions.")

        # Recalculate the Merkle root before mining in case the transaction list changed.
        self.merkle_root = MerkleTree(self.transactions).merkle_root

        prefix = "0" * difficulty
        self.nonce = 0

        while True:
            self.hash = self.calculate_hash()

            if self.hash.startswith(prefix):
                return self.hash

            self.nonce += 1

    def is_valid(self, difficulty: int) -> bool:
        """
        Verify transactions, Merkle root, hash integrity, and Proof-of-Work.
        """
        if type(self.index) is not int or self.index < 0:
            return False

        if type(self.nonce) is not int or self.nonce < 0:
            return False

        if not self.timestamp:
            return False

        try:
            previous_hash_bytes = bytes.fromhex(self.previous_hash)
            block_hash_bytes = bytes.fromhex(self.hash)
        except ValueError:
            return False

        if len(previous_hash_bytes) != 32 or len(block_hash_bytes) != 32:
            return False

        if not all(transaction.is_valid() for transaction in self.transactions):
            return False

        try:
            expected_merkle_root = MerkleTree(self.transactions).merkle_root
        except ValueError:
            return False

        if self.merkle_root != expected_merkle_root:
            return False

        if self.hash != self.calculate_hash():
            return False

        return self.hash.startswith("0" * difficulty)

    def to_dict(self) -> dict[str, Any]:
        """Return a serialisable view of the block."""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": [
                transaction.to_dict()
                for transaction in self.transactions
            ],
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash,
        }


class Blockchain:
    """
    Educational account-based blockchain.

    Features:
    - Genesis allocation
    - Signed transfer transactions
    - Pending transaction pool
    - Mining reward
    - Proof-of-Work blocks
    - Balance validation
    - Merkle/SPV proof lookup

    This is for education only. It is not a real cryptocurrency network.
    """

    SYSTEM_ADDRESS = "SYSTEM"

    def __init__(
        self,
        genesis_recipient: str,
        initial_balance: int = 100,
        mining_reward: int = 5,
        difficulty: int = 3,
    ) -> None:
        if not genesis_recipient:
            raise ValueError("A genesis recipient is required.")

        if type(initial_balance) is not int or initial_balance <= 0:
            raise ValueError("Initial balance must be a positive integer.")

        if type(mining_reward) is not int or mining_reward <= 0:
            raise ValueError("Mining reward must be a positive integer.")

        if type(difficulty) is not int or difficulty < 1 or difficulty > 6:
            raise ValueError("Difficulty must be an integer between 1 and 6.")

        self.genesis_recipient = genesis_recipient
        self.initial_balance = initial_balance
        self.mining_reward = mining_reward
        self.difficulty = difficulty

        self.chain: list[Block] = []
        self.pending_transactions: list[Transaction] = []

        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        genesis_transaction = Transaction.create_coinbase(
            recipient=self.genesis_recipient,
            amount=self.initial_balance,
        )

        genesis_block = Block.create(
            index=0,
            previous_hash="0" * 64,
            transactions=[genesis_transaction],
        )

        genesis_block.mine(self.difficulty)
        self.chain.append(genesis_block)

    @staticmethod
    def _apply_transaction(
        balances: dict[str, int],
        transaction: Transaction,
    ) -> None:
        """Apply a transaction to an in-memory balance map."""
        if transaction.kind == "COINBASE":
            balances[transaction.recipient] = (
                balances.get(transaction.recipient, 0) + transaction.amount
            )
            return

        balances[transaction.sender] = (
            balances.get(transaction.sender, 0) - transaction.amount
        )

        balances[transaction.recipient] = (
            balances.get(transaction.recipient, 0) + transaction.amount
        )

    def _confirmed_balances(self) -> dict[str, int]:
        """Replay confirmed blocks to calculate balances."""
        balances: dict[str, int] = {}

        for block in self.chain:
            for transaction in block.transactions:
                self._apply_transaction(balances, transaction)

        return balances

    def _confirmed_transaction_ids(self) -> set[str]:
        """Return all transaction IDs already confirmed in the chain."""
        return {
            transaction.txid
            for block in self.chain
            for transaction in block.transactions
        }

    def _available_balance_after_pending(self, address: str) -> int:
        """
        Calculate available balance after confirmed chain activity and
        already-queued pending transactions.

        This permits Bob to spend an incoming transaction from Alice if Alice's
        transaction appears earlier in the same pending-transaction order.
        """
        balances = self._confirmed_balances()

        for transaction in self.pending_transactions:
            self._apply_transaction(balances, transaction)

        return balances.get(address, 0)

    def get_balance(self, address: str) -> int:
        """Return confirmed balance only; excludes unmined transactions."""
        return self._confirmed_balances().get(address, 0)

    def add_transaction(self, transaction: Transaction) -> None:
        """Validate and add a signed transfer to the pending pool."""
        if not self.is_chain_valid():
            raise ValueError("Cannot add a transaction to an invalid chain.")

        if transaction.kind != "TRANSFER":
            raise ValueError(
                "Only signed TRANSFER transactions may enter the mempool.")

        if not transaction.is_valid():
            raise ValueError("Transaction signature or structure is invalid.")

        confirmed_ids = self._confirmed_transaction_ids()
        pending_ids = {
            pending_transaction.txid
            for pending_transaction in self.pending_transactions
        }

        if transaction.txid in confirmed_ids or transaction.txid in pending_ids:
            raise ValueError("Duplicate transaction ID is not allowed.")

        available_balance = self._available_balance_after_pending(
            transaction.sender
        )

        if available_balance < transaction.amount:
            raise ValueError("Insufficient available balance for transaction.")

        self.pending_transactions.append(transaction)

    def mine_pending(self, miner_address: str) -> Block:
        """
        Mine all pending transfers into one block and issue the miner reward.

        The reward transaction is first in the block, followed by user transfers.
        """
        if not miner_address:
            raise ValueError("Miner address is required.")

        if not self.pending_transactions:
            raise ValueError("There are no pending transactions to mine.")

        if not self.is_chain_valid():
            raise ValueError("Cannot mine on an invalid chain.")

        reward_transaction = Transaction.create_coinbase(
            recipient=miner_address,
            amount=self.mining_reward,
        )

        block = Block.create(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=[
                reward_transaction,
                *self.pending_transactions,
            ],
        )

        block.mine(self.difficulty)

        if not block.is_valid(self.difficulty):
            raise RuntimeError(
                "Newly mined block failed structural validation.")

        self.chain.append(block)
        self.pending_transactions = []

        return block

    def _validate_genesis_block(
        self,
        block: Block,
        balances: dict[str, int],
        transaction_ids: set[str],
    ) -> bool:
        """Validate the configured genesis allocation."""
        if block.index != 0:
            return False

        if block.previous_hash != "0" * 64:
            return False

        if not block.is_valid(self.difficulty):
            return False

        if len(block.transactions) != 1:
            return False

        transaction = block.transactions[0]

        if transaction.kind != "COINBASE":
            return False

        if not transaction.is_valid():
            return False

        if transaction.recipient != self.genesis_recipient:
            return False

        if transaction.amount != self.initial_balance:
            return False

        if transaction.txid in transaction_ids:
            return False

        transaction_ids.add(transaction.txid)
        self._apply_transaction(balances, transaction)

        return True

    def _validate_regular_block(
        self,
        block: Block,
        balances: dict[str, int],
        transaction_ids: set[str],
    ) -> bool:
        """Validate reward rules, transaction order, and account balances."""
        if not block.is_valid(self.difficulty):
            return False

        if len(block.transactions) < 2:
            return False

        reward_transaction = block.transactions[0]

        if reward_transaction.kind != "COINBASE":
            return False

        if not reward_transaction.is_valid():
            return False

        if reward_transaction.amount != self.mining_reward:
            return False

        if reward_transaction.txid in transaction_ids:
            return False

        transaction_ids.add(reward_transaction.txid)
        self._apply_transaction(balances, reward_transaction)

        for transaction in block.transactions[1:]:
            if transaction.kind != "TRANSFER":
                return False

            if not transaction.is_valid():
                return False

            if transaction.txid in transaction_ids:
                return False

            if balances.get(transaction.sender, 0) < transaction.amount:
                return False

            transaction_ids.add(transaction.txid)
            self._apply_transaction(balances, transaction)

        return True

    def is_chain_valid(self) -> bool:
        """
        Validate block links, Proof-of-Work, transaction signatures,
        rewards, duplicate transaction IDs, and sequential balances.
        """
        if not self.chain:
            return False

        balances: dict[str, int] = {}
        transaction_ids: set[str] = set()

        genesis_block = self.chain[0]

        if not self._validate_genesis_block(
            genesis_block,
            balances,
            transaction_ids,
        ):
            return False

        previous_block = genesis_block

        for expected_index, block in enumerate(self.chain[1:], start=1):
            if block.index != expected_index:
                return False

            if block.previous_hash != previous_block.hash:
                return False

            if not self._validate_regular_block(
                block,
                balances,
                transaction_ids,
            ):
                return False

            previous_block = block

        return True

    def generate_spv_proof(self, transaction_id: str) -> dict[str, Any]:
        """
        Locate a confirmed transaction and return its SPV inclusion proof.
        """
        for block in self.chain:
            for index, transaction in enumerate(block.transactions):
                if transaction.txid == transaction_id:
                    tree = MerkleTree(block.transactions)

                    return {
                        "block_index": block.index,
                        "transaction_index": index,
                        "merkle_root": tree.merkle_root,
                        "proof": tree.get_proof(index),
                    }

        raise ValueError(
            "Transaction ID was not found in the confirmed chain.")
