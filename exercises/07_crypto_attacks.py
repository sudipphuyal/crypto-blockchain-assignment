from __future__ import annotations

import argparse
import hashlib
import json
import math
import secrets

from ecdsa import BadSignatureError, SECP256k1, SigningKey, util


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def canonical_json(data: dict) -> bytes:
    """
    Deterministic serialisation for this classroom simulation.

    This is not Ethereum RLP encoding. It is only used to show why a signature
    must bind the transaction to a specific chain identifier.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------------------
# Exercise 7.2 — Birthday attack with a 16-bit mini hash
# ---------------------------------------------------------------------

def mini_hash_16(data: bytes) -> int:
    """
    Return the first 16 bits of SHA-256.

    This intentionally tiny output has only 2^16 possible values, making
    collisions feasible for a classroom experiment.
    """
    return int.from_bytes(sha256(data)[:2], byteorder="big")


def find_mini_hash_collision(max_attempts: int = 200_000) -> dict:
    """
    Generate random inputs until two distinct inputs have the same 16-bit hash.
    """
    seen: dict[int, bytes] = {}

    for attempt in range(1, max_attempts + 1):
        message = secrets.token_bytes(16)
        digest = mini_hash_16(message)

        if digest in seen and seen[digest] != message:
            return {
                "attempts": attempt,
                "hash_value": digest,
                "message_a": seen[digest],
                "message_b": message,
            }

        seen[digest] = message

    raise RuntimeError(
        f"No collision found in {max_attempts:,} attempts. "
        "Increase the limit and run again."
    )


# ---------------------------------------------------------------------
# Exercise 7.1 — 51% attack cost model
# ---------------------------------------------------------------------

def estimate_majority_hashrate_cost(
    network_hashrate_eh_per_second: float,
    rental_cost_usd_per_th_per_day: float,
) -> dict:
    """
    Educational economic model only.

    Inputs:
    - network_hashrate_eh_per_second: network hash rate in EH/s
    - rental_cost_usd_per_th_per_day: rental rate in USD per TH/s per day

    No network access or mining action is performed.
    """
    if network_hashrate_eh_per_second <= 0:
        raise ValueError("Network hash rate must be greater than zero.")

    if rental_cost_usd_per_th_per_day <= 0:
        raise ValueError("Rental cost must be greater than zero.")

    required_hashrate_eh = network_hashrate_eh_per_second * 0.51
    required_hashrate_th = required_hashrate_eh * 1_000_000

    daily_cost_usd = required_hashrate_th * rental_cost_usd_per_th_per_day
    hourly_cost_usd = daily_cost_usd / 24

    return {
        "required_hashrate_eh": required_hashrate_eh,
        "required_hashrate_th": required_hashrate_th,
        "daily_cost_usd": daily_cost_usd,
        "hourly_cost_usd": hourly_cost_usd,
    }


# ---------------------------------------------------------------------
# Exercise 7.3 — Replay attack and Chain ID model
# ---------------------------------------------------------------------

def verify_signature(
    verifying_key,
    message: bytes,
    signature_der: bytes,
) -> bool:
    try:
        return verifying_key.verify(
            signature_der,
            message,
            hashfunc=hashlib.sha256,
            sigdecode=util.sigdecode_der,
        )
    except BadSignatureError:
        return False


def sign_message(signing_key: SigningKey, message: bytes) -> bytes:
    return signing_key.sign_deterministic(
        message,
        hashfunc=hashlib.sha256,
        sigencode=util.sigencode_der,
    )


def replay_protection_demo() -> dict:
    """
    Conceptual model of EIP-155-style chain separation.

    Real Ethereum uses Keccak-256, RLP serialisation, and transaction-signature
    fields. This demonstration uses canonical JSON and SHA-256 only to make
    the security concept easy to inspect.
    """
    alice_private_key = SigningKey.generate(curve=SECP256k1)
    alice_public_key = alice_private_key.get_verifying_key()

    transaction = {
        "nonce": 7,
        "to": "0xB0B0000000000000000000000000000000000000",
        "value": "1.0",
        "gasLimit": 21000,
    }

    # Legacy-style payload: no chain identifier.
    legacy_message = canonical_json(transaction)
    legacy_signature = sign_message(alice_private_key, legacy_message)

    # EIP-155-style payloads: chain identifier is part of what is signed.
    ethereum_payload = {**transaction, "chainId": 1}
    ethereum_classic_payload = {**transaction, "chainId": 61}

    ethereum_message = canonical_json(ethereum_payload)
    ethereum_classic_message = canonical_json(ethereum_classic_payload)

    chain_bound_signature = sign_message(alice_private_key, ethereum_message)

    return {
        "legacy_valid_on_eth": verify_signature(
            alice_public_key,
            legacy_message,
            legacy_signature,
        ),
        "legacy_valid_on_etc": verify_signature(
            alice_public_key,
            legacy_message,
            legacy_signature,
        ),
        "chain_bound_valid_on_eth": verify_signature(
            alice_public_key,
            ethereum_message,
            chain_bound_signature,
        ),
        "chain_bound_valid_on_etc": verify_signature(
            alice_public_key,
            ethereum_classic_message,
            chain_bound_signature,
        ),
        "legacy_signature_length": len(legacy_signature),
        "chain_bound_signature_length": len(chain_bound_signature),
    }


# ---------------------------------------------------------------------
# Exercise 7.5 — Commit-reveal against front-running
# ---------------------------------------------------------------------

def create_commitment(action: str, salt: str) -> str:
    """
    Commitment = SHA-256(canonical JSON containing action + secret salt).

    The salt must be private and unpredictable until the reveal phase.
    """
    payload = {
        "action": action,
        "salt": salt,
    }
    return sha256_hex(canonical_json(payload))


def verify_commitment(
    commitment: str,
    revealed_action: str,
    revealed_salt: str,
) -> bool:
    return commitment == create_commitment(revealed_action, revealed_salt)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exercise 7: Cryptographic attacks and defences"
    )
    parser.add_argument(
        "--network-hashrate-eh",
        type=float,
        help="Optional current network hash rate in EH/s for the cost model.",
    )
    parser.add_argument(
        "--rental-usd-per-th-day",
        type=float,
        help="Optional rental price in USD per TH/s per day for the cost model.",
    )
    args = parser.parse_args()

    # ------------------------------------------------------------
    # Exercise 7.2 — Birthday collision
    # ------------------------------------------------------------
    print_section("Exercise 7.2 — Birthday Attack: 16-bit Mini Hash")

    collision = find_mini_hash_collision()

    rough_birthday_scale = int(math.sqrt(2**16))
    expected_mean_attempts = math.sqrt(math.pi * (2**16) / 2)

    print("Mini-hash output space:", "2^16 =", 2**16)
    print("Rule-of-thumb birthday scale sqrt(2^16):", rough_birthday_scale)
    print(
        f"Approximate mean attempts to first collision: {expected_mean_attempts:.1f}")

    print("\nCollision found:")
    print("Attempts:", collision["attempts"])
    print("Input A:", collision["message_a"].hex())
    print("Input B:", collision["message_b"].hex())
    print(f"mini_hash_16(A): {collision['hash_value']:04x}")
    print(f"mini_hash_16(B): {collision['hash_value']:04x}")

    assert collision["message_a"] != collision["message_b"]
    assert mini_hash_16(collision["message_a"]) == mini_hash_16(
        collision["message_b"]
    )

    print("Collision verification: PASSED")

    # ------------------------------------------------------------
    # Exercise 7.1 — 51% attack economics model
    # ------------------------------------------------------------
    print_section("Exercise 7.1 — Majority Hashrate Cost Model")

    print(
        "This section performs only an economic estimate. "
        "It does not interact with, rent from, or attack any network."
    )

    if (
        args.network_hashrate_eh is not None
        and args.rental_usd_per_th_day is not None
    ):
        estimate = estimate_majority_hashrate_cost(
            args.network_hashrate_eh,
            args.rental_usd_per_th_day,
        )

        print("Network hash rate:", args.network_hashrate_eh, "EH/s")
        print(
            "Rental price:",
            args.rental_usd_per_th_day,
            "USD per TH/s per day",
        )
        print(
            "Estimated 51% hash rate:",
            f"{estimate['required_hashrate_eh']:,.2f}",
            "EH/s",
        )
        print(
            "Equivalent hash rate:",
            f"{estimate['required_hashrate_th']:,.0f}",
            "TH/s",
        )
        print(
            "Estimated cost per hour:",
            f"${estimate['hourly_cost_usd']:,.2f}",
        )
        print(
            "Estimated cost per day:",
            f"${estimate['daily_cost_usd']:,.2f}",
        )
    else:
        print("No current figures supplied.")
        print(
            "Later, use dated public sources and run the command in this format:"
        )
        print(
            "python exercises/07_crypto_attacks.py "
            "--network-hashrate-eh <VALUE> "
            "--rental-usd-per-th-day <VALUE>"
        )
        print(
            "For the report, cite the source, date, network hash rate, "
            "rental price, units, and calculation assumptions."
        )

    # ------------------------------------------------------------
    # Exercise 7.3 — Replay attack / Chain ID
    # ------------------------------------------------------------
    print_section("Exercise 7.3 — Replay Attack and Chain ID")

    replay = replay_protection_demo()

    print("Conceptual legacy transaction without chain ID:")
    print("Signature valid for ETH scenario:", replay["legacy_valid_on_eth"])
    print("Signature valid for ETC scenario:", replay["legacy_valid_on_etc"])

    print("\nConceptual chain-bound transaction:")
    print("Signature valid for chainId=1:", replay["chain_bound_valid_on_eth"])
    print("Signature valid for chainId=61:",
          replay["chain_bound_valid_on_etc"])

    assert replay["legacy_valid_on_eth"] is True
    assert replay["legacy_valid_on_etc"] is True
    assert replay["chain_bound_valid_on_eth"] is True
    assert replay["chain_bound_valid_on_etc"] is False

    print("Replay-protection demonstration: PASSED")
    print(
        "Note: this is a conceptual model. Real EIP-155 uses Ethereum "
        "transaction encoding and Keccak-256 rather than this JSON model."
    )

    # ------------------------------------------------------------
    # Exercise 7.5 — Commit-reveal
    # ------------------------------------------------------------
    print_section("Exercise 7.5 — Commit-Reveal Against Front-Running")

    intended_action = "buy 100 tokens"
    secret_salt = secrets.token_hex(16)

    commitment = create_commitment(intended_action, secret_salt)

    valid_reveal = verify_commitment(
        commitment,
        intended_action,
        secret_salt,
    )

    altered_reveal = verify_commitment(
        commitment,
        "buy 1000 tokens",
        secret_salt,
    )

    print("Committed action: [hidden until reveal]")
    print("Commitment hash:", commitment)
    print("\nReveal action:", intended_action)
    print("Reveal valid:", valid_reveal)
    print("Modified reveal valid:", altered_reveal)

    assert valid_reveal is True
    assert altered_reveal is False

    print("Commit-reveal verification: PASSED")

    # ------------------------------------------------------------
    # Written-analysis reminders
    # ------------------------------------------------------------
    print_section("Written Analysis Reminders")

    print(
        "51% attack: an attacker with majority effective hash power may "
        "reorganise recent blocks and double-spend its own transactions, "
        "but cannot create arbitrary signatures for other users."
    )
    print(
        "MEV/front-running: public pending transactions can reveal profitable "
        "ordering opportunities. Commit-reveal can hide an action during the "
        "commit phase, but practical designs also need deadlines and rules "
        "for non-reveal behaviour."
    )
    print(
        "Quantum risk: sufficiently capable fault-tolerant quantum computers "
        "could threaten current public-key cryptography such as ECC. "
        "Post-quantum migration is an active research and standardisation area."
    )

    print("\nExercise 7 completed successfully.")


if __name__ == "__main__":
    main()
