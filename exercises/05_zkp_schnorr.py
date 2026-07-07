from __future__ import annotations

import math
import random
import secrets


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


# ---------------------------------------------------------------------
# Part A: Alibaba cave simulation
# ---------------------------------------------------------------------

def simulate_honest_prover(rounds: int) -> bool:
    """
    An honest prover knows the secret opening mechanism and can always
    exit from the side requested by the verifier.
    """
    return True


def simulate_dishonest_prover_once(rounds: int) -> bool:
    """
    A dishonest prover does not know the secret.

    In every round, the prover randomly chooses one side before hearing
    the verifier's requested exit side. The prover succeeds only if the
    requested side matches the side already chosen.

    Probability of passing all rounds: (1/2)^rounds.
    """
    for _ in range(rounds):
        prover_initial_side = secrets.choice(["A", "B"])
        verifier_requested_side = secrets.choice(["A", "B"])

        if prover_initial_side != verifier_requested_side:
            return False

    return True


def estimate_dishonest_success_rate(rounds: int, simulations: int) -> tuple[int, float]:
    """
    Run repeated simulations only to illustrate the probability.
    For large round counts, the theoretical value is more meaningful.
    """
    successful_attempts = 0

    for _ in range(simulations):
        if simulate_dishonest_prover_once(rounds):
            successful_attempts += 1

    return successful_attempts, successful_attempts / simulations


# ---------------------------------------------------------------------
# Part B: Schnorr identification protocol
# ---------------------------------------------------------------------

def modular_inverse(value: int, modulus: int) -> int:
    """Return the modular inverse of value modulo modulus."""
    return pow(value % modulus, -1, modulus)


def schnorr_setup() -> dict[str, int]:
    """
    Educational small-group setup.

    p = 23 is a small prime.
    q = 11 is a prime divisor of p - 1.
    g = 2 has order q in the multiplicative group modulo p.

    These values are deliberately tiny and insecure. They are used only
    to make every calculation easy to inspect.
    """
    p = 23
    q = 11
    g = 2

    private_secret_x = secrets.randbelow(q - 1) + 1
    public_key_y = pow(g, private_secret_x, p)

    return {
        "p": p,
        "q": q,
        "g": g,
        "x": private_secret_x,
        "y": public_key_y,
    }


def schnorr_prove_and_verify(
    p: int,
    q: int,
    g: int,
    private_secret_x: int,
    public_key_y: int,
) -> dict[str, int | bool]:
    """
    Schnorr identification protocol:

    1. Prover selects random r and sends t = g^r mod p.
    2. Verifier chooses a random challenge c.
    3. Prover computes s = r + c*x mod q.
    4. Verifier checks:
       g^s mod p == t * y^c mod p
    """
    random_nonce_r = secrets.randbelow(q - 1) + 1
    commitment_t = pow(g, random_nonce_r, p)

    challenge_c = secrets.randbelow(q)

    response_s = (random_nonce_r + challenge_c * private_secret_x) % q

    left_side = pow(g, response_s, p)
    right_side = (commitment_t * pow(public_key_y, challenge_c, p)) % p

    return {
        "r": random_nonce_r,
        "t": commitment_t,
        "c": challenge_c,
        "s": response_s,
        "left_side": left_side,
        "right_side": right_side,
        "valid": left_side == right_side,
    }


def simulate_invalid_schnorr_response(
    p: int,
    q: int,
    g: int,
    public_key_y: int,
) -> dict[str, int | bool]:
    """
    Demonstrate that a randomly guessed response normally fails.

    This is not a formal proof of soundness. It is only a classroom
    illustration of why a prover needs knowledge of the secret x.
    """
    fake_nonce_r = secrets.randbelow(q - 1) + 1
    fake_commitment_t = pow(g, fake_nonce_r, p)
    challenge_c = secrets.randbelow(q)
    guessed_response_s = secrets.randbelow(q)

    left_side = pow(g, guessed_response_s, p)
    right_side = (fake_commitment_t * pow(public_key_y, challenge_c, p)) % p

    return {
        "t": fake_commitment_t,
        "c": challenge_c,
        "guessed_s": guessed_response_s,
        "left_side": left_side,
        "right_side": right_side,
        "valid": left_side == right_side,
    }


def main() -> None:
    # -----------------------------------------------------------------
    # Exercise 5.1: Alibaba cave
    # -----------------------------------------------------------------
    print_section("Exercise 5.1 — Alibaba Cave Simulation")

    for rounds in [10, 30]:
        theoretical_fraud_probability = (1 / 2) ** rounds
        theoretical_percentage = theoretical_fraud_probability * 100

        print(f"Rounds: {rounds}")
        print(
            "Honest prover passes all rounds:",
            simulate_honest_prover(rounds),
        )
        print(
            "Theoretical dishonest success probability:",
            f"1 / 2^{rounds} = {theoretical_fraud_probability:.12f}",
        )
        print(
            "Theoretical dishonest success percentage:",
            f"{theoretical_percentage:.12f}%",
        )

        if rounds == 10:
            simulations = 20_000
            successes, estimated_rate = estimate_dishonest_success_rate(
                rounds,
                simulations,
            )

            print(f"Simulation runs: {simulations:,}")
            print(f"Dishonest successful runs: {successes}")
            print(f"Estimated success rate: {estimated_rate:.8f}")

        print()

    # -----------------------------------------------------------------
    # Exercise 5.2: Schnorr protocol
    # -----------------------------------------------------------------
    print_section("Exercise 5.2 — Schnorr Identification Protocol")

    setup = schnorr_setup()

    print("Toy group parameters:")
    print("p =", setup["p"])
    print("q =", setup["q"])
    print("g =", setup["g"])

    print("\nProver secret and public value:")
    print("Private secret x:", setup["x"],
          "(printed only for classroom validation)")
    print("Public key Y = g^x mod p:", setup["y"])

    result = schnorr_prove_and_verify(
        p=setup["p"],
        q=setup["q"],
        g=setup["g"],
        private_secret_x=setup["x"],
        public_key_y=setup["y"],
    )

    print("\nProtocol messages:")
    print("Prover random nonce r:", result["r"])
    print("Commitment t = g^r mod p:", result["t"])
    print("Verifier challenge c:", result["c"])
    print("Response s = r + c*x mod q:", result["s"])

    print("\nVerifier equation:")
    print("Left side:  g^s mod p =", result["left_side"])
    print("Right side: t * Y^c mod p =", result["right_side"])
    print("Verification result:", result["valid"])

    assert result["valid"] is True
    print("Schnorr proof verification: PASSED")

    # -----------------------------------------------------------------
    # Classroom soundness illustration
    # -----------------------------------------------------------------
    print_section("Soundness Illustration — Random Guess")

    invalid_result = simulate_invalid_schnorr_response(
        p=setup["p"],
        q=setup["q"],
        g=setup["g"],
        public_key_y=setup["y"],
    )

    print("Fake commitment t:", invalid_result["t"])
    print("Verifier challenge c:", invalid_result["c"])
    print("Guessed response s:", invalid_result["guessed_s"])
    print("Left side:  g^s mod p =", invalid_result["left_side"])
    print("Right side: t * Y^c mod p =", invalid_result["right_side"])
    print("Random guessed proof accepted:", invalid_result["valid"])

    # -----------------------------------------------------------------
    # Exercise 5.3: Conceptual shielded transaction
    # -----------------------------------------------------------------
    print_section("Exercise 5.3 — Conceptual Zcash Shielded Transaction")

    input_amount = 10
    output_amount = 9
    fee = 1

    print("Private values used only for this classroom example:")
    print("Input amount:", input_amount)
    print("Output amount:", output_amount)
    print("Fee:", fee)
    print(
        "Balance relation holds:",
        input_amount == output_amount + fee,
    )

    print("\nConceptual zero-knowledge statement:")
    print(
        "The prover can prove that committed inputs equal committed outputs "
        "plus the transaction fee, without publicly revealing the amounts or "
        "the participating identities."
    )
    print(
        "A real shielded Zcash transaction additionally uses cryptographic "
        "commitments, nullifiers, encryption, and a zk-SNARK proof. "
        "This script does not implement those production mechanisms."
    )

    # -----------------------------------------------------------------
    # Comparison notes
    # -----------------------------------------------------------------
    print_section("ZKP Technology Comparison")

    print("zk-SNARKs:")
    print(
        "- Usually produce compact proofs and fast verification."
    )
    print(
        "- Some constructions require a trusted setup."
    )

    print("\nzk-STARKs:")
    print(
        "- Avoid trusted setup in common designs and use hash-based techniques."
    )
    print(
        "- Proofs are generally larger than zk-SNARK proofs."
    )

    print("\nzkRollups:")
    print(
        "- Batch many Layer-2 transactions and publish a validity proof to Layer 1."
    )
    print(
        "- Improve scalability while inheriting Layer-1 verification."
    )

    print("\nBulletproofs:")
    print(
        "- Do not require trusted setup."
    )
    print(
        "- Often used for efficient range proofs, such as proving a value is "
        "within an allowed range without revealing the value."
    )


if __name__ == "__main__":
    main()
