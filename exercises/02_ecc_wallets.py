from __future__ import annotations

import argparse
import hashlib
import time
from dataclasses import dataclass

from Crypto.Hash import RIPEMD160, keccak
from ecdsa import SECP256k1, SigningKey, VerifyingKey


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass
class TestWallet:
    private_key: bytes
    public_key_uncompressed: bytes
    public_key_compressed: bytes
    wif: str
    bitcoin_address: str
    ethereum_address: str
    ethereum_checksum_address: str


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def keccak_256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def ripemd160(data: bytes) -> bytes:
    """
    Use hashlib when RIPEMD-160 is available through OpenSSL.
    Otherwise use PyCryptodome as a fallback.
    """
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        digest = RIPEMD160.new()
        digest.update(data)
        return digest.digest()


def base58_encode(data: bytes) -> str:
    """Encode bytes using Bitcoin Base58."""
    number = int.from_bytes(data, byteorder="big")
    encoded = ""

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + encoded


def base58check_encode(payload: bytes) -> str:
    """
    Base58Check = Base58(payload + first 4 bytes of double-SHA-256 checksum).
    """
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def compress_public_key(verifying_key: VerifyingKey) -> bytes:
    """
    Convert a 64-byte x||y secp256k1 public-key body into
    compressed SEC format: 02/03 || x-coordinate.
    """
    raw = verifying_key.to_string()
    x = raw[:32]
    y = int.from_bytes(raw[32:], byteorder="big")

    prefix = b"\x03" if y % 2 else b"\x02"
    return prefix + x


def private_key_to_wif(private_key: bytes, compressed: bool = True) -> str:
    """
    Mainnet WIF:
    0x80 || private_key || optional 0x01 compression flag || checksum.
    """
    payload = b"\x80" + private_key

    if compressed:
        payload += b"\x01"

    return base58check_encode(payload)


def public_key_to_bitcoin_p2pkh(public_key_compressed: bytes) -> str:
    """
    Bitcoin P2PKH address:
    Base58Check(0x00 || RIPEMD160(SHA256(compressed_public_key))).
    """
    public_key_hash = ripemd160(sha256(public_key_compressed))
    payload = b"\x00" + public_key_hash
    return base58check_encode(payload)


def public_key_to_ethereum_address(public_key_uncompressed: bytes) -> str:
    """
    Ethereum address:
    last 20 bytes of Keccak-256 of the 64-byte public-key body x||y.

    Do not include the 0x04 uncompressed-key prefix.
    """
    if len(public_key_uncompressed) != 64:
        raise ValueError("Ethereum public-key body must be exactly 64 bytes.")

    return "0x" + keccak_256(public_key_uncompressed)[-20:].hex()


def eip55_checksum_address(lowercase_address: str) -> str:
    """
    Optional EIP-55 checksum representation for readability.
    """
    address = lowercase_address.lower().replace("0x", "")
    address_hash = keccak_256(address.encode("ascii")).hex()

    checksummed = "".join(
        char.upper()
        if char.isalpha() and int(address_hash[index], 16) >= 8
        else char
        for index, char in enumerate(address)
    )

    return "0x" + checksummed


def create_test_wallet() -> TestWallet:
    """
    Generate an ephemeral, test-only secp256k1 wallet.
    Do not use this for funds or any real blockchain account.
    """
    signing_key = SigningKey.generate(curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()

    private_key = signing_key.to_string()
    public_key_uncompressed = verifying_key.to_string()
    public_key_compressed = compress_public_key(verifying_key)

    wif = private_key_to_wif(private_key, compressed=True)
    bitcoin_address = public_key_to_bitcoin_p2pkh(public_key_compressed)
    ethereum_address = public_key_to_ethereum_address(public_key_uncompressed)

    return TestWallet(
        private_key=private_key,
        public_key_uncompressed=public_key_uncompressed,
        public_key_compressed=public_key_compressed,
        wif=wif,
        bitcoin_address=bitcoin_address,
        ethereum_address=ethereum_address,
        ethereum_checksum_address=eip55_checksum_address(ethereum_address),
    )


def approximate_vanity_attempts(prefix: str) -> int:
    """
    Approximate expected attempts for a Bitcoin P2PKH prefix.

    P2PKH mainnet addresses usually start with '1' because their version byte is 0x00.
    Every extra Base58 character has an approximate probability of 1/58.
    """
    if not prefix.startswith("1"):
        raise ValueError(
            "This simple P2PKH example expects a prefix starting with '1'.")

    if any(character not in BASE58_ALPHABET for character in prefix):
        raise ValueError("The prefix contains a non-Base58 character.")

    return 58 ** (len(prefix) - 1)


def search_vanity_address(prefix: str, max_attempts: int) -> dict | None:
    """
    Educational vanity-address search. It only searches for short test prefixes.
    """
    started = time.perf_counter()

    for attempt in range(1, max_attempts + 1):
        signing_key = SigningKey.generate(curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()

        compressed_key = compress_public_key(verifying_key)
        bitcoin_address = public_key_to_bitcoin_p2pkh(compressed_key)

        if bitcoin_address.startswith(prefix):
            return {
                "attempts": attempt,
                "seconds": time.perf_counter() - started,
                "address": bitcoin_address,
            }

    return None


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exercise 2: ECC, Bitcoin addresses, and Ethereum addresses"
    )
    parser.add_argument(
        "--show-wif",
        action="store_true",
        help="Display the generated test WIF. Do not save or commit it.",
    )
    parser.add_argument(
        "--vanity-prefix",
        default="1A",
        help="Short Bitcoin P2PKH prefix to search for. Default: 1A",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=5000,
        help="Maximum number of test keys generated during vanity search.",
    )
    args = parser.parse_args()

    print_section("Exercise 2.1 — secp256k1 Key Pair and Addresses")

    wallet = create_test_wallet()

    print("Private key length:", len(wallet.private_key), "bytes")
    print("Private key:", "[hidden — test key generated at runtime]")

    if args.show_wif:
        print("WIF (test-only; never commit or reuse):", wallet.wif)
    else:
        print("WIF:", "[hidden — run with --show-wif to display locally]")

    print("\nUncompressed public-key body length:",
          len(wallet.public_key_uncompressed), "bytes")
    print("Uncompressed public-key body:",
          wallet.public_key_uncompressed.hex())

    print("\nCompressed public-key length:",
          len(wallet.public_key_compressed), "bytes")
    print("Compressed public-key:", wallet.public_key_compressed.hex())

    print("\nBitcoin P2PKH address:", wallet.bitcoin_address)
    print("Ethereum lowercase address:", wallet.ethereum_address)
    print("Ethereum EIP-55 checksum address:",
          wallet.ethereum_checksum_address)

    assert len(wallet.private_key) == 32
    assert len(wallet.public_key_uncompressed) == 64
    assert len(wallet.public_key_compressed) == 33
    assert wallet.bitcoin_address.startswith("1")
    assert wallet.ethereum_address.startswith("0x")
    assert len(wallet.ethereum_address) == 42

    print("\nBasic checks: PASSED")

    print_section("Exercise 2.2 — Discrete Logarithm Interpretation")

    print("Private key k is a random integer.")
    print("Public key K is calculated as K = k × G on secp256k1.")
    print(
        "Calculating K from k is efficient, but finding k from K is "
        "computationally infeasible because of the elliptic-curve discrete-logarithm problem."
    )

    print_section("Exercise 2.3 — Vanity Address Experiment")

    expected = approximate_vanity_attempts(args.vanity_prefix)

    print("Requested prefix:", args.vanity_prefix)
    print("Approximate expected attempts:", expected)
    print("Configured maximum attempts:", args.max_attempts)

    result = search_vanity_address(args.vanity_prefix, args.max_attempts)

    if result is None:
        print(
            f"No matching address found in {args.max_attempts} attempts. "
            "This is normal because vanity search is probabilistic."
        )
    else:
        print("Vanity address found:", result["address"])
        print("Attempts required:", result["attempts"])
        print(f"Elapsed time: {result['seconds']:.4f} seconds")

    print("\nFor report discussion:")
    print("Approximate expected attempts for 1A:",
          approximate_vanity_attempts("1A"))
    print("Approximate expected attempts for 1ABC:",
          approximate_vanity_attempts("1ABC"))
    print(
        "The 1ABC estimate is much larger, so a pure-Python search may take "
        "a long time. The estimate is sufficient for the written comparison."
    )


if __name__ == "__main__":
    main()
