from __future__ import annotations

import hashlib
import hmac
import math
import unicodedata
from dataclasses import dataclass

from Crypto.Hash import RIPEMD160, keccak
from ecdsa import SECP256k1, SigningKey
from mnemonic import Mnemonic


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HARDENED_OFFSET = 0x80000000
CURVE_ORDER = SECP256k1.order
SECONDS_PER_YEAR = 60 * 60 * 24 * 365.25


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    sha_hash = sha256(data)

    try:
        return hashlib.new("ripemd160", sha_hash).digest()
    except ValueError:
        digest = RIPEMD160.new()
        digest.update(sha_hash)
        return digest.digest()


def keccak_256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, byteorder="big")
    encoded = ""

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + encoded


def base58check_encode(payload: bytes) -> str:
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def ser32(value: int) -> bytes:
    return value.to_bytes(4, byteorder="big")


def ser256(value: int) -> bytes:
    return value.to_bytes(32, byteorder="big")


def compressed_public_key(private_key: int) -> bytes:
    signing_key = SigningKey.from_secret_exponent(
        private_key,
        curve=SECP256k1,
    )
    raw_public_key = signing_key.get_verifying_key().to_string()

    x_coordinate = raw_public_key[:32]
    y_coordinate = int.from_bytes(raw_public_key[32:], byteorder="big")

    prefix = b"\x03" if y_coordinate % 2 else b"\x02"
    return prefix + x_coordinate


def uncompressed_public_key_body(private_key: int) -> bytes:
    """
    Return 64 bytes: x-coordinate || y-coordinate.
    Ethereum uses this body without the 0x04 SEC prefix.
    """
    signing_key = SigningKey.from_secret_exponent(
        private_key,
        curve=SECP256k1,
    )
    return signing_key.get_verifying_key().to_string()


def bitcoin_p2pkh_address(private_key: int) -> str:
    public_key = compressed_public_key(private_key)
    payload = b"\x00" + hash160(public_key)
    return base58check_encode(payload)


def ethereum_address(private_key: int) -> str:
    public_key_body = uncompressed_public_key_body(private_key)
    return "0x" + keccak_256(public_key_body)[-20:].hex()


def eip55_checksum_address(address: str) -> str:
    lowercase = address.lower().replace("0x", "")
    address_hash = keccak_256(lowercase.encode("ascii")).hex()

    checksummed = "".join(
        character.upper()
        if character.isalpha() and int(address_hash[index], 16) >= 8
        else character
        for index, character in enumerate(lowercase)
    )

    return "0x" + checksummed


def bip39_seed(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    """
    BIP39 seed:
    PBKDF2-HMAC-SHA512 with 2048 iterations and a 64-byte output.
    """
    password = unicodedata.normalize("NFKD", mnemonic_phrase).encode("utf-8")
    salt_text = "mnemonic" + passphrase
    salt = unicodedata.normalize("NFKD", salt_text).encode("utf-8")

    return hashlib.pbkdf2_hmac(
        "sha512",
        password,
        salt,
        2048,
        dklen=64,
    )


@dataclass(frozen=True)
class HDPrivateNode:
    private_key: int
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDPrivateNode":
        digest = hmac.new(
            b"Bitcoin seed",
            seed,
            hashlib.sha512,
        ).digest()

        master_private_key = int.from_bytes(digest[:32], byteorder="big")
        master_chain_code = digest[32:]

        if master_private_key == 0 or master_private_key >= CURVE_ORDER:
            raise ValueError("Invalid BIP32 master private key.")

        return cls(
            private_key=master_private_key,
            chain_code=master_chain_code,
        )

    @property
    def public_key(self) -> bytes:
        return compressed_public_key(self.private_key)

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.public_key)[:4]

    def derive_child(self, index: int) -> "HDPrivateNode":
        if not 0 <= index <= 0xFFFFFFFF:
            raise ValueError("Child index must fit in uint32.")

        if index >= HARDENED_OFFSET:
            data = b"\x00" + ser256(self.private_key) + ser32(index)
        else:
            data = self.public_key + ser32(index)

        digest = hmac.new(
            self.chain_code,
            data,
            hashlib.sha512,
        ).digest()

        left_half = int.from_bytes(digest[:32], byteorder="big")
        child_chain_code = digest[32:]

        if left_half >= CURVE_ORDER:
            raise ValueError("Invalid child key material.")

        child_private_key = (left_half + self.private_key) % CURVE_ORDER

        if child_private_key == 0:
            raise ValueError("Invalid derived child private key.")

        return HDPrivateNode(
            private_key=child_private_key,
            chain_code=child_chain_code,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
        )

    def derive_path(self, path: str) -> "HDPrivateNode":
        if path == "m":
            return self

        if not path.startswith("m/"):
            raise ValueError("Path must start with m/.")

        node = self

        for component in path.split("/")[1:]:
            hardened = component.endswith("'")

            if hardened:
                component = component[:-1]

            if not component.isdigit():
                raise ValueError(f"Invalid path component: {component}")

            index = int(component)

            if index >= HARDENED_OFFSET:
                raise ValueError("Base index is too large.")

            if hardened:
                index += HARDENED_OFFSET

            node = node.derive_child(index)

        return node

    def to_xpub(self) -> str:
        """
        Serialize a mainnet BIP32 extended public key (xpub).
        """
        version = bytes.fromhex("0488B21E")

        payload = (
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + ser32(self.child_number)
            + self.chain_code
            + self.public_key
        )

        return base58check_encode(payload)


def derive_first_five_addresses(
    root: HDPrivateNode,
    coin_type: int,
    address_function,
) -> list[str]:
    addresses = []

    for index in range(5):
        path = f"m/44'/{coin_type}'/0'/0/{index}"
        child = root.derive_path(path)
        addresses.append(address_function(child.private_key))

    return addresses


def years_for_bruteforce(bits: int, guesses_per_second: float) -> float:
    return (2**bits) / guesses_per_second / SECONDS_PER_YEAR


def main() -> None:
    print_section("Exercise 6.1 — BIP39 Mnemonic and BIP32 Master Material")

    mnemonic_generator = Mnemonic("english")
    mnemonic_phrase = mnemonic_generator.generate(strength=128)

    assert mnemonic_generator.check(mnemonic_phrase)

    seed = bip39_seed(mnemonic_phrase)
    root = HDPrivateNode.from_seed(seed)

    print("Mnemonic word count:", len(mnemonic_phrase.split()))
    print("Mnemonic phrase: [hidden — temporary test-only value]")
    print("BIP39 seed length:", len(seed), "bytes =", len(seed) * 8, "bits")
    print("Master private-key length:", len(ser256(root.private_key)), "bytes")
    print("Master chain-code length:", len(root.chain_code), "bytes")

    print("Seed SHA-256 fingerprint:", sha256(seed).hex())
    print(
        "Master private-key SHA-256 fingerprint:",
        sha256(ser256(root.private_key)).hex(),
    )
    print(
        "Master chain-code SHA-256 fingerprint:",
        sha256(root.chain_code).hex(),
    )

    assert len(mnemonic_phrase.split()) == 12
    assert len(seed) == 64
    assert len(root.chain_code) == 32

    print("\nMnemonic, seed, and master-material checks: PASSED")

    print_section("BIP44 Address Derivation")

    bitcoin_addresses = derive_first_five_addresses(
        root,
        coin_type=0,
        address_function=bitcoin_p2pkh_address,
    )

    ethereum_addresses = derive_first_five_addresses(
        root,
        coin_type=60,
        address_function=ethereum_address,
    )

    print("Bitcoin path: m/44'/0'/0'/0/index")

    for index, address in enumerate(bitcoin_addresses):
        print(f"Bitcoin address [{index}]: {address}")

    print("\nEthereum path: m/44'/60'/0'/0/index")

    for index, address in enumerate(ethereum_addresses):
        print(f"Ethereum address [{index}]: {eip55_checksum_address(address)}")

    assert all(address.startswith("1") for address in bitcoin_addresses)
    assert all(address.startswith("0x") and len(address)
               == 42 for address in ethereum_addresses)

    print("\nAddress derivation checks: PASSED")

    print_section("Determinism Check")

    repeated_root = HDPrivateNode.from_seed(seed)

    repeated_bitcoin = derive_first_five_addresses(
        repeated_root,
        coin_type=0,
        address_function=bitcoin_p2pkh_address,
    )

    repeated_ethereum = derive_first_five_addresses(
        repeated_root,
        coin_type=60,
        address_function=ethereum_address,
    )

    print(
        "Same seed produces the same Bitcoin addresses:",
        bitcoin_addresses == repeated_bitcoin,
    )
    print(
        "Same seed produces the same Ethereum addresses:",
        ethereum_addresses == repeated_ethereum,
    )

    assert bitcoin_addresses == repeated_bitcoin
    assert ethereum_addresses == repeated_ethereum

    print("Determinism check: PASSED")

    print_section("Extended Public Key (xpub)")

    bitcoin_account = root.derive_path("m/44'/0'/0'")
    account_xpub = bitcoin_account.to_xpub()

    print("Account path: m/44'/0'/0'")
    print("xpub generated:", account_xpub.startswith("xpub"))
    print("xpub length:", len(account_xpub))
    print(
        "xpub value: [hidden — public-address hierarchy is privacy-sensitive]")

    assert account_xpub.startswith("xpub")
    print("xpub generation check: PASSED")

    print_section("Exercise 6.2 — Entropy and Brute-Force Discussion")

    guesses_per_second = 10**12

    years_12 = years_for_bruteforce(128, guesses_per_second)
    years_24 = years_for_bruteforce(256, guesses_per_second)

    print("Assumed brute-force speed: 10^12 guesses/second")

    print("\n12-word mnemonic:")
    print("Raw word combinations: 2048^12 = 2^132")
    print("Valid BIP39 entropy strength: 128 bits + 4-bit checksum")
    print(f"Full 2^128 search time: {years_12:.3e} years")

    print("\n24-word mnemonic:")
    print("Raw word combinations: 2048^24 = 2^264")
    print("Valid BIP39 entropy strength: 256 bits + 8-bit checksum")
    print(f"Full 2^256 search time: {years_24:.3e} years")

    print_section("Exercise 6.3 — Hardened and Non-Hardened Derivation")

    print("Hardened path example:     m/44'/0'/0'")
    print("Non-hardened path example: m/44'/0'/0'/0/0")

    print(
        "Hardened derivation requires private-key material and cannot be "
        "derived from an xpub alone."
    )
    print(
        "Non-hardened descendants can be derived from the corresponding xpub, "
        "allowing a receiving service to create new public addresses without "
        "receiving spending keys."
    )

    print("\nExercise 6 completed successfully.")


if __name__ == "__main__":
    main()
