"""Observe how a single ciphertext bit flip affects decrypted plaintext."""
from __future__ import annotations
from Crypto.Random import get_random_bytes
from .modes import MODE_FUNCS, block_size, encrypt, decrypt


def run_error_tests() -> list[dict[str, object]]:
    """Flip one bit in ciphertext block zero and count changed plaintext bytes/blocks."""
    rows = []
    for cipher in ("AES", "DES"):
        bs = block_size(cipher)
        key = get_random_bytes(16 if cipher == "AES" else 8)
        # Long aligned content keeps the final PKCS#7 block intact in ECB/CBC.
        plain = (b"0123456789ABCDEF" * 8)[:bs * 8]
        iv = get_random_bytes(bs)
        for mode in MODE_FUNCS:
            mode_iv = None if mode == "ECB" else iv
            ciphertext = encrypt(mode, plain, key, mode_iv, cipher)
            changed = bytearray(ciphertext)
            changed[0] ^= 1
            try:
                damaged = decrypt(mode, bytes(changed), key, mode_iv, cipher)
                n = min(len(plain), len(damaged))
                diff = [i for i in range(n) if plain[i] != damaged[i]]
                rows.append({"Cipher": cipher, "Mode": mode, "Damaged bytes": len(diff),
                             "Damaged blocks": len({i // bs for i in diff}), "Result": "Measured"})
            except ValueError as exc:
                rows.append({"Cipher": cipher, "Mode": mode, "Damaged bytes": "—",
                             "Damaged blocks": "—", "Result": f"Rejected: {exc}"})
    return rows
