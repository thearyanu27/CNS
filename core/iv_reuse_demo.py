"""Demonstrate the confidentiality risks of reusing IVs and nonces."""
from __future__ import annotations
from Crypto.Cipher import AES
from .modes import encrypt


def run_reuse_demo() -> dict[str, object]:
    """Return equalities showing XOR leakage for CTR/OFB and CBC first blocks."""
    key, iv = bytes(range(16)), bytes(range(16, 32))
    p1 = b"Transfer $1000 to Alice"
    p2 = b"Transfer $9000 to Alice"
    c1, c2 = {}, {}
    for mode in ("CTR", "OFB"):
        c1[mode] = encrypt(mode, p1, key, iv, "AES")
        c2[mode] = encrypt(mode, p2, key, iv, "AES")
    x_c = bytes(a ^ b for a, b in zip(c1["CTR"], c2["CTR"]))
    x_p = bytes(a ^ b for a, b in zip(p1, p2))
    ofb_xc = bytes(a ^ b for a, b in zip(c1["OFB"], c2["OFB"]))
    cbc1 = encrypt("CBC", p1, key, iv, "AES")
    cbc2 = encrypt("CBC", p2, key, iv, "AES")
    equal_block_a, equal_block_b = b"Same first block! alice", b"Same first block! bob!!"
    ca = encrypt("CBC", equal_block_a, key, iv, "AES")
    cb = encrypt("CBC", equal_block_b, key, iv, "AES")
    return {"plaintext_1": p1, "plaintext_2": p2, "ctr_xor_ciphertexts": x_c,
            "xor_plaintexts": x_p, "ctr_xor_matches": x_c == x_p,
            "ofb_xor_matches": ofb_xc == x_p, "cbc_first_blocks_differ": cbc1[:16] != cbc2[:16],
            "cbc_equal_first_blocks_match": ca[:16] == cb[:16]}
