"""Compare manual mode outputs with PyCryptodome built-in mode implementations."""
from __future__ import annotations
from Crypto.Cipher import AES, DES
from .modes import MODE_FUNCS, block_size, pkcs7_pad


def check_all() -> list[dict[str, object]]:
    """Return one output-equivalence result for every cipher and mode."""
    results = []
    for name, cipher_type, key in (("AES", AES, bytes(range(16))), ("DES", DES, bytes(range(8)))):
        bs = block_size(name)
        plain = (b"BlockCipherLab cross-check payload / " * 4)[:bs * 3]
        iv = bytes(range(bs))
        for mode, (enc, _) in MODE_FUNCS.items():
            if mode in ("ECB", "CBC"):
                payload = pkcs7_pad(plain, bs)
                if mode == "ECB":
                    built = cipher_type.new(key, cipher_type.MODE_ECB).encrypt(payload)
                    manual = enc(plain, key, None, name)
                else:
                    built = cipher_type.new(key, cipher_type.MODE_CBC, iv=iv).encrypt(payload)
                    manual = enc(plain, key, iv, name)
            elif mode == "CFB":
                built = cipher_type.new(key, cipher_type.MODE_CFB, iv=iv, segment_size=bs * 8).encrypt(plain)
                manual = enc(plain, key, iv, name)
            elif mode == "OFB":
                built = cipher_type.new(key, cipher_type.MODE_OFB, iv=iv).encrypt(plain)
                manual = enc(plain, key, iv, name)
            else:
                built = cipher_type.new(key, cipher_type.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big")).encrypt(plain)
                manual = enc(plain, key, iv, name)
            results.append({"Cipher": name, "Mode": mode, "Match": manual == built})
    return results
