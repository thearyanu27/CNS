"""Manual implementations of classic block cipher modes for education.

The only block operation used here is PyCryptodome's raw ECB primitive. These
modes are unauthenticated and must not be used to protect real data.
"""
from __future__ import annotations

from typing import Callable
from Crypto.Cipher import AES, DES

CipherName = str
BLOCK_SIZES = {"AES": AES.block_size, "DES": DES.block_size}


def _cipher(cipher: CipherName, key: bytes):
    name = cipher.upper()
    if name == "AES":
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits).")
        return AES.new(key, AES.MODE_ECB)
    if name == "DES":
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes (64 bits, including parity bits).")
        return DES.new(key, DES.MODE_ECB)
    raise ValueError("Cipher must be AES or DES.")


def block_size(cipher: CipherName) -> int:
    try:
        return BLOCK_SIZES[cipher.upper()]
    except KeyError as exc:
        raise ValueError("Cipher must be AES or DES.") from exc


def _check_iv(iv: bytes, size: int, what: str = "IV") -> None:
    if not isinstance(iv, bytes) or len(iv) != size:
        raise ValueError(f"{what} must be exactly {size} bytes for this cipher.")


def pkcs7_pad(data: bytes, size: int) -> bytes:
    """Pad with PKCS#7; a full block is added when input is aligned."""
    if size < 1 or size > 255:
        raise ValueError("PKCS#7 block size must be between 1 and 255 bytes.")
    n = size - len(data) % size
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, size: int) -> bytes:
    """Remove and validate PKCS#7 padding, raising a friendly ValueError."""
    if not data or len(data) % size:
        raise ValueError("Invalid PKCS#7 padding: plaintext is empty or not block-aligned.")
    n = data[-1]
    if n == 0 or n > size or data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid PKCS#7 padding. The key or ciphertext may be incorrect.")
    return data[:-n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ecb_encrypt(data: bytes, key: bytes, iv_or_nonce: bytes | None = None, cipher: CipherName = "AES") -> bytes:
    """ECB encrypts each padded block independently; identical blocks match."""
    del iv_or_nonce  # ECB deliberately has no IV.
    bs = block_size(cipher)
    raw = _cipher(cipher, key)
    padded = pkcs7_pad(data, bs)
    return b"".join(raw.encrypt(padded[i:i + bs]) for i in range(0, len(padded), bs))


def ecb_decrypt(data: bytes, key: bytes, iv_or_nonce: bytes | None = None, cipher: CipherName = "AES") -> bytes:
    del iv_or_nonce
    bs = block_size(cipher)
    if not data or len(data) % bs:
        raise ValueError("ECB ciphertext must contain one or more complete blocks.")
    raw = _cipher(cipher, key)
    padded = b"".join(raw.decrypt(data[i:i + bs]) for i in range(0, len(data), bs))
    return pkcs7_unpad(padded, bs)


def cbc_encrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """CBC XORs each plaintext block with the previous ciphertext (IV first)."""
    bs = block_size(cipher)
    _check_iv(iv_or_nonce, bs)
    raw = _cipher(cipher, key)
    padded = pkcs7_pad(data, bs)
    prev, out = iv_or_nonce, []
    for i in range(0, len(padded), bs):
        prev = raw.encrypt(_xor(padded[i:i + bs], prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    bs = block_size(cipher)
    _check_iv(iv_or_nonce, bs)
    if not data or len(data) % bs:
        raise ValueError("CBC ciphertext must contain one or more complete blocks.")
    raw = _cipher(cipher, key)
    prev, out = iv_or_nonce, []
    for i in range(0, len(data), bs):
        block = data[i:i + bs]
        out.append(_xor(raw.decrypt(block), prev))
        prev = block
    return pkcs7_unpad(b"".join(out), bs)


def cfb_encrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """Full-block CFB encrypts feedback, then XORs that keystream with data."""
    bs = block_size(cipher)
    _check_iv(iv_or_nonce, bs)
    raw, feedback, out = _cipher(cipher, key), iv_or_nonce, []
    for i in range(0, len(data), bs):
        # A final short segment is allowed; complete ciphertext blocks feed back.
        encrypted_feedback = raw.encrypt(feedback)
        chunk = data[i:i + bs]
        block = _xor(chunk, encrypted_feedback[:len(chunk)])
        out.append(block)
        if len(chunk) == bs:
            feedback = block
    return b"".join(out)


def cfb_decrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """CFB decryption also encrypts feedback; ciphertext supplies next feedback."""
    bs = block_size(cipher)
    _check_iv(iv_or_nonce, bs)
    raw, feedback, out = _cipher(cipher, key), iv_or_nonce, []
    for i in range(0, len(data), bs):
        block = data[i:i + bs]
        out.append(_xor(block, raw.encrypt(feedback)[:len(block)]))
        if len(block) == bs:
            feedback = block
    return b"".join(out)


def ofb_encrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """OFB repeatedly encrypts its own output to form a synchronous keystream."""
    bs = block_size(cipher)
    _check_iv(iv_or_nonce, bs)
    raw, feedback, out = _cipher(cipher, key), iv_or_nonce, []
    for i in range(0, len(data), bs):
        feedback = raw.encrypt(feedback)  # Feedback is keystream state, never ciphertext.
        chunk = data[i:i + bs]
        out.append(_xor(chunk, feedback[:len(chunk)]))
    return b"".join(out)


def ofb_decrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """OFB decryption is the same XOR operation as encryption."""
    return ofb_encrypt(data, key, iv_or_nonce, cipher)


def ctr_encrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """CTR encrypts successive full-width counter blocks and XORs the keystream."""
    bs = block_size(cipher)
    _check_iv(iv_or_nonce, bs, "Nonce/counter")
    raw, initial = _cipher(cipher, key), int.from_bytes(iv_or_nonce, "big")
    limit = 1 << (8 * bs)
    out = []
    for index, i in enumerate(range(0, len(data), bs)):
        if initial + index >= limit:
            raise ValueError("CTR counter overflow. Use a different nonce or shorter input.")
        counter = (initial + index).to_bytes(bs, "big")
        chunk = data[i:i + bs]
        out.append(_xor(chunk, raw.encrypt(counter)[:len(chunk)]))
    return b"".join(out)


def ctr_decrypt(data: bytes, key: bytes, iv_or_nonce: bytes, cipher: CipherName = "AES") -> bytes:
    """CTR decryption equals encryption because both XOR the same keystream."""
    return ctr_encrypt(data, key, iv_or_nonce, cipher)


MODE_FUNCS: dict[str, tuple[Callable, Callable]] = {
    "ECB": (ecb_encrypt, ecb_decrypt), "CBC": (cbc_encrypt, cbc_decrypt),
    "CFB": (cfb_encrypt, cfb_decrypt), "OFB": (ofb_encrypt, ofb_decrypt),
    "CTR": (ctr_encrypt, ctr_decrypt),
}


def encrypt(mode: str, data: bytes, key: bytes, iv_or_nonce: bytes | None = None, cipher: CipherName = "AES") -> bytes:
    """Dispatch encryption by mode name."""
    try:
        fn = MODE_FUNCS[mode.upper()][0]
    except KeyError as exc:
        raise ValueError("Mode must be ECB, CBC, CFB, OFB, or CTR.") from exc
    if mode.upper() == "ECB":
        return fn(data, key, None, cipher)
    if iv_or_nonce is None:
        raise ValueError(f"{mode.upper()} requires an IV or nonce.")
    return fn(data, key, iv_or_nonce, cipher)


def decrypt(mode: str, data: bytes, key: bytes, iv_or_nonce: bytes | None = None, cipher: CipherName = "AES") -> bytes:
    """Dispatch decryption by mode name."""
    try:
        fn = MODE_FUNCS[mode.upper()][1]
    except KeyError as exc:
        raise ValueError("Mode must be ECB, CBC, CFB, OFB, or CTR.") from exc
    if mode.upper() == "ECB":
        return fn(data, key, None, cipher)
    if iv_or_nonce is None:
        raise ValueError(f"{mode.upper()} requires an IV or nonce.")
    return fn(data, key, iv_or_nonce, cipher)
