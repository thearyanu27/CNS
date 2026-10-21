import pytest
from Crypto.Random import get_random_bytes
from core.modes import MODE_FUNCS, block_size, encrypt, decrypt, pkcs7_pad, pkcs7_unpad
from core.library_check import check_all

@pytest.mark.parametrize("cipher,key_len", [("AES", 16), ("DES", 8)])
@pytest.mark.parametrize("length", [0, 1, 7, 8, 15, 16, 31, 64])
def test_round_trip_all_modes(cipher, key_len, length):
    bs = block_size(cipher)
    data = bytes(range(length))
    key, iv = get_random_bytes(key_len), get_random_bytes(bs)
    for mode in MODE_FUNCS:
        payload = data
        mode_iv = None if mode == "ECB" else iv
        encrypted = encrypt(mode, payload, key, mode_iv, cipher)
        assert decrypt(mode, encrypted, key, mode_iv, cipher) == payload

@pytest.mark.parametrize("size", [8, 16])
def test_padding_edges(size):
    assert pkcs7_unpad(pkcs7_pad(b"", size), size) == b""
    assert pkcs7_unpad(pkcs7_pad(b"x" * size, size), size) == b"x" * size
    assert len(pkcs7_pad(b"x" * size, size)) == size * 2

def test_bad_padding():
    with pytest.raises(ValueError, match="Invalid PKCS#7 padding"):
        pkcs7_unpad(b"12345678\x00", 8)

def test_library_equivalence_all_modes_and_ciphers():
    results = check_all()
    assert len(results) == 10
    assert all(row["Match"] for row in results)
