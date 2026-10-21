"""Small, reproducible timing harness for the two ciphers and five modes."""
from __future__ import annotations
import time
import pandas as pd
import matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes
from .modes import MODE_FUNCS, block_size, encrypt, decrypt

SIZES = {"1 KB": 1024, "100 KB": 100 * 1024, "1 MB": 1024 * 1024}


def run_benchmarks(runs: int = 5) -> pd.DataFrame:
    """Measure average encrypt/decrypt milliseconds for each size/cipher/mode."""
    rows = []
    for size_name, length in SIZES.items():
        data = get_random_bytes(length)
        for cipher in ("AES", "DES"):
            key = get_random_bytes(16 if cipher == "AES" else 8)
            bs = block_size(cipher)
            # Selected sizes are aligned for full-block CFB on both ciphers.
            for mode in MODE_FUNCS:
                iv = None if mode == "ECB" else get_random_bytes(bs)
                enc_times, dec_times = [], []
                for _ in range(runs):
                    start = time.perf_counter()
                    encrypted = encrypt(mode, data, key, iv, cipher)
                    enc_times.append(time.perf_counter() - start)
                    start = time.perf_counter()
                    decrypt(mode, encrypted, key, iv, cipher)
                    dec_times.append(time.perf_counter() - start)
                rows.append({"Size": size_name, "Bytes": length, "Cipher": cipher, "Mode": mode,
                             "Encrypt ms": 1000 * sum(enc_times) / runs,
                             "Decrypt ms": 1000 * sum(dec_times) / runs})
    return pd.DataFrame(rows)


def benchmark_charts(frame: pd.DataFrame) -> tuple[plt.Figure, plt.Figure]:
    """Build clean comparison figures for encryption and decryption times."""
    figures = []
    for metric, title in (("Encrypt ms", "Average encryption time"), ("Decrypt ms", "Average decryption time")):
        fig, ax = plt.subplots(figsize=(10, 4.8))
        pivot = frame.groupby(["Size", "Cipher", "Mode"])[metric].mean().unstack(["Cipher", "Mode"])
        pivot.plot(kind="bar", ax=ax, width=0.82)
        ax.set_title(title)
        ax.set_ylabel("Milliseconds (lower is faster)")
        ax.set_xlabel("Input size")
        ax.grid(axis="y", alpha=0.25)
        ax.legend(title="Cipher / mode", ncol=5, fontsize=8)
        fig.tight_layout()
        figures.append(fig)
    return figures[0], figures[1]
