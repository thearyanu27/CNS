"""Static reference tables for the report and Streamlit app."""
from __future__ import annotations
import pandas as pd


def mode_comparison() -> pd.DataFrame:
    """Return concise practical characteristics of each classic mode."""
    return pd.DataFrame([
        {"Mode": "ECB", "Padding": "PKCS#7", "IV needed": "No", "Parallel encrypt": "Yes", "Parallel decrypt": "Yes", "Error propagation": "One block becomes garbled", "Hides patterns": "No", "Typical use": "Educational comparison only"},
        {"Mode": "CBC", "Padding": "PKCS#7", "IV needed": "Yes (unpredictable)", "Parallel encrypt": "No", "Parallel decrypt": "Yes", "Error propagation": "Current block garbled; next block bit flips", "Hides patterns": "Yes (with fresh IV)", "Typical use": "Legacy file/message encryption"},
        {"Mode": "CFB", "Padding": "None", "IV needed": "Yes (unique)", "Parallel encrypt": "No", "Parallel decrypt": "Yes", "Error propagation": "Current bit flips; following block garbled", "Hides patterns": "Yes (with fresh IV)", "Typical use": "Legacy stream-like links"},
        {"Mode": "OFB", "Padding": "None", "IV needed": "Yes (never reuse)", "Parallel encrypt": "No", "Parallel decrypt": "No", "Error propagation": "Only corresponding bit flips", "Hides patterns": "Yes (with unique IV)", "Typical use": "Legacy noisy-channel links"},
        {"Mode": "CTR", "Padding": "None", "IV needed": "Unique nonce/counter", "Parallel encrypt": "Yes", "Parallel decrypt": "Yes", "Error propagation": "Only corresponding bit flips", "Hides patterns": "Yes (with unique nonce)", "Typical use": "High-throughput encryption (add authentication)"},
    ])


def cipher_comparison() -> pd.DataFrame:
    """Return AES vs DES parameters and current security status."""
    return pd.DataFrame([
        {"Cipher": "AES", "Block size": "128 bits", "Key size": "128, 192, or 256 bits", "Security status": "Current standard when configured correctly", "Speed": "Typically fast; hardware acceleration common"},
        {"Cipher": "DES", "Block size": "64 bits", "Key size": "56 effective bits (64 stored bits)", "Security status": "Insecure; brute-forceable, comparison only", "Speed": "Generally slower than AES on modern CPUs"},
    ])
