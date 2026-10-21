# BlockCipherLab

**Implementation and Comparison of Block Cipher Modes of Operation (ECB, CBC, CFB, OFB, CTR) Using AES and DES in Python**

A college Cryptography and Security micro-project that implements five classic block cipher modes on top of PyCryptodome's raw single-block ECB primitive. It includes a Streamlit interface, image pattern demonstration, error propagation and IV reuse experiments, benchmarks, comparison tables, and automated tests.

> **Educational prototype only. DES is insecure and included for comparison only.** These classic modes do not authenticate data. Real systems should use authenticated encryption such as AES-GCM.

## Setup and run

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Run tests with `pytest`. Run the terminal experiments with `python main_cli.py`.

## Project layout

- `core/modes.py` — manual AES/DES ECB, CBC, full-block-segment CFB, OFB, and CTR; PKCS#7 padding for ECB/CBC only. CFB supports a final partial segment as in the library implementation.
- `core/library_check.py` — verifies manual ciphertext against PyCryptodome built-in mode outputs.
- `core/image_demo.py` — makes a sample pattern image or accepts an image, encrypts pixel bytes in all modes, and saves PNG visualizations while retaining image dimensions.
- `core/error_test.py` — flips a ciphertext bit and counts changed plaintext bytes and blocks.
- `core/iv_reuse_demo.py` — demonstrates XOR leakage in reused CTR/OFB keystreams and first-block equality leakage with a reused CBC IV.
- `core/benchmark.py` — averages encryption and decryption timings over five runs for 1 KB, 100 KB, and 1 MB and creates matplotlib charts.
- `core/comparison.py` — produces mode and cipher reference tables.
- `app.py` — Streamlit home, encryption, experiment, and comparison pages.
- `main_cli.py` — runs experiments and prints the outputs in a terminal.
- `tests/test_modes.py` — round-trip, padding edge, error, and library agreement tests.

## Modes and limitations

ECB and CBC use PKCS#7 padding. CFB uses the full block as its segment size (128 bits for AES, 64 bits for DES), while allowing a final short segment. OFB and CTR are stream-like and do not pad. This lab's CTR represents the nonce/counter as one full block and increments that value as a big-endian integer. Keep IVs/nonces unique as appropriate, and never reuse them with the same key in CTR or OFB. None of the modes provides integrity/authentication.
