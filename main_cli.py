"""Run the BlockCipherLab experiments from a terminal."""
from core.library_check import check_all
from core.error_test import run_error_tests
from core.iv_reuse_demo import run_reuse_demo
from core.benchmark import run_benchmarks
from core.comparison import mode_comparison, cipher_comparison


def main() -> None:
    print("BlockCipherLab — educational prototype; DES is insecure and for comparison only.\n")
    print("Manual mode vs PyCryptodome cross-check:")
    for row in check_all():
        print(f"  {row['Cipher']:3} {row['Mode']:3}: {'MATCH' if row['Match'] else 'MISMATCH'}")
    print("\nCiphertext bit-flip effects:")
    for row in run_error_tests():
        print(f"  {row['Cipher']:3} {row['Mode']:3}: {row['Damaged bytes']} bytes / {row['Damaged blocks']} blocks ({row['Result']})")
    demo = run_reuse_demo()
    print("\nIV/nonce reuse:")
    print(f"  CTR ciphertext XOR equals plaintext XOR: {demo['ctr_xor_matches']}")
    print(f"  OFB ciphertext XOR equals plaintext XOR: {demo['ofb_xor_matches']}")
    print(f"  Reused CBC IV exposes equal first blocks: {demo['cbc_equal_first_blocks_match']}")
    print("\nMode comparison:\n", mode_comparison().to_string(index=False))
    print("\nCipher comparison:\n", cipher_comparison().to_string(index=False))
    print("\nRunning benchmark (5 runs each)…")
    print(run_benchmarks().round(3).to_string(index=False))

if __name__ == "__main__":
    main()
