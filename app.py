"""BlockCipherLab: an interactive educational comparison of classic modes."""
from __future__ import annotations
import io
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from Crypto.Random import get_random_bytes
from PIL import Image
from core.modes import MODE_FUNCS, block_size, encrypt, decrypt
from core.library_check import check_all
from core.image_demo import make_sample_image, encrypt_image
from core.error_test import run_error_tests
from core.iv_reuse_demo import run_reuse_demo
from core.benchmark import run_benchmarks, benchmark_charts
from core.comparison import mode_comparison, cipher_comparison

st.set_page_config(page_title="BlockCipherLab", page_icon="🔐", layout="wide")
st.markdown("""<style>
.block-container{padding-top:2rem;max-width:1400px}.hero{padding:1.35rem 1.6rem;border-radius:16px;background:linear-gradient(120deg,#102a43,#2563eb);color:white;margin-bottom:1rem}
.small-note{color:#64748b;font-size:.9rem}.stTabs [data-baseweb="tab"]{font-weight:600}
</style>""", unsafe_allow_html=True)

PAGES = ["Home / Overview", "Text Encryption", "Run All Modes", "Image Demo", "Error Propagation", "IV Reuse Demo", "Benchmark", "Comparison Tables"]
st.sidebar.title("🔐 BlockCipherLab")
st.sidebar.caption("Cryptography & Security micro-project")
page = st.sidebar.radio("Navigate", PAGES)
st.sidebar.divider()
st.sidebar.caption("Educational prototype. DES is insecure and included for comparison only. Real systems should use authenticated encryption such as AES-GCM.")


def cipher_choice(label="Cipher"):
    choice = st.selectbox(label, ["AES-128", "AES-192", "AES-256", "DES"])
    return ("DES", 8) if choice == "DES" else ("AES", int(choice.split("-")[1]) // 8)


def key_widget(prefix: str, key_size: int):
    mode = st.radio("Key", ["Generate random key", "Enter key (hex)"], horizontal=True, key=f"{prefix}_key_mode")
    if mode == "Generate random key":
        key = get_random_bytes(key_size)
    else:
        raw = st.text_input("Key in hex", key=f"{prefix}_key_hex", placeholder=f"Enter {key_size*2} hex characters")
        if not raw:
            st.info("Enter a key in hexadecimal to continue.")
            return None
        try:
            key = bytes.fromhex(raw)
            if len(key) != key_size:
                st.error(f"Key must be exactly {key_size} bytes ({key_size*2} hex characters).")
                return None
        except ValueError:
            st.error("Key must contain valid hexadecimal characters.")
            return None
    st.code(key.hex(), language=None)
    return key


def iv_widget(prefix: str, mode: str, bs: int):
    if mode == "ECB":
        st.caption("ECB does not use an IV.")
        return None
    label = "Nonce/counter" if mode == "CTR" else "IV"
    option = st.radio(label, ["Generate random", "Enter hex"], horizontal=True, key=f"{prefix}_iv_mode")
    if option == "Generate random":
        value = get_random_bytes(bs)
    else:
        raw = st.text_input(f"{label} in hex ({bs} bytes)", key=f"{prefix}_iv_hex", placeholder=f"{bs*2} hex characters")
        if not raw:
            st.info(f"Enter a {label.lower()} in hexadecimal to continue.")
            return None
        try:
            value = bytes.fromhex(raw)
            if len(value) != bs:
                st.error(f"{label} must be exactly {bs} bytes ({bs*2} hex characters).")
                return None
        except ValueError:
            st.error(f"{label} must contain valid hexadecimal characters.")
            return None
    st.code(value.hex(), language=None)
    return value


def run_encrypt(mode, data, key, iv, cipher):
    return encrypt(mode, data, key, iv, cipher)

if page == "Home / Overview":
    st.markdown('<div class="hero"><h1>BlockCipherLab</h1><p>Implementation and comparison of ECB, CBC, CFB, OFB and CTR using AES and DES</p></div>', unsafe_allow_html=True)
    st.write("Explore how block cipher modes transform data, where errors spread, why IV/nonce reuse is dangerous, and how implementation timings compare.")
    st.subheader("Experiments in this lab")
    cols = st.columns(4)
    for col, title, detail in zip(cols, ["Five modes", "Two ciphers", "Error behavior", "Performance"], ["Manual chaining and feedback", "AES-128/192/256 and DES", "Bit flips and IV reuse", "1 KB, 100 KB and 1 MB"]):
        with col:
            st.metric(title, detail)
    st.subheader("Mode flow at a glance")
    st.code("Plaintext → mode operation → AES/DES single-block primitive → ciphertext\nCiphertext → inverse mode operation → plaintext", language="text")
    st.info("Educational prototype only. DES is insecure and included for comparison. Classic modes here do not authenticate data; use AES-GCM (or another authenticated-encryption scheme) in real systems.")
    with st.expander("Implementation cross-check"):
        results = pd.DataFrame(check_all())
        st.dataframe(results, use_container_width=True, hide_index=True)

elif page == "Text Encryption":
    st.title("Text Encryption")
    a, b = st.columns([1.15, 1])
    with a:
        text = st.text_area("Plaintext", "Meet me at the library at 10.", height=140)
        cipher, key_size = cipher_choice("Choose cipher")
        mode = st.selectbox("Mode", list(MODE_FUNCS))
    with b:
        key = key_widget("text", key_size)
        iv = iv_widget("text", mode, block_size(cipher))
    if st.button("Encrypt and verify", type="primary"):
        try:
            if key is None or (mode != "ECB" and iv is None):
                st.stop()
            plain = text.encode("utf-8")
            ciphertext = encrypt(mode, plain, key, iv, cipher)
            recovered = decrypt(mode, ciphertext, key, iv, cipher)
            st.subheader("Results")
            st.write("**Key (hex)**", key.hex())
            if iv is not None:
                st.write("**IV / nonce (hex)**", iv.hex())
            st.write("**Ciphertext (hex)**")
            st.code(ciphertext.hex(), language=None)
            st.write("**Decrypted text**")
            st.code(recovered.decode("utf-8"), language=None)
            st.success(f"Match: {'Yes' if recovered == plain else 'No'}")
        except (ValueError, UnicodeDecodeError) as exc:
            st.error(f"Could not encrypt/decrypt: {exc}")

elif page == "Run All Modes":
    st.title("Run All Modes")
    text = st.text_area("Same plaintext for every combination", "Repeated block: ABCDEFGHRepeated block: ABCDEFGH")
    if st.button("Run all 10 combinations", type="primary"):
        data = text.encode("utf-8")
        rows = []
        for cipher in ("AES", "DES"):
            key = get_random_bytes(16 if cipher == "AES" else 8)
            bs = block_size(cipher)
            for mode in MODE_FUNCS:
                iv = None if mode == "ECB" else get_random_bytes(bs)
                try:
                    c = encrypt(mode, data, key, iv, cipher)
                    p = decrypt(mode, c, key, iv, cipher)
                    rows.append({"Cipher": cipher, "Mode": mode, "Key (hex)": key.hex(), "IV/nonce (hex)": iv.hex() if iv else "—", "Ciphertext (hex)": c.hex(), "Round trip": "Match" if p == data else "Mismatch"})
                except ValueError as exc:
                    rows.append({"Cipher": cipher, "Mode": mode, "Key (hex)": key.hex(), "IV/nonce (hex)": iv.hex() if iv else "—", "Ciphertext (hex)": "—", "Round trip": str(exc)})
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

elif page == "Image Demo":
    st.title("Image Demo")
    st.write("The image header (dimensions and RGB format) is retained. Each mode encrypts only the raw pixel bytes.")
    uploaded = st.file_uploader("Upload an image (or leave empty for the sample)", type=["png", "jpg", "jpeg", "bmp"])
    try:
        original = Image.open(uploaded).convert("RGB") if uploaded else make_sample_image()
        with st.expander("Original image", expanded=True):
            st.image(original, caption="Original", width=480)
        with tempfile.TemporaryDirectory() as directory:
            results = encrypt_image(original, directory)
        cols = st.columns(3)
        for i, mode in enumerate(MODE_FUNCS):
            with cols[i % 3]:
                st.image(results[mode], caption=f"{mode} encrypted pixels", use_container_width=True)
    except Exception as exc:
        st.error(f"Image could not be processed: {exc}")

elif page == "Error Propagation":
    st.title("Error Propagation")
    st.write("A single ciphertext bit is flipped. The table counts changed plaintext bytes and blocks after decryption.")
    rows = run_error_tests()
    frame = pd.DataFrame(rows)
    st.dataframe(frame, use_container_width=True, hide_index=True)
    measurable = frame[frame["Damaged bytes"] != "—"].copy()
    if not measurable.empty:
        measurable["Damaged bytes"] = pd.to_numeric(measurable["Damaged bytes"])
        chart = measurable.pivot(index="Mode", columns="Cipher", values="Damaged bytes")
        st.bar_chart(chart)
    st.caption("CBC/ECB decryption can reject damaged final padding. The demo flips bit 0 to keep the final padding block untouched.")

elif page == "IV Reuse Demo":
    st.title("IV / Nonce Reuse Demo")
    result = run_reuse_demo()
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("CTR and OFB reuse")
        st.write("Two different plaintexts encrypted with the same key and counter/IV produce ciphertext XOR equal to plaintext XOR:")
        st.code(f"P1: {result['plaintext_1']!r}\nP2: {result['plaintext_2']!r}\nP1 XOR P2: {result['xor_plaintexts'].hex()}\nCTR C1 XOR C2: {result['ctr_xor_ciphertexts'].hex()}", language=None)
        st.success(f"CTR XOR leak demonstrated: {result['ctr_xor_matches']} · OFB: {result['ofb_xor_matches']}")
    with c2:
        st.subheader("CBC repeated IV")
        st.write("With a repeated CBC IV, equal first plaintext blocks produce equal first ciphertext blocks.")
        st.metric("Equal first blocks have equal ciphertext blocks", "Yes" if result["cbc_equal_first_blocks_match"] else "No")
        st.metric("Different first blocks collide in this example", "Yes" if not result["cbc_first_blocks_differ"] else "No")
    st.warning("Never reuse a CTR nonce or OFB IV with the same key. CBC IVs should be fresh and unpredictable.")

elif page == "Benchmark":
    st.title("Benchmark")
    st.write("Average of five encryption and decryption runs for each mode and cipher. Results depend on your machine.")
    if st.button("Run benchmark", type="primary"):
        with st.spinner("Measuring 60 combinations…"):
            frame = run_benchmarks(runs=5)
        st.session_state["benchmark_frame"] = frame
    if "benchmark_frame" in st.session_state:
        frame = st.session_state["benchmark_frame"]
        st.dataframe(frame.round(3), use_container_width=True, hide_index=True)
        encrypt_fig, decrypt_fig = benchmark_charts(frame)
        a, b = st.columns(2)
        with a: st.pyplot(encrypt_fig, use_container_width=True)
        with b: st.pyplot(decrypt_fig, use_container_width=True)

elif page == "Comparison Tables":
    st.title("Comparison Tables")
    st.subheader("Modes of operation")
    st.dataframe(mode_comparison(), use_container_width=True, hide_index=True)
    st.subheader("AES vs DES")
    st.dataframe(cipher_comparison(), use_container_width=True, hide_index=True)
    st.caption("ECB is deterministic and reveals repeated blocks. CBC/CFB/OFB/CTR require careful IV or nonce management. None of these modes provides authentication.")
