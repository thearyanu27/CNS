"""Encrypt image pixel bytes while preserving image dimensions and metadata."""
from __future__ import annotations
from pathlib import Path
from PIL import Image, ImageDraw
from Crypto.Random import get_random_bytes
from .modes import MODE_FUNCS, block_size, encrypt


def make_sample_image(path: str | Path | None = None, size: tuple[int, int] = (320, 220)) -> Image.Image:
    """Create a colorful bitmap with repeated shapes useful for ECB inspection."""
    image = Image.new("RGB", size, "#f4f1e8")
    draw = ImageDraw.Draw(image)
    draw.rectangle((20, 20, 150, 200), fill="#2563eb")
    draw.rectangle((170, 20, 300, 200), fill="#f97316")
    for x in range(32, 145, 28):
        for y in range(32, 190, 28):
            draw.ellipse((x, y, x + 15, y + 15), fill="#fef3c7")
    draw.text((195, 96), "ECB", fill="white", stroke_width=1, stroke_fill="black")
    if path is not None:
        image.save(path)
    return image


def encrypt_image(image: Image.Image, output_dir: str | Path, cipher: str = "AES", key: bytes | None = None) -> dict[str, Image.Image]:
    """Encrypt raw pixel bytes for all modes and return saved visualization images.

    The PNG files retain dimensions and mode as a header; only raw pixel bytes
    are encrypted. ECB/CBC padding is cropped for display after encryption.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    original = image.convert("RGB")
    raw = original.tobytes()
    bs = block_size(cipher)
    key = key or (get_random_bytes(16) if cipher.upper() == "AES" else get_random_bytes(8))
    outputs = {}
    for mode in MODE_FUNCS:
        iv = None if mode == "ECB" else get_random_bytes(bs)
        # CFB/OFB/CTR support a final short segment; ECB/CBC add PKCS#7 padding.
        payload = raw
        encrypted = encrypt(mode, payload, key, iv, cipher)
        pixels = (encrypted[:len(raw)] + bytes(max(0, len(raw) - len(encrypted))))[:len(raw)]
        result = Image.frombytes("RGB", original.size, pixels)
        result.save(out_dir / f"{cipher.lower()}_{mode.lower()}.png")
        outputs[mode] = result
    return outputs
