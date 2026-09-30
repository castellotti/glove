"""Generate the OCR fixtures (checked in; re-run only to change them).

    uv run --with pillow python extensions/ocr/tests/fixtures/generate.py

  sample.png        an image with two lines of text
  scanned.pdf       two image-only pages (no text layer): OCR is the only way in
  text-layer.pdf    one page with a real text layer (pdftotext reads it)
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
LINES = {
    "sample.png": ["GLOVE OCR FIXTURE", "The quick brown fox jumps over the lazy dog."],
    "page1": ["SCANNED PAGE ONE", "Invoice number 4711 is due on 2026-10-01."],
    "page2": ["SCANNED PAGE TWO", "Offline extraction keeps documents private."],
}
TEXT_LAYER = "TEXT LAYER PAGE: this sentence is real PDF text."


def _page(lines: list[str], size=(1240, 400)) -> Image.Image:
    img = Image.new("L", size, 255)
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=44)
    for i, line in enumerate(lines):
        draw.text((60, 80 + i * 110), line, fill=0, font=font)
    return img


def _text_pdf(text: str) -> bytes:
    stream = f"BT /F1 18 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def main() -> None:
    _page(LINES["sample.png"]).save(HERE / "sample.png", optimize=True)
    p1, p2 = _page(LINES["page1"], (1240, 1754)), _page(LINES["page2"], (1240, 1754))
    p1.save(HERE / "scanned.pdf", save_all=True, append_images=[p2], resolution=150)
    (HERE / "text-layer.pdf").write_bytes(_text_pdf(TEXT_LAYER))
    print("wrote", ", ".join(sorted(p.name for p in HERE.iterdir() if p.suffix in (".png", ".pdf"))))


if __name__ == "__main__":
    main()
