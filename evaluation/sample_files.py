"""
evaluation/sample_files.py — Generate real, well-formed files of the seven types in the
paper's Table II (text, audio, video, image, document, PDF, Excel) at a requested size.

The paper's own test files are not available, so we synthesize valid files with
the standard library only (no ffmpeg / Office needed).  Sizes are tuned to be
within about 1 % of the target; the actual size is always reported.

    text      .txt   pseudo-random English-like words
    audio     .wav   16-bit PCM mono, 8 kHz, tone + noise
    video     .avi   uncompressed RIFF AVI, 64x48 RGB frames
    image     .png   RGB noise image, stored (zlib level 0) IDAT
    document  .docx  Office Open XML word document (ZIP)
    pdf       .pdf   PDF 1.4 with text pages and a correct xref table
    excel     .xlsx  Office Open XML spreadsheet with numeric cells (ZIP)
"""

from __future__ import annotations

import io
import math
import random
import struct
import wave
import zipfile
import zlib
from typing import Callable, Dict, Tuple

WORDS = ("cloud storage integrity merkle hash tree signature encryption lattice ring "
         "verify block upload download dropbox secure file owner user key root node").split()


def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # deterministic test content (not used for crypto)


def make_text(size: int, seed: int = 1) -> bytes:
    rng, out = _rng(seed), io.StringIO()
    while out.tell() < size:
        out.write(" ".join(rng.choice(WORDS) for _ in range(12)) + ".\n")
    return out.getvalue().encode()[:size]


def make_wav(size: int, seed: int = 2) -> bytes:
    rng = _rng(seed)
    frames = max(0, (size - 44) // 2)
    pcm = b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / 8000)
                                         + rng.randint(-500, 500))) for i in range(frames))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(pcm)
    return buf.getvalue()


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


def make_png(size: int, seed: int = 3) -> bytes:
    rng = _rng(seed)
    width = 128
    height = max(1, round((size - 70) / (3 * width + 1 + 5 * 3 / 128)))
    raw = b"".join(b"\x00" + bytes(rng.getrandbits(8) for _ in range(3 * width))
                   for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(raw, 0))
            + _png_chunk(b"IEND", b""))


def make_avi(size: int, seed: int = 4) -> bytes:
    rng = _rng(seed)
    w, h = 64, 48
    frame_bytes = w * h * 3
    n = max(1, round((size - 244) / (frame_bytes + 8 + 16)))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return tag + struct.pack("<I", len(data)) + data + (b"\x00" if len(data) % 2 else b"")

    def lst(kind: bytes, data: bytes) -> bytes:
        return b"LIST" + struct.pack("<I", len(data) + 4) + kind + data

    avih = struct.pack("<IIIIIIIIII4I", 40000, frame_bytes * 25, 0, 0x10, n, 0, 1,
                       frame_bytes, w, h, 0, 0, 0, 0)
    strh = struct.pack("<4s4sIHHIIIIIIIIhhhh", b"vids", b"DIB ", 0, 0, 0, 0, 1, 25, 0, n,
                       frame_bytes, 0xFFFFFFFF, 0, 0, 0, w, h)
    strf = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, frame_bytes, 0, 0, 0, 0)
    hdrl = lst(b"hdrl", chunk(b"avih", avih) + lst(b"strl", chunk(b"strh", strh)
                                                   + chunk(b"strf", strf)))
    frames, idx, offset = [], [], 4
    for i in range(n):
        shade = (i * 9) % 256
        pixels = bytes((shade + rng.getrandbits(5)) % 256 for _ in range(frame_bytes))
        frames.append(chunk(b"00db", pixels))
        idx.append(struct.pack("<4sIII", b"00db", 0x10, offset, frame_bytes))
        offset += 8 + frame_bytes
    body = hdrl + lst(b"movi", b"".join(frames)) + chunk(b"idx1", b"".join(idx))
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"AVI " + body


def _zip(files: Dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def _fit(builder: Callable[[int], bytes], size: int) -> bytes:
    """Search the content count n so that builder(n) is as close to *size* as possible."""
    lo, hi = 1, 1
    while len(builder(hi)) < size:
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if len(builder(mid)) < size:
            lo = mid + 1
        else:
            hi = mid
    return builder(lo)


_CT = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def make_docx(size: int, seed: int = 5) -> bytes:
    words = make_text(size * 2, seed).decode().split("\n")

    def build(n: int) -> bytes:
        paras = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in words[:n])
        return _zip({
            "[Content_Types].xml": _CT + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            "_rels/.rels": _CT + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            "word/document.xml": _CT + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body>{paras}</w:body></w:document>",
        })
    return _fit(build, size)


def make_xlsx(size: int, seed: int = 6) -> bytes:
    rng = _rng(seed)
    values = [[rng.randint(0, 10 ** 6) for _ in range(8)] for _ in range(size // 20 + 10)]

    def build(n: int) -> bytes:
        rows = "".join(f'<row r="{r + 1}">' + "".join(
            f'<c r="{chr(65 + c)}{r + 1}"><v>{v}</v></c>' for c, v in enumerate(values[r]))
            + "</row>" for r in range(n))
        return _zip({
            "[Content_Types].xml": _CT + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
            "_rels/.rels": _CT + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            "xl/workbook.xml": _CT + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": _CT + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/worksheets/sheet1.xml": _CT + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f"<sheetData>{rows}</sheetData></worksheet>",
        })
    return _fit(build, size)


def make_pdf(size: int, seed: int = 7) -> bytes:
    lines = make_text(size * 2, seed).decode().split("\n")

    def build(n: int) -> bytes:
        per_page = 50
        pages = [lines[i:min(i + per_page, n)] for i in range(0, max(n, 1), per_page)]
        objs = ["<< /Type /Catalog /Pages 2 0 R >>", None,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
        kids = []
        for page in pages:
            text = "BT /F1 9 Tf 40 800 Td 11 TL " + " ".join(
                f"({ln.replace('(', '').replace(')', '')}) '" for ln in page) + " ET"
            stream = f"<< /Length {len(text)} >>\nstream\n{text}\nendstream"
            objs.append(stream)
            objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                        f"/Resources << /Font << /F1 3 0 R >> >> /Contents {len(objs)} 0 R >>")
            kids.append(f"{len(objs)} 0 R")
        objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n")
        offsets = []
        for i, o in enumerate(objs, 1):
            offsets.append(out.tell())
            out.write(f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1"))
        xref = out.tell()
        out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
        for off in offsets:
            out.write(f"{off:010d} 00000 n \n".encode())
        out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
        return out.getvalue()
    return _fit(build, size)


# Paper Table II order: Text, Audio, Video, Image, Document, PDF, Excel
FILE_TYPES: Dict[str, Tuple[str, Callable[[int], bytes]]] = {
    "Text": (".txt", make_text),
    "Audio": (".wav", make_wav),
    "Video": (".avi", make_avi),
    "Image": (".png", make_png),
    "Document": (".docx", make_docx),
    "PDF": (".pdf", make_pdf),
    "Excel": (".xlsx", make_xlsx),
}


def make_file(kind: str, size: int) -> Tuple[str, bytes]:
    ext, fn = FILE_TYPES[kind]
    return f"sample_{kind.lower()}{ext}", fn(size)
