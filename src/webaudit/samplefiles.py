"""Harmless, generated test material for automatic write flows: blank images, small documents and pre-written text.

Nothing here comes from the user's machine. Documents contain only the scan's test marker so uploaded data is recognizable and removable.
"""
from __future__ import annotations

import base64
import json
import re
import zipfile
from pathlib import Path
from typing import Optional

PNG_1X1 = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4//8/AwAI/AL+XJ/P2QAAAABJRU5ErkJggg==")  # white 1x1
GIF_1X1 = bytes.fromhex("47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b")
JPG_1X1 = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=")

SAMPLE_PARAGRAPH = ("WebAudit automated test content. This entry was created by an automated security scan of this application and can be "
                    "safely deleted. Marker: {m}")
SAMPLE_RESUME = ("Alex Test ({m})\nSoftware Engineer\nalex.test@example.invalid | Test City\n\nSummary\nAutomated test profile created by a security scan.\n\n"
                 "Experience\nTest Company - Software Engineer (2020-2024)\n- Built automated test pipelines and monitoring.\n- Improved release reliability.\n\n"
                 "Education\nB.Sc. Computer Science, Test University (2016-2020)\n\nSkills\nPython, SQL, Testing, Documentation\n")
SAMPLE_LATEX = ("\\documentclass{{article}}\n\\begin{{document}}\n\\section*{{Alex Test}}\nAutomated test document {m}\n\\end{{document}}\n")

LONG_FIELD_HINT = re.compile(r"about|summary|bio|description|content|text|paste|latex|cv|resume|notes?|message|comment|body|details|abstract|cover", re.I)
RESUME_HINT = re.compile(r"resume|cv|curriculum", re.I)
LATEX_HINT = re.compile(r"latex|tex\b", re.I)


def sample_text(hints: str, tag: str, marker: str, override: Optional[str] = None) -> str:
    """Pre-written text for a field. `hints` = its name/id/placeholder/label text."""
    if LATEX_HINT.search(hints):
        return SAMPLE_LATEX.format(m=marker)
    if tag == "textarea" or LONG_FIELD_HINT.search(hints):
        if override:
            return override.replace("{marker}", marker)
        return (SAMPLE_RESUME if RESUME_HINT.search(hints) else SAMPLE_PARAGRAPH).format(m=marker)
    return marker


def _pdf(text: str) -> bytes:
    """Minimal valid single-page PDF with correct xref offsets."""
    stream = f"BT /F1 14 Tf 72 720 Td ({text[:90]}) Tj ET".encode("latin-1", "replace")
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def _docx(path: Path, text: str) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                   f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>")


class SampleFiles:
    """Creates the files lazily in `directory` and picks one that satisfies an `<input accept>` value."""

    def __init__(self, directory: Path, marker: str) -> None:
        self.dir, self.marker = Path(directory), marker
        self.dir.mkdir(parents=True, exist_ok=True)
        text = f"WebAudit automated test document. Safe to delete. Marker: {marker}"
        self.files: dict[str, Path] = {}

        def put(name: str, data: bytes) -> None:
            p = self.dir / f"webaudit-test-sample.{name}"
            p.write_bytes(data)
            self.files[name] = p

        put("png", PNG_1X1)
        put("gif", GIF_1X1)
        put("jpg", JPG_1X1)
        put("pdf", _pdf(text))
        put("txt", (SAMPLE_RESUME.format(m=marker)).encode())
        put("md", f"# WebAudit test\n\n{text}\n".encode())
        put("csv", f"name,value\nwebaudit-test,{marker}\n".encode())
        put("json", json.dumps({"webaudit_test": True, "marker": marker}).encode())
        put("tex", SAMPLE_LATEX.format(m=marker).encode())
        d = self.dir / "webaudit-test-sample.docx"
        _docx(d, text)
        self.files["docx"] = d

    def pick(self, accept: Optional[str], hint: str = "") -> Path:
        toks = [t.strip().lower() for t in (accept or "").split(",") if t.strip()]
        ext_of = {"image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/gif": "gif", "application/pdf": "pdf",
                  "text/plain": "txt", "text/csv": "csv", "application/json": "json", "text/markdown": "md",
                  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx", "image/*": "png",
                  "application/x-tex": "tex", "text/x-tex": "tex"}
        for t in toks:  # exact extension / mime first
            e = t.lstrip(".") if t.startswith(".") else ext_of.get(t)
            if e == "jpeg":
                e = "jpg"
            if e in self.files:
                return self.files[e]
        if any(t.startswith("image/") for t in toks):
            return self.files["png"]
        if any(t.startswith("text/") for t in toks):
            return self.files["txt"]
        if not toks and re.search(r"image|photo|avatar|picture|logo|banner", hint, re.I):
            return self.files["png"]
        if not toks and re.search(r"resume|cv|document", hint, re.I):
            return self.files["pdf"]
        return self.files["txt"] if toks else self.files["pdf"]

    def listing(self) -> list[str]:
        return sorted(p.name for p in self.files.values())
