#!/usr/bin/env python3
"""
extract_office_attachments.py

Extracts embedded attachments from Office documents (xlsx, docx, pptx, etc.)
and converts them to their original formats.

Usage:
    python extract_office_attachments.py <office_file> [--output-dir <dir>]

Requirements:
    pip install compressed-rtf extract-msg olefile
"""

import argparse
import os
import shutil
import struct
import sys
import tempfile
import zipfile
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────────

def detect_format_from_bytes(data: bytes) -> str | None:
    """Return a file extension (without dot) based on magic bytes, or None."""
    signatures = [
        (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'ole'),   # OLE2 compound (msg, doc, xls, ppt, …)
        (b'PK\x03\x04',                          'zip'),   # ZIP (modern Office, jar, …)
        (b'%PDF',                                 'pdf'),
        (b'\x89PNG\r\n\x1a\n',                   'png'),
        (b'\xFF\xD8\xFF',                         'jpg'),
        (b'GIF87a',                               'gif'),
        (b'GIF89a',                               'gif'),
        (b'BM',                                   'bmp'),
        (b'II\x2A\x00',                           'tif'),
        (b'MM\x00\x2A',                           'tif'),
        (b'RIFF',                                 'riff'),  # WAV / AVI
        (b'\x1F\x8B',                             'gz'),
    ]
    for sig, ext in signatures:
        if data[:len(sig)] == sig:
            return ext
    return None


def ole_to_msg(data: bytes) -> bytes:
    """
    An OLE2 .bin embedded in Office XML is already a valid OLE2 compound
    document.  If it contains Outlook message streams it *is* a .msg file —
    no byte-level transformation is needed; just rename the extension.

    This function returns the data unchanged (the conversion is purely the
    file-extension rename done by the caller).
    """
    return data


def refine_ole_extension(data: bytes) -> str:
    """
    Try to determine the specific OLE sub-type (msg, doc, xls, ppt).
    Falls back to 'ole'.
    """
    try:
        import olefile
        import io
        ole = olefile.OleFileIO(io.BytesIO(data))
        streams = ['/'.join(e) for e in ole.listdir()]
        # Outlook MSG: contains __substg1.0_ streams
        if any('__substg1.0_' in s for s in streams):
            return 'msg'
        # Word .doc
        if ole.exists('WordDocument'):
            return 'doc'
        # Excel .xls
        if ole.exists('Workbook') or ole.exists('Book'):
            return 'xls'
        # PowerPoint .ppt
        if ole.exists('PowerPoint Document'):
            return 'ppt'
    except Exception:
        pass
    return 'ole'


# ── Core extractor ─────────────────────────────────────────────────────────────

class AttachmentExtractor:
    """Extracts embedded attachments from Office Open XML documents."""

    OFFICE_EXTS = {'.xlsx', '.docx', '.pptx', '.xlsm', '.xlsb',
                   '.docm', '.pptm', '.ppsx', '.ppsm'}

    # Paths inside the ZIP where embeddings live
    EMBEDDING_PATHS = [
        'xl/embeddings/',
        'word/embeddings/',
        'ppt/embeddings/',
        'xl/media/',
        'word/media/',
        'ppt/media/',
    ]

    def __init__(self, source: Path, output_dir: Path):
        self.source = source
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public entry point ──────────────────────────────────────────────────

    def extract(self) -> list[Path]:
        suffix = self.source.suffix.lower()
        if suffix not in self.OFFICE_EXTS:
            raise ValueError(
                f"Unsupported file type '{suffix}'. "
                f"Supported: {', '.join(sorted(self.OFFICE_EXTS))}"
            )
        if not zipfile.is_zipfile(self.source):
            raise ValueError(f"'{self.source}' does not appear to be a valid Office file (not a ZIP).")

        extracted: list[Path] = []
        with zipfile.ZipFile(self.source, 'r') as zf:
            names = zf.namelist()
            embedding_names = [
                n for n in names
                if any(n.startswith(p) for p in self.EMBEDDING_PATHS)
                   and not n.endswith('/')
            ]

            if not embedding_names:
                print("No embedded attachments found.")
                return []

            print(f"Found {len(embedding_names)} embedded item(s).")

            for zname in embedding_names:
                data = zf.read(zname)
                out_path = self._save_attachment(zname, data)
                if out_path:
                    extracted.append(out_path)

        return extracted

    # ── Internal helpers ────────────────────────────────────────────────────

    def _save_attachment(self, zname: str, data: bytes) -> Path | None:
        """Detect true format, convert if needed, write to output_dir."""
        stem = Path(zname).stem          # e.g. "Microsoft_Outlook_Message1"
        original_ext = Path(zname).suffix.lower()  # e.g. ".bin", ".emf", …

        fmt = detect_format_from_bytes(data)

        if fmt == 'ole':
            true_ext = refine_ole_extension(data)
            # No byte conversion needed – OLE compound == MSG on disk
            out_path = self.output_dir / f"{stem}.{true_ext}"
            out_path.write_bytes(data)
            print(f"  Extracted OLE/{true_ext}: {out_path.name}")
            return out_path

        if fmt == 'pdf':
            out_path = self.output_dir / f"{stem}.pdf"
            out_path.write_bytes(data)
            print(f"  Extracted PDF: {out_path.name}")
            return out_path

        if fmt in ('png', 'jpg', 'gif', 'bmp', 'tif'):
            out_path = self.output_dir / f"{stem}.{fmt}"
            out_path.write_bytes(data)
            print(f"  Extracted image/{fmt}: {out_path.name}")
            return out_path

        if fmt == 'zip':
            # Could be a nested Office document
            out_path = self.output_dir / f"{stem}{original_ext or '.zip'}"
            out_path.write_bytes(data)
            print(f"  Extracted ZIP/Office: {out_path.name}")
            return out_path

        # Unknown – keep original extension or mark as .bin
        fallback_ext = original_ext if original_ext else '.bin'
        out_path = self.output_dir / f"{stem}{fallback_ext}"
        out_path.write_bytes(data)
        print(f"  Extracted (unknown format, kept as {fallback_ext}): {out_path.name}")
        return out_path


# ── Special handling: EMF/WMF Ole Objects packed as .bin ───────────────────────
# Office sometimes wraps an OLE object in a proprietary container before
# embedding it.  The wrapper starts with a 20-byte header:
#   struct OBJECTHEADER { WORD sig=0x1C15; WORD headerSize; DWORD objectType; … }
# Detecting and stripping it is optional; most viewers handle the raw OLE fine.


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Extract and convert embedded attachments from Office documents."
    )
    parser.add_argument('file', help='Path to the Office document (xlsx, docx, pptx, …)')
    parser.add_argument(
        '--output-dir', '-o',
        default=None,
        help='Directory to write extracted files (default: <filename>_attachments/)'
    )
    args = parser.parse_args()

    source = Path(args.file).expanduser().resolve()
    if not source.exists():
        print(f"Error: '{source}' not found.", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir) if args.output_dir else \
        source.parent / f"{source.stem}_attachments"

    print(f"Source : {source}")
    print(f"Output : {output_dir}")
    print()

    extractor = AttachmentExtractor(source, output_dir)
    try:
        results = extractor.extract()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if results:
        print(f"\nDone. {len(results)} file(s) written to: {output_dir}")
    else:
        print("\nNo files extracted.")


if __name__ == '__main__':
    main()
