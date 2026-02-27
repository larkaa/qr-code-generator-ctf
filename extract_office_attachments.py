#!/usr/bin/env python3
"""
extract_office_attachments.py

Extracts embedded attachments from Office documents (xlsx, docx, pptx, etc.)
and converts them to their original formats, preserving the original filenames.

How it works:
  Modern Office files are ZIP archives. Embedded OLE objects live under paths
  like xl/embeddings/, word/embeddings/, ppt/embeddings/ as .bin files.

  Each .bin is an OLE2 compound document. When a file (e.g. an .msg) is
  embedded via Insert > Object, Excel wraps it in an "OLE Package":
    - Outer OLE2 compound doc  (.bin)
      └── \\x01Ole10Native stream
            ├── 4-byte total-size prefix
            ├── WORD   type (0x0002 = packager)
            ├── STR    label / original filename  (null-terminated ANSI)
            ├── STR    original path              (null-terminated ANSI)
            ├── WORD   unknown
            ├── BYTE   unknown
            ├── STR    original path again        (null-terminated ANSI)
            ├── DWORD  inner data length
            └── BYTES  raw inner file bytes  ← the actual .msg / .pdf / etc.

  If \\x01Ole10Native is absent, the OLE itself is the embedded object
  (e.g. a legacy .doc inserted as a native OLE server document).

Usage:
    python extract_office_attachments.py <office_file> [--output-dir <dir>]

Requirements:
    pip install olefile
"""

import argparse
import struct
import sys
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple


# ── Magic-byte format detection ────────────────────────────────────────────────

MAGIC_SIGNATURES = [
    (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'ole'),
    (b'PK\x03\x04',                         'zip'),
    (b'%PDF',                                'pdf'),
    (b'\x89PNG\r\n\x1a\n',                  'png'),
    (b'\xFF\xD8\xFF',                        'jpg'),
    (b'GIF87a',                              'gif'),
    (b'GIF89a',                              'gif'),
    (b'BM',                                  'bmp'),
    (b'II\x2A\x00',                          'tif'),
    (b'MM\x00\x2A',                          'tif'),
]


def detect_format(data: bytes) -> Optional[str]:
    for sig, ext in MAGIC_SIGNATURES:
        if data[:len(sig)] == sig:
            return ext
    return None


# ── OLE Package (\\x01Ole10Native) parser ─────────────────────────────────────

def parse_ole10native(stream_data: bytes) -> Tuple[Optional[str], Optional[bytes]]:
    """
    Parse a \\x01Ole10Native stream.
    Returns (original_filename, raw_file_bytes), or (None, None) on failure.

    Stream layout (strings are null-terminated ANSI):
      DWORD  total_size    - byte count of everything that follows
      WORD   type          - 0x0002 for packager
      STR    label         - display label, often the original filename
      STR    original_path - full original path (may be empty)
      WORD   unknown
      BYTE   unknown
      STR    original_path2 - duplicate path entry
      DWORD  data_size     - length of embedded raw bytes
      BYTES  data          - the actual file
    """
    pos = 0

    def read_dword() -> int:
        nonlocal pos
        val = struct.unpack_from('<I', stream_data, pos)[0]
        pos += 4
        return val

    def read_word() -> int:
        nonlocal pos
        val = struct.unpack_from('<H', stream_data, pos)[0]
        pos += 2
        return val

    def read_byte() -> int:
        nonlocal pos
        val = stream_data[pos]
        pos += 1
        return val

    def read_cstring() -> str:
        nonlocal pos
        end = stream_data.index(b'\x00', pos)
        s = stream_data[pos:end].decode('latin-1', errors='replace')
        pos = end + 1
        return s

    try:
        _total_size  = read_dword()
        _type        = read_word()       # expect 0x0002
        label        = read_cstring()    # e.g. "Invoice.msg"
        orig_path    = read_cstring()    # e.g. "C:\\Users\\...\\Invoice.msg" or ""
        _unk_word    = read_word()
        _unk_byte    = read_byte()
        orig_path2   = read_cstring()    # duplicate of orig_path
        data_size    = read_dword()
        raw          = stream_data[pos: pos + data_size]

        # Pick the best filename: prefer label, then path basename
        filename = None
        for candidate in (label, orig_path2, orig_path):
            name = Path(candidate).name if candidate else ''
            if name:
                filename = name
                break

        return filename, raw

    except Exception as e:
        return None, None


# ── OLE sub-type detection (no Ole10Native wrapper) ───────────────────────────

def detect_ole_subtype(data: bytes) -> str:
    """Inspect OLE streams to identify doc/xls/ppt/msg."""
    try:
        import olefile, io
        ole = olefile.OleFileIO(io.BytesIO(data))
        streams = ['/'.join(e) for e in ole.listdir()]
        if any('__substg1.0_' in s for s in streams):
            return 'msg'
        if ole.exists('WordDocument'):
            return 'doc'
        if ole.exists('Workbook') or ole.exists('Book'):
            return 'xls'
        if ole.exists('PowerPoint Document'):
            return 'ppt'
    except Exception:
        pass
    return 'ole'


# ── Per-embedding processor ────────────────────────────────────────────────────

def process_embedding(zname: str, data: bytes, output_dir: Path) -> Optional[Path]:
    """
    Detect format, unwrap OLE Package if present, recover original filename,
    and write the final file to output_dir.
    """
    fallback_stem = Path(zname).stem   # e.g. "oleObject1"
    fmt = detect_format(data)

    # ── Non-OLE: image, PDF, nested ZIP/Office ────────────────────────────────
    if fmt and fmt != 'ole':
        ext_map = {'zip': '.zip', 'pdf': '.pdf', 'png': '.png',
                   'jpg': '.jpg', 'gif': '.gif', 'bmp': '.bmp', 'tif': '.tif'}
        out_path = unique_path(output_dir / f"{fallback_stem}{ext_map.get(fmt, f'.{fmt}')}")
        out_path.write_bytes(data)
        print(f"  [{fmt.upper()}] {out_path.name}")
        return out_path

    # ── OLE2 compound document ────────────────────────────────────────────────
    if fmt == 'ole':
        try:
            import olefile, io
            ole = olefile.OleFileIO(io.BytesIO(data))
        except Exception as e:
            print(f"  [WARN] Cannot open OLE for '{zname}': {e}  → saving as .bin")
            out_path = unique_path(output_dir / f"{fallback_stem}.bin")
            out_path.write_bytes(data)
            return out_path

        # ── Packaged object (Insert > Object from file) ───────────────────────
        if ole.exists('\x01Ole10Native'):
            stream_data = ole.openstream('\x01Ole10Native').read()
            filename, inner_bytes = parse_ole10native(stream_data)

            if inner_bytes is not None and len(inner_bytes) > 0:
                out_name = filename if filename else f"{fallback_stem}.bin"
                out_path = unique_path(output_dir / out_name)
                out_path.write_bytes(inner_bytes)
                inner_ext = Path(out_name).suffix.lstrip('.').upper() or 'BIN'
                print(f"  [OLE Package → {inner_ext}] {out_path.name}  (label: {filename!r})")
                return out_path
            else:
                print(f"  [WARN] Ole10Native parse returned empty data for '{zname}'.")
                # Fall through to raw-OLE save below

        # ── Native OLE server object (legacy .doc, .xls embedded directly) ───
        subtype = detect_ole_subtype(data)
        out_path = unique_path(output_dir / f"{fallback_stem}.{subtype}")
        out_path.write_bytes(data)
        print(f"  [OLE/{subtype.upper()}] {out_path.name}")
        return out_path

    # ── Truly unknown ─────────────────────────────────────────────────────────
    orig_ext = Path(zname).suffix or '.bin'
    out_path = unique_path(output_dir / f"{fallback_stem}{orig_ext}")
    out_path.write_bytes(data)
    print(f"  [UNKNOWN] {out_path.name}")
    return out_path


def unique_path(path: Path) -> Path:
    """Append _1, _2, … to avoid overwriting existing files."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1


# ── Main ───────────────────────────────────────────────────────────────────────

OFFICE_EXTS = {'.xlsx', '.docx', '.pptx', '.xlsm', '.xlsb',
               '.docm', '.pptm', '.ppsx', '.ppsm'}

EMBEDDING_PREFIXES = [
    'xl/embeddings/',
    'word/embeddings/',
    'ppt/embeddings/',
    'xl/media/',
    'word/media/',
    'ppt/media/',
]


def extract_attachments(source: Path, output_dir: Path) -> List[Path]:
    if source.suffix.lower() not in OFFICE_EXTS:
        raise ValueError(
            f"Unsupported extension '{source.suffix}'. "
            f"Supported: {', '.join(sorted(OFFICE_EXTS))}"
        )
    if not zipfile.is_zipfile(source):
        raise ValueError(f"'{source}' is not a valid Office/ZIP file.")

    output_dir.mkdir(parents=True, exist_ok=True)
    results: List[Path] = []

    with zipfile.ZipFile(source, 'r') as zf:
        candidates = [
            n for n in zf.namelist()
            if any(n.startswith(p) for p in EMBEDDING_PREFIXES) and not n.endswith('/')
        ]

        if not candidates:
            print("No embedded objects found.")
            return []

        print(f"Found {len(candidates)} embedded item(s) in '{source.name}':\n")
        for zname in candidates:
            data = zf.read(zname)
            out = process_embedding(zname, data, output_dir)
            if out:
                results.append(out)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Extract embedded attachments from Office documents, "
                    "recovering original filenames."
    )
    parser.add_argument('file', help='Office document (xlsx, docx, pptx, …)')
    parser.add_argument('--output-dir', '-o', default=None,
                        help='Output directory (default: <filename>_attachments/)')
    args = parser.parse_args()

    source = Path(args.file).expanduser().resolve()
    if not source.exists():
        print(f"Error: '{source}' not found.", file=sys.stderr)
        sys.exit(1)

    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else source.parent / f"{source.stem}_attachments"
    )

    print(f"Source : {source}")
    print(f"Output : {output_dir}\n")

    try:
        results = extract_attachments(source, output_dir)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if results:
        print(f"\nDone — {len(results)} file(s) written to: {output_dir}")
    else:
        print("\nNothing extracted.")


if __name__ == '__main__':
    main()
