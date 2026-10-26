#!/usr/bin/env python3
"""Fail when a Windows binary needs the C runtime as a DLL.

Windows builds link the C runtime statically (.cargo/config.toml), so
`sourceorrery.exe` and `sourceorrery_ffi.dll` run on a Windows without the
Visual C++ Redistributable. A RUSTFLAGS variable replaces those flags
without a word, so the release and CI read each binary's import tables
(the import directory and the delay-load one) and refuse the runtime's
DLLs: VCRUNTIME* and MSVCP*, which only the Redistributable installs, and
the Universal CRT's (ucrtbase, api-ms-win-crt-*), which Windows has but a
static build does not import either.

    python3 scripts/release/check-pe-imports.py FILE.exe FILE.dll ...
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

RUNTIME_PREFIXES = ("vcruntime", "msvcp", "ucrtbase", "api-ms-win-crt-")

# Data directory indexes (PE format: Optional Header Data Directories).
IMPORT_DIRECTORY = 1
DELAY_IMPORT_DIRECTORY = 13
# Bytes per descriptor and the offset of its DLL name RVA.
IMPORT_DESCRIPTOR = (20, 12)
DELAY_IMPORT_DESCRIPTOR = (32, 4)


class NotPE(ValueError):
    """The file is not a PE image this script can read."""


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def imports(data: bytes) -> list[str]:
    """The DLL names a PE image imports, directly or delay-loaded, in table order."""
    try:
        if data[:2] != b"MZ":
            raise NotPE("no MZ header")
        pe = _u32(data, 0x3C)
        if data[pe : pe + 4] != b"PE\0\0":
            raise NotPE("no PE signature")
        sections_count = _u16(data, pe + 6)
        optional = pe + 24
        optional_size = _u16(data, pe + 20)
        magic = _u16(data, optional)
        if magic == 0x10B:  # PE32
            count, directories = _u32(data, optional + 92), optional + 96
        elif magic == 0x20B:  # PE32+
            count, directories = _u32(data, optional + 108), optional + 112
        else:
            raise NotPE(f"unknown optional header magic {magic:#x}")
        sections = []
        for i in range(sections_count):
            header = optional + optional_size + 40 * i
            virtual_size, address, raw_size, raw = struct.unpack_from("<IIII", data, header + 8)
            sections.append((address, max(virtual_size, raw_size), raw))

        def offset(rva: int) -> int:
            for address, size, raw in sections:
                if address <= rva < address + size:
                    return rva - address + raw
            raise NotPE(f"RVA {rva:#x} is in no section")

        names = []
        for index, (size, name_at) in (
            (IMPORT_DIRECTORY, IMPORT_DESCRIPTOR),
            (DELAY_IMPORT_DIRECTORY, DELAY_IMPORT_DESCRIPTOR),
        ):
            if index >= count:
                continue
            rva = _u32(data, directories + 8 * index)
            if rva == 0:
                continue
            descriptor = offset(rva)
            while True:
                entry = data[descriptor : descriptor + size]
                if len(entry) < size:
                    raise NotPE("an import table runs past the end of the file")
                if not any(entry):
                    break
                name = offset(_u32(entry, name_at))
                end = data.find(b"\0", name)
                if end < 0:
                    raise NotPE("a DLL name runs past the end of the file")
                names.append(data[name:end].decode("ascii"))
                descriptor += size
        return names
    except (struct.error, UnicodeDecodeError) as error:
        raise NotPE(f"truncated or malformed ({error})") from error


def runtime_dlls(names: list[str]) -> list[str]:
    """The names among `names` that are the C runtime's DLLs."""
    return [name for name in names if name.lower().startswith(RUNTIME_PREFIXES)]


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    failed = False
    for path in map(Path, argv):
        try:
            names = imports(path.read_bytes())
        except (OSError, NotPE) as error:
            print(f"error: {path}: {error}", file=sys.stderr)
            failed = True
            continue
        found = runtime_dlls(names)
        if found:
            print(
                f"error: {path} imports {', '.join(found)}: the C runtime as DLLs, not linked "
                "in (VCRUNTIME and MSVCP come only with the Visual C++ Redistributable); "
                "build with `-C target-feature=+crt-static` (.cargo/config.toml) and no RUSTFLAGS",
                file=sys.stderr,
            )
            failed = True
        else:
            print(f"{path}: no C runtime DLL ({', '.join(names) or 'no imports'})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
