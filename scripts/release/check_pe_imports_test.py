"""Tests for check-pe-imports.py:
python3 -m unittest scripts/release/check_pe_imports_test.py

Each test builds a small PE image with the import tables it needs and reads
it back, so the tests run on any platform.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_pe_imports", HERE / "check-pe-imports.py")
cpi = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["check_pe_imports"] = cpi
spec.loader.exec_module(cpi)

SECTION_RVA = 0x1000
SECTION_RAW = 0x400


def pe_image(
    imports: tuple[str, ...] = (),
    delay: tuple[str, ...] = (),
    *,
    magic: int = 0x20B,
    directories: int = 16,
    import_rva: int | None = None,
) -> bytes:
    """A PE image of one section holding these import and delay-load tables."""
    delay_at = 20 * (len(imports) + 1)
    names_at = delay_at + (32 * (len(delay) + 1) if delay else 0)
    section = bytearray(names_at)
    for table, at, size, name_at in ((imports, 0, 20, 12), (delay, delay_at, 32, 4)):
        for i, name in enumerate(table):
            struct.pack_into("<I", section, at + size * i + name_at, SECTION_RVA + len(section))
            section += name.encode("ascii") + b"\0"

    optional_size = (112 if magic == 0x20B else 96) + 8 * directories
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, magic)
    count_at, directories_at = (108, 112) if magic == 0x20B else (92, 96)
    struct.pack_into("<I", optional, count_at, directories)
    if imports:
        rva = SECTION_RVA if import_rva is None else import_rva
        struct.pack_into("<II", optional, directories_at + 8, rva, 20 * (len(imports) + 1))
    if delay:
        struct.pack_into("<II", optional, directories_at + 8 * 13, SECTION_RVA + delay_at, 32)

    header = bytearray(64)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 64)
    header += b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, optional_size, 0x22)
    header += optional
    header += b".idata\0\0" + struct.pack("<IIII", len(section), SECTION_RVA, len(section), SECTION_RAW)
    header += bytes(16)
    return bytes(header.ljust(SECTION_RAW, b"\0") + section)


def run(*images: bytes) -> tuple[int, str, str]:
    """main() over files holding these images: its status, stdout and stderr."""
    with tempfile.TemporaryDirectory() as directory:
        paths = []
        for i, image in enumerate(images):
            path = Path(directory, f"binary{i}.exe")
            path.write_bytes(image)
            paths.append(str(path))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = cpi.main(paths)
        return status, out.getvalue(), err.getvalue()


class ImportsTest(unittest.TestCase):
    def test_reads_both_tables_in_order(self):
        image = pe_image(("KERNEL32.dll", "ntdll.dll"), ("bcrypt.dll",))
        self.assertEqual(cpi.imports(image), ["KERNEL32.dll", "ntdll.dll", "bcrypt.dll"])

    def test_reads_pe32(self):
        self.assertEqual(cpi.imports(pe_image(("KERNEL32.dll",), magic=0x10B)), ["KERNEL32.dll"])

    def test_no_delay_directory_when_the_header_has_fewer(self):
        self.assertEqual(cpi.imports(pe_image(("KERNEL32.dll",), directories=2)), ["KERNEL32.dll"])

    def test_no_imports(self):
        self.assertEqual(cpi.imports(pe_image()), [])

    def test_refuses_what_is_not_a_pe_image(self):
        for data, reason in (
            (b"hello", "no MZ header"),
            (b"MZ", "truncated or malformed"),
            (b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"NE\0\0", "no PE signature"),
            (pe_image(magic=0x107), "magic 0x107"),
            (pe_image(("KERNEL32.dll",), import_rva=0x9000), "RVA 0x9000 is in no section"),
            (pe_image(("KERNEL32.dll",))[: SECTION_RAW + 4], "an import table runs past"),
            (pe_image(("KERNEL32.dll",))[: SECTION_RAW + 42], "a DLL name runs past"),
            (pe_image(("KERNEL32.dll",)).replace(b"KERNEL32", b"KERN\xc932"), "truncated or malformed"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(cpi.NotPE, reason):
                cpi.imports(data)

    def test_runtime_dlls_ignore_case_and_keep_the_rest_out(self):
        names = ["KERNEL32.dll", "VCRUNTIME140.dll", "vcruntime140_1.dll", "MSVCP140.dll",
                 "ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "msvcrt.dll", "ws2_32.dll"]
        self.assertEqual(cpi.runtime_dlls(names), names[1:6])


class MainTest(unittest.TestCase):
    def test_a_static_binary_passes(self):
        status, out, err = run(pe_image(("KERNEL32.dll", "ntdll.dll")), pe_image())
        self.assertEqual(status, 0, err)
        self.assertIn("no C runtime DLL (KERNEL32.dll, ntdll.dll)", out)
        self.assertIn("no C runtime DLL (no imports)", out)

    def test_the_c_runtime_as_a_dll_fails(self):
        status, out, err = run(
            pe_image(("KERNEL32.dll", "VCRUNTIME140.dll", "api-ms-win-crt-heap-l1-1-0.dll")),
            pe_image(("KERNEL32.dll",)),
        )
        self.assertEqual(status, 1)
        self.assertIn("imports VCRUNTIME140.dll, api-ms-win-crt-heap-l1-1-0.dll", err)
        self.assertIn("+crt-static", err)
        self.assertIn("binary1.exe: no C runtime DLL", out)

    def test_a_delay_loaded_runtime_fails(self):
        status, _, err = run(pe_image(("KERNEL32.dll",), ("VCRUNTIME140_1.dll",)))
        self.assertEqual(status, 1)
        self.assertIn("imports VCRUNTIME140_1.dll", err)

    def test_an_unreadable_file_fails(self):
        status, _, err = run(b"not a binary")
        self.assertEqual(status, 1)
        self.assertIn("no MZ header", err)
        err_out = io.StringIO()
        with contextlib.redirect_stderr(err_out):
            self.assertEqual(cpi.main([str(HERE / "no-such-binary.exe")]), 1)
        self.assertIn("no-such-binary.exe", err_out.getvalue())

    def test_no_arguments_prints_the_usage(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cpi.main([]), 2)
        self.assertIn("check-pe-imports.py FILE.exe", err.getvalue())


if __name__ == "__main__":
    unittest.main()
