"""Tests for abi-check.py: python3 -m unittest scripts/ci/abi_check_test.py"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("abi_check", HERE / "abi-check.py")
ac = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["abi_check"] = ac  # dataclasses look the module up by name
spec.loader.exec_module(ac)

HEADER = """
/* SourceOrrery C ABI. */
#ifndef SOURCEORRERY_H
#define SOURCEORRERY_H
#define SO_ABI_VERSION 1
#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
enum so_status
#ifdef __cplusplus
  : int32_t
#endif
 { SO_STATUS_OK = 0, SO_STATUS_ERROR = 1, SO_STATUS_PANIC = 2, };
typedef enum so_status so_status;
#else
typedef int32_t so_status;
#endif
typedef struct so_reader so_reader;
/** A caller-owned buffer. */
typedef struct so_bytes {
    uint8_t *ptr;
    size_t len;
} so_bytes;
uint32_t so_abi_version(void);
// Free a buffer.
void so_bytes_free(struct so_bytes *bytes);
so_status so_reader_open(const uint8_t *name,
                         size_t name_len,
                         struct so_reader **out_handle);
#ifdef __cplusplus
}  // extern "C"
#endif
#endif
"""


class Parsing(unittest.TestCase):
    def test_declarations_are_found_and_normalised(self) -> None:
        decls = ac.parse(HEADER)
        self.assertEqual(decls.abi_version, "1")
        self.assertEqual(
            decls.functions["so_reader_open"],
            "so_status so_reader_open(const uint8_t *name,size_t name_len,struct so_reader **out_handle)",
        )
        self.assertEqual(decls.functions["so_bytes_free"], "void so_bytes_free(struct so_bytes *bytes)")
        self.assertEqual(decls.structs["so_bytes"], "uint8_t *ptr;size_t len;")
        self.assertEqual(decls.enums["so_status.SO_STATUS_PANIC"], "2")
        self.assertNotIn("SOURCEORRERY_H", decls.functions)

    def test_whitespace_and_comments_do_not_matter(self) -> None:
        reflowed = HEADER.replace("const uint8_t *name,\n                         size_t name_len,", "const uint8_t  * name, size_t name_len,")
        self.assertEqual(ac.parse(reflowed).functions, ac.parse(HEADER).functions)


class Verdicts(unittest.TestCase):
    def check(self, current: str) -> tuple[bool, str]:
        return ac.verdict(ac.parse(HEADER), ac.parse(current), "v0.1.4")

    def test_identical_headers_pass(self) -> None:
        ok, report = self.check(HEADER)
        self.assertTrue(ok, report)
        self.assertIn("no incompatible change", report)

    def test_additions_are_compatible(self) -> None:
        current = HEADER.replace("#endif\n", "so_status so_reader_list(const struct so_reader *handle);\n#define SO_NEW 7\n#endif\n", 1)
        current = current.replace("SO_STATUS_PANIC = 2,", "SO_STATUS_PANIC = 2, SO_STATUS_BUSY = 3,")
        ok, report = self.check(current)
        self.assertTrue(ok, report)
        self.assertIn("function so_reader_list", report)
        self.assertIn("enum member so_status.SO_STATUS_BUSY", report)

    def test_changed_prototype_without_bump_fails(self) -> None:
        current = HEADER.replace("size_t name_len,", "uint32_t name_len,")
        ok, report = self.check(current)
        self.assertFalse(ok)
        self.assertIn("function so_reader_open changed", report)
        self.assertIn("SO_ABI_VERSION bumped", report)

    def test_removed_function_struct_change_and_enum_value_fail(self) -> None:
        current = HEADER.replace("void so_bytes_free(struct so_bytes *bytes);\n", "")
        current = current.replace("    size_t len;\n", "    size_t len;\n    size_t cap;\n")
        current = current.replace("SO_STATUS_PANIC = 2", "SO_STATUS_PANIC = 3")
        ok, report = self.check(current)
        self.assertFalse(ok)
        self.assertIn("function so_bytes_free was removed", report)
        self.assertIn("struct so_bytes changed", report)
        self.assertIn("enum member so_status.SO_STATUS_PANIC changed", report)

    def test_bumped_version_allows_incompatible_changes(self) -> None:
        current = HEADER.replace("#define SO_ABI_VERSION 1", "#define SO_ABI_VERSION 2").replace("size_t name_len,", "uint32_t name_len,")
        ok, report = self.check(current)
        self.assertTrue(ok, report)
        self.assertIn("allowed", report)

    def test_missing_version_macro_fails(self) -> None:
        ok, report = self.check(HEADER.replace("#define SO_ABI_VERSION 1\n", ""))
        self.assertFalse(ok)
        self.assertIn("missing", report)

    def test_real_header_is_compatible_with_itself(self) -> None:
        real = (HERE / ".." / ".." / "crates" / "sourceorrery-ffi" / "include" / "sourceorrery.h").read_text()
        decls = ac.parse(real)
        self.assertEqual(decls.abi_version, "1")
        self.assertIn("so_reader_get", decls.functions)
        self.assertIn("so_secret_list", decls.functions)
        self.assertGreaterEqual(len(decls.functions), 30, sorted(decls.functions))
        self.assertEqual(decls.structs["so_bytes"], "uint8_t *ptr;size_t len;")
        self.assertEqual(decls.enums["so_status.SO_STATUS_ERROR"], "1")
        self.assertTrue(ac.verdict(decls, decls, "self")[0])


if __name__ == "__main__":
    unittest.main()
