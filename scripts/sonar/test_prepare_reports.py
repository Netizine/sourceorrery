"""The import copy must preserve real execution counts and the existing scope."""

from pathlib import Path
import runpy
import tempfile
import unittest

production_lcov = runpy.run_path(str(Path(__file__).with_name("prepare-reports.py")))["production_lcov"]


class RustImportTests(unittest.TestCase):
    def test_preserves_source_counts_and_omits_only_inventory_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.rs").write_text("fn first() {}\nfn second() {}\n", encoding="utf-8")
            report = f"SF:{root / 'source.rs'}\nDA:1,4\nDA:2,0\nLF:2\nLH:1\nend_of_record\n"
            report += "SF:test.rs\nDA:1,100\nend_of_record\n"
            self.assertEqual(production_lcov(report, root, {"source.rs"}, {"test.rs"}),
                             "SF:source.rs\nDA:1,4\nDA:2,0\nLF:2\nLH:1\nend_of_record\n")

    def test_unknown_files_and_invalid_lines_fail_instead_of_disappearing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.rs").write_text("fn first() {}\n", encoding="utf-8")
            for record in (
                "SF:unknown.rs\nDA:1,1\n", "SF:../outside.rs\nDA:1,1\n",
                "SF:source.rs\nDA:2,1\n", "SF:source.rs\nDA:1,-1\n",
                "DA:1,1\n", "SF:source.rs\nSF:other.rs\nDA:1,1\n",
            ):
                with self.subTest(record=record), self.assertRaises(ValueError):
                    production_lcov(record + "end_of_record\n", root, {"source.rs"}, set())

    def test_overlapping_inventory_and_empty_production_report_fail(self):
        with self.assertRaises(ValueError):
            production_lcov("", Path.cwd(), {"source.rs"}, {"source.rs"})
        with self.assertRaises(ValueError):
            production_lcov("SF:test.rs\nDA:1,1\nend_of_record\n", Path.cwd(), set(), {"test.rs"})


if __name__ == "__main__":
    unittest.main()
