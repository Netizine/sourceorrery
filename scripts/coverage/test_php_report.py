"""Conversion checks independent of a PHP installation or vault fixture."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("php_report", Path(__file__).with_name("php-report.py"))
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class PhpCoverageTests(unittest.TestCase):
    def test_xdebug_states_source_filter_and_portable_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bindings/php/src/A&B.php"
            source.parent.mkdir(parents=True)
            source.write_text("<?php\n", encoding="utf-8")
            data = {
                str(source): {"7": 1, "4": -1, "5": -2},
                str(root / "bindings/php/tests/run.php"): {"1": 1},
                str(root.parent / "foreign.php"): {"1": 1},
            }
            report = reporter.coverage_xml(data, root)
            parsed = ET.fromstring(ET.tostring(report))
            self.assertEqual(parsed.attrib, {"version": "1"})
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0].get("path"), "bindings/php/src/A&B.php")
            self.assertEqual([line.attrib for line in parsed[0]], [
                {"lineNumber": "4", "covered": "false"},
                {"lineNumber": "7", "covered": "true"},
            ])

    def test_missing_sources_and_empty_reports_fail_instead_of_importing_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for data in [[], {}, {str(root / "bindings/php/src/Missing.php"): {"2": 1}}]:
                with self.assertRaises(ValueError):
                    reporter.coverage_xml(data, root)

    def test_invalid_line_data_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bindings/php/autoload.php"
            source.parent.mkdir(parents=True)
            source.write_text("<?php\n", encoding="utf-8")
            for lines in [[], {"0": 1}, {"2": -3}, {"2": "1"}, {"2": True}]:
                with self.assertRaises(ValueError):
                    reporter.coverage_xml({str(source): lines}, root)


if __name__ == "__main__":
    unittest.main()
