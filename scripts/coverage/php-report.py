"""Convert Xdebug line coverage to Sonar's generic coverage XML, not test results.

Only PHP SDK source files are imported. Xdebug -1 means executable but uncovered;
-2 means dead/non-executable and is omitted. Branch counts are not fabricated.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def coverage_xml(data: dict, repository: Path) -> ET.Element:
    if not isinstance(data, dict):
        raise ValueError("Expected Xdebug's filename-to-lines coverage mapping")
    repository = repository.resolve()
    report = ET.Element("coverage", version="1")
    for filename, lines in sorted(data.items()):
        source = Path(filename).resolve()
        try:
            relative = source.relative_to(repository).as_posix()
        except ValueError:
            continue
        if not (relative.startswith("bindings/php/src/") or relative == "bindings/php/autoload.php"):
            continue
        if source.suffix != ".php" or not source.is_file():
            raise ValueError(f"Coverage source does not exist: {relative}")
        if not isinstance(lines, dict):
            raise ValueError(f"Expected Xdebug line coverage for {relative}")
        covered_lines = []
        for number, hits in lines.items():
            line = int(number)
            if line < 1 or type(hits) is not int or hits < -2:
                raise ValueError(f"Invalid Xdebug line coverage for {relative}:{number}")
            if hits != -2:
                covered_lines.append((line, hits > 0))
        if not covered_lines:
            continue
        file_node = ET.SubElement(report, "file", path=relative)
        for line, covered in sorted(covered_lines):
            ET.SubElement(file_node, "lineToCover", lineNumber=str(line), covered=str(covered).lower())
    if len(report) == 0:
        raise ValueError("Xdebug reported no executable PHP SDK lines; check its coverage mode and filters")
    return report


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: python scripts/coverage/php-report.py coverage/php.json coverage/php.xml")
    repository = Path(__file__).resolve().parents[2]
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    report = coverage_xml(data, repository)
    ET.indent(report)
    ET.ElementTree(report).write(sys.argv[2], encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main()
