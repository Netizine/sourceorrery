"""Reject missing/empty reports before publishing a misleading coverage analysis."""

from pathlib import Path
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]


def xml_report(relative: str, tag: str, selector: str, attribute: str) -> None:
    root = ET.parse(REPO / relative).getroot()
    if root.tag != tag or not any(
        node.get(attribute) == "true" or node.get(attribute, "0").isdigit() and int(node.get(attribute, "0")) > 0
        for node in root.findall(selector)
    ):
        raise ValueError(f"No executed production lines in {relative}")
    print(relative)


def main() -> None:
    for relative in ["coverage/rust-combined.lcov", "coverage/rust-production.lcov",
                     "coverage/node/lcov.info", "coverage/site/lcov.info", "coverage/tooling-node/lcov.info"]:
        lines = (REPO / relative).read_text(encoding="utf-8").splitlines()
        if not any(line.startswith("SF:") for line in lines) or not any(
            line.startswith("DA:") and int(line.split(",")[1]) > 0 for line in lines
        ):
            raise ValueError(f"No executed production lines in {relative}")
        print(relative)
    xml_report("coverage/python.xml", "coverage", ".//class/lines/line", "hits")
    xml_report("coverage/tooling-python.xml", "coverage", ".//class/lines/line", "hits")
    xml_report("coverage/cpp.xml", "coverage", "file/lineToCover", "covered")
    xml_report("coverage/php.xml", "coverage", "file/lineToCover", "covered")
    xml_report("coverage/dotnet.xml", "CoverageSession", ".//SequencePoint", "vc")
    xml_report("bindings/java/target/site/jacoco/jacoco.xml", "report", "counter[@type='LINE']", "covered")
    go = (REPO / "coverage/go.out").read_text(encoding="utf-8").splitlines()
    if not go or not go[0].startswith("mode: ") or not any(
        line.startswith("bindings/go/") and int(line.rsplit(" ", 1)[1]) > 0 for line in go[1:]
    ):
        raise ValueError("No executed production lines in coverage/go.out")
    print("coverage/go.out")


if __name__ == "__main__":
    main()
