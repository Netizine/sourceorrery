"""Keep the complete Rust artifact and import only already-classified source files."""

from pathlib import Path
import runpy

REPO = Path(__file__).resolve().parents[2]


def production_lcov(contents: str, root: Path, sources: set[str], tests: set[str]) -> str:
    if sources & tests:
        raise ValueError("Source and test inventories overlap")
    records = []
    for record in contents.split("end_of_record"):
        if not record.strip():
            continue
        lines = record.strip().splitlines()
        source_lines = [line for line in lines if line.startswith("SF:")]
        if len(source_lines) != 1:
            raise ValueError("Each LCOV record must identify exactly one source file")
        path = (root / source_lines[0][3:]).resolve()
        relative = path.relative_to(root.resolve()).as_posix()
        if relative in tests:
            continue
        if relative not in sources:
            raise ValueError(f"LCOV file is outside the maintained analysis inventory: {relative}")
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        for line in lines:
            if line.startswith("DA:"):
                number, hits, *_ = line[3:].split(",")
                if not 1 <= int(number) <= line_count or int(hits) < 0:
                    raise ValueError(f"Invalid LCOV execution count or line: {relative}: {line}")
        records.append("\n".join(
            f"SF:{relative}" if line.startswith("SF:") else line for line in lines
        ) + "\nend_of_record\n")
    if not records:
        raise ValueError("No production records remain in the Rust report")
    return "".join(records)


def main() -> None:
    inventory = runpy.run_path(str(REPO / "scripts/sonar/check-scope.py"))["inventory"]
    sources = inventory("SourceOrrery.Analysis.Source.csproj")
    tests = inventory("SourceOrrery.Analysis.Tests.csproj")
    original = (REPO / "coverage/rust-combined.lcov").read_text(encoding="utf-8")
    report = production_lcov(original, REPO, sources, tests)
    (REPO / "coverage/rust-production.lcov").write_text(report, encoding="utf-8")
    print(f"Rust import: {report.count('SF:')} production files; complete report retained.")


if __name__ == "__main__":
    main()
