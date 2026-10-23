"""Check MSBuild's evaluated source/test inventory, including generated-file boundaries."""

import json
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[2]


def inventory(project: str) -> set[str]:
    result = subprocess.run(
        ["dotnet", "msbuild", project, "-getItem:Content", "-nologo"],
        cwd=REPO, check=True, capture_output=True, text=True,
    )
    files = {Path(item["FullPath"]) for item in json.loads(result.stdout)["Items"]["Content"]}
    project_directory = (REPO / project).parent
    # The .NET scanner moves linked files outside the project's directory into
    # root sources, which would silently turn linked test files into production.
    if outside := sorted(str(path) for path in files if not path.is_relative_to(project_directory)):
        raise SystemExit(f"Files outside their Sonar project directory: {outside}")
    return {path.relative_to(REPO).as_posix() for path in files}


def main() -> None:
    sources = inventory("SourceOrrery.Analysis.Source.csproj")
    tests = inventory("SourceOrrery.Analysis.Tests.csproj")
    if sources & tests:
        raise SystemExit(f"Files classified as both source and test: {sorted(sources & tests)}")

    expected_sources = {
        "crates/sourceorrery-core/src/lib.rs", "bindings/python/src/lib.rs",
        "bindings/node/src/lib.rs", "bindings/python/python/sourceorrery/__init__.py",
        "bindings/node/lib/index.js", "bindings/go/sourceorrery.go",
        "bindings/java/src/main/java/ai/sourceorrery/SecretReader.java",
        "bindings/php/src/SecretReader.php", "bindings/cpp/include/sourceorrery.hpp",
        "crates/sourceorrery-ffi/include/sourceorrery.h",
        "crates/sourceorrery-ffi/examples/get_secret.c",
        "bindings/cpp/examples/get_secret.cpp", "site/src/content.config.ts",
        "site/src/lib/doc-metadata.mjs", "scripts/release/set-version.py",
    }
    expected_tests = {
        "bindings/python/tests/test_reader.py", "bindings/python/tests/conftest.py",
        "bindings/python/conformance/run.py", "tests/conformance/sdk/harness.py",
        "bindings/node/__test__/reader.test.mjs", "bindings/go/reader_test.go",
        "bindings/java/src/test/java/ai/sourceorrery/ReaderTest.java",
        "bindings/php/tests/run.php", "bindings/cpp/tests/reader_test.cpp",
        "crates/sourceorrery-storage/src/sqlite/tests.rs",
        "crates/sourceorrery-cli/src/ui/view/tests.rs",
        "site/scripts/docs-tooling.test.mjs", "scripts/coverage/test_php_report.py",
        "scripts/release/set_version_test.py", "scripts/release/test_publish_crates.py",
        "scripts/release/package_managers_test.py", "scripts/ci/abi_check_test.py",
    }
    for label, expected, actual in [("production", expected_sources, sources), ("test", expected_tests, tests)]:
        if missing := expected - actual:
            raise SystemExit(f"Missing {label} files: {sorted(missing)}")
    for path in sources | tests:
        if any(part in {"node_modules", "target", "bin", "obj", "dist", ".astro", "__pycache__"} for part in Path(path).parts):
            raise SystemExit(f"Dependency/generated file leaked into analysis: {path}")
        if path.startswith("bindings/dotnet/") or path in {"bindings/node/index.js", "bindings/node/index.d.ts"}:
            raise SystemExit(f"File owned by another project or generated loader: {path}")
    print(f"Sonar scope: {len(sources)} production/tooling files, {len(tests)} test files; C# uses its real projects.")


if __name__ == "__main__":
    main()
