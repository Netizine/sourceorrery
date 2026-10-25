"""Exercise native.sh's external-build environment without compiling the SDKs."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
BASH = (
    str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe")
    if os.name == "nt" else shutil.which("bash")
)


class NativeCoverageEnvironmentTests(unittest.TestCase):
    def test_go_search_path_quotes_the_whole_argument_and_preserves_existing_flags(self):
        coverage_root = REPO / "coverage"
        coverage_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="go-env-", dir=coverage_root) as directory:
            self.assertEqual(Path(directory).resolve().parent, coverage_root.resolve())
            root = Path(directory) / "fixture repo"
            script = root / "scripts/coverage/sdk.sh"
            script.parent.mkdir(parents=True)
            shutil.copyfile(REPO / "scripts/coverage/sdk.sh", script)
            (root / "bindings/go").mkdir(parents=True)
            stub_dir = root / "bin"
            stub_dir.mkdir()
            go = stub_dir / "go"
            go.write_text('#!/usr/bin/env bash\nprintf "%s" "$CGO_LDFLAGS" > "$COVERAGE_ENV_LOG"\nexit 73\n',
                          encoding="utf-8", newline="\n")
            go.chmod(0o755)
            native = root / "native library"
            log = root / "environment.log"
            env = os.environ.copy()
            env.update({
                "COVERAGE_STUB_DIR": stub_dir.as_posix(),
                "COVERAGE_ENV_LOG": log.as_posix(),
                "CGO_LDFLAGS": '-pthread "-Wl,--as-needed"',
                "SOURCEORRERY_NATIVE_DIR": native.as_posix(),
                **{name: "fixture-only" for name in (
                    "SOURCEORRERY_HOME", "SOURCEORRERY_RECOVERY_KEY", "SOURCEORRERY_TEST_VAULT",
                    "SOURCEORRERY_TEST_MANIFEST", "SOURCEORRERY_TEST_OLD_VERSION",
                )},
            })
            result = subprocess.run(
                [BASH, "--noprofile", "--norc", "-c",
                 'export PATH="$(cd "$COVERAGE_STUB_DIR" && pwd):$PATH"; source "$@"',
                 "coverage-go-test", script.as_posix(), "go"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
            # Like Go's cmd/internal/quoted.Split, non-POSIX tokenization only
            # treats a quote at the start of an argument as an enclosing quote.
            arguments = shlex.split(log.read_text(), posix=False)
            arguments = [arg[1:-1] if arg[0] in "\"'" and arg[-1] == arg[0] else arg
                         for arg in arguments]
            self.assertEqual(arguments, ["-pthread", "-Wl,--as-needed", "-L" + native.as_posix()])

    def test_external_builds_and_reports_share_the_isolated_target_for_every_mode(self):
        coverage_root = REPO / "coverage"
        coverage_root.mkdir(exist_ok=True)
        for mode in ("workspace", "python", "node"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="native-env-", dir=coverage_root
            ) as directory:
                self.assertEqual(Path(directory).resolve().parent, coverage_root.resolve())
                root = Path(directory) / "fixture repo"
                script = root / "scripts/coverage/native.sh"
                script.parent.mkdir(parents=True)
                shutil.copyfile(REPO / "scripts/coverage/native.sh", script)
                stub_dir = root / "bin"
                stub_dir.mkdir()

                def stub(name, body):
                    path = stub_dir / name
                    path.write_text("#!/usr/bin/env bash\nset -eu\n" + body, encoding="utf-8", newline="\n")
                    path.chmod(0o755)

                # Model cargo-llvm-cov 0.9.1: show-env reports the directory
                # selected by Cargo metadata, but does not set CARGO_TARGET_DIR.
                stub("cargo", '''case "$*" in
  'llvm-cov --version') exit 0 ;;
  'llvm-cov show-env --sh'*)
    printf 'cwd=%s\nshow-args=%s\n' "$PWD" "$*" >> "$COVERAGE_ENV_LOG"
    printf "export CARGO_LLVM_COV_TARGET_DIR='%s'\\n" "${CARGO_TARGET_DIR:-$PWD/target}"
    printf "export LLVM_PROFILE_FILE='%s/test-%%p.profraw'\\n" "${CARGO_TARGET_DIR:-$PWD/target}"
    ;;
  'llvm-cov clean --workspace') exit 0 ;;
  *)
    printf 'build=%s\nreport=%s\nprofile=%s\n' "${CARGO_TARGET_DIR:-unset}" "$CARGO_LLVM_COV_TARGET_DIR" "$LLVM_PROFILE_FILE" >> "$COVERAGE_ENV_LOG"
    exit 73 ;;
esac
''')
                stub("npm", '''printf 'build=%s\nreport=%s\nprofile=%s\n' "${CARGO_TARGET_DIR:-unset}" "$CARGO_LLVM_COV_TARGET_DIR" "$LLVM_PROFILE_FILE" >> "$COVERAGE_ENV_LOG"
exit 73
''')
                stub("uname", "echo Linux\n")
                stub("rustc", "echo 'host: x86_64-unknown-linux-gnu'\n")
                for command in ("python3", "node", "gcc", "g++", "gcov", "gcovr"):
                    stub(command, "exit 0\n")
                for binding in ("python", "node"):
                    (root / "bindings" / binding).mkdir(parents=True)
                napi = root / "bindings/node/node_modules/.bin/napi"
                napi.parent.mkdir(parents=True)
                napi.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
                napi.chmod(0o755)
                fixture = root / "fixture"
                fixture.mkdir()
                manifest = fixture / "sourceorrery.toml"
                manifest.touch()
                log = root / "environment.log"
                env = os.environ.copy()
                env.update({
                    "COVERAGE_STUB_DIR": stub_dir.as_posix(),
                    "COVERAGE_ENV_LOG": log.as_posix(),
                    "CARGO_TARGET_DIR": "unrelated-caller-target",
                    "CARGO_LLVM_COV_TARGET_DIR": "unrelated-caller-report",
                    "SOURCEORRERY_COVERAGE_PYTHON": "python3",
                    "SOURCEORRERY_HOME": fixture.as_posix(),
                    "SOURCEORRERY_RECOVERY_KEY": "fixture-only",
                    "SOURCEORRERY_TEST_VAULT": "ci",
                    "SOURCEORRERY_TEST_MANIFEST": manifest.as_posix(),
                    "SOURCEORRERY_TEST_OLD_VERSION": "fixture-only",
                })
                command = [BASH, "--noprofile", "--norc", "-c",
                           'export PATH="$(cd "$COVERAGE_STUB_DIR" && pwd):$PATH"; source "$@"',
                           "coverage-env-test", script.as_posix(), mode]
                result = subprocess.run(command, env=env,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
                values = dict(line.split("=", 1) for line in log.read_text().splitlines())
                repository = values["cwd"] if mode == "workspace" else values["cwd"].rsplit("/bindings/", 1)[0]
                expected = f"{repository}/target/coverage-rust-{mode}"
                self.assertEqual(values["build"], expected)
                self.assertEqual(values["report"], expected)
                self.assertEqual(values["profile"], expected + "/test-%p.profraw")
                self.assertEqual("--target x86_64-unknown-linux-gnu" in values["show-args"], mode == "node")


if __name__ == "__main__":
    unittest.main()
