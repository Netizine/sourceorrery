#!/usr/bin/env bash
# Prove that the PHP package installs through Composer from a git tag, the
# way Packagist serves it: the repository is the package, the manifest is
# composer.json at the repository root and the version is the tag.
#
#   bash scripts/ci/php-package-install.sh 0.2.0
#
# The tree at HEAD is copied into a scratch repository (nothing in this
# checkout is tagged or touched), tagged v<version> there, added to a
# throwaway project as a `vcs` repository and required at exactly <version>.
# Composer's own autoloader must then resolve every class under
# bindings/php/src, including the exception classes that share one file.
# Needs git, php and composer on PATH. Run by the sdk-php CI job and by the
# release workflow's php job (docs/release.md).
set -euo pipefail

version="${1:?usage: $0 <version>}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "--- scratch repository tagged v$version"
mkdir "$work/src"
git -C "$root" archive --format=tar HEAD | tar -x -C "$work/src"
git -C "$work/src" init --quiet
git -C "$work/src" -c core.safecrlf=false add --all
git -C "$work/src" -c user.name=sourceorrery-ci -c user.email=ci@sourceorrery.invalid commit --quiet --message "release test"
git -C "$work/src" tag "v$version"

echo "--- composer require sourceorrery/sourceorrery:$version from that repository"
mkdir "$work/project"
printf '{"repositories":[{"type":"vcs","url":"%s"}],"require":{"sourceorrery/sourceorrery":"%s"}}\n' "$work/src" "$version" > "$work/project/composer.json"
composer --working-dir="$work/project" install --no-interaction --no-progress --prefer-source

echo "--- the installed version is the tag"
# Composer reports the tag as written (v9.9.9); the version it resolved is 9.9.9.
installed="$(composer --working-dir="$work/project" show sourceorrery/sourceorrery --format=json | php -r 'echo json_decode(stream_get_contents(STDIN), true)["versions"][0];')"
if [[ "${installed#v}" != "$version" ]]; then
    echo "::error::Composer installed sourceorrery/sourceorrery $installed, expected $version"
    exit 1
fi
echo "sourceorrery/sourceorrery $installed"

echo "--- every class under bindings/php/src autoloads through vendor/autoload.php"
# shellcheck disable=SC2016  # PHP code, not shell expansion
php -r '
    [$autoload, $src] = [$argv[1], $argv[2]];
    require $autoload;
    $classes = [];
    foreach (glob($src . "/*.php") as $file) {
        preg_match_all("/^(?:final |abstract )?class (\\w+)/m", file_get_contents($file), $found);
        array_push($classes, ...$found[1]);
    }
    $missing = array_filter($classes, static fn (string $class): bool => !class_exists("SourceOrrery\\" . $class));
    if ($missing !== []) {
        fwrite(STDERR, "::error::not autoloadable: " . implode(", ", $missing) . "\n");
        exit(1);
    }
    echo count($classes), " classes autoload\n";
' "$work/project/vendor/autoload.php" "$work/project/vendor/sourceorrery/sourceorrery/bindings/php/src"
