#!/usr/bin/env bash
# Decides whether a change can affect code, for the `changes` job in
# .github/workflows/ci.yml. Prints every changed file and writes
# `code=true` or `code=false`, and `deps=true` or `deps=false`, to
# $GITHUB_OUTPUT.
#
# A change is docs-only when every changed file is documentation:
#   - anything under docs/ or site/ (the site has its own build, docs.yml),
#   - a Markdown file or an image anywhere except crates/ and bindings/,
#     whose READMEs ship inside the packages those jobs build.
# Anything else is code. So is every case where the diff cannot be
# computed: an unknown event, a missing base, an empty diff. Renames count
# both paths (--no-renames), so moving a source file into docs/ is code.
#
# `deps` is true for every code change and for a change to a dependency
# graph that scripts/ci/dependency-audit.py audits but that would count as
# documentation (the site's npm graph): the dependency audit runs for it,
# the builds do not. The site's dependencies reach the deployed site.
#
# In CI:   EVENT and BEFORE come from the workflow (see ci.yml).
# Locally: bash scripts/ci/classify-changes.sh <base> <head>
set -uo pipefail

is_docs() {
	case "$1" in
		docs/* | site/*) return 0 ;;
		crates/* | bindings/*) return 1 ;;
		*.md | *.png | *.svg | *.jpg | *.jpeg | *.gif | *.webp) return 0 ;;
		*) return 1 ;;
	esac
}

# The audited dependency graphs under paths is_docs accepts.
is_dependency_graph() {
	case "$1" in
		site/package.json | site/package-lock.json | site/.npmrc) return 0 ;;
		*) return 1 ;;
	esac
}

zero=0000000000000000000000000000000000000000
base=""
head=HEAD
if [[ $# -eq 2 ]]; then
	base="$1"
	head="$2"
else
	case "${EVENT:-}" in
		# actions/checkout puts a pull request's merge commit at HEAD; its
		# first parent is the base branch it merges into.
		pull_request) base="HEAD^1" ;;
		push)
			if [[ -n "${BEFORE:-}" ]] && [[ "$BEFORE" != "$zero" ]] &&
				git fetch --quiet --depth=1 origin "$BEFORE"; then
				base="$BEFORE"
			fi
			;;
	esac
fi

code=true
deps=true
if [[ -n "$base" ]] && files="$(git diff --name-only --no-renames "$base" "$head")" && [[ -n "$files" ]]; then
	code=false
	deps=false
	while IFS= read -r file; do
		if is_dependency_graph "$file"; then
			echo "deps  $file"
			deps=true
		elif is_docs "$file"; then
			echo "docs  $file"
		else
			echo "code  $file"
			code=true
			deps=true
		fi
	done <<<"$files"
else
	echo "No diff to classify; treating the change as code."
fi

echo "code=$code deps=$deps"
{
	echo "code=$code"
	echo "deps=$deps"
} >>"${GITHUB_OUTPUT:-/dev/null}"
