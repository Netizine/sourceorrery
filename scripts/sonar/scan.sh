#!/usr/bin/env bash
# Run begin before building the analysis projects; run end after all reports exist.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
: "${SONAR_TOKEN:?Set SONAR_TOKEN in the environment (never commit it)}"
case "${1:-}" in
  begin)
    : "${JAVA_HOME:?Install the project JDK before analysis}"
    version="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')"
    dotnet sonarscanner begin \
      /k:Netizine_sourceorrery /o:netizine-3 "/v:$version" \
      "/s:$repo/SonarQube.Analysis.xml" \
      "/d:sonar.projectBaseDir=$repo" \
      "/d:sonar.java.jdkHome=$JAVA_HOME" \
      "/d:sonar.token=$SONAR_TOKEN"
    ;;
  end)
    dotnet sonarscanner end "/d:sonar.token=$SONAR_TOKEN"
    ;;
  *) echo 'usage: bash scripts/sonar/scan.sh begin|end' >&2; exit 2 ;;
esac
