#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

SCOPE="@earendil-works"
PACKAGES=(pi-ai pi-coding-agent pi-tui)
PIBOARD_FILE="$HOME/Library/Application Support/PiBoard/runtime/pi/current.json"
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

fail() {
  echo "bump-pi: $*" >&2
  exit 1
}

if [ "$#" -gt 1 ]; then
  fail "usage: scripts/bump-pi.sh [version]"
fi

if [ "$#" -eq 1 ]; then
  version="$1"
  source_label="argument"
else
  version="$(jq -er .activeVersion "$PIBOARD_FILE" 2>/dev/null)" ||
    fail "no activeVersion in '$PIBOARD_FILE' (missing or invalid); pass a version explicitly"
  source_label="PiBoard"
fi

[[ "$version" =~ $SEMVER_RE ]] ||
  fail "'$version' is not an exact version (expected MAJOR.MINOR.PATCH[-prerelease], no ranges or tags)"

echo "Applying pi $version (from $source_label)"

specs=()
for pkg in "${PACKAGES[@]}"; do
  specs+=("$SCOPE/$pkg@$version")
done
npm install --save-dev --save-exact "${specs[@]}"

problems=()
for pkg in "${PACKAGES[@]}"; do
  installed="$(jq -r .version "node_modules/$SCOPE/$pkg/package.json" 2>/dev/null || true)"
  if [ "$installed" != "$version" ]; then
    problems+=("$SCOPE/$pkg is '${installed:-missing}', expected '$version'")
  fi
done

# pi-coding-agent pins pi-ai and pi-tui exactly, so any nested scoped copy is a duplicate that breaks typecheck.
while IFS= read -r nested; do
  problems+=("duplicate copy: $nested")
done < <(find node_modules/"$SCOPE" -mindepth 4 -maxdepth 4 -path "*/node_modules/$SCOPE/*" 2>/dev/null || true)

if [ "${#problems[@]}" -gt 0 ]; then
  printf 'bump-pi: %s\n' "${problems[@]}" >&2
  exit 1
fi

npm run typecheck
scripts/test-isolated.sh

echo "Fork is on pi $version"
