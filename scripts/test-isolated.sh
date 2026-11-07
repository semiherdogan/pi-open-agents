#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Inherited PI_OPEN_AGENTS_* vars from a parent pi break unrelated tests.
while IFS= read -r name; do
  case "$name" in
    PI_OPEN_AGENTS_*) unset "$name" ;;
  esac
done < <(compgen -e)

exec npm test "$@"
