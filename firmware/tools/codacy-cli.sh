#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
launcher="${repo_root}/third_party/vscp-firmware/.codacy/cli.sh"

if [[ ! -x "${launcher}" ]]; then
  echo "Codacy launcher not found at ${launcher}" >&2
  exit 1
fi

# Common defaults for this firmware workspace.
export CODACY_PROJECT_TOKEN="${CODACY_PROJECT_TOKEN:-}"

cd "${repo_root}"
exec "${launcher}" "$@"
