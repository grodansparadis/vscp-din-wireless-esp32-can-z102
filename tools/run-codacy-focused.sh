#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
codacy_bin="${HOME}/.local/bin/codacy"
output_dir="${repo_root}/codacy-focused"

if [[ ! -x "${codacy_bin}" ]]; then
    echo "Codacy CLI not found at ${codacy_bin}" >&2
    exit 1
fi

mkdir -p "${output_dir}"

cd "${repo_root}"

"${codacy_bin}" analyze --tool opengrep --format sarif --output "${output_dir}/opengrep.sarif"
"${codacy_bin}" analyze --tool lizard --format sarif --output "${output_dir}/lizard.sarif"
"${codacy_bin}" analyze --tool trivy --format sarif --output "${output_dir}/trivy.sarif"

echo "Focused Codacy reports written to ${output_dir}"