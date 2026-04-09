#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd "$script_dir/.." && pwd)"
build_dir="$workspace_dir/build"

source /home/akhe/development/esp/esp-idf/export.sh

needs_fullclean=0
reason=""

if [[ -f "$build_dir/CMakeCache.txt" ]]; then
  generator="$(awk -F= '/^CMAKE_GENERATOR:INTERNAL=/{print $2; exit}' "$build_dir/CMakeCache.txt")"
  if [[ -n "$generator" && "$generator" != "Ninja" ]]; then
    needs_fullclean=1
    reason="CMakeCache.txt generator is '$generator'"
  fi
fi

if [[ $needs_fullclean -eq 0 && -f "$build_dir/Makefile" ]]; then
  needs_fullclean=1
  reason="top-level Makefile generator artifacts are present"
fi

if [[ $needs_fullclean -eq 0 && -f "$build_dir/CMakeFiles/Makefile.cmake" ]]; then
  if grep -q 'Unix Makefiles' "$build_dir/CMakeFiles/Makefile.cmake"; then
    needs_fullclean=1
    reason="CMakeFiles/Makefile.cmake still references Unix Makefiles"
  fi
fi

if [[ $needs_fullclean -eq 1 ]]; then
  echo "Detected stale CMake generator metadata in $build_dir ($reason). Running idf.py fullclean before continuing."
  idf.py fullclean
fi

exec idf.py "$@"