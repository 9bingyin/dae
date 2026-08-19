#!/bin/bash

set -euo pipefail

target_year="${1:-$(date +%Y)}"
if [[ ! $target_year =~ ^[0-9]{4}$ ]] || ((target_year < 2026)); then
  echo "target year must be 2026 or later" >&2
  exit 1
fi

period="2026"
if ((target_year > 2026)); then
  period="2026-${target_year}"
fi

mapfile -t files < <(rg -l 'Copyright \(c\) 2026(-[0-9]{4})?, 9bingyin' . || true)
if ((${#files[@]} == 0)); then
  exit 0
fi

sed -Ei "s/Copyright \(c\) 2026(-[0-9]{4})?, 9bingyin/Copyright (c) ${period}, 9bingyin/g" "${files[@]}"
