#!/bin/bash

# Command to obtain the list of target files
files=$(rg -F 'SPDX-License-Identifier: AGPL-3.0-only' --files-without-match --glob '*.go' --glob '!pkg/ebpf_internal/**/*.go' --glob '!pkg/geodata/**/*.go' .)

# Insert the specified lines to the top of each target file
insert_lines() {
  local file="$1"
  if [ -f "$file" ]; then
    # Inserting lines at the beginning of the file
    local tmp
    tmp=$(mktemp "${file}.XXXXXX") || return 1
    if {
      echo "/*"
      echo " * SPDX-License-Identifier: AGPL-3.0-only"
      echo " * Copyright (c) 2026, 9bingyin"
      echo " */"
      echo
      cat "$file"
    } >"$tmp"; then
      if chmod --reference="$file" "$tmp" && mv "$tmp" "$file"; then
        echo "Lines inserted into $file"
      else
        rm -f "$tmp"
        return 1
      fi
    else
      rm -f "$tmp"
      return 1
    fi
  else
    echo "File not found: $file"
  fi
}

# Loop through each file and insert lines to the top
while IFS= read -r file; do
  insert_lines "$file"
done <<<"$files"
