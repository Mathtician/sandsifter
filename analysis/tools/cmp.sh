#!/usr/bin/env bash
# compare capstone (cdis) and objdump on hex strings
cd "$(dirname "$0")"
for h in "$@"; do
  cs=$(echo "$h" | ./cdis | tr '\t' ' ' | sed 's/  */ /g;s/ $//')
  printf '%b' "$(echo "$h" | sed 's/../\\x&/g')" > /tmp/b.bin
  od=$(objdump -D -b binary -mi386 -Mx86-64 /tmp/b.bin 2>/dev/null | sed -n 's/^ *[0-9a-f]*:.*\t *//p' | head -1)
  printf "%-16s capstone: %-44s objdump: %s\n" "$h" "$cs" "$od"
done
