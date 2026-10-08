#!/bin/bash
# scan for TF #DB deferral: 1-byte opcodes and 0F xx, with modrm 00 and c0
out=$1
: > "$out"
for op in $(seq 0 255); do
  h=$(printf "%02x" $op)
  # skip blacklisted/dangerous: enter, int3, into, int, hlt handled by faults;
  # syscall/sysenter/swapgs etc are 0F-prefixed; single byte: f4 hlt -> #GP, fine
  r=$(timeout 2 ./step "${h}00" 2>/dev/null)
  echo "1b $h $r" >> "$out"
done
for op in $(seq 0 255); do
  h=$(printf "0f%02x" $op)
  [ "$h" = "0f34" ] && continue   # sysenter: skip
  r00=$(timeout 2 ./step "${h}00" 2>/dev/null)
  echo "2b $h 00 $r00" >> "$out"
  rc0=$(timeout 2 ./step "${h}c0" 2>/dev/null)
  echo "2b $h c0 $rc0" >> "$out"
done
