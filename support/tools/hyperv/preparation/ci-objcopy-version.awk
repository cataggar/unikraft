{
  sub(/^[ \t]+/, "")
  if ($0 ~ /^LLVM version /) {
    versions++
    if ($0 != "LLVM version 22.1.8") invalid = 1
  }
}
END { exit !(versions == 1 && !invalid) }
