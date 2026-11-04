#!/bin/bash
# Giai nen cac mau doc da chon (pick.txt) tu bo DataDog vao ~/d04_real/real_dataset
# va ghi bang nhan mal_map.csv. Chi giai nen + di chuyen file, KHONG chay ma trong goi.
# Chay trong VM Ubuntu co lap. Xem benchmark/README.md.
cd ~/d04_real/malicious-software-packages-dataset
OUT=~/d04_real/real_dataset
MAP=~/d04_real/mal_map.csv
rm -rf "$OUT"; mkdir -p "$OUT"
echo "pkg_id,category,zip" > "$MAP"
i=0
while read -r z; do
  z=${z#/}; i=$((i+1)); id=$(printf 'mal-%05d' $i)
  t=$(mktemp -d)
  if unzip -q -o -P infected "$z" -d "$t" 2>/dev/null; then
    p=$(find "$t" -type f -path '*/package/package.json' | awk '{print length, $0}' | sort -n | head -1 | cut -d' ' -f2-)
    if [ -n "$p" ]; then
      mv "$(dirname "$p")" "$OUT/$id"
      echo "$id,$(echo "$z" | cut -d/ -f3),$z" >> "$MAP"
    else echo "khong co package.json: $z"; fi
  else echo "unzip loi: $z"; fi
  rm -rf "$t"
done < ~/d04_real/pick.txt
echo "Xong: $(ls "$OUT" | wc -l) package"
