#!/usr/bin/env bash
# paper/ -> paper/build/main.pdf. Overleaf'in yaptığının yereldeki eşleniği:
# pdflatex, bibtex, pdflatex x2 (referanslar ve atıflar iki geçişte oturur).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/paper"
OUT="$SRC/build"
command -v pdflatex >/dev/null || { echo "[paper] pdflatex yok" >&2; exit 1; }
kpsewhich acmart.cls >/dev/null || { echo "[paper] acmart.cls yok: texlive-publishers" >&2; exit 1; }
# Bu kontrol bir kez kaybedilmiş bir saatin karşılığı: fonts-extra yoksa acmart
# Computer Modern'e düşer ve microtype ÖLÜMCÜL hata verir, eksik-font uyarısı değil.
kpsewhich libertine.sty >/dev/null || echo "[paper] UYARI: libertine yok -> microtype ölümcül hata verebilir (texlive-fonts-extra)" >&2
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$SRC"/*.tex "$SRC"/*.bib "$OUT/"
cd "$OUT"
pdflatex -interaction=nonstopmode main.tex >/dev/null || true
bibtex main >/dev/null 2>&1 || true
pdflatex -interaction=nonstopmode main.tex >/dev/null || true
pdflatex -interaction=nonstopmode main.tex >/dev/null || true
[ -f main.pdf ] || { echo "[paper] PDF üretilmedi; $OUT/main.log'a bak" >&2; tail -20 main.log >&2; exit 1; }
echo "[paper] $(pdfinfo main.pdf 2>/dev/null | awk '/^Pages/{print $2}') sayfa -> $OUT/main.pdf"
# NOT: bu ortamda `grep` ugrep ve `-c` sifir sayimda hicbir sey basmiyor -- sayimi
# kabukta yapiyoruz ki "0" ile "grep sustu" ayni goze gelmesin.
# Yalnizca ATIF/REFERANS tanimsizligini say. Duz "undefined" araması yanlis alarm
# uretiyordu: acmart+libertine iki `Font shape ... undefined` uyarisi biraktiriyor
# ve LaTeX onlari sessizce ikame ediyor -- derlemeyle ilgisi yok.
u=$(grep -c "Warning: \(Citation\|Reference\) .* undefined" main.log 2>/dev/null || true); u=${u:-0}
echo "[paper] tanimsiz atif/referans: $u"
[ "$u" = "0" ] || { echo "[paper] -> bibtex'i tekrar kosmak gerekebilir" >&2; }
