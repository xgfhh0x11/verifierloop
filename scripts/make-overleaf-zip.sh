#!/usr/bin/env bash
# Overleaf'e yüklenecek zip: KAYNAK dosyalar, derleme artefaktı yok, acmart.cls yok
# (Overleaf'in kendi kopyası var; ikinci bir kopya sürüm çakışması demek).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/paper"
OUT="$SRC/build"
ZIP="$OUT/verifierloop-paper-overleaf.zip"
command -v zip >/dev/null || { echo "[zip] zip yok: apt-get install zip" >&2; exit 1; }
mkdir -p "$OUT"; rm -f "$ZIP"
cd "$SRC"
# SABİT LİSTE KULLANMA. appendixA/B eklendiginde zip sessizce eksik cikti ve
# Overleaf'te derleme kirilirdi -- burada yakalandi. Glob + \input sayimi dogrular.
zip -q -j "$ZIP" *.tex refs.bib
want=$(( $(grep -c '\\input{' main.tex) + 1 ))   # input edilenler + main.tex
got=$(unzip -l "$ZIP" | grep -c '\.tex$')
[ "$got" -ge "$want" ] || { echo "[zip] EKSIK: $got .tex var, en az $want bekleniyor" >&2; exit 1; }
echo "[zip] $(unzip -l "$ZIP" | awk 'END{print $2}') dosya -> $ZIP"
unzip -l "$ZIP" | sed -n '4,$p' | head -12
