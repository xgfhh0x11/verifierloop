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
zip -q -j "$ZIP" main.tex intro.tex axes.tex procedure.tex evaluation.tex \
                 casestudy.tex threats.tex related.tex conclusion.tex refs.bib
echo "[zip] $(unzip -l "$ZIP" | awk 'END{print $2}') dosya -> $ZIP"
unzip -l "$ZIP" | sed -n '4,$p' | head -12
