#!/usr/bin/env bash
# Yayın-anı artifact hazırlığı. Ana hattı BOZMAZ: session-URL trailer'ı temizlenmiş
# bir `artifact-clean` dalı üretir ve doğrular. main sürerken tekrar tekrar çalışır.
#
# NEDEN geçmişi KORUYORUZ (squash DEĞİL): paper §4.1 ve held-out ön-kayıtları
# "the ordering is visible in the artifact's history" diyor -- commit sırası ve zaman
# damgaları ön-kaydın (sonuçtan ÖNCE mühürlendiğinin) kanıtı. Yalnız otomatik
# atıf/oturum trailer satırları düşürülür; konu, gövde ve gerçek yazar aynen kalır.
#
#   scripts/prepare-artifact.sh            # -> artifact-clean dalı + rapor
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -z "$(git status --porcelain)" ] || { echo "[artifact] çalışma ağacı kirli; önce commit/stash" >&2; exit 1; }

SRC=main
git branch -f artifact-src "$SRC" >/dev/null
git checkout -q artifact-clean 2>/dev/null && git reset -q --hard "$SRC" || git checkout -q -b artifact-clean "$SRC"

# Otomatik atıf/oturum trailer'larını at; başka hiçbir şeye dokunma.
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --msg-filter 'grep -vE "^(Co-Authored-By: |Claude-Session:)" || true' -- artifact-clean >/dev/null 2>&1

echo "== DOĞRULAMA =="
n_src=$(git rev-list --count "$SRC")
n_cln=$(git rev-list --count artifact-clean)
echo "  commit sayısı: main=$n_src  artifact-clean=$n_cln  (eşit olmalı: sıra korundu)"
leak=$(git log artifact-clean --format=%B | grep -cE "^(Co-Authored-By: |Claude-Session:)" || true)
echo "  temizlenen dalda kalan atıf/oturum satırı: $leak  (0 olmalı)"
# ağaç içeriği birebir aynı mı (yalnız mesajlar değişti)
diff_tree=$(git diff --stat "$SRC" artifact-clean | tail -1)
echo "  ağaç farkı (main vs artifact-clean): ${diff_tree:-YOK (birebir aynı içerik)}"
first_src=$(git log "$SRC"    --reverse --format=%ai | head -1)
first_cln=$(git log artifact-clean --reverse --format=%ai | head -1)
echo "  ilk commit zaman damgası korundu: $([ "$first_src" = "$first_cln" ] && echo EVET || echo HAYIR)"
git checkout -q "$SRC"
echo
echo "[artifact] hazır: 'artifact-clean' dalı. Yayın (kabulden sonra):"
echo "    gh repo create <ad> --public --source=. --remote=origin"
echo "    git push origin artifact-clean:main"
