# paper/

Kaynak: `main.tex` (iskelet + bölüm sözleşmeleri), `intro.tex` (yazıldı),
`refs.bib` (yalnız kaynaktan okunmuş girdiler).

**Derleme burada yapılamaz** — `acmart.cls` konteynerde yok. Overleaf'e yükle ya da
`texlive-publishers` kurulu bir makinede `latexmk -pdf main.tex`.

## Baştan verilmiş üç yapısal karar

1. **Sayfa limiti sayı olarak yazılmadı.** CFP'den doldurulacak. Bu projede
   uydurulmuş bir sayı, kaçınmak için var olduğumuz şeydir.
2. **Vaka çalışması ≤ 2.5 sayfa, sert.** Arkasındaki malzeme 112 girdilik bir
   mühendislik günlüğü; ağırlığı bölümü kronolojiye çeker ve kronoloji, günlüğün
   paper kılığına girmesidir. `main.tex` §5'in izin verilen içeriği madde madde
   yazılı, yasak olanı da.
3. **Harita gövdede tek figür, tamamı Ek A.** Boş hücre "denenmedi" demek, "kör"
   değil — ek bunu okurun göreceği yerde söylemek zorunda.

## Filtre

`intro.tex`'in son cümlesi vaka çalışmasının filtresidir. §5'te yazılan her
paragraf "bu, *where the reference reads* iddiasını mı taşıyor" testinden geçmeli.
Geçmiyorsa kronolojidir ve çıkar.

## Mekân

acmart sigconf, ISSTA'ya nişanlı. ICSE aynı sınıf; ISSTA-collocated workshop'lar
aynı sınıfın kısa biçimi. Aşağı ya da yana taşımak biçim değişikliği, yeniden
yazma değil. Takip işi (dış hata popülasyonunun bölüntülenmesi) bu paper'a
girmiyor; §7'de tasarımıyla adlandırıldı.
