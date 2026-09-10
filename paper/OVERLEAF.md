# Overleaf'te derleme

## Yükleme

`verifierloop-paper-overleaf.zip` → Overleaf → **New Project → Upload Project**.

Overleaf `main.tex`'i kendisi ana dosya olarak seçer (kök dizinde tek `\documentclass`
onda). Derleyici **pdfLaTeX**, TeX Live sürümü fark etmez — `acmart` 2020'den beri
her Overleaf imajında var.

Zip'te olanlar: `main.tex` + sekiz `\input` dosyası + `refs.bib`. `acmart.cls` ve
`ACM-Reference-Format.bst` **bilerek konmadı** — Overleaf'in kendi TeX Live'ında
zaten var ve dizine bir kopya koymak sürüm çakışması üretir.

## Beklenen çıktı

- **~7 sayfa**, iki sütun, `sigconf`.
- Sol kenarda **satır numaraları** — `review` seçeneğinin işi, kaldırmak için
  `main.tex`'in ilk satırındaki `review`'ı sil.
- Başlık bloğunda yazar yerine boşluk ve *"Conference acronym 'XX, June 03–05, 2018,
  Woodstock, NY"* — ikisi de acmart'ın **yer tutucusu**, hata değil. Gönderimde
  `\author{...}` ve `\acmConference{...}` doldurulunca gider.
- Kaynakça üç kaynak. `bibtex` otomatik koşar; ilk derlemede `[?]` görürsen
  **Recompile**'a bir kez daha bas.

## Yerelde aynısını derlemek

```bash
scripts/build-paper.sh          # -> paper/build/main.pdf
```

Gerekenler: `texlive-latex-recommended texlive-latex-extra texlive-publishers
texlive-fonts-recommended texlive-fonts-extra`. `texlive-fonts-extra` olmadan
acmart libertine yerine Computer Modern'e düşer ve microtype "auto expansion is
only possible with scalable fonts" diye **ölümcül** hata verir — Overleaf'te bu
olmaz, yerelde olur.

## Zip'i yeniden üretmek

```bash
scripts/make-overleaf-zip.sh    # -> paper/build/verifierloop-paper-overleaf.zip
```
