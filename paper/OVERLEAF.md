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

- **10 sayfa**, iki sütun, `sigconf`: gövde s.1–8, Ek A / Ek B / kaynakça s.9–10.
- Kaynakça altı kaynak. `bibtex` otomatik koşar; ilk derlemede `[?]` görürsen
  **Recompile**'a bir kez daha bas.
- `review` modunda kenardaki sayılar **satır numarasıdır, kelime sayımı değil**
  (`acmart.cls:2516`); sayfalamayı değiştirmez. Preprint modunda basılmaz.

## Gönderim / camera-ready anahtarları

**Şu anki mod (2026-09-21): `[sigconf,nonacm]` = Zenodo preprint.** Yazar bloğu gerçek,
ACM telif bloğu / "Conference'17" / sahte DOI-ISBN basılmıyor; yukarıdaki yer tutucu
notları yalnız `review`/`anonymous` modunda geçerli. Kaynakça altı kaynak.

| aşama | `\documentclass` | ayrıca |
|---|---|---|
| Zenodo preprint | `[sigconf,nonacm]` | `\author`/`\affiliation`/`\email` gerçek |
| çift-kör gönderim | `[sigconf,review,anonymous]` | `\acmConference{...}` doldurulmalı |
| camera-ready | `[sigconf]` | `\author`/`\affiliation` gerçek, `\acmDOI`, `\acmISBN`, `\copyrightyear` |

Sayfa altındaki *"Conference'17, July 2017, Washington, DC, USA"* acmart'ın
`\acmConference` yokluğunda bastığı yer tutucudur — hata değil, ama doldurulmamış
görünür.

Ölçülen yapı: gövde s.1–7, Appendix A s.8, REFERENCES s.9.

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
