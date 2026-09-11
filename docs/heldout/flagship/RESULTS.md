# Amiral bölüntünün yeniden üretimi — SONUÇLAR

Ön kayıt `1cff1f1`; Rater 1 mühür `04905f0` (Rater 2 okunmadan); bu dosya ondan sonra.

## Bileşim (57 commit, mekanik çerçeve, dosyada)

| | Rater 1 (bu oturum) | Rater 2 (kör model) |
|---|---|---|
| **Yes** — B'nin tükettiği alanı bozuyor → kör | **24 (%42)** | 27 (%47) |
| No-unconsumed — B'nin hiç okumadığı yer | 31 | — |
| No-examined — yüklem tarafı, B'nin kapsamı dışı | 1 | — |
| No (toplam) | 32 | 29 |
| Undecided | 1 | 1 |

**Eski bölüntü:** 23/40 kör (%58), 2/40 yüklem (%5) — yeniden üretilemedi.
**Yeni:** kör %42 (R1) / %47 (R2); bound 1/57; gerçekleşen erişim **0/57** (tek
yüklem vakası `1ad2f5838d34` pointer kolunda, B modellemiyor). Manşet ön kayıt gereği
Rater 1'in mühürlü bölüntüsüne çekiliyor: **%42 kör, %2 hedef, %0 gerçekleşen.**

## Güvenilirlik

- Ham uyum **53/57 = 0,930**, p_e = 0,485, **Cohen κ = 0,864** — Landis–Koch *almost
  perfect*. (Held-out 28'de κ = 0,714 idi; iki ölçüm de ön kayıt eşiğinin üstünde.)
- Her iki rater da **bir** Undecided verdi, farklı vakalarda.

## Dört uyumsuzluk — ve ikisinde haklı olan Rater 2

| commit | R1 | R2 | okuma |
|---|---|---|---|
| `2aaf67f0516f` | No | Undecided | R2: r0_size guard'ının koruduğu yazım diff'te görünmüyor. Savunulabilir. |
| `efc11a667878` | Undecided | Yes | R2: `___mark_reg_known` tüketilen alanları yeniden yazıyor. R1'in Undecided'ı "imprecise ≠ corrupt" ayrımı içindi. |
| `bb7f0f989ca7` | No | **Yes** | **R2 haklı.** Diff'in R1'in kesitinde olmayan bir hunk'ı `__mark_reg_unknown` zorluyor — sınır yazımı. R1 kırpılmış kesitten okudu. |
| `fce366a9dd0d` | No | **Yes** | **R2 haklı.** `dst_reg->type = PTR_TO_MAP_VALUE_ADJ` yazımını kısıtlıyor; `type` tüketiliyor. Yine R1'in kesitinin dışında. |

**Protokol asimetrisi, kayda:** Rater 1 diff'leri 16–28 satırlık kesitlerle okudu
(57 commit'i tek oturumda geçmek için); Rater 2 9000 karakter gördü. İki uyumsuzluk
doğrudan bu asimetriden. Altın ön kayıt gereği değiştirilmedi; ama doğru okuma
büyük olasılıkla Rater 2'ninki ve gerçek kör pay %42 ile %47 arasında.

## Ne değişti

- §4.2'nin "check any row" iddiası amiral bölüntü için **artık doğru**: çerçeve, iki
  rater dosyası ve gerekçeler artefakt.
- Manşet 58 → 42. Eski çerçeve elle seçilmişti ve oracle'ın yoluna doğru **daha da**
  zenginmiş; §6'nın dört-kat ölçümü bunu zaten söylüyordu.
- Yolda (Yes + No-examined) 25/57 = %44 vs filtresiz 3/20 = %15, Fisher p = 0.030.
