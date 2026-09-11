# Inter-rater — SONUÇLAR

Ön kayıt: `PREREGISTRATION.md` (commit `6f3effe`). Rater 2 = taze bağlamlı model
örneği, yalnız `PACKET.md` + B'nin kaynağı; etiketlere erişimi yoktu. Çıktı `RATER2.txt`.

## Sayılar

| | Yes | No | Undecided |
|---|---|---|---|
| Rater 1 (bu oturum) | 7 | 21 | **0** |
| Rater 2 (kör) | 4 | 22 | **2** |

- Ham uyum **25/28 = 0,893**
- Şans uyumu p_e = 0,625 (7/21 dağılımı şansı yükseltiyor; κ bu yüzden bilgilendirici)
- **Cohen κ = 0,714** — Landis–Koch *substantial*. Ön kayıttaki yanlışlanma eşiği
  (κ < 0,6) **aşılmadı**; "almost perfect" bandı (≥ 0,8) da **tutulmadı**.

## Rater 2 iki kez Undecided dedi — Rater 1 sıfır

Ön kayıt bunu peşinen şöyle bağlamıştı: *"Rater 2 sıfırdan fazla Undecided verirse,
hakemin 'belirsiz demeye isteksizlik' şüphesi lehine kanıt sayılır."* Sayılıyor. Kırkta
sıfır ve yirmi sekizde sıfır Undecided vermiş olmam, kör bir okuyucunun aynı
diff'lerde ikisinde durmasıyla yan yana konunca, §6'nın tehdidi artık ölçülü bir
gözlem.

## Üç uyumsuzluk — ikisi de gerekçesiyle, sessiz çözüm yok

| commit | R1 | R2 | R2'nin gerekçesi | okuma |
|---|---|---|---|---|
| `2658a1720a19` (H22) | Yes | **Undecided** | `collect_linked_regs` linked_regs'e giren register'ları filtreliyor; `id`'nin nasıl bozulduğu diff'ten belirsiz | R1'in Yes'i, id yazımının B'ye tüketildiği çıkarımına dayanıyordu; diff bunu **söylemiyor**, R1 biliyordu. Undecided savunulabilir. |
| `3a354149bcea` (H24) | Yes | **No** | `__clean_func_state` bir stack slotunun `spilled_ptr`/`slot_type`'ını bozuyor, **B stack slotlarını tüketmiyor** | **R2 haklı, harfi harfine.** §3.3'ün sorusu "B'nin tüketim kümesindeki bir artefaktı bozuyor mu" — stack slotu tüketim kümesinde DEĞİL, cevap No. R1 "iki kez kör" deyip Yes yazmıştı; körlük konusunda ikisi hemfikir, **kova** konusunda değil. |
| `713274f1f2c8` (H28) | Yes | **Undecided** | `check_stack_write_fixed_off` bir stack slotunun `spilled_ptr.id`'sini sıfırlıyor (modellenmemiş) | Aynı seam: yazılan alan bir **stack slotu**, B onu okumuyor. |

**Üçü de aynı dikişte:** stack slotuna yazılan bir alan. B stack slotlarını hiç
tüketmiyor (yakalama basmıyor). Böyle bir hata B'ye **kör**dür — ama §3.3'ün üçlemesinde
bu körlük "Yes" (tüketilen bozuldu) değil **"No"**'dur (tüketilmiyor), ve "No"nun
"potansiyel olarak görünür" okuması burada yanlış çıkar. H23 aynı seamı diğer taraftan
açmıştı (yolda ama modellenmemiş). Yani uyumsuzluklar rater gürültüsünden çok
**sorunun kendi zayıf noktasını** gösteriyor: "tüketilmiyor" iki farklı şeyi kapsıyor —
oracle'ın hiç bakmadığı bir alan ve oracle'ın modellemediği bir kol — ve ikisi de kör.

Altın değiştirilmedi (ön kayıt). Ama düzeltilecek şey altın değil, **soru**: §3.3'ün
"No" cevabı ikiye ayrılmalı ya da "blind because unconsumed" ayrıca adlandırılmalı.

## Sınırlar

- Rater 2 insan değil. Ölçülen şey: *aynı soruyu aynı kaynaktan okuyan bağımsız bir
  okuyucu aynı cevabı verir mi.* İnsan hakem uyumu değil.
- n=28, ve amiral 40 yeniden puanlanamadı (liste saklanmamış).
- Rater 1'in "Yes" sınıfı 7 vakayla küçük; üç uyumsuzluğun üçü de o sınıfta, yani
  Yes-sınıfı uyumu 4/7.
