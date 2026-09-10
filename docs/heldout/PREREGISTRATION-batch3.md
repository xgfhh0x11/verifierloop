# Parti 3 — ÖN KAYIT: yanlış-atıflı gerçek-pozitif var mı?

**Mühür tarihi:** 2026-09-10. Bu dosya **hiçbir koşumdan önce** commit edildi.
Sonuçlar ayrı commit'te (`RESULTS-batch3.md`). Parti 1–2'den farkı: doğrulama
kaynak okuması değil, **koşum**.

## 1. Test edilen tez

Reviewer'ın önerdiği simetri: kanıtsal bağımlılık yalnız kör nokta üretmez, aynı
zamanda **yanlış-atıflı gerçek-pozitif** üretir — oracle bazı alanları tüketir,
bazılarını yeniden hesaplar; çeliştiklerinde gerçek bir uyuşmazlık bildirir ama
suçu yanlış yere yazar.

## 2. Mekanizmadan türetilen öngörü — ve HEYECANLI OLANIN TERSİ

Model B `range_within`'i **yeniden hesaplıyor**, ama girdisi kernel'in kendi
yakalaması (`PRUNEPAIR ... r64=base+size`). Yani kernel'in yüklemi ile modelin
transkripsiyonu **aynı değerler üzerinde** koşuyor. Yukarı akıştan gelen bozuk bir
değer (F2'nin boş aralığı) ikisine de aynı şekilde giriyor.

Dolayısıyla mekanik beklenti: **model SUSAR.** Yanlış atıf için modelin, kernel'in
kullanmadığı **başka bir girdiden** yeniden hesap yapması gerekir — ki bu tam olarak
eksenin söylediği şey.

Bu öngörü kasten heyecanlı sonucun tersi: susarsa reviewer'ın simetri tezi **bu
oracle için çürür**; konuşursa tez **doğrulanır** ve paper'a en yüksek güçte girer.

## 3. Yanlışlanabilir üç önerme

**P1 (ön koşul).** F2 şekilli bir programın enstrümanlı kernel'deki yakalamasında,
`r64=ffffffffffffffff+ffffffffffffffff` veya `r32=ffffffff+ffffffff` taşıyan
**en az bir `PRUNEPAIR` satırı** bulunacak. (`CNUM64_EMPTY` = `{base=U64_MAX,
size=U64_MAX}`; enstrümantasyon `base+size`'ı ham basıyor, projeksiyon değil.)

**P2 (asıl önerme).** P1 sağlanırsa, `subsume-check.py` o çift için **uyuşmazlık
bildirmeyecek** (`disagree=0` o çiftte; `agree` ya da `unmodelled`).

**P3 (P2 düşerse).** Model uyuşmazlık bildirirse, bildirilen kol
(`p['arm']`) `range_within`/tnum ailesinden olacak — yani model **yüklemi** suçlarken
gerçek kusur yukarıda, `sync_linked_regs`'te.

## 4. Sonuç tablosu — üç dal, üçü de önceden adlandırıldı

| gözlem | okuma |
|---|---|
| **P1 düşer** (yakalamada boş aralık yok) | **SONUÇSUZ.** Boş durum prune noktasına taşınamadı. Tezin lehine ya da aleyhine kanıt değil; ne gerektiği yazılacak. Falsifikasyon diye sunulmayacak. |
| P1 tutar, **P2 tutar** (model susar) | **Simetri tezi bu oracle için ÇÜRÜDÜ.** Tam-tüketen bir oracle körlük üretir, yanlış atıf üretmez; yanlış atıf için bağımsız girdiden yeniden hesap gerekir. Paper'a bu biçimde girer. |
| P1 tutar, **P2 düşer**, P3 tutar | **Simetri tezi DOĞRULANDI**, koşumla. Paper'a en yüksek güçte girer. |
| P1 tutar, P2 düşer, **P3 de düşer** | Uyuşmazlık var ama kol beklenen yerde değil. Kısmi; gerçek kol rapor edilecek, yorum ona göre yazılacak. |

## 5. Protokol

1. `harness/f2probe.c`'ye iki şey eklenecek: (a) seçilen programın **tam verifier
   logunu** basma, (b) boş aralığın onarılmadan bir prune noktasına ulaşmasını
   hedefleyen varyantlar — `N0` (yük yok) ve yakınsayan bir dal eklenmiş hâli.
   Yüklemeler `BPF_F_TEST_STATE_FREQ` ile de yapılacak (her komut checkpoint →
   prune denemesi maksimum).
2. Koşum `.lab/build/bzImage-instr` üzerinde (`bpf-instr` = `dffc1150e2cc` +
   yalnız-basım `states.c` yaması; yama verifier mantığını değiştirmiyor).
3. Çıkan log `scripts/subsume-check.py`'ye verilecek.
4. Rapor: P1/P2/P3'ün her biri ayrı ayrı, ve yukarıdaki tablodaki dal adıyla.

## 6. Peşinen kabul edilen sınırlar

- Tek oracle (B), tek sistem. "Yanlış atıf hiç olmaz" değil, "bu oracle'da bu
  şekilde olmaz/olur" ölçülüyor.
- P1'in sağlanması programın şekline bağlı ve garanti değil; sonuçsuz dal gerçek
  bir olasılık, ve bu yüzden önceden adlandırıldı.
