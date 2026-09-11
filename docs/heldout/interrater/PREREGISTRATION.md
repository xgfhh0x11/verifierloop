# Inter-rater ÖN KAYIT — koşumdan ÖNCE mühürlendi

Hakem itirazı 6: *"partition 'with assistance' üretilmiş, bir kez audit edilmiş, 40'ta
sıfır undecided… çıktısı sınıflandırma olan bir yöntemde reproducibility'yi ölçmemek,
katkının kalbini boş bırakmak."* Doğru. Bu, §4.5'in "en küçük deney" dediği şey.

## Örneklem — ve neden 40 değil

**28 held-out commit** (`draw.txt` + `draw2.txt` + `draw4.txt`). Amiral 40'lık
bölüntü **yeniden puanlanamıyor**, çünkü commit listesi kayıt altına alınmamış —
yalnız toplam sayılar ve devlog 0102'de adı geçen birkaç SHA var. Bu, §4.2'nin
"check any row of it" iddiasına karşı bir eksik ve paper'da söylenmeli.

## Rater 2

Bağımsız bir model örneği (taze bağlam), yalnız `PACKET.md`'yi okuyor: §3.3'ün sorusu,
B'nin tüketim kümesinin olgusal tanımı, 28 diff. **Etiketlere erişimi yok**
(`docs/heldout/` dışı bırakıldı ve okuması yasaklandı). Rater 1 = bu oturumdaki
sınıflandırıcı. **Rater 2 bir insan değil**; bu, deneyin ölçtüğü şeyi daraltır —
"aynı soruyu aynı kaynaktan okuyan bağımsız bir okuyucu aynı cevabı verir mi", insan
hakem uyumu değil. Paper'a bu sınırla girer.

## Karşılaştırma düzeyi

§3.3'ün **üçlemesi**: Yes / No / Undecided. Rater 1'in etiketleri eşlenir:
DURUM → Yes; GÖRÜNÜR, YÜKLEM-görünmez, MODELLENMEMİŞ, ALAKASIZ → No.
Altın: **7 Yes, 21 No, 0 Undecided.**

## Metrik ve önceden söylenen beklenti

- Ham uyum ve **Cohen κ** (3 sınıf). 7/21 dağılımında şans uyumu yüksek; κ ham
  uyumdan daha bilgilendirici.
- Her uyumsuzluk **iki gerekçesiyle** rapor edilir; sessiz çözüm yok, altın
  değiştirilmez.
- Rater 2'nin **Undecided sayısı** ayrı rapor edilir. Rater 1 sıfır verdi; Rater 2
  sıfırdan fazla verirse bu, hakemin "belirsiz demeye isteksizlik" şüphesi lehine
  kanıt sayılır ve öyle yazılır.
- Eşik yok (eşik oyuna davet). Landis–Koch bandı raporlanır.

## Yanlışlanma

κ < 0,6 çıkarsa §4.2'nin denetlenebilirlik iddiası **zayıflatılır**, "check any row"
"rows disagree at rate X" ile değiştirilir. κ ≥ 0,8 çıkarsa paper bunu, sınırıyla
(model rater), §4.5'e yazar.
