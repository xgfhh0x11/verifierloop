# Amiral bölüntünün YENİDEN ÜRETİMİ — ÖN KAYIT (sınıflandırmadan ÖNCE mühürlendi)

## Neden

Hakem itirazı A: paper'ın manşet sayısı (58%/5%) 40 commit'lik bir bölüntüden geliyor
ve o bölüntünün **listesi artefakt olarak tutulmamış**. Kurtarma denendi ve olmadı:
0102'nin ölçütü ("gövdesinde verifier durumu alıntılayan") bir yargıydı, regex değil —
en yakın mekanik proxy 68 veriyor, 50 değil; eski oturum scratchpad'lerinde ve .lab'da
fan-out artefaktı yok; devlog'da 9 SHA adlı. **Liste kayıp.** Bu yüzden wording ile
yönetmek yerine bölüntü baştan, denetlenebilir biçimde üretiliyor.

## Çerçeve — bu sefer mekanik ve dosyada

`git log --grep=^Fixes:` (5e289c5a4a52'ye kadar, altı durum-eşdeğerliği dosyası) →
437; gövdesi şu regex'le verifier durumu alıntılayan → **68**:
`R[0-9]+(_w)?=|var_off|smin_value|umax_value|umin_value|smax_value|tnum\(|scalar\(|u32_m(in|ax)`
eksi 16 kalibrasyon çifti, eksi 28 held-out (zaten sınıflandırıldı) → **ÇERÇEVE = 57**
(`frame.txt`, `frame-subjects.txt`). Bu küme orijinal 40 ile **aynı değil** ve öyle
sunulmayacak; aynı *tür* çerçeve, bu sefer yeniden üretilebilir.

## Tasarım — iki rater, ikisi de sınıflandırmadan önce mühürlü protokolle

- **Rater 1** (bu oturum): §3.3'ün sorusu, yalnız diff'ten, dosya:fonksiyon çapasıyla,
  DÜZELTİLMİŞ üçlemeyle (Yes / No-unconsumed / No-examined / Undecided — §3.3'ün
  yeni "No" ayrımı). Sonuç `RATER1.txt`, rater 2 okunmadan commit edilir.
- **Rater 2** (kör model örneği): `PACKET.md` (held-out paketiyle aynı soru ve tüketim
  kümesi tanımı) — `docs/heldout/` okuması yasak. Sonuç `RATER2.txt`.
- Rater 1 ve 2 **eşzamanlı** koşar; hiçbiri diğerini görmez. Sıra git'ten denetlenir.

## Rapor edilecekler

1. Yeni bölüntünün bileşimi (Yes / No / Undecided, ve No'nun iki alt türü).
2. κ (Rater 1 × Rater 2), üçlemede; her uyumsuzluk iki gerekçesiyle.
3. **Eski 23/2/15 ile karşılaştırma** — yalnız toplam düzeyinde, çünkü eski liste yok.
   Yeni kör pay eskiye yakınsa manşet ayakta ve artık denetlenebilir; uzaksa manşet
   YENİ sayıya çekilir ve eski sayı "kurtarılamayan ilk deneme" olarak raporlanır.
4. Rater 1'in Undecided sayısı ayrıca — sıfır çıkarsa §6'nın şüphesi yine geçerli.

## Manşetin kaderi — önceden

Paper'ın 58%/5%'i **bu bölüntünün** sonucuyla değiştirilecek, hangi yöne giderse gitsin.
Eski bölüntü Appendix'te "yeniden üretilemedi" notuyla anılacak.
