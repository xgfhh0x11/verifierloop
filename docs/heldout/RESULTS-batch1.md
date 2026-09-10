# Held-out parti 1 — SONUÇLAR

Ön kayıt: `PREREGISTRATION.md`, commit `58967bf`. Bu dosya o commit'ten **sonra** yazıldı.

## 1. H1–H9 (ALAKASIZ öngörüleri): 9/9 tuttu

Öngörü: dokunulan fonksiyonların/alanların hiçbiri oracle B'nin kaynağında
(`scripts/subsume-check.py`, `harness/bpfsubs.h`) modellenmiş olmayacak.

| aranan | B'de geçiş |
|---|---|
| `btf_id_allow_sleepable`, `convert_ctx_accesses`, `jit_subprogs`, `record_func_key`, `check_kfunc_args`, `check_stack_read`, `save_aux_ptr_type`, `merge_ptr_types` | 0 |
| `insn_aux_data`, `subprogno`, `ptr_type` | 0 |

Dokuzunun dokuzu.

## 2. H10 (`0acd03a5bd18`) — asıl test

Öngörü: **B bunu göremez**, çünkü `prepare_func_exit()` `precise` ve `live`
yazıyor ve bu iki alan B'nin ham TÜKETTİĞİ girdiler.

Kaynakta bulunan:

```python
# subsume-check.py:375  — precision kısa-devresi
if o['prec'] == 0 and p['exact'] == 0:
    st.shortcircuit += 1; continue

# subsume-check.py:307  — canlılık kapısı
if o['era'] == '2021' and not o['live']:
    st.live_gated += 1; continue
```

`o['prec']` ve `o['live']`'ın ikisi de **kernel'in kendi yakalamasından** geliyor
(`PRUNEPAIR ... prec=(\d+) live=(\d+)`, satır 165 / 213 / 219 / 221). Kernel
precision'ı işaretlemeyi atlarsa yakalama `prec=0` der, model de `prec=0` okur ve
**aynı** kısa-devreyi alır. Aynısı `live` için. **Öngörü tuttu.**

### Ve neredeyse ters yönde hata yapıyordum

`live_bit()` (satır 264) `bpflive.h`'in **bağımsız yeniden hesabını** okuyor —
`LIVENESS status=ok mask=` satırı, `bpflive_run(ins, n, &out)`, girdisi komut akışı.
Bir an bunu kapı sandım ve kendi öngörümü yanlışlanmış ilan edecektim. Ama
`live_bit`'in dönüşü yalnız **sayaçlara** gidiyor (`live_cmps`, `dead_reg_cmps`,
`saw_tracked_reg`, satır 298–304); hiçbir şeyi kapatmıyor. Docstring bunu zaten
söylüyordu: *"model canlılık kapısını UYGULAMAZ, ama uygulamadığının BEDELİNİ
sayabilsin diye."*

Bu, paper'ın tezinin tam ortasındaki ayrım: **bağımsız bir yeniden hesap mevcut
olabilir ve yine de hükme bağlanmamış olabilir.** Kanıtsal bağımsızlık, girdinin
bağımsızlığı değil, **hükme giden girdinin** bağımsızlığı.

### Ön kaydın yanlışlanma koşulu KÖTÜ YAZILMIŞTI — kayda geçiyor

Yazdığım koşul: *"`precise`/`live` B'de modellenmiş bir yüklem koluysa öngörü
düşer."* İkisi de modellenmiş kollar (kısa-devre ve kapı), ama **kernel'in
değerlerini tüketerek**. Yani koşul harfi harfine okunursa H10 yanlışlanmış sayılır;
esasa göre okunursa tutmuş sayılır.

Ayrımı doğru yapan ölçüt paper'ın kendi ölçütü: **yeniden-hesaplıyor mu, tüketiyor
mu.** H10'u o ölçütle "tuttu" sayıyorum ve bunu burada ilan ediyorum — ama daha katı
bir hakem H10'u *belirsiz* sayabilir, ve o okuma savunulabilir. Parti 2'nin
yanlışlanma koşulu bu yüzden **"B bu alanı bağımsız olarak yeniden hesaplayıp hükme
bağlıyorsa öngörü düşer"** biçiminde yazılacak.

## 3. Bileşim — §6'nın birinci tehdidine doğrudan ölçüm

| çerçeve | ALAKASIZ | durum-eşdeğerliği yolunda |
|---|---|---|
| orijinal (mesajı durum alıntılayan), n=40 | 15 (%37,5) | 25 (%62,5) |
| held-out (o ölçütün tümleyeni), n=10 | **9 (%90)** | 1 (%10) |

Fisher kesin testi, iki yönlü: **p = 0,0040**.

Yani §6'nın "çerçeve yanlı ve yönünü biliyoruz" cümlesi artık bir sayı taşıyor:
mesajı verifier durumu alıntılayan fix'leri seçmek, durum-eşdeğerliği yolundaki
hataları **belirgin biçimde fazla temsil ediyor**. Sonucu: §5.3'ün %58 kör / %5
hedef rakamları **o çerçeveye koşullu**. Filtrelenmemiş bir çerçevede oracle B'nin
hem kör payı hem hedef payı düşer.

Bu bir sonuç, bağımsız testin parçası değil — ön kayıt böyle diyordu.

## 4. Sayım

- **Held-out vaka: 1 → 11.** (10 yeni + §4.1'in mevcut biri.)
- Bunların **kör sınırını** test edeni: 1 (H10). Dokuzu ALAKASIZ kolunu test ediyor.
- Yanlışlanan öngörü: 0. Belirsiz sayılabilecek: 1 (H10, yukarıdaki gerekçeyle).

Kör sınırını daha çok test etmek için parti 2 gerekiyor: aynı kural,
`sort frame.txt | sed -n '11,20p'`.
