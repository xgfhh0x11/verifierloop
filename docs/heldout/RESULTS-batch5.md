# Parti 5 — H21 çifti KURULDU ve KOŞTU: görünür kol iki kanalda da doğrulandı

Hakem itirazı 3: *"9 pair build edebilmişsin — tek görünür held-out case'i neden build
etmedin?"* Haklıydı; bir tur önce "marjinal" diye karşı çıkmıştım ve yanılmışım —
mesele bilgi değil, güvenilirlikti. Kuruldu.

## Kurulum

- `1ffc85d9298e~1` (`dec020280373`, buggy) ve `1ffc85d9298e` (fixed), 2023-06-13.
- Config **byte-özdeş** (md5 tek). Yakalama yaması: üç dönem varyantının hiçbiri
  uymadı; **dördüncü** yazıldı (`patches/prunepair-instrumentation-2023.patch`, 2021
  bloğunun `hit:` etiketine portu — aynı basım biçimi, alanlar aynı).
- Tetikleyici: **commit mesajının kendi örneği, birebir** (`f2probe.c: dump_h21`).
  §3.5'in cümlesi: en ucuz kalibrasyon commit'in zaten yaptığıdır.

## Kernel kanalı — kalibre

| | base | `BPF_F_TEST_STATE_FREQ` |
|---|---|---|
| buggy | reject 22 | **accept** |
| fixed | reject 22 | **reject 22** |

`STATE_FREQ` girdinin parçası, dedektörün değil (0103'ün dersi): bayraksız
sezgisel checkpoint'i kurmuyor, yol II yol I'e budanamıyor, hata ortaya çıkmıyor.

## Model kanalı — ilk koşum SESSİZ, ve sebebi bulgunun kendisi

İlk koşumda B buggy yakalamada **ateşlemedi**: `disagree=0, id_checks=0`. Oysa kritik
çift yakalanmıştı, commit örneğiyle birebir:

```
PRUNEPAIR insn=14 side=old r6 ... id=3 prec=1 live=1      (yol I:  r6.id=b)
PRUNEPAIR insn=14 side=old r7 ... id=3 prec=1 live=1      (        r7.id=b)
PRUNEPAIR insn=14 side=cur r6 ... id=2                    (yol II: r6.id=a)
PRUNEPAIR insn=14 side=cur r7 ... id=3                    (        r7.id=b)
```

Sebep, `subsume-check.py`'de:

```python
if o['era'] == '2021':   # live= tasiyan HER satir -> 2021 kolu
    # ... id/delta/ADD_CONST kollari henuz YOK: sadece range_within && tnum_in
```

`live=` alanı modelin dönem işaretiydi; 2023-06 da `live=` basıyor. Model 2023
yakalamasını 2021 koluna yolladı, ve o kolda `check_scalar_ids` **tasarım gereği yok** —
2021 kernel'inde de yoktu. **Aynı basım biçimi iki farklı yüklem taşıyor; biçim dönemi
belirleyemiyor.** Kaynak-düzeyi doğrulama "kol uygulanmış" demişti: cnum yolu için
doğru, bu yakalamanın gittiği yol için yanlış. Koşum bunu buldu; okuma bulamazdı.

Düzeltme çıkarım değil, açık bildirim: `--era 2023` bayrağı. 2023 kolu = tek taraflı
precision kısa-devresi, `REG_LIVE_READ` kapısı, `check_scalar_ids`, sonra
`range_within && tnum_in` — düzeltilmiş kernel'in yüklemi.

## İkinci koşum

| | `--era 2023` | `--era 2021` (kontrol) |
|---|---|---|
| buggy | **`candidate insn=14 arm=check_scalar_ids`, disagree=1** | disagree=0 (sessiz) |
| fixed | disagree=0, ve **prune olayının kendisi yok** (3 çift → 1) | — |

Tam olarak öngörülen kol, tam olarak commit'in çifti, düzeltilmişte sessiz.
`2f2ec8e7730e`'nin bire bir aynı imzası (o da `arm=check_scalar_ids`, o da fixed'de
prune yok oluyor) — iki ayrı hata, aynı kol, aynı davranış.

## Sıra dürüstçe

1. Held-out sınıflandırma: GÖRÜNÜR (`bd10090`, mühürlü).
2. Kaynak-düzeyi doğrulama: tuttu.
3. Koşum #1: **sessiz** — kaynak okumanın göremediği bir model sınırı.
4. Model düzeltmesi (`--era 2023`), koşumdan SONRA, gerekçesi yazılı.
5. Koşum #2: ateşledi; fixed sessiz; kontrol sessiz.

Adım 4 koşumdan sonra geldi; bu yüzden H21 **held-out onay** olarak değil, **kurulmuş
onaltıncı kalibrasyon çifti** olarak sayılıyor, ve held-out kaydına "kaynak düzeyinde
tuttu; koşumda önce model sınırına çarptı, sınır düzeltildi, sonra tuttu" diye giriyor.

## Açık

- C ikizi (`bpfsubs.h`) 2023 kolunu bilmiyor; 2023 yakalaması Rust parite testine
  fixture olarak eklenmedi. Eklenecekse önce C'ye kol gerekir.
