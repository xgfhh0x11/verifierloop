# Parti 3 — SONUÇLAR: simetri tezi test edildi ve **desteklenmedi**

Ön kayıt: `PREREGISTRATION-batch3.md`, commit `4c2e455`. Bu dosya ondan **sonra**.
Doğrulama bu sefer kaynak okuması değil, **koşum** — `.lab/build/bzImage-instr`
(= `dffc1150e2cc` + yalnız-basım `states.c` yaması) üzerinde.

## Dal: **P1 tuttu, P2 tuttu** → *"Simetri tezi bu oracle için çürüdü"*

Ön kayıttaki dört daldan ikincisi gerçekleşti.

### P1 — boş aralık bir prune çiftine girdi ✅

İlk iki şekil (`N0` yük yok, `CV` yakınsayan dal) **başarısız**: r6 prune noktasında
**ölü**, dolayısıyla `live_regs_before`'a girmiyor, karşılaştırılmıyor, basılmıyor.
Bu tesadüf değil yapısal: boş register'ı okuyan hemen her işlem
`reg_bounds_sanity_check`'i tetikleyip `__mark_reg_unbounded` ile onarıyor.

Kaçış yolu: **mağazanın kaynağı**. `check_store_reg()` kaynak register'a sanity
check uygulamıyor (yalnız `check_load_mem` hedefe uyguluyor, verifier.c:6703). Yani
`*(u32 *)(r8 +0) = r6` r6'yı **canlı tutuyor ve onarmıyor**. Üçüncü şekil (`KL`):

```
PRUNEPAIR insn=17 exact=0 side=old fr=0 r6 type=1 delta=0 var=0/2 r64=0+2 ...
PRUNEPAIR insn=17 exact=0 side=cur fr=0 r6 type=1 delta=0 var=0/2 \
          r64=ffffffffffffffff+ffffffffffffffff r32=ffffffff+ffffffff ...
```

`cur` tarafında `CNUM64_EMPTY`, ve kernel **bu çifti budadı** (satırlar yalnız
alınan prune'larda basılıyor). Dört yakalamada beş boş satır.

### P2 — model uyuşmazlık bildirmedi ✅ (öngörü tuttu)

| yakalama | boş satır | pairs | disagree | nontrivial | scalar_cmp | shortcircuited |
|---|---|---|---|---|---|---|
| `KL_keeplive` | 2 | 3 | **0** | 0 | 0 | 3 |
| `KL_keeplive_freq` | 1 | 3 | **0** | 0 | 0 | 3 |
| `MG_maygoto` | 1 | 1 | **0** | 0 | 0 | 1 |
| `MG_maygoto_freq` | 1 | 3 | **0** | 0 | 0 | 2 |

Hiçbirinde yanlış-atıflı bulgu yok. **P3'e sıra gelmedi.**

## Ve sebep, ön kayıttaki gerekçemden farklı — daha keskin

Ön kayıtta gerekçem şuydu: *"kernel'in yüklemi ile modelin transkripsiyonu aynı
değerler üzerinde koşuyor, dolayısıyla aynı cevabı verir."* Sayaçlar bunun **operatif
mekanizma olmadığını** söylüyor: `scalar_comparisons=0`, `nontrivial_pairs=0`,
`shortcircuited_regs>0`. Yani yeniden hesaplanan içerilme **hiç koşmadı**.

Kesen şey `subsume-check.py:375`:

```python
if o['prec'] == 0 and p['exact'] == 0:
    st.shortcircuit += 1; continue        # precision kısa-devresi
```

`prec` **tüketilen** bir alan. Yani:

> Kanıtsal bağımlılık iki kere iş görüyor. Tüketilen değer yalnızca yeniden
> hesaplanan yükleme **girdi olmakla** kalmıyor; tüketilen bir değer o yeniden
> hesabın **koşup koşmayacağına da karar verebiliyor.** Bu oracle'da olan ikincisi:
> bileşenin yazdığı precision bayrağı, oracle'ın kendi bağımsız aritmetiğinin
> çalışıp çalışmayacağını belirliyor. O bayrağın yukarısındaki bir kusur yanlış
> karara uğramıyor — **hiç incelenmiyor.**

## Açık kalan — ve kapatılmaya çalışıldı

Kısa-devre önce ateşlediği için, "yeniden hesaplanan kol boş bir aralıkta koşsaydı
uyuşur muydu, uyuşmaz mıydı" sorusu **cevapsız**. Kısa-devreyi açmak için
`may_goto` denendi (`is_may_goto_insn_at` kolu prune'u `exact=RANGE_WITHIN` ile
yaptırır): **başarısız** — dört yakalamanın hiçbirinde `exact=2` taşıyan çift
oluşmadı, boş register'ı taşıyan prune yine `exact=0` noktasında gerçekleşti.
Iterator veya callback şekli bir sonraki deneme olurdu; bu partide yapılmadı.

Yani ayakta duran iddia: *bu oracle, bu şekillerde, yanlış-atıflı gerçek-pozitif
üretmedi ve üretmemesinin sebebi tüketilen bir alanın kapı işlevi görmesi.*
Genel bir "yanlış atıf hiç olmaz" iddiası **değil**.

## Sayım

- Ön kayıtlı öngörü: 3 (P1, P2, P3). Tutan: 2. Sıra gelmeyen: 1. Yanlışlanan: 0.
- Doğrulama düzeyi: **koşum** (parti 1–2'nin kaynak-okuması çekincesi bu partide yok).
- Simetri tezi: **desteklenmedi.** Paper'a "doğrulandı" olarak girmiyor.
