# Parti 3 — SONUÇLAR: simetri **yapısal olarak icra edilemedi**, ve sebebi bulgunun kendisi

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

## Kapı ONTOLOJİK, incidental değil — kaynaktan doğrulandı

Kritik soru: 375. satırın kısa-devresi script'imin optimizasyonu mu, yoksa sadık her
modelin yapmak zorunda olduğu bir şey mi? **Kernel'in aynası, yani ontolojik:**

```
kernel bugün (tip)   kernel/bpf/states.c:548   if (!rold->precise && exact == NOT_EXACT) return true;
kernel dffc1150e2cc  kernel/bpf/states.c:551   if (!rold->precise && exact == NOT_EXACT) return true;
kernel 2019-12       kernel/bpf/verifier.c:7096 if (!rold->precise && !rcur->precise)     return true;
model                scripts/subsume-check.py:375  if o['prec'] == 0 and p['exact'] == 0: continue
```

Kernel `prec`'te kapı yaptığı için model de yapmak zorunda. Kapı **ilkeye ait, bu
oracle'a değil**.

## Ve bu kapı zaten haritada — iki bağımsız yol aynı yere iniyor

`f54c7898ed1c` (2019-12, "Fix precision tracking for unbounded scalars") bu oracle'a
tam bu kapı yüzünden görünmez: checkpoint'te old R1 sabit, cur R1 tamamen bilinmeyen,
**ikisi de imprecise** → kısa-devre ateşler → durum budanır → yürünmeyen dal
`goto pc-1`'e yeniden yazılır → program **askıda kalır**. Bu, kanal doğrulamasıyla
2026-09-08'de elle düşürülmüştü (kaynak düzeyinde, kernel kurulmadan).

Yani parti 3 yeni bir gözlem değil: **belgelenmiş bir yapısal körlüğün mekanizmasının
koşum-doğrulaması**, ve ona simetri sondajından, bağımsız bir yoldan varıldı.

## Sayım ve doğru çerçeve

- Ön kayıtlı önerme: 3 (P1, P2, P3). Tutan: 2. Sıra gelmeyen: 1. Yanlışlanan: 0.
- Doğrulama düzeyi: **koşum** (parti 1–2'nin kaynak-okuması çekincesi bu partide yok).

**Çerçeve dikkatli kurulmalı.** "Test edildi ve desteklenmedi" düz hâliyle yanıltıcı,
çünkü yeniden hesap **hiç koşmadı** (`scalar_comparisons=0`) — simetriye şans
verilmedi, yolu kapalıydı. Doğrusu: ön kayıtlı simetri örneklemesi koştu; yeniden
hesap **tüketilen bir alanla kapatıldı**; `may_goto` ile boş-register'lı `exact=2`
çifti zorlanamadı; dolayısıyla **simetri yapısal olarak icra edilemedi, ve neden
edilemediğinin koşum-doğrulanmış cevabı elimizde.**
