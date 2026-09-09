# Hunt devam belgesi — yeni bir session için

> **Bu belgeyi okuyan session'ın önceki bağlamı yok.** Burada yazan her şey kendi kendine
> yeter. Devlog (`docs/devlog/devlog.md`, 112 bacak) hikâyeyi anlatır, bu belge **ne
> yapılacağını ve ne YAPILMAYACAĞINI** anlatır.
>
> Tarih: 2026-09-10 · HEAD `a6fb835` · 392 test yeşil · kernel bulgusu: **0**

---

## 0. Bu session ne için, ne için DEĞİL

Proje bitmedi ama **odağı değişti**. Ana çıktı artık bulunmayan bug değil, ölçülmüş
**kör nokta haritası** (bkz. §3) ve ondan çıkan metodoloji tezi. Hunt devam ediyor, ama
yalnız bir türü:

| | yap | yapma |
|---|---|---|
| **1. tür** — GÖRÜLEN sınıfta yeni yüzey taramak | ✅ bu session'ın işi | |
| **2. tür** — KÖR olunan sınıfa yeni oracle yazmak | | ❌ paper bitene kadar |

**Neden bu ayrım.** Ölçüm diyor ki: gördüğümüz sınıf (yüklem hataları, tek-durum
tutarlılığı) zaten syzbot'un ve kernel'in kendi assertion'larının en çok dövdüğü yer; kör
olduğumuz sınıf (değer izleme — tutarlı ama yanlış, tarihsel hataların **%58**'i) otomatik
yaklaşımlara **yapısal olarak** kör ve insan kod-okumasıyla bulunuyor.

1. tür **kaynak-ucuz**: enstrüman kurulu, arka planda döner, kimsenin mesaisini yemez.
Sonuç ne olursa olsun kazanç — bug çıkarsa haritayla bulunmuş bir bug, çıkmazsa haritada
bir hücre daha dolar ve negatif sonuç sağlamlaşır.

2. tür **kaynak-pahalı** ve haritanın "buraya harcama" dediği yer. Yeni oracle = yeni model
+ yeni kalibrasyon + (bu projede ölçüldü) sekiz atıf/tazelik hatası. Paper bittikten sonra,
*ayrı bir araştırma sorusu* olarak ele alınabilir ("bu sınıf otomatik yakalanabilir mi?"),
mevcut enstrümanın devamı olarak değil.

> **Ve niyet kontrolü, açıkça.** Bu hunt "arka planda dönsün, düşük ihtimalli bonusu
> kaçırmayayım" enerjisiyle koşulmalı. "Belki bulurum ve kendimi kanıtlarım" enerjisiyle
> koşulursa, haritanın verdiği dürüst dersi inkâr etmiş oluruz. Harita "bu yüzey temiz,
> körlüğün ortak körlük" dedi; hunt onu çürütmek için değil, tamamlamak için.

---

## 1. Nasıl koşulur (kopyala-yapıştır)

```bash
# Uzun tur — enstrümanlı tip kernel (budama/subsumption oracle'ları bunu gerektirir)
KERNEL=$PWD/.lab/build/bzImage-instr SECONDS_BUDGET=3600 \
  scripts/run-fuzz.sh $PWD/.lab/fuzz-hunt-NN.log

# Sonuç satırı
grep "FUZZ done" .lab/fuzz-hunt-NN.log | tr ' ' '\n' | grep -E "^iters=|^findings=|^subs|^store|^live|^trunc="
```

`run-fuzz.sh` referans interpreter'ı önce kalibre eder ve geçmezse **durur** — kalibre
olmamış bir enstrüman her programı olası yanlış bulguya çevirir. Zaman aşımı payı bütçeyle
orantılı (%20 + 180s); bir saatlik tur bir kez bu yüzden kaybedilmişti.

**Beklenen büyüklükler** (1 saat, enstrümanlı, hunt-08/09'dan):
`iters≈2.0-2.3M · subspairs≈350-500k · subsnontrivial≈130-200k · livecells≈35-39M · trunc=0`

---

## 2. 1. tür hunt: ne taranacak

Erişim **doygun** ve bu dört noktayla ölçüldü — daha uzun koşmak kapsama getirmiyor
(bütçeyi iki katına çıkarmak +3 PC getirdi). Erişimin tek para birimi **gramer**.

| tur | süre | iters | seen_pcs |
|---|---|---|---|
| hunt-05 | 1801s | 1.110.297 | 6259 |
| hunt-07 | 1801s | 1.174.881 | 6199 |
| hunt-08 | 3601s | 2.277.364 | 6262 |
| hunt-09 | 3600s | 1.979.546 | 6319 |

**Ulaşılmayan temalar, puan sayısıyla** (`scripts/coverage-fraction.py`):

```
log + disasm printing      362   (oracle'ımız yok, verifier mantığı değil)
reference / spin lock      241   ← en büyük gerçek hedef
kfunc / BTF calls          211   ← 0095'te başlandı, referans interpreter orada SESSİZ
attach target/trampoline   163
callbacks / subprogs       160
dynptr / iterator           94
packet pointers             89
```

**Uyarı, ve ölçülmüş:** kfunc yüzeyini büyütmek `P(ulaş)`'ı büyütür ama `P(gör)`'ü
büyütmez — referans interpreter kfunc'larda hiçbir şey söylemiyor. Yani oraya şekil eklemek
kapsama sayısını yükseltir, bulgu olasılığını yükseltmez. Bunu bilerek yap.

**Gramere şekil eklemek:** `harness/diffharness.c` → `gi_emit_body()`, gen listesi `GI_*`
(store, stackvar, atomic, movsx, diamond, loop, iter, sdiv, link, delta, ...). Yeni gen
eklerken kompozisyon korpusunun **dört sağlık ölçütü** korunmalı (devlog 0069):
yapısal red 0 kalmalı · her parça yürüyüşten erişilebilir olmalı · her eksen sayacı
gerçekten sıfırdan büyük olmalı · kombinasyon kapsaması ORAN olarak gerilememeli.

---

## 3. Harita — sıfırın okunabilmesi için gereken

Tam hâli: `https://claude.ai/code/artifact/881707b8-fb9b-430a-9f68-d80b6f13fcb5`

**Görülen sınıflar** (kalibre pozitif, gerçek kernel commit'iyle):

| sınıf | oracle | çift |
|---|---|---|
| değer izleme — iç-tutarsız | Ω parsed-state | `3844d153a41a` `049c4e13714e` `ae67b9fb8c4e` `3cf2b61eb067` |
| değer izleme — tutarlı ama yanlış | store-location | `3878ae04e9fc` |
| yüklem — skaler kol | subsumption | `2f2ec8e7730e` `fd675184fc7a` `cd5b460ed1ec` |
| canlılık / CFG | canlılık kapısı | `3157f7e29996` |
| verdict bozulması | REG_INVARIANTS | `92424801261d` |

**Kör olunan sınıflar** (ölçülmüş sınır, sebebiyle):

| sebep | çift |
|---|---|
| sınıf enstrümanın dışında (aşırı-yaklaşım = aşırı-red) | `af9e89d8dd39` |
| referansın kendi doğruluk kaynağı hatayla aynı fikirde | `811c363645b3` |
| yön muhafazakâr — oracle susmak zorunda | `871ef8d50e7c` |
| dedektörün kendi bayrağı koşulu yaratamıyor | `2f2ec8e7730e` (budama farkı için) |
| gözlem öldürücü olaydan sağ çıkmayı gerektiriyor | `bc308be380c1` |
| **oracle hatanın bozduğu alanı okuyor** | `f54c7898ed1c` |

Sonuncusu paper'ın tezi: *bir model ancak girdisi kadar bağımsızdır.*

---

## 4. Bir "FINDING" çıkarsa — triyaj, pazarlıksız

Bu projede yedi kez üst üste "bulgu" göründü ve **yedisi de bizimdi**. Sıra:

1. **Genomu kaydet ve yeniden üret.**
   ```bash
   KERNEL=... HARNESS_ARGS="--fuzz-replay \"genes=N hi=H:...\"" TIMEOUT=300 \
     scripts/run-harness-vm.sh .lab/replay.log
   ```
   Genom **boşluk içerir**; `HARNESS_ARGS` misafirde tırnaksız açıldığı için tırnağı
   yukarıdaki gibi içeri gömmek şart, yoksa `bad_genome` alırsın.
2. **Dört bilinen yanlış-uyuşmazlık kaynağını aynı çıktıdan ele:** `dead_reg_cmps`,
   `ptr_id_pairs`, `subsunsup`/`storenoclaim`, ve tazelik (aşağı bak).
3. **Elle yeniden türet** — logdaki satırdan, iddiayı ve gözlemi kendin hesapla.
4. **Yamalı kernel'de hiçbir bulgu bırakılmaz.** `bzImage-instr` bir *oracle*, hüküm değil;
   orada çıkan her şey **stok kernel'de** yeniden türetilmek zorunda.

**Tazelik tuzağı, ölçülmüş:** pahalı oracle'lar `fresh > 0 || (iters & 7) == 0` kapısına
biner, yani `g_log` sekizde yedi iterasyonda bir ÖNCEKİ programın logudur. Log okuyan her
yeni kod bu kapıya bağlanmalı (`log_is_current`), yoksa "bu programın olayı + o programın
iddiası" diye çiftler ve sahte bulgu üretir.

---

## 5. Turdan sonra ne yazılır

- `docs/devlog/devlog.md`'ye bir bacak: ne koşuldu, **hangi paydaya karşı**, ne çıkmadı.
  Payda yoksa sonuç yok — "0 uyuşmazlık" ile "0/283.361 uyuşmazlık" farklı cümlelerdir.
- Harita hücresi: yeni yüzey tarandıysa hangi sınıf/oracle kesişimi doldu.
- Yeni gen eklendiyse dört sağlık ölçütünün ölçümü.

---

## 6. Dokunulmayacaklar

- **Kör sınıfa yeni oracle** — §0.
- **Kalibrasyon çiftlerinin fixture'ları** (`crates/pipeline/tests/fixtures/volume/`) —
  bunlar gerçek kernel yakalamaları, yeniden üretmek kernel derlemesi ister.
- **`patches/` sözleşmesi** — bir yama ancak stok ve yamalı kernel aynı korpusta byte-byte
  aynı verdict dizisini verirse kullanılabilir, ve bu her değişiklikte yeniden kanıtlanır.

---

## 7. Açık kalan tek yarım iş

`store-location` örnekleyicisi çalışıyor ve pipeline hüküm veriyor (21/21 blok tutarlı,
`desync=0`), ama **payda küçük**: 180 saniyede 21 blok. Uzun turda ~420/saat bekleniyor ve
o henüz koşulmadı. 1. tür hunt koşarken bu sayı kendiliğinden büyür; ayrıca bir şey
yapmaya gerek yok.
