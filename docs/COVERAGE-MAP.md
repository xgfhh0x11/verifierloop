# Kapsama Haritası — Taranan Yüzeyler ve Açık Uçlar

> Durum: HEAD `d96a049` (36 commit). Kaynak: `harness/diffharness.c` generator aileleri
> (`--gen*`), `crates/pipeline/tests/*_calibration.rs` pinlenmiş ölçümler, devlog 0025–0031.
> Bu belge kararı **kod tabanına dayandırılmış** bir haritadır: her sayı bir generator
> ailesinden ve onu donduran bir kalibrasyon testinden gelir.

---

## 1. Çerçeve — bir yüzey ne demek, "taradık" ne demek

Her yüzey iki eksenin kesişimidir:

- **Program şekli** — verifier'ın gördüğü akış/kontrol yapısı (tek-op, zincir, dal, birleşme, döngü, subprog).
- **Verifier'ın izlediği tip** — skaler (imm/reg-reg), 32↔64 alt-register, `PTR_TO_MAP_VALUE`, `PTR_TO_PACKET`, vb.

Bir kesişimi **"taradık"** demek iki şeyi birlikte ölçtük demektir:

1. **Karar uzayı** — verifier'ın accept/reject dağılımı (bu yüzey gerçek bir karar veriyor mu, yoksa hep mi kabul ediyor?).
2. **İç tutarlılık** — tnum ↔ bounds invariant'larının korunup korunmadığı; boş kesişim = verifier'ın kendisiyle çelişmesi. Dış ground-truth gerekmez, çünkü her izleyici aynı boş-olmayan erişilebilir değer kümesini bağımsız olarak aşırı-yaklaşır, öyleyse ikisi kesişmek zorundadır.

### Mantıksal önerme

> **Ω:** `P(x)` sınıfından bir program için verifier `K(x)` kararı veriyorsa, `K(x)` **tutarlıdır** — burada tutarlılık = tnum invariant'larının korunması + helper sözleşmelerinin karşılanması + belgelenmiş davranışla uyum.

Bugüne kadar kanıtlanan: Ω, **altı program ailesi** için ~13.000 örnek kontrolde geçerli, **0 sapma**, **0 parser kör noktası**. Kanıtlanmamış olan: Ω'nun aşağıdaki açık-uç sınıflarında geçerli olup olmadığı. Her açık uç, Ω'nun henüz test edilmemiş bir koşul altındaki halidir.

### Kritik ayrım — iki farklı ölçüm türü

| Aile türü | Ne ölçer | Neden |
| --- | --- | --- |
| **Skaler aileler** (`--gen`, `--gen-mix`, `--gen-rr`, `--gen-mb`) | **İç tutarlılık** | Saf skaler, bellek erişimi yok → **hep kabul**. Karar yok, sadece invariant koruması var. |
| **Pointer aileleri** (`--gen-ptr`, `--gen-pkt`) | **Gerçek accept/reject kararı** | Pointer üzerinden STORE OOB olabilir → verifier güvenli/güvensiz çizgisini çizer. |

Bu ayrım haritanın belkemiğidir: skaler aileler "verifier kendisiyle tutarlı mı" sorusunu, pointer aileleri "verifier doğru yerde reddediyor mu" sorusunu yanıtlar. **Yeni bir mantık hatası (kabul edilmemesi gerekeni kabul etmek) yalnızca pointer/erişim yüzeyinde görünür.**

---

## 2. Taranan yüzeyler — altı aile

Hepsi `harness/diffharness.c` içinde enumerative generator, hepsi bir fixture'a pinlenmiş, hepsi **0 sapma / 0 kör nokta**.

| # | Aile | Flag | Program | Karar | tnum-vs-bounds | Diğer payda | Devlog / commit |
| --- | --- | --- | ---: | --- | ---: | --- | --- |
| 1 | Skaler ALU × Compare | `--gen` | 242 | 242 kabul / 0 red | **1497** | reg32=0 | 0025 `8fcfa1e` |
| 2 | 32↔64 karışık genişlik | `--gen-mix` | 396 | 396 kabul / 0 red | **2167** | reg32_checked=**353** | 0026 `d34ca66` |
| 3 | Register-Register ALU | `--gen-rr` | 242 | 242 kabul / 0 red | **2453** | reg32=0 | `26daab0` |
| 4 | Çok-dal / çok-birleşme | `--gen-mb` | 242 | 242 kabul / 0 red | **2050** | reg32=0 | 0029 `0113a01` |
| 5 | Pointer aritmetiği (map_value) | `--gen-ptr` | 242 | **34 kabul / 208 red** | **1191** | — | 0030 `906cd74` |
| 6 | Paket pointer (SCHED_CLS) | `--gen-pkt` | 242 | **49 kabul / 193 red** | **1254** | — | 0031 `420022c` |

**Payda mantığı:** her aile tautoloji ayıklar. Verifier iki görünüm uyuştuğunda onları tek token olarak basar (`umax=umax32=255`); bir değeri kendisiyle karşılaştırmak invariant'ı ateşleyemez, o yüzden paydaya sayılmaz. Yani sayılar "yapabildiğimiz kadar çok kontrol" değil, "gerçekten iki bağımsız bilgi kaynağının çarpıştığı" kontrollerdir.

### Yüzey 1 — Skaler ALU × Comparison (`--gen`)

**Ne:** 11 ALU operatörü (and/or/xor/add/sub/mul/lsh/rsh/arsh/div/mod) × 11 karşılaştırma (jeq/jne/jlt/jle/jgt/jge/jslt/jsle/jsgt/jsge/jset) × {64,32}-bit = 242 program, enumeratif.
**Nasıl:** Tek register, doğrudan ALU → compare zinciri. Kısmen-bilinir bit maskesi + daraltılmış sınır aynı register'da buluşunca intrinsic tnum invariant'ı (`value & mask ≠ 0`) ateşleyebilir. **1497 kontrol, 0 sapma.**

### Yüzey 2 — 32↔64 Karışık Genişlik (`--gen-mix`) — *belgenizde açık uç sanılıyordu, aslında taranmış*

**Ne:** Dört alt-aile — `mix#64-32` (121), `mix#32-64` (121), `mix#movsx8/16/32` (33), `mix#hi` (121) = **396 program**.
**Nasıl:** Verifier bir skaleri **iki kez** izler (64-bit ve 32-bit alt-register) ve `reg_bounds_sync()` ikisini uzlaştırmak zorundadır. Üç invariant: `u32/s32_bounds_inverted`, `tnum32_bounds_inconsistent`, `reg32_reg64_inconsistent`. **2167 tnum kontrol + 353 bağımsız 32-görünüm kontrol.**

> **Analitik ders (yüksek değerli):** Tek-genişlik aile 1138 register'da 32-bit görünüm bastırdı ama **hiçbiri bağımsız bilgi taşımadı** — ctx'ten gelen bir u32 yüklemesi hep tek bir 2³² bloğuna sığar, verifier iki görünümü neredeyse kusursuz uzlaştırır. Bağımsızlığı zorlamak için **belirsiz bitleri ÜST yarıya taşımak** gerekti (`r0 <<= 32`, sonra yalnız alt yarıyı daralt). Bu 353 üretti. **Sonuç: bu bölge taranmış ama YALNIZ izole, tek-op halinde** — ALU zinciriyle veya pointer offset'iyle birleşimi hâlâ açık (bkz. Açık Uç T1-1).

### Yüzey 3 — Register-Register ALU (`--gen-rr`)

**Ne:** ALU'nun ikinci operandı immediate değil, kendi soyut durumunu taşıyan başka bir register. İki bağımsız bilinmez (`r1+0` ve `r1+4`), her ikisi de şekillendirilmiş. **2453 kontrol — en büyük payda**, 0 sapma. reg32_checked=0 (32↔64'ten farklı eksen).
**Neden ayrı yol:** Verifier `scalar_min_max_*` / `reg_bounds_sync` ile iki non-const skaleri işler ve reg-reg dalı daralmayı **her iki register'a** geri-yayar. imm ailesi bu yola hiç girmez.

### Yüzey 4 — Çok-Dal / Çok-Birleşme (`--gen-mb`)

**Ne:** İki ardışık dal + iki birleşme; ikinci dal, birincinin iki yolunun birleşimini daraltır. **2050 kontrol, 0 sapma.** reg32=0.
**Neden ayrı:** Tek-diamond ailelerin ulaşamadığı post-join daraltma yüzeyi — verifier iki yolu `tnum_or` ile birleştirir.

### Yüzey 5 — Pointer Aritmetiği, map_value (`--gen-ptr`) — *ilk gerçek karar yüzeyi*

**Ne:** Gerçek `PTR_TO_MAP_VALUE` (64 byte) + şekillendirilmiş+daraltılmış scalar offset + pointer üzerinden **1-byte STORE** (OOB-**write** kararı). **34 kabul / 208 red** (199 EACCES + 9 EINVAL diagnostics-yolu), **1191 kontrol** (hem offset'te hem pointer'ın kendi var_off'unda), 0 sapma.
**Neden karar:** Verifier bound'u **bilir** (`value_size`); `reg->off + size ≤ value_size` kontrolü kabul/reddi belirler.

### Yüzey 6 — Paket Pointer, SCHED_CLS (`--gen-pkt`) — *ötekï pointer türü*

**Ne:** `PTR_TO_PACKET` + scalar offset + programın kendi `if (data+1 > data_end) goto err` compare'ı → verifier statik `range` kaydeder (`find_good_pkt_pointers`) → 1-byte erişim. **49 kabul / 193 red** (184 EACCES = `MAX_PACKET_OFF` guard'ı + map_value ile aynı 9 EINVAL = scalar-şekillendirme özelliği), **1254 kontrol**, 0 sapma. Statik range log'da görünür (`r=0` → `r=16`).
**Kritik düzeltme:** Runtime `data_end`-fixing mekanizması **gerekmez** — karar yükleme-zamanı statik, saf komut-akışı fonksiyonu. `data_end` compare `>` (jgt) olarak sabit tutuldu (bu ilk increment).

---

## 3. Kapsama matrisi — asıl harita

Satır = program şekli, sütun = verifier'ın izlediği tip. `✓` taranmış · `◐` kısmen (bir aile dokundu ama izole/dar) · `○` açık · `—` yapısal olarak anlamsız.

| Program şekli ↓ \ İzlenen tip → | skaler (imm) | skaler (reg-reg) | 32↔64 alt-reg | map_value ptr | packet ptr | packet_meta / XDP | stack ptr | map-in-map | helper-sonuç ptr (`_OR_NULL`) |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **tek-op** | ✓ `--gen` | ✓ `--gen-rr` | ◐ `--gen-mix` | ✓ `--gen-ptr` | ✓ `--gen-pkt` | ○ | ○ | ○ | ○ |
| **zincirli-op (2+ ALU)** | ○ | ○ | ○ **(T1-1)** | ○ | ○ | ○ | ○ | — | — |
| **tek-diamond (dal)** | ✓ (`--gen` içinde) | ○ | ○ | ○ | ○ | ○ | ○ | — | ○ |
| **çok-dal / çok-birleşme** | ✓ `--gen-mb` | ○ | ○ | ○ | ○ | — | ○ | — | — |
| **bounded-loop (back-edge)** | ○ | ○ | ○ | ○ | ○ | — | ○ | — | — |
| **subprog / tail-call** | ○ | ○ | ○ | ○ | ○ | — | ○ | — | ○ |

Haritanın okunuşu: **taranan altı hücre birinci satırda yoğunlaşmış** (tek-op). Yani "verifier tek bir işlemi doğru izliyor mu" sorusunu altı tip için yanıtladık. Boş kalan her şey ya **bileşim** (op zinciri, dal + tip) ya da **yapısal yeni yüzey** (loop, subprog, stack, map-in-map, helper-sonuç). Tarihsel CVE'lerin çoğu tam da bu bileşim hücrelerinde yaşamıştır.

---

## 4. Açık uçlar — önceliklendirilmiş backlog

Sıralama ölçütü: **tarihsel ihlal yoğunluğu** (hangi koşul geçmişte en çok verifier hatasına yol açmış) × **kurulum maliyeti**. Her madde Ω önermesinin belirli bir koşul altındaki test edilmemiş halidir.

### Tier 1 — en yüksek beklenen değer (tarihsel olarak en yoğun bug bölgesi)

**T1-1 · 32↔64 senkron × pointer offset.** ✅ **TAMAMLANDI — her iki yarı (T1-1a soundness 2026-09-03 devlog 0034, `--gen-ptr-hi`; T1-1b desync-nöbetçisi 2026-09-04 devlog 0035, `--gen-sync`).**
Kurulum ölçümle verildi (`--probe-t1`): naive 32-bit shaping zero-extend → reg32=0 (0025 tuzağı); 32-bit ALU pointer'da yasak (Option B ölü); yalnız "hi" (üst-bilinmez) konstrüksiyonu yüzeye değiyor. **T1-1a** (52 program): pointer bağlamında **reg32_checked'i sıfırdan çıkaran ilk aile — 52, tamamen hi kolundan (bnd=0)**. hi all-reject (0/40, `adjust_ptr_min_max_vals` 64-bit'e bakıyor, verifier yapısal olarak pointer için hep 64), bnd 8/12 kontrol. 0 sapma. Mutual exclusivity: `reg32>0 ⟺ meşru-accept imkânsız` — bir reviewer önerisi (K<value_size) kurulmadan elendi. **T1-1b (TAMAMLANDI, devlog 0035, `--gen-sync`):** CVE-2020-8835 sınıfı desync-nöbetçisi. **0034'ün öngörüsü düzeltildi** — yeni oracle kolu GEREKMEDİ: fix commit `f2d67fec0b43` incelemesi desync'in **tam olarak mevcut invariant B** (`tnum32_bounds_inconsistent`) olduğunu gösterdi (buggy `__reg_bound_offset32` tnum32'yi {0}'a kırpıyordu, u32=[0x200,0x400] ile disjoint) → tek iş: B'yi CVE-şekilli state'lere süren aile. 24 program (cve 16 + shift 8), **24 kabul** (yüzey karar değil, daraltmanın bıraktığı register state); **reg32_checked=56, finding_count=0** (B tüm sync state'lerinde koştu → regresyon fire ederdi; sustu → görünümler tutarlı). Keskin nokta: **56/56 state çok-bloklu**, invariant C (single-block gated) kapalı ve **B tek nöbetçi** — CVE'nin tarihsel olarak yalnız tnum-vs-u32 redundancy'siyle yakalanabilir olmasının sebebi. Sınır: consistency DESYNC yakalar, tutarlı-ama-yanlış (b, diferansiyel-recompute) ertelendi. Pinlendi: `crates/pipeline/tests/sync_calibration.rs` (6 test) + `pointer_hi_calibration.rs`.

**T1-2 · Negatif offset + smin kontrolü (map_value pointer).** ✅ **TAMAMLANDI (2026-09-03, devlog 0033, `--gen-ptr-neg`).**
120 program (form{raw, grd} × C × reach); `r1 &= 15; r1 -= C` ile smin'i `-C`'ye itiyor. **60 kabul / 60 red; raw 4/60 (her kabul C==0), grd 56/60.** İki sonuç: **negatif-yetenekli hiçbir store kabul edilmedi** (smin alt-sınır kontrolü uygulanıyor, "R0 min value is negative" canlı) ve **grd guard'ı doğru kurtarıyor** (verifier işaretli daldan sonra smin≥0'ı yeniden türetip kabul ediyor, aşırı-reddetmiyor). Karar predikatı 120/120 tam, tnum 438, 0 sapma. Bu kernel'de OOB-below accept yok. Pinlendi: `crates/pipeline/tests/pointer_neg_calibration.rs`.

**T1-3 · Paket compare-operatörü sweep (jgt vs jge — `range_right_open`).** ✅ **TAMAMLANDI (2026-09-03, devlog 0032, `--gen-pkt-cmp`).**
240 program (form{gt,ge,lt,le} × M × off × W), offset şekli `r4 &= 7`'ye sabitlenmiş → karar saf range makinesinin fonksiyonu. **128 kabul / 112 red; gt=27, ge=37, lt=27, le=37.** İki sonuç: **operand-sırası simetrisi tam tutuyor** (gt==lt, ge==le) ve **closed vs right-open sınırı tam bir bayt** — 240/240 karar `off+W ≤ range` predikatına uyuyor (closed range=M, right-open range=M+1), 0 istisna. tnum 720, 0 sapma. Verifier tam programın ispatladığını ispatlıyor — bu kernel'de off-by-one yok. Pinlendi: `crates/pipeline/tests/packet_compare_calibration.rs`.

### Tier 2 — orta değer, düşük maliyet

**T2-1 · ALU zincirleme (skaler).** `r0 &= 0xff; r0 <<= 3; if r0 > 0x3f8 goto err`. Tarihsel: çift-ALU zincirinde smax güncellenmeden kalması. Her `--gen*` şu an tek ALU op.

**T2-2 · Store genişliği (map_value pointer).** `--gen-ptr` 1-byte. 2/4/8-byte, `reg->off + size ≤ value_size` kontrolünde `size`'ı doğrudan etkiler — off-by-one tam burada yaşar.

**T2-3 · İmzalı/işaretsiz compare karışımı.** Tek programda hem `jsgt` hem `jgt`. `umin/umax` ↔ `smin/smax` senkronu tarihsel olarak tutarsız güncellenmiş. `--gen` her programda tek compare kullanır.

**T2-4 · Helper-sonuç tipi geçişi (`_OR_NULL`).** `bpf_map_lookup_elem` → `PTR_TO_MAP_VALUE_OR_NULL`; verifier null kontrolünü zorunlu kılar. Null kontrolü atlanmış bir program kabul edilirse → mantık hatası. Helper kolu `arg_type` sözleşmesini kontrol ediyor ama sonuç-tipi geçişini değil.

### Tier 3 — yüksek değer ama yapısal kurulum gerektirir

**T3-1 · Bounded loop (`bpf_loop` / `may_goto`).** Sayaç her iterasyonda doğru azalıyor mu, verifier back-edge'de state'i doğru birleştiriyor mu? Looping leg olarak ayrıldı, kurulmadı. State-explosion sınırının kenarı da burada.

**T3-2 · Subprog / tail-call state transferi.** Çağrı sınırında register state taşınır; tnum bilgisi doğru mu aktarılıyor? Verifier her subprog'u ayrı analiz eder.

**T3-3 · Stack spill / reload.** Register stack'e yazılıp geri okunurken tnum ve tip korunuyor mu? `STACK_SPILL` ↔ `STACK_MISC` geçişi.

**T3-4 · İki pointer farkı.** `PTR_TO_MAP_VALUE`'dan başka pointer çıkarma — sonuç scalar mı pointer mı? Bu geçişte tarihsel confusion bug'ları var.

**T3-5 · Map-within-map.** `BPF_MAP_TYPE_ARRAY_OF_MAPS` — iki seviyeli pointer tracking. Hiç taranmadı.

**T3-6 · packet_meta ve XDP bağlamı.** `PTR_TO_PACKET_META` (data'nın solunda, farklı sınır mantığı) ve XDP'nin kendi erişim kontrolü (`xdp_is_valid_access`). `--gen-pkt` şu an SCHED_CLS.

---

## 5. Özet — bir sonraki hamle nereye

Harita üç şeyi söylüyor:

1. **Derinlik değil, genişlik kazandık.** Altı tipin her biri için tek-op davranışı sağlam ölçüldü (0 sapma). Ama matris ilk satırda yoğun — bileşim hücreleri boş.
2. **Tier 1'in iki hamlesi tamamlandı** — packet compare-op sweep (T1-3, devlog 0032: simetrik, bir-bayt-kesin) ve map-value negatif offset (T1-2, devlog 0033: smin alt-sınır uygulanıyor, OOB-below accept yok), ikisi de 0 sapma. Kalan tek Tier-1 hamlesi: **32↔64 × pointer-offset (T1-1)**, en yoğun tarihsel bölge — ve yapısal olarak en zoru.
3. **Yapısal borç Tier 3'te** — loop, subprog, stack spill, map-in-map, helper-sonuç. Bunlar yeni harness altyapısı ister ama tarihsel olarak en zengin bug damarları.

Reviewer önceliklendirme kuralı (oracle × input): oracle'ı input açken büyütme. Tier 1'deki hamleler oracle'ı büyütmeden mevcut input bütçesini yeni bir karar-koşuluna **nişan alır** — bu yüzden önce onlar.
