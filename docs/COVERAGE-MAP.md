# Kapsama Haritası — Taranan Yüzeyler ve Açık Uçlar

> Durum: HEAD `8824e73`+ (43 commit). Kaynak: `harness/diffharness.c` generator aileleri
> (`--gen*`), `crates/pipeline/tests/*_calibration.rs` pinlenmiş ölçümler, devlog 0025–0037.
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

## 2b. Yeni oracle — runtime yer-gerçeği (`--gen-rt`, devlog 0036)

Yukarıdaki altı ailenin hepsi **Ω**'ya (iç tutarlılık) dayanır: verifier'ın bastırdığı
tnum/bounds görünümleri **birbiriyle** çelişiyor mu? Bunun yapısal bir kör noktası var:
iki görünüm **aynı şekilde** bozulursa (consistent-but-wrong), birbirleriyle uyumlu
kalırlar ve hiçbir iç-tutarlılık invariant'ı ateşlemez. Tarihsel verifier bug'larının
çoğu (ör. CVE-2021-3490, 32-bit bounds) tam bu sınıfta.

Runtime oracle bu kör noktadan kaçan **ilk** dedektör. Daha güçlü bir önerme kanıtlar:

> **Ω_rt:** verifier bir programı kabul edip dönüş register'ı için `[lo,hi]` sınırını
> kanıtladıysa, programın **gerçek çalışma-zamanı** dönüş değeri de `[lo,hi]` içindedir.

Mekanizma: program tam-attacker-kontrollü 32-bit bir input'u (userspace'ten set edilen
map değeri) alır, verifier-izlenen bir ALU/compare şekli uygular, sınırlanmış değeri
**döndürür**. Harness onu `BPF_PROG_TEST_RUN` ile bir input süpürmesi üzerinde **fiilen
çalıştırır** ve gerçek `retval`'ı kaydeder. Pipeline her retval'ı r0'ın kanıtlanmış
scalar sınırlarının **birleşimiyle** karşılaştırır (birleşim = exit-başına sınırın
muhafazakâr üst-kümesi → geniş birleşim ihlali kaçırabilir ama asla uydurmaz). retval
sınır dışındaysa `runtime_bound_violation` — verifier kanıtladığı sınırı çalışmada aşan
bir programı kabul etmiş demektir; ve bu, verifier log'unun kendi-tutarlılığına **hiç
güvenmeden** yakalanır.

**Çıktı (bpf-next VM, kernel 5e289c5a, 2026-09-04):** `--gen-rt` = 37 program (and /
andadd / andlsh / cmp / alu32 şekilleri; hepsi ≤32-bit), her biri 12-değerli input
süpürmesi. **37 kabul, runtime_checked=444** (444 gerçek çalıştırma, her biri verifier'ın
kendi sınırıyla kontrol edildi), **finding_count=0** — hiçbir gerçek retval sınırını
aşmadı. **0 parser kör noktası.** Oracle'ın boş olmadığı kanıtlandı: planlı bir kaçış
(sınır dışı retval) tam bir kez ateşliyor; ve off-by-one sağlam: retval==umax ateşlemiyor,
umax+1 ateşliyor. Pinlendi: `crates/pipeline/tests/runtime_calibration.rs` (6 test).

**Sınır:** Ω_rt DESYNC'e de consistent-but-wrong'a da bakmaz — dönüş değerinin kanıtlanan
sınırı **çalışmada** aşıp aşmadığına bakar, bu yüzden ikisini de yakalayabilir; ama yalnız
dönüş-değeri kanalı (retval, 32-bit) üzerinden gözlemlenebilen bug'ları görür. v2 yönleri:
daha geniş gözlem kanalları (map/packet write, 64-bit değerler), pointer-erişim OOB'sinin
runtime tespiti, ve döngü/iterator input'ları.

### 2b.1 — Bellek-güvenliği ekseni (`--gen-rtw`, devlog 0037)

Runtime oracle'ının bellek-güvenliğine ilk genişlemesi ve **asıl av yüzeyinin (pointer OOB)
ilk ayağı**. Program attacker-input'tan bir offset üretir (verifier'ın in-bounds kanıtladığı)
ve `map_out` değerine bir sentinel yazar; harness map'i sıfırlar, çalıştırır, geri okur,
sentinel'i arar. Kabul edilen store iddiaen in-bounds → sağlam kernelde sentinel **daima**
value içine düşmeli; `store_off=none` = kernel belleğine gitti = verifier'ın kabul ettiği
OOB-write. **Bound parse gerekmez — doğrudan bellek-güvenliği.** Çıktı: 9 program (7 kabul /
2 red; red = over-wide maske, verifier'ın statik çizgisi), **runtime_writes_checked=84,
finding_count=0** — her store value içine düştü. Diş kanıtlandı (planlı `store_off=none` tam
bir kez `runtime_oob_write` ateşliyor). Pinlendi: `runtime_write_calibration.rs` (5 test).
Sıradaki: store genişliği 2/4/8B (T2-2 → §2b.2, DONE), packet write, store_off'u verifier'ın
pointer-offset bound'uyla karşılaştırma (pointer-tracking desync), döngü/iterator.

### 2b.2 — Store-genişlik ekseni (`--gen-rtw2`, devlog 0038)

T2-2: 2b.1'in tek-bayt sentinel'ini **çok-baytlı store**'a genişletir. Gerçek verifier
bug'ının off-by-one'ı `off + size ≤ value_size` kontrolünde — yani ölçülen eksen artık
store WIDTH. Store `size` bayt 0xFF yazar (imm=−1); harness her koşuda map'i **koşu-öncesi**
sıfırlar (tek 0xFF kaynağı store olduğundan önceki adımdan kalan sentinel yanlış sayılamaz),
İLK 0xFF'i (`store_off`) bulur ve ardışık run'ı sayar (`store_len`). Predikat: bellek-güvenli
⟺ `off≥0 VE store_len==store_size`; kısa run = **kısmi OOB** (base içeride ama bir bayt sınırı
aştı) — tek-baytın ifade edemediği yüzey. `map_or(true)` eski 1-byte fixture'ı geriye-uyumlu
tutar. İki şekil: **and.wN** (attacker offset r6&=MASK, kabul ⟺ MASK+N≤64) ve **bndc.wN**
(const offset; off=64−N tam sonda biter=KABUL, off=65−N bir bayt aşar=RED — kesin off-by-one).
Çıktı: 20 program (13 kabul / 7 red), **runtime_writes_checked=156, finding_count=0** — her
kabul edilen store tam genişliğini içeri yazdı; en sıkı sınır bndc.w8 (off=56, run=8, tam
64'te biter). Diş iki kez: planlı `store_off=none` VE planlı kısa run (`store_len<store_size`)
ayrı ayrı `runtime_oob_write` ateşliyor. Pinlendi: `runtime_write2_calibration.rs` (7 test).
Sıradaki: packet write (§2b.3, DONE), store_off vs verifier pointer-offset bound, döngü/iterator.

### 2b.3 — Packet-write ekseni (`--gen-pktw`, devlog 0039) — DONE

Runtime bellek-güvenliği oracle'ının **packet** ayağı: 2b.1/2b.2 map_value pointer'ından
geçiyor (sınırı verifier statik BİLİR, value_size); packet pointer'ın sınırını verifier
BİLMEZ — PROGRAM `data + M > data_end` compare'iyle ispatlar, verifier `range`'i statik
takip eder (`find_good_pkt_pointers`, tarihsel en yoğun bug bölgesi). Load-only packet
aileleri (`--gen-pkt`/`--gen-pkt-cmp`) yalnız accept/reject ve iç-tutarlılık görür;
bu leg accepted programı `BPF_PROG_TEST_RUN` (SCHED_CLS/skb) ile KOŞAR ve packet'i geri
okur, iç-tutarlı-ama-yanlış range'i yakalar. Runtime packet boyutu TAM M (=32,
data_size_in), böylece data_end byte M'e oturur; sağlam kernelde her accepted store
`off+W≤M` → tüm byte'lar `[0,M)`'e düşer, data_out'ta geri gelir (`store_len==store_size`).
`off+W=M+1` kabul eden buggy verifier son byte'ı data_end'e (skb tailroom, test_run
kopyalamaz) koyar → kısa run / yok → paylaşılan predikat `runtime_write_safety` ateşler.
**Kritik:** offset SABİT (compare M byte ispatlar, store off+W'ye ulaşır → verifier tek
hakem); compare'in store bölgesini tam yeniden-kontrol ettiği değişken şekil TAUTOLOJİ
olurdu (runtime kendini korur), o yüzden dışarıda. Şekil W{1,2,4,8}×3 kol (off 0 iç-kabul,
off=M−W sınır-kabul, off=M−W+1 off-by-one red). **Çıktı format 0038 ile bayt-özdeş →
parser/diff/metrics DEĞİŞMEDİ.** ÖLÇÜLEN (koşumdan önce türetilen tahminle bire bir):
12 program, **8 kabul / 4 red, runtime_writes_checked=8, finding_count=0,
parser_unrecognized=0**. Kabul sınırı her genişlikte tam `off=M−W` (w1 o31/o32, w2 o30/o31,
w4 o28/o29, w8 o24/o25) — her kabul edilen store TAM genişliğini `[0,M)` içine yazdı; en
sıkısı w8.o24 (8 byte'lık run tam byte 32 = data_end'de biter). Diş bu ailenin GERÇEK
capture'ı üzerinde iki kez: planlı `store_off=none` ve planlı kısa run ayrı ayrı
`runtime_oob_write` ateşliyor. Pinlendi: `packet_write_calibration.rs` (7 test),
fixture `fixtures/volume/gen-pktw-12.log`. **Kanal ölçüldü (0040, `--probe-pktw`):** bu leg'in tek okumaya-dayalı halkası — "test_run yalnız `[0,skb->len)`'i döndürür, OOB store gözlenemez" — artık ÖLÇÜM. Sağlam verifier her OOB store'u reddettiği için negatif yarıya store'u değil PENCEREYİ oynatarak gidildi (`bpf_skb_change_tail` store'dan SONRA `skb->len`'i küçültür). 4 kol, hepsi kabul: win32 out_size=32/off=31; win40 out_size=**40** (pencere `skb->len`'i takip eder, sabit değil); trim.o19 out_size=20/off=**19** (pencerenin son byte'ı çözülür); trim.o20 out_size=20/off=**none** (fiilen yazılmış `index==out_size` byte'ı DÖNMEZ). İki trim kolu tek byte'lık offset farkıyla zıt gözlenebilirlik → kenar byte-hassas, "yok" konumsal. `tail_zero=1` her kolda: pencere ötesi sıfır kalır, sentinel diye YANLIŞ OKUNAMAZ da. Store-location desync'in ön-koşulu kapandı. Pinlendi: `packet_channel_calibration.rs` (7 test), fixture `probe-pktw-4.log`. İlk increment kapalı `>`; compare-form
taraması (`>=`, operand-simetri) OI-9 takip.

### 2b.4 — Store-LOCATION desync ekseni (`--gen-loc`, devlog 0041) — DONE

Runtime oracle'ının **asıl avı**: 2b.1–2b.3 tek soru sorar — store nesnenin İÇİNDE mi?
Bir verifier bunu geçip yine de yanlış olabilir: offset'in soyut aritmetiği unsound ise
store, kendi durumunun İMKÂNSIZ dediği bir offset'e düşer ve hâlâ içeride kalır →
önceki her bacak sessiz. Bu, iç-tutarlılık oracle'ının yapısı gereği göremediği
"consistent-but-wrong" sınıfı. Bu bacak **verifier'ın kendi bastığı iddiayı** ölçüyor:
`17: R7=map_value(vs=64,umax=7,var_off=(0x0; 0x7))` + `17: (72) *(u8*)(r7+0) = -1` →
kanıtlanmış pencere = `ptr_off + insn_off + [umin,umax]`, var_off tnum'uyla daraltılmış.
**tnum yarısı şart:** `r6&=3; r6<<=2` {0,4,8,12} kanıtlar, offset 6 [0,12] içinde ve
imkânsız. Store'un yeri GENERATOR'dan bildiriliyor (`STORE insn= reg= off= size=`),
verifier'ın disassembly'sinden değil — oracle soruyu denetlediği bileşenden öğrenmemeli.
**Parser boşluğu kapandı:** pointer register'ın bounds/var_off/off'u atılıyordu
(`build_regstate` (c) kolu), artık saklanıyor. Yokluk kuralı iki farklı: `var_off` yok =
değişken parça sabit (mask 0), ama bir BOUND yok = uç değerinde (log.c bir bound'u
varsayılanındaysa basmaz) — bu scalar koluyla AYNI kural. İlk yazımda ikisi
karıştırılmış, `umin=0xff..f0` + basılmamış `umax` ters unsigned aralık gibi okunup
`pointer_neg_calibration`'da 6 sahte bulgu ateşlemişti; suite yakaladı, düzeltildi.
Eksen = soyut transfer fonksiyonu: 15 program (and7/and31/orand/addc/subc/lsh2/lsh3/
rsh/mul/xor/alu32/**jmp** = maske değil branch ile sınır/shpair/compose/off4).
**ÖLÇÜLDÜ (2026-09-05): 15 kabul / 0 red, `store_locations_checked=170`,
`runtime_writes_checked=170`, `finding_count=0`, `parser_unrecognized=0`** — her kabul
edilen store, verifier'ın kanıtladığı kümenin içine düştü (elle de doğrulandı; tnum
yarısı vakum değil: lsh2 tam {0,4,8,12}, compose {4,8,12,16}). Sayaç ayrı olmak zorunda
— sıfır bulgu ancak iddia OKUNMUŞSA anlamlı. **170 = 180 − 10:** `jmp` kolu offset'i
BRANCH ile sınırlıyor, 12 sweep input'unun 10'u sınırın üstünde olduğu için store'a hiç
ulaşmıyor. İlk capture bunları `store_off=none` diye OOB sanıp 10 sahte
`runtime_oob_write` verdi; `none` "sınır dışı" ile "hiç çalışmadı"yı karıştırıyordu
(önceki ailelerde store koşulsuzdu, o yüzden fark etmiyordu). Kaynakta çözüldü: program
store yolunda ayırt edici retval döndürüyor, harness `executed=` basıyor, ulaşılmamış
koşu yargılanmıyor; koşulsuz store'lu aileler tanık basmadığı için eski okuma ve dişleri
aynen duruyor. Dişler: (1) pencere dışı ama bellek-güvenli offset → desync ateşler,
`runtime_oob_write` SESSİZ (kapatılan kör nokta tam bu sessizlik), (2) pencere içi ama
tnum-imkânsız → tnum ihlali olarak ateşler, (3) `off4` kolunda insn_off'suz offset →
ateşler, (4) tanık AYIRT ediyor: aynı eksik sentinel `executed=1` ile OOB ateşler,
`executed=0` ile ateşlemez. Artı vakumsuzluk testi: kanıtlanmış pencere DAR olmalı
(`umax-umin<=56`). Pinlendi: `store_location_calibration.rs` (9 test), fixture
`fixtures/volume/gen-loc-15.log`; runner `scripts/run-loc.sh`.

### 2c — Pruning-soundness differential (`--gen-prune`, devlog 0042) — DONE, YENİ ORACLE SINIFI

İlk **kernel-vs-kernel** bacağı: karşılaştırmanın iki tarafı da kernel'in aynı program
üzerindeki kendi kararı, yani parse edilen bir bound ya da hesaplanan bir değer YOK —
yanlış olabilecek bir oracle'ımız yok (0041 tam olarak iki tane böyle bug taşımıştı).
Ve ilk kez **state pruning**e nişanlı: `regsafe`/`states_equal` (`states.c:507`, `:980`)
iki soyut state arasındaki İLİŞKİYİ yargılıyor; ne iç-tutarlılık ne runtime-değer
oracle'ı oraya ulaşabiliyor.

**Bu bacağın var olma nedeni = "neden 0 divergence"in kök nedeni.**
`reg_bounds_sanity_check()` (`verifier.c:2189`) birebir bizim invariant A/B/C'miz
(`range_bounds_violation`, `const_tnum_range_mismatch`, `const_tnum_range_mismatch_32`)
ve her ALU op'ta / her branch'in dört register'ında / her helper retval'inde / her
LDX'te koşuyor. Yani 0025–0035 boyunca kernel'in kendi kendine koşturduğu bir
assertion'ı dışarıdan yakalamaya çalışmışız. Consistency oracle sınıfı iki yönden kısır:
kaçırdığı sınıf runtime'a gidiyor, yakaladığı sınıf zaten in-tree korunuyor.

**Enstrüman ve YÖN.** `BPF_F_TEST_STATE_FREQ` pruning'i kapatmıyor, AÇIYOR
(`states.c:1248`: `force_new_state = env->test_state_freq || ...` → her instruction'da
checkpoint; varsayılan sezgisel ≥2 jump VE ≥8 insn bekliyor). Predikat bu yüzden yönlü:
**bayraklı ACCEPT + varsayılan REJECT = pruning soundness bug'ı** (reddi üreten yol
budandı — bunu ancak unsound `regsafe` yapar). Ters yön (bayraklı REJECT + varsayılan
ACCEPT) fazladan checkpoint'in state sayısını şişirmesinden doğan kaynak artefaktı
(`BPF_COMPLEXITY_LIMIT_INSNS`, `verifier.c:18348`); red sebebine göre sınıflandırılıp
AYRI sayılıyor, bulgu sayılmıyor — ama kaynak-limiti OLMAYAN ters flip gerçek bir
over-rejection olarak raporlanıyor.

**Payda:** bir çift ancak `freq_states > base_states` ise sayılıyor. State sayısı farkı
ne gürültü ne bulgu — deneyin koştuğunun KANITI (0041'in `store_locations_checked`
disiplini).

**Üçüncü kanal:** `BPF_F_TEST_REG_INVARIANTS` (1<<7) kernel'in kendi Ω'sını sert
`-EFAULT`'a çeviriyor; varsayılanla temiz yüklenip bayrakla EFAULT veren program
dışarıdan görülemeyecek bir iç tutarsızlık.

**Input — yanlış prune'un gözlemlenebilir olma şartı:** (a) birleşen akış, (b) `regsafe`'in
yargılamak zorunda olduğu iki farklı gelen state, (c) hangi yoldan gelindiğine bağlı
güvenliği olan downstream erişim. İki attacker değeri (offset r6, seçici r9) tek map
value'dan okunuyor → split r6'yı kısıtlamıyor. Store `map_value + r6 + 56`, sınır içi ⟺
`umax(r6) <= 7`. Verifier fall-through'u önce gezdiği için checkpoint'i o kaydediyor —
ORDER eksen. Shaper'lar: n7/t6 (güvenli) × w63/m39/o19/s56/a32 (ayrık/örtüşen/delikli
tnum/32-bit). 16 program = 2 safe + 6 dang + 6 ctrl + 2 stk (`stacksafe` yargıç).
**Saf-tnum kolu bilerek YOK:** güvenlik yalnız `umax`'a bağlı, tnum farkı kararı flip
edemez → vakum olurdu (0039'un tautology dışlama kuralı).

**ÖLÇÜLDÜ (2026-09-05): 16 program, 2 accept / 14 reject, `prune_pairs_checked=16`,
`finding_count=0`, `prune_resource_artifacts=0`, `parser_unrecognized=0`** — üç yükleme
de her programda aynı fikirde, ve bayrak HER programda state uzayını büyüttü (base 1–3 →
freq 4–7). Dört diş: soundness flip / kaynak artefaktı sayılıyor ama bulgu değil /
kaynak-sebepsiz ters flip ateşliyor / REG_INVARIANTS EFAULT ateşliyor. Artı payda
guard'ı. Pinlendi: `prune_calibration.rs` (9 test), fixture `gen-prune-16.log`, runner
`scripts/run-prune.sh`.

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
