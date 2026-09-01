# verifierloop — Review / Handoff Context Raporu

> **Bu belgenin amacı.** Projenin **şu ana kadar nereye geldiğini** bağımsız bir
> gözden geçiren (başka bir Claude ya da bir insan) için **iddia değil,
> doğrulanabilir kanıt** biçiminde toplar. Her önemli iddianın yanında **(a)
> nerede bakılır, (b) hangi komut çalıştırılır, (c) "geçti" ne demek** verilir.
> Reviewer'ın görevi: bu iddiaları kendi eliyle koşup teyit etmek ve
> **abartılmış/yanlış** olanları işaretlemek.
>
> - **Rapor tarihi:** 2026-09-01 (önceki sürümler: 2026-08-30, 2026-08-27)
> - **Repo kökü:** `/home/tylersec/verifierloop` — **git deposu** (branch `main`,
>   **23 commit**, HEAD `0024`'ün commit'i)
> - **Kernel rev (hedef):** `5e289c5a4a526e870efac0ca658635c47138593a` (`.lab/kernel.rev`)
> - **Son devlog entry'si:** `0024` — `docs/devlog/devlog.md`
> - **Test durumu:** `cargo test` → **82 passed, 0 failed** (2026-09-01 teyit edildi)

---

## 0. Reviewer için 60 saniyelik özet

**verifierloop**, `bpf-next` çekirdeğindeki **eBPF verifier**'ın *mantık
hatalarını* avlamak için tasarlanmış operasyonel bir araştırma döngüsüdür (kendi
lab'ında, kendi derlediği kernel'de, tek-kullanımlık QEMU VM'lerde — **yetkili /
savunma amaçlı güvenlik araştırması**).

**Bu oturumun sonunda ulaşılan nokta: ilk gerçek period CANLI koşuyor.** Beş-stage'li
pipeline ve loop, kendi derlediğimiz bpf-next kernel'inden gelen **gerçek verifier
verisiyle** uçtan uca çalışıyor:

```
gerçek bpf-next VM → diffharness (log_level=2) → VmHarnessDriver → run_period(loop)
   → normalize(VerifierLogParser) → score(Python) → diff → report
```

**Hacim açık (0018–0020).** syzkaller'ın kendi corpus'u bir shim ile `log_level=2`
verifier log'una çevrilip period olarak koşuyor. İki kampanya **commit'li regresyon
fixture'ı** olarak sabitlendi (95 ve 184 blok): **70 ve 151 kayıt**, **20 ve 44 farklı
gerçek reject metni**, her ikisinde de **0 divergence** (✔ V8/V10).

**Üç dedektör kolu canlı (0021–0024).** Beş ground-truth kaynağının **üçü çalışıyor**
(intrinsic invariant'lar; ağaçtan **auto-extract edilen 274 helper kontratı / 194
helper**; `verifier.rst`'ten **13 alıntı-çapalı** dokümante vaka), **biri kısmi**
(patch-diff: bulgu değil **kanıt** üretir), **biri stub** (`verifier.c`
state-transition). Üçü de gerçek yolda **kalibre**: temizde susar, enjekte
tutarsızlıkta bağırır.

**İlk SAĞLAMLIK (soundness) ölçümü yapıldı (0024).** `verifier.rst`'in "Understanding
eBPF verifier messages" bölümündeki **11 örnek program** — hepsi reddedilmesi
gereken — harness'e kodlandı ve gerçek bpf-next VM'inde koşuldu: **12 vakanın 12'sinde
de karar dokümanla uyuştu (divergences=0)**. Bu, döngünün ilk kez "verifier
reddetmesi gerekeni reddediyor mu" eksenini ölçmesi.

**Ölçülen sayılar:** parser kör nokta oranı **%0** (0/70, 0/151 ve 0/20 — üç bağımsız
yakalamada), koşu başına **~101 helper kontrolü**, **12 dokümante vaka kontrolü**,
**0 false positive**, **82 test** yeşil.

**Reviewer'ın en çok şüpheyle bakması gereken nokta:** hacim **gerçek bir verifier
bug'ı üretmedi** — beklenen sonuç (gerçek kernel + coverage-güdümlü corpus). Üç kol da
kalibre ve parser kör noktaları **ayrı kanalda** raporlandığı için bu "sağır" değil
"temiz" okunur. Hacmin ilk çıkardığı şey de verifier bug'ı değil **5 parser kör
noktasıydı**; hepsi parse-health'e düştü, sinyale karışmadı, düzeltildi ve regresyona
sabitlendi.

**Bu sürümün asıl bulgusu — ve kusur DOKÜMANDA (✔ V15).** 11 vakadan biri gerçek
ağaçta **kabul** ediliyor. Karar-mismatch'i olduğu için en yüksek sesli sinyal
sınıfı — ama gerekçe kaynakta bulundu: dokümante red **yalnız yetkisiz yükleme için**
geçerli (`verifier.c:21141` → `bpf_token_capable(token, CAP_PERFMON)`), doküman bu
koşulu hiç söylemiyor. OI-6'nın öngördüğü "gerçek regresyon mu, bayat prose mu?"
sorusunun ilk gerçek örneği; cevabı **prose** çıktı.

---

## 1. Ne olduğu — ve ne OLMADIĞI (kapsam sözleşmesi)

**Olan:** kapalı-döngü avlama hattı: fuzz/harness → gözlem → normalize → skorla →
ground-truth ile diffle → insana triyajlı batch → tekrar. Period = **exec sayısı**
(sayaç), zaman değil.

**Olmayan (reviewer bunları "eksik" diye işaretlememeli — kapsam dışı):**
- **Formal ispat / theorem-prover yok.** Ground truth = dokümantasyon + patch diff
  + klasik mantıksal analiz; formal model değil.
- Entegre edilecek **harici motor yok.** Döngü kendi üzerine kapanır.
- Belirtilmeyen her şey ad-hoc yerine **TODO**.

**Kaynak belgeler:** `README.md`, `docs/RUNBOOK.md` (operatör manueli),
`docs/OPEN-ITEMS.md` (**izlenen açık maddeler** — kapanmamış hipotezler/eksikler),
`docs/eBPF ... Mimari ...md` (tasarım), `docs/devlog/devlog.md` (0001–0023).

---

## 2. Mimari ve dil sınırı

İki dil, tek bir tipli **dosya-tabanlı JSON sözleşmesinde** buluşur (paylaşılan
process belleği yok): **Rust** (orkestrasyon, loop, VM kontrol, pipeline stage'leri)
⇄ **Python** (istatistik, anomali skorlama). Sınır: `contract` crate ↔
`python/.../contract.py`.

| Crate / dizin | Sorumluluk | Durum |
|---|---|---|
| `metrics` | 4 metrik-şema grubu (core/derived/counterfactual/expectation) | CORE donduruldu |
| `contract` | Rust↔Python JSON sözleşmesi | Implemente + testli |
| `pipeline` | 5 stage + ground-truth + **2 gerçek parser** | ingest/normalize/score/diff/report ✅ |
| `vmctl` | QEMU VM kontrolü | İskelet (şimdilik script'ler kullanılıyor) |
| `orchestrator` | Loop runtime + **VmHarnessDriver** | Loop + gerçek sürücü ✅ |
| `harness/` | **Guest-side C** differential/verifier-log harness | v0 ✅ (decision+reg-state) |
| `scripts/` | Lab bring-up + fuzzer + **in-VM harness run** | Çalışır |
| `python/` | Analiz paketi (score stage) | Baseline scorer ✅ |

---

## 3. Pipeline + entegrasyon durumu (stage/parça bazında)

```
ingest ✅ → normalize ✅ → score ✅ → diff ✅ → report ✅ → (human-in-the-loop)
```

| Parça | Ne yapar | Gerçekten yapılan | Hâlâ TODO |
|---|---|---|---|
| **ingest** | native çıktıyı DEĞİŞTİRMEDEN topla | toplama+indeks+hash | — |
| **normalize** | ham → CORE şeması | **golden fixture** anchor + **2 gerçek parser** (aşağı) | zenginleştirme |
| **score** | Rust→Python anomaly scoring | `baseline-hard-signals-v0` | istatistiksel |
| **diff** | documented-vs-observed | intrinsic invariant'lar + helper `bpf_func_proto` (274 kontrat) + documented behaviour (**13 vaka**, karar/mesaj ayrı ağırlıkta) + patch-diff kanıtı | `verifier.c` loader (kaynak 1) |
| **report** | score ⋈ diff → triyaj | join + sıralama | — |
| **`VerifierLogParser`** | harness çıktısı → CoreMetrics | decision, reject reason (verbatim), register-state, processed | full `scalar(...)` gerçek veride test edildi (0014); pointer/helper reg tipleri henüz yok |
| **`VmHarnessDriver`** | VM'de harness koş, exec→N | `FuzzDriver` impl, `ScriptRunner`, `FakeRunner` test | syzkaller-driven execs |
| **`run-harness-vm.sh`** | harness'i bpf-next VM'inde koş, çıktı yakala | init=+seri, loop-mount, -snapshot | — |

**Kritik invaryant (reviewer teyit etmeli):** `diff` asla `ANOMALY_SCORES` okumaz
(score ranks / diff states / report assembles). Parser **asla malformed tnum
üretmez** (const→mask 0, unknown→value 0) → diff'te false-positive tetiklemez.

---

## 4. Bizzat KOŞULMUŞ doğrulamalar (2026-08-27, ilk elden)

**(V1) Derleme + testler**
```
$ cargo build   → Finished
$ cargo test    → 74 passed, 0 failed
```
(dağılım: contract 5, orchestrator 6 [loop 4 + vm_driver 2], pipeline lib 18
[+5 verifier_log], golden_normalize 1, diğerleri şema/iskelet 0.)

**(V2) Pipeline uçtan uca — SENTETİK veri**
```
$ cargo run -q -p pipeline --example report_demo -- <dir>
PERIOD REPORT  ... top_score=0.95 divergences=3   (kurgusal buggy kayıt: diff+score çalışıyor)
```

**(V3) Pipeline — GERÇEK harness verisi (VM/root gerektirmez, committed sample)**
```
$ cargo run -q -p pipeline --example harness_demo -- <dir>
rec0/1 accept | rec2 reject "R0 !read_ok" | rec3-5 ranged-scalar (r0&=0xff, r0<<=8, cmp)
→ 6 kayıt, 0 anomali / 0 divergence  (full-scalar diff invariant'ları GERÇEK veride koşar)
```

**(V4) İLK GERÇEK PERIOD — CANLI (bpf-next VM boot eder; root+TCG, dakikalar)**
```
$ cargo run -q -p orchestrator --example real_period -- <dir>
HARVEST  period=1 exec_count=6 collected_files=1
PERIOD REPORT  records=6 flagged=0 divergences=0
  rec0/1 accept | rec2 reject "R0 !read_ok" | rec3-5 ranged-scalar accept   (6-program corpus, 0014)
```
Gerçek bpf-next VM → loop harvest → downstream pipeline. **exit 0.**

> **⚠️ Reviewer dikkat:** V4 gerçek veri + gerçek VM + gerçek loop'tur, AMA harness
> **sabit corpus** koşar (0014'te 6 programa çıktı: 3 basic + 3 ranged-scalar),
> syzkaller-güdümlü fuzzing değil. "0 anomali" doğru sonuçtur ama **henüz true-positive
> bir bulgu üretilmedi** (corpus temiz + verifier tutarlı). 0014 ile diff'in intrinsic
> invariant'ları artık gerçek ranged register-state'lerde koşuyor. Gerçek bug-avı hacmi
> için syzkaller-güdümlü execs sıradaki iş.

**(V5) Detektör kalibre — diff GERÇEK parser yolunda doğru bağırıyor**
```
$ cargo test -p pipeline --test diff_detector_calibration   → 3 passed
```
Gerçek harness bloğu → ingest→normalize(VerifierLogParser)→diff: temiz state → 0 bulgu
(susma); tek-karakter fault (`var_off=(0x0;0xff)`→`(0x1;0xff)`, malformed tnum) →
`tnum_malformed` yakalanır (doğru bağırma). "0 anomali" artık *kalibre dedektör* demek.

**(V6) Helper kolu kalibre — expected bir DOSYADAN, teste gömülü değil**
```
$ cargo run -q -p pipeline --example helper_provenance
  GROUND TRUTH file: data/groundtruth/helper_protos.tsv  -> arg0 expected = "map_ptr"
  fault-injected observed=scalar:  NO ground truth -> 0 finding;  with file -> 1 finding
  helper_arg_type_mismatch  expected="map_ptr" (FROM FILE)  observed="scalar" (FROM LOG)
```
`cargo test -p pipeline --test helper_calibration` → 3 passed. Karar dosyadan gelir:
dosyayı kaldır → bulgu kaybolur. Observed gerçek verifier log'undan; expected `bpf_func_proto`
diliminden (kaynak: kernel/bpf/helpers.c ARG_CONST_MAP_PTR). intrinsic (tnum) + helper —
her iki dedektör kolu gerçek yolda kalibre.

**(V7) Unparsed politikası — parser gürültüsü sinyalin DIŞINDA**
```
$ cargo run -q -p pipeline --example parse_health_demo -- <dir>
  SIGNAL   : divergences=0  flagged=0
  PARSE HEALTH (separate): records=2  with_notes=1  unparsed_blocks=2
     unparsed: headless (no RESULT), map_lookup (non-verifier RESULT)
     noted   : rec1 [unrecognized reg-type form: arena_ptr]
```
`cargo test -p pipeline --test unparsed_policy` → 4 passed. RESULT'sız/hatalı blok
ayrı `unparsed` kovasına gider (sahte accept'e dönüşmez); bilinmeyen reg-tipi → not;
ikisi de ASLA divergence olmaz. Gerçek 7-program sample temiz (0 unparsed/0 not).
Hacim gelince parser kör noktaları buraya düşer, sinyale değil.

**(V8) İLK SYZKALLER-GÜDÜMLÜ HACİMLİ PERIOD — canlı (VM boot eder, dakikalar)**
```
$ TIMEOUT=1200 cargo run -q -p orchestrator --example syz_period -- <dir>
  [syzreplay] captured 95 program block(s)
  HARVEST  period=1 exec_count=95
  RECORDS  70 (accept 35 / reject 35)
  SIGNAL   divergences=0  flagged=0
  PARSE HEALTH (separate)  records=70  with_notes=5  unparsed_blocks=25
  distinct verifier reject reasons (20): "BPF_EXIT uses reserved fields",
    "At program exit the register R0 has smin=... should have been in [0, 1]", ...
```
Kampanya: 900 sn gerçek fuzzing (corpus 54→254, coverage 0→7523 BB, 18k+ exec).
Hacim **5 parser kör noktası** çıkardı (verifier bug'ı değil) — hepsi parse-health'e
düştü, düzeltildi, regresyona sabitlendi (devlog 0018). Aynı veri VM'siz yeniden
analiz edilebilir: `cargo run -p pipeline --example parse_report -- <capture>`.

**(V9) SONUÇ: düzeltme-sonrası parser kör nokta oranı = %0; helper kolu uyanık**
```
$ cargo run -q -p pipeline --example parse_report -- crates/pipeline/tests/fixtures/volume/syz-replay-95.log
  BLOCKS   95 = 70 records + 25 unparsed
  PARSE HEALTH (separate, never signal)
    UNRECOGNIZED (parser blind-spots) : 0/70 = 0.0%   <-- must stay ~0
    not observed (verifier never ran) : 25            <-- expected, not a parser issue
    records with notes (lower confidence): 5
```
%26 "unparsed" iki kategoriyi karıştırıyordu; ayrıldı: **`unrecognized`** (parser
verilen çıktıyı okuyamadı = **0/70 = %0**) vs **`not_observed`** (verifier hiç
çalışmadı: EINVAL 12 / EFAULT 7 / E2BIG 6 = 25). Gerçek 95-bloklu yakalama
**commit'li fixture** + `volume_parse_health` (3 test) ile kilitli — oran artık
iddia değil invaryant. **Helper kolu**: proto dilimi 1→12 kontrat / 8 helper
(gerçek kernel kaynağı, satır referanslı) → aynı hacimde **112 gözlemin 51'i
kapsandı (%45), 45'i accept'te fiilen kontrol edildi** (öncesi: 0 = dormant),
**0 false positive**. Ayrıca **accept-only kapısı**: reddedilmiş programdaki
uyuşmazlık verifier'ın doğru çalışmasıdır, divergence sayılmaz.

**(V10) İKİ METRİK BÜYÜK ÖRNEKLEMDE — %0 korundu, dedektör kolu boşta değil**
```
$ cargo run -q -p pipeline --example parse_report -- crates/pipeline/tests/fixtures/volume/syz-replay-184.log
  RECORDS  151 (accept 72 / reject 79)
  SIGNAL   divergences=0  flagged=0
  CHECKS   helper-arg comparisons actually performed: 82   (0 findings out of 82 checks)
  BLOCKS   184 = 151 records + 33 unparsed
    UNRECOGNIZED (parser blind-spots) : 0/151 = 0.0%
```

| | capture #1 (95) | capture #2 (184) |
|---|---|---|
| kör nokta oranı | 0/70 = **%0** | 0/151 = **%0** |
| helper kontrolü yapıldı | 45 | **82** |
| farklı gerçek reject metni | 20 | **44** |

30 dk kampanya (corpus.db 75→127 KB). **(1)** Oran ~2x örneklemde **%0'da kaldı**
(tek örneklem şansı değil; her iki fixture da commit'li ve test ikisini birden koşar).
**(2)** Helper kolu **82 gerçek karşılaştırma** yaptı → "0 mismatch" = corpus/verifier
sağlam, kol uykuda değil. Payda artık `DiffSummary.helper_args_checked` olarak
raporun parçası; test `N ≥ 45` şartını kilitler.

**(V11) Proto dilimi artık ELLE değil AĞAÇTAN üretiliyor (OI-4 kapandı)**
```
$ cargo run -p pipeline --example extract_protos -- .lab/bpf-next data/groundtruth/helper_protos.tsv
  extracted 274 contracts across 194 helpers      (öncesi: elle 12 kontrat / 8 helper)
```
`helper_proto::extract_from_tree` `kernel/` + `net/` altındaki `bpf_func_proto`
tanımlarını tarar. **Çıkarım mekanik, eşleme yargı**: `SINGLE_FAMILY_ARG_TYPES`
tablosu küçük ve gözden geçirilebilir — bir arg yalnızca tek bir reg-tipi ailesine
sabitleniyorsa kontrat olur; `ARG_ANYTHING`/`ARG_PTR_TO_MEM*`/map-key/BTF **düşürülür**.
Doğrulama: elle yazılmış **12 kontratın 12'si** birebir üretildi, ve gerçek hacimde
**0 false positive** ile kontroller arttı (45→**52** ve 82→**101**). Ayrıca bir
**sessiz kayıp** hatası bulundu ve düzeltildi (`__weak` bildirimleri gerçek tanımı
yutuyordu → `bpf_tail_call` kayıptı); regresyon testi var.

**(V12) ÜÇÜNCÜ DEDEKTÖR KOLU: documented-behavior (kaynak 2) canlı**
```
$ cargo run -q -p pipeline --example harness_demo -- <dir>
  ground truth: 274 helper contracts, 3 documented cases (0 stale)
  CHECKS  helper-arg: 1  documented cases: 3
  divergences=0
```
`Documentation/bpf/verifier.rst` **kural çıkarılacak prose değil** — açık davranış
iddiaları içeriyor ("will be rejected, since R2 is unreadable…", "is a correct
program"), her biri örnek programın yanında. Bunlar **çalıştırılabilir**: programı
gerçek kernel'de koştur, kararı dokümanın dediğiyle karşılaştır.

**Köken disiplini (alıntı-çapa):** her vaka dokümanın **kendi cümlesini birebir**
taşır; `load()` alıntının hâlâ dosyada olduğunu **doğrular** — yoksa vaka **STALE**
olur ve **asla kullanılmaz**. Yani doküman değişirse kural sessizce bayatlamaz.

Gerçek bpf-next VM'inde üç vaka da dokümana uydu (`R2 !read_ok`, accept,
`R1 invalid mem access 'scalar'`). **6 kalibrasyon testi**: uyumda susar, çelişkide
bağırır, ground-truth yokken hiçbir şey demez (iddia dokümanda, checker'da değil),
drift edince susar.

**(V13) KAYNAK 4 (patch-diff): doküman-vs-kod bayatlığı ARTIK BİR RAKAM**
```
$ cargo run -q -p pipeline --example harness_demo -- <dir>
  doc-vs-code (source 4): documentation last changed 2025-09-18 (107e16979905),
  verifier.c last changed 2026-08-18 (a2e98481a639), 351 verifier.c commits since
```
Kaynak 2'nin yapısal zayıflığı: alıntı-çapa cümlenin **var olduğunu** korur, **doğru
olduğunu** değil. Kaynak 4 bunu **koddan** telafi ediyor: doküman ~11 ay / **351
verifier commit'i** geride. Bu kanıt bir documented divergence çıktığında bulgunun
`detail`'ine iliştiriliyor.

**Kapsam dürüstlüğü:** kaynak 4 **kendi başına bulgu üretmiyor** (tam cross-version
diff iki-revizyon gözlemi ister, lab tek sürüm derliyor) ve **hüküm vermiyor** —
"stale/bug/likely" gibi kelime içermemesi test edilerek zorlanıyor; karar insanın.
Git yoksa **sessiz** kalıyor (uydurma kanıt yok).

**Gönderilmeyen tasarım (ölçüm sonucu):** "verifier mesaj sözlüğü" kontrolü
denendi ve **ölçüldü**: 43 gözlenen reject metninin yalnız **%51'i** kernel
kaynağıyla eşleşti (mesajlar birden çok `verbose()` çağrısından birleşiyor) →
bulgu kaynağı olarak yarı yarıya gürültü olurdu, **gönderilmedi**. Ölçümün yan
ürünü: **yeni bir parser kör noktası** (`SCC enter` state-walk işaretçisi reject
gerekçesi sanılıyordu — *makul ama yanlış* veri; gerçek gerekçe
`R1 type=fp expected=map_ptr` idi). Kaynakta doğrulandı (`states.c:174`), düzeltildi,
regresyon testi eklendi.

**(V14) KAYNAK 2'NİN DAMARI ÖLÇÜLDÜ — prose tükendi, örnek bölümü işlenmedi (2026-08-30)**
```
$ grep -c '^Error::' .lab/bpf-next/Documentation/bpf/verifier.rst
11
$ grep -n -iE "will be rejected|is a correct program|the verifier will reject" \
      .lab/bpf-next/Documentation/bpf/verifier.rst
7 aday satır  (3'ü 0022'de kodlandı)
```
`verifier.rst` 560 satır ve içinde **iki ayrı damar** var; ikisi çok farklı değerde:

- **Prose iddiaları (0022'de kodlanan damar) — tükenmek üzere.** Dokümanın açıkça
  davranış iddia ettiği 7 aday cümleden **3'ü zaten kodlu**; geriye ~4 kalıyor, biri de
  `'secure' mode` koşullu. `OPEN-ITEMS.md`'nin "birkaç düzine yüksek-değerli invariant"
  hedefi bu damardan **karşılanamaz** — o beklenti düzeltilmeli.
- **"Understanding eBPF verifier messages" bölümü (satır 353–560) — işlenmemiş.**
  **11 örnek geçersiz program**, her biri **tam beklenen hata metniyle**:
  `unreachable insn 1`, `R2 !read_ok`, `invalid stack off=8 size=8`,
  `invalid indirect read from stack off -8+0 size 8`,
  `fd 0 is not pointing to valid bpf_map`, `R0 invalid mem access 'map_value_or_null'`,
  `misaligned access off 4 size 8`, `R0 invalid mem access 'imm'`,
  `Unreleased reference id=1` …

**Bu damar prose'dan üç nedenle güçlü:**
1. Programlar zaten `BPF_MOV64_REG(...)` **makro formunda** — `harness/diffharness.c`
   ile birebir aynı format, çeviri yargısı yok. (Mevcut 3 vaka pseudo-asm'den elle
   çevrilmişti; o çeviri gözden geçirilmesi gereken bir yargıydı.)
2. Beklenti accept/reject değil, **tam hata metni** — çok daha sıkı bir kontrat.
3. **11'inin hepsi reddedilmesi gereken program** → verifier'ın *sağlamlık* (soundness)
   yönünü test ediyorlar. Biri **accept** alırsa bu doğrudan gerçek bir soundness
   bug'ıdır; projenin aradığı en yüksek değerli sinyal budur.

**Hacim bu yüzeye ulaşmadı (ölçüldü).** 279 bloklu iki commit'li yakalamada dokümante
hata metinlerinden yalnız **2'si** göründü: `!read_ok` (3 kez) ve
`is not pointing to valid bpf_map` (9 kez). Diğer **6 sınıf hiç görülmedi**
(`unreachable insn`, `invalid stack off`, `invalid indirect read from stack`,
`invalid mem access`, `misaligned access`, `Unreleased reference id` — hepsi 0).
Görülen 2'si bu bölümün **bayat olmadığını** gösterir (OI-6 endişesini bu damar için
zayıflatır); görülmeyen 6'sı ise syzkaller corpus'unun ulaşamadığı **yeni tespit
yüzeyidir**.

**Vaka başına maliyet (ölçüldü):** `harness/diffharness.c:150-187` deseni — vaka başına
~8 satır C (insn dizisi + bir `run_one` çağrısı) + `verifier_rst.rs` içindeki
`DOCUMENTED_CASES` tablosunda ~6 satır Rust.

**Reviewer bunu şöyle sorgulamalı:** "11 vakanın tam hata metnini beklemek, dokümanın
351 commit geride olduğu bir yerde çok mu iddialı?" — evet, bu yüzden §6'daki tasarım
şartı: **karar** ile **mesaj** ayrı ağırlıkta.

**(V15) MESAJ DAMARI KODLANDI — 11 vaka, ilk soundness ölçümü (2026-09-01)**
```
$ cargo run -q -p pipeline --example harness_demo -- /tmp/vl-hd
ground truth: 274 helper contracts, 12 documented cases (0 stale, 1 superseded, 0 error-text drifted)
  SUPERSEDED doc_msg_uninit_stack_arg: ...CAP_PERFMON...
CHECKS  helper-arg: 2  documented cases: 12   NOTES (evidence, not verdicts): 5
PERIOD REPORT  records=20  flagged=0  divergences=0

$ cargo run -q -p pipeline --example parse_report -- harness/samples/bpf-next-sample.txt
BLOCKS   20 = 20 records + 0 unparsed
  UNRECOGNIZED (parser blind-spots) : 0/20 = 0.0%
```
V14'ün işaret ettiği damar işlendi: `verifier.rst:353-560`'taki **11 örnek program**
harness'e kodlandı (biri prose vakasının aynısı olduğu için **10 yeni program**;
toplam **13 dokümante vaka**). Sample yeniden yakalandı: **10 → 20 program**, taze
in-VM capture.

**Üç ağırlık, tek kanal değil** (tasarım şartı uygulandı):

| gözlem | sonuç | neden |
| --- | --- | --- |
| doküman reject der, verifier accept eder | **DIVERGENCE** | soundness sinyali |
| karar doğru, hata metni farklı | **NOTE** — `finding_count`'a girmez | doküman 351 commit geride; metin drift'i bug değil |
| kaynakta doğrulanmış önkoşul iddiayı geçersiz kılar | **SUPERSEDED** | aksi halde kalıcı sahte alarm |

**Ölçüm sonucu:** 12 vakanın **12'sinde karar uyuştu** → `divergences=0`. Hata
metinlerinin **5'i birebir tuttu**, **5'i sürüklenmiş** ve hepsi NOT olarak düştü
(`invalid stack off=8 size=8` → `invalid write to stack R10 off=8 size=8`;
`R0 invalid mem access 'imm'` → `'scalar'`; `misaligned access off 4 size 8` →
`misaligned value access off 0+4 size 8`; `Unreleased reference id=1, alloc_insn=7` →
`id=2 alloc_insn=7` ×2).

**Ve bir vaka ACCEPT aldı** — `doc_msg_uninit_stack_arg`. Susturulmadan önce gerekçe
**kaynakta** bulundu:
```
kernel/bpf/verifier.c:21141  env->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token);
include/linux/bpf.h:2869     return bpf_token_capable(token, CAP_PERFMON);
```
Dokümante red **yalnız yetkisiz yükleme için** geçerli; harness root ile yüklüyor.
Doküman bu koşulu söylemiyor → kusur dokümanda. Vaka silinmedi: o satır **çapa**
olarak kaydedildi, kernel gevşetmeyi kaldırırsa vaka kendiliğinden canlanır.

**Reviewer bunu şöyle sorgulamalı:** "susturma mekanizması, rahatsız edici bulguları
sessizce yok etmenin yolu olabilir mi?" — evet, bu yüzden **OI-7** açıldı: susturma
dosya+satır+birebir kod metni ister, her yüklemede yeniden doğrulanır, kaynak
okunamazsa **susturmaz**, ve susturulanlar gerekçesiyle raporlanıp denominatörden
düşülür. Ayrıca **OI-8**: 11 programın 3 yerinde doküman bir şeyi söylemiyor (map fd,
value_size, program tipi/flag) ve harness seçmek zorunda kaldı — ilk `doc_msg_*`
bulgusunda **ilk şüpheli o yargılardır**, verifier değil.

---

## 5. Lab ortamı + kritik ortam gerçekleri

| Bileşen | Konum | Kanıt |
|---|---|---|
| Self-built kernel | `.lab/build/bzImage` (41 MB) | rev `5e289c5a…`; BTF/bpffs/kcov VM-içi onaylı |
| Disposable rootfs | `.lab/images/rootfs.img` (2 GB) | isim-bağımsız ağ; harness enjekte edilebiliyor |
| syzkaller | `.lab/syzkaller/bin/*` + `manager.cfg` | derli; TCG'de KCOV-güdümlü fuzzing 0009'da kanıtlı |
| Harness binary | `harness/diffharness` (gitignore) | static; VM'de değişmeden koşar |

**KVM DURUMU (önemli; 2026-08-26, 08-28 ve 08-30'da tekrar probe edildi):** `/dev/kvm` node'u **var** (muhtemelen
kullanıcının BIOS update'i) **ama** `qemu -enable-kvm` hâlâ `No such device` →
nested-virt donanım katmanı kapalı → **her şey TCG** (yavaş). Kullanıcı Windows 11
geçişinden sonra KVM'i açmayı planlıyor. Son probe (2026-08-30): `/dev/kvm` node'u var
ama `grep -c -E '(vmx|svm)' /proc/cpuinfo` = **0** → CPU sanallaştırma bayrakları hiç
görünmüyor. Period=exec-count olduğu için loop mantığı etkilenmez, sadece duvar-saati.

---

## 6. Açık uçlar / sıradaki iş (dosya:satır)

**Ground-truth kaynaklarının güncel durumu (0021–0023 sonrası):**

| # | Kaynak | Durum | Dosya |
|---|---|---|---|
| 5 | Klasik mantıksal analiz (intrinsic tnum/bounds/JIT-interp) | ✅ canlı, kalibre | `diff.rs` |
| 3 | Helper `bpf_func_proto` | ✅ canlı — 274 kontrat / 194 helper | `groundtruth/helper_proto.rs` |
| 2 | Dokümante davranış (`verifier.rst`) | ✅ canlı — **13 vaka** (12 kontrol + 1 superseded); tavanı ~17 (ölçüldü) | `groundtruth/verifier_rst.rs` |
| 4 | patch-diff | 🟡 **kısmi** — kanıt üretir, bulgu üretmez | `groundtruth/patch_diff.rs` |
| 1 | `verifier.c` state-transition | ❌ **stub** (17 satır, `todo!()`) | `groundtruth/verifier_c.rs` |

**Sıradaki iş — ölçülmüş önceliklendirme (gerekçe: ✔ V15):**

1. ~~`verifier.rst` örnek bölümünü kodla — 11 vaka.~~ **YAPILDI (0024, ✔ V15).**
   3 → 13 vaka; syzkaller'ın hiç üretmediği 6 hata sınıfı artık üretiliyor; karar ile
   mesaj ayrı ağırlıkta (`notes` kanalı); ilk soundness ölçümü `divergences=0`.
   Kaynak 2'nin tavanı ölçüldü: ~4 prose iddiası kaldı, sonra **doküman bitiyor**.
2. **Kaynak 1 için pilot (ARTIK SIRADAKİ İŞ)** — tüm `verifier.c` değil, **tek bir geçiş ailesi**
   (ör. `check_alu_op` bounds güncellemesi) mekanik olarak çıkarılabilir mi? Amaç,
   5. kaynağın fizibilitesini tamamına yatırım yapmadan öğrenmek.
3. **OI-2** — syzkaller crash/coverage'ını pipeline'a bağla. Kanal gerçek, ama şu anki
   içeriği 2 crash ve ikisi de TCG-artefaktı şüphesi altında (OI-1) → KVM açılana kadar
   düşük öncelik, aksi halde kanal çoğunlukla gürültü besler.
4. **Altyapı borcu:** `vmctl` Rust wrapper (script yerine); **interpreter kernel** modu
   (JIT↔interp; `CONFIG_BPF_JIT_ALWAYS_ON=y` nedeniyle ayrı kernel gerekir);
   **istatistiksel scoring** (`python/.../scoring.py`); daha zengin harness corpus'u
   (pointer aritmetiği, map erişimi).

**OI-1** (crash artefaktı hipotezi) KVM açılana kadar **falsifiable ama test edilemez**.
**OI-7** (susturma = yanlış-negatif riski) ve **OI-8** (harness çeviri yargıları =
yanlış-pozitif riski) 0024 ile açıldı; ikisi de duran talimat, kusur değil.
Tam liste ve gerekçeler: `docs/OPEN-ITEMS.md`.

---

## 7. Reviewer doğrulama checklist'i (kopyala-çalıştır)

Hafif (VM/root gerekmez):
- **R1** `cargo build` → Finished. ✔ V1
- **R2** `cargo test` → **82 passed, 0 failed**. ✔ V1
- **R3** `just check-python` (ya da elle import) → `python import OK`.
- **R4** `cargo run -q -p pipeline --example report_demo -- /tmp/vl1` → `top_score=0.95`. ✔ V2
- **R5** `cargo run -q -p pipeline --example harness_demo -- /tmp/vl2` → 6 gerçek kayıt (3 ranged-scalar dahil), 0 anomali. ✔ V3
- **R6** `cargo test -p pipeline --test golden_normalize` → yeşil (parser-katmanı guardrail).
- **R7** Guardrail invaryantı: `crates/pipeline/src/diff.rs` içinde `anomaly_scores` okuması OLMADIĞINI teyit et.

Ağır (bpf-next VM boot eder; root + TCG, dakikalar):
- **R8** `sudo ./harness/... ` yerine host'ta `./harness/diffharness` (root) → 3 blok verifier log.
- **R9** `TIMEOUT=300 ./scripts/run-harness-vm.sh /tmp/out.log` → "captured 20 program block(s)"
  (in-VM authoritative capture; `harness/samples/bpf-next-sample.txt` ile karşılaştır).
- **R10** `TIMEOUT=220 cargo run -q -p orchestrator --example real_period -- /tmp/vlp` →
  `HARVEST ... PERIOD REPORT records=6 divergences=0`. ✔ V4
- **R11** `cargo test -p pipeline --test diff_detector_calibration` → 3 passed
  (dedektör kalibre: temizde susar, enjekte tutarsızlıkta `tnum_malformed`). ✔ V5
- **R12** `cargo test -p pipeline --test helper_calibration` → 3 passed; ve
  `cargo run -p pipeline --example helper_provenance` → expected FROM FILE, decision dosyaya bağlı. ✔ V6
- **R13** `cargo test -p pipeline --test unparsed_policy` → 4 passed; ve
  `cargo run -p pipeline --example parse_health_demo` → parse-health divergence'lardan ayrı. ✔ V7
- **R14** (ağır) `TIMEOUT=1200 cargo run -p orchestrator --example syz_period -- /tmp/vlsyz`
  → 70 kayıt, 20 gerçek reject metni, divergences=0, parse-health ayrı. ✔ V8
- **R15** `cargo test -p pipeline --test volume_parse_health` → 3 passed (unrecognized==0,
  sayılar mutabık); `cargo test -p pipeline --test helper_calibration` → 5 passed
  (dilim uyanık + false positive yok + accept-only kapısı). ✔ V9
- **R16** `cargo run -p pipeline --example parse_report -- crates/pipeline/tests/fixtures/volume/syz-replay-184.log`
  → 151 kayıt, unrecognized 0/151, **101 kontrol** (0021 sonrası), divergences=0. ✔ V10/V11
- **R17** `cargo test -p pipeline helper_proto` → 5 passed (inclusion rule, bildirim/tanım
  regresyonu, bayrak-niteleyici, commit'li dilim). ✔ V11
- **R18** `cargo test -p pipeline --test documented_behavior` → **12 passed**
  (susma/bağırma kalibrasyonu + köken + drift + kaynak-4 kanıtı). ✔ V12/V13/V15
- **R19** `cargo test -p pipeline groundtruth::patch_diff` → 4 passed (kanıt hüküm
  içermez, geçmiş yoksa sessizlik). ✔ V13
- **R20** R18'in içindeki 0024 testleri özellikle: yeniden yazılmış hata metni **not**
  üretir (bulgu değil, `finding_count=0`), yanlış karar **bulgu** üretir, superseded
  vaka hiç kontrol edilmez ve denominatöre girmez. ✔ V15
- **R21** `cargo test -p pipeline groundtruth::verifier_rst` → **7 passed**; kritik
  ikisi: kanıt yoksa **susturmaz**, önkoşul kalkarsa vaka **kendiliğinden canlanır**. ✔ V15
- **R22** `cargo run -q -p pipeline --example harness_demo -- /tmp/vl-hd` →
  `12 documented cases (0 stale, 1 superseded, ...)`, `NOTES: 5`, `divergences=0`;
  susturulan vakanın gerekçesi ekrana basılır. ✔ V15
- **R23** (ağır) `TIMEOUT=300 ./scripts/run-harness-vm.sh /tmp/out.log` →
  "captured 20 program block(s)"; `harness/samples/bpf-next-sample.txt` ile karşılaştır. ✔ V15

**Crash'ler hakkında (0020) — bulgu olarak SAYILMADI:** 30 dk'lık kampanya 2 crash
üretti (`int3 in sk_filter_trim_cap`, `int3 in __seccomp_filter`). Teşhis: her ikisinin
RIP'i `filter.h:763` = `static_branch_unlikely(&bpf_stats_enabled_key)`; crash'ler
fuzzer'ın programlarında değil alakasız sistem süreçlerinde (udev/seccomp); syzkaller
`bpf$ENABLE_STATS` ile bu key'i flip ediyor → int3-tabanlı text patching →
`-accel tcg,thread=multi` altında eşzamanlı yürütme. Yani **emülasyon artefaktı olması
muhtemel, verifier logic bug'ı değil**.

**Ama statü "kapandı" DEĞİL, askı maddesi.** İki nüans: (a) `repro=false` hipotezi
*destekler ama kanıtlamaz* — gerçek yarış-koşullu kernel bug'ları da non-deterministiktir;
(b) falsifying test (**KVM/bare-metal'de tekrar**) şu an **koşulamıyor** (KVM bloklu,
2026-08-28 probe: `vmx/svm` = 0). Yani hipotez **falsifiable ama test edilmemiş**.
Açık/düşük-öncelikli olarak `docs/OPEN-ITEMS.md` **OI-1**'de izleniyor (falsifying test,
güç uyarısı ve KVM'siz kısmi testlerin neden koşulmadığı orada). Reviewer bu teşhisi
sorgulamalı.

**Reviewer'ın özellikle sorgulaması istenen iddialar (şüphe listesi):**
1. "İlk gerçek period çalışıyor" → evet ama **sabit corpus**, syzkaller-fuzzing değil
   (§4 notu). Abartı mı, dürüst mü?
2. "0 anomali doğru" → **KAPANDI (0014→0015).** diff'in intrinsic invariant'ları GERÇEK
   ranged register-state'lerde koşuyor, VE dedektör gerçek parser yolunda **kalibre**:
   temizde susar, enjekte malformed-tnum'da `tnum_malformed` diye bağırır
   (`diff_detector_calibration`, ✔ V5). Yani "0 anomali" artık *sağır dedektör* değil.
   (Gerçek bir verifier bug'ı hâlâ yüzeye çıkmadı — beklenen: corpus temiz + kernel doğru.)
3. **Parser** — **Güncelleme (0014→0016):** full `scalar(...)` VE **helper-call arg
   reg-tipleri** (`map_ptr`, `fp`/PTR_TO_STACK) artık GERÇEK bpf-next verisinde parse edilip
   test ediliyor (`map_lookup`). Ayrıca **helper kolu kalibre**: expected bir DOSYADAN
   (`bpf_func_proto` dilimi) yükleniyor, teste gömülü değil (✔ V6). Bu şüphe artık kapalı.
4. **JIT↔interp ertelendi** (`CONFIG_BPF_JIT_ALWAYS_ON=y` → tek kernel'de imkânsız).
   Bu kısıt doğru teşhis mi?
5. **`run-harness-vm.sh`** loop-mount + `-snapshot` + seri-parse: sağlam mı, kırılgan mı?

---

## 8. Devlog haritası (derin dalış)

`docs/devlog/devlog.md` — her entry: Ne/Neden/Tasarım kararları/Kapsam dışı/Doğrulama/Dosyalar/Sonraki.

| # | Konu | Durum |
|---|---|---|
| 0001–0007 | contract → ingest → loop spine → normalize → score → diff → report | Pipeline uçtan uca ✅ |
| 0008 | Gerçek kernel/VM bring-up | ✅ (TCG; KVM bloklu) |
| 0009 | syzkaller entegrasyonu + VM ağ düzeltmesi | ✅ (TCG'de fuzzing) |
| 0010 | Golden fixture (parser-katmanı guardrail) + git init | ✅ |
| 0011 | Differential/verifier-log harness v0 (guest-side C) | ✅ (JIT↔interp ertelendi) |
| 0012 | `VerifierLogParser` + gerçek veri uçtan uca | ✅ |
| 0013 | Gerçek `FuzzDriver` + **ilk gerçek period canlı** | ✅ |
| 0014 | Harness zenginleştirme (ranged-scalar) + full-scalar path gerçek veride | ✅ |
| 0015 | Detektör kalibrasyonu (intrinsic): diff true-positive gerçek yolda | ✅ |
| 0016 | Helper kolu: file-loaded `bpf_func_proto` + helper true-positive | ✅ |
| 0017 | Unparsed politikası (parser kör noktaları ayrı kova; rapor ayrı gösterir) | ✅ |
| 0018 | **İlk syzkaller-güdümlü hacimli period** + hacmin çıkardığı 5 parser kör noktası | ✅ |
| 0019 | Kör nokta oranı **%0** ölçüldü + proto dilimi 8 helper'a genişledi (helper kolu uyandı) | ✅ |
| 0020 | 2. hacimli period (2x corpus): %0 korundu, **82 helper kontrolü** + crash teşhisi | ✅ |
| 0021 | `bpf_func_proto` **auto-extraction**: 12→274 kontrat, 8→194 helper (OI-4 kapandı) | ✅ |
| 0022 | **Üçüncü kol**: documented-behavior (`verifier.rst`), alıntı-çapalı + drift-tespitli | ✅ |
| 0023 | **patch-diff (kaynak 4)**: doküman-vs-kod bayatlık kanıtı + SCC parser kör noktası | ✅ |

---

## 9. Tek cümlelik doğrulanabilir durum ifadesi

> "verifierloop'un beş-stage'li pipeline'ı ve loop'u, kendi derlediğimiz bpf-next
> kernel'inden gelen **gerçek verifier verisiyle uçtan uca canlı koşuyor**; hacim açık
> (syzkaller corpus'u → shim → `log_level=2` → period) ve iki kampanya **commit'li
> regresyon fixture'ı** olarak sabitlendi (95 ve 184 blok).
> Beş ground-truth kaynağının **üçü canlı** (intrinsic invariant'lar; ağaçtan
> **auto-extract edilen** 274 helper kontratı / 194 helper; `verifier.rst`'ten
> **13 alıntı-çapalı** dokümante vaka), **biri kısmi** (patch-diff: bulgu değil kanıt
> üretir), **biri stub** (`verifier.c` state-transition).
> Ölçülen sayılar: **parser kör nokta oranı %0** (0/70, 0/151 ve 0/20), koşu başına
> **~101 helper kontrolü** ve **12 dokümante vaka kontrolü**, **0 false positive**,
> **82 test** yeşil.
> Üç dedektör kolu da gerçek yolda **kalibre** (temizde susar, enjekte tutarsızlıkta
> bağırır) ve parser kör noktaları **ayrı kanalda** raporlanıyor — bu yüzden
> `divergences=0` *temiz* okunur, *sağır* değil.
> **İlk sağlamlık (soundness) ölçümü yapıldı:** reddedilmesi gereken 12 dokümante
> programın 12'sinde de karar dokümanla uyuştu; 5 hata metni birebir tuttu, 5'i
> sürüklendi ve **kanıt** olarak düştü, **hüküm** olarak değil.
> **Gerçek bir verifier bug'ı henüz yüzeye çıkmadı** (beklenen) — çıkan tek
> karar-mismatch'inin gerekçesi kaynakta bulundu ve kusur **dokümanda** çıktı
> (yetkili yüklemede `allow_uninit_stack`; doküman koşulu söylemiyor).
> **Eksik olan:** kaynak 1 (`verifier.c`) stub — artık **tek** stub; kaynak 2'nin
> tavanı ölçüldü (~17 vaka, ~4 kaldı); kaynak 4 kısmi (iki-revizyon gözlemi
> gerekiyor); JIT↔interp cross-kernel modu; istatistiksel scoring; ve **KVM host-side
> bloklu → her şey TCG'de**.
> **Sıradaki iş:** kaynak 1 için **tek geçiş ailesi pilotu** (ör. `check_alu_op`
> bounds) — tamamına yatırım yapmadan fizibiliteyi ölçmek."
