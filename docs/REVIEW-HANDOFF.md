# verifierloop — Review / Handoff Context Raporu

> **Bu belgenin amacı.** Projenin **şu ana kadar nereye geldiğini** bağımsız bir
> gözden geçiren (başka bir Claude ya da bir insan) için **iddia değil,
> doğrulanabilir kanıt** biçiminde toplar. Her önemli iddianın yanında **(a)
> nerede bakılır, (b) hangi komut çalıştırılır, (c) "geçti" ne demek** verilir.
> Reviewer'ın görevi: bu iddiaları kendi eliyle koşup teyit etmek ve
> **abartılmış/yanlış** olanları işaretlemek.
>
> - **Rapor tarihi:** 2026-08-27
> - **Repo kökü:** `/home/tylersec/verifierloop` — **git deposu** (branch `main`,
>   8 commit: `bf506f1`…HEAD)
> - **Kernel rev (hedef):** `5e289c5a4a526e870efac0ca658635c47138593a` (`.lab/kernel.rev`)
> - **Son devlog entry'si:** `0019` — `docs/devlog/devlog.md`

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

**Güncelleme (0018): hacim açıldı.** Artık syzkaller'ın kendi corpus'u (900 sn'lik
gerçek kampanya) bir shim ile `log_level=2` verifier log'una çevrilip period olarak
koşuyor: **70 kayıt, 20 farklı gerçek reject metni, 0 divergence** (✔ V8).

**Reviewer'ın en çok şüpheyle bakması gereken nokta:** hacim **gerçek bir verifier
bug'ı üretmedi** — beklenen sonuç (gerçek kernel + coverage-güdümlü corpus), ve
dedektörün her iki kolu kalibre olduğu için bu "sağır" değil "temiz" okunur. Ayrıca
hacmin ilk çıkardığı şey **5 parser kör noktasıydı**, verifier bug'ı değil — hepsi
parse-health'e düştü, sinyale karışmadı, düzeltildi ve regresyona sabitlendi.
**Güncelleme (0019):** hacmin "%26 unparsed" sayısı ölçüldü — gerçek parser kör
nokta oranı **%0** (25'in tamamı "verifier hiç çalışmadı"), ve **helper kolu
uyandırıldı** (dilim 8 helper'a genişledi: %45 kapsam, 45 fiili kontrol, 0 false
positive). Bkz ✔ V9.

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
`docs/eBPF ... Mimari ...md` (tasarım), `docs/devlog/devlog.md` (0001–0019).

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
| **diff** | documented-vs-observed | intrinsic invariant'lar (tnum/bounds/JIT-interp) + helper oracle | dış loader'lar (verifier.c/rst/patch) |
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
$ cargo test    → 52 passed, 0 failed
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

---

## 5. Lab ortamı + kritik ortam gerçekleri

| Bileşen | Konum | Kanıt |
|---|---|---|
| Self-built kernel | `.lab/build/bzImage` (41 MB) | rev `5e289c5a…`; BTF/bpffs/kcov VM-içi onaylı |
| Disposable rootfs | `.lab/images/rootfs.img` (2 GB) | isim-bağımsız ağ; harness enjekte edilebiliyor |
| syzkaller | `.lab/syzkaller/bin/*` + `manager.cfg` | derli; TCG'de KCOV-güdümlü fuzzing 0009'da kanıtlı |
| Harness binary | `harness/diffharness` (gitignore) | static; VM'de değişmeden koşar |

**KVM DURUMU (önemli, probe edildi 2026-08-26):** `/dev/kvm` node'u **var** (muhtemelen
kullanıcının BIOS update'i) **ama** `qemu -enable-kvm` hâlâ `No such device` →
nested-virt donanım katmanı kapalı → **her şey TCG** (yavaş). Kullanıcı Windows 11
geçişinden sonra KVM'i açmayı planlıyor. Period=exec-count olduğu için loop mantığı
etkilenmez, sadece duvar-saati.

---

## 6. Açık uçlar / sıradaki iş (dosya:satır)

1. **Hacmi tekrar aç** — parser oturdu (%0 kör nokta) ve helper kolu uyandı (%45
   kapsam), yani daha uzun bir kampanya artık her iki kolu da çalışır halde koşar.
   *(0019 sırası tamamlandı: parser doğrulandı → dilim genişledi → sıra hacimde.)*
   Ayrıca `bpf_func_proto` **auto-extraction** (dilim hâlâ curated) ve syzkaller
   coverage/crash → DERIVED hâlâ ayrı işler.
2. **Daha zengin harness corpus'u** (`harness/diffharness.c`) — pointer aritmetiği,
   helper çağrıları, map erişimi → gerçek helper `arg_type` + register-state sinyali.
3. **Dış ground-truth loader'ları** — `crates/pipeline/src/groundtruth/*.rs`
   (verifier.c/rst/patch; `.lab/bpf-next` yerel).
4. **`vmctl`** Rust wrapper (script yerine); **interpreter kernel** modu (JIT↔interp,
   ALWAYS_ON nedeniyle ayrı kernel gerekir); **istatistiksel scoring** (`python/.../scoring.py`).

---

## 7. Reviewer doğrulama checklist'i (kopyala-çalıştır)

Hafif (VM/root gerekmez):
- **R1** `cargo build` → Finished. ✔ V1
- **R2** `cargo test` → **52 passed, 0 failed**. ✔ V1
- **R3** `just check-python` (ya da elle import) → `python import OK`.
- **R4** `cargo run -q -p pipeline --example report_demo -- /tmp/vl1` → `top_score=0.95`. ✔ V2
- **R5** `cargo run -q -p pipeline --example harness_demo -- /tmp/vl2` → 6 gerçek kayıt (3 ranged-scalar dahil), 0 anomali. ✔ V3
- **R6** `cargo test -p pipeline --test golden_normalize` → yeşil (parser-katmanı guardrail).
- **R7** Guardrail invaryantı: `crates/pipeline/src/diff.rs` içinde `anomaly_scores` okuması OLMADIĞINI teyit et.

Ağır (bpf-next VM boot eder; root + TCG, dakikalar):
- **R8** `sudo ./harness/... ` yerine host'ta `./harness/diffharness` (root) → 3 blok verifier log.
- **R9** `TIMEOUT=220 ./scripts/run-harness-vm.sh /tmp/out.log` → "captured 6 program block(s)"
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

---

## 9. Tek cümlelik doğrulanabilir durum ifadesi

> "verifierloop'un **beş-stage'li pipeline'ı** ve **loop'u**, kendi derlediğimiz
> bpf-next kernel'inden gelen **gerçek verifier verisiyle uçtan uca canlı koşuyor**;
> **hacim açık**: syzkaller'ın kendi corpus'u (900 sn gerçek kampanya) bir shim ile
> `log_level=2` verifier log'una çevrilip period olarak koşuyor (`syz_period`:
> 70 kayıt, **20 farklı gerçek reject metni**, 0 divergence; 52 test geçer).
> Düzeltme-sonrası **parser kör nokta oranı %0** (0/70; kalan 25 blok "verifier hiç
> çalışmadı") ve **helper kolu uyanık** (8 helper'lık `bpf_func_proto` dilimi,
> %45 kapsam, 0 false positive).
> Dedektörün **her iki kolu** (intrinsic tnum + file-loaded `bpf_func_proto`) gerçek
> yolda kalibre, ve **parser kör noktaları ayrı kanalda** raporlanıyor (hacmin
> çıkardığı 5 kör nokta düzeltildi). **Eksik olan**: proto dilimini hacimde gözlenen
> `bpf_func_proto` **auto-extraction** (dilim curated), `verifier.c`/`verifier.rst`/
> patch-diff loader'ları, JIT↔interp cross-kernel modu ve **daha uzun hacim**;
> **KVM host-side bloklu, TCG çalışır**; **gerçek bir verifier bug'ı henüz yüzeye
> çıkmadı** (beklenen)."
