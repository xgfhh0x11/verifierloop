# verifierloop — Review / Handoff Context Raporu

> **Bu belgenin amacı.** Bu rapor, projenin **şu ana kadar nereye geldiğini**
> bağımsız bir gözden geçiren (başka bir Claude ya da bir insan) için
> **iddia değil, doğrulanabilir kanıt** biçiminde toplar. Her önemli iddianın
> yanında **(a) nerede bakılır, (b) hangi komut çalıştırılır, (c) "geçti" ne
> demek** verilir. Reviewer'ın görevi: bu iddiaları kendi eliyle koşup teyit
> etmek ve **abartılmış/yanlış** olanları işaretlemek.
>
> - **Rapor tarihi:** 2026-08-26
> - **Repo kökü:** `/home/tylersec/verifierloop` (git deposu **değil** — sürüm
>   kontrolü yok; devlog + bu rapor kalıcı hafızadır)
> - **Kernel rev (hedef):** `5e289c5a4a526e870efac0ca658635c47138593a` (`.lab/kernel.rev`)
> - **Son devlog entry'si:** `0009` (syzkaller entegrasyonu) — `docs/devlog/devlog.md`

---

## 0. Reviewer için 60 saniyelik özet

**verifierloop**, `bpf-next` çekirdeğindeki **eBPF verifier**'ın *mantık
hatalarını* avlamak için tasarlanmış operasyonel bir araştırma döngüsüdür
(kendi lab'ında, kendi derlediği kernel'de, tek-kullanımlık QEMU VM'lerde —
**yetkili/savunma amaçlı güvenlik araştırması**). İki kol var:

1. **Yazılım pipeline'ı (Rust ⇄ Python):** `ingest → normalize → score → diff →
   report`. **Beş stage de kod olarak yazılı ve uçtan uca koşuyor.** Ama şu an
   **sentetik/örnek veriyle** koşuyorlar — gerçek kernel çıktısını parse eden
   gerçek parser'lar, gerçek VM sürücüsü ve dış ground-truth loader'ları **henüz
   TODO**. Yani: **stage mantığı gerçek, stage'lere akan veri henüz sahte.**
2. **Lab ortamı (kernel + VM + fuzzer):** self-built `bpf-next` bzImage,
   disposable Debian rootfs ve **syzkaller** kuruldu; syzkaller **TCG üzerinde
   gerçek kernel'imizde fiilen fuzzing yapıyor** (KCOV feedback dahil). **KVM
   kapalı** (WSL2 host'ta nested-virt yok) → her şey TCG'de (yavaş ama çalışır).

**İki kol henüz birbirine bağlı değil.** Kritik boşluk tam da bu: syzkaller'ın
gerçek çıktısı henüz pipeline'a akmıyor (parser + FuzzDriver eksik).

**Reviewer'ın en çok şüpheyle bakması gereken nokta:** "pipeline çalışıyor"
iddiası **doğru ama dar** — gerçek verifier verisiyle değil, `*_demo.rs`
içindeki elle yazılmış örneklerle çalışıyor. Bu bilinçli bir iskelet kararı,
gizlenmiş bir eksik değil (aşağıda §4 ve §6'da açıkça işaretli).

---

## 1. Ne olduğu — ve ne OLMADIĞI (kapsam sözleşmesi)

**Olan:**
- Kendi kapalı-döngü avlama hattı: fuzz → gözlem → normalize → skorla →
  ground-truth ile diffle → insana triyajlı batch ver → tekrar.
- "Period" = **exec sayısı** (bir sayaç), **zaman değil**. Wall-clock yalnızca
  veriye basılan bir etikettir, asla durma kriteri değildir.

**Olmayan (kapsam dışı — reviewer bunları "eksik" diye işaretlememelidir):**
- **Formal ispat / theorem-prover yok.** "Ground truth" formal bir model değil;
  dokümantasyon + patch diff'leri + klasik mantıksal analizdir.
- Entegre edilecek **harici bir motor yok.** Döngü kendi üzerine kapanır.
- İskelet turunda belirtilmeyen her şey ad-hoc karar yerine **TODO** bırakılmıştır.

**Kaynak belgeler:** `README.md` (iskelet + mevcut durum anlatısı),
`docs/eBPF Verifier Logic Bug Hunt — Mimari ve Mühendislik Prensipleri.md`
(tasarım prensipleri), `docs/devlog/devlog.md` (0001–0009 implementasyon kaydı).

---

## 2. Mimari ve dil sınırı

İki dil, **tek bir tipli dosya-tabanlı JSON sözleşmesinde** buluşur (paylaşılan
process belleği yok):

- **Rust** — mimari, orkestrasyon, döngü runtime'ı, VM kontrolü, pipeline stage'leri.
- **Python** — istatistik, veri işleme, anomali skorlama.
- **Sınır** — `contract` crate'i (Rust) ↔ `python/.../contract.py`. Rust
  orchestrator normalize-metrik artifact'ını period dizinine yazar, Python
  analizörü çağırır, skorları geri okur. **İkisi lockstep tutulmalı.**

**Workspace crate haritası** (`Cargo.toml`):

| Crate | Sorumluluk | Durum |
|---|---|---|
| `metrics` | 4 metrik-şema grubu (core/derived/counterfactual/expectation) | CORE donduruldu; diğerleri minimal + TODO |
| `contract` | Rust↔Python JSON artifact sözleşmesi (dil sınırı) | Implemente + testli |
| `pipeline` | Period pipeline stage'leri (modüller) + ground-truth adaptörleri | 5 stage implemente; parser/loader TODO |
| `vmctl` | Disposable QEMU VM kontrolü (KVM primary / TCG fallback) | İskelet; qemu-child/ssh/monitor TODO |
| `orchestrator` | Döngü runtime'ı (binary); confirmation-bias guardrail'ini barındırır | Spine implemente; gerçek FuzzDriver TODO |

**Python paketi** (`python/src/verifierloop_analysis/`): `contract.py`,
`scoring.py`, `__main__.py` + `schemas/{core,derived,counterfactual,expectation,
normalized,diff,report}.py`. Runtime bağımlılığı yok (bare interpreter'da import
olsun diye; numpy/scipy `TODO`).

---

## 3. Pipeline durumu — stage stage (KANIT ile)

```
ingest ✅ → normalize ✅ → score ✅ → diff ✅ → report ✅ → (human-in-the-loop)
          (parser TODO)   (istatistik TODO)  (dış-kaynak loader TODO)
```

| Stage | Ne yapar | Gerçekten yapılan | Hâlâ TODO | Ana dosya |
|---|---|---|---|---|
| **ingest** | Her aracın DEFAULT native çıktısını **değiştirmeden** `raw/`'a toplar, `RAW_INDEX` yazar | Toplama + indeksleme + hash | (hash SHA-256'ya geçebilir) | `crates/pipeline/src/ingest.rs` |
| **normalize** | Ham blob'ları dondurulmuş CORE şemasına çevirir, `NORMALIZED` yazar | Enjekte edilebilir `RecordParser` arayüzü + CORE şema | **Gerçek per-tool parser'lar** (`UnimplementedParser`) | `crates/pipeline/src/normalize.rs:59` |
| **score** | Rust, Python analizörüne contract üzerinden delege eder, `ANOMALY_SCORES` okur | Rust↔Python çağrısı + `baseline-hard-signals-v0` şeffaf skorlayıcı | **İstatistiksel skorlama** | `crates/pipeline/src/score.rs`, `python/.../scoring.py` |
| **diff** | Gözlemi ground-truth ile karşılaştırır, `DIFF_FINDINGS` yazar. Şiddet ATAMAZ (diff durum bildirir, score sıralar) | 2 tür: **intrinsic logical invariants** (tnum iyi-biçimlilik, bound sırası, tnum/bounds tutarlılık, JIT↔interp denklik) + enjekte edilebilir **GroundTruth oracle** (helper arg_type) | **Dış loader'lar**: verifier.c / verifier.rst / patch-diff | `crates/pipeline/src/diff.rs`, `crates/pipeline/src/groundtruth/` |
| **report** | `ANOMALY_SCORES` ⋈ `DIFF_FINDINGS` join'leyip **mevcut** skora göre sıralı triyaj batch'i (`PERIOD_REPORT`) üretir | Join + sıralama; yeni skor/şiddet İCAT ETMEZ | — (pipeline uçtan uca tamam) | `crates/pipeline/src/report.rs` |

**Kritik tasarım invaryantı (reviewer teyit etmeli):** `diff` asla
`ANOMALY_SCORES`'u okumaz (score ranks / diff states / report assembles ayrımı).
Bu, confirmation-bias guardrail'inin bir parçası.

---

## 4. Bizzat KOŞULMUŞ doğrulamalar (2026-08-26, ilk elden çıktı)

Aşağıdakiler bu raporu yazarken fiilen çalıştırıldı; çıktı özetleri gerçektir.

**(V1) Rust workspace derleniyor**
```
$ cargo build
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.78s      ✅
```

**(V2) Rust testleri geçiyor — 22 unit test**
```
$ cargo test
contract:     5 passed; 0 failed
orchestrator: 4 passed; 0 failed
pipeline:    13 passed; 0 failed
metrics/vmctl/main: 0 test (kasıtlı — bunlar şema/iskelet)               ✅ toplam 22 passed, 0 failed
```

**(V3) Python paketi bare interpreter'da import oluyor**
```
$ python3 -c "import sys; sys.path.insert(0,'python/src'); import verifierloop_analysis, verifierloop_analysis.contract, verifierloop_analysis.schemas; print('python import OK')"
python import OK                                                            ✅
```

**(V4) TÜM pipeline uçtan uca — gerçek Python skorlaması ile**
`report_demo` beş stage'i tek komutta koşar (ingest→normalize→score[gerçek
Python]→diff→report):
```
$ cargo run -q -p pipeline --example report_demo -- <base_dir>
wrote .../periods/1/anomaly_scores.json (flagged=1/2, method=baseline-hard-signals-v0)
PERIOD REPORT  exec_count=4200  records=2  flagged=1  divergences=3  top_score=0.95
triage (score DESC):
  rec1 score=0.95 reasons=["jit/interp retval divergence (jit=1 interp=0)",
       "helper arg_type violation: bpf_map_lookup_elem arg1 expected PTR_TO_MAP_KEY observed SCALAR_VALUE"]
      - [LogicalInvariant] tnum_malformed
      - [LogicalInvariant] jit_interp_divergence
      - [HelperProto]      helper_arg_type_mismatch
  rec0 score=0 reasons=[] divergences=0                                     ✅
```
Üretilen artifact'lar (6): `raw/index.json`, `raw/syzkaller/verifier.log`,
`normalized_metrics.json`, `anomaly_scores.json`, `diff_findings.json`,
`period_report.json`.

> **⚠️ Reviewer dikkat:** V4'teki veri **`report_demo.rs` içindeki elle yazılmış
> örnektir** (bilerek malformed tnum + JIT/interp sapması + helper ihlali içeren
> kurgusal kayıtlar). Bu, **stage mantığının** (skorlama, invariant tespiti,
> join, sıralama) doğru çalıştığını kanıtlar — **gerçek verifier verisinin
> aktığını kanıtlamaz.** Gerçek veri akışı bilinçli olarak §6'daki TODO'lara
> bağlıdır.

---

## 5. Lab ortamı — diskteki kanıt (0008 + 0009)

Aşağıdakiler `.lab/` altında fiilen mevcut (`ls` ile teyit edildi; `.lab`
gitignore'lu, ağır artifact'ler):

| Bileşen | Konum | Kanıt |
|---|---|---|
| Self-built kernel | `.lab/build/bzImage` | 41 MB, rev `5e289c5a…`; BTF/bpffs/kcov **VM içinde** onaylı (`.lab/verify-serial.log`) |
| Disposable rootfs | `.lab/images/rootfs.img` | 2 GB Debian; **isim-bağımsız ağ** (systemd-networkd wildcard) yamalı |
| VM ssh anahtarları | `.lab/images/vm-id_ed25519{,.pub}` | mevcut |
| syzkaller host bin'leri | `.lab/syzkaller/bin/` | `syz-manager`, `syz-repro`, `syz-mutate`, `syz-db`, … |
| syzkaller target bin'leri | `.lab/syzkaller/bin/linux_amd64/` | `syz-executor`, `syz-execprog` |
| Üretilmiş manager config | `.lab/syzkaller/manager.cfg` | TCG, `enable_syscalls:["bpf*"]`, count=4 |

**syzkaller'ın fiilen fuzzing yaptığının kanıtı (0009'dan, 5 dk'lık koşu):**
`Coverage: enabled` + `ExtraCoverage: enabled` (KCOV feedback), `syscalls:
44/8300` (bpf odağı), ısınma sonrası `exec total 44→1207`, `coverage 0→5177 BB`,
`corpus 2→45` → **~40–45 exec/sn (4 VM, TCG)**. KVM'de ~10–20x daha hızlı olurdu.

**Ortam kısıtı (önemli):** WSL2 host'ta **KVM yok** — `-enable-kvm` şu an
başarısız (`Hyper-V: Nested features: 0x0`), `.wslconfig`'te
`nestedVirtualization=true` olmasına rağmen. Politika: TCG yalnızca yavaş yol;
loop mantığı etkilenmez çünkü period = exec-count. KVM'i açmak host-side bir
işlem (Windows'ta `wsl --shutdown`, host bir VM ise VT-x/EPT expose).

> **Not:** syzkaller/VM koşusunu bu raporu yazarken **yeniden koşmadım** (5+ dk
> ve TCG); yukarıdaki throughput rakamları 0009'un kaydından gelir. Reviewer
> isterse §7-R6 ile yeniden üretebilir. Şu an **hiçbir fuzzer/VM çalışmıyor** ve
> `data/` boş (henüz gerçek period koşulmadı).

---

## 6. Açık uçlar / TODO sınırları (dosya:satır)

Bunların hepsi **bilinçli iskelet sınırlarıdır**, gizli hata değil:

1. **Gerçek `RecordParser`** — syzkaller native çıktısı (verifier log / KCOV) →
   CORE şeması. `crates/pipeline/src/normalize.rs:59` (`UnimplementedParser`).
2. **Gerçek `FuzzDriver`** — şu an `MockDriver` var; gerçek olan vmctl → syzkaller
   manager'ı sürüp exec sayacını period N'e bağlamalı.
   `crates/orchestrator/src/driver.rs:45`, `crates/orchestrator/src/loop_runtime.rs:167`.
3. **`vmctl`** — qemu child handle + ssh/monitor endpoint'leri sonlandırılmalı.
   `crates/vmctl/src/lib.rs:18`, `kvm.rs:7`, `tcg.rs:10`.
4. **Dış ground-truth loader'ları** (artık `.lab/bpf-next` yerel olduğundan
   yazılabilir): `crates/pipeline/src/groundtruth/{verifier_c,verifier_rst,
   helper_proto,patch_diff}.rs`.
5. **İstatistiksel skorlama** — `baseline-hard-signals-v0` yerine gerçek
   istatistik. `python/.../scoring.py`.
6. **DERIVED / COUNTERFACTUAL** metrik şemaları zenginleştirilmeli.
   `crates/metrics/src/{derived,counterfactual}.rs`.

**En doğal sıradaki iş (0010 adayı):** #1 (parser) + #2 (FuzzDriver) — bu ikisi
lab kolunu yazılım koluna **fiilen bağlar**; ondan sonra ilk gerçek period koşar.

---

## 7. Reviewer doğrulama checklist'i (kopyala-çalıştır)

Her madde bağımsız koşulabilir. "Geçti" kriteri yanında.

- **R1 — Derleme:** `cargo build` → `Finished` (hata yok). ✔ V1
- **R2 — Testler:** `cargo test` → `0 failed` (22 passed). ✔ V2
- **R3 — Python import:** `just check-python` → `python import OK`. ✔ V3
- **R4 — Uçtan uca pipeline:**
  `cargo run -q -p pipeline --example report_demo -- /tmp/vl-review`
  → `PERIOD REPORT ... top_score=0.95 ... divergences=3`, 6 artifact üretilir. ✔ V4
- **R5 — Guardrail invaryantı:** `crates/pipeline/src/diff.rs` içinde
  `ANOMALY_SCORES`/`anomaly_scores` okuması OLMADIĞINI teyit et; guardrail
  metni `crates/orchestrator/src/loop_runtime.rs` yorumunda duruyor mu?
- **R6 — (Ağır, opsiyonel) Fuzzer:** `DURATION=300 just run-fuzzers` → syz-manager
  4 VM açar, `Coverage: enabled`, corpus/coverage artar. (~5+ dk, TCG.)
- **R7 — Contract lockstep:** `crates/contract/src/lib.rs` ↔
  `python/.../contract.py` şema-versiyon/alanları eşleşiyor mu?
  `cargo run -p contract --example interop` round-trip'i koşar.
- **R8 — Lab artifact'leri var mı:** `ls -la .lab/build/bzImage
  .lab/images/rootfs.img .lab/syzkaller/bin/syz-manager .lab/syzkaller/manager.cfg`.

**Reviewer'ın özellikle sorgulaması istenen iddialar (şüphe listesi):**
1. "Pipeline çalışıyor" → **evet ama sentetik veriyle** (R4 notu). Gerçek kernel
   verisi henüz akmıyor (§6 #1–#2). Bu abartı mı, dürüst mü?
2. "diff, klasik mantıksal analizi yapıyor" → intrinsic invariant'lar
   (`diff.rs`) gerçekten tnum/bound/JIT-interp mantığını mı uyguluyor, yoksa
   placeholder mı?
3. "syzkaller fuzzing yapıyor" → 0009 kanıtı yeterli mi, yoksa R6 ile yeniden mi
   üretilmeli?
4. Rust↔Python sınırı gerçekten process-ayrık ve şema-versiyonlu mu, yoksa
   kırılgan mı?

---

## 8. Devlog haritası (derin dalış için)

`docs/devlog/devlog.md` — her entry sabit formatta (Ne/Neden/Tasarım
kararları/Kapsam dışı/Doğrulama/Dosyalar/Sonraki adımlar):

| # | Konu | Durum |
|---|---|---|
| 0001 | `contract` serde (Rust↔Python JSON) | Tamamlandı |
| 0002 | `ingest` stage | Tamamlandı |
| 0003 | Orchestrator spine (period = N-exec) | Tamamlandı |
| 0004 | `normalize` + CORE şeması donduruldu | Tamamlandı (parser TODO) |
| 0005 | `score` (Rust↔Python) | Tamamlandı (istatistik TODO) |
| 0006 | `diff` (documented-vs-observed + oracle) | Tamamlandı (dış loader TODO) |
| 0007 | `report` (score ⋈ diff) | Tamamlandı (pipeline uçtan uca) |
| 0008 | Gerçek kernel/VM bring-up | Tamamlandı (TCG; KVM host-side bloklu) |
| 0009 | syzkaller entegrasyonu + VM ağ düzeltmesi | Tamamlandı (TCG'de fuzzing) |

---

## 9. Tek cümlelik doğrulanabilir durum ifadesi

> "verifierloop'un **beş-stage'li yazılım pipeline'ı** (ingest→normalize→score→
> diff→report) Rust↔Python sınırıyla birlikte **kod olarak tamam ve sentetik
> veriyle uçtan uca koşuyor** (22 test geçer, `report_demo` çalışır); **lab
> ortamı** (self-built bpf-next bzImage + disposable rootfs + syzkaller) **kurulu
> ve TCG'de fiilen KCOV-güdümlü fuzzing yapıyor**; **eksik olan tek büyük parça**,
> gerçek syzkaller çıktısını pipeline'a bağlayan **gerçek parser + FuzzDriver +
> dış ground-truth loader'ları** (hepsi işaretli TODO); **KVM host-side bloklu**."
