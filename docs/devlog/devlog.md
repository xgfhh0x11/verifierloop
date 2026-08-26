# Development log — verifierloop

Bu dosya, iskelet kurulduktan sonra **implementasyona geçilen her iş parçasının**
tek bir yerdeki kaydıdır. Amaç, periyot sınırındaki human-in-the-loop için (ve
gelecekteki geliştirme için) **ne yapıldığını, neden yapıldığını ve hangi tasarım
kararlarının verildiğini** kalıcı hâle getirmek.

> **Not:** iskelet kurulumunun kendisi (repo layout, stub'lar, config
> template'leri, `README`, `justfile`) top-level `README.md`'de anlatılır; bu log
> iskeletten **sonraki** implementasyon adımlarını izler. Daha önce her adım ayrı
> bir dosyaydı (`0001`…`0005`); hepsi burada birleştirildi.

Her entry'nin sabit bir formatı vardır:

- **Ne yapıldı** — somut değişiklik.
- **Neden** — bağlam / gerekçe.
- **Tasarım kararları** — prompt'ta belirtilmemiş, geliştirme sırasında verilen
  kararlar + rationale (geri alınabilir olmaları için açıkça yazılır).
- **Kapsam dışı / hâlâ stub** — bilinçli olarak yapılmayanlar.
- **Doğrulama** — çalıştırılan komutlar + sonuçlar (iddia değil, kanıt).
- **Dokunulan dosyalar**.
- **Sonraki adımlar**.

## Entry'ler

| # | Başlık | Durum |
| --- | --- | --- |
| 0001 | `contract` crate — serde implementasyonu (Rust↔Python JSON contract) | Tamamlandı |
| 0002 | `pipeline::ingest` — ham çıktı toplama stage'i | Tamamlandı |
| 0003 | Orchestrator spine — period döngüsü (period = N-exec) | Tamamlandı |
| 0004 | `normalize` stage + CORE metrik şeması donduruldu | Tamamlandı (parser'lar TODO) |
| 0005 | `score` stage — Rust↔Python anomaly scoring (contract) | Tamamlandı (baseline; istatistik TODO) |
| 0006 | `diff` stage — documented-vs-observed + ground-truth oracle | Tamamlandı (dış-kaynak loader'ları TODO) |
| 0007 | `report` stage — triyajlı PERIOD_REPORT (score ⋈ diff) | Tamamlandı (pipeline uçtan uca) |
| 0008 | Gerçek bpf-next kernel/VM ortamı (build + rootfs + boot) | Tamamlandı (TCG çalışır; KVM host-side bloklu) |
| 0009 | syzkaller entegrasyonu (fuzzing stack) + VM ağ düzeltmesi | Tamamlandı (TCG'de fuzzing çalışır) |
| 0010 | Golden fixture (parser-katmanı guardrail) + git init + veri-kaynağı netleştirmesi | Tamamlandı (normalize anchor'lı; gerçek parser'lar hâlâ TODO) |
| 0011 | Differential/verifier-log harness v0 (guest-side C) + gerçek log örneği | Tamamlandı (decision+reg-state; JIT↔interp ertelendi; parser sonraki) |
| 0012 | Verifier-log parser (`VerifierLogParser`) + gerçek veri uçtan uca | Tamamlandı (harness→CoreMetrics; pipeline gerçek veriyle koşuyor) |

### Pipeline durumu (özet)

```
ingest ✅ → normalize ✅ → score ✅ → diff ✅ → report ✅   → (human-in-the-loop)
          (parser TODO)   (istatistik TODO)  (dış-kaynak
                                              loader TODO)
```

**Beş stage de artık uçtan uca koşuyor.** Kalan: gerçek entegrasyon
(native-format parser'lar, gerçek FuzzDriver/VM, dış ground-truth loader'ları).

---

## 0001 — `contract` crate: serde implementasyonu

- **Tarih:** 2026-08-22
- **Durum:** Tamamlandı
- **Alan:** `crates/contract`, `python/src/verifierloop_analysis/contract.py`
- **İlgili:** Rust↔Python language boundary (JSON artifact contract)

### Ne yapıldı
`contract` crate'inin envelope'u iskelet stub'ından (`todo!()`) gerçek,
serileştirilebilir bir contract'a çevrildi. Rust orchestrator ile Python analiz
tarafı artık **dosya-tabanlı JSON artifact'ları** üzerinden veri değişebiliyor.

- `serde` + `serde_json` bağımlılıkları eklendi (cache'ten **offline** derlendi).
- `Artifact<T = serde_json::Value>` — generic payload'lı envelope; `serde` ile
  (de)serialize. Alanlar: `contract_version: u32`, `period_id: u64`,
  `producer: Producer`, `payload: T`.
- `Producer` enum'ı (snake_case: `ingest`/`normalize`/`score`/`diff`/`report`).
- `ContractError` (`Io` / `Json` / `VersionMismatch`) — gerçek hata tipi,
  `std::error::Error` implementasyonlu.
- `read_artifact` / `read_raw`: **payload'dan önce versiyon kontrolü** (uyumsuz
  dosya net `VersionMismatch` verir, kafa karıştırıcı payload hatası değil).
- `write_artifact`: **atomik yazma** (tmp sibling + `rename`), parent dizin
  oluşturma, pretty JSON + trailing newline.
- `PeriodPaths`: gerçek path çözümü (`<data_root>/periods/<N>/…`) + isimli
  yardımcılar (`normalized()`, `anomaly_scores()`, …). (Sonradan `period_id`
  alanı da eklendi — bkz. 0002.)
- `CONTRACT_VERSION` 0 → **1** (envelope donduğu için).
- **Python mirror lockstep'e getirildi**: aynı envelope, aynı `Producer` string
  değerleri, `read/write_artifact` stdlib `json` ile implemente edildi
  (versiyon kontrolü + atomik `os.replace`), `ContractVersionError`.

### Neden
Boundary "typed, file-based JSON artifact contract" olarak tasarlanmıştı ama
iskelette sadece imza vardı. Sonraki stage'ler (özellikle `score`, Python'a
delege eder) çalışan bir contract olmadan yazılamazdı. Bu adım o zemini kurdu.

### Tasarım kararları (prompt'ta belirtilmemiş)
1. **Generic `Artifact<T>` (default `serde_json::Value`).** Envelope'u *şimdi*
   dondurup, metrik payload tipleri hâlâ `Tbd` iken onları beklemeden çalışmak
   için. Tipler kesinleşince `Artifact<NormalizedMetrics>` olarak yerine oturur.
2. **`metrics` bağımlılığı contract'tan çıkarıldı.** Generic payload artık
   `Tbd`'ye ihtiyaç duymuyor; contract yalnızca serde'ye bağlı.
3. **`CONTRACT_VERSION` 1'e yükseltildi.** Envelope artık gerçek/dondu.
4. **Python `read/write` de implemente edildi.** Contract çift yönlü (Python
   NORMALIZED okur, ANOMALY_SCORES yazar); Rust-only bırakmak boundary'yi yarım
   bırakırdı ve "keep the two in lockstep" invariant'ını bozardı.

### Kapsam dışı / hâlâ stub
- Metrik payload tiplerinin somutlaştırılması (hâlâ `Tbd`).
- Contract'ı kullanan stage'ler (`score` vb.) — ayrı iş.

### Doğrulama
- `cargo test -p contract --offline` → **5/5 test geçti** (path layout, producer
  snake_case, untyped round-trip, typed round-trip, version-mismatch tespiti).
- **Cross-language round-trip (iki yön)**:
  - Rust `interop write` → dosya → **Python `read_artifact`** okudu, assertion'lar geçti.
  - Python `write_artifact` → dosya → **Rust `interop read`** okudu; versiyon/producer/payload eşleşti.
- Örnek: `cargo run -p contract --example interop -- <write|read> <path>`.

### Dokunulan dosyalar
- `crates/contract/Cargo.toml` (serde deps; metrics dep kaldırıldı)
- `crates/contract/src/lib.rs` (envelope + Producer + hata tipi + read/write + PeriodPaths + testler)
- `crates/contract/examples/interop.rs` (cross-language kanıt)
- `python/src/verifierloop_analysis/contract.py` (mirror + read/write)

### Sonraki adımlar
- `pipeline::ingest`'i bu contract üzerinden `RAW_INDEX` yazacak şekilde bağla
  → yapıldı, bkz. 0002.

---

## 0002 — `pipeline::ingest`: ham çıktı toplama stage'i

- **Tarih:** 2026-08-22
- **Durum:** Tamamlandı
- **Alan:** `crates/pipeline` (`ingest` modülü), `crates/contract` (küçük ekleme)
- **İlgili:** Pipeline stage 1; 0001 (contract kullanımı)

### Ne yapıldı
Pipeline'ın ilk stage'i `ingest` iskelet stub'ından gerçek implementasyona
çevrildi. Ingest, araçların ürettiği native çıktıyı **değiştirmeden** toplar ve
`RAW_INDEX` contract artifact'ı olarak kataloglar.

- **Toplama (dönüştürme değil):** her aracın çıktı dosyaları **byte-for-byte**
  `<period>/raw/<tool>/…` altına kopyalanır. Parse/normalize/rename YOK.
- **Dosya + dizin** girdisi (dizinler rekürsif, alt yapı korunur, deterministik
  sıralama).
- **`RawObservation { exec_count, entries[] }`** → `RAW_INDEX` (`raw/index.json`)
  contract üzerinden atomik yazılır (`Producer::Ingest`).
- **`RawEntry` provenance**: tool, orijinal path, saklanan path, byte boyutu,
  mtime (yalnızca **label**), içerik fingerprint'i.
- **Fingerprint:** FNV-1a-64 (hex) — dependency yok, deterministik,
  cross-platform. Kriptografik DEĞİL (dedup/değişiklik tespiti için).
- `IngestError` (`Io` / `Contract`) hata tipi.
- `Source { tool, path }` girdi tipi — orchestrator config'den dolduracak;
  imza: `ingest::run(period, sources, exec_count)`.

**Yan değişiklikler**
- `contract::PeriodPaths`'e `period_id: u64` alanı (envelope'u damgalamak için;
  Rust + Python mirror lockstep).
- `pipeline` crate'ine `serde` bağımlılığı (`RawObservation`/`RawEntry` derive).
- `pipeline/examples/ingest_demo.rs` (kullanım + e2e kanıt).

### Neden
Prompt'un tool-output ilkesi: *her aracın DEFAULT-mode native çıktısını
değiştirmeden topla; normalization'ı ayrı bir sonraki stage'de yap, asla
kaynakta değil.* Ingest bu ilkenin somutlaştığı yer — ham veriyi kutsal tutup
şekillendirmeyi `normalize`'a bırakır. Bu ayrıca confirmation-bias guardrail'ini
destekler: loop kendi yorumunu veriye erken bulaştırmaz.

### Tasarım kararları (prompt'ta belirtilmemiş)
1. **Kopyala, referans verme.** Asıl hunt **disposable VM**'lerde döner; VM yok
   edilince veri kaybolmasın diye harvest host'ta kendi kendine yeterli olmalı.
2. **`RAW_INDEX` payload şeması** `{ exec_count, entries[] }` — ingest'in çıktı
   kontratı bu.
3. **FNV-1a-64 fingerprint** + **mtime'ı epoch-saniye integer** olarak (chrono
   gibi bir date bağımlılığı eklememek için). SHA-256'ya yükseltme = TODO.
4. **`Source` girdisi orchestrator'dan gelir** — ingest fuzzer çalıştırmaz/VM'e
   dokunmaz; araçlar zaten diske yazdıktan sonra devreye girer.

### Kapsam dışı / hâlâ stub
- `normalize` / `score` / `diff` / `report` stage'leri (hâlâ `todo!()`).
- Orchestrator wiring (loop_runtime ingest'i henüz çağırmıyor).
- Gerçek fuzzer/VM entegrasyonu (syzkaller, differential harness, QEMU).
- Fingerprint'in kriptografik hâle getirilmesi (SHA-256).

### Doğrulama
- `cargo test -p pipeline --offline` → **3/3 test geçti**: (a) dosya+dizin
  bozulmadan kopyalanıyor, (b) `RAW_INDEX` artifact'ı contract üzerinden geri
  okunuyor, (c) fingerprint deterministik + içeriğe duyarlı (boş girdi FNV
  offset basis'i veriyor).
- **End-to-end**: `cargo run -p pipeline --example ingest_demo -- <dir>` sahte
  native çıktıyı topladı → `raw/index.json` yazdı → **Python contract üzerinden
  okudu** (assertion'lar geçti) → kopyalanan blob kaynakla `diff` = **IDENTICAL**.
- Tüm workspace: `cargo test --offline` yeşil.

### Dokunulan dosyalar
- `crates/pipeline/Cargo.toml` (serde + example)
- `crates/pipeline/src/ingest.rs` (implementasyon + testler)
- `crates/pipeline/examples/ingest_demo.rs`
- `crates/contract/src/lib.rs` (`PeriodPaths.period_id`)
- `python/src/verifierloop_analysis/contract.py` (`PeriodPaths.period_id`)

### Sonraki adımlar
- **`normalize` stage'i**: `RAW_INDEX` → 4 metrik grubu şeması (CORE'un
  doldurulması burada başlar). Metrik field tipleri burada somutlaşmaya başlar.

---

## 0003 — Orchestrator spine: period döngüsü (period = N-exec)

- **Tarih:** 2026-08-22
- **Durum:** Tamamlandı
- **Alan:** `crates/orchestrator` (yeni lib + `period`/`driver`/`loop_runtime`)
- **İlgili:** 0001 (contract), 0002 (ingest)

### Ne yapıldı
Var olan parçalar (contract + ingest) çalışan bir omurgada birleştirildi ve
projenin kalbindeki **period = N-exec modeli** gerçek yapıldı.

- **`orchestrator` lib + bin'e bölündü** (`src/lib.rs` modülleri açar; `main.rs`
  ince wrapper). Böylece example/test'ler public API'yi kullanabiliyor.
- **`period::Period` gerçek**: sınır **exec sayısı** (kümülatif N), zaman değil.
  `is_complete()` = `execs_this_period() >= exec_threshold`. `harvest_unix` yalnız
  bir **label** (harvest'ta damgalanır), asla durma kriteri değil.
- **`driver::FuzzDriver` trait'i** — fuzzer'ların *nasıl* exec ürettiğini soyutlar
  (`exec_count`, `pump`, `sources`). Gerçek VM-tabanlı driver henüz yok (TODO).
- **`driver::MockDriver`** — deterministik, her `pump`'ta exec'i artırıp tool
  başına sahte native çıktı yazar; test/example için.
- **`loop_runtime`**: `LoopConfig`, `Harvest`, `LoopError`, `run_period` (bir
  periyodu exec sınırına kadar sürer, sonra `ingest` ile harvest'lar),
  `run_periods` (ardışık periyotlar; sınırlar N, 2N, 3N… exec'te), `run()` entry.
- **`examples/period_spine.rs`** — spine'ı MockDriver ile koşan e2e demo.
- Guardrail yorumu `loop_runtime`'da korundu + spine'ın **ingest harvest'ında
  durması** guardrail gerekçesiyle (human-in-the-loop) bağlandı.

### Neden
"Orchestrator spine" seçildi (normalize yerine) çünkü: (a) metrik tiplerini
kesinleştirmeyi zorlamaz (prompt bunu ertelemişti), (b) projenin merkezî kavramı
olan **period = N-exec** modelini gerçek kılar, (c) contract + ingest'i çalışan
uçtan uca bir omurgada birleştirir, (d) spine'ın harvest'ta durması tam da
human-in-the-loop sınırıdır.

### Tasarım kararları (prompt'ta belirtilmemiş)
1. **`FuzzDriver` soyutlaması + `MockDriver`.** Loop kontrol akışı gerçek
   VM/syzkaller olmadan test edilebilir olsun diye. Gerçek driver = TODO.
2. **Kümülatif exec-count sınırları** — periyot sınırları N, 2N, 3N… exec'te;
   `Period` `exec_start` + `exec_threshold` tutar.
3. **`orchestrator` lib+bin.** Example/test'ler için lib gerekli; bin ince kaldı.
4. **Spine ingest harvest'ında durur.** Downstream (normalize/score/diff/report)
   hâlâ stub; bu bilinçli — human-in-the-loop devralır.
5. **`harvest_unix` = epoch saniye** (date bağımlılığı yok); yalnız label.

### Kapsam dışı / hâlâ stub
- Gerçek VM-tabanlı `FuzzDriver` (vmctl + syzkaller + differential harness).
- `normalize` / `score` / `diff` / `report` stage'leri.
- İkincil verimlilik gözlemi (yeni coverage/exec) — rapor için, henüz yok.
- `run()` gerçek driver'ı construct etmiyor (TODO); kontrol akışı MockDriver ile
  test/example üzerinden çalışır.

### Doğrulama
- `cargo test -p orchestrator --offline` → **4/4 geçti**: period sınırı exec
  count'a bağlı (zamana değil), zero-threshold anında tamamlanır, bir periyot
  sınırda harvest'lar, periyotlar kümülatif exec ile ilerler.
- **End-to-end**: `cargo run -p orchestrator --example period_spine -- <dir>`
  → 3 periyot (sınır=100 exec, +40/pump → 120/240/360), her periyot kendi harvest
  dizini, **Python** periyot 2'nin `RAW_INDEX`'ini contract'tan okudu (assertion'lar geçti).
- Tüm workspace: `cargo test --offline` yeşil.

### Dokunulan dosyalar
- `crates/orchestrator/src/lib.rs` (yeni)
- `crates/orchestrator/src/main.rs` (ince wrapper)
- `crates/orchestrator/src/period.rs` (gerçek Period + testler)
- `crates/orchestrator/src/driver.rs` (yeni: FuzzDriver + MockDriver)
- `crates/orchestrator/src/loop_runtime.rs` (period döngüsü + testler)
- `crates/orchestrator/examples/period_spine.rs` (yeni)

### Sonraki adımlar
- Ya **`normalize`** (önce CORE metrik şemasını kesinleştir), ya da **gerçek
  `FuzzDriver`** (vmctl + syzkaller) — hangisinin önce geleceği kullanıcıya bağlı.

---

## 0004 — `normalize` stage + CORE metrik şemasının dondurulması

- **Tarih:** 2026-08-22
- **Durum:** Tamamlandı (parser'lar TODO)
- **Alan:** `crates/metrics` (4 grup donduruldu), `crates/pipeline` (`normalize`),
  `python/.../schemas/`
- **İlgili:** 0002 (ingest → RAW_INDEX), 0001

### Ne yapıldı
Prompt'un bilinçli olarak ertelediği **CORE metrik field tipleri** kullanıcı
onayıyla donduruldu ("Full + evolution" varyantı) ve `normalize` stage'i gerçek
assembly/provenance/artifact mantığıyla kuruldu.

**Metrik şeması (donduruldu, serde'li)**
- **CORE** (`metrics::core`): `VerifierDecision` (Accept | Reject{reason}),
  `register_evolution: Vec<RegSnapshot{ insn_idx, regs: Vec<RegState{ reg,
  reg_type, tnum{value,mask}, umin/umax/smin/smax }> }>`, `Processed{
  insn_processed, states_processed }`, `Option<JitInterpDiff>`, `CoverageDelta{
  new_bb, exec_n }`, `Vec<HelperArgViolation>`. `reg_type` ve reject `reason`
  **verbatim String** (sürüm-drift'ine dayanıklı, ham gözlemi bozmama ilkesi).
- **DERIVED**: `efficiency_per_exec: Option<f64>` (REPORT-ONLY), `record_count`.
- **COUNTERFACTUAL**: `enabled: bool` (opt-in, default OFF), `alternatives`.
- **EXPECTATION**: `Expectation` enum (NoPrediction/Expected/Unexpected, default
  NoPrediction) + `predicted`.

**`normalize` stage**
- `NormalizedMetrics { exec_count, records: Vec<MetricRecord>, derived }`;
  `MetricRecord { core, counterfactual, expectation }` — counterfactual ve
  expectation core'un ÜSTÜNDE, onu asla değiştirmeden.
- `run(period, raw, parser)`: harvest'lanmış `raw/` kopyalarını okur, her dosyayı
  `RecordParser`'a verir, CORE'ları toplar, exec sayacı N'i provenance olarak
  damgalar, counterfactual(OFF) + expectation(NoPrediction) ile sarar, DERIVED'ı
  doldurur, `NORMALIZED` artifact'ını contract üzerinden yazar.
- **`RecordParser` trait'i** (enjekte edilebilir) + **`UnimplementedParser`**
  (gerçek native formatlar gelene kadar sıfır kayıt üretir).
- Python schema mirror'ı dondurulmuş tiplere güncellendi + `normalized.py`.

### Neden
`normalize` pipeline'da sıradaki. Ama CORE'u doldurmak field tiplerini
kesinleştirmeyi gerektiriyordu; bu prompt'ta ertelenmişti, o yüzden kullanıcıya
sorup (Full + evolution) donduruldu. Gerçek byte-parse'ları native formatlara
bağlı olduğundan (henüz yok), parser MockDriver gibi enjekte edilebilir bırakıldı.

### Tasarım kararları (bu adımda verilen)
1. **CORE = Full + evolution** (kullanıcı seçti) — `register_evolution` insn başına
   snapshot listesi; verifier bug-hunting'de merkezi.
2. **`reg_type`/`reason` = verbatim String** (enum değil) — kernel sürümleri arası
   drift'e dayanıklı.
3. **Enjekte edilebilir `RecordParser`** — assembly/provenance/artifact mantığı
   gerçek native format olmadan test edilebilsin; gerçek parser'lar swap-in.
4. **Kayıt-başına counterfactual + expectation, periyot-başına derived** — CORE
   per-observation; counterfactual/expectation ONun üstünde; derived periyot düzeyi.
5. **`normalize` loop'a otomatik bağlanmadı** — spine hâlâ harvest'ta durur;
   normalize standalone stage olarak koşulur/test edilir.

### Kapsam dışı / hâlâ stub
- **Gerçek per-tool parser'lar** (syzkaller verifier log, differential retval,
  KCOV) — native formatlara bağlı, TODO.
- `score` / `diff` / `report` stage'leri.
- `efficiency_per_exec` hesabı (yeterli exec gerekir).
- normalize'ın loop'a otomatik bağlanması.

### Doğrulama
- `cargo test -p pipeline --offline` → **5/5** (3 ingest + 2 normalize: assembly +
  provenance + artifact round-trip; UnimplementedParser sıfır kayıt).
- **End-to-end**: `cargo run -p pipeline --example normalize_demo -- <dir>`
  → ingest → normalize → `normalized_metrics.json` (dolu frozen şema JSON'da) →
  **Python** contract üzerinden okudu; tagged `verifier_decision`, tnum,
  helper_arg_violations, `exec_n=4200`, counterfactual OFF, expectation
  `no_prediction` — assertion'lar geçti.
- Tüm workspace: `cargo test --offline` yeşil; Python import OK.

### Dokunulan dosyalar
- `crates/metrics/Cargo.toml`, `src/{lib,core,derived,counterfactual,expectation}.rs`
- `crates/pipeline/src/normalize.rs`, `examples/normalize_demo.rs`
- `python/src/verifierloop_analysis/schemas/*.py` (+ `normalized.py`)

### Sonraki adımlar
- **`score`** stage'i (Python, contract üzerinden anomaly scoring) — NORMALIZED'ı
  okuyup ANOMALY_SCORES yazar. VEYA gerçek bir `RecordParser` (native format).

---

## 0005 — `score` stage: Rust↔Python anomaly scoring (contract üzerinden)

- **Tarih:** 2026-08-22
- **Durum:** Tamamlandı (baseline scorer; istatistiksel yöntem TODO)
- **Alan:** `crates/pipeline` (`score`), `python/.../scoring.py` + `__main__.py`
- **İlgili:** 0004 (NORMALIZED), 0001

### Ne yapıldı
Pipeline'ın 3. stage'i `score` kuruldu — **Python tarafının ilk gerçek işi** ve
tam Rust↔Python dosya-contract sınırını çalıştırır.

- **Rust `score`**: `Analyzer` trait (enjekte edilebilir) + `PythonAnalyzer`
  (gerçek subprocess: `python3 -m verifierloop_analysis --period-dir <dir>`).
  `run(period, analyzer)` → analyzer'ı çağırır, `ANOMALY_SCORES` artifact'ını
  contract üzerinden geri okur.
- **`AnomalyScores` payload'ı**: `{ exec_count, scored: [{index, score, reasons}],
  summary: {record_count, flagged, max_score}, method }`.
- **Python scoring baseline** (`baseline-hard-signals-v0`): şeffaf, kural tabanlı
  hard-signal'lar — JIT↔interp sapması (retval/data_out) → 0.95; helper arg_type
  ihlali → 0.85; temiz → 0.0. Eğitim verisi gerektirmez, deterministik.
- **Python CLI** (`__main__.py`): NORMALIZED oku → skorla → ANOMALY_SCORES yaz
  (Producer.SCORE), dosya-contract'ın Python yarısı.
- **GUARDRAIL**: skorlar insan triyajı için SIRALAR; fuzzer input seçimini ASLA
  beslemez (hem `scoring.py` hem `score.rs` içinde yazılı).

### Neden
`score` pipeline'da sıradaki. Python istatistik/anomaly scoring'in sahibi; bu
stage o sınırı gerçek kılar. `score`, `normalize`'ın yazdığı NORMALIZED'ı yeniden
yazmaz — yalnızca Python'a devreder ve skorları geri okur.

### Tasarım kararları (bu adımda verilen)
1. **Baseline scorer sormadan seçildi** — CORE şeması gibi dondurulmuş bir contract
   DEĞİL, değiştirilebilir logic. Hard-signal kural tabanlı = en az taahhütlü,
   apaçık doğru başlangıç (gerçek bug göstergelerini flag'ler). İstatistiksel
   outlier scoring = TODO (bir sonraki yöntem).
2. **Enjekte edilebilir `Analyzer` + gerçek `PythonAnalyzer`** — Rust testleri
   Python runtime olmadan hermetik; gerçek subprocess yolu e2e'de kanıtlanır.
3. **`score` NORMALIZED'ı yeniden yazmaz** — normalize üretir, score devreder.
4. **`PythonAnalyzer` PYTHONPATH konfigüre edilebilir** — paket kurulmadan
   repo içi `python/src`'ye karşı koşmak için (`repo_pythonpath()` yardımcı).

### Kapsam dışı / hâlâ stub
- **İstatistiksel outlier scoring** (z-score/IQR, numeric CORE alanları) — TODO.
- `diff` / `report` stage'leri.
- `score`'un loop'a otomatik bağlanması (spine hâlâ harvest'ta durur).

### Doğrulama
- `cargo test -p pipeline --offline` → **6/6** (3 ingest + 2 normalize + 1 score;
  score testi hermetik `CannedAnalyzer` ile read-back'i doğrular).
- Python self-test: divergence→0.95, helper ihlali→0.85, temiz→0.0.
- **End-to-end (gerçek subprocess)**: normalize_demo → `score_demo` (Rust python3'ü
  spawn eder) → Python NORMALIZED okudu, skorladı, ANOMALY_SCORES yazdı → Rust geri
  okudu → helper-ihlalli reject kaydı flag'lendi (0.85), method=baseline-hard-signals-v0.
  Python kendi çıktısını contract'tan tekrar okudu, assertion'lar geçti.
- Tüm workspace: `cargo test --offline` yeşil; Python import OK.

### Dokunulan dosyalar
- `crates/pipeline/src/score.rs`, `examples/score_demo.rs`
- `python/src/verifierloop_analysis/scoring.py`, `__main__.py`

### Sonraki adımlar
- **`diff`** stage'i (documented-vs-observed; 4 ground-truth kaynağı) — VEYA
  istatistiksel scoring yöntemi, VEYA gerçek bir native-format `RecordParser`.
  → yapıldı, bkz. 0006.

---

## 0006 — `diff` stage: documented-vs-observed + ground-truth oracle

- **Tarih:** 2026-08-23
- **Durum:** Tamamlandı (dış-kaynak loader'ları TODO)
- **Alan:** `crates/pipeline` (`diff` + `groundtruth`), `python/.../schemas/diff.py`
- **İlgili:** 0004 (NORMALIZED), 0001 (contract)

### Ne yapıldı
Pipeline'ın 4. stage'i `diff` kuruldu — projenin **"not-a-proof" kalbi**: gözlenen
davranışı (NORMALIZED) ground-truth'a karşı kıyaslayıp **documented-vs-observed
sapmalarını** çıkarır. İki kullanıcı kararı önce alındı (frozen contract olduğu
için): (Q1) baseline kapsamı = **intrinsik invariant + enjekte oracle**, (Q2)
`DIFF_FINDINGS` şeması = **zengin (expected/observed ayrı)**.

- **İki kontrol türü:**
  1. **Intrinsik mantıksal invariant'lar** (CORE'dan doğrudan, dış dosya yok — "klasik
     mantıksal analiz" sütunu): tnum iyi-biçimli mi (`value & mask == 0`), bounds
     sıralı mı (`umin<=umax`, `smin<=smax`), tnum↔bounds tutarlı mı (tnum span'i
     `[value, value|mask]` ile `[umin,umax]` kesişiyor mu), JIT↔interp eşdeğerliği.
  2. **Kaynak-destekli** (enjekte edilebilir `GroundTruth` oracle): helper `arg_type`
     kontratı (source 3) — CORE'un `helper_arg_violation` sinyalini dokümante
     proto'ya karşı doğrular. verifier.c / rst / patch-diff sorguları TODO (tree gerekir).
- **`GroundTruth` trait'e çevrildi** (eski boş struct yerine) — enjekte edilebilir
  oracle; `NoGroundTruth` (her şeye None; sadece intrinsik kontroller koşar) +
  `StaticGroundTruth` (in-memory helper-proto tablosu; reference oracle). Dört
  submodule loader'ı (`verifier_c`/`verifier_rst`/`helper_proto`/`patch_diff`) TODO
  kaldı; `helper_proto::HelperProtoModel` gerçek bir `(helper,arg)->arg_type` tablosu.
- **`DIFF_FINDINGS` payload'ı (donduruldu, serde):** `DiffFindings { exec_count,
  findings: Vec<DivergenceFinding>, summary }`; `DivergenceFinding { record_index:
  Option<u64>, source, kind, aspect, expected, observed, detail }`;
  `GroundTruthSource` enum (verifier_c/documentation/helper_proto/patch_diff/
  **logical_invariant**, snake_case); `DiffSummary { record_count, finding_count,
  by_source }`. `kind`/`aspect`/`expected`/`observed` = verbatim String.
- **`run(period, metrics, ground_truth)`** — yalnız NORMALIZED okur, ANOMALY_SCORES'a
  BAKMAZ; findings toplar, `by_source` sayar, `DIFF_FINDINGS`'i contract üzerinden yazar.
- **Python mirror** `schemas/diff.py` + `schemas/__init__` export.

### Neden
`diff` pipeline'da sıradaki ve projenin asıl amacı (gözlem ≠ dokümante davranış)
burada somutlaşır. Kernel tree henüz yok; bu yüzden dış-kaynak loader'ları
(verifier.c/rst/patch) — normalize'ın gerçek parser'ları gibi — TODO. Ama intrinsik
mantıksal invariant'lar dış dosya gerektirmez, dolayısıyla stage **vacuous değil**:
şimdiden gerçek logic-bug göstergelerini (tnum bozulması, range-desync, JIT/interp
sapması) yakalar.

### Tasarım kararları (bu adımda verilen)
1. **Q1: intrinsik + enjekte oracle** (kullanıcı seçti) — stage şimdi gerçek bulgu
   üretir; oracle soyutlaması gerçek loader'lar için swap-in noktası.
2. **Q2: zengin bulgu şeması** (kullanıcı seçti) — expected/observed ayrı; report
   stage'i doğrudan tablolar. **severity/score YOK.**
3. **`diff` ANOMALY_SCORES okumaz** (varsayılan, kullanıcı onayladı) — guardrail:
   nesnel sapma kaydı, döngünün kendi skorundan etkilenmemeli. diff **saptar**,
   score **sıralar**.
4. **`logical_invariant` 5. `GroundTruthSource` sütunu** — prompt'un "klasik mantıksal
   analiz" ground-truth sütununun somutlaşması (5. dış dosya değil, intrinsik yöntem).
5. **`GroundTruth` struct → trait** — enjekte edilebilirlik için; `NoGroundTruth` =
   `UnimplementedParser`'ın diff karşılığı.
6. **tnum invariant'ı** `value & mask == 0` — kernel `struct tnum` semantiği (known
   bit'ler value'da, unknown bit'ler mask'te; örtüşme = bozuk soyut durum).

### Kapsam dışı / hâlâ stub
- **Dış-kaynak loader'ları** (verifier.c decision model, verifier.rst kuralları,
  patch-diff delta'ları) — bpf-next tree gerektirir, TODO; ilgili `GroundTruth`
  trait metotları da onlarla gelecek.
- `report` stage'i (scores + diff'i birleştirir).
- İstatistiksel scoring, gerçek native-format parser'lar, gerçek FuzzDriver.
- `diff`'in loop'a otomatik bağlanması (spine hâlâ harvest'ta durur).

### Doğrulama
- `cargo test -p pipeline --offline` → **11/11** (öncekiler + 5 diff: temiz gözlem
  sıfır bulgu, malformed tnum, inverted bounds, jit/interp sapması, helper-proto
  oracle olmadan sessiz / oracle ile bulgu + artifact round-trip).
- Tüm workspace: `cargo test --offline` → **20/20** yeşil.
- **End-to-end**: `cargo run -p pipeline --example diff_demo -- <dir>` → ingest →
  normalize (clean+buggy kayıt) → diff → 3 bulgu (2 logical_invariant: tnum_malformed
  + jit_interp_divergence; 1 helper_proto: arg_type_mismatch), clean kayıt 0 bulgu →
  `diff_findings.json` yazıldı.
- **Cross-language**: Python `DIFF_FINDINGS`'i contract üzerinden okudu; producer=diff,
  by_source doğru, her finding şema-uyumlu (`source` mirror değerlerinden biri), ve
  **severity/score alanı YOK** (guardrail veriden doğrulandı). Python import OK.

### Dokunulan dosyalar
- `crates/pipeline/src/diff.rs` (şema + intrinsik + oracle kontrolü + run + testler)
- `crates/pipeline/src/groundtruth/mod.rs` (GroundTruth trait + NoGroundTruth + StaticGroundTruth)
- `crates/pipeline/src/groundtruth/helper_proto.rs` (gerçek HelperProtoModel tablosu)
- `crates/pipeline/examples/diff_demo.rs` (e2e)
- `python/src/verifierloop_analysis/schemas/diff.py` (+ `schemas/__init__.py`)

### Sonraki adımlar
- **`report`** stage'i (triyajlı periyot raporu; ANOMALY_SCORES + DIFF_FINDINGS'i
  birleştirir → human-in-the-loop batch'i) — VEYA gerçek bir ground-truth loader
  (helper proto extraction, kernel tree gelince), VEYA istatistiksel scoring.
  → yapıldı, bkz. 0007.

---

## 0007 — `report` stage: triyajlı PERIOD_REPORT (score ⋈ diff)

- **Tarih:** 2026-08-23
- **Durum:** Tamamlandı (pipeline uçtan uca çalışır)
- **Alan:** `crates/pipeline` (`report`), `python/.../schemas/report.py`
- **İlgili:** 0005 (ANOMALY_SCORES), 0006 (DIFF_FINDINGS), 0001 (contract)

### Ne yapıldı
Pipeline'ın **son halkası** `report` kuruldu — periyot sınırındaki **human-in-the-loop
teslim noktası**. `score`'un sıralamasıyla (`ANOMALY_SCORES`) `diff`'in sapmalarını
(`DIFF_FINDINGS`) tek bir **triyajlı per-record batch**'te birleştirir. Kullanıcı
kararı önce alındı (frozen contract): **2 yargı artifact'ı (yalın)** — NORMALIZED
okumaz.

- **`run(period, generated_unix)`** — periyodun ANOMALY_SCORES + DIFF_FINDINGS'ini
  contract üzerinden okur, record_index üzerinde JOIN eder, `PERIOD_REPORT` yazar.
  NORMALIZED okumaz, yeniden skorlamaz.
- **JOIN + sıralama**: diff findings per-record (record_index=Some) vs period-level
  (None) olarak ayrılır; her kayıt için score+reasons ile o kaydın divergence'ları
  birleştirilir; iki artifact'ta görünen indislerin BİRLEŞİMİ üzerinde çalışır
  (skorsuz ama sapmalı kayıt düşmez). **Sıralama yalnız mevcut score'a göre azalan**
  (eşitlikte record_index artan).
- **`PERIOD_REPORT` payload'ı (donduruldu, serde):** `PeriodReport { exec_count,
  generated_unix: Option<u64>, items: Vec<TriageItem>, period_findings:
  Vec<DivergenceFinding>, summary }`; `TriageItem { record_index, score,
  score_reasons, divergences }`; `ReportSummary { record_count, flagged,
  divergence_count, top_score }`.
- **`generated_unix` yalnız LABEL** — caller damgalar (report saati kendisi
  OKUMAZ); asla durma kriteri değil.
- **Python mirror** `schemas/report.py` (diff mirror'ını yeniden kullanır) + export.

### Neden
`report` pipeline'ın son adımı ve döngünün insana teslim ettiği batch. score
**sıralar**, diff **saptar**, report **birleştirir** — üç ayrı sorumluluk.

### Tasarım kararları (bu adımda verilen)
1. **Kullanıcı seçimi: 2 yargı artifact'ı (yalın)** — report yalnız ANOMALY_SCORES +
   DIFF_FINDINGS birleştirir; NORMALIZED (expectation flag, verifier karar,
   efficiency) rapora GİRMEZ. Daha az kuplaj.
2. **Rust (`pipeline::report`)** — scaffold zaten Rust; report = join+order+summarize
   (assembly/orkestrasyon, istatistik DEĞİL), o yüzden Python değil.
3. **GUARDRAIL: yalnız mevcut score'a göre sırala** — report yeni bir sıralama/severity
   ÜRETMEZ. score ranks, report assembles. severity alanı yok.
4. **`generated_unix` label-only, injected** — report clock'u kendisi okumaz;
   "zaman yalnız label" ilkesi.
5. **İndis birleşimi üzerinde JOIN** — skorsuz-ama-sapmalı (veya tersi) kayıt sessizce
   düşmesin diye.

### Kapsam dışı / hâlâ stub
- Gerçek entegrasyon: native-format parser'lar, gerçek FuzzDriver/VM, dış
  ground-truth loader'ları (verifier.c/rst/patch).
- İstatistiksel scoring; ikincil efficiency hesabı.
- `report`'un loop'a otomatik bağlanması (spine hâlâ harvest'ta durur; downstream
  stage'ler standalone koşulur/test edilir).

### Doğrulama
- `cargo test -p pipeline --offline` → **13/13** (öncekiler + 2 report: join/order/
  summary + PERIOD_REPORT round-trip; timestamp label opsiyonel).
- Tüm workspace: `cargo test --offline` → **22/22** yeşil.
- **End-to-end (tam pipeline, gerçek Python)**: `cargo run -p pipeline --example
  report_demo -- <dir>` → ingest → normalize → score (python3) → diff → report →
  buggy kayıt (score 0.95, 3 divergence) temiz kaydın (score 0) ÜSTÜNDE sıralandı;
  summary records=2 flagged=1 divergences=3 top_score=0.95 → `period_report.json`.
- **Cross-language**: Python PERIOD_REPORT'u contract'tan okudu; producer=report,
  item'lar score'a göre AZALAN sıralı (guardrail veriden doğrulandı), her item
  şema-uyumlu ve **severity alanı YOK**, generated_unix label. Python import OK.

### Dokunulan dosyalar
- `crates/pipeline/src/report.rs` (şema + join/order/summary + run + testler)
- `crates/pipeline/examples/report_demo.rs` (tam 5-stage e2e)
- `python/src/verifierloop_analysis/schemas/report.py` (+ `schemas/__init__.py`)

### Sonraki adımlar
- Pipeline uçtan uca tamam. Kalan büyük parçalar **gerçek entegrasyon**:
  (a) gerçek native-format `RecordParser`'lar (syzkaller verifier log / differential
  / KCOV), (b) gerçek `FuzzDriver` (vmctl + syzkaller + QEMU/KVM), (c) dış
  ground-truth loader'ları (verifier.c/rst/patch, kernel tree gelince),
  (d) `report`'u loop spine'ına bağlayıp periyot sonunda otomatik üretmek,
  (e) istatistiksel anomaly scoring.
  → gerçek kernel/VM ortamı kuruldu, bkz. 0008.

---

## 0008 — Gerçek bpf-next kernel/VM ortamı (build + rootfs + boot bring-up)

- **Tarih:** 2026-08-24
- **Durum:** Tamamlandı — VM uçtan uca boot ediyor (TCG). KVM host-side bloklu (aşağıda).
- **Alan:** `scripts/` (yeni), `config/qemu/*.sh` (gerçek), `config/kernel/*.config`,
  `justfile`, `.lab/` (gitignore'lı build artefaktları)
- **İlgili:** 0006 (diff → ground-truth kaynak dosyaları), tüm pipeline

### Ne yapıldı
Saf-yazılım iskeletinden **gerçek sistem kurulumuna** geçildi: self-built bpf-next
kernel + disposable QEMU VM. İskelet config placeholder'ları (kernel `.config`
fragment, QEMU launch script'leri, wslconfig notu) gerçek, çalışır script'lere
dönüştürüldü ve uçtan uca koşuldu.

- **`scripts/fetch-kernel.sh`** — bpf-next'i `--filter=blob:none` ile çeker (idempotent).
  *Not: kernel.org sunucusu partial-clone'u desteklemiyor (`filtering not recognized`),
  filtre yok sayıldı → tam klon oldu.* Sonuç aslında **daha yetenekli**: tüm geçmiş
  (1.47M commit) + tüm blob'lar yerel → **4 ground-truth kaynak dosyası da yerel**
  (verifier.c 21454 satır, verifier.rst, helper proto'lar, cross-version diff'ler).
  HEAD = `5e289c5a` (Linux 7.2.0 bpf-next), `.lab/kernel.rev`'e yazıldı. ~5.4 GB.
- **`scripts/build-kernel.sh`** — `defconfig + kvm_guest.config + lab fragment +
  olddefconfig`, sonra `-j24 bzImage`. bzImage 40M, vmlinux 569M, **BTF gömülü**.
- **`scripts/create-rootfs.sh`** — `debootstrap` Debian bookworm minimal → raw ext4
  (`mkfs.ext4 -d`, **loop-mount YOK** → WSL2'de sağlam). Serial autologin (root),
  sshd + üretilen ed25519 anahtar, DHCP, ve `init=` ile koşan `/root/verify.sh`.
  Image 452M.
- **`config/qemu/launch-{kvm,tcg}.sh`** — placeholder'dan gerçek/çalışır: `panic=1
  oops=panic nokaslr`, ssh port-forward, `-no-reboot`, `-snapshot` (disposable).
- **`scripts/boot-vm.sh`** (KVM/TCG dispatch) + **`scripts/verify-vm.sh`** (otomatik:
  boot → BTF/bpffs/kcov assert → poweroff; KVM başarısızsa TCG'ye düşer).
- **`justfile`** — `fetch-kernel`/`build-kernel`/`create-rootfs`/`verify-vm`/
  `boot-vm-{kvm,tcg}` artık gerçek script'leri çağırıyor (exit-1 placeholder değil).
- **`.gitignore`** — `.lab/` (ağır artefaktlar) zaten hariçti.

### Ortam gerçekleri (keşif)
root (uid=0, sudo serbest); 24 core / 31 GB RAM / 922 GB boş; gcc 11.4, pahole
v1.25, qemu 6.2, debootstrap — hepsi mevcut; kernel.org bpf-next ağdan erişilebilir.
Eksik: **go** (syzkaller için; bu adımın kapsamı dışı), `bpftool` (WSL stub;
kernel tree'den derlenebilir).

### Tasarım kararları / kullanıcı seçimleri
1. **Kaynak: blobless partial clone** (kullanıcı seçti) — sunucu desteklemeyince
   tam klona düştü; kabul edildi çünkü 2.1 GB zaten inmişti + otoritatif kaynak +
   tam geçmiş (source-4 için üstün). Şeffaf bildirildi.
2. **Kapsam: uçtan uca, milestone raporlu** (kullanıcı seçti).
3. **rootfs = debootstrap Debian minimal** (varsayılan; kurulu + standart tek yol).
4. **`mkfs.ext4 -d` (loop-mount'suz)** — WSL2'de loop device sorunlarından kaçınmak için.
5. **Artefaktlar `~/verifierloop/.lab/`** altında (gitignore).

### Bulgular (önemli)
- **KCSAN düştü** — lab fragment hem KASAN hem KCSAN istiyordu ama ikisi **karşılıklı
  dışlayan** (aynı kernelde olamaz); `olddefconfig` KASAN'ı koruyup KCSAN'ı attı.
  Primary hunt kernel'i KASAN'da kalır (memory-safety, corruption→primitive'e yakın);
  **KCSAN ayrı bir build** gerektirir (data-race avı için). Fragment'a not düşülmeli.
- **KVM host-side bloklu** — `/dev/kvm` var/yazılabilir ama qemu `-enable-kvm`:
  `Could not access KVM kernel module: No such device`. Kök neden: dmesg'de
  **`Hyper-V: Nested features: 0x0`** — Hyper-V nested virt'i WSL2 guest'ine hiç
  geçirmiyor (cpuinfo'da vmx/svm yok). `.wslconfig`'de `nestedVirtualization=true`
  YAZILI ama etki etmemiş → muhtemelen `wsl --shutdown` ile yeniden başlatılmalı.
  dmesg'de **VMware vmxnet3** görünmesi Windows host'un kendisinin bir VMware VM'i
  olabileceğini düşündürüyor (üçlü nesting → VMware katmanında VT-x/EPT expose gerekir).
  **Geçici çözüm: TCG fallback çalışıyor** (yavaş; spec'e göre yalnız manuel
  PoC/differential — asıl throughput değil). KVM'i açmak WSL-dışı, host-side iş.

### Doğrulama (kanıt, iddia değil)
- **Kernel**: `.lab/build/bzImage` (40M, `7.2.0-g5e289c5a4a52`); `readelf -S vmlinux`
  → `.BTF` + `.BTF_ids` section'ları mevcut.
- **VM boot (otomatik, `verify-vm.sh`)**: userspace'e ulaştı; VM içinden:
  **BTF present (6,841,473 bytes)**, **bpffs mounted**, **kcov present** — üçü de PASS.
  Serial log `.lab/verify-serial.log`.
- **KVM vs TCG**: KVM boot userspace'e ulaşamadı (yukarıdaki neden) → **TCG fallback
  ile PASS**. Yani ortam çalışır, hızlandırma host-side açılınca KVM'e geçecek.

### Dokunulan dosyalar
- `scripts/{fetch-kernel,build-kernel,create-rootfs,boot-vm,verify-vm}.sh` (yeni)
- `config/qemu/launch-kvm.sh`, `config/qemu/launch-tcg.sh` (gerçek/çalışır)
- `justfile` (gerçek recipe'ler)
- `.lab/` (build artefaktları; gitignore)

### Sonraki adımlar
- **KVM'i aç** (kullanıcı, host-side): Windows'ta `wsl --shutdown` → yeniden aç →
  `egrep -c '(vmx|svm)' /proc/cpuinfo` > 0 ve qemu `-enable-kvm` doğrula. Host bir
  VMware VM'i ise VMware ayarlarında "Virtualize Intel VT-x/EPT" aç.
- **go kur + syzkaller** derle (fuzzing stack).
- Gerçek **`FuzzDriver`** (vmctl → boot-vm.sh/launch script'leri; syzkaller manager).
- Gerçek **native-format `RecordParser`**'lar; **dış ground-truth loader**'ları
  (artık kaynak dosyalar `.lab/bpf-next` içinde yerel).
  → syzkaller kuruldu ve TCG'de fuzzing yapıyor, bkz. 0009.

---

## 0009 — syzkaller entegrasyonu (PRIMARY fuzzer) + VM ağ düzeltmesi

- **Tarih:** 2026-08-25
- **Durum:** Tamamlandı — syzkaller TCG'de gerçek kernel'imizde fuzzing yapıyor.
- **Alan:** `scripts/` (setup/gen-config/run), `config/syzkaller/`, `justfile`,
  `scripts/create-rootfs.sh` (ağ düzeltmesi)
- **İlgili:** 0008 (kernel/VM ortamı)

### Ne yapıldı
Fuzzing stack'in birincil aracı **syzkaller** kuruldu ve self-built bpf-next
kernel'imize karşı çalışır hale getirildi (KVM yok → TCG). Kullanıcı Windows 10 +
nested-virt olmadığı için TCG kalıcı yol; syzkaller kendi QEMU VM'lerini yönetir.

- **`scripts/setup-syzkaller.sh`** — Go yoksa resmi tarball'dan kurar (Go 1.26.5),
  syzkaller'ı klonlar + derler (`-j24`). Host bin'ler (`syz-manager` vb.) + target
  `syz-executor` üretildi.
- **`scripts/gen-syz-config.sh`** — lab layout'undan gerçek `syz-manager` config'i
  üretir: `type: qemu`, **TCG** (`-accel tcg,thread=multi -cpu qemu64`),
  **bpf-odaklı** `enable_syscalls: ["bpf*"]` (verifier = `BPF_PROG_LOAD` yolu),
  paralel VM (count=4), `sandbox: none`. Absolute path'ler .lab'den.
- **`scripts/run-syzkaller.sh`** — `DURATION=<s>` ile sınırlı kampanya (benchmark).
- **`justfile`** — `setup-syzkaller` + `run-fuzzers`.

### VM ağ hatası (asıl uğraş) — teşhis ve düzeltme
İlk kampanya **5 dk boyunca hiç fuzzing yapmadı** — syz-manager 4 VM oluşturdu ama
sessizce boot-timeout bekliyordu (VM'e bağlanamıyordu).

**Kademeli izolasyon (kanıt, tahmin değil):**
1. Kendi launch'ımızla (virtio-net) VM'e host'tan **ssh başarılı** →
   `enp0s3 UP 10.0.2.15/24`, sshd + host key'ler tamam. Yani **image sağlam**.
2. `syz-manager -debug` → syzkaller'ın gerçek qemu komutu + VM konsolu:
   NIC = **`e1000`** PCI slot 4 → arayüz **`enp0s4: renamed from eth0`**; ardından
   tekrarlayan **`ssh failed: exit status 255`**.
3. Kök neden: rootfs'in `/etc/network/interfaces`'ı sadece `eth0`/`enp0s3`'ü
   kapsıyordu; syzkaller'ın `enp0s4`'ü DHCP config dışında → IP yok → ssh yok.

**Düzeltme:** image ağını **isim-bağımsız** yaptım — `systemd-networkd` wildcard
unit (`[Match] Name=en* eth*` → `DHCP=yes`). Hem mevcut image'ı **loop-mount** ile
yamaladım (WSL2'de loop mount çalıştı) hem `create-rootfs.sh`'i kalıcı güncelledim
(ifupdown per-isim yerine networkd wildcard + `systemctl --root enable`).

**Yan ders (kendi tanılama hatam):** `pkill -f qemu-system`, komut satırında
"qemu-system" **stringi geçen background bash'in kendisini** öldürüyordu (self-kill,
exit 144, hedef process hiç çalışmadı). Çözüm: `pkill -x qemu-system-x86_64`
(tam-isim eşleşmesi).

### Tasarım kararları / seçimler
1. **TCG kalıcı** (KVM yok, 0008) — `qemu_args`'te `-accel tcg,thread=multi`.
2. **bpf-odaklı `enable_syscalls: ["bpf*"]`** — spec'in "bpf() + related" odağı;
   verifier `BPF_PROG_LOAD`'da çalışır. syzkaller 8300'den **44 syscall** enable etti.
3. **İsim-bağımsız ağ** (`systemd-networkd` wildcard) — herhangi bir QEMU NIC
   adı/slot'u için sağlam; syzkaller-uyumlu image'ların standart yaklaşımı.
4. **Go resmi tarball** (apt Go çok eski) — 1.26.5.

### Doğrulama (kanıt)
- **Bağlantı**: `-debug` sonrası → `scp /syz-executor` (ssh çalışıyor) →
  `/syz-executor runner` → `proc 0: got execute reply` → programlar VM'de yürüyor
  (`netlink: ...` çıktıları).
- **Machine check**: `Coverage: enabled`, `ExtraCoverage: enabled` (KCOV feedback),
  `syscalls: 44/8300` (bpf odağı), corpus büyüyor.
- **Throughput (TCG, 5 dk, count=4)**: ~90s ısınma (TCG'de VM boot + machine check
  + corpus triage), sonra kararlı fuzzing. Isınma sonrası pencere: `exec total`
  44→1207, `coverage` 0→5177 BB, `corpus` 2→45 — yani **~40-45 exec/sn (4 VM
  toplam)**, hâlâ tırmanıyorken. **KCOV feedback döngüsü çalışıyor** (coverage
  30 sn'de 0→5177). Crash yok (5 dk'lık minik koşuda beklenen). KVM'de bu ~10-20x
  daha yüksek olurdu; ama period=exec-count olduğu için loop mantığı etkilenmez.

### Dokunulan dosyalar
- `scripts/{setup-syzkaller,gen-syz-config,run-syzkaller}.sh` (yeni)
- `scripts/create-rootfs.sh` (ağ: ifupdown → systemd-networkd wildcard)
- `justfile` (setup-syzkaller, run-fuzzers)
- `.lab/syzkaller/` (klon+build), `.lab/images/rootfs.img` (yamalı)

### Sonraki adımlar
- syzkaller'ın DEFAULT native çıktısını `ingest` ile toplayıp gerçek
  **`RecordParser`** yazmak (syzkaller verifier log / KCOV → CORE şeması).
- Gerçek **`FuzzDriver`** (vmctl → syz-manager'ı yönetir; exec sayacını N period'a bağlar).
- Throughput'u artırmak: count/procs ayarı, KASAN'sız "hızlı" kernel (hacim fazı).


## 0010 — Golden fixture (parser-katmanı guardrail) + git init + veri-kaynağı netleştirmesi

- **Tarih:** 2026-08-26
- **Durum:** Tamamlandı — normalize artık committed bir golden anchor'a sahip; repo git altında.
- **Alan:** `crates/pipeline` (normalize + tests), `examples/report_demo.rs`,
  mimari doc, repo kökü (git).
- **İlgili:** 0004 (normalize/CORE şeması), 0009 (syzkaller).

### Ne yapıldı
1. **Repo git'e alındı.** `git init` (branch `main`), ilk commit `bf506f1`:
   kaynak + `config/` + `scripts/` + `docs/` + devlog + `REVIEW-HANDOFF.md` (72 dosya).
   `.lab/`, `target/`, `*.img`, `bzImage`, ssh anahtarları `.gitignore` ile dışarıda —
   commit öncesi guard'larla teyit (1MB üstü / ağır artifact sızıntısı yok).
   "Kalıcı hafıza devlog'dur" cümlesi artık gerçek bir güvence.
2. **`ReferenceParser` kütüphaneye taşındı** (`normalize.rs`). Daha önce
   `report_demo` içinde yaşayan `DemoParser` mantığı tek bir **known-good**
   tanıma indirgendi: sentinel `clean`/`buggy` satırları → **tam CORE kaydı**
   (tnum, register-state, JIT/interp diff, helper ihlali). `buggy` her downstream
   sinyalini bilerek tetikler (malformed tnum `value&mask!=0`, retval sapması,
   helper `arg_type` ihlali). Gerçek tool parser'ı DEĞİL — golden fixture'ın
   deterministik kaynağı.
3. **Committed golden fixture** (`crates/pipeline/tests/fixtures/golden/`):
   `verifier.log` (ham girdi) + `normalized.expected.json` (bilinen-doğru
   `NormalizedMetrics`, kodun **gerçek** çıktısından üretildi, elle değil).
4. **Regresyon testi** `crates/pipeline/tests/golden_normalize.rs`:
   `ingest(golden raw) → normalize(ReferenceParser)` çıktısının committed golden'a
   **birebir** eşit olduğunu doğrular. `serde_json` dev-dependency eklendi.
5. **`report_demo` inceltildi** — yerel `DemoParser` silindi, `normalize::ReferenceParser`
   kullanılıyor (tek kaynak; pipeline davranışı değişmedi).
6. **Örnek syzkaller kampanyası** (200 sn) koşuldu → syzkaller'ın DEFAULT native
   çıktısının ne olduğu somut olarak keşfedildi (aşağıda).
7. **Mimari doc netleştirildi** — §4'e "hangi araç hangi CORE alanını üretir"
   veri-kaynağı haritası eklendi.

### Neden (reviewer notu — parser-katmanı confirmation-bias guardrail)
Anomali sinyalleri (diff invariant'ları, scoring) normalize'ın **downstream'inde**.
Bu yüzden hatalı bir parser, verifier bug'ı gibi görünen **sahte divergence** üretir.
İlk gerçek period'da yüzeye çıkan ilk "bug"lar büyük ihtimalle **parser'ın kendi
hataları** olur. Golden anchor bu ikisini ayırır: golden test'teki her drift =
**parser/şema regresyonu**; test geçerken çıkan her sapma = **gerçek verifier
anomalisi** adayı. Bu, döngünün confirmation-bias guardrail'inin parser
seviyesindeki karşılığıdır. (Hafızaya `parser-golden-fixture-guardrail` olarak yazıldı.)

### Keşif — syzkaller DEFAULT çıktısı ve veri-kaynağı ayrımı (önemli)
200 sn'lik kampanyanın diskteki tüm çıktısı: `manager log + workdir/corpus.db
(+ crashes/)`. **syzkaller tek başına verifier'ın accept/reject + register-state
evrimini ÜRETMEZ** — o veri kernel'in verifier **log buffer**'ında
(`BPF_PROG_LOAD .log_level=2`) ve dmesg'de. Sonuç: verifier-semantik CORE
alanlarının birincil üreticisi **differential harness**'tir; syzkaller'ın işi
coverage-güdümlü input üretimi + crash yüzeye çıkarmadır. Dolayısıyla "gerçek
per-tool parser" tek değil **iki** parser'a bölünür (syz coverage/crash + harness
verifier-log). Detaylı tablo mimari doc §4'te.

### Tasarım kararları (bu adımda verilen)
1. **Golden'ı elle yazma, koddan üret** — `report_demo` çıktısının `.payload`'ı
   golden olarak kaydedildi; drift'e karşı otoritesi kodun kendisidir.
2. **`ReferenceParser` library'de** (demo + test tek kaynaktan; duplikasyon yok).
3. **`exec_count=4200` golden'a gömülü**; test sabiti (`GOLDEN_EXEC_N`) eşleştirir —
   provenance damgası (exec_n) golden'ın parçası.
4. **Karşılaştırma struct düzeyinde** (`assert_eq` on `NormalizedMetrics`), JSON
   string düzeyinde değil — formatlama/anahtar-sırası kırılganlığı yok.

### Kapsam dışı / hâlâ stub
- Gerçek **syzkaller coverage/crash parser'ı** ve **differential-harness verifier-log
  parser'ı** (golden bunların hedef çıktısını değil, normalize montajını sabitler).
- Differential harness'in kendisi (kod olarak henüz yok; §4'te tasarım olarak var).
- Gerçek `FuzzDriver`, dış ground-truth loader'ları — değişmedi.

### Doğrulama (kanıt)
- `cargo test` → **23 passed, 0 failed** (golden testi dahil; önce 22'ydi).
  `test reference_parser_reproduces_golden_normalized ... ok`.
- `report_demo` → `top_score=0.95 divergences=3` (davranış **değişmedi** —
  ReferenceParser'a geçiş regresyon getirmedi).
- Kampanya (200 sn, TCG, count=4): `machine check` geçti, `Coverage: enabled`,
  `ExtraCoverage: enabled`, `syscalls: 44/8300`, `corpus: 54`. **Dürüst not:**
  bu koşuda machine check ~100 sn sürdü, kalan ~65 sn candidate triage'de geçti →
  `coverage=0 exec total=26`'da kaldı; 0009'un 5 dk'lık koşusundaki 0→5177 BB
  büyümesine **ulaşılmadı** (pencere kısaydı). Stack canlı; coverage büyümesi için
  daha uzun pencere gerekir. Crash yok (beklenen).
- `git log -1` → `bf506f1`, working tree temiz.

### Dokunulan dosyalar
- `crates/pipeline/src/normalize.rs` (+ `ReferenceParser`)
- `crates/pipeline/tests/golden_normalize.rs` (yeni), `tests/fixtures/golden/*` (yeni)
- `crates/pipeline/Cargo.toml` (`serde_json` dev-dep)
- `crates/pipeline/examples/report_demo.rs` (DemoParser → ReferenceParser)
- `docs/eBPF Verifier ... Mimari ...md` (§4 veri-kaynağı haritası; §5 normalize satırı)
- repo: `.git/` (init), commit `bf506f1`

### Sonraki adımlar
- **Differential harness** (verifier-semantik CORE'un üreticisi): accepted programı
  `log_level=2` ile yükle → log buffer'dan register-state + decision; `BPF_PROG_TEST_RUN`
  ile JIT vs interp retval/data_out. Bunun native çıktısından **gerçek verifier-log
  parser'ı** (golden pattern'iyle: gerçek ham örnek → beklenen normalized).
- **syzkaller coverage/crash parser'ı** (KCOV delta + crash raporu → CORE coverage_delta).
- Gerçek **`FuzzDriver`** (vmctl → syz-manager; exec sayacı → period N).


## 0011 — Differential/verifier-log harness v0 (guest-side C) + gerçek log örneği

- **Tarih:** 2026-08-26
- **Durum:** Tamamlandı (v0) — harness gerçek verifier-log üretiyor; decision +
  register-state. JIT↔interp ertelendi; in-VM authoritative capture + parser sonraki.
- **Alan:** `harness/` (yeni), `scripts/build-harness.sh` (yeni), mimari doc, `.gitignore`.
- **İlgili:** 0010 (veri-kaynağı haritası), 0009 (kernel/syzkaller).

### Ne yapıldı
syzkaller'ın üretmediği (0010) **verifier-semantik CORE sinyalini** üreten guest-side
harness yazıldı: **`harness/diffharness.c`** — raw `bpf()` syscall ile küçük BPF
programlarını `log_level=2` ile yükler, kernel verifier log buffer'ını **verbatim**
basar (minimal frame içinde). 3 program: `return0` (accept), `alu_state` (accept,
zengin register-state), `uninit_r0` (reject). **Host WSL kernel'de koşturulup
gerçek log formatı yakalandı** → `harness/samples/host-6.18-sample.txt`. Ayrıca
`scripts/build-harness.sh` (static tercih), `harness/README.md`, binary `.gitignore`'a.

### Neden
Verifier **logic bug** sinyalinin gerçek kaynağı budur: accept/reject + register-state
evrimi (tnum/bounds), syzkaller'ın crash/coverage'ından farklı bir eksen. Parser'ı
tahminle değil **gerçek formata** göre yazabilmek için önce gerçek örnek gerekti.

### Tasarım kararları (bu adımda verilen)
1. **C** — raw `bpf()`, sıfır bağımlılık, **static** derlenir → disposable VM'de
   değişmeden koşar. "Native output UNCHANGED" ilkesinin en temiz hâli.
2. **`SOCKET_FILTER`** prog type — root ile attach gerektirmeden yüklenir (v0 için ideal).
3. **`log_level=2`** — tam register-state evrimi.
4. **Native format** — `===PROG / RESULT / ---LOG--- <verbatim> / ---END---`.
   Harness'in kendi çerçevesi minimal; verifier log byte-for-byte içeride.
5. **JIT↔interp ertelendi** — aşağıdaki kısıt nedeniyle (iki kernel gerekir).

### Bulgular (önemli)
- **`CONFIG_BPF_JIT_ALWAYS_ON=y`** (hem fragment hem built `.config`) → interpreter
  derleme-dışı, `bpf_jit_enable` 1'e sabit → **tek kernel'de JIT↔interp differential
  İMKÂNSIZ**. Ayrı bir interpreter-only kernel + cross-kernel koşu ister; ertelendi.
  (Mimari doc §4 haritası buna göre düzeltildi — önceki hâli fazla iyimserdi.)
- **Gerçek log formatı** (parser'ın hedefi):
  - karar: `RESULT decision=accept|reject`;
  - reject reason: log içinde `R0 !read_ok` gibi satır (verbatim String);
  - register-state: `N: (op) ... ; Rk=13` satırları (const → compact değer);
  - sayaçlar: `processed N insns ... total_states T peak_states P`.
- Host sample **representative**; **authoritative** capture = aynı binary'yi
  bpf-next VM'inde (rev `.lab/kernel.rev`) koşmak — FuzzDriver wiring'in parçası.

### Doğrulama (kanıt)
- `cc -O2 -static` → 16 KB, `statically linked` (VM-uyumlu).
- `./harness/diffharness` (host): `return0` → accept, `processed 2 insns`;
  `alu_state` → accept, `R0` 1→8→8→13, `processed 5 insns`; `uninit_r0` → reject,
  `R0 !read_ok`, `errno=13`, `processed 1 insns`. Tümü `samples/host-6.18-sample.txt`'de.

### Kapsam dışı / hâlâ stub
- **Gerçek verifier-log parser'ı** (bu harness çıktısı → `CoreMetrics`) — sonraki adım.
- **In-VM authoritative capture** (bpf-next kernel) — FuzzDriver ile.
- **JIT↔interp** cross-kernel modu; **syzkaller coverage/crash parser'ı**.

### Dokunulan dosyalar
- `harness/diffharness.c`, `harness/README.md`, `harness/samples/host-6.18-sample.txt` (yeni)
- `scripts/build-harness.sh` (yeni)
- `.gitignore` (harness binary)
- `docs/eBPF Verifier ... Mimari ...md` (§4 JIT↔interp kısıtı düzeltmesi)

### Sonraki adımlar
- **Verifier-log parser'ı** (`normalize.rs`): bu sample'a karşı, **golden pattern'iyle**
  (gerçek raw → beklenen normalized CORE) — decision + reject reason + register-state
  + insn_processed. Golden guardrail buraya da uygulanır.
- **In-VM authoritative capture** + harness'i `RawObservation` akışına bağlamak.
- Gerçek **`FuzzDriver`** (vmctl → VM'de harness + syz-manager; exec sayacı → period N).


## 0012 — Verifier-log parser (`VerifierLogParser`) + gerçek veri uçtan uca

- **Tarih:** 2026-08-26
- **Durum:** Tamamlandı — harness'in gerçek çıktısı artık `CoreMetrics`'e parse
  ediliyor ve pipeline'dan uçtan uca akıyor.
- **Alan:** `crates/pipeline/src/verifier_log.rs` (yeni), `examples/harness_demo.rs`
  (yeni), `lib.rs`.
- **İlgili:** 0011 (harness), 0010 (golden guardrail), 0004 (CORE şeması).

### Ne yapıldı
**`pipeline::verifier_log::VerifierLogParser`** yazıldı — 0011 harness'inin native
formatını (`===PROG / RESULT / ---LOG--- <verbatim> / ---END---`) `Vec<CoreMetrics>`'e
çevirir. Çıkarılanlar: **decision** (accept/reject), **reject reason** (verbatim
String), **register-state evrimi** (per-insn snapshot; `; Rk=...` ve tam-durum
satırları), **processed** (`insn_processed`, `total_states`). Ayrıca
**`harness_demo`** example'ı: committed harness sample → `ingest → normalize(VerifierLogParser)
→ score → diff → report` (root/VM gerektirmez).

### Neden
Bu, 0011 harness'ini fiilen pipeline'a bağlayan parça (§2b parser). Artık gerçek
verifier gözlemi CORE şemasına giriyor — sentetik `ReferenceParser` değil.

### Tasarım kararları (bu adımda verilen)
1. **Sağlam reg-token tokenizer** — token sınırı yalnız ` R<digit>=` boundary'sinde;
   `var_off=(0x0; 0xff)` gibi parantez-içi boşluk/`;` bozmuyor (regex'siz, sıfır dep).
2. **tnum asla malformed üretilmez** — const → `tnum{v,0}` + exact bounds; bilinmeyen
   scalar → `value=0` (yani `value&mask==0` hep tutar). Böylece parser, `diff`'in
   tnum invariant'ında **false-positive tetiklemez** — parser-katmanı guardrail'in
   somut hâli.
3. **Non-scalar** (ctx/fp/map_value) → `reg_type` **verbatim** prefix; tnum/bounds default.
4. **`jit_interp_diff = None`** — ALWAYS_ON kernel (0011); helper ihlalleri **diff**'te
   karar verilir, burada değil; `states_processed = total_states`.

### Doğrulama (kanıt)
- **5 unit test** (`verifier_log`): 3 programın parse'ı + `R0` evrimi `[1,8,8,13]` +
  reject reason `"R0 !read_ok"` + `var_off` tokenizer'ı. Full suite **23 → 28 passed, 0 failed**.
- **`harness_demo`** (gerçek sample, uçtan uca): 3 gerçek kayıt —
  `rec0 accept insn=2`, `rec1 accept insn=5`, `rec2 reject "R0 !read_ok" insn=1` —
  ve **0 anomali / 0 divergence**. Bu **doğru** sonuç: temiz + meşru-reddedilmiş
  programlar false finding üretmemeli → parser sahte sinyal uydurmuyor.

### Kapsam dışı / hâlâ stub
- Tam `scalar(umin=...,umax=...,var_off=...)` formu **best-effort** (host sample'da
  yok; unit test'te sentetik olarak var). In-VM authoritative capture ile doğrulanacak.
- **In-VM authoritative capture** (bpf-next log formatı), **JIT↔interp** cross-kernel,
  **syzkaller coverage/crash parser'ı**, gerçek **`FuzzDriver`**.

### Dokunulan dosyalar
- `crates/pipeline/src/verifier_log.rs` (yeni, parser + testler)
- `crates/pipeline/examples/harness_demo.rs` (yeni)
- `crates/pipeline/src/lib.rs` (`pub mod verifier_log;`)

### Sonraki adımlar
- Gerçek **`FuzzDriver`** — `vmctl` ile VM'de harness (ve syz-manager) sürüp
  çıktıyı `RawObservation` akışına bağla; exec sayacını period N'e bağla.
  Bu, `MockDriver`'ı gerçekle değiştirir ve **ilk gerçek period**'u koşturur.
- **In-VM authoritative capture**: aynı harness'i bpf-next VM'inde koşup
  log formatını doğrula (register-state verbosity host'tan farklı olabilir).
- **syzkaller coverage/crash parser'ı** (KCOV delta + crash → CORE coverage/crash).
