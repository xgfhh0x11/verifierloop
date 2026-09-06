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
| 0013 | Gerçek `FuzzDriver` (VmHarnessDriver) + in-VM capture + **ilk gerçek period canlı** | Tamamlandı (loop gerçek bpf-next VM'de koşuyor; MockDriver değişti) |
| 0014 | Harness zenginleştirme: ranged-scalar programlar → full-scalar path + diff gerçek veride | Tamamlandı (parser chained-value fix; diff invariant'ları gerçek ranged-state'te koşuyor) |
| 0015 | Detektör kalibrasyonu: diff true-positive'i GERÇEK parser yolunda kanıtlandı | Tamamlandı (temizde susar, enjekte tutarsızlıkta bağırır) |
| 0016 | Helper kolu: parser-kapsaması + bpf_func_proto dilimi/loader + helper true-positive | Tamamlandı (expected LOADER'dan; provenance çıktıda gösterildi) |
| 0017 | Unparsed politikası: parser kör noktaları ayrı kovada (hacimden önce) | Tamamlandı (blok→unparsed, satır→note; asla anomali; rapor ayrı gösterir) |
| 0018 | **İlk syzkaller-güdümlü hacimli period** + hacmin çıkardığı 5 parser kör noktası | Tamamlandı (70 kayıt, 20 gerçek reject metni, 0 divergence) |
| 0019 | Kör nokta oranı ölçüldü (**%0**) + proto dilimi 8 helper'a genişletildi (helper kolu uyandı) | Tamamlandı (accept-only kapısı; 0 false positive) |
| 0020 | 2. hacimli period (2x corpus): kör nokta **%0 korundu**, helper kolu **82 kontrol** | Tamamlandı (+ 2 crash: TCG artefaktı, verifier bug'ı değil) |
| 0021 | `bpf_func_proto` **auto-extraction** (OI-4 kapandı): 12→274 kontrat, 8→194 helper | Tamamlandı (101 kontrol, 0 false positive) |
| 0022 | **Üçüncü dedektör kolu**: documented-behavior (verifier.rst) — alıntı-çapalı, drift-tespitli | Tamamlandı (3 vaka canlı; kalibre) |
| 0023 | **patch-diff (kaynak 4)**: doküman-vs-kod bayatlık kanıtı + SCC parser kör noktası | Tamamlandı (doküman 351 commit geride) |
| 0024 | **`verifier.rst` mesaj bölümü**: 11 örnek program → ilk SAĞLAMLIK ölçümü + `notes` (kanıt) kanalı | Tamamlandı (13 vaka; 12/12 karar uyuştu; 1 vaka kaynakta doğrulanmış önkoşulla superseded) |
| 0025 | **Hedefli üretim** (242 enumerative program) + intrinsic kolun eksik paydası | Tamamlandı (syzkaller hacmi: 0 kontrol edilebilir gözlem; hedefli: 1497) |
| 0026 | **32↔64 senkron kolu**: CORE'a 32-bit görünüm + 3 invariant + karışık-genişlik aile (396) | Tamamlandı (32↔64 paydası 0 → 353; yol boyunca 10 sahte bulgu üreten parser hatası düzeltildi) |

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
  `register_evolution: Vec<RegSnapshot{ insn_idx, regs: Vec<RegState{ reg, reg_type, tnum{value,mask}, umin/umax/smin/smax }> }>`,
  `Processed{ insn_processed, states_processed }`, `Option<JitInterpDiff>`,
  `CoverageDelta{ new_bb, exec_n }`, `Vec<HelperArgViolation>`. `reg_type` ve reject `reason`
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
- **`AnomalyScores` payload'ı**:
  `{ exec_count, scored: [{index, score, reasons}], summary: {record_count, flagged, max_score}, method }`.
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
- **`DIFF_FINDINGS` payload'ı (donduruldu, serde):**
  `DiffFindings { exec_count, findings: Vec<DivergenceFinding>, summary }`;
  `DivergenceFinding { record_index: Option<u64>, source, kind, aspect, expected, observed, detail }`;
  `GroundTruthSource` enum (verifier_c/documentation/helper_proto/patch_diff/
  **logical_invariant**, snake_case);
  `DiffSummary { record_count, finding_count, by_source }`.
  `kind`/`aspect`/`expected`/`observed` = verbatim String.
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
- **`PERIOD_REPORT` payload'ı (donduruldu, serde):**
  `PeriodReport { exec_count, generated_unix: Option<u64>, items: Vec<TriageItem>, period_findings: Vec<DivergenceFinding>, summary }`;
  `TriageItem { record_index, score, score_reasons, divergences }`;
  `ReportSummary { record_count, flagged, divergence_count, top_score }`.
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
- **End-to-end (tam pipeline, gerçek Python)**:
  `cargo run -p pipeline --example report_demo -- <dir>` → ingest → normalize →
  score (python3) → diff → report →
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
- **`scripts/build-kernel.sh`** —
  `defconfig + kvm_guest.config + lab fragment + olddefconfig`, sonra
  `-j24 bzImage`. bzImage 40M, vmlinux 569M, **BTF gömülü**.
- **`scripts/create-rootfs.sh`** — `debootstrap` Debian bookworm minimal → raw ext4
  (`mkfs.ext4 -d`, **loop-mount YOK** → WSL2'de sağlam). Serial autologin (root),
  sshd + üretilen ed25519 anahtar, DHCP, ve `init=` ile koşan `/root/verify.sh`.
  Image 452M.
- **`config/qemu/launch-{kvm,tcg}.sh`** — placeholder'dan gerçek/çalışır:
  `panic=1 oops=panic nokaslr`, ssh port-forward, `-no-reboot`, `-snapshot`
  (disposable).
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
200 sn'lik kampanyanın diskteki tüm çıktısı:
`manager log + workdir/corpus.db (+ crashes/)`.
**syzkaller tek başına verifier'ın accept/reject + register-state
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
**`harness_demo`** example'ı: committed harness sample →
`ingest → normalize(VerifierLogParser) → score → diff → report`
(root/VM gerektirmez).

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


## 0013 — Gerçek `FuzzDriver` (VmHarnessDriver) + in-VM capture + ilk gerçek period canlı

- **Tarih:** 2026-08-26
- **Durum:** Tamamlandı — döngü gerçek bpf-next VM'inde canlı koşuyor; `MockDriver`
  yerini gerçek VM-destekli sürücüye bıraktı; **ilk gerçek period** uçtan uca çalıştı.
- **Alan:** `scripts/run-harness-vm.sh` (yeni), `orchestrator::driver` (VmHarnessDriver),
  `examples/real_period.rs` (yeni), `verifier_log.rs` (reject-reason fix), `loop_runtime` (mesaj),
  `harness/samples/bpf-next-sample.txt` (yeni, authoritative).
- **İlgili:** 0011/0012 (harness + parser), 0003 (loop spine), 0008 (VM).

### Ne yapıldı
1. **`scripts/run-harness-vm.sh`** — harness'i disposable bpf-next VM'inde koşup
   DEFAULT native çıktısını host'ta yakalar. verify-vm deseni: `init=/root/run-harness.sh`
   + **seri konsol** (ssh yok, ağ/timing derdi yok). Binary loop-mount ile rootfs'e
   enjekte edilir; boot `-snapshot` olduğu için VM yazımları ephemeral. Bu aynı
   zamanda **in-VM authoritative capture**.
2. **Rust gerçek sürücü** (`orchestrator::driver`):
   - `HarnessRunner` trait — VM ağır işini soyutlar (VM'siz test için enjekte edilebilir).
   - `VmHarnessDriver<R>` — `FuzzDriver` impl; her `pump` harness batch'ini koşar,
     `ingest`'i yakalanan çıktıya yöneltir; **exec = kümülatif program sayısı** (period sınırı).
   - `ScriptRunner` — `run-harness-vm.sh`'i çağırır; `FakeRunner` — VM'siz unit test.
3. **`real_period` example** — `run_period` ile **canlı harvest** + downstream
   pipeline (normalize→score→diff→report). `loop_runtime::run()` mesajı buna yönlendirir.
4. **Parser düzeltmesi** — aşağıdaki authoritative-capture bulgusu.

### Bulgu (önemli) — bpf-next host'tan zengin log üretiyor
In-VM capture, host formatından farkları ortaya çıkardı: **ön-analiz blokları**
(`topo_order`, `subprog#0: analyzing`, `stack use/def`) ve **çok satırlı reject
diagnostic** (`Verification failed: ... / Reason: ... / Suggestion: ...`).
Parser'ın eski reject-reason heuristic'i ("son anlamlı satır") yeni formatta
yanlışlıkla **"Suggestion:" satırını** yakalıyordu. → **forward-scan**'e çevrildi:
state section'dan sonraki **ilk** arıza satırı (`R0 !read_ok`), hem host hem
bpf-next'te stabil. Register-state kısmı zaten sağlamdı (girintili preamble
atlanıyor). **In-VM authoritative capture bu parser açığını yakaladı — golden/guardrail
felsefesinin işlemesi.** Authoritative sample commit'lendi + parser testi `include_str!`
ile ona pinlendi.

### Tasarım kararları (bu adımda verilen)
1. **`init=` + seri konsol** (ssh değil) — verify-vm deseni; ağ/ssh timing yok, sağlam.
2. **Loop-mount enjeksiyon + `-snapshot`** — taze binary base image'e yazılır, VM
   yazımları ephemeral kalır (disposability korunur).
3. **`HarnessRunner` injection** — RecordParser/GroundTruth deseninin aynısı; sürücü
   VM'siz unit-test edilebilir (`FakeRunner`).
4. **exec = `===PROG` blok sayısı**; `exec_threshold=1` → tek harness batch tek VM
   boot'ta period'u kapatır (v0 için doğru granülarite).

### Doğrulama (kanıt)
- Full suite **28 → 31 passed, 0 failed** (parser bpf-next testi + 2 vm_driver testi).
- `run-harness-vm.sh` **canlı**: bpf-next VM boot → harness → **3 blok** yakalandı.
- `real_period` **canlı (exit 0)**:
  `HARVEST period=1 exec_count=3 collected_files=1`;
  `PERIOD REPORT records=3 flagged=0 divergences=0`;
  `rec0 accept insn=2`, `rec1 accept insn=5`, `rec2 reject "R0 !read_ok" insn=1`;
  **0 anomali** (temiz + meşru-reddedilmiş programlar için doğru).

### Kapsam dışı / hâlâ stub
- **syzkaller-driven execs** — harness şu an sabit 3-program corpus'u koşuyor;
  syzkaller'ın ürettiği programları harness'e beslemek + coverage/crash parser'ı ayrı.
- **JIT↔interp** cross-kernel modu (ALWAYS_ON, 0011).
- **`vmctl`** hâlâ script'i sarmıyor (Rust wrapper sonraki); çok-batch accumulation
  (v0 son batch'i harvest eder; `exec_threshold=1` ile tek batch).

### Dokunulan dosyalar
- `scripts/run-harness-vm.sh` (yeni)
- `crates/orchestrator/src/driver.rs` (HarnessRunner/VmHarnessDriver/ScriptRunner + testler)
- `crates/orchestrator/examples/real_period.rs` (yeni)
- `crates/orchestrator/src/loop_runtime.rs` (`run()` mesajı)
- `crates/pipeline/src/verifier_log.rs` (reject-reason forward-scan + bpf-next testi)
- `harness/samples/bpf-next-sample.txt` (yeni, authoritative in-VM capture)

### Sonraki adımlar
- **syzkaller → harness besleme**: syzkaller'ın ürettiği programları/corpus'u harness'e
  verip verifier'ı gerçek fuzz yüzeyinde koştur; **syzkaller coverage/crash parser'ı**
  (KCOV delta + crash → CORE) ekle. Bu, ilk gerçek bug avı yüzeyi.
- **Daha zengin harness corpus'u** (pointer aritmetiği, helper çağrıları, map erişimi)
  → daha çok register-state + gerçek helper `arg_type` sinyali.
- **`vmctl`** Rust wrapper (script yerine); **interpreter kernel** modu (JIT↔interp).


## 0014 — Harness zenginleştirme: ranged-scalar programlar → full-scalar path + diff gerçek veride

- **Tarih:** 2026-08-27
- **Durum:** Tamamlandı — harness artık ranged/unknown-bit scalar üreten programlar
  koşuyor; parser bunların **full `scalar(...)`** formunu gerçek bpf-next verisinde
  doğru çözüyor; diff'in intrinsic invariant'ları gerçek varyasyonlu register-state'te koşuyor.
- **Alan:** `harness/diffharness.c` (+3 program), `verifier_log.rs` (chained-value fix + test),
  `harness/samples/bpf-next-sample.txt` (6 program), `examples/harness_demo.rs`.
- **İlgili:** 0011/0012 (harness+parser), 0013 (ilk gerçek period). Reviewer'ın
  "diff gerçek-veride denenmedi / full-scalar denenmedi" açığını kapatır.

### Ne yapıldı
Harness'e ctx okuyup **ranged/unknown-bit scalar** üreten 3 program eklendi:
`ranged_and` (`r0 = *(u32*)(r1+0); r0 &= 0xff` → `var_off=(0x0; 0xff)`),
`shift_unknown` (`r0 <<= 8` → known-zero düşük bitler), `bounded_cmp` (karşılaştırmayla
umax daralması). Bunlar verifier'ın **full `scalar(...)`** formunu tetikler — const
compact form değil. Authoritative bpf-next sample 6 programa güncellendi; parser testi
full-scalar assertion'larıyla genişletildi; `harness_demo` enriched sample'a çevrildi.

### Bulgu (önemli) — gerçek scalar formu "chained-value" içeriyor
Gerçek çıktı (host + bpf-next aynı):
`R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=255, var_off=(0x0; 0xff))`.
Yani **tek sayı birden çok alan adı tarafından paylaşılıyor**
(`smax=umax=...=255`). Parser'ın eski field okuması "smax="den sonra sayı bekliyordu,
ama "umax=" görüyordu → smax'ı **kaçırıyordu**. → **`value_after_key`** ile düzeltildi:
key'den sonra `word=` zincirlerini atlayıp sondaki sayıya ulaşır. tnum var_off'tan;
umin yokken default 0 (verifier bastırınca implied 0).

### Doğrulama (kanıt)
- `verifier_log` **6 test** (full-scalar assertion'ları gerçek veride):
  `ranged_and` → `tnum{0, 0xff}`, `(umin,umax)=(0,255)`, `(smin,smax)=(0,255)`;
  `shift_unknown` → `tnum.mask=0xffffffff00`; her rec'te `value & mask == 0`
  (parser tutarsızlık üretmiyor). Full suite **31 passed**.
- `harness_demo` (enriched, uçtan uca): **6 gerçek kayıt** (rec3/4/5 ranged-scalar),
  `PERIOD REPORT records=6 flagged=0 divergences=0`. **diff'in intrinsic invariant'ları
  (tnum iyi-biçimlilik, bound sırası, tnum/bounds tutarlılık) artık GERÇEK ranged
  register-state'lerde koşuyor** ve 0 divergence buluyor — gerçek verifier tutarlı
  olduğu için doğru (false positive yok). Logic-bug tespit yolu artık gerçek varyasyonlu
  veride denenmiş durumda.

### Kapsam dışı / hâlâ stub
- Hâlâ **sabit corpus** (6 program, generator değil) — pointer aritmetiği, helper
  çağrıları, map erişimi sonraki zenginleştirme (gerçek helper `arg_type` sinyali için).
- **syzkaller coverage/crash** entegrasyonu (aggregate → DERIVED) ayrı iş.
- diff'in **true-positive**'ini kanıtlayan kasıtlı-tutarsız-state testi (şimdilik yalnız
  sentetik `report_demo` malformed tnum üretiyor).

### Dokunulan dosyalar
- `harness/diffharness.c` (+`BPF_LDX_MEM` makrosu, +3 program)
- `crates/pipeline/src/verifier_log.rs` (`value_after_key` chained-value fix + test)
- `harness/samples/bpf-next-sample.txt` (6 program, authoritative in-VM)
- `crates/pipeline/examples/harness_demo.rs` (enriched sample)

### Sonraki adımlar
- Daha zengin corpus: **pointer aritmetiği + helper çağrıları + map erişimi** →
  gerçek helper `arg_type` ihlali sinyali + PTR_TO_* register tipleri.
- **syzkaller coverage/crash → DERIVED** (fuzzer sinyalini periyoda bağla).
- diff için **kasıtlı-tutarsız-state** birim testi (true-positive kanıtı).


## 0015 — Detektör kalibrasyonu: diff'in true-positive'i GERÇEK parser yolunda kanıtlandı

- **Tarih:** 2026-08-27
- **Durum:** Tamamlandı — diff'in intrinsic invariant'ları artık gerçek
  `VerifierLogParser` yolunda hem **susma** (temiz) hem **doğru bağırma** (enjekte
  tutarsızlık) yönünden kanıtlı.
- **Alan:** `crates/pipeline/tests/diff_detector_calibration.rs` (yeni).
- **İlgili:** 0014 (diff gerçek ranged-state'te koşuyor), 0006 (diff invariant'ları).
  Reviewer'ın §7-şüphe-2'sini kapatır.

### Ne yapıldı
Bir **detektör-kalibrasyon** integration testi eklendi. Gerçek harness native
formatındaki bir bloğu (bpf-next `ranged_and`) tam gerçek yoldan geçirir:
`ingest → normalize(VerifierLogParser) → diff`. Üç test:
1. **`silent_on_clean_real_state`** — temiz, kendi-içinde-tutarlı gerçek state → **0 bulgu**.
2. **`shouts_on_injected_inconsistency_via_real_parser`** — maskeli scalar'ın tnum'ına
   tek-karakter fault enjekte edilir (`var_off=(0x0; 0xff)` → `(0x1; 0xff)`, yani
   `value & mask != 0`, malformed tnum) → diff **`tnum_malformed`** yakalar.
3. **`control_and_mutant_differ_only_by_the_injection`** — kontrol ile mutant tam
   **tek karakter** farklı; dolayısıyla sonuç farkının tek sebebi dedektörün o
   faulta tepkisi.

### Neden (reviewer'ın önceliklendirmesi — hacimden ÖNCE)
Bir dedektörün **susması** ile **doğru bağırması** ayrı ispatlardır. diff'in
true-positive'i o ana dek yalnız sentetik `report_demo`'da (ReferenceParser)
kanıtlıydı; gerçek parser yolunda dedektörün gerçek bir tutarsızlığı yakaladığı
gösterilmemişti. Bu, **syzkaller-hacmini açmadan önce** gelmeli: aksi halde sistem
binlerce program koşup "0 anomali" derse, bunun *temiz corpus* mu yoksa *sağır
dedektör* mü olduğu ayırt edilemez. Önce dedektörün gerçek yolda bir kez doğru
bağırdığını gör, sonra hacmi aç — periyodik-hasat çıktısına güvenmenin ön koşulu.

### Tasarım kararı (bu adımda verilen)
- **Fault-injection gerçek native formatta** yapıldı (gerçek verifier talep üzerine
  bug üretemez), tek-karakter mutasyonla — böylece kontrol/mutant yalnız enjeksiyonla
  ayrışır. **malformed tnum** seçildi çünkü invariant'a birebir eşleşir
  (`value & mask == 0` ihlali) ve hedef substring maskeli satıra özgü (geniş scalar
  `0xffffffff))` ile bitiyor, dokunulmuyor).

### Doğrulama (kanıt)
- `diff_detector_calibration` → **3 passed**. Full suite **31 → 34 passed, 0 failed**.
- `silent_on_clean_real_state`: temiz gerçek blok → `findings` boş.
- `shouts_...`: enjekte malformed tnum → `tnum_malformed` bulgusu (gerçek parser yolunda).

### Kapsam dışı / hâlâ stub
- Diğer invariant'lar (bound inversion, tnum/bounds inconsistency) gerçek-path'te
  ayrıca değil sentetik unit testte kanıtlı — tek true-positive kalibrasyon için
  yeterli; istenirse genişletilir. `jit_interp` bacağı ALWAYS_ON nedeniyle zaten ölü.
- Gerçek bir verifier bug'ı hâlâ yüzeye çıkmadı (beklenen — corpus temiz + kernel doğru).

### Dokunulan dosyalar
- `crates/pipeline/tests/diff_detector_calibration.rs` (yeni)

### Sonraki adımlar
- Dedektör artık kalibre → **güvenle** ya syzkaller-hacmi (fuzz volume) ya da daha
  zengin corpus (helper çağrıları → helper `arg_type` oracle kolunu gerçek veride tetikle).


## 0016 — Helper kolu: parser-kapsaması + `bpf_func_proto` dilimi/loader + helper true-positive kalibrasyonu

- **Tarih:** 2026-08-27
- **Durum:** Tamamlandı — helper arg-type mismatch'i artık gerçek yolda kalibre:
  observed gerçek verifier log'dan, expected bir **dosyadan yüklenen** `bpf_func_proto`
  diliminden; karar diff'te. Provenance çıktıda gösteriliyor.
- **Alan:** `harness/diffharness.c` (+map_lookup), `metrics/core.rs`
  (`helper_arg_observations`), `verifier_log.rs` (parse_helper_calls), `groundtruth/`
  (loader + `helper_arg_regtype`), `diff.rs` (check_helper_observations),
  `data/groundtruth/helper_protos.tsv` (yeni), testler + demo.
- **İlgili:** 0015 (intrinsic kalibrasyon), 0006 (diff), 0014 (harness). Reviewer'ın
  helper-kolu bar'ını karşılar.

### Neden (reviewer'ın kritik ayrımı)
`tnum` iyi-biçimliliği **intrinsic** (CORE'dan hesaplanır, dış kaynak yok). Ama helper
arg-type mismatch **intrinsic DEĞİL** — beklenen tip `bpf_func_proto`'dan gelir. Bu
yüzden helper kolunu "gerçek veride kalibre" etmek, beklenen arg tipinin bir **dosyadan
loader ile** gelmesini gerektirir; teste gömülürse dış-ground-truth değil sentetik
kalır. Ve karar nereden geliyor **çıktıda gösterilmeli**.

### Ne yapıldı
1. **Harness helper-kapsaması:** `map_lookup` programı — `BPF_MAP_CREATE` + `LD_MAP_FD`
   + `call bpf_map_lookup_elem(&map, &key)`. 7-program authoritative in-VM sample.
2. **CORE (observation-only):** `helper_arg_observations: Vec<HelperArgObservation>`
   (helper, arg_index, observed reg-tipi ailesi). **`expected` YOK** — mimari olarak
   beklenti CORE'a giremez; o ground-truth'a ait. `#[serde(default, skip_serializing_if)]`
   → golden/demolar byte-identical (bozulmadı). Legacy `helper_arg_violations` korundu.
3. **Parser:** `parse_helper_calls` — un-indented state trace'i biriktirir,
   `(85) call <helper>#<id>` satırında arg register'larının (R1..R5) reg-tipi
   ailesini gözlemler.
   Gerçek veride: arg0=`map_ptr`, arg1=`fp`.
4. **Ground truth (dosyadan):** `data/groundtruth/helper_protos.tsv` — GERÇEK kernel
   kontratı (`kernel/bpf/helpers.c:55  .arg1_type = ARG_CONST_MAP_PTR` → arg0 reg-tipi
   `map_ptr`). `HelperProtoModel::load_from_file` + `arg_regtype` +
   `GroundTruth::helper_arg_regtype`.
5. **diff:** `check_helper_observations` — observed reg-tipi vs **loaded** expected;
   uymuyorsa `helper_arg_type_mismatch`. Expected YALNIZCA ground-truth'tan.
6. **Testler + demo** (aşağıda).

### Tasarım kararları (bu adımda verilen)
- **reg-tipi FAMILY** karşılaştırması (`fp-4`→`fp`, `map_ptr(ks=4,vs=8)`→`map_ptr`).
- **arg0 seçildi** (ARG_CONST_MAP_PTR → tek crisp reg-tipi `map_ptr`); arg1 (birçok
  geçerli tip: fp/map_value/pkt) bilinçli olarak dilime KONMADI → `None` → sessiz
  (yanlış tek-tip dayatıp false-positive üretmemek için).
- **Fault-injection gerçek log'da** (verifier gerçek mismatch'i zaten reddeder), +
  **NoGroundTruth negatif kontrolü** (dosyasız → karar yok).
- **Additive + skip-if-empty** (düşük yıkım): CORE şeması genişledi ama eski artifact/
  golden/demolar değişmedi.

### Doğrulama (kanıt)
- **Parser (gerçek veri):** `verifier_log` testi 7 blok; `map_lookup` → arg0=`map_ptr`,
  arg1=`fp` gözlemleniyor; scalar programlar 0 gözlem.
- **`helper_calibration` (3 test):**
  (a) eşleşen observed → **susar** (0 bulgu);
  (b) mismatch **loader'ı GEREKTİRİR** — `NoGroundTruth` → 0 bulgu, dosya-yüklü dilim → 1 bulgu;
  (c) `finding.expected == oracle.helper_arg_regtype(...)` yani **dosyadan-yüklenen değer**
  (teste gömülü değil), `observed == "scalar"` (enjekte).
- **`helper_provenance` demo çıktısı** (çıktıda gösterim):
  `expected="map_ptr" (FROM FILE)  observed="scalar" (FROM LOG)`; NoGT → 0, file → 1;
  "dosyayı kaldır, bulgu kaybolur → karar dış ground-truth".
- Full suite **34 → 37 passed, 0 failed**. Python mirror güncellendi (`helper_arg_observations`), import OK.

### Kapsam dışı / hâlâ stub
- `bpf_func_proto` **auto-extraction** (kernel kaynağını parse etme) hâlâ TODO — bu,
  kaynak satırına atıflı **curated** bir dilim. arg1/diğer helper'lar dilimde yok.
- Legacy `helper_arg_violations` (sentetik `report_demo`/score yolu) kaldırılacak —
  `report_demo` bu observation-only modele migrate edilince.

### Dokunulan dosyalar
- `harness/diffharness.c` (map_lookup + BPF_ST_MEM/BPF_EMIT_CALL makroları)
- `harness/samples/bpf-next-sample.txt` (7 program, authoritative)
- `crates/metrics/src/core.rs` (`HelperArgObservation` + alan)
- `crates/pipeline/src/verifier_log.rs` (parse_helper_calls + test)
- `crates/pipeline/src/groundtruth/{helper_proto.rs,mod.rs}` (loader + `helper_arg_regtype`)
- `crates/pipeline/src/diff.rs` (check_helper_observations)
- `data/groundtruth/helper_protos.tsv` (yeni; gerçek kontrat dilimi)
- `crates/pipeline/tests/helper_calibration.rs`, `examples/helper_provenance.rs` (yeni)
- CORE literalleri (+`helper_arg_observations: Vec::new()`), `python/.../schemas/core.py`

### Sonraki adımlar
- **syzkaller hacmi** — dedektörün her iki kolu (intrinsic + helper) gerçek yolda
  kalibre; artık hacmi güvenle açabiliriz.
- `bpf_func_proto` dilimini genişlet / auto-extract; legacy violations alanını kaldır.


## 0017 — Unparsed politikası: parser kör noktaları ayrı kovada (hacimden önce)

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — parser tanımadığı log formunu artık sessizce düşürmüyor
  ya da anomali saymıyor; ayrı bir `unparsed` kovasına / `parse_notes`'a koyuyor,
  ve rapor bunu divergence'lardan ayrı gösteriyor.
- **Alan:** `normalize.rs` (ParseOutput/UnparsedBlock/parse_notes/unparsed),
  `verifier_log.rs` (classify_block), `report.rs` (ParseHealth), testler + demo,
  python mirror.
- **İlgili:** 0012 (parser), 0007 (report). Reviewer'ın hacim-öncesi sıralama ricası.

### Neden (reviewer'ın hacim-öncesi şartı)
İlk hacimli period önce **parser'ın kör noktalarını** çıkarır — verifier bug'ını
değil. Bu ayrım olmadan rapor **parser-gürültüsü ile gerçek sinyali karıştırır**
(sistem "0 anomali" der, ama bu temiz mi yoksa parser sessizce mi düştü belli olmaz).
Politika hacimden ÖNCE tanımlanmalı.

### Ne yapıldı — üç-yönlü ayrım
`RecordParser::parse` artık
`ParseOutput { records: Vec<ParsedRecord>, unparsed: Vec<UnparsedBlock> }` döndürür:
1. **Tam-parse** → normal kayıt, not yok.
2. **Kısmi-parse** → kayıt + `parse_notes` (düşük güven; tanınmayan reg-tipi, eksik
   `processed`). Hâlâ bir GÖZLEM, anomali değil.
3. **Unparsed** → güvenilir verifier kararı olmayan blok (RESULT yok, ya da
   non-verifier `decision=error`) ayrı **kovaya** gider — **sahte kayda dönüşmez**
   (en tehlikeli silent-misparse: RESULT'sız blok → default `accept` — engellendi).

`normalize`: `NormalizedMetrics.unparsed` + `MetricRecord.parse_notes` (serde
`skip_if_empty` → golden/eski artifact'ler byte-identical). `report`: **`ParseHealth`**
(records / records_with_notes / unparsed_blocks) — divergence sayısından **AYRI**.

### Değişmez kural
Unparsed/partial **ASLA** verifier anomalisi olmaz ve **ASLA** sessizce düşmez.
`parse_issues_never_become_diff_anomalies` testi bunu kilitler.

### Doğrulama (kanıt)
- **`unparsed_policy` (4 test):** undecidable blok → `unparsed` kovası (kayıt değil);
  novel reg-tipi (`arena_ptr`) → not; parse-issue'lar diff'te 0 anomali; **gerçek
  7-program sample temiz** → 0 unparsed / 0 not (politika gerçek veriyi false-flag'lemiyor).
- **`parse_health_demo`** (karışık batch, uçtan uca): `SIGNAL divergences=0` ama
  `PARSE HEALTH records=2 with_notes=1 unparsed_blocks=2`; unparsed'lar (`headless`:
  no RESULT, `map_lookup`: non-verifier RESULT) ve notlu kayıt (`arena_ptr`) ayrı
  listeleniyor. **Parser gürültüsü sinyalin DIŞINDA.**
- Full suite **37 → 41 passed, 0 failed**. Python mirror (`UnparsedBlock`,
  `ParseHealth`, `parse_notes`) + import OK; `harness_demo` python score hâlâ çalışıyor.

### Kapsam dışı / hâlâ stub
- Gerçek **syzkaller-güdümlü hacim** (sonraki iş) — politika artık hazır; o hacim
  geldiğinde parser kör noktalarını doğru sınıflar (reviewer'ın bakacağı şey).
- Not-tespiti şimdilik: bilinmeyen reg-tipi ailesi + eksik `processed`. Hacim yeni
  kör nokta türleri gösterdikçe genişletilir.

### Dokunulan dosyalar
- `crates/pipeline/src/normalize.rs` (ParseOutput/ParsedRecord/UnparsedBlock, run, MetricRecord/NormalizedMetrics)
- `crates/pipeline/src/verifier_log.rs` (classify_block + unrecognized_reg_families)
- `crates/pipeline/src/report.rs` (ParseHealth)
- `crates/pipeline/tests/unparsed_policy.rs`, `examples/parse_health_demo.rs` (yeni)
- `crates/pipeline/{examples/{normalize,diff}_demo.rs, src/diff.rs}` (trait uyumu)
- `python/.../schemas/{normalized,report}.py` (mirror)

### Sonraki adımlar
- **syzkaller-güdümlü ilk hacimli period** — programları harness'e besle; çıktının
  parse-health'i (unparsed/notes) hacimde nasıl davranıyor gözle. Dedektör kalibre +
  unparsed politikası hazır olduğundan, "0 anomali" artık güvenle yorumlanabilir.


## 0018 — İlk syzkaller-güdümlü hacimli period + hacmin çıkardığı parser kör noktaları

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — syzkaller'ın corpus'u gerçek verifier log'una çevrilip
  bpf-next VM'inde period olarak koştu; hacim **5 parser kör noktası** çıkardı,
  hepsi düzeltildi ve regresyona sabitlendi.
- **Alan:** `harness/syzreplay/shim.c` (yeni), `scripts/{syz-replay-build,run-syzreplay-vm}.sh`
  (yeni), `verifier_log.rs` (5 düzeltme + 6 test), `examples/{parse_report,syz_period}.rs` (yeni),
  RUNBOOK §4b.
- **İlgili:** 0017 (unparsed politikası — bu koşuda sınandı), 0013 (FuzzDriver).

### Fizibilite → çözüm (neden shim)
syzkaller **`log_level=2` verifier log'u üretmez** (o veri çağıranın `log_buf`'ında).
Yani "syzkaller-güdümlü" olmak için corpus'u harness yoluna sokmak gerekti. Yol:

```
corpus.db → syz-db unpack → syz-prog2c → C → [shim: -Dsyscall=vl_syscall]
   → BPF_PROG_LOAD'a log_level=2 + log_buf enjekte → gerçek verifier log
   → harness native format → ingest → normalize → score → diff → report
```

**Programlar syzkaller'ın kendisi**; shim yalnız **log yakalama alanlarını** ekler
(prog/insn/attr'a dokunmaz) ve gerçek fd'yi çağırana döndürür (map/prog fd zincirleri
bozulmaz). Çıktı zaten `VerifierLogParser`'ın okuduğu format.
`run-syzreplay-vm.sh` mevcut `ScriptRunner` sözleşmesine birebir uyduğu için
**sürücü soyutlaması değişmeden** çalıştı (0013 tasarımının sınavı).

### Koşu (kanıt)
- **Kampanya:** 900 sn, gerçek fuzzing → corpus.db 7 KB→**75 KB**, corpus 54→**254**,
  coverage 0→**7523 BB**, **18k+ exec** (~24/sn, TCG), crash yok.
- **Replay:** PROG_LOAD içeren **79** corpus programı → 79 static binary.
- **Period (VM, TCG):** **95 blok** yakalandı → **70 kayıt** (35 accept / 35 reject),
  **25 unparsed**, **0 divergence**, exec_count=95.

### Hacmin çıkardığı 5 parser kör noktası (hepsi düzeltildi)
Reviewer'ın öngörüsü birebir: **ilk hacim verifier bug'ı değil, parser kör noktası
çıkardı** — ve 0017 politikası sayesinde hiçbiri sinyale karışmadı.

| # | Kör nokta | Kök neden | Düzeltme |
| --- | --- | --- | --- |
| 1 | `reg-type "1"` | son token'a satır metadata'sı (`refs=2`) yapışıyordu | `value_head()` — paren-derinliği farkında değer kesme |
| 2 | `ringbuf_mem_or_null` bilinmiyor | `_or_null` ayrı aile sanılıyordu | `base_family()` — nullability eki strip |
| 3 | boş log'lu reject → sahte `Reject{unknown}` | verifier hiç çalışmamış (E2BIG/EINVAL) | **unparsed kovası** ("empty verifier log — nothing observed") |
| 4 | **29x `reject reason: unknown`** + `mark_precise:` gerekçe sanılması | reason taraması önce bir state satırı görmeyi şart koşuyordu; ama **rejectlerin 54/60'ında hiç state yok** (özlü token en başta, `func#0`'dan hemen sonra) | state şartı kaldırıldı + `is_analysis_noise()` filtresi + `Verification failed:` headline fallback |
| 5 | `invalid type id 1 in func infoprocessed 0 insns...` | verifier mesajı newline'sız basıyor, `processed` özeti yapışıyor | `strip_glued_summary()` |

Ayrıca: reason bulunamazsa artık **uydurulmuyor** — kayıt kalır ama
`"reject reason not identified in log"` **notu** düşer (0017 politikasının ruhu).

### Düzeltme öncesi/sonrası (aynı yakalanmış veri)
```
ÖNCE : reject reasons = 29x "unknown" + 3x "mark_precise: frame0: last_idx ..."   (kirli)
SONRA: 20 farklı GERÇEK verifier metni, ör.
       "At program exit the register R0 has smin=4294967295 smax=4294967295 should have been in [0, 1]"
       "BPF_EXIT uses reserved fields" | "fd -1 is not pointing to valid bpf_map"
       "cannot call GPL-restricted function from non-GPL compatible program"
PARSE HEALTH: records=70  with_notes=5 (2 missing 'processed', 3 reason-not-identified)
              unparsed_blocks=25 (hepsi "empty verifier log" = syscall-seviyesi red)
SIGNAL      : divergences=0  flagged=0
```

### Bulgu — helper kolu hacimde UYKUDA
Period **112 helper-arg gözlemi / 8 farklı helper** üretti
(`bpf_ringbuf_reserve`, `bpf_snprintf`, …), ama `helper_protos.tsv` dilimi yalnız
`bpf_map_lookup_elem` arg0'ı kapsıyor → oracle hepsine `None` → **sessiz** (doğru
davranış: "korroborasyon yok" ≠ "ihlal yok"). Yani helper dedektörü kalibre ama
hacimde **fiilen dormant**; açık ve somut sonraki iş: dilimi bu helper'lara genişletmek.

### Dürüst sınırlar
- **Gerçek verifier bug'ı yok** (beklenen: gerçek kernel + syzkaller corpus'u,
  0 divergence doğru sonuç). Dedektör kalibre olduğu için bu "sağır" değil "temiz".
- **25/95 blok unparsed (%26)** — hepsi verifier'ın hiç çalışmadığı syscall-seviyesi
  redler; CORE'a girmemeleri doğru.
- Kalan 3 "reason not identified": log'da gerçekten **hiç arıza metni yok**
  (sadece `processed 0 insns`) — verinin sınırı, parser'ın değil.
- `run-syzreplay-vm.sh` her koşuda binary'leri sıfırdan derliyor (~66 sn) — israf,
  ileride cache'lenebilir.

### Doğrulama
- Full suite **41 → 47 passed, 0 failed** (6 yeni regresyon testi: hacim-keşifli
  formların tamamı — metadata yapışması, `_or_null`, boş log, state'siz reject,
  glued summary, mark_precise, tanımlanamayan reason).
- `parse_report` aynı yakalanmış veriyi VM'siz yeniden analiz eder (triyaj aracı).

### Dokunulan dosyalar
- `harness/syzreplay/shim.c`, `scripts/syz-replay-build.sh`, `scripts/run-syzreplay-vm.sh` (yeni)
- `crates/pipeline/src/verifier_log.rs` (5 düzeltme + 6 test)
- `crates/pipeline/examples/parse_report.rs`, `crates/orchestrator/examples/syz_period.rs` (yeni)
- `docs/RUNBOOK.md` (§4b syzkaller-güdümlü period + bayat maddeler senkronu)

### Sonraki adımlar
- **`bpf_func_proto` dilimini genişlet** — hacimde gözlenen 8 helper'ı kapsa
  (helper kolunu dormant'tan çıkarır). Auto-extraction hâlâ TODO.
- Daha uzun kampanya + daha çok corpus → daha geniş reject/reg-type yüzeyi.
- `verifier.c` / `verifier.rst` / patch-diff loader'ları (kalan 3 ground-truth kaynağı).


## 0019 — Kör nokta ORANI (%0) + proto dilimi 8 helper'a genişletildi

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — "unparsed %26" sorusu **ölçülerek** cevaplandı (gerçek
  kör nokta **%0**), sayılar mutabık hale getirildi, ve helper kolu dormant'tan
  çıkarıldı (45 fiili kontrol, 0 false positive).
- **Alan:** `normalize.rs` (`UnparsedKind`), `verifier_log.rs`, `report.rs`
  (`ParseHealth` bölündü), `diff.rs` (accept-only kapısı),
  `data/groundtruth/helper_protos.tsv` (1→12 kontrat), fixtures + 5 test.
- **İlgili:** 0018 (hacim), 0016 (helper kalibrasyonu), 0017 (unparsed politikası).
  Reviewer'ın iki şartını karşılar.

### 1. Sorun: `%26 unparsed` sayısı okunamıyordu (raporlama hatası — bende)
Reviewer haklıydı: "5 kör nokta düzeltildi" bir **süreç** ifadesi; lazım olan
**sonuç** ifadesiydi. Ölçünce şu çıktı — ve tek kovada **kategorik olarak farklı
iki şeyi** topladığım ortaya çıktı:

| | sayı | |
| --- | --- | --- |
| Toplam blok | 95 | |
| Verifier log'u **dolu** → hepsi kayda dönüştü | 70 | **70/70 = %100 parse** |
| Verifier log'u **boş** (verifier hiç çalışmadı: EINVAL 12, EFAULT 7, E2BIG 6) | 25 | syscall-seviyesi red |
| **Parser formatı okuyamadı** | **0** | **%0 gerçek kör nokta** |

Yani %26, "parser başarısızlığı" değil "gözlenecek bir şey yoktu". Düzeltme:
**`UnparsedKind`** eklendi — `NotObserved` (araç verifier çıktısı üretmedi; hacimde
BEKLENEN) vs **`Unrecognized`** (parser verilen çıktıyı okuyamadı; **asıl metrik**).
`ParseHealth` buna göre bölündü ve **mutabakat satırı** eklendi
(`blocks = records + unparsed`) — 95≠70 artık hata gibi görünmüyor.

```
BLOCKS   95 = 70 records + 25 unparsed
PARSE HEALTH (separate, never signal)
  UNRECOGNIZED (parser blind-spots) : 0/70 = 0.0%   <-- must stay ~0
  not observed (verifier never ran) : 25            <-- expected, not a parser issue
  records with notes (lower confidence): 5
```

**Kalıcılık:** gerçek 95-bloklu hacim yakalaması **commit'li fixture** yapıldı
(`tests/fixtures/volume/syz-replay-95.log`, 84 KB) + `volume_parse_health.rs` (3 test):
unrecognized == 0, sayılar mutabık, notlu kayıt < %10, ≥15 farklı gerçek reject metni.
Yani oran artık **bir iddia değil, kilitli bir invaryant**.

### 2. Semantik düzeltme (dilimi genişletmeden ÖNCE): accept-only kapısı
Hacim şunu görünür kıldı: **reddedilmiş** bir programda helper arg-tipi uyuşmazlığı
**verifier'ın doğru çalıştığının kanıtıdır**, bug değil. Gerçek av sinyali tersi:
**kabul edilmiş** programda dokümante kontratın ihlali. `check_helper_observations`
artık yalnız `Accept` kayıtlarında koşuyor — bu yapılmadan dilim genişletilseydi,
her reddedilen program gürültü üretirdi.

### 3. Proto dilimi: 1 → 12 kontrat / 8 helper (gerçek kaynak, satır referanslı)
Hacimde gözlenen 8 helper'ın `bpf_func_proto`'ları `.lab/bpf-next`'ten çıkarıldı:
`ringbuf.c:554/555/596/635/637/666`, `helpers.c:55/1096/1097`, `core.c:3209/3210`,
`bpf_trace.c:421`.

**Dahil etme kuralı (dosyada da yazılı):** bir arg YALNIZCA `arg_type`'ı **tek bir**
verifier reg-tipi ailesine karşılık geliyorsa listelenir. `ARG_ANYTHING` (her tip
geçerli) ve `ARG_PTR_TO_MEM/_OR_NULL` (meşru olarak fp VEYA map_value VEYA pkt…)
**bilinçli olarak dışarıda** — tek tip dayatmak false positive üretirdi. Dışarıda
kalan = "korroborasyon yok" = sessizlik (≠ "ihlal yok").

### Doğrulama (kanıt)
- **Helper kolu uyandı:** aynı hacim verisinde **112 gözlem → 51 kapsandı (%45)**,
  bunların **45'i accept kaydında** (fiilen kontrol edilen). Öncesi: **0** (dormant).
- **False positive yok:** genişletilmiş dilim + gerçek hacim → `helper_arg_type_mismatch`
  **0**. (Bu kritikti: dilim gürültü üretmiyor.)
- **Accept-only kapısı testi:** aynı ihlal, `accept` → bulgu VAR; `reject` → bulgu YOK.
- Full suite **47 → 52 passed, 0 failed**.

### Dürüst sınırlar
- Dilim **curated**; auto-extraction hâlâ TODO. Kapsam **%45** — kalan %55 çoğunlukla
  `ARG_ANYTHING`/`ARG_PTR_TO_MEM` (bilinçli dışarıda, kapsanamaz değil).
- Helper kolu artık uyanık ama **hiç true-positive üretmedi** — gerçek kernel,
  beklenen sonuç.
- 5 notlu kayıt: 2 eksik `processed`, 3 log'da gerçekten arıza metni olmayan reject.

### Dokunulan dosyalar
- `crates/pipeline/src/normalize.rs` (`UnparsedKind` + `UnparsedBlock.kind`)
- `crates/pipeline/src/verifier_log.rs` (kind sınıflandırması)
- `crates/pipeline/src/report.rs` (`ParseHealth`: blocks/unrecognized/not_observed)
- `crates/pipeline/src/diff.rs` (accept-only kapısı)
- `data/groundtruth/helper_protos.tsv` (1 → 12 kontrat, 8 helper)
- `crates/pipeline/tests/{volume_parse_health.rs,fixtures/volume/syz-replay-95.log}` (yeni)
- `crates/pipeline/tests/helper_calibration.rs` (+2 test), örnek çıktı formatları

### Sonraki adımlar
- **Hacmi tekrar aç** (reviewer sırası tamam: parser oturdu %0 → dilim genişledi →
  hacim): daha uzun kampanya, helper kolu artık uyanık koşacak.
- `bpf_func_proto` auto-extraction; `verifier.c`/`verifier.rst`/patch-diff loader'ları.


## 0020 — 2. hacimli period: iki metrik büyük örneklemde doğrulandı (+ crash teşhisi)

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — reviewer'ın istediği iki sayı ~2x daha büyük ve çeşitli
  bir örneklemde ölçüldü: kör nokta oranı **%0'da kaldı**, helper kolu **82 fiili
  kontrol** yaptı. Ayrıca kampanya 2 crash üretti; teşhis edildi ve **bulgu olarak
  sayılmadı**.
- **Alan:** `diff.rs`/`report.rs` (kontrol paydası), `verifier_log.rs` (not zenginleştirme),
  yeni fixture + testler.
- **İlgili:** 0019 (ilk ölçüm), 0018 (ilk hacim).

### Enstrümantasyon: kontrol PAYDASI (yapısal cevap)
"0 helper bulgusu" ancak **kaç kontrol yapıldığı** biliniyorsa yorumlanabilir. `diff`
artık `helper_args_observed` / `helper_args_checked` sayıyor (accept-only + dilimin
kapsadığı) ve rapor basıyor:

```
CHECKS   helper-arg comparisons actually performed: 82   (0 findings out of 82 checks)
```

Ayrım: **N>0 + 0 bulgu = programlar sağlamdı (kanıt)**; **N=0 + 0 bulgu = kol boşta,
hiçbir şey kanıtlamaz**. `volume_parse_health` testi `N ≥ 40` şartını kilitler — dilim
ya da accept-kapısı sessizce eşleşmeyi bıraksa "temiz rapor" yerine test kırmızı olur.

### Koşu
30 dk kampanya (corpus.db **75 KB → 127 KB**, corpus 317+, coverage ~7900 BB) →
replay → VM'de period.

### İki metrik — yan yana (iki bağımsız yakalama)

| | capture #1 (95 blok) | capture #2 (184 blok) |
| --- | --- | --- |
| kayıt | 70 (35 acc / 35 rej) | **151** (72 acc / 79 rej) |
| **UNRECOGNIZED (kör nokta)** | 0/70 = **%0** | **0/151 = %0** |
| not observed (verifier hiç çalışmadı) | 25 | 33 |
| notlu kayıt | 5 (%7) | 10 (%6.6) |
| **helper kontrolü yapıldı** | 45 | **82** |
| helper bulgusu | 0 | 0 |
| farklı gerçek reject metni | 20 | **44** |
| divergence | 0 | 0 |

**(1)** Kör nokta oranı ~2x örneklemde **%0'da kaldı** — tek örneklem şansı değil.
**(2)** Helper kolu **82 gerçek karşılaştırma** yaptı → "0 mismatch" = *corpus/verifier
sağlam*, "kol uykuda" değil. Her iki fixture da commit'li; test **ikisinde birden**
`unrecognized == 0` ve sayı mutabakatı şartını koşuyor.

Notlu kayıtların 8'i "reason not identified" — incelendi: log'larında **yalnız
`processed 0 insns`** var, yani verifier hiç mesaj basmamış (verinin sınırı, parser'ın
değil). Not artık errno taşıyor:
`reject reason not identified in log (errno=22; verifier printed no message)`.

### Crash'ler — teşhis edildi, BULGU DEĞİL
Kampanya 2 crash üretti: `int3 in sk_filter_trim_cap`, `int3 in __seccomp_filter`.
**Aradığımız bug sınıfı değil ve büyük olasılıkla emülasyon artefaktı:**

- Her ikisinin RIP'i **aynı nokta**: `filter.h:763` =
  `static_branch_unlikely(&bpf_stats_enabled_key)` (kaynakta doğrulandı, `filter.h:744`).
- Crash'ler **fuzzer'ın programlarında değil**, alakasız sistem süreçlerinde:
  `udev-worker` (netlink broadcast → sk_filter) ve `systemd-udevd` (seccomp).
- syzkaller `bpf$ENABLE_STATS` çağırıyor → bu static key'i flip ediyor → kernel
  static branch'i **int3-tabanlı text patching** ile yamalıyor.
- Biz `-accel tcg,thread=multi` kullanıyoruz; TCG'de eşzamanlı kod-yaması/vCPU
  serializasyonu zayıf → başka bir vCPU int3'ü poke-handler devrede değilken yürütüyor.

**Kanıt ağırlığı düzeltmesi (reviewer notu).** Her ikisi `repro=false`; bunu ilk yazımda
fazla yükledim. Non-determinizm artefakt hipoteziyle **tutarlıdır ama onu kanıtlamaz** —
**gerçek yarış-koşullu kernel bug'ları da non-deterministiktir**. Yani destekleyici,
ayırt-edici değil. Asıl ağırlık taşıyan kanıt (1) RIP'in canlı-yamalanan static branch'te
olması ve (2) crash'in fuzz edilen programda değil ilgisiz daemon'larda olmasıdır.

**Statü: KAPANMADI — askı maddesi.** Hipotez falsifiable ama **test edilmemiş**, çünkü
falsifying test (KVM/bare-metal'de tekrar) şu an koşulamıyor (KVM bloklu; 2026-08-28
probe: `vmx/svm` flag sayısı **0**). Bulgu olarak sunulmuyor, ama "teşhis edildi ve
kapandı" da denmiyor: **açık, düşük öncelikli, KVM açılınca tekrar bakılacak** olarak
`docs/OPEN-ITEMS.md` **OI-1**'de izleniyor — falsifying test, güç (power) uyarısı ve
KVM'siz kısmi testlerin neden koşulmadığı orada yazılı.

### Dürüst sınırlar
- Hâlâ **gerçek verifier bug'ı yok** — beklenen (gerçek kernel, sağlam corpus).
- Helper kolu 82 kontrol yaptı ama **hiç true-positive görmedi**; kalibrasyonu
  0016'daki fault-injection testi kanıtlıyor, hacim değil.
- Dilim kapsamı hâlâ kısmi (`ARG_ANYTHING`/`ARG_PTR_TO_MEM` bilinçli dışarıda).
- TCG throughput ana kısıt; KVM ~10-20x hızlandırırdı.

### Dokunulan dosyalar
- `crates/pipeline/src/{diff,report}.rs` (helper_args_observed/checked)
- `crates/pipeline/src/verifier_log.rs` (not + errno)
- `crates/pipeline/tests/fixtures/volume/syz-replay-184.log` (yeni), `volume_parse_health.rs`
- `crates/pipeline/examples/parse_report.rs`, `crates/orchestrator/examples/syz_period.rs` (CHECKS satırı)

### Sonraki adımlar
- `bpf_func_proto` **auto-extraction** (dilim curated; kapsamı büyütür).
- `verifier.c` / `verifier.rst` / patch-diff loader'ları (kalan 3 ground-truth kaynağı).
- syzkaller **coverage/crash → DERIVED** (crash'ler şu an pipeline dışında).
- KVM açılınca crash'leri yeniden test et (OI-1; hipotezi doğrula/çürüt).


## 0021 — `bpf_func_proto` auto-extraction: dilim elle değil ağaçtan (OI-4 kapandı)

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — ground-truth kaynak 3'ün **gerçek loader'ı** yazıldı
  (`helper_proto::load()` stub'ı dolduruldu); dilim **12→274 kontrat, 8→194 helper**.
- **Alan:** `groundtruth/helper_proto.rs` (extract_from_tree/arg_type_to_regtype/to_tsv),
  `examples/extract_protos.rs` (yeni), `data/groundtruth/helper_protos.tsv` (artık üretilen).
- **İlgili:** OI-4 (kapandı), 0016/0019 (helper kolu), 0020 (kontrol paydası).

### Neden bu iş (KVM bloklu olduğu için sıradaki en yüksek değer)
Reviewer'ın sıradaki tercihleri KVM-crash-tekrarı (bloklu, bkz OI-1) ya da daha uzun
hacimdi. Bunun yerine **fiilen kontrol yapan tek kolu çoğaltan** işi seçtim: dilim elle
yazılıyordu (12 kontrat), yani hacimde görülen yeni helper'lar **sessizce
korrobore edilmiyordu** (OI-4). Auto-extraction bunu yapısal olarak çözer.

**Neden diğer iki kaynak seçilmedi (dürüst fizibilite):**
- **`verifier.rst`** 20 KB **düz metin**. Ondan "kural" çıkarmak ya benim okuyup
  yazdığım kuralları "dokümandan geldi" diye sunmak (sahte köken) ya da kırılgan NLP
  olurdu. Yapılmadı.
- **patch-diff (kaynak 4)** anlamlı olması için **iki kernel sürümünden gözlem**
  gerektirir; elimizde tek rev var. Gözlemsel karşılığı yok.

### Ne yapıldı
`extract_from_tree(kernel_src)` — `kernel/` ve `net/` altındaki `.c` dosyalarını tarar,
`const struct bpf_func_proto <name>_proto = { … };` bloklarını bulur, `.argN_type`
alanlarını okur (kernel `arg1` = bizim index 0).

**Mekanik olan çıkarım; yargı olan eşleme.** `SINGLE_FAMILY_ARG_TYPES` tablosu küçük,
muhafazakâr ve gözden geçirilebilir: bir arg **yalnızca** `arg_type`'ı tek bir verifier
reg-tipi ailesine sabitliyorsa kontrata dönüşür (`ARG_CONST_MAP_PTR`→map_ptr,
`ARG_PTR_TO_CTX`→ctx, `ARG_MEM_SIZE*`/`ARG_CONST_*SIZE*`→scalar,
`ARG_PTR_TO_RINGBUF_MEM`→ringbuf_mem, `ARG_PTR_TO_CONST_STR`→map_value).
`ARG_ANYTHING`, `ARG_PTR_TO_MEM*`, map key/value ve BTF/sock/timer pointer'ları
**düşürülür** — tek aile dayatmak false positive üretirdi. `|` sonrası bayraklar
(`MEM_RDONLY`, `OBJ_RELEASE`, `PTR_MAYBE_NULL`) **niteleyici**, aile değiştirmez.

TSV artık **üretilen** artefakt (başlıkta "GENERATED, do not edit by hand" + üretme
komutu + dahil-etme kuralı). Testler ağaç olmadan çalışsın diye commit'li kalıyor.

### Bulunan hata (sessiz kayıp sınıfı)
İlk sürüm `bpf_tail_call`'ı **sessizce kaçırdı**. Kök neden: `kernel/bpf/core.c`'de
gerçek tanımlardan hemen önce bir dizi `__weak` **bildirimi** var (`=` yok); parser
"sonraki `=`"i sınırsız arayınca gerçek tanımın gövdesini atlıyordu. Düzeltme:
`;` ile `{`'den hangisi önce geliyorsa ona göre **bildirim/tanım ayrımı**.
`272 → 274 kontrat`, `bpf_tail_call` geri geldi. Regresyon testi yazıldı.

### Doğrulama (kanıt)
- **Elle yazılmış 12 kontratın 12'si de** çıkarımda birebir aynı çıktı (köken kontrolü).
- **Gerçek hacim verisinde false positive YOK**, ve kontrol sayısı arttı:

| | capture #1 (95) | capture #2 (184) |
| --- | --- | --- |
| helper kontrolü (önce, elle dilim) | 45 | 82 |
| **helper kontrolü (sonra, çıkarım)** | **52** | **101** |
| helper bulgusu | 0 | 0 |
| kör nokta oranı | %0 | %0 |

- **4 yeni birim testi**: inclusion rule (multi-family düşürülür), bildirim/tanım
  regresyonu, bayrak-niteleyici ayrımı, commit'li dilimin yüklenmesi + hacim
  helper'larını kapsaması. Full suite **54 → 58 passed**.

### Dürüst sınırlar
- Kapsam hâlâ **kısmi ve bilinçli**: 274 kontrat, ama `ARG_ANYTHING` (232 kullanım) ve
  `ARG_PTR_TO_MEM*` aileleri dışarıda — bunlar kapsanamaz değil, **tek aileye
  indirgenemez**. Kapsam artışı yeni helper'lardan geliyor, yeni arg *türlerinden* değil.
- Eşleme tablosu **benim yargım**; yanlış bir satır false positive üretir. Bu yüzden
  küçük tutuldu ve gerçek hacimde 0-false-positive ile doğrulandı.
- Helper kolu 101 kontrol yapıyor ama **hâlâ hiç true-positive görmedi** (gerçek kernel).

### Dokunulan dosyalar
- `crates/pipeline/src/groundtruth/helper_proto.rs` (loader + eşleme + 4 test)
- `crates/pipeline/examples/extract_protos.rs` (yeni)
- `data/groundtruth/helper_protos.tsv` (üretilen; 274 kontrat / 194 helper)
- `crates/pipeline/tests/volume_parse_health.rs` (kontrol eşiği 40→45)
- `docs/OPEN-ITEMS.md` (OI-4 kapandı)

### Sonraki adımlar
- **OI-2**: syzkaller crash/coverage'ını pipeline'a bağla (crash'ler hâlâ veri yolu dışında).
- **OI-1**: KVM açılınca crash'leri tekrar test et.
- Daha uzun hacim: dilim artık 194 helper kapsadığı için yeni helper'lar otomatik kontrol edilir.


## 0022 — Üçüncü dedektör kolu: documented-behavior (`verifier.rst`), alıntı-çapalı

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — ground-truth **kaynak 2** canlı; dedektör iki koldan
  **üçe** çıktı. 3 dokümante vaka gerçek bpf-next'te koşuyor, kalibre ve drift-tespitli.
- **Alan:** `groundtruth/verifier_rst.rs` (stub → gerçek loader), `groundtruth/mod.rs`
  (`documented_outcome`), `diff.rs` (`check_documented_behavior` + payda),
  `normalize.rs` (`source_label` provenance), `harness/diffharness.c` (+3 program).
- **İlgili:** OI-3 (kısmen kapandı). Reviewer'ın önceliklendirmesi.

### Neden bu iş
Reviewer'ın tespiti: aranan logic bug sınıflarının çoğu tnum invariant'ı veya helper
arg-type ile değil, **"dokümante edilen ile gözlenen davranış farkı"** ile yakalanır —
ve o eksen tamamen eksikti (5 kaynaktan 3'ü stub, fiilen iki kol).

### İlk teşhisimin düzeltilmesi
0021'de `verifier.rst`'i "20 KB düz metin, ondan kural çıkarmak sahte köken ya da
kırılgan NLP olur" diye elemiştim. **Düzgün okuyunca yanıldığımı gördüm:** doküman
*kural* çıkarılacak prose değil, **açık davranış iddiaları** içeriyor — her biri bir
örnek programın yanında:

| Program (dokümandan) | Dokümanın kendi cümlesi | Sonuç |
| --- | --- | --- |
| `bpf_mov R0 = R2; bpf_exit` | "will be rejected, since R2 is unreadable at the start of the program" | Reject |
| `bpf_mov R6 = 1; bpf_call foo; bpf_mov R0 = R6; bpf_exit` | "is a correct program" | Accept |
| `R1 = 1; R2 = 2; bpf_xadd *(u32*)(R1+3) += R2; exit` | "will be rejected, since R1 doesn't have a valid pointer type" | Reject |

Bunlar **çalıştırılabilir**: programı gerçek kernel'de koştur, gözlenen kararı
dokümanın dediğiyle karşılaştır. Fark = gerçek documented-vs-observed divergence.

### Tasarım — alıntı-çapalı köken (provenance discipline)
Kural benim okumam olduğu için köken **doğrulanabilir** olmalı. Her `DocumentedCase`
dokümanın **kendi cümlesini birebir** ve satır numarasını taşır; `load()` dosyayı
yeniden okuyup **alıntının hâlâ orada olduğunu kontrol eder**:

- alıntı bulunur → vaka **kullanılabilir**,
- alıntı bulunamaz → vaka **STALE** olarak raporlanır ve **asla kullanılmaz**.

Yani doküman değişirse kural sessizce bayatlamaz; **gürültülü şekilde düşer**. (Prose
hard-wrap'li olduğu için karşılaştırma whitespace-normalize edilir.) Pseudo-asm →
gerçek insn çevirisi harness'te, vaka id'sinin yanında — `SINGLE_FAMILY_ARG_TYPES` ile
aynı şekilde **gözden geçirilebilir yargı**; ama **beklenti** dokümandan gelir, benden değil.

### Mimari not
`MetricRecord.source_label` eklendi (provenance; CORE saf gözlem kalsın diye kayıt
seviyesinde, `skip_if_none` → golden bozulmadı). Kaydı dokümante vakayla eşleştiren
anahtar bu. `diff` ayrıca `documented_cases_checked` **paydasını** sayıyor (0020'deki
helper paydasının aynısı: "0 bulgu / N kontrol" yorumlanabilir olsun diye).

### Doğrulama (kanıt)
- **Gerçek dokümana karşı**: 3 vakanın 3'ü de çapalandı, **0 stale**.
- **Gerçek bpf-next VM'inde** (in-VM capture, 10 programlı yeni authoritative sample):
  `doc_unreadable_reg` → reject (`R2 !read_ok`), `doc_callee_saved_r6` → accept,
  `doc_bad_ptr_xadd` → reject (`R1 invalid mem access 'scalar'`). **Üçü de dokümana uyuyor.**
- **Uçtan uca** (`harness_demo`):
  `ground truth: 274 helper contracts, 3 documented cases (0 stale)` /
  `CHECKS helper-arg: 1 documented cases: 3` / `divergences=0`.
- **6 kalibrasyon testi** (diğer kolların aldığı iki-yönlü ispatın aynısı):
  uyumda **susar**; çelişkide **bağırır** (expected=reject, observed=accept,
  source=Documentation); **ground truth yokken hiçbir şey demez** (iddia dokümanda,
  checker'da değil); **drift edince vaka susar** (bayat iddia öne sürmez); ilgisiz
  programlara dokunmaz. Full suite **58 → 67 passed**.

### Dürüst sınırlar
- **Sadece 3 vaka.** Doküman daha fazla açık iddia içeriyor; her yeni vaka, prose'dan
  çıkarım değil, **açıkça yazılmış bir cümle** bulmayı gerektirir (bilinçli yavaş yol).
- Kaynak **1 (`verifier.c`)** ve **4 (patch-diff)** hâlâ stub → dedektör 3 kollu, 5 değil.
- Bu kolda da **hiç true-positive yok**: kernel kendi dokümantasyonuyla uyumlu (beklenen).

### Dokunulan dosyalar
- `crates/pipeline/src/groundtruth/verifier_rst.rs` (stub → loader + 3 test)
- `crates/pipeline/src/groundtruth/mod.rs` (`documented_outcome`, `with_verifier_rst`)
- `crates/pipeline/src/diff.rs` (`check_documented_behavior` + `documented_cases_checked`)
- `crates/pipeline/src/normalize.rs` (`MetricRecord.source_label`, `ParsedRecord.label`)
- `crates/pipeline/src/verifier_log.rs` (label taşıma)
- `harness/diffharness.c` (+3 dokümante program), `harness/samples/bpf-next-sample.txt` (10 blok)
- `crates/pipeline/tests/documented_behavior.rs` (yeni, 6 test)

### Sonraki adımlar
- Dokümandan **daha fazla açık iddia** kodla (vaka sayısını artır).
- **OI-2**: syzkaller crash/coverage'ı pipeline'a bağla.
- **OI-3** kalanı: `verifier.c` (kaynak 1) ve patch-diff (kaynak 4).
- **OI-5** (yeni): extraction tablosunun denetlenemez yüzeyi — bkz OPEN-ITEMS.


## 0023 — patch-diff (kaynak 4): doküman-vs-kod bayatlık kanıtı + bir parser kör noktası

- **Tarih:** 2026-08-28
- **Durum:** Tamamlandı — kaynak 4 canlı (kanıt üreticisi olarak, bulgu üreticisi
  olarak değil); ayrıca ölçüm sırasında **yeni bir parser kör noktası** bulunup düzeltildi.
- **Alan:** `groundtruth/patch_diff.rs` (stub → git loader), `groundtruth/mod.rs`
  (`doc_staleness_evidence`), `diff.rs` (kanıtı bulguya iliştirme),
  `verifier_log.rs` (SCC gürültüsü).
- **İlgili:** 0022 (kaynak 2'nin zayıflığı), OI-3.

### Neden bu iş (reviewer'ın gerekçesi)
Kaynak 2'nin yapısal zayıflığı: **alıntı-çapa cümlenin var olduğunu korur, doğru
olduğunu değil.** Bir documented divergence'ın iki sebebi olabilir — gerçek bug ya da
eskimiş doküman. patch-diff bunu telafi eder çünkü **koddan gelir, dokümandan değil**.

### ÖNCE ölçtüm, sonra karar verdim (gönderilmeyen tasarım)
İlk planım "verifier mesaj sözlüğü" kontrolüydü: gözlenen reject metni kernel
kaynağındaki `verbose(env, "…")` şablonlarından biriyle eşleşmeli. Göndermeden önce
gerçek veriye karşı **ölçtüm**: **43 tekil gözlenen metnin yalnız %51'i eşleşti.**
Sebep: mesajlar tek literal değil, **birden çok ayrı `verbose()` çağrısından**
birleşiyor (`"%s the register %s has"` + `" smin=%lld"` + …). Yani bu kontrol bulgu
kaynağı olarak **yarı yarıya gürültü** üretirdi → **gönderilmedi.** Ölçüm olmasa
"çalışıyor" sanıp gönderecektim.

### Ölçümün yan ürünü: yeni parser kör noktası (makul ama YANLIŞ veri)
Eşleşmeyenleri incelerken `SCC enter (1)`'in reject gerekçesi olarak raporlandığını
gördüm. Kaynakta doğrulandı: `kernel/bpf/states.c:174/216/246` —
`SCC enter/exit/backedge` **state-walk işaretçileri**, insn satırları arasında ve
**gerçek arıza metninden ÖNCE** basılıyor. O blokta gerçek gerekçe
`R1 type=fp expected=map_ptr` idi. Yani parser "unknown" değil, **makul ama yanlış**
bir değer üretiyordu — bu daha kötü, çünkü sessizce güven veriyor.
`is_analysis_noise`'a eklendi + regresyon testi (gerçek bloktan).

### Ne yapıldı — kaynak 4'ün DÜRÜST kapsamı
Tam bir cross-version davranış diff'i **iki kernel sürümünden gözlem** ister; lab tek
sürüm derliyor. Bu yüzden kaynak 4 **kendi başına bulgu üretmiyor**; kaynak 2'yi
**niteliyor**:

```
doc-vs-code (source 4): documentation last changed 2025-09-18 (107e16979905),
verifier.c last changed 2026-08-18 (a2e98481a639), 351 verifier.c commits since
```

Yani reviewer'ın endişesi artık bir **rakam**: doküman ~11 ay ve **351 verifier
commit'i** geride. Bir documented divergence çıktığında bu kanıt **bulgunun
`detail`'ine iliştiriliyor** — triyaj sorusu sıfırdan sorulmuyor, gerçeklerle geliyor.

### Tasarım kararları
1. **Bulgu değil kanıt.** Bayatlık tek başına divergence sayılmaz (divergence sayacı
   kirlenmez); yalnız kaynak-2 bulgusunu nitelendirir.
2. **Hüküm vermez, olguyu söyler.** Not "stale/bug/likely" gibi kelime içermez —
   test bunu zorunlu kılıyor. Karar insanın.
3. **Kanıt yoksa sessizlik.** Git yoksa/başarısızsa model boş döner ve bulgu
   niteleyicisiz durur — uydurma kanıt yok (test var).

### Doğrulama (kanıt)
- **4 birim testi** (parse, bozuk satır → tahmin yok, not hüküm içermez, geçmiş
  yoksa sessizlik) + **2 entegrasyon testi** (bulgu kanıtı taşır / git yokken
  niteleyicisiz durur).
- **Gerçek ağaçta**: yukarıdaki 351-commit notu gerçek `git log`'dan geliyor.
- **Uçtan uca**: `274 helper contracts, 3 documented cases (0 stale)` +
  source-4 notu + `divergences=0`. Full suite **67 → 74 passed**.

### Dürüst sınırlar
- Kaynak 4 **kısmi**: sadece doc-vs-code bayatlığı. Gerçek cross-version davranış
  diff'i hâlâ iki-revizyon gözlemi gerektiriyor (çaba değil, **bağımlılık** engeli).
- Mesaj-sözlüğü kontrolü ölçüm sonucu **gönderilmedi** (%51 eşleşme). Şablon modeli
  çok-çağrılı birleşimi desteklerse yeniden değerlendirilebilir.
- Kaynak 1 (`verifier.c` state-transition) hâlâ stub.

### Dokunulan dosyalar
- `crates/pipeline/src/groundtruth/patch_diff.rs` (stub → git loader + 4 test)
- `crates/pipeline/src/groundtruth/mod.rs` (`doc_staleness_evidence`, `with_patch_diff`)
- `crates/pipeline/src/diff.rs` (kanıtı `detail`'e iliştirme)
- `crates/pipeline/src/verifier_log.rs` (SCC gürültüsü + regresyon testi)
- `crates/pipeline/tests/documented_behavior.rs` (+2 test), `examples/harness_demo.rs`

### Sonraki adımlar
- Dokümante vaka sayısını artır (hedef: birkaç düzine yüksek-değerli invariant).
- **OI-2**: syzkaller crash/coverage'ı pipeline'a bağla.
- Kaynak 1 (`verifier.c`) — en zor olan; şu an açık.

---

## 0024 — `verifier.rst` mesaj bölümü: 11 örnek program, ilk SAĞLAMLIK (soundness) testi

- **Tarih:** 2026-09-01
- **Durum:** Tamamlandı — kaynak 2'nin ikinci damarı kodlandı (3 → **13 vaka**);
  ölçüm sırasında **dokümanın eksik bir koşulu** kaynakta doğrulandı.
- **Alan:** `harness/diffharness.c` (+10 program, `run_one_ex`), `groundtruth/verifier_rst.rs`
  (+`expected_error`, +`SourcePrecondition`), `diff.rs` (**notes** kanalı),
  `groundtruth/mod.rs`, `verifier_log.rs` (regresyon), `schemas/diff.py`.
- **İlgili:** V14 ölçümü (REVIEW-HANDOFF), OI-6, 0022, 0023.

### Neden bu iş
V14'te ölçülmüştü: 0022'nin kullandığı **prose damarı tükeniyor** (7 aday cümlenin
3'ü kodluydu, ~4 kalmıştı). `verifier.rst`'in "Understanding eBPF verifier messages"
bölümü (satır 353-560) ise hiç işlenmemişti ve üç yönden daha güçlü: programlar
**zaten `BPF_*` makro formunda** (harness'in kullandığı makroların aynısı → çeviri
yargısı yok, transkripsiyon var), her biri **tam beklenen hata metnini** taşıyor, ve
**11'i de reddedilmesi gereken** program. Sonuncusu asıl mesele: bu, döngünün ilk kez
verifier'ın **sağlamlığını** (accept etmemesi gerekeni accept ediyor mu) test etmesi.

### Ne yapıldı — üç ağırlık, tek kanal değil
Doküman koddan **351 verifier commit'i geride** (OI-6). O yüzden iki tür iddia aynı
ağırlıkta olamaz; üçüncü bir durum da ölçüm sırasında ortaya çıktı:

| gözlem | sonuç | gerekçe |
| --- | --- | --- |
| `expected=reject`, `observed=accept` | **DIVERGENCE** (bulgu) | kernel kendi dokümanının güvenli demediği programı kabul etmiş |
| karar doğru, **hata metni** farklı | **NOTE** (kanıt, hüküm değil) | mesaj metinleri sürüm-drift'ine açık; bu doküman bayatlığıdır, bug değil |
| kaynakta doğrulanmış bir **önkoşul** iddiayı geçersiz kılıyor | **SUPERSEDED** (susturulur) | iddia bizim yükleme yolumuza uygulanmıyor; yine de iddia edilirse kalıcı sahte alarm üretir |

`DiffFindings`'e ayrı bir **`notes: Vec<EvidenceNote>`** kanalı eklendi (+
`summary.note_count`). Notlar `finding_count`'a **girmez** — tek farkı yeniden
yazılmış bir hata metni olan bir period "temiz" okunmaya devam etmeli.
`skip_serializing_if` sayesinde mevcut golden artifact'lar byte-identical kaldı.

### Susturma mekanizmasının maliyeti bilerek yüksek tutuldu
`SourcePrecondition` bir dosya + satır + **birebir kod metni** ister ve `load()` o
metnin ağaçta **hâlâ durduğunu doğrular**. Yani bir dokümante iddiayı susturmak
**pozitif, yeniden-kontrol edilebilir kanıt** gerektiriyor; kernel önkoşulu kaldırırsa
çapa tutmaz ve **vaka kendiliğinden geri canlanır**. Kaynak okunamazsa vaka **canlı
kalır** (susturma için kanıt şart; kanıtın yokluğu susturmaz). Susturulan vakalar
sayılır ve gerekçesiyle birlikte **raporlanır**, sessizce düşmez.

### ÖLÇÜM — gerçek bpf-next VM'inde (in-VM capture, 20 programlı yeni sample)
```
ground truth: 274 helper contracts, 12 documented cases (0 stale, 1 superseded, 0 error-text drifted)
  SUPERSEDED doc_msg_uninit_stack_arg: ...
CHECKS  helper-arg: 2  documented cases: 12   NOTES (evidence, not verdicts): 5
PERIOD REPORT  records=20  flagged=0  divergences=0
BLOCKS  20 = 20 records + 0 unparsed   UNRECOGNIZED: 0/20 = 0.0%
```
- **divergences = 0** → 12 vakanın **12'sinde de karar dokümanla uyuştu**. Bu,
  sağlamlık ekseninde ilk temiz ölçüm.
- **5 hata metni birebir tuttu**: `R2 !read_ok`, `R0 !read_ok`, `unreachable insn 1`,
  `fd 0 is not pointing to valid bpf_map`, `R0 invalid mem access 'map_value_or_null'`.
- **5 metin sürüklenmiş** (hepsi NOTE, hiçbiri bulgu değil):

| doküman | bpf-next |
| --- | --- |
| `invalid stack off=8 size=8` | `invalid write to stack R10 off=8 size=8` |
| `misaligned access off 4 size 8` | `misaligned value access off 0+4 size 8` |
| `R0 invalid mem access 'imm'` | `R0 invalid mem access 'scalar'` |
| `Unreleased reference id=1, alloc_insn=7` | `Unreleased reference id=2 alloc_insn=7` |

### Asıl bulgu — doküman EKSİK, verifier değil
`doc_msg_uninit_stack_arg` ("stack'i initialize etmeden adresini fonksiyona geçiren
program") gerçek ağaçta **ACCEPT** alıyor. Karar-mismatch'i olduğu için bu en yüksek
sesli sinyal sınıfı — ama gerekçesi kaynakta bulundu:

```
kernel/bpf/verifier.c:21141  env->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token);
include/linux/bpf.h:2869     return bpf_token_capable(token, CAP_PERFMON);
```
Yani dokümante red **yalnız yetkisiz (unprivileged) yükleme için** geçerli; harness
root ile yüklüyor. Doküman bu koşulu **hiç söylemiyor** → kusur **dokümanda**.
Vaka silinmedi: yukarıdaki satır çapa olarak kaydedildi, kernel gevşetmeyi kaldırırsa
vaka kendiliğinden geri gelir. Bu, OI-6'nın öngördüğü "gerçek regresyon mu, bayat
prose mu?" sorusunun **ilk gerçek örneği** ve cevabı prose çıktı.

### Hacmin ulaşamadığı yüzey — doğrulandı
V14 ölçümü 279 bloklu iki commit'li yakalamada bu hata sınıflarından **6'sının hiç
görülmediğini** söylüyordu. Şimdi hepsi üretildi: `unreachable insn`,
`invalid write to stack`, `invalid indirect read from stack` (bkz. superseded),
`invalid mem access`, `misaligned value access`, `Unreleased reference`. Parser
bunların **hepsini** tanıdı (0/20 kör nokta) ve 9 red gerekçesi label-çapalı
regresyon testine sabitlendi — 0018'in dersi: yeni hata şekilleri parser'ı
sessizce bozarsa detector "temiz" der.

### Çeviri yargıları (kaydedildi, gizlenmedi)
Doküman üç yerde bir şeyi söylemiyor; her biri harness'te ilgili vakanın yanında
**JUDGEMENT** olarak yazılı:
- **(a) map fd.** Doküman `BPF_LD_MAP_FD(BPF_REG_1, 0)` yazıyor ama kendi log'unda
  `r1 = 1` (gerçek map) gösteriyor. fd 0, vakanın konusu olan kontrole **varmadan**
  pseudo-ldimm64 çözümünde patlar → o vakalara gerçek map verildi. Konusu **fd 0 olan**
  vaka 0'ı korudu.
- **(b) value_size.** Doküman map'in value_size'ını hiç söylemiyor; 16 seçildi ki
  dokümante offset'ler (`off 4 size 8`) sınır içinde kalsın ve vaka kendi konusuna ulaşsın.
- **(c) program tipi / flag.** `bpf_sk_lookup_tcp` bir socket filter'dan çağrılamaz →
  o iki vaka `sched_cls` olarak koşuyor. Hizalama vakası ise x86'da
  `BPF_F_STRICT_ALIGNMENT` olmadan **meşru şekilde kabul edilir** (efficient unaligned
  access) — flag olmadan dokümanın iddiası bu mimaride zaten geçerli değil.

### Doğrulama
- **4 yeni birim testi** (`verifier_rst.rs`): mesaj damarı tam metin taşıyor; metin
  sürüklenirse **karar kontrolü hayatta kalır** ve kayıp gürültülü raporlanır;
  doğrulanmış önkoşul susturur; **kanıt yoksa susturmaz ve kendiliğinden geri gelir**.
- **4 yeni entegrasyon testi** (`documented_behavior.rs`): birebir metin → tam sessizlik;
  yeniden yazılmış metin → **not**, bulgu değil, `finding_count=0`; yanlış karar →
  **bulgu**, notu ezer; superseded vaka → hiç kontrol edilmez ve denominatöre girmez.
- **Parser regresyonu** (`verifier_log.rs`): 20 blok + 9 red gerekçesi label-çapalı pinlendi.
- Full suite **74 → 82 passed**, 0 failed.

### Dürüst sınırlar
- 10 mesaj vakasının **5'inde metin tutmadı**. Doküman metin düzeyinde gerçekten
  bayat; bu damarın değeri **karar** yarısında, metin yarısı sadece kanıt.
- `Unreleased reference` id'si dokümanda 1, ağaçta 2. Ref-id numaralandırması
  incelenmedi; metin farkı zaten not olarak düşüyor.
- **Susturma bir yanlış-negatif riskidir** (OI-7). Şu an 1 vaka susturulu ve
  gerekçesi kaynakta doğrulanmış, ama mekanizma kötüye kullanılabilir.
- Çeviri yargıları (a/b/c) kaynak 2 için OI-5'in karşılığıdır (OI-8).
- Kaynak 2'nin gerçek tavanı ölçüldü: prose ~4 + mesaj 0 kaldı → **~17 vaka**,
  "birkaç düzine" değil. OPEN-ITEMS düzeltildi.

### Dokunulan dosyalar
- `harness/diffharness.c` (+10 program, `run_one_ex`, `BPF_STX_MEM`/`BPF_LD_MAP_FD`)
- `harness/samples/bpf-next-sample.txt` (10 → **20 program**, taze in-VM capture)
- `crates/pipeline/src/groundtruth/verifier_rst.rs` (13 vaka, `expected_error`,
  `SourcePrecondition`, `from_sources`, +4 test)
- `crates/pipeline/src/groundtruth/mod.rs` (`documented_expected_error`)
- `crates/pipeline/src/diff.rs` (`EvidenceNote`, `notes`, `note_count`, metin karşılaştırma)
- `crates/pipeline/src/verifier_log.rs` (+ label-çapalı regresyon), `report.rs`
- `crates/pipeline/tests/documented_behavior.rs` (+4 test), `examples/harness_demo.rs`
- `python/src/verifierloop_analysis/schemas/diff.py` (mirror: `EvidenceNote` + denominatörler)

### Sonraki adımlar
- **Kaynak 1 pilotu** — tüm `verifier.c` değil, tek bir geçiş ailesi (ör. `check_alu_op`
  bounds) mekanik olarak çıkarılabilir mi?
- Kalan ~4 prose iddiasını kodla (düşük getiri, ucuz).
- **OI-2** — KVM açılana kadar düşük öncelik.

---

## 0025 — Hedefli üretim: input bütçesini nişan almak + intrinsic kolun eksik paydası

- **Tarih:** 2026-09-01
- **Durum:** Tamamlandı — ilk hedefli period koştu (242 program, gerçek bpf-next VM).
  Yan ürün olarak **projenin kendi ölçüm boşluğu** bulundu ve kapatıldı.
- **Alan:** `harness/diffharness.c` (`--gen` enumerative üretici), `diff.rs`
  (`tnum_bounds_checkable` + `tnum_bounds_checked` paydası), yeni
  `examples/signal_density.rs`, `scripts/run-harness-vm.sh` (`HARNESS_ARGS`),
  yeni fixture + `tests/targeted_generation.rs`.
- **İlgili:** Reviewer hükmü (2026-09-01), 0015 (intrinsic kolun kalibrasyonu),
  0018–0020 (hacim), 0024.

### Neden bu iş — reviewer'ın teşhisi
*Bug avı = oracle × input.* Oracle tarafı üç kalibre kolla güçlüydü; input ~241
programda takılıydı (KVM bloklu, her şey TCG'de). Ve planlanan bir sonraki iş
(kaynak 1 pilotu) **yine oracle büyütüyordu** — yani "hiç bug bulamayan daha mükemmel
bir dedektör" üretme riski. Sıra input tarafına geçti; ama "daha çok program" değil,
**doğru programlar**.

### Nereye nişan alındı, ve neden tam oraya
Beş kaynaktan **yalnız biri dış ground-truth istemiyor**: intrinsic invariant kolu —
verifier'ı *kendisine* karşı kontrol eder (tnum iyi-biçimliliği, sınır sıralaması,
tnum↔bounds uyumu). Yani o kola input vermek, yeni oracle yazmadan doğrudan mevcut
oracle'ı çarpar. Ama o kol ancak **soyut durumu ilginç** register'larda ateşleyebilir:
aynı anda **kısmen-bilinen bitler** VE **daraltılmış sınırlar**. Böyle durumlar bir
syscall fuzzer'ının corpus'unda kazara oluşmaz; **inşa edilmeleri gerekir**.

### Rastgele değil, ENUMERATIVE
Birkaç yüz execution'lık bütçede bir uzayı örneklemek israftır. Üretici,
`11 alu op × 11 karşılaştırma × {64-bit, 32-bit}` = **242 programın her birini
tam bir kez** basıyor. Sonuç: uzay **örneklenmiyor, kapsanıyor**; program N her
koşuda aynı program; ve **etiket tarifin kendisi** (`gen#w64.and.jlt#004`) — bir bulgu
rapordan, seed'e ya da corpus dosyasına bakmadan yeniden inşa edilebilir.

İskeletin her parçası yük taşıyor:
```
0: r0 = *(u32 *)(r1 + 0)   ctx'ten bilinmeyen skaler
1: <alu op1>               tnum'u (and/or/xor/shift) YA DA sınırları (add/sub/mul/div/mod)
                           oynatır — ikisi FARKLI verifier kod yollarında izlenir
2: if r0 <cmp> imm goto 5  iki dalda da sınırları daraltır; karşılaştırmayı tnum'a
                           geri yaymak, iki izleyicinin anlaşmak zorunda olduğu yer
3: <alu op2>               daralmış değer üzerinde aritmetik (düşen dal)
4: goto 6
5: <alu op2'>              öteki daralma üzerinde aritmetik (atlayan dal)
6: r0 &= 0xffff            ← BİRLEŞME noktası: iki farklı soyut durum burada birleşir
7: exit
```
32-bit varyant `BPF_ALU32`/`BPF_JMP32` kullanıyor, çünkü verifier `u32_min/u32_max`'ı
64-bit sınırlardan ayrı tutup ikisini uzlaştırmak zorunda — tarihsel olarak verifier
range bug'larının en yoğun kaynağı.

### ASIL BULGU — intrinsic kolun paydası hiç yoktu, ve payda 0'dı
0016'dan beri helper kolu paydasını, 0022'den beri dokümante kol paydasını
raporluyoruz. **Intrinsic kol hiç raporlamıyordu.** Ölçünce ortaya çıkan şey şu —
commit'li syzkaller hacminde, **ham metin seviyesinde**:

| | syz-replay-184 (184 blok) | gen-targeted-242 (242 blok) |
| --- | --- | --- |
| `var_off=` geçişi | **0** | 1623 |
| `umin=` geçişi | **0** | 378 |
| `smin=` geçişi | **1** | 1655 |
| tnum↔bounds kontrol edilebilir gözlem | **0** | **1497** |
| kayıt başına | **0.00** | **6.19** |
| en az bir kontrol edilebilir kaydı olan | **%0** | **%100** |

Yani: projenin **ilk yazdığı (0006) ve en iyi kalibre ettiği (0015)** dedektör kolu,
279 bloklu "hacim" boyunca **incelenecek tek bir soyut durum bile görmedi**. O kolun
"0 divergence"ı, diğer kolların "0 bulgu / 101 kontrol"üyle aynı görünüyordu ama
**0 bulgu / 0 kontrol**tü — kanıtın yokluğu, yokluğun kanıtı değil.

Bu, projenin kendi payda disiplininin **kendisine uygulanmamış** olmasıydı.
`DiffSummary.tnum_bounds_checked` eklendi; `parse_report` payda 0 ise bunu **açıkça
uyarı olarak** basıyor.

### Paydanın kendisi de dürüst olmak zorundaydı
İlk yazdığım predicate `R0=13` gibi **sabitleri** de sayıyordu ve syzkaller'a
2.36/kayıt gibi sahte bir skor veriyordu. Yanlıştı: bir sabit için parser hem tnum'u
hem sınırları **AYNI token'dan** türetir, yani kontrol 13'ü 13 ile karşılaştırır —
tautoloji, ne olursa olsun ateşleyemez. Bunu paydaya saymak, tam da bu alanın
engellemek için var olduğu hatayı işlemek olurdu. Predicate sabitleri dışlıyor,
non-scalar placeholder'ları dışlıyor, ve bilerek **eksik sayıyor** (`var_off=(0xd; 0x0)`
ayırt edilemiyor) — eksik saymak "0 bulgu"yu olduğundan **zayıf** gösterir, yani
yanılmanın güvenli yönü.

### Ölçüm — gerçek bpf-next VM'inde
```
$ HARNESS_ARGS=--gen TIMEOUT=600 ./scripts/run-harness-vm.sh
[harness-vm] captured 242 program block(s)

RECORDS  242 (accept 242 / reject 0)
SIGNAL   divergences=0  flagged=0  top_score=0
CHECKS   helper-arg: 0 comparisons | tnum-vs-bounds: 1497 checkable register
         observations | documented cases: 0
BLOCKS   242 = 242 records + 0 unparsed
  UNRECOGNIZED (parser blind-spots) : 0/242 = 0.0%
```
- **242/242 accept** — kasıtlı: reddedilen program az durum bastırır; buradaki amaç
  reddettirmek değil, **maksimum soyut durum** üretmek.
- **1497 kontrol, 0 bulgu.** Bu ilk kez *anlamlı* bir temizlik: kol artık kör değil,
  bakıyor ve bir şey görmüyor.
- **0 parser kör noktası** — beş yeni durum şekli (32-bit karşılaştırmalar, arsh,
  div/mod, dal birleşmeleri) parser'ı bozmadı.

### Doğrulama
- **8 yeni test** (`targeted_generation.rs`): hedefli corpus paydayı >1000 yapar;
  **syzkaller corpus'u tam 0 yapar** (bulgu teste sabitlendi — parser değişip bu sayı
  oynarsa yüksek sesle kırılsın); corpus tam parse edilir; 242 etiketin hepsi tekil
  ve tarif taşır; ve predicate testleri: **sabit tautolojidir**, fully-unknown
  ateşleyemez, pointer placeholder'ı sayılmaz, kısmen-bilinen+daraltılmış sayılır.
- Full suite **82 → 90 passed**, 0 failed.
- Yeni ölçüm aracı `signal_density` dedektörle **aynı predicate'i** çağırıyor
  (`pipeline::diff::tnum_bounds_checkable`) — corpus metriği ile dedektör "kontrol
  edilebilir" tanımında sessizce ayrışamaz.

### Dürüst sınırlar
- **Bulgu yok.** 1497 kontrol, 0 divergence. Beklenen (kernel doğru), ama artık
  "0 out of 0" değil.
- **Tek iskelet.** Aile alu×cmp çarpımını kapsıyor ama tek bir program şekli
  üzerinden: 8 insn, tek dal, yalnız immediate operand. Yok olanlar: register-register
  ops, çok-dallı/döngülü akış, pointer aritmetiği, **aynı programda 32-bit ve 64-bit
  karışımı**, sign-extension (movsx), 64-bit immediate. Sonuncu ikisi bilinen verifier
  bug bölgeleri → sıradaki artış orası (OI-9).
- **Metrik bir vekildir.** Yüksek "kontrol edilebilir gözlem" sayısı bug bulma gücünü
  garanti etmez; yalnız *ateşleme ihtimalinin sıfır olmadığını* garanti eder.
- 242 program hâlâ küçük bir sayı. Hedefleme, hacim eksikliğini telafi eder ama
  ortadan kaldırmaz; KVM açılınca ikisi çarpılır.

### Dokunulan dosyalar
- `harness/diffharness.c` (`--gen`, `GEN_ALU`/`GEN_CMP` tabloları, ALU32/JMP32/JA makroları)
- `crates/pipeline/src/diff.rs` (`tnum_bounds_checkable`, `tnum_bounds_checked`)
- `crates/pipeline/examples/signal_density.rs` (yeni), `examples/parse_report.rs`
- `crates/pipeline/tests/fixtures/volume/gen-targeted-242.log` (yeni fixture, in-VM)
- `crates/pipeline/tests/targeted_generation.rs` (yeni, 8 test)
- `scripts/run-harness-vm.sh` (`HARNESS_ARGS`)
- `python/src/verifierloop_analysis/schemas/diff.py` (mirror)

### Sonraki adımlar
- **Aileyi genişlet (OI-9):** aynı programda 32/64 karışımı, movsx, register-register
  ops, çok-dallı akış. En yüksek getiri: 32↔64 senkronu.
- **İki-revizyon differential** (reviewer sırasında 2.) — oracle olarak doküman değil
  başka bir kernel.
- KVM (3.) — donanım; açılınca hedefleme × hacim.

---

## 0026 — 32↔64 senkron bölgesi: parser'ı açmak, kolu kurmak, aileyi oraya sokmak

- **Tarih:** 2026-09-01
- **Durum:** Tamamlandı — OI-9'un işaret ettiği kör nokta kapandı. Yol boyunca
  **10 sahte bulgu üreten bir parser hatası** bulundu ve kaynakta doğrulanarak düzeltildi.
- **Alan:** `metrics/core.rs` (32-bit görünüm CORE'a), `verifier_log.rs`
  (`field_s32` + çıkarım), `diff.rs` (`check_subregister_invariants`,
  `reg32_checkable`, `reg32_checked`), `harness/diffharness.c` (`--gen-mix`,
  4 alt-aile), yeni fixture + `tests/subregister_calibration.rs`.
- **İlgili:** OI-9, 0025, reviewer önceliklendirmesi.

### Önce engel: nişan alsak da sinyali göremiyorduk
OI-9 "aileyi 32↔64 bölgesine genişlet" diyordu. Genişletmeden önce ölçtüm:
verifier o bölgenin verisini **basıyor** — hedefli yakalamada `...32=` içeren
**1258 satır** — ama **parser onları hiç okumuyordu**. CORE'da `u32_min/u32_max/
s32_min/s32_max` alanları yoktu. Yani doğru programları üretip **tam da önemli olan
yarıyı çöpe atacaktık**. 0026 bu yüzden üç parçalı oldu: parser → kol → aile.

### 1. CORE'a 32-bit görünüm (Option olarak, ve bu bilinçli)
`RegState`'e dört alan eklendi, hepsi `Option`. Sebep `kernel/bpf/log.c`'de:
`print_scalar_ranges()` bir sınırı **ekstremdeyse basmıyor** (`omit`). Yani "basılmadı"
ile "sıfır" farklı şeyler. Parser **sessizliği koruyor**; ekstreme çözme işini
**tüketici** yapıyor (`reg32_unsigned`, yanında gerekçesiyle). `skip_serializing_if`
sayesinde golden fixture byte-identical kaldı.

### 2. Yeni kol — üç invariant, hepsi aynı ispat şemasında
Verifier bir skaleri **iki kez** izliyor (64-bit ve 32-bit alt-register) ve
`reg_bounds_sync()` ikisini uzlaştırmak zorunda. Üç kontrol de **aşırı-yaklaşım
kesişimi**: her izleyici aynı boş-olmayan erişilebilir değer kümesini bağımsız olarak
aşırı-yaklaşıyor, öyleyse ikisi **kesişmek zorunda**; boş kesişim = verifier'ın
kendisiyle çelişmesi. Dış ground-truth gerekmiyor.

| kontrol | ne karşılaştırıyor |
| --- | --- |
| `u32_bounds_inverted` / `s32_bounds_inverted` | 32-bit aralığın kendi sıralaması |
| `tnum32_bounds_inconsistent` | tnum'un alt-32 span'i ↔ `[u32_min, u32_max]` |
| `reg32_reg64_inconsistent` | 64-bit aralığın alt-yarı penceresi ↔ 32-bit aralık |

Sonuncusu **yalnız 64-bit aralık tek bir 2³² bloğunda kaldığında** sağlam (o zaman
tüm değerler aynı üst yarıyı paylaşır); blok sınırını aşınca alt yarı sarmalanır ve
64-bit uçlar hiçbir şey söylemez → kontrol **tahmin etmek yerine atlanıyor**.

Payda (duran kural): `reg32_checked`. Ve payda yine tautoloji ayıklıyor — verifier iki
görünüm uyuştuğunda onları **tek token** olarak basıyor (`umax=umax32=255`); bir değeri
kendisiyle karşılaştırmak ateşleyemez, o yüzden sayılmıyor.

### 3. ASIL OLAY — ilk koşu 10 bulgu üretti, hepsi BENİM parser'ımdı
Yeni kol commit'li 242-programlık yakalamada **divergences=10** verdi. Proje kuralı
gereği ilk şüpheli verifier değil parser'dı — ve öyleydi:
```
s32_min=2147483888  s32_max=-5      <-- "ters aralık"
ham satır:  smin32=0x80000010
```
Gerekçe kaynakta, hem de yorumuyla — `kernel/bpf/log.c:558-567`:
> *"if we choose to print them in hex format then sign extension is misleading …
> **So we avoid sign extension if we choose to print values in hex.**"*

Yani hex basılan `smin32` **ham u32 pattern'i**; `0x80000010` = **-2147483632**.
Düz tamsayı okunduğunda +2147483664 çıkıyor — i32 alanının tamamen dışında — ve bu
tam olarak "verifier imkânsız bir aralık raporladı" gibi görünüyor. **Makul ama yanlış**
veri: 0023'ün SCC kör noktasıyla aynı sınıf, en tehlikelisi, çünkü sessizce güven
vermiyor — **bağırarak yanlış güven veriyor**. `field_s32` eklendi (hex → i32 →
sign-extend; decimal dokunulmadan geçer), 10 bulgu sıfıra düştü, 3 parser regresyon
testi yazıldı.

### 4. Aile — ve neden ilk denemem yetmedi
Dört alt-aile, hepsi enumerative:
`mix#64-32` (121), `mix#32-64` (121), `mix#movsx8/16/32` (33), `mix#hi` (121) = **396**.

İlk üçünü yazıp ölçtüm: host kernel'de **152** bağımsız görünüm, ama **gerçek
bpf-next'te sadece 4**. Sebep tahmin değil ölçüm: bpf-next'in deduction'ı, değer tek
bir 2³² bloğuna sığdığında iki görünümü neredeyse kusursuz uzlaştırıyor — ve ctx'ten
gelen bir u32 yüklemesi **hep** öyle sığıyor. Yani "karışık genişlik" tek başına yetmiyor.

Gereken şekil: **belirsiz bitleri ÜST yarıya taşı, sonra yalnız ALT yarıyı daralt.**
`r0 <<= 32` sonrası 64-bit aralık çok sayıda bloğa yayılıyor (64-bit uçlar alt yarıyı
hiç kısıtlamıyor) ama 32-bit karşılaştırma alt yarıyı tam olarak sabitliyor — iki
görünümün **bağımsız tutulmak zorunda** olduğu yer tam burası. (BPF'in bir özelliği
alternatifi kapatıyor: her 32-bit ALU op üst yarıyı **sıfırlar**, yani üst yarı
belirsiz kalırken alt yarı düzenlenemez; şekillendirme 64-bit olmak zorunda, sadece
**karşılaştırma** 32-bit.) `mix#hi` bu.

### Ölçüm — gerçek bpf-next VM'inde, üç corpus yan yana
```
capture                    blocks records   regs  partial   cross cross/rec  32-view  32-chk
syz-replay-184.log            184     151    944        0       0      0.00        0       0
gen-targeted-242.log          242     242   2512     1499    1497      6.19     1138       0
gen-mixed-396.log             396     396   4340     2488    2167      5.47     1965     353
```
```
RECORDS  396 (accept 396 / reject 0)
SIGNAL   divergences=0
CHECKS   tnum-vs-bounds: 2167   |   32<->64 bağımsız görünüm: 353
BLOCKS   396 = 396 records + 0 unparsed   UNRECOGNIZED: 0/396 = 0.0%
```
**OI-9'un iddiası artık bir sayı:** tek-genişlikli aile **1138 register'da** 32-bit
görünüm bastırdı ve **hiçbiri** bağımsız bilgi taşımadı — yapısal, daha çok program
eklemek değiştirmez. Karışık aile **353**.

### Doğrulama
- **7 kalibrasyon testi** (`subregister_calibration.rs`), hepsi **gerçek parser
  yolunda** (bu kolun ilk koşusu bir parser hatası ürettiği için parser'ı atlayan test
  işe yaramaz): uyumda susar; tnum↔u32 çelişince bağırır; 32↔64 çelişince bağırır;
  ters aralıkta bağırır; **64-bit'i tekrarlayan görünüm kontrol sayılmaz**; tam
  32-bit aralık sayılmaz; **hex-negatif s32 ters aralık DEĞİLDİR** (bugün bulunan
  hatanın regresyonu).
- **3 parser birim testi** + **4 corpus testi** (396 kayıt, 4 alt-aile, tekil etiket,
  0 kör nokta, ve tek-genişlikli ailenin **tam 0** aldığı pinlenmiş).
- Full suite **90 → 104 passed**, 0 failed.

### Dürüst sınırlar
- **Bulgu yok.** 2167 + 353 kontrol, 0 divergence.
- 353/1965 ≈ **%18** — 32-bit görünüm basılan register'ların çoğu hâlâ 64-bit'i
  tekrarlıyor. bpf-next'in senkronu sıkı; bu iyi haber ama düşük verim demek.
- Hâlâ kapsanmayan şekiller: **register-register operand** (immediate formundan farklı
  verifier yolu), çok-dallı/döngülü akış, pointer aritmetiği, `BPF_LD_IMM64` ile
  64-bit sabitler. OI-9 kapanmadı, **daraltıldı**.
- Metrik bir vekil olmayı sürdürüyor: yüksek payda ateşleme *ihtimalinin* sıfır
  olmadığını garanti eder, bug bulma gücünü değil.

### Dokunulan dosyalar
- `crates/metrics/src/core.rs` (`RegState` + 4 opsiyonel 32-bit alan, `Default`)
- `crates/pipeline/src/verifier_log.rs` (`field_s32`, çıkarım, +3 test)
- `crates/pipeline/src/diff.rs` (yeni kol, `reg32_checkable`, `reg32_unsigned`, payda)
- `harness/diffharness.c` (`--gen-mix`, `run_mixed`/`run_movsx`/`run_upper_half`)
- `crates/pipeline/tests/fixtures/volume/gen-mixed-396.log` (yeni, in-VM)
- `crates/pipeline/tests/subregister_calibration.rs` (yeni, 7 test),
  `tests/targeted_generation.rs` (+4 test)
- `crates/pipeline/examples/signal_density.rs`, `examples/parse_report.rs`
- `python/.../schemas/core.py`, `schemas/diff.py` (mirror)
- `docs/RUNBOOK.md` + `docs/REVIEW-HANDOFF.md` (KVM/Win11 düzeltmesi)

### Sonraki adımlar
- **OI-9 kalanı:** register-register operandlar ve çok-dallı akış.
- **İki-revizyon differential** (reviewer sırasında 2.) — oracle olarak başka bir kernel.
- KVM: **Win11 gerçek ön koşul** (reviewer düzeltmesi; Win10'da nested-virt yok).

## 0027 — Win11/KVM'in nakde çevrilmesi ve seri konsolun sessizce bozduğu satırlar

- **Tarih:** 2026-09-01
- **Durum:** Tamamlandı. Reviewer önceliği 3 (KVM) bir bağımlılık olmaktan çıkıp
  **aksiyona** dönüştü; yol boyunca **sessiz bir parser bozulması** bulundu, kaynakta
  düzeltildi ve etkisi geriye dönük ölçüldü.
- **Alan:** `scripts/run-harness-vm.sh` (accelerator otomatik seçimi),
  `verifier_log.rs` (`console_timestamp_at`, `repair_console_interleaving`, yeni not),
  3 yeni test.
- **İlgili:** 0025, 0026, `oracle × input` kuralı, OI-10 (yeni).

### 0. Önce ön koşul: KVM gerçekten açıldı
Kullanıcı host'u Windows 11'e taşıdı. 0026'daki not ("WSL2 nested virt Win11'e özgü")
doğrulandı: `vmx` 0 → 24, `kvm_intel` yüklü, `/dev/kvm` yazılabilir,
`scripts/boot-vm.sh` kendi kurduğumuz bpf-next'i (`7.2.0-g5e289c5a4a52`) ~1.9s'de
login prompt'a getiriyor. `run-harness-vm.sh` artık accelerator'ı otomatik seçiyor
(`ACCEL=tcg` eski yolu zorluyor).

### 1. Hız — ve bir beklenti düzeltmesi
| | KVM | TCG |
| --- | --- | --- |
| `--gen` (242 program) | 6.7s | 17.6s |
| `--gen-mix` (396 program) | 10.8s | — |
| medyan `load_ns` | 348 429 | 6 827 080 |

**Devlog/hafızadaki "TCG'de ~5 dk" notu yanlıştı** — gerçekte 17.6s. Duvar saati
kazancı 45x değil **2.6x**; dürüst rakam verifier yüklemesinde **~20x**. Aradaki fark
şu: bu koşular kısa ve boot-dominant, dolayısıyla KVM'in asıl getirisi harness'ta
değil, **saatlerce koşan syzkaller'da**.

### 2. Accelerator semantik bir seçim değil — varsayılmadı, ölçüldü
242 programın tamamı iki accelerator altında `load_ns` normalize edildiğinde
**byte-identical** verifier çıktısı üretiyor. Bu, KVM'e geçişin ölçümleri
karşılaştırılabilir bıraktığının kanıtı.

### 3. Asıl bulgu: seri konsol satırın ORTASINA yazıyor
Harness çıktısı VM'in seri konsolundan yakalanıyor — ama kernel de aynı konsola
yazıyor. Bir printk satırın **ortasına** düşebiliyor. Gerçek koşudan, harfiyen:

```text
processed 10 insns (limit 1000000) max_states_per_i[    2.301324] clocksource: ...
nsn 0 total_states 1 peak_states 1 mark_read 0
```

`parse_processed` için bu **sessiz** bir bozulma: `processed ` hâlâ eşleşiyor, yani
`insn_processed` doğru okunuyor, ama `total_states` artık o satırda değil ve
`unwrap_or(0)` gerçek `total_states 1`'i **0** olarak kaydediyor. Ne bir not, ne bir
`unparsed` bloğu. Ölçülen kanıt:

```text
CLEAN: insn_processed=10 states_processed=1   unparsed=0
SPLIT: insn_processed=10 states_processed=0   unparsed=0
```

Bu tam olarak projenin en çok korunduğu sınıf: **verifier gözlemi kılığında bir
parser hatası** — 0026'nın 10 sahte bulgusuyla aynı aile.

### 4. Düzeltme: onar, ama sessizce onarma
`repair_console_interleaving` blok RESULT/log'a ayrılmadan **önce** çalışıyor (printk
`RESULT` satırının ortasına da düşebilir). Tam satırlık konsol çıktısı atılıyor;
ortaya düşen printk'te önek korunup devam satırıyla birleştiriliyor. İki gözlenen
şekil de aynı kuralla çözülüyor — satır sonuna düşen printk'te "devam", orijinal
satırın kendi (boş) kalanı oluyor.

Zaman damgası kalıbı bilerek dar: printk `[%5lu.%06lu]` basıyor, bu yüzden **tam altı**
ondalık hane şart. `[0.5]`, `[12.34]`, `[1.23456789]` eşleşmiyor — verifier metnini
yeme riski test altında.

Ve kritik olan: onarılan kayıt bir **not** taşıyor
(`repaired N console-interleaved line(s)`). Kaydedilmeyen bir onarım, sadece daha
sessiz bir bozulmadır.

### 5. Geçmiş sonuçlar etkilendi mi? — ölçüldü, hayır
Commit'li yedi yakalama taranınca 7 araya girme bulundu; altısı zararsız tam satır.
**Biri gerçek bir mid-line splice** (`syz-replay-184.log:5094`). Düzeltme öncesi ve
sonrası CORE metrikleri (885 kayıt, 6 dosya) **birebir aynı** — çünkü o splice
girintili, parser'ın zaten atladığı bir satıra denk gelmiş. Yani geçmiş
"0 divergence" sonuçları ayakta; ama bu **tasarım değil, şans** oldu ve bunun kayda
geçmesi gerekiyor (OI-10).

**Testler:** 104 → **107**.


## 0028 — Pipeline'ı açmak: F1'i çekirdekten sökmek, binfmt+get_maintainer'ı düzeltmek, iki YENİ zehri ayıklamak — ve OI-1 neden hâlâ kapanmadı

- **Tarih:** 2026-09-03
- **Durum:** Kısmen tamamlandı. Unblock işi **çalıştı ve kalıcı** (üç zehir kapandı,
  bir dördüncüsü konteyn edildi); **OI-1 KAPANMADI** — pre-registered temiz-powered
  bar hiçbir koşuda karşılanmadı, çünkü nested-KVM ortamı sürekli 8-VM yükünde
  çökmeden uzun kampanya vermiyor.
- **Alan:** `scripts/gen-syz-config.sh` (`kernel_src`, `disable_syscalls`, `ignores`),
  `config/kernel/bpf-verifier-lab.config` (`CONFIG_BINFMT_MISC`),
  `.lab/bpf-next` `kernel/bpf/disasm.c` (F1 guard, lab-patch = upstream yaması, commit'li),
  `docs/findings/F1-print_bpf_insn-oob/` (patch + SUBMISSION.md), `docs/OPEN-ITEMS.md`
  (OI-1 güncelleme, OI-11, OI-12).
- **İlgili:** F1, OI-1, OI-11 (yeni), OI-12 (yeni), 0027, `oracle × input`.

### 0. Neden bu iş — reviewer teşhisi
KVM 0027'de açıldı ama asıl getirisi (yüksek hacim) config/bug'larla kapalıydı. İki
şerit — deterministik `--gen` yolu ve syzkaller hacim yolu — kaynak için yarışmıyor;
OI-9 multi-branch beklemekle bir şey kaybetmez, ama unblock **OI-1'in kritik
yolunda**: 0027 sonrası retest kendini çökertmişti (63k exec/27 dk), yani "crash yok"
underpowered bir null'du. KVM'e geçmenin asıl sebebi o testti.

### 1. Config-only unblock — ve düzeltilmiş bir yanlış kol
- **get_maintainer.pl eksik DEĞİLDİ.** `.lab/bpf-next/scripts/`'te duruyor; config'te
  `kernel_obj` vardı, `kernel_src` yoktu → syz-manager onu bulamadı. Fix tek satır.
  **Doğrulandı:** get_maintainer artık F1 yaması için recipient listesi üretiyor.
- **binfmt_misc: 86 sahte SYZFAIL.** `CONFIG_BINFMT_MISC=y` + `ignores`. **Ölçüldü:**
  sonraki tüm koşularda binfmt SYZFAIL = 0.
- **log_level=0 yanlış koldu (düzeltildi).** Capture (`shim.c:73`,`diffharness.c:133`)
  sabit `log_level=2`; oracle'ın `var_off`/`umin`/`tnum`'u oradan. Log kısmak oracle'ı
  kör ederdi. Containment imza/patch bazında olmalı.

### 2. F1 churn değil PANİK → lab-patch + rebuild = upstream yaması
Çekirdek KASAN+UBSAN, fuzz VM'leri `oops=panic`: F1 tetiklenince KASAN raporu VM'i
öldürüyordu. Suppress reproduction'ı keser, VM ölümünü kesmez. Doğru containment:
`disasm.c` guard'ı lab-patch + rebuild → F1 bizim çekirdekte hiç ateşlenmez.
**Rebuild doğrulandı:** BINFMT_MISC/KASAN/UBSAN/KCOV/BTF hepsi `=y`, guard derlendi,
`.BTF` section mevcut (build script'in "no .BTF" uyarısı `readelf -S` grep'inin dar
olması, kozmetik). Guard aynen upstream yaması: `Fixes: b9c5d822f677`. Yama +
recipient + gönderim `SUBMISSION.md`'de; **göndermek insan aksiyonu** (DCO'ya gerçek
isim). **Ölçüldü:** sonraki tüm koşularda print_bpf_insn crash = 0.

### 3. Ölçüm — ve peş peşe İKİ yeni zehir (her biri OI-1'i bir kez daha void etti)
Unblock sonrası KVM throughput smoke'ta ~720 exec/s (zehirli 39/s'e karşı ~18x). Ama
temiz OI-1 nullu için iki katman daha çıktı:

- **3. zehir — PROG_TEST_RUN rcu stall (OI-11).** İlk powered retest (30 dk) çöktü:
  `rcu detected stall in sys_bpf` → tüm VM'lerde `repeatedly failed` kaskadı, throughput
  720→70/s. Stall trace net: `bpf_test_timer_continue` (`net/bpf/test_run.c:83`) —
  yüksek `repeat`li `BPF_PROG_TEST_RUN`, KCOV+KASAN altında 21s eşiğini aşıyor. İki
  kez hedef-dışı: (1) program YÜRÜTME, verification değil; (2) bilinen instrumentation
  artifaktı. Fix: `disable_syscalls` (üç TEST_RUN varyantı; `bpf$*TEST_RUN*` glob'u
  `[FATAL] unknown disabled syscall` ile reddedildi → tam isimler). Bu, input bütçesini
  verifier'a **nişan alıyor** (`oracle × input`: nişan al, sadece büyütme). Smoke: rcu
  stall 0.

- **4. zehir — reproduction-starvation (OI-12).** İkinci powered retest (20 dk) YİNE
  çöktü, ama farklı: ~2 dk sağlıklı (~700/s, tepe 988), sonra **kademeli** düşüş
  (700→260→120→7/s), son ~10 dk ölü. **rcu stall YOK, kernel crash raporu YOK**
  (b83ebc/9deb'de OOM/hung-task imzası yok; host memory 18 GB boş). Tetik manager
  log'unda: 04:24:56 `start reproducing 'SYZFAIL: repeatedly failed to execute the
  program'` — hemen ardından throughput düştü. syzkaller, reproduce edilemeyen bir
  executor/infra hatasını reproduce etmeye VM ayırıyor → fuzzing havuzu açlıktan
  ölüyor (F1 churn'ünün bir kat altı). Fix: o başlığı `ignores`'a ekle. **Ama smoke4
  gösterdi ki bu yetmez:** `repeatedly failed` reproduction'ı kesildi (0), ama alttaki
  `lost connection` oranı YÜKSEK kaldı (6 dk'da 16) ve degradation sürdü (851→79/s) —
  syzkaller bu sefer `lost connection`'ı reproduce etmeye başladı. Bir infra-başlığını
  ignore etmek reproduction'ı sadece bir sonrakine kaydırıyor. **Kök neden nested-KVM
  altında yüksek VM-ölüm oranı; tek bir config knob'u değil.** Bu ORTAM-seviyesi bir
  limit, kod bug'ı değil — bu yüzden whack-a-mole'ü burada durdurdum.

### 4. OI-1 — VERDİCT: hâlâ AÇIK (goalpost taşınmadı)
Kriter önden konuldu (reviewer notu): int3=0 **ancak** tek bir TEMİZ koşu exec≥150k
bar'ını geçerse anlamlı; kampanya kendini çökertirse null **void**. Sonuç: hiçbir koşu
bar'ı temiz geçmedi — her KVM kampanyası er ya da geç çöküyor. **int3 ~0.67M kümülatif
exec'te (5 kampanya) HİÇ tekrar etmedi** — TCG-artifact hipotezini **DESTEKLER** (ve
emülasyon-artifact zaten "ispat" değil güçlü-destek sınıfı), ama pre-registered
temiz-powered bar karşılanmadığı için **OI-1 kapanmıyor**. Bu turda iki kez temiz-değil
bir koşuda kapatma cazibesine direndim; bu ikincisi.

### 5. Dürüst sınırlar
- Unblock kalıcı: binfmt/F1/TEST_RUN kapandı, reproduction-starvation konteyn edildi.
  Deterministik `--gen` yolu bunların hiçbirinden etkilenmez (nested-KVM instability
  syzkaller hacim yoluna özgü).
- Açık kalan: nested-KVM (WSL2→KVM→QEMU) 8-VM sürekli yükte temiz uzun kampanya
  vermiyor. Ucuz sonraki probe'lar (KOŞULMADI): **tek-VM KVM kampanyası** (8-VM
  contention'ı eler; OI-1'in orijinal partial-discriminator'larından biri de budur),
  `VMMEM` 2048→4096, `VMCOUNT` 8→4, periyodik VM reboot.
- F1 upstream'de fix BEKLİYOR (gönderilmedi); bizim taraf sadece lab konteynmentı.

### 6. Dokunulan dosyalar
`scripts/gen-syz-config.sh`, `config/kernel/bpf-verifier-lab.config`,
`.lab/bpf-next/kernel/bpf/disasm.c` (lab-patch, commit'li),
`docs/findings/F1-print_bpf_insn-oob/{0001-*.patch,SUBMISSION.md}`,
`docs/OPEN-ITEMS.md`.

### 7. Sonraki adımlar (öneri — reviewer kararı)
(a) **Tek-VM KVM OI-1 probe'u** — en ucuzu, nested-virt contention hipotezini test eder
ve temiz düşük-hızlı exposure biriktirebilir. (b) Ya da kümülatif int3=0'ı kabul edip
OI-1'i "destekleniyor; pre-registered bar ORTAM nedeniyle karşılanamadı" notuyla
düşük-öncelikte açık bırak. (c) **OI-9 multi-branch** deterministik yolda engelsiz —
nested-KVM instability'sinden bağımsız ilerleyebilir.

## 0029 — OI-1'in tek-VM verdikti (ortam limiti) + OI-9 çok-dallı aile (`--gen-mb`)

- **Tarih:** 2026-09-03
- **Durum:** Tamamlandı. İki iş, hard-stop'lu: (1) OI-1 için tek-VM KVM probe'u —
  önden kayıtlı tek koşu, kapandı → **OI-1 açık kalıyor, ortam nedeniyle** (fix-and-rerun
  YOK); (2) OI-9 çok-dallı/çok-birleşme ailesi eklendi, ölçüldü, pinlendi.
- **Alan:** `harness/diffharness.c` (`--gen-mb` ailesi),
  `crates/pipeline/tests/multi_branch_calibration.rs` (+fixture
  `gen-multibranch-242.log`), `docs/OPEN-ITEMS.md` (OI-1, OI-9).
- **İlgili:** OI-1, OI-9, OI-11/OI-12 (0028), `oracle × input`.

### 1. OI-1 — tek-VM probe'u: hard-stop'lu tek koşu
Kullanıcı (1)+(3)'ü paralel, **bir hard-stop şartıyla** onayladı; şartı ben koydum:
tam BİR kampanya, max 30 dk, bu turun SON OI-1 koşusu, ne olursa olsun başka fix/rerun
yok. Tek-VM mantığı: 8-VM contention'ı eler; ayrıca tek VM'de yedek VM olmadığı için
OI-12 reproduction-starvation'ı yapısal olarak da zayıflar.

**Sonuç — tek-VM DAHA KÖTÜ, daha iyi değil:** 30 dakikada **31 VM kopması** ("lost
connection"), corpus triage HİÇ bitmedi (candidates 1057'de takılı kaldı), yalnızca
**~4.2k exec** (150k bar'ın 35x altında). int3=0, ama kampanya işlevsiz — tam void bir
null. Bu, nested-KVM kararsızlığının **8-VM contention OLMADIĞINI** kanıtlıyor: tek VM
bile sürekli kopuyor. (Confound: bu probe VMCPU 2→4 / VMMEM 2048→4096 da yaptı; hard-stop
ayrıştırma için rerun'ı yasakladı — ama sonuç iki durumda da aynı.)

**Verdikt:** WSL2 nested-KVM bu host'ta üretken bir syzkaller kampanyası taşıyamıyor;
OI-1 syzkaller yolunda bu ortamda çözülemez. Tüm koşullarda int3 hiç tekrar etmedi
(~0.68M kümülatif exec) → TCG-artifact hipotezini **DESTEKLER** ama İSPATLAMAZ. OI-1
düşük öncelikte açık; gerçek çözüm bare-metal ya da nested-olmayan KVM ister (Win11
ön-koşulu gibi, repo dışı). **Bu turda üçüncü kez temiz-değil bir koşuda kapatma
cazibesine direndim; hard-stop tam da bunun içindi.**

### 2. OI-9 — çok-dallı / çok-birleşme ailesi (`--gen-mb`)
`--gen` ve `--gen-rr` ailelerinin her programında TEK compare, TEK birleşme noktası
var. Yeni aile İKİ ardışık dal + İKİ birleşme taşıyor, ve ikinci dal, birinci dalın iki
yolunun BİRLEŞİMİ olan bir durumu daraltıyor:

```
0: r0 = *(u32*)(r1+0)      1: r0 <op> imm1        2: if r0 <cmp> imm_a goto 5
3: r0 <op> imm2  4: goto 6  5: r0 <op> imm3       6: [BİRLEŞME1] if r0 <cmp> imm_b goto 9
7: r0 <op> imm2  8: goto 10 9: r0 <op> imm3       10:[BİRLEŞME2] r0 &= 0xffff  11: exit
```

imm_a=`c->imm`, imm_b=`a->imm2` (farklı sabit → ikinci dal gerçek bir ikinci daraltma,
birincinin trivial tekrarı değil). Etiket reçetenin kendisi (`genmb#w{32,64}.alu.cmp#idx`)
→ her bulgu tek başına yeniden kurulabilir. Yapı gereği hepsi kabul (aynı geçerli op'lar,
sadece zincirli), böylece tnum-vs-bounds paydası temiz kalıyor.

**Ölçüm (gerçek bpf-next `5e289c5a4a52`, in-VM, KVM boot ~11s):** 242 program, **242/242
kabul**, tnum_bounds_checked=**2050** (tek-genişlik 1497'nin üstünde, reg-reg 2453'ün
altında — iki birleşme, tek-diamond'dan fazla ama iki-bağımsız-bilinmeyen reg-reg kadar
değil), **0/2050 divergence**, 0 parser kör-noktası. reg32_checked=**0** (her program
tek-genişlik → 32<->64 ekseni mixed ailenin işi; pinlendi). 4 test
`multi_branch_calibration.rs`'de geçiyor.

**Hâlâ verifier LOGIC bug'ı yok** — ama artık çok-dal/çok-birleşme yüzeyinde 0/2050.

### 3. Dürüst sınırlar
- OI-1 verdikti bir ortam limiti, kod sonucu değil; deterministik `--gen*` yolu (kısa,
  tek-VM boot) etkilenmiyor — `--gen-mb` bunu bir kez daha gösterdi (11s'de temiz koştu).
- Çok-dallı aile *sıralı dallanma*; gerçek *looping* (back-edge) ayrı bir leg —
  provably-bounded sayaç ister ve kabul profili farklı (hepsi-kabul değil). Ertelendi.
- OI-9'da sıradaki: pointer arithmetic, sonra looping.

### 4. Dokunulan dosyalar
`harness/diffharness.c`, `crates/pipeline/tests/multi_branch_calibration.rs`,
`crates/pipeline/tests/fixtures/volume/gen-multibranch-242.log`, `docs/OPEN-ITEMS.md`.

## 0030 — Pointer-arithmetic ailesi (`--gen-ptr`): verifier'ın pointer-güvenlik kararı, ilk çıktı

- **Tarih:** 2026-09-03
- **Durum:** Tamamlandı (ilk artım). OI-9'un en yüksek beklenen-değerli yüzeyi —
  reviewer'ın işaretlediği gibi: skalar range mantığının aksine burada bir logic bug
  yanlış-KABUL edilen bir OOB-**write** demek (F1'in OOB-read'inden daha yüksek severity).
- **Alan:** `harness/diffharness.c` (`--gen-ptr`),
  `crates/pipeline/tests/pointer_arith_calibration.rs` (+fixture `gen-ptr-242.log`),
  `docs/OPEN-ITEMS.md` (OI-9).
- **İlgili:** OI-9, F1 (aynı diagnostics.c yolu), `oracle × input`.

### 1. Tasarım — gerçek bir pointer, sınırlı offset, pointer üzerinden STORE
Önceki tüm aileler (`--gen`/`-rr`/`-mb`/`-mix`) yalnızca SKALAR birleştiriyor. Bu aile
gerçek bir `PTR_TO_MAP_VALUE` alıyor (64-byte ARRAY value'da `bpf_map_lookup_elem`),
şekillendirilmiş+daraltılmış bir skalar offset ekliyor, ve ayarlanmış pointer üzerinden
**yazıyor**:

```
6: if r0==0 goto 15   (zorunlu null-check)   7: r1 = *(u32*)(r0+0)  (bilinmeyen offset)
8: r1 <alu> imm1   9: if r1 <cmp> imm goto 12   10/12: r1 <alu> imm2/imm3 (dal)
13: r0 += r1  (POINTER ARITH)   14: *(u8*)(r0+0) = r1  (STORE -> bounds check)
```

Yapı gereği **hepsi-kabul DEĞİL** — kabul, verifier'ın offset'in value_size içinde
kaldığını ISPATLAYIP ispatlayamamasına bağlı, ki test edilen karar tam bu.

### 2. İlk çıktı (gerçek bpf-next `5e289c5a4a52`, in-VM, KVM boot ~11s)
- **242 program, 34 kabul / 208 red** — gerçek bir accept/reject karar yüzeyi. Red
  dağılımı: **199 EACCES** (güvenlik reddi) + **9 EINVAL**.
- **tnum_bounds_checked = 1191**, **0 divergence**. Oracle hem skalar offset'i HEM DE
  pointer'ın kendi `var_off`'unu kontrol ediyor (`R0=map_value(...,var_off=(0x0; 0xf))`).
- **0 parser kör-noktası** (unparsed=0, unrecognized=0) — bir İLK koşu için dikkat
  çekici: parser map_value pointer state'ini, `r0 += r1` pointer aritmetiğini ve
  diagnostics.c red raporlarını temiz okudu. (Kıyas: 0026'nın ilk koşusu 10 parser
  bulgusu üretmişti; reg-reg de dikkat istemişti.) reg32_checked=0.
- **Kabul örneği** (`genptr#w64.and.jeq#000`): `and 0xf0f` + `jeq 0x40` offset'i [0,15]'e
  daraltıyor; 15 < 64 → 1-byte yazma sınır içinde → kabul. Pointer'a offset işleniyor:
  `R0=map_value(ks=4,vs=64,...,umax=15,var_off=(0x0; 0xf))`.

### 3. 9 EINVAL — generator bug'ı DEĞİL, diagnostics.c yolu (F1 ile aynı tesis)
EINVAL alanlar imzalı karşılaştırmalarda kümeleniyor (`jsgt`/`jsge`/`jset` × `sub`/`or`/
`xor`/`arsh`). Log'ları verifier'ın **diagnostics raporlayıcısını** gösteriyor —
"Instruction context" + "Suggestion: Clamp or bounds-check the scalar offset before
applying it to the pointer". Yani meşru bir verifier reddi (yeni tanılama yolu), bozuk
program değil. Yan fayda: aile F1'in geldiği aynı diagnostics.c tesisini yoğun
kullanıyor ve F1 guard'ının ayakta olduğunu doğruluyor (bunlar LDX, LDSX+DW değil → OOB yok).

### 4. Hâlâ verifier LOGIC bug'ı yok — ama artık DÖRT yüzey taranmış
Tek-genişlik 1497 + reg-reg 2453 + çok-dallı 2050 + pointer 1191 ≈ **7200 kontrol,
0 divergence**. "Bulamıyoruz" değil — "bu dört yüzey (skalar imm, reg-reg, çok-birleşme,
pointer/OOB-write) temiz, sıradakine".

### 5. Dürüst sınırlar — ve sıradaki artımlar
- Bu ilk artım: **1-byte store** ve yalnızca **map-value** pointer. Genişletmeler:
  daha geniş store'lar (2/4/8-byte, sınır kenarını daha sıkı zorlar), **stack** ve
  **packet** pointer'ları (paket data/data_end sınır kontrolü — tarihsel olarak en yoğun
  bug bölgesi), ve 9 EINVAL imzalı-karşılaştırma alt-ailesinin ayrı incelenmesi.
- Oracle sınırı: intrinsic leg tnum-vs-bounds TUTARLILIĞINI kontrol ediyor; "bu kabul
  DOĞRU muydu" (yanlış-kabul = OOB-write) için gereken ground-truth ayrı bir problem —
  ama tutarlılık ihlali de o bug sınıfının bir göstergesi ve şu an 0/1191.

### 6. Dokunulan dosyalar
`harness/diffharness.c`, `crates/pipeline/tests/pointer_arith_calibration.rs`,
`crates/pipeline/tests/fixtures/volume/gen-ptr-242.log`, `docs/OPEN-ITEMS.md`.

## 0031 — Packet-pointer ailesi (`--gen-pkt`): program-ispatlı sınır, statik takip, ilk çıktı

- **Tarih:** 2026-09-03
- **Durum:** Tamamlandı (ilk artım). Reviewer'ın tasarım sorusuna cevap bir **premise
  düzeltmesi** gerektirdi ve o düzeltme tasarımı belirledi.
- **Alan:** `harness/diffharness.c` (`--gen-pkt`, SCHED_CLS),
  `crates/pipeline/tests/packet_pointer_calibration.rs` (+fixture `gen-pkt-242.log`),
  `docs/OPEN-ITEMS.md` (OI-9).
- **İlgili:** OI-9, 0030 (map-value pointer), `oracle × input`.

### 0. Premise düzeltmesi — `data_end` sabitleme mekanizması GEREKMİYOR
Reviewer'ın endişesi: packet'ta `data + off < data_end` runtime'da gerçekleşir; runtime
`data_end` sabitlenmezse kabul/red kararı değişkenleşir ve deterministik ölçüm anlamını
kaybeder. **Bu doğru değil — verifier'ın packet-bounds kararı tamamen STATİK (load-time).**
Verifier runtime `data_end` değerini hiç bilmez (bilinmeyen değerli bir pointer). Yaptığı
şey (`find_good_pkt_pointers`, `verifier.c:16068`, kernel'in kendi yorumuyla):
`r2 = data; r2 += 8; if (r2 > pkt_end) goto err` → programın KENDİ compare'i; verifier
güvenli yolda `new_range = reg_umax(dst_reg)` kaydeder (programın eklediği STATİK
offset'ten türetilir) ve her packet erişimini `check_mem_region_access(..., reg->range, ...)`
ile o kayıtlı range'e karşı load-time'da kontrol eder. Harness zaten sadece LOAD ediyor,
hiç çalıştırmıyor — runtime yok. Kabul/red, komut dizisinin saf fonksiyonu →
deterministik `--gen` yolu ve paydası aynen geçerli. **Kaynakta doğrulandı, log'da canlı
görüldü** (§2).

Doğru olan kısım (reviewer'ın ikinci noktası): mekanizma farklı. Map-value'da verifier
sınırı BİLİR (value_size); packet'ta program sınırı kendi compare'iyle İSPATLAR, verifier
ispatı takip eder. Farklı kod yolu, kendi kenarlarıyla — `MAX_PACKET_OFF` (0xffff)
overflow guard'ı ve `range_right_open` (`>` vs `>=`). Tarihsel bug yoğunluğu tam orada.

### 1. Tasarım
`socket_filter` direkt packet erişimini **yasaklıyor** (`sk_filter_is_valid_access` →
`return false`, doğrulandı); `SCHED_CLS` izin veriyor (`data→PTR_TO_PACKET`,
`data_end→PTR_TO_PACKET_END`, doğrulandı) → aile `run_one_ex` ile SCHED_CLS yüklüyor.

```
0: r2=*(u32*)(r1+76) data   1: r3=*(u32*)(r1+80) data_end   2: r4=*(u32*)(r1+0) len
3: r4<alu>imm1   4: if r4<cmp>imm goto 7   5/7: r4<alu>imm2/imm3   8: r2 += r4 (PKT ARITH)
9: r5=r2  10: r5+=1   11: if r5 > r3 goto 13  (PROGRAMIN KENDİ SINIR KONTROLÜ → range)
12: *(u8*)(r2+0) = r4  (STORE, range'e karşı)   13: r0=0  14: exit
```
Kabul ≈ şekillendirme offset umax'ını `MAX_PACKET_OFF` içinde tutup range kaydedilebilir
kılıyor mu — tam o guard'ın accept/reject taraması. `data_end` compare'i bu ilk artımda
`>`'de sabit (kanonik idiom); onu enumerate etmek (jgt/jge/jlt/jle → right-open/closed)
doğal ikinci artım.

### 2. İlk çıktı — mekanizma log'da CANLI
- **242 program, 49 kabul / 193 red** (184 EACCES + 9 EINVAL). Map-value'dan (34/208)
  biraz daha çok kabul — 0xffff sınırı value_size=64'ten gevşek, beklenen.
- **tnum_bounds_checked = 1254, 0 divergence, 0 parser kör-noktası.** `pkt(id=1,r=16,
  ...,var_off=(0x0; 0xf))`, `pkt_end()` ve SCHED_CLS parser'a yeni şekillerdi; hepsi
  temiz okundu (pkt token'ı var_off+bounds taşıyor → pointer'ın kendi offset'i oracle'a
  gitti). 1 parse notu = OI-10 console-interleave onarımı (zararsız tür).
- **Statik range canlı** (`genpkt#w64.and.jeq#000`): `9: R2=pkt(id=1,r=0,...umax=15)` →
  `11: if r5 > r3 goto pc+1 ; R3=pkt_end() R5=pkt(id=1,r=16,...)` → `12: *(u8*)(r2+0)=r4`
  kabul. `r=0 → r=16`, compare boyunca, saf statik umax'tan. §0'ın kanıtı.
- **Red = MAX_PACKET_OFF guard'ı** (`genpkt#w64.or.jeq#011`): `or 0x00f0` üst bitleri
  bilinmeyen bırakıyor (`unknown mask 0xffffff0c`, umax ≫ 0xffff) → range kaydedilemez →
  "outside of the object of size 0" → red. Tasarlandığı gibi.

### 3. 9 EINVAL — map-value ailesiyle BİREBİR aynı indeksler
087, 138, 139, 149, 150, 182, 183, 204, 205 — `w64.sub.jset` + `w32.{or,xor,arsh,sub}×
{jsgt,jsge}`. Pointer tipinden BAĞIMSIZ, skalar şekillendirmenin (imzalı compare'lerin
diagnostics.c raporlayıcısını tetiklemesi) bir özelliği. Yeniden üretilebilir bir alt-aile;
ayrı incelemeye değer, bug değil.

### 4. BEŞ yüzey taranmış — hâlâ logic bug yok
1497 + 2453 + 2050 + 1191 + **1254 ≈ 8450 kontrol, 0 divergence**. Skalar imm, reg-reg,
çok-birleşme, map-value pointer (OOB-write), packet pointer (program-ispatlı sınır).

### 5. Dürüst sınırlar — sıradaki
- 1-byte store, `data_end` compare'i `>`'de sabit. En yüksek değerli genişletmeler:
  **`data_end` operatör taraması** (jgt/jge/jlt/jle → `range_right_open` kenarı — kernel'in
  kendi "off-by-one" bölgesi), daha geniş store'lar (2/4/8-byte), 9-EINVAL alt-ailesi.
- Oracle intrinsic tutarlılığı kontrol ediyor; "bu kabul DOĞRU muydu" (yanlış-kabul =
  OOB-write) için ground-truth ayrı — ama tutarlılık ihlali o sınıfın göstergesi, şu an 0/1254.

### 6. Dokunulan dosyalar
`harness/diffharness.c`, `crates/pipeline/tests/packet_pointer_calibration.rs`,
`crates/pipeline/tests/fixtures/volume/gen-pkt-242.log`, `docs/OPEN-ITEMS.md`.

## 0032 — Packet `data_end` compare-op taraması (`--gen-pkt-cmp`): T1-3, range_right_open kenarı

- **Tarih:** 2026-09-03
- **Durum:** Tamamlandı. 0031'in adını koyduğu "doğal ikinci artım" — kernel'in kendi
  "off-by-one" bölgesi ölçüldü ve **tam tutarlı çıktı**.
- **Alan:** `harness/diffharness.c` (`--gen-pkt-cmp`, `run_generated_pktcmp*`, `PKT_DCMP`
  tablosu), `crates/pipeline/tests/packet_compare_calibration.rs` (yeni, 5 test, +fixture
  `gen-pktcmp-240.log`), `docs/OPEN-ITEMS.md` (OI-9), `docs/COVERAGE-MAP.md` (T1-3).
- **İlgili:** OI-9, 0031 (packet pointer), coverage haritası T1-3, `oracle × input`.

### 0. Hedef — tek değişken: range'i kuran compare
0031 offset şekillendirmesini (alu×cmp) tarıyordu ama sınır kontrolünü `>`'de (BPF_JGT)
sabit tutuyordu. T1-3 tersini yapar: offset şekillendirmesini tek bilinen skalere
(`r4 &= 7`, [0,7]) **sabitler** ve YALNIZ `find_good_pkt_pointers`'ı besleyen compare'i
süpürür. Böylece accept/reject, range makinesinin saf fonksiyonu olur. İki dik eksen:

- **closed vs right-open** — {gt,lt} `r5 <= end` ispatlar, {ge,le} `r5 < end` ispatlar.
  Kayıtlı range bir bayt kayar; bu kernel'in tarihsel off-by-one bölgesi.
- **operand-sırası simetrisi** — gt (`r5 > end`) ile lt (`end < r5`) AYNI OOB koşulunun
  iki yazımı; ge ile le keza. `find_good_pkt_pointers` ikisini aynı görmek zorunda.

Program (11 insn, SCHED_CLS): `r2=data; r4=len; r4&=7; r2+=r4; r5=r2; r5+=M;
if (r5 <dcmp> r3) goto skip; *(uW*)(r2+off)=r4; skip: r0=0; exit`. Grid: form(4) ×
headroom M(1..5) × store-offset off(0..3) × genişlik W(1,2,4) = **240 program**.

### 1. Çıktı — bpf-next VM'de (kernel 5e289c5a), 2026-09-03
- **240 program, 128 kabul / 112 red.** Form başına: **gt=27, ge=37, lt=27, le=37** (her
  biri /60).
- **Simetri TAM tutuyor:** gt == lt (27) ve ge == le (37). `find_good_pkt_pointers`
  operand-sırasına simetrik — süpürmenin birinci sorusu temiz "evet".
- **Closed vs right-open TAM bir bayt:** predikat `accept ⟺ off+W ≤ range`, closed
  range=M, right-open range=M+1 — **240/240 birebir uyuşuyor, 0 istisna.** Right-open
  formlar (`>=`/`<=`) closed formlardan tam 10 fazla kabul ediyor (37 vs 27), ve fark her
  (M,off,W) hücresinde tam bir baytlık kaymadan geliyor. **Off-by-one yok, drift yok** —
  verifier tam olarak programın ispatladığını ispatlıyor, ne bir bayt fazla ne eksik.
- **tnum_bounds_checked = 720** (alu×cmp ailelerinden düşük — offset şekli sabit,
  çeşitlilik yerine izolasyon), **reg32_checked = 0, 0 divergence, 0 parser kör-noktası.**

### 2. Kenarı izole eden çift
`gt.M1.o0.w2` (closed, reach=2, M=1 → 2>1) **red**; `ge.M1.o0.w2` (right-open, reach=2,
M+1=2 → 2≤2) **kabul**. Tek fark compare'in `>` vs `>=` olması — `range_right_open`'ın
kararı tek baytta çevirdiği nokta, canlı. Kabul tarafı da güvenli: `>=` ile M=1 iken 2-byte
store'un kabulü, verifier'ın `r5 < end`'den `r5+1 ≤ end` çıkarımının doğru sonucu.

### 3. Verdikt
Tarihsel olarak en yoğun packet-bounds off-by-one bölgesi bu kernel'de **tam tutarlı**.
Süpürmenin iki sorusu (operand simetrisi + closed/open bir-bayt) da temiz geçti; 0/720
invariant ihlali. Logic bug yok — ama bu, aranan sınıfın (`range_right_open` yanlış-kabulü
= OOB-write) ta kendisiydi; oracle onu görebilecek çözünürlükteydi ve verifier temiz çıktı.

### 4. Sıradaki (T1 kalanı)
- T1-2 negatif offset + smin (map-value): `r2 += -4`, smin kontrol yolu — ucuz, doğrudan
  karar yüzeyi. T2-2 daha geniş store'lar map-value'da. 9-EINVAL alt-ailesi hâlâ açık.
- Bu artım da 0/720 ihlalle kapandı: altı ailenin üstüne yedinci ölçüm, hâlâ logic bug yok.

## 0033 — Negatif-offset map-value ailesi (`--gen-ptr-neg`): T1-2, smin alt-sınır yolu

- **Tarih:** 2026-09-03
- **Durum:** Tamamlandı. Coverage haritasının T1-2'si — pointer'ın alt (negatif) kenarı.
  smin kontrolü **uygulanıyor**; aranan tarihsel bug sınıfı bu kernel'de yok.
- **Alan:** `harness/diffharness.c` (`--gen-ptr-neg`, `run_generated_ptrneg*`, `PTRNEG_C`
  + `PTRNEG_REACH`), `crates/pipeline/tests/pointer_neg_calibration.rs` (yeni, 5 test,
  +fixture `gen-ptrneg-120.log`), `docs/OPEN-ITEMS.md` (OI-9), `docs/COVERAGE-MAP.md` (T1-2).
- **İlgili:** OI-9, 0030 (--gen-ptr, pozitif offset / üst sınır), coverage T1-2.

### 0. Hedef — pointer'ın ALT kenarı
`--gen-ptr` map_value pointer'a POZİTİF bounded scalar ekliyor → karar ÜST sınırda
(`umax + size ≤ value_size`). T1-2 öteki kenarı sürüyor: işaretli minimumu NEGATİF
olabilen offset — map value'nun başının ALTINA yazma. Kernel bunu ayrı bir kontrolle
korur (`check_map_access`: "R%d min value is negative, either use unsigned index or do a
if (index >=0) check"). Tarihsel olarak bu smin yolu atlanmış/yanlış türetilmiş — atlanırsa
**OOB-below WRITE kabul edilir**, ağır sınıf.

Offset deterministik negatife itiliyor: `r1 &= 15` (→[0,15]) sonra `r1 -= C`
(→ işaretli [-C, 15-C], smin=-C). İki form:
- **raw** — guard yok. smin<0 ise store REDDEDİLMELİ. raw C>0'ın canlı bir store'u kabul
  etmesi, bu kolun avladığı bug'dır.
- **grd** — `if (r1 s< 0) goto skip_store`. Store yolunda verifier smin≥0'ı yeniden
  türetip KABUL etmeli (yalnızca her negatifi aşırı-reddetmediğini kanıtlar). İşaretli
  daldan sonra smin re-türetimini test eder — tam o kod yolu.

Grid: form{raw,grd} × C{0,1,2,4,8,16,24,32,48,64}(10) × reach{(off,W)}(6) = **120 program**,
value_size=64, mask=15.

### 1. Çıktı — bpf-next VM (kernel 5e289c5a), 2026-09-03
- **120 program, 60 kabul / 60 red.** raw **4/60** (her kabul C==0), grd **56/60**.
- **Karar predikatı 120/120 tam:** `accept ⟺ (grd ∧ C≥16, ölü store) ∨ (r1min≥0 ∧
  15−C+off+W ≤ 64)` — 0 istisna. Karar, store-yolu offset aralığının [0, value_size]'e
  karşı saf fonksiyonu.
- **Sağlamlık (T1-2'nin özü):** negatif-yetenekli hiçbir store kabul edilmedi — raw
  kabullerin **tümü C==0** (ispatlanabilir ≥0). "R0 min value is negative" mesajı canlı,
  smin alt-sınır kontrolü **uygulanıyor** (vacuously yok değil). grd 56 kabul → verifier
  işaretli daldan sonra smin≥0'ı doğru türetiyor, aşırı-reddetmiyor.
- **tnum_bounds_checked = 438, reg32_checked = 0, 0 divergence, 0 parser kör-noktası.**

### 2. Mekanizma detayı — red NEDENİ sabit off'a göre kayıyor (bug değil)
raw C>0'da beklenen "negatif-min" değil bazen üst-sınır mesajı çıkıyor. Sebep: sabit `off`
etkin min'i (`smin_ptr + off`) sıfırın üstüne kaldırınca alt kontrol geçiyor, ama
`r1 -= C` (C>0, umin=0<C) unsigned bound'u U64_MAX'e patlatıyor → üst kontrol reddediyor.
İkisi de doğru red; verifier benim ilk modelimden daha hassas. Karar (accept/reject) her
iki durumda da tutarlı — 120/120.

### 3. Verdikt
Map-value negatif-offset smin alt-sınır kontrolü bu kernel'de **uygulanıyor ve tutarlı**.
raw negatif store'ların hepsi reddedildi, grd rescue'ları kabul edildi, 0/438 invariant
ihlali. Sekizinci ölçüm, hâlâ logic bug yok. Sıradaki T1: **T1-1** 32↔64 × pointer-offset
(en yoğun tarihsel bölge). Kalan: daha geniş map-value store'ları, 9-EINVAL alt-ailesi.

## 0034 — 32↔64 × pointer-offset ailesi (`--gen-ptr-hi`): T1-1a, üst-bilinmez soundness probe

- **Tarih:** 2026-09-03
- **Durum:** Tamamlandı (T1-1a — soundness yarısı). Kurulum kararı **ölçümle** verildi
  (`--probe-t1`, 3 iddia), ve mutual-exclusivity teoremi bir reviewer önerisini (K<value_size
  ekle) kurmadan önce eledi. Ayırt edici yarı (T1-1b) yeni bir oracle kolu gerektiriyor, ayrı.
- **Alan:** `harness/diffharness.c` (`--probe-t1`, `--gen-ptr-hi`, `run_probe_t1_family`,
  `run_hi_soundness`/`run_hi_bounded`), `crates/pipeline/tests/pointer_hi_calibration.rs`
  (yeni, 5 test, +fixture `gen-hi-52.log`), `docs/OPEN-ITEMS.md`, `docs/COVERAGE-MAP.md` (T1-1).
- **İlgili:** OI-9, 0026 (32↔64 skaler kol), 0030 (--gen-ptr), CVE-2020-8835, coverage T1-1.

### 0. Kurulum ölçümle verildi — 3 iddia, 3 teyit (--probe-t1)
Tam aileden önce 3 hand-built program VM'de koştu, program-başına reg32_checked + mesajla:
- **naiveA** (`w1 &= 0x3f; r0 += r1`): reg32=**0**, accept. `zext_32_to_64` (verifier.c:5652,
  `if (alu32) zext` @15695) üst yarıyı sıfırlıyor → iki görünüm çakışıyor → 0025 tuzağı.
- **hi** (üst-bilinmez + 32-bit compare): reg32=**2**, reject. Yüzeye değen tek kurulum.
- **ptr32** (`w0 += w1`): reg32=0, "R0 32-bit pointer arithmetic prohibited" (verifier.c:14585)
  → bounds mantığına hiç girmiyor, Option B ölü.

### 1. Provenance — red pointer-add'den, 64-bit görünümden
hi red mesajı ("math between map_value pointer and register with unbounded min value")
`check_reg_sane_offset_scalar` (verifier.c:14190) tarafından, `adjust_ptr_min_max_vals`
**içinden satır 14665**'te, `off_reg` üzerinde basılıyor; o fonksiyon offset'in **64-bit**
sınırlarını (`reg_smin`/`reg_umax`) okuyor, **u32/s32'ye hiç bakmıyor**. Yani "verifier
pointer için 32 mi 64 mü kullanır" sorusunun cevabı yapısal olarak kesin: **her zaman 64.**
Bu, hi'nin neden geçerli soundness probe'u olduğunu kanıtlıyor — reg32>0 (bağımsız 32-durum
var) ama karar 64'ten, accept=bug.

### 2. Mutual exclusivity — bir reviewer önerisini kurmadan eledi
`reg32>0 ⟺ üst 32 bilinmez ⟺ umax≥2³² & smin=S64_MIN`; meşru-accept `⟺ umax<value_size<2³²
⟺ üst bitler sabit ⟺ reg32=0`. İki koşul aynı anda olamaz. Yani "K<value_size ekle,
verifier'ın 32 mi 64 mü kullandığını gör" önerisi hi'de **boş küme** üretiyordu — her K için
üst yarı bilinmez kalır, smin=S64_MIN, red. K alt-ekseni eklenmedi (0025 tuzağının tasarım
katmanına taşınmış hali). Ayırt edici test yapısal olarak farklı bir aile → T1-1b.

### 3. Çıktı — bpf-next VM (kernel 5e289c5a), 2026-09-03
- **52 program, 8 kabul / 44 red.** hi kolu (40): **0 kabul / 40 red** — mutual
  exclusivity'nin öngördüğü all-reject, **0 yanlış-kabul** (bug yok), hepsi "unbounded min
  value". bnd kolu (12): 8 kabul / 4 red (4'ü doğru üst-sınır redleri, mask+off+W>64).
- **reg32_checked = 52, TAMAMEN hi kolundan (bnd = 0).** Pointer bağlamında reg32'yi
  sıfırdan çıkaran **ilk aile** — ve bounded kolun tam 0 olması, yüzeyin tam hi
  konstrüksiyonu olduğunun kanıtı. **0 divergence, 0 parser kör-noktası.**

### 4. İmza ve sınır
T1-1a'nın imzası accept/reject dengesi değil: **reg32_checked>0 + 0 yanlış-kabul.** Kanıtladığı:
"üst-bilinmez offset pointer erişimini lisanslayamaz; verifier pointer-add'de yalnız 64'e bakar."
Gerçek ama dar — çünkü adjust_ptr_min_max_vals zaten yapısal olarak 32'ye bakmıyor, bu kolun
bulacağı bug'ı kod yapısı zaten engelliyor. Düşük-sürprizli, temiz, provenance-teyitli. Kapat, geç.

### 5. Asıl av T1-1b (ayrı, öncelikli) — yeni oracle kolu gerekiyor
Ayırt edici "verifier doğru görünümü/sync'i mi kullanıyor" testi (CVE-2020-8835 sınıfı):
meşru-64-sınırlı offset, sync-kırılgan 32↔64 dizisiyle üretiliyor; bug = **yanlış-kabul veya
32↔64 görünüm ayrışması accept'e rağmen**. İmzası reg32>0 DEĞİL (sağlam verifier'da sync
çalışır → reg32=0). Mevcut hiçbir dedektör kolu "aynı register'ın 32 ve 64 görünümü tutarsız"ı
kontrol etmiyor → T1-1b iki iş: **yeni 32↔64-sync-invariant oracle kolu** (intrinsic tnum'un
0026'daki genişlemesinin accept-tarafı) + onu besleyen sync-kırılgan aile. Sıradaki karar orada.

## 0035 — 32↔64 sync-kırılgan aile (`--gen-sync`): T1-1b, CVE-2020-8835 sınıfı regresyon nöbetçisi

- **Tarih:** 2026-09-04
- **Durum:** Tamamlandı (T1-1b — T1-1'in ayırt edici yarısı; T1-1a soundness yarısıydı, 0034).
  **0034'ün öngörüsü düzeltildi:** T1-1b "iki iş" (yeni 32↔64-sync oracle kolu + aile) diye
  tahmin edilmişti; çözülen oracle sorusu (fix commit `f2d67fec0b43` incelemesi) desync'in
  **tam olarak mevcut invariant B** (`tnum32_bounds_inconsistent`, diff.rs) olduğunu gösterdi
  → **tek iş**: sync-kırılgan aile, B'yi yeniden kullanarak. Epistemik olarak daha temiz
  (yeni model/invariant değil, mevcut redundancy'nin ölçümü).
- **Alan:** `harness/diffharness.c` (`--probe-t1b`, `--gen-sync`, `run_probe_t1b_family`,
  `run_sync_cve`/`run_sync_shift`/`run_generated_sync_family`), `scripts/probe-t1b.sh`,
  `scripts/run-sync.sh`, `crates/pipeline/tests/probe_t1b_reg32.rs` (#[ignore] probe),
  `crates/pipeline/tests/measure_log.rs` (#[ignore] genel ölçüm), `crates/pipeline/tests/
  sync_calibration.rs` (yeni, 6 test, +fixture `gen-sync-24.log`), `docs/OPEN-ITEMS.md`,
  `docs/COVERAGE-MAP.md` (T1-1).
- **İlgili:** OI-9, 0026 (32↔64 skaler kol), 0034 (T1-1a), CVE-2020-8835, fix `f2d67fec0b43`
  (`__reg_bound_offset32`), diff.rs invariants B ve C, coverage T1-1.

### 0. Oracle kararı — desync = mevcut invariant B (yeni kol GEREKMEDİ)
CVE-2020-8835 fix commit'i (`__reg_bound_offset32`) el ile incelendi: bug, tnum'un düşük-32'sini
**{0}'a kırpıyordu** oysa u32 compare'leri `[0x200,0x400]`'e daraltmıştı → iki bağımsız tracker
(tnum vs u32) **ayrışıyor (DESYNC)**, "tutarlı-ama-yanlış" değil. Bu ayrışma diff.rs'teki
invariant B'nin tam tanımı: "tnum düşük-32 span'i `[u32_min,u32_max]` ile kesişmeli". Buggy
state'te tnum32=[0,0], u32=[512,1024] → disjoint → **B fire eder** (el ile doğrulandı). Yani
T1-1b yeni oracle kolu değil, B'yi CVE-şekilli state'lere sürecek bir aile.

### 1. Probe teyidi (--probe-t1b) — B çalışıyor + susuyor
Tam aileden önce 2 hand-built program (fix commit'in kendi reprodüseri + `<<32|load` shift
konstrüksiyonu) VM'de koştu, pipeline ile ölçüldü:
- **probe#cve8835**: accept, **reg32_checked=2**, finding_count=0.
- **probe#shift**: accept, **reg32_checked=3**, finding_count=0.
İkisi de reg32>0 (B bu state'lerde çalışıyor → regresyon yakalanırdı) ve finding_count=0 (bu
düzeltilmiş kernelde B susuyor → false-positive üretmiyor). İstenen sonuç aynen.

### 2. B, çok-blok rejiminde TEK nöbetçi (C yapısal olarak kapalı)
Kritik nokta: invariant C (`reg32_reg64_inconsistent`) **tek-2³²-blok** ile gated
(`umin>>32 == umax>>32`); CVE konstrüksiyonu 64-bit aralığı **birden çok bloğa** yayıyor
(ör. `[0x2000000200, 0x3f00000400]` → 0x20 ≠ 0x3f), bu yüzden C bu state'lerde **atlanıyor**.
Geriye 32-görünümü izleyen tek invariant olarak **B kalıyor** — CVE-2020-8835'in tarihsel
olarak sadece tnum-vs-u32 redundancy'siyle yakalanabilir olmasının sebebi tam bu (5.7 öncesi
ayrı u32 bounds yoktu → yakalanamazdı). Ölçüm bunu doğruluyor: ailedeki **56 checkable
scalar-state'in 56'sı da çok-bloklu** (%100) — aile, B'nin saf bir izolasyonu.

### 3. Çıktı — bpf-next VM (kernel 5e289c5a), 2026-09-04
`--gen-sync` = cve{pair(4)×win(4)}=16 + shift{win(4)×pol(2)}=8 → **24 program**. SYNC_WIN[0]
= `[0x200,0x400]` tarihsel CVE penceresi.
- **24 kabul / 0 red.** Programlar önemsiz-güvenli (daraltma sonrası `MOV r0,0; EXIT`) —
  yüzey karar değil, daraltmanın **bıraktığı register state**'i.
- **reg32_checked = 56** (cve=32, shift=24) — B tüm sync state'lerinde koştu → CVE-2020-8835
  regresyonu fire ederdi. **finding_count = 0** — B sustu → 32↔64 görünümler tutarlı: çalışan
  nöbetçi, false-positive yok. **56/56 çok-bloklu** (C kapalı, B tek başına). **0 divergence,
  0 parser kör-noktası.**

### 4. İmza ve sınır
T1-1b'nin imzası accept/reject dengesi DEĞİL (0034'te öngörüldüğü gibi, hepsi accept):
**reg32_checked>0 + finding_count=0 + boş-olmayan çok-blok altkümesi.** Kanıtladığı: "mevcut
invariant B, CVE-2020-8835 sınıfı 32↔64 desync'i için çalışan bir regresyon nöbetçisi, hem de
invariant C'nin yardım edemediği çok-blok rejiminde." **Sınır — dikkat:** consistency oracle'ı
DESYNC yakalar (iki görünüm bağımsız kodla tutulur, birindeki bug diğeriyle uyuşmazlıktan
görünür); "tutarlı-ama-yanlış" (iki görünüm de AYNI şekilde bozulur) yakalanmaz — o, ertelenen
(b) diferansiyel-recompute bölgesi. CVE-2020-8835 bir desync'ti, bu yüzden B'nin kapsamında.
Pinlendi: `crates/pipeline/tests/sync_calibration.rs` (6 test). Tam suite 145 yeşil.

### 5. Sıradaki
T1-1 (T1-1a soundness + T1-1b desync-nöbetçisi) kapandı. Açık uçlar: (a) daha geniş map-value
store'lar (2/4/8B) + EINVAL alt-ailesi (T1-1a'dan devreden); (b) "tutarlı-ama-yanlış" için
diferansiyel-recompute oracle'ı (consistency'nin yapısal kör noktası — ayrı, büyük iş);
gerçek *looping* (back-edge) hâlâ açık. Öncelik sırası COVERAGE-MAP.md'de.

## 0036 — Runtime yer-gerçeği oracle'ı (`--gen-rt`): verifier log'una güvenmeyen ilk dedektör

- **Tarih:** 2026-09-04
- **Durum:** Yeni oracle, ilk artış (input ailesi değil — **oracle değişikliği**). Stratejik
  dönüş: 0025–0035 arası tüm aileler aynı iç-tutarlılık oracle'ına (Ω) dayanıyordu; daha
  fazla input eklemek bug *bulmak* için azalan getiri, çünkü Ω yapısal olarak
  "consistent-but-wrong"u kaçırıyor. Bu oracle o kör noktadan kaçan ilki.
- **Alan:** `harness/diffharness.c` (`--gen-rt`, `run_rt_one`, `run_rt_prog`,
  `run_generated_rt_family`, `rt_map_set` — `BPF_PROG_TEST_RUN` + `BPF_MAP_UPDATE_ELEM`),
  `crates/metrics/src/core.rs` (`RuntimeSample` + `CoreMetrics.runtime_samples`, serde-skip),
  `crates/pipeline/src/verifier_log.rs` (`parse_runtime_samples`, RUNTIME satırı ayrıştırma),
  `crates/pipeline/src/diff.rs` (`check_runtime_ground_truth`, `runtime_checked`,
  `runtime_bound_violation`), `crates/pipeline/tests/runtime_calibration.rs` (yeni, 6 test,
  +fixture `gen-rt-37.log`), `crates/pipeline/tests/measure_log.rs` (+runtime_checked satırı),
  `scripts/run-rt.sh`, `docs/COVERAGE-MAP.md` (§2b), `docs/OPEN-ITEMS.md` (OI-9).
- **İlgili:** 0035 (T1-1b BOUND = consistent-but-wrong), CVE-2021-3490 (32-bit bounds),
  OI-9, OI-11 (`test_run` high-repeat → RCU-stall; bu yüzden repeat=1), [[oracle-times-input]].

### 0. Neden — Ω'nun yapısal kör noktası
Ω (iç tutarlılık) verifier'ın bastırdığı görünümlerin **birbiriyle** çelişip çelişmediğine
bakar. İki görünüm **aynı şekilde** bozulursa uyumlu kalır, hiçbir Ω-invariant'ı ateşlemez.
Tarihsel bug'ların çoğu (CVE-2021-3490 = 32-bit bounds güncelleme hatası) bu sınıfta. Reviewer
kuralı ([[oracle-times-input]]): input açken oracle'ı büyütme — ama artık input değil oracle aç.

### 1. Ω_rt — daha güçlü önerme, yer-gerçeğiyle
> **Ω_rt:** verifier bir programı kabul edip dönüş register'ı için `[lo,hi]` kanıtladıysa,
> programın **gerçek çalışma-zamanı** dönüş değeri de `[lo,hi]` içindedir.

Mekanizma: program tam-attacker-kontrollü 32-bit input'u (userspace'ten `BPF_MAP_UPDATE_ELEM`
ile set edilen map değeri) okur, verifier-izlenen bir ALU/compare şekli uygular, sınırlanmış
değeri döndürür. Harness `BPF_PROG_TEST_RUN` ile 12-değerli bir input süpürmesi üzerinde
**fiilen çalıştırır**, gerçek `retval`'ı kaydeder (`RUNTIME input=.. retval=..` satırı).
Pipeline retval'ı r0'ın kanıtlanmış scalar sınırıyla karşılaştırır. Bu, verifier log'unun
**kendi-tutarlılığına hiç güvenmez** — yer gerçeğidir.

### 2. Sağlamlık — union + ≤32-bit guard (yanlış-pozitif yok)
İki incelik, ikisi de "safe direction = under-claim":
- **Referans sınır = r0'ın tüm scalar state'lerinin BİRLEŞİMİ.** Null-check yolu 0 döndürür
  (r0 ∈ [0,0]); "en yüksek insn" seçmek onu alıp retval=1'i yanlış-pozitif yapardı. Birleşim
  = exit-başına sınırın muhafazakâr üst-kümesi → geniş birleşim ihlali **kaçırabilir** ama
  asla **uydurmaz**. (Bizim programlarda r0 yalnız iki exit'te scalar → birleşim tam.)
- **retval düşük-32 bit.** 64-bit sınır yalnız `umax < 2³²` iken kontrol edilir (aksi halde
  atlanır, tahmin edilmez); u32-görünüm kolu her zaman geçerli. v1'de tüm şekiller ≤32-bit.

### 3. Çıktı — bpf-next VM (kernel 5e289c5a), 2026-09-04
`--gen-rt` = 37 program (and 6 + andadd 9 + andlsh 9 + cmp 4 + alu32 9; alu32 =
CVE-2021-3490 lezzeti, 32-bit bounds yolu), her biri 12-değerli süpürme.
- **37 kabul / 0 red. runtime_checked = 444** (37×12 gerçek çalıştırma, her biri verifier'ın
  kendi kanıtladığı sınırla kontrol edildi). **finding_count = 0** — hiçbir gerçek retval
  sınırını aşmadı. **0 parser kör noktası.** map/testrun hata satırı = 0.

### 4. Oracle dişli mi — planlı-kaçış + sınır testi
"0 bulgu"nun anlamı, ancak oracle bir bug'a ateşleyebiliyorsa vardır. İki negatif kontrol
pinlendi: (a) **diş** — `and#000`'ın ([0,1]) bir retval'ı 0xdead0000'e bozulunca **tam bir
kez** `runtime_bound_violation` ateşliyor; (b) **off-by-one sağlam** — retval==umax (=1)
ateşlemiyor, umax+1 (=2) ateşliyor. Yani `>` doğru operatör, sınır dahil, oracle boş değil.

### 5. Sınır ve v2
Ω_rt yalnız dönüş-değeri kanalından (retval, 32-bit) gözlemlenebilen bug'ları görür. Bu,
ertelenen (b) diferansiyel-recompute'a **farklı** bir saldırı: recompute sınırı soyut
yeniden-türetir (ikinci bir implementasyon riski), runtime gerçek değeri gözler (ikinci
implementasyon gerekmez ama sadece kanalın gösterdiğini görür). v2 yönleri: daha geniş
gözlem kanalları (map/packet write, 64-bit değerler), pointer-erişim OOB'sinin runtime
tespiti, ve döngü/iterator input'ları. Pinlendi: `runtime_calibration.rs` (6 test). Tam
suite 151 yeşil.

## 0037 — Runtime bellek-güvenliği oracle'ı (map-value store, `--gen-rtw`): OOB-write yer-gerçeği

- **Tarih:** 2026-09-04
- **Durum:** v2 — runtime oracle'ının (0036) skaler dönüş-değerinden **bellek-güvenliği**
  eksenine ilk genişlemesi. Asıl av yüzeyinin (pointer OOB) ilk ayağı.
- **Alan:** `harness/diffharness.c` (`--gen-rtw`, `run_rtw_one`/`run_rtw_prog`/
  `run_generated_rtw_family`, `rt_map_set_bytes`, `rt_map_get` — iki map + sentinel
  yaz/geri-oku), `crates/metrics/src/core.rs` (`RuntimeSample.store_off`, serde-skip),
  `crates/pipeline/src/verifier_log.rs` (`store_off` ayrıştırma), `crates/pipeline/src/
  diff.rs` (`check_runtime_write_safety`, `runtime_writes_checked`, `runtime_oob_write`;
  retval oracle'ına store-sample guard'ı), `crates/pipeline/tests/runtime_write_
  calibration.rs` (yeni, 5 test, +fixture `gen-rtw-9.log`), `crates/pipeline/tests/
  measure_log.rs`, `scripts/run-rtw.sh`, `docs/COVERAGE-MAP.md`, `docs/OPEN-ITEMS.md`.
- **İlgili:** 0036 (retval oracle, Ω_rt), 0030 (`--gen-ptr` — aynı statik accept/reject
  yüzeyi), OI-9, T2-2 (store genişliği), [[oracle-times-input]].

### 0. Neden — retval kanalı bellek güvenliğini görmüyor
0036'nın kanalı dönüş skaleri; ama asıl sömürülebilir verifier bug'ları "verifier bu
bellek erişimini güvenli saydı, runtime'da değildi" tipinde. Bu oracle onu doğrudan
ölçüyor: program bir sentinel yazıyor, biz nereye düştüğüne bakıyoruz.

### 1. Mekanizma — sentinel yaz + geri oku (bound parse YOK)
İki map: `map_in` (attacker input), `map_out` (yazma hedefi, value_size=64). Program
input'tan bir offset üretir (`r6 &= MASK [+ C]`, verifier'ın in-bounds kanıtladığı),
`*(u8*)(map_out + off) = 0xFF` yazar. Harness her koşuda: map_out'u sıfırlar,
`BPF_PROG_TEST_RUN`, map_out'u geri okur, 0xFF'i arar → `store_off`. Kabul edilen bir
store **iddiaen** in-bounds; sağlam kernelde sentinel **daima** value içine düşmeli.
`store_off=none` (sentinel yok) = store okunabilir value'nun dışına, kernel belleğine
gitti = verifier'ın kabul ettiği bir OOB-write. **Bound parse etmeye gerek yok** —
doğrudan bellek-güvenliği özelliği.

### 2. Çıktı — bpf-next VM (kernel 5e289c5a), 2026-09-04
`--gen-rtw` = 9 program (and 4 + andadd 3 in-bounds ACCEPT + over 2 REJECT kontrol).
- **7 kabul / 2 red.** 2 red = over-wide maske (off≤127 > value_size-1); verifier'ın
  statik in-bounds kontrolü çiziyor (EACCES). **runtime_writes_checked = 84** (7×12
  gerçek store, her biri düştüğü yer için kontrol edildi). **finding_count = 0** — her
  kabul edilen store value içine düştü (`store_off = input & MASK [+ C]`, hep [0,63]).
  **0 store_off=none, 0 parser kör noktası.**

### 3. Diş + reject kontrolü
"0 bulgu" ancak oracle bir OOB'ye ateşleyebiliyorsa anlamlı: planlı bir `store_off=none`
örneği tam bir kez `runtime_oob_write` ateşliyor. Ve reject kontrolü: over-wide programlar
load-time'da reddediliyor → hiç koşmuyor → hiç kontrol edilmiyor (verifier'ın statik
çizgisi doğru yerde). Pinlendi: `runtime_write_calibration.rs` (5 test).

### 4. Sınır ve sıradaki
v1-store 1-byte + map_value. Sıradaki eksenler: store genişliği 2/4/8B (T2-2 —
`off+size ≤ value_size` off-by-one'ı tam burada), packet write (SCHED_CLS, farklı sınır
mantığı), ve store_off'u verifier'ın kanıtladığı pointer-offset bound'uyla karşılaştırma
(sadece "value içinde mi" değil, "verifier'ın dediği yerde mi" — pointer-tracking desync).
Sonra döngü/iterator input'ları. Tam suite 156 yeşil.

## 0038 — Çok-baytlı store genişliği (map-value, `--gen-rtw2`): T2-2, `off+size ≤ value_size` off-by-one'ı

- **Tarih:** 2026-09-04
- **Durum:** 0037'nin (tek-bayt sentinel) **genişlik** eksenine genişlemesi. Ölçülen
  eksen artık store WIDTH — gerçek bir verifier bug'ının vuracağı off-by-one tam
  `off + size ≤ value_size` kontrolünde yaşıyor.
- **Alan:** `harness/diffharness.c` (`--gen-rtw2`, `run_rtw2_one`/`run_rtw2_prog`/
  `run_generated_rtw2_family`, `rtw2_size_code`), `crates/metrics/src/core.rs`
  (`RuntimeSample.store_len` + `.store_size`, serde-skip), `crates/pipeline/src/
  verifier_log.rs` (`store_len`/`store_size` ayrıştırma), `crates/pipeline/src/diff.rs`
  (`check_runtime_write_safety`: `store_len==store_size` full-run predikatı, `map_or(true)`
  geriye-uyum), `crates/pipeline/tests/runtime_write2_calibration.rs` (yeni, 7 test,
  +fixture `gen-rtw2-20.log`), `scripts/run-rtw2.sh`, `docs/COVERAGE-MAP.md`,
  `docs/OPEN-ITEMS.md`.
- **İlgili:** 0037 (`--gen-rtw`, tek-bayt), 0036 (retval oracle), OI-9,
  [[oracle-times-input]].

### 0. Neden — tek bayt off-by-one'ı ifade edemez
0037'nin sentinel'i 1 bayt: `store_off=none` ya var ya yok. Ama asıl av yüzeyi
`off+size ≤ value_size`: base offset in-bounds olsa bile N-baytlık bir store value
sonunu bir bayt aşabilir. Bunu görmek için store WIDTH'i değişken yapmak ve **tüm**
sentinel baytlarının içeri düştüğünü ölçmek gerekiyor.

### 1. Mekanizma — N-bayt sentinel + ardışık-run sayımı
Store artık `BPF_ST_MEM(size_code, r7, off, imm=-1)` → `size` bayt 0xFF (DW için imm
64-bit'e sign-extend → 8 bayt). Harness her koşuda map_out'u **koşu-öncesi** sıfırlar
(tek 0xFF kaynağı bu store olduğundan önceki süpürme adımından kalan bir sentinel asla
yanlış sayılamaz — reviewer'ın sentinel-tuzağı sorusuna cevap bu koşu-başı re-zero),
sonra İLK 0xFF'i (`store_off`) bulur ve ardışık 0xFF run'ını sayar (`store_len`),
`store_size` ile birlikte yazar. Predikat: kabul edilen store bellek-güvenli ⟺
`off≥0 VE store_len==store_size`. Kısa run (`store_len<store_size`) = **kısmi OOB**
(bazı baytlar sınırı aştı). `map_or(true)` eski 1-byte fixture'ı (size yok) varlıkla
geçirir — geriye-uyumlu.

### 2. İki şekil — attacker offset + tam off-by-one kontrolü
- **and.wN:** `r6 &= MASK`, store size N at `map_out+r6`. Kabul ⟺ MASK+N ≤ 64.
  Maskeler {0x7,0x1f,0x3f} × N{1,2,4,8} = 12 program: 0x7/0x1f her N kabul; 0x3f N=1
  kabul (63+1=64), N≥2 red (65/67/71 > 64).
- **bndc.wN:** const offset ST insn'in off alanında. off=64−N tam value sonunda biter
  (KABUL); off=65−N bir bayt aşar (RED) — kesin off-by-one. N{1,2,4,8}×2 = 8 program.

### 3. Çıktı — bpf-next VM (kernel 5e289c5a), 2026-09-04
20 program, **13 kabul / 7 red** (3 and-taşma + 4 bndc-red). **runtime_writes_checked =
156** (13×12), **finding_count = 0** — her kabul edilen store TAM genişliğini içeri
yazdı. En sıkı sınır bndc.w8#018: base off=56, 8 bayt tam 64'te bitiyor, her örnek
`store_off=56 store_len=8 store_size=8`. **0 store_off=none, 0 parser kör noktası.**

### 4. Diş (iki kez) + reject kontrolü
Non-vacuity iki yoldan: (a) planlı `store_off=none` (0037'den miras) ve (b) **T2-2'ye
özgü** planlı kısa run (`store_len=5 store_size=8`) — her ikisi de tam bir kez
`runtime_oob_write` ateşliyor; ikincisi tek-bayt oracle'ının hiç ifade edemediği
kısmi-OOB. Reject kontrolü: genişlik-taşmaları load-time'da reddediliyor → hiç koşmuyor
→ hiç kontrol edilmiyor; bndc çiftleri (off=64−N kabul / off=65−N red) off-by-one'ı
ikiye bölüyor. Pinlendi: `runtime_write2_calibration.rs` (7 test).

### 5. Sınır ve sıradaki
Store hâlâ map_value; offset bilgisi "value içinde mi TAM olarak" düzeyinde — henüz
verifier'ın kanıtladığı pointer-offset bound'uyla karşılaştırılmıyor. Sıradaki: packet
write (SCHED_CLS), `store_off`'u verifier'ın pointer-offset bound'uyla karşılaştırma
(pointer-tracking desync, "içeride mi" değil "dediği yerde mi"), sonra döngü/iterator
input'ları. Tam suite 163 yeşil.

## 0039 — Packet-write runtime bellek-güvenliği oracle'ı (`--gen-pktw`): T3, PTR_TO_PACKET store yer-gerçeği

- **Tarih:** 2026-09-04
- **Durum:** TAMAM. Kod bir önceki oturumda yazıldı (build/VM adımları oturum-ortası
  araç-erişim düşüşüyle bloklanmıştı — checkpoint'teki "TOOL-DROP"); capture bu taze
  oturumda alındı, sayılar ÖNCEDEN türetilen tahminle bire bir tuttu, calibration testi
  aktive edildi (`.rs.pending` → `.rs`), fixture pinlendi.
- **Alan:** `harness/diffharness.c` (`--gen-pktw`, `run_pktw_one`/`run_pktw_prog`/
  `run_generated_pktw_family`, `PKTW_M`), `scripts/run-pktw.sh` (yeni),
  `crates/pipeline/tests/packet_write_calibration.rs` (yeni, 7 test),
  `crates/pipeline/tests/fixtures/volume/gen-pktw-12.log` (yeni, gerçek VM capture),
  `docs/COVERAGE-MAP.md` (§2b.3), `docs/OPEN-ITEMS.md`.
  **Pipeline (parser/diff/metrics) DEĞİŞMEDİ** — çıktı formatı 0038 ile bayt-özdeş.
- **İlgili:** 0038 (`--gen-rtw2`, map-value store-genişlik), 0037 (`--gen-rtw`),
  0031 (`--gen-pkt`, load-only packet pointer), 0032 (`--gen-pkt-cmp`, range makinesi
  compare taraması), [[store-location-desync-is-the-hunt]], [[oracle-times-input]].

### 0. Neden — packet, oracle'ın asıl av yüzeyinin ikinci yarısı
0037/0038 map_value pointer'ından geçiyor; sınırı verifier statik BİLİYOR (value_size).
Packet pointer öteki tür: verifier packet'in nerede bittiğini BİLMEZ — PROGRAM kendi
`data + M > data_end` compare'i ile ispatlar, verifier ortaya çıkan `range`'i statik
TAKİP eder (`find_good_pkt_pointers`, verifier.c). Bu range makinesi tarihsel olarak en
yoğun packet-bounds bug bölgesi. Load-only packet aileleri (`--gen-pkt`/`--gen-pkt-cmp`)
yalnızca accept/reject'i ve verifier'ın KENDİ iç-tutarlılığını görebiliyor — store'un
gerçekte NEREYE düştüğünü asla göremiyor. Bu leg accepted programı `BPF_PROG_TEST_RUN`
ile KOŞUYOR ve packet'i geri okuyor, böylece iç-tutarlı ama YANLIŞ bir range'i yakalıyor
(her log-only kolun paylaştığı kör nokta — "consistent-but-wrong").

### 1. Mekanizma — runtime packet boyutu tam M, byte M = data_end
Şekil (SCHED_CLS — socket_filter direct packet erişimini yasaklar):
`r2=data; r3=data_end; r5=r2; r5+=M; if (r5 > r3) skip; *(uW*)(r2 + off) = -1`. Runtime
packet uzunluğu TAM M'e ayarlanıyor (`data_size_in = PKTW_M = 32`, ≥ ETH_HLEN=14), böylece
data_end byte M'e düşüyor ve compare `data+M > data_end` yanlış (M ≤ M) → accepted store
KOŞUYOR. `bpf_prog_test_run_skb` skb'yi taze kurar (data_in sıfır → tek 0xFF kaynağı
store), koştuktan sonra yalnız `[0, skb->len)`'i data_out'a kopyalar — byte M skb
tailroom'da (kopyalanmaz). Harness data_out'ta İLK 0xFF'i (`store_off`) bulur, ardışık
run'ı sayar (`store_len`), `store_size` ile yazar — çıktı 0038 ile bayt-özdeş, o yüzden
parser/diff/metrics DEĞİŞMEDEN yeniden kullanılıyor.

Sağlam kernel: her accepted store `off + W ≤ M`, tüm W sentinel byte'ı `[0, M)`'e düşer,
data_out'ta geri gelir (`store_len == store_size`). `off + W = M + 1` kabul eden bir
verifier (range off-by-one) store'un son byte'ını data_end'e (tailroom) koyar → run
kısalır (`store_len < store_size`) ya da yok olur (`store_off=none`) → paylaşılan
predikat (`check_runtime_write_safety`) tam da bunu ateşler.

### 2. Neden compare-korumalı DEĞİL — dişin yaşadığı yer
Kritik tasarım kararı: store'u koruyan runtime branch, store bölgesini TAM yeniden
kontrol EDERSE (offset değişken, compare `data+off+W > data_end`), runtime kendi kendini
korur ve buggy bir verifier bile runtime OOB üretemez — branch off+W ≤ len'i runtime'da
yeniden doğrular. O yüzden böyle bir şekil TAUTOLOJİ (asla ateşlemeyen bir payda), oracle
× input kuralının dışladığı şey. Diş yalnız compare'in ispatladığından DAHA İLERİYE ulaşan
store'dan gelir: compare M byte ispatlar, store `off+W`'ye ulaşır, `off+W ≤ M` kararının
TEK hakemi verifier'dır. Bu tam `--gen-pkt-cmp`'in dişi — ama koşturulmuş hâli. Bu yüzden
offset SABİT (değişken r4 yok), packet boyutu M'e sabitlenip byte M tam data_end'e
oturtuluyor.

### 3. Aile — kapalı `>` idiom, W{1,2,4,8} × 3 kol
12 program. Her W için üç kol: off 0 iç-kabul, off=M−W sınır-kabul (byte M-1'de tam biter,
en sıkı in-bounds store), off=M−W+1 off-by-one (son byte data_end'de olur → RED).
**ÖLÇÜLEN (koşumdan ÖNCE predikattan türetilmiş tahminle bire bir aynı): 8 kabul /
4 red, runtime_writes_checked = 8** (her kabul 1 kez koşar, input = packet boyutu 0x20),
**finding_count = 0, parser_unrecognized = 0.** Kabul sınırı her genişlikte tam
`off = M−W`: w1 o31 kabul / o32 red, w2 o30/o31, w4 o28/o29, w8 o24/o25 — yani red nedeni
her seferinde tek byte'lık aşım. Her kabul edilen store TAM genişliğini in-bounds yazdı;
en sıkısı w8.o24 (8 byte'lık run tam byte 32 = data_end'de biter). Sınır başka bir yere
düşseydi bu, "capture hatası" değil, İLK ÖNCE incelenecek potansiyel bulgu olurdu. BPF_ST (store-immediate) → PTR_TO_PACKET kabul EDİLİR: do_check_insn
BPF_ST kolu `check_mem_access(BPF_WRITE)`'a gider, packet-özel blok yok
(atomic_ptr_type_ok packet'i yalnız ATOMIC için bloklar); `--gen-pkt` zaten STX packet
write'ı kabul ettiriyor. Reject nedeni check_packet_access -EACCES "invalid access to
packet". İlk increment kapalı `>`'ye sabit; operatör taraması (`>=` right-open, operand-
sırası simetrisi) doğal takip — tıpkı `--gen-pkt` → `--gen-pkt-cmp` gibi (OI-9'a eklendi).

### 4. Diş + reject kontrolü — GERÇEK capture üzerinde doğrulandı
Diff predikatı 0037/0038'den paylaşıldığı için diş zaten `runtime_write2_calibration`'da
kanıtlıydı; yine de non-vacuity bu ailenin KENDİ gerçek capture'ı üzerinde ayrıca
sınandı: planlı `store_off=none` (w1.o0#000) ve planlı kısa run
(`store_len=5 store_size=8`, en sıkı sınır w8.o24#010) — her biri tam bir kez
`runtime_oob_write` ateşliyor (pipeline üzerinden ayrıca elle de doğrulandı:
w8.o24 satırı `store_off=none` ve `store_len=7` varyantlarıyla mutasyona uğratıldığında
`finding_count` 0 → 1). Reject kontrolü: off-by-one programları
load-time'da reddedilir → koşmaz → kontrol edilmez; W başına (off=M−W kabul / off=M−W+1
red) çift off-by-one'ı ikiye böler.

### 5. Sınır ve sıradaki
Store artık packet, ama `store_off` hâlâ yalnız "packet İÇİNDE mi TAM olarak"
düzeyinde ölçülüyor — henüz verifier'ın PROVED pointer-offset bound'uyla
karşılaştırılmıyor. Asıl av (store-location desync — "içeride mi" değil "DEDİĞİ yerde mi",
[[store-location-desync-is-the-hunt]]) bir sonraki merkezi hamle. Bu leg onun packet
altyapısını (SCHED_CLS test_run + data_out geri-okuma) kuruyor. Sonra: compare-form
taraması, sonra döngü/iterator input'ları.

Tam suite 170 yeşil (163 + bu ailenin 7 testi).

## 0040 — Packet gözlem-kanalı ölçümü (`--probe-pktw`): iddia → ölçüm, desync'in ön-koşulu

- **Tarih:** 2026-09-04
- **Durum:** TAMAM. Ölçüm alındı, dört iddianın dördü de doğrulandı, pinlendi.
- **Alan:** `harness/diffharness.c` (`--probe-pktw`, `run_pktw_probe_one`/
  `run_pktw_probe_prog`/`run_probe_pktw_family`), `scripts/probe-pktw.sh` (yeni),
  `crates/pipeline/tests/packet_channel_calibration.rs` (yeni, 7 test),
  `crates/pipeline/tests/fixtures/volume/probe-pktw-4.log` (yeni, gerçek VM capture).
  **Pipeline DEĞİŞMEDİ** — probe çıktısı ayrı bir `CHANNEL` satırı, parser'a girmiyor.
- **İlgili:** 0039 (`--gen-pktw`), [[store-location-desync-is-the-hunt]].

### 0. Neden — 0039'un tek okumaya-dayalı halkası
0039 "sentinel yok / kısa" durumunu OOB write olarak OKUYOR. Bu okuma kanal hakkında bir
İDDİAYA dayanıyordu: `bpf_prog_test_run_skb` yalnız `[0, skb->len)`'i geri kopyalar, yani
`data_end`'i aşan store skb tailroom'a düşer ve dönmez. İddia kernel kaynağı OKUNARAK
kuruldu, GÖZLENEREK değil — sağlam verifier her OOB store'u REDDETTİĞİ için 0039 kanalın
yalnız POZİTİF yarısını (paket içindeki byte geri gelir) çalıştırdı; negatif yarı
("yazılmış ama pencere dışındaki byte GERÇEKTEN görünmez") hiç ölçülmedi. Sıradaki leg
(store-location desync) "verifier X dedi, store Y'ye düştü" diyecek; o "Y'ye düştü"ye
güvenmek için kanalın byte-hassas çözdüğünü ÖLÇMÜŞ olmak gerekiyor — yoksa bir desync
bulgusu pekâlâ bir kanal artefaktı olabilir.

### 1. Mekanizma — store'u değil PENCEREYİ oynat
Buggy verifier olmadan OOB geometrisini üretmenin yolu: store'u dışarı taşımak yerine
pencereyi içeri çekmek. `bpf_skb_change_tail()` store KOŞTUKTAN SONRA `skb->len`'i
küçültüyor, böylece paket tamponuna FİİLEN yazılmış bir byte dönen uzunluğun dışında
kalıyor — tam olarak bir OOB store'un geometrisi, ama yalnız KABUL EDİLMİŞ programlarla.
Probe her koşumdan sonra kernel'in attr'a geri yazdığı gerçek `data_size_out`'u okuyor.

### 2. Ölçüm (4 kol, hepsi kabul, `retval=0` → change_tail başarılı)
| kol | in | store | trim | out_size | store_off | tail_zero |
|---|---|---|---|---|---|---|
| `win32` | 32 | 31 | — | **32** | 31 | 1 |
| `win40` | 40 | 31 | — | **40** | 31 | 1 |
| `trim.o19` | 32 | 19 | 20 | **20** | **19** | 1 |
| `trim.o20` | 32 | 20 | 20 | **20** | **none** | 1 |

Okunuşu: (a) pencere TAM paket (`out_size == skb->len`), (b) pencere sabit değil,
`skb->len`'i TAKİP ediyor (32→40), (c) pencerenin SON byte'ı çözülüyor (o19 görünür),
(d) **negatif yarı**: `index == out_size`'a fiilen yazılmış byte dönmüyor (o20 = `none`).
o19 ile o20 arasındaki TEK fark bir byte'lık store offset'i — aynı şekil, aynı shrink —
ve gözlenebilirlik zıt: kenar **byte-hassas**, ve "yok" konumsal, change_tail'in veriyi
bozmasının artefaktı değil. `tail_zero=1` her kolda aynı iddianın öteki yönü: önceden
sıfırlanmış çıkış tamponu `out_size`'ın ötesinde sıfır kalıyor, yani oradaki bir byte
yanlışlıkla sentinel olarak da OKUNAMAZ.

### 3. Sonuç
0039'un "yok ⟹ OOB" okuması artık argüman değil ÖLÇÜM: yazılmış-ama-pencere-dışı byte
gerçekten görünmez, pencere içindeki son byte gerçekten görünür, ve ikisi arasındaki
sınır tam bir byte. Store-location desync ailesinin ön-koşulu karşılandı — "store Y'ye
düştü" artık ölçülmüş bir kanal üzerinden söylenebilir. Tam suite 177 yeşil.

## 0041 — Store-location desync (`--gen-loc`): "içeride mi" değil "DEDİĞİ yerde mi" — asıl av

- **Tarih:** 2026-09-04
- **Durum:** Kod + pipeline YAZILDI, **VM CAPTURE BEKLİYOR.** Oturum-ortası araç-erişim
  düşüşü (checkpoint'teki "TOOL-DROP") build/VM adımlarını bloklandı; bu kez yalnız
  Bash exec değil Bash mutasyonu da kesildi (Read/Edit/Write çalıştı, read-only Bash
  çalıştı). Pipeline değişiklikleri blok ÖNCESİ temiz derlendi. Aktivasyon (taze /
  default-mode oturum): `scripts/run-loc.sh` → capture'ı
  `crates/pipeline/tests/fixtures/volume/gen-loc-15.log`'a kopyala →
  `mv store_location_calibration.rs.pending .rs` → `cargo test -p pipeline`.
- **Alan:** `harness/diffharness.c` (`--gen-loc`, `run_loc_one`/`run_loc_prog`/
  `run_generated_loc_family`, 15 şekil), `scripts/run-loc.sh` (yeni),
  `crates/metrics/src/core.rs` (`RegState.ptr_off`, yeni `StoreSite`,
  `CoreMetrics.store_site`), `crates/pipeline/src/verifier_log.rs` (pointer register
  artık bounds/var_off/off SAKLIYOR; `parse_store_site`, `parse_ptr_const_off`),
  `crates/pipeline/src/diff.rs` (`check_store_location`, `store_locations_checked`),
  `crates/pipeline/tests/measure_log.rs`,
  `crates/pipeline/tests/store_location_calibration.rs.pending` (yeni, 7 test).
- **İlgili:** 0037/0038/0039 (runtime write legs), 0040 (kanal ölçümü — ön-koşul),
  [[store-location-desync-is-the-hunt]], [[oracle-times-input]].

### 0. Neden — her önceki bacağın paylaştığı kör nokta
0037/0038/0039 TEK bir soru soruyor: store nesnenin İÇİNDE mi kaldı? Bir verifier bunu
geçip yine de yanlış olabilir: offset için soyut aritmetiği sağlam değilse, store kendi
durumunun İMKÂNSIZ dediği bir offset'e düşer — ve hâlâ nesnenin içinde kalır, dolayısıyla
önceki her bacak SESSİZ kalır. Bu "consistent-but-wrong" sınıfı: verifier'ın iki görüşü
birbiriyle uyumlu, yalnız GERÇEKLİKLE uyumsuz — bir iç-tutarlılık oracle'ının yapısı
gereği göremeyeceği şey (CVE-2021-3490 sınıfı).

### 1. Karşılaştırılan şey — verifier zaten kendi iddiasını basıyor
Store insn'inde verifier durumu yazdırıyor:
```
17: R7=map_value(ks=4,vs=64,smin=0,smax=umax=7,var_off=(0x0; 0x7))
17: (72) *(u8 *)(r7 +0) = -1
```
Yani "offset [0,7]'de, ve yalnız bitleri (0x0; 0x7)'ye uyan offset'lerde". Runtime
sentinel'in gerçekte nereye düştüğünü söylüyor. `check_store_location` ikisini
karşılaştırıyor:
```
kanıtlanmış pencere = ptr_off + insn_off + [umin, umax], var_off tnum'uyla daraltılmış
```
**tnum yarısı interval kadar önemli:** `r6 &= 3; r6 <<= 2` {0,4,8,12}'yi kanıtlar, yani
offset 6 [0,12]'nin İÇİNDE ve yine de imkânsız. Delikli kanıt kümesi = "dediği yer"in
tam anlamı.

**Parser'da bulunan boşluk:** `build_regstate` (c) kolu pointer register'ı tip-string'e
indirip bounds/var_off/off'u SIFIRLIYORDU — yani verifier'ın konum iddiası pipeline'a
hiç girmiyordu. Düzeltildi; pointer için "yok" = TAM SIFIR okunuyor (verifier bir
pointer'ın değişken parçası gerçekten sıfırken var_off basmaz), scalar kolu ise bunu
YAPMAMALI (orada "yok" = uçta demek — ters okuma). Ayrı bir tuzak: `find("off=")`
`var_off=(...)` içinde de eşleşiyor, o yüzden `parse_ptr_const_off` sınır-duyarlı.

### 2. Provenans — soruyu denetlenen bileşenden öğrenme
Store'un hangi insn olduğu ve hangi register'dan geçtiği GENERATOR'dan geliyor
(`STORE insn= reg= off= size=` satırı), verifier'ın kendi disassembly'sinden DEĞİL.
Harness programı kendisi kurdu; bunlar INPUT hakkında yer-gerçeği. Oracle'ın denetlediği
bileşenden soruyu öğrenmesi, aradığı hatayı görmezden gelmesine yol açardı.

### 3. Aile — eksen = soyut transfer fonksiyonu
15 program, her biri offset'i başka bir ALU zinciriyle şekillendiriyor (çünkü fazla-dar
= unsound bound tam oradan gelir): and7, and31, orand, addc, subc, lsh2, lsh3, rsh, mul,
xor, alu32 (32-bit op), **jmp** (maske değil BRANCH ile sınırlı — `reg_set_min_max`,
farklı kod yolu), shpair (`<<60` sonra `>>60`), compose (and/add/lsh zinciri), off4
(store kendi +4'ünü taşır → `ptr_off + insn_off + var` aritmetiğini karşılaştırmanın
İKİ tarafında da sınar). Hepsi 64-byte value'nun iyice içine düşüyor, yani KARAR burada
yüzey değil — 15'i de kabul bekleniyor ve yüzey nereye düştükleri.

Beklenen (türetilmiş, capture otorite): 15 program, 15 kabul / 0 red,
`store_locations_checked = 180` (15 × 12 sweep input), `finding_count = 0`.
**Capture bu türetmeyi 180 → 170'te düzeltti; nedeni aşağıda (§6).**
**`store_locations_checked` ayrı bir sayaç olmak zorunda:** `runtime_writes_checked`
yalnız "içeride mi" diye sorar; sıfır bulgu ancak KANIT okunmuşsa anlamlıdır — sayaç 0
ise kernel temiz değil, iddia okunamamış demektir.

### 4. Dişler — üçü de kritik
1. **Pencere dışı ama bellek-güvenli:** `orand` [8,15] kanıtlar; ekilen `store_off=3`
   map value'nun içinde (0037/0038 predikatı SESSİZ) ama kanıtın dışında → tam bir
   `store_location_desync`, **sıfır** `runtime_oob_write`. O sessizlik tam olarak bu
   bacağın kapatmak için var olduğu kör nokta.
2. **Pencere içi ama tnum-imkânsız:** `lsh2` {0,4,8,12} kanıtlar; ekilen `store_off=6`
   [0,12]'nin içinde, value'nun içinde, yine de imkânsız → ateşler ve "impossible under
   var_off" diye raporlanır (interval değil tnum ihlali olarak).
3. **insn_off iddianın parçası:** `off4` kolunda ekilen `store_off=0`, +4 tabanının
   altında → ateşler. Karşılaştırmanın iki tarafı da insn_off'u uygulamazsa bu ekim
   sessiz kalırdı.
Ayrıca **vakumsuzluk testi**: her programın kanıtlanmış penceresi DAR olmalı
(`umax-umin <= 56`) — nesne kadar geniş bir pencere bu bacağı vakum yapardı.

### 5. Bulgu çıkarsa
Buradaki bir bulgu ne otomatik kernel hatası ne otomatik bizim hatamız — bu çağın
üretmek için kurulduğu TEK çıktı. Sıra: (a) bulgunun alıntıladığı log satırından
kanıtlanmış pencereyi elle yeniden türet, (b) harness'in bildirdiği `STORE insn=`
gerçekten store mu diye bak, (c) ancak ondan sonra verifier bulgusu de.

### 6. Capture (2026-09-05) — türetme iki yerden düzeltildi, ikisi de bizim tarafımızdan

**Sonuç: 15 program, 15 kabul / 0 red, `store_locations_checked = 170`,
`runtime_writes_checked = 170`, `finding_count = 0`, `parser_unrecognized = 0`.**
Her kabul edilen store, verifier'ın kendi kanıtladığı kümenin içine düştü. Elle
türetme (log satırından pencereyi yeniden hesaplayıp runtime offset'leriyle
karşılaştırma) 15/15 arm'da bunu bağımsız olarak doğruladı, ve tnum yarısının vakum
olmadığını gösterdi: `lsh2` tam {0,4,8,12}'ye, `lsh3` {0,8,16,48,56}'ya, `compose`
{4,8,12,16}'ya düştü — aradaki hiçbir offset'e değil. `off4` kanıtı [4,11] olarak
okundu, yani `insn_off` karşılaştırmanın iki tarafında da uygulanıyor.

İlk capture bunu vermedi: **170 kontrol ve 10 `runtime_oob_write` bulgusu** döndü.
Protokol (a-b-c) uygulandı, elle türetme kernel'i temize çıkardı, ve hata bu oracle'da
bulundu. İki ayrı düzeltme çıktı — ikisi de "beklenen sayı tutmadı"dan değil, sayının
NEDEN tutmadığından geldi.

**(i) `store_off = none` iki anlamlıydı.** "Value içinde sentinel yok" demek, store'un
SINIR DIŞINA çıkması ile store'un HİÇ ÇALIŞMAMASI arasında ayrım yapmıyor. 0037/0038/
0039'un her ailesinde store koşulsuz çalışıyordu (maske tabanlı), dolayısıyla `none`
yalnız ilkini ifade edebilirdi — predikat bu söylenmemiş varsayımın üstüne yazılmıştı.
`jmp` arm'ı tam da onu kırıyor: offset'i BRANCH ile sınırlıyor (`if r6 > 7 goto exit`),
ve 12 sweep input'unun 10'u sınırın üstünde olduğu için store'a hiç ulaşmıyor.
Düzeltme belirsizliği **kaynakta** çözüyor, diff aşamasında tahmin ederek değil:
program store yolunda ayırt edici bir değer döndürüyor (`r0 = 1`, atlama yollarında 0),
harness bunu `executed=` olarak basıyor, ve store'a ulaşmamış bir koşu yargılanmıyor.
Dişler aynen duruyor — koşulsuz store'lu aileler tanık BASMIYOR (`executed = None`) ve
eski okuma değişmeden geçerli, `executed=1` + sentinel yok hâlâ OOB write. Yani 170
indirilmiş bir çıta değil, TÜREV bir sayı: 180 sweep koşusundan, store'a kanıtlanabilir
şekilde hiç ulaşmayan 10'u düşülmüş hâli. Ailenin `jmp` kolunun 12 input'un yalnız
2'sinde store etmesi input sweep'inin doğal sonucu (RT_INPUTS'un küçük değerleri
0 ve 1); sweep'i bu arm için genişletmek diğer ailelerin sabitlenmiş sayılarını
bozacağı için yapılmadı — branch kod yolu 2 örnekle de sınanıyor.

**(ii) Pointer bound'larında yokluk kuralı yanlıştı.** 0041'in parser düzeltmesi
`build_regstate` (c) kolunda "yokluk = TAM SIFIR" kuralını dört bound'a da uygulamıştı.
Bu kural yalnız `var_off` için doğru (verifier bir pointer'ın değişken parçası gerçekten
sabitse var_off basmaz; sabit parça ayrıca `off=` olarak basılır). Bound'lar için kural
TERSİ ve tipten bağımsız: kernel bir bound'u UÇ değerindeyse basmıyor (log.c).
`map_value(...,umin=0xfffffffffffffff0,var_off=(0xfffffffffffffff0; 0xf))` satırı
`umax`'ı U64_MAX olduğu için atlıyor; yokluğu 0 okumak ters bir unsigned aralık
uyduruyor ve `unsigned_bounds_inverted` invariant'ını tamamen tutarlı bir pointer
state'i üzerinde ateşliyordu. Bu, workspace suite'inde `pointer_neg_calibration`'ın
6 sahte bulgusu olarak yakalandı — [[parser-golden-fixture-guardrail]]'in tam olarak
var olma nedeni: parser hatası, bulgu kılığında. Pointer kolu artık scalar koluyla aynı
uç-değer kuralını kullanıyor; `check_store_location`'ın "kullanılabilir iddia" koruması
da aynı dile çevrildi (bilinmeyen bit var + üst sınır belirtilmemiş ⟹ pencere yok).
Bu düzeltme `--gen-loc` sayılarını değiştirmiyor (15 arm'ın hepsinde `umax` zaten
basılıydı), ama 0041 commit edilmeden ÖNCE yakalanması bu bacağın kendi kör noktasını
kapatıyor.

**Testler:** `store_location_calibration.rs` 9 test — üç orijinal diş (pencere dışı ama
bellek-güvenli → `runtime_oob_write` SESSİZ; pencere içi ama tnum-imkânsız; `insn_off`
iddianın parçası), vakumsuzluk guard'ı, artı iki yeni tanık testi: tanığın şekli
(yalnız `jmp` arm'ı atlıyor, ve atlayan bir koşu ASLA sentinel bırakmıyor — bıraksaydı
tanığın kendisi çelişik olurdu ve gerçek bir OOB'yi susturabilirdi) ve tanığın
AYIRT ETMESİ (aynı eksik sentinel, `executed=1` ile OOB olarak ateşliyor, `executed=0`
ile ateşlemiyor). Workspace 186 yeşil.

---

## 0042 — Pruning-soundness differential (`--gen-prune`): kernel-vs-kernel, ve "neden 0 divergence"in kök nedeni

### 1. Teşhis — niye altı bacak boyunca hiçbir şey bulamadık

Reviewer'ın sorusu ("eBPF bu kadar alevli bir yüzeyken nasıl hâlâ bir logic bug yok")
üç sebeple cevaplandı, üçü de ağaçta/literatürde doğrulandı.

**(i) Ω oracle'ımızı kernel zaten içeride koşturuyor.** `reg_bounds_sanity_check()`
(`verifier.c:2189`) birebir bizim invariant A/B/C'miz:
```c
if (range_bounds_violation(reg))        msg = "range bounds violation";
if (const_tnum_range_mismatch(reg))     msg = "const tnum out of sync with range bounds";
if (const_tnum_range_mismatch_32(reg))  msg = "const subreg tnum out of sync ...";
```
Ve her ALU op'ta (`:16060`), her branch'in dört register'ında (`:16621-24`), her helper
retval'inde (`:10507`), her LDX'te (`:6703`) çağrılıyor. Desync olursa `verifier_bug()`
ateşliyor ve `__mark_reg_unbounded()` ile toparlıyor; `BPF_F_TEST_REG_INVARIANTS` (1<<7)
onu sert `-EFAULT`'a çeviriyor. Yani 0025–0035'in tamamı, kernel'in her instruction'da
kendi kendine koşturduğu bir assertion'ı dışarıdan yakalamaya çalışıyordu. Bu, ikinci
pivotu ("consistency oracle'ları consistent-but-wrong'u kaçırır") keskinleştiriyor:
sadece kaçırmıyorlar — YAKALADIKLARI sınıf da zaten in-tree korunuyor. Consistency
oracle sınıfı iki yönden de kısır.

**(ii) Aynı eksen akademik olarak da dövülmüş.** Tek-instruction soyut transfer
fonksiyonları Agni (CAV'23) tarafından SMT'ye çıkarılıp kontrol edilmiş, tnum
toplama/çarpma soundness'ı ayrıca kanıtlanmış (CGO'22). *(Hafızadan; makalelerin
varlığından eminim, güncel CI entegrasyonundan değil — OI'ye "Agni hangi kernel
sürümünü kapsıyor" notu düşüldü, çünkü kanıtlanmış bir sürümün ardından regresyon
çıkabilir.)*

**(iii) Asıl sebep: input uzayı şekil olarak fakir.** Son 5 yılın bug listesi state
pruning (`regsafe`/`states_equal`), precision backtracking, callback/loop doğrulama,
pointer tip geçişleri, speculative yollar. Ortak yapıları: bug İKİ özelliğin
etkileşimini + ya döngü ya callback ya tam bir pruning çifti gerektiriyor. Biz 15–242
düz-çizgi program üretiyorduk. `oracle × input` kuralının çarpması: altı bacak boyunca
oracle büyüdü, input aç kaldı. Kernel'in kendi selftest'leri haritayı bedava veriyor —
bu bayrakları kimler kullanıyor: `precise.c`, `calls.c`, `iters_looping.c`,
`verifier_iterating_callbacks.c`, `verifier_live_stack.c`.

### 2. Yeni oracle sınıfı — kernel vs kernel

Bu bacakta karşılaştırmanın İKİ tarafı da kernel'in aynı program üzerindeki kendi
kararı. Parse ettiğimiz bir bound yok, hesapladığımız bir değer yok — yani yanlış
olabilecek bir oracle'ımız yok. (0041 tam olarak iki tane böyle bug taşıdı.)

**Yön düzeltmesi — kaynak beni düzeltti.** Önce "TEST_STATE_FREQ pruning'i devre dışı
bırakır" demiştim; `states.c:1248` tersini söylüyor:
```c
force_new_state = env->test_state_freq || bpf_is_force_checkpoint(env, insn_idx) || ...
add_new_state = force_new_state;
if (jmps_processed - prev >= 2 && insn_processed - prev >= 8) add_new_state = true;
```
Varsayılan sezgisel kural checkpoint'i ancak ≥2 jump VE ≥8 insn sonra koyuyor; bayrak
HER instruction'da zorluyor. Yani pruning daha **agresif** oluyor, `regsafe` çok daha
fazla aday çift yargılıyor. Bu, bulgunun yönünü belirliyor:

- **bayraklı ACCEPT + varsayılan REJECT** → reddi üreten yol budandı. Bunu ancak
  unsound bir `regsafe` yapar. **Bulgu bu.**
- **bayraklı REJECT + varsayılan ACCEPT** → fazladan checkpoint state sayısını
  şişiriyor, `BPF_COMPLEXITY_LIMIT_INSNS` (`verifier.c:18348`, "BPF program is too
  large", `-E2BIG`) devreye girebiliyor. Enstrümanın artefaktı: red sebebine göre
  sınıflandırılıyor, ayrı sayılıyor, bulgu sayılmıyor. Kaynak-limiti OLMAYAN bir ters
  flip ise gerçek bir anlaşmazlık ve over-rejection olarak raporlanıyor — tooth 2'nin
  tüm yönü aklamasını engelleyen şey bu.

**Payda.** Bir çift ancak bayrak state uzayını DEĞİŞTİRDİYSE sayılıyor
(`freq_states > base_states`). Aynı state'leri gezen iki koşunun anlaşması pruning
hakkında kanıt değil, hiçbir şeyin denenmediğinin kanıtı. Reviewer "state sayısı farkı
bulgu değil" derken haklı, ama onu ATMAK yerine payda yapmak gerekiyor — 0041'in
`store_locations_checked` disiplininin aynısı.

**Üçüncü kanal, bir bayrak biti.** `BPF_F_TEST_REG_INVARIANTS` her load'a ekleniyor:
varsayılanla temiz yüklenip bayrakla EFAULT veren program, dışarıdan asla
göremeyeceğimiz bir iç tutarsızlık.

### 3. Input — yanlış prune'un GÖZLEMLENEBİLİR olması için üç şart

(a) birleşen kontrol akışı, (b) `regsafe`'in gerçekten yargılamak zorunda kaldığı iki
farklı gelen state, (c) hangi yoldan gelindiğine BAĞLI güvenliği olan bir downstream
erişim. Üçüncüsü yoksa yanlış prune kararı değiştirmez, bug sessiz kalır.

İki attacker değeri tek map value'dan okunuyor (offset kaynağı r6, branch seçici r9),
böylece **split r6'yı kısıtlamıyor** — her yolun r6 state'i yalnızca kendi shaper'ından
geliyor. Yollar birleşip `map_value + r6 + 56`'ya 1 byte yazıyor; sınır içi ⟺
`umax(r6) <= 7`. Verifier FALL-THROUGH'u önce geziyor (`check_cond_jmp_op` jump
hedefini stack'e itiyor), yani checkpoint'i fall-through kaydediyor — ORDER bu yüzden
bir eksen, kaza değil.

Shaper'lar: `n7`=[0,7] güvenli, `t6`={0,2,4,6} güvenli (tnum-refined), `w63`=[0,63],
`m39`=[32,39] (ayrık), `o19`=[4,19] (örtüşen), `s56`={0,8,..,56} (aynı umin, delikli
tnum), `a32`=[0,63] 32-bit yoldan. 16 program: 2 `safe.*` + 6 `dang.*` (güvenli olan
önce checkpoint'liyor → yanlış prune kararı flip ederdi) + 6 `ctrl.*` (ayna: geniş olan
önce, dar olan meşru şekilde kapsanıyor → sound prune, mekanizmanın çalıştığının kanıtı)
+ 2 `stk.*` (fark register'da değil STACK SLOT'ta → yargıç `regsafe` değil `stacksafe`).

**Saf-tnum kolu bilerek YOK:** store'un güvenliği yalnız `umax`'a bağlı, dolayısıyla bir
tnum farkı kararı flip EDEMEZ — vakum bir kol olurdu. (0039'un tautology dışlama
kuralının aynısı.)

### 4. Sonuç

**16 program, 2 accept / 14 reject** (türetmeyle birebir: accept ⟺ iki yol da güvenli),
**`prune_pairs_checked=16`, `finding_count=0`, `prune_resource_artifacts=0`,
`parser_unrecognized=0`.** Üç yükleme de (varsayılan / state-freq / reg-invariants) her
programda aynı kararı verdi, ve bayrak HER programda state uzayını büyüttü
(base 1–3 → freq 4–7), yani deney gerçekten koştu.

Dört diş de ateşliyor: (1) ekilen bayraklı-accept + varsayılan-reject →
`prune_soundness_desync` bir kez, (2) ekilen `freq_reason=too_large` ters flip → bulgu
DEĞİL ama artefakt olarak sayılıyor, (3) kaynak-sebepsiz ters flip →
`prune_verdict_disagreement`, (4) ekilen `inv_reason=efault` →
`reg_invariants_violation`. Artı payda guard'ı: `freq_states == base_states` olan çift
paydadan düşüyor.

### 5. Yol boyunca yakalanan: token çarpışması, ikinci kez

İlk capture `records=16 (accept=8 reject=56)` verdi — 64 = 16×4. Sebep:
`measure_log.rs` `text.matches("decision=accept")` diye ALT-DİZGİ sayıyor, ve benim
`base_decision=accept` token'ım onu içeriyor. **0041'deki `find("off=")`'ın
`var_off=(...)` içinde eşleşmesinin birebir aynı sınıfı, iki leg arayla.** İki taraftan
da düzeltildi: token'lar `*_verdict=` olarak yeniden adlandırıldı (çarpışamayacak isim,
bir kez seçilir), ve sayaç `RESULT decision=` diye çapalandı. Ders: bu projede yeni bir
çıktı satırı eklerken mevcut alt-dizgi konvansiyonlarına karşı isim çakışması kontrolü
artık rutin olmalı.

Pinlendi: `crates/pipeline/tests/prune_calibration.rs` (9 test), fixture
`fixtures/volume/gen-prune-16.log`; runner `scripts/run-prune.sh`. Workspace 195 yeşil.

**Sıradaki:** loop/iterator input'ları (kernel'in kendi tehlike haritası oraya işaret
ediyor: `iters_looping.c`, `verifier_iterating_callbacks.c`), sonra SMT — ama `regsafe`'e
nişanlı (γ(new) ⊆ γ(old) refinement iddiası), ALU transfer fonksiyonlarına değil.

---

## 0043 — İlk back-edge ailesi (`--gen-loop`, `may_goto`): input artışı, oracle aynen taşındı

### 1. Neden bu, ve neden oracle DEĞİŞMEDİ

0042'nin teşhisi şuydu: altı bacak boyunca sıfır bulgu, çünkü ürettiğimiz her program
ileri-yönlü bir DAG'dı — gerçek bug listesi (state pruning, precision, convergence)
back-edge olmadan erişilemez. Bu bacak tam olarak o eksiği kapatıyor ve **oracle'a tek
satır eklemiyor**: aynı üç yükleme, aynı yönlü predikat, aynı `freq_states > base_states`
paydası, aynı parser ve diff kodu. `oracle × input` kuralının uygulanmış hâli — bütçe
input'a gitti.

Mekanizma OI-13'te kaynaktan seçilmişti: `may_goto`. Tek ham instruction
(`BPF_JCOND`=0xe0, `BPF_MAY_GOTO`=0, `verifier.c:19075` `dst_reg==0 && imm==0` istiyor),
BTF yok, kfunc yok, subprog yok. Atlama hedefi döngü ÇIKIŞI, fall-through gövdeye devam
— kernel'in kendi `__cond_break` makrosuyla doğrulandı (`.byte 0xe5`, offset `l_break`'i
gösteriyor). Fall-through'ta verifier `may_goto_depth`'i artırıp aynı instruction'daki
önceki girişe karşı `widen_imprecise_scalars()` çağırıyor (`verifier.c:16923`) — precision
ve pruning'in üstünde oturan kasıtlı bir yakınsama üst-yaklaşımı.

### 2. Karar TÜREV: iterasyon sayıları üzerinden JOIN

Store'a ulaşan state, 0, 1, 2, ... iterasyonun JOIN'i — **sıfır-iterasyon yolu dâhil**,
çünkü bütçe girişte tükenmiş olabilir. Store +56'da olduğu için program kabul edilebilir
⟺ bu join `umax(r6) <= 7` tutuyor. İki keskin çift:

- `incmask` (`r6 += 1; r6 &= 7` → [0,7], KABUL) vs `maskinc` (`r6 &= 7; r6 += 1` → join
  [0,8], RED). Aynı iki işlem, ters SIRA, bir byte fark. Verifier reddedende tam olarak
  `umin=1,umax=8,var_off=(0x0; 0xf)` basıyor.
- `mask.m7` (KABUL) vs `mask.m63` (RED). Aynı gövde; tek fark geniş girip hemen break
  etmenin geniş aralığı store'a taşıması — sıfır-iterasyon yolu.

**SONUÇ: 12 program, 6 kabul / 6 red — türetmeyle birebir.** `prune_pairs_checked=12`,
`finding_count=0`, `prune_resource_artifacts=0`, `parser_unrecognized=0`. Üç yükleme de
her programda aynı fikirde, bayrak her programda state uzayını büyüttü (1→4, 2→7, 2→6).

### 3. İlk capture VAKUMDU ve bunu yüksek sesle söyledi

İlk koşu 10 kabul / 2 red verdi ve *hepsi* `init_mask`'in saf fonksiyonuydu — `nop.m7`
ile `inc.m7` ayırt edilemiyordu, ikisi de 2→6 state. On farklı gövdenin aynı sonucu
vermesi gövdenin doğrulanmadığının kanıtı. Disassembly onayladı:
```
  9: (e5) may_goto pc+2
 10: (07) r6 += 1
 11: (05) goto pc-4      <- insn 8'e (r6 &= 7) dönüyor, 9'a (may_goto) değil
```
Kök neden C'de: `ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - n - 1)` — `n++`'ın yan
etkisi offset ifadesine karşı **sıralanmamış**, offset artmış `n` ile hesaplanmış.
Her iterasyon giriş invariant'ını yeniden kuruyordu, yani "on temiz kabul" hiçbir şey
kanıtlamıyordu. Düzeltme: back-edge indeksi store'dan ÖNCE alınıyor. Bu vakum, testte
kalıcı bir guard'a çevrildi (`the_loop_body_actually_affects_the_verdict`): aynı giriş
maskesini paylaşan kollar arasında hem kabul hem red bulunmalı.

İkinci bir zayıflık da düzeltildi: `cond` kolunun eşiği 7'ydi, giriş aralığı [0,7] iken
koşul HER ZAMAN doğru → reset ölü kod, dal tek yönlü. Eşik 3 yapıldı, iki taraf da
erişilebilir, join gerçekten hesaplanıyor. (0039/0042'nin tautoloji dışlama kuralı.)

### 4. Testler

`loop_calibration.rs` 8 test: vakum guard'ı, türetilmiş karar tablosu (kol başına
gerekçesiyle yazılı, hesaplanmış değil — şekil değişirse insan yeniden türetsin),
sıra-duyarlılığı çifti, differential'ın headline'ı, bayrağın her programda tuttuğu,
0042'nin dişinin BU capture üzerinde ateşlediği (ekilen bayraklı-accept →
`prune_soundness_desync`), kernel'in kendi invariant kanalının sessiz kaldığı, ve parser
kör noktası yok. Workspace 203 yeşil.

**Sıradaki:** açık iteratorler (OI-13'ün ikinci sırası — `states.c` kendi
`bpf_is_state_visited`'ında iterator loop-detection'ının özel-durum olduğunu ve
`states_maybe_looping`'in ID remapping konusunda "too simplistic" olduğunu itiraf
ediyor; maliyet `BPF_PSEUDO_KFUNC_CALL` + load-time BTF). Ayrıca bu ailenin doğal
artışı: kabul edilen loop programlarını ÇALIŞTIRIP 0041'in store-location oracle'ını
üzerlerine koşmak — verifier'ın fixpoint'i runtime'ın gerçek iterasyon sayısı için de
tutmak zorunda.

---

## 0044 — Loop fixpoint vs runtime (`--gen-loopr`): kanıt okundu, ve maliyet önce ölçüldü

### 1. Soru, ve 0043'te bıraktığı delik

0043 back-edge programın KARARININ checkpoint sıklığına dayanıklı olup olmadığını
sordu. Bu bacak 0041'in daha güçlü sorusunu döngü üstünde soruyor: verifier, store'daki
offset register'ına bir sınırı **sınırsız sayıda iterasyon üzerinden bir FIXPOINT
hesaplayarak** kanıtlıyor; runtime ise milyonlarca iterasyon sayısından somut birini
seçiyor. Store, hangi sayı seçilirse seçilsin kanıtlanmış kümenin içine düşmek zorunda.

Aynı zamanda 0043'ün deliğini kapatıyor: o aile `STORE` satırı basıyor ama hiç
çalıştırmıyordu, yani `store_locations_checked = 0` — kendi kuralımıza göre iddia hiç
okunmadı, ve oradaki sıfır bulgu konum sorusu hakkında hiçbir şey ifade etmiyordu.

### 2. Maliyet ÖNCE ölçüldü (`--probe-loopr`)

Aileyi kurmadan önce tek soru şuydu: bir may_goto programı gerçekte ne kadar dönüyor?
`BPF_MAX_LOOPS = 8*1024*1024` sayısı ilk bakışta 8M iterasyon diyor, ama x86-64'te
`bpf_jit_supports_timed_may_goto()` **true** — bütçe SAYI değil ZAMAN:
`bpf_check_timed_may_goto()` 0xffff'lik sayacı `NSEC_PER_SEC / 4` dolana kadar
tazeliyor. Ölçüm: **250.3 / 250.5 / 251.4 ms** — bütçe birebir.

Zaman tabanlı olması bu bacağı mümkün kılan şey: KASAN/KCOV yavaşlığı aynı 250 ms
içindeki iterasyon SAYISINI düşürüyor, koşuyu uzatmıyor. OI-11 tam olarak uzun
kernel-içi çalıştırma hakkında tahmin yürütmemek dersiydi; bu yüzden 18 saniyelik bir
kernel dönüşüne körlemesine girmek yerine 0040'taki gibi önce probe edildi.

### 3. Sweep bu ailenin kendisi

Paylaşılan `RT_INPUTS` 12 değer taşıyor, ama buradaki giriş state'i `input & 7` ve o 12
değer yalnız **beş** farklı kalıntıya düşüyor — yedi koşu × 250 ms hiçbir şey satın
almadan harcanırdı. `LOOPR_INPUTS` sekiz kalıntının hepsini kapsıyor.

### 4. Sonuç

**7 program (6 kabul + 1 red kontrolü), `store_locations_checked = 48`,
`runtime_writes_checked = 48`, `finding_count = 0`, `parser_unrecognized = 0`.**
Her store, verifier'ın fixpoint'inin kanıtladığı kümenin içine düştü. Landing setleri
(r6 = off − 56):

| kol | ulaşılan r6 | yorum |
|---|---|---|
| `nop` | {0..7} | gövde offset'e dokunmuyor, sekiz kalıntının hepsi |
| `mask` | {0..7} | idempotent |
| `xor3` | {0..6} | [0,7] içinde |
| `incmask` | {2,3,4,6,7} | iterasyon sayısına bağlı → **nondeterministik** |
| `shr` | {0} | deterministik olarak sıfıra iniyor |
| `cond` | {0,1,2,3} | dal 3'ün üstünü sıfırlıyor |

**Nondeterminizm burada özellik.** Son offset bütçeye kaç iterasyon sığdığına bağlı,
yani `incmask` her koşuda başka yere düşüyor. Oracle **üyelik** soruyor, eşitlik değil —
her koşu fixpoint'i taze bir noktadan örneklüyor. Aşağı akışta hiçbir şey bu kollar için
kesin bir `store_off` iddia etmemeli.

**`cond` muhafazakârlığı gösteriyor:** verifier [0,7] kanıtlıyor, runtime yalnız [0,3]'e
ulaşıyor. Bu doğru yön — kanıttan DAR bir runtime kümesi sadece imprecision; kanıttan
GENİŞ olsaydı bulgu olurdu. Test bunu açıkça sabitliyor.

### 5. Dürüst sınır

Bütçe her zaman sonuna kadar harcandığı için runtime **sıfır-iterasyon yolunu hiç
almıyor**. O yol verifier için gerçek (0043'te `mask.m63`'ün reddedilme sebebi), ama
burada yalnızca verifier tarafı kanıt — runtime tarafından hiç doğrulanmadı.

### 6. Testler

`loop_runtime_calibration.rs` 7 test: headline (48 kontrol, 0 bulgu), **vakum guard'ı**
(gövde runtime'da gerçekten koşmuş olmalı — `shr` her girdide base'e düşüyor ve `nop`'un
setinden farklı; koşmasaydı hepsi `nop` gibi olurdu), pencerenin dar olduğu, muhafazakâr
yönün serbest / geniş yönün bulgu olduğu, 0041'in dişinin BU capture'da ateşlediği
(pencere dışı ama value içi offset → `store_location_desync` bir kez,
`runtime_oob_write` SESSİZ), probe'un ölçtüğü bütçenin pinlenmesi, ve parser kör noktası
yok. Workspace 210 yeşil.

**Sıradaki:** açık iteratorler (OI-13'ün ikinci sırası; `BPF_PSEUDO_KFUNC_CALL` +
load-time BTF makinesi gerekiyor).

---

## 0045 — Açık iteratorler (`--gen-iter`): kernel'in kendi pruning yolunda özel-durum yaptığı mekanizma

### 1. Neden bu mekanizma

OI-13'ün ikinci sırası, ve listedeki en yoğun hedef — çünkü kernel riski kendi ağzıyla
söylüyor. `bpf_is_state_visited` (states.c) iteratorler için olağan loop detection'ını
ATLIYOR: *"BPF open-coded iterators loop detection is special. states_maybe_looping()
logic is too simplistic in detecting states that might be equivalent, because it doesn't
know about ID remapping, so don't even perform it."* Pruning yolunda, itiraf edilmiş bir
basitleştirmeyle gerekçelendirilmiş bir özel durum.

### 2. Ödenen altyapı: BTF

Iterator döngüsü kfunc çağrılarından kuruluyor, kfunc çağrısı ise
`src_reg = BPF_PSEUDO_KFUNC_CALL` ve `imm` = fonksiyonun **BTF id**'si — yalnız çalışan
kernel'de var olan bir sayı. libbpf olmadığı için harness `/sys/kernel/btf/vmlinux`'u
okuyup tip bölümünü kendisi yürüyor. Yürüyüş affetmiyor: her tip 12-byte başlık + kind'a
özgü kuyruk, bir tipi yanlış atlarsan **ondan sonraki bütün id'ler kayıyor** — ve yanlış
id load hatası değil, *başka bir fonksiyonu çağırmak*. Derlediğimiz distro header'ı
`BTF_KIND_FLOAT`'ta bitiyor, o yüzden DECL_TAG/TYPE_TAG/ENUM64 harness'te tanımlandı;
onlarsız yürüyüş modern bir vmlinux'ta sessizce kayardı.

Probe (`--probe-iter`) çözülen id'leri **basıyor** — tam da sessiz kayma görünür olsun
diye: `new=83158 next=83159 destroy=83156`, 6.8 MB BTF. Üç kol: çıplak döngü kabul,
maskeli birikimci + store kabul, sınırsız birikimci + store red. Kabuller id'lerin doğru
olduğunun kanıtı.

*(Probe'un ilk koşusunda `arm=0` EINVAL / "processed 0 insns" verdi. Bulgu değil: o kolda
map lookup yok, dolayısıyla sondaki null-path bloğuna hiç dallanılmıyordu → ulaşılamaz
insn. Blok artık yalnız ona dallanan bir şey varsa basılıyor.)*

### 3. Üç oracle bedavaya biniyor

Yeni oracle YOK: 0042'nin üç-yüklemeli pruning differential'ı, 0041'in store-location
kontrolü, 0037'nin write-safety kontrolü — üçü de değişmeden. Iteratorler en fazla sekiz
tur ve may_goto'nun 250 ms bütçesi (0044) yok, yani runtime yarısı burada neredeyse
bedava.

### 4. Sonuç

**12 program, 7 kabul / 5 red, `store_locations_checked=56`, `runtime_writes_checked=56`,
`prune_pairs_checked=12`, `finding_count=0`, `parser_unrecognized=0`.** Iterator state
makinesi gerçekten çalıştı: **120 `state=active` + 25 `state=drained`** — vakum değil.

**Mekanizma differential'ı:** `.o56` karar tablosu 0043'ün may_goto tablosuyla **on
gövdenin onunda da aynı**. İki farklı back-edge mekanizması, aynı transfer fonksiyonu,
aynı karar — biri yanlış yakınsasaydı burada ayrışırlardı. Bu, ailelerarası bir test
olarak pinlendi.

### 5. Capture türetmeyi yine düzeltti — ve bu sefer verifier hakkında bir OLGU çıktı

`.o48` kolları mekanizma-duyarlı çift olarak tasarlanmıştı: offset 48'de erişim
`umax(r6) <= 15` ise sınır içi, ve 8 turluk bir `inc` bunu sağlamalı ([0,7] giriş + en
fazla 8 artış), sınırsız bir may_goto döngüsü sağlayamaz. **Reddedildi.** Log nedenini
söylüyor:

```
fp-8=iter_num(id=1,state=active,depth=8)  R6=[7,14]
fp-8=iter_num(id=1,state=active,depth=9)  R6=[8,15] → +1 → [9,16]
```

**Verifier iterator DERİNLİĞİNİ takip ediyor, ama sabit `[0,8)` aralığını trip sayısını
sınırlamak için KULLANMIYOR** — durmayı state yakınsamasından bekliyor, dolayısıyla
gerçekte mümkün olandan fazla tur geziyor, depth 9'da r6 [9,16]'ya çıkıyor ve `umax=16`
üzerinden reddediyor. Runtime'da döngü tam 8 tur dönüyor, yani program aslında güvenli.
Bu bir **over-rejection**: güvenli yönde imprecision, hata değil. Olgu olarak pinlendi
(`nop.o48` aynı offset'te kabul ediliyor, yani kol vakum değil).

### 6. Testler

`iterator_calibration.rs` 8 test: iterator state makinesinin gerçekten çalıştığı
(active VE drained), BTF çözümünün çalışan id ürettiği, **mekanizma differential'ı**
(on ortak gövde), headline (56 kontrol, 0 bulgu), `.o48` olgusunun pinlenmesi, 0041
dişinin BU capture'da ateşlediği, runtime'ın yalnız kanıtlanmış pencerelerde kaldığı, ve
parser kör noktası yok. Workspace 218 yeşil.

*(Yol boyunca test kendi hatasını yakaladı: mekanizma karşılaştırmasının filtresi gövde
adına bakıyordu, ama `inc` ve `nop`'un hem `.o56` hem `.o48` kolu var → 10 yerine 12
karşılaştırma. Filtre kolun kendi etiketine çevrildi.)*

**Sıradaki:** iterator ailesinin asıl hedefi olan ID-REMAPPING — `states.c`'nin
"too simplistic ... doesn't know about ID remapping" dediği şey; iki iterator (ya da
iterator + refcounted pointer) arasında id eşlemesi gerektiren şekiller, ki bu ailenin
tek-iterator şekli oraya henüz dokunmuyor.

---

## 0046 — Skaler ID remapping (`--gen-idmap`): `states.c`'nin "too simplistic" dediği şey

### 1. Hedef, kernel'in kendi tarifiyle

`check_ids()` (states.c:319) iki state'i karşılaştırırken **bijektif** bir old↔cur id
eşlemesi kuruyor; `check_scalar_ids()` bunu skalerler için sarıyor. Neden var olduğunu
kernel `regsafe` yorumunda hipotezle değil **programla** anlatıyor:

```
1: r6 = unbound scalar, ID=a
2: r7 = unbound scalar, ID=b
3: if (r6 > r7) goto +1
4: r6 = r7                 <- ikisi de id=b: LINKLI
5: if (r6 > X) goto ...    <- sync_linked_regs paylaşılan id üzerinden r7'yi de daraltıyor
6: ... r7 ile bellek işlemi ...
```

(6)'ya iki state ulaşıyor: **I.** `r6{id=b}, r7{id=b}`, **II.** `r6{id=a}, r7{id=b}`.
II'de (5)'teki sınır kontrolü r7'ye hiç dokunmadı. `check_ids()` ikisini eşitlerse II
budanır ve güvensiz erişim kabul edilir.

### 2. Aile: farkı YALNIZCA linkaj yapacak biçimde

Ayrım noktası üçüncü bir skaleri test ediyor, yani ne r6 ne r7 dalın kendisiyle
kısıtlanıyor. Daraltma kontrolü yalnız r6'yı adlandırıyor, yani r7 **ancak** paylaşılan
id üzerinden daralabilir. Ve her RED şekli, yalnızca linkin iki yolda da var olup
olmadığında farklılaşan bir KABUL kontrolüyle eşleniyor — bu eşleme olmadan bir red
sadece "şekil güvensiz" derdi, "linkaj karar veriyor" demezdi.

Eksen = linkin NASIL kurulduğu, çünkü her biçim farklı bir id taşıyor: düz `r7 = r6`
sade paylaşılan id (`assign_scalar_id_before_mov`, verifier.c:3470 kaynağa id basıyor);
`r7 = r6; r7 += 4` ayrıca `BPF_ADD_CONST64` (bit 31) kuruyor, yani çift `id` ve
`id|flag` taşıyor ve `check_scalar_ids` **hem bileşik hem taban** id'yi tutarlı
eşlemek zorunda; 32-bit biçim `BPF_ADD_CONST32` (bit 30) kuruyor ve kernel farklı bayrak
tipleri arasında budamayı reddediyor çünkü alu32 zero-extend ediyor.

### 3. Sonuç

**9 program, 5 kabul / 4 red — türetmeyle birebir**, `store_locations_checked=40`,
`runtime_writes_checked=40`, `prune_pairs_checked=9`, `finding_count=0`,
`parser_unrecognized=0`.

| kol | karar | anlam |
|---|---|---|
| `nolink.one.r7` | red | taban: r7 hiçbir yolda daralmıyor |
| `nolink.one.r6` | kabul | kontrol: daraltılan r6 üzerinden |
| **`mov.one.r7`** | **red** | asıl şekil — linksiz state budanmadı |
| `mov.both.r7` | kabul | kontrol: iki yolda link → r7 daraldı |
| `mov.one.r6` | kabul | kontrol |
| `addc64.one/both.r7` | red / kabul | `BPF_ADD_CONST64` |
| `addc32.one/both.r7` | red / kabul | `BPF_ADD_CONST32` |

**`*.both` kollarının kabul edilmesi bu bacağın vakumsuzluk kanıtı:** paylaşılan id
üzerinden r7'nin gerçekten daraltıldığını gösteriyor. Olmasaydı onlar da reddedilirdi ve
`*.one` redleri linkaj hakkında hiçbir şey söylemezdi.

Mekanizma state dump'ında da görünür, çıkarımla değil doğrudan:
```
11: (bf) r7 = r6      ; R6=scalar(id=1,...) R7=scalar(id=1,...)
13: (25) if r6 > 0x7  ; R6=scalar(id=1,...umax=7...) R7=scalar(id=1,...umax=7...)
```
İkinci satır tam olarak kernel yorumundaki (5) adımı: kontrol yalnız r6'yı adlandırıyor,
r7 paylaşılan id üzerinden daralıyor.

0042'nin üç-yüklemeli enstrümanı değişmeden bindi ve buraya özellikle iyi oturuyor:
`BPF_F_TEST_STATE_FREQ` pruning denemelerini çoğalttığı için bir id-eşleme hatası
bayrakla çok daha fazla şans buluyor. Dokuz programın hepsinde üç yükleme aynı fikirde.

### 4. Testler

`idmap_calibration.rs` 7 test: **headline+vakumsuzluk tek assertion'da** (her link biçimi
için one RED / both KABUL), taban ve doğrudan-kullanım kontrollerinin sonucu iki taraftan
çerçevelemesi, paylaşılan id'nin ve yayılımının log'da görünürlüğü, dört link biçiminin
de mevcut olduğu, oracle'ların paydayla birlikte sessizliği, 0041 dişinin ateşlemesi, ve
parser kör noktası yok. Workspace 225 yeşil.

*(Yol boyunca test kendi hatasını yakaladı: `find` ilk "r7 = r6" satırını alıyordu, o da
state anotasyonu olmayan düz listeleme satırı. Anotasyonlu olan seçildi.)*

**Sıradaki:** id eşlemesinin **injektifliği** — `check_ids` `map[i].cur == cur_id` ama
`old` farklıysa reddediyor; iki linkli çiftin ÇAPRAZ eşlendiği şekiller bunu doğrudan
sınar ve bu aile henüz oraya dokunmuyor. Ayrıca `BPF_ID_MAP_SIZE` tükenmesi
(`check_ids` dolduğunda state'leri denk-değil sayıyor).

---

## 0047 — ID-map bijeksiyonu (`--gen-idpart`): ilk sıfır-olmayan bulgu, ve bulgu BİZDEYDİ

### 1. Soru

0046 linkin VAR olup olmadığını sordu. Bu bacak eşlemenin **bijeksiyon** olup olmadığını
soruyor — `check_ids`'in gerçek kontratı (states.c:319): tutarlılık (bir old id tek bir
cur id'ye) ve injektiflik (iki old id aynı cur id'ye düşemez). Hangi `if`'in ateşleyeceği
program seviyesinden kontrol edilemiyor (register'lar sırayla karşılaştırılıyor, ilk
tutarsızlık kazanıyor), o yüzden aile kontrol edilebilen şeyi değiştiriyor: **id yapısı**,
yani register'ların linkli sınıflara bölünmesi.

### 2. Eksik olan yarı: COMPLETENESS

Şimdiye kadarki her bacak soundness test etti — güvensiz bir şeyi asla kabul etme.
`swap` kolları öbür yönü test ediyor: **aynı** bölünme farklı instruction sırasıyla
kurulunca farklı id NUMARALARI basılıyor (`++env->id_gen` global). Bunları kabul etmek
ancak remapping gerçekten eşliyorsa mümkün; eşitlik dayatan bir `check_ids` bunları
fazladan reddederdi. Capture ikisini de gösteriyor: fall yolu `id=1`, taken yolu `id=2`,
yapıca aynı bölünme, ve **kabul**.

### 3. Sonuç

**12 program, 7 kabul / 5 red — türetmeyle birebir** (kabul ⟺ her iki yol da r9'u
daraltılan sınıfa koyuyor), `store_locations_checked=56`, `prune_pairs_checked=12`,
`parser_unrecognized=0`.

### 4. İLK SIFIR-OLMAYAN BULGU — ve triyaj

İlk capture **`finding_count=2`** verdi: `same-addc` kolunda iki `store_location_desync`.
Protokol (a-b-c) uygulandı.

**(a) Elle türetme.** Verifier store insn'inde **İKİ** state basmış:
```
28: R2=map_value(...,umax=7,var_off=(0x0; 0x7))         <- fall yolu:  r9 = r6      ∈ [0,7]
28: R2=map_value(...,umin=4,umax=11,var_off=(0x0; 0xf)) <- taken yolu: r9 = r6 + 4  ∈ [4,11]
```
Runtime 56 ve 58'e düştü (input 4 → r9=8, input 6 → r9=10), ikisi de **ikinci** state'in
penceresi `48 + [4,11] = [52,59]` içinde. Store tam olarak verifier'ın kanıtladığı yere
düştü — gittiği yolda.

**(b)** Bildirilen `insn=28` gerçekten store: `28: (72) *(u8 *)(r2 +48) = -1`.

**(c) Verdict: BİZİM hatamız.** `check_store_location` store insn'indeki **ilk** iddiayı
alıyordu. Bu, önceki her aileden miras kalan bir tek-yol varsayımı — bugüne kadar store'a
hep tek yol vardı. Düzeltme 0036'nın retval kanalına zaten verdiği muamele: iddiaların
**BİRLEŞİMİ**. Birleşim muhafazakâr bir üst küme, yani bulguyu KAÇIRABİLİR ama
uyduramaz — ve uydurmak tam olarak ilk-eşleşme sürümünün yaptığı şeydi.

**Bu, bir oracle varsayımının yeni bir input şeklinde kırılmasının ÜÇÜNCÜ örneği**
(0041'de `store_off=none`'ın iki anlamı, 0044'te iterasyon sayısı, şimdi bu) —
[[oracle-assumptions-from-past-families]] kuralının tuttuğu üçüncü sefer. a-b-c triyaj
sırasının pazarlığa açık olmamasının sebebi tam olarak bu: önce elle türet, ve kernel'i
temize çıkaran bir türetme parmağı bize doğrultuyor.

### 5. Birleşimin getirdiği yeni yükümlülük

Birleşim kontrolü **zayıflatıyor**, o yüzden iki şey ayrıca sabitlendi: (i) tüm suite'in
dişleri hâlâ ateşliyor (tek-yollu ailelerde birleşim aynı kümeyi verdiği için hiçbiri
körelmedi), (ii) çok-yollu bir store'da **bütün** iddiaların dışındaki bir offset hâlâ
ateşliyor ve rapor birleşimin dikkate alındığını söylüyor. Artı doğrudan regresyon
guard'ı: `same-addc`'nin ilk yolun penceresini AŞAN gerçek landing'leri var ve bunlar
bulgu ÜRETMEMELİ — birleşim düzeltmesinden önce başarısız olacak assertion bu.

### 6. Testler

`idpart_calibration.rs` 6 test: karar tablosu, **completeness** (aynı bölünme + farklı id
numaraları → kabul, ve numaraların gerçekten farklı olduğu), oracle'ların paydayla
sessizliği, regresyon guard'ı, birleşim üzerinden diş, parser kör noktası yok.
Workspace 231 yeşil.

**Sıradaki:** `BPF_ID_MAP_SIZE` tükenmesi — `check_ids` tablo dolduğunda state'leri
denk-değil sayıyor (`return false`), yani sınır aşıldığında pruning tamamen duruyor. O
sınırın nerede olduğu ve aşıldığında ne olduğu ölçülebilir.

---

## 0048 — Çok-frame'li state'ler (`--gen-frame`): subprog boyutu, ve sessiz bir parser deliği

### 1. Önce kapatılan bir kapı: idmap tükenmesi kurulabilir DEĞİL

0047'nin sonunda "sıradaki `BPF_ID_MAP_SIZE` tükenmesi" demiştim. Türetme onu kapattı:
`BPF_ID_MAP_SIZE = (MAX_BPF_REG + MAX_BPF_STACK/BPF_REG_SIZE + MAX_STACK_ARG_SLOTS) ×
MAX_CALL_FRAMES = (11 + 64 + 7) × 16 = **1312**`. Bir programın gerçekten doldurabileceği
id taşıyan slotlar register'lar + spill edilmiş stack slotları = frame başına 11 + 64 =
**75**, yani maksimum çağrı derinliğinde bile 1200 < 1312. Kernel'in kendi yorumu da aynı
şeyi söylüyor: tükenme "referenced dynptrs [that] acquire intermediate references that do
not live in either" gerektiriyor. Linkli skalerlerden, spill'lerden veya çağrı
derinliğinden kurulacak her tükenme ailesi **vakum** olurdu. OI-13b olarak kaydedildi ki
bir daha denenmesin.

### 2. Dokunulmamış boyut: subprog

Bu projenin ürettiği her program TEK frame'deydi. `states_equal`
`if (old->curframe != cur->curframe) return false` ile açılıp sonra her frame'i sırayla
karşılaştırıyor — yani state karşılaştırmasının çok-frame'li yarısı hiç sınanmamıştı. Ve
`calls.c` kernel'in kendi tehlike listesinde (BPF_F_TEST_STATE_FREQ kuran dosyalardan
biri).

Subprog çağrısı BTF ya da kfunc istemiyor: `BPF_CALL` + `src_reg = BPF_PSEUDO_CALL` +
`imm` = callee'nin pc-göreli offset'i. Asıl soru sınırı NEYİN geçtiği: yalnız r1-r5
geçiyor, callee'nin r6-r9'u tanımsız başlıyor. Bir skalerin link id'si argüman
register'ına sağ kalırsa, bir argümanı daraltmak diğerini `sync_linked_regs` üzerinden
**linkin kurulduğundan FARKLI bir frame içinde** daraltır.

### 3. Cevap: evet, geçiyor

Aile bunu varsayımla değil inşayla cevaplıyor — 0046'nın eşleme deseniyle:
`one.a2` **red**, `both.a2` **KABUL**. Id'ler sınırda dursaydı ikisi de reddedilirdi;
bu eşleme bacağın vakumsuzluk kanıtı. Log doğrudan gösteriyor:

```
22: (bf) r7 = r2      ; frame1: R7=scalar(id=1,…)
23: (25) if r6 > 0x7  ; frame1: R6=scalar(id=1,…umax=7…) R7=scalar(id=1,…umax=7…)
```
frame0'da basılan id, frame1'de yaşıyor ve bir argümanı diğeri üzerinden daraltıyor.

**6 program, 4 kabul / 2 red**, `store_locations_checked=32`, `runtime_writes_checked=32`,
`prune_pairs_checked=6`, `finding_count=0`, `parser_unrecognized=0`.

### 4. Sessiz parser deliği — ve payda kuralının bedelini ödediği yer

İlk capture `store_locations_checked = **0**` verdi, oysa log frame1 state'leriyle doluydu.
Sebep: verifier her çok-frame'li state'i `frameN:` ile önekliyor, ve önek register
token'larının ÖNÜNDE duruyor:
```
33: frame1: R3=map_value(ks=4,vs=64,…)
```
Bu yüzden tam-state satırı "tam-state satırı gibi görünmüyor", `;` koluna düşüyor, `;`
bulunmayınca atılıyor. Ve **sessizce** başarısız oluyor — tanınmayan satır değil, boş bir
register evolution — yani `parser_unrecognized` 0 kalıyor ve tek belirti sıfır payda.

İlk düzeltmem yetmedi: öneki state çıkarımından *sonra* soymuştum, oysa önek (a)/(b)
kararından ÖNCE kalkmalı. Düzeltilince payda 0 → 32, ve `tnum_bounds_checked` 131 → 142
(frame1 state'leri artık invariant kontrollerini de besliyor).

**"Sıfır bulgu ancak iddia OKUNMUŞSA anlamlı" kuralı olmasaydı bu bacak hiçbir şey
görmeden temiz sonuç raporlayacaktı.** Kural 0041'de konmuştu; bedelini burada ödedi.

Frame indeksi bilerek snapshot'a taşınmıyor: instruction indeksleri bir programın
subprog'ları arasında benzersiz, yani bir insn tam olarak bir subprog'a ait. İleride aynı
insn iki farklı çağrı derinliğinde görülürse iddialar birleşir — 0047'den beri
store-location kontrolü zaten BİRLEŞİM kullanıyor, yani muhafazakâr yön.

### 5. Testler

`frame_calibration.rs` 6 test: cevabın kendisi (one red / both kabul + üç kontrol),
caller'da basılan id'nin callee frame'inde görünürlüğü, **paydanın gerçekten okunduğu**,
callee frame register'larının bounds'la pipeline'a ulaştığı, dişin callee frame'i içinde
ateşlediği, ve parser kör noktası yok. Workspace 237 yeşil.

---

## 0049 — Spill edilmiş linkler ve delta aritmetiği (`--gen-spill`)

### 1. İki boşluk, tek satırda görünür

0046-0048 id makinesini register'larda ve frame'ler arasında sınadı. `sync_linked_regs`
(verifier.c:16847) tek satırda iki eksik boyutu gösteriyor:

```c
reg = e->is_reg ? &vstate->frame[e->frameno]->regs[e->regno]
                : &vstate->frame[e->frameno]->stack[e->spi].spilled_ptr;
```

**(1)** Linkli sınıf **stack slotlarını** da kapsıyor, ve `stacksafe`'in kendi `check_ids`
çağrıları var. Şimdiye kadarki her id ailesi skalerlerini register'da tuttu.
**(2)** ADD_CONST kolu, bir sınıfın iki üyesi farklı delta taşıyorsa gerçek **aritmetik**
yapıyor: `__mark_reg_known(&fake_reg, (s64)reg->delta - (s64)known_reg->delta)`. 0046 ve
0047'de hep TEK delta (4) çıplak bir tabana bağlıydı, yani çıkarmanın hiç iki önemsiz
olmayan operandı olmadı.

### 2. Sonuç: ikisi de çalışıyor — ve eşleme bunu kanıtlıyor

**8 program, 4 kabul / 4 red**, `store_locations_checked=32`, `runtime_writes_checked=32`,
`prune_pairs_checked=8`, `finding_count=0`, `parser_unrecognized=0`.

Her şekil için tek-yol RED / iki-yol KABUL:
- `spill.no` red, `spill.one` red, **`spill.both` kabul** → spill edilmiş kopya sınıfta
  kalıyor. Kalmasaydı `spill.both` de reddedilirdi.
- `delta.no` red, `delta.one` red, **`delta.both` kabul** (hem delta 12 hem delta 4).

### 3. Kabul tek başına kanıt değil — sayılar kanıt

Delta kolu için fazla-geniş ama yine de güvenli bir sınır da kabul edilirdi. Log tam
sayıları veriyor:

```
R6=scalar(id=1,   smin=smin32=0,          smax=umax=smax32=umax32=7)
R9=scalar(id=1+12, smin=umin=smin32=umin32=12, smax=umax=smax32=umax32=19, var_off=(0x0; 0x1f))
```

[12,19] tam olarak [0,7] + 12 — genişletilmiş değil, **doğru**. Kernel bileşik id'yi
`1+12` diye basıyor (taban + delta), ki aritmetiği log'dan denetlenebilir kılan da bu.
Test bu sayıları verdict yerine **değer** olarak sabitliyor.

Spill kolunda da mekanizma doğrudan görünüyor: slot kontrolden önce
`fp-16=scalar(id=1, umax=0xffffffff)`, sonra `fp-16=scalar(id=1, umax=7)` — stack
slotunun kendisi id taşıyor ve onun üzerinden daralıyor.

### 4. Testler

`spill_calibration.rs` 6 test: spill edilmiş kopyanın sınıfta kaldığı (eşlemeyle),
slotun id taşıyıp daraldığının dump'ta görünürlüğü, **delta aritmetiğinin değerle
sabitlenmesi** (base [0,7] + delta-12 üyesi tam [12,19] + `+12` gösterimi), oracle'ların
paydayla sessizliği, diş, ve parser kör noktası yok. Workspace 243 yeşil.

---

## 0050 — Precision, budamanın kaldıracı (`--gen-prec`) — ve iki oracle hatası daha

### 1. Kaldıraç

`regsafe` (states.c:551) verifier'ın en güçlü budama kuralını içeriyor:

```c
if (!rold->precise && exact == NOT_EXACT)
        return true;
```

**Imprecise bir eski skaler HERHANGİ bir güncel skalerle eşleşiyor.** Yani precision,
budamayı durduran şeyin ta kendisi: değeri bellek güvenliğini belirleyen bir register
precise işaretlenmezse, yalnız o register'da farklılaşan iki state eşitlenir ve güvensiz
olan budanır. Bunu doğru yapmak zorunda olan `mark_chain_precision`, ve `precise.c`
kernel'in kendi tehlike listesinde. Backtracker işini log'luyor
(`mark_precise: frame%d: regs=%s`, backtrack.c:280), yani mekanizma karardan çıkarsanmak
zorunda değil — gözlemlenebilir.

### 2. Eksen: fark eden register karara giriyor mu

İlk iki kol **tek bir instruction'ın tek bir operandında** farklı — store hangi
register'ı ekliyor — dolayısıyla aralarındaki her fark precision'dır, başka bir şey değil.

**Ölçüldü:** `c8_16.s7` (store r7'yi kullanıyor) backtracker'ın `regs=r7`'yi **19 kez**
kovaladığını gösteriyor ve **3** state gezmiş. `c8_16.s6` (store r6'yı kullanıyor, r7 ölü)
`regs=r7`'yi **hiç** kovalamıyor — onun yerine `regs=r6` — ve **2** state gezmiş. Aradaki
tek state, `states.c:551`'in buduğu state.

**Dikkat: ham `mark_precise` satır sayısı ters yönde** (s6=27 > s7=23), çünkü backtracker
başka register'lar için de çalışıyor. Sinyal sayı değil, **hangi register'ın kovalandığı**.
Bunu teste de bu şekilde yazdım.

Karar sabitin saf fonksiyonu, ve sınır tam bir byte: offset 40'ta `umax <= 23` güvenli,
yani **23 kabul / 24 red**.

**6 program, 4 kabul / 2 red**, `store_locations_checked=32`, `prune_pairs_checked=6`,
`parser_unrecognized=0`.

### 3. İki oracle hatası daha — ikisi de a-b-c triyajıyla

İlk capture **24 bulgu** verdi. Triyaj ikisini de bizde buldu, ve ikisi de aynı kök
sebepten görünür oldu: bu aile ilk kez **sabit offsetli** pointer üretiyor.

**(i) `imm=` vs `off=`.** Verifier sabit offsetli bir pointer'ı `imm=16` diye basıyor,
`off=16` diye değil. `log.c:682-687`:
```c
if (tnum_is_const(reg->var_off)) {          /* pointer with fixed offset */
        if (reg->var_off.value) { verbose_a("imm="); verbose_snum(env, reg->var_off.value); }
}
```
Yani **`imm=` = `var_off.value`** (var_off sabitken ve sıfır değilken), `off=` ise ayrı
bir alan (`reg->off`). Yalnız `off=` okumak sabiti 0 yapıyordu, dolayısıyla sabit offsetli
her store kendi iddiasından kaçmış gibi görünüyordu. Artık `imm=` tnum'un **değerine**
okunuyor (mask 0), ki semantik evi orası.

**(ii) Ters pencere.** Basılmamış `umax` log konvansiyonunda U64_MAX demek, ve
`u64::MAX as i64` = **−1**. Bunu aralık ucu olarak kullanmak `hi = base − 1` veriyordu —
bulgu metnindeki `[40, 39]`. Karşılaştırma artık baştan sona **u64** üzerinde ve değişken
parça üzerinde yürüyor; **belirtilmemiş bir üst sınır hiçbir şey kısıtlamaz, uç nokta
değildir.** Bu hata 0041'den beri latentti ve hiç tetiklenmemişti çünkü önceki her ailenin
pointer'ı basılı bir `umax` taşıyordu.

Düzeltmeden sonra 24 → **0 bulgu**, payda 32'de sabit, ve **tüm suite'in dişleri hâlâ
ateşliyor** (249 yeşil). Üstelik düzeltme oracle'ı *güçlendiriyor*: sabit offsetli bir
iddia artık tek NOKTA, yani kontrol en keskin hâlinde — diş testi bunu 48 ile 56
arasındaki 52'yi ekerek sabitliyor.

### 4. Testler

`precision_calibration.rs` 6 test: kaldıracın iki bağımsız yolla sabitlenmesi (hangi
register kovalanıyor + state sayısı), bir-byte sınırı, **`imm=` regresyon guard'ı**
(iddialar tnum değeri 8 ve 16 ile parse edilmeli), oracle'ların paydayla sessizliği,
nokta-iddia üzerinde diş, parser kör noktası yok. Workspace 249 yeşil.

---

## 0051 — Hangi `exact_level`'a giriyoruz (`--gen-exact`): bir tahmin kuruldu ve ölçümle çürütüldü

### 1. Üç seviye, üç ayrı çağrı yeri

`regsafe` bir `exact_level` alıyor ve seviyeye göre bambaşka davranıyor (states.c):

| seviye | davranış |
|---|---|
| `EXACT` | `regs_exact()`: memcmp + check_ids — mümkün olan en katı karşılaştırma |
| `NOT_EXACT` | precision kısa-devresi geçerli: `!rold->precise` her şeye uyar |
| `RANGE_WITHIN` | range/tnum mantığı çalışır, precision kısa-devresi **çalışmaz** |

Çağrı yerleri: ana budama yolu `loop ? RANGE_WITHIN : NOT_EXACT` seçiyor
(`:1405`, `loop = incomplete_read_marks(...)` — dikkat, "back-edge var mı" DEĞİL);
iterator yolları `RANGE_WITHIN` geçiyor (`:1333/:1358/:1364`); ve `EXACT` yalnız `:1372`'de,
**tek bir iş için**: sonsuz döngü tespiti — ki o da `"infinite loop detected at insn %d"`
basıyor. Bu, EXACT seviyesine girdiğimizi dışarıdan doğrulamanın tek yolu, ve aile bunu
işaretçi olarak kullanıyor.

### 2. Kurulan tahmin — ve ölçümün onu çürütmesi

Precision kısa-devresi `exact == NOT_EXACT`'a kapılı. Dolayısıyla 0050'nin sonucu (ölü bir
register verifier'a bir state budatıyor) `RANGE_WITHIN` olan her yerde geçerli OLMAMALI.
Eğer bir may_goto döngüsü RANGE_WITHIN seçiyorsa, aynı çift döngü içine konduğunda fark
kapanmalı.

**Ölçüm: kapanmıyor.** `loop.s6` tıpkı `flat.s6` gibi 2 state'e buduyor ve register hiç
geri-izlenmiyor; `loop.s7` ise ters yöne gidip **6 state** ve **50 geri-izleme** yapıyor.

Yani **bir döngünün içinde olmak tek başına RANGE_WITHIN seçtirmiyor** — kapı gerçekten
`incomplete_read_marks`, back-edge'in varlığı değil. Bunu kaynaktan okuduğumda belirsiz
olduğunu işaretleyip iddia etmemiştim; iyi ki, çünkü tahmin yanlıştı ve ölçüm düzeltti.
Test bunu kalıcı hâle getiriyor: `loop.s6` ile `flat.s6` **aynı** state sayısına buduyor,
ki karşılaştırmanın iki bağlamda da NOT_EXACT olduğunu söyleyen şey bu.

### 3. Sonuç

**5 program, 4 kabul / 1 red.** `inf.s6` reddediliyor **ve** `infinite_loop_detected=1` —
EXACT yoluna girdik. `store_locations_checked=32`, `runtime_writes_checked=32`,
`prune_pairs_checked=5`, `finding_count=0`, `parser_unrecognized=0`.

### 4. İki inşa hatası — ikisi de kernel'in kendi hata metninden teşhis edildi

**(i)** Koşulsuz `goto head` back-edge'i sonrasındaki her şeyi ulaşılamaz yapıyor:
*"Remove the unreachable instruction"*, `processed 0 insns`. `check_cfg` tek bir state
yürümeden reddediyor, yani EXACT yoluna hiç girilmiyor. Back-edge **koşullu** olmak
zorunda. Bunu teste bir guard olarak yazdım: `inf` kolu için `base_states >= 1` şart —
çünkü CFG reddi de `decision=reject` diyor ama sıfır state ile, ve kol sessizce anlamsız
hâle gelirdi.

**(ii)** `may_goto` **girişte** çıkabiliyor, dolayısıyla ilk kez döngü içinde atanan bir
register sıfır-iterasyon yolunda tanımsız: *"Initialize R7 on every path before this
instruction"*. 0043'te kararları belirleyen sıfır-iterasyon yolunun aynısı — bu sefer beni
ısırdı.

### 5. Payda

Bu ailenin ölçümü state sayıları, ama sıfır konum-paydasıyla "temiz" rapor etmek tam da
kendi eleştirdiğimiz şey olurdu. Kabul edilen programlar diğer her aile gibi çalıştırıldı;
payda 32.

`exact_level_calibration.rs` 6 test. Workspace 255 yeşil.

---

## 0052 — RANGE_WITHIN'e bilerek girmek (`--gen-rw`): tahmin ikinci kez çürüdü, ve enstrümanın sınırı bulundu

### 1. Nişanı düzeltmek

0051 bir may_goto döngüsünün RANGE_WITHIN seçtirmediğini ölçmüştü. Bu bacak, seviyeyi
**koşulsuz** geçen bir çağrı yerine nişan aldı — `states.c:1333`, iterator'ın next-call
instruction'ı. Kritik ayrıntı: o karşılaştırma **yalnız o instruction'a** uygulanıyor,
döngü gövdesindeki her insn'e değil. Dolayısıyla iki state'in **döngü başında** buluşması
gerekiyor, yani split döngüden ÖNCE olmalı. İçeride olsaydı çift sıradan bir
instruction'da karşılaşır ve yine ana NOT_EXACT yolunu ölçerdik.

### 2. Ölçüm

| kol | r7 geri-izleme | iter_active | base_states |
|---|---|---|---|
| flat.s7 | 19 | 0 | 3 |
| flat.s6 | 0 | 0 | 2 |
| iter.s7 | 64 | **14** | 8 |
| iter.s6 | 0 | **7** | 5 |

Ölü-register kolu iterator bağlamında **hâlâ birleştiriyor**, ve maliyet tam:
**aktif-iterator state sayısının yarısı** (7'ye 14). Precise kol register'ın iki değerini
de her iterator state'inde taşıyor, imprecise kol tek birleşik değer taşıyor — oran tam 2.

**4 program, 4 kabul**, `store_locations_checked=32`, `prune_pairs_checked=4`,
`finding_count=0`, `parser_unrecognized=0`.

### 3. Ama tahmin hâlâ çözülmedi — ve sebebi enstrümanın sınırı

`:1333`'ü sonuna kadar okuyunca kendi okumam düzeldi:

```c
if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
        ...
        if (iter_state->iter.state == BPF_ITER_STATE_ACTIVE) {
                loop = true;
                goto hit;          /* <- hit BUDAMA yolunun kendisi */
        }
```

Yani RANGE_WITHIN orada **budayabiliyor**. Ama blok `sl->state.branches` ile kapılı ve
tamamlanmış state'ler ana karşılaştırmaya (`:1405`, `loop ? RANGE_WITHIN : NOT_EXACT`)
düşüyor. **İkisi de bizim çiftimizi birleştirebilir, ve log hangisinin ateşlediğini
söylemiyor.** 2× oranı bir birleşmenin OLDUĞUNU kanıtlıyor; onu bir seviyeye
ATFEDEMİYOR.

**Bacağın asıl sonucu bu sınır:** dışarıdan işareti olan tek seviye EXACT
("infinite loop detected", 0051'de işaretçi olarak kullanıldı). *"X bağlamı Y seviyesini
seçer"* biçimindeki tahminler bu enstrümanla test edilemez. OI-14 olarak kapatıldı ki
üçüncü kez denenmesin. Ölçülebilir olan şey — birleşmenin olup olmadığı ve maliyeti —
teste yazıldı.

Seviye atfetmek kernel'in şu an basmadığı bir şeyi gerektiriyor; ucuz yolu yerel ağaca bir
debug yaması, ki bu da test edilen şeyi değiştirmek demek ve ayrı bir karar.

### 4. Testler

`range_within_calibration.rs` 7 test: iterator kollarının gerçekten iterator kullandığı
(yoksa karşılaştırma iki düz-çizgi programı arasında olurdu), flat temel çizgisinin aynı
capture'da bulunması, **2:1 oranı**, **sınırın test olarak yazılması** (hiçbir kol
seviyeyi ilan etmiyor, log seviyeyi asla adlandırmıyor), oracle'ların paydayla sessizliği,
diş, ve parser kör noktası yok. Workspace 262 yeşil.

---

## 0053 — dynptr slice'ları (`--gen-dyn`): iki parçalı güvenlik sözleşmesi, ve TAZE yüzeyde ilk bacak

### 1. Dördüncü pivot: olgun yüzeyden taze koda

0043-0052 verifier'ın en zırhlı bölgelerini taradı (ALU, range, pruning, state
karşılaştırması) ve on bacak temiz çıktı. Reviewer'la yapılan strateji kontrolünde iki
**dik** eksen ayrıldı: **yüzey** (olgun ↔ taze) ve **üretim stratejisi** (adlandırılmış ↔
adlandırılmamış şekil). Yüzey değiştirmek birincisini çözüyor, ikincisini çözmüyor. Bu
bacak birincisi; kompozisyon jeneratörü ikincisi olacak.

Geçiş kararı, sıfır-bulgu sayısından **bağımsız** bir ölçütle sınandı: mevcut oracle'lar
dynptr'a ulaşmıyor — bu bir kapsama boşluğu ve geçen hafta bug bulmuş olsak da aynı
boşluk olurdu. Ölçüt geçti.

### 2. Neden burası: statik iddia ile gerçek sınır ayrı kaynaklardan

Verifier bir slice hakkında şunu kanıtlıyor (verifier.c:13729):
```c
regs[BPF_REG_0].mem_size = meta->arg_constant.value;   /* = buffer__szk */
regs[BPF_REG_0].type = PTR_TO_MEM | type_flag;
```
**Statik sınır ÇAĞIRANIN SABİTİ** — dynptr'ın uzunluğu değil, `size - offset` de değil.
Gerçek sınır runtime'da (helpers.c):
```c
u64 len = buffer__szk;
err = bpf_dynptr_check_off_len(ptr, offset, len);
if (err) return NULL;
case BPF_DYNPTR_TYPE_LOCAL: return ptr->data + ptr->offset + offset;
```
Yani güvenlik **iki parçalı bir sözleşme** ve hiçbir yarısı tek başına yetmiyor. Daha önce
hiçbir ailemizde iki yarının farklı yerlerden geldiği bir şekil olmamıştı. LOCAL bir
dynptr'da slice orijinal belleğin İÇİNE işaret ettiği için mevcut sentinel-geri-okuma
oracle'ı bileşimi uçtan uca gözlüyor — **yeni oracle yok, yalnız input yüzeyi değişti.**

### 3. Sonuç

**6 program, 5 kabul / 1 red**, `store_locations_checked=24`, `runtime_writes_checked=24`,
`prune_pairs_checked=6`, `finding_count=0`, `parser_unrecognized=0`.

| kol | karar | runtime slice | düşüş |
|---|---|---|---|
| o0.z8.k0 | kabul | ok | 0 |
| o0.z8.k7 | kabul | ok | 7 (slice'ın son byte'ı) |
| o0.z8.k8 | **red** | ok | — (statik off-by-one, `k == szk`) |
| o24.z8.k7 | kabul | ok | **31** (= 24+7, dynptr'ın son byte'ı) |
| o28.z8.k0 | kabul | **NULL** | none |
| o0.z64.k0 | kabul | **NULL** | none |

**Son iki satır bacağın bütün meselesi:** verifier 32 byte'lık bir dynptr üzerinde
`sz=64`'lük bir slice kanıtı basıyor (`R0=mem(id=2,parent_id=1,sz=64)` — log'da çıplak),
ve `off+szk > size` olan slice'ı da kabul ediyor. İkisinde de dayanağı yok; programı
güvende tutan tek şey runtime NULL. Biz de tam olarak onu gözlüyoruz.

`o24.z8.k7`'nin **31**'e düşmesi koordinat çevirisini doğruluyor: slice gerçekten
`data + offset` döndürüyor.

### 4. Capture'dan ÖNCE çözülen iki şey

**(i) Koordinat çevirisi.** Slice pointer'ın tabanı `map_value + dynptr_offset`; verifier
yalnız `mem(sz=N)` görüyor (map value ile ilişkisi yok), runtime gözlemi ise map value
koordinatında. Beş kez oracle varsayımından ısırıldıktan sonra bunu capture'dan önce
çözdüm: `STORE` satırı zaten generator provenansı, çeviriyi generator yapıyor
(`off + k`). Böylece sınanabilir kalan şey gerçek bir özellik oluyor — slice'ın tam
olarak `data + offset` döndürmesi.

**(ii) Helper id'si.** `BPF_FUNC_dynptr_from_mem` iki header'da da yok. `197` tahminimi
kernel'in kendi mapper'ından doğruladım (`FN(dynptr_from_mem, 197, ##ctx)`) — yanlış
helper id'si load hatası değil, **başka bir helper'ı çağırmak**.

### 5. Yol boyunca: program tipi kapısı

İlk capture'da **altı kolun altısı da** reddedildi — 0043'ün vakum tell'i (tek biçim
sonuç = yapısal sorun). Sebep, kaynağı okurken üstünden geçtiğim satırdı
(verifier.c:13737): `bpf_dynptr_slice_rdwr` **doğrudan paket yazımına izin veren** bir
program tipi istiyor. Kayda değer olan: kontrol *paket* yazımı hakkında ama **her** dynptr
tipini kapatıyor — paketle hiç ilgisi olmayan, map value üzerindeki LOCAL bir dynptr'ı
bile. Aile SCHED_CLS'e taşındı; `prune_load_once` artık `prune_load_typed` üzerinden
program tipi parametresi alıyor.

### 6. 0041'in tanığı taze yüzeyde bedelini ödedi

Burada NULL slice **tasarlanmış** bir sonuç, dal artefaktı değil — iki kol meşru şekilde
hiç store etmiyor. `executed` tanığı olmasaydı onların `store_off=none`'ı kol başına üç
kez `runtime_oob_write` ateşlerdi. 0041'in kaynakta çözdüğü belirsizlik, tamamen farklı
bir yönden yeniden geldi ve düzeltme tuttu. Bu, "belirsizliği diff'te tahmin etme,
kaynakta çöz" kuralının en iyi doğrulaması.

`dynptr_calibration.rs` 7 test. Workspace 269 yeşil.

---

## 0054 — Kompozisyon jeneratörü (`--gen-comp`): adlandırılmamış şekiller, ve geçerlilik ölçümle kapandı

### 1. Dördüncü pivotun ikinci yarısı

0053 yüzeyi değiştirdi (olgun → taze kod). Ama diğer ekseni değiştirmedi: o aile de dâhil
şimdiye kadarki **her** aile, bug sınıfını **adlandırabildiğim** şekilleri üretti.
Dolayısıyla "temiz" bugüne kadar yalnız *"yazmayı düşündüğüm şekillerde temiz"* demekti.
Bu jeneratör 0043-0053'te kurulan parçaları — link biçimleri, spill, ALU şekillendirme,
branch daraltma, sınırlı döngü, dynptr slice — **rastgele birleştiriyor**, oracle'lar
sabit tutularak.

### 2. Asıl zorluk oracle değil, GEÇERLİLİK

Rastgele uç uca eklenmiş bir program neredeyse her zaman reddedilir, ve reddedilen program
runtime oracle'larına hiç ulaşmaz — 0041-0050'nin sürekli bulduğu payda-sıfır tuzağının
bir katman yukarısı. Çözüm, programı bir byte dizisi değil **tipli bir BAĞLAM üzerinde
yürüyüş** olarak ele almak: her parça canlı durumdan ne **istediğini** ve ne **sağladığını**
bildiriyor, ve jeneratör yalnız gereksinimleri o an sağlanan parçaları öneriyor.

**Bağlam register tiplerinden fazlasını taşımak zorunda, ve sebebi dynptr** — parçaların
en zengin arayüzü onda. Verifier'ın id ile takip ettiği 16-byte'lık bir `STACK_DYNPTR` slot
çiftini tüketiyor, ve geriye çağıranın seçtiği bir sabit boyutlu `PTR_TO_MEM` **artı** map
value içinde slice tabanının karşılık geldiği bir **offset** veriyor. O son alan 0053'ün
koordinat çevirisinin genelleştirilmiş hâli: store'un bildirilen offset'i her zaman
sentinel geri-okumasının kullandığı koordinatta.

### 3. Geçerlilik sonucu — ve sıfırı yorumlanabilir kılan şey bu

**48 program, 29 kabul / 19 red.** Ama ham kabul oranı yanlış sayı; red meşru bir karar.
Doğru soru redlerin **semantik** mi (store gerçekten sınır dışı) yoksa **yapısal** mı
(jeneratör bozuk program üretti) olduğu:

| | |
|---|---|
| bounds kaynaklı red | **19** |
| yapısal red (tanımsız register / ulaşılamaz insn / geçersiz insn) | **0** |

Jeneratörün ürettiği **her** program yapısal olarak sağlam, ve kararını belirleyen tek şey
oracle'ın zaten sorduğu semantik soru. Reviewer'ın uyardığı arayüz-uyumluluğu problemi
tahminle değil ölçümle kapandı.

### 4. Sayılar

`store_locations_checked=205` — **herhangi bir runtime bacağının bugüne kadarki en geniş
paydası** (0041'de 170'ti). `runtime_writes_checked=205`, `prune_pairs_checked=48` (48
programın hepsi kernel-vs-kernel differential'ı için kullanılabilir),
`tnum_bounds_checked=421`, `finding_count=0`, `parser_unrecognized=0`.

### 5. Yenilik

Tarifler gerçekten kombinasyon: `spill,link,dynptr`, `spill,dynptr,spill,narrow`,
`shape,link,narrow,narrow,link`, `spill,link,link,spill,spill` — elle yazdığım hiçbir
ailenin üretemeyeceği şekiller. Test bunu sabitliyor: en az 20 farklı tarif, ve en az bir
tarif dynptr'ı başka iki parça türüyle birleştirmeli. Tek şekli 48 kez üreten bir jeneratör
diğer bütün testleri geçer ve hiçbir şey kanıtlamazdı.

### 6. Determinizm

Bir bulgu tekrarlanabilir olmak zorunda: yürüyüş tohumlanmış bir xorshift ile sürülüyor ve
her program kendi tohumunu basıyor, yani korpus yeniden üretilebilir ve tek bir program tek
başına oynatılabilir.

### 7. Bu "temiz"in anlamı

Bu, on bacaklık ekseninkinden farklı bir sıfır. Orada "adlandırdığım şekiller temiz"ti;
burada korpusun bir kısmı benim adlandırmadığım kombinasyonlardan oluşuyor. Hâlâ küçük bir
korpus (48 program) ve parça havuzu altı türle sınırlı — ama ilk kez ifade,
"düşündüklerim temiz"in ötesine geçiyor.

`composition_calibration.rs` 6 test. Workspace 275 yeşil.

---

## 0055 — Havuzu genişlet, korpusu büyüt: 9 parça, 192 program, 971 gözlem

### 1. Üç yeni parça

`alu32` (32-bit ALU), `iter` (açık iterator döngüsü — may_goto'dan farklı bir back-edge
mekanizması), `pkt` (paket pointer'ı, programın kendi kanıtladığı range ile).

**`pkt` bilerek bir OKUMA.** Store olsaydı gözlem kanalı map_out'tan pakete kayardı ve
bütün korpusun paylaştığı koordinat eşlemesi bozulurdu. Okuma, `PTR_TO_PACKET`'i ve
`find_good_pkt_pointers`'ın range takibini kompozisyona sokarken kanalı tek tutuyor ve
geriye taze bir skaler veriyor. Bağlam bir alan daha kazandı: **spill edilmiş ctx** —
`r1` yalnız girişte context tutuyor ve ondan önceki her helper çağrısı onu eziyor.

### 2. Geçerlilik sayacı ilk eklemede ateşledi — ve YANLIŞ ateşledi

Genişletilmiş havuzun ilk koşusunda sayaç **16 yapısal red** raporladı. İnceleyince
hepsinin `invalid access to map value` olduğu çıktı — bu bir **bounds** hatası, yapısal
değil. Benim `invalid ` kalıbım gevşekti ve semantik bir reddi yapısal saymıştı.

**Gerçek yapısal red: sıfır.** Yani üç yeni parça türü (endişelendiğim iterator slot'u ve
paket parçası dâhil) arayüz tasarımını bozmadı.

Ama ders sayacın kendisinde: **kurt masalı anlatan bir metrik, olmayan metrikten kötüdür.**
Sınıflandırma gevşek kalıptan **bilinen-semantik izin listesine** çevrildi — her red sebebi
sınıflandırılabilmeli, ve listede olmayan bir sebep korpusa güvenilmeden önce triyaja
zorluyor. Testte de böyle yazılı.

### 3. Verim sorunu ve düzeltmesi

İlk genişletilmiş koşu 192 programda yalnız **79** kabul verdi (%41; 0054'te %60'tı).
Sebep: yeni parçaların hepsi kanıtlanmış sınırı geçersiz kılıyor, dolayısıyla store çoğu
zaman sınırsız kalıp reddediliyor — ve **reddedilen program runtime oracle'ına hiç
ulaşmıyor.** Epilog artık sınır kanıtlanmamışsa store'dan önce dörtte üç olasılıkla bir
daraltma basıyor; dörtte bir bilerek bırakılıyor, çünkü red meşru bir karar ve red tarafı
olmayan bir korpus karar yüzeyini hiç sınamaz.

**Kabul 79 → 150 (%78).**

### 4. `reg32` kapsama açığı — parça eklemek yetmiyor

İlk genişletilmiş koşuda `reg32_checked = 0`, üstelik `alu32` en çok kullanılan parça (91
kez). Sebep: başlangıç skalerleri `BPF_W` yüklemesiyle geliyordu, yani üst 32 bit
sıfır-genişletilmiş — 32-bit görünüm 64-bit görünümle çakışıyor ve denetlenecek ayrı bir
şey kalmıyor. 0034'te bu ekseni sıfırdan kaldıran şey "üst-bilinmeyen" kurulumuydu.

Bir skaler artık **64 bit** yükleniyor, böylece alu32'nin üst-bilinmeyen bir operandı
oluyor. **`reg32_checked` 0 → 5.** Ders: bir parçayı havuza koymak ekseni açmaya yetmiyor;
parçanın üstünde çalışacağı **durumun** da doğru olması gerekiyor.

### 5. Sonuç

**192 program, 150 kabul / 42 red**, `store_locations_checked=971` (0054'te 205 —
**neredeyse 5 kat**), `runtime_writes_checked=971`, `prune_pairs_checked=192`,
`tnum_bounds_checked=1327`, `reg32_checked=5`, `finding_count=0`,
`parser_unrecognized=0`.

42 reddin hepsi semantik, üç farklı mesajda: `unbounded memory access` (24),
`math between map_value pointer and register with unbounded min value` (15),
`invalid access to map value` (3).

Test iki yeni guard kazandı: dokuz parçanın **hepsinin** yürüyüşten erişilebilir olduğu
(havuza konup hiç seçilmeyen bir parça dekordur), ve alt-register ekseninin gerçekten
canlı olduğu. Workspace 276 yeşil.

---

## 0056 — Kapsama-yönlendirmeli yürüyüş: çift değil ÜÇLÜ cephesi (%35 → %87)

### 1. Dördüncü sağlık metriği, ve ölçümün soruyu bir kat yukarı taşıması

Reviewer'ın eklediği metrik: "her parça erişilebilir" yetmez, çünkü hedeflediğimiz bug
sınıfları **iki ya da daha fazla özelliğin etkileşiminde** yaşıyor. Asıl soru, parça
kullanım sayısı değil, **parça-kombinasyon uzayının** ne kadarının gerçekleştiği.

Çözüm kurmadan önce ölçtüm, ve cevap tahmin edilenden iyi çıktı — ama sınırı bir kat
yukarı taşıdı:

| | uniform yürüyüş |
|---|---|
| bitişik sıralı çiftler | **79 / 79** erişilebilir (%100) |
| bitişik üçlüler | **235 / 679** (%35) |

Eksik iki çift (`dynptr→dynptr`, `iter→iter`) **tasarım gereği imkânsız** — `comp_can`
her ikisini program başına bir kez veriyor. Yani çift uzayı zaten doygun; cephe üçlüde.
Ve tarif uzunlukları 2–5'ti: **2 uzunluğundaki 48 program hiç üçlü üretmiyordu.**

### 2. Uniform yürüyüş → kapsama-yönlendirmeli yürüyüş

Korpus boyunca görülen bitişik çift/üçlü tabloları tutuluyor. Seçim sırası: önce
**görülmemiş bir ÜÇLÜ** tamamlayan parça, sonra görülmemiş bir çift, sonra herhangi biri.
Beraberlikler tohumlanmış RNG ile çözülüyor, yani yönlendirme **tekrarlanabilirliğe hiç
mal olmuyor** — korpus hâlâ tohumlardan yeniden üretilebilir. Tarifler 3'ten başlıyor.

**Üçlüler: 235 → 592 / 679 (%35 → %87).** Aynı 192 program.

### 3. Yönlendirme her sayıyı birden iyileştirdi

| | önce | sonra |
|---|---|---|
| kabul | 150 / 192 | **169 / 192** |
| `store_locations_checked` | 971 | **1033** |
| `tnum_bounds_checked` | 1327 | **1867** |
| `reg32_checked` | 5 | **13** |
| bitişik üçlü | 235 (%35) | **592 (%87)** |

23 reddin hepsi semantik (`math between…unbounded` 8, `unbounded memory access` 8,
`invalid access to map value` 7), **yapısal red sıfır**. `finding_count=0`,
`parser_unrecognized=0`.

Bu, beklenmedik bir yan etki değil: daha çeşitli kombinasyonlar daha çeşitli register
durumları üretiyor, o da hem daha çok programı kabul edilebilir kılıyor hem de daha çok
invariant kontrolünü besliyor. Kapsama sürüşü yalnız çeşitliliği değil **paydayı** da
büyütüyor.

### 4. Yol boyunca

Kapsama tabloları ilk denemede `enum comp_piece`'ten **önce** yerleşti ve derleme
`CP_PIECE_N undeclared` verdi — bu oturumda üçüncü kez aynı sıralama tuzağı
(0045'te `LOOPR_INPUTS`, 0054'te `BPF_FUNC_dynptr_from_mem`). VM bayat binary'yi koştu ve
sayılar birebir aynı çıktı; **değişmeyen sayı, değişikliğin uygulanmadığının tell'i** oldu.

### 5. Guard

Metrik kalıcı teste çevrildi: her tarif en az 3 parça (2'lik tarif üçlü üretmez), bitişik
çiftler tam 79, bitişik üçlüler en az 500. Bir sonraki parça eklendiğinde izlenecek dört
sayı: yapısal red 0, her parça erişilebilir, her eksen sayacı sıfırı terk etmiş, ve
**kombinasyon kapsaması düşmemiş.**

`composition_calibration.rs` 8 test. Workspace 277 yeşil.

---

## 0057 — Onuncu parça: subprog çağrısı, ve metrik-4'ün göreliye çevrilmesi

### 1. Parça: `call` — havuzdaki tek YAPISAL yeni şey

Diğer dokuz parça tek bir frame içinde çalışıyor. `call` ikinci bir **frame** açıyor, ve
`states_equal` frame'leri ayrı ayrı karşılaştırıyor. 0048 skaler link id'lerinin sınırı
geçtiğini ölçmüştü; kompozisyonda bu artık önceki parçaların kurduğu **her** id yapısıyla
rastgele karşılaşıyor.

Callee argümanını daraltıp döndürüyor, yani caller'ın sonra dayandığı sınır **başka bir
frame'in içinde** kanıtlanmış oluyor — parçanın havuzda olma sebebi tam olarak bu.

Yapısal risk gerçekti: çağrı insn'i sonradan yamalanıyor (callee ana gövdenin son
exit'inden sonra ekleniyor, adresi ancak o zaman biliniyor). **Sıfır bozuk program üretti**
— 54 reddin hepsi semantik.

### 2. Metrik-4 düştü, tam da öngörüldüğü gibi

10 parça / 192 program: **çiftler 97/97 (%100)**, ama **üçlüler 645/916 (%70)** —
9 parçadaki %87'den. Mutlak sayı *arttı* (592 → 645); oran düştü çünkü erişilebilir uzay
**N³** ile büyüdü (679 → 916).

Bu, reviewer'ın keskinleştirmesinin somut kanıtı: **metrik-4 mutlak eşik olamaz.** Sabit
bir eşik her parça eklemesinde sahte alarm verirdi, üstelik gerçekleşen üçlü sayısı
artarken. Guard artık gözlenen parça setinden hesaplanan **erişilebilir uzaya oran**:
çiftler tam kapsanmalı, üçlüler erişilebilirin en az %85'i. `comp_can`'in program başına
bir kez verdiği parçalar (`dynptr`, `iter`, `call`) erişilebilir sayımından düşülüyor —
tekrarları yapı gereği imkânsız, kapsama aleyhine sayılmamalı.

### 3. Korpus parçayla büyüdü: 192 → 320

| metrik | 9 parça / 192 | 10 parça / 192 | **10 parça / 320** |
|---|---|---|---|
| yapısal red | 0 | 0 | **0** |
| çiftler | 79/79 | 97/97 | **97/97 (%100)** |
| üçlüler | 592/679 (%87) | 645/916 (%70) | **877/916 (%96)** |
| kabul | 169/192 | 155/192 | **266/320** |
| `store_locations_checked` | 1033 | 974 | **1740** |
| `tnum_bounds_checked` | 1867 | 2273 | **3808** |
| `reg32_checked` | 13 | 7 | **12** |

`finding_count=0`, `parser_unrecognized=0`. 54 reddin hepsi semantik
(`unbounded memory access` 30, `math between…unbounded` 13,
`invalid access to map value` 11).

### 4. Yol boyunca

Yama deseni iki aile tarafından paylaşıldığı için ilk düzenleme benzersiz eşleşmedi ve
**hiçbir şey yazılmadan** durdu (assert). Kompozisyona özgü satıra çapalayıp tekrarladım.
Bu, sessizce yanlış aileyi düzenlemekten iyi bir başarısızlık modu.

`composition_calibration.rs` 8 test. Workspace 277 yeşil.

---

## 0058 — Onbirinci parça: SKB dynptr (ikinci dynptr TİPİ), korpus 448

### 1. Parça

`bpf_dynptr_from_skb` — `bpf_kfunc_check_set_skb` içinde ve `BPF_PROG_TYPE_SCHED_CLS`'e
kayıtlı (filter.c:12879), yani ailenin tipiyle doğrudan erişilebilir. BTF id'leri
çözüldü: `from_skb=82823`, `slice_ro=82836`, `slice_rdwr=82837`.

0053'ün LOCAL dynptr'ı bir map value üzerine kuruluyordu; bu **skb üzerine** kuruluyor,
yani slice farklı bir tip bayrağı taşıyor (`get_dynptr_type_flag`) ve skb yolundan
gidiyor — verinin doğrusal olmayabildiği, slice'ın pakete işaret etmek yerine çağıranın
tamponuna **kopyalayabildiği** yol.

**Salt-okunur `bpf_dynptr_slice` bilerek seçildi, iki sebeple:** `rdwr` varyantının hiç
kurmadığı `MEM_RDONLY` bayrağını açıyor, ve pakete yazamadığı için gözlem kanalını map
value'da tutuyor. `CP_PKT`'nin okuma olmasıyla aynı gerekçe — bir paket yazımı bütün
korpusun paylaştığı koordinat eşlemesini bozardı.

### 2. Dört sağlık metriği

| | 10 parça / 320 | **11 parça / 448** |
|---|---|---|
| yapısal red | 0 | **0** (57 reddin hepsi semantik) |
| her parça erişilebilir | 10/10 | **11/11** (`dynskb` 202 programda) |
| eksen sayaçları | reg32 12, tnum 3808 | **reg32 25, tnum 5452** |
| çiftler | 97/97 | **117/117 (%100)** |
| üçlüler | 877/916 (%96) | **1185/1207 (%98)** |
| kabul | 266/320 | **391/448** |
| `store_locations_checked` | 1740 | **2560** |

`finding_count=0`, `parser_unrecognized=0`.

Bu sefer kapsama **düşmedi bile** — 0057'de 10. parça eklendiğinde %87'den %70'e inip
korpus büyütülerek %96'ya çıkmıştı; burada korpus parçayla birlikte büyütüldüğü için
metrik hiç gerilemedi (%96 → %98). Kural işliyor: **havuz büyürse korpus da büyümeli**,
çünkü erişilebilir üçlü uzayı N³ ile artıyor (916 → 1207).

### 3. Memory yeniden yapılandırıldı

Operasyonel bir sorun kapatıldı: `MEMORY.md` 53.6 KB'ye ulaşmış ve limitin (24.4 KB) iki
katını aştığı için **kısmen yükleniyordu** — yani bir sonraki oturum eksik bilgiyle
açılacaktı. Tek bir 51.770 karakterlik satır (0025-0057 birikimli checkpoint) sorunun
tamamıydı.

Dönem dosyalarına bölündü — `state-of-play` (özet + dört sağlık metriği + triyaj kuralı,
önce okunacak), `harness-gotchas` (birden fazla kez ısıran operasyonel tuzaklar), ve dört
dönem dosyası (consistency / runtime-oracle / state-comparison / composition). İndeks
artık **1.8 KB**, giriş başına tek satır.

---

## 0059 — Onikinci parça: ringbuf dynptr — havuzdaki ilk REFERANS özelliği

### 1. Neden bu parça

Havuzdaki on bir parçanın hepsi **sınır** hakkında. Ringbuf rezervasyonu **referans**
hakkında: verifier, rezervasyonun **her yolda** serbest bırakıldığını kanıtlamak zorunda,
yoksa program referans sızdırıyor ve reddediliyor. Tek parçada üç yeni şey geliyor —
üçüncü bir dynptr tipi (RINGBUF), yeni bir map tipi, ve pooldaki ilk *bounds-dışı*
doğruluk özelliği.

Helper id'leri kernel'in kendi mapper'ından: `reserve_dynptr=198`, `submit=199`,
`discard=200`; üçü de `bpf_base_func_proto`'da, yani tüm program tiplerinde.

### 2. Capture'dan önce çözülen tuzak

`bpf_dynptr_slice` `KF_RET_NULL`, yani null kontrolü gerekiyor. O dal programın çıkışına
gitseydi rezervasyon **submit edilmeden** çıkılırdı ve verifier bu parçayı içeren **her**
programı sızıntı diye reddederdi — jeneratörün kendi ürettiği bir kusur, test edilen bir
özellik değil. Null dalı submit'e yönlendirildi, böylece her yol rezervasyonu bırakıyor.

Sonuç bunu doğruladı: **hiç "Unreleased reference" reddi yok**, 84 reddin hepsi bounds.
237 program referans alıp bırakıyor, on bir başka parça türüyle rastgele birleşmiş hâlde.

### 3. Dört sağlık metriği

| | 11 parça / 448 | **12 parça / 576** |
|---|---|---|
| yapısal red | 0 | **0** |
| parça erişilebilirliği | 11/11 | **12/12** (`ringbuf` 237 programda) |
| eksen sayaçları | reg32 25, tnum 5452 | **reg32 24, tnum 6809** |
| çiftler | 117/117 | **139/139 (%100)** |
| üçlüler | 1185/1207 (%98) | **1544/1558 (%99)** |
| kabul | 391/448 | **492/576** |
| `store_locations_checked` | 2560 | **3129** |

`finding_count=0`, `parser_unrecognized=0`.

### 4. Diş testi kırılgandı ve düzeltildi

Suite kırmızıya döndü: diş testi sabit `store_off=63` ekiyordu ve artık ateşlemiyordu.
Sebep bir bulgu değil, testin kendi varsayımı — seçilen programın kanıtlanmış penceresi
63'ü **meşru olarak** kapsıyordu (daraltma sınırı 15 ise store tabanı 48, pencere [48,63]).
Sabit bir değer "kesin dışarıda" değil.

Ekim artık programın **kendi bildirdiği** store offset'inden türetiliyor: bir byte altı.
`admits()` landing site'ın tabanda ya da üstünde olmasını istediği için (`v >= 0`), bu
değer negatif olmayan her pointer offset'i için kanıtlanabilir şekilde dışarıda. Diş
korpus değiştikçe kırılmayacak.

Ayrıca yapısal-red izin listesine `Unreleased reference` eklendi: bir sızıntı verifier'ın
değil **jeneratörün** kusuru olurdu, o yüzden semantik değil yapısal sayılmalı.

`composition_calibration.rs` 8 test. Workspace 277 yeşil.

---

## 0060 — Onüçüncü parça: refcounted socket — referans, bu sefer bir POINTER üzerinden

### 1. Parça

0059 referans takibini havuza bir **dynptr** üzerinden sokmuştu; bu onu bir **pointer**
üzerinden sokuyor. `bpf_sk_lookup_tcp` `PTR_TO_SOCKET_OR_NULL` döndürüyor ve bir
`ref_obj_id` taşıyor, `bpf_sk_release` onu tüketiyor.

O id dekor değil: `regsafe`/`stacksafe` onu `check_ids`'ten geçiriyor — yani bu parça,
0046 ve 0047'nin düz skalerlerle sınadığı **aynı id-eşleme makinesine** refcounted bir
pointer sokuyor. Havuzdaki iki referans parçası artık aynı özelliği iki farklı taşıyıcıda
sınıyor.

Erişilebilirlik ve id'ler kaynaktan: `FN(sk_lookup_tcp, 84)`, `FN(sk_release, 86)`, ve
ikisi de `tc_cls_act_func_proto` içinde (filter.c:8720, 8724) — yani SCHED_CLS'ten
erişilebilir.

### 2. Referans hiçbir yola sızmıyor

Acquire → oku → release, ve null yolu ikisini de atlıyor. Bu doğru, sızıntı değil: NULL
bir referans taşımıyor, dolayısıyla o yolda release'i atlamak kuralın kendisi. 0059'un
ringbuf'ında null dalı submit'e yönlendirilmek zorundaydı (rezervasyon *alınmıştı*);
burada tam tersi geçerli, ve ayrımı parça bazında düşünmek gerekiyor.

Sonuç doğruladı: **hiç "Unreleased reference" reddi yok**, 109 reddin hepsi bounds.

### 3. Dört sağlık metriği

| | 12 parça / 576 | **13 parça / 704** |
|---|---|---|
| yapısal red | 0 | **0** |
| parça erişilebilirliği | 12/12 | **13/13** (`skref` 267 programda) |
| eksen sayaçları | reg32 24, tnum 6809 | **reg32 15, tnum 8626** |
| çiftler | 139/139 | **163/163 (%100)** |
| üçlüler | 1544/1558 (%99) | **1937/1975 (%98)** |
| kabul | 492/576 | **595/704** |
| `store_locations_checked` | 3129 | **3981** |

`finding_count=0`, `parser_unrecognized=0`.

`reg32_checked` 24'ten 15'e düştü — sayaç sıfırı terk etmeye devam ediyor (metrik-3
geçiyor) ama dalgalanıyor, çünkü hangi programların 32-bit görünümü ayrıştıracak duruma
ulaştığı rastgele yürüyüşe bağlı. İzlenecek şey sıfır olup olmadığı; mutlak değeri değil.

### 4. Yol boyunca

Koşu 600 saniyeyi aştı ve arka plana alındı — 704 program, ve `loop` parçası her
test_run'da may_goto'nun 250 ms'lik zaman bütçesini harcıyor. Bu artık ölçeklemenin
maliyet sürücüsü: korpus büyüdükçe TIMEOUT onunla birlikte artmalı (704 program ~2400s
bütçeyle koştu).

---

## 0061 — KALİBRASYON: oracle gerçek bir verifier hatasını yakalıyor mu? (İki kör nokta bulundu)

### 1. Neden bu iş birincildi

On sekiz bacak, sıfır kernel bulgusu. Her bacakta oracle'ın **bizim ektiğimiz** ihlalde
ateşlediğini kanıtladık; hiçbirinde **kernel'in gerçekten sahip olduğu** bir hatada
ateşlediğini görmedik. O kanıt olmadan sıfır iki şeyden hangisi olduğunu söylemiyor:
bpf-next bu yüzeylerde sağlam mı, yoksa oracle'ın kör noktası mı var.

### 2. Hedef seçimi

Ağaçta 2022 sonrası verifier soundness fix'leri tarandı. Seçilen:
**`3844d153a41a` — "bpf: Fix insufficient bounds propagation from
adjust_scalar_min_max_vals"** (2022-07-01, Kuee K1r0a bildirmiş):

> *"a corner case where the **tnum becomes constant** … but the register's **bounds are
> not** … This in turn **allows to leak pointers** through turning a pointer register as is
> into an unknown scalar via `adjust_ptr_min_max_vals()`."*

Üç sebeple ideal: (a) gerçek bir **soundness** hatası (over-rejection değil), (b) imzası
tam olarak otuz bacaktır koşturduğumuz özellik, (c) commit **kernel'in kendi bastığı
hatalı state'i** içeriyor — yani kernel derlemeden yarısı test edilebilir.

```
before:  9: (07) r3 += -32767  ; R3_w=scalar(imm=0,umax=1,var_off=(0x0; 0x0))   <--- [*]
after:   9: (07) r3 += -32767  ; R3_w=scalar(imm=0,umax=0,var_off=(0x0; 0x0))
```

### 3. İlk ölçüm: oracle bu hatayı GÖREMİYORDU

Hatalı state pipeline'a verildi: **`tnum_bounds_checked=0`, `finding_count=0`,
`parser_unrecognized=0`.** Payda sıfır, ve sessiz. İki ayrı kör nokta çıktı, her biri tek
başına hatayı görünmez kılmaya yeterdi:

**(i) Parser eski register biçimini tanımıyordu.** Eski kernel'lar `R3_w=` basıyor (`_w` =
bu insn tarafından yazıldı); `looks_like_reg_token_start` yalnız `R<rakam>=` kabul
ediyordu. Hiçbir state parse edilmiyor, payda sessizce sıfırlanıyor,
`parser_unrecognized` 0 kalıyor — payda kuralının yakalamak için var olduğu şeklin ta
kendisi, yeni bir yönden. *(Kendi fixture'larımızda sıfır `_w` var, yani mevcut
sonuçlarımız etkilenmiyor — bu tam olarak bir kalibrasyon engeli.)*

**(ii) Invariant yeterince güçlü değildi.** Kontrolümüz yalnız tnum aralığının
`[umin,umax]` ile **kesiştiğini** sınıyordu. Hatalı state'te aralık [0,0], bounds [0,1] —
**kesişiyorlar**, yani state parse edilse bile kontrol sessiz kalırdı. Eksik olan, kernel'in
kendi `reg_bounds_sanity_check`'inde aynı adla bulunan daha güçlü özellik: **sabit bir
tnum bounds'u sabitlemek zorunda.**

Üstelik `tnum_bounds_checkable` gate'i `mask != 0` şartı koyuyordu — yani sabit tnum'lu
register'lar kontrolden **tamamen dışlanıyordu**.

### 4. Düzeltme ve sonuç

`_w` biçimi parse ediliyor; `const_tnum_range_mismatch` eklendi (kernel'in kendi adıyla),
gate'i "üst sınır BASILMIŞ olmalı" (basılmamış `umax` = U64_MAX, onu gerçek sınır saymak
her sabit-var_off register'ında yanlış ateşlerdi).

**İki taraflı kalibrasyon geçti:**
- hatalı state → `const_tnum_range_mismatch`, **insn 9 r3** — commit'in `<--- [*]` ile
  işaretlediği yer, birebir.
- düzeltilmiş state → **sessiz**. İkisinde de ateşleyen bir kontrol hiçbir şey kanıtlamazdı.

### 5. Güçlü invariant mevcut korpusta ne yaptı

**704-program kompozisyon korpusu: `finding_count=0`**, ama `tnum_bounds_checked`
8626 → **16326** (sabit-tnum durumu paydayı neredeyse ikiye katladı). Yani bpf-next
daha güçlü kontrol altında da temiz, ve o sıfır artık belirgin biçimde daha fazlasını
söylüyor.

**Syzkaller korpusu 0025'in bir iddiasını revize etti.** Guard ateşledi ("re-measure
before trusting any 'clean'") ve doğru ateşledi: payda 0 → **357**. 0025'in tespiti
(*"syzkaller'ın skalerleri ya tam bilinen ya tam bilinmeyen, hiç kısmi bilinen değil"*)
**kesişim** kontrolü için hâlâ doğru — o hâlâ sıfır alıyor. Ama sabit yarı farklı bir
erişilebilirlik sorusu: *tam bilinen* skaler tam da bu korpusun dolu olduğu şey. 357
değerlendirme, **0 bulgu** — "hiçbir şeye erişmiyor"dan daha güçlü bir ifade.

### 6. Kalıcı hale getirildi

`calibration.rs` 4 test, fixture'lar `fixtures/calibration/` altında (kernel'in kendi
çıktısı, commit'ten birebir alıntı): gerçek hatanın yakalandığı, düzeltmede sessiz
kalındığı, eski register biçiminin sessizce kaybolmadığı, ve **kesişimin yetmediğinin**
özellik olarak sabitlendiği. Workspace 281 yeşil.

### 7. Ne değişti, dürüstçe

Kalibrasyondan önce: 18 bacak sıfır bulgu, anlamı belirsiz.
Kalibrasyondan sonra: oracle bu sınıftaki **gerçek bir soundness hatasını yakalıyor** —
ve o yeteneği ancak bugün kazandı, çünkü iki kör noktası vardı. Bu, sıfırı belirsizlikten
çıkarıp bilgiye çeviren şey; ve iki kör noktanın varlığı, kalibrasyonun neden birincil iş
olduğunun kanıtı.

---

## 0062 — Kalibrasyonun ikinci yarısı: gerçek bug hangi INPUT'un önemli olduğunu söyler

### 1. Kalibrasyon iki şey verir, biri gözden kaçmıştı

0061 birinci yarıyı yaptı: gerçek bir bug'a karşı **oracle** test edildi, iki kör nokta
çıktı. İkinci yarı şu: bir bug raporu aynı zamanda **hangi input şeklinin o sınıfı
ürettiğini** söylüyor. Kernel yamalı olsa bile o şekli üretmek, sınıfa kalıcı bir dedektör
bırakıyor.

### 2. Aday taraması

Ağaçta 2020 sonrası, commit mesajında register state **alıntılayan** verifier soundness
fix'leri tarandı: 23 aday. Dördü doğrudan bizim iddialarımızı sınıyor —
`f2d67fec0b43` (CVE-2020-8835, 0035'in hedefi), `049c4e13714e` (alu32 const subreg),
`af9e89d8dd39` (`sync_linked_regs` id korunumu, 0046/0047), `3878ae04e9fc` (linkli
register'lar arası delta, 0049).

### 3. CVE-2020-8835 commit mesajından kalibre EDİLEMİYOR

İlk hedef oydu, çünkü 0035'in merkezî iddiası *"desync zaten invariant B'dir"*. Ama 2020
formatındaki log **hiç 32-bit alan basmıyor** (aynı ölçüm 2023 commit'inde 12 alan
buluyor). İnvariant B tnum32'yi u32 sınırlarıyla karşılaştırıyor; o alanlar yoksa
karşılaştıracak bir şey de yok.

Yani bu hedef **eski kernel derlemesi gerektiriyor** — 0061'de çizdiğim sınırın tam
olarak öbür tarafı: "bir bug'ın imzası commit mesajından okunamıyorsa ancak o zaman kernel
derle". Park edildi, sebebiyle birlikte.

*(2020 formatı ayrıca `inv`/`invP`, `umin_value=`, boşluksuz `var_off=(0xA;0xB)` kullanıyor
— parser'ın tanımadığı üçüncü bir biçim ailesi. O da kernel derleme kararına bağlı.)*

### 4. `3878ae04e9fc` bizde bir kapsama açığı buldu

Bug: `sync_linked_regs` **32-bit** bir delta'yı 64-bit'miş gibi yayıyor. `known_reg =
0xFFFFFFFF`, delta 1 iken verifier `0x100000000` diyor; gerçek değer 0'a sarıyor. Commit'in
kendi ifadesiyle *"can lead to accepting a program with OOB access"*.

Bu **consistent-but-wrong** sınıfı — verifier'ın state'i kendi içinde tutarlı, sadece
yanlış. Consistency invariant'ları göremez; runtime store-location oracle'ı görür.

Ve asıl mesele: **0049'un delta kolu yalnız alu64 kullanıyordu.** Delta aritmetiğini
*değerle* sabitlemiştik ama 32-bit biçimi hiç üretmemiştik — bug'ın yaşadığı şekli.

Fix ağacımızda (HEAD 2026-09-03, fix 2024-10), yani bedava bir bug yok. Ama şekil eklendi:
`SPL_DELTA32`, `--gen-spill` 8 → **12 kol**. Sonuç: 6 kabul / 6 red,
`store_locations_checked=48`, `finding_count=0`. alu32 linki alu64'le **aynı** [12,19]
sınırını üretiyor, id `1+12` olarak basılıyor.

**Dürüst kapsam:** kol 32-bit delta *link şeklini* kapsıyor, gerçek bug'ın ihtiyaç duyduğu
*sarma tetikleyicisini* (taban 2³²'ye yakın) değil. Bu bir sonraki incelik, ve teste öyle
yazıldı — kapsıyormuş gibi göstermek, kapsamamaktan kötü olurdu.

### 5. Ders

Gerçek-bug kalibrasyonu iki ayrı çıktı veriyor ve ikisi de değerli: **oracle** tarafında
kör nokta (0061'de iki tane), **input** tarafında kapsama açığı (burada bir tane). İkincisi
kernel yamalı olsa bile kazanç, çünkü sınıfa dedektör bırakıyor. Workspace 282 yeşil.

---

## 0064 — İkinci kalibrasyon çifti: enstrüman gerçek hatayı, onu içeren kernel üzerinde yakaladı

### 1. Neden bu sefer kernel derlemek gerekti

`3844d153a41a` commit mesajından kalibre edilebilmişti çünkü tutarsız state **normal
register state'i olarak** basılıyordu. `92424801261d` öyle değil: bozulan register'lar
(`true_reg2`, `false_reg1/2`) `reg_set_min_max`'in içinde yaşıyor ve normal state olarak
hiç basılmıyor — yalnız kernel'in kendi *"REG INVARIANTS VIOLATION"* mesajında görünüyorlar.

Yani tespit kanalı parse edilmiş state değil, **verdict**: 0042'nin üçüncü yüklemesi,
`BPF_F_TEST_REG_INVARIANTS`'ın `reg_bounds_sanity_check`'i uyar-ve-toparla'dan sert
`-EFAULT`'a çevirdiği yer. Bunu sınamak, hatalı kernel'ı **çalıştırmayı** gerektiriyor.

### 2. Kurulum

`92424801261d~1`'de park edilmiş bir git worktree, ve `build-kernel.sh` artık `SRC`/`OUT`
alıyor — iki kernel **aynı config'le** derleniyor, çünkü karşılaştırma ancak yalnız fix'te
farklıysa anlamlı.

Yolda bir tuzak: script `[ -d "$SRC/.git" ]` kontrol ediyordu, ama `.git` bir clone'da
**dizin**, bir worktree'de **dosya**. Build anında reddetti. Yeniden kullanılan varsayımın
yeni kullanımda kırılması — bu projenin imza hatası, bu sefer altyapı katmanında.

### 3. Tetikleyici

Commit'in kendi disassembly'sinden transkribe edildi: bilinmeyen skaleri 31 bite maskele,
bit 1'i kur, sonra **bit 1'i kapalı** bir sabitle eşitlik karşılaştır. False dalı
matematiksel olarak imkânsız (`0x7ffffffd` = 1111…1101) ama verifier onu yine de analiz
ediyor, ve o analiz sahte register'ı bozuyor.

### 4. Sonuç — iki taraflı

| | hatalı kernel | düzeltilmiş kernel |
|---|---|---|
| `base_verdict` | accept | accept |
| `inv_verdict` | **reject, errno 14 (EFAULT)** | accept, reason none |
| kernel ihlal bildirdi mi | **evet** | hayır |
| pipeline `finding_count` | **1 — `reg_invariants_violation`** | **0** |

Kernel'in kendi mesajı commit'tekiyle birebir çıktı:
```
REG INVARIANTS VIOLATION (true_reg2):  range bounds violation u64=[0x7fffffff, 0x7ffffffd]
REG INVARIANTS VIOLATION (false_reg2): const tnum out of sync with range bounds
```
İkisi de bizim invariant'larımızın kernel'daki adları — ve ikincisi **0061'de eklemek
zorunda kaldığımız** özellik.

### 5. Dürüst kapsam

Bu, **REG_INVARIANTS kanalını** uçtan uca doğruluyor. Parse-edilmiş-state invariant'
larımızın bu hatayı yakalayacağını **göstermiyor** — yakalayamazlar, çünkü bozulan
register'lar state olarak hiç basılmıyor. İki bug, iki kanal; birinin sonucu ötekine
geçmiyor. Teste de böyle yazıldı.

### 6. Kalibrasyonun durumu

İki bağımsız çift, iki farklı kanal:

| çift | kanal | kaynak |
|---|---|---|
| `3844d153a41a` (0061) | `const_tnum_range_mismatch`, basılı state | commit mesajı |
| `92424801261d` (0064) | `reg_invariants_violation`, verdict | **gerçek kernel koşusu** |

`calibration.rs` 7 test, `scripts/run-calibration.sh` ikisini de koşturuyor.
Workspace 285 yeşil.

---

## 0065 — Üçüncü kalibrasyon çifti: invariant doğruydu, oracle LOG'U okuyamıyordu

### 1. Hedef

`049c4e13714e`, "bpf: Fix alu32 const subreg bound tracking on bitwise operations"
(2021-05, Manfred Paul bildirmiş). `scalar32_min_max_and/or/xor()` 32-bit sınır
güncellemesini `scalar_min_max_*()`'a devrediyordu, ama o yalnız **iki 64-bit register de
sabitse** gerçekten güncelliyor. Alt yarısı sabit, tamamı sabit olmayan bir register'da
32-bit sınırlar bayat kalıyor — ve commit'in kendi log'u onları imkânsız bir durumda
gösteriyor:

```
önce:  ...,s32_min_value=1,s32_max_value=0,u32_min_value=1,u32_max_value=0)
sonra: ...,s32_min_value=0,s32_max_value=0,u32_min_value=0,u32_max_value=0)
```

`u32_min > u32_max` **boş kümeyi** gösteriyor. `u32_bounds_inverted` ve
`s32_bounds_inverted` 0026'dan beri bu pipeline'da duruyor ve bunu görür görmez yakalar.

### 2. Üçüncü tip kör nokta

| çift | kör nokta |
|---|---|
| `3844d153a41a` (0061) | oracle'da **özellik eksikti** |
| `92424801261d` (0064) | durum hiç basılmıyor → başka bir **kanal** gerekti |
| `049c4e13714e` (0065) | özellik vardı ve doğruydu. Oracle **log'u okuyamıyordu.** |

2021 kernel'ı SCALAR_VALUE'yu `inv` yazıyor (precise ise `invP`), sınırlarını da
`umin_value=` / `u32_min_value=` diye. Böyle her register pointer koluna düşüyor,
`reg_type` olarak `"inv"` alıyor, **32-bit görünümünü tamamen kaybediyor** ve sonra her
skaler kontrol tarafından atlanıyor.

Fix kapalıyken bu fixture üzerinde ölçüldü: `finding_count=0`, `parser_unrecognized=0`,
`tnum_bounds_checked=0`, `reg32_checked=0`. Tam sessiz değil — her kayıt bir
`parse_notes` girdisi taşıyordu (`unrecognized reg-type form: inv`) — ama hiçbir şey bir
parse note'una bakmıyor, ve manşet sayılar temiz bir geçiş gibi okunuyor. Asıl işaret
**paydaların sıfıra çökmesiydi**: 0025 kuralı dördüncü kez işini yaptı.

Düzeltme sonrası: buggy → **6 bulgu** (üç bağımsız invariant × iki kol), fixed → **0**.
Üç invariant: `u32_bounds_inverted`, `s32_bounds_inverted`, ve `tnum32_bounds_inconsistent`
— kesişim kontrolü bu sefer **yetiyor** (0061'de yetmiyordu, orada bozuk span sınırların
İÇİNDE oturuyordu).

### 3. Ölçüm kapsamı: commit mesajı byte-birebir DEĞİL

`print_verifier_state`'i o revizyonda okudum: `umax_value` `%llu` ile basılıyor, hex
`(0x...)` şerhi hiç yok, ve `smin_value` yalnız `umin_value`'dan farklıysa basılıyor.
Commit'teki log **genişletilmiş**. Bu yüzden her fixture ikinci bir program taşıyor,
`-omitted`: kernel'in kendi atlama kurallarına göre kaynaktan **mekanik olarak türetilmiş**,
ve alıntı değil türetme diye etiketlenmiş.

Asıl önemli kol o: hatanın imzası atlamalardan **sağ çıkıyor** (`u32_min_value=1` ≠
`umin_value=0` olduğu için basılıyor), yani tespit commit mesajının biçimlendirmesinin
bir yan ürünü değil.

### 4. Ve eksik payda — bu bacağın asıl bulgusu

Dört sıralama kontrolü (`umin <= umax` ve kardeşleri) bilerek kapısız: ters bir aralık
kendi başına bir çelişki, karşılaştıracak ikinci bir izleyiciye ihtiyacı yok. Ama bu
aynı zamanda **hiçbir şeyin onları saymadığı** anlamına geliyordu — 35 bacak boyunca
"ters aralık yok", paydasız. 0025'in ortadan kaldırmak için yazıldığı belirsizliğin
aynısı.

`bounds_order_checked` artık ateşlenebilecek her karşılaştırmayı sayıyor. Atlanmış bir
sınır kendi ekstremumuna çözülür ve bir ekstremum uç asla diğerinin ters tarafında
olamaz — o yüzden yalnız iki ucu da ekstremumdan uzak olan karşılaştırmalar sayılıyor
(`tnum_bounds_checkable`'ın sabitler için yaptığı tautoloji ayıklamasının aynısı).

Cevap utandırıcı değil, rahatlatıcı çıktı:

| korpus | `bounds_order_checked` | bulgu |
|---|---|---|
| `gen-comp-704` | **26336** | 0 |
| `gen-mixed-396` | 5152 | 0 |
| `gen-multibranch-242` | 4765 | 0 |
| `gen-regreg-242` | 4143 | 0 |
| `syz-replay-184` | 539 | 0 |

Toplam ~58 bin. Yani "ters aralık yok" 0/0 değildi — 0/58000'di. Sadece kimse saymamıştı.
Dikkat: kompozisyon korpusunda bu sayı `tnum_bounds_checked`'ten (16326) **büyük** —
projedeki en geniş payda.

### 5. Bir tuzak daha, bu sefer kendi çalışma yöntemimde

Dişleri sınamak için parser fix'ini geçici kapatıp geri yükledim — ama geri yüklediğim
yedek, üç yeni parser unit testini eklemeden ÖNCE alınmıştı. Testler sessizce kayboldu.
İşaret: workspace sayısı 293 → 290. **Bir yedekten geri yükleme, yedek alındığından beri
yapılan her şeyi geri alır** — stale-binary ipucunun editör hâli.

### 6. Durum

Üç bağımsız çift, üç ayrı kör nokta tipi. `calibration.rs` 12 test + 3 parser unit testi,
hiçbiri VM istemiyor. Workspace 293 yeşil.

---

## 0066 — Payda kuralını alışkanlıktan GUARD'a çevirmek: üç paydasız invariant daha, biri hiç koşmamış

Reviewer'ın 0065 üzerine önerisi: "yeni bir invariant eklenirken paydası tanımlanmadan CI
geçmesin. Yoksa 40. bacakta dördüncü bir paydasız-invariant çıkar."

Haklıydı — ama tahmininden fazlası çıktı: **üç tane.**

### 1. Kuralın deliği

0025'in duran kuralı "sıfır paydada sessiz kalma" idi. 0065 gösterdi ki kuralın
göremediği bir delik var: bir invariant **hiç payda tanımlanmadan** eklenebiliyor, ve o
zaman kural ateşlenemiyor bile — bakılacak bir sayaç yok.

Diff aşamasının bütün bulgu türlerini denetledim. 19 türden 4'ü (0065'te düzelttiğim
sıralama kontrolleri) zaten paydasızdı. Kalanlarda üç tane daha:

| bulgu | ne zamandan beri paydasız |
|---|---|
| `tnum_malformed` | ilk bacaktan beri |
| `reg_invariants_violation` | 0042'den beri — **kalibrasyon çift-2'nin sertifikaladığı kanal** |
| `jit_interp_divergence` | başından beri |

### 2. `jit_interp_divergence` — asıl yakalanan

Bu invariant **hiçbir kaydı hiç incelememiş**. `verifier_log.rs` `jit_interp_diff`'i
koşulsuz `None` yapıyor (`// v0: ALWAYS_ON kernel, no interp`). Yani projenin aldığı her
capture'da bu bacağın sessizliği bir kanıt yokluğu — 0025'in ortaya çıkarmak için
yazıldığı şeklin ta kendisi, kırk bacak boyunca gözden kaçmış çünkü kimse saymamış.

Düzeltilmedi, **sabitlendi**: `jit_interp_checked` sıfır olduğunu bildiriyor, ve test
bunu bilinen bir boşluk olarak pinliyor ("bir interpreter kanalı doğduğunda bu assert
ters döner ve testi gerçek bir payda istemek üzere yeniden yaz").

### 3. Ölçüm — ve iki yeni sayacın söyledikleri

| korpus | `tnum_wellformed` | `reg_invariants` | `jit_interp` |
|---|---|---|---|
| `gen-comp-704` | 351 | **595** | 0 |
| `gen-mixed-396` | 422 | 0 | 0 |
| `gen-pkt-242` | 330 | 0 | 0 |
| `gen-pktcmp-240` | **0** | 0 | 0 |
| `syz-replay-184` | **0** | 0 | 0 |

İki şey çıktı:

**(a)** Well-formedness kontrolü sandığımdan çok daha ince: 704 programda 351. Çünkü
`value & mask` ancak bir register aynı anda hem bilinen-1 bitleri hem bilinmeyen bitleri
taşıyorsa sıfırdan farklı olabilir, ve çoğu durum ikisinden biri. **Dokuz aile bu
kontrolde tam sıfır alıyor** — iki syzkaller korpusu ve 240 programlık paket-karşılaştırma
süpürmesi dahil. Onların "bozuk tnum yok"u baştan beri 0/0'dı.

**(b)** `reg_invariants_checked=595` — kompozisyon korpusunun kabul sayısı. Yani
0064'te sertifikaladığımız VERDICT kanalı bu korpusta 595 kez gerçekten koşmuş, ve
temiz. Bu sayı olmadan o "0 ihlal" hiçbir şey demiyordu.

### 4. Guard

`INVARIANT_DENOMINATORS`: her bulgu türü → paydası olan sayaç. Test kendi kaynağını
(`src/diff.rs`) tarıyor, her `kind: "..."` literalini çıkarıyor ve kayıt defterinde
olmayanı reddediyor. Ters yön de kapalı: artık üretilmeyen bir tür için kayıt kalırsa o
da hata (kapsam hakkında artık doğru olmayan bir iddia).

Dişler sınandı: `tnum_malformed`'ı `brand_new_uncounted_check` diye yeniden adlandırdım,
iki test de doğru mesajla düştü. Yorum satırları taranmıyor — bu dosyanın kendi metni
aradığı deseni içeriyor, ve onu yutan bir tarayıcı hayalet tür bildirirdi.

### 5. Bu kuralın olgunlaşma çizgisi

- **0025**: payda diye bir şey olduğunu keşfet.
- **0025-0064**: her yeni bacakta payda ekle (alışkanlık).
- **0065**: alışkanlığın dört invariant'ı atladığını fark et.
- **0066**: alışkanlığı guard'a çevir — atlamak artık derlenmiyor.

Workspace 299 yeşil.

---

## 0067 — Dördüncü kalibrasyon çifti: ilk kez kör nokta YOK, ve 32-bit hatayı 32-bit invariant göremiyor

### 1. Hedef, ve tek satırlık hata

`ae67b9fb8c4e`, "bpf: Fix truncation bug in coerce_reg_to_size_sx()" (2024-10). İşaret
genişletmeli bir mov'dan sonra verifier yeni sınırları **zincir atama** ile yazıyordu:

```c
reg->umin_value = reg->u32_min_value = s64_min;
```

Bu, önce `u32_min_value = (u32)s64_min` (kesme), sonra `umin_value = u32_min_value`
demek — 64-bit sınır, zaten kesilmiş 32-bit'ten türetiliyor. Fix sadece sırayı
değiştiriyor.

Ama aynı fonksiyon `var_off = tnum_range(s64_min, s64_max)`'i **kesilmemiş** değerlerden
kuruyor. Yani hatalı durum:

```
tnum  : [0xfffffffffffffffe, 0xffffffffffffffff]
sınır : [0xfffffffe,         0xffffffff]
```

İki küme **ayrık**. Ve ayrık tnum-vs-sınır bu projenin **en eski** invariant'ı —
`tnum_bounds_inconsistent`, ilk bacaktan beri diff aşamasında.

### 2. Sonuç: ilk kez tamir gerekmedi

| | |
|---|---|
| buggy | **1 bulgu**, `tnum_bounds_inconsistent`, insn 3 r0 |
| fixed | **0** |

Üç çift üç ayrı delik bulmuştu (eksik özellik / yanlış kanal / okunamayan format).
Dördüncü hiçbiri bulmadı — ve bu ancak ilk üçü bulduğu için bir anlam taşıyor. En eski
kontrol ölü ağırlık değilmiş.

### 3. Sezgiye aykırı kısım — ve asıl ders

Bu bir **32-bit kesme** hatası. 0026'nın 32↔64 invariant'ları buna **kör**:
`reg32_checked` her iki yarıda da 0.

Sebep hatanın kendisi: 64-bit sınırı alt yarısına kesmek iki görünümü **birebir aynı**
yapıyor, ve `reg32_checkable` 32-bit görünümü 64-bit'in söylemediği bir şey söylemeyen
register'ları dışarıda bırakıyor. Bozulma, o kontrolün aradığı anlaşmazlığı **silmiş
oluyor**.

Kanıtı taşıyan şey, kesmeden etkilenmemiş **64-bit tnum**. "32-bit kontrolleri 32-bit
hatalara nişanla" tam olarak çıkarılmaması gereken ders — testle sabitlendi.

### 4. Provenance

Bu sefer buggy yarı **yeniden kurma gerektirmiyor**: commit'in log'u zaten kendi
kernel'ının bastığı formatta (2024 log.c, bizim capture aldığımızın aynısı; eksik
`umax32=` U32_MAX olduğu için normal kuralla bastırılmış).

Fixed yarı ise hiç alıntı değil: `--probe-sx` commit'in kendi disassembly'sini güncel
kernel'da üç genişlikte üretiyor, capture aynen giriyor. Gerçek çıktı:

```
3: (bf) r0 = (s8)r0  ; R0=scalar(smin=smin32=-2,smax=smax32=-1,
                                 umin=0xfffffffffffffffe,umin32=0xfffffffe,
                                 var_off=(0xfffffffffffffffe; 0x1))
```

Fix'in içeriği tam burada okunuyor: 64-bit sınır tam genişliğini koruyor, 32-bit olan
onun kesilmişi.

### 5. Durum

Dört çift, dört farklı sonuç: eksik özellik, yanlış kanal, okunamayan format, ve **tamir
gerektirmeyen bir doğrulama**. `calibration.rs` 15 test. Workspace 302 yeşil.

---

## 0068 — Beşinci kalibrasyon çifti: ilk kez cevap bir SINIR — bu enstrüman bu sınıfı göremez

### 1. Hedef

`af9e89d8dd39`, "bpf: Preserve id of register in sync_linked_regs()" (2026-01).
`sync_linked_regs()`'in delta kolu `copy_register_state(reg, known_reg)` çağırıp sonra
yalnız `off` ve `subreg_def`'i geri koyuyordu. Üstündeki yorum zaten *"Must preserve off,
id and add_const flag"* diyordu — kod id'yi korumuyordu.

```
r1 = r0        ; ikisi de id=1
r1 += 4        ; r1 → id=1+4
if r1 < 10 ... ; sync r1'in sınırlarını r0'a taşıyor AMA r0'a ADD_CONST damgası da vuruyor
r2 = r0        ; assign_scalar_id_before_mov ADD_CONST görüyor → r0'a YENİ id
```

Link kopuyor. Sonra r1 için bulunan sınırlar r0'a hiç ulaşmıyor.

### 2. Neden bizim enstrümanımızın dışında — ve asıl bulgu bu

Ortaya çıkan durum **kendi içinde tutarlı**: r0 gerçekte [10,255] iken [6,255] taşıyor.
Bu bir **aşırı-yaklaşım**, yani sağlam bir verifier'ın üretmesine izin verilen şey. Hata
bir **fazladan-reddetme**, unsoundness değil.

Bu projenin bütün invariant'ları iç-tutarlılık kontrolü. Hiçbir şeyle çelişmeyen bir
durumda hiçbiri ateşlenemez. **Tartışılmadı, ölçüldü:**

| | buggy | fixed |
|---|---|---|
| trigger | **reject, "div by zero"** | accept |
| control | accept | accept |
| pipeline bulgu | **0** | **0** |
| `tnum_bounds_checked` | 14 | 23 |
| `bounds_order_checked` | 53 | 68 |
| `prune_pairs_checked` | 2 | 2 |
| `reg_invariants_checked` | 1 | 2 |

Sessizlik **paydalı**. 0065/0066'nın satın aldığı tam olarak bu: "sessiz" değil,
"14+53+2+1 değerlendirilmiş kontrolde sessiz" diyebiliyorum. Paydasız olsaydı bu leg
0025 tuzağına düşmüş olurdu.

Kernel'in kendi denetçisi de sessiz: `inv_verdict=reject inv_errno=22 inv_reason=verdict`
— sıradan reddin aynası, `-EFAULT` değil. Yani **çift-2'yi yakalayan kanal bunu
yakalayamıyor.**

### 3. Kontrol kolu

Trigger'dan tek bir instruction farkla: ikinci link (`r2 = r0`) yok. Her iki kernel'da da
kabul ediliyor. Eğer o da flip etseydi, flip kopuk link hakkında olmazdı ve kol hiçbir şey
kanıtlamazdı.

### 4. Gören kanal — ve onun dürüst sınırı

Gören şey **verdict**, kernel SÜRÜMLERİ arasında. Ama: iki kernel sürümünün bir verdict'te
anlaşmaması **normaldir** — hassasiyet her sürümde değişir. Yani bir flip ancak hangi
tarafın hata olduğunu zaten biliyorsan kanıttır.

**Sürüm-farkı bir kalibrasyon aleti, bir av oracle'ı değil.** Bu çiftin kurduğu şey bir
sınır — ve delik bulmak yerine sınır kuran ilk çift.

### 5. Log'da görünen ama çelişki olmayan fark

```
buggy  5: (bf) r2 = r0 ; R0=scalar(id=2,...)
fixed  5: (bf) r2 = r0 ; R0=scalar(id=1,...)
buggy  6: ...          ; R1=scalar(id=1+4,umin=14,...)          ← R0 güncellenmiyor
fixed  6: ...          ; R0=scalar(id=1,umin=10,...) R1=...     ← taşınıyor
```

Fark **görünür**, ama çelişki değil. `id=2` kendi içinde tutarlı; yalnız *daha iyi bir
verifier'ın aynı programla yaptığı şeye* göre yanlış. Bu sınıf için bir dedektör başka bir
invariant değil, bir **referans** ister.

### 6. Sonraki için: girdi ŞEKLİ

0062'nin dersi — gerçek bir bug hangi input'un önemli olduğunu da söyler. Buradaki şekil:
**link → sabit ekle → linkli register üzerinde dallan → temel register'dan İKİNCİ bir link
kur.** Hiçbir ailemiz bunu üretmiyor. `--probe-idlink` şimdilik şekli sabitliyor;
kompozisyon havuzuna bir `relink` parçası olarak eklemek kendi bacağını hak ediyor.

### 7. Durum

Beş çift, beş farklı cevap: eksik özellik, yanlış kanal, okunamayan format, tamir
gerektirmeyen doğrulama, ve **görüş alanı dışında bir sınıf**. `calibration.rs` 18 test.
Workspace 305 yeşil.

---

## 0069 — Ondördüncü parça `relink`: şeklini gerçek bir bug'ın adlandırdığı ilk parça — ve dişleri tuttu

### 1. Nereden geldi

0068'in ikinci getirisi bir girdi şekliydi: **link → sabit ekle → linkli üye üzerinde dallan
→ TEMEL register'dan İKİNCİ bir link kur.** Hiçbir ailemiz bunu üretmiyordu. Artık
kompozisyon havuzunda 14. parça.

Parça bütün diziyi kendisi üretiyor, yürüyüşün doğru register'a bir `narrow` koymasını
ummuyor — CP_NARROW'un hangi register'ı seçtiği rastgele, ayrı parçalar hâlinde şekil
neredeyse hiç kurulmazdı.

Ve **karar-ilgili** olacak şekilde kuruldu: epilogue'un store offset'i İKİNCİ (daha dar)
sınırdan hesaplanıyor, o sınır da temele ancak linki hayatta kaldıysa ulaşıyor.

### 2. Dört sağlık metriği

| metrik | sonuç |
|---|---|
| 1 — yapısal red = 0 | 121 red, hepsi bounds. Biri **yeni bir sebep**: `min value is negative`. Delta-link temele negatif `smin` veriyor (`rB=rA; rB+=4`, rB'ye sınır → rA `smin=-4`). Bounds sorusu; **triyaj edilip** allowlist'e girdi. |
| 2 — her parça erişilebilir | 14/14 |
| 3 — her eksen sayacı sıfırı terk ediyor | store_loc=4560, tnum=22650, order=40214, wellform=753, prune=896, reginv=775, reg32=25 |
| 4 — kombinasyon kapsaması | çiftler **190/190**, üçlüler **2461/2504 (%98)** |

896 program, 775 accept / 121 reject, `findings=0`, `parser_unrecognized=0`, 895 farklı tarif.

### 3. Parçanın kendi diş testi — ve bu bacağın asıl sonucu

Korpusun **tamamı iki kernel'da koşturuldu**: bpf-next ucu ve `af9e89d8dd39~1`'den aynı
config'le derlenmiş olan. Tohuma göre eşleştirildi:

| | |
|---|---|
| tohumla eşleşen program | **896** |
| iki kernel'da tarif aynı | **896** (jeneratör kernel'dan bağımsız — karşılaştırma anlamlı) |
| verdict çevrilmesi | **7** |
| …tarifinde `relink` olan | **7** |
| …olmayan | **0** |
| yön | hepsi accept → reject |

**Özgüllük tam, duyarlılık düşük — ikisi de dürüst.** `relink` içermeyen 598 programın
hiçbiri çevrilmedi: korpusta bu hataya duyarlı başka hiçbir şey yok. 298 relink
programından yalnız 7'si çevrildi, çünkü şekil karara ancak relink son sınır-kuran parça
olduğunda ve epilogue store pointer'ını sınıfın temelinden kurduğunda ulaşıyor. Rastgele
kompozisyon jeneratörünün doğası bu: şekil garantiyle değil, bir oranla var.

### 4. Mekanizma, elle doğrulandı (a-b-c triyajı)

Aynı instruction'larda, yan yana — ve bu **jeneratörün yazdığı** bir program, elle
transkribe edilmiş bir selftest değil:

```
fixed  65: if r9 > 0x10 ; R6=scalar(id=8,...umax=12)   ← temel sınıf üzerinden daraldı
       66: r7 = r6      ; R6=scalar(id=8,...umax=12)   ← id 8 KALDI
       67: if r9 > 0xf  ; R6=scalar(id=8,...umax=11)   ← ve daha da daraldı
       69: *(u8 *)(r8+52), R8 umax=11 → 52+11 = 63, son geçerli bayt   ACCEPT

buggy  66: r7 = r6      ; R6=scalar(id=9,...) R7=scalar(id=9,...)  ← id YENİDEN BASILDI
       67: if r9 > 0xf  ; R6 hiç güncellenmiyor — link gitti
       69: aynı store 52+12 = 64'e ulaşıyor, 64 baytlık değerin bir bayt ötesi   REJECT
```

Bir baytlık sınır. Commit'in kendi anlattığı hikâye, bizim ürettiğimiz bir programda.

### 5. Kendi hatalarım — ikisi de bu bacakta

**(a) `jexit` taşması.** `relink` paylaşılan atlama-yaması tablosuna parça başına **iki**
giriş yazıyor; her mevcut parça bir tane yazıyordu ve tarif 8 parçaya çıkabiliyor.
`jexit[16]` bir parça uzağındaydı ve taşma **hiçbir teşhis vermezdi**. Sınır artık
jeneratörün kendi sabitinden türetiliyor: `jexit[2 * COMP_MAXSTEPS + 4]`. Ders: **bir
havuza parça eklerken, tüketicilerin ESKİ en-kötü-duruma göre boyutladığı her paylaşılan
sabit kaynağı denetle.**

**(b) Silinen `CP_SKREF` case'i.** `comp_can`'e `CP_RELINK` eklerken kullandığım
çok-satırlı string anchor `CP_SKREF` case'ini kapsıyor ve siliyordu; parça
`default: return 0`'a düşüp havuzdan kayboldu (267 → 0). Bütün öbür sayılar sağlıklıydı —
**metrik 2 yakaladı** ("seçilmeyen parça dekorasyondur"). Kalıcı refleks: string-replace
ameliyatından sonra `git diff | grep '^-'` ve her silmeyi oku.

### 6. Bir maliyet notu

Korpus fixture'ı 17MB; `.git` 21MB'a çıktı ve her korpus yenilemesi yeni bir blob ekliyor.
Korpus tohumlardan yeniden üretilebilir (her program seed'ini basıyor) ama bu VM koşusu
ister; fixture'ı pinlemek test paketini hermetik tutuyor. İki kernel'lık korpuslar
commit'lenmedi — çevrilen 7 program her iki kernel'dan ayrı bir fixture olarak pinlendi
(200KB).

Workspace 307 yeşil. Runner: `scripts/run-comp-diff.sh`.

---

## 0070 — Parser üç sessiz körlük daha; ve altıncı kalibrasyon çifti tahminimi çürüttü

Bu bacak iki parçadan oluşuyor ve ikisi de aynı dersin farklı yüzü: **enstrümanın neye
baktığını sandığın ile gerçekte neye baktığı arasındaki fark.**

### BÖLÜM 1 — Parser denetimi: üç sessiz kayıp

Parser'ı kernel'in `log.c`'sine karşı sistematik denetledim. Üç gerçek kayıp çıktı, üçü de
**sessiz** — hiçbir hata, sadece eksik payda.

**(1) `to caller at N:` — subprogram dönüş durumu.** `print_verifier_state()` her
register'ı bir **boşlukla** başlatıyor (`verbose(env, " R%d", i)`), yani başlığı newline ile
biten her durum dökümü girintili bir satıra düşüyor. Parser'ın ilk satırı
`if line.starts_with(' ') { continue; }` — liveness gürültüsünü atmak için. Bütün sınıfı
atıyordu. **Bir çağrı sınırındaki register transferi YALNIZCA orada basılıyor.**
Kompozisyon korpusunda 1962 satır.

İndeksi olan alınıyor, olmayan alınmıyor: `to caller at %d:` indeksi söylüyor; `caller:`,
`callee:`, `returning from callee:` söylemiyor ve onlara indeks uydurmak, store-konumu
kontrolüne verifier'ın hiç yapmadığı bir iddiayı beslemek olurdu.

**(2) `from A to B:` — budama noktası dökümleri.** `verbose(env, "\nfrom %d to %d%s:",
env->prev_insn_idx, env->insn_idx, ...)` ardından `print_verifier_state(print_all=true)`.
**B tam olarak `env->insn_idx`** — durumun ait olduğu instruction, yani atıf çıkarım değil,
log'un kendi söylediği şey. Ve `print_all=true` olduğu için sadece scratched olanları değil
**bütün canlı register'ları** taşıyor: satır-başı düzeyinde log'daki en zengin anlık
görüntü. Başlık (`from 33 to 15`) hepsi-rakam olmadığı için düşüyordu. Korpuslarda
**5851 satır**.

Ve bu yalnız kayıp payda değil, **yanlış-bulgu riskiydi**: store-konumu kontrolü store'u
verifier'ın gerçekte yaptığı iddiaların bir **alt kümesiyle** karşılaştırıyordu.

**(3) `rdonly_mem` ve akrabaları.** `log.c:435-443` set edilmiş her tip bayrağını isim
önüne yapıştırıyor (`rdonly_ ringbuf_ user_ percpu_ rcu_ untrusted_ trusted_`), ve
PTR_TO_BTF_ID'nin tabanı `ptr_` + struct adı — hiç `btf_id` diye basılmıyor.
`base_family` bunların hiçbirini soymuyordu, dolayısıyla sıradan bir salt-okunur dynptr
slice'ı **896 kaydın 634'ünde** "bilinmeyen aile" notu üretiyordu. Bu hacimde kalıcı bir
not, notsuzluktan kötüdür: gerçekten yeni bir şeklin içinde aranması gereken gürültü tam
olarak budur.

**Ölçülmüş etki** (`gen-comp-896`): `tnum_bounds_checked` 22650 → **25955**,
`bounds_order_checked` 40214 → **45668**, "unrecognized" notu 634 → **0**, bulgu 0.
Bütün ailelerde paydalar arttı ya da aynı kaldı; hiçbirinde düşmedi.

### BÖLÜM 2 — Altıncı çift: `811c363645b3`, ve yanlış çıkan tahmin

`check_stack_write_fixed_off()` 64-bit `BPF_ST_MEM`'in immediate'ini
`__mark_reg_known(&fake_reg, (u32)insn->imm)` ile izliyordu. `insn->imm` bir s32 — cast
**işareti düşürüyor**: `-44` → `4294967252`.

```
buggy  1: *(u64 *)(r2 -40) = -44 ; fp-40_w=4294967252
       2: r0 = *(u64 *)(r2 -40)  ; R0_w=4294967252
fixed  1: *(u64 *)(r2 -40) = -44 ; fp-40=-44
       2: r0 = *(u64 *)(r2 -40)  ; R0=-44
```

**Tahmin** (benim ve bağımsız bir tarama geçişinin, aynı biçimde): `r0` büyük pozitif bir
sabit gibi göründüğü için `if r0 s< 0xa` yanlış görünür, verifier programın 1 döndürdüğünü
kanıtlar — oysa değer gerçekte -44, dal gerçekte alınır, program gerçekte 0 döner. Retval
oracle'ı için temiz bir isabet.

**Gerçekte olan:** hatalı kernel'da gözlenen dönüş değeri **1** — yanlış kanıtla birebir
uyumlu.

Sebep: verifier dalı **statik** çözdüğü için öbür tarafı hiç yürümüyor, ve
`bpf_opt_hard_wire_dead_code_branches()` (`kernel/bpf/fixups.c:564`) bir tarafı hiç
`seen` olmayan her koşullu atlamayı `JA`'ya çeviriyor — yani dal **çalışan programdan
çıkarılıyor**.

> **Runtime oracle'ının referansı, verifier'ın ÜRETTİĞİ programdır; gönderilen program
> değil.** Etkisi yanlış bir STATİK DAL ÇÖZÜMÜ olan her hata ona yapısal olarak
> görünmezdir: yanlış inanç yayılan koda gömülür, gözlem de yanlış kanıtla uyuşur.

Bu, 0068'inkinden **daha keskin** bir sınır. Orada durum yalnızca gerçekten genişti.
Burada enstrümanın kendi yer gerçeği, hatayla uyuşacak şekilde yeniden yazılmış.

Ve bir muhakeme kalıbını da geçersiz kılıyor: sonucu "erişilebilir kodun dead-code
rewrite'ı" diye tarif edilen her tarihsel düzeltme bu sınıfta — commit mesajı bozuk durumu
ne kadar temiz alıntılarsa alıntılasın.

**Payda ile birlikte ölçüldü:** hatalı yakalamada `runtime_checked=2`, `finding_count=0`.
Yani kontrol **koştu ve geçti**. Sessizlik "kimse bakmadı" değil; oracle programı
değerlendirdi ve tutarlı buldu — çünkü program tutarlı olacak şekilde yeniden yazılmıştı.

**Kontrol kolu** (`+44`, cast'ten etkilenmeyen pozitif immediate) iki kernel'da da 1
döndürüyor. Fark özellikle kaybolan işarete ait.

### Ne yakalardı

Farklı bir **referans**. Üretilen bir program için harness sonucu verifier'dan bağımsız
biliyor — bu program kapalı formda: -44 yaz, geri oku, -44 < 10, 0 döndür. Gözlenen
retval'i verifier'ın iddiası yerine **jeneratörün beklentisiyle** karşılaştırmak bunu
görünmezden tek satırlık bir kontrole çeviriyor. Bacağın ileriye dönük çıktısı bu.

Workspace 313 yeşil. Runner: `scripts/probe-spill.sh`.

---

## 0071 — Referansı verifier OLMAYAN ilk oracle: jeneratörün kendi beklentisi

### 1. 0070'in bıraktığı boşluk

0070 yapısal bir sınır ölçtü: bu projedeki **her** oracle ya verifier'ı kendisiyle
karşılaştırıyor, ya da bir runtime gözlemini **verifier'ın kendi bastığı iddiayla**
karşılaştırıyor. Bir hata verifier'ı kendi içinde tutarlı biçimde yanıltıyorsa ve dead-code
hard-wiring o inancı yayılan koda gömüyorsa, bütün aile yapısal olarak kör.

Çemberi kırmanın tek yolu referansı dışarıdan almak. Ve kapalı formda üretilmiş bir program
için harness cevabı zaten **program metninden** biliyor.

### 2. Ne eklendi

`EXPECT intended_retval=N` — jeneratörün, verifier'a hiç danışmadan, programın ne
döndürmesi gerektiğine dair kendi iddiası. `check_runtime_intent` gözlenen dönüş değerini
onunla karşılaştırıyor. Payda: `runtime_intent_checked` (0066 guard'ı zaten bunu zorunlu
kılıyordu — kayıt defterine girmeden derlenmiyor).

Token bilerek `retval=` diye adlandırılmadı: `parse_runtime_samples` onu her boşlukla
ayrılmış token'da önek olarak arıyor, ve bu proje iki kez tam bu sınıftan hata yayınladı
(0041, 0042).

### 3. Sonuç — 0070'in görünmez dediği yakalamanın ta kendisinde

| | hatalı kernel | düzeltilmiş |
|---|---|---|
| `runtime_checked` (eski oracle) | **2** | 1 |
| eski oracle bulgusu | **0** | 0 |
| `runtime_intent_checked` (yeni) | **2** | 2 |
| yeni oracle bulgusu | **1** — beklenen 0, gözlenen 1 | 0 |

**İki payda da aynı yakalamada sıfırdan farklı.** Gösterilen şey bu: bu, eski oracle'ın
*ulaşamadığı* bir vaka değil — **ulaştığı ve göremediği** bir vaka.

Kontrol kolu (`+44`) kendi farklı beklentisini taşıyor (`intended_retval=1`) ve iki
kernel'da da onu karşılıyor — yani oracle sabit bir değer üzerinden kazara geçmiyor.

### 4. Dürüst maliyet: referans artık bizim kodumuz

Bu oracle'ın referansı jeneratör, yani kendi yazdığımız şey. Yanlış bir beklenti **yanlış
bir bulgu** üretir — tıpkı yanlış bir `STORE` bildiriminin store-konumu kontrolü için
yapacağı gibi. Bu yüzden triyaj sırası koda yazıldı: (1) jeneratörün beklentisi yanlış,
(2) harness tarif ettiğinden başka bir program koşturdu, (3) verifier semantiğini yanlış
anladığı bir programı kabul etti. **Yalnız üçüncüsü bir kernel bulgusu.**

Ve kapsamı dar tutuldu: `intended_retval` `Option`, çoğu aile bir iddia edemez, ve
uydurulmuş bir beklenti hiç yoktan kötüdür.

### 5. Sıradaki

Bu oracle şu an yalnız `--probe-spill`'de. Kapalı formda sonuç üretebilen her aile onu
bedavaya kullanabilir; kompozisyon jeneratörü için ise iddia ancak tarif kapalı-form
kaldığı sürece kurulabilir — bir sonraki bacağın sorusu bu.

Workspace 316 yeşil.

---

## 0073 — Bağımsız referans interpreter, ve onun kalibrasyonu

### 1. Neden

0070'in ölçtüğü sınır yapısaldı: bu projedeki her oracle'ın referansı **kernel'in kendisi**.
Verifier kendi içinde tutarlı biçimde yanılırsa ve
`bpf_opt_hard_wire_dead_code_branches()` o inancı yayılan koda gömerse, ailenin tamamı
sessiz kalıyor. Çıkış yolu tek: ISA'nın **ikinci bir uygulaması**.

Ajan raporu bu sınıfın nadir olmadığını gösterdi: 11 yılda 13 sağlam örnek, ama **son 34
ayda 6 tanesi, dördü tek bir ayda (Nisan 2026)**, en yenisi 29 günlük. İkisinin commit
mesajında birebir *"verifier-vs-runtime mismatch"* geçiyor. 2019-2023 kohortunun tamamı
**tek bir fuzzer** tarafından, **saf kapalı-form skaler programlarda** bulunmuş — yani şekil
yönlendirilmiş bir jeneratörle erişilebilir.

### 2. `harness/bpfref.h`

Emitlenen `struct bpf_insn` dizisini yorumluyor — **jeneratörün niyetini değil**. İki kural:
emitter'larla hiç kod paylaşmıyor, ve tek girdisi komut akışı. Jeneratör kastettiğinden
başka bir şey emitlerse, interpreter baytları izler.

Kapsam: ALU/ALU64 (K ve X), MOV/MOVSX, JMP/JMP32, LD_IMM64, stack LDX/STX/ST (MEMSX dahil),
EXIT. Dışındaki her şey tahmin edilmiyor, `UNSUPPORTED` diye bildiriliyor.

### 3. Ve kalibrasyonu — asıl mesele

**İkinci bir uygulama ancak birincinin haklı olduğu her yerde onunla uyuşuyorsa değerlidir.
Yanlış bir ikinci uygulama her programı yanlış bulguya çevirir.** O yüzden yargılamadan
önce yargılandı: saf bir uygulamanın saptığı 16 nokta program olarak emitlendi, **hem
bpfref'te hem gerçek kernel'da** koşturuldu, hepsinin uyuşması şart koşuldu.

```
16 verdict=agree
```

Tuzaklar egzotik oldukları için değil, ilk denemede yanlış yapıldıkları için seçildi:
32-bit ALU'nun (MOV ve NEG dahil) koşulsuz sıfır-genişletmesi; `MOV|K`'nin iki ALU sınıfı
arasında işaret-genişletme farkı; JMP32'nin yalnız alt yarıyı karşılaştırması; `x/0 = 0` ve
`x%0 = x`; `S64_MIN sdiv -1 = S64_MIN`; minimumun negasyonunun sarması; DW immediate
store'un s32'yi **işaret-genişletmesi** (811c363645b3'ün verifier tarafında yanlış yaptığı
kuralın ta kendisi); MEMSX'in üst yarıyı doldurması; ALU sınıfında MOVSX'in 32 bitte
durması; 32-bit MOD'un sıfır bölende üst yarıyı sıfırlaması; `off`'un işaretli olması;
LD_IMM64'ün iki yuva tüketmesi.

Her program ayırt edici bitlerini **alt 32 bite** düşürecek şekilde kuruldu, çünkü
`BPF_PROG_TEST_RUN`'ın retval'i bir u32 — tuzakların birçoğu üst yarı hakkında, ve değeri
doğrudan döndürmek bilgi taşımayan yarıyı karşılaştırırdı.

### 4. İlk koşu bir uyuşmazlık gösterdi — ve o bendim

`jmp32_ignores_upper_half`: ref 7, kernel 0. Triyaj sırası (önce ben, sonra kernel) hemen
cevabı verdi: satırın tamamı `load=reject load_errno=22 ran=0` diyordu. Program **7 komut
bildirip 6 emitlemişti**; verifier yüklemede reddetmiş, `kernel=0` da ilklenmemiş varsayılan
değerdi. Semantik uyuşmazlığa birebir benziyordu ve değildi.

Çıktı buna göre düzeltildi: `not-run` / `ref-fault` / `agree` / `DISAGREE` ayrı ayrı
bildiriliyor artık — bir yükleme reddi uyuşmazlık **değildir**, ve onu öyle raporlamak
0055'in "kurt geldi diye bağıran metrik" dersinin tekrarı olurdu. Test de bunu ayrıca
pinliyor.

### 5. Durum

`scripts/probe-ref.sh` ikisini de koşturup her satırın `agree` bitmesini şart koşuyor.
`reference_interpreter.rs` üç test: hepsi uyuşuyor, hepsi gerçekten koştu, ve tuzaklar
birbirinden ayrışıyor (aynı cevabı veren bir süit hiçbir şey test etmezdi).

Workspace 320 yeşil. Sıradaki: bu referansı hacme çıkaran kapalı-form jeneratör, ajanın
tarihsel verimlilik sıralamasındaki 1 numaralı şekle nişanlı — **link-then-diverge**, ki
`relink` parçası olarak zaten elimizde.

---

## 0074 — Nişan alınmış kapalı-form aile: 32768 karşılaştırma, sıfır uyuşmazlık — ve iki oracle hatası daha

### 1. Ne kuruldu

`--gen-intent`: verifier'a hiç danışmayan bir oracle tarafından yargılanan ilk korpus. Her
programın dönüş değerini `bpfref.h` hesaplıyor (0073'te 16 tuzakta kalibre edilmiş bağımsız
ISA uygulaması), kernel'in JIT'inin gerçekte döndürdüğüyle karşılaştırılıyor.

**Kapalı-form bize, bilinmez verifier'a.** Saf sabitler aralık izleyicisine yanlış yapacak
bir şey bırakmazdı; o yüzden tohum skalerler harness'ın az önce yazdığı bir map'ten geliyor.
`bpfref` gövdeden başlıyor, lookup yapan sabit prologue modellenmiyor — **atlanıyor**.

Şekiller ajan taramasının tarihsel verimlilik sıralamasından: link-then-diverge, 32-bit
genişlik/işaret hatasının işaretli karşılaştırmaya beslenmesi, sabit-sabitleme, signed
div/mod.

### 2. Üç iterasyon, hepsi ölçümle

**İlk koşu:** 512 programın 207'si **yapısal** reddedildi (`Initialize R<N>`) — prologue
r6/r7/r9 tohumluyor ama adımlar r8'i seçebiliyordu. Ve 1830 örneğin 727'si erken dallanıp
sabit döndürüyordu: uyuşan ama hiçbir şey gözlemlemeyen örnekler. Ayrıca nişan aldığım
şekil 305 kabul programın **2'sinde** oluşmuştu — adımları bağımsız çekmek, 0069'da
`relink`'in kaçındığı tuzağın aynısı. Aynı hatayı ikinci kez yaptım.

**İkinci koşu:** 512/512 kabul, sıfır boşa örnek. Ama bir tasarım eksiği kaldı: 811c
sınıfı bir sapma ancak verifier bir değeri **kesin sabit sandığında** doğar — o zaman dalı
statik çözer ve dead-code hard-wiring öbür tarafı siler. Map'ten gelen bilinmeyenlerle
verifier o duruma hiç girmiyordu, yani o sınıf **hiç üretilemiyordu**. `pin` adımı eklendi.

**Tam koşu:** 4096 program, **4096 kabul**, **32768 karşılaştırma**, 767 farklı cevap,
13 adımın hepsi dengeli, **0 uyuşmazlık**.

### 3. Ama pipeline 39 bulgu verdi — ve ikisi de bizimdi

Yeni oracle sessizdi; ateşleyen **eski** oracle'dı (`runtime_bound_violation`). İki ayrı
hata çıktı, ikisi de "yeni girdi ailesi devralınmış varsayımı kırıyor".

**(a) Birleşimde okunan yokluk — yedinci kez.** Verifier'ın basmadığı bir sınır kendi
**ekstremumundadır**, yani 32-bit görünümü basılmamış bir yolun aralığı **tamdır** ve onu
içeren birleşim de tamdır. Oracle ise o state'i **atlıyordu**, birleşimi gerçeğinden dar
yapıyordu. Somut vaka: log insn 14'te dört state basıyor, biri `umin32=6,umax32=0x7fffffff`,
üçü hiç 32-bit alan basmıyor; oracle tek yolun penceresiyle dört yolun dönüş değerlerini
yargılıyordu. 0041 ve 0050 aynı konvansiyonun **tek bir state içindeki** hâliydi; bu, ilk
kez **birkaçının birleşiminde** saklanışı. 39 → 26 bulgu.

**(b) Basılan state'ler kanıtlananların alt kümesi.** Verifier state'i yalnız register
"scratched" olduğunda basıyor, dolayısıyla çıkışına **birden çok yoldan** ulaşan bir
programda basılan küme kanıtlananın kesin alt kümesi. Birleşim gerçek iddiadan dar kalıyor.
Somut vaka: bir programın log'unda tek bir `22: (bf) r0 = r6 ; R0=0xffffffff` var — verifier'ın
şerh düştüğü tek yol — oysa program başka bir yoldan meşru olarak 0 döndürüyor.

Çözüm, jeneratörün `STORE` bildirimiyle aynı provenance kuralı: **program hakkındaki bir
olguyu jeneratör bildirir, oracle da kendi ön koşulunu denetler.** `EXPECT paths=multi`.
Tek-yollu aileler (bu oracle'ın kurulduğu `--gen-rt`) etkilenmiyor. 26 → 0.

### 4. Durum

`scripts/run-intent.sh` önce referansı kalibre ediyor ve kalibre değilse **koşuyu iptal
ediyor** — kalibre olmamış bir enstrümanla avlanmak avlanmamaktan kötüdür.

Bulgu yok. Ama bu "temiz" sayılı: bağımsız bir ISA uygulamasına karşı, tarihsel olarak en
verimli şekle nişanlı 4096 programda 32768 yürütme, sıfır boşa örnek. Workspace 325 yeşil.

---

## 0075 — Üçüncü uygulama: kernel'in kendi interpreter'ı, ve kırk bacaktır ölü olan invariant

### 1. Engel gerçekti

`CONFIG_BPF_JIT_ALWAYS_ON=y` — kernel'in kendi `___bpf_prog_run`'ı **derlemeden
çıkarılmış**. 0066'da `jit_interp_divergence` invariant'ının projenin bütün tarihinde tek
bir kayıt incelemediğini bulmuştum; sebebi buymuş. Parser'da yıllardır duran
`jit_interp_diff: None, // v0: ALWAYS_ON kernel, no interp` yorumu tam bunu söylüyormuş —
ama kimse onu bir **eksiklik** olarak okumamıştı.

`build-kernel.sh` artık `EXTRA_FRAG` alıyor; `config/kernel/nojit.config` o simgeyi
kapatıyor. Variant **paylaşılan artefaktları ezmiyor** — kendi `.config`'ini yanına yazıyor,
çünkü sessizce takas edilmiş bir config en kötü bayat artefakt türüdür. (Özet satırı da
yalan söylüyordu; düzeltildi.)

### 2. Üç bağımsız uygulama

| uygulama | notu |
|---|---|
| x86-64 JIT | varsayılan |
| kernel interpreter | `bpf_jit_enable=0`, ancak yeni variant'ta mümkün |
| `bpfref.h` | bizim, 16 tuzakta kalibre (0073) |

Ve önemli ayrıntı: `bpf_jit_enable` **yükleme zamanında** okunuyor
(`bpf_prog_select_runtime`), yani zaten yüklenmiş bir programın altında bayrağı çevirmek
hiçbir şey değiştirmiyor. Program **ikinci kez yüklenmek** zorunda. Bunu tek bir süreçte
yapmak, iki sonucun **tek bir kayda** atfedilmesini sağlıyor — invariant'ın yazıldığından
beri beklediği şey buydu.

### 3. Sonuç

Tam koşu, 4096 program × 8 girdi:

| karşılaştırma | sonuç |
|---|---|
| kernel-JIT vs kernel-INTERPRETER | 32768 karşılaştırma, **0 uyuşmazlık** |
| kernel-JIT vs `bpfref` | 32768, **0** |
| kernel-INTERPRETER vs `bpfref` | 32760, **0** |

`jit_interp_checked` ilk kez sıfırdan farklı.

### 4. Bir sahte alarm, ve neden sahte olduğu

İlk analizim "bir program iki modda farklı verdict aldı" dedi. Değil: log satırı bir RCU
stall mesajıyla bölünmüş —

```
===PROG genintent#s7d2ee64d#2778 type=sock[  123.324686] rcu: INFO: rcu_preempt detected stalls...
```

— ve benim ad-hoc python analizim, pipeline'ın 0027'den beri yaptığı konsol-onarımını
yapmıyordu. Program kabul edilmişti. **OI-10 (paylaşılan yakalama kanalı) bu bacakta ilk
kez ısırdı**: 4096 program × 8 test_run yükü altında kernel seri hatta konuşuyor. Pipeline
onarıyor ve not düşüyor; yardımcı scriptler onarmıyor — yakalamayı elle ayrıştıran her
analiz bunu hesaba katmalı.

### 5. Testin kendi eskimesini önceden söylemesi

0066'daki test şunu yazmıştı: *"bir interpreter kanalı kurulduğunda bu assert ters döner ve
test gerçek bir payda istemek üzere yeniden yazılmalı."* Aynen o yapıldı — ve iki yarısı
birden sabitlendi: intent korpusunda payda **64**, kompozisyon korpusunda hâlâ **0**, çünkü
o aile çift yüklemeyi yapmıyor. **Boşluk yalnız onu ÖLÇEN yerde kapandı**; ölçmeyen bir
ailenin sıfırını temiz sanmak ilk hatanın tekrarı olurdu.

Workspace 326 yeşil.
