# verifierloop — Operatör Manueli (RUNBOOK)

> **Amaç:** "neyi, nereden, hangi sırayla çalıştırırım" — kopyala-çalıştır.
> Karmaşa yok. Bir şeyi hatırlamıyorsan **§2 (sağlık + demo)** ile başla.
>
> - Repo kökü: `/home/tylersec/verifierloop` — **tüm komutlar buradan çalışır.**
> - Son güncelleme: 2026-08-28 (bu makinede probe edilerek doğrulandı).

---

## 1. Bu makinede ne var / ne yok

| Araç | Gerekli mi | Durum (2026-08-26) |
| --- | --- | --- |
| `cargo` (Rust) | evet | ✅ 1.93 |
| `python3` | evet (score stage) | ✅ 3.10 |
| `qemu-system-x86_64` | evet (VM/fuzzer) | ✅ 6.2 |
| `go` | syzkaller derlemek için | ✅ 1.26 (syzkaller zaten derli) |
| `just` | opsiyonel kısayol | ❌ **kurulu değil** |
| KVM (`-enable-kvm`) | hız (opsiyonel) | ❌ **çalışmıyor** → TCG (bkz §6) |

> [!important] İki şeyi unutma
> 1. **`just` yok.** README/justfile'da `just build-kernel` görürsen, karşılığı
>    doğrudan `./scripts/build-kernel.sh`'tir. Bu manuel hep doğrudan yolu verir.
> 2. **KVM çalışmıyor** (probe edildi: `/dev/kvm` node'u var ama `-enable-kvm`
>    → `No such device`). Her şey **TCG** (yazılımsal, yavaş ama çalışır).

---

## 2. En sık yapacakların (kopyala-çalıştır)

### A) Sağlık kontrolü — "hiçbir şeyi bozdum mu?" (~30 sn)
```bash
cargo build            # Rust workspace derleniyor mu
cargo test             # 43 test geçmeli (0 failed)
python3 -c "import sys; sys.path.insert(0,'python/src'); import verifierloop_analysis; print('python OK')"
```

### B) Pipeline'ı uçtan uca gör — sentetik veriyle (~5 sn)
Beş stage'in tamamı (ingest→normalize→score→diff→report) tek komutta:
```bash
cargo run -q -p pipeline --example report_demo -- /tmp/vl-demo
```
Görmen gereken: `PERIOD REPORT ... top_score=0.95 divergences=3` + triyaj listesi.
Artifact'ler: `/tmp/vl-demo/data/periods/1/*.json`.

> ⚠️ Bu **sentetik** veri (elle yazılmış örnek kayıt) — stage mantığını gösterir.
> **Gerçek** verifier verisi için: `harness_demo` (committed in-VM sample),
> `real_period` (canlı VM), ya da `syz_period` (syzkaller-güdümlü, §4b).

### C) Stage'leri tek tek koştur
Her biri bir `<base_dir>` alır; aynı dizini paylaşan stage'ler zincirlenir.
```bash
cargo run -q -p pipeline --example ingest_demo    -- /tmp/vl
cargo run -q -p pipeline --example normalize_demo -- /tmp/vl   # ingest'in üstüne
cargo run -q -p pipeline --example score_demo     -- /tmp/vl   # normalize'ın üstüne (python3 gerekir)
cargo run -q -p pipeline --example diff_demo      -- /tmp/vl
cargo run -q -p pipeline --example report_demo    -- /tmp/vl   # hepsini tek başına da koşar
```

### D) Golden fixture'ı yeniden üret — SADECE CORE şemasını bilerek değiştirdiysen
```bash
cargo run -q -p pipeline --example report_demo -- /tmp/vl-golden
python3 -c "import json; json.dump(json.load(open('/tmp/vl-golden/data/periods/1/normalized_metrics.json'))['payload'], open('crates/pipeline/tests/fixtures/golden/normalized.expected.json','w'), indent=2, sort_keys=True)"
cargo test -p pipeline --test golden_normalize   # yeşil olmalı
```
> Golden test kırmızıysa ve şemayı **değiştirmediysen**: bu bir regresyon, düzelt —
> golden'ı ezme. (Parser-katmanı guardrail; bkz devlog 0010.)

### E) `harness/diffharness.c`'yi değiştirdiysen — authoritative sample'ı yenile
Committed sample (`harness/samples/bpf-next-sample.txt`) **gerçek bpf-next VM'inden
alınmış** bir yakalamadır; host'ta üretilen çıktı onun yerine geçmez (host kernel
farklı, mesaj metinleri farklı çıkar).
```bash
./scripts/build-harness.sh                                   # önce derle
./harness/diffharness | head -40                             # hızlı akıl sağlığı (root, host kernel)
TIMEOUT=300 ./scripts/run-harness-vm.sh /tmp/vm-capture.log   # ~3-5 dk, TCG
# başlık bloğunu koruyup gövdeyi değiştir, sonra:
cargo test -p pipeline --lib parses_bpf_next_richer_format    # blok sayısı + red gerekçeleri pinli
```
> Sample'daki blok sayısı ve red gerekçeleri teste **çapalıdır** — yeni program
> eklediysen test kırmızı olur ve bilerek güncellenmesi gerekir. Bu kasıtlı: yeni bir
> hata metni şekli parser'ı sessizce bozarsa dedektör "temiz" der (devlog 0018/0024).

---

## 3. Lab: kernel + VM kurulumu (ağır, sıralı — **zaten yapıldı**)

Bunlar `.lab/`'i sıfırdan kurar. `.lab/` şu an dolu, yani **normalde bunlara
dokunmazsın**; ancak temiz makinede veya kerneli tazelemek istersen sırayla:

```bash
./scripts/fetch-kernel.sh      # bpf-next'i .lab/bpf-next'e klonla (blobless)
./scripts/build-kernel.sh      # bzImage üret (.lab/build/bzImage, BTF'li)
./scripts/create-rootfs.sh     # disposable Debian rootfs (.lab/images/rootfs.img)
./scripts/verify-vm.sh         # boot et, BTF+bpffs+kcov doğrula, kapat
```

**Şu an hazır (kontrol):**
```bash
ls -la .lab/build/bzImage .lab/images/rootfs.img   # varsa kurulum tamam
```

---

## 4. Fuzzer'ı çalıştır (syzkaller — birincil)

```bash
./scripts/setup-syzkaller.sh              # bir kez (zaten yapıldı; syzkaller derler)

# Sınırlı kampanya (benchmark / örnek toplama):
DURATION=600 ./scripts/run-syzkaller.sh   # ~10 dk sonra kendiliğinden durur

# Süresiz (Ctrl-C ile durdurana kadar):
./scripts/run-syzkaller.sh
```

- **Dashboard:** çalışırken → http://127.0.0.1:56741
- **Çıktı:** `.lab/syzkaller/workdir/` → `corpus.db`, `crashes/` (crash olursa)
- **TCG gerçeği:** ısınma ~90–100 sn (VM boot + machine check + candidate triage).
  **Coverage büyümesini görmek için en az 5 dk ver** — kısa koşu (200 sn) triage'de
  takılır (bkz devlog 0010).

---

## 4b. Syzkaller-güdümlü period (hacim yolu)

syzkaller'ın corpus'unu **gerçek verifier log'una** çevirip pipeline'a sokar:
corpus → `syz-prog2c` → replay shim (`log_level=2` enjekte eder) → bpf-next VM.

```bash
# 1) corpus büyüt (fuzzer'ı bir süre koştur)
DURATION=900 ./scripts/run-syzkaller.sh

# 2) replay binary'lerini derle (corpus -> C -> shim ile static binary)
./scripts/syz-replay-build.sh

# 3) VM'de replay + native çıktı yakala
TIMEOUT=900 ./scripts/run-syzreplay-vm.sh /tmp/syz-capture.log

# 4a) sadece triyaj (VM'siz, yakalanmış dosyadan)
cargo run -q -p pipeline --example parse_report -- /tmp/syz-capture.log

# 4b) ya da TAM period (2+3+4 hepsi; VM boot eder, dakikalar)
TIMEOUT=900 cargo run -q -p orchestrator --example syz_period -- /tmp/syz-period
```

Çıktıda **iki kanal ayrı** okunur:
- `SIGNAL divergences=...` → gerçek verifier sinyali (triyaj et),
- `PARSE HEALTH ... with_notes / unparsed_blocks` → **parser kör noktaları**
  (anomali DEĞİL; parser'ı düzeltmen gereken yer).

> Hacim ilk çalıştığında büyük ihtimalle `parse notes` / `unparsed` çıkar — bu
> beklenen ve doğru davranış: parser'ın görmediği log formları sinyale karışmadan
> ayrı raporlanır (devlog 0017/0018).

---

## 5. VM'e elle gir (manuel PoC / debug)

```bash
ACCEL=tcg ./scripts/boot-vm.sh    # disposable VM, seri konsol (KVM yok, TCG kullan)
```
Çıkış: VM içinde `poweroff` ya da QEMU'yu öldür (bkz §7 gotcha).

---

## 6. KVM mı, TCG mi? (hız meselesi)

Şu an: **TCG** (probe edildi 2026-08-26, `-enable-kvm` → `No such device`).
KVM ~10–20x daha hızlı olurdu; ama loop mantığı **period = exec-count** olduğu için
sadece duvar-saati etkilenir, sonuçlar değil.

**KVM'i açmayı denemek (host-side, senin yapman gereken):**
1. Windows'ta `wsl --shutdown`, sonra WSL'i yeniden aç.
2. WSL içinde test et:
   ```bash
   egrep -c '(vmx|svm)' /proc/cpuinfo          # > 0 olmalı
   qemu-system-x86_64 -enable-kvm -machine q35 -m 128 -display none \
     -serial stdio -kernel .lab/build/bzImage -append "console=ttyS0 panic=-1" 2>&1 | head
   ```
   Kernel boot mesajları akıyorsa KVM **çalışıyor**. `No such device` görürsen hâlâ kapalı.
3. Hâlâ kapalıysa: `.wslconfig`'te `nestedVirtualization=true` (varsa), ve host
   Windows'un kendisi bir VM ise hypervisor'da **VT-x/EPT expose** et.
   Not: BIOS'ta VT-x açık olsa da WSL2/Hyper-V nested-virt'i ayrı bir katman.

KVM çalışırsa: syzkaller config'i zaten TCG'ye sabit; `scripts/gen-syz-config.sh`
içindeki `QEMU_ARGS`'ı KVM'e çevirip config'i yeniden üretmen gerekir.

---

## 7. Nerede ne var (harita)

| Yol | Ne |
| --- | --- |
| `crates/` | Rust kodu (pipeline, orchestrator, metrics, contract, vmctl) |
| `python/` | Python analiz paketi (score stage) |
| `scripts/` | Lab bring-up + fuzzer script'leri (asıl çalıştırdıkların) |
| `config/` | kernel `.config` fragment'ı, qemu launch şablonları |
| `.lab/` | **Ağır artifact'ler** (git dışı): kernel, rootfs, syzkaller, bpf-next |
| `.lab/syzkaller/workdir/` | fuzzer çıktısı (corpus, crashes) |
| `data/` | period harvest çıktısı (runtime; git dışı) |
| `docs/devlog/devlog.md` | ne yapıldı/neden — kalıcı hafıza |
| `docs/REVIEW-HANDOFF.md` | başka birine "doğrula" diye verilen rapor |

---

## 8. Sık takıldıran şeyler (gotchas)

- **`just <şey>` "command not found"** → `just` kurulu değil. `./scripts/<şey>.sh`
  ya da yukarıdaki `cargo run` karşılığını kullan.
- **QEMU'yu öldürürken kendini öldürme:** `pkill -f qemu` komut satırında
  "qemu" geçen **kendi shell'ini** de öldürür. Doğrusu: `pkill -x qemu-system-x86_64`.
- **syzkaller sessiz bekliyor / hiç exec yok** → VM'e ssh olamıyordur. Ağ zaten
  isim-bağımsız yapıldı (devlog 0009); yine olursa `-debug` ile config'i koştur.
- **`score`/`report_demo` python hatası** → `python3` PATH'te ve `python/src`
  importlanabilir olmalı (§2-A ile test et).

---

## 9. Henüz ÇALIŞMAYAN (placeholder — yanılma!)

Bunlar bilerek **niyet basıp `exit 1`** yapar; henüz bağlı değil:

| Komut (justfile'da) | Durum |
| --- | --- |
| `collect-metrics` | placeholder — gerçek parser + VM bağlanınca |
| `run-period` | placeholder — gerçek `FuzzDriver` bağlanınca |
| `period-report` | placeholder |

> Not: bunlar **eski `just` kısayolları**. Karşılıkları artık gerçek ve çalışıyor:
> tek period → `cargo run -p orchestrator --example real_period` (harness) veya
> `--example syz_period` (syzkaller-güdümlü, §4b); triyaj → `parse_report`.
> Yani gerçek veri akıyor; kalan iş hacim + dış ground-truth loader'ları.

---

## 10. "Yeni oturuma başladım, nereden bakayım?" (30 sn)

```bash
cat docs/devlog/devlog.md | sed -n '26,50p'   # entry tablosu + pipeline durumu
git --no-pager log --oneline -5                 # son commit'ler
cargo test                                        # her şey yeşil mi (82 passed)
```
Detaylı durum: `docs/REVIEW-HANDOFF.md`. Ne yapıldığının hikâyesi: `docs/devlog/devlog.md`.
