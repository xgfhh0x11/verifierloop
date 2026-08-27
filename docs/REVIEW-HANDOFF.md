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
> - **Son devlog entry'si:** `0015` — `docs/devlog/devlog.md`

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

**Reviewer'ın en çok şüpheyle bakması gereken nokta:** "ilk gerçek period çalışıyor"
iddiası **doğru ama dar**. Harness şu an **sabit 6-program corpus'u** koşuyor (3 basic + 3 ranged-scalar) —
syzkaller-güdümlü gerçek fuzzing DEĞİL. Yani kanıtlanan şey **mekanizma + gerçek
verifier verisi akışı**, henüz **bug avı hacmi değil**. Ayrıca şu ana kadar gerçek
veriden **hiç true-positive anomali yüzeye çıkmadı** (bilinçli: corpus temiz). Bu
dürüstçe işaretli (§4, §7).

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
`docs/eBPF ... Mimari ...md` (tasarım), `docs/devlog/devlog.md` (0001–0015).

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
$ cargo test    → 34 passed, 0 failed
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

1. **syzkaller → harness besleme + coverage/crash parser** — harness'i syzkaller'ın
   ürettiği programlarla besle; KCOV delta + crash → CORE. **İlk gerçek bug-avı yüzeyi.**
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
- **R2** `cargo test` → **34 passed, 0 failed**. ✔ V1
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

**Reviewer'ın özellikle sorgulaması istenen iddialar (şüphe listesi):**
1. "İlk gerçek period çalışıyor" → evet ama **sabit corpus**, syzkaller-fuzzing değil
   (§4 notu). Abartı mı, dürüst mü?
2. "0 anomali doğru" → **KAPANDI (0014→0015).** diff'in intrinsic invariant'ları GERÇEK
   ranged register-state'lerde koşuyor, VE dedektör gerçek parser yolunda **kalibre**:
   temizde susar, enjekte malformed-tnum'da `tnum_malformed` diye bağırır
   (`diff_detector_calibration`, ✔ V5). Yani "0 anomali" artık *sağır dedektör* değil.
   (Gerçek bir verifier bug'ı hâlâ yüzeye çıkmadı — beklenen: corpus temiz + kernel doğru.)
3. **Parser** bpf-next authoritative capture'a karşı doğrulandı. **Güncelleme (0014):**
   full `scalar(...)` formu (chained-value `smax=umax=255` + var_off) artık GERÇEK bpf-next
   verisinde parse edilip test ediliyor. Kalan: pointer/helper register tipleri henüz görülmedi.
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

---

## 9. Tek cümlelik doğrulanabilir durum ifadesi

> "verifierloop'un **beş-stage'li pipeline'ı** ve **loop'u**, kendi derlediğimiz
> bpf-next kernel'inden gelen **gerçek verifier verisiyle uçtan uca canlı koşuyor**
> (`real_period` örneği: gerçek VM → harvest → report, 31 test geçer); harness'i
> pipeline'a bağlayan **gerçek parser + VM-destekli FuzzDriver** yazıldı ve
> `MockDriver`'ı değiştirdi; **eksik olan**, harness'i **syzkaller-güdümlü gerçek
> fuzz hacmine** bağlamak (henüz sabit 6-program corpus'u), dış ground-truth
> loader'ları ve JIT↔interp cross-kernel modu; **KVM host-side bloklu, TCG çalışır.**"
