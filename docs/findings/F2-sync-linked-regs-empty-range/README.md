# F2 — `sync_linked_regs()` bir register'ı BOŞ aralığa düşürüyor, ve bunu hiçbir denetim görmüyor

**Kernel:** bpf-next `7.2.0-gdffc1150e2cc` (2026-09-03), stok, `Not tainted`
**Bulan:** verifierloop, av turu 11, tohum `0x5EED0011` (2026-09-10)
**Sınıf:** verifier iç invariant ihlali (`REG INVARIANTS VIOLATION`) — **bellek güvenliği hatası DEĞİL**
**Atıf:** `bbc631085503` ("bpf: replace min/max fields with struct cnum{32,64}") — tek commit'e indirildi
**Durum:** stok kernel'de yeniden üretildi, küçültüldü, mekanizma kaynakta çivilendi,
atıf iki byte-özdeş config'li derlemeyle kapatıldı, **inceleme bacağında bağımsız olarak dört kernelde
yeniden koşuldu**. Upstream'e gönderilmedi.

---

## Tek cümle

Bir koşullu dalın **imkânsız** kolunda, karşılaştırmaya girmeyen üçüncü bir register
`sync_linked_regs()` ile boş aralığa (`CNUM64_EMPTY`) düşürülüyor; ölü-dal tespiti ve
invariant denetimi bu yazımdan **önce** koştuğu için kimse görmüyor.

## Ne gözlendi

```
verifier bug: REG INVARIANTS VIOLATION (alu): range bounds violation
  r64={.base=0xffffffffffffffff, .size=0xffffffffffffffff}
  r32={.base=0xffffffff, .size=0xffffffff} var_off=(0x0, 0x6)
WARNING: kernel/bpf/verifier.c:2211 at reg_bounds_sanity_check+0x178/0xa10
```

`{U64_MAX, U64_MAX}` = `CNUM64_EMPTY`: register'ın aralığı boş küme, tnum'u hâlâ `{0,2,4,6}`.

## Küçültülmüş reproducer (20 gen → 4 gen)

Genom: `genes=4 hi=0:15.2.0.8.41,3.1.1.1.31,15.0.2.2.32,10.0.1.7.39`
Çekirdek dizi (r6/r9 map değerinden okunmuş bilinmeyen skalerler):

```
17: (25) if r9 > 0x9 goto pc+1
18: (57) r6 &= 9            ; r6 ∈ {0,1,8,9}
19: (27) r6 *= 2            ; r6 ∈ {0,2,16,18}  var_off=(0x0; 0x12)  range [0,18]
20: (26) if w6 > 0x3 goto pc+1
21: (57) r9 &= 3
22: (bf) r7 = r6            ; BAĞ — r6 ve r7 aynı id
23: (07) r7 += 8            ; BPF_ADD_CONST, id=3+8
24: (bf) r9 = r6
25: (25) if r7 > 0x10 goto pc+1
26: (0f) r6 += r6           ; <-- REG INVARIANTS VIOLATION (alu)
27: (bf) r0 = r6
28: (95) exit
```

24'te `R6=scalar(id=3, umin=4, umax=18, var_off=(0x0; 0x12))` → gerçek küme `{16,18}`;
`R7 = r6+8` → `{24,26}`. `r7 > 16` dalının **düşen kolu imkânsız** (`[12,16] ∩ {24,26} = ∅`).
Verifier o kolu yine de yürüyor, ve 25'ten sonra kernel'in kendi logu şunu yazıyor:

```
25: (25) if r7 > 0x10 goto pc+1
   R6=scalar(id=3,smin=smin32=-1,smax=smax32=-2,var_off=(0x0; 0x2))
   R7=scalar(id=3+8,smin=umin=smin32=umin32=12,smax=umax=smax32=umax32=16,var_off=(0x8; 0x12))
```

Bu satır bulgunun tamamını taşıyor: **karşılaştırmanın rafine ettiği R7 sağlam**
(`[12,16]`, iyi biçimli); boşalan (`smin=-1, smax=-2` — `CNUM64_EMPTY`'nin işaretli
yazılışı) ondan **sonra** yazılan R6.

## Mekanizma — kaynakta tam yeri

`check_cond_jmp_op()`, `kernel/bpf/verifier.c`:

| satır | ne |
|---|---|
| 16157 / 16169 | `regs_refine_cond_op()` — dalların rafinesi |
| **17050** | `regs_bounds_sanity_check_branches()` — **DENETİM** |
| **17063–17071** | `sync_linked_regs()` — **YAZIM, denetimden SONRA** |

- `regs_bounds_sanity_check_branches()` (16617) yalnız `true_reg1/2`, `false_reg1/2` —
  yani **karşılaştırmaya giren** register'ları denetliyor (16621–16624).
- `is_branch_taken()` → `simulate_both_branches_taken()` ölü dalı zaten boş-aralıkla
  tespit ediyor (`range_bounds_violation()`, 16165/16177) — ama yine sadece o iki register için.
- Bizim boşalan register (r6) karşılaştırmada YOK. `25: (25) if r7 > 0x10` bir
  `BPF_JGT|BPF_K`; dst=r7, src register yok — yani 17063'teki `BPF_SRC == BPF_X` kolu hiç
  koşmuyor, sadece 17069'daki dst kolu koşuyor. r6'ya dokunan tek şey o.
- `sync_linked_regs()` sonunda `reg_bounds_sync(reg)` → `__reg_bound_offset()` →
  `cnum64_intersect_with(&reg->r64, cnum64_from_tnum(reg->var_off))` (2082) → `EMPTY`.
  Sonuç hiçbir yerde denetlenmiyor, yol ölü ilan edilmiyor.

**Boşluk tek cümlede:** ölü-dal tespiti ve invariant denetimi bağlı-register yayılımından
ÖNCE koşuyor; `sync_linked_regs()` üçüncü bir register'ı boşaltabiliyor ve bunu kimse görmüyor.

## Bu bir gözlem etkisi (Heisenberg) DEĞİL — kaynaktan kanıt

`BPF_F_TEST_REG_INVARIANTS` tüm kernel'de **tek yerde okunuyor**, ve rapordan **sonra**:

```c
2211:  verifier_bug(env, "REG INVARIANTS VIOLATION (%s): %s ...");   /* rapor */
2217:  if (env->test_reg_invariants)
2218:          return -EFAULT;                                        /* TEK okuma */
2219:  __mark_reg_unbounded(reg);                                     /* bayraksız yol */
```

(`grep -rn test_reg_invariants kernel/bpf/` → yalnız 2217 ve 21213'teki `attr`'dan atama.)

Bayrak hiçbir durum hesabına giremiyor. `verifier_bug` da yalnızca `BPF_WARN_ONCE` +
`bpf_log` — durum değiştirmiyor. Harness tarafında da parite tam: `prune_load_typed()`
üç yüklemenin üçünde de `log_level=2` kullanıyor, tek değişen `prog_flags`.

Boş aralık bayrak olmadan da oluşuyor; bayrak sadece onu görünür kılıyor.

## Ne KABUL edilmiyor: "accept" tek başına unsoundness kanıtı değil

| yükleme | sonuç |
|---|---|
| `base` (bayraksız) | accept |
| `BPF_F_TEST_STATE_FREQ` | accept |
| `BPF_F_TEST_REG_INVARIANTS` | reject, errno 14 (EFAULT) |

Bu tabloyu "verifier bozuk durumu kabul ediyor" diye okumak **yanlış olur.** Bayraksız yolda
2219 koşuyor: `__mark_reg_unbounded(reg)` — boş kümeyi ⊤'ye **genişletiyor**, yani sound yön.
Stok kernel programı `r6=∅` ile değil `r6=⊤` ile doğrulayıp kabul ediyor. Üstelik
`BPF_WARN_ONCE` olduğu için üretimde ilkinden sonrası tamamen sessiz bir genişletme.

Bulgunun içeriği kabul değil, şu: **verifier kendi invariant'ının yasakladığı durumu,
hiçbir denetimin kapsamadığı bir yoldan kuruyor**, ve sound kalmasının tek sebebi o register
hakkındaki tüm bilgiyi atan battaniye bir geri düşüş.

## Atıf: 17 commit → tek commit

İki stok derleme, **byte-özdeş config** (`md5 f5a6ed6d…`), aynı minimal genom:

| commit | ne yapıyor | inv_verdict |
|---|---|---|
| `789b7c1c64b9` (pre-cnum, 2026-04-24) | — | accept, ihlal yok |
| `b93f7180f0bc` | min/max için accessor fonksiyonları (mekanik) | accept, ihlal yok |
| **`bbc631085503`** | **min/max alanları → `struct cnum{32,64}`** | reject errno=14, ihlal var |

Dördünde de `base_verdict=accept base_states=4 freq_states=12` — yani negatif kontroller
programı alakasız bir sebeple reddetmiyor, **aynı şekilde doğruluyor**; tek fark invariant
denetimi. Ham satırlar: `evidence.txt`.

    Fixes: bbc631085503 ("bpf: replace min/max fields with struct cnum{32,64}")

## Bağımsız doğrulama (inceleme bacağı, 2026-09-10)

Bulguyu bulan koşumdan ayrı olarak, inceleme bacağında dört kernel yeniden koşuldu ve dördü de
yukarıdaki tabloyu üretti. Ayrıca:

- `.lab/bpf-next` ağacı `dffc1150e2cc`'de temiz (`git status` boş, `git diff` boş).
- `vmlinux` bandı `7.2.0-gdffc1150e2cc`; ağaçtaki `verifier.c:2211` tam olarak kernel'in
  WARNING'inde adı geçen `verifier_bug` çağrısı — yani ikili bu kaynakla eşleşiyor.
- `bzImage` ≠ `bzImage-instr` (farklı md5): bulgu enstrümanlı kernel'de değil, stokta.

## Yenilik — dürüst ve ince

Bu **yeni bir hata sınıfı değil.** Harishankar Vishwanathan'ın RFC'si tam bu problemi tarif
ediyor: *"bpf, verifier: Detect empty intersection between tnum and ranges"*
([lkml, 2025-11-07](https://lkml.org/lkml/2025/11/7/1313); Paul Chaignon'un yanıtıyla,
[2025-11-13](https://lkml.org/lkml/2025/11/13/1451)). RFC'nin kendi örneği bizim şeklimizin
aynısı: `t = x0x1 {1,3,9,11}, r = [4,8]` — `tmin <= umax && tmax >= umin`, yine de kesişim boş.

**Semptom türü de bilinen bir tür.** RFC'nin kapak mektubu bunu açıkça söylüyor: fuzzing
kampanyaları `REG INVARIANTS VIOLATION` tetikleyen programları zaten rapor etti. Yani "bir
fuzzer bunu buldu" başlı başına bir katkı değil.

Ayakta kalan katkı **tek cümle**, ve kaynaktan doğrulanabilir: RFC entegrasyon noktası olarak
`regs_refine_cond_op()` çağrılarından sonrasını (~16169) işaret ediyor; `sync_linked_regs()`
17063'te, yani **ondan sonra** koşuyor. Oraya konan bir denetim bu şekli yakalamaz — çünkü
boşalan register koşulun rafine ettiği register değil, ondan sonra yazılan bağlı register.

Aynı sınıf gerçek dünyada da görülmüş (Cilium/Talos, kernel 6.18.x — siderolabs/talos#12726;
bu atıf ikinci elden, doğrulanmadı).

## Ne KANITLANMADI

- **Sömürülebilirlik gösterilmedi.** Yol ölü; ölü yolun ürettiği durumların canlı yolları
  budamakta kullanılıp kullanılmadığı ayrı bir soru. (0092/`92424801261d` bu riskin tarihsel
  örneği: "fix state pruning of fake registers".)
- Bu, tek başına bir *unsoundness* iddiası değildir. Kanıtlanan şey: kernel kendi
  invariant'ını ihlal ediyor, kendi deyimiyle "verifier bug", ve bayraksız yolda bunu
  sessiz bir genişletmeyle örtüyor.

## İkinci, bağımsız şekil (tur 12)

Tohum `0x5EED0012`, ayrı bir soy, 60 komut (`genes=15 hi=0:3.1.0.5.61,…`), av logunda **470**
ihlal. Stok kernel'de aynı imza: `(alu)`, `range bounds violation`, `CNUM_EMPTY`. Altı özdeş
turun hiç bulamayıp farklı tohumlu ilk iki turun ikisinin de bulması, şeklin ne kadar kolay
tetiklendiğini gösteriyor. Log: `.lab/replay-r12-stock.log`.

## Yeniden üretme

```bash
# NOT: SSHPORT şart. Varsayılan 10022'yi eşzamanlı bir av VM'i tutuyorsa qemu sessizce
# başlamaz ve script "markers not found" der — yükleme hatası sanılır.
SSHPORT=10122 KERNEL=$PWD/.lab/build/bzImage \
  HARNESS_ARGS='--fuzz-replay "genes=4 hi=0:15.2.0.8.41,3.1.1.1.31,15.0.2.2.32,10.0.1.7.39"' \
  TIMEOUT=300 scripts/run-harness-vm.sh .lab/replay-min-stock.log
grep -E "^PRUNE " .lab/replay-min-stock.log      # inv_verdict=reject inv_errno=14
grep "REG INVARIANTS" .lab/replay-min-stock.log
```

Negatif kontrol için `KERNEL=$PWD/.lab/build/bzImage-cn-a` (accept, ihlal yok).

## Provenans ve kanıt boşlukları

- Ham loglar `.lab/` altında (gitignore, ağır): `fuzz-hunt-11.log` (76 bulgu),
  `replay-inv-stock.log`, `replay-min-stock.log`, `replay-min-precnum.log`,
  `replay-min-cn-a.log`, `replay-min-cn-b.log`, `replay-r12-stock.log`.
  Bu dizindeki `evidence.txt` bunlardan çıkarılmış minimal, sürüm kontrollü kanıttır.
- **İhlal vermeyen kontrol logları kendi kernel kimliklerini taşımıyor** — WARNING yoksa
  sürüm dökümü de yok, dolayısıyla provenans artefaktta değil koşma anındaki env var'da.
  İnceleme bacağında yeniden koşularak kapatıldı; artefakt tek başına kanıtlamıyor.
  Açık madde: OPEN-ITEMS **OI-18**.
- `.lab/harness-serial.log` tek ve paylaşımlı dosya; eşzamanlı koşumlar birbirinin üstüne
  yazıyor. Açık madde: OPEN-ITEMS **OI-19**.
