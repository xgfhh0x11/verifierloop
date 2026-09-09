# patches/ — baskı-amaçlı kernel enstrümantasyonu

Buradaki yamalar test edilen ağaca uygulanır ve **yalnızca çıktı üretir**. Hiçbiri
verifier'ın bir kararını değiştirmez, ve bu bir iddia değil bir **koşuldur**: bir yama
ancak stok ve yamalı kernel aynı korpusta **byte-byte aynı verdict dizisini** verirse
kullanılabilir.

## `prunepair-instrumentation.patch`

`kernel/bpf/states.c`, `hit:` etiketi — yani `states_equal()` iki durumu eşdeğer bulup
budamaya karar verdiği an. Orada **hem `sl->state` (eski/checkpoint) hem `cur` (güncel)**
kapsamdadır; log ise (0088'de ölçüldü) o çiftin **hiçbir tarafını** taşımaz.

Neden `print_verifier_state` yeniden kullanılmadı: o fonksiyon yüklemin alanını ifade
edemiyor. `range_within` artık `cnum{base,size}` üzerinde yay-içerilmesi iken log sekiz
türetilmiş projeksiyon basıyor; `precise` kontrolün yapılıp yapılmayacağına karar verirken
logda yalnız bir `P` ön-eki olarak var; `id` maskelenmiş basıldığı için `regsafe`'in sert
uyuşmazlık saydığı ADD_CONST32/64 ayrımı kayboluyor. Bu yüzden **ham alanlar** basılıyor.

Kurulum:

```bash
git -C .lab/bpf-next worktree add --detach $PWD/.lab/bpf-instr HEAD
git -C .lab/bpf-instr apply $PWD/patches/prunepair-instrumentation.patch
SRC=$PWD/.lab/bpf-instr OUT=$PWD/.lab/build/bzImage-instr scripts/build-kernel.sh
```

Kullanmadan önce ZORUNLU doğrulama (0098'de koşuldu ve geçti):

```bash
HARNESS_ARGS=--gen-comp TIMEOUT=1800 scripts/run-harness-vm.sh /tmp/stock.log
KERNEL=$PWD/.lab/build/bzImage-instr HARNESS_ARGS=--gen-comp TIMEOUT=1800 \
  scripts/run-harness-vm.sh /tmp/instr.log
diff <(grep -oE '^RESULT decision=[a-z]+ .*errno=[0-9]+' /tmp/stock.log) \
     <(grep -oE '^RESULT decision=[a-z]+ .*errno=[0-9]+' /tmp/instr.log)   # BOŞ olmalı
```

**Bir bulgu asla yamalı kernel'de bırakılmaz.** Yama oracle'dır, hüküm değil: yamalı
kernel'de çıkan her şey stok kernel'de yeniden türetilmek zorundadır.

## `prunepair-instrumentation-minmax.patch` — dönem varyantı (pre-cnum)

Aynı enstrümantasyon, 2026-04-24 ÖNCESİ ağaç için. İki fark:

- dosya `kernel/bpf/verifier.c` (o revizyonda `kernel/bpf/states.c` yok),
- alanlar `r64`/`r32` yerine `umin..umax` / `smin..smax` / `u32` / `s32`, ve `parent_id` yok.

Ayıraç anlamlıdır ve tüketicinin hangi yüklemi borçlu olduğunu söyler: **`+` base+size yayı**
(cnum, `cnum_is_subset`), **`..` min..max aralığı** (pre-cnum, sekiz karşılaştırmalı
`range_within`). `scripts/subsume-check.py` iki biçimi de okur ve her yakalamada o dönemin
KENDİ yüklemini uygular — dönemin hatasını da birebir taşıyarak, çünkü aksi hâlde aradaki her
fark bir "bulgu" gibi görünür.

Kurulum ve zorunlu doğrulama, tip varyantıyla aynı; `2f2ec8e7730e` çifti için **iki yarı da**
koşuldu:

```
stok  .lab/build/bzImage-buggy8     896 blok, 775 accept / 121 reject
yama  .lab/build/bzImage-instr-b8   896 blok, 775 accept / 121 reject
verdict dizisi, errno DAHİL: AYNI    ·    PRUNEPAIR: yamalı 11.866, stok 0
```

Bu, sözleşmenin ilk kez **doğru kontrolle** koşulmasıdır: karşılaştırılan iki kernel aynı
revizyonda ve yalnızca yamada ayrılıyor. 0100'ün dönem koşusu era-yamalı ↔ tip-stok
karşılaştırmıştı, ki o yamayı izole etmez.

## Dönem hassasiyeti

Yama, bastığı ALANLARA bağlı olarak dönem hassastır ve her kalibrasyon hedefi için küçük
bir varyant gerekebilir. Ölçülmüş sınırlar:

| alan | ne zamandan beri var |
|---|---|
| `r64` / `r32` (cnum) | **2026-04-24**, `bbc631085503` — bundan eski bir kernel'de yama derlenmez |
| `parent_id` | `cd5b460ed1ec~1`'den sonra |
| `kernel/bpf/states.c` | dosya olarak sonradan ayrıldı; pre-cnum ağaçta hepsi `verifier.c` |

**DÜZELTME (bacak 0101).** Bu taban ÖNCE yanlış gerekçelendirilmişti: "model
`cnum_is_subset`'i uyguluyor, o yüklem 2026-04-24'ten önce mevcut değil." Yüklemin eski
kernel'de olmaması modelin sınırı DEĞİL — varlık sebebi o; nitekim `cd5b460ed1ec`
`is_subset`'i `cnum_defs.h`'e EKLEYEN commit'tir, yani hatalı ağaçta o yüklem hiç yok.

Gerçek taban **alanlardır**: yama `r64`/`r32` olmadan derlenmez. Ve alanlardan gelen bir
taban **kaldırılabilir** — bu dosyadaki min/max varyantı onu kaldırdı. Bu yüzden 2023-11-11
REG_INVARIANTS tabanının kardeşi değildir: o taban ontolojiktir (bayrak kernel'de yok), bu
taban seçilmiş yakalama biçiminin sonucuydu. `2f2ec8e7730e` (2026-04-11) bu ayrım sayesinde
kalibre EDİLDİ, edilemez değil.
