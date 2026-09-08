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
