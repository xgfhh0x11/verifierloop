# Held-out parti 2 — ÖN KAYIT (doğrulamadan ÖNCE mühürlendi)

Çerçeve ve soru parti 1 ile aynı (`PREREGISTRATION.md` §1, §3).
Çekiliş: `sort frame.txt | sed -n '11,20p'` → `draw2.txt`. Aynı içerikten-bağımsız kural.

## Yanlışlanma koşulu — parti 1'inki kötü yazılmıştı, düzeltildi

Parti 1'de yazdığım koşul "modellenmiş bir yüklem kolu" ile "bağımsız olarak yeniden
hesaplanıyor"u karıştırıyordu (bkz. `RESULTS-batch1.md` §2). Bu partide koşul şu:

> Bir **DURUM** öngörüsü, B'nin o alanı **kernel'den tüketmek yerine bağımsız olarak
> yeniden hesaplayıp HÜKME bağladığı** gösterilirse yanlışlanır. Alanın modellenmiş
> bir kolda geçmesi tek başına yanlışlamaz — belirleyici olan, hükme giden değerin
> nereden geldiği.
>
> Bir **ALAKASIZ** öngörüsü, dokunulan fonksiyon veya alan B'nin kaynağında
> modellenmişse yanlışlanır.

## Sınıflandırma ve öngörüler

| # | commit | tarih | karar | çapa | öngörü |
|---|---|---|---|---|---|
| **H11** | `0db63c0b86e9` | 2024-04-26 | **DURUM** | `mark_btf_ld_reg()`: `type_may_be_null(flag)` ise `reg->id = ++env->id_gen` | B `id`'yi yakalamadan **tüketiyor** (`id=` alanı, `check_ids`); atanmamış id her iki tarafa da aynı gelir → görünmez |
| H12 | `10e14e9652bf` | 2023-11-09 | ALAKASIZ | `push_insn()` — CFG keşfi, `env->cfg.insn_state` | B'nin okuma kümesinde değil (A'nın alanı) |
| H13 | `122fdbd2a030` | 2024-03-22 | ALAKASIZ | `check_alu_op()` — arena yoksa addr_space_cast reddi | yalnız verdict |
| H14 | `12659d28615d` | 2024-12-02 | ALAKASIZ | `process_iter_arg()` — PTR_TO_STACK tip kontrolü | argüman doğrulama |
| H15 | `17c4b65a2493` | 2024-11-08 | ALAKASIZ | `check_return_code()` — kprobe session retval aralığı | program-çıkışı yolu, budama yüklemi değil (0102'nin `763aa759d3b2` emsali) |
| **H16** | `180c7000712d` | 2026-08-03 | **DURUM** | `process_spin_lock()`: son unlock'ta `invalidate_rcu_protected_refs()` | geçersizleştirme register `type`'ını yazar; B `type`'ı tüketir (`o['t'] != c['t']`), iki taraf da bayat tipi taşır → görünmez |
| H17 | `18752d73c189` | 2024-09-13 | ALAKASIZ | `check_raw_mode_ok()` — helper proto argümanları | durum alanı değil |
| H18 | `18cdd90aba79` | 2025-02-27 | ALAKASIZ | `do_misc_fixups()` — `MOV32_IMM`→`MOV64_IMM` inline percpu | doğrulama sonrası komut yeniden yazımı (A'nın alanı) |
| H19 | `1ae497c78f01` | 2024-09-05 | ALAKASIZ | `type_may_be_null()` başlığa taşınıyor | saf refactor |
| H20 | `1b30d4441727` | 2025-08-01 | ALAKASIZ | `free_states()` / `compute_scc()` — `scc_cnt` bellek sızıntısı | bellek yönetimi |

**Parti 2 bileşimi: 8 ALAKASIZ · 2 DURUM · 0 YÜKLEM.**
**Kümülatif (20 vaka): 17 ALAKASIZ · 3 DURUM · 0 YÜKLEM.**
