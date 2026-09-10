# Held-out parti 1 — ÖN KAYIT (doğrulamadan ÖNCE mühürlendi)

**Tarih:** 2026-09-10 · **Amaç:** §4.1'in `n=1` held-out zayıflığını kapatmak.

Bu dosya doğrulamadan **önce** commit edildi. Doğrulama sonuçları ayrı bir commit'te
(`RESULTS.md`). Sıra git geçmişinden kontrol edilebilir; bu, testin held-out olduğunun
tek kanıtı.

---

## 1. Çerçeve — mekanik, ve orijinalden KASITLI olarak farklı

```
git -C .lab/bpf-next log --grep="^Fixes:" --since=2023-01-01 -- \
    kernel/bpf/{verifier,states,backtrack,cnum,tnum,liveness}.c
```
→ **208** commit. Sonra iki çıkarma:

- Gövdesinde verifier **durumu alıntılayan** commit'ler (`R[0-9]=`, `var_off`,
  `smin_value`, `umax_value`, `tnum(`, `scalar(`, `u32_m(in|ax)`): **28**. Bunlar
  orijinal 50'lik çerçevenin filtresidir; zaten sınıflandırıldılar.
- On altı kalibrasyon commit'i ve devlog 0102'de adı geçen beş başlık-tuzağı.

→ **held-out çerçeve: 176** commit (`frame.txt`).

**Neden alıntılayanları ÇIKARIYORUZ:** §6'nın ilk tehdidi, orijinal çerçevenin
"mesajı durum alıntılayan" ölçütüyle seçilmiş olması. Held-out kümesini o ölçütün
**tümleyeninden** çekmek iki işi birden yapıyor: prosedürü bağımsız vakalarda test
etmek, ve çerçeve yanlılığının yönünü ölçmek.

**Kabul edilen sapma:** 2023 kesimi derlenebilirlik için. Bu, örneklemi yeni koda
doğru yanlılaştırır ve §5.3 zaten yüzeyin orada çalkalandığını söylüyor.

## 2. Çekiliş kuralı — içerikten bağımsız, yeniden üretilebilir

```
sort frame.txt | head -10
```

SHA'ya göre artan sıralama. Kural commit'in **içeriğiyle** hiçbir ilişki taşımıyor,
ama sonradan birebir yeniden üretilebilir. On vaka `draw.txt`'te.

## 3. Soru (§3.3), oracle **B** (subsumption modeli) için

Fix, iki durumu karşılaştıran **YÜKLEM**'i mi değiştiriyor (`states_equal`,
`regsafe`, `range_within`, `check_ids`, `stacksafe`), yoksa modelin ham okuduğu bir
**DURUM** alanını yazan kodu mu (`u{32,64}_m{in,ax}`, `s{32,64}_m{in,ax}`, `var_off`,
`id`, `precise`, `live`, `type`, `off`, `range`) — yoksa ikisi de değil mi
(**ALAKASIZ**)?

Karar **yalnız diff'ten**, `dosya:fonksiyon` alıntısıyla.

## 4. Sınıflandırma ve ÖNGÖRÜLER

| # | commit | tarih | karar | çapa | öngörü (yanlışlanabilir) |
|---|---|---|---|---|---|
| H1 | `00244bdaa423` | 2026-08-05 | ALAKASIZ | `btf_id_allow_sleepable()` — BTF/attach politikası | B'nin okuduğu hiçbir alanı yazmıyor, yüklem değil |
| H2 | `00750788dfc6` | 2024-09-04 | ALAKASIZ | `convert_ctx_accesses()` — yalnız girinti | anlamsal değişiklik yok |
| H3 | `0108a4e9f358` | 2023-06-12 | ALAKASIZ | `jit_subprogs()` — kallsyms/`extable` | doğrulama SONRASI JIT muhasebesi |
| H4 | `032547272eb0` | 2025-07-03 | ALAKASIZ | `record_func_key()` — `verifier_bug`+EFAULT → `verbose`+EINVAL | yalnız tanı sınıfı; B durum satırı okur, verdict değil |
| H5 | `05670f81d128` | 2023-11-01 | ALAKASIZ | `CONFIG_CGROUPS`, BTF_ID kümeleri | derleme hatası |
| H6 | `0613d8ca9ab3` | 2023-05-18 | ALAKASIZ | `convert_ctx_accesses()` — `ALU64_IMM`→`ALU32_IMM` | keşif bittikten sonra komut yeniden yazımı |
| H7 | `06d686f771dd` | 2023-09-13 | ALAKASIZ | `check_kfunc_args()`, `KF_ARG_PTR_TO_CALLBACK` | argüman kontrol yolu; `subprogno` B'nin okuma kümesinde değil |
| H8 | `082cdc69a465` | 2023-03-15 | ALAKASIZ | `check_stack_read()` — spec_v1 reddi kaldırılıyor | verdict değişimi, durum alanı değil |
| H9 | `09c447564fca` | 2026-08-14 | ALAKASIZ | `save_aux_ptr_type()` → `insn_aux_data.ptr_type` | `bpf_reg_state` değil; `states_equal` bunu karşılaştırmıyor |
| **H10** | `0acd03a5bd18` | 2023-12-02 | **DURUM** | `prepare_func_exit()`: `mark_reg_read(REG_LIVE_READ64)` + `mark_chain_precision(BPF_REG_0)` | **B bunu göremez**: `precise` ve `live` B'nin ham TÜKETTİĞİ alanlar; bozulmuş bayrak B'ye veri olarak gelir, hata olarak değil |

**Bileşim: 9 ALAKASIZ · 1 DURUM · 0 YÜKLEM.**

## 5. Doğrulama protokolü — mühürden sonra koşulacak

1. **H10 (asıl test):** B'nin kaynağında (`scripts/subsume-check.py`, `harness/bpfsubs.h`)
   `precise`/`live` gerçekten **tüketilen girdi** mi, yoksa modellenmiş bir yüklem kolu
   mu? Tüketilen girdiyse öngörü tuttu; modellenmiş bir kolsa **öngörü yanlışlandı** ve
   öyle rapor edilecek.
2. **H1–H9:** dokunulan fonksiyonların hiçbiri B'nin kaynağında modellenmemiş olmalı.
   Bir tanesi bile modellenmişse o vaka için öngörü yanlışlandı.
3. Bileşim farkı (9/10 vs orijinal 15/40) ayrıca ölçülecek — bu §6'nın ilk tehdidine
   dair bir SONUÇ, bağımsız testin parçası değil.

## 6. Bu partinin peşinen bilinen zayıflığı

On vakanın dokuzu ALAKASIZ çıktı, yani **kör sınırını test eden tek vaka H10**.
Bu bir seçim hatası değil, çerçevenin bileşimi — ve bileşimin kendisi bir ölçüm.
Kör sınırını daha çok test etmek için sonraki partiler gerekiyor; bu parti bir
sonraki çekilişi *yönlendirmeyecek*, çünkü o da aynı kuralla, sıradaki 10 ile
sürecek (`sort frame.txt | sed -n '11,20p'`).
