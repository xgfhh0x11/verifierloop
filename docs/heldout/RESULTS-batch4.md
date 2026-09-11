# Held-out parti 4 — SONUÇLAR: görünür kol kapandı, ve üçleme bir boşluk açtı

Ön kayıt: `PREREGISTRATION-batch4.md`, commit `bd10090`. Bu dosya ondan **sonra**.

## 1. H21 — görünür kol, ve öngörülenden güçlü

Öngörü: `regsafe()`'in SCALAR_VALUE kolundaki değişikliği (`regs_exact()` yerine
`memcmp(..., offsetof(id))` + `check_scalar_ids()`) **B görebilir.**

Kaynakta bulunan: `check_scalar_ids` transkribe edilmiş (satır 96, 120) ve gerçek
bir **hüküm kolu**:

```python
# subsume-check.py:383
if not p['idmap'].check_scalar_ids(o['id'], c['id']):
    p['arm'] = 'check_scalar_ids'; verdict = 'break'; break
```

Dahası: bu kol B'nin **kalibre edilmiş pozitifinin** ta kendisi — `2f2ec8e7730e`
çiftinde buggy kernel'de `disagree=1 arm=check_scalar_ids`, korpus ölçeğinde 15
uyuşmazlık, fixed'de 0. Yani held-out GÖRÜNÜR öngörüsü yalnız "kol modellenmiş"
demiyor; **o kolun gerçek bir hatada ateşlediği bağımsız olarak biliniyor.**

**Öngörü tuttu.** Sınırın üst kolu artık held-out test edilmiş durumda.

## 2. H26 — YÜKLEM ama GÖRÜNMEZ, ve bu ayrımın ikinci vakası

`refsafe()`'e `check_ids(parent_id)` ekleniyor — tartışmasız bir karşılaştırma
fonksiyonu, yani YÜKLEM. Ama B'nin kaynağında `refsafe` yalnız **uygulanmayan
kollar** raporunda geçiyor:

```
refsafe_idmap_seed=not-observable-from-capture   (subsume-check.py:442,449)
```

**Öngörü tuttu**, ve §5.3'ün *"PREDICATE does not imply visible"* cümlesine
`1ad2f5838d34`'ten sonra ikinci bağımsız vaka geldi — bu sefer held-out.

## 3. H23 — üçlemenin dışında, ve bu ön kayıtta yazılıydı

`2b2efe1937ca` `is_state_visited()`'in may_goto kolunda `states_equal` çağrısının
**önüne** bir koşul ekliyor. Doğrulama:

| aranan | B'de |
|---|---|
| `is_state_visited`, `may_goto_depth`, `may_goto`, `update_loop_entry` | **0** |
| `states_equal`'in kendisi | değişmemiş (diff'te yok) |
| B'nin okuduğu herhangi bir alan | bozulmuyor |

Yani: YÜKLEM değil, DURUM değil, ve yolun **dışında da değil**. §3.3'ün üçlemesi
bu vakayı adlandıramıyor. Doğru cevap dördüncü kategori: **yolda, ama hiçbir
oracle'ın modellemediği bir parçada.** Appendix A bunu pointer kolu için zaten `u`
işaretiyle taşıyor; §3.3 taşımıyordu.

**Sonuç: §3.3'ün "ALAKASIZ = durum-eşdeğerliği yolunun dışında" tanımı yanlış;
doğrusu "oracle'ın TÜKETTİĞİNİN dışında", ve dördüncü cevap ayrıca adlandırılmalı.**

## 4. Kalan beş öngörü

| # | karar | doğrulama | sonuç |
|---|---|---|---|
| H22 | DURUM | `collect_linked_regs` B'de 0; `id` satır 338'de **tüketiliyor** | tuttu |
| H24 | DURUM | B stack slotlarını **hiç karşılaştırmıyor** (satır 99–100: yama stack'i basmıyor, model karar vermiyor) — iki kez kör | tuttu |
| H25 | ALAKASIZ | `might_throw`, `cfg.c`, `bpf_check_cfg`, `exception` → hepsi 0 | tuttu |
| H27 | DURUM | `propagate_precision` B'de 0; `precise` satır 375'te **tüketiliyor** (§5.4'ün kapısı) | tuttu |
| H28 | DURUM | `check_stack_write` B'de 0; `id` tüketiliyor | tuttu |

## 5. Kümülatif

| | parti 1 | parti 2 | parti 4 | toplam |
|---|---|---|---|---|
| vaka | 10 | 10 | 8 | **28** |
| tutan | 10 | 10 | 8 | **28** |
| yanlışlanan | 0 | 0 | 0 | **0** |

**§4.1'in held-out sayısı: 1 → 29** (28 ön-kayıtlı + özgün bir).

Kolların testi:
- **kör kol:** 7 vaka (H10, H11, H16, H22, H24, H27, H28)
- **görünür kol:** **1 vaka (H21)** — bu partiden önce sıfırdı
- **YÜKLEM-ama-görünmez:** 1 vaka (H26)
- **modellenmemiş (dördüncü kategori):** 1 vaka (H23)
- ALAKASIZ: 18

## 6. Dürüst kalan sınırlar

- **Doğrulama hâlâ kaynak düzeyinde.** H21 için daha güçlüsü mümkündü —
  `1ffc85d9298e~1` ve `1ffc85d9298e` min/max dönem yakalama yamasıyla derlenip
  koşulurdu — ve **yapılmadı**. H21'in gücü, kolun bağımsız bir kalibre pozitifi
  olmasından geliyor, bu partinin kendi koşumundan değil.
- **Tabaka zenginleştirilmiş.** Bu partinin bileşimi taban oranların tahmini
  değil, ve parti 1–2'nin bileşim ölçümü (p=0,0008) bununla güncellenmedi.
- n=29 hâlâ küçük; 2023 kesimi örneklemi yeni koda yanlılaştırıyor.
