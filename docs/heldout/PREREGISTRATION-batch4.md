# Held-out parti 4 — ÖN KAYIT: **görünür kol**

Parti 1–2 yirmi vaka üretti ve **hiçbiri YÜKLEM çıkmadı**, yani sınırın görünürlük
kolu held-out olarak test edilmedi. §4.1 bunu kendi kabul ediyor. Bu parti o boşluğu
hedefliyor.

## 1. Tabakalı çekiliş — ve neden döngüsel değil

Filtresiz çerçevede yüklem hatası oranı ~%1–2; aynı kuralla çekmeye devam etmek
makul bir bütçede sıfır YÜKLEM verir. Bu yüzden **ilan edilmiş bir tabaka**
kullanıyorum:

> **Stratum S** = held-out çerçevesindeki (176), parti 1–2'de çekilmemiş, ve
> **commit MESAJI** şu sözcüklerden birini içeren commit'ler: `prun`,
> `states_equal`, `state equival`, `regsafe`, `range_within`, `check_ids`,
> `scalar_ids`, `stacksafe`, `refsafe`, `equivalen`. → **19 commit**
> (`stratumS.txt`).

**Döngüsel değil, ve bunun ölçülmüş sebebi var:** tabaka **mesaja** bakıyor,
sınıflandırma **kaynağa**. Bu projenin daha önceki bir popülasyonda ölçtüğü
**sekiz başlık tuzağı** (devlog 0102: `71b547f56124`, `763aa759d3b2`,
`cc52d9140aa9`, `4cabc5b186b5` ve dört öncesi) mesajın sınıfı belirlemediğinin
doğrudan kanıtı.

**Bedeli peşinen kabul:** tabaka zenginleştirilmiş, dolayısıyla **bu partinin
bileşimi taban oranların tahmini DEĞİL.** Parti 1–2'nin bileşim ölçümü (17/20
ALAKASIZ, p=0,0008) bu partiyle güncellenmeyecek.

Çekiliş yine içerikten bağımsız: `sort stratumS.txt | head -8` → `draw4.txt`.

## 2. Yanlışlanma koşulları (parti 2'nin düzeltilmiş biçimi)

- **GÖRÜNÜR** öngörüsü, fix'in dokunduğu karşılaştırma kolu B'nin kaynağında
  **modellenmiş değilse** yanlışlanır.
- **DURUM** öngörüsü, B o alanı kernel'den tüketmek yerine **bağımsız hesaplayıp
  hükme bağlıyorsa** yanlışlanır.
- **ALAKASIZ** öngörüsü, dokunulan fonksiyon/alan B'nin kaynağında modellenmişse
  yanlışlanır.

## 3. Sınıflandırma ve öngörüler

| # | commit | karar | çapa (yalnız diff'ten) | öngörü |
|---|---|---|---|---|
| **H21** | `1ffc85d9298e` | **YÜKLEM → GÖRÜNÜR** | `regsafe()` SCALAR_VALUE kolu: `regs_exact()` yerine `memcmp(..., offsetof(id))` + `check_scalar_ids()` | **B bunu GÖREBİLİR** — B tam bu kolu, düzeltilmiş hâliyle modelliyor |
| H22 | `2658a1720a19` | DURUM | `collect_linked_regs()` artık `live_regs_before`'da olmayan register'ları atlıyor → `reg->id` yazıyor | kör: B `id`'yi tüketiyor |
| **H23** | `2b2efe1937ca` | **MODELLENMEMİŞ** | `is_state_visited()`'in may_goto kolu: `states_equal` çağrısının ÖNÜNE `may_goto_depth` koşulu ekliyor | kör, **ama üçlemenin dışında**: `states_equal` değişmiyor, B'nin okuduğu alan bozulmuyor; kusur B'nin modellemediği bir KAPIDA |
| H24 | `3a354149bcea` | DURUM | `__clean_func_state()`: ölü hi-half'te pointer spill metadata'sı korunuyor → stack slot durumu | kör, üstelik iki kez: yakalama stack slotlarını hiç basmıyor |
| H25 | `3d562d35a044` | ALAKASIZ | `might_throw`, `cfg.c` — istisna yolları | B'nin okuma kümesinde değil |
| **H26** | `41025f441fe6` | **YÜKLEM → GÖRÜNMEZ** | `refsafe()`: REF_TYPE_PTR için `check_ids(parent_id)` ekliyor | **YÜKLEM ama B görmez** — `refsafe` B'de modellenmiş değil (`refsafe_idmap_seed=not-observable-from-capture`). §5.3'ün "YÜKLEM ≠ görünür" ayrımının ikinci vakası |
| H27 | `52c2b005a3c1` | DURUM | `propagate_precision()` artık `REG_LIVE_READ` de arıyor → `precise` yazıyor | kör: B `precise`'ı tüketiyor (§5.4'ün kapısı) |
| H28 | `713274f1f2c8` | DURUM | `check_stack_write_fixed_off()`: daraltan spill'de `spilled_ptr.id = 0` | kör: B `id`'yi tüketiyor |

**Bileşim: 1 GÖRÜNÜR · 1 YÜKLEM-ama-görünmez · 4 DURUM · 1 MODELLENMEMİŞ · 1 ALAKASIZ.**

## 4. H23 üçlemede bir boşluk açıyor — şimdiden kayda geçiyorum

§3.3 üç cevap tanıyor: YÜKLEM / DURUM / ALAKASIZ. H23 hiçbirine temiz oturmuyor:
`states_equal` değişmiyor (YÜKLEM değil), B'nin okuduğu hiçbir alan bozulmuyor
(DURUM değil), ama durum-eşdeğerliği yolunun tam ortasında (ALAKASIZ da değil).
Doğru cevap dördüncü bir kategori: **yolda, ama hiçbir oracle'ın modellemediği bir
parçada** — Appendix A'nın pointer kolu için zaten `u` işaretiyle taşıdığı şey.

Bunu sonuç olarak değil, **öngörünün bir parçası** olarak yazıyorum: eğer
doğrulama H23'ü gerçekten bu dördüncü kutuya koyarsa, §3.3'ün üçlemesi
düzeltilmeli — "ALAKASIZ" bugünkü metinde *"yolun dışında"* diye tanımlı, oysa
doğru tanım *"oracle'ın tükettiğinin dışında"*.

## 5. Doğrulama protokolü

Her vaka için B'nin kaynağı (`scripts/subsume-check.py`, `harness/bpfsubs.h`):
dokunulan kol/alan modellenmiş mi, ve modellenmişse **tüketiliyor mu, yeniden
hesaplanıp hükme mi bağlanıyor**.

**Peşinen kabul:** bu, parti 1–2'nin kaynak-düzeyi doğrulamasıyla aynı seviye.
H21 için daha güçlüsü mümkün — `1ffc85d9298e~1` ve `1ffc85d9298e` derlenip
min/max dönem yakalama yamasıyla koşulur — ve yapılmadıysa öyle rapor edilecek.
