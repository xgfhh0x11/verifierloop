# Held-out parti 2 — SONUÇLAR

Ön kayıt: `PREREGISTRATION-batch2.md`, commit `956b461`. Bu dosya ondan **sonra**.

## 1. İki DURUM öngörüsü — ikisi de tuttu

| # | alan | B'de nereden geliyor | hükme nasıl giriyor | sonuç |
|---|---|---|---|---|
| **H11** | `id` | yakalama regex'i `id=([0-9a-f]+)` (satır 139/147/162) → `o['id']` | `check_ids(o['id'], c['id'])`, satır 338 | **tüketiliyor** → kör. Öngörü tuttu |
| **H16** | `type` | yakalama regex'i `type=(\d+)` → `o['t']` | `if o['t'] != c['t']: break`, satır 306 | **tüketiliyor** → kör. Öngörü tuttu |

Yanlışlanma koşulu (bağımsız yeniden hesap → hüküm) hiçbirinde gerçekleşmedi.
B'nin kaynağındaki tek bağımsız yeniden hesap `bpflive.h`'in canlılık maskesi ve o
da yalnız sayaçlara gidiyor (`live_bit`, satır 298–304); hükmü veren kapı satır
307'de kernel'in kendi `o['live']` alanını kullanıyor.

## 2. Sekiz ALAKASIZ öngörüsü — 8/8

`push_insn`, `insn_state`, `check_alu_op`, `process_iter_arg`, `check_return_code`,
`retval_range`, `process_spin_lock`, `check_raw_mode_ok`, `do_misc_fixups`,
`type_may_be_null`, `free_states`, `compute_scc`, `scc_cnt` — on üç ismin hepsi B'nin
kaynağında **0** kez geçiyor.

## 3. Kümülatif

| | parti 1 | parti 2 | toplam |
|---|---|---|---|
| vaka | 10 | 10 | **20** |
| tutan öngörü | 10 | 10 | **20** |
| yanlışlanan | 0 | 0 | **0** |
| kör sınırını test eden (DURUM) | 1 | 2 | **3** |
| ALAKASIZ | 9 | 8 | **17** |
| YÜKLEM | 0 | 0 | **0** |

**§4.1'in held-out sayısı: 1 → 21.** (20 yeni + mevcut biri.)

## 4. Çerçeve bileşimi — §6'nın birinci tehdidi, kümülatif

| çerçeve | ALAKASIZ | durum-eşdeğerliği yolunda |
|---|---|---|
| orijinal (mesajı durum alıntılayan), n=40 | 15 (%37,5) | 25 (%62,5) |
| held-out (o ölçütün tümleyeni), n=20 | **17 (%85)** | 3 (%15) |

Fisher kesin testi, iki yönlü: **p = 0,00077**.

Yani §5.3'ün %58 kör / %5 hedef rakamları **çerçeveye koşullu**, ve koşulun yönü
ölçüldü: durum alıntılayan mesajlara göre seçmek, durum-eşdeğerliği yolundaki
hataları yaklaşık **dört kat** fazla temsil ediyor (%62,5 vs %15).

Bu, §5.3'ün rakamlarını çürütmüyor — onların **neyin oranı olduğunu** düzeltiyor.

## 5. Dürüst kalan zayıflıklar

- **YÜKLEM öngörüsü sıfır.** Yirmi vakada bir tane bile "potansiyel olarak görünür"
  çıkmadı, yani bound'un **üst** kolu (görünürlük) held-out olarak hâlâ test edilmedi.
  Sınırın test edilen tarafı yalnız kör tarafı.
- **Doğrulama kaynak-düzeyinde.** Üç DURUM vakasının hiçbirinde kernel derlenip
  oracle koşulmadı; doğrulama "alan B'nin kaynağında tüketiliyor mu" sorusuydu.
  Bu, §4.1'in mevcut tek held-out vakasıyla aynı düzey — ama sistem kurup koşmak
  daha güçlü olurdu ve yapılmadı.
- **n=20 hâlâ küçük**, ve 2023 kesimi örneklemi yeni koda yanlılaştırıyor.
