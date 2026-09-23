# EK F — Birinci statü vakası F-1 (ön-kayıt)

**Kayıt tarihi:** 2026-09-23
**Çözülme tarihi:** 2026-10-23 (30 gün) — ya da ilk CVE-değeri taşıyan uyanma, hangisi önce gelirse.
**Kaydı yapan:** verifierloop av-döngüsü ajanı (Claude). Karar sonuç bilinmeden verilmiştir.

Bu vaka, EK F'nin tümünün aksine, **ikinci statü değil birinci statüdür**: yanlışlama koşulu
sonuçtan *önce* yazılmıştır ve bu dosya o andan itibaren git geçmişine çivilenmiştir
(aşağıdaki commit). Amaç, "arayan bulur" itirazını kapatmak: karar da, onu çürütecek koşul da
sonuç gelmeden sabittir.

---

## Alan

Linux BPF doğrulayıcısının (verifier) sürekli diferansiyel fuzzing'i — verifierloop.
Hedef çekirdek: stok bpf-next `dffc1150e2cc` (7.2.0). Enstrüman, gramer-tabanlı bir üreteç +
bağımsız-referanslı oracle'lar (çalışma-anı için `bpfref` yorumlayıcı; register/pruning
tutarlılığı için çekirdeğin kendi `BPF_F_TEST_REG_INVARIANTS` / `BPF_F_TEST_STATE_FREQ`
bayrakları). Av döngüsü tur başına ayrı tohumla kesintisiz koşar; her tur `.lab/hunt-ledger.txt`'e
zaman damgalı bir satır yazar.

## Çerçeveyle verilen karar

Enstrümanın verimi **P(reach) × P(see)**'dir. İki ölçüm bu iki çarpanı sabitler:

1. **Erişim (P(reach)) gramere bağlı ve DOYGUN.** 250+ turda `seen_pcs ≈ 6260`, doğrulama-geçişi
   kapsamı `~3680–3695 / 10258` bandında platoda; ne süre, ne tohum çeşitliliği, ne dağılım
   politikası onu kıpırdatıyor.
2. **Görme (P(see)) yalnız doğrulayıcı-olmayan bir referansın var olduğu yerde yüksektir.**
   Oracle'lar skaler-aritmetik yüzeyde en güçlü — ve kapsam ölçümü o yüzeyin doygun olduğunu
   söylüyor (`cnum.o %95.8`). Taze yüzeyde (kfunc/BTF, referans/kilit, tipler) bağımsız referans
   yok, dolayısıyla oracle orada kör.

**Karar:** Mevcut enstrümanı mevcut gramerde koşturmaya DEVAM et; kfunc/referans gramer genleri
ekleyip o yüzeyde bulgu arama pivotu YAPMA. Çerçevenin iddiası: böyle bir pivot o yüzeyde
P(reach)'i artırır ama P(see)'yi artırmaz, yani CVE-değeri taşıyan bulgu vermez. Bulguların
görünür olduğu yüzey skaler/pruning/tutarlılık yüzeyidir — ve o yüzey çözülmüştür.

## Tahmin (çerçevenin söylediği)

2026-09-23 → 2026-10-23 penceresinde, döngü kesintisiz koştuğu sürece:

- **(Büyüklük)** SIFIR üretim-CVE'si-değeri taşıyan bulgu. "CVE-değeri" = stok (bayraksız = `base`)
  doğrulayıcının gerçekten güvensiz bir programı KABUL etmesi; kanıtı şunlardan herhangi biri:
  elle-triyajı gerçek bir anlamsal sapma olarak doğrulanan bir **bpfref çalışma-anı diferansiyeli**;
  gerçek bir sound-olmayan kabule triyaj edilen bir **base-kabul + freq-red** (`prune_verdict_disagreement`);
  ya da base'in kabul ettiği bir programdan gelen **kernel oops/panic**.
- **(Süregelen benign sinyal)** `reg_invariants` (sync_linked_regs / alu ailesi) ve
  `prune_soundness_desync` sinyalleri TEKRARLAMAYA devam eder (reg_invariants kabaca her 5–8 turda
  bir), ve HER BİRİ üretim-güvenli triyaj olur (base reddeder, ya da base kabul edip WARN yolu
  ∅→⊤ ile sound toparlar).

## Yanlışlama koşulu (önden yazılmış)

Bu okuma **düşer** eğer 2026-10-23'ten önce döngü, yukarıda tanımlanan anlamda **tek bir
CVE-değeri taşıyan bulgu** üretirse — yani elle-triyajı ayakta kalan bir "stok-güvensizi-kabul-eder"
vakası. Tek bir örnek bile "enstrüman çözülmüş bir yüzeye nişanlı" iddiasını çürütür.

İkincil (daha zayıf) çürütme: eğer `reg_invariants`/`prune` benign sinyalleri sıfıra düşerse —
o zaman yüzey iddia edildiği gibi tetiklenmiyor demektir, ve büyüklük tahmini boş bir doğru olurdu.

**Bilerek düşen kısım:** Bu tahmin, kendi projem için KÖTÜ olan sonucu (sıfır CVE) çerçevenin
DOĞRU teşhisi olarak öngörüyor. Bir CVE bulmak av için harika olurdu ama bu okumayı yanlışlardı.
Gerilim kasıtlı: bahis, çerçevenin ölü bir yüzeyi doğru teşhis ettiği üzerinedir.

## Çözüm mekanizması (sonradan uydurulamaz)

- Her tur `.lab/hunt-ledger.txt`'e zaman damgalı satır yazar; her uyanma `.lab/hunt-loop-WAKE`'e
  gerekçe + kaydedilmiş artefakt bırakır. Döngünün CVE-değeri-wake politikası commit'li
  (devlog 0125 + CVE-politikası düzenlemesi).
- Bu ön-kayıt ŞİMDİ git'e commit'lenmiştir; içeriği ve zaman damgası herhangi bir sonuçtan
  öncedir. 2026-10-23'te (ya da ilk CVE-değeri uyanmasında) sonuç ledger'dan okunup buraya
  "SONUÇ" başlığı altında eklenecek — değiştirilmeden, düştüyse düştü olarak.

## SONUÇ

_(2026-10-23'te ya da ilk CVE-değeri uyanmasında doldurulacak. Şu an boş — kaydın birinci
statü olmasının şartı budur.)_
