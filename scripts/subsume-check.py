#!/usr/bin/env python3
"""Bağımsız `states_equal` modeli — ve önce onun kendi kalibrasyonu (devlog 0099).

`bpflive.h` canlılık analizini emitlenen baytlardan bağımsız yeniden hesaplıyor; bu, aynı
şeyin BUDAMA KARARI için karşılığıdır. Girdisi `patches/prunepair-instrumentation.patch`
ile alınmış bir yakalamadır: kernel iki durumu eşdeğer bulup budadığı anda her iki tarafın
HAM alanları (`PRUNEPAIR` satırları).

NEDEN HAM ALANLAR. 0088, kararın logdan denetlenemeyeceğini ölçtü ve sebebi biçim değil
ifade gücüydü: `range_within` artık `cnum{base,size}` üzerinde yay-içerilmesi iken log sekiz
türetilmiş projeksiyon basıyor; `precise` kontrolün yapılıp yapılmayacağına karar verirken
logda yalnız bir `P` ön-eki; `id` maskelenmiş basıldığı için ADD_CONST32/64 ayrımı kayboluyor.

YÖN VE DİSİPLİN. Elimizde yalnız kernel'in ALDIĞI prune'lar var, yani tek yön görülebilir:
kernel budadı ve model "içerilme yok" diyor. Bu ya kernel'in sağlamsızlığıdır ya bizim
modelimizin eksiği — ve `bpflive.h`'in dersi gereği, kanıtlanana kadar ikincisi varsayılır.
Model, karar veremediği bir çifti TAHMİN ETMEZ, `modellenmedi` sayar.

ÖNEMSİZLİK KONTROLÜ (0084). Bir uyum sayısı tek başına değersizdir: precision kısa-devresi
(`!rold->precise && exact == NOT_EXACT`) register'ı hiç karşılaştırmadan geçirir. Script bu
yüzden range/tnum kontrolünün GERÇEKTEN koştuğu çift sayısını ayrıca bildirir.

Kullanım:
    scripts/subsume-check.py <PRUNEPAIR taşıyan yakalama>
"""
import re, sys

UT64 = (1 << 64) - 1
UT32 = (1 << 32) - 1
SCALAR_VALUE = 1
BPF_ADD_CONST = (1 << 31) | (1 << 30)

# kernel/bpf/cnum_defs.h'ten transkribe edildi, oradan kopyalanmadı.
def cnum_is_empty(base, size, mask):
    return base == mask and size == mask

def cnum_urange_overflow(base, size, mask):
    return size > mask - base

def cnum_is_subset(bb, bs, sb, ss, mask):
    """bigger ⊇ smaller"""
    if cnum_is_empty(sb, ss, mask):
        return True
    if cnum_is_empty(bb, bs, mask):
        return False
    sb = (sb - bb) & mask          # bigger.base'i orijine döndür
    if cnum_urange_overflow(sb, ss, mask) and bs < mask:
        return False
    # Kernel bu toplamayı `ut` icinde yapar, yani SARAR (cnum_defs.h:244). Python'un
    # sinirsiz tamsayisi sarmaz, ve iki taraf tam olarak burada ayrilir: bigger.size
    # == UT_MAX iken yeniden-temellenen smaller sardiginda kernel true doner, maskesiz
    # model false -- yani YANLIS BULGU yonunde. Bu korpusta hic atesle(n)medi; sarti
    # "checkpoint'te bilinmeyen skaler + guncel durumda sarmali yay", ki --probe-wraparc
    # tam o sekli uretmeye calisiyor. Vektorler: SELFTEST_SUBSET.
    return ((sb + ss) & mask) <= bs

def s64(x):
    return x - (1 << 64) if x >> 63 else x

def s32(x):
    return x - (1 << 32) if x >> 31 else x

def range_within_minmax(o, c):
    """2026-04-24 ÖNCESİ kernel'in `range_within`'i: sekiz min/max karşılaştırması.

    Bu, cnum yay-içerilmesinin daha zayıf bir yakınsaması ve `cd5b460ed1ec` tam olarak
    bunu düzeltti. Model o dönemi modellerken o dönemin YÜKLEMİNİ uygular — yoksa aradaki
    her fark bir 'bulgu' gibi görünür ve payda çöpe döner. Dönem tabanı ALANLARDAN gelir,
    yüklemden değil ([[era-floors]])."""
    return (o['umin'] <= c['umin'] and o['umax'] >= c['umax'] and
            o['smin'] <= c['smin'] and o['smax'] >= c['smax'] and
            o['u32min'] <= c['u32min'] and o['u32max'] >= c['u32max'] and
            o['s32min'] <= c['s32min'] and o['s32max'] >= c['s32max'])

def tnum_in(a_value, a_mask, b_value, b_mask):
    """a ⊇ b"""
    if b_mask & ~a_mask:
        return False
    return a_value == (b_value & ~a_mask)

class IdMap:
    """kernel/bpf/states.c'nin `check_ids` + `check_scalar_ids`'i, transkribe edildi.

    Sıra ÖNEMLİ: idmap her `states_equal` çağrısında sıfırlanır ve register'lar frame
    sırasıyla, sonra stack slotlarıyla doldurulur. Yama stack'i henüz basmadığı için model
    id taşıyan bir stack slotu OLABİLECEK programda karar vermez — `check_ids`'in tabloyu
    ARTIMLI doldurması, eksik bir girdinin sonraki her kararı kaydırması demek."""

    def __init__(self, tmp_id_gen_seed=1 << 20):
        self.map = []
        self.tmp = tmp_id_gen_seed

    def check_ids(self, old_id, cur_id):
        if bool(old_id) != bool(cur_id):
            return False
        if old_id == 0:
            return True
        for o, c in self.map:
            if o == old_id:
                return c == cur_id
            if c == cur_id:
                return False
        self.map.append((old_id, cur_id))
        return True

    def check_scalar_ids(self, old_id, cur_id):
        """DÜZELTİLMİŞ sürüm (2f2ec8e7730e sonrası). Hatalı sürüm yalnız bileşik id'yi
        eşliyordu; taban id'nin de tutarlı eşlenmesi gerektiği kontrolü eksikti, ve
        modelin buggy kernel'den ayrıldığı nokta tam olarak burasıdır."""
        if not old_id:
            return True
        if not cur_id:
            self.tmp += 1
            cur_id = self.tmp
        if not self.check_ids(old_id, cur_id):
            return False
        if old_id & BPF_ADD_CONST:
            if not self.check_ids(old_id & ~BPF_ADD_CONST, cur_id & ~BPF_ADD_CONST):
                return False
        return True


ROW = re.compile(
    r'^PRUNEPAIR insn=(\d+) exact=(\d+) side=(old|cur) fr=(\d+) r(\d+) '
    r'type=(\d+) delta=(-?\d+) var=([0-9a-f]+)/([0-9a-f]+) '
    r'r64=([0-9a-f]+)\+([0-9a-f]+) r32=([0-9a-f]+)\+([0-9a-f]+) '
    r'id=([0-9a-f]+) pid=([0-9a-f]+) fno=(\d+) prec=(\d+)$')

# DÖNEM VARYANTI: `..` min..max aralığı demek, `+` base+size yayı. Ayıraç, tüketicinin
# hangi yüklemi borçlu olduğunu söyler.
ROW_MM = re.compile(
    r'^PRUNEPAIR insn=(\d+) exact=(\d+) side=(old|cur) fr=(\d+) r(\d+) '
    r'type=(\d+) delta=(-?\d+) var=([0-9a-f]+)/([0-9a-f]+) '
    r'u64=([0-9a-f]+)\.\.([0-9a-f]+) s64=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'u32=([0-9a-f]+)\.\.([0-9a-f]+) s32=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'id=([0-9a-f]+) fno=(\d+) prec=(\d+)$')

# 2021 DÖNEMİ: `live=` alanı hem gerekli (o çağın regsafe'i REG_LIVE_READ ile kapılıyor)
# hem de dönem işareti — satırın kendisi tüketiciye hangi regsafe'i borçlu olduğunu söylüyor.
ROW_21 = re.compile(
    r'^PRUNEPAIR insn=(\d+) exact=(\d+) side=(old|cur) fr=(\d+) r(\d+) '
    r'type=(\d+) delta=(-?\d+) var=([0-9a-f]+)/([0-9a-f]+) '
    r'u64=([0-9a-f]+)\.\.([0-9a-f]+) s64=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'u32=([0-9a-f]+)\.\.([0-9a-f]+) s32=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'id=([0-9a-f]+) fno=(\d+) prec=(\d+) live=(\d+)$')

LIVE = re.compile(r'^LIVENESS status=ok n=(\d+) mask=([0-9a-f]+)$')

def parse_lines(lines):
    """Bir çift = bir `old` koşusu + onu izleyen `cur` koşusu. Bu gruplamanın doğruluğu
    bağımsız olarak doğrulanabilir: çift sayısı, logdaki `: safe` prune olayı sayısıyla
    eşleşmelidir (0088'de 2038 ölçülmüştü, bu script de 2038 buluyor).

    Yakalama LIVENESS satırı taşıyorsa (harness `bpflive.h` iddiasını basar) o iddia
    çifte iliştirilir: model canlılık kapısını UYGULAMAZ, ama uygulamadığının BEDELİNİ
    sayabilsin diye."""
    pairs, cur = [], None
    live_mask, live_n = None, 0
    for line in lines:
        line = line.rstrip()
        if line.startswith("===PROG"):
            live_mask, live_n = None, 0
            continue
        mlive = LIVE.match(line)
        if mlive:
            live_n, live_mask = int(mlive[1]), mlive[2]
            continue
        if line.startswith("LIVENESS status=unsupported"):
            live_mask, live_n = None, 0
            continue
        m = ROW_21.match(line)
        era = '2021'
        if not m:
            m = ROW.match(line)
            era = 'cnum'
        if not m:
            m = ROW_MM.match(line)
            era = 'minmax'
        if not m:
            continue
        insn, exact, side, fr, reg = int(m[1]), int(m[2]), m[3], int(m[4]), int(m[5])
        rec = dict(t=int(m[6]), delta=int(m[7]), vv=int(m[8], 16), vm=int(m[9], 16),
                   era=era)
        if era == 'cnum':
            rec.update(b64=int(m[10], 16), sz64=int(m[11], 16),
                       b32=int(m[12], 16), sz32=int(m[13], 16),
                       id=int(m[14], 16), prec=int(m[17]))
        else:
            rec.update(umin=int(m[10], 16), umax=int(m[11], 16),
                       smin=s64(int(m[12], 16)), smax=s64(int(m[13], 16)),
                       u32min=int(m[14], 16), u32max=int(m[15], 16),
                       s32min=s32(int(m[16], 16)), s32max=s32(int(m[17], 16)),
                       id=int(m[18], 16), prec=int(m[20]))
            if era == '2021':
                rec['live'] = int(m[21])
        if side == 'old' and (cur is None or cur['done']):
            cur = {'insn': insn, 'exact': exact, 'old': {}, 'cur': {}, 'done': False,
                   'live': live_mask, 'live_n': live_n}
            pairs.append(cur)
        if cur is None:
            continue
        (cur['old'] if side == 'old' else cur['cur'])[(fr, reg)] = rec
        if side == 'cur':
            cur['done'] = True
    return pairs

def parse(path):
    with open(path, errors="replace") as fh:
        return parse_lines(fh)


class Stats:
    """Sayaçlar. `denominator()` bir BÖLÜNTÜ döndürür: dört terminal kategori toplamı
    çift sayısını vermek ZORUNDA, yoksa 'önemsiz olmayan' bir pay eski payın yeni adıdır."""

    def __init__(self):
        self.scalar_cmp = self.shortcircuit = self.other_type = self.id_checks = 0
        self.agree_trivial = self.agree_nontrivial = 0
        self.breaks = self.unmodelled = 0
        self.nontrivial_legacy = 0
        self.reasons = {}
        # UYGULANMAYAN KOLLARIN BEDELİ — hiçbiri modelde yok, ikisi yakalamadan sayılabiliyor
        self.live_gated = 0              # 2021: REG_LIVE_READ kapısı (o çağda MODELLENİYOR)
        self.ptr_id_pairs = 0            # pointer id'si kernel'in idmap'ini tohumlar, model atlar
        self.dead_reg_cmps = 0           # kernel'in HİÇ karşılaştırmadığı register'da yaptığımız kıyas
        self.live_cmps = 0
        self.pairs_no_live_claim = 0     # bpflive o programı REDDETTİ — iddia yok
        self.pairs_no_tracked_reg = 0    # iddia var, ama çiftte izlenen register yok (yalnız r10)

    def pairs(self):
        return self.agree_trivial + self.agree_nontrivial + self.breaks + self.unmodelled


def live_bit(p, fr, reg):
    """kernel `func_states_equal` yalnız `live_regs_before` içindeki register'ı kıyaslar.
    None = iddia yok (model o programı reddetmiş), True/False = canlı/ölü."""
    if p['live'] is None or fr != 0 or reg >= 10 or p['insn'] >= p['live_n']:
        return None
    return bool(int(p['live'][p['insn'] * 3:p['insn'] * 3 + 3], 16) & (1 << reg))


def evaluate(p, st):
    """Tek bir çifti kernel'in `regsafe` skaler kolundan geçir.
    Döndürür: 'unmodelled' | 'agree' | 'break'. Kırılma hâlinde p['arm'] hangi kolun
    düşürdüğünü söyler — bir aday çıktığında triyajın ilk sorusu budur.

    TEK ÇIKIŞLI: muhasebe sonda, bir kez. `nontrivial` bir çifti, kırılsa bile
    range/tnum'un GERÇEKTEN koştuğu her durumda sayar (0084'ün kuralı, ve orijinal
    sürümün semantiği)."""
    if not p['old'] or not p['cur']:
        st.unmodelled += 1
        st.reasons['eksik taraf'] = st.reasons.get('eksik taraf', 0) + 1
        return 'unmodelled'

    verdict = 'agree'
    ran_range = False
    saw_tracked_reg = False
    ptr_id = False

    for key, o in sorted(p['old'].items()):          # frame, sonra register sırası
        fr, reg = key
        c = p['cur'].get(key)
        if c is None:
            st.unmodelled += 1
            st.reasons["cur'da yok"] = st.reasons.get("cur'da yok", 0) + 1
            return 'unmodelled'

        lb = live_bit(p, fr, reg)
        if lb is not None:
            saw_tracked_reg = True
            if lb:
                st.live_cmps += 1
            else:
                st.dead_reg_cmps += 1

        if o['t'] != c['t']:
            p['arm'] = 'type'; verdict = 'break'; break
        if o['era'] == '2021' and not o['live']:
            # 2021 regsafe'in İLK satırı: `if (!(rold->live & REG_LIVE_READ)) return true;`
            # Bu, bugünkü live_regs_before kapısının atası ve register bazında basılıyor —
            # yani o çağda kapı MODELLENEBİLİR, tahmin gerekmiyor.
            st.live_gated += 1; continue
        if o['t'] != SCALAR_VALUE:
            st.other_type += 1
            if o['id'] or c['id']:
                ptr_id = True            # kernel burada idmap'i doldururdu, model doldurmuyor
            continue
        # regsafe'in skaler kolu, sırasıyla:
        if o['era'] == '2021':
            # O çağın kısa devresi ÇİFT TARAFLI ve id/delta/ADD_CONST kolları henüz YOK:
            # skaler kol tam olarak `range_within(rold,rcur) && tnum_in(...)`.
            if o['prec'] == 0 and c['prec'] == 0:
                st.shortcircuit += 1; continue
            st.scalar_cmp += 1; ran_range = True
            if not range_within_minmax(o, c):
                p['arm'] = 'range_within'; verdict = 'break'; break
            if not tnum_in(o['vv'], o['vm'], c['vv'], c['vm']):
                p['arm'] = 'tnum_in'; verdict = 'break'; break
            continue
        if o['prec'] == 0 and p['exact'] == 0:
            st.shortcircuit += 1; continue        # precision kısa-devresi
        if o['id'] and (o['id'] & BPF_ADD_CONST) != (c['id'] & BPF_ADD_CONST):
            p['arm'] = 'add_const_flag'; verdict = 'break'; break
        if (o['id'] & BPF_ADD_CONST) and o['delta'] != c['delta']:
            p['arm'] = 'delta'; verdict = 'break'; break
        if o['id'] or c['id']:
            st.id_checks += 1        # id kolu GERÇEKTEN koştu (0084'ün kuralı)
        if not p['idmap'].check_scalar_ids(o['id'], c['id']):
            p['arm'] = 'check_scalar_ids'; verdict = 'break'; break
        st.scalar_cmp += 1; ran_range = True
        if o['era'] == 'cnum':
            held = (cnum_is_subset(o['b64'], o['sz64'], c['b64'], c['sz64'], UT64) and
                    cnum_is_subset(o['b32'], o['sz32'], c['b32'], c['sz32'], UT32))
        else:
            held = range_within_minmax(o, c)
        if not held:
            p['arm'] = 'range_within'; verdict = 'break'; break
        if not tnum_in(o['vv'], o['vm'], c['vv'], c['vm']):
            p['arm'] = 'tnum_in'; verdict = 'break'; break

    if ptr_id:
        st.ptr_id_pairs += 1
    if p['live'] is None:
        st.pairs_no_live_claim += 1
    elif not saw_tracked_reg:
        # yalnız r10 (PTR_TO_STACK) taşıyan çift: `live_regs_before` r0-r9'u izler, yani
        # kernel de burada hiçbir register KARŞILAŞTIRMAZ. Denetlenebilir bir hücre yok.
        st.pairs_no_tracked_reg += 1
    if ran_range:
        st.nontrivial_legacy += 1
    if verdict == 'break':
        st.breaks += 1
    elif ran_range:
        st.agree_nontrivial += 1
    else:
        st.agree_trivial += 1
    return verdict


def run(pairs):
    st = Stats()
    candidates = []
    for p in pairs:
        p['idmap'] = IdMap()          # her çift için sıfırlanır, kernel'deki gibi
        p['arm'] = None
        if evaluate(p, st) == 'break':
            candidates.append(p)
    return st, candidates


def main(path):
    pairs = parse(path)
    st, candidates = run(pairs)
    for p in candidates:
        print(f"SUBSUME candidate insn={p['insn']} exact={p['exact']} arm={p['arm']}")
    agree = st.agree_trivial + st.agree_nontrivial
    print(f"SUBSUME pairs={len(pairs)} modelled={agree + st.breaks} "
          f"agree={agree} disagree={st.breaks} unmodelled={st.unmodelled}")
    print(f"SUBSUME nontrivial_pairs={st.nontrivial_legacy} scalar_comparisons={st.scalar_cmp} "
          f"shortcircuited_regs={st.shortcircuit} other_type_regs={st.other_type} "
          f"id_checks={st.id_checks}")
    # PAYDA KURALI: dört terminal kategori çift sayısını vermek zorunda.
    print(f"SUBSUME denominator pairs={len(pairs)} trivial={st.agree_trivial} "
          f"nontrivial={st.agree_nontrivial} breaks={st.breaks} "
          f"unmodelled={st.unmodelled} sums={'ok' if st.pairs() == len(pairs) else 'MISMATCH'}")
    # UYGULANMAYAN KOLLAR. refsafe'in idmap tohumlaması yakalamadan GÖZLENEMEZ — yama
    # refs[]/active_lock_id basmıyor — ve bunu söylemek sayının kendisidir.
    print(f"SUBSUME unimplemented_arms ptr_id_pairs={st.ptr_id_pairs} "
          f"dead_reg_cmps={st.dead_reg_cmps} live_reg_cmps={st.live_cmps} "
          f"pairs_without_liveness_claim={st.pairs_no_live_claim} "
          f"pairs_without_tracked_reg={st.pairs_no_tracked_reg} "
          f"live_gated_regs={st.live_gated} "
          f"refsafe_idmap_seed=not-observable-from-capture")
    for k, v in sorted(st.reasons.items()):
        print(f"SUBSUME unmodelled_reason {k}={v}")
    return 0


# ---- KENDİ KALİBRASYONU -------------------------------------------------------------
#
# Bir modelin testi, modelin YANLIŞ hâlinde DÜŞMEK zorundadır; iki yanda da geçen bir
# vektör o hatanın testi değil, yanından geçen bir vektördür. Aşağıdaki her vektör bir
# ölçülmüş olaya bağlı, ve hangi kolun onu düşürdüğü adıyla yazılı.

SELFTEST_SUBSET = [
    # (ad, bigger(base,size), smaller(base,size), mask, beklenen)
    ("B1 · old BİLİNMEYEN, cur SARMALI YAY — maskesiz model burada YANLIŞ BULGU üretir",
     (0, UT32), (0xfffffff0, 0x20), UT32, True),
    ("B1 · aynısı, bigger.base sıfır değil",
     (5, UT32), (0xfffffff0, 0x20), UT32, True),
    ("B1 · 64 bit karşılığı",
     (0, UT64), (UT64 - 0xf, 0x20), UT64, True),
    ("cd5b460ed1ec'in kendi karşı örneği — sarmalı yayın BOŞLUĞUNDA bir değer",
     (0x7FFFFFF0, 0x80000020), (0x100, 0x100), UT32, False),
    ("bigger.size < UT_MAX iken sarmalı smaller hâlâ reddedilmeli",
     (0x10, 0x20), (0xfffffff0, 0x20), UT32, False),
    ("boş smaller her zaman içerilir", (0, 0), (UT32, UT32), UT32, True),
    ("boş bigger hiçbir şeyi içermez", (UT32, UT32), (0, 0), UT32, False),
    ("sabit ⊇ sabit", (7, 0), (7, 0), UT32, True),
    ("sabit ⊉ farklı sabit", (7, 0), (8, 0), UT32, False),
]

SELFTEST_TNUM = [
    ("bilinmeyen ⊇ sabit", (0, UT64), (5, 0), True),
    ("sabit ⊉ bilinmeyen", (5, 0), (0, UT64), False),
    ("alt bitleri sabit yay, uyan değer", (0x10, 0xffffffe0), (0x110, 0), True),
    ("alt bitleri sabit yay, UYMAYAN değer", (0x10, 0xffffffe0), (0x100, 0), False),
]

SELFTEST_IDS = [
    # 2f2ec8e7730e'nin kendi örneği: old r2.id=A, r3.id=A|flag; cur r2.id=B, r3.id=C|flag.
    # Taban çapraz-kontrolü OLMADAN geçerdi; DÜZELTİLMİŞ yüklem düşürür. Bu, modelin o
    # hataya karşı POZİTİF kontrolüdür — hatalı kernel budar, model reddeder.
    ("2f2ec8e7730e · taban id tutarsızlığı yakalanmalı",
     [(0xA, 0xB), (0xA | BPF_ADD_CONST, 0xC | BPF_ADD_CONST)], False),
    ("tutarlı taban geçmeli",
     [(0xA, 0xB), (0xA | BPF_ADD_CONST, 0xB | BPF_ADD_CONST)], True),
    ("old_id=0 her zaman geçer", [(0, 0x5)], True),
    ("aynı old iki farklı cur'a eşlenemez", [(0xA, 0xB), (0xA, 0xC)], False),
]

# DÖNEM KOLU (2026-04-24 öncesi min/max `range_within`). Yeni bir kol test edilmeden
# eklenirse B4'ün ta kendisi tekrarlanır, o yüzden burası da vektörlü.
def _mm(umin, umax, smin, smax, u32min, u32max, s32min, s32max):
    return dict(umin=umin, umax=umax, smin=smin, smax=smax,
                u32min=u32min, u32max=u32max, s32min=s32min, s32max=s32max)

FULL64 = _mm(0, UT64, -(1 << 63), (1 << 63) - 1, 0, UT32, -(1 << 31), (1 << 31) - 1)
CONST7 = _mm(7, 7, 7, 7, 7, 7, 7, 7)

SELFTEST_MINMAX = [
    ("bilinmeyen ⊇ sabit", FULL64, CONST7, True),
    ("sabit ⊉ bilinmeyen", CONST7, FULL64, False),
    ("sabit ⊇ kendisi", CONST7, CONST7, True),
    # cd5b460ed1ec'in KENDİ karşı örneği: sarmalı yayın projeksiyonları tam aralığa açılır,
    # boşluktaki bir değer min/max kontrolünden GEÇER. Dönem modeli bu ZAYIFLIĞI birebir
    # taşımak zorunda — yoksa dönem kernel'iyle her yerde ayrışır ve payda çöpe döner.
    ("cd5b460ed1ec · sarmalı yayın boşluğundaki değer min/max'ten GEÇER (dönemin hatası)",
     FULL64, _mm(0x100, 0x200, 0x100, 0x200, 0x100, 0x200, 0x100, 0x200), True),
    ("işaretli sınır: old.smin > cur.smin ise düşer",
     _mm(0, UT64, 0, (1 << 63) - 1, 0, UT32, 0, (1 << 31) - 1),
     _mm(0, UT64, -1, (1 << 63) - 1, 0, UT32, -1, (1 << 31) - 1), False),
]

# Dönem biçiminin uçtan uca ayrıştırılması: `..` ayıracı min..max demek, ve işaretli
# alanlar ham iki-tümleyen basılır (s64=ffff..ffff -> -1).
SELFTEST_ERA = """\
===PROG selftest#era ===
PRUNEPAIR insn=3 exact=2 side=old fr=0 r6 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..7fffffff id=0 fno=0 prec=1
PRUNEPAIR insn=3 exact=2 side=cur fr=0 r6 type=1 delta=0 var=7/0 u64=7..7 s64=7..7 u32=7..7 s32=7..7 id=0 fno=0 prec=1
"""

# 2021 DÖNEMİ, uçtan uca. Üç ayrı davranış pinleniyor: REG_LIVE_READ kapısı, ÇİFT TARAFLI
# kısa devre, ve fd675184fc7a'nın kendi imzası — 64-bit sınırlar aynı, 32-bit sınırlar
# ayrışıyor. Hatalı kernel yalnız dört 64-bit karşılaştırma yaptığı için budar; model
# sekizin tamamını uyguladığı için reddeder. Bu, o çiftin BEKLENEN sinyalidir.
SELFTEST_2021_TRIGGER = """\
===PROG selftest#era2021 ===
PRUNEPAIR insn=7 exact=0 side=old fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..3030 id=0 fno=0 prec=1 live=1
PRUNEPAIR insn=7 exact=0 side=cur fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..7fffffff id=0 fno=0 prec=1 live=1
"""

# Aynı çift, ama old ÖLÜ: o çağın regsafe'i ilk satırda `return true` der, model de öyle.
SELFTEST_2021_LIVEGATE = """\
===PROG selftest#era2021gate ===
PRUNEPAIR insn=7 exact=0 side=old fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..3030 id=0 fno=0 prec=1 live=0
PRUNEPAIR insn=7 exact=0 side=cur fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..7fffffff id=0 fno=0 prec=1 live=0
"""

# Aynı çift, iki taraf da imprecise: ÇİFT TARAFLI kısa devre geçer.
SELFTEST_2021_SC = SELFTEST_2021_TRIGGER.replace("prec=1", "prec=0")

# B3a · ÖLÜ REGISTER. Model canlılık kapısını uygulamıyor: kernel `live_regs_before`
# dışındaki register'ı HİÇ karşılaştırmaz, model karşılaştırır. Aşağıdaki çiftte r6 ölü
# ve içerilme tutmuyor — kernel budardı, model "aday" der. Vektör bu BOŞLUĞU pinliyor:
# davranış değişirse (kapı bağlanırsa) burası düşer ve bilinçli güncellenir.
SELFTEST_DEADREG = """\
===PROG selftest#deadreg ===
LIVENESS status=ok n=4 mask=001001001001
PRUNEPAIR insn=2 exact=2 side=old fr=0 r6 type=1 delta=0 var=7/0 r64=7+0 r32=7+0 id=0 pid=0 fno=0 prec=1
PRUNEPAIR insn=2 exact=2 side=cur fr=0 r6 type=1 delta=0 var=0/ffffffffffffffff r64=0+ffffffffffffffff r32=0+ffffffff id=0 pid=0 fno=0 prec=1
"""


def self_test():
    fails = []

    def check(group, name, got, want):
        if got != want:
            fails.append(f"{group}: {name}\n    beklenen={want} alınan={got}")

    for name, big, small, mask, want in SELFTEST_SUBSET:
        check("cnum_is_subset", name,
              cnum_is_subset(big[0], big[1], small[0], small[1], mask), want)

    for name, a, b, want in SELFTEST_TNUM:
        check("tnum_in", name, tnum_in(a[0], a[1], b[0], b[1]), want)

    for name, body, want_breaks, want_arm in [
            ("fd675184fc7a imzası: 64-bit aynı, 32-bit ayrışıyor → reddedilmeli",
             SELFTEST_2021_TRIGGER, 1, 'range_within'),
            ("REG_LIVE_READ kapısı: old ölü → kıyas hiç yapılmaz",
             SELFTEST_2021_LIVEGATE, 0, None),
            ("çift taraflı kısa devre: iki taraf da imprecise → geçer",
             SELFTEST_2021_SC, 0, None)]:
        pr = parse_lines(body.splitlines())
        check("2021 dönemi", name + " [ayrıştırma]", len(pr), 1)
        if pr:
            check("2021 dönemi", name + " [era]", pr[0]['old'][(0, 4)]['era'], '2021')
            st21, c21 = run(pr)
            check("2021 dönemi", name, st21.breaks, want_breaks)
            if want_arm:
                check("2021 dönemi", name + " [kol]", c21[0]['arm'] if c21 else None, want_arm)

    for name, big, small, want in SELFTEST_MINMAX:
        check("range_within_minmax", name, range_within_minmax(big, small), want)

    era = parse_lines(SELFTEST_ERA.splitlines())
    check("parse", "dönem biçimi bir çift üretmeli", len(era), 1)
    if era:
        o = era[0]['old'][(0, 6)]
        check("parse", "dönem biçimi 'minmax' işaretlenmeli", o['era'], 'minmax')
        check("parse", "işaretli alan iki-tümleyenden çözülmeli", o['smin'], -(1 << 63))
        st_e, _ = run(era)
        check("dönem kolu", "bilinmeyen ⊇ sabit, uyum beklenir",
              (st_e.breaks, st_e.agree_nontrivial), (0, 1))

    for name, seq, want in SELFTEST_IDS:
        idmap = IdMap()
        got = all(idmap.check_scalar_ids(o, c) for o, c in seq)
        check("check_scalar_ids", name, got, want)

    pairs = parse_lines(SELFTEST_DEADREG.splitlines())
    check("parse", "ölü-register vektörü tek çift üretmeli", len(pairs), 1)
    if pairs:
        st, cands = run(pairs)
        check("B3a boşluğu", "kernel budardı, model aday der (kapı UYGULANMIYOR)",
              (st.breaks, st.dead_reg_cmps), (1, 1))
        check("B3a boşluğu", "düşüren kol range_within olmalı",
              cands[0]['arm'] if cands else None, 'range_within')

    for f in fails:
        print("SELFTEST FAIL " + f)
    total = (len(SELFTEST_SUBSET) + len(SELFTEST_TNUM) + len(SELFTEST_IDS)
             + len(SELFTEST_MINMAX) + 7 + 10)  # +7 parse/ölü-reg/dönem, +10 2021 kolu
    print(f"SELFTEST vectors={total} failed={len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        sys.exit(self_test())
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1]))
