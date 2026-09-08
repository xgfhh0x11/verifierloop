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
    return (sb + ss) <= bs

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

def parse(path):
    """Bir çift = bir `old` koşusu + onu izleyen `cur` koşusu. Bu gruplamanın doğruluğu
    bağımsız olarak doğrulanabilir: çift sayısı, logdaki `: safe` prune olayı sayısıyla
    eşleşmelidir (0088'de 2038 ölçülmüştü, bu script de 2038 buluyor)."""
    pairs, cur = [], None
    for line in open(path, errors="replace"):
        m = ROW.match(line.rstrip())
        if not m:
            continue
        insn, exact, side, fr, reg = int(m[1]), int(m[2]), m[3], int(m[4]), int(m[5])
        rec = dict(t=int(m[6]), delta=int(m[7]), vv=int(m[8], 16), vm=int(m[9], 16),
                   b64=int(m[10], 16), s64=int(m[11], 16),
                   b32=int(m[12], 16), s32=int(m[13], 16),
                   id=int(m[14], 16), prec=int(m[17]))
        if side == 'old' and (cur is None or cur['done']):
            cur = {'insn': insn, 'exact': exact, 'old': {}, 'cur': {}, 'done': False}
            pairs.append(cur)
        if cur is None:
            continue
        (cur['old'] if side == 'old' else cur['cur'])[(fr, reg)] = rec
        if side == 'cur':
            cur['done'] = True
    return pairs

def main(path):
    pairs = parse(path)
    agree = disagree = unmodelled = nontrivial = 0
    scalar_cmp = shortcircuit = other_type = id_checks = 0
    reasons = {}
    for p in pairs:
        if not p['old'] or not p['cur']:
            unmodelled += 1; reasons['eksik taraf'] = reasons.get('eksik taraf', 0) + 1
            continue
        skip = False; holds = True; ran_range = False
        idmap = IdMap()          # her çift için sıfırlanır, kernel'deki gibi
        for key, o in sorted(p['old'].items()):   # frame, sonra register sırası
            c = p['cur'].get(key)
            if c is None:
                skip = True; reasons["cur'da yok"] = reasons.get("cur'da yok", 0) + 1; break
            if o['t'] != c['t']:
                holds = False; break
            if o['t'] != SCALAR_VALUE:
                other_type += 1; continue          # pointer kolları henüz modellenmiyor
            # regsafe'in skaler kolu, sırasıyla:
            if o['prec'] == 0 and p['exact'] == 0:
                shortcircuit += 1; continue        # precision kısa-devresi
            if o['id'] and (o['id'] & BPF_ADD_CONST) != (c['id'] & BPF_ADD_CONST):
                holds = False; break
            if (o['id'] & BPF_ADD_CONST) and o['delta'] != c['delta']:
                holds = False; break
            if o['id'] or c['id']:
                id_checks += 1        # id kolu GERÇEKTEN koştu (0084'ün kuralı)
            if not idmap.check_scalar_ids(o['id'], c['id']):
                holds = False; break
            scalar_cmp += 1; ran_range = True
            if not (cnum_is_subset(o['b64'], o['s64'], c['b64'], c['s64'], UT64) and
                    cnum_is_subset(o['b32'], o['s32'], c['b32'], c['s32'], UT32)):
                holds = False; break
            if not tnum_in(o['vv'], o['vm'], c['vv'], c['vm']):
                holds = False; break
        if skip:
            unmodelled += 1; continue
        if ran_range:
            nontrivial += 1
        if holds:
            agree += 1
        else:
            disagree += 1
            print(f"SUBSUME candidate insn={p['insn']} exact={p['exact']}")
    print(f"SUBSUME pairs={len(pairs)} modelled={agree + disagree} "
          f"agree={agree} disagree={disagree} unmodelled={unmodelled}")
    print(f"SUBSUME nontrivial_pairs={nontrivial} scalar_comparisons={scalar_cmp} "
          f"shortcircuited_regs={shortcircuit} other_type_regs={other_type} "
          f"id_checks={id_checks}")
    for k, v in sorted(reasons.items()):
        print(f"SUBSUME unmodelled_reason {k}={v}")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1]))
