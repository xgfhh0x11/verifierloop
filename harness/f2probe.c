// f2probe — F2 (sync_linked_regs boş-aralık) için ELLE YAZILMIŞ, kontrol-kollu prob.
//
// NEDEN AYRI BİR İKİLİ: diffharness.c eşzamanlı bir av turu tarafından kullanılıyor ve
// paylaşımlı rootfs'e kurulan tek bir ikili var. Bu prob o aleti hiç değiştirmesin diye
// tamamen kendi kendine yeter: kendi makroları, kendi bpf() sarmalayıcısı.
//
// ÜÇ SORUYU AYRI AYRI CEVAPLIYOR:
//   Kapı 2 — boş aralıklı register bir BELLEK ERİŞİMİNE base+offset olarak girerse ne olur?
//            (M1 mağaza, M2 yükleme). Kabul edilirse KASAN'lı kernel'de çalıştırılıyor.
//   Kapı 3 — genom değil, elle yazılmış minimal program + ÜÇ KONTROL KOLU. Her kontrol
//            tek bir bileşeni kaldırıyor; ihlalin o bileşene bağlı olduğunu gösteriyor.
//
// Çıktı satır-çerçeveli: F2 name=<ad> flags=<0|inv> verdict=<accept|reject> errno=<n>
//                        viol=<0|1> ctx=<...> tail=<reddin son satırı>
//
// Build: cc -O2 -static -o harness/f2probe harness/f2probe.c

#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_ALU64_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                 \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_MOV64_IMM(DST, IMM)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K,                    \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_MOV64_REG(DST, SRC)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                    \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K,                   \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                                       \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                                        \
    ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,              \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_LD_MAP_FD(DST, FD)                                                 \
    ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = DST,      \
                       .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = (FD)}),  \
    ((struct bpf_insn){0})
#define BPF_EMIT_CALL(FUNC)                                                    \
    ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (FUNC)})
#define BPF_EXIT_INSN()                                                        \
    ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0})

static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

static char g_log[1 << 22];

/* Değişken kısım: ihlalin oluştuğu noktaya konan yük. Her varyant burada ayrışıyor. */
enum payload { PL_ALU, PL_STORE, PL_LOAD, PL_NONE };

/* Kontrol kolları: her biri TEK bir bileşeni kaldırır.
   NO_ADDCONST — r7 = r6 ama +8 yok      -> kesişim {16}, boş değil
   NO_LINK     — r7 bağımsız yüklenir     -> sync_linked_regs r6'ya hiç dokunmaz
   NO_UMIN     — w6>3 dalı yok            -> umin 0 kalır, kesişimde 0 var          */
enum arm { ARM_FULL, ARM_NO_ADDCONST, ARM_NO_LINK, ARM_NO_UMIN };

static int build(struct bpf_insn *p, int map_fd, enum arm arm, enum payload pl) {
    int n = 0;
    p[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    p[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    { struct bpf_insn ld[] = { BPF_LD_MAP_FD(BPF_REG_1, map_fd) };
      p[n++] = ld[0]; p[n++] = ld[1]; }
    p[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    int jnull = n;
    p[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);   /* off sonra doldurulur */
    p[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);     /* r8 = map_value ptr */
    p[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    p[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 9);    /* {0,1,8,9} */
    p[n++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 2);    /* {0,2,16,18} */

    if (arm != ARM_NO_UMIN) {
        p[n++] = BPF_JMP32_IMM(BPF_JGT, BPF_REG_6, 3, 1);  /* taken: umin 4 */
        p[n++] = BPF_MOV64_IMM(BPF_REG_9, 0);              /* atlanan dolgu */
    }

    if (arm == ARM_NO_LINK) {
        /* r7 aynı aralığı taşır ama BAĞ YOK: bağımsız yükleme + aynı aritmetik. */
        p[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
        p[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 9);
        p[n++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, 2);
        p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 8);
    } else {
        p[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);      /* BAĞ: aynı id */
        if (arm != ARM_NO_ADDCONST)
            p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 8); /* BPF_ADD_CONST */
    }

    /* İmkânsız kol: r7 > 16'nın DÜŞEN kolu. Yük oraya konuyor. */
    int npl = (pl == PL_ALU) ? 1 : (pl == PL_STORE ? 3 : (pl == PL_LOAD ? 3 : 0));
    p[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 16, npl);

    switch (pl) {
    case PL_ALU:
        p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_6);
        break;
    case PL_STORE:
        p[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
        p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_6); /* ptr += boş skaler */
        p[n++] = BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 0x41);
        break;
    case PL_LOAD:
        p[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
        p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_6);
        p[n++] = BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0);
        break;
    case PL_NONE: break;
    }

    p[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    p[n++] = BPF_EXIT_INSN();
    p[jnull].off = n - jnull - 2;   /* null ise son iki insn'e (r0=0; exit) atla */
    return n;
}

static void run(const char *name, int map_fd, enum arm arm, enum payload pl, uint32_t flags) {
    struct bpf_insn ins[64];
    int n = build(ins, map_fd, arm, pl);

    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insn_cnt = n;
    a.insns = (uint64_t)(unsigned long)ins;
    a.license = (uint64_t)(unsigned long)"GPL";
    a.log_level = 2;
    a.log_size = sizeof(g_log);
    a.log_buf = (uint64_t)(unsigned long)g_log;
    a.prog_flags = flags;
    g_log[0] = '\0';
    int fd = bpf(BPF_PROG_LOAD, &a, sizeof(a));
    int e = errno;

    const char *v = strstr(g_log, "REG INVARIANTS VIOLATION");
    char ctx[32] = "-";
    if (v) {
        const char *o = strchr(v, '('), *c = o ? strchr(o, ')') : NULL;
        if (o && c && (size_t)(c - o) < sizeof(ctx)) {
            size_t k = (size_t)(c - o - 1);
            memcpy(ctx, o + 1, k); ctx[k] = '\0';
        }
    }
    /* Reddin sebebi loğun son dolu satırıdır; verdict'i açıklayan tek şey o. */
    /* Reddin SEBEBI lazim: son dolu satirlarin hepsini bas, "processed N insns"
       ozetini atlayarak. Tek satir secmek kirilgan cikti -- bazi redlerde sebep
       satirindan sonra bos satir var. */
    char tail[400] = "-";
    if (fd < 0) {
        const char *lines[8]; int nl = 0;
        char *buf = strdup(g_log);
        for (char *t = strtok(buf, "\n"); t; t = strtok(NULL, "\n")) {
            if (!*t) continue;
            if (!strncmp(t, "processed ", 10)) continue;
            if (nl < 8) { lines[nl++] = t; }
            else { memmove(lines, lines + 1, 7 * sizeof(*lines)); lines[7] = t; }
        }
        tail[0] = '\0';
        for (int i = (nl > 3 ? nl - 3 : 0); i < nl; i++) {
            strncat(tail, lines[i], sizeof(tail) - strlen(tail) - 4);
            strncat(tail, " | ", sizeof(tail) - strlen(tail) - 1);
        }
        free(buf);
    }
    printf("F2 name=%-22s insns=%2d flags=%-3s verdict=%-6s errno=%-3d viol=%d ctx=%-10s\n     tail=%s\n",
           name, n, flags ? "inv" : "0", fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : e,
           v ? 1 : 0, ctx, tail);
    fflush(stdout);

    /* Kapı 2'nin asıl sorusu: kabul edilen bir bellek erişimi ÇALIŞTIRILDIĞINDA ne oluyor?
       Bunu userspace'ten değil, kernel'in KASAN'ından öğreniyoruz — bu yüzden sadece
       koşturuyoruz ve konsola ne düştüğüne bakıyoruz. */
    if (fd >= 0 && (pl == PL_STORE || pl == PL_LOAD) && flags == 0) {
        char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)pkt;
        t.test.data_size_in = sizeof(pkt);
        t.test.repeat = 1;
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        printf("F2 RUN  name=%-22s testrun=%d errno=%d retval=0x%08x\n",
               name, r, r < 0 ? errno : 0, r < 0 ? 0 : (unsigned)t.test.retval);
        fflush(stdout);
    }
    if (fd >= 0) close(fd);
}

int main(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 64;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) { printf("F2 ERROR map_create errno=%d\n", errno); return 1; }

    printf("F2 BEGIN\n");
    struct { const char *name; enum arm arm; enum payload pl; } T[] = {
        { "P0_alu",            ARM_FULL,          PL_ALU   },  /* referans: ihlal beklenir  */
        { "C1_no_addconst",    ARM_NO_ADDCONST,   PL_ALU   },  /* kontrol: beklenmez        */
        { "C2_no_link",        ARM_NO_LINK,       PL_ALU   },  /* kontrol: beklenmez        */
        { "C3_no_umin",        ARM_NO_UMIN,       PL_ALU   },  /* kontrol: beklenmez        */
        { "M1_store_via_ptr",  ARM_FULL,          PL_STORE },  /* KAPI 2: mağaza            */
        { "M2_load_via_ptr",   ARM_FULL,          PL_LOAD  },  /* KAPI 2: yükleme           */
        { "M3_store_no_link",  ARM_NO_LINK,       PL_STORE },  /* KAPI 2 KONTROLÜ: boş değil */
        { "M4_load_no_link",   ARM_NO_LINK,       PL_LOAD  },  /* KAPI 2 KONTROLÜ: boş değil */
        { "N0_no_payload",     ARM_FULL,          PL_NONE  },  /* yük yokken ne oluyor      */
    };
    for (unsigned i = 0; i < sizeof(T)/sizeof(T[0]); i++) {
        run(T[i].name, map_fd, T[i].arm, T[i].pl, 0);
        run(T[i].name, map_fd, T[i].arm, T[i].pl, 1u << 7 /* BPF_F_TEST_REG_INVARIANTS */);
    }
    printf("F2 END\n");
    close(map_fd);
    return 0;
}
