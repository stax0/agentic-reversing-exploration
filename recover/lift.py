#!/usr/bin/env python3
"""
Abstract interpreter for VM edge actions.

Recovers, per action: the phase guard/update, any variant assertion, the
ValueKey derivation arguments, and the exact (dst <- src) register permutation.

Values are symbolic tuples; the three called helpers are modelled as stubs.
Anything the interpreter cannot model becomes an opaque ('top',) rather than a
silently wrong constant, and `verify` cross-checks two actions against hand
decompilation.
"""
import sys, os, json, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import Image, TABLES, M64

VEC_DATA = (0x17E37C, 0x17E5F4)
MASK_FN  = 0x77DCC
VKEY_FN  = 0x13CE14
T32_FN   = (0x77E48, 0x77E74)
ID_FN    = 0x24544
RET      = 0xD65F03C0
TOP      = ("top",)

# ctx field offsets we care about
F_VKEY, F_STEP, F_VARIANT, F_PHASE, F_BANK = 0x90, 0xA0, 0xA8, 0xB0, 0xB4


def ptr(base, off):
    return ("ptr", base, off)


def add(v, k):
    if v is None or v is TOP:
        return TOP
    if v[0] == "ptr":
        return ptr(v[1], v[2] + k)
    if v[0] == "c":
        return ("c", (v[1] + k) & M64)
    return TOP


class Act:
    def __init__(self):
        self.phase_assert = None
        self.phase_write = None
        self.variant_assert = None
        self.vkey_args = None
        self.moves = []          # (dst_idx, src_idx, kind)
        self.unmodelled = 0


def lift(img, fn, end):
    a_ = Act()
    reg = [None] * 32
    reg[0] = ptr("ctx", 0)
    reg[31] = ptr("sp", 0)
    mem = {}
    ncall_vecdata = 0
    pc = fn

    def ld(v):
        if v is TOP or v is None or v[0] != "ptr":
            return TOP
        return mem.get((v[1], v[2]), ("load", v[1], v[2]))

    while pc < end:
        w = img.u32(pc)
        pc += 4
        if w == RET:
            break
        rd, rn, rm = w & 31, (w >> 5) & 31, (w >> 16) & 31

        # ---- move wide immediate ----
        if (w & 0x7F800000) in (0x12800000, 0x52800000, 0x72800000):
            hw, imm = (w >> 21) & 3, (w >> 5) & 0xFFFF
            sh = hw * 16
            kind = w & 0x7F800000
            if kind == 0x52800000:
                reg[rd] = ("c", (imm << sh) & M64)
            elif kind == 0x12800000:
                reg[rd] = ("c", (~(imm << sh)) & M64)
            else:
                cur = reg[rd][1] if (reg[rd] and reg[rd][0] == "c") else 0
                reg[rd] = ("c", (cur & ~(0xFFFF << sh) | (imm << sh)) & M64)
            continue

        # ---- add/sub immediate (pointer arithmetic) ----
        if (w & 0x7F800000) in (0x11000000, 0x51000000):
            imm = (w >> 10) & 0xFFF
            if (w >> 22) & 1:
                imm <<= 12
            if (w & 0x7F800000) == 0x51000000:
                imm = -imm
            reg[rd] = add(reg[rn], imm)
            continue

        # ---- loads / stores (scaled + unscaled, 64/32) ----
        st = None
        if (w & 0xFFC00000) == 0xF9000000:
            st = ("s", ((w >> 10) & 0xFFF) * 8)
        elif (w & 0xFFC00000) == 0xF9400000:
            st = ("l", ((w >> 10) & 0xFFF) * 8)
        elif (w & 0xFFC00000) == 0xB9000000:
            st = ("s32", ((w >> 10) & 0xFFF) * 4)
        elif (w & 0xFFC00000) == 0xB9400000:
            st = ("l32", ((w >> 10) & 0xFFF) * 4)
        elif (w & 0xFFC00000) in (0xF8000000, 0xB8000000):
            o = (w >> 12) & 0x1FF
            st = ("s", o - 512 if o & 0x100 else o)
        elif (w & 0xFFC00000) in (0xF8400000, 0xB8400000):
            o = (w >> 12) & 0x1FF
            st = ("l", o - 512 if o & 0x100 else o)
        if st:
            tgt = add(reg[rn], st[1])
            if st[0].startswith("s"):
                if tgt is not TOP and tgt[0] == "ptr":
                    mem[(tgt[1], tgt[2])] = reg[rd]
                    if tgt[1] == "ctx" and tgt[2] == F_PHASE:
                        v = reg[rd]
                        a_.phase_write = v[1] if (v and v[0] == "c") else "?"
            else:
                reg[rd] = ld(tgt)
            continue

        # ---- branch with link ----
        if (w & 0xFC000000) == 0x94000000:
            off = w & 0x3FFFFFF
            if off & 0x2000000:
                off -= 0x4000000
            tgt = (pc - 4 + off * 4) & M64
            if tgt in VEC_DATA:
                reg[0] = ptr("src" if ncall_vecdata == 0 else "dst", 0)
                ncall_vecdata += 1
            elif tgt == MASK_FN:
                k, idx, salt = reg[0], reg[2], reg[3]
                knd = "new" if (k and k[0] == "newkey") else "old"
                reg[0] = ("mask", knd,
                          idx[1] if (idx and idx[0] == "c") else "?",
                          salt[1] if (salt and salt[0] == "c") else "?")
            elif tgt == VKEY_FN:
                a_.vkey_args = tuple(
                    (reg[i][1] if (reg[i] and reg[i][0] == "c") else
                     ("field:%#x" % reg[i][2] if (reg[i] and reg[i][0] == "load"
                                                  and reg[i][1] == "ctx") else "?"))
                    for i in (2, 3, 4, 5, 6))
                reg[0] = ("newkey", 0)
                reg[1] = ("newkey", 1)
            elif tgt in T32_FN:
                reg[0] = ("t32", reg[0])
            elif tgt == ID_FN:
                pass                      # identity stub: x0 unchanged
            else:
                a_.unmodelled += 1
                reg[0] = TOP
            for i in range(2, 18):        # caller-saved
                reg[i] = TOP
            continue

        # ---- compare immediate: catch the phase / variant guards ----
        if (w & 0x7F800000) == 0x71000000:            # SUBS (CMP) immediate
            imm = (w >> 10) & 0xFFF
            src = reg[rn]
            if src and src[0] == "load" and src[1] == "ctx":
                if src[2] == F_PHASE:
                    a_.phase_assert = imm
                elif src[2] == F_VARIANT:
                    a_.variant_assert = imm
            continue
        if (w & 0x7F000000) in (0x34000000, 0x35000000):   # CBZ / CBNZ
            src = reg[rd]
            if src and src[0] == "load" and src[1] == "ctx":
                if src[2] == F_VARIANT:
                    a_.variant_assert = 0
                elif src[2] == F_PHASE:
                    a_.phase_assert = 0
            continue

        # ---- data-processing: build expressions ----
        # NB: in data-processing encodings register 31 is XZR (zero), NOT SP.
        # SP only means SP in load/store and add/sub-immediate addressing.
        def gp(i):
            return ("c", 0) if i == 31 else reg[i]

        def binop(op):
            return ("e", op, gp(rn), gp(rm))
        if (w & 0x7F200000) == 0x4A000000:
            reg[rd] = binop("^")
        elif (w & 0x7F200000) == 0x0B000000:
            reg[rd] = binop("+")
        elif (w & 0x7F200000) == 0x4B000000:
            reg[rd] = binop("-")
        elif (w & 0x7F200000) == 0x0A000000:
            reg[rd] = binop("&")
        elif (w & 0x7F200000) == 0x2A000000:
            reg[rd] = gp(rm) if rn == 31 else gp(rn)        # MOV via ORR
        elif (w & 0x7F800000) == 0x52000000:
            reg[rd] = ("e", "^imm", gp(rn), None)
        else:
            pass            # everything else leaves regs alone (glue)

    # ---------- decode the dst stores into (dst, src, kind) ----------
    def find_src(v, depth=0):
        """Walk an expression for the single src[] load it is built from."""
        if v is None or v is TOP or depth > 12:
            return None
        if v[0] == "load" and v[1] == "src":
            return v[2] // 8
        if v[0] == "t32":
            return find_src(v[1], depth + 1)
        if v[0] == "e":
            for side in (v[2], v[3]):
                r = find_src(side, depth + 1)
                if r is not None:
                    return r
        return None

    def has_mask(v, depth=0):
        if v is None or v is TOP or depth > 12:
            return False
        if v[0] == "mask":
            return True
        if v[0] == "t32":
            return has_mask(v[1], depth + 1)
        if v[0] == "e":
            return has_mask(v[2], depth + 1) or has_mask(v[3], depth + 1)
        return False

    for (base, off), val in sorted(mem.items(), key=lambda kv: kv[0][1]):
        if base != "dst":
            continue
        s = find_src(val)
        a_.moves.append((off // 8, s, "remask" if has_mask(val) else "plain"))
    return a_


def main():
    img = Image(sys.argv[1])
    starts = set()
    for _nm, (base, n) in TABLES.items():
        for i in range(n):
            starts.add(img.qword(base + 8 * i))
    starts |= {MASK_FN, VKEY_FN, ID_FN, *VEC_DATA, *T32_FN}
    ta, tsz = img.sections[".text"]
    starts.add(ta + tsz)
    S = sorted(starts)
    nxt = {S[i]: S[i + 1] for i in range(len(S) - 1)}

    ab, nact = TABLES["act"]
    acts = {}
    for i in range(nact):
        fn = img.qword(ab + 8 * i)
        acts[i] = lift(img, fn, nxt[fn])

    # ---------------- verify against hand decompilation ----------------
    print("=== verification against decompiled act0 / act4 ===")
    # expected moves read from the decompilation of act4 @ 0x788F0
    exp4 = {(999, 836, "remask"), (933, 749, "remask"), (703, 812, "plain"),
            (506, 745, "plain"), (905, 119, "plain"), (693, 515, "plain"),
            (269, 123, "plain")}
    got4 = set(acts[4].moves)
    print("act4 phase %s -> %s | variant_assert=%s | vkey_args=%s"
          % (acts[4].phase_assert, acts[4].phase_write,
             acts[4].variant_assert, acts[4].vkey_args))
    print("act4 moves match decompile: %s" % (got4 == exp4))
    if got4 != exp4:
        print("   expected-not-got:", sorted(exp4 - got4))
        print("   got-not-expected:", sorted(got4 - exp4))
    exp0 = {(79, 55, "plain"), (724, 400, "plain"), (725, 657, "remask"),
            (854, 779, "plain"), (938, 384, "remask"), (987, 237, "plain"),
            (995, 439, "plain")}
    print("act0 phase %s -> %s | moves match decompile: %s"
          % (acts[0].phase_assert, acts[0].phase_write,
             set(acts[0].moves) == exp0))

    bad = [i for i, a in acts.items() if a.unmodelled]
    unresolved = [i for i, a in acts.items()
                  if any(s is None for _d, s, _k in a.moves)]
    print("\nactions calling something unmodelled: %d" % len(bad))
    print("actions with an unresolved move source: %d" % len(unresolved))

    # ---------------- the phase state machine ----------------
    print("\n=== phase state machine (%d actions) ===" % nact)
    trans = collections.Counter((a.phase_assert, a.phase_write)
                                for a in acts.values())
    ph = set()
    for f, t in trans:
        ph |= {f, t}
    print("   %d distinct phases, %d transitions, each used by exactly 1 action: %s"
          % (len(ph), len(trans), set(trans.values()) == {1}))
    print("variant assertions:",
          dict(collections.Counter(a.variant_assert for a in acts.values())))
    agree = sum(1 for a in acts.values()
                if a.vkey_args and a.vkey_args[1:3] == (a.phase_assert, a.phase_write))
    print("vkey (phase_from, phase_to) args match the guard/update pair: %d/%d"
          % (agree, nact))

    nm = [len(a.moves) for a in acts.values()]
    rm = sum(1 for a in acts.values() for _d, _s, k in a.moves if k == "remask")
    print("\nmoves per action: min=%d max=%d total=%d (remask=%d plain=%d)"
          % (min(nm), max(nm), sum(nm), rm, sum(nm) - rm))

    json.dump({str(i): dict(phase_assert=a.phase_assert, phase_write=a.phase_write,
                            variant=a.variant_assert, vkey=a.vkey_args,
                            moves=a.moves) for i, a in acts.items()},
              open("act_lifted.json", "w"))
    print("wrote act_lifted.json")


if __name__ == "__main__":
    main()
