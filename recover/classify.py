#!/usr/bin/env python3
"""Structurally classify the 313 VM opcode handlers into archetypes."""
import sys, os, json, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import Image, TABLES

HELPERS = {
    0x17E200: "vec_at",    0x17D570: "vec_size",  0x17E37C: "vec_data",
    0x17E5F4: "vec_data2", 0x77DCC:  "MASK",      0x247E4: "mix",
    0x13CE14: "vkey_edge", 0x248E4:  "vkey_init", 0x24A0C: "absorb",
    0x24AA4:  "blk_ks",    0x77E48:  "h77E48",    0x77E74: "h77E74",
}

# (mask, match) -> label.  Order matters: more specific first.
ALU = [
    (0xFFFFFFFF, 0xD65F03C0, "RET"),
    (0xFFFFFFFF, 0xD503201F, "NOP"),
    (0xFC000000, 0x94000000, "BL"),
    (0xFC000000, 0x14000000, "B"),
    (0xFF000000, 0x54000000, "B.cond"),
    (0x7F000000, 0x34000000, "CBZ"),
    (0x7F000000, 0x35000000, "CBNZ"),
    (0x7F000000, 0x36000000, "TBZ"),
    (0x7F000000, 0x37000000, "TBNZ"),
    # data-processing, 2 source (width-agnostic: sf masked out)
    (0x7FE0FC00, 0x1AC00800, "UDIV"),
    (0x7FE0FC00, 0x1AC00C00, "SDIV"),
    (0x7FE0FC00, 0x1AC02000, "LSLV"),
    (0x7FE0FC00, 0x1AC02400, "LSRV"),
    (0x7FE0FC00, 0x1AC02800, "ASRV"),
    (0x7FE0FC00, 0x1AC02C00, "RORV"),
    (0x7FE08000, 0x1B000000, "MADD/MSUB"),
    # 3-source catch-all: SMADDL/UMADDL/SMULH/UMULH (bits[28:24]=11011).
    # Must follow MADD/MSUB, which is the op31=000 case.
    (0x1F000000, 0x1B000000, "MADDL/MULH"),
    (0x7FE00000, 0x1A800000, "CSEL/CSINC"),
    # logical, shifted register (bit21 = N -> BIC/ORN/EON/BICS)
    (0x7F200000, 0x0A000000, "AND.reg"),
    (0x7F200000, 0x0A200000, "BIC.reg"),
    (0x7F200000, 0x2A000000, "ORR.reg"),
    (0x7F200000, 0x2A200000, "ORN.reg"),
    (0x7F200000, 0x4A000000, "EOR.reg"),
    (0x7F200000, 0x4A200000, "EON.reg"),
    (0x7F200000, 0x6A000000, "ANDS.reg"),
    (0x7F200000, 0x6A200000, "BICS.reg"),
    # add/sub, shifted register
    (0x7F200000, 0x0B000000, "ADD.reg"),
    (0x7F200000, 0x2B000000, "ADDS.reg"),
    (0x7F200000, 0x4B000000, "SUB.reg"),
    (0x7F200000, 0x6B000000, "SUBS/CMP.reg"),
    # add/sub, extended register
    (0x7FE00000, 0x0B200000, "ADD.ext"),
    (0x7FE00000, 0x4B200000, "SUB.ext"),
    # move wide immediate (bit23 set), must precede logical immediate
    (0x7F800000, 0x12800000, "MOVN"),
    (0x7F800000, 0x52800000, "MOVZ"),
    (0x7F800000, 0x72800000, "MOVK"),
    # logical immediate
    (0x7F800000, 0x12000000, "AND.imm"),
    (0x7F800000, 0x32000000, "ORR.imm"),
    (0x7F800000, 0x52000000, "EOR.imm"),
    (0x7F800000, 0x72000000, "ANDS.imm"),
    # add/sub immediate
    (0x7F800000, 0x11000000, "ADD.imm"),
    (0x7F800000, 0x31000000, "ADDS.imm"),
    (0x7F800000, 0x51000000, "SUB.imm"),
    (0x7F800000, 0x71000000, "SUBS/CMP.imm"),
    # bitfield
    (0x7F800000, 0x13000000, "SBFM"),
    (0x7F800000, 0x33000000, "BFM"),
    (0x7F800000, 0x53000000, "UBFM"),
    # loads/stores, all glue
    (0xFFC00000, 0xF9000000, "STR"),
    (0xFFC00000, 0xF9400000, "LDR"),
    (0xFFC00000, 0xF8000000, "STUR"),
    (0xFFC00000, 0xF8400000, "LDUR"),
    (0xFFC00000, 0xB9000000, "STR.32"),
    (0xFFC00000, 0xB9400000, "LDR.32"),
    (0xFFC00000, 0xB8000000, "STUR.32"),
    (0xFFC00000, 0xB8400000, "LDUR.32"),
    (0x7FC00000, 0x39000000, "STRB"),
    (0x7FC00000, 0x39400000, "LDRB"),
    (0x7FC00000, 0x38000000, "STURB"),
    (0x7FC00000, 0x38400000, "LDURB"),
    (0x7FC00000, 0x38800000, "LDURSB"),
    (0x7FC00000, 0x38C00000, "LDURSB.32"),
    (0xFFC00000, 0x3C800000, "STUR.q"),
    (0xFFC00000, 0x3CC00000, "LDUR.q"),
    (0xFFC00000, 0x3D800000, "STR.q"),
    (0xFFC00000, 0x3DC00000, "LDR.q"),
    (0x7FC00000, 0x29000000, "STP"),
    (0x7FC00000, 0x29400000, "LDP"),
    (0x7FC00000, 0x28800000, "STP.post"),
    (0x7FC00000, 0x28C00000, "LDP.post"),
    (0x7FC00000, 0x29800000, "STP.pre"),
    (0x7FC00000, 0x29C00000, "LDP.pre"),
    (0x9F000000, 0x90000000, "ADRP"),
    (0x9F000000, 0x10000000, "ADR"),
]
COND = ["EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
        "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"]
CSVAR = {(0, 0): "CSEL", (0, 1): "CSINC", (1, 0): "CSINV", (1, 1): "CSNEG"}


def refine(w, lab):
    """Fold the condition field into the label, so operators stop collapsing."""
    if lab == "CSEL/CSINC":
        return "%s[%s]" % (CSVAR[((w >> 30) & 1, (w >> 10) & 1)],
                           COND[(w >> 12) & 0xF])
    if lab == "B.cond":
        return "B.%s" % COND[w & 0xF]
    return lab


# ops that actually carry arithmetic meaning (ignore glue/addressing)
SEMANTIC = {"EOR.reg", "ADD.reg", "SUB.reg", "AND.reg", "ORR.reg", "UDIV", "SDIV",
            "LSLV", "LSRV", "ASRV", "MADD/MSUB", "SUBS/CMP.reg",
            "ANDS.reg", "ADDS.reg", "EOR.imm", "AND.imm", "ORR.imm",
            "SUBS/CMP.imm", "ANDS.imm", "BIC.reg", "ORN.reg", "EON.reg",
            "SBFM", "UBFM", "RORV", "ADD.ext", "SUB.ext"}


def is_semantic(lab):
    return lab in SEMANTIC or lab.startswith(("CSEL", "CSINC", "CSINV", "CSNEG"))


def classify(w):
    for m, v, lab in ALU:
        if (w & m) == v:
            return lab
    return "???"


def main():
    img = Image(sys.argv[1])
    starts = set()
    for _nm, (base, n) in TABLES.items():
        for i in range(n):
            starts.add(img.qword(base + 8 * i))
    starts |= set(HELPERS)
    ta, tsz = img.sections[".text"]
    starts.add(ta + tsz)
    S = sorted(starts)
    nxt = {S[i]: S[i + 1] for i in range(len(S) - 1)}

    opb, nop = TABLES["op"]
    plain = {int(k): v for k, v in json.load(open("plain.json")).items()}
    usage = collections.Counter(v[0] for v in plain.values())

    sigs, unknown = {}, 0
    for op in range(nop):
        fn = img.qword(opb + 8 * op)
        end = nxt[fn]
        calls, ops = collections.Counter(), collections.Counter()
        for a in range(fn, end, 4):
            w = img.u32(a)
            lab = classify(w)
            if lab == "???":
                unknown += 1
                continue
            lab = refine(w, lab)
            if lab == "BL":
                off = (w & 0x3FFFFFF)
                if off & 0x2000000:
                    off -= 0x4000000
                tgt = (a + off * 4) & ((1 << 64) - 1)
                calls[HELPERS.get(tgt, "f%06x" % tgt)] += 1
            elif is_semantic(lab):
                ops[lab] += 1
        sigs[op] = (tuple(sorted(calls.items())), tuple(sorted(ops.items())),
                    (end - fn) // 4)

    print("unknown instruction words across all 313 handlers:", unknown)

    # group by (calls, semantic ops), ignore exact size
    arch = collections.defaultdict(list)
    for op, (c, o, _sz) in sigs.items():
        arch[(c, o)].append(op)
    print("distinct archetypes: %d  (from 313 opcodes)\n" % len(arch))

    rows = sorted(arch.items(), key=lambda kv: -sum(usage[o] for o in kv[1]))
    print("%-5s %-5s %-7s  %-34s %s" % ("blks", "ops", "size", "semantic ops", "calls"))
    print("-" * 110)
    for (c, o), ops_ in rows[:26]:
        blks = sum(usage[x] for x in ops_)
        szs = {sigs[x][2] for x in ops_}
        sem = " ".join("%s*%d" % (k, v) for k, v in o) or "(none)"
        cal = " ".join("%s*%d" % (k, v) for k, v in c) or "(none)"
        print("%-5d %-5d %-7s  %-34s %s"
              % (blks, len(ops_), min(szs) if len(szs) == 1 else "%d-%d" % (min(szs), max(szs)),
                 sem[:34], cal[:60]))
        if len(ops_) <= 6:
            print("        ops: %s" % ops_)
    json.dump({str(k): [list(map(list, v[0])), list(map(list, v[1])), v[2]]
               for k, v in sigs.items()}, open("op_sigs.json", "w"))


if __name__ == "__main__":
    main()
