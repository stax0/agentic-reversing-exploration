#!/usr/bin/env python3
"""Structurally classify the 609 VM edge actions (third dispatch table)."""
import sys, os, json, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import Image, TABLES
from classify import classify, refine, is_semantic, HELPERS

UNC = 0xFFFFFFFF


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

    edges = {int(k): v for k, v in json.load(open("edges.json")).items()}
    use = collections.Counter()
    noact = 0
    for outs in edges.values():
        for e in outs:
            if e["action"] == UNC:
                noact += 1
            else:
                use[e["action"]] += 1

    ab, nact = TABLES["act"]
    sigs, unknown, ldst = {}, 0, {}
    for a_id in range(nact):
        fn = img.qword(ab + 8 * a_id)
        end = nxt[fn]
        calls, ops = collections.Counter(), collections.Counter()
        offs = []
        for a in range(fn, end, 4):
            w = img.u32(a)
            lab = classify(w)
            if lab == "???":
                unknown += 1
                continue
            lab = refine(w, lab)
            if lab == "BL":
                off = w & 0x3FFFFFF
                if off & 0x2000000:
                    off -= 0x4000000
                tgt = (a + off * 4) & ((1 << 64) - 1)
                calls[HELPERS.get(tgt, "f%06x" % tgt)] += 1
            elif is_semantic(lab):
                ops[lab] += 1
            # scaled 64-bit LDR/STR: imm12*8, large offsets are bank indices
            if lab in ("LDR", "STR"):
                imm = ((w >> 10) & 0xFFF) * 8
                if imm >= 0x400:            # beyond any handler stack frame
                    offs.append(imm // 8)
        sigs[a_id] = (tuple(sorted(calls.items())), tuple(sorted(ops.items())),
                      (end - fn) // 4)
        ldst[a_id] = offs

    print("unknown instruction words across all 609 edge actions:", unknown)
    print("edges with NO action (0xFFFFFFFF): %d of %d"
          % (noact, sum(len(v) for v in edges.values())))
    print("distinct actions referenced: %d / 609" % len(use))
    print("action reference counts: %s"
          % dict(collections.Counter(use.values())))

    arch = collections.defaultdict(list)
    for k, (c, o, _s) in sigs.items():
        arch[(c, o)].append(k)
    print("\ndistinct SHAPES: %d (from 609 actions)" % len(arch))

    # shape ignoring multiplicity -> the template
    tmpl = collections.Counter()
    for k, (c, o, _s) in sigs.items():
        tmpl[(tuple(sorted(x for x, _ in c)), tuple(sorted(x for x, _ in o)))] += 1
    print("distinct TEMPLATES (call/op kinds, ignoring counts): %d" % len(tmpl))
    for t, cnt in tmpl.most_common():
        print("   %3d actions  calls=%s" % (cnt, list(t[0])))
        print("                ops  =%s" % list(t[1]))

    szs = [s for _c, _o, s in sigs.values()]
    print("\naction size: min=%d max=%d median=%d"
          % (min(szs), max(szs), sorted(szs)[len(szs) // 2]))
    ncp = [len(v) for v in ldst.values()]
    print("bank-index refs per action: min=%d max=%d total=%d"
          % (min(ncp), max(ncp), sum(ncp)))
    mk = [dict(sigs[k][0]).get("MASK", 0) for k in sigs]
    print("MASK calls per action: min=%d max=%d total=%d" % (min(mk), max(mk), sum(mk)))

    json.dump({str(k): [list(map(list, v[0])), list(map(list, v[1])), v[2]]
               for k, v in sigs.items()}, open("act_sigs.json", "w"))
    json.dump({str(k): v for k, v in ldst.items()}, open("act_idx.json", "w"))
    print("\nwrote act_sigs.json + act_idx.json")


if __name__ == "__main__":
    main()
