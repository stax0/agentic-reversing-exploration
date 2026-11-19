#!/usr/bin/env python3
"""Fully static recovery of the libverify.so VM program.

    python3 recover.py <path-to-libverify.so>

Pure standard library. Parses the ELF, applies R_AARCH64_RELATIVE relocations,
simulates each of the 487 block loaders (eight AArch64 encodings, anything else
raises), then breadth-first decrypts the whole program carrying each edge's key
pair. Keys chain per control-flow edge from one hardcoded root, so a block only
decrypts on a legal path. Every block ends in a 64-bit MAC that is checked, so a
wrong model cannot pass silently. Writes plain/edges/keys.json.
"""
import sys, os, json, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import Image, load_all, decrypt, TABLES, ROOT_K0, ROOT_K1

N_OPS, N_ACTS, N_BLOCKS = 313, 609, 487
UNC = 0xFFFFFFFF


def main():
    img = Image(sys.argv[1])
    here = os.path.dirname(os.path.abspath(__file__))

    ta, tsz = img.sections[".text"]
    print("relocs=%d  .text=[%#x,%#x)" % (img.nrel, ta, ta + tsz))
    for nm, (base, n) in TABLES.items():
        p = [img.qword(base + 8 * i) for i in range(n)]
        assert all(ta <= x < ta + tsz and x % 4 == 0 for x in p), nm
        print("  %-6s @%#x n=%-4d distinct=%d  all in .text, 4-aligned"
              % (nm, base, n, len(set(p))))

    cipher = {i: w for i, (w, rc) in load_all(img).items()}
    assert sum(len(v) for v in cipher.values()) == 10380
    print("decoded 487 loaders -> %d block words" % sum(len(v) for v in cipher.values()))

    # ---- BFS with chained keys ------------------------------------------
    plain, keys, edges, bad = {}, {0: (ROOT_K0, ROOT_K1)}, {}, []
    q = [(0, ROOT_K0, ROOT_K1)]
    ops, acts, mods, conds = (collections.Counter() for _ in range(4))

    while q:
        b, k0, k1 = q.pop()
        if b in plain:
            continue
        pl, ok = decrypt(cipher[b], k0, k1)
        if not ok:
            bad.append(b)
            continue
        plain[b] = pl
        n = len(pl)
        ops[pl[0]] += 1
        assert pl[0] < N_OPS and pl[1] <= n - 4, b

        p, outs = pl[1] + 3, []
        for g in range(pl[2]):
            cond, usev, mod, ntgt = pl[p:p + 4]
            p += 4
            assert usev <= 1 and mod != 0 and ntgt <= (n - 1 - p) // 4, b
            mods[mod] += 1
            conds["uncond" if cond == UNC else cond] += 1
            for _t in range(ntgt):
                act, nxt, nk0, nk1 = pl[p:p + 4]
                p += 4
                assert (act == UNC or act < N_ACTS) and nxt < N_BLOCKS, b
                acts[act] += 1
                assert keys.get(nxt, (nk0, nk1)) == (nk0, nk1), \
                    "block %d reached with two key pairs" % nxt
                keys[nxt] = (nk0, nk1)
                outs.append(dict(group=g, cond=cond, use_variant=usev,
                                 modulus=mod, action=act, next=nxt))
                q.append((nxt, nk0, nk1))
        edges[b] = outs

    print("\nreachable=%d/487  tags valid=%d  tag failures=%s"
          % (len(plain), len(plain), bad or "none"))
    print("opcodes used=%d/313  edge actions used=%d/609  edges=%d"
          % (len(ops), len([a for a in acts if a != UNC]),
             sum(len(v) for v in edges.values())))
    print("modulus histogram:", dict(sorted(mods.items())))
    print("cond slots:", dict(conds))
    term = sorted(b for b, o in edges.items() if not o)
    print("terminal blocks:", [(b, plain[b][0]) for b in term])

    for nm, obj in (("plain", plain), ("edges", edges), ("keys", keys)):
        json.dump({str(k): v for k, v in obj.items()},
                  open(os.path.join(here, nm + ".json"), "w"))
    print("\nwrote plain/edges/keys.json to", here)


if __name__ == "__main__":
    main()
