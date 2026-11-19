"""Minimal ELF64 loader for libverify.so: flat image + R_AARCH64_RELATIVE relocs."""
import struct

M64 = (1 << 64) - 1


class Image:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
        e_phentsz = struct.unpack_from("<H", d, 0x36)[0]
        e_phnum = struct.unpack_from("<H", d, 0x38)[0]

        loads, dynamic = [], None
        for i in range(e_phnum):
            o = e_phoff + i * e_phentsz
            p_type, _fl = struct.unpack_from("<II", d, o)
            p_off, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from("<QQQQQQ", d, o + 8)
            if p_type == 1:
                loads.append((p_off, p_vaddr, p_filesz, p_memsz))
            elif p_type == 2:
                dynamic = (p_off, p_filesz)

        top = max(v + ms for _o, v, _fs, ms in loads)
        self.mem = bytearray(top)
        for p_off, p_vaddr, p_filesz, _ms in loads:
            self.mem[p_vaddr:p_vaddr + p_filesz] = d[p_off:p_off + p_filesz]

        # dynamic table -> RELA
        DT = {}
        off, sz = dynamic
        for o in range(off, off + sz, 16):
            tag, val = struct.unpack_from("<qQ", d, o)
            if tag == 0:
                break
            DT[tag] = val

        self.nrel = 0
        rela, relasz, relaent = DT.get(7), DT.get(8), DT.get(9, 24)
        if rela is not None:
            for o in range(rela, rela + relasz, relaent):
                r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
                if (r_info & 0xFFFFFFFF) == 1027:          # R_AARCH64_RELATIVE
                    struct.pack_into("<Q", self.mem, r_off, r_add & M64)
                    self.nrel += 1

        # section headers, for sanity checks only
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shentsz = struct.unpack_from("<H", d, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
        so = e_shoff + e_shstrndx * e_shentsz
        stroff = struct.unpack_from("<Q", d, so + 0x18)[0]
        self.sections = {}
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsz
            nameoff = struct.unpack_from("<I", d, o)[0]
            addr = struct.unpack_from("<Q", d, o + 0x10)[0]
            size = struct.unpack_from("<Q", d, o + 0x20)[0]
            end = d.index(b"\0", stroff + nameoff)
            self.sections[d[stroff + nameoff:end].decode()] = (addr, size)

    def qword(self, a):
        return struct.unpack_from("<Q", self.mem, a)[0]

    def u32(self, a):
        return struct.unpack_from("<I", self.mem, a)[0]


# ----------------------------------------------------------------- VM crypto
GOLD  = 0x9E3779B97F4A7C15        # == -0x61C8864680B583EB mod 2**64
ROOT_K0, ROOT_K1 = 0xD53C59684C39E959, 0xEEF8BF4E76A7A167

TABLES = {"block": (0x188D48, 487), "op": (0x189C80, 313), "act": (0x18A648, 609)}


def mix(x):
    """splitmix64 finalizer @0x247E4"""
    x &= M64
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & M64
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & M64
    return x ^ (x >> 31)


def ks(k0, k1, i):
    """vm_block_keystream @0x24AA4"""
    return mix((k0 + GOLD * (i + 1)) & M64) ^ k1


def decrypt(enc, k0, k1):
    """Returns (plain, tag_ok). Tag rule read off vm_run @0x23FE0..0x240CC."""
    pl = [w ^ ks(k0, k1, i) for i, w in enumerate(enc)]
    h = mix(k0 ^ k1)
    for i in range(len(pl) - 1):
        h = mix(h ^ pl[i])
    return pl, bool(pl) and h == pl[-1]


# ------------------------------------------------- AArch64 loader simulator
RET_INSN = 0xD65F03C0
OUT_BASE = 0x1000000000000
SP_BASE  = 0x2000000000000


def run_loader(img, fn, limit=8000):
    """Simulate one block loader. Returns (words, returned_count).

    Only the 8 encodings the loaders actually use are implemented; anything
    else raises, so silent mis-decoding is impossible.
    """
    reg = [0] * 32
    reg[0] = OUT_BASE
    reg[31] = SP_BASE
    mem = {}
    a, steps = fn, 0

    while True:
        steps += 1
        if steps > limit:
            raise RuntimeError("runaway at %#x" % a)
        w = img.u32(a)
        a += 4

        if w == RET_INSN:
            break
        rd, rn = w & 31, (w >> 5) & 31

        if (w & 0xFF800000) in (0xD2800000, 0xF2800000, 0x92800000):   # MOVZ/MOVK/MOVN
            hw, imm = (w >> 21) & 3, (w >> 5) & 0xFFFF
            sh = hw * 16
            if (w & 0xFF800000) == 0xD2800000:                          # MOVZ
                reg[rd] = (imm << sh) & M64
            elif (w & 0xFF800000) == 0xF2800000:                        # MOVK
                reg[rd] = (reg[rd] & ~(0xFFFF << sh) | (imm << sh)) & M64
            else:                                                       # MOVN
                reg[rd] = (~(imm << sh)) & M64

        elif (w & 0xFFC00000) == 0xF9000000:                            # STR  Xt,[Xn,#imm]
            mem[(reg[rn] + ((w >> 10) & 0xFFF) * 8) & M64] = reg[rd]

        elif (w & 0xFFC00000) == 0xF9400000:                            # LDR  Xt,[Xn,#imm]
            reg[rd] = mem.get((reg[rn] + ((w >> 10) & 0xFFF) * 8) & M64, 0)

        elif (w & 0xFF000000) in (0x91000000, 0xD1000000):              # ADD/SUB imm
            imm = (w >> 10) & 0xFFF
            if (w >> 22) & 1:
                imm <<= 12
            reg[rd] = (reg[rn] + (-imm if (w & 0xFF000000) == 0xD1000000 else imm)) & M64

        else:
            raise RuntimeError("unhandled insn %#010x at %#x" % (w, a - 4))

    # collect the contiguous run of stores to the out buffer
    offs = sorted(k - OUT_BASE for k in mem
                  if OUT_BASE <= k < OUT_BASE + 0x100000)
    if not offs:
        return [], reg[0]
    if offs != list(range(0, len(offs) * 8, 8)):
        raise RuntimeError("non-contiguous out stores: %r" % offs[:12])
    return [mem[OUT_BASE + o] for o in offs], reg[0]


def load_all(img):
    """Decode every block loader -> {block_id: (ciphertext, returned_count)}."""
    base, n = TABLES["block"]
    out = {}
    for i in range(n):
        out[i] = run_loader(img, img.qword(base + 8 * i))
    return out
