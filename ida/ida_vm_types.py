#!/usr/bin/env python3
"""
ida_vm_types.py: apply VM types/names to the libverify.so IDA database.
"""

import os
import json

import idc
import ida_bytes
import ida_name
import ida_funcs

# ---------------------------------------------------------------- addresses
BLOCK_LOADERS = 0x188D48   # 487 entries (0x1E7)  -> the bytecode
OP_HANDLERS   = 0x189C80   # 313 entries (0x139)  -> the ISA
EDGE_ACTIONS  = 0x18A648   # 609 entries (0x261)  -> on-branch actions

N_BLOCKS, N_OPS, N_ACTS = 487, 313, 609

NAME_HANDLERS = True       # also name+type all 1409 table targets

_ok = 0
_fail = []


# ---------------------------------------------------------------- helpers
def step(label, fn, *args):
    """Run one idempotent step, recording failures instead of aborting."""
    global _ok
    try:
        fn(*args)
        _ok += 1
        print("  [ok]   %s" % label)
    except Exception as e:
        _fail.append((label, str(e)))
        print("  [FAIL] %s: %s" % (label, e))


def parse_decls(decls):
    n = idc.parse_decls(decls, 0)
    if n:
        raise RuntimeError("%d declaration error(s)" % n)


def settype(ea, proto):
    if not idc.SetType(ea, proto):
        raise RuntimeError("SetType rejected: %s" % proto)


def force_name(ea, nm):
    if not ida_name.set_name(ea, nm, ida_name.SN_FORCE | ida_name.SN_NOCHECK):
        raise RuntimeError("set_name failed")


def name_and_type(ea, nm, decl):
    force_name(ea, nm)
    settype(ea, decl)


def name_table(base, count, prefix, proto):
    """Name + type every function the table points at. Dedupes aliases."""
    named, seen = 0, {}
    for i in range(count):
        tgt = ida_bytes.get_qword(base + 8 * i)
        if not tgt or tgt == idc.BADADDR:
            continue
        f = ida_funcs.get_func(tgt)
        if f is None:
            ida_funcs.add_func(tgt)
            f = ida_funcs.get_func(tgt)
        if f is None:
            continue
        head = f.start_ea
        if head in seen:            # same function reachable from 2+ slots
            continue
        seen[head] = i
        nm = "%s_%03d" % (prefix, i)
        ida_name.set_name(head, nm, ida_name.SN_FORCE | ida_name.SN_NOCHECK)
        if proto:
            idc.SetType(head, proto % nm)
        named += 1
    print("    %s: %d slots -> %d distinct functions (%d aliased)"
          % (prefix, count, named, count - named))


def _cond_str(c):
    return "none" if c == 0xFFFFFFFF else str(c)


def find_recover_dir():
    """Locate plain/edges/keys.json for the block annotations. A snapshot ships
    beside this script, so it runs with no prior step; recover.py regenerates the
    same files under recover/ if you would rather use a fresh copy."""
    cands = []
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        cands += [here,                                   # the bundled snapshot
                  os.path.join(here, os.pardir, "recover"),
                  os.path.join(here, "recover")]
    except NameError:
        pass
    for getter in (idc.get_idb_path, idc.get_input_file_path):
        try:
            d = os.path.dirname(getter())
            cands += [d, os.path.join(d, os.pardir, "recover"),
                      os.path.join(d, "recover")]
        except Exception:
            pass
    for c in cands:
        if (os.path.isfile(os.path.join(c, "plain.json")) and
                os.path.isfile(os.path.join(c, "edges.json"))):
            return c
    return None


def annotate_blocks():
    """Comment each loader with its decrypted block: opcode, edges, keys."""
    d = find_recover_dir()
    if not d:
        raise RuntimeError("recover/plain.json not found near the script, run "
                           "recover.py or keep the recover/ folder beside ida/")
    with open(os.path.join(d, "plain.json")) as f:
        plain = json.load(f)
    with open(os.path.join(d, "edges.json")) as f:
        edges = json.load(f)
    try:
        with open(os.path.join(d, "keys.json")) as f:
            keys = json.load(f)
    except IOError:
        keys = {}
    done = 0
    for bid_s, words in plain.items():
        bid = int(bid_s)
        tgt = ida_bytes.get_qword(BLOCK_LOADERS + 8 * bid)
        if not tgt or tgt == idc.BADADDR:
            continue
        op = words[0]
        lines = ["VM block %d   op=%d (vm_op_%03d)" % (bid, op, op)]
        k = keys.get(bid_s)
        if k:
            lines.append("decrypt keys  k0=%#018x  k1=%#018x" % (k[0], k[1]))
        for e in edges.get(bid_s, []):
            lines.append(
                "  act %d -> block %d (vm_act_%03d)  grp=%d cond=%s var=%d mod=%d"
                % (e["action"], e["next"], e["action"], e["group"],
                   _cond_str(e["cond"]), e["use_variant"], e["modulus"]))
        idc.set_func_cmt(tgt, "\n".join(lines), 0)
        done += 1
    print("    annotated %d block loaders" % done)


# opcode semantics recovered in the writeup. Keyed by
# opcode number; the handler address is resolved from the table at run time so
# it is correct by construction. "inferred" marks the ones not individually
# cross-checked, matching the writeup's own hedging.
COMMENTS_BY_OP = {
    45:  "op45 NOP (64 blocks): body is `if (word[1] != 0) error`, only fires an edge action",
    50:  "op50 (8 blocks): ReleaseByteArrayElements + Context::forget",
    51:  "op51 RETURN (2 blocks): unmask a register into retval (subtractive), then halt",
    54:  "op54 (16 blocks): edge_sel = (a != b)",
    72:  "op72 (15 blocks): edge_sel = (a != b)",
    107: "op107 (10 blocks): low-bit extract, x & 1",
    113: "op113 (17 blocks): JNI byte store into a native buffer",
    122: "op122 (15 blocks): JNI byte store, inferred as the subtractive-unmask pair of op113",
    125: "op125 (12 blocks): low-bit extract, x & 1",
    135: "op135 (8 blocks): branch-free select, (a&b)|(c&d)",
    311: "op311 RETURN (1 block): unmask a register into retval, halt. Accept exit (block 482)",
    312: "op312 RETURN (1 block): unmask into retval, halt. Reject exit (block 486); "
         "inferred identical to op311",
}

VM_RUN_CMT = (
    "vm_run -- the interpreter. Per iteration: fetch block_loaders[block_id] -> N\n"
    "encrypted words; decrypt (XOR splitmix64 keystream) and verify the trailing\n"
    "MAC; dispatch op_handlers[word[0]]; then walk the edge table, run\n"
    "edge_actions[...], and load the next block id plus its (k0, k1).\n"
    "Root = block 0 with hardcoded keys k0=0xD53C59684C39E959 "
    "k1=0xEEF8BF4E76A7A167; keys then chain per edge."
)


def apply_doc_comments():
    """Bake the writeup's documented findings in as function comments."""
    n = 0
    if idc.set_func_cmt(0x23ED0, VM_RUN_CMT, 0):   # vm_run
        n += 1
    for op, text in COMMENTS_BY_OP.items():
        tgt = ida_bytes.get_qword(OP_HANDLERS + 8 * op)
        if tgt and tgt != idc.BADADDR and idc.set_func_cmt(tgt, text, 0):
            n += 1
    print("    applied %d documented comments" % n)


# ---------------------------------------------------------------- 1. structs
# VMContext is byte-exact: 0xEC bytes, every field offset verified against
# Context::Context @0x17C24C and against vm_run's own field accesses.
DECLS = r"""
struct VMVec
{
  unsigned __int64 *begin;
  unsigned __int64 *end;
  unsigned __int64 *cap;
};

struct VMContext
{
  struct VMVec     borrowed;      // 0x00 vector<Context::Borrowed>, JNI refs
  struct VMVec     bank0;         // 0x18 register bank 0, 1007 u64
  struct VMVec     bank1;         // 0x30 register bank 1, 1007 u64
  struct VMVec     words;         // 0x48 current DECRYPTED block
  void            *env;           // 0x60 JNIEnv*
  void            *thiz;          // 0x68 jobject
  unsigned __int64 k0;            // 0x70 block decryption key 0
  unsigned __int64 k1;            // 0x78 block decryption key 1
  unsigned __int64 retval;        // 0x80 -> verifyPin result (low byte)
  unsigned __int64 nonce;         // 0x88 atomic call counter: 0,1,2,...
  unsigned __int64 vkey0;         // 0x90 ValueKey lo
  unsigned __int64 vkey1;         // 0x98 ValueKey hi
  unsigned __int64 step;          // 0xA0 step counter
  unsigned int     variant;       // 0xA8 0..9, = perm[nonce % 10]
  unsigned int     block_id;      // 0xAC the VM PC
  unsigned int     cont_flag;     // 0xB0
  unsigned int     bank;          // 0xB4 active bank index 0/1
  unsigned int     edge_sel;      // 0xB8 set by op handler -> picks edge group
  unsigned int     error;         // 0xBC 1=invalid continuation, 2=div by zero
  unsigned __int64 nwords;        // 0xC0
  unsigned __int8  halted;        // 0xC8
  unsigned __int8  pad[3];        // 0xC9
  unsigned int     cond_slot[8];  // 0xCC..0xEC each 0..3, RNG seeded
};
"""

print("[*] parsing struct declarations")
step("VMVec + VMContext", parse_decls, DECLS)

# ---------------------------------------------------------------- 2. prototypes
# Several of these return a 128-bit pair in x0/x1; __int128 makes the
# decompiler model that instead of losing the high half.
PROTOS = [
    (0x23AE0, "int __fastcall Java_com_example_pinlock_PinVerifier_verifyPin("
              "void *env, void *cls, void *pin)"),
    (0x23C48, "void __fastcall vm_init(struct VMContext *ctx, void **pin)"),
    (0x23ED0, "void __fastcall vm_run(struct VMContext *ctx)"),
    (0x17C24C, "void __fastcall VMContext_ctor(struct VMContext *ctx)"),

    # crypto core
    (0x247E4, "unsigned __int64 __fastcall splitmix64_mix(unsigned __int64 x)"),
    (0x24AA4, "unsigned __int64 __fastcall vm_block_keystream("
              "unsigned __int64 k0, unsigned __int64 k1, unsigned __int64 idx)"),
    (0x249CC, "unsigned __int64 __fastcall rng_next(unsigned __int64 *s)"),
    (0x24858, "unsigned int __fastcall rng_bounded(unsigned __int64 *s, unsigned int bound)"),
    (0x24A0C, "unsigned __int128 __fastcall key_absorb("
              "unsigned __int64 h0, unsigned __int64 h1, unsigned __int64 x)"),
    (0x248E4, "unsigned __int128 __fastcall vkey_init_valueini("
              "unsigned __int64 g0, unsigned __int64 g1, unsigned __int64 salt, "
              "unsigned __int64 nonce, unsigned int variant, unsigned int zero)"),
    (0x13CE14, "unsigned __int128 __fastcall vkey_next_valueedg("
               "unsigned __int64 vk0, unsigned __int64 vk1, unsigned __int64 salt, "
               "unsigned int a, unsigned int b, unsigned int c, unsigned __int64 d)"),
    (0x77DCC, "unsigned __int64 __fastcall reg_mask_valuemas("
              "unsigned __int64 vk0, unsigned __int64 vk1, unsigned int idx, "
              "unsigned __int64 salt)"),
    (0x24560, "unsigned __int128 __fastcall vm_seed_global_getrandom(void)"),
    (0x246BC, "unsigned int __fastcall vm_pick_variant("
              "unsigned __int64 g0, unsigned __int64 g1, unsigned __int64 nonce, "
              "unsigned int n)"),
    (0x24544, "void vm_unpack_result_stub(void)"),

    # runtime helpers (were mis-signatured as protobuf/sqlite3/ASN1/ImGui)
    (0x17E200, "unsigned __int64 *__fastcall vec_u64_at(struct VMVec *v, size_t i)"),
    (0x17D570, "size_t __fastcall vec_u64_size(struct VMVec *v)"),
    (0x17E37C, "unsigned __int64 *__fastcall vec_u64_data(struct VMVec *v)"),
    (0x17E5F4, "unsigned __int64 *__fastcall vec_u64_data_2(struct VMVec *v)"),
    (0x17C718, "void __fastcall vec_u64_resize(struct VMVec *v, size_t n)"),
    (0x17E340, "void __fastcall swap_u32(unsigned int *a, unsigned int *b)"),
    (0x17E1CC, "unsigned __int64 __fastcall atomic_fetch_add_u64("
               "unsigned __int64 *p, unsigned __int64 delta, int memorder)"),
    (0x17E25C, "unsigned __int64 __fastcall atomic_fetch_add_u64_impl("
               "unsigned __int64 *p, unsigned __int64 delta, int memorder)"),
]

print("[*] naming + typing VM functions")
for _ea, _proto in PROTOS:
    _nm = _proto.split("(")[0].split()[-1].lstrip("*")
    step("name %s @ %#x" % (_nm, _ea), force_name, _ea, _nm)
    step("type %s @ %#x" % (_nm, _ea), settype, _ea, _proto)

# ---------------------------------------------------------------- 2b. globals
# These were named in the MCP session; the script also types them so the
# decompiler reads them correctly.
GLOBALS = [
    (0x18FE98, "vm_global_key",       "unsigned __int64 vm_global_key[2]"),
    (0x18FEA8, "vm_global_key_guard", "unsigned __int64 vm_global_key_guard"),
    (0x18FEB0, "vm_fallback_counter", "unsigned __int64 vm_fallback_counter"),
    (0x18FEB8, "vm_call_counter",     "unsigned __int64 vm_call_counter"),
]

print("[*] naming + typing VM globals")
for _ea, _nm, _decl in GLOBALS:
    step("name %s @ %#x" % (_nm, _ea), force_name, _ea, _nm)
    step("type %s @ %#x" % (_nm, _ea), settype, _ea, _decl)

# ---------------------------------------------------------------- 3. tables
TABLES = [
    (BLOCK_LOADERS, "vm_block_loaders",
     "__int64 (__fastcall *vm_block_loaders[%d])(unsigned __int64 *out)" % N_BLOCKS),
    (OP_HANDLERS, "vm_op_handlers",
     "void (__fastcall *vm_op_handlers[%d])(struct VMContext *ctx)" % N_OPS),
    (EDGE_ACTIONS, "vm_edge_actions",
     "void (__fastcall *vm_edge_actions[%d])(struct VMContext *ctx)" % N_ACTS),
]

print("[*] typing the three dispatch tables")
for _ea, _nm, _decl in TABLES:
    step("%s @ %#x" % (_nm, _ea), name_and_type, _ea, _nm, _decl)

# ---------------------------------------------------------------- 4. targets
if NAME_HANDLERS:
    print("[*] naming the 1409 table targets (this takes a moment)")
    step("block loaders", name_table, BLOCK_LOADERS, N_BLOCKS, "vm_block",
         "__int64 __fastcall %s(unsigned __int64 *out)")
    step("op handlers", name_table, OP_HANDLERS, N_OPS, "vm_op",
         "void __fastcall %s(struct VMContext *ctx)")
    step("edge actions", name_table, EDGE_ACTIONS, N_ACTS, "vm_act",
         "void __fastcall %s(struct VMContext *ctx)")

# ---------------------------------------------------------------- 5. annotations
print("[*] annotating block loaders with the recovered program")
step("block annotations", annotate_blocks)

# ---------------------------------------------------------------- 6. comments
print("[*] applying documented opcode + interpreter comments")
step("documented comments", apply_doc_comments)

# ---------------------------------------------------------------- summary
print("\n" + "=" * 62)
print("done: %d steps ok, %d failed" % (_ok, len(_fail)))
for _label, _err in _fail:
    print("  FAILED %s: %s" % (_label, _err))
print("=" * 62)
print("""
How the program was recovered (see recover/recover.py):

  * Root block is 0 with HARDCODED keys
      k0 = 0xD53C59684C39E959   k1 = 0xEEF8BF4E76A7A167
  * Keys are then CHAINED per edge: each target record carries its
    successor's (k0, k1) in words[p+2], words[p+3].
  * recover.py decrypts by BFS from block 0, carrying each edge's keys,
    and verifies every block's trailing tag (487/487 pass):
        h = mix(k0 ^ k1); for i in 0..n-2: h = mix(h ^ word[i])
        assert h == word[n-1]
    Its output (plain.json, edges.json, keys.json) is what the block
    annotations above are read from.
""")
