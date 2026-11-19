// toy_vm.c: a tiny, runnable model of the libverify.so PIN-check VM.
//
// This is not the real VM. It is a roughly 100x smaller version that keeps the
// same mechanisms described in ../README.md, so the two can be read side by
// side:
//
//   ENCRYPTION     each block is a keystream-XOR ciphertext ending in a MAC
//                  (section 2.3). A wrong key fails the MAC, so the VM notices.
//   HANDLER CHAIN  decrypt, dispatch on word[0], the handler sets edge_sel, then
//                  walk the edge table to the next block carrying its keys
//                  (section 2.1). The keys live in the ciphertext of the block
//                  that jumps to you, the static ratchet (section 2.4).
//   RANDOMIZATION  a per-call variant and 8 random condition slots steer branch
//                  selection, and every register value is positionally masked
//                  (sections 3.1 to 3.3). The variant and the random branches
//                  both reconverge, so the answer never changes, which the
//                  program demonstrates by running under many random seeds.
//
// The toy program computes one thing: does the input equal a secret?
//   verify(SECRET)   -> 1   (accept)
//   verify(anything) -> 0   (reject)
//
// Build and run:   cc -O2 -Wall toy_vm.c -o toy_vm && ./toy_vm
//
// Differences from the real binary, so the toy is not over-read:
//   - 4 blocks / 5 opcodes / 3 variants, vs 487 / 313 / 10.
//   - Block loaders are one array lookup here; in libverify.so they are 487
//     functions that build each word from MOVZ/MOVK immediates (section 2.2).
//   - Edge actions here re-mask registers in place (identity permutation). The
//     real actions also scatter registers across two banks so register numbers
//     are not stable between blocks; that part is omitted for clarity, while the
//     mask re-keying that binds blinding to the path is faithful.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GOLD      0x9E3779B97F4A7C15ULL
#define VALUEMAS  0x76616C75656D6173ULL   // "valuemas", big-endian ASCII
#define VALUEEDG  0x76616C7565656467ULL   // "valueedg"
#define VALUEINI  0x76616C7565696E69ULL   // "valueini"

#define ROOT_K0   0xD53C59684C39E959ULL   // the only hardcoded block keys (section 2.4)
#define ROOT_K1   0xEEF8BF4E76A7A167ULL

#define NREG      8
#define NBLOCK    4
#define NVARIANT  3                        // real VM: 10
#define SECRET    42

// ---------------------------------------------------------------------------
// 1. CRYPTO  (section 2.3), splitmix64, the block keystream, and the MAC
// ---------------------------------------------------------------------------
static uint64_t mix(uint64_t x) {          // splitmix64 finalizer @0x247E4
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
static uint64_t ks(uint64_t k0, uint64_t k1, int i) {   // keystream word i @0x24AA4
    return mix(k0 + GOLD * (uint64_t)(i + 1)) ^ k1;
}
static uint64_t mac(const uint64_t *plain, int n, uint64_t k0, uint64_t k1) {
    uint64_t h = mix(k0 ^ k1);             // fmix chain over all but the last word
    for (int i = 0; i < n - 1; i++) h = mix(h ^ plain[i]);
    return h;                              // must equal plain[n-1]
}

// ---------------------------------------------------------------------------
// 2. VALUE MASKING  (section 3.1), additive, positional, and it cancels
// ---------------------------------------------------------------------------
// Every register slot stores  (true_value + M(vk, index)).  The mask is a pure
// function of the register INDEX and the current 128-bit ValueKey, so moving a
// value only means swapping M(old) for M(new): it cancels, which is why an
// analyst can pick any self-consistent ValueKey.
static uint64_t M(uint64_t vk0, uint64_t vk1, int index) {
    return mix((vk0 ^ VALUEMAS) ^ mix(vk1 - GOLD * (uint64_t)index));
}
// The ValueKey is re-derived on every edge, bound to the path: the phase pair,
// the variant and the step counter all go in (section 3.2). Reorder or replay
// an edge and every later mask diverges.
static void vkey_next(uint64_t *vk0, uint64_t *vk1,
                      int from_phase, int to_phase, int variant, int step) {
    uint64_t a = *vk0 ^ VALUEEDG;
    uint64_t b = *vk1 + ((uint64_t)from_phase << 32 | (uint32_t)to_phase);
    b += GOLD * (uint64_t)variant + (uint64_t)step;
    *vk0 = mix(a ^ mix(b));
    *vk1 = mix(b ^ mix(a));
}

// ---------------------------------------------------------------------------
// 3. THE PROGRAM, in the clear, authored here, then encrypted by build()
// ---------------------------------------------------------------------------
// Opcodes (handler ids):
enum { OP_CMP = 0, OP_NOP = 45, OP_RET1 = 311, OP_RET0 = 312 };

// An authored edge target. next_k0/next_k1 are filled in by build() with the
// successor block's keys, that is the ratchet being baked into the ciphertext.
typedef struct { int action_id, next_block; } ATarget;
typedef struct {                 // one edge group
    int cond_slot;               // which of the 8 random slots indexes this group
    int use_variant;             // 1 => indexed by the per-call variant instead
    int modulus;                 // real VM: always 4 for random groups
    int nt;                      // number of targets
    ATarget t[NVARIANT];
} AGroup;
typedef struct {                 // one authored block
    int handler;                 // -> word[0]
    int nops; uint64_t ops[4];   // operands (e.g. register indices to compare)
    int ng;  AGroup g[2];        // edge groups, indexed by edge_sel
} ABlock;

// Block 0: compare input(reg0) to secret(reg1); store eq into reg2; branch.
//   edge_sel = (input != secret):
//     0 (equal)     -> a RANDOM 4-way group, ALL targets reconverge on block 1
//     1 (not equal) -> block 2 (reject)
// Block 1: NOP, then a VARIANT group of NVARIANT targets, ALL reconverge on blk 3
// Block 2: RET0  (reject), unmask reg2 (==0) into retval
// Block 3: RET1  (accept), unmask reg2 (==1) into retval
static ABlock PROG[NBLOCK] = {
  /*0*/ { OP_CMP, 2, {0,1}, 2, {
            { .cond_slot=3, .use_variant=0, .modulus=NVARIANT, .nt=NVARIANT,
              .t={ {10,1},{11,1},{12,1} } },     // equal -> all roads to block 1
            { .cond_slot=0, .use_variant=0, .modulus=1, .nt=1,
              .t={ {13,2} } } } },               // not equal -> block 2
  /*1*/ { OP_NOP, 0, {0}, 1, {
            { .cond_slot=0, .use_variant=1, .modulus=1, .nt=NVARIANT,
              .t={ {20,3},{21,3},{22,3} } } } },  // variant fan-out -> all block 3
  /*2*/ { OP_RET0, 1, {2}, 0, {{0}} },           // return reg2 (==0)
  /*3*/ { OP_RET1, 1, {2}, 0, {{0}} },           // return reg2 (==1)
};

// Per-block decryption keys. Every edge into a block carries these exact values
// (so reconverging edges agree). Block 0 is the hardcoded root.
static uint64_t BK0[NBLOCK], BK1[NBLOCK];
static void init_block_keys(void) {
    BK0[0] = ROOT_K0; BK1[0] = ROOT_K1;
    for (int b = 1; b < NBLOCK; b++) {
        BK0[b] = mix(ROOT_K0 ^ (0x1000ULL + b));
        BK1[b] = mix(ROOT_K1 ^ (0x2000ULL + b));
    }
}

// The "loader" store: build() serializes each block to plaintext words, appends
// the MAC, then encrypts. CIPHER[b] is what load_block() hands back at runtime.
static uint64_t CIPHER[NBLOCK][64];
static int      CLEN[NBLOCK];

static int serialize(const ABlock *B, uint64_t *w) {   // -> number of DATA words
    int n = 0;
    w[n++] = B->handler;          // word[0] = handler id
    w[n++] = B->nops;             // word[1] = edge_base: edges start at nops+3
    w[n++] = B->ng;               // word[2] = max_edge_sel (number of groups)
    for (int i = 0; i < B->nops; i++) w[n++] = B->ops[i];
    for (int g = 0; g < B->ng; g++) {
        const AGroup *G = &B->g[g];
        w[n++] = G->cond_slot; w[n++] = G->use_variant;
        w[n++] = G->modulus;   w[n++] = G->nt;
        for (int k = 0; k < G->nt; k++) {
            w[n++] = G->t[k].action_id;
            w[n++] = G->t[k].next_block;
            w[n++] = BK0[G->t[k].next_block];   // <-- ratchet: successor's keys
            w[n++] = BK1[G->t[k].next_block];   //     baked into this ciphertext
        }
    }
    return n;
}
static void build(void) {
    for (int b = 0; b < NBLOCK; b++) {
        uint64_t plain[64];
        int data = serialize(&PROG[b], plain);
        plain[data] = mac(plain, data + 1, BK0[b], BK1[b]);  // tag = last word
        int n = data + 1;
        for (int i = 0; i < n; i++) CIPHER[b][i] = plain[i] ^ ks(BK0[b], BK1[b], i);
        CLEN[b] = n;
    }
}
static int load_block(int id, uint64_t *out) {       // the "block loader" call
    memcpy(out, CIPHER[id], CLEN[id] * sizeof(uint64_t));
    return CLEN[id];
}

// ---------------------------------------------------------------------------
// 4. THE INTERPRETER  (section 2.1), fetch, decrypt+verify, dispatch, branch
// ---------------------------------------------------------------------------
typedef struct {
    uint64_t k0, k1;                 // current block's decryption keys (ctx+0x70/78)
    uint64_t vk0, vk1;               // the 128-bit ValueKey (ctx+0x90/98)
    uint64_t reg[NREG];              // masked registers (one bank in this toy)
    int block_id;                    // the PC (ctx+0xAC)
    int phase;                       // ctx+0xB0, here: == block_id
    int edge_sel;                    // ctx+0xB8, set by the handler
    int variant;                     // ctx+0xA8, 0..NVARIANT-1
    int cond_slot[8];                // ctx+0xCC, each 0..3
    int step;
    int halted, retval;
    int trace;
} Ctx;

static uint64_t reg_get(Ctx *c, int i){ return c->reg[i] - M(c->vk0,c->vk1,i); }
static void     reg_set(Ctx *c, int i, uint64_t v){ c->reg[i] = v + M(c->vk0,c->vk1,i); }

// EXECUTE: run the block's opcode. Comparisons set edge_sel, a compare result
// is not a flag, it IS the computed goto (section 2.1).
static void dispatch(Ctx *c, const uint64_t *w) {
    int nops = (int)w[1];
    const uint64_t *op = &w[3];      // operands begin at word[3]
    switch ((int)w[0]) {
        case OP_CMP: {               // reg[op2] = (reg[a]==reg[b]); edge_sel=(a!=b)
            uint64_t a = reg_get(c, (int)op[0]);
            uint64_t b = reg_get(c, (int)op[1]);
            reg_set(c, 2, a == b ? 1 : 0);
            c->edge_sel = (a != b) ? 1 : 0;
            if (c->trace) printf("    op CMP   reg[%d]==reg[%d]? -> eq=%llu, edge_sel=%d\n",
                                 (int)op[0], (int)op[1], (unsigned long long)(a==b), c->edge_sel);
            break;
        }
        case OP_NOP:                 // used in 64 real blocks; just fires an edge
            c->edge_sel = 0;
            if (c->trace) printf("    op NOP\n");
            break;
        case OP_RET1: case OP_RET0:  // RETURN: unmask a register into retval, halt
            c->retval = (int)reg_get(c, (int)op[0]);
            c->halted = 1;
            if (c->trace) printf("    op RET   retval = unmask(reg[%d]) = %d\n",
                                 (int)op[0], c->retval);
            break;
    }
    (void)nops;
}

// The edge action: re-key the ValueKey (bound to the phase hop + variant + step)
// and re-mask every register for the new key. Identity permutation in the toy.
static void run_edge_action(Ctx *c, int action_id, int from_phase, int to_phase) {
    uint64_t nvk0 = c->vk0, nvk1 = c->vk1;
    vkey_next(&nvk0, &nvk1, from_phase, to_phase, c->variant, c->step + 1);
    for (int i = 0; i < NREG; i++)                 // dst = src - M_old + M_new
        c->reg[i] = c->reg[i] - M(c->vk0,c->vk1,i) + M(nvk0,nvk1,i);
    c->vk0 = nvk0; c->vk1 = nvk1;                  // (the move cancels the old mask)
    if (c->trace) printf("    edge action %d  (phase %d->%d), ValueKey re-keyed\n",
                         action_id, from_phase, to_phase);
}

// Find edge group `sel`, then pick a target within it (BRANCH, two levels).
static void branch(Ctx *c, const uint64_t *w) {
    int nops = (int)w[1], ngroups = (int)w[2];
    int off = 3 + nops;                            // edge table start
    if (ngroups == 0) return;                      // terminal block (RET handled)
    int sel = c->edge_sel; if (sel >= ngroups) sel = ngroups - 1;

    for (int g = 0; g < sel; g++) {                // skip to the chosen group
        int nt = (int)w[off + 3];
        off += 4 + nt * 4;
    }
    int use_variant = (int)w[off + 1];
    int modulus     = (int)w[off + 2];
    int nt          = (int)w[off + 3];

    int idx = use_variant ? (c->variant % nt)                       // (2a) variant
                          : (c->cond_slot[(int)w[off]] % modulus);  // (2b) random 4-way
    if (idx >= nt) idx = nt - 1;

    const uint64_t *tgt = &w[off + 4 + idx * 4];
    int action_id = (int)tgt[0], next_block = (int)tgt[1];
    uint64_t nk0 = tgt[2], nk1 = tgt[3];           // <-- keys pulled from ciphertext

    if (c->trace) printf("    branch: group %d/%s -> target %d -> block %d\n",
                 sel, use_variant ? "variant" : "random", idx, next_block);

    run_edge_action(c, action_id, c->phase, next_block);
    c->block_id = next_block;
    c->phase    = next_block;
    c->k0 = nk0; c->k1 = nk1;                       // THE RATCHET (section 2.4)
    c->step++;
}

static int mac_ok(uint64_t *w, int n, Ctx *c);   // defined just below

static int vm_run(Ctx *c) {
    while (!c->halted) {
        uint64_t w[64];
        int n = load_block(c->block_id, w);                       // FETCH
        if (c->trace) printf("  block %d: fetched %d words\n", c->block_id, n);
        if (!mac_ok(w, n, c)) {                                   // DECRYPT + verify
            printf("  !! MAC FAILED on block %d (wrong key), real VM aborts\n",
                   c->block_id);
            return -1;
        }
        dispatch(c, w);                                           // EXECUTE
        if (c->halted) break;
        branch(c, w);                                            // BRANCH + ratchet
    }
    return c->retval;
}

// decrypt in place, then check the per-block MAC (the free correctness oracle)
static int mac_ok(uint64_t *w, int n, Ctx *c) {
    for (int i = 0; i < n; i++) w[i] ^= ks(c->k0, c->k1, i);
    return mac(w, n, c->k0, c->k1) == w[n - 1];
}

// ---------------------------------------------------------------------------
// 5. ENTRY, build the ValueKey, seed randomness, inject input, run
// ---------------------------------------------------------------------------
static uint64_t xrng_state;
static uint64_t xrng(void){ xrng_state=mix(xrng_state); return xrng_state; }

static int verify(int input, uint64_t seed, int trace) {
    Ctx c; memset(&c, 0, sizeof c);
    c.trace = trace;

    xrng_state = seed ? seed : 1;
    uint64_t nonce = xrng();                 // per-call counter in the real VM
    c.variant = (int)(nonce % NVARIANT);     // perm[nonce % 10] (section 3.3), simplified
    for (int i = 0; i < 8; i++) c.cond_slot[i] = (int)(xrng() & 3);  // uniform 0..3

    // ValueKey init ("valueini"); value is irrelevant to the result, masks cancel
    c.vk0 = mix(VALUEINI ^ nonce);
    c.vk1 = mix(VALUEINI + nonce);

    c.block_id = 0; c.phase = 0;
    c.k0 = ROOT_K0; c.k1 = ROOT_K1;          // root keys; the rest ratchet in

    reg_set(&c, 0, (uint64_t)input);         // reg0 = the input
    reg_set(&c, 1, (uint64_t)SECRET);        // reg1 = the secret

    if (trace) printf("verify(%d)  variant=%d  cond=%d%d%d%d...\n", input,
        c.variant, c.cond_slot[0],c.cond_slot[1],c.cond_slot[2],c.cond_slot[3]);
    return vm_run(&c);
}

int main(void) {
    init_block_keys();
    build();

    printf("=== one traced accept and one traced reject ===\n");
    verify(SECRET, 0xABCDEF, 1);
    printf("\n");
    verify(SECRET + 1, 0x123456, 1);

    printf("\n=== randomization is decorative: 5000 random seeds each ===\n");
    int acc_ok = 1, rej_ok = 1;
    for (uint64_t s = 1; s <= 5000; s++) {
        if (verify(SECRET,     s * 2654435761ULL, 0) != 1) acc_ok = 0;
        if (verify(SECRET + 7, s * 2654435761ULL, 0) != 0) rej_ok = 0;
    }
    printf("accept always returns 1 under every seed/variant/branch : %s\n",
           acc_ok ? "YES" : "NO");
    printf("reject always returns 0 under every seed/variant/branch : %s\n",
           rej_ok ? "YES" : "NO");

    printf("\n=== the MAC catches a wrong key ===\n");
    CIPHER[1][0] ^= 1;   // corrupt one word of block 1's ciphertext
    int r = verify(SECRET, 0xABCDEF, 0);
    printf("tampered block 1, verify(SECRET) returned %d (expected -1)\n", r);
    return 0;
}
