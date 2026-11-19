# Agentic reversing exploration, breaking a virtualised native PIN check

After years of manually finding the needle in the haystack, it felt like time to
spin up some agents, set up MCP, and feel the helping hand of AI in reversing. This
repository is that experiment. It documents how I reverse engineered a
virtualisation-obfuscated native PIN check on Android, together with the tooling the
agents and I built along the way.

The honest verdict is that it is much faster. Work that used to be days of scrolling
disassembly turned into an agent naming functions, applying types and recovering
structure while I watched. The biggest lift was code generation. Most of the scripts
here, from the ELF parser to the Frida brute-force driver, were written by the agent
from a short description and then tightened over a few rounds.

The skill that mattered shifted too. It used to be how well you knew your tooling.
Here it was knowing that a technique exists, roughly how it works, and when to point
an agent at it.

It is not magic though. The agents throw plenty of false positives, confidently walk
down the wrong path, and need steering to stay on the real problem. So nothing here
was taken on trust. Every claim was checked, and this VM makes that easy, each of the
487 blocks carries its own checksum and a wrong guess fails it (section 2.3).

The target was a CTF style Android crackme. Neither the binary nor the recovered VM
program is included, since the organisers do not allow sharing the challenge itself.

**Target** `target.apk`, `com.example.pinlock`<br>
**Verification code** `lib/arm64-v8a/libverify.so`, `Java_com_example_pinlock_PinVerifier_verifyPin` @ `0x23AE0`<br>
**Accepted PIN** `739184`

---

## Contents

- [Summary](#summary)
- [Approach, an agentic workflow](#approach-an-agentic-workflow)
- [1. Method](#1-method)
- [2. The encrypted bytecode program](#2-the-encrypted-bytecode-program)
- [3. Runtime masking and randomness](#3-runtime-masking-and-randomness)
- [4. The PIN verification algorithm](#4-the-pin-verification-algorithm)
- [5. Strengths and weaknesses](#5-strengths-and-weaknesses)
- [Appendix A, the context object](#appendix-a-the-context-object)
- [Appendix B, the glass-box patch](#appendix-b-the-glass-box-patch)

---

## Summary

`verifyPin` does not compare strings. It runs a small bytecode virtual machine
over a 487-block program that decides accept or reject. The work was to recover
that machine and its program, then to read the algorithm the program encodes.

The protection is a virtual machine used as an obfuscator, built in six layers.
Each layer is aimed at a different way of analysing it:

1. the program is stored as code, not data, so there is no blob to find or dump
2. every bytecode word is encrypted with a SplitMix64 keystream
3. the key for each block is passed in by the block that branches to it, a chain
   rooted in two hardcoded constants
4. every live value is masked with a position-dependent key
5. that masking key is tied to the exact path taken to reach each point
6. the control flow is shuffled on every call, across ten program variants

The whole program was recovered statically and offline. Each of the 487 blocks
is checked by the VM's own checksum, and 487 of 487 pass. The algorithm was then
read by patching out the masking. One instruction overwritten in the mask
generator leaves every register in cleartext while the verdict stays the same
(section 4).

The check validates six ASCII digits, mixes them into a sixteen-byte value, and
compares that byte by byte against a sixteen-byte target which exists only inside
the running computation. It accepts only on a full match. The transform reaches
full avalanche, meaning a change to any one digit changes the whole result, so
there is no way to solve one digit at a time.

The accepted PIN here came from brute force. Recovering it from the machine
alone, without trying candidates, follows from the recovered transform but was
not carried out (section 4.2).

---

## Approach, an agentic workflow

The analysis ran as an agentic workflow, with an AI agent driving a set of reverse
engineering tools and writing most of the scripts in this repository. The obfuscation
here is advanced, and that approach is what made a result of this depth reachable in
the time available. The work split across four roles.

**MCP driven static analysis.** Two Model Context Protocol servers, `ida-pro-mcp` and
a radare2 server, let the agent read and annotate the binary directly, naming
functions, applying types and leaving comments, and navigating 1.4 MB of generated
code without stepping through it by hand. `ida/ida_vm_types.py` is the artefact of
that pass, it reapplies the recovered structure to the IDA database as names, types
and comments.

**Agent automated static recovery.** The `recover/` pipeline parses the ELF,
simulates each block loader, follows the control-flow edges and carries the key
chain, then checks every block against its own MAC. The agent generated and
orchestrated this, and it recovers all 487 blocks offline with 487 of 487 checksums
valid (section 2).

**Agent automated fuzzing and brute force.** `brute/` calls the native function
directly through Frida and sweeps the input space in an automated loop at about 1 ms
per call, which returned the accepting PIN in about 13 minutes (section 1).

**Dynamic instrumentation with Frida.** `dynamic/` holds the glass-box patch that
reads the computation in the clear and the handler tracer (section 4 and appendix B).

The agentic approach did not solve everything. Symbolic execution over the whole
binary was tried and did not work, angr fell back to its slow engine and never
reached the VM loop (section 4.2). The static recovery and the glass-box patch
carried the result instead.

---

## 1. Method

The library exports one JNI function. Its `.text` is 1.4 MB against 3.8 KB of
`.rodata`, and the C++ symbols carry a generated namespace
`vm_path_<redacted>`. That marks a code-virtualisation obfuscator, not a
string check. `verifyPin` and the interpreter `vm_run` @ `0x23ED0` give the
architecture.

The 1.4 MB of generated VM code makes reading the disassembly directly
impractical, so dynamic tracing was the natural next step. That ran into a
libunwind side effect, which ruled out direct hooks inside `libverify`.

With tracing stalled, brute force gave an anchor instead. Calling the native
function directly through Frida bypasses the UI, runs at about 1 ms per call, and
returned `739184` in about 13 minutes. That is a known-accepting input, used to
anchor a trace of a correct run.

The structure then came from static recovery. Because the key chain is rooted in
two fixed constants (section 2.4), the encrypted program never changes between
runs. Starting at block 0 and following the edges outward, each block hands over
the keys for the next, so all 487 can be decrypted on a desk, each checksum
verified. The algorithm came from the glass-box patch (section 4), since the
masking is the only layer that hides the computation and it can be switched off at
a single point.

The scripts here are the tooling from each role in the Approach section. The target
binary is not part of the repository, so the scripts that read it run against your
own copy, and the recovered program files (`plain.json`, `edges.json`, `keys.json`)
are written by `recover.py` rather than shipped.

- `recover/` is the static recovery: `recover.py` decrypts all 487 blocks offline
  (section 2.4), with `classify.py` and `classify_acts.py` grouping the opcodes and
  edge actions (section 5), and `toy_vm.c` a small runnable model of the whole
  machine.
- `dynamic/` holds the glass-box patch that reads the computation in the clear
  (section 4 and appendix B) and the handler tracer.
- `brute/` is the Frida brute force that recovered the accepting PIN.
- `ida/` reapplies the analysis to the disassembly as function names, types and
  comments, reading the recovered program from the JSON that `recover.py` writes.

---

## 2. The encrypted bytecode program

The first layers hide and lock the program itself. It is bytecode run by an
interpreter, stored as code rather than data, encrypted, and decrypted with a key
that is fixed at compile time.

### 2.1 The interpreter and three tables

`MainActivity` checks `length == 6` and calls native `verifyPin`, which builds a
context and runs `vm_run`. The entry point in the DEX is a short stub, a length
gate in front of the native call:

```
invoke-virtual {v0}, Ljava/lang/String;.length:()I
move-result v1
const/4 v2, 0x6
if-eq v1, v2, :verify          # only a 6-character PIN reaches the check
...
:verify
invoke-static {v0}, Lcom/example/pinlock/PinVerifier;.verifyPin:(Ljava/lang/String;)Z
```

The `vm_run` loop does four things per block: fetch the
encrypted words from `block_loaders[block_id]`, decrypt them and verify the block
checksum, dispatch `op_handlers[word[0]]`, then take one of the block's outgoing
edges.

A decrypted block is `[handler, edge_base, max_edge_sel, operands..., MAC]`. An
edge is one branch to a successor block, and it carries three things: a register
shuffle (`edge_actions[...]`), the next block id, and that block's decryption
keys.

Most blocks have exactly one edge. 431 of the 487 blocks just run their handler
and fall through to a single successor, carrying its keys, and 4 more are end
blocks where the run stops. Block 0 is one of the single-edge blocks: it
decrypts to handler 0 with one unconditional edge to block 1, handing over the
keys `(0x87CEAC3FC8655CEB, 0xF973E9203E71DBB3)`, under which block 1 decrypts
with a valid checksum (section 2.4).

The two-level selection only matters at the remaining 52 blocks, the ones with
more than one edge, which are the same 52 split points section 3.3 analyses.
There the handler first sets `edge_sel` to pick one edge group out of
`max_edge_sel`, then a condition slot indexes that group's jump table to one
target. The condition slot holds a value in `0..3` and is seeded at random, so
which target is taken can vary from run to run. Whichever target is chosen, it
names the shuffle to apply, the next block, and that block's `(k0, k1)`.

The three table sizes are not guessed. The interpreter bounds-checks each index
and the bounds are the sizes:

| Table | Entries | Indexed by | Role |
|---|---|---|---|
| block loaders | 487 | `block_id`, the VM PC | one block's encrypted bytecode |
| opcode handlers | 313 | `word[0]` | the instruction's effect |
| edge actions | 609 | the branch taken | per-branch register shuffle |

They sit next to each other in `.data.rel.ro` and the arithmetic closes exactly
(`0x188D48 + 487*8 = 0x189C80`, `+ 313*8 = 0x18A648`, `+ 609*8 = 0x18B950`), 1409
pointers with no slack, all verified inside `.text`.

### 2.2 Bytecode stored as code

Nothing is encrypted or self-modifying, and `.text` decodes cleanly end to end.
Each block is a small function, and the fetch is a call that returns its words.
Because ARM64 cannot load a 64-bit constant in one instruction, each encrypted
word is built from one `MOVZ` and three `MOVK` immediates. A bytecode word
therefore lives as four 16-bit immediate fields, not as bytes in a section.

For example, the first word of block 0 is assembled like this:

```
MOVZ X8, #0x17d3, LSL #0
MOVK X8, #0xd6a0, LSL #16
MOVK X8, #0x0bb7, LSL #32
MOVK X8, #0xbbd8, LSL #48
```

The four immediates build the encrypted word `0xBBD80BB7D6A017D3`, which the
keystream in section 2.3 turns into the decrypted word `0x0`, handler id 0.

The program is invisible to `strings`, entropy scans and blob-carving. The cost
is size: almost all of the 1.4 MB `.text` is this generated code rather than a
fixed interpreter. The 81 KB of bytecode, stored as `MOVZ`/`MOVK` loaders, is
about a fifth of it, and the largest share, 56%, is the register shuffling in
section 3.1.

### 2.3 Encryption and a per-block checksum

```c
mix(x)      = SplitMix64 finalizer                      // 0x247E4
ks(k0,k1,i) = mix(k0 + 0x9E3779B97F4A7C15*(i+1)) ^ k1   // 0x24AA4
plain[i]    = enc[i] ^ ks(k0, k1, i)
```

The last word of every block is a `mix`-chain checksum over the rest. It is the
binary's only integrity check, and nothing checksums the code itself.

For analysis it is a free correctness check. A wrong key, keystream or block
model all fail it, so a recovered program that passes all 487 checks is correct,
not just plausible.

### 2.4 The keys form a static chain

Decryption keys are not constant. Each edge carries its successor's `(k0, k1)`
inside the block that branches to it, and only the root is fixed, hardcoded in
`vm_init` (`0xD53C59684C39E959`, `0xEEF8BF4E76A7A167` @ `0x23DD8`/`0x23DF0`).

A block cannot be decrypted without arriving on a legal path, which makes the
scheme look like a runtime defence. It is not one. Every key descends from those
two compile-time constants with no runtime randomness, so the whole program can be
decrypted offline, starting at block 0 and following the edges outward.

This was confirmed directly. Block 1 under block 0's edge keys gives a well-formed
header and a valid checksum, while the fixed root key gives garbage. It then holds
across the graph: 487 of 487 blocks reachable, 487 of 487 valid, and no block
reached under two key pairs. This static root is the single thing that makes the
whole offline recovery possible.

---

## 3. Runtime masking and randomness

The remaining layers do not touch the program. They obscure each run while it
happens, using values drawn at runtime: every register is masked, the mask is
tied to the path taken, and the control flow is shuffled.

### 3.1 Value masking, two register banks

Every value in the VM's two register banks (1007 slots each) is stored masked by
a keystream from a 128-bit `ValueKey`:

```c
M(i, salt) = mix( (vk0 ^ salt) ^ mix( vk1 + "valuemas" - 0x61C8864680B583EB*i ) )
```

The mask depends on the register index, so the same value looks different in two
slots. It cancels for static analysis, because a value is moved by removing the
old mask and applying the new one in a single expression, read directly off
`act4` @ `0x788F0` as `dst[999] = src[836] - M_old(836) + M_new(999)`.

A static model can fix the `ValueKey` to a single value and every mask drops
out, so the layer only ever defended live memory.

Every edge re-keys the `ValueKey`, copies a shuffled selection of registers into
the other bank while re-masking, and flips banks, so register numbers are not
stable across blocks. This shuffling is the 56% of the binary noted in section
2.2.

Three big-endian ASCII tags separate the three derivations: `valueini` seeds the
first `ValueKey`, `valueedg` re-keys it on every edge, and `valuemas` makes the
per-register mask `M` above.

### 3.2 The key schedule is bound to the path

`ctx+0xB0` holds a path token that every edge action checks and then updates, and
the token pair is mixed into the key derivation along with the variant and a step
counter. So the masking key at any point depends on the whole path taken to reach
it, and edges cannot be reordered, skipped or replayed without every later mask
going wrong.

This check-and-update was recovered in full, and for all 609 actions the token
values passed to the key derivation match that action's own check-and-write pair.

### 3.3 Randomised control flow, and why it is decoration

There are two sources of per-call variation: eight condition slots seeded in
`0..3`, and ten program variants chosen as `perm[nonce % 10]` (`vm_pick_variant`
@ `0x246BC`). With all 609 actions recovered, the effect is measurable and
smaller than it looks.

The control flow splits at 52 points, where a random value sends the run down one
of several routes. At 51 of them the routes soon merge back together and carry on
the same. A different verdict would have to leave through a different exit, so a
split that merges back changes the path but not the result. The one split that
never merges back is the accept-or-reject decision itself, the only place a
different choice leads to a different outcome. The ten variants are the same
story: only 60 of the 609 actions ever read the variant, at three places, and all
three merge back.

The point of this layer is to make two runs of the same PIN look different, not to
change the result. For analysis the variant can be set to any fixed value.

---

## 4. The PIN verification algorithm

Static recovery gives the machine. The algorithm was read by removing the
masking.

### 4.1 Reading the values in the clear

The mask hides every intermediate value and unmasks only at a comparison, so a
plain trace shows the digits go in and the verdict comes out with nothing legible
between. Removing the mask turns that black box into a glass box, with the whole
computation running in cleartext.

The key comes from one 128-bit draw. `vm_init` calls `vm_seed_global_getrandom` @
`0x24560`, which is `syscall(278 = getrandom, buf, 16)` through the `syscall`
wrapper, with no `getrandom` symbol to hook, drawn once per process. The mask
itself is applied and removed by one leaf function, `reg_mask_valuemas` @
`0x77DCC`.

Overwriting that function with `return 0` makes every keystream word zero, so
both the XOR mask and the additive strip become the identity and every register
holds cleartext. The verdict stays the same, because the block checksum covers
bytecode and not registers. The overwrite is a raw code patch, not an inline
hook, because inline hooks inside `libverify` hit a libunwind side effect that aborts
the process (a tooling quirk, not an integrity check). Appendix B has the exact
bytes and the method.

With the mask gone the decision reads directly:

- The verdict is one comparison at block 479. `reg[424]` is `0` for the accepting
  PIN and `0xFFFFFFFFFFFFFFFF` for every reject.
- `reg[424]` is a mismatch accumulator. A loop over blocks 456 to 477 mixes the
  six digit bytes into a sixteen-byte value and compares it byte by byte against
  a sixteen-byte internal target, sixteen rounds in all, one per target byte.
  Each round ORs the difference `computed - target` into the accumulator
  `reg[424]` (op307). The round reads digit bytes (op294, op295), mixes with a
  32-bit XOR (op296) and accumulates.
- Input validation is visible first: six characters each checked against
  `'0'..'9'`, and the ASCII of `739184` appears in order.

The cleartext corrects an earlier reading: it took the once-per-round
compare at block 462 for the target check, but in the clear its operands are the
same for every input, so block 462 is decoration rather than the comparison.

### 4.2 The transform is a mixing, nonlinear hash

Flipping any single digit changes all sixteen per-byte mismatches, one for each
byte of the target. So the transform reaches full avalanche: one digit touches the
whole result, and there is no per-digit feedback to split the problem.

It is also nonlinear, which means the result of one PIN cannot be predicted from
the results of others by simple addition or XOR. This was checked with a
linearity test: if the transform were linear, `f(730000)` would equal
`f(700000) + f(030000) - f(000000)`, where the all-zero PIN is the baseline
subtracted once so the two digit changes are not counted twice. It does not, on
any of the sixteen bytes, and the XOR version of the same test fails too. So there
is no easy formula to run the transform backwards.

No target value is stored in the clear anywhere. It exists only as the sixteen
bytes the transform has to reproduce.

So the shape is clear: validate the digits, mix them through a nonlinear
transform, compare the result byte by byte against a sixteen-byte internal
constant, and accept only when every byte matches.

The PIN here came from brute force. Getting it without trying candidates is only a
matter of effort, not of the design. The target is computed on the fly and never
stored, and the transform mixes every digit into the whole result, so it cannot be
read off or run backwards. It has to be reproduced and solved. Three routes:

- **Model and solve.** The glass box gives the transform and the sixteen-byte
  target in cleartext, so the sixteen rounds can be rebuilt offline and the
  equation `computed(digits) == target` handed to a constraint solver such as z3.
- **Offline emulator.** Rebuild just the VM's opcode handlers as a small program
  on a computer, run it over the recovered blocks, and try all one million PINs
  there. This needs no phone and is repeatable, but it is still brute force.
- **Scoped symbolic execution.** Run a symbolic executor over only the handler
  code, feed it the loaders and edge actions already recovered, and let the solver
  produce the input.

Symbolic execution was tried on the whole binary and did not work. angr fell back
to its slow engine, got stuck in the C++ setup and the parts already recovered,
and never reached the VM loop. Scoping it to the handlers is the fix, and that was
left out of the time budget.

---

## 5. Strengths and weaknesses

Trying all PINs is possible by design, so being brute-forceable is not itself a
finding.

**Strengths.**

- No secret is stored. The PIN is not in the binary, not even as a hash, so there
  is only a computation to invert.
- The check mixes the whole PIN at once, with no per-digit feedback and no early
  exit, so it cannot be cracked one digit at a time.
- Nothing is reused. 291 of 313 opcodes and all 609 edge actions appear exactly
  once, so each one must be worked out on its own. This is the biggest single cost
  for an analyst.
- The masking key depends on the exact path taken, so a live trace cannot be
  reordered, cut short or replayed.
- The program is stored as code, so tools that scan data never see it.
- The per-block checksum blocks patching straight through the check.

**Weaknesses.**

- The decryption keys come from two fixed constants with no per-run randomness, so
  the whole encrypted program can be decrypted offline, without ever running the
  app. This is why static recovery works, and it is the deepest weakness.
- A failed block checksum is thrown back to the app as a plain-text message,
  `invalid VM continuation`, with `divide by zero` for a division fault, so a
  wrong key or a bad patch announces itself at once. This is how the recovery
  stayed on the right path.
- The same checksum tells the analyst when a block has been decrypted correctly,
  which is 487 free confirmations.
- The masking cancels on paper, and one instruction removes it from a live run
  too.
- The building blocks are left recognisable. SplitMix64 and the plain-text tags
  `valueini`, `valueedg` and `valuemas` point straight at what each part does.
- One comparison at block 479 decides accept or reject, so there is a single point
  to flip.
- There is no runtime self-defence: no anti-debug or anti-hook, no root or
  emulator detection, and no control-flow flattening or other OLLVM-style tricks.
  This looks deliberate for the exercise, since any one of them would block both
  the brute force and the glass-box patch and push the work well past a reasonable
  time budget.

In short, the design hides the algorithm well, but does little to protect the
final yes-or-no, or to survive being taken apart offline.

The strongest fixes would be:

- derive the root key at runtime, for example from a server or device attestation,
  so the program cannot be decrypted offline,
- make the random branches stay genuinely different instead of almost always
  rejoining into the same path, so an analyst has to understand each one rather
  than ignore them,
- fail quietly when tampered with, instead of aborting straight away.

---

## Appendix A, the context object

0xEC bytes, offsets read off the constructor `Context::Context` @ `0x17C24C`,
grouped by role:

```
registers and values
  0x18  register bank 0 [1007 x u64]
  0x30  register bank 1 [1007 x u64]
  0x90 / 0x98  ValueKey (128-bit)
  0xB4  active bank (0/1)

decryption
  0x48  current decrypted block
  0x70 k0 / 0x78 k1  block decryption keys

control flow
  0xA8  variant (0..9)
  0xAC  block_id (the VM PC)
  0xB0  path token
  0xB8  edge_sel
  0xC8  halted
  0xCC  cond_slot[8], each 0..3

call interface
  0x60  JNIEnv*
  0x80  return value
  0x88  per-call nonce
  0xBC  error (1 bad continuation, 2 div0)
```

The `jstring` argument enters at `reg[0x234]`, and the returned boolean is the
low byte of `retval`. A decrypted block is
`[handler_id, edge_base, max_edge_sel, operands..., MAC]`, followed by its edge
groups `{cond_slot, use_variant, modulus, n_targets}` and the targets
`{action_id, next_block, next_k0, next_k1}`.

## Appendix B, the glass-box patch

Each patch is a raw code overwrite, applied live with Frida using
`Memory.patchCode` at the function's runtime address. Writing the same bytes into
the `.so` at the file offsets below and re-signing the APK gives a permanent
patch, since `extractNativeLibs` is false and the check performs no signature
check of its own. None of the three patches sits on the bytecode decrypt path, so
the block checksum still passes and the verdict stays the same.

```
reg_mask_valuemas  @ 0x77DCC  (file 0x73DCC)
    MOV X0,#0 ; RET              ->  00 00 80 d2 c0 03 5f d6
    masks off, every register reads in cleartext

vm_pick_variant    @ 0x246BC  (file 0x206BC)
    MOV W0,#7 ; RET              ->  e0 00 80 52 c0 03 5f d6
    pin the variant

vm_seed_global_getrandom  @ 0x24560  (file 0x20560)
    MOV X0,#0 ; MOV X1,#0 ; RET  ->  00 00 80 d2 01 00 80 d2 c0 03 5f d6
    fix the entropy at the root
```

`reg_mask -> 0` is enough on its own for cleartext, because the mask vanishes
whatever the key is. The getrandom stub and the pinned variant also fix the
entropy, the variant and the condition slots, so the whole run becomes
deterministic.

Confirmed on device: `739184` gives `reg[424] = 0` and "Access granted", and every
reject gives `0xFFFFFFFFFFFFFFFF`.
