// Glass box for libverify.so: turn off the per-register value masking so the VM's
// registers hold cleartext, then read the PIN check's accumulator directly.
//
// reg_mask_valuemas @ 0x77DCC returns the per-register mask word that the handlers
// XOR in (and add/subtract on moves). Overwriting it with `return 0` makes every
// blind and unblind the identity, so the register file is plaintext. The verdict is
// unchanged, since the block MAC covers the bytecode rather than the registers.
// vm_pick_variant @ 0x246BC -> 7 pins the interleaved variant so the path is stable.
//
// The accepting run leaves reg[424] (the mismatch accumulator) == 0 at block 479;
// every reject leaves it 0xFFFFFFFFFFFFFFFF. reg[852] is the compare's zero operand.

var base = null, dispatch = null, TextView = null;
var acc = null, target = null, following = false;

function patch(rva, bytes) {
    Memory.patchCode(base.add(rva), bytes.length, function (p) { p.writeByteArray(bytes); });
}

function attach() {
    Java.use("com.example.pinlock.PinVerifier").verifyPin("000000"); // force the lib to load
    base = Module.findBaseAddress("libverify.so");
    if (!base) return "libverify.so not loaded";
    dispatch = base.add(0x24184);                               // opcode-dispatch BLR, x0 = ctx
    TextView = Java.use("android.widget.TextView");
    patch(0x77DCC, [0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]); // reg_mask       MOV X0,#0 ; RET
    patch(0x246BC, [0xe0, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]); // vm_pick_variant MOV W0,#7 ; RET
    return "ok " + base;
}

function activity() {
    var hit = [];
    Java.choose("com.example.pinlock.MainActivity",
                { onMatch: function (i) { hit.push(i); }, onComplete: function () {} });
    return hit[0].v.value;
}

function setPin(pin) {
    var field = activity().getClass().getDeclaredField("c");   // the EditText
    field.setAccessible(true);
    var et = Java.cast(field.get(activity()), TextView);
    var str = Java.cast(Java.use("java.lang.String").$new(pin), Java.use("java.lang.CharSequence"));
    et.setText.overload("java.lang.CharSequence", "android.widget.TextView$BufferType")
      .call(et, str, Java.use("android.widget.TextView$BufferType").NORMAL.value);
    return "" + et.getText();
}

function verdict() {
    var field = activity().getClass().getDeclaredField("d");   // the result label
    field.setAccessible(true);
    return "" + Java.cast(field.get(activity()), TextView).getText();
}

function bankU64(ctx, idx) {
    var bank = ctx.add(0xB4).readU32();                         // active bank, 0 or 1
    var data = ctx.add(0x18 + 0x18 * bank).readPointer();       // std::vector begin pointer
    return data.add(idx * 8).readU64().toString();
}

rpc.exports = {
    prep:   function () { return new Promise(function (r) { Java.perform(function () { try { r(attach()); } catch (e) { r("err " + e); } }); }); },
    setpin: function (p) { return new Promise(function (r) { Java.scheduleOnMainThread(function () { Java.perform(function () { try { r(setPin(p)); } catch (e) { r("err " + e); } }); }); }); },
    result: function () { return new Promise(function (r) { Java.scheduleOnMainThread(function () { Java.perform(function () { try { r(verdict()); } catch (e) { r("err " + e); } }); }); }); },
    follow: function () {
        acc = null; target = null; following = true;
        Stalker.follow(Process.id, { transform: function (it) {
            var i;
            while ((i = it.next()) !== null) {
                if (i.address.compare(dispatch) === 0) it.putCallout(function (c) {
                    var ctx = c.x0;
                    if (ctx.add(0xAC).readU32() === 479 && acc === null) {
                        acc = bankU64(ctx, 424);
                        target = bankU64(ctx, 852);
                    }
                });
                it.keep();
            }
        }});
        return "following";
    },
    stop: function () {
        if (following) { Stalker.unfollow(Process.id); Stalker.flush(); following = false; }
        return { acc: acc, target: target };
    }
};
