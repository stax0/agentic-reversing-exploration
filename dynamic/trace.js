// trace.js: record the VM's decision opcodes for one PIN entry.
//
// Driven by trace.py. prep() resolves libverify.so and the handler addresses of the
// five decision opcodes (op 1/46/49/54/72). setpin() writes the PIN into the UI
// field. startfollow() uses Stalker to watch the main thread and, at each probe,
// records [block_id, opcode, x0, x9] -- the two values the opcode compares. The
// check is triggered by a real UI tap (Frida does not instrument calls it makes
// itself); stop() ends the follow and result() reads the on-screen verdict.

var base = null, TextView = null, recs = [], following = false, PROBES = {};

function setup() {
    var PV = Java.use("com.example.pinlock.PinVerifier");
    try { PV.verifyPin("000000"); } catch (e) {}                 // force libverify to load
    base = Module.findBaseAddress("libverify.so");
    if (!base) return "err no libverify";
    TextView = Java.use("android.widget.TextView");
    var offs = { 1: 0x24fac, 46: 0x2c1cc, 49: 0x2c820, 54: 0x2d184, 72: 0x3155c };
    PROBES = {};
    for (var op in offs) PROBES[base.add(offs[op]).toString()] = parseInt(op);
    return "ok " + base;
}

function setpin(pin) {
    var mas = [];
    Java.choose("com.example.pinlock.MainActivity",
        { onMatch: function (i) { mas.push(i); }, onComplete: function () {} });
    var z = mas[0].v.value;
    var fc = z.getClass().getDeclaredField("c");                 // the EditText
    fc.setAccessible(true);
    var et = Java.cast(fc.get(z), TextView);
    et.setText.overload('java.lang.CharSequence', 'android.widget.TextView$BufferType')
      .call(et,
            Java.cast(Java.use("java.lang.String").$new(pin), Java.use("java.lang.CharSequence")),
            Java.use("android.widget.TextView$BufferType").NORMAL.value);
    return "" + et.getText();
}

function resultText() {
    var mas = [];
    Java.choose("com.example.pinlock.MainActivity",
        { onMatch: function (i) { mas.push(i); }, onComplete: function () {} });
    var z = mas[0].v.value;
    var fd = z.getClass().getDeclaredField("d");                 // the result label
    fd.setAccessible(true);
    return "" + Java.cast(fd.get(z), TextView).getText();
}

rpc.exports = {
    prep: function () {
        return new Promise(function (res) {
            Java.perform(function () {
                try { res(setup()); } catch (e) { res("err " + e); }
            });
        });
    },
    setpin: function (pin) {
        return new Promise(function (res) {
            Java.scheduleOnMainThread(function () {
                Java.perform(function () {
                    try { res(setpin(pin)); } catch (e) { res("err " + e); }
                });
            });
        });
    },
    startfollow: function () {
        recs = [];
        following = true;
        Stalker.follow(Process.id, { transform: function (it) {
            var insn;
            while ((insn = it.next()) !== null) {
                var op = PROBES[insn.address.toString()];
                if (op !== undefined) {
                    (function (opc) {
                        it.putCallout(function (c) {
                            var ctx = c.fp.sub(8).readPointer();
                            var blk = ctx.add(0xAC).readU32();
                            recs.push([blk, opc, c.x0.toString(), c.x9.toString()]);
                        });
                    })(op);
                }
                it.keep();
            }
        }});
        return "following";
    },
    stop: function () {
        if (following) { Stalker.unfollow(Process.id); Stalker.flush(); following = false; }
        return { n: recs.length, recs: recs };
    },
    result: function () {
        return new Promise(function (res) {
            Java.scheduleOnMainThread(function () {
                Java.perform(function () {
                    try { res(resultText()); } catch (e) { res("err " + e); }
                });
            });
        });
    }
};
