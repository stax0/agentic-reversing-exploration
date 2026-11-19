// fastcall.js: call verifyPin directly, skipping the UI.
//
// Driven by brute2.py. prep() resolves the JNI entry points and the native
// verifyPin; brute(start, count) then calls it for each PIN in the range and
// returns the first one it accepts. Calling the function directly bypasses the
// VM's anti-observation layers and costs about 1 ms per call.

var verifyPin = null, NewStringUTF = null, DeleteLocalRef = null;
var env = null, klass = null;

function setup() {
    var e = Java.vm.getEnv();
    env = e.handle;
    var vt = env.readPointer();                                  // JNIEnv function table
    NewStringUTF   = new NativeFunction(vt.add(167 * 8).readPointer(), 'pointer', ['pointer', 'pointer']);
    DeleteLocalRef = new NativeFunction(vt.add(23 * 8).readPointer(),  'void',    ['pointer', 'pointer']);

    Java.use("com.example.pinlock.PinVerifier");            // force class init -> System.loadLibrary("verify")
    var base = Module.findExportByName("libverify.so",
        "Java_com_example_pinlock_PinVerifier_verifyPin");
    if (!base) return "libverify not loaded";
    verifyPin = new NativeFunction(base, 'int', ['pointer', 'pointer', 'pointer']);
    klass = ptr(0);                                              // verifyPin ignores its jclass
    return "ok base=" + base + " klass=" + klass;
}

rpc.exports = {
    prep: function () {
        return new Promise(function (res) {
            Java.perform(function () {
                try { res(setup()); } catch (e) { res("err " + e); }
            });
        });
    },
    brute: function (start, count) {
        return new Promise(function (res) {
            Java.scheduleOnMainThread(function () {
                try {
                    var t0 = Date.now(), hit = -1;
                    for (var i = 0; i < count; i++) {
                        var n = start + i, p = "" + n;
                        while (p.length < 6) p = "0" + p;
                        var cs = Memory.allocUtf8String(p);
                        var js = NewStringUTF(env, cs);
                        var r = verifyPin(env, klass, js);
                        DeleteLocalRef(env, js);
                        if (r !== 0) { hit = n; break; }
                    }
                    res({ hit: hit, ms: Date.now() - t0 });
                } catch (e) { res({ err: "" + e }); }
            });
        });
    }
};
