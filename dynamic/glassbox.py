#!/usr/bin/env python3
# Drive glassbox.js. For each PIN: launch the app fresh, set the input field, fire a
# real tap on CHECK, then read the (now cleartext) accumulator at block 479 and the
# on-screen verdict.
#
#   python glassbox.py 739184 639184 000000
#
# Requirements: a rooted emulator-5554 with the app installed and frida-server 16.4.10
# at /data/local/tmp/frida-server16. The real tap matters: calls made from the Frida
# script are not instrumented, so the input is set via Frida but triggered by adb input.
import os
import sys
import time
import subprocess
import frida

ADB = os.environ.get("ADB", "adb")
DEVICE = "emulator-5554"
PKG = "com.example.pinlock"
CHECK_BUTTON = (540, 1297)
JS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "glassbox.js")


def adb(*args):
    return subprocess.run([ADB, *args], capture_output=True, text=True)


def shell(cmd):
    return adb("shell", *cmd.split())


def frida_up():
    try:
        frida.get_device(DEVICE, timeout=5).enumerate_processes()
        return True
    except Exception:
        return False


def ensure_frida():
    if frida_up():
        return
    shell("su 0 pkill -f frida-server")
    time.sleep(1)
    subprocess.run([ADB, "shell",
                    "su 0 sh -c 'setsid /data/local/tmp/frida-server16 >/dev/null 2>&1 &'"])
    for _ in range(12):
        time.sleep(1.5)
        if frida_up():
            return
    raise RuntimeError("frida-server did not come up")


def capture(pin):
    shell("am force-stop %s" % PKG)
    time.sleep(1)
    shell("input keyevent 4")
    shell("monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG)
    time.sleep(3)
    pid = int(adb("shell", "pidof", PKG).stdout.split()[0])
    session = frida.get_device(DEVICE, timeout=10).attach(pid)
    script = session.create_script(open(JS).read())
    script.on("message", lambda m, d: None)
    script.load()
    status = script.exports_sync.prep()
    if "ok" not in status:
        raise RuntimeError(status)
    script.exports_sync.setpin(pin)
    script.exports_sync.follow()
    shell("input tap %d %d" % CHECK_BUTTON)
    time.sleep(1.3)
    out = script.exports_sync.stop()
    verdict = script.exports_sync.result()
    try:
        session.detach()
    except Exception:
        pass
    return out, verdict


def run(pin):
    for _ in range(5):
        try:
            ensure_frida()
            out, verdict = capture(pin)
            if out["acc"] is not None:
                return out, verdict
        except Exception as e:
            print("  retry:", str(e)[:50])
            shell("input keyevent 4")
            time.sleep(2)
    raise RuntimeError("capture failed for " + pin)


def main():
    for pin in sys.argv[1:] or ["739184", "639184", "000000"]:
        out, verdict = run(pin)
        acc, target = int(out["acc"]), int(out["target"])
        print("%s  reg424(acc)=%-20d reg852(target)=%d  %r" % (pin, acc, target, verdict[:16]))


if __name__ == "__main__":
    main()
