#!/usr/bin/env python3
"""Dynamic VM-handler tracer for target (see the writeup, section 1).

For a given PIN, captures the executed VM block sequence and the two operands at
every decision opcode (op1/46/49/54/72). Frida does not instrument calls it makes
itself, so the input field is set via Frida and the check is triggered with a real
UI tap while Stalker follows the main thread.

Setup: rooted API-30 arm64 emulator, frida-server 16.4.10 on device, host
frida==16.4.10, app installed. Usage: python3 trace.py 739184 [639184 ...]
"""
import frida, subprocess, time, sys, json, os
ADB=os.environ.get("ADB","adb")
PKG="com.example.pinlock"; HERE=os.path.dirname(os.path.abspath(__file__))
TAP_CHECK=(540,1297)   # CHECK PIN button centre (from uiautomator dump)
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True)
def shell(c): return sh("shell",*c.split())
def main(pins):
    sh("shell","am","force-stop",PKG); time.sleep(1)
    sh("shell","monkey","-p",PKG,"-c","android.intent.category.LAUNCHER","1"); time.sleep(3)
    pid=int(sh("shell","pidof",PKG).stdout.split()[0])
    dev=frida.get_device("emulator-5554",timeout=10); sess=dev.attach(pid)
    s=sess.create_script(open(os.path.join(HERE,"trace.js")).read()); s.on("message",lambda m,d:None); s.load()
    print("prep:", s.exports_sync.prep())
    out={}
    for pin in pins:
        s.exports_sync.setpin(pin); s.exports_sync.startfollow()
        shell("input tap %d %d"%TAP_CHECK); time.sleep(1.0)
        r=s.exports_sync.stop(); res=s.exports_sync.result()
        out[pin]=r["recs"]; print("%s compares=%d %s"%(pin,r["n"],res[:22]))
    sess.detach(); return out
if __name__=="__main__":
    pins=sys.argv[1:] or ["739184"]
    json.dump(main(pins), open(os.path.join(HERE,"trace_out.json"),"w"))
    print("wrote trace_out.json")
