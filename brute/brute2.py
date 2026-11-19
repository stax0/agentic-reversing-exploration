#!/usr/bin/env python3
# Brute force the 6-digit PIN by calling verifyPin directly through fastcall.js,
# which bypasses every anti-observation layer. Resumable via progress.txt, ~1 ms
# per call. Usage: python brute2.py
import frida,sys,time,subprocess,os
HERE=os.path.dirname(os.path.abspath(__file__))
ADB=os.environ.get("ADB","adb"); PKG="com.example.pinlock"
PROG=os.path.join(HERE,"progress.txt")
def sh(*a): return subprocess.run([ADB]+list(a),capture_output=True,text=True).stdout.strip()
def pid():
    for _ in range(30):
        p=sh("shell","pidof",PKG).strip()
        if p: return int(p.split()[0])
        time.sleep(0.5)
    return None
def launch():
    sh("shell","am","force-stop",PKG); time.sleep(1)
    sh("shell","monkey","-p",PKG,"-c","android.intent.category.LAUNCHER","1"); time.sleep(3)
    return pid()
def attach_prep():
    p=pid() or launch()
    d=frida.get_usb_device(timeout=10); sess=d.attach(p)
    s=sess.create_script(open(os.path.join(HERE,"fastcall.js")).read()); s.on("message",lambda m,dd:None); s.load()
    r=s.exports_sync.prep()
    if "ok" not in str(r): raise RuntimeError("prep failed: "+str(r))
    return sess,s
start=0
if os.path.exists(PROG):
    try: start=int(open(PROG).read().strip())
    except: start=0
print("resume from",start); sys.stdout.flush()
BATCH=1500; t0=time.time(); n0=start
sess,s=attach_prep()
while start < 1000000:
    try:
        r=s.exports_sync.brute(start,min(BATCH,1000000-start))
        if isinstance(r,dict) and r.get("hit",-1)>=0:
            print("\n*** FOUND PIN: %06d ***"%r["hit"]); sys.stdout.flush(); break
        start+=BATCH; open(PROG,"w").write(str(start))
        if start % 30000 == 0:
            el=time.time()-t0; rate=(start-n0)/el if el else 0
            print("progress %d  (%.0f/s, eta %.0fmin)"%(start,rate,(1000000-start)/rate/60 if rate else 0)); sys.stdout.flush()
    except Exception as e:
        print("crash at ~%d (%s); relaunching..."%(start,type(e).__name__)); sys.stdout.flush()
        try: sess.detach()
        except: pass
        time.sleep(2)
        for attempt in range(5):
            try: sess,s=attach_prep(); break
            except Exception as e2: print("  reattach fail:",str(e2)[:80]); time.sleep(3)
        else: print("could not reattach; abort"); break
else:
    print("no PIN found")
