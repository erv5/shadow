#!/usr/bin/env python3
"""My Viettel jailbreak-detection tracer. Captures WHICH checks run AND what they return,
so we can tell if Shadow is neutralizing them or if something leaks."""
import frida, sys, threading

DEV = "00008030-001170403E32402E"
APP = sys.argv[1] if len(sys.argv)>1 else "com.viettel.ttnd.vietteldiscovery"

JS = r"""
'use strict';
function loghit(cat, detail){ send({cat:cat, detail:String(detail)}); }
var RE = /cydia|substrate|substitute|ellekit|libhooker|jailbreak|taurine|dopamine|\/var\/jb|\/jb\/|apt\.|sileo|zebra|hookkit|frida|bootstrap|TweakInject|MobileSubstrate|libSandy|Cephei|preferenceloader|checkra1n|palera1n|\.deb|org\.coolstar/i;

// --- file existence (C) with return value ---
["access","stat","lstat"].forEach(function(fn){
    var ptr = Module.findGlobalExportByName(fn);
    if(!ptr) return;
    Interceptor.attach(ptr, {
      onEnter:function(args){ try{ this.p=args[0].readCString(); }catch(e){ this.p=null; } },
      onLeave:function(rv){ if(this.p && RE.test(this.p)) loghit(fn, this.p+" => rv="+rv); }
    });
});
var openPtr = Module.findGlobalExportByName("open");
if(openPtr) Interceptor.attach(openPtr,{
  onEnter:function(a){ try{ this.p=a[0].readCString(); }catch(e){ this.p=null; } },
  onLeave:function(rv){ if(this.p && RE.test(this.p)) loghit("open", this.p+" => fd="+rv); }
});

// --- NSFileManager with result ---
try{
  var fm = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
  if(fm) Interceptor.attach(fm.implementation,{
    onEnter:function(args){ this.p=new ObjC.Object(args[2]).toString(); },
    onLeave:function(rv){ if(RE.test(this.p)) loghit("NSFileManager.exists", this.p+" => "+rv); }
  });
}catch(e){}

// --- canOpenURL with result ---
try{
  var cou = ObjC.classes.UIApplication["- canOpenURL:"];
  if(cou) Interceptor.attach(cou.implementation,{
    onEnter:function(args){ this.u=new ObjC.Object(args[2]).toString(); },
    onLeave:function(rv){ loghit("canOpenURL", this.u+" => "+rv); }
  });
}catch(e){}

// --- getenv WITH RETURN VALUE (does DYLD_INSERT_LIBRARIES leak?) ---
var ge = Module.findGlobalExportByName("getenv");
if(ge) Interceptor.attach(ge,{
  onEnter:function(a){ try{ this.k=a[0].readCString(); }catch(e){ this.k=null; } },
  onLeave:function(rv){
    if(this.k && /DYLD_INSERT|DYLD_PRINT|MSAFE|_JB|JAILBREAK/i.test(this.k)){
      var val = rv.isNull()? "NULL" : rv.readCString();
      loghit("getenv", this.k+" => "+val);
    }
  }
});

// --- sysctl: decode mib to spot P_TRACED (KERN_PROC) anti-debug ---
var sc = Module.findGlobalExportByName("sysctl");
if(sc) Interceptor.attach(sc,{
  onEnter:function(a){
    try{
      var mib=a[0]; var ctl=mib.readU32(); var k2=mib.add(4).readU32(); var k3=mib.add(8).readU32();
      // CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1 ; P_TRACED check uses KERN_PROC pid
      if(ctl===1 && k2===14) loghit("sysctl","KERN_PROC query (possible P_TRACED antidebug) mib=["+ctl+","+k2+","+k3+"]");
    }catch(e){}
  }
});

// --- dyld loaded images snapshot (did Shadow hide tweak dylibs?) ---
setTimeout(function(){
  try{
    var cnt=new NativeFunction(Module.findGlobalExportByName("_dyld_image_count"),'uint32',[]);
    var gn=new NativeFunction(Module.findGlobalExportByName("_dyld_get_image_name"),'pointer',['uint32']);
    var seen=[];
    for(var i=0;i<cnt();i++){var n=gn(i).readCString(); if(n&&/TweakInject|ellekit|libhooker|substrate|substitute|Shadow|hookkit|frida|Cephei|libSandy|Substitute|Substrate/i.test(n)) seen.push(n);}
    loghit("dyld-snapshot", seen.length? seen.join(" | ") : "(no tweak dylibs visible - Shadow hiding or none injected)");
  }catch(e){ loghit("dyld-snapshot","err "+e); }
},1200);

loghit("init","hooks armed v2");
"""

def on_msg(m, data):
    if m.get("type") == "send":
        p = m.get("payload", {}); print(f"[{p.get('cat')}] {p.get('detail')}", flush=True)
    elif m.get("type") == "error":
        print("JS-ERROR:", (m.get("stack") or m), flush=True)

def main():
    d = frida.get_device(DEV, timeout=15)
    pid = d.spawn([APP])
    s = d.attach(pid)
    sc = s.create_script(JS); sc.on("message", on_msg); sc.load()
    print("[*] armed, resuming", flush=True)
    d.resume(pid)
    print("[*] watching 150s — open/use the app now", flush=True)
    threading.Event().wait(150)
    print("[*] done", flush=True)

if __name__ == "__main__":
    main()
