#!/usr/bin/env python3
"""Starling (AdyenPOS) + generic hook-visibility tracer.
Same probe set as trace_viettel.py, plus a prologue scanner: reads the first
bytes of commonly-hooked libc functions INSIDE the app and reports which are
branch-patched (B = 0x14 opcode) — i.e. what an integrity check sees when it
reads function bytes directly (bypassing any vm_read_overwrite blinding)."""
import frida, sys, threading

DEV = "00008030-001170403E32402E"
APP = sys.argv[1] if len(sys.argv)>1 else "uk.co.starlingbank.Starling"

JS = r"""
'use strict';
function loghit(cat, detail){ send({cat:cat, detail:String(detail)}); }
function callerOf(ctx){
  try{
    var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    if(bt && bt.length){
      var s = DebugSymbol.fromAddress(bt[0]);
      return (s.moduleName || "?") + "!" + (s.name || s.address);
    }
  }catch(e){}
  return "?";
}

var RE = /cydia|substrate|substitute|ellekit|libhooker|jailbreak|taurine|dopamine|\/var\/jb|\/jb\/|apt\.|sileo|zebra|hookkit|frida|bootstrap|TweakInject|MobileSubstrate|libSandy|Cephei|preferenceloader|checkra1n|palera1n|\.deb|org\.coolstar/i;

["access","stat","lstat"].forEach(function(fn){
    var ptr = Module.findGlobalExportByName(fn);
    if(!ptr) return;
    Interceptor.attach(ptr, {
      onEnter:function(args){ try{ this.p=args[0].readCString(); this.c=callerOf(this.context); }catch(e){ this.p=null; } },
      onLeave:function(rv){ if(this.p && RE.test(this.p)) loghit(fn, this.p+" => rv="+rv+"  ["+this.c+"]"); }
    });
});
var openPtr = Module.findGlobalExportByName("open");
if(openPtr) Interceptor.attach(openPtr,{
  onEnter:function(a){ try{ this.p=a[0].readCString(); this.c=callerOf(this.context); }catch(e){ this.p=null; } },
  onLeave:function(rv){ if(this.p && RE.test(this.p)) loghit("open", this.p+" => fd="+rv+"  ["+this.c+"]"); }
});

try{
  var fm = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
  if(fm) Interceptor.attach(fm.implementation,{
    onEnter:function(args){ this.p=new ObjC.Object(args[2]).toString(); this.c=callerOf(this.context); },
    onLeave:function(rv){ if(RE.test(this.p)) loghit("NSFileManager.exists", this.p+" => "+rv+"  ["+this.c+"]"); }
  });
}catch(e){}

try{
  var cou = ObjC.classes.UIApplication["- canOpenURL:"];
  if(cou) Interceptor.attach(cou.implementation,{
    onEnter:function(args){ this.u=new ObjC.Object(args[2]).toString(); },
    onLeave:function(rv){ loghit("canOpenURL", this.u+" => "+rv); }
  });
}catch(e){}

var ge = Module.findGlobalExportByName("getenv");
if(ge) Interceptor.attach(ge,{
  onEnter:function(a){
    try{
      this.k=a[0].readCString();
      this.caller = "";
      try{
        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        if(bt && bt.length) {
          var s = DebugSymbol.fromAddress(bt[0]);
          this.caller = (s.moduleName || "?") + "!" + (s.name || s.address);
        }
      }catch(e){}
    }catch(e){ this.k=null; }
  },
  onLeave:function(rv){
    if(this.k && /DYLD_INSERT|DYLD_PRINT|MSAFE|_JB|JAILBREAK/i.test(this.k)){
      var val = rv.isNull()? "NULL" : rv.readCString();
      loghit("getenv", this.k+" => "+val+"  [caller: "+this.caller+"]");
    }
  }
});

var sc = Module.findGlobalExportByName("sysctl");
if(sc) Interceptor.attach(sc,{
  onEnter:function(a){
    try{
      var mib=a[0]; var ctl=mib.readU32(); var k2=mib.add(4).readU32();
      if(ctl===1 && k2===14) loghit("sysctl","KERN_PROC query (P_TRACED antidebug?)");
    }catch(e){}
  }
});

// --- prologue visibility: what an integrity check sees when reading bytes directly ---
setTimeout(function(){
  var fns = ["access","stat","lstat","open","fopen","sysctl","syscall","getenv","dladdr","dlsym","dlopen","getpid","getppid","task_get_exception_ports","sandbox_check","vm_read_overwrite"];
  var hits = [];
  fns.forEach(function(fn){
    var p = Module.findGlobalExportByName(fn);
    if(!p) return;
    try{
      var w = p.readU32();
      var op = w & 0xFC000000;
      if(op === 0x14000000 || op === 0x94000000){
        hits.push(fn + " B/BL-patched");
      }
    }catch(e){}
  });
  loghit("prologue-scan", hits.length ? hits.join(" | ") : "(no visible patches)");
}, 1500);

// --- dyld loaded images snapshot ---
setTimeout(function(){
  try{
    var cnt=new NativeFunction(Module.findGlobalExportByName("_dyld_image_count"),'uint32',[]);
    var gn=new NativeFunction(Module.findGlobalExportByName("_dyld_get_image_name"),'pointer',['uint32']);
    var seen=[];
    for(var i=0;i<cnt();i++){var n=gn(i).readCString(); if(n&&/TweakInject|ellekit|libhooker|substrate|substitute|Shadow|hookkit|frida|Cephei|libSandy/i.test(n)) seen.push(n);}
    loghit("dyld-snapshot", seen.length? seen.join(" | ") : "(no tweak dylibs visible)");
  }catch(e){ loghit("dyld-snapshot","err "+e); }
},1200);

// --- raw module enumeration (frida's own dyld walk: what link_map readers see) ---
setTimeout(function(){
  try{
    var seen = [];
    Process.enumerateModules().forEach(function(m){
      if(/TweakInject|ellekit|libhooker|substrate|substitute|Shadow|hookkit|Cephei|libSandy/i.test(m.path)) seen.push(m.path.split("/").pop());
    });
    loghit("raw-images", "tweak-named via enumerateModules: " + (seen.length? seen.join(" | ") : "(none visible)"));
  }catch(e){ loghit("raw-images","err "+e); }
}, 1800);

loghit("init","hooks armed (starling)");
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
    print("[*] watching 150s", flush=True)
    threading.Event().wait(150)
    print("[*] done", flush=True)

if __name__ == "__main__":
    main()
