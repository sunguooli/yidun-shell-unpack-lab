# spawn_py.py：Python 驱动的 spawn + 守卫 + maps解析 + RegisterNatives
# 比 CLI 管道可靠：消息不丢，会话显式控制
import frida, sys, time, re

PKG = "com.zjwh.android_wh_physicalfitness"

JS = r"""
'use strict';
var watched = {};
var libc = Process.getModuleByName('libc.so');
function sendLine(s) { send({type:'log', line:s}); }

// ---- 守卫：TracerPid 补丁 ----
['openat','open'].forEach(function(name){
    var p = libc.findExportByName(name);
    if(!p) return;
    Interceptor.attach(p, {
        onEnter: function(args){
            var path = (name==='openat')?args[1]:args[0];
            try{ this.s = path.readUtf8String(); }catch(e){ this.s=null; }
        },
        onLeave: function(rv){
            if(this.s==null) return;
            var fd = rv.toInt32(); if(fd<0) return;
            if(this.s==='/proc/self/status' || /\/proc\/\d+\/status$/.test(this.s)) watched[fd]='status';
            else if(/\/proc\/[^ ]*maps$/.test(this.s)) watched[fd]='maps';
        }
    });
});
Interceptor.attach(libc.findExportByName('read'), {
    onEnter: function(args){ this.fd=args[0].toInt32(); this.buf=args[1]; },
    onLeave: function(rv){
        var n=rv.toInt32(); if(n<=0) return;
        var t=watched[this.fd]; if(!t) return;
        var data; try{ data=this.buf.readUtf8String(n);}catch(e){return;}
        if(data==null) return;
        var patched = (t==='status')
            ? data.replace(/TracerPid:\s*[1-9]\d*/g,'TracerPid:\t0')
            : data.split('\n').filter(function(l){
                var lo=l.toLowerCase();
                return lo.indexOf('frida')<0 && lo.indexOf('gadget')<0 && lo.indexOf('kworkerd')<0;
              }).join('\n');
        if(t==='maps' && patched.length && !patched.endsWith('\n')) patched+='\n';
        if(patched!==data && patched.length<=data.length){
            this.buf.writeUtf8String(patched);
            rv.replace(ptr(patched.length));
        }
    }
});

// ---- 守卫：libc 自杀拦截（触发时上报并枚举 maps）----
var done = {};
function onKill(fn) {
    sendLine('BLOCKED ' + fn);
    if (done.maps) return;
    done.maps = true;
    try {
        var openat = new NativeFunction(libc.findExportByName('openat'),'int',['int','pointer','int','int']);
        var read = new NativeFunction(libc.findExportByName('read'),'int',['int','pointer','int']);
        var closeF = new NativeFunction(libc.findExportByName('close'),'int',['int']);
        var fd = openat(-100, Memory.allocUtf8String('/proc/self/maps'), 0, 0);
        if (fd >= 0) {
            var buf = Memory.alloc(512*1024);
            var total=0, r;
            while((r=read(fd, buf.add(total), 65536))>0) total+=r;
            closeF(fd);
            var seen={}, n=0;
            var raw = buf.readUtf8String(total);
            var allLines = raw.split('\n');
            sendLine('first 3 raw lines: ' + JSON.stringify(allLines.slice(0,3)));
            sendLine('lines containing apk: ' + allLines.filter(function(l){return l.indexOf('.apk')>=0;}).length);
            allLines.filter(function(l){return l.indexOf('.apk')>=0 && l.indexOf('overlay')<0;}).slice(0,35).forEach(function(l){
                sendLine('APK: ' + l.substring(0, 160));
            });
            allLines.forEach(function(ln){
                var m = ln.match(/^[0-9a-f]+-[0-9a-f]+ (....) [0-9a-f]+ \S+ \d+\s+(\/\S+)$/);
                if (m && !seen[m[2]]) {
                    seen[m[2]]=1; n++;
                    if (/nesec|ijiami|tianmu|seckit/i.test(m[2])) sendLine('RASP-MAP: ' + m[2] + ' perm=' + m[1]);
                    if (/zjwh|base\.apk/i.test(m[2])) sendLine('APP-MAP: ' + m[2] + ' perm=' + m[1]);
                }
            });
            sendLine('total mapped files: ' + n);
        }
    } catch(e) { sendLine('maps err: ' + e); }
}
['exit','_exit','abort'].forEach(function(fn){
    var p=libc.findExportByName(fn);
    if(p) Interceptor.replace(p, new NativeCallback(function(){ onKill(fn); }, 'void', []));
});
['kill','tgkill','pthread_kill','raise'].forEach(function(fn){
    var p=libc.findExportByName(fn);
    if(p) Interceptor.replace(p, new NativeCallback(function(){ onKill(fn); return 0; }, 'int', []));
});
sendLine('guards up');
"""

def on_message(msg, data):
    if msg.get('type') == 'send':
        print(msg['payload']['line'], flush=True)
    else:
        print('[frida]', msg, flush=True)

device = frida.get_usb_device(timeout=10)
print("[*] spawning", PKG, flush=True)
pid = device.spawn([PKG])
session = device.attach(pid)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
device.resume(pid)
print(f"[*] resumed pid={pid}", flush=True)

t0 = time.time()
alive_mark = 0
while time.time() - t0 < 45:
    time.sleep(3)
    try:
        alive = device.get_process(pid)
        alive_mark += 1
    except Exception:
        print("[*] process gone at t+%ds" % (time.time()-t0), flush=True)
        break
else:
    print("[*] survived full 45s", flush=True)
session.detach()
