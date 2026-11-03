// spawn_guard.js：spawn 抢跑守卫
// 原理：watchdog 靠读 /proc/*/status 的 TracerPid 判断被调试。
// 我们把所有 status 读取结果里的 TracerPid 改成 0 → watchdog 永远觉得安全。
// 同时过滤 maps 里的 frida 痕迹（次路径），记录 popen 行为（摸底慢路径）。
'use strict';

var watched = {};   // fd -> 'status' | 'maps'

function note(msg) { console.log('[guard] ' + msg); }

// ---- 1) 监视 open/openat，标记 status / maps 文件 ----
function watchOpen(name) {
    var p = Process.getModuleByName('libc.so').findExportByName(name);
    if (!p) { note('no export ' + name); return; }
    Interceptor.attach(p, {
        onEnter: function (args) {
            var path = (name === 'openat') ? args[1] : args[0];
            try { this.s = path.readUtf8String(); } catch (e) { this.s = null; }
        },
        onLeave: function (retval) {
            if (this.s == null) return;
            var fd = retval.toInt32();
            if (fd < 0) return;
            if (this.s === '/proc/self/status' || /\/proc\/\d+\/status$/.test(this.s) || this.s === '/proc/thread-self/status') {
                watched[fd] = 'status';
            } else if (/\/proc\/[^ ]*maps$/.test(this.s)) {
                watched[fd] = 'maps';
            }
        }
    });
    note('hooked ' + name);
}
watchOpen('openat');
watchOpen('open');

// ---- 2) read 时按 fd 类型补丁返回内容 ----
var readP = Process.getModuleByName('libc.so').findExportByName('read');
Interceptor.attach(readP, {
    onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
    },
    onLeave: function (retval) {
        var n = retval.toInt32();
        if (n <= 0) return;
        var type = watched[this.fd];
        if (!type) return;
        var data;
        try { data = this.buf.readUtf8String(n); } catch (e) { return; }
        if (data == null) return;
        var patched = data;
        if (type === 'status') {
            patched = patched.replace(/TracerPid:\s*[1-9]\d*/g, 'TracerPid:\t0');
        } else if (type === 'maps') {
            var lines = data.split('\n').filter(function (l) {
                var low = l.toLowerCase();
                return low.indexOf('frida') === -1 && low.indexOf('gadget') === -1 && low.indexOf('linjector') === -1 && low.indexOf('kworkerd') === -1;
            });
            patched = lines.join('\n');
            if (patched.length && !patched.endsWith('\n')) patched += '\n';
        }
        if (patched !== data && patched.length <= data.length) {
            this.buf.writeUtf8String(patched);
            retval.replace(ptr(patched.length));
            note('patched ' + type + ' read on fd=' + this.fd);
        }
    }
});
note('hooked read');

// ---- 3) 记录 popen/system/execve，摸清慢路径 ----
['popen', 'system', 'execve'].forEach(function (fn) {
    var p = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try { note(fn + ': ' + args[0].readUtf8String()); } catch (e) {}
        }
    });
    note('hooked ' + fn + ' (log only)');
});

// ---- 4) 保险丝：拦截 libc 层自杀（部分路径可能走 libc） ----
['exit', '_exit', 'abort'].forEach(function (fn) {
    var p = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!p) return;
    Interceptor.replace(p, new NativeCallback(function (a) {
        note('BLOCKED ' + fn + '(' + a + ')');
    }, 'void', ['pointer']));
});
['kill', 'tgkill', 'pthread_kill', 'raise'].forEach(function (fn) {
    var p = Process.getModuleByName('libc.so').findExportByName(fn);
    if (!p) return;
    Interceptor.replace(p, new NativeCallback(function () { note('BLOCKED ' + fn); return 0; }, 'int', []));
});

note('all guards installed, resuming');

// ---- 5) 周期枚举关键模块（setInterval 比 setTimeout 可靠）----
var enumTimer = setInterval(function () {
    try {
        var hits = [];
        Process.enumerateModules().forEach(function (m) {
            if (/nesec|ijiami|tianmu|frida|seckit/i.test(m.name))
                hits.push(m.name + ' base=' + m.base + ' size=' + m.size);
        });
        if (hits.length) {
            console.log('=== RASP modules ===');
            hits.forEach(function (h) { console.log('  ' + h); });
        }
        console.log('=== tick: total modules ' + Process.enumerateModules().length + ', RASP hits ' + hits.length);
    } catch (e) { console.log('enum err: ' + e); }
}, 5000);
setTimeout(function () { clearInterval(enumTimer); }, 60000);
