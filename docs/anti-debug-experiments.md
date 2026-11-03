# 某校园运动类App · 杀进程对抗实验记录（2026-10-28 晚）

> 目标：真机运行时定位壳/RASP 杀 frida 的机制，尝试运行时 patch 保护 frida（路线1）
> 设备：vivo_S7 (bluejay) root/Magisk，App 为原始加固包 7.3.61

## 结论速览

1. **frida-server 停掉时 App 稳定存活**（45s+ 观测无异常）。
2. **strace/ptrace 附加 → ~1 秒内 watchdog 自杀**：死法 `exit_group(0)`，无 tombstone、无 FATAL，Zygote 报 `exited cleanly (0)` 或 `(28)`。
3. **frida 附加 → 同样秒死**，即使先把进程 SIGSTOP 冻住也会死——因为 frida 注入要恢复线程运行，恢复瞬间 watchdog 读到 TracerPid 立即 exit。且 logcat 有 App 派生的 `grep/wc/sh/getenforce` 子进程（popen 进程扫描特征），说明检测不止 TracerPid 一条。
4. **watchdog 线程归属**：simpleperf（内核采样，进程无感）采样到线程落在 `libnesec.so + 0x143766`，调用 `dl_iterate_phdr`（遍历已加载库，找 frida/xposed 特征）。
5. **libnesec.so 是自解密壳**：`0x143766` 在文件里全是 0，运行时内存里才是真代码（dump 验证反汇编为合法 ARM64）。maps 里壳 so 只占 4 个小区间，真代码所在段运行时被改写。
6. **运行时 patch GOT 无效**：把 rw 区里指向 libc `exit/abort/raise` 的 7 个指针槽改成 `ret` gadget 或诱饵 `0xdead0000`，App 依然干净退出且未触发 SIGSEGV——证明 watchdog 不走这些指针，大概率内联 `svc #0` 直调 exit_group（爱加密 `libijiami_1011.so` 导入了 `syscall`）。

## 关键数据

- 壳 so：apk 内 `lib/arm64-v8a/libnesec.so`（1,879,264 字节），APK file offset `0x10d49fa4`
- 运行时映射特征（file offset → 每次启动基址不同）：
  - `r-xp 0x10e86000`（vaddr 0x13c000 起，~0xf000）= 解密代码区
  - `rw-p 0x10e97000`（~0x7e000）= GOT/数据区
- libc(bionic) 函数偏移：`exit=0x75860 _exit=0xdcd40 abort=0x70560 raise=0x84fe0 syscall=0x96d00`
- libnesec 解密代码里可用的 `ret` gadget：vaddr `0x14372c`（`c0 03 5f d6`）
- 自杀 syscall 编号：exit_group=94, exit=93
- watchdog 临死前打开 `/proc/self/status`、`/proc/<pid>/status`（strace 实证）

## 复现命令链

```bash
# 基线：停 frida-server → 启动 App → 稳定活
adb shell "su -c 'pkill -9 frida-server'"
adb shell am start -n com.zjwh.android_wh_physicalfitness/.mvi.splash.SplashActivity

# 触发死亡：strace 附加（或启动 frida-server 后 frida -U -p <pid>）
adb push strace_arm64 /data/local/tmp/strace   # 需配 libncursesw.so.6
adb shell "su -c 'LD_LIBRARY_PATH=/data/local/tmp strace -f -e trace=exit_group -o /data/local/tmp/kill.log -p <PID>'"
# 观察：唯一 exit_group(0) 来自 watchdog tid

# 定位 watchdog：simpleperf 内核采样
adb shell "su -c 'simpleperf record -p <PID> --duration 6 -o /data/local/tmp/perf.data --call-graph fp'"
adb shell "su -c 'simpleperf report -i /data/local/tmp/perf.data --children'"  # 找 libnesec.so 帧

# dump 解密代码（root 读 /proc/pid/mem）
adb shell "su -c 'dd if=/proc/<PID>/mem of=/data/local/tmp/rx.bin bs=4096 skip=$((映射基址/4096)) count=N'"
```

## 工具脚本（本目录）

- `scan_dynsym.py` / `scan_elf_generic.py`：ELF dynsym 扫描（IDA 的 enum_import_names 有 bug 时的替代）
- `kill_probe.js`：frida 最小探针
- `tpoll.sh` / `tpoll2.sh` / `sample_threads.sh`：轮询 /proc/<pid>/task 的 comm/syscall，抓 watchdog tid
- `plan_a.py` ~ `plan_a4.py`：冻结→找 GOT 槽→改写指针→解冻→frida 验证（**已证伪：watchdog 不走 GOT**）
- `ice_attach.js`：冻结态预装 hook 的 frida 脚本（未成功，注入需恢复线程，恢复即死）

## 下一步候选

- A. dump 完整解密代码区 → 反汇编定位内联 svc exit_group 的调用点 → 但代码段 r-x，运行时改写需 mprotect/ptrace，且重启即失效（学习价值高）
- B. frida spawn 模式 + 极早 hook（`-f` 启动即挂，抢在 watchdog 线程创建前）——待试
- C. 回到脱壳思路：frida-dexdump spawn 瞬间 dump（壳解密 dex 后第一时间）
- D. 放弃运行时对抗，ROM/内核层（定制系统镜像，隐藏 frida）——工作量大但一劳永逸

## 2026-10-28 深夜追加（方案B实测）

**方案B基本跑通**：`frida -U -f` spawn 模式 + 双守卫（`/proc/*/status` 的 TracerPid 读结果打补丁 + libc `exit/_exit/abort/kill/tgkill/pthread_kill/raise` 全 replace），App 带 frida 存活 60s+，多次实验可复现。

关键脚本：
- `spawn_guard.js`：纯 JS 守卫（CLI 管道模式用，注意 frida 17 无 `Module.findExportByName`，要 `Process.getModuleByName().findExportByName()`）
- `spawn_py.py`：**Python 驱动版（推荐）**，消息经 send() 通道不丢；frida-server 改名 `kworkerd` 降低 popen 扫描特征

新发现（补认知）：
1. **进程内读 /proc/self/maps 被壳过滤**：App 自己读只能看到 framework-res.apk，壳的 base.apk 映射全隐藏。外部 root 读才见真相 → 在进程内做 maps 分析不可行。
2. **`Process.enumerateModules()` 会被壳搞崩**（枚举到一半进程死）→ 必须用 libc 直读+解析。
3. **watchdog 主杀器是 `raise`**：BLOCKED raise 反复出现，raise 被拦后它还会换路径（某次 3 秒后还是死了），说明自杀路径有重试/多条。
4. 壳 so 加载不触发 libc `dlopen` 钩子（不走标准 dlopen），JNI_OnLoad 定位需另找挂载点（.init_array 时机）。
5. libart.so strip，无 RegisterNatives 符号；正确路径是 `(*env)->RegisterNatives` 虚表槽位（index 215），但需先拿到 JNIEnv*。

**JNI_OnLoad 定位状态**：未定位到 libnesec 的（导出名全乱码、无 JNI_OnLoad）；libijiami 有正规 JNI_OnLoad 导出但尚未在存活窗口内完成 hook 验证。下轮可用「BLOCKED raise 回调里再钉 hook」的策略（该回调必触发且触发时全部 RASP 已加载）。
