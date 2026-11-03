# 某校园运动类App（易盾加固）libnesec.so 反调试对抗 · 进度交接总结

> 日期：2026-11-02
> 用途：交接给其他模型/协作者，独立可读
> 目标边界：本地离线学习研究，不碰服务端校验、不用于作弊

---

## 0. 一句话现状

已能在真机上让 App 带 frida 存活 30~60 秒（可复现），已 dump 出 libnesec 全部运行时解密代码，已定位三个检测调用点和一个 exit_group 裸 syscall 跳板，但**长期稳定共存尚未达成**，`exit(28)` 干净退出的发起点未定位。

---

## 1. 环境与样本

| 项 | 值 |
|---|---|
| 设备 | vivo S7（bluejay），Android 16，Magisk root |
| 样本 | `target.apk` 7.3.61，包名 `com.zjwh.android_wh_physicalfitness` |
| 加固 | 网易易盾一代整体加固（`libnesec.so`，SONAME `libsecexe.so`） |
| 叠加 RASP | 爱加密 `libijiami_1011.so`、字节天幕 `libsecsdk_tianmu.so`/`libnative-tianmu-lib.so`、MSA `libmsaoaidsec.so`（OAID SDK，自带反调试） |
| 工具 | frida 17.5.5（手机端 frida-server 已改名 `kworkerd`）、IDA MCP、simpleperf、strace、NDK 28.2 |
| 工作目录 | `<本地工作目录>/` |

---

## 2. 已确认的事实（全部有直接证据）

### 2.1 壳的结构（静态实测）

- `libnesec.so` 是**自定义 ELF**：段名为 `.gnu.fragment`（真代码）/`.gnu.draft`/`.gnu.stub`，`.text` 只有 16 字节
- 导入表 54 项，**无 `kill`/`ptrace`/`syscall`**，只有 `abort/exit/raise/popen`
- **导出名全部乱码**（不是 strip，是故意污染），无 `JNI_OnLoad` 导出
- `.gnu.stub` 在文件里全 0，运行时由壳的 loader 填充
- **运行时自解密**：`0x143766` 等偏移在文件里是密文/空，内存里才是真代码

### 2.2 死亡机制（运行时实测）

| 触发 | 死法 | 证据 |
|---|---|---|
| strace/ptrace 附加 | `exit_group(0)`，~1 秒，无 tombstone 无 FATAL | strace 日志 |
| frida 附加（裸奔） | `exited cleanly (28)`，1~3 秒 | logcat |
| NOP 掉 exit 跳板后 | SIGSEGV 空指针崩溃（NOP 改变了控制流导致后续崩溃） | logcat |
| 用户操作到某界面 | 弹 toast "检测到应用在hook环境下运行" → 退出 | 用户实测 |

### 2.3 已定位的检测点（frida backtrace 实证）

| 偏移 | 行为 | 频率 |
|---|---|---|
| `libnesec.so+0xe6968` | 读 `/proc/self/status`（TracerPid 检查，fopen+fgets 逐行解析） | 启动一次 |
| `libnesec.so+0x10c39c` | 读 `/proc/self/maps`（扫注入特征） | 持续轮询 |
| `libnesec.so+0x115ce4` | `cmp w0,#1` 判定回调 | 待确认 |

另有一个 **exit_group 裸 syscall 跳板**（`movz x8,#94; svc #0`）和 kill 跳板（x8=129），位于匿名解密区。

### 2.4 检测手段清单（至少 4 条独立通道）

1. **TracerPid**（读 `/proc/self/status`）
2. **maps 扫描**（找 `/memfd:frida-agent-64.so (deleted)` 等注入特征，走 `pread64`）
3. **popen 进程扫描**（logcat 里有 App 派生的 `sh/grep/wc/getenforce` 子进程）
4. **`dl_iterate_phdr`** 遍历已加载库（simpleperf 实证）

### 2.5 方案 B（spawn + 守卫）已验证有效

**核心结论：spawn 抢跑 + 三层守卫，App 带 frida 可存活 30~60 秒，可复现。**

守卫内容：
1. read/pread64 打补丁：`/proc/*/status` 的 `TracerPid` 归 0；maps 里含 `frida/gadget/kworkerd` 的行抹掉
2. libc `exit/_exit/abort` 用 `Interceptor.replace` 拦截
3. `raise/kill/tgkill/pthread_kill` 信号参数置 0（空操作）

关键文件：`spawn_guard.js`（CLI 用）、`spawn_py.py`（Python 驱动，消息更可靠）

**注意**：守卫只能延缓，不能根除。exit(28) 的条件触发路径仍未定位。

---

## 3. 已证伪/已排除的路线

| 路线 | 结果 | 教训 |
|---|---|---|
| 静态找 xref 定位检测点 | 失败 | 自定义 ELF + 运行时填桩，静态 xref 全断 |
| patch GOT 里的 exit 指针 | 无效 | 写入可能从未成功（dd 写他人内存需 ptrace attach，未验证） |
| 冻住进程再 attach frida | 失败 | frida 注入必须恢复线程，恢复瞬间 watchdog 就检测到 TracerPid |
| NOP exit_group 跳板 | 进程 SIGSEGV | NOP 改变控制流，后续代码崩溃。**该改决策，不该改刀** |
| 拦 MSA 检测线程（0x1c544/0x1b8d4/0x26e5c） | 照样死 | MSA 不是主杀手，且拦截有副作用（pthread_t 野指针） |
| `Process.enumerateModules/enumerateRanges` | 崩进程 | 枚举器撞壳的内存布局就死，改用 `findModuleByName` + 按页 try/catch 读 |
| 钩 Java `System.exit`/`Runtime.exit` | 未触发 | exit(28) 不走 Java 层，或钩未装上（Java 全局在 spawn 早期未就绪） |

---

## 4. 已产出材料（本目录）

| 文件 | 内容 |
|---|---|
| `libnesec_code_full.bin` | libnesec 全部 7 个真实代码区段的运行时解密版（2.58MB） |
| `libnesec_live.bin` | 检测点所在区段（0xe5000~0x117000）运行时解密版（200KB） |
| `dex_out/` | 4 个零注入 dump 的真实业务 dex（共 54,369 类） |
| `memdex2` / `memdex2.c` | 自研零注入 dex 内存扫描器（NDK 编译，root 读 /proc/pid/mem 扫 `dex\n035`） |
| `spawn_guard.js` | 守卫脚本（已验证有效） |
| `spawn_py.py` | Python 驱动版 |
| `step5.js`~`step26.js` | 各轮实验脚本（含踩坑过程） |
| `实验记录-杀进程对抗-20261028.md` | 详细实验记录 |

**另有云端脱壳产物**：9 个业务 dex（77,928 类），在 `kimicode-job/dex9/`（更全，分析应优先用它）

---

## 5. 技术要点备忘（踩坑精华）

### 5.1 frida 17.5.5 API 变更（必看）

| 旧写法（失效） | 新写法 |
|---|---|
| `Module.findExportByName(null, name)` | `Module.findGlobalExportByName(name)`（1 个参数）或 `Process.getModuleByName('libc.so').findExportByName(name)` |
| `Module.getGlobalExportByName(null, name)` | 同上（传 null 会 TypeError） |
| `Memory.readByteArray(addr, size)` | 不存在 → 用 `addr.readByteArray(size)`（指针方法） |
| `Memory.readBytes` / `ptr.readBytes` | 均不存在 |
| `NativePointer.toNumber()` | 不存在 → 用 `parseInt(ptr.toString(16), 16)` |
| `Process.enumerateModules()` / `enumerateRanges()` | **会崩掉壳进程**，禁用 |

### 5.2 壳对抗的通用规律

- **栈回溯**：`Backtracer.ACCURATE` 穿不透 ART 编译码（boot.oat 重复帧 = 断链垃圾值），钩子在 Java 层用 Java 栈回溯，native 层在壳自己的 C 函数里 backtrace 才有效
- **hook 回调里 JS 异常 = 进程崩**（线程状态损坏），回调必须全 try/catch
- **frida CLI 管道模式**（`echo "%resume" | frida ...`）里 `setTimeout/setInterval` 不触发，要么用 Python 驱动，要么在 hook 回调里做事
- **watchdog 读 maps 用 pread64 不用 read**，读 status 用 read——两个入口都要堵

---

## 6. 下一步建议（按优先级）

### 方案 ①：对检测函数本体做返回值改造（最贴近目标）
- 目标：`0x115ce4`（`cmp w0,#1` 判定回调）或 `0xe6968`（TracerPid 解析函数）
- 做法：spawn + 守卫 + `Interceptor.attach(base+0x115ce0)` 观察函数指针指向 → 找到真正的检查函数 → 强制其返回 0
- **这是文章方案 B 的精确版，优先级最高**

### 方案 ②：零注入脱壳已验证可用
- `memdex2` 已能独立 dump dex，不依赖 frida
- 但云端 9 dex 更全，分析应优先用云端产物

### 方案 ③：长期共存（条件触发路径）
- exit(28) 的条件触发点未定位，下次撞到时用组合观测（守卫 + strace 抓 exit_group 的 tid + pthread_create 记录线程创建顺序）定位

### 不要做
- 全量修复净包（4849 个 native 桩，工程量不成正比）
- 别再 NOP 任何 syscall（副作用崩溃）
- 别再动 MSA 线程（不是主杀手）

---

## 7. 一句话给下一个接手的人

> 壳是易盾一代整体加固 + 三家 RASP，检测靠 TracerPid/maps/popen/dl_iterate_phdr 四条独立通道，spawn+守卫已能撑 30~60 秒窗口，检测点坐标已有（0xe6968/0x10c39c/0x115ce4），下一步对 `0x115ce4` 判定函数做返回值改造即可尝试长期共存。**脱壳产物在云端 dex9 和本地 dex_out，分析优先用云端。**
