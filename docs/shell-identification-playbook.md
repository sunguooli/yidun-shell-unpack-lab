# 壳特征识别与脱壳决策手册

> 基于某校园运动类App（网易易盾一代 + 三 RASP）实战复盘整理
> 整理日期：2026-10-22

---

## 一、本样本的壳特征全景（静态 + 运行时）

### 静态特征（不运行 app 就能看）

| 特征 | 本样本表现 | 为什么是壳的特征 |
|---|---|---|
| classes.dex 极小 | 仅 30 个类，全是 `com.netease.nis.wrapper.*` | 整体加固把业务代码全部搬走，dex 只剩壳的 Java 层入口 |
| Application 指向壳类 | Manifest 里 Application = `MyApplication`（壳包名） | 壳要抢先于一切业务代码执行，必须占据 Application 入口 |
| assets 巨型加密文件 | 81.6MB 内嵌 payload | 业务 dex（及资源）被加密藏在这里 |
| 自研 so 无 `Java_` 导出 | libnesec.so 导出表零 Java_ 前缀 | 正常 so 直接导出 Java_ 函数；壳引擎用 RegisterNatives 动态注册隐藏真实入口 |
| so 里有高熵密文段 | 0x20000 处 64KB 窗口熵值 8.00 | 加密数据/代码段的指纹（明文代码熵通常 6 以下） |
| extractNativeLibs=false | 安装后 lib/ 目录为空 | 现代 app 趋势；副作用是 so 不落盘，传统"删 so"手法失效 |

### 运行时特征（跑起来才能看）

| 特征 | 本样本表现 | 说明 |
|---|---|---|
| attachBaseContext 抢跑 | 壳 Application 第一步就 `System.loadLibrary("nesec")` | 解密必须在任何业务类加载前完成 |
| dex 解密后毁头 | payload dex 头索引区落地即销毁，ART 照常运行 | 一代壳的进阶反 dump：让你 dump 到废 dex |
| frida 行为级检测 | spawn 注入 68ms 静默死；改端口/改进程名无效 | 检测的是 gum 特征/agent 行为，不是端口字符串 |
| ptrace 容忍短窗口 | 外部 ptrace dump 几秒~几十秒后进程才被收 | TracerPid 轮询类检测，非 blanket 反调试 |
| 多 RASP 共存 | netseckit 4.2.4 + 爱加密 + 天幕 | 大厂 app 常叠加多家防护，攻击面要分开评估 |

---

## 二、通用识别方法论（拿到新 app 的五步体检）

```
第1步 看 dex：jadx / MT管理器 / jadx-gui
  → classes.dex 类数 < 100 且是单一代码风格？→ 加固
  → 记录壳包名（com.netease.nis / com.stub / com.tencent.StubShell / qihoo…）

第2步 看 Manifest：Application 名、meta-data（加固厂常留标记）
  → 壳的 Application 必然替换了原包名

第3步 看 assets + lib：体积异常大的无扩展名文件 = 加密 payload
  → lib/ 下的自研 so 名单，挨个过第4步

第4步 so 体检（静态，三看）：
  ① 导出表：有无 Java_ 前缀？没有 → 壳味浓（RegisterNatives 型）
  ② 熵值扫描：找熵 >7.5 的连续段 → 密文段（可用 so_health.py）
  ③ 字符串：strings | grep -iE "frida|gum|ptrace|TracerPid|/proc/self"
     → 直接告诉你它查什么（本样本靠这个一步确认反注入）

第5步 运行时验证：logcat 抓 nativeloader 加载链
  → 谁在什么时机加载了哪个 so，加载顺序就是防御链的顺序
```

**判代速查**：
- **一代（整体加固）**：dex 全空、payload 整包加密运行时整体解密 → 内存里有完整 dex → 传统 dump 可破
- **二代（抽取壳）**：dex 里类方法体为空（NOP），方法指令按需解密执行 → 内存里没有完整 dex → 必须 hook 解密点逐方法还原（Youpk/FART 类）
- **VMP（虚拟化）**：关键函数被翻译成自定义指令由 so 内置 VM 解释执行 → 无静态等价物 → 只能逆 VM 或黑盒调用（unidbg）
- **本样本的特殊性**：一代的底子 + 毁头反 dump + 行为级反注入，三件套叠加

---

## 三、卡点决策手册（每卡住一步该干什么）

| # | 卡住的现象 | 先判断 | 然后干什么 |
|---|---|---|---|
| 0 | 不知道包名 | — | `frida-ps -Uai`（名字↔包名对照最直观）；或 MT 管理器；`pm list packages` |
| 1 | 不确定有没有壳 | dex 类数 + Application 名 | <100 类 + 陌生 Application → 有壳；类数正常再看 so |
| 2 | 不确定壳的档位 | payload 形态 + 运行时 dex | 整包大文件→一代；方法体空→二代抽抽；IDA 里函数大 switch 分发→VMP 嫌疑 |
| 3 | frida 一注就死 | 检测的是字符串/端口还是行为 | 先改名改端口重编 strongR 试（半天成本）；死了就是行为级→放弃 frida 主路 |
| 4 | dump 出来 dex 没类/头乱 | 竞速 dump 一次（启动毫秒级 attach） | 头还是坏的 → 落地即加密，外部时机无解 → 转 unidbg M1 |
| 5 | unidbg 跑 so 报错 | 三类补环境：JNI 缺实现 / 文件读写 / 系统属性 | 报错信息逐个补，这是 M1 的日常，属正常消耗不是翻车 |
| 6 | dex 拿到但想改 app | — | dex 塞回 APK 重打包重签名，壳的 so 直接不打包 → 检测面消失 |

**元规则**：
1. 每换一种手法失败，都要留下"为什么失败"的精确结论——本样本三条外路（frida 杀/删库死/dump 废头）死因各不相同，正是这些死因拼出了壳的完整画像。
2. 外部手段连续两次失败，就不要再试第三种外部工具（BlackDex/FRIDA-DEXDump/panda 本质同类），应立即换维度（模拟器/静态）。
3. 大佬的经验话术（如 rm -f）先验证前提（extractNativeLibs 状态），一分钟的事，能避免一天的弯路。

---

## 四、主流厂商壳难度排行（经验性，非全量实测）

> 说明：同一厂家的免费版/企业版差距巨大，排行按"现在（2026）遇到企业版"的实际体感。
> 免费版普遍是一代可 dump；企业版才上二代/VMP/反调试全家桶。

| 档位 | 厂商/产品 | 典型特征 | 脱壳主路 |
|---|---|---|---|
| T0 | **网易易盾（企业版）** ← 本样本 | 一代 + dex 毁头 + 行为级反 frida + 可叠 VMP | unidbg M1 截解密；VMP 部分黑盒 |
| T0 | **腾讯御安全/乐固（企业版）** | 二代抽取为主，可开 VMP、反调试成熟 | Youpk/FART 类 hook 还原；VMP 函数黑盒 |
| T0 | **阿里聚安全（企业版）** | 整体加固 + dex 变形 + 反注入 | 竞速 dump / M1；环境检测较严 |
| T1 | **360 加固（企业版/新版）** | 一代为主但反 dump 逐年加强 | 外部 dump 成功率逐年下降，M1 兜底 |
| T1 | **梆梆（企业版）** | 老牌一代，免费版极脆 | 免费版 BlackDex/FDex2 秒破 |
| T2 | **爱加密（早期/免费版）** | 一代，dex 解密后完整躺内存（本样本同时叠了它家 RASP） | dump 直出 |
| T2 | **百度加固、通付盾等** | 一代为主，维护渐少 | dump 直出 |

**与工具的对照**：
- BlackDex（虚拟框架内 dump）：一代免费版通杀，企业版/反检测 app 失效（本样本实测失败）
- FRIDA-DEXDump：一代直出，但依赖 frida 能活着（本样本死因：行为级检测）
- Youpk / FART（ROM 层 hook）：一代二代通吃，需要刷机或特定环境
- panda-dex-dumper（ptrace 外部）：无注入风险但怕 TracerPid 轮询（本样本死因：扫描时间一长进程被杀）
- unidbg M1（模拟器内截获）：结构上最高位——不跟检测方打攻防，让它替你把活干了

---

## 五、一句话总结

> 识别壳 = 看 dex 类数 + Application 名 + assets 大文件 + so 导出表和熵值；
> 破壳 = 一代 dump、二代 hook 还原、VMP 黑盒，外路不通就上 unidbg 截解密时刻；
> 每卡一步先精确归因，再换维度，不要同维度三连撞。
