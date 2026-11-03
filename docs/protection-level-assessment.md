# 某校园运动类App · 易盾加固鉴定报告

- 鉴定日期：2026-10-12
- 样本：`target.apk`（325,728,402 字节），已复制至本地工作区
- 包名：`com.zjwh.android_wh_physicalfitness`
- **用途边界：仅本地离线个人学习研究，不针对服务端、不上传任何数据、不分发。**

---

## 1. 结论

| 项 | 结论 |
|---|---|
| 加固方案 | **网易易盾 · 整体加固（一代壳结构）** |
| 壳 native | `lib/arm64-v8a/libnesec.so`（1,879,264 字节）+ x86 版 `libnesec-x86.so` |
| 加固时间戳 | 2026-08-17（`classes.dex` / `libnesec.so` / `AndroidManifest.xml` 三处一致） |
| 叠加 RASP | 易盾 `libnetseckit-4.2.4.so` ＋ 爱加密 `libijiami_1011.so` ＋ 字节天幕 `libsecsdk_tianmu.so` / `libnative-tianmu-lib.so` |
| 脱壳类别 | 整体加固 dump（与 360 奶酪单词同构，RASP 更强） |
| 预估周期 | 阶段 1（dump）1–3 天；全项目 2–4 周，视里程链路所在层浮动 |

## 2. 鉴定证据

### 2.1 壳 dex 结构（决定性）

`classes.dex`（81,592,472 字节）头部解析：

- magic `dex\n035`，合法 dex；
- **class_defs 仅 30 个**，类名全部为 `CDCCC` / `CDCD` / `CDLCC` 等混淆壳类（易盾壳典型特征）；
- string_ids 仅 1084 条。

→ 壳 dex 本身不含业务代码；81MB 体积为**加密后的原业务 dex 载荷内嵌其中**，运行时由 `libnesec.so` 解密并加载。**这是整体加固（一代）的结构特征，非方法抽取（二代）**——抽取壳的 dex 里能看到业务类名但方法体为空，本样本连业务类名都不存在。

### 2.2 时间戳证据

加固器写入的文件时间为 2026-08-17 10:34–10:37，仅出现在 `classes.dex`、`libnesec*.so`、`AndroidManifest.xml`；其余 so 均为 1981-01-01（未被动过的原版）——符合"加固只替换 dex + 注入壳 so + 改清单"的行为模式。

## 3. App 架构盘点（so 清单分析）

| so | 归属 | 与本项目的关系 |
|---|---|---|
| `libflutter.so` (10.8MB) + `libapp.so` (8.6MB) | **Flutter 引擎 + Dart AOT 业务代码** | ⚠️ 若里程 UI 在 Flutter 层，修改对象是 AOT 机器码，无反编译器可用，难度跳档 |
| `libAMapSDK_NAVI_v10_0_700.so` (39MB) | 高德导航 SDK | 跑步轨迹模块疑似基于它（原生层回调链路） |
| `libswsport.so` (637KB) | 厂商自研（"sw sport"） | 跑步业务 native 实现候选，重点分析对象 |
| `libsqlcipher.so` (3.6MB) | SQLCipher | 本地跑步记录加密存储；改里程可能直接改库 |
| `libnetseckit-4.2.4.so` | 易盾 | 通信安全/防抓包组件 |
| `libijiami_1011.so` | 爱加密 RASP | 反 frida / 反调试 |
| `libsecsdk_tianmu.so` / `libnative-tianmu-lib.so` | 字节天幕 | 反 frida / 反调试 |
| 其余 | Bugly、穿山甲/优量汇广告、ijk/rxffmpeg 播放器、tensorflowlite、uni/统计 SDK 等 | 与本项目无关 |

**关键未知项**：跑步/里程链路在哪一层（Flutter 平台通道 / 纯 Java / native 回调）——需 dump 出原 dex 后用 jadx 确认。

## 4. 风险登记

| 风险 | 影响 | 应对 |
|---|---|---|
| 里程逻辑在 Flutter AOT 层 | smali patch 不适用，需机器码级手术 | dump 后先定位链路；若在 Flutter 层则重新评估改法（hook 平台通道/内存改） |
| 离线无法进入跑步界面 | 本地改完没地方显示 | 视情况 patch 登录/网络依赖，或改本地记录库的展示链路 |
| 三家 RASP 叠加杀 frida | frida-dexdump 可能一附加就死 | 复用奶酪单词"最小 patch 掐自杀点"打法；必要时换端口、清理 maps 指纹 |
| 完整性校验拒绝重打包 app | 二次签名后无法启动 | patch 签名校验（有重签名经验） |
| 本地库 SQLCipher 加密 | 直接改 DB 需要密钥 | 走 app 自身读写路径或 hook 加解密函数 |

## 5. 脱壳路线

- **阶段 1 · Dump（1–3 天）**：frida-dexdump 直接跑；被 RASP 杀则上定制脚本——最小 patch 掐自杀 syscall + 内存搜 `dex\n035` 落地即 dump。目标：还原出原业务 dex。
- **阶段 2 · 定位（1 天）**：jadx 打开原 dex，找跑步/里程/运动数据链路，确定所在层。
- **阶段 3 · 修改（周期大头）**：按链路所在层选改法（smali patch / frida hook / native patch）。
- **阶段 4 · 打包运行（1–2 天）**：重签名 + 过完整性校验，跑起本地离线版验证。

## 6. 边界声明

本项目全部操作在本地离线副本上进行：脱壳产物不用于绕过服务端校验、不上传任何数据、不向第三方分发工具或补丁。项目目标仅为学习易盾整体加固的对抗与还原技术。
