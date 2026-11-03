# 某校园运动类 App 加固对抗实战记录

一次针对网易易盾一代加固（叠加多家 RASP）Android 样本的完整逆向脱壳实战。
**本仓库的价值不在"脱壳成功"，而在过程：工具、方法、踩坑记录、以及诚实的未解问题。**

> ⚠️ 仅供安全学习研究。样本与脱壳产物均不上传，需自备。所有实验仅在本地离线环境进行。

## 目标样本

| 项 | 值 |
|---|---|
| 应用 | 某校园运动类 App（应用名脱敏） |
| 包名 | com.zjwh.android_wh_physicalfitness |
| 加固 | 网易易盾一代整体加固（libnesec.so，自定义 ELF，运行时自解密） |
| 叠加 RASP | 爱加密 libijiami_1011.so、字节天幕 libsecsdk_tianmu.so、MSA libmsaoaidsec.so |
| 环境 | Pixel 真机（Android，Magisk root）、frida 17.x、NDK、IDA |

## 当前结论总表

| 问题 | 状态 |
|---|---|
| dex 脱壳 | ✅ 达成（9 个业务 dex，77,928 类，8 项核验通过；含自研零注入内存扫描器） |
| 净包回装 + 启动 | ✅ 装得上、启得动（启动链修复闭环） |
| 界面还原 | ⚠️ 黑屏：启动路径方法体被壳抽取为 native 桩（ACC_NATIVE / code_off=0），需 smali 重建，工程量已评估 |
| frida 长期共存 | ❌ 未达成：exit(28) 的发起点未定位（内联 svc，不走 libc / 信号 / 共享跳板） |
| 检测通道清单 | ✅ 已确认 4 条：TracerPid、maps 扫描（pread64）、popen 进程扫描、dl_iterate_phdr |

## 仓库内容

```
tools/
  memdex2/          零注入 dex 内存扫描器（NDK，root 直读 /proc/pid/mem，不依赖 frida）
  frida-guard/      spawn + 三层守卫脚本（读路径伪造 + libc exit 拦截 + 信号中和），验证可存活 30~60s 窗口
docs/
  protection-level-assessment.md   加固档位鉴定报告（样本到手第一步该看什么）
  shell-identification-playbook.md 壳特征识别与脱壳决策手册（含各家壳难度对比）
  anti-debug-experiments.md        杀进程对抗实验记录（方法、结果、证伪路线）
  progress-handoff.md              全量进度交接总结（含已定位的检测点偏移、死亡机制证据链）
```

## 关键认知（细节见 docs）

1. 易盾样本的死亡机制是**"检测到就自杀"**（exit/raise 伪装成闪退），不是拒绝运行
2. libnesec.so 是自定义 ELF：`.gnu.fragment` 存真代码、`.gnu.stub` 运行时填充、导出名故意污染、`.text` 只有 16 字节——静态 xref 全断，必须运行时观测
3. 对抗的核心矛盾：**守卫每多一层，native 足迹就大一分，检测面就宽一分**——Java 层反射（mCookie）比 native hook 的存活窗口更长
4. "dump 出来 ≠ 能用"：壳抽取了启动路径方法体到 native，回填 dex 后这些方法无实现，需要按业务逻辑重建 smali
5. 未解之谜（诚实标注）：exit(28) 的内联调用发起点；四条检测通道的完整权重

## 工具用法速览

```bash
# memdex2：零注入 dump（需 root，目标进程在运行）
adb push memdex2 /data/local/tmp/ && adb shell "su -c '/data/local/tmp/memdex2 <pid>'"
adb pull /sdcard/dex_out/ ./

# frida 守卫：spawn 模式 + 三层守卫，争取分析窗口
python spawn_py.py   # 按脚本内 PKG 常量修改目标包名
```

## 免责

本项目所有内容仅用于学习 Android 加固与逆向技术。仓库不包含任何样本、密钥或可绕过第三方服务的行为。请在合法授权范围内使用相关技术。
