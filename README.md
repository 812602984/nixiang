# Privacy Scanner

**零依赖的 APK / IPA 隐私合规静态扫描器** —— 一条命令看清一个 App 声明了哪些权限、集成了哪些第三方 SDK、穿了什么加固壳，并输出一份可交付的评估报告。

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

不用装 `pip install` 几十 MB 的依赖，克隆下来直接跑。

---

## 30 秒跑起来

```bash
git clone https://github.com/812602984/nixiang.git
cd nixiang

# 扫仓库自带的合成样本（无需任何真实 App）
python3 scanner.py tests/samples/demo-app.apk
```

输出：

```
[扫描] demo-app.apk
  权限 5 项 / SDK 4 个 / 加固 2 个 → out/demo-app-apk-报告.md

[完成] 1 个文件，汇总表：out/汇总.csv
demo-app.apk 高风险权限 4 项：读取已安装应用列表, 读取设备与通话状态, 读取通讯录, 精确位置
```

扫自己的包：

```bash
python3 scanner.py /path/to/app.apk                  # 单个文件
python3 scanner.py ./packages/ --out reports         # 整个目录
python3 scanner.py ./packages/ --out reports --json  # 同时导出原始 JSON
```

环境要求：Python 3.8+，无第三方依赖。

---

## 它长什么样

报告是七章结构，以下是真实输出片段：

### 结论摘要

- 声明权限 / 隐私用途共 **5** 项，其中高风险 **4** 项
- 识别第三方 SDK **4** 个，其中高风险（涉设备标识 / 广告归因）**3** 个
- 加固状态：**梆梆加固、360 加固**
- 对外 URL Scheme **2** 个，导出组件 **1** 个

### 第三方 SDK 清单

| 风险 | SDK | 厂商 | 用途 | 命中证据 |
| --- | --- | --- | --- | --- |
| 中 | 微信开放 SDK | 腾讯 | 三方登录 / 分享 / 支付 | `classes.dex: com.tencent.mm.opensdk` |
| 高 | 友盟+ 统计 | 阿里 / 友盟 | 统计 / 推送 | `classes.dex: com.umeng.analytics` |
| 高 | 穿山甲 / 巨量引擎 | 字节跳动 | 广告 | `classes.dex: com.bytedance.sdk.openadsdk` |
| 高 | 神策数据 | 神策 | 埋点统计 | `classes.dex: com.sensorsdata.analytics` |

**每条命中都带证据** —— 精确到"在哪个 dex 文件里命中了哪条字符串"，你可以自己去那个文件里 `strings` 一下复核，而不是凭空相信一个结论。

### 输出文件

| 文件 | 内容 |
| --- | --- |
| `out/<app>-<格式>-报告.md` | 七章报告：基本信息 / 结论摘要 / 权限清单 / SDK 清单 / 对外暴露面 / 合规风险与复核点 / 检测方法与局限 |
| `out/汇总.csv` | 多应用拉平明细（`utf-8-sig`，Excel 直接打开不乱码），便于横向对比一批 App |
| `out/<app>-<格式>-结果.json` | 原始结构化结果（加 `--json` 时生成） |

---

## 检测能力

### APK

- **二进制 AXML 解析**：字符串池（UTF-8 / UTF-16 双编码）、START/END ELEMENT、属性值类型还原（string / int / bool / reference / float）；对被加固工具抹掉属性名的情况，用资源 ID 兜底映射
- 包名、版本、`versionCode`、`minSdk` / `targetSdk`
- 权限清单，按高/中/低分级并附中文含义
- 第三方 SDK：扫 dex 字符串 + zip 条目名 + native 库名
- 加固识别：梆梆 / 爱加密 / 360 / 腾讯乐固 / 阿里聚安全 / 娜迦 / 顶象 / 网易易盾
- 对外暴露面：URL Scheme、exported 组件（含"未声明 exported 但有 intent-filter 即默认暴露"的 API < 31 规则）

### IPA

- `Info.plist`：Bundle ID、版本、`MinimumOSVersion`、`UIBackgroundModes`
- iOS 侧"权限" = `*UsageDescription` 键，按敏感度分级（含 ATT 追踪授权、本地网络）
- `CFBundleURLTypes` 提取 URL Scheme
- `Frameworks/` 内嵌框架名作为 SDK 证据，并扫描框架二进制
- 主二进制 Mach-O 解析判定 App Store 加密状态（thin / fat 双支持，读 `LC_ENCRYPTION_INFO` / `_64` 的 `cryptid`）

### 规则库（`rules/`，可自行扩充）

- `sdk_rules.json`：约 39 条 SDK 特征 + 8 条加固特征；patterns 同时覆盖点号（`com.umeng`）、斜杠（`com/umeng`，dex 类名形式）、iOS 二进制类名（`UMeng`）三种写法
- `permissions.json`：Android 约 35 条权限 + iOS 21 条 `UsageDescription` 分级

---

## 为什么不用 androguard

| 理由 | 说明 |
| --- | --- |
| **零依赖** | 拿到目录 `python3 scanner.py xxx.apk` 就能跑，不用 pip 装几十 MB 依赖，也不用担心版本冲突 |
| **能力可见** | APK 的 `AndroidManifest.xml` 编译后是二进制 AXML（`ResChunk` 结构），不是文本 XML。本项目按 AOSP `ResourceTypes.h` 规范自己实现了 parser，而不是包一层别人的库 |
| **可解释** | 报告里每条命中都带证据，不是黑盒输出一个 JSON |

---

## 工作流程

```
输入 .apk / .ipa / 目录
    │
    ├─ scanner.py       看后缀分派，收集文件清单
    │
    ├─ APK 链路         当 zip 打开 → 解析二进制 AXML → 分组权限 → 扫 dex 特征 → 判加固
    │
    └─ IPA 链路         当 zip 打开 → 找 Payload/xxx.app → 读 Info.plist
                        → 扫框架与二进制 → 解析 Mach-O 判加密
    │
    └─ report.py        生成七章 Markdown + 拉平 CSV
```

静态扫描只回答"**声明了什么**"，不回答"**实际有没有调用**"——后者需要动态 hook，见下方局限。

---

## 目录结构

```
.
├── scanner.py              # CLI 入口：多文件/目录、报告落盘、单文件失败不中断
├── report.py               # CSV 明细 + Markdown 七章报告
├── parsers/
│   ├── axml.py             # 二进制 AXML 解析（核心）
│   ├── apk_parser.py       # APK：Manifest + dex 特征 + 加固
│   └── ipa_parser.py       # IPA：plist + Framework + Mach-O 加密判定
├── rules/
│   ├── sdk_rules.json      # SDK / 加固特征库
│   └── permissions.json    # 权限与 UsageDescription 分级
├── tests/
│   ├── make_fixtures.py    # 按 ResChunk 规范合成 AXML，造最小 APK / IPA
│   └── samples/            # 合成样本（无真实 App，可安全分发）
└── docs/
    └── 代码详解.md          # 逐文件逐逻辑讲解，面向不熟悉二进制格式的读者
```

`tests/samples/` 里的 APK / IPA 是**用代码合成出来的**，不含任何真实应用代码，因此可以放心提交到公开仓库。

---

## 已知局限

1. **静态 ≠ 实际行为**。清单里声明了权限，不代表运行时真调用了；反过来，通过反射 / native 层调用也可能不体现在清单里。要证明"隐私弹窗弹出前就采集了设备信息"，只能动态 hook。
2. **加固会削弱特征命中**。壳会把 dex 加密，字符串搜不到；必须先脱壳（Frida dump / 内存 dump）再扫。工具能识别壳类型，报告里会明确提示。
3. **特征匹配有误报**。命中字符串可能只是"引用了但没集成"，或类名巧合。报告把 SDK 命中和"是否实际采集"分开陈述，不直接下结论。
4. **未覆盖动态加载**。插件化 / 热修复框架在运行时才下载的 dex 不在静态扫描范围内。
5. **iOS 侧看不到组件导出关系**。iOS 没有 Android 那套 exported 组件机制，`exported_components` 恒为空是设计使然，不是漏检。

---

## 合规与免责声明

**本工具仅用于安全研究与合规自查。** 使用前请确认：

- 只分析**自己设备上已安装的公开 App**，或自己拥有 / 已获得书面授权的目标
- 不破解他人付费服务、不绕过风控获取数据、不分析金融 / 政务等敏感行业应用
- 产出定位为"安全评估报告"，不公开披露未修复漏洞细节
- 报告结论只陈述"声明了什么"，不臆断"违规"

作者不对因使用本工具产生的任何法律责任负责。**请勿将扫描结果用于敲诈、勒索、恶意曝光或商业竞争。**

---

## 文档

- [`docs/代码详解.md`](docs/代码详解.md) —— 12 章，从整体流程到逐文件拆解：AXML 逐段拆解、exported 三态、Mach-O 与 cryptid、七章报告的设计意图，以及第十一章「一条命令的完整旅程」——把 `scanner.py` → `ipa_parser.py` → `report.py` 的函数级调用顺序和落盘过程完整走一遍

---

## License

[MIT](LICENSE)
