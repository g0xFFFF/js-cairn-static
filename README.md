# JS Cairn Static

> 面向安全测试的 JS/API 攻击面提取工具。  
> 用 AST 静态分析和 Playwright 运行时采集，从前端资源中提取 API、参数、请求模板，并导出给 Burp 和大模型使用的结构化数据。

---

## 这个项目解决什么问题

做前端接口审计时，很多人会把整站打包后的 JavaScript 直接丢给大模型，让它找 API、猜参数、生成测试思路。

这条路能用，但成本很高：

```text
1. JS chunk 多，上下文消耗大。
2. 前端代码里有大量 UI、状态管理和第三方库噪声。
3. 大模型容易找到 URL，却还原不出完整参数。
4. 没有运行时证据时，请求模板经常不可直接使用。
```

`JS Cairn Static` 的思路是：

```text
先在本地提取 API 和参数 → 再把压缩后的结构化结果交给 Burp 或大模型。
```

这样可以减少 token 消耗，也能让后续安全测试更聚焦。

---

## 核心能力

```text
HTML / JS / chunk
→ AST / wrapper / dataflow 分析
→ API + method + query/body/header 参数
→ Playwright runtime capture
→ 静态结果与运行时请求合并
→ Burp 请求模板
→ LLM API 测试输入小包
```

当前重点能力：

- 提取 `fetch` / `axios` / `XHR` 请求
- 识别部分 wrapper 封装请求
- 提取 URL、method、query、body、header 参数线索
- 使用 Playwright 捕获运行时真实请求
- 回填运行时 query / body / header 真值
- 导出 Burp HTTP 请求模板
- 导出适合大模型做自动化测试规划的精简 JSON

---

## 安装

要求：Python 3.11+

### 1. 克隆项目

```bash
git clone https://github.com/<your-name>/js-cairn-static.git
cd js-cairn-static
```

### 2. 创建虚拟环境

Windows PowerShell：

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS / Linux：

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. 安装依赖

普通使用：

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
python -m playwright install chromium
```

开发 / 跑测试：

```bash
python -m pip install -r requirements-dev.txt
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

---

## 快速开始

扫描一个 URL：

```bash
python -m js_cairn_static.cli "https://example.com/app"
```

扫描本地目录：

```bash
python -m js_cairn_static.cli examples
```

默认输出目录：

```text
out/oneshot/
```

默认行为：

```text
URL 目标：静态分析 + 自动尝试 Playwright 运行时采集
本地文件/目录：只做静态分析，并使用 http://example.local 生成请求模板
```

---

## 登录态采集

如果目标需要登录，先保存 Playwright storage_state：

```bash
python -m js_cairn_static.cli login-state "https://example.com/login" --out out/auth/storage_state.json
```

浏览器打开后手动完成登录，回到终端确认保存。

之后带登录态运行：

```bash
python -m js_cairn_static.cli "https://example.com/app" --storage-state out/auth/storage_state.json
```

---

## 输出文件

一次 one-shot 运行后，输出结构如下：

```text
out/oneshot/
├── artifacts/
│   ├── api_assets.json
│   ├── bp/
│   │   ├── bp_seed_requests.json
│   │   └── bp_seed_requests.http
│   └── llm_input/
│       ├── api_inventory.json
│       └── llm_api_test_input.json
└── runtime/
    ├── network_capture.json
    └── hook_events.json
```

文件说明：

| 文件 | 作用 |
|---|---|
| `api_assets.json` | 静态分析提取出的 API 资产 |
| `bp_seed_requests.json` | 结构化 Burp 请求种子 |
| `bp_seed_requests.http` | 可贴进 Burp Repeater / 编辑器的 HTTP 模板 |
| `api_inventory.json` | 静态 + 运行时融合后的 API 总表 |
| `llm_api_test_input.json` | 给大模型做 API 测试规划的小包 |
| `network_capture.json` | Playwright 捕获的真实网络请求 |
| `hook_events.json` | Runtime hook 事件 |

---

## 给 Burp 用

导出的 HTTP 模板在：

```text
out/oneshot/artifacts/bp/bp_seed_requests.http
```

可以复制到 Burp Repeater、HTTP Client 或其他发包工具中继续验证。

---

## 给大模型用

不要把整站 JS 直接喂给大模型，优先使用：

```text
out/oneshot/artifacts/llm_input/llm_api_test_input.json
```

它保留的是安全测试更需要的上下文：

```text
endpoint
method
query/body/header params
runtime_seen
sample_request
raw_http template
missing_data
```

配套 Prompt：

```text
docs/third_party_ai_autopentest_prompt.txt
```

---

## 常用命令

### one-shot 主流程

```bash
python -m js_cairn_static.cli "<目标URL或本地路径>"
```

常用参数：

```text
--out-dir            输出目录，默认 out/oneshot
--no-runtime         URL 目标跳过 Playwright 运行时采集
--storage-state      Playwright storage_state 文件
--base-url           扫描本地文件/目录时使用的 base URL
--show-browser       显示浏览器窗口
--browser-timeout    浏览器超时时间，默认 30000 ms
--runtime-wait       页面加载后额外等待时间，默认 3000 ms
--strict-ssl         远程资源采集时强制校验证书
--max-remote-assets  最多下载多少远程 JS/CSS/HTML 资源，默认 48
--limit              限制最终导出的 API 数量
--quiet              减少控制台输出
```

### 只做静态扫描

```bash
python -m js_cairn_static.cli scan "https://example.com/app" --out out/api_assets.json --summary
```

### 只做运行时采集

```bash
python -m js_cairn_static.cli capture "https://example.com/app" --out-dir out/runtime --storage-state out/auth/storage_state.json --show-browser
```

### 从已有资产导出 Burp 模板

```bash
python -m js_cairn_static.cli export-bp --workspace out/oneshot --limit 50
```

### 从已有资产和运行时结果导出 LLM 输入

```bash
python -m js_cairn_static.cli export-llm-input --workspace out/oneshot --runtime-dir out/oneshot/runtime --limit 50
```

---

## 项目结构

```text
src/js_cairn_static/
├── collector.py        HTML / JS / chunk 收集
├── analyzer.py         静态分析主流程
├── ast_visitor.py      AST Visitor 语义提取
├── extractors.py       fetch / axios / XHR / wrapper 提取
├── dataflow.py         轻量参数来源分析
├── runtime_capture.py  Playwright 网络采集和 runtime hook
├── bp_templates.py     Burp / HTTP 请求模板导出
├── llm_input.py        静态 + 运行时融合，生成 LLM 输入
└── cli.py              命令行入口
```

---

## 安全边界

默认工作流是：

```text
collect → extract → merge → export
```

工具默认不自动执行以下高风险动作：

```text
删除
支付
审批
重置密码
大规模未授权重放
```

接口资产提取和漏洞验证是两个阶段。这个项目主要解决第一阶段：尽可能把 API、参数和运行时请求整理成可继续测试的数据。

---

## 测试

```bash
python -m pytest -q
```

当前测试覆盖：

```text
AST 提取
请求模板生成
运行时结果合并
LLM 输入导出
CLI 参数解析
采集器行为
```

---

## 适合谁

这个项目适合：

- 前端 JS 审计
- API 安全测试
- Burp 前置资产整理
- 自动化渗透测试工程化
- 想把大模型接入安全测试，但不想直接喂整站 JS 的人

---
如果对你有帮助的话，就关注我的公众号吧

<img width="430" height="430" alt="2af29784e597e0181c725997e6a9d3ee" src="https://github.com/user-attachments/assets/aec13022-b3af-46fb-b86c-3721278d7c13" />


## License

MIT
