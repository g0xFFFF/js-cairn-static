# JS Cairn Static

> 面向安全测试的 JS/API 攻击面提取工具：AST 静态分析 + Playwright 运行时采集 + Burp/LLM 输入导出。

`JS Cairn Static` 解决的是一个很具体的问题：

```text
不要把整站打包后的 JavaScript 直接丢给大模型。
先在本地提取 API、参数和运行时证据，再把压缩后的结构化结果交给 Burp 或大模型。
```

## 它能做什么

```text
HTML / JS / chunk
→ AST / wrapper / 轻量 dataflow 分析
→ API + method + params
→ 可选 Playwright runtime capture
→ 静态结果与运行时结果合并
→ Burp 请求种子
→ LLM API 测试输入小包
```

核心目标：

```text
1. 尽可能发现更多前端 API。
2. 尽可能恢复 query/body/header 参数名。
3. 用 Playwright 回填运行时真实请求证据。
4. 导出适合 Burp 和大模型继续处理的小文件。
```

## 安装

```bash
python -m pip install -e .[dev]
python -m playwright install chromium
```

要求：Python 3.11+

## 快速开始

对 URL 运行 one-shot 主流程：

```bash
python -m js_cairn_static.cli "https://example.com/app"
```

对本地样例运行：

```bash
python -m js_cairn_static.cli examples
```

默认行为：

```text
URL 目标：静态分析 + 自动尝试 Playwright 运行时采集
本地文件/目录：静态分析 + 使用 http://example.local 作为请求模板 base URL
默认输出目录：out/oneshot/
```

## 登录态

如果目标需要登录，先保存 Playwright storage_state：

```bash
python -m js_cairn_static.cli login-state "https://example.com/login" --out out/auth/storage_state.json
```

再带登录态运行：

```bash
python -m js_cairn_static.cli "https://example.com/app" --storage-state out/auth/storage_state.json
```

## 输出文件

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

```text
api_assets.json              静态分析提取出的 API 资产
bp_seed_requests.json        结构化 Burp 请求种子
bp_seed_requests.http        可贴进 Burp Repeater / 编辑器的 HTTP 模板
api_inventory.json           静态 + 运行时融合后的 API 总表
llm_api_test_input.json      给大模型做 API 测试规划的小包
network_capture.json         Playwright 捕获的网络请求
hook_events.json             Runtime hook 事件
```

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

## 给大模型喂什么

不要喂整站 JS，优先喂这个文件：

```text
out/oneshot/artifacts/llm_input/llm_api_test_input.json
```

它保留的是后续安全测试更需要的上下文：

```text
endpoint
method
query/body/header params
runtime_seen
sample_request
raw_http template
missing_data
```

配套的第三方 AI 自动化渗透测试 Prompt：

```text
docs/third_party_ai_autopentest_prompt.txt
```

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

## 安全边界

默认工作流是：

```text
collect → extract → merge → export
```

默认不自动执行删除、支付、审批、重置密码、大规模未授权重放等高风险业务动作。

## 测试

```bash
python -m pytest -q
```
