# 架构说明

JS Cairn Static 当前只保留 one-shot 主链，定位是：

```text
一次输入目标 → 一次收集资源 → 一次提取 API/参数 → 一次导出 Burp 与 LLM 输入
```

主流程：

```text
Target URL / Local Files
→ Collector
→ StaticAnalyzer
→ AST Visitor / Wrapper / Dataflow
→ Risk Tagging
→ api_assets.json
→ Playwright Runtime Capture（可选）
→ Static + Runtime Merge
→ bp_seed_requests.http
→ llm_api_test_input.json
```

## 主模块

| 模块 | 职责 |
|---|---|
| `collector.py` | 收集 HTML / JS / chunk / sourcemap |
| `analyzer.py` | 编排静态分析主流程 |
| `ast_visitor.py` | AST call / object / literal 语义提取 |
| `extractors.py` | 提取 fetch / axios / XHR / wrapper API |
| `dataflow.py` | 轻量参数来源与可控性分析 |
| `risk.py` | 风险标签与优先级打分 |
| `runtime_capture.py` | Playwright network + hook 采集 |
| `bp_templates.py` | 导出 Burp / raw HTTP 请求模板 |
| `llm_input.py` | 融合静态与运行时结果，生成大模型小包 |
| `cli.py` | `oneshot` 与辅助命令入口 |

## 输出

```text
artifacts/api_assets.json
artifacts/bp/bp_seed_requests.json
artifacts/bp/bp_seed_requests.http
artifacts/llm_input/api_inventory.json
artifacts/llm_input/llm_api_test_input.json
runtime/network_capture.json
runtime/hook_events.json
```

## 设计原则

```text
1. 本地尽可能多提 API 与参数。
2. Playwright 补静态层拿不到的真实请求。
3. 只把压缩后的小包交给大模型。
4. 默认不执行危险写操作。
5. 不维护长期资产库，不引入 project / SQLite 维度。
```
