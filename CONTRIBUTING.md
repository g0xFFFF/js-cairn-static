# Contributing

感谢关注 JS Cairn Static。

这个项目关注的是：

```text
前端 JS 接口挖掘
API 攻击面恢复
AST / 数据流 / wrapper 反解
LLM Evidence Packet
自动化渗透测试工程化
```

## 本地开发

```bash
python -m pip install -e .
python -m pytest -q
```

运行 demo：

```bash
python -m js_cairn_static.cli pipeline examples --out-dir out/demo --summary
```

## 提交建议

优先提交这些类型：

```text
新的 JS 请求模式识别
wrapper 反解增强
风险标签规则增强
Evidence Packet 字段优化
测试用例
文档和示例
```

提交前请确认：

```bash
python -m pytest -q
```

## 不要提交

```text
真实目标扫描结果
真实 token / cookie / 密钥
未脱敏客户数据
批量攻击脚本
未授权目标 payload
out/ 目录下的本地产物
```

## 设计原则

```text
plan-first，不默认执行危险写操作
证据和结论分离
模型和执行分离
原始数据和公开内容分离
```
