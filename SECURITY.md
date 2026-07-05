# Security Policy

## Scope

JS Cairn Static 是面向授权安全测试、代码审计和安全工程化研究的工具。

推荐用途：

```text
自有项目
授权测试项目
CTF / 靶场
安全研究环境
```

## Sensitive Data

请不要在 issue、PR 或讨论中提交：

```text
真实 token
真实 cookie
真实密钥
真实客户数据
未公开漏洞细节
未脱敏扫描报告
```

如需提交复现，请使用 `examples/` 下的最小样例或自行构造脱敏代码。

## Reporting Security Issues

如果你发现本项目自身存在安全问题，请优先私下联系维护者，避免公开披露可直接利用细节。

报告建议包含：

```text
影响版本
问题描述
最小复现
影响范围
建议修复方向
```

## Execution Boundary

当前 `pipeline` 命令默认生成：

```text
API assets
Evidence Packets
Validation Plans
Findings Markdown
Runtime Hook script
```

它不会自动执行删除、支付、审批、重置密码等危险动作。
真实 Replay 应接入授权环境、Policy Gate、限速和审计日志。
