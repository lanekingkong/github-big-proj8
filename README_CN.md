# CodeGuardian — AI 代码信任验证平台

> **守护你的代码，信任你的 AI。**

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 项目概述

**CodeGuardian** 是一个开源的全栈 **AI 代码信任验证平台**，解决 2026 年开发者面临的核心痛点：**96% 的开发者不信任 AI 生成的代码，但 42% 的代码已是 AI 写的，无人敢签字上线**。

CodeGuardian 通过多模型共识审查、量化信任评分、安全漏洞扫描、幻觉检测和上下文一致性分析，在 AI 生成代码与生产可信度之间架起桥梁——全部集成到无缝的 CLI 和 CI/CD 管道中。

### 解决的核心痛点

| 痛点 | 解决方案 |
|---|---|
| **信任危机** — AI 代码质量参差不齐，无人愿承担上线风险 | 多模型共识审查 + 量化信任评分（0–100） |
| **上下文负债** — AI 不了解业务历史和架构知识 | 上下文一致性引擎验证代码与项目上下文的一致性 |
| **幻觉问题** — AI 生成看似合理但实际错误的代码 | 幻觉检测引擎标记可疑模式 |
| **审查瓶颈** — 人工审查速度跟不上 AI 生成速度 | 自动化 SAST + 基于规则 + 启发式多模型编排 |
| **责任归属** — 谁为 AI 代码质量负责？ | 可审计的信任报告，含模型溯源和共识级别 |

---

## 项目愿景

成为 AI 编程时代的 **"代码质量签名系统"**——让开发者能够**信任、验证、并安全地部署 AI 生成的代码**。

---

## 核心功能

### 1. 多模型共识审查
- 同时咨询多个 AI 模型进行代码审查
- 汇总发现结果并生成统一报告，包含共识评分
- 识别模型之间的一致/分歧点
- **无 API 密钥时自动回退到基于规则的分析**

### 2. AI 代码信任评分（0–100）
- 量化信任指标，含 A–F 字母等级
- 多维度分析：
  - **安全评分** — 漏洞和注入风险评估
  - **正确性评分** — 逻辑缺陷和错误检测
  - **一致性评分** — 上下文对齐验证
  - **幻觉风险** — AI 生成异常检测
  - **依赖风险** — 供应链和版本风险

### 3. 幻觉检测引擎
- 检测重复代码块（复制粘贴式幻觉）
- 标记可能拼写错误或不存在的导入
- 识别不匹配已知库的 AI 生成模式

### 4. 安全漏洞扫描器（SAST）
- 8 种内置漏洞模式，含 CWE 参考
- SQL 注入、XSS、命令注入、硬编码密钥、路径遍历、不安全反序列化等
- 可扩展自定义规则系统
- 多语言支持

### 5. CI/CD 集成
- 支持 GitHub Actions、GitLab CI
- JSON 输出供上游消费
- 整个代码库的批量审查及汇总报告

### 6. CLI 优先设计
- 富文本终端 UI，彩色标注严重级别
- 四个主要命令：`review`、`scan`、`score`、`batch`
- 机器可读 JSON 输出，便于自动化

---

## 安装

### 从 PyPI（推荐）
```bash
pip install codeguardian
```

### 从源码安装
```bash
git clone https://github.com/lanekingkong/CodeGuardian.git
cd CodeGuardian
pip install -e ".[dev]"
```

---

## 快速开始

### 审查单个文件
```bash
codeguardian review src/app.py
```

### 扫描目录的安全漏洞
```bash
codeguardian scan ./my-project --recursive
```

### 快速信任评分（轻量模式）
```bash
codeguardian score src/main.go --json
```

### 批量审查所有代码文件
```bash
codeguardian batch ./src --output report.json
```

---

## 命令参考

| 命令 | 描述 | 关键选项 |
|---|---|---|
| `review <文件>` | 完整多模型审查 + 信任报告 | `--context`、`--json` |
| `scan <目录>` | 安全漏洞扫描 | `--recursive`、`--json` |
| `score <文件>` | 快速信任评分计算 | `--json` |
| `batch <目录>` | 批量审查所有代码文件 | `--output`、`--json` |
| `version` | 显示版本信息 | — |

---

## 架构

```
codeguardian/
├── pyproject.toml          # 项目元数据与依赖
├── LICENSE                 # MIT 许可证
├── src/
│   └── codeguardian/
│       ├── __init__.py
│       ├── cli.py                  # Typer CLI 入口
│       └── core/
│           ├── models.py           # Pydantic 领域模型
│           ├── scanner.py          # SAST 漏洞扫描器
│           ├── reviewer.py         # 多模型代码审查引擎
│           └── trust_scorer.py     # 量化信任评分
└── tests/
    └── test_core.py        # 29+ 单元/集成测试
```

---

## 信任评分解读

| 分数区间 | 等级 | 状态 | 行动建议 |
|---|---|---|---|
| 95–100 | A | 优秀 | 生产就绪，风险极低 |
| 85–94 | B | 良好 | 可安全部署，建议小幅改进 |
| 70–84 | C | 一般 | 建议审查后再上生产 |
| 50–69 | D | 需要关注 | 存在多个问题，不建议上生产 |
| < 50 | F | 不安全 | 严重问题 — 请勿部署 |

---

## 漏洞类别

| 类别 | 规则 ID | 严重级别范围 |
|---|---|---|
| **注入** | CG-SQL-001, CG-EVAL-001, CG-PATH-001 | 严重 |
| **敏感数据** | CG-HARD-001, CG-LOG-001 | 严重 / 中等 |
| **XSS** | CG-XSS-001 | 高 |
| **反序列化** | CG-DESER-001 | 严重 |
| **依赖** | CG-DEP-001 | 中等 |

每条发现均包含：
- CWE ID 参考（适用时）
- 代码片段上下文
- 严重级别（严重 / 高 / 中等 / 低 / 信息）
- 可操作的修复建议

---

## 扩展点

### 自定义漏洞规则

```python
from codeguardian.core.scanner import SecurityScanner

custom_patterns = [
    {
        "id": "CUSTOM-001",
        "category": "custom",
        "severity": "high",
        "title": "自定义检查",
        "pattern": re.compile(r"dangerous_call\(\)"),
        "recommendation": "替换为安全替代方案。",
    }
]

scanner = SecurityScanner(custom_patterns=custom_patterns)
vulns = scanner.scan_text(code)
```

### 编程接口

```python
import asyncio
from codeguardian.core.reviewer import CodeReviewer

async def main():
    reviewer = CodeReviewer()
    report = await reviewer.review("src/app.py", context="电商结算服务")
    print(f"信任评分: {report.trust_score.overall}/100 — {report.trust_score.grade}")

asyncio.run(main())
```

---

## 开发

```bash
# 克隆仓库
git clone https://github.com/lanekingkong/CodeGuardian.git
cd CodeGuardian

# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest tests/ -v --cov=codeguardian

# 格式化和 lint
ruff check src/
black src/
```

---

## 路线图

- [ ] LLM API 集成（OpenRouter、Anthropic、OpenAI）
- [ ] Web 仪表盘（React + TailwindCSS）
- [ ] CI/CD 插件生态（GitHub Actions、GitLab CI、Jenkins）
- [ ] 信任评分历史记录数据库后端
- [ ] 多仓库批量分析
- [ ] 高级规则定义的 DSL

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE)。

---

## 作者

**lanekingkong** — [GitHub](https://github.com/lanekingkong)
