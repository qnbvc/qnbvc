# 网站安全智能巡检智能体（安恒信息 企业赛题）

面向「网站安全风险评估 + 敏感信息防泄露」的可部署智能体原型。当前仓库包含**方案设计层**交付物（赛题拆解、功能清单、框架设计、工具清单、架构图），以及 `framework/` 下的可运行代码骨架。

本项目位于 GitHub 仓库 [qnbvc/qnbvc](https://github.com/qnbvc/qnbvc) 的 `website-security-lab/` 子目录。

## 目录

| 文件 | 内容 |
| --- | --- |
| [docs/00-简化版框架.md](docs/00-简化版框架.md) | **推荐先看这个**：4 板块 + 10 节点主流程 + 3 条子流程的精简框架（对比赛原型够用） |
| [docs/assets/simple_framework.svg](docs/assets/simple_framework.svg) | 简化版一页架构图 |
| [docs/assets/flow_relation.svg](docs/assets/flow_relation.svg) | 主流程与子流程的关系图（粗粒度 vs 细粒度、谁调谁、入出契约） |
| [docs/07-搭建实操手册.md](docs/07-搭建实操手册.md) | **照着搭**：创建智能体的名称/介绍/开场白（可直接复制）、10 节点配置表、提示词、联调顺序 |
| [docs/assets/agent_avatar.png](docs/assets/agent_avatar.png) | 智能体头像（512×512，可直接上传） |

以下为详细设计（作为附录，用不到可以只看 00）：

| 文件 | 内容 |
| --- | --- |
| [docs/01-赛题解析与功能清单.md](docs/01-赛题解析与功能清单.md) | 命题意图、需求逐句拆解、评分指标映射、**功能清单（P0/P1/P2）**、演示与验收要点 |
| [docs/02-智能体框架设计.md](docs/02-智能体框架设计.md) | 分层板块架构、多智能体角色、核心机制、统一数据模型、端到端时序、恒脑平台适配 |
| [docs/03-开源工具清单与合规基线.md](docs/03-开源工具清单与合规基线.md) | 工具矩阵、非破坏性档位、授权范围配置样例、危险操作禁用清单 |
| [docs/04-恒脑平台节点编排设计.md](docs/04-恒脑平台节点编排设计.md) | **按恒脑节点（模型/工具/智能体/交互/代码/自规划 + 开始结束）编排的框架**，含"功能 → 节点组成"对照表 |
| [docs/05-子流程一-授权与配置-完整流程.md](docs/05-子流程一-授权与配置-完整流程.md) | 子流程① 展开为 13 个节点的完整流程：逐节点设计、数据契约、异常回退表、验收用例 |
| [docs/06-节点连线与数据流规范.md](docs/06-节点连线与数据流规范.md) | **节点之间怎么连**：边表（源出→目标入）、8 种边类型、变量规范、fork/join、环与重试 |
| [docs/assets/architecture.svg](docs/assets/architecture.svg) | 智能体总体架构图（板块式） |
| [docs/assets/node_flow.svg](docs/assets/node_flow.svg) | 节点编排图（主流程 14 节点 + 8 条子流程） |
| [docs/assets/subflow1.svg](docs/assets/subflow1.svg) | 子流程① 完整流程图（13 节点 + 异常回退 + 数据契约） |
| [docs/assets/wiring.svg](docs/assets/wiring.svg) | 节点连线图（主流程边标签 + 条件/异常/闭环边 + fork·join） |
| [framework/](framework/) | 骨架代码：范围校验与限速、工具插件注册、Finding 统一模型、编排流水线 |
| [range/](range/) | **可运行靶场**：本地一键启动、干净/篡改双态、弱配置与敏感信息场景、队友远程访问说明 |
| [deploy.ps1](deploy.ps1) / [deploy.sh](deploy.sh) | 一键检查环境、运行测试并启动靶场 |
| [docs/12-GitHub发布与队友部署.md](docs/12-GitHub发布与队友部署.md) | GitHub 克隆、部署、远程访问、更新与排障 |

## 可运行骨架（已实测跑通）

```powershell
cd framework
python -m wn_agent.cli --demo          # 两轮：建基线 → 站点被篡改后复测
python -m unittest discover -s tests   # 30 条回归测试
```

## 可运行靶场

```powershell
cd D:\Network_Security\website-security-lab
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\range\start.ps1

# 另一个窗口：基线 → 篡改 → 复测
python range\demo.py
```

靶场入口为 `http://127.0.0.1:8080/`，完整场景、远程访问和验收说明见 [range/README.md](range/README.md) 与 [range/authorization.range.json](range/authorization.range.json)。

## 从 GitHub 克隆并启用

```powershell
git clone https://github.com/qnbvc/qnbvc.git
cd qnbvc\website-security-lab
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\deploy.ps1
```

Linux / macOS：

```bash
git clone https://github.com/qnbvc/qnbvc.git
cd qnbvc/website-security-lab
LAB_CONTROL_TOKEN=team-lab-2026 ./deploy.sh
```

`deploy` 脚本会自动检查 Python 3.10+、运行 37 条回归测试并启动靶场。队友浏览器访问 `http://127.0.0.1:8080/`；远程访问见 [部署文档](docs/12-GitHub发布与队友部署.md)。

## 离线骨架实测结果

第一轮原始命中 25 → 去重后 17 条；第二轮（页面被注入隐藏 iframe、恶意外链与混淆脚本）
原始命中 31 → 去重后 23 条，其中新增 6 条（篡改 1、未授权外链 2、挂马特征 3），
并输出"新增 / 复现 / 已消失"的基线对比。同时演示了授权闸门对**范围外域名、未授权档位、排除路径**的拦截留痕。

示例报告：[framework/out/report-pass2.md](framework/out/report-pass2.md)；审计日志：[framework/out/audit.jsonl](framework/out/audit.jsonl)。

## 一句话定位

在**授权范围内**，把「人工网站巡检」改造成**周期性、可解释、可复测、可告警、可导出**的自动化闭环：

```
授权配置 → 资产/页面发现 → 智能规划与工具编排 → 三类检测
        → 去重/验证/分级 → 证据+影响+修复建议 → 告警 → 基线对比 → 复测 → 报告
```

## 与评分指标的对应

| 指标 | 权重 | 承载模块 |
| --- | --- | --- |
| 功能完整性 | 25% | 资产发现、周期巡检、风险检测、敏感信息自定义、告警与报告闭环 |
| 检测效果 | 30% | 检测引擎 + 去重/验证/降误报（召回率、准确率、误报率） |
| 智能体能力 | 20% | 规划器、工具路由、结果关联去重、证据解释、修复建议 |
| 安全合规 | 10% | 授权边界、限速、最小权限、日志审计、非破坏性 |
| 工程化与创新 | 15% | 部署易用性、稳定性、扩展性、可视化、创新点 |

> 备注：`docs/` 中关于「恒脑安全智能体平台」的接口与运行方式属于设计建议，具体 SDK 与编排规范需以平台官方文档为准。
