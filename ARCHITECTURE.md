# CTF 解题 Agent 软件工程设计（V0）

## 目标与边界

系统用于授权 CTF 题目、公开 benchmark 和赛事平台适配。它接收题面与附件，在隔离环境中进行分析、生成候选答案、按平台协议提交，并保存可复现的运行证据。平台连接通过显式 `BaseURL` 配置完成；平台访问、模型调用和题目执行都必须可替换、可测试。

第一阶段只实现一个可靠的“单题闭环 + 多题调度”基础，不把榜单分数或某个模型绑定为架构前提。攻防题的工具调用必须始终运行在题目专属容器中；平台客户端只由编排层接触。

## 架构决策

### 1. 以现有 `Agent/langgraph` 作为运行时骨架

保留它已有的分类器、题型专家、交互式工具和 Docker 生命周期管理。LangGraph 负责有边界的工作流，不负责平台协议或凭据。

### 2. 移植 `midnights` 的协议边界

将 `ChallengeProvider`、`FlagSubmitter`、尝试状态、截止时间和错误分类抽象成平台无关接口。NSSCTF、湾区杯、CTFd、Cybench 和本地 fixture 各自实现 adapter，不把平台字段散落在 solver 中。

### 3. 采用 `baidu-agent` 的可观测性，但统一事件模型

CSV 面板保留为导出格式，内部先定义不可变事件：`run_started`、`challenge_loaded`、`tool_called`、`model_called`、`candidate_found`、`submission_result`、`checkpoint_saved`、`run_finished`。事件中不得写入 API token、Cookie 或完整敏感环境变量。

### 4. 状态分成三层

```text
RunState       一次比赛/benchmark 运行的全局状态
ChallengeState 一道题的状态、候选答案、工具会话和截止时间
Evidence       原始输出、摘要、附件哈希、模型与配置版本
```

LangGraph checkpoint 保存当前题的可恢复状态；SQLite 保存本地单机运行；需要多进程或多机时再换 PostgreSQL。跨题共享的知识只允许写入结构化、带来源和版本的 `KnowledgeStore`，不能把整段聊天记录无限累积到 prompt。

## 目标运行流程

```text
RunController
  -> PlatformAdapter.list_or_fetch
  -> ChallengeRegistry（轮次/版本/附件哈希）
  -> Scheduler（并发、截止时间、取消）
  -> Classifier
  -> SpecialistGraph（web/pwn/reverse/crypto/forensics/misc）
  -> LocalVerifier（格式与证据）
  -> PlatformAdapter.submit
  -> Writeup/Evidence Export
```

每道题使用独立容器、独立工作目录和独立状态命名空间。提交只允许经过一个幂等的 `SubmissionGate`，重复提交、格式不符和已拒绝候选必须在本地拦截。结束时先停止调度，再等待在途调用收敛，最后导出证据和 WriteUp 草稿。

## 模块边界

| 模块 | 责任 | 禁止依赖 |
|---|---|---|
| `platforms/` | BaseURL、登录、取题、提交、平台错误映射 | solver、Docker |
| `orchestrator/` | 调度、时钟、取消、恢复、提交门 | 具体模型 prompt |
| `graph/` | 分类、专家路由、有限重试、状态转移 | 平台私有字段 |
| `env/` | 容器、文件、交互会话、资源限制 | 平台 token |
| `models/` | 统一模型接口、超时、token/cost 统计 | 提交 API |
| `evidence/` | 事件、原始输出、哈希、WriteUp 导出 | 改写原始日志 |
| `benchmarks/` | 本地 fixture、指标、回放和对比 | 真实赛事凭据 |

## 首批接口

```python
class ChallengeProvider(Protocol):
    async def list_challenges(self, run: RunSpec) -> list[Challenge]: ...

class FlagSubmitter(Protocol):
    async def submit(self, challenge_id: str, candidate: str) -> SubmitResult: ...

class ExecutionBackend(Protocol):
    async def start(self, spec: SandboxSpec) -> SandboxHandle: ...
    async def exec(self, handle: SandboxHandle, request: ExecRequest) -> ExecResult: ...
    async def stop(self, handle: SandboxHandle) -> None: ...
```

`Challenge` 必须包含 `id`、`round_id`、题型提示、题面、附件哈希和远端目标（若有）；`SubmitResult` 必须包含 accepted、平台消息、服务器时间和幂等键。所有时间使用 UTC 时间戳，展示层再转换时区。

## 参考项目的取舍

| 项目 | 采用 | 不直接采用 |
|---|---|---|
| LangGraph | 图状态、节点、checkpoint 接口 | 默认无持久化的 `compile()` 作为生产配置 |
| `midnights` | 平台无关协议、凭据隔离、离线契约测试 | 其特定 arena 的计分与时限规则 |
| `baidu-agent` | 面板、成本和运行指标 | “永不放弃”作为统一策略 |
| D-CIPHER | Planner/Executor 的实验分层 | 未验证的 benchmark 成绩作为质量保证 |
| EnIGMA/SWE-agent | 有状态交互会话与输出摘要 | 将软件开发工具接口直接当成赛事接口 |
| BoxPwnr | benchmark adapter、trace/replay 思路 | 将公开 trace 的累计统计当作可复现结果 |
| OpenSage、Veria | 作为架构对照和后续实验 | 在 V0 直接引入动态拓扑、多模型 racing |

## V0 必须补齐的缺口

1. 为主图配置持久化 checkpoint；至少提供 SQLite 实现，并测试进程重启后的恢复。
2. 将平台 adapter、submit gate 和轮次/版本 registry 接入现有 `Scheduler`。
3. 为容器加入进程异常后的孤儿发现与清理；固定镜像摘要、CPU/内存/PID/网络策略。
4. 把所有模型调用、工具调用和提交结果写入统一事件流，并支持 JSONL 重放。
5. 建立本地 benchmark：固定题面、附件哈希、模拟提交端点、超时、拒绝、重启和重复提交场景。
6. 对每个题型专家设置有限步数、最大输出、单题预算和明确的失败状态；取消“无限重试”。

## V1 再考虑的能力

V0 的离线指标稳定后，再评估题型专家间的结构化协作、并行候选、上下文压缩和模型路由。每项能力都必须以固定 benchmark 的成功率、耗时、成本、错误提交数和恢复率做 A/B 对比；没有指标收益就不合入主线。

## 验收指标

- 相同 fixture 和配置可重复运行，附件与配置哈希一致。
- 模拟平台拒绝、网络中断、模型超时、进程重启后，任务能恢复或明确失败，不重复提交。
- 任意一次提交都能追溯到题目版本、候选来源、工具输出和模型调用事件。
- 真实平台 adapter 在没有凭据时只能运行 dry-run；所有单元测试和 benchmark 测试不触碰真实赛事。

