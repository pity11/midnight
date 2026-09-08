# Midnight

“午夜拾光”战队的授权 CTF 与 benchmark 自主解题 Agent。基于
**LangGraph**，采用路由、分类专家、隔离执行和可追溯事件日志。

完整设计见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 特性

- 覆盖 pwn / reverse / web / crypto / misc 等题型，每题型有专属专家子图。
- 每道题在**独立 Docker 容器**中执行；pwn/reverse 用 `linux/amd64`（Apple Silicon 经 Rosetta）。
- 支持**并发**解多题（asyncio + 每题独立容器/图实例）。
- **交互式工具 (IAT)**：gdb / nc / pwntools 包装成非阻塞会话工具。
- **跨专家求助**：`ask_expert` 工具让专家在同一容器内借调其他题型能力。
- 取题 / 提交 flag 两端为**预留接口**（Protocol），可后续用 skill/MCP 针对各赛事实现。
- **运行事件日志**：采用 JSONL 追加写记录关键状态，默认过滤凭据字段。

## 落地前置

1. 安装 **Docker Desktop**，并开启 *Use Rosetta for x86/amd64 emulation*（pwn/reverse 必需）。
2. 安装 **uv**：`curl -LsSf https://astral.sh/uv/install.sh | sh`。
3. 准备模型凭据：复制 `.env.example` 为 `.env` 并填入 `ANTHROPIC_API_KEY`（或在 `config/models.yaml` 切到本地 Ollama）。

## 快速开始

```bash
uv sync                       # 安装依赖
cp .env.example .env          # 填模型 key
uv run midnight --help       # 查看入口
```

## 目录结构

```
config/        模型 / 镜像 / 工具 / 运行配置（YAML）
docker/        各题型镜像 Dockerfile
src/midnight/ 核心代码（graph / tools / env / models / interfaces / orchestrator）
tests/         单测 + 离线 mock 题目 fixtures
```

## 实施进度

- [x] M0 脚手架
- [x] M1 单题闭环（远程 x86 开发机已端到端跑通）
- [x] M2 题型专家（路由+classify + checksec/rop_gadget/r2_interact/ghidra/http_request）
- [x] M3 交互式工具 (IAT)（gdb / nc / r2 的 pexpect 非阻塞会话）
- [x] M3.5 跨专家求助（ask_expert 同容器内联委派）
- [x] M4 并发（每题独立容器并发，已验证 3 题/3 类型）
- [x] 重试/回退（verify 无 flag 或 submit 被拒 → 带反馈重跑同专家，上限 max_attempts；拒绝的 flag 拉黑）
- [ ] M5 接口完善（接真实赛事 Provider/Submitter）

镜像就绪：`midnight/{misc,pwn,re}:latest`（x86 原生）。radare2 在 re 镜像中为可选（默认未装，r2_interact 缺失时优雅降级，提示用 objdump/gdb）。

## 远程开发

本项目在远程 x86_64 开发机上开发/运行（本地不跑 x86、不装 Docker）：

```bash
# 同步代码到远程
rsync -az -e "ssh -p 36000" --exclude '.venv' --exclude '__pycache__' \
  ./ root@<host>:/root/midnight/

# 远程：建 venv（python3.12）+ 安装
ssh -p 36000 root@<host> 'cd /root/midnight && python3.12 -m venv .venv \
  && .venv/bin/pip install -e ".[dev]" langchain-anthropic'

# 用 stub 模型跑闭环（无需 LLM / token）
MIDNIGHT_MODELS_FILE=models.stub.yaml .venv/bin/python -m midnight.app \
  --challenges-dir tests/fixtures
```

环境变量：`MIDNIGHT_MODELS_FILE`（切模型配置）、`MIDNIGHT_MAX_CONCURRENCY`（并发数）。

## 开发边界

默认只运行本地 fixture。真实平台接入必须实现独立 adapter，并由显式配置
开启提交；测试不读取真实平台凭据，也不访问真实赛事接口。
