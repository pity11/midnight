# Midnight 线下赛启动指南

本指南用于允许自主 CTF Agent 取题、解题和提交的线下比赛。正式运行前必须完成一次完整预检；比赛现场只使用已经安装、已经构建并已经验证的冻结版本。

Windows 10/11 队员请改用 [Windows PowerShell 部署与启动指南](competition-startup-windows-cn.md)。

## 1. 首次安装（必须在赛前联网完成）

在每台准备使用的电脑上分别执行：

```bash
git clone <repository-url> midnight
cd midnight
uv sync --extra dev
cp .env.example .env
chmod 600 .env
cp config/platform.ichunqiu.example.yaml config/platform.local.yaml
```

然后编辑两个本地文件：

- `.env`：存放模型密钥和队伍 Token；
- `config/platform.local.yaml`：存放主办方接口地址和三个 endpoint。

这两个文件均被 `.gitignore` 排除，**从 GitHub 克隆后不会自动存在或包含现场配置**。平台 YAML 应从主办方接口文档填写，或通过队内私密方式复制已经核验的本地版本，不要提交到 Git。

`.env` 的最小内容为：

```dotenv
MIDNIGHT_LLM_API_KEY=主办方发放的大模型APIKey
MIDNIGHT_LLM_BASE_URL=主办方提供的OpenAI兼容API地址
MIDNIGHT_LLM_MODEL=主办方指定的模型名
MIDNIGHT_PLATFORM_TOKEN=队伍Token
```

`MIDNIGHT_LLM_BASE_URL` 应完整保留主办方要求的路径（通常包含 `/v1`），`MIDNIGHT_LLM_MODEL` 必须使用主办方给出的精确模型标识。队伍 Token 只用于题目查询、环境重置和 Flag 提交；模型 APIKey 只用于模型网关，两者不能互换。现有 `CUC_*` 变量仅作为赛前测试网关的兼容回退；现场填写的 `MIDNIGHT_LLM_*` 优先级更高。

不要通过 Git、聊天记录或公开文件传递 `.env`。同一轮只在比赛指定的单台电脑上运行正式命令，避免多个进程使用相同 Token 重复取题或提交。

## 2. 赛前冻结与离线准备

`scripts/competition` 不会启动 Docker Desktop。可以在 Docker Desktop 设置中启用登录时启动，也可以在准备阶段手工启动；必须等待 `docker info` 成功后再运行 Agent。

启动 Docker Desktop，并在项目根目录执行：

```bash
scripts/competition local-preflight
scripts/competition platform-preflight
```

`local-preflight` 会检查项目配置、真实模型连通性、结构化 JSON、工具动作协议，以及 Pwn、Reverse、Web、Crypto、Forensics、Misc 和兜底沙箱的工具能力。第一次运行可能构建镜像，必须在赛前联网完成。`platform-preflight` 只查询题目，不重置环境、不解题、不提交。

## 3. 现场 30 分钟准备阶段

现场领取模型 APIKey、Base URL、模型名和新队伍 Token 后，打开本地凭据文件：

```bash
nano .env
```

将 `MIDNIGHT_LLM_API_KEY`、`MIDNIGHT_LLM_BASE_URL`、`MIDNIGHT_LLM_MODEL` 和 `MIDNIGHT_PLATFORM_TOKEN` 替换为现场值。Nano 中按 `Ctrl-O`、回车保存，再按 `Ctrl-X` 退出。不要修改变量名，不要在等号两侧添加空格，不要给值添加说明文字。

如果主办方只更换 Token 和模型参数，`config/platform.local.yaml` 不需要修改；如果现场下发了新的题目查询、重置或提交地址，必须按新接口文档更新该文件的 `base_url` 和三个 endpoint。

先用快速模型预检验证现场模型，而不启动解题：

```bash
scripts/competition model-preflight
```

成功时必须同时出现：

```text
configuration OK
model preflight OK: competition:现场模型名
model tool protocol preflight OK
```

这证明 Base URL、APIKey、模型名、结构化 JSON 和工具动作协议均可用。随后执行：

```bash
scripts/competition platform-preflight
```

最后再运行一次完整本地检查，确认 Docker 和镜像正常：

```bash
scripts/competition local-preflight
```

如果 `model-preflight` 失败，不能进入正式挑战。优先核对现场提供的 Base URL 是否包含正确路径、模型名是否精确、APIKey 是否属于模型网关；如果主办方接口不是 OpenAI `chat/completions` 兼容格式，需要在准备阶段向裁判索取对应调用范式。

CUC provider 对单次网关超时执行一次有界传输重试，且始终受整题截止时间约束。若重试后仍失败，脱敏报告会从持久化 checkpoint 恢复尝试次数、Token 和工具计数，避免把已经发生的活动错误记录为 0。
CUC 的输出上限按职责限制为分类 512、默认连接检查 1024、解题专家 1536 Token。JSON 工具协议每轮只应产生一个动作，这能减少拥塞时的排队与无效长输出。

若主办方提供联调题，再按顺序执行：

```bash
scripts/competition dry-run TEST_CHALLENGE_ID
scripts/competition submit-test TEST_CHALLENGE_ID
```

`dry-run` 会取题和解题，但禁止提交。`submit-test` 只应对主办方明确授权的测试题使用。提交测试成功后冻结代码、依赖和镜像，不要在比赛现场运行 `git pull`、`uv sync`、Docker 清理或镜像重建。

上面两个带题号的命令用于开发人员定点排查接口。队员演练正式的“只启动、不输入题号”流程时执行：

```bash
scripts/competition rehearsal
```

`rehearsal` 会自动生成新的 run ID，从平台拉取当前全部测试题，包括已经解过的题，然后自主解题并提交。平台可能接受正确答案但不重复计分。该命令只用于明确允许重复提交的测试平台；正式比赛不要使用它。

需要让同一道测试题从空白状态重新求解和提交时，为每次彩排指定新的 run ID：

```bash
MIDNIGHT_RUN_ID=rehearsal-1 scripts/competition submit-test TEST_CHALLENGE_ID
```

run ID 只能使用不含空格的简短名称，例如下一次改成 `rehearsal-2`。如果复用相同 run ID，Midnight 会复用断点和提交账本，这是恢复功能，不代表重新求解。

通常不需要手工指定 run ID；直接执行 `scripts/competition rehearsal` 会自动生成。它只是日志、断点和提交账本的本地运行名称，不是题号。

在比赛使用的网络环境中再次运行前，检查终端是否遗留无效代理：

```bash
env | grep -i proxy
```

如果现场不运行 Clash 或其他代理，清除遗留代理后再启动：

```bash
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
```

如果确实需要本机代理，先确认代理程序和端口可用。赛事平台适配器默认不读取环境代理。仓库内置的 CUC 模型 provider 使用 `network_mode: direct_ipv4`：它会忽略终端遗留代理并强制走 IPv4，避免校园 VPN 只接管 IPv4 时，模型域名的 IPv6 流量绕过 VPN 后被重定向到统一认证。其他模型 provider 默认仍按环境变量选择网络。

## 4. 正式比赛启动

在裁判允许启动 Agent 后，第二环节只执行：

```bash
cd /path/to/midnight
scripts/competition round2
```

第三环节只执行：

```bash
cd /path/to/midnight
scripts/competition round3
```

正式命令会自动完成：

1. 查询全部未解题目；
2. 下载附件并获取交互题靶场地址；
3. 分类并启动隔离 Docker 沙箱；
4. 调用比赛模型自主分析和执行工具；
5. 校验候选 Flag 并向赛事平台提交；
6. 保存日志、工作目录、提交账本和断点。

默认最多同时解 8 道题，但平台交互靶场实例严格限制为 2 个。只有题面和附件的静态题可以占用其余并发；Pwn/Reverse 仍共享一个本地重型分析槽。所有题都在本地 Docker 沙箱中运行，这些本地沙箱不占平台靶场名额。解题窗口为 27 分钟，为 30 分钟赛段保留约 3 分钟收尾。若题目在命令启动后稍晚发布，程序会每 5 秒查询一次，最长等待 5 分钟；这段时间内遇到临时 DNS 或接口连接错误也会继续重试，且等待时间不占用 27 分钟解题预算。macOS 会自动使用 `caffeinate`，防止电脑和磁盘在运行期间休眠。

启动后保持终端、Docker Desktop 和赛事网络正常。规则要求自主运行的阶段不要触碰设备；所有操作以现场裁判指令为准。

## 5. 如何判断运行正常

正常启动会看到：

```text
config loaded: ...
discovered N challenge(s)
run id: round2
```

如果题目尚未发布，会先看到：

```text
waiting up to 300 seconds for live challenges
```

程序结束时会打印每题状态和 `solved X/Y`。只要存在未解题，进程退出码可能为 `1`；这表示本轮有题未解，不能据此判断程序启动失败。崩溃应以 traceback、配置错误、Docker 错误或接口错误为准。

启动命令在前台运行，原终端会实时显示配置加载、发现题目、分类、模型请求、容器启动、专家尝试、提交结果和清理结果。它不会打印模型隐藏推理、完整 Flag 或每条工具原始输出。

测试时可以另开一个终端，观察经过脱敏的生命周期事件：

```bash
cd /path/to/midnight
scripts/competition monitor rehearsal-1
```

按 `Ctrl-C` 只会结束这个监控命令，不会停止另一个终端中的 Agent。正式自主阶段是否允许打开或操作监控终端，以现场规则和裁判指令为准。

取证任务会在各自工作区内部维护文件读取范围、内容哈希和写入证据账本，并把长日志、EVTX、PCAP 与 Linux IR 输出压缩为短证据记录。Pwn 任务会按 `solve.py` 哈希和本地/目标模式记录执行状态与脱敏失败摘要；相同版本在相同模式运行两次后必须修改脚本才能继续。监控和报告只使用脱敏的工具次数、错误、Token 与提交状态；不要打开工作区账本、模型推理正文、候选 Flag 或 evaluator oracle。

运行数据分别位于：

```text
logs/round2/
logs/round3/
```

其中 `events.jsonl` 是事件日志，`report.json` 是结果摘要，`checkpoints.sqlite` 是断点，`submissions.sqlite` 防止同一 run ID 重复提交，`artifacts/` 保存附件，`workspaces/` 保存解题脚本和证据。工作目录可能包含 Flag，不要公开上传 `logs/`。

## 6. 中断与恢复

如果进程意外中断，只能在规则和裁判允许再次操作时重跑同一命令：

```bash
scripts/competition round2
```

或：

```bash
scripts/competition round3
```

相同命令会复用对应 run ID、断点、工作区和提交账本。不要在彩排时提前使用 `round2` 或 `round3`，否则会污染正式轮次的断点；彩排使用 `dry-run` 和 `submit-test`。

若允许维护且确认有遗留容器，只清理对应轮次：

```bash
.venv/bin/python -m midnight.app --cleanup-run round2
```

第三环节将 `round2` 改为 `round3`。不要执行会删除全部 Docker 镜像、容器或卷的命令。

## 7. 常见故障

- `Missing local Python environment`：`.venv` 未提前安装；回到可联网准备阶段执行 `uv sync --extra dev`。
- Docker 连接失败：启动 Docker Desktop，再运行 `docker info`。
- `required credential is missing: MIDNIGHT_PLATFORM_TOKEN`：检查 `.env` 的变量名和值。
- 模型返回 401/403：检查 `MIDNIGHT_LLM_API_KEY`；不要使用平台 Token。
- 模型返回 404：重点检查 `MIDNIGHT_LLM_BASE_URL` 是否缺少或重复 `/v1`，以及 `MIDNIGHT_LLM_MODEL` 是否为精确名称。
- 平台返回 401/403：检查 `MIDNIGHT_PLATFORM_TOKEN`；不要使用模型密钥。
- `platform reported no unsolved challenges`：只读预检下通常表示题未开放或已经解完；正式命令会先等待 5 分钟。
- Apple Silicon 上 Pwn/Reverse 较慢：amd64 镜像仿真会增加开销，因此 Pwn/Reverse 已被单独限制为一个本地重型分析槽。

## 8. 现场最短清单

准备阶段：

```bash
cd /path/to/midnight
scripts/competition model-preflight
scripts/competition platform-preflight
scripts/competition local-preflight
```

第二环节：

```bash
scripts/competition round2
```

第三环节：

```bash
scripts/competition round3
```

写入密钥只完成配置。执行对应 `round2` 或 `round3` 命令后，Agent 才开始自动取题、解题和提交。
