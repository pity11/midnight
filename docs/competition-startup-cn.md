# Midnight 线下赛启动指南

本指南用于允许自主 CTF Agent 取题、解题和提交的线下比赛。正式运行前必须完成一次完整预检；比赛现场只使用已经安装、已经构建并已经验证的冻结版本。

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
CUC_API_KEY=主办方发放的大模型密钥
CUC_BASE_URL=
CUC_MODEL=
MIDNIGHT_PLATFORM_TOKEN=队伍Token
```

`CUC_BASE_URL` 和 `CUC_MODEL` 留空时使用项目中已经核验的默认值。只有主办方明确给出新地址或新模型名时才填写，不能把说明文字或占位符写成配置值。队伍 Token 只用于赛事平台；`CUC_API_KEY` 只用于模型网关，两者不能互换。

不要通过 Git、聊天记录或公开文件传递 `.env`。同一轮只在比赛指定的单台电脑上运行正式命令，避免多个进程使用相同 Token 重复取题或提交。

## 2. 赛前冻结与离线准备

启动 Docker Desktop，并在项目根目录执行：

```bash
scripts/competition local-preflight
scripts/competition platform-preflight
```

`local-preflight` 会检查项目配置、真实模型连通性，以及 Pwn、Reverse、Web、Crypto、Forensics、Misc 和兜底沙箱的工具能力。第一次运行可能构建镜像，必须在赛前联网完成。`platform-preflight` 只查询题目，不重置环境、不解题、不提交。

若主办方提供联调题，再按顺序执行：

```bash
scripts/competition dry-run TEST_CHALLENGE_ID
scripts/competition submit-test TEST_CHALLENGE_ID
```

`dry-run` 会取题和解题，但禁止提交。`submit-test` 只应对主办方明确授权的测试题使用。提交测试成功后冻结代码、依赖和镜像，不要在比赛现场运行 `git pull`、`uv sync`、Docker 清理或镜像重建。

在比赛使用的网络环境中再次运行前，检查终端是否遗留无效代理：

```bash
env | grep -i proxy
```

如果现场不运行 Clash 或其他代理，清除遗留代理后再启动：

```bash
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
```

如果确实需要本机代理，先确认代理程序和端口可用。模型客户端可能读取这些环境变量；赛事平台适配器默认不读取环境代理。

## 3. 正式比赛启动

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

默认并发为 2，解题窗口为 27 分钟，为 30 分钟赛段保留约 3 分钟收尾。若题目在命令启动后稍晚发布，程序会每 5 秒查询一次，最长等待 5 分钟；这段时间内遇到临时 DNS 或接口连接错误也会继续重试，且等待时间不占用 27 分钟解题预算。macOS 会自动使用 `caffeinate`，防止电脑和磁盘在运行期间休眠。

启动后保持终端、Docker Desktop 和赛事网络正常。规则要求自主运行的阶段不要触碰设备；所有操作以现场裁判指令为准。

## 4. 如何判断运行正常

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

运行数据分别位于：

```text
logs/round2/
logs/round3/
```

其中 `events.jsonl` 是事件日志，`report.json` 是结果摘要，`checkpoints.sqlite` 是断点，`submissions.sqlite` 防止同一 run ID 重复提交，`artifacts/` 保存附件，`workspaces/` 保存解题脚本和证据。工作目录可能包含 Flag，不要公开上传 `logs/`。

## 5. 中断与恢复

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

## 6. 常见故障

- `Missing local Python environment`：`.venv` 未提前安装；回到可联网准备阶段执行 `uv sync --extra dev`。
- Docker 连接失败：启动 Docker Desktop，再运行 `docker info`。
- `required credential is missing: MIDNIGHT_PLATFORM_TOKEN`：检查 `.env` 的变量名和值。
- 模型返回 401/403：检查 `CUC_API_KEY`；不要使用平台 Token。
- 平台返回 401/403：检查 `MIDNIGHT_PLATFORM_TOKEN`；不要使用模型密钥。
- `platform reported no unsolved challenges`：只读预检下通常表示题未开放或已经解完；正式命令会先等待 5 分钟。
- Apple Silicon 上 Pwn/Reverse 较慢：amd64 镜像仿真会增加开销，未重新压测前保持默认并发 2。

## 7. 现场最短清单

准备阶段：

```bash
cd /path/to/midnight
scripts/competition local-preflight
scripts/competition platform-preflight
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
