# Midnight Windows 部署与比赛启动指南

本指南用于在 Windows 10/11 电脑上从公开 GitHub 仓库部署 Midnight。Midnight
控制器在 Windows 中运行，每道题的分析工具运行在 Docker Desktop 的 Linux
容器中，因此不需要在 Windows 主机逐个安装 GDB、tshark、Volatility 或其他
CTF 工具。

## 1. 前置条件

赛前联网安装以下软件：

- Git for Windows；
- Docker Desktop，启用 WSL 2 后端和 Linux containers；
- uv，按 <https://docs.astral.sh/uv/getting-started/installation/> 的 Windows
  方法安装；
- 至少预留约 35 GB 磁盘空间和 8 GB 内存，建议 16 GB 内存。

安装后重新打开 PowerShell，确认以下命令可用：

```powershell
git --version
uv --version
docker version
```

首次执行脚本若被 PowerShell 执行策略拦截，只对当前窗口临时放行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## 2. 克隆并一键准备

在 PowerShell 中执行：

```powershell
git clone https://github.com/pity11/midnight.git
cd midnight
.\scripts\competition.ps1 setup
```

`setup` 会完成以下工作：

1. 创建 `.venv` 并安装锁定依赖；
2. 在缺失时创建 `.env` 和 `config\platform.local.yaml`；
3. 自动启动 Docker Desktop（如果安装在默认路径）；
4. 构建所有专家镜像；
5. 用离线 stub 配置检查七类镜像中的工具契约。

首次构建镜像需要较长时间。若使用 Clash Verge 的 7890 端口，可在同一
PowerShell 窗口先执行：

```powershell
$Env:MIDNIGHT_BUILD_PROXY = "http://127.0.0.1:7890"
$Env:MIDNIGHT_APT_MIRROR = "http://mirrors.tuna.tsinghua.edu.cn/ubuntu"
.\scripts\competition.ps1 setup
```

脚本不会把代理写入镜像运行环境。赛前不要执行 Docker 的全局清理命令，否则
可能删除已经准备好的工具镜像。

## 3. 填写本地凭据和平台接口

打开本地凭据文件：

```powershell
notepad .env
```

填写：

```dotenv
MIDNIGHT_LLM_API_KEY=主办方发放的大模型APIKey
MIDNIGHT_LLM_BASE_URL=主办方提供的OpenAI兼容地址
MIDNIGHT_LLM_MODEL=主办方指定的模型名
MIDNIGHT_PLATFORM_TOKEN=队伍Token
```

再打开平台配置：

```powershell
notepad config\platform.local.yaml
```

按主办方接口文档填写 `base_url`、题目查询、环境重置和答案提交 endpoint。
模型 APIKey 与队伍 Token 用途不同，不能互换。这两个本地文件已被
`.gitignore` 排除，不会上传 GitHub。

## 4. 必须完成的预检

```powershell
.\scripts\competition.ps1 model-preflight
.\scripts\competition.ps1 platform-preflight
.\scripts\competition.ps1 local-preflight
```

预检分别验证模型 JSON/工具协议、平台只读取题接口，以及 Docker 中全部工具。
`platform-preflight` 不启动靶场、不解题、不提交。

CUC provider 对单次网关超时执行一次有界传输重试，且始终受整题截止时间约束。若重试后仍失败，脱敏报告会从持久化 checkpoint 恢复尝试次数、Token 和工具计数，避免把已经发生的活动错误记录为 0。
CUC 的输出上限按职责限制为分类 512、默认连接检查 1024、解题专家 1536 Token。JSON 工具协议每轮只应产生一个动作，这能减少拥塞时的排队与无效长输出。
若专家节点的原请求和传输重试都失败，Midnight 会把它记录为本轮模型故障并进入正常专家重试，而不是直接终止整题；整题截止时间仍优先。
不可变 benchmark bundle 的 manifest 分类属于可信元数据，会直接路由到对应专家而不再调用分类模型；实时比赛平台提供的普通 hint 仍保留模型分类与降级路径。

若主办方提供联调环境，可以让 Agent 自动获取全部测试题并提交：

```powershell
.\scripts\competition.ps1 rehearsal
```

也可以在开发排错时指定主办方测试题号：

```powershell
.\scripts\competition.ps1 dry-run TEST_CHALLENGE_ID
.\scripts\competition.ps1 submit-test TEST_CHALLENGE_ID
```

## 5. 比赛启动

第二环节只执行：

```powershell
.\scripts\competition.ps1 round2
```

第三环节只执行：

```powershell
.\scripts\competition.ps1 round3
```

脚本会自动取题、下载附件、按类型启动 Docker 沙箱、调用模型、验证候选 Flag、
提交并保存断点。默认最多并发处理 8 道题，平台交互实例最多同时占用 2 个。

意外中断后，在裁判允许操作时重新执行相同的 `round2` 或 `round3` 命令，即可
使用相同 run ID 恢复。不要改名或删除 `logs\round2`、`logs\round3`。

## 6. 监控与结果位置

测试期间可在另一个 PowerShell 窗口运行：

```powershell
.\scripts\competition.ps1 monitor rehearsal-20260911-120000
```

终端会显示脱敏事件。正式自主阶段是否允许打开监控窗口，以现场裁判要求为准。

取证任务会在各自工作区内部维护文件读取范围、内容哈希和写入证据账本，并把长日志、EVTX、PCAP 与 Linux IR 输出压缩为短证据记录。Pwn 任务会按 `solve.py` 哈希和本地/目标模式记录执行状态与脱敏失败摘要；相同版本在相同模式运行两次后必须修改脚本才能继续。监控和报告只使用脱敏的工具次数、错误、Token 与提交状态；不要打开工作区账本、模型推理正文、候选 Flag 或 evaluator oracle。

每轮数据在 `logs\RUN_ID\`：

- `events.jsonl`：脱敏生命周期事件；
- `report.json`：结果和资源统计；
- `checkpoints.sqlite`：恢复断点；
- `submissions.sqlite`：防止重复提交；
- `artifacts\`：附件；
- `workspaces\`：Agent 生成的分析文件和证据。

`logs\` 可能包含 Flag，已被 Git 忽略，不要手工上传。

## 7. 工具清单

工具均位于 Docker 镜像中，不要求队员在 Windows 安装。清单来源：

- `docs\curated-ctf-tools.md`：工具用途和调用条件；
- `config\tools.yaml`：各专家可调用的 Midnight 工具；
- `config\sandbox_profiles.yaml`：镜像必须具备的命令和 Python 模块；
- `config\toolpacks.yaml`：第三方工具版本、来源、许可证和固定哈希。

主要覆盖：

- Pwn：GDB、pwntools、checksec、ROPgadget、ropper、angr、pwninit、one_gadget；
- Reverse：radare2、UPX、JADX、apktool、PyInstaller 提取、Kaitai Struct；
- Web：Fenjing、TInjA、jwt_tool、sqlmap、ffuf、nmap、nikto、whatweb；
- Crypto：RsaCtfTool、xortool、Z3、fpylll、PyCryptodome、SymPy；
- Forensics/应急：Volatility 3、Hayabusa、EVTX、Sleuth Kit、TestDisk、tshark、
  log-audit、YARA、binwalk、foremost、ExifTool、OCR、音视频和归档工具。

`local-preflight` 会在断网容器中逐项验证必须工具，缺少任何必需项都会失败。

## 8. 常见问题

- 找不到 `uv`：按 uv 官方 Windows 安装文档安装，关闭并重新打开 PowerShell；
- Docker 无法启动：打开 Docker Desktop，确认使用 Linux containers；
- Docker 提示 WSL 问题：在管理员 PowerShell 中更新 WSL，然后重启电脑；
- 模型 401/403：检查 `MIDNIGHT_LLM_API_KEY`；
- 模型 404：检查 Base URL 的 `/v1` 和精确模型名；
- CUC 模型跳转到统一认证：内置 provider 已用 `network_mode: direct_ipv4` 强制模型流量走 IPv4 校园 VPN；先确认 VPN 的 IPv4 路由正常，不需要关闭系统 IPv6；
- 平台 401/403：检查 `MIDNIGHT_PLATFORM_TOKEN`；
- `solved X/Y` 不是满分且退出码为 1：表示部分题未解，不代表启动失败；
- Windows ARM 电脑：Pwn/Reverse 的 `linux/amd64` 镜像需要仿真，速度会明显降低。
