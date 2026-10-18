# 12 · GitHub 发布与队友部署

本文给仓库所有者和队友使用。目标是从 GitHub 拉取项目后，在不安装 Docker、数据库或第三方 Python 包的情况下，启动完整的巡检靶场和智能体演示。

## 仓库结构

```text
qnbvc/
└─ website-security-lab/
   ├─ deploy.ps1                      Windows 一键校验并启动
   ├─ deploy.sh                       Linux / macOS 一键校验并启动
   ├─ range/                          合成安全靶场
   │  ├─ server.py                    无第三方依赖的 HTTP 靶场
   │  ├─ start.ps1 / start.sh         只启动靶场
   │  ├─ demo.py                      基线 → 篡改 → 复测
   │  ├─ authorization.range.json     靶场授权配置
   │  └─ site/                        干净、篡改、弱配置、泄露数据
   ├─ framework/                      巡检智能体骨架
   └─ docs/                           设计与部署文档
```

## 发布方式

`qnbvc/qnbvc` 同时是 GitHub Profile 仓库，根目录 `README.md` 保留个人主页内容，本项目放在 `website-security-lab/` 子目录。更新项目时只提交子目录和必要的根目录入口文件：

```powershell
git pull --rebase origin main
git add website-security-lab README.md .github .gitignore .gitattributes
git commit -m "Update website security lab"
git push origin main
```

不要把 `website-security-lab/range/out/` 下的运行状态、真实凭据、单位数据或授权书原件提交到公开仓库。`.gitignore` 已排除运行时输出和本地压缩包。

## 队友克隆

```powershell
git clone https://github.com/qnbvc/qnbvc.git
cd qnbvc\website-security-lab
```

不需要 `pip install`，核心项目只使用 Python 3.10+ 标准库。

## Windows 部署

推荐双击或在 PowerShell 中运行：

```powershell
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\deploy.ps1
```

脚本会：

1. 检查 Python 版本；
2. 运行 `framework/tests` 和 `range/tests`；
3. 启动靶场，默认监听 `0.0.0.0:8080`；
4. 在控制台打印控制令牌。

只想验证环境、不启动服务：

```powershell
.\deploy.ps1 -VerifyOnly
```

只允许本机访问：

```powershell
.\deploy.ps1 -BindHost 127.0.0.1
```

关闭控制接口后再启动，适合公网演示：

```powershell
.\deploy.ps1 -NoControl
```

如果 PowerShell 执行策略阻止脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1
```

## Linux / macOS 部署

```bash
LAB_CONTROL_TOKEN=team-lab-2026 ./deploy.sh
```

只验证：

```bash
VERIFY_ONLY=1 ./deploy.sh
```

只监听本机：

```bash
LAB_HOST=127.0.0.1 LAB_CONTROL_TOKEN=team-lab-2026 ./deploy.sh
```

如果脚本没有执行权限：

```bash
chmod +x deploy.sh range/start.sh
```

## 本地访问

```text
http://127.0.0.1:8080/
```

主要入口：

| 地址 | 用途 |
| --- | --- |
| `/` | 正常门户；切换后为篡改门户 |
| `/news.html` | 敏感关键词、手机号、AccessKey |
| `/files/statistics.csv` | CSV 敏感数据 |
| `/weak/` | 缺失安全响应头、目录列表、调试接口 |
| `/leaks/` | 合成敏感文件目录 |
| `/backup.zip` | 可解压的合成备份 |
| `/.env`、`/.git/config` | 暴露面检测 |

## 队友远程访问

### 方案一：Tailscale

主机和队友加入同一 tailnet：

```powershell
tailscale up
tailscale ip -4
.\deploy.ps1 -BindHost 0.0.0.0 -Port 8080
```

队友访问：

```text
http://100.x.x.x:8080/
```

### 方案二：同一局域网

主机用 `ipconfig` 查询局域网地址，队友访问：

```text
http://192.168.x.x:8080/
```

需要时临时放行 Windows 防火墙 TCP 8080；不要直接映射家庭路由器端口。

### 方案三：Cloudflare Tunnel

临时演示：

```powershell
cloudflared tunnel --url http://127.0.0.1:8080
```

长期演示建议使用命名隧道加 Cloudflare Access，只允许指定邮箱访问。公开展示时使用 `-NoControl`，避免暴露切换接口。

## 运行完整演示

启动服务后，在另一个窗口执行两轮巡检：

```powershell
cd framework
python -m wn_agent.cli --http `
  --url http://127.0.0.1:8080/ `
  --config ..\range\authorization.range.json `
  --memory ..\range\out\memory.json `
  --out ..\range\out `
  --name range-pass1
```

切换到篡改态：

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8080/__lab/tamper `
  -Headers @{ "X-Lab-Token" = "team-lab-2026" }
```

第二轮：

```powershell
python -m wn_agent.cli --http `
  --url http://127.0.0.1:8080/ `
  --config ..\range\authorization.range.json `
  --memory ..\range\out\memory.json `
  --out ..\range\out `
  --name range-pass2
```

也可以直接运行自动演示，不需要先启动服务：

```powershell
python range\demo.py
```

报告输出到 `range/out/demo/range-pass2.md`。

## 授权配置

默认配置只允许本机和 Tailscale 网段的被动检查。队友如果从自己的机器运行智能体，需要把实际目标加入 `range/authorization.range.json`：

```json
{
  "scope": {
    "domains": ["127.0.0.1", "localhost", "lab.example.com"],
    "ip_ranges": ["127.0.0.0/8", "100.64.0.0/10"]
  },
  "safety": {
    "active_assets": ["127.0.0.1:8080", "100.x.x.x:8080", "lab.example.com"]
  }
}
```

这只是靶场授权。接入真实资产时，必须换成真实授权编号、授权书附件、有效期和最小范围。

## 更新代码

```powershell
git pull
.\deploy.ps1 -VerifyOnly
```

更新后如果服务已经在运行，先停止旧进程，再重新启动。

## 常见问题

| 问题 | 处理 |
| --- | --- |
| `python` 不是内部或外部命令 | 安装 Python 3.10+，勾选 Add to PATH |
| `deploy.ps1` 被策略阻止 | 使用 `powershell -ExecutionPolicy Bypass -File .\deploy.ps1` |
| 8080 被占用 | 使用 `-Port 18080`，同时修改巡检 URL |
| 队友无法打开 | 检查 Tailscale、Windows 防火墙和 `BindHost` |
| 扫描提示 T1 未授权 | 把实际 `IP:端口` 写入 `safety.active_assets` |
| 页面无法切换 | 确认 `LAB_CONTROL_TOKEN` 与请求头一致，且未使用 `-NoControl` |
| 报告中出现端口不同 | 每轮巡检的 `--url` 必须指向当前靶场端口 |

## 安全边界

- 靶场仅使用合成人员、密钥和业务数据；
- 没有上传、爆破、命令执行或破坏性扫描接口；
- 控制接口需要 `X-Lab-Token`；
- 目录穿越返回 403；
- 公开访问优先使用 Tailscale 或 Cloudflare Access；
- 不把 Juice Shop、WebGoat 等脆弱应用直接暴露到互联网。
