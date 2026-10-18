## Hi there 👋

<!--
**qnbvc/qnbvc** is a ✨ _special_ ✨ repository because its `README.md` (this file) appears on your GitHub profile.

Here are some ideas to get you started:

- 🔭 I’m currently working on ...
- 🌱 I’m currently learning ...
- 👯 I’m looking to collaborate on ...
- 🤔 I’m looking for help with ...
- 💬 Ask me about ...
- 📫 How to reach me: ...
- 😄 Pronouns: ...
- ⚡ Fun fact: ...
-->

---

## 项目

### 网站安全智能巡检智能体与可部署靶场

面向政企网站授权巡检的智能体原型，覆盖页面发现、漏洞与弱配置、页面篡改/挂马、敏感信息泄露、去重验证、基线对比、复测和报告导出。

项目包含：

- 无第三方依赖的合成安全靶场，一条命令启动；
- Windows / Linux 一键部署脚本；
- 37 条自动化回归测试；
- Tailscale、局域网和 Cloudflare Tunnel 队友访问方案；
- 智能体骨架、恒脑节点编排设计和完整部署文档。

进入项目目录：

```powershell
cd website-security-lab
```

Windows 启动：

```powershell
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\deploy.ps1
```

Linux / macOS 启动：

```bash
LAB_CONTROL_TOKEN=team-lab-2026 ./deploy.sh
```

启动后访问 `http://127.0.0.1:8080/`。

详细说明：

- [项目 README](website-security-lab/README.md)
- [GitHub 发布与队友部署](website-security-lab/docs/12-GitHub发布与队友部署.md)
- [靶场使用说明](website-security-lab/range/README.md)
