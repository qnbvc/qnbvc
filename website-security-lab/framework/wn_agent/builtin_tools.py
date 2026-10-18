"""内置的被动型检测适配器（示例实现，真实项目可替换为 nuclei / gitleaks / YARA 等）。"""

from __future__ import annotations

import difflib
import re
from urllib.parse import urlsplit

from .models import Evidence, Finding, FindingType, Severity, Tier, now_iso
from .tools import ToolContext, ToolMeta

SECURITY_HEADERS = {
    "content-security-policy": ("CSP 缺失", Severity.MEDIUM, "CWE-1021"),
    "x-frame-options": ("点击劫持防护头缺失", Severity.LOW, "CWE-1021"),
    "strict-transport-security": ("HSTS 缺失", Severity.MEDIUM, "CWE-319"),
    "x-content-type-options": ("MIME 嗅探防护头缺失", Severity.LOW, "CWE-16"),
    "referrer-policy": ("Referrer-Policy 缺失", Severity.INFO, "CWE-200"),
}

PROBE_PATHS = ("/backup.zip", "/config/database.yml", "/phpinfo.php", "/.env")

OBFUSCATION_PATTERNS = (
    ("MALWARE.EVAL_DECODE_CHAIN",
     r"eval\s*\(\s*(unescape|atob|String\.fromCharCode)",
     "混淆脚本：eval + 解码链", Severity.CRITICAL),
    ("MALWARE.DOCUMENT_WRITE_UNESCAPE",
     r"document\.write\s*\(\s*unescape",
     "混淆脚本：document.write(unescape(...))", Severity.HIGH),
    ("MALWARE.HIDDEN_IFRAME",
     r"<iframe[^>]*(width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)",
     "隐藏 iframe（0 尺寸）", Severity.HIGH),
    ("MALWARE.HIDDEN_ELEMENT_LINK",
     r"style\s*=\s*[\"'][^\"']*(display\s*:\s*none|font-size\s*:\s*0)",
     "隐藏元素（暗链特征）", Severity.HIGH),
)


def _extract_links(text: str) -> list[str]:
    return re.findall(r"""(?:href|src)\s*=\s*["'](https?://[^"']+)["']""", text, re.I)


def _mask(value: str) -> str:
    if len(value) <= 6:
        return value[0:1] + "*" * max(0, len(value) - 2) + value[-1:]
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def _mask_url(url: str) -> str:
    """URL 证据保留主机名、脱敏查询串，便于人工核对又不泄露参数值。"""

    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}{parts.path}"
    return f"{base}?<参数已脱敏>" if parts.query else base


class SecurityHeadersTool:
    """弱配置检测：安全响应头基线（对标 ZAP baseline 的被动检查）。"""

    meta = ToolMeta("security-headers", "misconfig", Tier.T0,
                    "检查安全响应头与服务器版本信息泄露",
                    upstream="OWASP ZAP baseline / 自研基线")

    def run(self, ctx: ToolContext) -> list[Finding]:
        resp = ctx.fetch(ctx.page.url, Tier.T0, self.meta.name)
        if resp.status != 200:
            return []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings: list[Finding] = []
        for name, (desc, severity, cwe) in SECURITY_HEADERS.items():
            if name not in headers:
                findings.append(Finding(
                    asset=ctx.asset, url=ctx.page.url, ftype=FindingType.MISCONFIG,
                    rule_id=f"MISCONFIG.MISSING_HEADER.{name}", title=f"{desc}：{name}",
                    severity=severity, tool=self.meta.name, tier=Tier.T0,
                    location=name, cwe=cwe, confidence=0.85,
                    evidence=[Evidence("request_response", f"响应头中未出现 {name}",
                                       raw_ref=ctx.page.url)],
                    impact="浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。",
                    remediation=f"在 Web 服务器或 CDN 为全站响应补充 {name} 响应头并回归验证。",
                    first_seen=now_iso(),
                ))
        server = headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            findings.append(Finding(
                asset=ctx.asset, url=ctx.page.url, ftype=FindingType.MISCONFIG,
                rule_id="MISCONFIG.SERVER_VERSION_LEAK", title="响应头泄露服务器版本",
                severity=Severity.LOW, tool=self.meta.name, tier=Tier.T0,
                location="server", cwe="CWE-200", confidence=0.9,
                evidence=[Evidence("request_response", f"Server: {_mask(server)}")],
                impact="攻击者可据此匹配已知漏洞版本。",
                remediation="隐藏或泛化 Server 响应头中的版本信息。",
                first_seen=now_iso(),
            ))
        return findings


class ExposurePathTool:
    """暴露面探测：备份文件、配置文件、调试页面（T1 受控探测，需资产显式授权）。"""

    meta = ToolMeta("exposure-path", "vuln", Tier.T1,
                    "探测备份文件 / 配置文件 / 调试端点是否可公开访问",
                    upstream="feroxbuster / dirsearch 类")

    def run(self, ctx: ToolContext) -> list[Finding]:
        parts = urlsplit(ctx.page.url)
        origin = f"{parts.scheme}://{parts.netloc}"
        findings: list[Finding] = []
        for path in PROBE_PATHS:
            url = origin + path
            resp = ctx.fetch(url, Tier.T1, self.meta.name)
            if resp.status != 200:
                continue
            rule = path.strip("/").replace("/", "_").replace(".", "_").upper()
            findings.append(Finding(
                asset=ctx.asset, url=url, ftype=FindingType.VULN,
                rule_id=f"EXPOSURE.SENSITIVE_FILE.{rule}", title=f"敏感文件可公开访问：{path}",
                severity=Severity.CRITICAL, tool=self.meta.name, tier=Tier.T1,
                location=path, cwe="CWE-538", confidence=0.9, reachability=1.0,
                evidence=[Evidence("request_response",
                                   f"GET {url} -> HTTP 200，返回 {len(resp.text)} 字节",
                                   raw_ref=url)],
                impact="备份或配置文件可被匿名下载，可能导致凭据或业务数据整体泄露。",
                remediation=f"在 Web 服务器或网关屏蔽 {path} 的公开访问并清理该类文件。",
                first_seen=now_iso(), verify_hint=path,
            ))
        return findings


class SensitiveScanTool:
    """敏感信息检测：自定义关键词 / 正则 / 文件类型 / 样例指纹。"""

    meta = ToolMeta("sensitive-scan", "leak", Tier.T0,
                    "按自定义关键词、正则、文件类型与样例样本匹配敏感信息",
                    upstream="gitleaks / Microsoft Presidio / 自研规则引擎")

    def run(self, ctx: ToolContext) -> list[Finding]:
        rules = ctx.rules or {}
        resp = ctx.fetch(ctx.page.url, Tier.T0, self.meta.name)
        if resp.status != 200 or not resp.text:
            return []
        text = resp.text
        hits: list[tuple[str, str, str, Severity]] = []

        for keyword in rules.get("keywords", []):
            if keyword and keyword in text:
                hits.append((f"LEAK.KEYWORD.{keyword}",
                             f"命中自定义敏感关键词：{keyword}", keyword, Severity.HIGH))

        for rule in rules.get("regex", []):
            try:
                pattern = re.compile(rule.get("pattern", ""))
            except re.error:
                continue
            for match in list(pattern.finditer(text))[:3]:
                hits.append((f"LEAK.REGEX.{rule.get('name', 'unnamed')}",
                             f"命中敏感信息规则：{rule.get('name', 'unnamed')}",
                             match.group(0), Severity.HIGH))

        for sample in rules.get("samples", []):
            if sample and sample in text:
                hits.append(("LEAK.SAMPLE.MATCH", "命中样例样本指纹", sample, Severity.CRITICAL))

        ext = ctx.page.url.rsplit(".", 1)[-1].lower()
        if ext in [t.lower() for t in rules.get("file_types", [])]:
            hits.append((f"LEAK.FILE_TYPE.{ext}", f"命中敏感文件类型：.{ext}", "", Severity.MEDIUM))

        whitelist = rules.get("whitelist", [])
        findings: list[Finding] = []
        for rule_id, title, matched, severity in hits:
            if any(w and (w in matched or matched in w) for w in whitelist):
                continue
            hint = matched if matched != ext else ""
            findings.append(Finding(
                asset=ctx.asset, url=ctx.page.url, ftype=FindingType.LEAK,
                rule_id=rule_id, title=title, severity=severity,
                tool=self.meta.name, tier=Tier.T0,
                location="页面内容", cwe="CWE-200", confidence=0.8,
                evidence=[Evidence("match_context",
                                   f"命中值（已脱敏）：{_mask(matched)}" if matched
                                   else f"该资源（.{ext}）可被公开下载",
                                   raw_ref=f"{ctx.page.url}#{rule_id}")],
                impact="敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。",
                remediation="下线或加密该内容、补充访问控制，并排查同类页面与模板。",
                first_seen=now_iso(), verify_hint=hint,
            ))
        return findings


class IntegrityTool:
    """页面篡改检测：内容哈希与文本 diff 的基线比对。"""

    meta = ToolMeta("integrity-baseline", "tamper", Tier.T0,
                    "与上一周期基线对比正文内容哈希与文本差异",
                    upstream="自研（内容基线 + DOM/文本 diff）")

    def run(self, ctx: ToolContext) -> list[Finding]:
        if ctx.memory is None:
            return []
        resp = ctx.fetch(ctx.page.url, Tier.T0, self.meta.name)
        if resp.status != 200:
            return []
        baseline = ctx.memory.get_baseline(ctx.page.url)
        if not baseline or baseline.get("content_hash") == ctx.page.content_hash:
            return []          # 首次巡检只建基线；内容一致则不报
        diff = list(difflib.unified_diff(baseline.get("text", "").splitlines(),
                                         resp.text.splitlines(), lineterm="", n=1))
        preview = "\n".join(diff[2:8])[:600] or "(结构变化，无逐行差异)"
        return [Finding(
            asset=ctx.asset, url=ctx.page.url, ftype=FindingType.TAMPER,
            rule_id="TAMPER.CONTENT_CHANGED", title="页面内容与基线不一致",
            severity=Severity.HIGH, tool=self.meta.name, tier=Tier.T0,
            location="正文", cwe="CWE-345", confidence=0.75,
            evidence=[Evidence("diff", preview, raw_ref=f"{ctx.page.url}#diff")],
            impact="页面可能被非授权修改（挂马、暗链、内容篡改或误发布）。",
            remediation="核对发布流水线确认变更来源；若非授权修改，立即回滚并排查入侵路径。",
            first_seen=now_iso(),
        )]


class MalwareLinkTool:
    """挂马与恶意外链检测：外链白名单比对 + 隐藏元素 + 混淆脚本特征。"""

    meta = ToolMeta("malware-link", "malware", Tier.T0,
                    "检测新增未授权外部链接、隐藏元素与混淆脚本",
                    upstream="YARA / abuse.ch URLhaus / 自研规则引擎")

    def __init__(self, trusted_domains: list[str] | None = None) -> None:
        self.trusted = set(trusted_domains or [])

    def run(self, ctx: ToolContext) -> list[Finding]:
        resp = ctx.fetch(ctx.page.url, Tier.T0, self.meta.name)
        if resp.status != 200:
            return []
        text = resp.text
        findings: list[Finding] = []
        trusted = self.trusted | set(ctx.rules.get("trusted_domains", []))
        own_host = urlsplit(ctx.page.url).netloc.lower()
        for link in sorted(set(_extract_links(text))):
            host = urlsplit(link).netloc.lower()
            if not host or host == own_host or host in trusted or host.endswith(".gov.cn"):
                continue
            if host:
                findings.append(Finding(
                    asset=ctx.asset, url=ctx.page.url, ftype=FindingType.MALWARE,
                    rule_id="MALWARE.EXTERNAL_LINK",
                    title=f"页面引入未授权外部链接：{host}",
                    severity=Severity.HIGH, tool=self.meta.name, tier=Tier.T0,
                    location=host, cwe="CWE-829", confidence=0.7,
                    evidence=[Evidence("match_context", f"外链：{_mask_url(link)}")],
                    impact="外部资源可被第三方替换，导致挂马、暗链或流量劫持。",
                    remediation="将外部资源本地化，或在 CSP 白名单中仅放行可信域名。",
                    first_seen=now_iso(), verify_hint=link,
                ))
        for rule_id, pattern, title, severity in OBFUSCATION_PATTERNS:
            match = re.search(pattern, text, re.I)
            if match:
                findings.append(Finding(
                    asset=ctx.asset, url=ctx.page.url, ftype=FindingType.MALWARE,
                    rule_id=rule_id, title=title, severity=severity,
                    tool=self.meta.name, tier=Tier.T0, location="HTML 源码",
                    cwe="CWE-506", confidence=0.65,
                    evidence=[Evidence("match_context",
                                       f"命中片段：{match.group(0)[:80]}（规则 {rule_id}）")],
                    impact="疑似挂马脚本或暗链，可能在用户浏览器执行恶意逻辑。",
                    remediation="隔离并人工审计该段脚本，确认后清理并排查写入路径。",
                    first_seen=now_iso(), verify_hint=match.group(0)[:60],
                ))
        return findings
