---
name: skill-security-audit
description: "对指定 Skill（本地/未安装/远程）执行安全体检，检查权限、配置、日志、记忆、token、失败率并输出 0-100 评分的 Markdown 报告（代码审计需人工单独完成）。"
---

## 适用场景
- 在安装第三方 Skill 前先做安全体检。
- 审查现有 Skill（含本地未注册或 Web 上公开的 .skill/.zip 仓库）。
- 用户要求给出隐私、权限、记忆、token、失败率五个维度的 0-100 评分以及修复建议。

## 工具
- `python3 skills/skill-security-audit/scripts/audit_skill.py`（基于 agent-audit 扩展）。
  - 支持参数：
    - `--skill-path /path/to/skill`：本地目录或 `.skill` 解压路径。
    - `--skill-url https://example.com/foo.skill`：远程 Skill（脚本会下载再分析）。
    - `--agent-path/--agent-url`：如需同时附带未安装的 agent JSON 进行权限交叉分析（可选）。
    - `--markdown audit_report.md`：输出 Markdown 路径（默认英文）。
    - `--lang zh`：可选，输出中文报告（默认 `en`）。

## 工作流程
1. **准备输入**
   - 本地已安装 Skill：路径通常为 `skills/<name>`。
   - 本地未安装 Skill：解压 `.skill`/`.zip` 后提供目录。
   - Web Skill：直接传 URL（脚本自动下载文本或压缩包）。

2. **执行体检**
   ```bash
   cd ~/.openclaw/workspace
   python3 skills/skill-security-audit/scripts/audit_skill.py \
     --skill-path skills/multichain-contract-vuln \
     --markdown reports/multichain-contract-vuln-audit.md
   ```
   - 也可混用 `--skill-url`/`--agent-path`/`--agent-url` 加入更多待检对象。
   - 如需远程 Skill：`python3 ... --skill-url https://example.com/foo.skill --markdown reports/foo.md`
   - 需要中文报告：命令加上 `--lang zh`

3. **分析维度（每项 0-100）**
   - **隐私泄露**：扫描 Skill 文本及引用资源中的 API 密钥、私钥等敏感片段。
   - **权限**：统计 Skill/Agent 声明的高危工具（exec/browser/message/nodes/cron/canvas/gateway）。
   - **记忆膨胀**：检查 `memory/` 目录与 Skill 附带数据体积。
   - **Token 成本**：解析日志中的模型调用（若日志缺失会给出告警）。
   - **失败率**：基于 `~/.openclaw/logs/*.log` 的 error/exception 行进行估算。
   - 输出英文 Markdown，内容含评分表、告警、权限概览与建议。

4. **解释输出**
   - Markdown 报告章节：风险评分、修复建议、权限概览、数据告警、日志摘要等。
   - 权限概览会列出当前 skill 检测到的 high-risk 工具（exec/browser/gateway 等），便于对照权限。
   - `Recommendations` 区块会根据具体风险（日志错误、exec/gateway、记忆泄漏等）给出对应整改项。

5. **交付**
   - 在回复中给出 `reports/<scope>-skill-audit.md` 的绝对路径、核心发现与关键评分。
   - 如需附加证据，可贴日志/命令片段（不再输出 JSON 文件）。

## 注意事项
- 运行脚本前确保位于 `~/.openclaw/workspace`，以便读取 `openclaw.json`、日志和 memory。
- 远程 URL 仅支持公开可下载的文本、`.skill`、`.zip` 文件，若需鉴权请先手动下载。
- 如果 Skill 包含二进制/大文件，可在报告中记录并评估它们的权限与隐私风险。
- 静态/动态代码审计如需执行，请直接在会话中让助手阅读源代码给出结论，不通过此脚本自动化。
