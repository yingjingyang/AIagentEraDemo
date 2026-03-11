---
name: skill-stress-lab
description: 对任意 Skill 进行压力测试、记录稳定性/性能/资源指标，并输出 0-100 评分的 Markdown 报告。
---

## 适用场景
- 发布新 Skill 前，需要验证在高并发、大上下文、异常注入下的稳定性。
- 用户反馈 Skill 表现不稳定，需回归测试并量化分数。
- 想比较多个 Skill 的表现，输出统一的 100 分制报告。

## 核心资源
- [Stress Plan 模板](references/stress-plan-template.md)：定义场景矩阵与执行参数。
- [评分 Rubric](references/scoring-rubric.md)：五维度（稳定性/性能/资源/一致性/恢复）**各自 0-100**，总分为五项平均值。
- [报告模板](references/report-template.md)：测试结束后填充 Markdown 并交付。
- `scripts/stress_runner.py`：并发命令触发器，支持 `--runs`（默认 5 次）与 `--concurrency`（默认 2）参数。

## 自动指标采集（可选）
- `scripts/stress_runner.py` 现支持 `--collect-metrics`（依赖 `psutil`）来采集子进程的 CPU / RSS 最大值与平均值，并可通过 `--metrics-output` 输出为 JSON。
- 若目标 Skill 能在本地维护 OpenAI token/外部 API 调用的累计 JSON，可分别通过 `--openai-usage-file`、`--api-count-file` 让 stress_runner 自动计算 delta 并写入汇总报告。
- 示例：
  ```bash
  pip install psutil  # 首次使用需要安装
  python3 skills/skill-stress-lab/scripts/stress_runner.py \ 
    --command "python3 {skill}/scripts/run_cli.py" \ 
    --skill-dir skills/soon-network-explorer \ 
    --runs 10 --concurrency 3 \ 
    --collect-metrics \ 
    --metrics-output reports/stress/metrics.json \ 
    --openai-usage-file /tmp/openai_usage.json \ 
    --api-count-file /tmp/api_counter.json
  ```
  汇总报告会额外附带 `avg_max_cpu_pct`、`openai_tokens_total` 等字段，便于在评分阶段引用。

## 工作流程

### 1. 建立测试计划
1. 阅读目标 Skill 的 `SKILL.md` + scripts，确认触发条件、依赖和输出。
2. 使用 `references/stress-plan-template.md` 复制到 `tests/<skill-name>-plan.md`，填写：
   - 场景矩阵：Baseline、Burst、Long Context、Tool Failure、Edge Cases。
   - 并发度、轮次、间隔。
   - 监控指标（响应时间、token 消耗、错误率）。
3. 若需自动化，可扩展自定义脚本（例如 `python stress_runner.py --plan plan.yaml`）记录结果日志，并在计划中注明 `runs`/`并发度`；若未另行设定，则 CLI 默认 `runs=5`。

### 2. 执行压力测试
- **Baseline**：正常输入下跑 ≥5 轮，记录平均响应、token。
- **Burst Load / 并行压测**：必须采用并行方式触发（tmux、多 shell 或 `scripts/stress_runner.py --command "..." --runs 10 --concurrency 4`）。若未指定 `--runs`，CLI 默认 5 次；可根据计划覆盖。命令模板支持 `{skill}`、`{skill_name}`、`{run}` 占位符：
  ```bash
  python3 skills/skill-stress-lab/scripts/stress_runner.py \
    --command "python3 {skill}/scripts/run_cli.py --input repo --chain evm" \
    --skill-dir skills/multichain-contract-vuln \
    --runs 8 --concurrency 4 \
    --summary-report reports/stress-summary.md
  ```
  上例会把 `--skill-dir` 指定的目录自动填入 `{skill}` 参数，实现“把参数传给目标 skill”，并通过 `--summary-report` 只输出一份汇总结果（若下游命令的 `--scope` 固定，还能避免每轮生成独立报告）。
- **Long Context**：构造 16k+ tokens 或大型文件输入，验证上下文截断情况。
- **Tool Failure 注入**：人为断开依赖（如禁止 `browser`, `exec`），确认 Skill 的降级策略。
- **Edge Cases**：异常参数、空输入、极端数据。

> **记录方式**：
> - 保留命令历史、日志（`openclaw logs`, `slack transcripts`）。
> - 汇总每个场景的成功次数 / 失败次数 / 平均耗时。
> - 统计 token / 资源消耗，可从日志或模型计费数据中提取。

### 3. 评分 & 报告
1. 根据 [scoring-rubric.md](references/scoring-rubric.md) 给五个维度分别打分（0-100）。
2. 说明评分原因，例如“稳定性 80：50 轮仅失败 2 次 (4%)”。
3. 取五项平均作为总分（0-100），并在报告中写明“本报告采用五维度独立 0-100 评分，取平均得分”。
4. 复制 [report-template.md](references/report-template.md) 至 `reports/<skill>-stress-report.md`，填入：
   - 基本信息（Skill、版本、环境）。
   - 测试摘要（运行次数、成功率、平均响应、token、错误数）。
   - 评分表 + 详细场景描述。
   - 问题/建议 + 附录（日志位置、脚本、commit）。

### 4. 交付
- 在回复中附上总分与主要问题摘要，并提供报告绝对路径。
- 若需对比历史结果，保留 `reports/` 下以日期命名的多份报告。

## 提示
- 可以结合 `tmux`, `GNU parallel`, 或 OpenClaw cron 来模拟并发。
- 若 Skill 依赖外部 API，务必在计划中注明速率限制，避免触发封锁。
- 建议在 QA 环境运行，避免把压力直接施加在生产账号上。
- 若测试过程中发现关键故障，立即暂停并在报告中记录“终止原因”。
