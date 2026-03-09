# Stress Test Plan Template

## 1. 目标 Skill 概述
- Skill 名称：
- 版本/commit：
- 触发条件：
- 依赖工具：

## 2. 场景矩阵
| 场景 | 描述 | 输入样例 | 预期行为 | 风险点 |
| --- | --- | --- | --- | --- |
| Baseline | | | | |
| Burst Load | | | | |
| Long Context | | | | |
| Tool Failure | | | | |
| Edge Cases | | | | |

## 3. 执行参数
- 并发度：
- 轮次：
- 间隔：
- 监控指标：latency / token / error 率

## 4. 自动化脚本（可选）
- `python stress_runner.py --plan plan.yaml`
- 日志位置：

## 5. 风险缓解
- 回滚方案：
- 限速策略：
- 数据隔离：
