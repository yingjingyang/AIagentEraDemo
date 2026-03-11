#!/usr/bin/env python3
"""Concurrent stress runner for Skill测试，支持可选指标采集。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover
    psutil = None


@dataclass
class RunResult:
    idx: int
    code: int
    duration: float
    stdout: str
    stderr: str
    metrics: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.code == 0


class MetricsSampler:
    """后台线程定期采样目标进程 CPU/内存。"""

    def __init__(self, pid: int, interval: float = 0.2) -> None:
        self.pid = pid
        self.interval = interval
        self.samples: List[tuple[float, float]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        if psutil is None:  # pragma: no cover
            return
        self._thread.start()

    def stop(self) -> None:
        if psutil is None:  # pragma: no cover
            return
        self._stop.set()
        self._thread.join(timeout=1)

    def _run(self) -> None:
        if psutil is None:  # pragma: no cover
            return
        try:
            proc = psutil.Process(self.pid)
            proc.cpu_percent(interval=None)  # prime
            while not self._stop.is_set():
                cpu = proc.cpu_percent(interval=self.interval)
                rss = proc.memory_info().rss
                self.samples.append((cpu, rss))
        except psutil.NoSuchProcess:
            return

    def summary(self) -> Dict[str, float]:
        if not self.samples:
            return {}
        cpus = [s[0] for s in self.samples]
        rss_vals = [s[1] for s in self.samples]
        return {
            "max_cpu_pct": max(cpus),
            "avg_cpu_pct": statistics.mean(cpus),
            "max_rss_mb": max(rss_vals) / (1024 * 1024),
            "avg_rss_mb": statistics.mean(rss_vals) / (1024 * 1024),
        }


def safe_load_json(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def numeric_delta(before: Any, after: Any) -> Any:
    if isinstance(before, dict) and isinstance(after, dict):
        delta: Dict[str, float] = {}
        for key, value in after.items():
            before_val = before.get(key, 0)
            if isinstance(value, (int, float)) and isinstance(before_val, (int, float)):
                delta[key] = value - before_val
        return delta
    if isinstance(after, (int, float)) and isinstance(before, (int, float)):
        return after - before
    return after


def aggregate_nested(dicts: List[Dict[str, Any]]) -> Dict[str, float]:
    agg: Dict[str, float] = {}
    for item in dicts:
        for key, value in item.items():
            if isinstance(value, (int, float)):
                agg[key] = agg.get(key, 0.0) + float(value)
    return agg


def aggregate_metrics(results: List[RunResult]) -> Dict[str, Any]:
    cpu_max = [r.metrics.get("max_cpu_pct") for r in results if r.metrics.get("max_cpu_pct") is not None]
    cpu_avg = [r.metrics.get("avg_cpu_pct") for r in results if r.metrics.get("avg_cpu_pct") is not None]
    rss_max = [r.metrics.get("max_rss_mb") for r in results if r.metrics.get("max_rss_mb") is not None]
    rss_avg = [r.metrics.get("avg_rss_mb") for r in results if r.metrics.get("avg_rss_mb") is not None]
    openai_list = [r.metrics.get("openai_tokens", {}) for r in results if r.metrics.get("openai_tokens")]
    api_list = [r.metrics.get("external_api", {}) for r in results if r.metrics.get("external_api")]

    summary: Dict[str, Any] = {}
    if cpu_max:
        summary["avg_max_cpu_pct"] = statistics.mean(float(x) for x in cpu_max)
    if cpu_avg:
        summary["avg_avg_cpu_pct"] = statistics.mean(float(x) for x in cpu_avg)
    if rss_max:
        summary["avg_max_rss_mb"] = statistics.mean(float(x) for x in rss_max)
    if rss_avg:
        summary["avg_avg_rss_mb"] = statistics.mean(float(x) for x in rss_avg)
    if openai_list:
        summary["openai_tokens_total"] = aggregate_nested([d for d in openai_list if isinstance(d, dict)])
    if api_list:
        summary["external_api_total"] = aggregate_nested([d for d in api_list if isinstance(d, dict)])
    return summary


async def execute(
    idx: int,
    command: str,
    workdir: Path | None,
    log_dir: Path | None,
    sem: asyncio.Semaphore,
    collect_metrics: bool,
    openai_file: Optional[Path],
    api_file: Optional[Path],
) -> RunResult:
    await sem.acquire()
    usage_before = safe_load_json(openai_file) if openai_file else {}
    api_before = safe_load_json(api_file) if api_file else {}
    try:
        start = time.perf_counter()
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(workdir) if workdir else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        sampler: Optional[MetricsSampler] = None
        if collect_metrics and psutil is not None:
            sampler = MetricsSampler(proc.pid)
            sampler.start()
        stdout_bytes, stderr_bytes = await proc.communicate()
        if sampler:
            sampler.stop()
        duration = time.perf_counter() - start
        stdout = stdout_bytes.decode(errors="ignore")
        stderr = stderr_bytes.decode(errors="ignore")
        metrics: Dict[str, Any] = {}
        if sampler:
            metrics.update(sampler.summary())
        if openai_file:
            metrics["openai_tokens"] = numeric_delta(usage_before, safe_load_json(openai_file))
        if api_file:
            metrics["external_api"] = numeric_delta(api_before, safe_load_json(api_file))

        result = RunResult(idx=idx, code=proc.returncode or 0, duration=duration, stdout=stdout, stderr=stderr, metrics=metrics)
        if log_dir:
            log_dir.mkdir(parents=True, exist_ok=True)
            (log_dir / f"run-{idx}.out").write_text(stdout)
            (log_dir / f"run-{idx}.err").write_text(stderr)
        return result
    finally:
        sem.release()


def build_command(template: str, context: Dict[str, str]) -> str:
    try:
        return template.format(**context)
    except KeyError as exc:
        missing = exc.args[0]
        raise ValueError(f"命令模板缺少占位符：{{{missing}}}") from exc


async def run_stress(
    command_template: str,
    runs: int,
    concurrency: int,
    workdir: Path | None,
    log_dir: Path | None,
    base_context: Dict[str, str],
    collect_metrics: bool,
    openai_file: Optional[Path],
    api_file: Optional[Path],
) -> List[RunResult]:
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    for idx in range(runs):
        ctx = dict(base_context)
        ctx["run"] = str(idx + 1)
        command = build_command(command_template, ctx)
        tasks.append(
            asyncio.create_task(
                execute(idx + 1, command, workdir, log_dir, sem, collect_metrics, openai_file, api_file)
            )
        )
    return await asyncio.gather(*tasks)


def summarize(results: List[RunResult]) -> Dict[str, Any]:
    total = len(results)
    successes = sum(1 for item in results if item.ok)
    durations = [item.duration for item in results]
    avg = statistics.mean(durations) if durations else 0.0
    p95 = statistics.quantiles(durations, n=100)[94] if len(durations) >= 20 else max(durations, default=0.0)
    print("===== Stress Summary =====")
    print(f"Total runs: {total}")
    success_rate = (successes / total * 100) if total else 0.0
    print(f"Successes: {successes} ({success_rate:.1f}% )")
    print(f"Avg duration: {avg:.2f}s")
    print(f"P95 duration: {p95:.2f}s")
    failed = [item for item in results if not item.ok]
    if failed:
        print(f"Failures ({len(failed)}):")
        for item in failed[:5]:
            print(f"- Run #{item.idx} exit {item.code}, duration {item.duration:.2f}s")
    else:
        print("No failures detected.")
    summary = {
        "total": total,
        "successes": successes,
        "durations": durations,
        "avg": avg,
        "p95": p95,
        "failures": failed,
        "success_rate": (successes / total) if total else 0.0,
    }
    metrics_summary = aggregate_metrics(results)
    if metrics_summary:
        summary["metrics_summary"] = metrics_summary
        print("\nMetrics summary:")
        for key, value in metrics_summary.items():
            if isinstance(value, dict):
                print(f"- {key}: {json.dumps(value)}")
            else:
                print(f"- {key}: {value}")
    return summary


def write_summary_report(
    path: Path,
    stats: Dict[str, Any],
    command_template: str,
    runs: int,
    concurrency: int,
    skill_dir: Path | None,
    log_dir: Path | None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Skill Stress Summary",
        "",
        "## 执行参数",
        f"- Command: `{command_template}`",
        f"- Runs: {runs}",
        f"- Concurrency: {concurrency}",
        f"- Skill dir: {skill_dir if skill_dir else '-'}",
        f"- Log dir: {log_dir if log_dir else '-'}",
        "",
        "## 结果概览",
        f"- 总次数: {stats['total']}",
        f"- 成功次数: {stats['successes']} ({stats['success_rate']*100:.1f}% )",
        f"- 平均耗时: {stats['avg']:.2f}s",
        f"- P95 耗时: {stats['p95']:.2f}s",
    ]
    if stats.get("failures"):
        lines.append("")
        lines.append("### 失败样本")
        for item in stats["failures"][:5]:
            lines.append(f"- Run #{item.idx} exit {item.code}, duration {item.duration:.2f}s")
    if stats.get("metrics_summary"):
        lines.append("")
        lines.append("## 指标汇总")
        for key, value in stats["metrics_summary"].items():
            if isinstance(value, dict):
                lines.append(f"- {key}: {json.dumps(value)}")
            else:
                lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("> 由 stress_runner 自动生成，仅保留汇总结果；如需原始 stdout/stderr 请查看日志目录。")
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"汇总报告写入：{path}")


def maybe_write_metrics(path: Optional[Path], results: List[RunResult]) -> None:
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "run": r.idx,
            "exit_code": r.code,
            "duration": r.duration,
            "metrics": r.metrics,
        }
        for r in results
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"指标明细写入：{path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Concurrent stress runner for Skill tests")
    parser.add_argument("--command", required=True, help="要执行的命令，例如 'python3 audit_scan.py --markdown report.md'")
    parser.add_argument("--runs", type=int, default=5, help="运行次数（默认：5）")
    parser.add_argument("--concurrency", type=int, default=2, help="并发数（默认：2）")
    parser.add_argument("--workdir", type=Path, help="命令执行目录")
    parser.add_argument("--log-dir", type=Path, help="保存 stdout/stderr 的目录 (可选)")
    parser.add_argument("--skill-dir", type=Path, help="被压测的 skill 目录（用于 {skill}/{skill_name} 占位符）")
    parser.add_argument("--summary-report", type=Path, help="汇总 Markdown 报告输出路径")
    parser.add_argument("--collect-metrics", action="store_true", help="启用 CPU/RSS 监控（需要 psutil）")
    parser.add_argument("--metrics-output", type=Path, help="可选：将每次 run 的 metrics 写入 JSON")
    parser.add_argument("--openai-usage-file", type=Path, help="OpenAI 累计用量 JSON（用于计算 token delta）")
    parser.add_argument("--api-count-file", type=Path, help="外部 API 请求量 JSON（用于计算 delta）")
    args = parser.parse_args()

    if args.runs <= 0:
        parser.error("--runs 必须大于 0")
    if args.concurrency <= 0:
        parser.error("--concurrency 必须大于 0")
    if args.collect_metrics and psutil is None:
        print("[warn] 未安装 psutil，CPU/内存监控会被忽略。可执行 `pip install psutil` 后再启用 --collect-metrics。")

    workdir = args.workdir.resolve() if args.workdir else None
    log_dir = args.log_dir.resolve() if args.log_dir else None
    skill_dir = args.skill_dir.resolve() if args.skill_dir else None
    summary_report = args.summary_report.resolve() if args.summary_report else None
    metrics_output = args.metrics_output.resolve() if args.metrics_output else None
    openai_file = args.openai_usage_file.resolve() if args.openai_usage_file else None
    api_file = args.api_count_file.resolve() if args.api_count_file else None

    if workdir and not workdir.exists():
        parser.error(f"工作目录不存在：{workdir}")
    if skill_dir and not skill_dir.exists():
        parser.error(f"Skill 目录不存在：{skill_dir}")

    context: Dict[str, str] = {}
    if skill_dir:
        context["skill"] = str(skill_dir)
        context["skill_name"] = skill_dir.name

    results = asyncio.run(
        run_stress(
            args.command,
            args.runs,
            args.concurrency,
            workdir,
            log_dir,
            context,
            args.collect_metrics,
            openai_file,
            api_file,
        )
    )
    stats = summarize(results)
    if summary_report:
        write_summary_report(summary_report, stats, args.command, args.runs, args.concurrency, skill_dir, log_dir)
    maybe_write_metrics(metrics_output, results)


if __name__ == "__main__":
    main()
