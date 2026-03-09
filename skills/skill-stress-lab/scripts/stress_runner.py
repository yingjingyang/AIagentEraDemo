#!/usr/bin/env python3
"""Simple concurrent runner to stress test a command multiple times."""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class RunResult:
    idx: int
    code: int
    duration: float
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


async def execute(idx: int, command: str, workdir: Path | None, log_dir: Path | None, sem: asyncio.Semaphore) -> RunResult:
    await sem.acquire()
    try:
        start = time.perf_counter()
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(workdir) if workdir else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        duration = time.perf_counter() - start
        stdout = stdout_bytes.decode(errors="ignore")
        stderr = stderr_bytes.decode(errors="ignore")
        result = RunResult(idx=idx, code=proc.returncode or 0, duration=duration, stdout=stdout, stderr=stderr)
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
) -> List[RunResult]:
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    for idx in range(runs):
        ctx = dict(base_context)
        ctx["run"] = str(idx + 1)
        command = build_command(command_template, ctx)
        tasks.append(asyncio.create_task(execute(idx + 1, command, workdir, log_dir, sem)))
    return await asyncio.gather(*tasks)


def summarize(results: List[RunResult]) -> Dict[str, Any]:
    total = len(results)
    successes = sum(1 for item in results if item.ok)
    durations = [item.duration for item in results]
    avg = statistics.mean(durations) if durations else 0.0
    p95 = statistics.quantiles(durations, n=100)[94] if len(durations) >= 20 else max(durations, default=0.0)
    print("===== Stress Summary =====")
    print(f"Total runs: {total}")
    print(f"Successes: {successes} ({(successes/total*100):.1f}% )" if total else "Successes: 0")
    print(f"Avg duration: {avg:.2f}s")
    print(f"P95 duration: {p95:.2f}s")
    failed = [item for item in results if not item.ok]
    if failed:
        print(f"Failures ({len(failed)}):")
        for item in failed[:5]:
            print(f"- Run #{item.idx} exit {item.code}, duration {item.duration:.2f}s")
    else:
        print("No failures detected.")
    return {
        "total": total,
        "successes": successes,
        "durations": durations,
        "avg": avg,
        "p95": p95,
        "failures": failed,
        "success_rate": (successes / total) if total else 0.0,
    }


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
    if stats["failures"]:
        lines.append("")
        lines.append("### 失败样本")
        for item in stats["failures"][:5]:
            lines.append(f"- Run #{item.idx} exit {item.code}, duration {item.duration:.2f}s")
    lines.append("")
    lines.append("> 由 stress_runner 自动生成，仅保留汇总结果；如需原始 stdout/stderr 请查看日志目录。")
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"汇总报告写入：{path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Concurrent stress runner for Skill tests")
    parser.add_argument("--command", required=True, help="要执行的命令，例如 'python3 audit_scan.py --markdown report.md'")
    parser.add_argument("--runs", type=int, default=5, help="运行次数（默认：5）")
    parser.add_argument("--concurrency", type=int, default=2, help="并发数（默认：2）")
    parser.add_argument("--workdir", type=Path, help="命令执行目录")
    parser.add_argument("--log-dir", type=Path, help="保存 stdout/stderr 的目录 (可选)")
    parser.add_argument("--skill-dir", type=Path, help="被压测的 skill 目录（用于 {skill}/{skill_name} 占位符）")
    parser.add_argument("--summary-report", type=Path, help="汇总 Markdown 报告输出路径")
    args = parser.parse_args()

    if args.runs <= 0:
        parser.error("--runs 必须大于 0")
    if args.concurrency <= 0:
        parser.error("--concurrency 必须大于 0")

    workdir = args.workdir.resolve() if args.workdir else None
    log_dir = args.log_dir.resolve() if args.log_dir else None
    skill_dir = args.skill_dir.resolve() if args.skill_dir else None
    summary_report = args.summary_report.resolve() if args.summary_report else None

    if workdir and not workdir.exists():
        parser.error(f"工作目录不存在：{workdir}")
    if skill_dir and not skill_dir.exists():
        parser.error(f"Skill 目录不存在：{skill_dir}")

    context: Dict[str, str] = {}
    if skill_dir:
        context["skill"] = str(skill_dir)
        context["skill_name"] = skill_dir.name

    results = asyncio.run(
        run_stress(args.command, args.runs, args.concurrency, workdir, log_dir, context)
    )
    stats = summarize(results)
    if summary_report:
        write_summary_report(summary_report, stats, args.command, args.runs, args.concurrency, skill_dir, log_dir)


if __name__ == "__main__":
    main()
