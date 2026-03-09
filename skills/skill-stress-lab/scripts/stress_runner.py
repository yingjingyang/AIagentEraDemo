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
from typing import Dict, List


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


def summarize(results: List[RunResult]) -> None:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Concurrent stress runner for Skill tests")
    parser.add_argument("--command", required=True, help="要执行的命令，例如 'python3 audit_scan.py --markdown report.md'")
    parser.add_argument("--runs", type=int, default=5, help="运行次数（默认：5）")
    parser.add_argument("--concurrency", type=int, default=2, help="并发数（默认：2）")
    parser.add_argument("--workdir", type=Path, help="命令执行目录")
    parser.add_argument("--log-dir", type=Path, help="保存 stdout/stderr 的目录 (可选)")
    parser.add_argument("--skill-dir", type=Path, help="被压测的 skill 目录（用于 {skill}/{skill_name} 占位符）")
    args = parser.parse_args()

    if args.runs <= 0:
        parser.error("--runs 必须大于 0")
    if args.concurrency <= 0:
        parser.error("--concurrency 必须大于 0")

    workdir = args.workdir.resolve() if args.workdir else None
    log_dir = args.log_dir.resolve() if args.log_dir else None
    skill_dir = args.skill_dir.resolve() if args.skill_dir else None

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
    summarize(results)


if __name__ == "__main__":
    main()
