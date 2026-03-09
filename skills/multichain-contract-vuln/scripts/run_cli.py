#!/usr/bin/env python3
"""Command-line helper for the multichain-contract-vuln skill.

Features (initial version):
- Auto-generate Markdown audit report skeleton for EVM/Solana scopes
- For EVM projects, optionally run Slither and summarize detector findings
- For Solana projects, optionally run cargo/anchor commands and capture logs
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def slugify(name: str) -> str:
    return "-".join(
        filter(None, ["".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")])
    ) or "scope"


def detect_chain(input_path: Path, explicit: str | None) -> str:
    if explicit:
        return explicit.lower()
    if input_path.is_file() and input_path.suffix in {".sol", ".vy"}:
        return "evm"
    if (input_path / "Cargo.toml").exists() or (input_path / "Anchor.toml").exists():
        return "solana"
    return "evm"


def run_cmd(cmd: List[str], cwd: Path | None = None) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def run_slither(target: Path, json_path: Path, slither_bin: str | None = None) -> Tuple[bool, str]:
    binary = slither_bin or shutil.which("slither")
    if not binary:
        return False, "Slither 未安装（请先 pip install slither-analyzer）"

    cmd = [binary, str(target), "--json", str(json_path)]
    code, out, err = run_cmd(cmd, cwd=target.parent if target.is_file() else target)
    if code != 0:
        return False, f"Slither 执行失败 (exit {code})\nSTDOUT:\n{out}\nSTDERR:\n{err}"
    return True, out or "Slither 执行完成"


def parse_slither(json_path: Path) -> Dict:
    if not json_path.exists():
        return {"findings": [], "summary": {}}
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    detectors = data.get("results", {}).get("detectors", [])
    findings = []
    summary: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for detector in detectors:
        impact = detector.get("impact", "Informational").title()
        if impact not in summary:
            summary[impact] = 0
        summary[impact] += 1
        findings.append(
            {
                "check": detector.get("check", "unknown"),
                "impact": impact,
                "confidence": detector.get("confidence"),
                "description": detector.get("description", ""),
                "elements": detector.get("elements", []),
            }
        )
    return {"findings": findings, "summary": summary}


def summarize_findings(findings: List[Dict]) -> str:
    if not findings:
        return "未检出 Slither 漏洞（请手动复核业务逻辑）。"
    lines = []
    for idx, finding in enumerate(findings, 1):
        elements = finding.get("elements") or []
        signatures = ", ".join(
            sorted(
                {
                    elem.get("name") or elem.get("type", "")
                    for elem in elements
                    if isinstance(elem, dict)
                }
            )
        )
        lines.append(
            f"### {idx}. [{finding['impact']}] {finding['check']}\n"
            f"- **描述**：{finding.get('description', '').strip()}\n"
            f"- **命中位置**：{signatures or 'N/A'}\n"
            f"- **置信度**：{finding.get('confidence', 'Unknown')}\n"
        )
    return "\n".join(lines)


def run_solana_checks(target: Path, run_anchor: bool) -> List[str]:
    logs = []
    cargo = shutil.which("cargo")
    if cargo:
        code, out, err = run_cmd([cargo, "clippy", "--", "-D", "warnings"], cwd=target)
        tag = "cargo clippy"
        logs.append(f"`{tag}` exit {code}\nSTDOUT:\n{out}\nSTDERR:\n{err}\n")
    if run_anchor and (target / "Anchor.toml").exists():
        anchor = shutil.which("anchor")
        if anchor:
            code, out, err = run_cmd([anchor, "test", "--skip-build"], cwd=target)
            tag = "anchor test"
            logs.append(f"`{tag}` exit {code}\nSTDOUT:\n{out}\nSTDERR:\n{err}\n")
    return logs


def build_report(
    scope: str,
    chain: str,
    target: Path,
    report_path: Path,
    slither_data: Dict | None,
    solana_logs: List[str] | None,
    extra_notes: List[str],
):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()

    summary_lines = []
    if slither_data:
        for sev in SEVERITY_ORDER:
            count = slither_data["summary"].get(sev, 0)
            summary_lines.append(f"{sev}: {count}")
    else:
        summary_lines.append("自动化摘要：暂无（请参照手动检查清单）")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(
            f"# {scope} Multichain Audit Report\n\n"
            f"生成时间：{timestamp}\n\n"
            f"## 范围概况\n- 目标：{target}\n- 链别：{chain.upper()}\n- 工具：multichain-contract-vuln CLI (v0.1)\n\n"
        )
        f.write("## 自动化摘要\n" + "\\n".join(summary_lines) + "\n\n")

        if slither_data:
            f.write("## Slither 检测详情\n")
            f.write(summarize_findings(slither_data["findings"]))
            f.write("\n\n")

        if solana_logs:
            f.write("## Solana 命令输出\n")
            for log in solana_logs:
                f.write(log + "\n")

        if extra_notes:
            f.write("## 附加说明\n")
            for note in extra_notes:
                f.write(f"- {note}\n")

    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description="multichain-contract-vuln CLI helper")
    parser.add_argument("--input", required=True, help="待分析的合约文件或目录")
    parser.add_argument("--chain", choices=["evm", "solana"], help="目标链别")
    parser.add_argument("--scope", help="报告名称/前缀，默认取输入目录名")
    parser.add_argument(
        "--report",
        help="输出 Markdown 路径（默认 reports/<scope>-multichain-audit.md）",
    )
    parser.add_argument("--slither-bin", help="自定义 slither 可执行路径")
    parser.add_argument("--run-anchor", action="store_true", help="Solana 项目额外执行 anchor test")
    args = parser.parse_args()

    target = Path(args.input).expanduser().resolve()
    if not target.exists():
        print(f"输入路径不存在：{target}", file=sys.stderr)
        return 1

    chain = detect_chain(target, args.chain)
    scope = args.scope or slugify(target.stem if target.is_file() else target.name)
    report_path = Path(args.report).expanduser().resolve() if args.report else Path.cwd() / "reports" / f"{scope}-multichain-audit.md"

    slither_data = None
    solana_logs: List[str] | None = None
    notes: List[str] = []

    if chain == "evm":
        json_path = report_path.with_suffix(".slither.json")
        ok, message = run_slither(target, json_path, args.slither_bin)
        if ok:
            slither_data = parse_slither(json_path)
        else:
            notes.append(message)
        if not slither_data or not slither_data["findings"]:
            notes.append("Slither 未检出高危项，请继续根据 checklist 手动审计。")
    else:
        solana_logs = run_solana_checks(target if target.is_dir() else target.parent, args.run_anchor)
        if not solana_logs:
            notes.append("未运行 cargo/anchor 命令（可能未安装相关工具）。")

    report_file = build_report(scope, chain, target, report_path, slither_data, solana_logs, notes)
    print(f"✅ 报告已生成：{report_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
