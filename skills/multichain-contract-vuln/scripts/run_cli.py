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
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib import error as urlerror, request as urlrequest

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
ETHERSCAN_DOMAINS = {
    "mainnet": "api.etherscan.io",
    "goerli": "api-goerli.etherscan.io",
    "sepolia": "api-sepolia.etherscan.io",
}
CHAIN_IDS = {"mainnet": 1, "goerli": 5, "sepolia": 11155111}
SOURCE_EXTS = {".sol", ".vy", ".rs", ".ts", ".tsx", ".js", ".toml", ".json"}


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


def _sanitize_relative_path(rel_path: str) -> Path:
    cleaned = rel_path.replace("\\", "/").lstrip("/")
    path = Path(cleaned)
    # 防止 .. 逃逸
    sanitized = Path()
    for part in path.parts:
        if part in {"..", ""}:
            continue
        sanitized /= part
    return sanitized if str(sanitized) else Path("Contract.sol")


def _parse_etherscan_sources(raw: str, contract_name: str) -> Dict[str, str]:
    if not raw:
        return {}
    blob = raw.strip()
    if blob.startswith("{{") and blob.endswith("}}"):
        blob = blob[1:-1]
    try:
        parsed = json.loads(blob)
        if isinstance(parsed, list) and parsed:
            parsed = parsed[0]
        if isinstance(parsed, dict):
            sources = parsed.get("sources")
            if isinstance(sources, dict):
                result: Dict[str, str] = {}
                for rel, meta in sources.items():
                    content = meta.get("content") if isinstance(meta, dict) else None
                    if content:
                        result[str(_sanitize_relative_path(rel))] = content
                if result:
                    return result
            if "SourceCode" in parsed and isinstance(parsed["SourceCode"], str):
                return {f"{contract_name or 'Contract'}.sol": parsed["SourceCode"]}
    except json.JSONDecodeError:
        pass
    return {f"{contract_name or 'Contract'}.sol": blob}


def fetch_from_etherscan(address: str, network: str, api_key: str | None) -> Dict[str, str]:
    if not api_key:
        return {}
    domain = ETHERSCAN_DOMAINS.get(network, ETHERSCAN_DOMAINS["mainnet"])
    url = (
        f"https://{domain}/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}"
    )
    try:
        with urlrequest.urlopen(url, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}
    if payload.get("status") != "1":
        return {}
    result = payload.get("result") or []
    if not result:
        return {}
    entry = result[0]
    return _parse_etherscan_sources(entry.get("SourceCode", ""), entry.get("ContractName", ""))


def fetch_from_sourcify(address: str, network: str) -> Dict[str, str]:
    chain_id = CHAIN_IDS.get(network, 1)
    buckets = ["full_match", "partial_match"]
    for bucket in buckets:
        base = f"https://repo.sourcify.dev/contracts/{bucket}/{chain_id}/{address}/"
        metadata_url = base + "metadata.json"
        try:
            with urlrequest.urlopen(metadata_url, timeout=15) as resp:
                metadata = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
        sources = metadata.get("sources")
        if not isinstance(sources, dict):
            continue
        result: Dict[str, str] = {}
        for rel, meta in sources.items():
            content = meta.get("content") if isinstance(meta, dict) else None
            if not content:
                continue
            result[str(_sanitize_relative_path(rel))] = content
        if result:
            return result
    return {}


def download_onchain_sources(address: str, network: str, api_key: str | None) -> Tuple[Path | None, str | None]:
    normalized = address.strip()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    normalized = normalized.lower()
    tmp_root = Path(tempfile.mkdtemp(prefix="multichain-evm-"))
    dest_dir = tmp_root / normalized.replace("0x", "")
    etherscan_sources = fetch_from_etherscan(normalized, network, api_key)
    sources = etherscan_sources or fetch_from_sourcify(normalized, network)
    if not sources:
        return None, None
    for rel, content in sources.items():
        path = dest_dir / _sanitize_relative_path(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return dest_dir, f"链上地址 {normalized} 的源码已下载到 {dest_dir}"


def _collect_source_files(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    files: List[Path] = []
    for ext in SOURCE_EXTS:
        files.extend(sorted(target.rglob(f"*{ext}")))
    return files[:100]


def bundle_sources(target: Path, bundle_path: Path) -> Optional[str]:
    sources = _collect_source_files(target)
    if not sources:
        return None
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    with open(bundle_path, "w", encoding="utf-8") as fh:
        fh.write("# Contract Sources Bundle\n\n")
        for path in sources:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            language = path.suffix.lstrip('.') or 'txt'
            fh.write(f"## {path}\n")
            fh.write(f"```{language}\n{text}\n```\n\n")
    return f"源码聚合文件：{bundle_path}（共 {len(sources)} 个文件）"


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
    parser.add_argument("--input", help="待分析的合约文件或目录")
    parser.add_argument("--evm-address", help="链上 EVM 合约地址（自动下载源码）")
    parser.add_argument("--network", default="mainnet", help="EVM 网络：mainnet/goerli/sepolia，默认 mainnet")
    parser.add_argument("--etherscan-api-key", help="Etherscan API Key（默认读取环境变量）")
    parser.add_argument("--chain", choices=["evm", "solana"], help="目标链别")
    parser.add_argument("--scope", help="报告名称/前缀，默认取输入目录名")
    parser.add_argument(
        "--report",
        help="输出 Markdown 路径（默认 reports/<scope>-multichain-audit.md）",
    )
    parser.add_argument("--slither-bin", help="自定义 slither 可执行路径")
    parser.add_argument("--auto-static", action="store_true", help="启用本地静态分析（默认关闭，以便改用 AI 审计）")
    parser.add_argument("--run-anchor", action="store_true", help="Solana 项目额外执行 anchor test（需同时开启 --auto-static）")
    parser.add_argument("--bundle", type=Path, help="把源码聚合输出到 Markdown，便于 AI 审计")
    args = parser.parse_args()

    notes: List[str] = []
    target: Path | None = None
    if args.input:
        target = Path(args.input).expanduser().resolve()
        if not target.exists():
            print(f"输入路径不存在：{target}", file=sys.stderr)
            return 1
    elif args.evm_address:
        api_key = args.etherscan_api_key or os.getenv("ETHERSCAN_API_KEY")
        fetched_dir, fetch_note = download_onchain_sources(args.evm_address, args.network.lower(), api_key)
        if not fetched_dir:
            print("❌ 无法从链上获取源码（请确认地址已验证或配置 Etherscan/Sourcify）", file=sys.stderr)
            return 1
        target = fetched_dir
        if fetch_note:
            notes.append(fetch_note)
    else:
        print("必须提供 --input 或 --evm-address", file=sys.stderr)
        return 1

    chain_hint = args.chain or ("evm" if args.evm_address else None)
    chain = detect_chain(target, chain_hint)
    scope = args.scope or slugify(target.stem if target.is_file() else target.name)
    report_path = Path(args.report).expanduser().resolve() if args.report else Path.cwd() / "reports" / f"{scope}-multichain-audit.md"
    bundle_path = (
        Path(args.bundle).expanduser().resolve()
        if args.bundle
        else Path.cwd() / "reports" / f"{scope}-sources.md"
    )

    slither_data = None
    solana_logs: List[str] | None = None

    bundle_note = bundle_sources(target, bundle_path)
    if bundle_note:
        notes.append(bundle_note)
    else:
        notes.append("未生成源码聚合（未检测到支持的源码后缀）")

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
