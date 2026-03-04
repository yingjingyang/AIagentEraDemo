#!/usr/bin/env python3
"""AI Agent/Skill audit scanner.

Scans OpenClaw config, workspace memory, and log files to surface risk info
around permissions, privacy, token usage, and stability.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import ssl
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore


HOME = Path.home()
CONFIG_PATH = HOME / ".openclaw" / "openclaw.json"
WORKSPACE = HOME / ".openclaw" / "workspace"
MEMORY_DIR = WORKSPACE / "memory"
LOG_DIR = HOME / ".openclaw" / "logs"
DEFAULT_OUTPUT = WORKSPACE / "audit_report.json"

HIGH_RISK_TOOLS = {
    "exec",
    "browser",
    "message",
    "nodes",
    "cron",
    "canvas",
    "gateway",
}
SENSITIVE_PATTERNS = {
    "API Key": re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    "Ethereum Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Mnemonic": re.compile(r"\b(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}\b", re.IGNORECASE),
    "Private Block": re.compile(r"-----BEGIN[\s\w]+PRIVATE KEY-----"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Database URL": re.compile(r"(postgres|mysql|mongodb|redis|mssql)://[^\s]+", re.IGNORECASE),
}
TOKEN_PATTERNS = [
    re.compile(r'"model"\s*:\s*"(?P<model>[^"]+)".*?"totalTokens"\s*:\s*(?P<tokens>\d+)', re.IGNORECASE | re.DOTALL),
    re.compile(r'model=(?P<model>\S+).*?(?:tokens|totalTokens)=(?P<tokens>\d+)', re.IGNORECASE),
]
MNEMONIC_KEYWORDS = ("mnemonic", "seed phrase", "seed", "助记词")


def _fallback_yaml(raw: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def _parse_front_matter(text: str) -> Tuple[Dict[str, Any], str]:
    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return {}, text
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        return {}, text
    front_raw = parts[1]
    body = parts[2]
    manifest: Dict[str, Any] = {}
    if yaml:
        try:
            loaded = yaml.safe_load(front_raw)  # type: ignore[arg-type]
            if isinstance(loaded, dict):
                manifest = loaded
        except Exception:
            manifest = _fallback_yaml(front_raw)
    else:
        manifest = _fallback_yaml(front_raw)
    if not isinstance(manifest, dict):
        manifest = {}
    return manifest, body


def _extract_requirements(meta: Any) -> Tuple[List[str], List[str]]:
    bins: List[str] = []
    env_vars: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            stripped = node.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                except Exception:
                    return
                _walk(parsed)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered in {"bins", "tools"}:
                    if isinstance(value, list):
                        bins.extend(str(item) for item in value)
                    else:
                        bins.append(str(value))
                elif lowered in {"env", "envs", "environment", "variables"}:
                    if isinstance(value, list):
                        env_vars.extend(str(item) for item in value)
                    elif isinstance(value, dict):
                        env_vars.extend(str(k) for k in value.keys())
                    else:
                        env_vars.append(str(value))
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    if isinstance(meta, dict):
        _walk(meta)
    return bins, env_vars


def _score_external_metrics(payload: Dict[str, Any], body: str) -> Dict[str, int]:
    chunks: List[str] = []
    if payload:
        try:
            chunks.append(json.dumps(payload, ensure_ascii=False))
        except Exception:
            chunks.append(str(payload))
    if body:
        chunks.append(body)
    haystack = "\n".join(chunks).lower()

    def _hits(keywords: List[str]) -> int:
        return sum(1 for keyword in keywords if keyword in haystack)

    def _score(base: int, step: int, keywords: List[str], cap: int = 90) -> int:
        return min(cap, base + _hits(keywords) * step)

    privacy_keywords = [
        "private key",
        "mnemonic",
        "seed",
        "api_key",
        "bot_token",
        "secret",
        "wallet_private_key",
        "telegram_bot_token",
    ]
    privilege_keywords = [
        "exec",
        "subprocess",
        "docker",
        "curl",
        "requests",
        "websocket",
        "browser",
        "message",
        "nodes",
        "gateway",
    ]
    memory_keywords = ["log", "history", "persist", "state", "memory"]
    token_keywords = ["openai", "gpt", "llm", "token", "context"]
    failure_keywords = ["kill switch", "retry", "timeout", "exception", "fail", "watchdog", "error"]

    return {
        "privacy": _score(5, 15, privacy_keywords),
        "privilege": _score(15, 10, privilege_keywords),
        "memory": _score(10, 10, memory_keywords),
        "token": _score(10, 10, token_keywords),
        "failure": _score(20, 10, failure_keywords),
    }

    bins: List[str] = []
    env_vars: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            stripped = node.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                except Exception:
                    return
                _walk(parsed)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered in {"bins", "tools"}:
                    if isinstance(value, list):
                        bins.extend(str(item) for item in value)
                    else:
                        bins.append(str(value))
                elif lowered in {"env", "envs", "environment", "variables"}:
                    if isinstance(value, list):
                        env_vars.extend(str(item) for item in value)
                    elif isinstance(value, dict):
                        env_vars.extend(str(k) for k in value.keys())
                    else:
                        env_vars.append(str(value))
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    if isinstance(meta, dict):
        _walk(meta)
    return bins, env_vars


def _load_skill_text_from_path(raw_path: str) -> Tuple[str, str]:
    path = Path(raw_path).expanduser()
    candidate = path
    if path.is_dir():
        candidate = path / "SKILL.md"
    if not candidate.exists():
        raise FileNotFoundError(f"未找到 SKILL.md：{candidate}")
    text = candidate.read_text(encoding="utf-8", errors="ignore")
    return candidate.stem, text


def _fetch_text_from_url(url: str) -> str:
    try:
        context = ssl.create_default_context()
        with urlopen(url, context=context) as resp:  # nosec - 用户指定 URL
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="ignore")
    except Exception:
        proc = subprocess.run(["curl", "-fsSL", url], capture_output=True, text=True)
        if proc.returncode != 0:
            raise URLError(proc.stderr.strip() or "无法通过 curl 获取内容")
        return proc.stdout


def _load_skill_text_from_url(url: str) -> Tuple[str, str]:
    text = _fetch_text_from_url(url)
    name = Path(urlparse(url).path).stem or url
    return name, text


def _analyze_external_skill(name_hint: str, text: str, origin: str) -> Dict[str, Any]:
    manifest, body = _parse_front_matter(text)
    payload = manifest if isinstance(manifest, dict) else {}
    name = payload.get("name") or name_hint or origin
    bins, env_vars = _extract_requirements(payload)
    risk_score, meta_notes = _assess_skill_risk(name, payload)
    notes = [f"未安装 skill · 来源：{origin}"]
    if env_vars:
        unique_env = sorted(set(env_vars))
        notes.append("声明环境变量：" + ", ".join(unique_env))
        risk_score = min(100, risk_score + 5)
    if bins:
        notes.append("依赖工具：" + ", ".join(sorted(set(bins))))
    for label, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(body):
            notes.append(f"正文匹配 {label}")
            risk_score = min(100, risk_score + 5)
    masked: Dict[str, str] = {}
    config_keys: List[str] = []
    if payload:
        for key, value in payload.items():
            config_keys.append(str(key))
            serialized = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
            masked[key] = _mask_value(serialized)
    external_scores = _score_external_metrics(payload, body)
    return {
        "type": "skill",
        "name": name,
        "tools": sorted(set(bins)),
        "highRiskTools": [],
        "skills": None,
        "riskScore": min(100, risk_score),
        "notes": notes + meta_notes,
        "configKeys": config_keys,
        "config": masked,
        "externalScores": external_scores,
    }


def load_external_skills(path_inputs: Optional[List[str]], url_inputs: Optional[List[str]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for raw in path_inputs or []:
        if not raw:
            continue
        try:
            name_hint, text = _load_skill_text_from_path(raw)
            origin = str(Path(raw).expanduser())
            entries.append(_analyze_external_skill(name_hint, text, origin))
        except Exception as exc:
            print(f"⚠️ 无法读取本地 skill {raw}: {exc}", file=sys.stderr)
    for url in url_inputs or []:
        if not url:
            continue
        try:
            name_hint, text = _load_skill_text_from_url(url)
            entries.append(_analyze_external_skill(name_hint, text, url))
        except (URLError, OSError) as exc:
            print(f"⚠️ 无法获取远程 skill {url}: {exc}", file=sys.stderr)
    return entries


def _load_agent_json_from_path(raw_path: str) -> Tuple[str, Any]:
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"未找到 agent JSON：{path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    data = json.loads(text)
    return path.stem, data


def _load_agent_json_from_url(url: str) -> Tuple[str, Any]:
    text = _fetch_text_from_url(url)
    data = json.loads(text)
    name = Path(urlparse(url).path).stem or url
    return name, data


def _normalize_agent_entries(blob: Any) -> List[Tuple[str, Dict[str, Any]]]:
    entries: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(blob, dict):
        agents_section = blob.get("agents")
        if isinstance(agents_section, dict):
            for name, payload in agents_section.items():
                entries.append((str(name), payload or {}))
        else:
            name = str(blob.get("name") or blob.get("agent") or "external-agent")
            entries.append((name, blob))
    return entries


def _analyze_external_agent(name: str, payload: Dict[str, Any], origin: str) -> Dict[str, Any]:
    payload = payload or {}
    tools = _normalize_tools(payload.get("tools", {}))
    skills = payload.get("skills") or []
    high_risk = [tool for tool in tools if tool in HIGH_RISK_TOOLS]
    score = min(100, 15 + 20 * len(high_risk)) if high_risk else 15
    notes = [f"未安装 agent · 来源：{origin}"]
    if skills:
        notes.append("可调用 skills：" + ", ".join(skills))
    description = payload.get("description")
    if description:
        notes.append(str(description))
    if high_risk:
        notes.append("包含高危工具：" + ", ".join(high_risk))
    return {
        "type": "agent",
        "name": name,
        "tools": tools,
        "highRiskTools": high_risk,
        "skills": skills,
        "riskScore": score,
        "notes": notes,
    }


def load_external_agents(path_inputs: Optional[List[str]], url_inputs: Optional[List[str]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def _extend(blob: Any, origin: str) -> None:
        for name, payload in _normalize_agent_entries(blob):
            entries.append(_analyze_external_agent(name, payload, origin))

    for raw in path_inputs or []:
        if not raw:
            continue
        try:
            _, data = _load_agent_json_from_path(raw)
            origin = str(Path(raw).expanduser())
            _extend(data, origin)
        except Exception as exc:
            print(f"⚠️ 无法读取本地 agent {raw}: {exc}", file=sys.stderr)
    for url in url_inputs or []:
        if not url:
            continue
        try:
            _, data = _load_agent_json_from_url(url)
            _extend(data, url)
        except (URLError, OSError, json.JSONDecodeError) as exc:
            print(f"⚠️ 无法获取远程 agent {url}: {exc}", file=sys.stderr)
    return entries


def human_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    for unit in ["KB", "MB", "GB"]:
        num_bytes /= 1024.0
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
    return f"{num_bytes:.2f} TB"


def _warn_perms(path: Path) -> None:
    try:
        stat_info = path.stat()
    except OSError:
        return
    if stat_info.st_mode & 0o077:
        print(f"⚠️  警告：{path} 权限过宽 (建议 600)", file=sys.stderr)


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    _warn_perms(CONFIG_PATH)
    with CONFIG_PATH.open() as f:
        return json.load(f)


def _normalize_tools(value: Any) -> List[str]:
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def _mask_value(value: Any) -> str:
    serialized = str(value)
    if len(serialized) <= 4:
        return "***"
    return f"{serialized[:2]}***{serialized[-2:]}"


def _assess_skill_risk(name: str, payload: Dict[str, Any]) -> Tuple[int, List[str]]:
    base = 15
    notes: List[str] = []
    sensitive_keys = ("key", "secret", "token", "password", "dsn", "api", "private")
    for key, value in payload.items():
        lower_key = key.lower()
        if any(flag in lower_key for flag in sensitive_keys):
            base += 10
            notes.append(f"包含敏感配置: {key}")
        if isinstance(value, str):
            for label, pattern in SENSITIVE_PATTERNS.items():
                if label == "Mnemonic":
                    continue
                if pattern.search(value):
                    base += 5
                    notes.append(f"{key} 匹配 {label}")
                    break
    return min(100, base), notes


def collect_permissions(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    agents = config.get("agents", {})
    for name, payload in agents.items():
        payload = payload or {}
        tools = _normalize_tools(payload.get("tools", {}))
        skills = payload.get("skills") or []
        high_risk = [tool for tool in tools if tool in HIGH_RISK_TOOLS]
        score = min(100, 15 + 20 * len(high_risk)) if high_risk else 15
        entries.append(
            {
                "type": "agent",
                "name": name,
                "tools": tools,
                "highRiskTools": high_risk,
                "skills": skills,
                "riskScore": score,
                "notes": (["包含高危工具：" + ", ".join(high_risk)] if high_risk else []),
            }
        )

    skill_cfg = (config.get("skills") or {}).get("entries", {})
    for name, payload in skill_cfg.items():
        payload = payload or {}
        masked = {key: _mask_value(value) for key, value in payload.items()}
        risk_score, risk_notes = _assess_skill_risk(name, payload)
        entries.append(
            {
                "type": "skill",
                "name": name,
                "tools": _normalize_tools(payload.get("tools", [])),
                "highRiskTools": [],
                "skills": None,
                "riskScore": risk_score,
                "notes": (["已配置凭据"] if payload else []) + risk_notes,
                "configKeys": list(payload.keys()),
                "config": masked,
            }
        )
    return entries


@dataclass
class MemoryIssue:
    path: str
    size_bytes: int
    issues: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": human_size(self.size_bytes),
            "issues": self.issues,
        }


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def scan_memory(directory: Path) -> Dict[str, Any]:
    results: List[MemoryIssue] = []
    total_size = 0
    sensitive_hits = 0
    if not directory.exists():
        return {"totalSize": 0, "files": [], "sensitiveHits": 0}

    base_dir = directory.resolve()
    for path in directory.glob("*.md"):
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if path.is_symlink() or not _is_within(base_dir, resolved):
            continue
        try:
            stat_info = path.stat()
        except OSError:
            continue
        size = stat_info.st_size
        total_size += size
        file_issues: List[str] = []
        counts = {label: 0 for label in SENSITIVE_PATTERNS}
        mnemonic_snippets: List[str] = []
        capture_ttl = 0
        try:
            with path.open("r", errors="ignore") as fh:
                for line in fh:
                    lowered = line.lower()
                    if any(keyword in lowered for keyword in MNEMONIC_KEYWORDS):
                        capture_ttl = 4
                        mnemonic_snippets.append(line)
                    elif capture_ttl > 0:
                        mnemonic_snippets.append(line)
                        capture_ttl -= 1
                    for label, pattern in SENSITIVE_PATTERNS.items():
                        if label == "Mnemonic":
                            continue
                        matches = pattern.findall(line)
                        if matches:
                            count = len(matches)
                            counts[label] += count
                            sensitive_hits += count
        except Exception:
            continue

        if mnemonic_snippets:
            snippet_text = " ".join(mnemonic_snippets)
            matches = SENSITIVE_PATTERNS["Mnemonic"].findall(snippet_text)
            if matches:
                counts["Mnemonic"] += len(matches)
                sensitive_hits += len(matches)

        for label, count in counts.items():
            if count:
                file_issues.append(f"{label} ×{count}")
        if size > 1_000_000:
            file_issues.append("文件超过 1MB，建议归档")
        if file_issues:
            results.append(MemoryIssue(str(path), size, file_issues))
    return {
        "totalSize": total_size,
        "files": [item.to_dict() for item in results],
        "sensitiveHits": sensitive_hits,
    }


def scan_logs_and_tokens(directory: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    log_entries: List[Dict[str, Any]] = []
    total_errors = 0
    total_lines = 0
    token_totals: Dict[str, int] = {}
    if not directory.exists():
        return (
            {"files": [], "errorRate": 0.0, "dataAvailable": False},
            {"totalTokens": 0, "byModel": [], "dataAvailable": False},
        )

    keywords = ("error", "exception", "traceback", "failed")
    for path in directory.glob("*.log"):
        errors = 0
        lines = 0
        try:
            stat_info = path.stat()
            with path.open("r", errors="ignore") as fh:
                for line in fh:
                    lines += 1
                    lower = line.lower()
                    if any(k in lower for k in keywords):
                        errors += 1
                    if "model" in lower:
                        for pattern in TOKEN_PATTERNS:
                            match = pattern.search(line)
                            if match:
                                model = match.group("model")
                                tokens = int(match.group("tokens"))
                                token_totals[model] = token_totals.get(model, 0) + tokens
                                break
        except Exception:
            continue
        total_errors += errors
        total_lines += lines
        log_entries.append(
            {
                "path": str(path),
                "size": human_size(stat_info.st_size),
                "errors": errors,
                "lines": lines,
                "updatedAt": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            }
        )
    rate = total_errors / total_lines if total_lines else 0.0
    total_tokens = sum(token_totals.values())
    per_model = [
        {"model": model, "tokens": count}
        for model, count in sorted(token_totals.items(), key=lambda item: item[1], reverse=True)
    ]
    return (
        {"files": log_entries, "errorRate": rate, "dataAvailable": True},
        {"totalTokens": total_tokens, "byModel": per_model, "dataAvailable": True},
    )


def score_privacy(sensitive_hits: int) -> int:
    if sensitive_hits == 0:
        return 5
    return min(100, 30 + sensitive_hits * 15)


def score_privilege(permissions: List[Dict[str, Any]]) -> int:
    high = sum(len(entry.get("highRiskTools", [])) for entry in permissions if entry["type"] == "agent")
    return min(100, 15 + high * 20) if high else 15


def score_memory(total_size: int) -> int:
    mb = total_size / 1_000_000
    if mb <= 2:
        return 10
    if mb <= 5:
        return 40
    return min(100, 40 + int((mb - 5) * 10))


def score_tokens(total_tokens: int) -> int:
    if total_tokens == 0:
        return 10
    if total_tokens <= 500_000:
        return 35
    return min(100, 35 + int((total_tokens - 500_000) / 50_000))


def score_failures(error_rate: float) -> int:
    return min(100, int(error_rate * 400))


def build_suggestions(report: Dict[str, Any]) -> List[str]:
    suggestions: List[str] = []
    if report["privacyRisk"] > 30:
        suggestions.append("在 memory/ 中查找敏感信息并进行脱敏或迁移到安全存储。")
    if report["privilegeRisk"] > 30:
        suggestions.append("为含 exec/browser 的 Agent 添加操作确认或拆分角色。")
    if report["memoryRisk"] > 40:
        suggestions.append("定期归档 memory 文件（>1MB）并替换为摘要。")
    if report["tokenRisk"] > 35:
        suggestions.append("为高消耗模型设置预算守卫或改用低成本模型。")
    if report["failureRisk"] > 25:
        suggestions.append("检查日志中高频错误，增加重试/超时保护。")
    return suggestions


def generate_report(extra_skills: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    config = load_config()
    permissions = collect_permissions(config)
    if extra_skills:
        permissions.extend(extra_skills)
    memory_info = scan_memory(MEMORY_DIR)
    log_info, token_info = scan_logs_and_tokens(LOG_DIR)

    report = {
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "permissions": permissions,
        "memory": memory_info,
        "logs": log_info,
        "tokens": token_info,
        "externalOnly": bool(extra_skills),
    }
    report["privacyRisk"] = score_privacy(memory_info.get("sensitiveHits", 0))
    report["privilegeRisk"] = score_privilege(permissions)
    report["memoryRisk"] = score_memory(memory_info.get("totalSize", 0))
    report["tokenRisk"] = score_tokens(token_info.get("totalTokens", 0))
    report["failureRisk"] = score_failures(log_info.get("errorRate", 0.0))
    report["suggestions"] = build_suggestions(report)
    return report


def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def save_report(report: Dict[str, Any], output: Path) -> None:
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    _secure_write(output, payload)


def to_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# AI Agent 体检报告",
        f"生成时间：{report['generatedAt']}",
        "",
        "## 风险评分",
        f"- 隐私泄露：{report['privacyRisk']}",
        f"- 越权风险：{report['privilegeRisk']}",
        f"- 记忆膨胀：{report['memoryRisk']}",
        f"- Token 成本：{report['tokenRisk']}",
        f"- 失败率：{report['failureRisk']}",
        "",
        "## 修复建议",
    ]
    if report.get("suggestions"):
        for item in report["suggestions"]:
            lines.append(f"- {item}")
    else:
        lines.append("- 暂无高风险项。")

    lines.extend([
        "",
        "## 权限概览",
        "| 类型 | 名称 | 工具 | 高危 | 备注 |",
        "| --- | --- | --- | --- | --- |",
    ])
    for entry in report["permissions"]:
        lines.append(
            f"| {entry['type']} | {entry['name']} | {', '.join(entry.get('tools', [])) or '-'} | {', '.join(entry.get('highRiskTools', [])) or '-'} | {'; '.join(entry.get('notes', [])) or '-'} |"
        )

    lines.extend([
        "",
        "## 记忆问题",
        "| 文件 | 大小 | 问题 |",
        "| --- | --- | --- |",
    ])
    if report["memory"]["files"]:
        for item in report["memory"]["files"]:
            lines.append(f"| {item['path']} | {item['size']} | {', '.join(item['issues'])} |")
    else:
        lines.append("| - | - | - |")

    lines.extend([
        "",
        "## Token 使用",
        "| 模型 | Tokens |",
        "| --- | --- |",
    ])
    if report["tokens"]["byModel"]:
        for item in report["tokens"]["byModel"]:
            lines.append(f"| {item['model']} | {item['tokens']} |")
    else:
        lines.append("| - | - |")

    lines.extend([
        "",
        "## 日志摘要",
        "| 文件 | 大小 | 错误 | 行数 | 更新时间 |",
        "| --- | --- | --- | --- | --- |",
    ])
    if report["logs"]["files"]:
        for item in report["logs"]["files"]:
            lines.append(
                f"| {item['path']} | {item['size']} | {item['errors']} | {item['lines']} | {item['updatedAt']} |"
            )
    else:
        lines.append("| - | - | - | - | - |")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan OpenClaw workspace for agent/skill risks.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="输出 JSON 报告路径")
    parser.add_argument("--markdown", type=Path, help="可选 Markdown 报告路径")
    parser.add_argument("--skill-path", action="append", default=[], help="未安装 skill 的本地路径 (文件或目录)")
    parser.add_argument("--skill-url", action="append", default=[], help="未安装 skill 的远程 URL")
    parser.add_argument("--agent-path", action="append", default=[], help="未安装 agent 的 JSON 文件或 openclaw.json 片段")
    parser.add_argument("--agent-url", action="append", default=[], help="未安装 agent 的远程 JSON URL")
    args = parser.parse_args()

    extra_skills = load_external_skills(args.skill_path, args.skill_url)
    extra_agents = load_external_agents(args.agent_path, args.agent_url)
    combined = (extra_skills or []) + (extra_agents or [])
    report = generate_report(combined)
    save_report(report, args.output)
    if args.markdown:
        _secure_write(args.markdown, to_markdown(report))
    print(f"✅ 体检完成：JSON -> {args.output.name}")
    if args.markdown:
        print(f"✅ Markdown -> {args.markdown.name}")


if __name__ == "__main__":
    main()
