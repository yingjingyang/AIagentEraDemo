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
from datetime import datetime, timezone
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
DEFAULT_OUTPUT: Path | None = None

HIGH_RISK_TOOLS = {
    "exec",
    "browser",
    "message",
    "nodes",
    "cron",
    "canvas",
    "gateway",
}

HIGH_RISK_KEYWORDS = {
    "exec": ("subprocess", "os.system", "Popen(", "run_cmd(", "shlex"),
    "browser": ("playwright", "selenium", "browser."),
    "message": ("message.", "send_message", "message.send"),
    "nodes": ("nodes.", "node_client", "node.run"),
    "cron": ("schedule.", "cron", "apscheduler"),
    "canvas": ("canvas.", "canvas_"),
    "gateway": ("urlopen", "requests", "httpx", "aiohttp", "websocket", "socket.create_connection"),
}

TOOL_REMEDIATION_HINTS = {
    "exec": "Require manual approval or sandboxing before running subprocess/CLI commands (e.g., slither, forge).",
    "gateway": "Restrict outbound HTTP calls to allowlisted endpoints (e.g., Etherscan/Sourcify) and redact secrets.",
    "browser": "Limit headless browser access to trusted origins and rotate credentials.",
    "message": "Scope messaging actions to approved channels and add rate limits.",
    "nodes": "Validate node instructions and pin allowed commands for remote devices.",
    "cron": "Document scheduled actions and enforce owner acknowledgement before enabling cron jobs.",
    "canvas": "Restrict canvas interactions to non-sensitive dashboards and require read-only mode when possible.",
}

TOOL_REMEDIATION_HINTS_ZH = {
    "exec": "在运行 subprocess/CLI（如 slither、forge）前增加人工审批或沙箱隔离。",
    "gateway": "将外部 HTTP 请求限制在允许的端点（如 Etherscan/Sourcify）并做好脱敏。",
    "browser": "将浏览器自动化限制在可信域名，并定期轮换凭据。",
    "message": "仅允许向批准的频道发送消息，并加上频率限制。",
    "nodes": "校验节点指令，只允许预设的远端命令。",
    "cron": "记录所有定时任务并在启用前获得负责人确认。",
    "canvas": "仅对非敏感 Dashboard 使用 canvas，必要时改为只读模式。",
}
TEXT_PATTERN_DEFS = {
    "API Key": re.compile(r"(api[_-]?key|apikey)[\s:=]+['\"][A-Za-z0-9]{20,}['\"]", re.IGNORECASE),
    "Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Mnemonic": re.compile(r"(mnemonic|seed phrase)[^\n]*\b(\w+\s+){11,23}\w+\b", re.IGNORECASE),
    "Personal Info": re.compile(r"(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"),
    "Password": re.compile(r"(password|passwd|pwd)[\s:=]+['\"][^'\"]{8,}['\"]", re.IGNORECASE),
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


def detect_high_risk_tools_from_path(base_path: Optional[Path]) -> Tuple[List[str], Dict[str, List[Tuple[str, str]]]]:
    if base_path is None or not base_path.exists():
        return [], {}
    base_dir = base_path if base_path.is_dir() else base_path.parent
    findings: Dict[str, Set[Tuple[str, str]]] = {}
    for pattern in ("*.py", "*.ts", "*.js", "*.sh"):
        for candidate in base_dir.rglob(pattern):
            if candidate.is_dir() or candidate.stat().st_size > 500_000:
                continue
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lowered = text.lower()
            rel_path = str(candidate.relative_to(base_dir))
            for tool, keywords in HIGH_RISK_KEYWORDS.items():
                for keyword in keywords:
                    if keyword.lower() in lowered:
                        findings.setdefault(tool, set()).add((rel_path, keyword))
                        break
    detected = sorted(findings.keys())
    detail_map = {tool: sorted(list(values)) for tool, values in findings.items()}
    return detected, detail_map


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
        raise FileNotFoundError(f"SKILL.md not found: {candidate}")
    text = candidate.read_text(encoding="utf-8", errors="ignore")
    return candidate.stem, text


def _fetch_text_from_url(url: str) -> str:
    try:
        context = ssl.create_default_context()
        with urlopen(url, context=context) as resp:  # nosec - user-supplied URL
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="ignore")
    except Exception:
        proc = subprocess.run(["curl", "-fsSL", url], capture_output=True, text=True)
        if proc.returncode != 0:
            raise URLError(proc.stderr.strip() or "Unable to fetch content via curl")
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
    notes: List[str] = []
    try:
        origin_path = Path(origin).expanduser()
        origin_path_str = str(origin_path) if origin_path.exists() else None
    except Exception:
        origin_path = None
        origin_path_str = None
    detected_high_risk, high_risk_details = detect_high_risk_tools_from_path(origin_path)
    if origin_path_str:
        notes.append(f"Local skill path: {origin_path_str}")
    else:
        notes.append(f"External skill source: {origin}")
    if detected_high_risk:
        risk_score = max(risk_score, 40 + 15 * (len(detected_high_risk) - 1))
    if env_vars:
        unique_env = sorted(set(env_vars))
        notes.append("Environment variables: " + ", ".join(unique_env))
        risk_score = min(100, risk_score + 5)
    if bins:
        notes.append("CLI dependencies: " + ", ".join(sorted(set(bins))))
    for label, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(body):
            notes.append(f"Body matches {label}")
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
        "highRiskTools": detected_high_risk,
        "skills": None,
        "riskScore": min(100, risk_score),
        "notes": notes + meta_notes,
        "configKeys": config_keys,
        "config": masked,
        "externalScores": external_scores,
        "highRiskDetails": high_risk_details,
        "originPath": origin_path_str,
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
            print(f"⚠️ Unable to read local skill {raw}: {exc}", file=sys.stderr)
    for url in url_inputs or []:
        if not url:
            continue
        try:
            name_hint, text = _load_skill_text_from_url(url)
            entries.append(_analyze_external_skill(name_hint, text, url))
        except (URLError, OSError) as exc:
            print(f"⚠️ Unable to fetch remote skill {url}: {exc}", file=sys.stderr)
    return entries


def _load_agent_json_from_path(raw_path: str) -> Tuple[str, Any]:
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Agent JSON not found: {path}")
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
    notes = [f"External agent source: {origin}"]
    if skills:
        notes.append("Accessible skills: " + ", ".join(skills))
    description = payload.get("description")
    if description:
        notes.append(str(description))
    if high_risk:
        notes.append("Includes high-risk tools: " + ", ".join(high_risk))
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
            print(f"⚠️ Unable to read local agent {raw}: {exc}", file=sys.stderr)
    for url in url_inputs or []:
        if not url:
            continue
        try:
            _, data = _load_agent_json_from_url(url)
            _extend(data, url)
        except (URLError, OSError, json.JSONDecodeError) as exc:
            print(f"⚠️ Unable to fetch remote agent {url}: {exc}", file=sys.stderr)
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
        print(f"⚠️ Warning: {path} permissions are too broad (recommended 600)", file=sys.stderr)


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
            notes.append(f"Sensitive config key detected: {key}")
        if isinstance(value, str):
            for label, pattern in SENSITIVE_PATTERNS.items():
                if label == "Mnemonic":
                    continue
                if pattern.search(value):
                    base += 5
                    notes.append(f"{key} matches {label}")
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
                "notes": (["Includes high-risk tools: " + ", ".join(high_risk)] if high_risk else []),
            }
        )

    skill_cfg = (config.get("skills") or {}).get("entries", {})
    for name, payload in skill_cfg.items():
        payload = payload or {}
        masked = {key: _mask_value(value) for key, value in payload.items()}
        risk_score, risk_notes = _assess_skill_risk(name, payload)
        tool_list = _normalize_tools(payload.get("tools", []))
        high_risk = [tool for tool in tool_list if tool in HIGH_RISK_TOOLS]
        entries.append(
            {
                "type": "skill",
                "name": name,
                "tools": tool_list,
                "highRiskTools": high_risk,
                "skills": None,
                "riskScore": risk_score,
                "notes": (["Configured credentials detected"] if payload else []) + risk_notes,
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
    pattern_hits: List[Dict[str, str]] = []
    if not directory.exists():
        return {"totalSize": 0, "files": [], "sensitiveHits": 0, "dataAvailable": False, "patternHits": []}

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
                    matched_labels = _scan_patterns_in_line(line, path, pattern_hits)
                    if matched_labels:
                        sensitive_hits += len(matched_labels)
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
        "patternHits": pattern_hits,
        "dataAvailable": True,
    }


def scan_logs_and_tokens(directory: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    log_entries: List[Dict[str, Any]] = []
    total_errors = 0
    total_lines = 0
    token_totals: Dict[str, int] = {}
    pattern_hits: List[Dict[str, str]] = []
    if not directory.exists():
        return (
            {"files": [], "errorRate": 0.0, "dataAvailable": False, "patternHits": [], "sensitiveHits": 0},
            {"totalTokens": 0, "byModel": [], "dataAvailable": False},
        )

    keywords = ("error", "exception", "traceback", "failed")
    for path in directory.glob("*.log"):
        errors = 0
        lines = 0
        try:
            stat_info = path.stat()
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
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
                    _scan_patterns_in_line(line, path, pattern_hits)
        except Exception:
            continue
        total_errors += errors
        total_lines += lines
        log_entries.append(
            {
                "path": str(path),
                "size": human_size(stat_info.st_size),
                "sizeBytes": stat_info.st_size,
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
    log_info = {
        "files": log_entries,
        "errorRate": rate,
        "dataAvailable": True,
        "patternHits": pattern_hits,
        "sensitiveHits": len(pattern_hits),
    }
    token_info = {"totalTokens": total_tokens, "byModel": per_model, "dataAvailable": True}
    return log_info, token_info


def score_privacy(sensitive_hits: int) -> int:
    if sensitive_hits == 0:
        return 0
    return min(100, 40 + (sensitive_hits - 1) * 15)


def score_privilege(permissions: List[Dict[str, Any]]) -> int:
    high = sum(len(entry.get("highRiskTools", [])) for entry in permissions)
    if high == 0:
        return 0
    return min(100, 40 + (high - 1) * 15)


def score_memory(total_size: int) -> int:
    mb = total_size / 1_000_000
    if mb <= 2:
        return 0
    if mb <= 5:
        return 40
    return min(100, 40 + int((mb - 5) * 10))


def score_tokens(total_tokens: int) -> int:
    if total_tokens == 0:
        return 0
    if total_tokens <= 500_000:
        return 35
    return min(100, 35 + int((total_tokens - 500_000) / 50_000))


def score_failures(error_rate: float) -> int:
    if error_rate == 0:
        return 0
    return min(100, 40 + int(error_rate * 400))


def build_suggestions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions: List[Dict[str, Any]] = []
    memory_block = report.get("memory", {})
    memory_files = memory_block.get("files", [])
    if memory_files:
        focus = [
            {"path": item["path"], "issues": item.get("issues", [])}
            for item in memory_files[:3]
        ]
        suggestions.append({"type": "memory_sensitive", "files": focus})
    elif report["privacyRisk"] > 0 and not memory_block.get("dataAvailable", True):
        suggestions.append({"type": "memory_missing"})

    permissions = report.get("permissions", [])
    for entry in permissions:
        risky = entry.get("highRiskTools") or []
        for tool in risky:
            suggestions.append({"type": "tool", "skill": entry["name"], "tool": tool})

    total_size = memory_block.get("totalSize", 0)
    if report["memoryRisk"] > 0 and total_size:
        suggestions.append({"type": "memory_size", "size": total_size})

    token_block = report.get("tokens", {})
    models = token_block.get("byModel", [])
    if report["tokenRisk"] > 0 and models:
        top = models[0]
        suggestions.append({"type": "token", "model": top["model"], "tokens": top["tokens"]})

    log_block = report.get("logs", {})
    logs = log_block.get("files", [])
    if report["failureRisk"] > 0 and logs:
        worst = max(logs, key=lambda item: item.get("errors", 0))
        if worst.get("errors"):
            suggestions.append(
                {
                    "type": "log_errors",
                    "path": worst["path"],
                    "errors": worst["errors"],
                    "lines": worst["lines"],
                }
            )

    if not suggestions:
        suggestions.append({"type": "none"})
    return suggestions


def _translate_warning(message: str, lang: str) -> str:
    if lang != "zh":
        return message
    mapping = {
        "memory/ directory not found; skipped memory scan": "未检测到 memory/ 目录，已跳过记忆扫描",
        "memory/ directory not found; unable to audit persistence.": "未检测到 memory/ 目录，无法审计持久化内容",
        "logs/ directory not found; failure rate assumed 0": "未检测到 logs/ 目录，失败率按 0 处理",
        "logs/ directory is empty; failure rate assumed 0": "logs/ 目录为空，失败率按 0 处理",
        "logs/ directory not found; failure rate unavailable.": "未检测到 logs/ 目录，无法计算失败率",
        "Log files missing tokenUsage metadata; token cost set to 0": "日志缺少 tokenUsage 信息，Token 成本按 0 处理",
        "Token usage data missing from logs.": "日志缺少 tokenUsage 数据，无法统计。",
    }
    return mapping.get(message, message)


def _translate_note(note: str, lang: str) -> str:
    if lang != "zh":
        return note
    replacements = {
        "Local skill path:": "本地 Skill 路径：",
        "External skill source:": "外部 Skill 来源：",
        "Detected high-risk tools:": "检测到高危权限：",
        "Environment variables:": "声明的环境变量：",
        "CLI dependencies:": "依赖工具：",
        "Body matches": "正文匹配",
        "Sensitive config key detected:": "检测到敏感配置键：",
        "Configured credentials detected": "检测到已配置的凭据",
    }
    for eng, zh in replacements.items():
        if note.startswith(eng):
            return note.replace(eng, zh, 1)
    return note


def _render_suggestions(suggestions: List[Dict[str, Any]], lang: str) -> List[str]:
    rendered: List[str] = []
    for item in suggestions:
        stype = item.get("type")
        if stype == "memory_sensitive":
            files = item.get("files", [])
            summary = "; ".join(
                f"{Path(entry['path']).name} ({', '.join(entry.get('issues', []))})" for entry in files
            )
            if lang == "zh":
                rendered.append(f"清理以下 memory 文件中的敏感内容：{summary}")
            else:
                rendered.append(f"Scrub or relocate sensitive content in: {summary}")
        elif stype == "memory_missing":
            rendered.append(
                "请创建 memory/ 目录以启用隐私扫描。" if lang == "zh" else "Provide a memory/ directory so privacy scans can run."
            )
        elif stype == "tool":
            tool = item.get("tool", "-")
            skill = item.get("skill", "skill")
            hint = (
                TOOL_REMEDIATION_HINTS_ZH.get(tool, f"为 {tool} 增加防护。")
                if lang == "zh"
                else TOOL_REMEDIATION_HINTS.get(tool, f"Add guardrails before invoking {tool}.")
            )
            rendered.append(f"{skill} – {hint}")
        elif stype == "memory_size":
            size_text = human_size(item.get("size", 0))
            rendered.append(
                f"memory/ 总大小约 {size_text}，建议归档或压缩超 1MB 的文件。"
                if lang == "zh"
                else f"Memory footprint is {size_text}; archive or summarize files over 1MB."
            )
        elif stype == "token":
            model = item.get("model")
            tokens = item.get("tokens")
            rendered.append(
                f"模型 {model} 最近消耗 {tokens} tokens，建议设置预算或改用低成本模型。"
                if lang == "zh"
                else f"Model {model} consumed {tokens} tokens recently; enforce budgets or switch to cheaper models."
            )
        elif stype == "log_errors":
            path = item.get("path")
            errors = item.get("errors")
            lines = item.get("lines")
            rendered.append(
                f"{path} 记录 {errors} 个错误 / {lines} 行日志，建议排查并加上重试/超时。"
                if lang == "zh"
                else f"{path} logged {errors} errors across {lines} lines; investigate and add retries/timeouts."
            )
        elif stype == "none":
            rendered.append("暂无需要整改的项目。" if lang == "zh" else "No remediation required based on current telemetry.")
    return rendered


def _render_pattern_table(hits: List[Dict[str, str]], lang: str, title_en: str, title_zh: str) -> List[str]:
    if not hits:
        return []
    lines = ["", title_zh if lang == "zh" else title_en]
    if lang == "zh":
        lines.append("| 类型 | 文件 | 内容 |")
        lines.append("| --- | --- | --- |")
    else:
        lines.append("| Pattern | File | Snippet |")
        lines.append("| --- | --- | --- |")
    for hit in hits:
        lines.append(f"| {hit['label']} | {hit['path']} | {hit['line']} |")
    return lines


def _scan_patterns_in_line(line: str, path: Path, hits: List[Dict[str, str]]) -> List[str]:
    labels: List[str] = []
    for label, regex in TEXT_PATTERN_DEFS.items():
        if regex.search(line):
            snippet = line.strip()
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            hits.append({"label": label, "path": str(path), "line": snippet})
            labels.append(label)
    return labels


def scan_skill_logs(skill_path: Path, limit: int = 20) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    count = 0
    for log_file in sorted(skill_path.rglob("*.log")):
        if count >= limit:
            break
        try:
            if log_file.stat().st_size > 1_000_000:
                continue
            with log_file.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    _scan_patterns_in_line(line, log_file, hits)
        except Exception:
            continue
        count += 1
    return hits


def _build_skill_bundle(paths: List[Path], max_files: int = 20, max_chars: int = 12000) -> str:
    collected: List[str] = []
    remaining = max_chars
    files: List[Path] = []
    for base in paths:
        if not base.exists():
            continue
        candidates = []
        skill_md = base / "SKILL.md"
        if skill_md.exists():
            candidates.append(skill_md)
        for pattern in ("scripts/**/*", "references/**/*", "*.py", "*.md"):
            candidates.extend(sorted(base.glob(pattern)))
        for candidate in candidates:
            if candidate.is_dir() or candidate in files or candidate.suffix in {".log", ""}:
                continue
            files.append(candidate)
            if len(files) >= max_files:
                break
        if len(files) >= max_files:
            break
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        snippet = text.strip()
        if len(snippet) > remaining:
            snippet = snippet[: remaining - 3] + "..."
        collected.append(f"### {file_path}\n{snippet}")
        remaining -= len(snippet)
        if remaining <= 0:
            break
    return "\n\n".join(collected)


def run_ai_review(skill_entries: List[Dict[str, Any]], model: str, lang: str) -> Dict[str, Any]:
    paths = []
    for entry in skill_entries or []:
        origin = entry.get("originPath")
        if origin:
            p = Path(origin)
            if p.exists():
                paths.append(p)
    if not paths:
        return {"status": "skipped", "reason": "no local skill paths"}
    try:
        from openai import OpenAI
    except Exception as exc:
        return {"status": "error", "reason": f"openai package missing: {exc}"}
    if not os.getenv("OPENAI_API_KEY"):
        return {"status": "error", "reason": "OPENAI_API_KEY not set"}
    bundle = _build_skill_bundle(paths)
    if not bundle:
        return {"status": "skipped", "reason": "skill files empty"}
    client = OpenAI()
    system_prompt = (
        "You are a security auditor. Review provided skill files and list potential risks, sensitive data, or bad practices."
        if lang != "zh"
        else "你是一名安全审计员，请审查提供的 Skill 文件，指出潜在风险、敏感信息或不当做法。"
    )
    user_prompt = (
        "Summarize risks and actionable fixes for the following skill contents:\n\n"
        if lang != "zh"
        else "请审查以下 Skill 内容并用中文给出风险与修复建议：\n\n"
    ) + bundle
    try:
        response = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
        )
        summary = getattr(response, "output_text", "")
        if not summary:
            try:
                summary = response.output[0]["content"][0]["text"]  # type: ignore[index]
            except Exception:
                summary = ""
        return {"status": "ok", "model": model, "summary": summary or "(empty response)"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def _risk_label(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _select_logs(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not entries:
        return []
    focus = [entry for entry in entries if entry.get("errors", 0) > 0 or entry.get("sizeBytes", 0) >= 500_000]
    if not focus:
        focus = sorted(entries, key=lambda item: item.get("sizeBytes", 0), reverse=True)[:3]
    return focus


def generate_report(
    extra_skills: Optional[List[Dict[str, Any]]] = None,
    extra_agents: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    skills = extra_skills or []
    agents = extra_agents or []
    config = load_config()
    permissions = collect_permissions(config)
    combined = []
    if skills:
        combined.extend(skills)
    if agents:
        combined.extend(agents)
    if combined:
        permissions.extend(combined)

    memory_info = scan_memory(MEMORY_DIR)
    log_info, token_info = scan_logs_and_tokens(LOG_DIR)

    skill_log_hits: List[Dict[str, str]] = []
    for entry in skills:
        origin = entry.get("originPath")
        if origin:
            origin_path = Path(origin)
            if origin_path.exists():
                skill_log_hits.extend(scan_skill_logs(origin_path))

    log_sensitive_hits = log_info.get("sensitiveHits", 0) + len(skill_log_hits)
    privacy_hits = memory_info.get("sensitiveHits", 0) + log_sensitive_hits

    report = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "permissions": permissions,
        "memory": memory_info,
        "logs": log_info,
        "tokens": token_info,
        "externalOnly": bool(combined),
        "skillLogHits": skill_log_hits,
    }
    report["privacyRisk"] = score_privacy(privacy_hits)
    report["privilegeRisk"] = score_privilege(permissions)
    report["memoryRisk"] = score_memory(memory_info.get("totalSize", 0))
    report["tokenRisk"] = score_tokens(token_info.get("totalTokens", 0))
    report["failureRisk"] = score_failures(log_info.get("errorRate", 0.0))

    warnings: List[str] = []
    if not memory_info.get("dataAvailable", True):
        warnings.append("memory/ directory not found; skipped memory scan")
    if not log_info.get("dataAvailable", True):
        warnings.append("logs/ directory not found; failure rate assumed 0")
    elif not log_info.get("files"):
        warnings.append("logs/ directory is empty; failure rate assumed 0")
    if not token_info.get("dataAvailable", True):
        warnings.append("Log files missing tokenUsage metadata; token cost set to 0")
    report["warnings"] = warnings

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


def to_markdown(report: Dict[str, Any], lang: str = "en") -> str:
    lang = lang if lang == "zh" else "en"
    title = "# 技能安全体检报告" if lang == "zh" else "# Skill Security Audit Report"
    generated_label = "生成时间" if lang == "zh" else "Generated"
    risk_header = "## 风险评分" if lang == "zh" else "## Risk Scores"
    rec_header = "## 修复建议" if lang == "zh" else "## Recommendations"
    warn_header = "## 告警" if lang == "zh" else "## Warnings"
    perm_header = "## 权限概览" if lang == "zh" else "## Permission Overview"
    memory_header = "## 记忆问题" if lang == "zh" else "## Memory Findings"
    token_header = "## Token 使用" if lang == "zh" else "## Token Usage"
    log_header = "## 日志摘要" if lang == "zh" else "## Log Summary"

    def add_pattern_section(hits: Optional[List[Dict[str, str]]], title_zh: str, title_en: str) -> None:
        if not hits:
            return
        header = title_zh if lang == "zh" else title_en
        lines.extend([
            "",
            header,
            "| Pattern | File | Snippet |" if lang != "zh" else "| 类型 | 文件 | 片段 |",
            "| --- | --- | --- |",
        ])
        for hit in hits[:50]:
            lines.append(
                "| {label} | {path} | {line} |".format(
                    label=hit.get("label", "-"),
                    path=hit.get("path", "-"),
                    line=hit.get("line", "-"),
                )
            )

    lines = [title, f"{generated_label}：{report['generatedAt']}", "", risk_header]
    if lang == "zh":
        lines.extend([
            f"- 隐私风险：{report['privacyRisk']}",
            f"- 权限风险：{report['privilegeRisk']}",
            f"- 记忆膨胀：{report['memoryRisk']}",
            f"- Token 成本：{report['tokenRisk']}",
            f"- 失败率：{report['failureRisk']}",
            "> 评分说明：0-30=低，31-60=中，>60=高",
        ])
    else:
        lines.extend([
            f"- Privacy: {report['privacyRisk']}",
            f"- Privilege: {report['privilegeRisk']}",
            f"- Memory Footprint: {report['memoryRisk']}",
            f"- Token Cost: {report['tokenRisk']}",
            f"- Failure Rate: {report['failureRisk']}",
            "> Score legend: 0-30 = Low, 31-60 = Medium, >60 = High",
        ])

    lines.append("")
    lines.append(rec_header)
    suggestion_lines = _render_suggestions(report.get("suggestions", []), lang)
    for text_line in suggestion_lines:
        lines.append(f"- {text_line}")

    warnings = report.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append(warn_header)
        for warn in warnings:
            lines.append(f"- ⚠️ { _translate_warning(warn, lang)}")

    perm_columns = (
        "| 类型 | 名称 | 高危权限 | 风险等级 | 备注 |"
        if lang == "zh"
        else "| Type | Name | High-Risk Tools | Risk Level | Notes |"
    )
    lines.extend(["", perm_header, perm_columns, "| --- | --- | --- | --- | --- |"])
    level_map = {"High": "高", "Medium": "中", "Low": "低"}
    for entry in (item for item in report["permissions"] if item.get("type") == "skill"):
        high_values = entry.get("highRiskTools") or ["-"]
        base_notes = [_translate_note(note, lang) for note in entry.get("notes", [])]
        detail_map = entry.get("highRiskDetails", {})
        first_tool = True
        for tool in high_values:
            tool_notes: List[str] = []
            if first_tool and base_notes:
                tool_notes.extend(base_notes)
            details = detail_map.get(tool, [])
            if details:
                joined = "; ".join(
                    f"{path}（关键字：{keyword}）" if lang == "zh" else f"{path} (keyword: {keyword})"
                    for path, keyword in details
                )
                prefix = "匹配文件：" if lang == "zh" else "Matched files: "
                tool_notes.append(prefix + joined)
            notes_text = "; ".join(tool_notes) or "-"
            level = _risk_label(entry.get("riskScore", 0))
            if lang == "zh":
                level = level_map.get(level, level)
            lines.append(
                "| {type} | {name} | {high} | {level} | {notes} |".format(
                    type=entry["type"],
                    name=entry["name"],
                    high=tool,
                    level=level,
                    notes=notes_text,
                )
            )
            first_tool = False

    memory_block = report.get("memory", {})
    if memory_block.get("files"):
        memory_columns = (
            "| 文件 | 大小 | 问题 |" if lang == "zh" else "| File | Size | Issues |"
        )
        lines.extend(["", memory_header, memory_columns, "| --- | --- | --- |"])
        for item in memory_block["files"]:
            issues = ", ".join(item.get("issues", []))
            lines.append(f"| {item['path']} | {item['size']} | {issues} |")
    elif not memory_block.get("dataAvailable", True):
        note = "memory/ directory not found; unable to audit persistence."
        lines.extend(["", memory_header, f"> ⚠️ {_translate_warning(note, lang)}"])

    add_pattern_section(memory_block.get("patternHits"), "## 记忆敏感匹配", "## Memory Pattern Hits")

    token_block = report.get("tokens", {})
    if token_block.get("byModel"):
        token_columns = "| 模型 | Tokens |" if lang == "zh" else "| Model | Tokens |"
        lines.extend(["", token_header, token_columns, "| --- | --- |"])
        for item in token_block.get("byModel", []):
            lines.append(f"| {item['model']} | {item['tokens']} |")
    elif not token_block.get("dataAvailable", True):
        lines.extend(["", token_header, f"> ⚠️ {_translate_warning('Token usage data missing from logs.', lang)}"])

    log_block = report.get("logs", {})
    if log_block.get("dataAvailable", True) and log_block.get("files"):
        filtered_logs = _select_logs(log_block["files"])
        if filtered_logs:
            log_columns = (
                "| 文件 | 大小 | 错误 | 行数 | 更新时间 |"
                if lang == "zh"
                else "| File | Size | Errors | Lines | Updated At |"
            )
            lines.extend(["", log_header, log_columns, "| --- | --- | --- | --- | --- |"])
            for item in filtered_logs:
                lines.append(
                    f"| {item['path']} | {item['size']} | {item['errors']} | {item['lines']} | {item['updatedAt']} |"
                )
    elif not log_block.get("dataAvailable", True):
        lines.extend(["", log_header, f"> ⚠️ {_translate_warning('logs/ directory not found; failure rate unavailable.', lang)}"])

    add_pattern_section(log_block.get("patternHits"), "## 日志敏感匹配", "## Log Pattern Hits")
    add_pattern_section(report.get("skillLogHits"), "## Skill 日志敏感匹配", "## Skill Log Pattern Hits")

    ai_review = report.get("aiReview")
    if ai_review:
        header = "## AI 分析" if lang == "zh" else "## AI Review"
        lines.append("")
        lines.append(header)
        status = ai_review.get("status")
        if status == "ok":
            lines.append(ai_review.get("summary", "").strip() or "(empty)")
        else:
            reason = ai_review.get("reason", "unknown")
            msg = f"AI 分析失败：{reason}" if lang == "zh" else f"AI review failed: {reason}"
            lines.append(f"> ⚠️ {msg}")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan OpenClaw workspace for agent/skill risks.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Optional JSON report path")
    parser.add_argument("--markdown", type=Path, help="Optional Markdown report path")
    parser.add_argument("--lang", choices=["en", "zh"], default="en", help="Report language (default: en)")
    parser.add_argument("--ai-review", action="store_true", help="Send skill contents to an AI reviewer (requires OPENAI_API_KEY)")
    parser.add_argument("--ai-model", default=os.getenv("SKILL_AUDIT_AI_MODEL", "gpt-4o-mini"), help="Model to use when --ai-review is enabled")
    parser.add_argument("--skill-path", action="append", default=[], help="Local skill paths (file or directory)")
    parser.add_argument("--skill-url", action="append", default=[], help="Remote skill URLs")
    parser.add_argument("--agent-path", action="append", default=[], help="Local agent JSON files or openclaw.json excerpts")
    parser.add_argument("--agent-url", action="append", default=[], help="Remote agent JSON URLs")
    args = parser.parse_args()

    extra_skills = load_external_skills(args.skill_path, args.skill_url)
    extra_agents = load_external_agents(args.agent_path, args.agent_url)
    report = generate_report(extra_skills=extra_skills, extra_agents=extra_agents)
    if args.ai_review:
        report["aiReview"] = run_ai_review(extra_skills, args.ai_model, args.lang)
    if args.output:
        save_report(report, args.output)
        print(f"✅ JSON report saved to {args.output.name}")
    if args.markdown:
        _secure_write(args.markdown, to_markdown(report, args.lang))
        print(f"✅ Markdown report saved to {args.markdown.name}")
    if not args.output and not args.markdown:
        print("Audit completed, but no output path was provided.")


if __name__ == "__main__":
    main()
