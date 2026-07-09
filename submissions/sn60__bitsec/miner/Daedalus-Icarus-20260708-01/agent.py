from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_SUFFIXES = {".sol", ".vy", ".move", ".rs"}
IGNORE_DIRS = {
    ".git",
    ".github",
    "artifacts",
    "broadcast",
    "cache",
    "coverage",
    "docs",
    "example",
    "examples",
    "lib",
    "mock",
    "mocks",
    "node_modules",
    "out",
    "script",
    "scripts",
    "test",
    "tests",
    "vendor",
}

MAX_FILE_BYTES = 230_000
MAX_FILES = 90
MAX_MAP = 18_500
MAX_AUDIT = 39_000
MAX_FINDINGS = 9
MAX_SECONDS = 245
MODEL_TIMEOUT = 155

SOL_FUNC = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:\{|;)")
SOL_UNIT = re.compile(r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)")
VY_FUNC = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:")
RS_FUNC = re.compile(r"(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MOVE_FUNC = re.compile(r"(?m)^\s*(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)")
IMPORT = re.compile(r"(?m)^\s*import\b[^;]*?[\"']([^\"']+)[\"']")

RISK_TERMS = (
    "withdraw",
    "redeem",
    "deposit",
    "mint",
    "burn",
    "transfer",
    "transferFrom",
    "safeTransfer",
    "approve",
    "permit",
    "signature",
    "nonce",
    "claim",
    "reward",
    "harvest",
    "stake",
    "unstake",
    "swap",
    "exchange",
    "liquidity",
    "reserve",
    "balance",
    "share",
    "price",
    "oracle",
    "rate",
    "fee",
    "invariant",
    "collateral",
    "borrow",
    "repay",
    "liquidate",
    "auction",
    "escrow",
    "vesting",
    "router",
    "pool",
    "vault",
    "market",
    "delegatecall",
    "call{",
    "raw_call",
    "tx.origin",
    "selfdestruct",
    "assembly",
    "unchecked",
    "initialize",
    "upgrade",
)

HIGH_VALUE_FAMILIES = (
    "asset accounting mismatch",
    "share or supply mispricing",
    "invariant break",
    "incorrect decimal or rate scaling",
    "slippage bypass",
    "oracle manipulation or stale price",
    "missing authorization on state-changing control",
    "signature replay or nonce bug",
    "external call before accounting update",
    "liquidation or collateral edge case",
    "vesting or reward claim corruption",
)

SYSTEM = (
    "You are a smart-contract security auditor. Report only concrete high or critical "
    "bugs that are directly supported by the supplied source. Do not report gas, style, "
    "missing event, centralization, or generic best-practice issues. Return JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    root = _root(project_dir)
    if root is None:
        return _empty()
    files = _scan(root)
    if not files:
        return _empty()

    by_rel = {item["rel"]: item for item in files}
    by_name = {Path(item["rel"]).name: item for item in files}
    collected: list[dict[str, Any]] = []
    collected.extend(_cheap_detectors(files))

    chosen, map_findings = _model_map(inference_api, files)
    collected.extend(map_findings)
    primary, secondary = _batches(chosen, files)

    if time.monotonic() - started < MAX_SECONDS:
        collected.extend(_model_audit(inference_api, primary, by_name, "first"))
    if time.monotonic() - started < MAX_SECONDS:
        collected.extend(_model_audit(inference_api, secondary, by_name, "second"))

    normalized = []
    for raw in collected:
        item = _normalize(raw, by_rel)
        if item is not None:
            normalized.append(item)
    return {"vulnerabilities": _unique(normalized)}


def _empty() -> dict:
    result: list[dict[str, Any]] = []
    return {"vulnerabilities": result}


def _root(project_dir: str | None) -> Path | None:
    options = []
    if project_dir:
        options.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            options.append(value)
    options.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in options:
        try:
            path = Path(raw).expanduser().resolve()
        except OSError:
            continue
        if not path.is_dir():
            continue
        try:
            if any(child.is_file() and child.suffix.lower() in SOURCE_SUFFIXES for child in path.rglob("*")):
                return path
        except OSError:
            continue
    return None


def _scan(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel_path = path.relative_to(root)
            if any(part.lower() in IGNORE_DIRS for part in rel_path.parts[:-1]):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _source_like(text, path.suffix.lower()):
            continue
        rel = rel_path.as_posix()
        funcs = _functions(text, path.suffix.lower())
        units = SOL_UNIT.findall(text)
        if not units and path.suffix.lower() in {".vy", ".rs", ".move"}:
            units = [path.stem]
        out.append(
            {
                "rel": rel,
                "text": text,
                "suffix": path.suffix.lower(),
                "units": units[:10],
                "functions": funcs[:90],
                "score": _score(rel, text, funcs),
            }
        )
    out.sort(key=lambda item: (-int(item["score"]), str(item["rel"])))
    return out[:MAX_FILES]


def _source_like(text: str, suffix: str) -> bool:
    if suffix == ".sol":
        return "function " in text or "contract " in text or "library " in text
    if suffix == ".vy":
        return "def " in text or "@external" in text
    if suffix == ".move":
        return "module " in text or "fun " in text
    if suffix == ".rs":
        return "fn " in text or "pub " in text
    return False


def _functions(text: str, suffix: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if suffix == ".sol":
        for match in SOL_FUNC.finditer(text):
            name = match.group(1)
            tail = " ".join(match.group(3).split())
            rows.append({"name": name, "sig": f"{name}({match.group(2).strip()}) {tail}".strip()})
    elif suffix == ".vy":
        for match in VY_FUNC.finditer(text):
            name = match.group(1)
            ret = f" -> {match.group(3).strip()}" if match.group(3) else ""
            rows.append({"name": name, "sig": f"{name}({match.group(2).strip()}){ret}"})
    elif suffix == ".rs":
        rows.extend({"name": m.group(1), "sig": m.group(0).strip()} for m in RS_FUNC.finditer(text))
    elif suffix == ".move":
        rows.extend({"name": m.group(1), "sig": m.group(0).strip()} for m in MOVE_FUNC.finditer(text))
    return rows


def _score(rel: str, text: str, funcs: list[dict[str, str]]) -> int:
    low_rel = rel.lower()
    low = text.lower()
    score = min(len(funcs), 45)
    for term in RISK_TERMS:
        term_low = term.lower()
        score += min(low.count(term_low), 8) * 3
        if term_low in low_rel:
            score += 9
    if "public" in low or "external" in low or "@external" in low:
        score += 8
    if any(x in low for x in ("totalassets", "total_assets", "totalsupply", "total_supply", "balances", "reserves")):
        score += 9
    if any(x in low for x in ("onlyowner", "onlyrole", "accesscontrol", "assert msg.sender", "require(msg.sender")):
        score += 3
    return score


def _line(text: str, token: str) -> int | None:
    if not token:
        return None
    idx = text.find(token)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def _risk_excerpt(text: str) -> list[str]:
    terms = [term.lower() for term in RISK_TERMS]
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(term in low for term in terms):
            compact = " ".join(line.strip().split())
            if compact:
                rows.append(f"{number}: {compact[:175]}")
        if len(rows) >= 18:
            break
    return rows


def _map(files: list[dict[str, Any]]) -> str:
    rows = []
    for item in files:
        rows.append(
            json.dumps(
                {
                    "file": item["rel"],
                    "units": item["units"],
                    "score": item["score"],
                    "functions": [fn["sig"][:175] for fn in item["functions"][:34]],
                    "risk_lines": _risk_excerpt(item["text"]),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(rows)[:MAX_MAP]


def _ask(inference_api: str | None, prompt: str, max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(2):
        try:
            request = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(request, timeout=MODEL_TIMEOUT) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
            return _content(payload)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, TimeoutError, ValueError) as exc:
            last = exc
        if attempt == 0:
            time.sleep(1.0)
    raise RuntimeError(f"model request failed: {last}")


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _json(text: str) -> dict[str, Any]:
    value = text.strip()
    if value.startswith("```"):
        value = re.sub(r"^```[A-Za-z]*\s*", "", value)
        value = re.sub(r"\s*```$", "", value)
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    start = value.find("{")
    if start < 0:
        return {}
    depth = 0
    inside = False
    escape = False
    for offset in range(start, len(value)):
        char = value[offset]
        if inside:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                inside = False
            continue
        if char == '"':
            inside = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(value[start : offset + 1])
                    return parsed if isinstance(parsed, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _model_map(inference_api: str | None, files: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "You are selecting attack surfaces from a smart-contract repository map. "
        "Return strict JSON with target files and any already-obvious high-impact findings:\n"
        '{"target_files":["path"],"findings":[{"title":"specific bug","file":"path",'
        '"contract":"name","function":"name","line":1,"severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> broken state transition",'
        '"impact":"specific loss, insolvency, stuck funds, or critical denial",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize these bug families: "
        + "; ".join(HIGH_VALUE_FAMILIES)
        + ". Do not invent files/functions. Prefer a few precise findings.\n\n"
        + _map(files)
    )
    try:
        obj = _json(_ask(inference_api, prompt, 4300))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities")
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else [],
    )


def _batches(targets: list[str], files: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for item in files:
            rel = item["rel"]
            if target == rel or rel.endswith(target) or target.endswith(rel) or Path(target).name == Path(rel).name:
                if item not in ordered:
                    ordered.append(item)
                break
    for item in files:
        if item not in ordered:
            ordered.append(item)
    return ordered[:4], ordered[4:9]


def _context(item: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    pieces = []
    for match in IMPORT.finditer(item["text"]):
        imported = match.group(1).rsplit("/", 1)[-1]
        other = by_name.get(imported)
        if other and other["rel"] != item["rel"]:
            pieces.append(f"\n// Related import: {other['rel']}\n{other['text'][:2600]}")
        if len(pieces) >= 2:
            break
    return "".join(pieces)


def _model_audit(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    label: str,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Deep audit this {label} source batch. Return only concrete high or critical vulnerabilities. "
        "Each finding must have exact file, function, exploit mechanism, and impact. JSON shape:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"functionName","line":1,"severity":"high|critical",'
        '"mechanism":"precondition -> attacker transaction(s) -> broken invariant/accounting/auth",'
        '"impact":"specific user/protocol loss, insolvency, or critical denial",'
        '"description":"2-4 precise sentences with code details"}]}\n'
        "Check asset/share accounting, ordering of external calls and state writes, reserve/invariant math, "
        "oracle/rate freshness, decimal scaling, authorization boundaries, replay protection, liquidation math, "
        "vesting/reward accounting, and slippage guarantees. Omit uncertain or low-impact issues.\n"
    )
    parts = [header]
    remaining = MAX_AUDIT - len(header)
    for item in batch:
        block = (
            f"\n\n===== FILE: {item['rel']} =====\n"
            f"Units: {', '.join(item['units'])}\n"
            f"{item['text']}"
            f"{_context(item, by_name)}\n"
        )
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    try:
        obj = _json(_ask(inference_api, "".join(parts), 6400))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities")
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _cheap_detectors(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in files:
        if item["suffix"] != ".sol":
            continue
        text = item["text"]
        low = text.lower()
        unit = item["units"][0] if item["units"] else Path(item["rel"]).stem
        if "tx.origin" in low:
            out.append(
                _finding(
                    title=f"{unit} - authorization depends on tx.origin",
                    file=item["rel"],
                    contract=unit,
                    function=_near_function(item, "tx.origin"),
                    line=_line(low, "tx.origin"),
                    severity="high",
                    mechanism="A privileged path checks tx.origin, so a trusted user can be routed through an attacker contract while the origin remains privileged.",
                    impact="If the protected action controls assets or configuration, the attacker can cause unauthorized state changes or fund movement.",
                )
            )
        for fn in _sol_blocks(text):
            body = fn["body"].lower()
            if (".call{" in body or ".call(" in body) and "nonreentrant" not in body:
                call_at = min(pos for pos in (body.find(".call{"), body.find(".call(")) if pos >= 0)
                after = body[call_at:]
                if any(token in after for token in ("balances[", "balanceof[", "-=", "= 0", "totalsupply", "total_supply")):
                    out.append(
                        _finding(
                            title=f"{unit}.{fn['name']} - external call before accounting update",
                            file=item["rel"],
                            contract=unit,
                            function=fn["name"],
                            line=fn["line"],
                            severity="high",
                            mechanism="The function performs an external call before finalizing balance or supply accounting and has no visible reentrancy guard in the function body.",
                            impact="A malicious receiver can reenter while stale balances remain available, enabling repeated withdrawals or corrupted protocol accounting.",
                        )
                    )
            if "ecrecover" in body and "nonce" not in body:
                out.append(
                    _finding(
                        title=f"{unit}.{fn['name']} - signature path lacks visible nonce binding",
                        file=item["rel"],
                        contract=unit,
                        function=fn["name"],
                        line=fn["line"],
                        severity="high",
                        mechanism="The function verifies a signature but the function body does not show nonce consumption or replay-state binding.",
                        impact="A valid signature can potentially be reused to repeat the authorized action, causing repeated transfers, approvals, claims, or order fills.",
                    )
                )
    return out[:5]


def _sol_blocks(text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for match in SOL_FUNC.finditer(text):
        tail = match.group(3).lower()
        if "public" not in tail and "external" not in tail:
            continue
        start = text.find("{", match.end() - 1)
        if start < 0:
            continue
        depth = 0
        end = start
        for pos in range(start, len(text)):
            char = text[pos]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        blocks.append({"name": match.group(1), "body": text[start:end], "line": text.count("\n", 0, match.start()) + 1})
    return blocks


def _finding(
    *,
    title: str,
    file: str,
    contract: str,
    function: str,
    line: int | None,
    severity: str,
    mechanism: str,
    impact: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "file": file,
        "contract": contract,
        "function": function,
        "line": line,
        "severity": severity,
        "mechanism": mechanism,
        "impact": impact,
        "description": mechanism + " " + impact,
    }


def _near_function(item: dict[str, Any], token: str) -> str:
    text = item["text"]
    idx = text.lower().find(token.lower())
    if idx < 0:
        return ""
    best = ""
    pos = -1
    for fn in item["functions"]:
        name = fn.get("name", "")
        candidate = text.find(name)
        if 0 <= candidate <= idx and candidate > pos:
            best = name
            pos = candidate
    return best


def _normalize(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    if not file_value:
        return None
    chosen = None
    for rel, item in by_rel.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel) or Path(file_value).name == Path(rel).name:
            chosen = item
            file_value = rel
            break
    if chosen is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    title = _clean(str(raw.get("title") or ""))
    contract = _clean(str(raw.get("contract") or ""))
    function = _clean(str(raw.get("function") or "")).strip("`()")
    if "." in function:
        function = function.rsplit(".", 1)[-1]
    valid_names = {fn["name"] for fn in chosen["functions"]}
    if function and valid_names and function not in valid_names:
        function = ""
    if not contract and chosen["units"]:
        contract = chosen["units"][0]
    if not title:
        title = f"{contract or Path(file_value).stem}.{function or 'logic'} - high-impact vulnerability"
    if _reject_topic(title + " " + str(raw.get("description") or "")):
        return None

    mechanism = _clean(str(raw.get("mechanism") or ""))
    impact = _clean(str(raw.get("impact") or ""))
    description = _clean(str(raw.get("description") or ""))
    if len(mechanism) < 25 and len(description) < 120:
        return None

    where = f"In `{file_value}`"
    if contract:
        where += f", contract/module `{contract}`"
    if function:
        where += f", function `{function}()`"
    pieces = [where + "."]
    if mechanism:
        pieces.append("Mechanism: " + mechanism.rstrip(".") + ".")
    if impact:
        pieces.append("Impact: " + impact.rstrip(".") + ".")
    if description:
        pieces.append(description)
    final_description = " ".join(pieces)
    if len(final_description) < 100:
        return None

    line = raw.get("line")
    if not isinstance(line, int):
        if function:
            prefix = "function " if chosen["suffix"] == ".sol" else "def "
            line = _line(chosen["text"], prefix + function)
        else:
            line = None

    return {
        "title": title[:220],
        "description": final_description[:3000],
        "severity": severity,
        "file": file_value,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "confidence": 0.91 if severity == "critical" else 0.86,
    }


def _clean(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())


def _reject_topic(text: str) -> bool:
    low = text.lower()
    blocked = (
        "missing event",
        "event emission",
        "gas optimization",
        "floating pragma",
        "code style",
        "naming convention",
        "centralization risk",
        "best practice",
        "comment",
        "documentation",
    )
    return any(token in low for token in blocked)


def _unique(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    ordered = sorted(
        items,
        key=lambda item: (
            str(item.get("severity")) == "critical",
            float(item.get("confidence") or 0),
            len(str(item.get("description") or "")),
        ),
        reverse=True,
    )
    out = []
    for item in ordered:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            re.sub(r"[^a-z0-9]+", " ", str(item.get("title") or "").lower())[:130],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
