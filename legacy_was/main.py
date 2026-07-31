from __future__ import annotations

import csv
import html
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


RISK_RULES = [
    ("WOW001", "Iteração sobre _G", "Crítico", 100, re.compile(r"\b(?:pairs|ipairs|next)\s*\(\s*_G\s*\)")),
    ("WOW002", "Template Secure", "Crítico", 95, re.compile(r"Secure(?:ActionButton|Handler|UnitButton)Template")),
    ("WOW003", "StaticPopupDialogs", "Alto", 75, re.compile(r"\bStaticPopupDialogs\b")),
    ("WOW004", "Settings API", "Alto", 70, re.compile(r"\bSettings\.")),
    ("WOW005", "Acesso global _G", "Alto", 65, re.compile(r"(?:\b_G\b|_G\s*\[)")),
    ("WOW006", "hooksecurefunc", "Médio", 45, re.compile(r"\bhooksecurefunc\s*\(")),
    ("WOW007", "CreateFrame", "Baixo", 15, re.compile(r"\bCreateFrame\s*\(")),
    ("WOW008", "RegisterEvent", "Baixo", 10, re.compile(r"\bRegister(?:Unit)?Event\s*\(")),
    ("WOW009", "C_Timer", "Baixo", 10, re.compile(r"\bC_Timer\.")),
    ("WOW010", "SlashCmdList", "Médio", 35, re.compile(r"\bSlashCmdList\b")),
]

METRIC_PATTERNS = {
    "functions": re.compile(r"\bfunction\b"),
    "create_frame": re.compile(r"\bCreateFrame\s*\("),
    "register_event": re.compile(r"\bRegister(?:Unit)?Event\s*\("),
    "set_script": re.compile(r"\bSetScript\s*\("),
    "hook_script": re.compile(r"\bHookScript\s*\("),
    "c_timer": re.compile(r"\bC_Timer\."),
    "pairs": re.compile(r"\bpairs\s*\("),
    "ipairs": re.compile(r"\bipairs\s*\("),
    "next": re.compile(r"\bnext\s*\("),
    "globals": re.compile(r"(?:\b_G\b|_G\s*\[)"),
    "settings": re.compile(r"\bSettings\."),
    "static_popup": re.compile(r"\bStaticPopupDialogs\b"),
    "slash_commands": re.compile(r"\bSlashCmdList\b"),
    "hooksecurefunc": re.compile(r"\bhooksecurefunc\s*\("),
    "secure_templates": re.compile(r"Secure(?:ActionButton|Handler|UnitButton)Template"),
}

FUNCTION_PATTERNS = [
    re.compile(r"^\s*(?:local\s+)?function\s+([A-Za-z_][\w\.\:]*)\s*\("),
    re.compile(r"^\s*([A-Za-z_][\w\.\:]*)\s*=\s*function\s*\("),
]

CALL_PATTERN = re.compile(r"(?<![\w])([A-Za-z_][\w\.\:]*)\s*\(")
CONTROL_WORDS = {
    "if", "for", "while", "function", "return", "elseif", "until",
    "not", "and", "or", "local", "print",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    weight: int
    file: str
    line: int
    code: str


@dataclass
class LuaFunction:
    uid: str
    name: str
    file: str
    start_line: int
    end_line: int
    calls: list[str] = field(default_factory=list)
    resolved_calls: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    frames: int = 0
    timers: int = 0
    settings_calls: int = 0
    globals_access: int = 0
    complexity: int = 1
    call_depth: int = 0
    fan_in: int = 0
    fan_out: int = 0
    coupling: int = 0
    maintainability: int = 100
    risk_score: int = 0
    risk_level: str = "Baixo"
    hotspot_score: int = 0


@dataclass
class FileMetrics:
    path: str
    lines: int = 0
    functions: int = 0
    create_frame: int = 0
    register_event: int = 0
    set_script: int = 0
    hook_script: int = 0
    c_timer: int = 0
    pairs: int = 0
    ipairs: int = 0
    next: int = 0
    globals: int = 0
    settings: int = 0
    static_popup: int = 0
    slash_commands: int = 0
    hooksecurefunc: int = 0
    secure_templates: int = 0
    risk_score: int = 0
    risk_level: str = "Baixo"
    dependencies: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ProjectReport:
    project: str
    root: str
    toc: str | None
    interface: str | None
    version: str | None
    load_order: list[str]
    missing_references: list[str]
    lua_files: int
    xml_files: int
    total_lines: int
    totals: dict[str, int]
    risk_score: int
    risk_level: str
    generated_at: str
    files: list[FileMetrics]
    findings: list[Finding]
    functions: list[LuaFunction]
    dependencies: dict[str, list[str]]
    hotspots: list[LuaFunction]


def read_text(path: Path) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Não foi possível ler {path}")


def parse_toc(root: Path):
    toc_files = sorted(root.glob("*.toc"))
    if not toc_files:
        return None, {}, [], []

    toc = toc_files[0]
    metadata, load_order, missing = {}, [], []

    for raw_line in read_text(toc).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("##"):
            value = line[2:].strip()
            if ":" in value:
                key, val = value.split(":", 1)
                metadata[key.strip()] = val.strip()
            continue
        if line.startswith("#"):
            continue
        normalized = line.replace("\\", "/")
        load_order.append(normalized)
        if not (root / normalized).exists():
            missing.append(normalized)

    return toc, metadata, load_order, missing


def risk_level(score: int) -> str:
    if score >= 70:
        return "Crítico"
    if score >= 45:
        return "Alto"
    if score >= 20:
        return "Médio"
    return "Baixo"


def detect_function_name(line: str) -> str | None:
    for pattern in FUNCTION_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def strip_strings_and_comments(line: str) -> str:
    line = re.sub(r"--.*$", "", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line


def block_delta(line: str) -> int:
    cleaned = strip_strings_and_comments(line)
    opens = len(re.findall(r"\bfunction\b", cleaned))
    opens += len(re.findall(r"\bthen\b", cleaned))
    opens += len(re.findall(r"\bdo\b", cleaned))
    opens += len(re.findall(r"\brepeat\b", cleaned))
    closes = len(re.findall(r"\bend\b", cleaned))
    closes += len(re.findall(r"\buntil\b", cleaned))
    return opens - closes


def parse_functions(text: str, relative_file: str) -> list[LuaFunction]:
    lines = text.splitlines()
    functions: list[LuaFunction] = []
    index = 0

    while index < len(lines):
        name = detect_function_name(lines[index])
        if not name:
            index += 1
            continue

        start = index + 1
        depth = block_delta(lines[index])
        end_index = index

        while depth > 0 and end_index + 1 < len(lines):
            end_index += 1
            depth += block_delta(lines[end_index])

        body_lines = lines[index:end_index + 1]
        body = "\n".join(body_lines)
        calls: list[str] = []

        for body_line in body_lines:
            clean = strip_strings_and_comments(body_line)
            for call in CALL_PATTERN.findall(clean):
                if call not in CONTROL_WORDS and call != name:
                    calls.append(call)

        calls = sorted(set(calls))
        events = sorted(set(re.findall(r'Register(?:Unit)?Event\s*\(\s*["\']([^"\']+)["\']', body)))

        complexity = 1
        complexity += len(re.findall(r"\bif\b|\belseif\b|\bfor\b|\bwhile\b|\brepeat\b", body))
        complexity += len(re.findall(r"\band\b|\bor\b", body))

        frames = len(re.findall(r"\bCreateFrame\s*\(", body))
        timers = len(re.findall(r"\bC_Timer\.", body))
        settings_calls = len(re.findall(r"\bSettings\.", body))
        globals_access = len(re.findall(r"(?:\b_G\b|_G\s*\[)", body))

        score = min(
            100,
            min(30, frames * 6)
            + min(25, timers * 5)
            + min(35, settings_calls * 12)
            + min(35, globals_access * 12)
            + min(20, complexity),
        )

        uid = f"{relative_file}:{name}:{start}"
        functions.append(LuaFunction(
            uid=uid,
            name=name,
            file=relative_file,
            start_line=start,
            end_line=end_index + 1,
            calls=calls,
            events=events,
            frames=frames,
            timers=timers,
            settings_calls=settings_calls,
            globals_access=globals_access,
            complexity=complexity,
            risk_score=score,
            risk_level=risk_level(score),
        ))
        index = end_index + 1

    return functions


def scan_lua_file(path: Path, root: Path) -> tuple[FileMetrics, list[LuaFunction]]:
    text = read_text(path)
    relative = str(path.relative_to(root)).replace("\\", "/")
    lines = text.splitlines()
    metrics = FileMetrics(path=relative, lines=len(lines))

    for name, pattern in METRIC_PATTERNS.items():
        setattr(metrics, name, len(pattern.findall(text)))

    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        for rule_id, title, severity, weight, pattern in RISK_RULES:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id, title, severity, weight,
                    relative, line_number, line.strip()
                ))

    metrics.findings = findings
    weights = sorted((f.weight for f in findings), reverse=True)[:5]
    metrics.risk_score = min(100, round(sum(weights) / len(weights))) if weights else 0
    metrics.risk_level = risk_level(metrics.risk_score)
    return metrics, parse_functions(text, relative)


def aggregate(files: list[FileMetrics]) -> dict[str, int]:
    return {
        key: sum(getattr(item, key) for item in files)
        for key in METRIC_PATTERNS
    }


def overall_risk(files: list[FileMetrics]) -> tuple[int, str]:
    scores = sorted((item.risk_score for item in files), reverse=True)[:5]
    score = round(sum(scores) / len(scores)) if scores else 0
    return score, risk_level(score)


def short_name(name: str) -> str:
    return name.split(".")[-1].split(":")[-1]


def resolve_symbol_table(functions: list[LuaFunction]) -> dict[str, list[LuaFunction]]:
    table: dict[str, list[LuaFunction]] = defaultdict(list)
    for fn in functions:
        table[fn.name].append(fn)
        table[short_name(fn.name)].append(fn)
    return table


def calculate_depth(uid: str, graph: dict[str, list[str]], limit: int = 20) -> int:
    max_depth = 0
    queue = deque([(uid, 0)])
    visited = {uid}

    while queue:
        current, depth = queue.popleft()
        max_depth = max(max_depth, depth)
        if depth >= limit:
            continue
        for target in graph.get(current, []):
            if target not in visited:
                visited.add(target)
                queue.append((target, depth + 1))
    return max_depth


def enrich_functions(functions: list[LuaFunction]) -> dict[str, list[str]]:
    symbol_table = resolve_symbol_table(functions)
    by_uid = {fn.uid: fn for fn in functions}
    graph: dict[str, list[str]] = defaultdict(list)
    reverse: dict[str, list[str]] = defaultdict(list)

    for fn in functions:
        resolved: list[str] = []
        for call in fn.calls:
            candidates = symbol_table.get(call) or symbol_table.get(short_name(call)) or []
            if not candidates:
                continue

            same_file = [candidate for candidate in candidates if candidate.file == fn.file]
            target = (same_file or candidates)[0]
            if target.uid == fn.uid:
                continue
            resolved.append(target.uid)
            graph[fn.uid].append(target.uid)
            reverse[target.uid].append(fn.uid)

        fn.resolved_calls = sorted(set(resolved))

    for fn in functions:
        fn.callers = sorted(set(reverse.get(fn.uid, [])))
        fn.fan_in = len(fn.callers)
        fn.fan_out = len(fn.resolved_calls)
        related_files = {
            by_uid[target].file
            for target in fn.resolved_calls + fn.callers
            if target in by_uid and by_uid[target].file != fn.file
        }
        fn.coupling = len(related_files)
        fn.call_depth = calculate_depth(fn.uid, graph)

        maintainability_penalty = (
            fn.complexity * 2
            + fn.fan_out * 2
            + fn.coupling * 4
            + fn.risk_score // 3
        )
        fn.maintainability = max(0, 100 - maintainability_penalty)
        fn.hotspot_score = min(
            100,
            round(
                fn.risk_score * 0.45
                + min(fn.complexity * 4, 100) * 0.25
                + min((fn.fan_in + fn.fan_out) * 8, 100) * 0.20
                + min(fn.coupling * 15, 100) * 0.10
            )
        )

    return {uid: sorted(set(targets)) for uid, targets in graph.items()}


def build_file_dependencies(files: list[FileMetrics], functions: list[LuaFunction]) -> dict[str, list[str]]:
    by_uid = {fn.uid: fn for fn in functions}
    dependencies: dict[str, set[str]] = defaultdict(set)

    for fn in functions:
        for target_uid in fn.resolved_calls:
            target = by_uid.get(target_uid)
            if target and target.file != fn.file:
                dependencies[fn.file].add(target.file)

    result = {file: sorted(values) for file, values in dependencies.items()}
    for item in files:
        item.dependencies = result.get(item.path, [])
    return result


def build_report(root: Path) -> ProjectReport:
    toc, metadata, load_order, missing = parse_toc(root)
    lua_paths = sorted(root.rglob("*.lua"))
    xml_paths = sorted(root.rglob("*.xml"))

    file_metrics: list[FileMetrics] = []
    functions: list[LuaFunction] = []

    for path in lua_paths:
        metrics, parsed_functions = scan_lua_file(path, root)
        file_metrics.append(metrics)
        functions.extend(parsed_functions)

    enrich_functions(functions)
    dependencies = build_file_dependencies(file_metrics, functions)
    totals = aggregate(file_metrics)
    project_score, project_level = overall_risk(file_metrics)
    findings = [finding for item in file_metrics for finding in item.findings]
    hotspots = sorted(
        functions,
        key=lambda fn: (-fn.hotspot_score, -fn.risk_score, -fn.complexity)
    )[:25]

    return ProjectReport(
        project=root.name,
        root=str(root),
        toc=toc.name if toc else None,
        interface=metadata.get("Interface"),
        version=metadata.get("Version"),
        load_order=load_order,
        missing_references=missing,
        lua_files=len(lua_paths),
        xml_files=len(xml_paths),
        total_lines=sum(item.lines for item in file_metrics),
        totals=totals,
        risk_score=project_score,
        risk_level=project_level,
        generated_at=datetime.now().isoformat(timespec="seconds"),
        files=file_metrics,
        findings=findings,
        functions=functions,
        dependencies=dependencies,
        hotspots=hotspots,
    )


def save_json(report: ProjectReport, output: Path) -> None:
    output.write_text(
        json.dumps(asdict(report), ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def save_functions_json(report: ProjectReport, output: Path) -> None:
    output.write_text(
        json.dumps([asdict(item) for item in report.functions], ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def save_hotspots_json(report: ProjectReport, output: Path) -> None:
    output.write_text(
        json.dumps([asdict(item) for item in report.hotspots], ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def save_risk_csv(report: ProjectReport, output: Path) -> None:
    with output.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file, delimiter=";")
        writer.writerow(["Regra", "Severidade", "Peso", "Arquivo", "Linha", "Código"])
        for item in sorted(report.findings, key=lambda x: (-x.weight, x.file, x.line)):
            writer.writerow([
                item.rule_id, item.severity, item.weight,
                item.file, item.line, item.code
            ])


def dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def save_call_graph(report: ProjectReport, output: Path) -> None:
    by_uid = {fn.uid: fn for fn in report.functions}
    lines = [
        "digraph WAS_CallGraph {",
        '  graph [rankdir="LR"];',
        '  node [shape="box", fontname="Segoe UI"];',
    ]

    for fn in report.functions:
        label = f"{fn.name}\\n{fn.file}:{fn.start_line}"
        lines.append(f'  "{dot_escape(fn.uid)}" [label="{dot_escape(label)}"];')
        for target_uid in fn.resolved_calls:
            if target_uid in by_uid:
                lines.append(
                    f'  "{dot_escape(fn.uid)}" -> "{dot_escape(target_uid)}";'
                )

    lines.append("}")
    output.write_text("\n".join(lines), encoding="utf-8")


def save_dependency_graph(report: ProjectReport, output: Path) -> None:
    lines = [
        "digraph WAS_DependencyGraph {",
        '  graph [rankdir="LR"];',
        '  node [shape="folder", fontname="Segoe UI"];',
    ]

    all_files = {item.path for item in report.files}
    for file in sorted(all_files):
        lines.append(f'  "{dot_escape(file)}";')

    for source, targets in sorted(report.dependencies.items()):
        for target in targets:
            lines.append(
                f'  "{dot_escape(source)}" -> "{dot_escape(target)}";'
            )

    lines.append("}")
    output.write_text("\n".join(lines), encoding="utf-8")


def badge(level: str) -> str:
    css = {
        "Baixo": "low", "Médio": "medium",
        "Alto": "high", "Crítico": "critical",
    }.get(level, "low")
    return f'<span class="badge {css}">{html.escape(level)}</span>'


def save_html(report: ProjectReport, output: Path) -> None:
    by_uid = {fn.uid: fn for fn in report.functions}

    hotspot_rows = []
    for fn in report.hotspots:
        hotspot_rows.append(f"""
        <tr>
          <td><strong>{fn.hotspot_score}</strong></td>
          <td><code>{html.escape(fn.name)}</code></td>
          <td><code>{html.escape(fn.file)}</code></td>
          <td>{fn.start_line}-{fn.end_line}</td>
          <td>{fn.complexity}</td>
          <td>{fn.fan_in}</td>
          <td>{fn.fan_out}</td>
          <td>{fn.coupling}</td>
          <td>{fn.call_depth}</td>
          <td>{fn.maintainability}</td>
          <td>{fn.risk_score} {badge(fn.risk_level)}</td>
        </tr>""")

    file_rows = []
    for item in sorted(report.files, key=lambda x: (-x.risk_score, x.path)):
        deps = ", ".join(item.dependencies)
        file_rows.append(f"""
        <tr>
          <td><code>{html.escape(item.path)}</code></td>
          <td>{item.lines}</td><td>{item.functions}</td>
          <td>{item.create_frame}</td><td>{item.register_event}</td>
          <td>{item.globals}</td><td>{item.settings}</td>
          <td>{html.escape(deps)}</td>
          <td><strong>{item.risk_score}</strong> {badge(item.risk_level)}</td>
        </tr>""")

    function_rows = []
    for fn in sorted(report.functions, key=lambda x: (-x.hotspot_score, x.file, x.start_line)):
        caller_names = [
            by_uid[uid].name for uid in fn.callers if uid in by_uid
        ]
        callee_names = [
            by_uid[uid].name for uid in fn.resolved_calls if uid in by_uid
        ]
        function_rows.append(f"""
        <tr>
          <td><code>{html.escape(fn.name)}</code></td>
          <td><code>{html.escape(fn.file)}</code></td>
          <td>{fn.start_line}-{fn.end_line}</td>
          <td>{fn.complexity}</td>
          <td>{fn.fan_in}</td>
          <td>{fn.fan_out}</td>
          <td>{fn.call_depth}</td>
          <td>{fn.coupling}</td>
          <td>{fn.maintainability}</td>
          <td>{html.escape(", ".join(caller_names[:10]))}</td>
          <td>{html.escape(", ".join(callee_names[:10]))}</td>
          <td>{fn.hotspot_score}</td>
          <td>{fn.risk_score} {badge(fn.risk_level)}</td>
        </tr>""")

    finding_rows = []
    for item in sorted(report.findings, key=lambda x: (-x.weight, x.file, x.line)):
        finding_rows.append(f"""
        <tr>
          <td>{html.escape(item.rule_id)}</td>
          <td>{badge(item.severity)}</td>
          <td><code>{html.escape(item.file)}</code></td>
          <td>{item.line}</td>
          <td>{html.escape(item.title)}</td>
          <td><code>{html.escape(item.code)}</code></td>
        </tr>""")

    totals = report.totals
    load_order = "".join(
        f"<li><code>{html.escape(item)}</code></li>"
        for item in report.load_order
    )
    missing = "".join(
        f"<li><code>{html.escape(item)}</code></li>"
        for item in report.missing_references
    )

    document = f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>WAS Function Explorer - {html.escape(report.project)}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
header{{padding:26px;background:#111827;border-bottom:1px solid #334155}}
main{{padding:22px;max-width:1800px;margin:auto}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px}}
.value{{font-size:29px;font-weight:700;margin-top:8px}}
table{{width:100%;border-collapse:collapse;background:#1e293b;margin-top:14px}}
th,td{{padding:9px;border-bottom:1px solid #334155;text-align:left;vertical-align:top}}
th{{background:#111827;position:sticky;top:0}}
code{{color:#93c5fd;white-space:pre-wrap}}
.badge{{display:inline-block;padding:3px 8px;border-radius:999px;font-size:12px}}
.low{{background:#14532d}} .medium{{background:#854d0e}}
.high{{background:#9a3412}} .critical{{background:#991b1b}}
section{{margin-top:26px}} .small{{color:#94a3b8}}
nav a{{color:#93c5fd;margin-right:18px;text-decoration:none}}
</style>
</head>
<body>
<header>
<h1>WoW Addon Studio — Function Explorer & Hotspots</h1>
<div class="small">{html.escape(report.project)} • {html.escape(report.generated_at)}</div>
<nav>
<a href="#dashboard">Dashboard</a>
<a href="#hotspots">Hotspots</a>
<a href="#files">Arquivos</a>
<a href="#functions">Funções</a>
<a href="#risks">Riscos</a>
<a href="#toc">TOC</a>
</nav>
</header>
<main>
<section id="dashboard">
<div class="grid">
<div class="card">Risco geral<div class="value">{report.risk_score}</div>{badge(report.risk_level)}</div>
<div class="card">Arquivos Lua<div class="value">{report.lua_files}</div></div>
<div class="card">Linhas<div class="value">{report.total_lines}</div></div>
<div class="card">Funções<div class="value">{len(report.functions)}</div></div>
<div class="card">Hotspots<div class="value">{len(report.hotspots)}</div></div>
<div class="card">Achados<div class="value">{len(report.findings)}</div></div>
<div class="card">Frames<div class="value">{totals["create_frame"]}</div></div>
<div class="card">Eventos<div class="value">{totals["register_event"]}</div></div>
</div>
</section>

<section id="hotspots"><h2>Top Hotspots</h2>
<table><thead><tr>
<th>Hotspot</th><th>Função</th><th>Arquivo</th><th>Linhas</th>
<th>Complexidade</th><th>Fan-in</th><th>Fan-out</th><th>Acoplamento</th>
<th>Profundidade</th><th>Manutenibilidade</th><th>Risco</th>
</tr></thead><tbody>{''.join(hotspot_rows)}</tbody></table></section>

<section id="files"><h2>Dependências por arquivo</h2>
<table><thead><tr>
<th>Arquivo</th><th>Linhas</th><th>Funções</th><th>Frames</th>
<th>Eventos</th><th>_G</th><th>Settings</th><th>Depende de</th><th>Risco</th>
</tr></thead><tbody>{''.join(file_rows)}</tbody></table></section>

<section id="functions"><h2>Function Explorer</h2>
<table><thead><tr>
<th>Função</th><th>Arquivo</th><th>Linhas</th><th>Complexidade</th>
<th>Fan-in</th><th>Fan-out</th><th>Profundidade</th><th>Acoplamento</th>
<th>Manutenibilidade</th><th>Chamada por</th><th>Chama</th><th>Hotspot</th><th>Risco</th>
</tr></thead><tbody>{''.join(function_rows)}</tbody></table></section>

<section id="risks"><h2>Risk Explorer</h2>
<table><thead><tr>
<th>Regra</th><th>Severidade</th><th>Arquivo</th><th>Linha</th><th>Achado</th><th>Código</th>
</tr></thead><tbody>{''.join(finding_rows)}</tbody></table></section>

<section id="toc"><h2>Ordem de carregamento</h2>
<div class="card"><ol>{load_order or "<li>Vazia</li>"}</ol></div>
<h2>Referências ausentes</h2>
<div class="card"><ul>{missing or "<li>Nenhuma</li>"}</ul></div></section>
</main>
</body>
</html>"""
    output.write_text(document, encoding="utf-8")


def ask_path() -> Path:
    print("=" * 76)
    print(" WoW Addon Studio v0.5.0 - Function Explorer & Hotspots")
    print("=" * 76)
    raw = input("\nCole o caminho da pasta do addon:\n> ").strip().strip('"')
    return Path(raw).expanduser()


def main() -> int:
    try:
        root = ask_path()
        if not root.exists() or not root.is_dir():
            print("\nERRO: a pasta informada não existe.")
            return 1

        print("\nConstruindo tabela de símbolos, dependências e hotspots...")
        report = build_report(root)

        output_dir = Path(__file__).resolve().parent.parent / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)

        outputs = {
            "HTML": output_dir / "AuditReport.html",
            "JSON": output_dir / "AuditReport.json",
            "CSV": output_dir / "RiskReport.csv",
            "FUNÇÕES": output_dir / "FunctionsReport.json",
            "HOTSPOTS": output_dir / "HotspotsReport.json",
            "CALL GRAPH": output_dir / "CallGraph.dot",
            "DEPENDÊNCIAS": output_dir / "DependencyGraph.dot",
        }

        save_html(report, outputs["HTML"])
        save_json(report, outputs["JSON"])
        save_risk_csv(report, outputs["CSV"])
        save_functions_json(report, outputs["FUNÇÕES"])
        save_hotspots_json(report, outputs["HOTSPOTS"])
        save_call_graph(report, outputs["CALL GRAPH"])
        save_dependency_graph(report, outputs["DEPENDÊNCIAS"])

        print("\nAnálise concluída!")
        print(f"Projeto: {report.project}")
        print(f"Versão TOC: {report.version or 'não informada'}")
        print(f"Arquivos Lua: {report.lua_files}")
        print(f"Linhas: {report.total_lines}")
        print(f"Funções indexadas: {len(report.functions)}")
        print(f"Hotspots: {len(report.hotspots)}")
        print(f"Achados: {len(report.findings)}")
        print(f"Risco geral: {report.risk_score} ({report.risk_level})")
        print("\nArquivos gerados:")
        for name, path in outputs.items():
            print(f"{name}: {path}")
        return 0
    except Exception as exc:
        print(f"\nERRO inesperado: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
