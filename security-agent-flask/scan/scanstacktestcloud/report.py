"""Saídas do scan: console, JSON, CSV e HTML autocontido."""

from __future__ import annotations

import csv
import html
import io
import json
import os
import sys
from typing import Dict, List

from .models import Finding, Pillar, ScanResult, Severity

COLORS = {
    Severity.CRITICAL: "\033[97;41m",
    Severity.HIGH: "\033[31;1m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def render_console(result: ScanResult, limit: int = 40, show_all: bool = False) -> str:
    color = _use_color()

    def c(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    out = io.StringIO()
    counts = result.counts_by_severity()
    alias = f" ({result.account_alias})" if result.account_alias else ""

    out.write(f"\n{c('scanstacktestcloud — posture scan', BOLD)}\n")
    out.write(f"Conta {result.account_id}{alias} · {len(result.regions)} regiões · {result.duration_seconds}s\n")
    out.write(
        f"{result.checks_executed} execuções de check · {result.resources_evaluated} recursos avaliados\n\n"
    )

    out.write(f"  Posture score  {c(str(result.posture_score) + '/100', BOLD)}\n")
    line = "  "
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        line += f"{c(sev.label, COLORS[sev])} {counts[sev.value]:<4} "
    out.write(line + "\n")
    if result.estimated_monthly_waste:
        out.write(f"  Desperdício estimado  US$ {result.estimated_monthly_waste:,.2f}/mês\n")
    out.write("\n")

    ordered = sorted(result.findings, key=lambda f: f.sort_key)
    shown = ordered if show_all else ordered[:limit]

    for pillar in (Pillar.SECURITY, Pillar.RELIABILITY, Pillar.COST):
        group = [f for f in shown if f.pillar is pillar]
        if not group:
            continue
        total = len(result.by_pillar(pillar))
        plural = "achado" if total == 1 else "achados"
        head = f"{c(pillar.label, BOLD)} · {total} {plural}"
        out.write(head + "\n")
        for f in group:
            badge = (
                c(f" {f.severity.label:^8} ", COLORS[f.severity])
                if color
                else f"{f.severity.label:<8}"
            )
            waste = f"  ~US$ {f.monthly_waste_usd:,.0f}/mês" if f.monthly_waste_usd else ""
            out.write(f"  {badge} [{f.risk_score:>5.1f}] {f.title}{waste}\n")
            loc = f.resource_arn or f.resource_id
            out.write(f"      {c(f.check_id, DIM)} · {f.region} · {c(loc, DIM)}\n")
        out.write("\n")

    if not show_all and len(ordered) > limit:
        out.write(f"  ... mais {len(ordered) - limit} achados. Use --all ou exporte para JSON/HTML.\n\n")

    if result.errors:
        by_code: Dict[str, int] = {}
        for e in result.errors:
            by_code[e.error_code] = by_code.get(e.error_code, 0) + 1
        out.write(c("Checks não concluídos", BOLD) + "\n")
        for code, n in sorted(by_code.items(), key=lambda kv: -kv[1]):
            out.write(f"  {n:>4}x {code}\n")
        out.write("  Normalmente significa permissão faltando na role de leitura.\n\n")

    if not result.findings:
        out.write("  Nenhum achado nos checks executados.\n\n")
    return out.getvalue()


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False, default=str)


def write_csv(result: ScanResult, path: str) -> None:
    cols = [
        "check_id", "severity", "risk_score", "pillar", "title", "region",
        "resource_id", "resource_arn", "monthly_waste_usd", "well_architected", "remediation",
    ]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for f in sorted(result.findings, key=lambda x: x.sort_key):
            row = f.to_dict()
            row["pillar"] = f.pillar.label
            row["severity"] = f.severity.label
            writer.writerow(row)


# ----------------------------------------------------------------------- HTML

CSS = """
:root {
  --paper: #eef0f2;
  --surface: #ffffff;
  --ink: #101820;
  --muted: #5b6770;
  --rule: #d2d8dd;
  --critical: #9b1b30;
  --high: #c06a0c;
  --medium: #3f6798;
  --low: #6b7a85;
  --info: #8e9aa3;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px 20px 96px;
  background: var(--paper); color: var(--ink);
  font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
  font-size: 15px; line-height: 1.55;
  font-variant-numeric: tabular-nums;
}
.wrap { max-width: 880px; margin: 0 auto; }
header { margin-bottom: 32px; }
h1 { font-size: 19px; font-weight: 600; letter-spacing: -0.01em; margin: 0 0 4px; }
header p { margin: 0; color: var(--muted); font-size: 13px; }
code, .mono { font-family: ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace; font-size: 12.5px; }

.summary {
  display: flex; flex-wrap: wrap; gap: 28px; align-items: flex-end;
  background: var(--surface); border: 1px solid var(--rule);
  padding: 24px 26px; margin-bottom: 36px;
}
.score { line-height: 1; }
.score b { font-size: 56px; font-weight: 650; letter-spacing: -0.03em; display: block; }
.score span { color: var(--muted); font-size: 13px; }
.tally { display: flex; gap: 20px; }
.tally div b { display: block; font-size: 22px; font-weight: 600; line-height: 1.2; }
.tally div span { font-size: 12px; color: var(--muted); }
.waste { margin-left: auto; text-align: right; }
.waste b { display: block; font-size: 22px; font-weight: 600; }
.waste span { font-size: 12px; color: var(--muted); }

section { margin-bottom: 44px; }
h2 { font-size: 15px; font-weight: 600; margin: 0 0 2px; }
.section-note { color: var(--muted); font-size: 13px; margin: 0 0 14px; }

.finding {
  background: var(--surface); border: 1px solid var(--rule); border-left-width: 3px;
  padding: 16px 18px; margin-bottom: 10px;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low, .finding.info { border-left-color: var(--low); }
.finding h3 { font-size: 15px; font-weight: 600; margin: 0 0 6px; }
.meta { color: var(--muted); font-size: 12.5px; margin-bottom: 10px; }
.meta .sev { font-weight: 600; }
.sev.critical { color: var(--critical); }
.sev.high { color: var(--high); }
.sev.medium { color: var(--medium); }
.sev.low, .sev.info { color: var(--low); }
.finding p { margin: 0 0 10px; max-width: 68ch; }
.fix { border-top: 1px solid var(--rule); padding-top: 10px; font-size: 14px; }
.fix b { font-weight: 600; }
details { margin-top: 10px; }
summary { cursor: pointer; color: var(--muted); font-size: 12.5px; }
summary:focus-visible { outline: 2px solid var(--medium); outline-offset: 2px; }
pre {
  background: var(--paper); border: 1px solid var(--rule); padding: 10px 12px;
  overflow-x: auto; font-size: 12px; margin: 8px 0 0;
}
.empty { color: var(--muted); font-style: italic; }
footer { border-top: 1px solid var(--rule); padding-top: 16px; color: var(--muted); font-size: 12.5px; }
@media (max-width: 620px) {
  .summary { gap: 18px; }
  .waste { margin-left: 0; text-align: left; }
  .score b { font-size: 44px; }
}
"""


def _finding_html(f: Finding) -> str:
    e = html.escape
    sev = f.severity.value
    waste = (
        f" · <b>US$ {f.monthly_waste_usd:,.2f}/mês</b>" if f.monthly_waste_usd else ""
    )
    wa = f" · {e(f.well_architected)}" if f.well_architected else ""
    resource = e(f.resource_arn or f.resource_id)
    evidence = ""
    if f.evidence:
        body = e(json.dumps(f.evidence, indent=2, ensure_ascii=False, default=str))
        evidence = f"<details><summary>Evidência coletada</summary><pre>{body}</pre></details>"
    return f"""
    <article class="finding {sev}">
      <h3>{e(f.title)}</h3>
      <p class="meta">
        <span class="sev {sev}">{e(f.severity.label)}</span>
        · risco {f.risk_score} · {e(f.region)} · <code>{e(f.check_id)}</code>{wa}{waste}
      </p>
      <p>{e(f.description)}</p>
      <p class="mono">{resource}</p>
      <div class="fix"><b>Como corrigir:</b> {e(f.remediation)}</div>
      {evidence}
    </article>"""


def render_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts_by_severity()
    alias = f" · {e(result.account_alias)}" if result.account_alias else ""
    ordered = sorted(result.findings, key=lambda f: f.sort_key)

    tally = "".join(
        f'<div><b class="sev {s.value}">{counts[s.value]}</b><span>{e(s.label.capitalize())}</span></div>'
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    )

    sections = []
    notes = {
        Pillar.SECURITY: "Ordenado por risco real: a severidade base é ajustada por exposição à internet, privilégio e sensibilidade do dado.",
        Pillar.RELIABILITY: "Pontos onde a perda de uma AZ, um delete acidental ou uma falha de backup vira indisponibilidade.",
        Pillar.COST: "Recursos ociosos e oportunidades de troca. Os valores são estimativas para priorização.",
    }
    for pillar in (Pillar.SECURITY, Pillar.RELIABILITY, Pillar.COST):
        group = [f for f in ordered if f.pillar is pillar]
        body = (
            "".join(_finding_html(f) for f in group)
            if group
            else '<p class="empty">Nenhum achado neste pilar.</p>'
        )
        extra = ""
        if pillar is Pillar.COST and result.estimated_monthly_waste:
            extra = f" Total estimado: US$ {result.estimated_monthly_waste:,.2f}/mês."
        sections.append(
            f"<section><h2>{e(pillar.label)} — {len(group)}</h2>"
            f'<p class="section-note">{e(notes[pillar])}{extra}</p>{body}</section>'
        )

    errors_html = ""
    if result.errors:
        by_code: Dict[str, int] = {}
        for err in result.errors:
            by_code[err.error_code] = by_code.get(err.error_code, 0) + 1
        rows = ", ".join(f"{n}× {e(code)}" for code, n in sorted(by_code.items(), key=lambda kv: -kv[1]))
        errors_html = (
            f"<p>{len(result.errors)} execuções de check não concluíram ({rows}). "
            "Em geral falta permissão na role de leitura — o resultado acima está incompleto nesses pontos.</p>"
        )

    waste_block = (
        f'<div class="waste"><b>US$ {result.estimated_monthly_waste:,.2f}</b>'
        f"<span>desperdício estimado por mês</span></div>"
        if result.estimated_monthly_waste
        else ""
    )

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Posture scan — conta {e(result.account_id)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Posture scan da conta {e(result.account_id)}{alias}</h1>
    <p>{len(result.regions)} regiões · {result.resources_evaluated} recursos avaliados ·
       {result.checks_executed} execuções de check · concluído em {result.duration_seconds}s ·
       {e(result.finished_at[:19].replace('T', ' '))} UTC</p>
  </header>

  <div class="summary">
    <div class="score"><b>{result.posture_score}</b><span>posture score de 100</span></div>
    <div class="tally">{tally}</div>
    {waste_block}
  </div>

  {''.join(sections)}

  <footer>
    {errors_html}
    <p>Gerado por um scanner read-only construído com boto3. Nenhuma credencial foi armazenada
       e nenhuma chamada de escrita foi executada. Valores de custo são estimativas de lista.</p>
  </footer>
</div>
</body>
</html>"""


def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(result))
