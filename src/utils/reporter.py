"""
ReportGenerator — produces JSON, TXT, and HTML reports.
HTML report includes the Fatah2 banner and full risk table.
"""

import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SEV_COLORS = {
    "critical": "#ff2d55",
    "high":     "#ff9500",
    "medium":   "#ffd60a",
    "low":      "#30d158",
    "info":     "#636366",
}


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self, result, formats: list[str]) -> list[Path]:
        slug = result.domain.replace(".", "_")
        ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"{slug}_{ts}"
        paths = []

        writers = {
            "json": self._write_json,
            "txt":  self._write_txt,
            "html": self._write_html,
        }
        for fmt in formats:
            writer = writers.get(fmt.lower())
            if writer:
                p = await writer(result, base)
                paths.append(p)
            else:
                logger.warning(f"Unknown format: {fmt}")
        return paths

    # ── JSON ──────────────────────────────────────────────────────────────────

    async def _write_json(self, result, base: str) -> Path:
        path = self.output_dir / f"{base}.json"
        risk_serial = {}
        for k, v in result.risk_scores.items():
            try:
                risk_serial[k] = asdict(v)
            except Exception:
                risk_serial[k] = str(v)

        data = {
            "meta": {
                "tool":        "Fatah2",
                "author":      "Pr0fessor SnApe",
                "domain":      result.domain,
                "started_at":  result.started_at,
                "finished_at": result.finished_at,
            },
            "statistics":  result.statistics,
            "subdomains":  result.subdomains,
            "endpoints":   result.endpoints,
            "risk_scores": risk_serial,
            "errors":      result.errors,
        }
        path.write_text(json.dumps(data, indent=2, default=str))
        return path

    # ── TXT ───────────────────────────────────────────────────────────────────

    async def _write_txt(self, result, base: str) -> Path:
        path = self.output_dir / f"{base}.txt"
        stats = result.statistics
        lines = [
            "═══════════════════════════════════════════════════",
            "  FATAH2 — Advanced Recon Suite",
            "  Crafted by Pr0fessor SnApe",
            "═══════════════════════════════════════════════════",
            f"  Domain    : {result.domain}",
            f"  Started   : {result.started_at}",
            f"  Finished  : {result.finished_at}",
            f"  Subdomains: {stats.get('total_subdomains', 0)}",
            f"  Live hosts: {stats.get('live_hosts', 0)}",
            f"  Endpoints : {stats.get('total_endpoints', 0)}",
            f"  Duration  : {stats.get('scan_duration_s', 0)}s",
            "═══════════════════════════════════════════════════",
            "",
            "[ SUBDOMAINS ]",
        ]

        for sd_item in result.subdomains:
            sd = sd_item.get("subdomain", sd_item) if isinstance(sd_item, dict) else sd_item
            lines.append(f"  {sd}")

        lines += ["", "[ LIVE HOSTS ]"]
        for sd_item in result.subdomains:
            if not isinstance(sd_item, dict) or not sd_item.get("url"):
                continue
            sd   = sd_item.get("subdomain", "")
            url  = sd_item.get("url", "")
            code = sd_item.get("status_code", "")
            risk = result.risk_scores.get(sd)
            sev  = risk.severity.upper() if risk else "?"
            score = risk.overall if risk else "-"
            lines.append(f"  [{sev:8}] ({score:4}) {url} (HTTP {code})")

        lines += ["", "[ HIGH / CRITICAL FINDINGS ]"]
        for host, risk in sorted(
            result.risk_scores.items(),
            key=lambda x: x[1].overall, reverse=True,
        ):
            if risk.severity in ("high", "critical"):
                lines.append(f"\n  [{risk.severity.upper()}] {host}  score={risk.overall}")
                for f in risk.findings:
                    lines.append(f"     ↳ {f}")

        lines += ["", "[ ENDPOINTS ]"]
        for ep in result.endpoints:
            lines.append(f"  {ep.get('method','GET'):7} {ep.get('url','')}")

        if result.errors:
            lines += ["", "[ ERRORS ]"]
            lines.extend(f"  {e}" for e in result.errors)

        path.write_text("\n".join(lines))
        return path

    # ── HTML ──────────────────────────────────────────────────────────────────

    async def _write_html(self, result, base: str) -> Path:
        path = self.output_dir / f"{base}.html"
        stats = result.statistics

        host_rows = ""
        for sd_item in result.subdomains:
            if not isinstance(sd_item, dict):
                continue
            sd    = sd_item.get("subdomain", "")
            url   = sd_item.get("url", f"https://{sd}")
            code  = sd_item.get("status_code", "-")
            techs = ", ".join(sd_item.get("technologies", []))
            risk  = result.risk_scores.get(sd)
            sev   = risk.severity if risk else "info"
            score = risk.overall  if risk else "-"
            color = SEV_COLORS.get(sev, "#636366")
            host_rows += (
                f"<tr>"
                f"<td><a href='{url}' target='_blank'>{sd}</a></td>"
                f"<td class='code'>{code}</td>"
                f"<td style='color:{color};font-weight:700'>"
                f"{sev.upper()} ({score})</td>"
                f"<td class='gray'>{techs}</td>"
                f"</tr>\n"
            )

        ep_rows = ""
        for ep in result.endpoints[:1000]:
            method = ep.get("method", "GET")
            url    = ep.get("url", "")
            status = ep.get("status", "")
            color  = "#ffd60a" if any(
                p in url for p in [".env", "admin", "swagger", "debug", ".git"]
            ) else "inherit"
            ep_rows += (
                f"<tr><td class='method'>{method}</td>"
                f"<td style='color:{color};word-break:break-all'>{url}</td>"
                f"<td class='code'>{status}</td></tr>\n"
            )

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for risk in result.risk_scores.values():
            sev_counts[risk.severity] = sev_counts.get(risk.severity, 0) + 1

        sev_bars = ""
        for sev, count in sev_counts.items():
            if count > 0:
                color = SEV_COLORS.get(sev, "#636366")
                sev_bars += (
                    f"<div class='sev-row'>"
                    f"<span class='sev-label' style='color:{color}'>"
                    f"{sev.upper()}</span>"
                    f"<div class='bar-wrap'>"
                    f"<div class='bar' style='width:{min(count*20,300)}px;"
                    f"background:{color}'></div></div>"
                    f"<span class='sev-count'>{count}</span></div>\n"
                )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fatah2 — {result.domain}</title>
<style>
:root {{
  --bg:#0a0e17; --bg2:#0f1623; --bg3:#141d2b;
  --border:#1e2d45; --text:#c8d8f0; --dim:#607090;
  --accent:#00c8ff; --purple:#a855f7; --green:#30d158;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;
  font-size:14px;line-height:1.6}}
.banner{{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:2rem 2.5rem 1.5rem}}
.ascii{{color:var(--accent);font-size:11px;line-height:1.3;white-space:pre;
  letter-spacing:0.05em}}
.tagline{{color:var(--purple);margin-top:.5rem;font-size:13px}}
.by{{color:var(--dim);font-size:12px;margin-top:.2rem}}
.meta{{color:var(--dim);margin-top:.75rem;font-size:12px}}
main{{padding:2rem 2.5rem}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:1rem;margin-bottom:2rem}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:1.25rem;text-align:center}}
.stat-num{{font-size:2.2rem;font-weight:700;color:var(--accent);display:block}}
.stat-lbl{{color:var(--dim);font-size:11px;margin-top:.25rem;
  text-transform:uppercase;letter-spacing:.08em}}
.sev-chart{{background:var(--bg2);border:1px solid var(--border);
  border-radius:8px;padding:1.25rem;margin-bottom:2rem}}
.sev-row{{display:flex;align-items:center;gap:.75rem;margin:.4rem 0}}
.sev-label{{width:70px;font-size:12px;font-weight:700;text-align:right}}
.bar-wrap{{flex:1}}
.bar{{height:14px;border-radius:3px;min-width:4px;transition:width .3s}}
.sev-count{{color:var(--dim);font-size:12px;width:30px;text-align:right}}
h2{{color:var(--accent);font-size:14px;letter-spacing:.1em;
  text-transform:uppercase;border-bottom:1px solid var(--border);
  padding-bottom:.5rem;margin:2rem 0 1rem}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--bg3);padding:.6rem .75rem;text-align:left;
  color:var(--dim);font-size:11px;text-transform:uppercase;
  letter-spacing:.08em;border-bottom:1px solid var(--border)}}
td{{padding:.45rem .75rem;border-bottom:1px solid #0f1a29;vertical-align:top}}
tr:hover td{{background:#0f1a29}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
.code{{color:var(--dim);font-size:12px}}
.method{{color:var(--green);font-size:12px;font-weight:700}}
.gray{{color:var(--dim)}}
footer{{border-top:1px solid var(--border);padding:1.5rem 2.5rem;
  color:var(--dim);font-size:11px;text-align:center}}
</style>
</head>
<body>

<div class="banner">
<div class="ascii"> ███████╗ █████╗ ████████╗ █████╗ ██╗  ██╗██████╗
 ██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║  ██║╚════██╗
 █████╗  ███████║   ██║   ███████║███████║ █████╔╝
 ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══██║██╔═══╝
 ██║     ██║  ██║   ██║   ██║  ██║██║  ██║███████╗
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝</div>
<div class="tagline">Advanced Recon Suite · v2.0.0</div>
<div class="by">Crafted by Pr0fessor SnApe</div>
<div class="meta">
  Target: <strong style="color:var(--text)">{result.domain}</strong>
  &nbsp;|&nbsp; Started: {result.started_at}
  &nbsp;|&nbsp; Finished: {result.finished_at}
</div>
</div>

<main>
<div class="stats">
  <div class="stat">
    <span class="stat-num">{stats.get('total_subdomains',0)}</span>
    <div class="stat-lbl">Subdomains</div>
  </div>
  <div class="stat">
    <span class="stat-num">{stats.get('live_hosts',0)}</span>
    <div class="stat-lbl">Live Hosts</div>
  </div>
  <div class="stat">
    <span class="stat-num">{stats.get('total_endpoints',0)}</span>
    <div class="stat-lbl">Endpoints</div>
  </div>
  <div class="stat">
    <span class="stat-num">{stats.get('scan_duration_s',0)}s</span>
    <div class="stat-lbl">Duration</div>
  </div>
</div>

<div class="sev-chart">
  <h2 style="margin-top:0;border:none">Risk Breakdown</h2>
  {sev_bars}
</div>

<h2>Discovered Hosts</h2>
<table>
<thead><tr>
  <th>Subdomain</th><th>Status</th><th>Risk</th><th>Technologies</th>
</tr></thead>
<tbody>{host_rows}</tbody>
</table>

<h2>Endpoints (top 1000)</h2>
<table>
<thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead>
<tbody>{ep_rows}</tbody>
</table>
</main>

<footer>Fatah2 · Crafted by Pr0fessor SnApe · For authorized security assessments only</footer>
</body></html>"""

        path.write_text(html)
        return path
