"""
Report Generator Tool v2
Executive HTML reports from engagement data or tool JSON exports

Sources:
  --input scan_results.json / .csv   (legacy per-tool exports)
  --from-store                       (active engagement: findings/services)

HTML output: exec summary (metadata, scope, top risks), severity
distribution with inline-SVG charts (zero CDN, offline), finding cards
with CVSS badges + evidence collapse, per-host service drilldown, and an
@media print stylesheet (Print -> Save as PDF needs no dependencies).
"""

import html as html_lib
import json
import os
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, kv, Colors, emit_json
)

from vantic.core import store

META = {
    "name": "report",
    "title": "Report Generator",
    "category": "ANALYSIS & REPORTING",
    "description": "Executive HTML/JSON/Markdown reports",
    "risk": "safe",
    "examples": [
        "vantic report --from-store --output report.html",
        "vantic report --input scan_results.json --output report.html",
        "vantic report --input results.csv --output report.md --format markdown",
    ],
    "flow": [
        ("opt", "--output", "Output file", "vantic_report.html"),
        ("opt", "--format", "Format (html/json/markdown)", "html"),
        ("opt", "--input", "Input JSON/CSV (blank = engagement store)", ""),
        ("opt", "--title", "Report title", ""),
    ],
    "guard": {},
}

SENSITIVE_SERVICES = {'MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'MSSQL',
                     'Oracle', 'FTP', 'Telnet', 'RDP', 'Memcached'}
WEB_SERVICES = {'HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt', 'Node.js', 'Django'}

SEV_COLORS = {"critical": "#ff5252", "high": "#ff9800", "medium": "#ffeb3b",
             "low": "#4fc3f7", "info": "#90a4ae"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _coerce_port(entry):
    try:
        port = int(float(entry.get('port', 0)))
    except (ValueError, TypeError):
        port = 0
    try:
        rt = float(entry.get('response_time', 0) or 0)
    except (ValueError, TypeError):
        rt = 0.0
    return {'port': port, 'status': str(entry.get('status', 'UNKNOWN')).upper(),
            'service': str(entry.get('service', 'unknown')), 'response_time': rt,
            'banner': str(entry.get('banner', '') or '')}


def collect_data(input_file=None, from_store=False):
    """Gather (findings, services, ports, engagement_meta) from a source."""
    findings_list = []
    services = []
    ports = []
    meta = {}

    if from_store or (not input_file and store.is_active()):
        meta = store.metadata() or {}
        findings_list = store.findings_all()
        services = store.services_all()
        return findings_list, services, ports, meta

    if input_file:
        if input_file.lower().endswith('.json'):
            with open(input_file, 'r', errors='ignore') as f:
                data = json.load(f)
            if isinstance(data, list):
                data = {'ports': data}
            ports = [_coerce_port(p) for p in data.get('ports', [])]
            # Tool exports may carry findings (shape: {"tool",..., "results"})
            findings_list = data.get('findings', [])
        elif input_file.lower().endswith('.csv'):
            import csv
            with open(input_file, 'r', errors='ignore') as f:
                ports = [_coerce_port(p) for p in csv.DictReader(f)]
        else:
            raise ValueError("Unsupported input format (use .json or .csv)")
    return findings_list, services, ports, meta


# ---------- SVG charts (no CDN, offline) ----------

def svg_donut(counts, size=170):
    """Severity donut via stroke-dasharray segments."""
    total = sum(counts.values()) or 1
    radius = size / 2 - 18
    circumference = 2 * 3.141592653589793 * radius
    segs = []
    offset = 0.0
    for sev in SEV_ORDER:
        val = counts.get(sev, 0)
        if not val:
            continue
        frac = val / total
        dash = frac * circumference
        segs.append(
            f'<circle r="{radius:.1f}" cx="{size / 2}" cy="{size / 2}" fill="none" '
            f'stroke="{SEV_COLORS[sev]}" stroke-width="22" '
            f'stroke-dasharray="{dash:.1f} {circumference - dash:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" transform="rotate(-90 {size / 2} {size / 2})"/>')
        offset += dash
    label = f'<text x="{size / 2}" y="{size / 2 - 4}" text-anchor="middle" fill="#e0e0e0" ' \
           f'font-size="30" font-weight="bold">{total}</text>' \
           f'<text x="{size / 2}" y="{size / 2 + 20}" text-anchor="middle" fill="#888" ' \
           f'font-size="12">findings</text>'
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            + ''.join(segs) + label + '</svg>')


def svg_bars(counts, width=430, height=150):
    """Severity bar chart via rects."""
    max_val = max(list(counts.values()) + [1])
    bar_w = (width - 40) / len(SEV_ORDER)
    bars = []
    for i, sev in enumerate(SEV_ORDER):
        val = counts.get(sev, 0)
        h = (val / max_val) * (height - 45)
        x = 20 + i * bar_w
        y = height - 30 - h
        bars.append(
            f'<rect x="{x + 6:.0f}" y="{y:.1f}" width="{bar_w - 12:.0f}" height="{max(h, 0):.1f}" '
            f'rx="3" fill="{SEV_COLORS[sev]}"/>'
            f'<text x="{x + 6 + (bar_w - 12) / 2:.0f}" y="{y - 6:.1f}" text-anchor="middle" '
            f'fill="#bbb" font-size="12">{val}</text>'
            f'<text x="{x + 6 + (bar_w - 12) / 2:.0f}" y="{height - 12}" text-anchor="middle" '
            f'fill="#888" font-size="11">{sev}</text>')
    return f'<svg width="{width}" height="{height}">' + ''.join(bars) + '</svg>'


# ---------- HTML ----------

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: linear-gradient(135deg, #101418 0%, #131c26 100%); color: #e8e8e8;
  padding: 40px 20px; min-height: 100vh; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
.header {{ text-align: center; padding: 40px; background: rgba(255,255,255,0.04);
  border-radius: 15px; margin-bottom: 30px; }}
.header h1 {{ font-size: 2.4em; background: linear-gradient(135deg, #00d9ff, #00ff88);
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 10px; }}
.header p {{ color: #98a2ab; font-size: 1.05em; }}
.section {{ background: rgba(255,255,255,0.04); border-radius: 15px; padding: 30px;
  margin-bottom: 20px; }}
.section h2 {{ color: #00d9ff; margin-bottom: 20px; padding-bottom: 10px;
  border-bottom: 1px solid rgba(0,217,255,0.25); }}
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 16px; margin-bottom: 10px; }}
.stat-card {{ background: rgba(0,217,255,0.07); padding: 22px; border-radius: 12px;
  text-align: center; border: 1px solid rgba(0,217,255,0.18); }}
.stat-card.critical {{ border-color: rgba(255,87,34,0.35); background: rgba(255,87,34,0.08); }}
.stat-card.high {{ border-color: rgba(255,152,0,0.35); background: rgba(255,152,0,0.08); }}
.stat-number {{ font-size: 2.6em; font-weight: bold; color: #00d9ff; }}
.stat-card.critical .stat-number {{ color: #ff5722; }}
.stat-card.high .stat-number {{ color: #ff9800; }}
.stat-label {{ color: #98a2ab; margin-top: 8px; font-size: 0.92em; }}
.charts {{ display: flex; flex-wrap: wrap; gap: 30px; align-items: center;
  justify-content: center; padding: 10px 0; }}
.legend {{ display: flex; gap: 14px; flex-wrap: wrap; justify-content: center;
  color: #98a2ab; font-size: 0.9em; margin-top: 8px; }}
.legend span::before {{ content: "●"; margin-right: 5px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.08); }}
th {{ background: rgba(0,217,255,0.08); color: #00d9ff; font-weight: 600; font-size: 0.92em; }}
tr:hover {{ background: rgba(255,255,255,0.04); }}
.badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 700; }}
.badge.critical {{ background: rgba(255,82,82,0.18); color: #ff5252; }}
.badge.high {{ background: rgba(255,152,0,0.18); color: #ff9800; }}
.badge.medium {{ background: rgba(255,235,59,0.15); color: #ffeb3b; }}
.badge.low {{ background: rgba(79,195,247,0.15); color: #4fc3f7; }}
.badge.info {{ background: rgba(144,164,174,0.15); color: #90a4ae; }}
.cvss {{ font-family: ui-monospace, monospace; color: #00d9ff; font-size: 0.85em; }}
details {{ margin-top: 6px; }}
summary {{ cursor: pointer; color: #00d9ff; font-size: 0.88em; }}
pre.evidence {{ background: rgba(0,0,0,0.35); padding: 12px; border-radius: 8px;
  margin-top: 8px; white-space: pre-wrap; font-size: 0.82em; color: #b8c4cc;
  font-family: ui-monospace, monospace; }}
.footer {{ text-align: center; padding: 30px; color: #5c676f; margin-top: 40px; }}
@media print {{
  body {{ background: #fff; color: #111; }}
  .section, .header {{ background: #f6f8fa; border: 1px solid #ddd; }}
  .header h1 {{ -webkit-text-fill-color: #0077b6; }}
  th {{ color: #0077b6; }}
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>{title}</h1>
    <p>{subtitle}</p>
    <p style="margin-top: 10px; font-size: 0.9em;">{author} | {date}</p>
  </div>

  <div class="stat-grid">
    {stat_cards}
  </div>

  <div class="section">
    <h2>Severity Distribution</h2>
    <div class="charts">
      {donut}
      {bars}
    </div>
    <div class="legend">
      <span style="color:{lcritical}">Critical</span>
      <span style="color:{lhigh}">High</span>
      <span style="color:{lmedium}">Medium</span>
      <span style="color:{llow}">Low</span>
      <span style="color:{linfo}">Info</span>
    </div>
  </div>

  {exec_section}

  <div class="section">
    <h2>Findings</h2>
    {findings_cards}
  </div>

  {services_section}

  <div class="footer">
    <p>Report generated by <strong>Vantic Breach</strong></p>
    <p style="margin-top: 10px;">&copy; {year} Vantic | Every wall has a way in.</p>
  </div>
</div>
</body>
</html>'''


def generate_html(findings_list, services, ports, output, title, author, meta):
    counts = {sev: 0 for sev in SEV_ORDER}
    for f in findings_list:
        counts[f.get('severity', 'info')] = counts.get(f.get('severity', 'info'), 0) + 1

    open_ports = [p for p in ports if p['status'] == 'OPEN']
    stat_cards = f'''
      <div class="stat-card"><div class="stat-number">{len(findings_list)}</div>
        <div class="stat-label">Findings</div></div>
      <div class="stat-card critical"><div class="stat-number">{counts['critical']}</div>
        <div class="stat-label">Critical</div></div>
      <div class="stat-card high"><div class="stat-number">{counts['high']}</div>
        <div class="stat-label">High</div></div>
      <div class="stat-card"><div class="stat-number">{len(services) or len(open_ports)}</div>
        <div class="stat-label">Services Observed</div></div>
      <div class="stat-card"><div class="stat-number">{len(ports)}</div>
        <div class="stat-label">Ports Scanned</div></div>'''

    # Exec summary: scope + top-5 risks
    exec_bits = []
    if meta:
        exec_bits.append('<div class="section"><h2>Engagement</h2>'
                         '<table><tr><th>Field</th><th>Value</th></tr>')
        for k in ('name', 'client', 'auth_ref', 'start_date', 'end_date', 'created_at'):
            if meta.get(k):
                exec_bits.append(f'<tr><td>{k.replace("_", " ").title()}</td>'
                                 f'<td>{html_lib.escape(str(meta[k]))}</td></tr>')
        exec_bits.append('</table></div>')
    top = sorted(findings_list,
                 key=lambda f: SEV_ORDER.index(f.get('severity', 'info')))[:5]
    if top:
        exec_bits.append('<div class="section"><h2>Top Risks</h2><ol>')
        for f in top:
            exec_bits.append(
                f'<li><span class="badge {f.get("severity", "info")}">'
                f'{f.get("severity", "info").upper()}</span> '
                f'{html_lib.escape(str(f.get("title", "")))}'
                f' <span style="color:#98a2ab">({html_lib.escape(str(f.get("target", "")))})</span></li>')
        exec_bits.append('</ol></div>')
    exec_section = ''.join(exec_bits)

    # Finding cards
    if findings_list:
        cards = []
        for f in sorted(findings_list, key=lambda x: SEV_ORDER.index(x.get('severity', 'info'))):
            cvss = ''
            if f.get('cvss_score') is not None:
                cvss = f'<span class="cvss">CVSS {f["cvss_score"]} ' \
                       f'{html_lib.escape(str(f.get("cvss_vector", "")))}</span>'
            ev = html_lib.escape(str(f.get('evidence', '') or '-'))[:2000]
            rem = html_lib.escape(str(f.get('remediation', '') or '-'))
            cards.append(f'''
              <div style="margin-bottom:18px; padding:16px; border-radius:10px;
                background: rgba(255,255,255,0.03); border-left: 4px solid
                {SEV_COLORS[f.get('severity', 'info')]}">
                <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                  <span class="badge {f.get('severity', 'info')}">
                    {f.get('severity', 'info').upper()}</span>
                  <strong>{html_lib.escape(str(f.get('title', '')))}</strong> {cvss}
                </div>
                <div style="color:#98a2ab; font-size:0.88em; margin-top:6px;">
                  {html_lib.escape(str(f.get('target', '') or '-'))}
                  {(' : ' + str(f.get('port'))) if f.get('port') else ''}
                  &middot; {html_lib.escape(str(f.get('family', '')))}
                  &middot; via {html_lib.escape(str(f.get('tool', '')))}
                </div>
                <div style="margin-top:10px;"><b>Remediation:</b> {rem}</div>
                <details><summary>Evidence</summary>
                  <pre class="evidence">{ev}</pre>
                </details>
              </div>''')
        findings_cards = ''.join(cards)
    else:
        findings_cards = '<p style="color:#98a2ab">No findings recorded ' \
                         '(run tools with an active engagement to collect them).</p>'

    # Services drilldown
    if services:
        rows = []
        for s in services:
            rows.append(f'''<tr><td>{html_lib.escape(str(s.get('host', '')))}</td>
              <td>{s.get('port')}</td><td>{html_lib.escape(str(s.get('protocol', 'tcp')))}</td>
              <td>{html_lib.escape(str(s.get('service_name') or '-'))}</td>
              <td style="font-family:ui-monospace,monospace;font-size:0.82em;">
                {html_lib.escape(str(s.get('banner') or '-')[:80])}</td></tr>''')
        services_section = ('<div class="section"><h2>Observed Services</h2><table>'
                           '<tr><th>Host</th><th>Port</th><th>Proto</th>'
                           '<th>Service</th><th>Banner</th></tr>'
                           + ''.join(rows) + '</table></div>')
    elif open_ports:
        rows = ''.join(
            f'<tr><td><strong>{p["port"]}</strong></td>'
            f'<td>{html_lib.escape(p["service"])}</td>'
            f'<td><span class="badge info">{p["status"]}</span></td>'
            f'<td>{p["response_time"]:.1f}ms</td></tr>' for p in open_ports)
        services_section = ('<div class="section"><h2>Open Ports</h2><table>'
                           '<tr><th>Port</th><th>Service</th><th>Status</th>'
                           '<th>Response</th></tr>' + rows + '</table></div>')
    else:
        services_section = ''

    html = HTML_TEMPLATE.format(
        title=html_lib.escape(title),
        subtitle='Security assessment report' + (
            f' · engagement {html_lib.escape(str(meta.get("name", "")))}' if meta.get('name') else ''),
        author=html_lib.escape(author),
        date=datetime.now().strftime('%B %d, %Y at %H:%M'),
        year=datetime.now().year,
        stat_cards=stat_cards,
        donut=svg_donut(counts),
        bars=svg_bars(counts),
        exec_section=exec_section,
        findings_cards=findings_cards,
        services_section=services_section,
        lcritical=SEV_COLORS['critical'], lhigh=SEV_COLORS['high'],
        lmedium=SEV_COLORS['medium'], llow=SEV_COLORS['low'], linfo=SEV_COLORS['info'],
    )
    with open(output, 'w') as f:
        f.write(html)
    return output


def generate_markdown(findings_list, services, ports, output, title):
    counts = {sev: 0 for sev in SEV_ORDER}
    for f in findings_list:
        counts[f.get('severity', 'info')] = counts.get(f.get('severity', 'info'), 0) + 1

    md = [f"# {title}", "",
          f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "",
          "## Summary", ""]
    for sev in SEV_ORDER:
        md.append(f"- **{sev.title()}:** {counts[sev]}")
    if findings_list:
        md += ["", "## Findings", ""]
        for f in sorted(findings_list, key=lambda x: SEV_ORDER.index(x.get('severity', 'info'))):
            md.append(f"### [{f.get('severity', 'info').upper()}] {f.get('title')}")
            if f.get('target'):
                md.append(f"- Target: `{f.get('target')}`" +
                          (f":{f.get('port')}" if f.get('port') else ""))
            if f.get('remediation'):
                md.append(f"- Fix: {f['remediation']}")
            md.append("")
    if services:
        md += ["## Services", "", "| Host | Port | Service | Banner |",
               "|------|------|---------|--------|"]
        for s in services:
            md.append(f"| {s.get('host')} | {s.get('port')} | "
                      f"{s.get('service_name') or '-'} | {str(s.get('banner') or '-')[:40]} |")
    open_ports = [p for p in ports if p['status'] == 'OPEN']
    if open_ports:
        md += ["", "## Open Ports", "", "| Port | Service | Status |",
               "|------|---------|--------|"]
        for p in open_ports:
            md.append(f"| {p['port']} | {p['service']} | {p['status']} |")
    with open(output, 'w') as f:
        f.write('\n'.join(md) + '\n')
    return output


def add_arguments(parser):
    parser.add_argument('--input', help='Input data (JSON/CSV tool export)')
    parser.add_argument('--from-store', action='store_true',
                       help='Report from the active engagement store')
    parser.add_argument('--output', required=True, help='Output file')
    parser.add_argument('--format', choices=['html', 'json', 'markdown'], default='html')
    parser.add_argument('--title', help='Report title')
    parser.add_argument('--author', help='Report author')


def run(args):
    """Run report generator."""
    input_file = getattr(args, 'input', None)
    from_store = getattr(args, 'from_store', False)
    output_file = args.output
    output_format = args.format
    title = getattr(args, 'title', None) or 'Vantic Security Report'
    author = getattr(args, 'author', None) or 'Vantic'

    print_header("REPORT GENERATOR", output_format.upper())
    kv("Input", input_file or "engagement store" if (from_store or store.is_active())
       else input_file)
    kv("Output", output_file, Colors.BOLD)
    kv("Format", output_format)
    print()

    try:
        findings_list, services, ports, meta = collect_data(input_file, from_store)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print_error(f"Error reading input: {e}")
        return

    if not findings_list and not services and not ports:
        print_warning("Nothing to report - no findings, services or ports found")
        print_info("Collect data first: run tools with an active engagement "
                   "(vantic engage new + use), or pass --input a tool export")
        return

    try:
        if output_format == 'json':
            with open(output_file, 'w') as f:
                json.dump({'findings': findings_list, 'services': services,
                          'ports': ports, 'engagement': meta}, f,
                          indent=2, default=str)
            out = output_file
        elif output_format == 'markdown':
            out = generate_markdown(findings_list, services, ports, output_file, title)
        else:
            out = generate_html(findings_list, services, ports, output_file,
                                title, author, meta)
        print_success(f"Report generated: {Colors.CYAN}{out}{Colors.RESET}")
        if output_format == 'html':
            print_info("Print to PDF: open the file, Print, 'Save as PDF' "
                       "(print stylesheet included)")
    except OSError as e:
        print_error(f"Error generating report: {e}")
