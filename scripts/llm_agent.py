import json
import os
import sys
import requests
from datetime import datetime

REPORTS_DIR = "/home/server/devsecops-project/reports"
OLLAMA_URL  = "http://localhost:11434/api/generate"
MODEL       = "mistral"

def get_latest_report():
    files = sorted([
        f for f in os.listdir(REPORTS_DIR)
        if f.startswith("zap_report") and f.endswith(".json")
    ])
    if not files:
        print("[!] No ZAP reports found.")
        sys.exit(1)
    latest = os.path.join(REPORTS_DIR, files[-1])
    print(f"[*] Analyzing report: {files[-1]}")
    return latest

def parse_vulnerabilities(report_path):
    with open(report_path) as f:
        data = json.load(f)
    vulns = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            vulns.append({
                "name":      alert.get("name", "Unknown"),
                "risk":      alert.get("riskdesc", "Unknown"),
                "desc":      alert.get("desc", "")[:150],
                "solution":  alert.get("solution", "")[:150],
                "instances": len(alert.get("instances", []))
            })
    return vulns

def count_by_severity(vulnerabilities):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for v in vulnerabilities:
        risk = v['risk'].split(" ")[0]
        if risk in counts:
            counts[risk] += 1
    return counts

def ask_mistral(vulnerabilities):
    top3 = vulnerabilities[:3]
    vuln_text = ""
    for i, v in enumerate(top3, 1):
        vuln_text += f"Vulnerability {i}: {v['name']} - Risk: {v['risk']}\n"

    prompt = f"""You are a security expert. Analyze these web vulnerabilities briefly:

{vuln_text}

For each vulnerability provide:
1. What it is (1 sentence)
2. How to fix it (1-2 sentences)

Be very brief and direct."""

    print("[*] Sending report to Mistral for analysis...")
    print("[*] This may take 1-2 minutes...")

    response = requests.post(OLLAMA_URL, json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }, timeout=600)

    if response.status_code != 200:
        print(f"[!] Ollama error: {response.status_code}")
        sys.exit(1)

    return response.json().get("response", "No response received")

def save_html_report(vulnerabilities, analysis):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    counts    = count_by_severity(vulnerabilities)
    total     = len(vulnerabilities)

    # Policy decision
    blocking = counts["Critical"] + counts["High"]
    if blocking > 0:
        decision      = "DEPLOYMENT BLOCKED"
        decision_color = "#ff4444"
        decision_icon  = "✗"
    else:
        decision      = "DEPLOYMENT ALLOWED"
        decision_color = "#00d4aa"
        decision_icon  = "✓"

    # Build vulnerability cards for top 3
    vuln_cards = ""
    risk_colors = {
        "Critical": "#ff0055",
        "High":     "#ff4444",
        "Medium":   "#ffaa00",
        "Low":      "#00aaff",
        "Informational": "#888888"
    }
    for v in vulnerabilities[:3]:
        risk_word = v['risk'].split(" ")[0]
        color = risk_colors.get(risk_word, "#888888")
        vuln_cards += f"""
        <div class="vuln-card" style="border-left: 4px solid {color}">
            <div class="vuln-header">
                <span class="risk-badge" style="background:{color}">{risk_word}</span>
                <span class="vuln-instances">{v['instances']} instance(s)</span>
            </div>
            <h3 class="vuln-name">{v['name']}</h3>
            <p class="vuln-desc">{v['desc']}</p>
        </div>
        """

    # Build AI analysis paragraphs
    analysis_html = ""
    for line in analysis.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("**") or line[0].isdigit():
            analysis_html += f'<p class="analysis-point">{line}</p>'
        else:
            analysis_html += f'<p class="analysis-text">{line}</p>'

    # Chart data for JS
    chart_labels = list(counts.keys())
    chart_values = list(counts.values())
    chart_colors = ["#ff0055", "#ff4444", "#ffaa00", "#00aaff", "#888888"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S-Gate Security Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg:        #0a0e1a;
            --surface:   #0f1628;
            --surface2:  #151d35;
            --accent:    #00d4aa;
            --accent2:   #0088ff;
            --text:      #c8d6f0;
            --text-dim:  #5a6a8a;
            --danger:    #ff4444;
            --warning:   #ffaa00;
            --info:      #00aaff;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Exo 2', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            background-image:
                radial-gradient(ellipse at 20% 20%, rgba(0,212,170,0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(0,136,255,0.05) 0%, transparent 50%);
        }}

        /* ── TOP BAR ── */
        .topbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 40px;
            border-bottom: 1px solid rgba(0,212,170,0.15);
            background: rgba(15,22,40,0.8);
            backdrop-filter: blur(10px);
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .logo {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 1.4rem;
            color: var(--accent);
            letter-spacing: 3px;
        }}
        .logo span {{ color: var(--text-dim); }}
        .timestamp {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-dim);
        }}
        .status-pill {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 2px;
            color: {decision_color};
            border: 1px solid {decision_color};
            background: rgba(0,0,0,0.3);
            animation: pulse-border 2s infinite;
        }}
        @keyframes pulse-border {{
            0%, 100% {{ box-shadow: 0 0 0 0 {decision_color}44; }}
            50% {{ box-shadow: 0 0 0 6px transparent; }}
        }}

        /* ── MAIN LAYOUT ── */
        .main {{
            padding: 40px;
            max-width: 1400px;
            margin: 0 auto;
        }}

        /* ── HERO DECISION BANNER ── */
        .hero {{
            text-align: center;
            padding: 50px 20px;
            margin-bottom: 40px;
            position: relative;
            overflow: hidden;
        }}
        .hero::before {{
            content: '';
            position: absolute;
            inset: 0;
            background: radial-gradient(ellipse at center, {decision_color}11 0%, transparent 70%);
        }}
        .decision-icon {{
            font-size: 4rem;
            color: {decision_color};
            display: block;
            margin-bottom: 10px;
            font-family: 'Share Tech Mono', monospace;
        }}
        .decision-text {{
            font-size: 2.5rem;
            font-weight: 700;
            color: {decision_color};
            letter-spacing: 4px;
            text-transform: uppercase;
            text-shadow: 0 0 30px {decision_color}66;
        }}
        .decision-sub {{
            color: var(--text-dim);
            margin-top: 10px;
            font-size: 0.9rem;
            letter-spacing: 1px;
        }}

        /* ── STAT CARDS ── */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 16px;
            margin-bottom: 40px;
        }}
        @media (max-width: 900px) {{
            .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
            position: relative;
            overflow: hidden;
        }}
        .stat-card::after {{
            content: '';
            position: absolute;
            bottom: 0; left: 0; right: 0;
            height: 3px;
            background: var(--card-color);
        }}
        .stat-card:hover {{
            transform: translateY(-4px);
            border-color: var(--card-color);
        }}
        .stat-number {{
            font-size: 2.2rem;
            font-weight: 700;
            color: var(--card-color);
            font-family: 'Share Tech Mono', monospace;
        }}
        .stat-label {{
            font-size: 0.7rem;
            color: var(--text-dim);
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-top: 6px;
        }}

        /* ── DASHBOARD GRID ── */
        .dashboard {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 40px;
        }}
        @media (max-width: 800px) {{
            .dashboard {{ grid-template-columns: 1fr; }}
        }}

        /* ── PANELS ── */
        .panel {{
            background: var(--surface);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 16px;
            padding: 28px;
        }}
        .panel-title {{
            font-size: 0.75rem;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .panel-title::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: rgba(0,212,170,0.2);
        }}

        /* ── CHART ── */
        .chart-container {{
            position: relative;
            height: 280px;
        }}

        /* ── VULN CARDS ── */
        .vuln-card {{
            background: var(--surface2);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 14px;
            transition: transform 0.2s;
        }}
        .vuln-card:hover {{ transform: translateX(4px); }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .risk-badge {{
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #000;
        }}
        .vuln-instances {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-dim);
        }}
        .vuln-name {{
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 6px;
        }}
        .vuln-desc {{
            font-size: 0.8rem;
            color: var(--text-dim);
            line-height: 1.5;
        }}

        /* ── AI ANALYSIS ── */
        .analysis-point {{
            font-size: 0.9rem;
            color: var(--accent);
            font-weight: 600;
            margin: 12px 0 4px;
        }}
        .analysis-text {{
            font-size: 0.85rem;
            color: var(--text);
            line-height: 1.7;
            padding-left: 12px;
            border-left: 2px solid rgba(0,212,170,0.2);
            margin-bottom: 8px;
        }}

        /* ── FULL WIDTH PANEL ── */
        .panel-full {{
            background: var(--surface);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 24px;
        }}

        /* ── FOOTER ── */
        .footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-dim);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            letter-spacing: 2px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }}

        /* ── SCAN BAR ── */
        .scan-bar {{
            height: 6px;
            background: var(--surface2);
            border-radius: 3px;
            margin: 8px 0;
            overflow: hidden;
        }}
        .scan-bar-fill {{
            height: 100%;
            border-radius: 3px;
            background: var(--fill-color);
        }}
        .severity-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }}
        .severity-label {{
            font-size: 0.75rem;
            color: var(--text-dim);
            width: 100px;
        }}
        .severity-count {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.8rem;
            color: var(--text);
        }}
    </style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
    <div class="logo">S<span>-</span>GATE</div>
    <div class="timestamp">SCAN · {timestamp}</div>
    <div class="status-pill">{decision_icon} {decision}</div>
</div>

<div class="main">

    <!-- HERO -->
    <div class="hero">
        <span class="decision-icon">{decision_icon}</span>
        <div class="decision-text">{decision}</div>
        <div class="decision-sub">Automated Security Gate · Powered by OWASP ZAP + Mistral 7B</div>
    </div>

    <!-- STAT CARDS -->
    <div class="stats-grid">
        <div class="stat-card" style="--card-color: #ff0055">
            <div class="stat-number">{counts['Critical']}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card" style="--card-color: #ff4444">
            <div class="stat-number">{counts['High']}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card" style="--card-color: #ffaa00">
            <div class="stat-number">{counts['Medium']}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card" style="--card-color: #00aaff">
            <div class="stat-number">{counts['Low']}</div>
            <div class="stat-label">Low</div>
        </div>
        <div class="stat-card" style="--card-color: #888888">
            <div class="stat-number">{counts['Informational']}</div>
            <div class="stat-label">Info</div>
        </div>
        <div class="stat-card" style="--card-color: #00d4aa">
            <div class="stat-number">{total}</div>
            <div class="stat-label">Total</div>
        </div>
    </div>

    <!-- DASHBOARD GRID -->
    <div class="dashboard">

        <!-- CHART PANEL -->
        <div class="panel">
            <div class="panel-title">Vulnerability Distribution</div>
            <div class="chart-container">
                <canvas id="vulnChart"></canvas>
            </div>
        </div>

        <!-- SEVERITY BREAKDOWN -->
        <div class="panel">
            <div class="panel-title">Severity Breakdown</div>
            <br>
            {"".join([f'''
            <div class="severity-row">
                <span class="severity-label">{label}</span>
                <div class="scan-bar" style="flex:1; margin: 0 12px; --fill-color:{color}">
                    <div class="scan-bar-fill" style="width:{int(counts[label]/max(total,1)*100)}%; background:{color}"></div>
                </div>
                <span class="severity-count">{counts[label]}</span>
            </div>
            ''' for label, color in [("Critical","#ff0055"),("High","#ff4444"),("Medium","#ffaa00"),("Low","#00aaff"),("Informational","#888888")]])}
        </div>

        <!-- TOP VULNERABILITIES -->
        <div class="panel">
            <div class="panel-title">Top Vulnerabilities</div>
            {vuln_cards}
        </div>

        <!-- AI ANALYSIS -->
        <div class="panel">
            <div class="panel-title">AI Analysis · Mistral 7B</div>
            {analysis_html}
        </div>

    </div>

</div>

<!-- FOOTER -->
<div class="footer">
    S-GATE DEVSECOPS PIPELINE · OWASP ZAP 2.17 · MISTRAL 7B · {datetime.now().year}
</div>

<script>
const ctx = document.getElementById('vulnChart').getContext('2d');
new Chart(ctx, {{
    type: 'doughnut',
    data: {{
        labels: {chart_labels},
        datasets: [{{
            data: {chart_values},
            backgroundColor: {chart_colors},
            borderColor: '#0a0e1a',
            borderWidth: 3,
            hoverOffset: 8
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{
                position: 'bottom',
                labels: {{
                    color: '#5a6a8a',
                    padding: 16,
                    font: {{ size: 11 }}
                }}
            }}
        }},
        cutout: '65%'
    }}
}});
</script>

</body>
</html>"""

    output_path = os.path.join(REPORTS_DIR, f"ai_report_{file_ts}.html")
    with open(output_path, "w") as f:
        f.write(html)
    print(f"[+] ✅ AI dashboard report saved: {output_path}")
    return output_path


if __name__ == "__main__":
    report_path     = get_latest_report()
    vulnerabilities = parse_vulnerabilities(report_path)

    if not vulnerabilities:
        print("[*] No vulnerabilities found in report.")
        sys.exit(0)

    print(f"[*] Found {len(vulnerabilities)} vulnerabilities — analyzing top 3")
    analysis = ask_mistral(vulnerabilities)
    save_html_report(vulnerabilities, analysis)
    print("\n[+] ✅ AI analysis complete!")
