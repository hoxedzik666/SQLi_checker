"""
ReportGenerator - Generowanie raportów HTML
"""

import json
import os
from typing import List, Dict


class ReportGenerator:
    """Generowanie interaktywnych raportów HTML z Charts.js"""
    
    def __init__(self, output_dir: str = "outputs"):
        """
        Inicjalizacja generatora raportów
        
        Args:
            output_dir: Katalog do zapisywania raportów
        """
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def generate_html_report(self, filepath: str, vulnerabilities: List[Dict], 
                            stats_types: Dict, stats_payloads: Dict) -> None:
        """
        Generuje interaktywny raport HTML
        
        Args:
            filepath: Ścieżka do pliku wyjściowego
            vulnerabilities: Lista wykrytych podatności
            stats_types: Statystyki typów podatności
            stats_payloads: Statystyki effectiveness payloadów
        """
        v_json = json.dumps(vulnerabilities)
        t_labels = json.dumps(list(stats_types.keys()))
        t_data = json.dumps(list(stats_types.values()))
        p_labels = json.dumps([p[:30] for p in stats_payloads.keys()])
        p_data = json.dumps(list(stats_payloads.values()))
        
        html = f"""
        <!DOCTYPE html>
        <html lang="pl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SQL Injection Audit Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
                    color: #eee;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: auto;
                    background: #2d2d2d;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.5);
                }}
                
                h1 {{
                    color: #00d4ff;
                    text-align: center;
                    margin-bottom: 30px;
                    text-shadow: 0 0 10px rgba(0,212,255,0.3);
                }}
                
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .summary-card {{
                    background: linear-gradient(135deg, #333 0%, #444 100%);
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #00d4ff;
                    text-align: center;
                }}
                
                .summary-card h3 {{
                    color: #00d4ff;
                    font-size: 14px;
                    margin-bottom: 10px;
                    text-transform: uppercase;
                }}
                
                .summary-card .number {{
                    color: #00ff88;
                    font-size: 32px;
                    font-weight: bold;
                }}
                
                .charts {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                    gap: 30px;
                    margin-bottom: 30px;
                }}
                
                .chart-box {{
                    background: #333;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                }}
                
                .chart-box h2 {{
                    color: #00d4ff;
                    font-size: 16px;
                    margin-bottom: 15px;
                    text-transform: uppercase;
                }}
                
                .vulnerabilities {{
                    margin-top: 30px;
                }}
                
                .vulnerabilities h2 {{
                    color: #00d4ff;
                    margin-bottom: 15px;
                    text-transform: uppercase;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    background: #333;
                    border-radius: 8px;
                    overflow: hidden;
                }}
                
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #444;
                }}
                
                th {{
                    background: linear-gradient(135deg, #00d4ff 0%, #0099ff 100%);
                    color: #000;
                    font-weight: bold;
                }}
                
                tr:hover {{
                    background: #3d3d3d;
                }}
                
                .status-vulnerable {{
                    color: #00ff88;
                    font-weight: bold;
                }}
                
                code {{
                    background: #1a1a1a;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    color: #00d4ff;
                }}
                
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #444;
                    text-align: center;
                    color: #999;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 SQL Injection Audit Report</h1>
                
                <div class="summary">
                    <div class="summary-card">
                        <h3>Total Vulnerabilities</h3>
                        <div class="number" id="totalVulns">0</div>
                    </div>
                    <div class="summary-card">
                        <h3>Vulnerability Types</h3>
                        <div class="number" id="vulnTypes">0</div>
                    </div>
                    <div class="summary-card">
                        <h3>Effective Payloads</h3>
                        <div class="number" id="effectivePayloads">0</div>
                    </div>
                </div>
                
                <div class="charts">
                    <div class="chart-box">
                        <h2>Vulnerability Types</h2>
                        <canvas id="typeChart"></canvas>
                    </div>
                    <div class="chart-box">
                        <h2>Most Effective Payloads</h2>
                        <canvas id="payloadChart"></canvas>
                    </div>
                </div>
                
                <div class="vulnerabilities">
                    <h2>Detected Vulnerabilities</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Domain</th>
                                <th>Target</th>
                                <th>Method</th>
                                <th>Payload</th>
                            </tr>
                        </thead>
                        <tbody id="vulnTable"></tbody>
                    </table>
                </div>
                
                <div class="footer">
                    <p>Generated by SQLi Checker | Security Audit Report</p>
                </div>
            </div>
            
            <script>
                const vulns = {v_json};
                const typeStats = {t_labels};
                const typeData = {t_data};
                const payloadLabels = {p_labels};
                const payloadData = {p_data};
                
                // Aktualizacja statystyk
                document.getElementById('totalVulns').textContent = vulns.length;
                document.getElementById('vulnTypes').textContent = typeStats.length;
                document.getElementById('effectivePayloads').textContent = payloadLabels.length;
                
                // Tabela podatności
                const tbody = document.getElementById('vulnTable');
                vulns.forEach(v => {{
                    const row = `<tr>
                        <td>${{v.time}}</td>
                        <td><code>${{v.domain}}</code></td>
                        <td>${{v.target}}</td>
                        <td><span class="status-vulnerable">${{v.method}}</span></td>
                        <td><code>${{v.payload}}</code></td>
                    </tr>`;
                    tbody.innerHTML += row;
                }});
                
                // Wykres typów podatności
                if (typeStats.length > 0) {{
                    new Chart(document.getElementById('typeChart'), {{
                        type: 'doughnut',
                        data: {{
                            labels: typeStats,
                            datasets: [{{
                                data: typeData,
                                backgroundColor: ['#ff6384','#36a2eb','#ffce56','#4bc0c0','#9966ff','#ff9f40']
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            plugins: {{
                                legend: {{ position: 'bottom', labels: {{ color: '#fff' }} }}
                            }}
                        }}
                    }});
                }}
                
                // Wykres payloadów
                if (payloadLabels.length > 0) {{
                    new Chart(document.getElementById('payloadChart'), {{
                        type: 'bar',
                        data: {{
                            labels: payloadLabels,
                            datasets: [{{
                                label: 'Success Count',
                                data: payloadData,
                                backgroundColor: '#00d4ff',
                                borderColor: '#0099ff',
                                borderWidth: 1
                            }}]
                        }},
                        options: {{
                            indexAxis: 'y',
                            responsive: true,
                            plugins: {{
                                legend: {{ labels: {{ color: '#fff' }} }}
                            }},
                            scales: {{
                                x: {{ ticks: {{ color: '#999' }} }},
                                y: {{ ticks: {{ color: '#999' }} }}
                            }}
                        }}
                    }});
                }}
            </script>
        </body>
        </html>
        """
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"[OK] Raport HTML wygenerowany: {filepath}")
        except Exception as e:
            print(f"[ERROR] Błąd generowania raportu: {e}")
