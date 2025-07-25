#!/usr/bin/env python3
"""
Report Generator - Generación de reportes HTML/JSON/TXT
"""

import json
import time
from datetime import datetime
from jinja2 import Template
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class ReportGenerator:
    def __init__(self):
        self.report_data = {}
    
    def generate_console_report(self, scan_results):
        """Generar reporte en consola"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        scan_stats = scan_results.get('scan_stats', {})
        
        # Estadísticas del escaneo
        duration = scan_stats.get('end_time', 0) - scan_stats.get('start_time', 0)
        
        console.print("\n" + "="*80)
        console.print(f"🎯 SCAN RESULTS FOR: {scan_results.get('target', 'Unknown')}", style="bold blue")
        console.print("="*80)
        
        # Estadísticas generales
        stats_table = Table(title="📊 Scan Statistics", show_header=True)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Duration", f"{duration:.2f} seconds")
        stats_table.add_row("Requests Made", str(scan_stats.get('requests_made', 0)))
        stats_table.add_row("Vulnerabilities Found", str(len(vulnerabilities)))
        
        console.print(stats_table)
        console.print()
        
        if not vulnerabilities:
            console.print("✅ No vulnerabilities found!", style="bold green")
            return
        
        # Agrupar vulnerabilidades por severidad
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Tabla de severidad
        severity_table = Table(title="⚠️  Vulnerability Breakdown", show_header=True)
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="green")
        severity_table.add_column("Percentage", style="yellow")
        
        total_vulns = len(vulnerabilities)
        for severity, count in severity_counts.items():
            if count > 0:
                percentage = (count / total_vulns) * 100
                color = self._get_severity_color(severity)
                severity_table.add_row(severity, str(count), f"{percentage:.1f}%", style=color)
        
        console.print(severity_table)
        console.print()
        
        # Detalles de vulnerabilidades
        console.print("🔍 VULNERABILITY DETAILS", style="bold red")
        console.print("-" * 50)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            self._print_vulnerability_detail(i, vuln)
    
    def _get_severity_color(self, severity):
        """Obtener color según severidad"""
        colors = {
            'HIGH': 'bold red',
            'MEDIUM': 'bold yellow',
            'LOW': 'bold blue',
            'INFO': 'bold green'
        }
        return colors.get(severity, 'white')
    
    def _print_vulnerability_detail(self, index, vuln):
        """Imprimir detalles de una vulnerabilidad"""
        severity = vuln.get('severity', 'UNKNOWN')
        color = self._get_severity_color(severity)
        
        title = f"[{index}] {vuln.get('type', 'Unknown Vulnerability')}"
        
        vuln_panel = Panel(
            f"🎯 [bold]URL:[/bold] {vuln.get('url', 'N/A')}\n"
            f"📋 [bold]Category:[/bold] {vuln.get('category', 'Unknown')}\n"
            f"⚠️  [bold]Severity:[/bold] [{color}]{severity}[/{color}]\n"
            f"📝 [bold]Evidence:[/bold] {vuln.get('evidence', 'No evidence provided')}",
            title=title,
            border_style=color,
            expand=False
        )
        
        console.print(vuln_panel)
        console.print()
    
    def generate_html_report(self, scan_results, output_file):
        """Generar reporte HTML"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>VulnHunter Pro - Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .vulnerability { background: white; margin: 10px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .severity-high { border-left: 5px solid #dc3545; }
        .severity-medium { border-left: 5px solid #ffc107; }
        .severity-low { border-left: 5px solid #17a2b8; }
        .severity-info { border-left: 5px solid #28a745; }
        .evidence { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 VulnHunter Pro - Vulnerability Report</h1>
        <p>Target: {{ target }}</p>
        <p>Generated: {{ timestamp }}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>{{ vulnerabilities|length }}</h3>
            <p>Vulnerabilities Found</p>
        </div>
        <div class="stat-box">
            <h3>{{ scan_stats.requests_made }}</h3>
            <p>Requests Made</p>
        </div>
        <div class="stat-box">
            <h3>{{ "%.2f"|format(duration) }}s</h3>
            <p>Scan Duration</p>
        </div>
    </div>
    
    <h2>🔍 Vulnerability Details</h2>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability severity-{{ vuln.severity|lower }}">
        <h3>{{ vuln.type }}</h3>
        <p><strong>URL:</strong> {{ vuln.url }}</p>
        <p><strong>Category:</strong> {{ vuln.category }}</p>
        <p><strong>Severity:</strong> <span style="color: {% if vuln.severity == 'HIGH' %}#dc3545{% elif vuln.severity == 'MEDIUM' %}#ffc107{% elif vuln.severity == 'LOW' %}#17a2b8{% else %}#28a745{% endif %};">{{ vuln.severity }}</span></p>
        <div class="evidence">{{ vuln.evidence }}</div>
    </div>
    {% endfor %}
</body>
</html>
        """
        
        template = Template(html_template)
        scan_stats = scan_results.get('scan_stats', {})
        duration = scan_stats.get('end_time', 0) - scan_stats.get('start_time', 0)
        
        html_content = template.render(
            target=scan_results.get('target', 'Unknown'),
            vulnerabilities=scan_results.get('vulnerabilities', []),
            scan_stats=scan_stats,
            duration=duration,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        console.print(f"📄 HTML report saved to: {output_file}", style="bold green")
    
    def generate_json_report(self, scan_results, output_file):
        """Generar reporte JSON"""
        report_data = {
            'scan_info': {
                'target': scan_results.get('target'),
                'timestamp': datetime.now().isoformat(),
                'scanner': 'VulnHunter Pro',
                'version': '1.0'
            },
            'scan_stats': scan_results.get('scan_stats', {}),
            'vulnerabilities': scan_results.get('vulnerabilities', [])
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        console.print(f"📄 JSON report saved to: {output_file}", style="bold green")
