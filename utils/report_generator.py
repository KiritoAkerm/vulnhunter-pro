#!/usr/bin/env python3
"""
Report Generator
Generate comprehensive security reports
"""

import json
import datetime
from pathlib import Path
from jinja2 import Template

class ReportGenerator:
    def __init__(self):
        self.templates_dir = Path("templates")
        
    def generate_html_report(self, scan_results, output_file):
        """Generar reporte HTML"""
        template_content = """
<!DOCTYPE html>
<html>
<head>
    <title>VulnHunter Pro - Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background: #ecf0f1; padding: 20px; margin: 20px 0; }
        .vulnerability { border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; }
        .high { border-left: 5px solid #e74c3c; }
        .medium { border-left: 5px solid #f39c12; }
        .low { border-left: 5px solid #f1c40f; }
        .info { border-left: 5px solid #3498db; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 VulnHunter Pro Security Report</h1>
        <p>Generated on {{ timestamp }}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Target:</strong> {{ target }}</p>
        <p><strong>Vulnerabilities Found:</strong> {{ vuln_count }}</p>
        <p><strong>Scan Duration:</strong> {{ duration }} seconds</p>
    </div>
    
    <h2>🚨 Vulnerabilities</h2>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability {{ vuln.severity.lower() }}">
        <h3>{{ vuln.type }}</h3>
        <p><strong>Severity:</strong> {{ vuln.severity }}</p>
        <p><strong>URL:</strong> {{ vuln.url }}</p>
        <p><strong>Evidence:</strong> {{ vuln.evidence }}</p>
        <p><strong>Category:</strong> {{ vuln.category }}</p>
    </div>
    {% endfor %}
</body>
</html>
        """
        
        template = Template(template_content)
        
        html_content = template.render(
            target=scan_results['target'],
            vuln_count=len(scan_results['vulnerabilities']),
            duration=scan_results['scan_stats']['end_time'] - scan_results['scan_stats']['start_time'],
            vulnerabilities=scan_results['vulnerabilities'],
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
