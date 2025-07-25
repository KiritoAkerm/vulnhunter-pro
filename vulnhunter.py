#!/usr/bin/env python3
"""
VulnHunter Pro - Advanced AI-Powered Vulnerability Scanner
Author: KiritoAkerm (@kiritoakerm)
GitHub: https://github.com/KiritoAkerm/vulnhunter-pro
PayPal: quiquegnates@gmail.com
"""

import sys
import argparse
import asyncio
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.scanner_engine import VulnHunterEngine
    from reports.report_generator import ReportGenerator
    from rich.console import Console
    from rich.panel import Panel
except ImportError as e:
    print(f"❌ Missing dependencies: {e}")
    print("Run: ./install_simple.sh")
    sys.exit(1)

console = Console()

def print_banner():
    """Mostrar banner"""
    banner = """
╭─────────────────────────────────────────────────────────────────╮
│                                                                 │
│     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗                       │
│     ██║   ██║██║   ██║██║     ████╗  ██║                       │
│     ██║   ██║██║   ██║██║     ██╔██╗ ██║                       │
│     ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║                       │
│      ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║                       │
│       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝                       │
│                                                                 │
│            🎯 HUNTER PRO - Advanced Vulnerability Scanner       │
│            📧 Author: KiritoAkerm (@kiritoakerm)                │
│            💰 PayPal: quiquegnates@gmail.com                              │
│            🐙 GitHub: KiritoAkerm/vulnhunter-pro               │
│                                                                 │
╰─────────────────────────────────────────────────────────────────╯

    🔍 Advanced vulnerability scanning with AI-powered analysis
    📊 Multiple output formats (HTML, JSON, Console)
    🚀 High-performance asynchronous scanning
    """
    console.print(Panel(banner, style="bold blue"))

def create_parser():
    """Crear parser de argumentos"""
    parser = argparse.ArgumentParser(
        description="VulnHunter Pro - Advanced Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vulnhunter.py -u https://example.com --quick
  python3 vulnhunter.py -u https://example.com --full-scan -o report
  python3 vulnhunter.py -u https://example.com --stealth --format json
        """
    )
    
    parser.add_argument('-u', '--url', type=str, required=True, 
                       help='Target URL to scan (required)')
    
    # Modos de escaneo
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('--quick', action='store_true', 
                           help='Quick scan mode (default)')
    scan_group.add_argument('--full-scan', action='store_true', 
                           help='Full comprehensive scan')
    scan_group.add_argument('--stealth', action='store_true', 
                           help='Stealth mode (slower but less detectable)')
    
    # Opciones de salida
    parser.add_argument('--output', '-o', type=str, 
                       help='Output file name (without extension)')
    parser.add_argument('--format', choices=['html', 'json', 'txt'], default='html',
                       help='Report format (default: html)')
    parser.add_argument('--no-console', action='store_true',
                       help='Skip console output (only save to file)')
    
    return parser

async def main():
    """Función principal"""
    print_banner()
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Validar URL
    if not (args.url.startswith('http://') or args.url.startswith('https://')):
        console.print("❌ URL must start with http:// or https://", style="bold red")
        return
    
    # Determinar modo de escaneo
    scan_mode = "quick"
    if args.full_scan:
        scan_mode = "full"
    elif args.stealth:
        scan_mode = "stealth"
    
    try:
        console.print(f"🎯 Starting {scan_mode} scan of {args.url}")
        
        # Inicializar scanner
        engine = VulnHunterEngine()
        
        # Configurar delays según modo
        if scan_mode == "stealth":
            engine.config['scanner']['delay'] = 2.0
        elif scan_mode == "full":
            engine.config['scanner']['delay'] = 1.0
        
        # Ejecutar escaneo
        results = await engine.scan_target(args.url, scan_mode)
        
        # Generar reportes
        report_gen = ReportGenerator()
        
        # Reporte en consola (a menos que se deshabilite)
        if not args.no_console:
            report_gen.generate_console_report(results)
        
        # Guardar resultados si se especifica
        if args.output:
            if args.format == 'html':
                output_file = f"{args.output}.html"
                report_gen.generate_html_report(results, output_file)
            elif args.format == 'json':
                output_file = f"{args.output}.json"
                report_gen.generate_json_report(results, output_file)
            else:  # txt
                output_file = f"{args.output}.txt"
                console.print(f"💾 TXT format saved to {output_file}")
        
        # Resumen final
        vuln_count = len(results.get('vulnerabilities', []))
        if vuln_count > 0:
            console.print(f"\n🚨 Scan completed! Found {vuln_count} potential issues.", style="bold yellow")
        else:
            console.print(f"\n✅ Scan completed! No vulnerabilities found.", style="bold green")
        
    except KeyboardInterrupt:
        console.print("\n⚠️  Scan interrupted by user", style="yellow")
    except Exception as e:
        console.print(f"\n❌ Error during scan: {e}", style="bold red")

if __name__ == "__main__":
    asyncio.run(main())
