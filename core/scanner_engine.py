#!/usr/bin/env python3
"""
Scanner Engine - Core scanning functionality
"""

import asyncio
import aiohttp
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class VulnHunterEngine:
    def __init__(self):
        self.target = None
        self.vulnerabilities = []
        self.scan_stats = {
            'start_time': 0,
            'end_time': 0,
            'requests_made': 0
        }
        
        # Configuración básica
        self.config = {
            'scanner': {
                'timeout': 10,
                'delay': 0.5,
                'max_redirects': 5
            }
        }
    
    async def scan_target(self, target_url, scan_mode="quick"):
        """Ejecutar escaneo del objetivo"""
        self.target = target_url
        self.scan_stats['start_time'] = time.time()
        
        console.print(f"🔍 Initializing {scan_mode} scan...")
        
        # Crear sesión HTTP
        timeout = aiohttp.ClientTimeout(total=self.config['scanner']['timeout'])
        async with aiohttp.ClientSession(timeout=timeout) as session:
            
            # Progreso del escaneo
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                
                # Escaneo básico de conectividad
                task1 = progress.add_task("🌐 Testing connectivity...", total=None)
                connectivity_results = await self.test_connectivity(session, target_url)
                self.vulnerabilities.extend(connectivity_results)
                progress.update(task1, completed=True)
                
                # Análisis de headers
                task2 = progress.add_task("🔒 Analyzing security headers...", total=None)
                header_results = await self.analyze_headers(session, target_url)
                self.vulnerabilities.extend(header_results)
                progress.update(task2, completed=True)
                
                # Análisis de SSL/TLS
                task3 = progress.add_task("🔐 Checking SSL/TLS configuration...", total=None)
                ssl_results = await self.analyze_ssl(session, target_url)
                self.vulnerabilities.extend(ssl_results)
                progress.update(task3, completed=True)
                
                # Escaneo básico de vulnerabilidades
                if scan_mode in ["full", "quick"]:
                    task4 = progress.add_task("🔍 Scanning for common vulnerabilities...", total=None)
                    basic_vulns = await self.basic_vulnerability_scan(session, target_url)
                    self.vulnerabilities.extend(basic_vulns)
                    progress.update(task4, completed=True)
                
                # Escaneo avanzado solo en modo full
                if scan_mode == "full":
                    task5 = progress.add_task("🎯 Advanced vulnerability scanning...", total=None)
                    advanced_vulns = await self.advanced_vulnerability_scan(session, target_url)
                    self.vulnerabilities.extend(advanced_vulns)
                    progress.update(task5, completed=True)
        
        self.scan_stats['end_time'] = time.time()
        
        return {
            'target': self.target,
            'vulnerabilities': self.vulnerabilities,
            'scan_stats': self.scan_stats
        }
    
    async def test_connectivity(self, session, url):
        """Probar conectividad básica"""
        vulnerabilities = []
        
        try:
            async with session.get(url) as response:
                self.scan_stats['requests_made'] += 1
                
                console.print(f"✅ Target accessible (Status: {response.status})")
                
                if response.status != 200:
                    vulnerabilities.append({
                        'type': 'Unusual HTTP Status Code',
                        'severity': 'INFO',
                        'url': url,
                        'evidence': f"Server returned HTTP {response.status} instead of 200 OK",
                        'category': 'Information Gathering'
                    })
                
                # Verificar redirects
                if len(response.history) > 0:
                    vulnerabilities.append({
                        'type': 'HTTP Redirects Detected',
                        'severity': 'INFO',
                        'url': url,
                        'evidence': f"Site redirects through {len(response.history)} hop(s)",
                        'category': 'Information Gathering'
                    })
                
        except Exception as e:
            console.print(f"❌ Connection failed: {e}")
            vulnerabilities.append({
                'type': 'Connection Failed',
                'severity': 'HIGH',
                'url': url,
                'evidence': f"Unable to connect to target: {str(e)}",
                'category': 'Connectivity'
            })
        
        return vulnerabilities
    
    async def analyze_headers(self, session, url):
        """Analizar headers de seguridad"""
        vulnerabilities = []
        
        try:
            async with session.get(url) as response:
                self.scan_stats['requests_made'] += 1
                headers = response.headers
                
                # Headers de seguridad importantes
                security_headers = {
                    'Strict-Transport-Security': {
                        'description': 'HSTS header missing - site vulnerable to protocol downgrade attacks',
                        'severity': 'MEDIUM'
                    },
                    'X-Frame-Options': {
                        'description': 'X-Frame-Options missing - site vulnerable to clickjacking attacks',
                        'severity': 'MEDIUM'
                    },
                    'X-Content-Type-Options': {
                        'description': 'X-Content-Type-Options missing - MIME sniffing attacks possible',
                        'severity': 'LOW'
                    },
                    'Content-Security-Policy': {
                        'description': 'CSP header missing - XSS and injection attacks easier',
                        'severity': 'MEDIUM'
                    },
                    'X-XSS-Protection': {
                        'description': 'X-XSS-Protection missing - XSS protection disabled',
                        'severity': 'LOW'
                    },
                    'Referrer-Policy': {
                        'description': 'Referrer-Policy missing - information leakage possible',
                        'severity': 'LOW'
                    }
                }
                
                for header, info in security_headers.items():
                    if header not in headers:
                        vulnerabilities.append({
                            'type': f'Missing Security Header: {header}',
                            'severity': info['severity'],
                            'url': url,
                            'evidence': info['description'],
                            'category': 'Security Headers'
                        })
                
                # Server information disclosure
                if 'Server' in headers:
                    vulnerabilities.append({
                        'type': 'Server Information Disclosure',
                        'severity': 'LOW',
                        'url': url,
                        'evidence': f"Server header reveals: {headers['Server']}",
                        'category': 'Information Disclosure'
                    })
                
                # X-Powered-By disclosure
                if 'X-Powered-By' in headers:
                    vulnerabilities.append({
                        'type': 'Technology Stack Disclosure',
                        'severity': 'LOW',
                        'url': url,
                        'evidence': f"X-Powered-By header reveals: {headers['X-Powered-By']}",
                        'category': 'Information Disclosure'
                    })
                
        except Exception as e:
            console.print(f"❌ Header analysis failed: {e}")
        
        return vulnerabilities
    
    async def analyze_ssl(self, session, url):
        """Analizar configuración SSL/TLS"""
        vulnerabilities = []
        
        # Solo analizar si es HTTPS
        if not url.startswith('https://'):
            vulnerabilities.append({
                'type': 'Insecure Protocol (HTTP)',
                'severity': 'HIGH',
                'url': url,
                'evidence': 'Site uses HTTP instead of HTTPS - data transmitted in plain text',
                'category': 'Encryption'
            })
        
        return vulnerabilities
    
    async def basic_vulnerability_scan(self, session, url):
        """Escaneo básico de vulnerabilidades"""
        vulnerabilities = []
        
        # Probar algunos paths comunes
        common_paths = [
            '/admin',
            '/login',
            '/phpmyadmin',
            '/backup',
            '/.env',
            '/config.php',
            '/wp-admin',
            '/administrator',
            '/robots.txt',
            '/sitemap.xml',
            '/.git',
            '/debug',
            '/test'
        ]
        
        console.print(f"🔍 Testing {len(common_paths)} common paths...")
        
        for path in common_paths:
            try:
                test_url = url.rstrip('/') + path
                async with session.get(test_url) as response:
                    self.scan_stats['requests_made'] += 1
                    
                    if response.status == 200:
                        content_length = len(await response.text())
                        vulnerabilities.append({
                            'type': 'Exposed Sensitive Path',
                            'severity': 'MEDIUM' if path in ['/.env', '/config.php', '/.git'] else 'LOW',
                            'url': test_url,
                            'evidence': f"Accessible path: {path} (Status: {response.status}, Size: {content_length} bytes)",
                            'category': 'Information Disclosure'
                        })
                
                # Delay entre requests
                await asyncio.sleep(self.config['scanner']['delay'])
                
            except Exception:
                pass  # Ignorar errores en paths individuales
        
        return vulnerabilities
    
    async def advanced_vulnerability_scan(self, session, url):
        """Escaneo avanzado de vulnerabilidades"""
        vulnerabilities = []
        
        # SQL Injection básico
        sql_payloads = ["'", "1'OR'1'='1", "admin'--", "' UNION SELECT NULL--"]
        
        console.print("🎯 Testing for SQL injection...")
        
        for payload in sql_payloads:
            try:
                test_url = f"{url}?id={payload}"
                async with session.get(test_url) as response:
                    self.scan_stats['requests_made'] += 1
                    text = await response.text()
                    
                    # Buscar errores SQL comunes
                    sql_errors = ['sql syntax', 'mysql_fetch', 'ORA-', 'Microsoft JET Database']
                    if any(error.lower() in text.lower() for error in sql_errors):
                        vulnerabilities.append({
                            'type': 'Potential SQL Injection',
                            'severity': 'HIGH',
                            'url': test_url,
                            'evidence': f"SQL error detected with payload: {payload}",
                            'category': 'Injection'
                        })
                        break
                
                await asyncio.sleep(self.config['scanner']['delay'])
                
            except Exception:
                pass
        
        # XSS básico
        xss_payload = "<script>alert('XSS')</script>"
        try:
            test_url = f"{url}?search={xss_payload}"
            async with session.get(test_url) as response:
                self.scan_stats['requests_made'] += 1
                text = await response.text()
                
                if xss_payload in text:
                    vulnerabilities.append({
                        'type': 'Reflected XSS Vulnerability',
                        'severity': 'HIGH',
                        'url': test_url,
                        'evidence': f"XSS payload reflected in response: {xss_payload}",
                        'category': 'Cross-Site Scripting'
                    })
        except Exception:
            pass
        
        return vulnerabilities
