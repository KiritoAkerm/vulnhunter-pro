#!/usr/bin/env python3
"""
XSS Scanner Module
Cross-Site Scripting vulnerability detection
"""

import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

class XSSScanner:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(`XSS`)">',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>'
        ]
    
    async def scan(self, target_url):
        """Escanear XSS"""
        console.print(f"🎭 Scanning XSS for {target_url}")
        
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param_name in params.keys():
                param_vulns = await self.test_xss_parameter(target_url, param_name)
                vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    async def test_xss_parameter(self, base_url, param_name):
        """Testear XSS en parámetro específico"""
        vulnerabilities = []
        
        for payload in self.xss_payloads:
            try:
                parsed_url = urlparse(base_url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
                
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    if payload in content:
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'severity': 'HIGH',
                            'url': test_url,
                            'evidence': f"Payload reflected: {payload}",
                            'category': 'Cross-Site Scripting',
                            'parameter': param_name,
                            'payload': payload
                        })
                
                await asyncio.sleep(self.config['scanner']['delay'])
                
            except Exception as e:
                console.print(f"❌ Error testing XSS: {e}")
        
        return vulnerabilities
