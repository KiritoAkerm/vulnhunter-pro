        if 'Server' in headers:
            vulnerabilities.append({
                'type': 'Server Information Disclosure',
                'severity': 'LOW',
                'url': url,
                'evidence': f"Server: {headers['Server']}",
                'category': 'Information Disclosure'
            })
        
        # X-Powered-By header disclosure
        if 'X-Powered-By' in headers:
            vulnerabilities.append({
                'type': 'Technology Stack Disclosure',
                'severity': 'LOW',
                'url': url,
                'evidence': f"X-Powered-By: {headers['X-Powered-By']}",
                'category': 'Information Disclosure'
            })
        
        return vulnerabilities
    
    async def analyze_html_content(self, content, url):
        """Analizar contenido HTML básico"""
        vulnerabilities = []
        
        # Buscar comentarios HTML sospechosos
        import re
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        
        for comment in comments:
            if any(keyword in comment.lower() for keyword in ['password', 'key', 'token', 'secret']):
                vulnerabilities.append({
                    'type': 'Sensitive Information in Comments',
                    'severity': 'MEDIUM',
                    'url': url,
                    'evidence': f"Comment: {comment[:100]}...",
                    'category': 'Information Disclosure'
                })
        
        # Buscar formularios sin protección CSRF
        forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
        for form in forms:
            if 'csrf' not in form.lower() and 'token' not in form.lower():
                vulnerabilities.append({
                    'type': 'Missing CSRF Protection',
                    'severity': 'MEDIUM',
                    'url': url,
                    'evidence': 'Form without apparent CSRF protection',
                    'category': 'Security Misconfiguration'
                })
        
        return vulnerabilities
