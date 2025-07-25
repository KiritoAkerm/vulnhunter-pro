#!/bin/bash

echo "🚀 VulnHunter Pro - Simple Installation"
echo "======================================"

# Crear entorno virtual
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias básicas
echo "📦 Installing basic dependencies..."
pip install aiohttp rich jinja2

# Crear requirements básico
cat > requirements_basic.txt << 'EOL'
aiohttp==3.9.1
rich==13.7.0
jinja2==3.1.2
beautifulsoup4==4.12.2
requests==2.31.0
EOL

echo "✅ Basic installation completed!"
echo "To run: source venv/bin/activate && python3 vulnhunter.py -u https://httpbin.org --quick"
