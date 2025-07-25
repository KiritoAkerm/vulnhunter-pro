#!/bin/bash

# VulnHunter Pro - Instalador Automático
# Author: KiritoAkerm (@kiritoakerm)

echo "🚀 VulnHunter Pro - Advanced Vulnerability Scanner"
echo "=================================================="
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is required but not installed.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python 3 found${NC}"

# Verificar pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}❌ pip3 is required but not installed.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ pip3 found${NC}"

echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

echo -e "${BLUE}🎭 Installing Playwright browsers...${NC}"
python3 -m playwright install

echo -e "${BLUE}📁 Creating necessary directories...${NC}"
mkdir -p {database,projects,wordlists/custom,reports/output}

echo -e "${BLUE}🗂️ Setting up wordlists...${NC}"
mkdir -p wordlists/{common,spanish,english,custom}

# Crear wordlists básicas
cat > wordlists/common/directories.txt << 'WORDLIST'
admin
administrator
wp-admin
phpmyadmin
cpanel
webmail
mail
ftp
backup
test
dev
staging
api
login
signin
dashboard
panel
control
WORDLIST

cat > wordlists/common/files.txt << 'WORDLIST'
index.php
admin.php
login.php
config.php
database.php
backup.sql
.env
.git
.htaccess
robots.txt
sitemap.xml
web.config
WORDLIST

echo -e "${BLUE}🔧 Setting up __init__.py files...${NC}"
find . -type d -name "core" -o -name "modules" -o -name "plugins" -o -name "utils" | xargs -I {} touch {}/__init__.py

echo -e "${GREEN}✅ Installation completed!${NC}"
echo ""
echo -e "${YELLOW}🚀 Quick Start:${NC}"
echo "  python3 vulnhunter.py -u https://example.com --quick"
echo ""
echo -e "${YELLOW}📖 Help:${NC}"
echo "  python3 vulnhunter.py --help"
echo ""
echo "Happy Hunting! 🎯"
