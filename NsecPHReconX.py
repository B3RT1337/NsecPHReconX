#!/usr/bin/env python3
import os;os.system('cls' if os.name == 'nt' else 'clear')
BANNER = """\033[91m
             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            @@@@@@@@@@@@@@@@@@@@@@&&&&&&&%&&&&..&&@&@@@@@@@@@@@@@@@@@@@@
            @@@@@@@@@@@@@@@@&&%*/&&#&*&&&/&&&&#/((.(&((&&@@@@@@@@@@@@@@@
            @@@@@@@@@@@@&&%###.#((/&&&&&&&&&&&&&&&./*&*(&((&&%@@@@@@@@@@
            @@@@@@@@@@&&&&&&#&%%&%@......    .....@&&%&*/,&&%&&@@@@@@@@@
            @@@@@@@&%%%%%%%%%&*,@.@*... .    .....@/@*.@%%%%%%,%%&@@@@@@
            @@@@@@%%%%.,%%%//@.@@.... (       ,.....&@%&@.%%%*,%%%%@@@@@
            @@@@%%%%%%%%%.@.@@@......            ..,..,@@.@.&%%%%%%%%@@@
            @@@%#%%##%%@,@&@@..@%..     , , ,     ..&@..@@.@.@######%#@@
            @@@#######@,@..@..@#%#      ,,,,,    ..%%%%.,@..@%########&@
            @@######(@,.*@.,..%%%#((      ,      #%%%&&@...@&.,@((#(####
            @@#(( (((/,@.@@..#%#&####(         ###%%%%&@..@@.@.,((( /((@
            @@( ,.* /,@@..@.  %&%%%#%%%#  ,  #%%%%##&@&  .@..@@,/ *#/ (@
            @@((/////%,,@@.@   &#&@&&#(##& %##(#&&@@%@%  @.@@.,,**/////@
            @@////***#,@@@.@.  &%@@@@@@@@((#@@@@@@@@&%   @**@@,@****///@
            @@@/******@,@..(@@.%@#@@@@@&(&&@#@@@@@&#@%,@@...@,@,,*****@@
            @@@@****,,,#..@@@.@*&%%&&#&&@@@@@&&%&&%%&@@.@@@..@,,,,***@@@
            @@@@@**,,,,..@.@@..,(,*@ &#@%%&&&@%&.@/,/...@@.@...,,,,,@@@@
            @@@@@@,,,@@**@.@.,(%%*#(% .&%#&#%&, .#%,,(#*.@.@/(@@@,,@@@@@
            @@@@@@@%,,,.@&@#..@.,,..@.%.,@,&* .&,...,.@..@/./,@(,#@@@@@@
            @@@@@@@@@@,,@(*@%@*@.,*@ *,....%.../ @.   @.@@*@@*,@@@@@@@@@
            @@@@@@@@@@@@%,.%(..@*.@, .&,,.    /@/@.@*@@@@,*,#@@@@@@@@@@@
            @@@@@@@@@@@@@@@@@..*(&@.. @(%. @ @@@@.@#(*.,@@@@@@@@@@@@@@@@
             @@@@@@@@@@@@@@@@@@@@@@(....*....*...*@@@@@@@@@@@@@@@@@@@@@

        ╔╗╔┬ ┬┬  ┬    ╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗╦ ╦  ╦═╗┌─┐┌─┐┌─┐┌┐┌  ═╗ ╦
        ║║║│ ││  │    ╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ╠═╝╠═╣  ╠╦╝├┤ │  │ ││││  ╔╩╦╝
        ╝╚╝└─┘┴─┘┴─┘  ╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╩  ╩ ╩  ╩╚═└─┘└─┘└─┘┘└┘  ╩ ╚═
\033[0m
\033[95m            Developed By: B3RT1337  GitHub: B3RT1337/NsecPHReconX
\033[95m            All-in-One Reconnaissance & Vulnerability Scanner\033[0m
\033[93m            Path Finder | Subdomain Enum | Port Scanner | Vuln Scanner\033[0m
"""
import ssl
from datetime import datetime
import requests
import json
import sys
import time
import re
import socket
import threading
import random
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import warnings
warnings.filterwarnings('ignore')

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ============================================
# CONFIG
# ============================================
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) AppleWebKit/537.36',
    'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)',
    'Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)',
    'Mozilla/5.0 (compatible; OpenAI Bot/1.0; +https://openai.com/bot)',
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0 (compatible; Bingbot/2.0)',
    'Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://anthropic.com/bot)',
    'Mozilla/5.0 (compatible; Claude-Web/1.0; +https://anthropic.com)',
    'Mozilla/5.0 (compatible; Applebot/0.3; +http://www.apple.com/go/applebot)',
    'Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; +https://duckduckgo.com/duckduckbot)',
    'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    'Mozilla/5.0 (compatible; FacebookBot/1.0; +https://developers.facebook.com/docs/sharing/bot)',
    'Mozilla/5.0 (compatible; Twitterbot/1.0; +https://developer.twitter.com/en/docs/twitter-for-websites/cards/guides/getting-started)',
    'Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)',
    'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
    'Mozilla/5.0 (compatible; Slackbot/1.0; +https://api.slack.com/robots)',
    'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
    'Mozilla/5.0 (compatible; SemrushBot/7.0; +http://www.semrush.com/bot.html)',
    'Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; Googlebot/2.1)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 (compatible; GPTBot/1.2)',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; ClaudeBot/1.0)',
]

THREADS = 20
TIMEOUT = 6
CONNECT_TIMEOUT = 3
OUTPUT_DIR = "recon_output"
MAGICPATH_FILE = "utils/magicpath.txt"

# ============================================
# URL PARSER
# ============================================
def parse_base_url(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base.rstrip('/')

def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    return domain

# ============================================
# PROGRESS ANIMATION
# ============================================
class Spinner:
    def __init__(self):
        self.chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.thread = None
        self.running = False
        self.current = 0
        self.total = 0
        self.found = 0
        self.lock = threading.Lock()
    
    def update(self, current, total, found):
        with self.lock:
            self.current = current
            self.total = total
            self.found = found
    
    def spin(self):
        idx = 0
        while self.running:
            with self.lock:
                cur = self.current
                tot = self.total
                fnd = self.found
            
            char = self.chars[idx % len(self.chars)]
            idx += 1
            
            if tot > 0 and cur > 0:
                pct = (cur / tot) * 100
                bar_width = 20
                filled = int(bar_width * cur / tot)
                bar = '█' * filled + '░' * (bar_width - filled)
                status = f"\r{char} Scanning [{bar}] {pct:.1f}% ({cur}/{tot}) Found: {fnd}   "
            elif tot > 0:
                status = f"\r{char} Initializing... 0/{tot}   "
            else:
                status = f"\r{char} Working...   "
            
            sys.stdout.write(status)
            sys.stdout.flush()
            time.sleep(0.06)
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.3)
        sys.stdout.write("\r" + " " * 90 + "\r")
        sys.stdout.flush()

spinner = Spinner()

# ============================================
# COLORS & LOGGING
# ============================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

output_lock = threading.Lock()

def sp(msg):
    with output_lock:
        sys.stdout.write(f"\r{msg}\n")
        sys.stdout.flush()

def log_info(msg):
    sp(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")

def log_success(msg):
    sp(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")

def log_fail(msg):
    sp(f"{Colors.RED}[-]{Colors.RESET} {msg}")

def log_warn(msg):
    sp(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def log_found(msg):
    sp(f"{Colors.PURPLE}{Colors.BOLD}[$]{Colors.RESET} {msg}")

def save_result(filename, data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        if isinstance(data, (dict, list)):
            json.dump(data, f, indent=2, default=str)
        else:
            f.write(str(data))
    log_info(f"Saved: {filepath}")

# ============================================
# PATH LISTS
# ============================================
COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php", "/administrator",
    "/phpmyadmin", "/pma", "/mysql", "/db", "/database",
    "/.git/config", "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/.svn/entries", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/backup", "/backups", "/backup.zip", "/backup.sql", "/dump.sql",
    "/config.php", "/configuration.php", "/settings.php", "/setup.php",
    "/install.php", "/install", "/setup", "/installation",
    "/api", "/api/v1", "/api/v2", "/api/admin", "/api/users",
    "/graphql", "/graphiql", "/swagger", "/swagger-ui.html",
    "/api/docs", "/api/swagger", "/openapi.json",
    "/console", "/dashboard", "/panel", "/cp", "/cpanel",
    "/webadmin", "/whm", "/plesk", "/horde", "/webmail",
    "/mail", "/squirrelmail", "/roundcube", "/owa",
    "/jenkins", "/jira", "/confluence", "/bitbucket", "/gitlab",
    "/solr", "/elasticsearch", "/kibana", "/grafana", "/prometheus",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/health", "/info", "/metrics", "/trace", "/dump",
    "/server-status", "/server-info", "/status", "/nginx_status",
    "/sitemap.xml", "/robots.txt", "/humans.txt", "/security.txt",
    "/test.php", "/info.php", "/phpinfo.php",
    "/test", "/dev", "/staging", "/beta", "/sandbox",
    "/debug", "/debug/default/view",
    "/error", "/errors", "/error_log", "/error.log",
    "/logs", "/log", "/access.log", "/debug.log",
    "/tmp", "/temp", "/cache", "/upload", "/uploads",
    "/files", "/file", "/download", "/downloads",
    "/images", "/img", "/css", "/js", "/static", "/assets",
    "/vendor", "/node_modules", "/bower_components",
    "/composer.json", "/package.json", "/package-lock.json",
    "/yarn.lock", "/Gemfile", "/Gemfile.lock", "/Pipfile",
    "/credentials", "/credential", "/secret", "/secrets",
    "/private", "/secure", "/hidden", "/internal",
    "/old", "/new", "/v1", "/v2", "/v3", "/api/v3",
    "/cron", "/cron.php", "/worker", "/task",
    "/shell", "/cmd", "/exec", "/command",
    "/docker", "/docker-compose.yml", "/Dockerfile",
    "/k8s", "/kubernetes", "/helm",
    "/wp-content", "/wp-includes", "/wp-json", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-trackback.php", "/wp-cron.php",
    "/user/login", "/user/register", "/user/password",
    "/app_dev.php", "/app.php", "/index.php", "/index.html",
    "/web.config", "/web.xml",
    "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/status",
    "/.well-known/", "/.well-known/security.txt",
    "/druid", "/druid/index.html",
    "/zabbix", "/nagios", "/icinga",
    "/magento", "/shopify", "/woocommerce",
]


SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh", "vpn", "remote",
    "admin", "administrator", "panel", "cp", "cpanel",
    "webadmin", "whm", "manage", "management",
    "api", "api-v1", "api-v2", "rest", "graphql",
    "dev", "development", "staging", "stage", "test",
    "testing", "uat", "qa", "beta", "sandbox",
    "demo", "preview", "new",
    "blog", "news", "media", "press",
    "shop", "store", "eshop", "buy", "checkout",
    "cart", "billing", "pay", "payment",
    "support", "help", "helpdesk", "ticket",
    "docs", "documentation", "wiki", "kb",
    "status", "monitor", "monitoring", "health",
    "analytics", "stats", "statistics",
    "cdn", "static", "assets", "img", "images",
    "m", "mobile", "app", "apps",
    "secure", "ssl", "security", "auth", "login",
    "portal", "my", "dashboard", "account", "accounts",
    "db", "database", "mysql", "mongo", "redis",
    "elastic", "elasticsearch", "kibana", "grafana",
    "jenkins", "ci", "cd", "pipeline", "git", "gitlab",
    "docker", "k8s", "kubernetes", "container",
    "ns1", "ns2", "dns1", "dns2", "mx", "mx1",
    "web", "www2", "www3", "proxy", "gateway",
    "internal", "intranet", "corp", "corporate",
    "backup", "backups", "archive", "old",
]


VULN_PATHS = {
    "/wp-json/wp/v2/users": "WordPress User Enumeration",
    "/wp-content/debug.log": "WordPress Debug Log",
    "/wp-content/backups": "WordPress Backups",
    "/.git/HEAD": "Git Repository Exposed",
    "/.git/config": "Git Config Exposed",
    "/.git/index": "Git Index Exposed",
    "/.env": "Environment File Exposed",
    "/.env.local": "Local Environment File Exposed",
    "/wp-config.php": "WordPress Config Exposed",
    "/swagger-ui.html": "Swagger UI Exposed",
    "/api-docs": "API Documentation Exposed",
    "/v2/api-docs": "Swagger V2 API Docs",
    "/phpmyadmin": "phpMyAdmin Exposed",
    "/pma": "phpMyAdmin Exposed",
    "/adminer": "Adminer Exposed",
    "/adminer.php": "Adminer Exposed",
    "/actuator/env": "Spring Boot Environment",
    "/actuator/configprops": "Spring Boot Config Properties",
    "/druid/index.html": "Druid Monitor Exposed",
    "/backup": "Backup Directory Exposed",
    "/backup.zip": "Backup ZIP Exposed",
    "/dump.sql": "SQL Dump Exposed",
    "/docker-compose.yml": "Docker Compose Exposed",
    "/Dockerfile": "Dockerfile Exposed",
}


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>prompt(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=prompt(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "' onmouseover=alert(1) '",
    "\" onfocus=alert(1) autofocus=\"",
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>eval('al'+'ert(1)')</script>",
    "<style>@keyframes x{}</style><div style=\"animation-name:x\" onanimationstart=\"alert(1)\">",
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "admin'--",
    "admin' OR '1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT @@version--",
    "' UNION SELECT database()--",
    "' UNION SELECT user()--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' OR SLEEP(3)--",
    "\" OR SLEEP(3)--",
    "' AND SLEEP(3)--",
    "' OR 1=1#",
    "' OR '1'='1'#",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND '1'='1",
    "' AND '1'='2",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "') OR ('1'='1",
    "') OR 1=1--",
    "')) OR 1=1--",
    "admin'-- -",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 OFFSET 1--",
    "'; DROP TABLE users--",
    "'; EXEC xp_cmdshell('dir')--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' OR username LIKE '%admin%'--",
]

# ============================================
# HTTP CLIENT
# ============================================
class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = 5
        self.session.headers.update({"Connection": "keep-alive"})
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=2))
        self.session.mount('http://', requests.adapters.HTTPAdapter(max_retries=2))
    
    def get_headers(self):
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
        }
    
    def get(self, url, referer=None, retries=2):
        headers = self.get_headers()
        if referer:
            headers["Referer"] = referer
        
        for attempt in range(retries + 1):
            try:
                return self.session.get(url, headers=headers, 
                                        timeout=(CONNECT_TIMEOUT, TIMEOUT), 
                                        allow_redirects=True)
            except requests.exceptions.SSLError:
                # Try without SSL verification
                try:
                    return self.session.get(url, headers=headers,
                                            timeout=(CONNECT_TIMEOUT, TIMEOUT),
                                            allow_redirects=True, verify=False)
                except:
                    pass
            except:
                if attempt == retries:
                    return None
                time.sleep(0.5)
        return None
    
    def post(self, url, data=None):
        try:
            return self.session.post(url, data=data, headers=self.get_headers(),
                                    timeout=(CONNECT_TIMEOUT, TIMEOUT), allow_redirects=True)
        except:
            return None

# ============================================
# MAGICPATH LOADER
# ============================================
def load_magicpath():
    if os.path.exists(MAGICPATH_FILE):
        with open(MAGICPATH_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            paths = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not line.startswith('/'):
                        line = '/' + line
                    paths.append(line)
            log_success(f"Loaded {len(paths)} paths from {MAGICPATH_FILE}")
            return paths
    else:
        log_warn(f"{MAGICPATH_FILE} not found. Using built-in wordlist only.")
        return []

# ============================================
# ENDPOINT EXTRACTOR FROM JS/HTML
# ============================================
def extract_endpoints_from_page(client, target_url):
    """Extract API endpoints and paths from page source and external JS files"""
    endpoints = set()
    
    resp = client.get(target_url)
    if not resp:
        return []
    
    html = resp.text or ''
    patterns = [
        r'(?:href|src|action|data-url|data-src)=["\']([^"\']+)["\']',
        r'(?:url|path|endpoint|api)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            match = match.strip()
            if match.startswith('/') and not match.startswith('//'):
                endpoints.add(match.split('?')[0])
            elif match.startswith('http'):
                parsed = urlparse(match)
                endpoints.add(parsed.path.split('?')[0])
    js_patterns = [
        r'(?:get|post|put|delete|ajax|fetch|request)\s*\(["\']([^"\']+)["\']',
        r'(?:url|URL|api|API|endpoint|baseUrl|baseURL)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\'](/[^"\']*(?:\/[^"\']*)*)["\']',
        r'(?:path|route|href)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in js_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            match = match.strip()
            if match.startswith('/') and len(match) > 2 and not match.startswith('//'):
                match = match.split('?')[0]
                endpoints.add(match)
    
    # Find and fetch external JS files
    js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    js_files = [urljoin(target_url, js) for js in js_files if js.endswith('.js')][:10]
    
    for js_url in js_files:
        js_resp = client.get(js_url)
        if js_resp and js_resp.text:
            js_content = js_resp.text
            for pattern in js_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    match = match.strip()
                    if match.startswith('/') and len(match) > 2 and not match.startswith('//'):
                        match = match.split('?')[0]
                        endpoints.add(match)
    
    theme_files = [
        f"{OUTPUT_DIR}/extracted_theme_top_extract.js",
        f"{OUTPUT_DIR}/extracted_common.js",
        f"{OUTPUT_DIR}/extracted_iconfont.js",
    ]
    for tf in theme_files:
        if os.path.exists(tf):
            with open(tf, 'r', encoding='utf-8', errors='ignore') as f:
                js_content = f.read()
            for pattern in js_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    match = match.strip()
                    if match.startswith('/') and len(match) > 2 and not match.startswith('//'):
                        match = match.split('?')[0]
                        endpoints.add(match)
    
    skip_extensions = ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                       '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webp',
                       '.js', '.map', '.json']
    
    filtered = set()
    for ep in endpoints:
        ep_clean = ep.split('?')[0].split(';')[0]
        if any(ep_clean.lower().endswith(ext) for ext in skip_extensions):
            continue
        if '//' in ep_clean:
            continue
        if len(ep_clean) > 1:
            filtered.add(ep_clean)
    
    return list(filtered)

def hackertarget_subdomains(domain):
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": random.choice(USER_AGENTS)})
        if resp.status_code == 200 and not resp.text.startswith("error"):
            for line in resp.text.strip().split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if sub and sub != domain and '.' in sub:
                        subdomains.add(sub)
    except:
        pass
    return list(subdomains)

def crtsh_subdomains(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10, headers={"User-Agent": random.choice(USER_AGENTS)})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:500]:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and '*' not in sub and sub.endswith(domain):
                        subdomains.add(sub)
    except:
        pass
    return list(subdomains)

# ============================================
# PATH FINDER - DUAL COLOR OUTPUT
# ============================================
class PathFinder:
    def __init__(self, target_url, client):
        self.target = target_url.rstrip('/')
        self.client = client
        self.results = []
        self.found_count = 0
        self.scanned_count = 0
        
        # Get homepage baseline for false positive detection
        self.homepage_content = ""
        self.homepage_title = ""
        resp = self.client.get(self.target)
        if resp:
            self.homepage_content = (resp.text or '')[:2000]
            title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text or '', re.IGNORECASE)
            if title_match:
                self.homepage_title = title_match.group(1).strip()
        
        magic_paths = load_magicpath()
        self.wordlist_paths = set(magic_paths + COMMON_PATHS)
        
        log_info("Extracting endpoints from page source...")
        extracted = extract_endpoints_from_page(client, target_url)
        log_success(f"Extracted {len(extracted)} endpoints from page/JS files")
        
        self.extracted_set = set(extracted)
        self.wordlist_set = self.wordlist_paths
        
        seen = set()
        self.paths = []
        for p in extracted:
            if p not in seen:
                seen.add(p)
                self.paths.append(p)
        for p in magic_paths + COMMON_PATHS:
            if p not in seen:
                seen.add(p)
                self.paths.append(p)
    
    def is_wordlist_path(self, path):
        """Check if path came from wordlist (from  or built-in)"""
        return path in self.wordlist_set
    
    def is_extracted_path(self, path):
        """Check if path was extracted from page source"""
        return path in self.extracted_set and path not in self.wordlist_set
    
    def is_false_positive(self, resp, path):
        """Check if response is just homepage or error page (false positive)"""
        if not resp:
            return False
        
        content = (resp.text or '')[:3000].lower()
        length = len(resp.text or '')
        status = resp.status_code
        
        # Check if content matches homepage baseline
        if self.homepage_content and content[:1000] == self.homepage_content[:1000]:
            return True
        
        # Check if same title as homepage
        title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text or '', re.IGNORECASE)
        page_title = title_match.group(1).strip() if title_match else ""
        if self.homepage_title and page_title == self.homepage_title:
            return True
        
        # 403 with small body = likely custom 404 (not real 403 forbidden)
        if status == 403 and length < 1000:
            not_found_patterns = [
                'not found', '404', 'page not found', 'does not exist',
                'the requested url was not found', 'errordocument',
                'no such file', 'cannot be found', 'was not found on this server'
            ]
            if any(pattern in content for pattern in not_found_patterns):
                return True
        
        # Generic 404 indicators in any status
        if status in [200, 403, 404]:
            not_found_indicators = [
                '404 not found', 'page not found', 'does not exist on this server',
                'the requested url was not found', 'error 404'
            ]
            if any(indicator in content for indicator in not_found_indicators):
                return True
            
            # Check for empty/small error pages
            if length < 500 and any(word in content for word in ['not found', 'error', 'forbidden', '404']):
                return True
        
        return False
    
    def check_path(self, path):
        url = f"{self.target}{path}"
        resp = self.client.get(url)
        if resp is None:
            return None
        
        status = resp.status_code
        length = len(resp.content) if resp.content else 0
        content = (resp.text or '')[:3000].lower()
        
        # Skip empty 200 responses
        if status == 200 and length < 10:
            return None
        
        # FAKE 403 DETECTION - Check if 403 is actually a 404
        if status == 403:
            # Small 403 pages are usually fake (real 404)
            if length < 1000:
                fake_patterns = [
                    'not found', '404', 'errordocument', 'does not exist',
                    'was not found', 'no such file', 'cannot be found',
                    'the requested url was not found'
                ]
                if any(p in content for p in fake_patterns):
                    return None  # Skip - it's really a 404
            
            # Also check title for error indicators
            title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text or '', re.IGNORECASE)
            title = title_match.group(1).strip().lower() if title_match else ""
            if any(word in title for word in ['403 forbidden', '404 not found', 'not found', 'error']):
                if length < 1000:
                    return None
        
        # Skip false positives (homepage mirrors, error pages)
        if self.is_false_positive(resp, path):
            return None
        
        # Only accept meaningful status codes
        if status not in [200, 201, 202, 301, 302, 307, 308, 401, 403, 405, 500]:
            return None
        
        source = "extracted"
        if self.is_wordlist_path(path):
            source = "wordlist"
        
        result = {
            "url": url, "status": status, "length": length,
            "content_type": resp.headers.get('Content-Type', ''),
            "source": source
        }
        
        # Extract title for display
        title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text or '', re.IGNORECASE)
        if title_match:
            title = title_match.group(1).strip()
            if title:
                result["title"] = title
        
        if path in VULN_PATHS:
            result["vulnerability"] = VULN_PATHS[path]
        
        return result
    

    
    def scan(self):
        log_info(f"Starting Path Finder on {self.target}")
        total = len(self.paths)
        log_info(f"Total paths to test: {total}")
        
        self.scanned_count = 0
        self.found_count = 0
        lock = threading.Lock()
        
        spinner.update(0, total, 0)
        spinner.start()
        
        def worker(path):
            result = self.check_path(path)
            with lock:
                self.scanned_count += 1
                if result:
                    self.results.append(result)
                    self.found_count += 1
                    
                    title = result.get('title', '')
                    title_str = f" - {title[:50]}" if title else ""
                    
                    status_str = f"[{result['status']}] {result['url']} ({result['length']} bytes){title_str}"
                    source = result.get('source', 'unknown')
                    
                    if source == 'wordlist':
                        sp(f"{Colors.PURPLE}{Colors.BOLD}  >>> {status_str}{Colors.RESET}")
                    elif result['status'] == 200:
                        sp(f"{Colors.GREEN}  {status_str}{Colors.RESET}")
                    elif result['status'] in [401, 403]:
                        sp(f"{Colors.YELLOW}  {status_str}{Colors.RESET}")
                    else:
                        sp(f"{Colors.CYAN}  {status_str}{Colors.RESET}")
                    
                    if 'vulnerability' in result:
                        log_found(f"    VULN: {result['vulnerability']}")
                
                spinner.update(self.scanned_count, total, self.found_count)
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            executor.map(worker, self.paths)
        
        spinner.stop()
        self.results.sort(key=lambda x: (x['status'], -x['length']))
        save_result("path_scan_results.json", self.results)
        log_success(f"Path scan complete. Found {len(self.results)} paths.")
        
        # Show breakdown
        wordlist_found = sum(1 for r in self.results if r.get('source') == 'wordlist')
        extracted_found = sum(1 for r in self.results if r.get('source') == 'extracted')
        log_info(f"Wordlist hits: {wordlist_found} | Extracted hits: {extracted_found}")
        
        return self.results

# ============================================
# SUBDOMAIN ENUMERATOR
# ============================================
class SubdomainEnumerator:
    def __init__(self, domain, client):
        parts = domain.split(':')[0].split('.')
        if len(parts) > 2:
            known_tlds = ['.co.', '.com.', '.net.', '.org.', '.gov.', '.edu.', '.ph.', '.uk.', '.au.', '.sg.', '.my.']
            domain_str = '.'.join(parts)
            
            if len(parts) >= 3 and f".{parts[-2]}." in '.'.join([''] + known_tlds):
                self.root_domain = '.'.join(parts[-3:])
                self.subdomain_part = '.'.join(parts[:-3])
            else:
                self.root_domain = '.'.join(parts[-2:])
                self.subdomain_part = '.'.join(parts[:-2])
        else:
            self.root_domain = domain.split(':')[0]
            self.subdomain_part = ''
        
        self.client = client
        log_info(f"Root domain: {self.root_domain} | Subdomain: {self.subdomain_part or 'N/A'}")
    
    def check_subdomain(self, subdomain):
        fqdn = subdomain
        
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(fqdn, 'A', lifetime=2)
                return {"subdomain": fqdn, "ips": [str(r) for r in answers], "method": "dns"}
            except:
                pass
        
        for proto in ['https', 'http']:
            url = f"{proto}://{fqdn}"
            resp = self.client.get(url)
            if resp and resp.status_code < 500:
                return {"subdomain": fqdn, "url": url, "status": resp.status_code, "method": "http"}
        
        return None
    
    def enumerate(self):
        log_info(f"Enumerating subdomains for {self.root_domain}")
        
        ht_subs = hackertarget_subdomains(self.root_domain)
        log_success(f"HackerTarget: {len(ht_subs)} subdomains")
        
        crt_subs = crtsh_subdomains(self.root_domain)
        log_success(f"crt.sh: {len(crt_subs)} subdomains")
        
        all_subs = set()
        for sub in SUBDOMAINS:
            clean_sub = f"{sub}.{self.root_domain}"
            clean_sub = clean_sub.split(':')[0]
            all_subs.add(clean_sub)
        
        if self.subdomain_part:
            for sub in SUBDOMAINS:
                clean_sub = f"{sub}.{self.subdomain_part}.{self.root_domain}"
                clean_sub = clean_sub.split(':')[0]
                all_subs.add(clean_sub)
        
        for sub in ht_subs + crt_subs:
            if sub and '*' not in sub and sub.count('.') >= 2:
                clean_sub = sub.split(':')[0]
                all_subs.add(clean_sub)
        
        all_subs = list(all_subs)
        
        if len(all_subs) == 0:
            log_info("No subdomains to test.")
            save_result("subdomain_results.json", [])
            return []
        
        log_info(f"Testing {len(all_subs)} subdomains...")
        
        found = []
        scanned = [0]
        total = len(all_subs)
        lock = threading.Lock()
        
        spinner.update(0, total, 0)
        spinner.start()
        
        def worker(sub):
            result = self.check_subdomain(sub)
            with lock:
                scanned[0] += 1
                if result:
                    found.append(result)
                    log_found(f"  {result['subdomain']} [{result.get('status', 'DNS')}]")
                spinner.update(scanned[0], total, len(found))
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            executor.map(worker, all_subs)
        
        spinner.stop()
        save_result("subdomain_results.json", found)
        log_success(f"Subdomain enumeration complete. Found {len(found)} live subdomains.")
        return found

# ============================================
# TECHNOLOGY DETECTOR
# ============================================
class TechnologyDetector:
    def __init__(self, target_url, client):
        self.target = target_url
        self.client = client
        self.technologies = {}
        self.headers_info = {}
        self.meta_info = {}
        self.cookies_info = {}
        
        self.signatures = {
            # JavaScript Frameworks
            "jQuery": [r"jquery[.-]?(\d+\.\d+\.\d+)?", r"jquery"],
            "Bootstrap": [r"bootstrap[.-]?(\d+\.\d+\.\d+)?", r"bootstrap"],
            "React.js": [r"react[.-]?(\d+\.\d+\.\d+)?", r"__REACT_", r"react-dom"],
            "Angular": [r"angular[.-]?(\d+\.\d+\.\d+)?", r"ng-version"],
            "Vue.js": [r"vue[.-]?(\d+\.\d+\.\d+)?", r"vue\.js", r"vue-router"],
            "Next.js": [r"next[.-]?(\d+\.\d+\.\d+)?", r"__NEXT_", r"next/router"],
            "Nuxt.js": [r"nuxt[.-]?(\d+\.\d+\.\d+)?", r"__NUXT_"],
            "Svelte": [r"svelte[.-]?(\d+\.\d+\.\d+)?"],
            "Alpine.js": [r"alpine[.-]?(\d+\.\d+\.\d+)?", r"x-data"],
            "Tailwind CSS": [r"tailwind[.-]?(\d+\.\d+\.\d+)?"],
            
            # CMS
            "WordPress": [r"wp-content", r"wordpress", r"wp-json"],
            "Joomla": [r"joomla", r"com_content"],
            "Drupal": [r"drupal", r"sites/all"],
            "Magento": [r"magento", r"Mage\.Cookies", r"mage\/"],
            "Shopify": [r"shopify", r"myshopify"],
            "WooCommerce": [r"woocommerce", r"wc-api"],
            "PrestaShop": [r"prestashop"],
            "OpenCart": [r"opencart"],
            "TYPO3": [r"typo3"],
            "Ghost": [r"ghost"],
            
            # Backend Frameworks
            "Laravel": [r"laravel", r"XSRF-TOKEN", r"laravel_session"],
            "Django": [r"django", r"csrfmiddlewaretoken", r"django\.", r"__django"],
            "Ruby on Rails": [r"rails", r"authenticity_token", r"rails-"],
            "Express.js": [r"express", r"x-powered-by.*express"],
            "Spring Boot": [r"spring-boot", r"actuator"],
            "Flask": [r"flask", r"werkzeug"],
            "FastAPI": [r"fastapi"],
            "Phoenix": [r"phoenix", r"phx-"],
            "ASP.NET": [r"__VIEWSTATE", r"asp\.net", r"__RequestVerificationToken"],
            ".NET Core": [r"\.net core", r"aspnetcore"],
            "PHP": [r"php", r"PHPSESSID", r"\.php"],
            "Node.js": [r"node\.js", r"nodejs"],
            
            # Web Servers
            "Nginx": [r"nginx"],
            "Apache": [r"apache", r"httpd"],
            "IIS": [r"iis", r"microsoft-iis"],
            "LiteSpeed": [r"litespeed"],
            "Caddy": [r"caddy"],
            "Tomcat": [r"tomcat", r"apache-tomcat"],
            
            # CDN & Security
            "Cloudflare": [r"cloudflare", r"cf-ray"],
            "AWS CloudFront": [r"cloudfront", r"x-amz-cf-id"],
            "Akamai": [r"akamai"],
            "Fastly": [r"fastly"],
            "BunnyCDN": [r"bunnycdn", r"bunny\.net"],
            "Varnish": [r"varnish", r"x-varnish"],
            "Sucuri": [r"sucuri"],
            "Incapsula": [r"incapsula"],
            
            # Analytics
            "Google Analytics": [r"google-analytics", r"gtag", r"ga\.js"],
            "Google Tag Manager": [r"googletagmanager"],
            "Facebook Pixel": [r"facebook\.net", r"fbq\("],
            "Hotjar": [r"hotjar"],
            "Matomo": [r"matomo", r"piwik"],
            
            # E-commerce
            "MrShopPlus": [r"mrshopplus", r"DTB_", r"FS_MRSHOPPLUS"],
            "BigCommerce": [r"bigcommerce"],
            "Squarespace": [r"squarespace"],
            "Wix": [r"wix\.com", r"wixstatic"],
            "Webflow": [r"webflow"],
            
            # JavaScript Libraries
            "Axios": [r"axios"],
            "Lodash": [r"lodash"],
            "Moment.js": [r"moment\.js", r"moment\.min"],
            "Socket.io": [r"socket\.io"],
            "Three.js": [r"three\.js", r"three\.min"],
            "GSAP": [r"gsap", r"greensock"],
            "Swiper": [r"swiper", r"swiper-bundle"],
            "AOS": [r"aos\.js", r"aos\.min", r"animate on scroll"],
        }
        
        self.headers_signatures = {
            "Server": "server",
            "X-Powered-By": "powered_by",
            "X-Generator": "generator",
            "X-Drupal-Cache": "Drupal",
            "X-Drupal-Dynamic-Cache": "Drupal",
            "X-Magento-Cache-Debug": "Magento",
            "CF-Ray": "Cloudflare",
            "X-Amz-Cf-Id": "AWS CloudFront",
            "X-Sucuri-ID": "Sucuri",
            "X-Varnish": "Varnish",
            "X-Cache": "cache",
            "X-AspNet-Version": "ASP.NET",
            "X-AspNetMvc-Version": "ASP.NET MVC",
            "X-Runtime": "runtime",
            "X-Shopify-Stage": "Shopify",
            "X-Request-Id": "request_id",
            "X-Wix-Request-Id": "Wix",
        }
    
    def extract_version(self, text, tech_name):
        patterns = {
            "jQuery": r'jquery[.-]?(\d+\.\d+\.\d+)',
            "Bootstrap": r'bootstrap[.-]?(\d+\.\d+\.\d+)',
            "React.js": r'react[.-]?(\d+\.\d+\.\d+)',
            "Angular": r'angular[.-]?(\d+\.\d+\.\d+)',
            "Vue.js": r'vue[.-]?(\d+\.\d+\.\d+)',
            "WordPress": r'wordpress[.-]?(\d+\.\d+\.\d+)?',
            "WooCommerce": r'woocommerce[.-]?(\d+\.\d+\.\d+)?',
            "PHP": r'php[.-]?(\d+\.\d+\.\d+)?',
            "Nginx": r'nginx[.-/]?(\d+\.\d+\.\d+)?',
            "Apache": r'apache[.-/]?(\d+\.\d+\.\d+)?',
        }
        
        if tech_name in patterns:
            match = re.search(patterns[tech_name], text, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1)
        return None
    
    def detect(self):
        log_info(f"Detecting technologies on {self.target}")
        
        resp = self.client.get(self.target)
        if not resp:
            log_fail("Failed to fetch target.")
            return {}
        
        html = (resp.text or '')[:100000]
        html_lower = html.lower()
        headers = resp.headers
        cookies = resp.cookies
        
        for header, tech_name in self.headers_signatures.items():
            value = headers.get(header)
            if value:
                if tech_name == "server":
                    self.headers_info["Server"] = value
                    for server_type in ["nginx", "apache", "iis", "litespeed", "caddy", "tomcat"]:
                        if server_type in value.lower():
                            self.technologies[value] = {"source": "header", "type": server_type.capitalize()}
                            break
                    if value not in self.technologies:
                        self.technologies[value] = {"source": "header"}
                elif tech_name == "powered_by":
                    self.headers_info["X-Powered-By"] = value
                    self.technologies[value] = {"source": "header"}
                elif tech_name == "generator":
                    self.meta_info["Generator"] = value
                    self.technologies[value] = {"source": "header", "type": "Generator"}
                else:
                    self.technologies[tech_name] = {"source": "header", "value": value}
        
        meta_patterns = [
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        ]
        for pattern in meta_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                match_lower = match.lower()
                if any(word in match_lower for word in ['wordpress', 'joomla', 'drupal', 'shopify', 'wix', 'squarespace']):
                    for tech_name, patterns_list in self.signatures.items():
                        for sig in patterns_list:
                            if re.search(sig, match, re.IGNORECASE):
                                version = self.extract_version(match, tech_name)
                                self.technologies[tech_name] = {
                                    "source": "meta",
                                    "version": version or "unknown",
                                    "value": match
                                }
                                break
        
        for tech_name, patterns in self.signatures.items():
            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = self.extract_version(html, tech_name)
                    self.technologies[tech_name] = {
                        "source": "content",
                        "version": version or "unknown",
                        "pattern": pattern
                    }
                    break
        
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for js_url in js_files[:20]:
            for tech_name in self.signatures:
                for pattern in self.signatures[tech_name]:
                    if re.search(pattern, js_url, re.IGNORECASE):
                        if tech_name not in self.technologies:
                            version = self.extract_version(js_url, tech_name)
                            self.technologies[tech_name] = {
                                "source": "script_src",
                                "version": version or "unknown",
                                "url": js_url
                            }
                        break
        
        css_files = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for css_url in css_files[:10]:
            for tech_name in ["Bootstrap", "Tailwind CSS", "Bulma", "Foundation", "Materialize", "UIkit"]:
                if tech_name.lower().replace(' ', '') in css_url.lower() or tech_name.lower().replace(' ', '-') in css_url.lower():
                    if tech_name not in self.technologies:
                        self.technologies[tech_name] = {
                            "source": "css_url",
                            "url": css_url
                        }
        
        cookie_map = {
            "PHPSESSID": "PHP",
            "laravel_session": "Laravel",
            "csrftoken": "Django",
            "_shopify_s": "Shopify",
            "woocommerce_cart_hash": "WooCommerce",
            "wp-settings": "WordPress",
            "wordpress_logged_in": "WordPress",
            "mage-cache": "Magento",
            "prestashop": "PrestaShop",
            "cf_clearance": "Cloudflare",
            "__cfduid": "Cloudflare",
        }
        for cookie_name, tech_name in cookie_map.items():
            if cookie_name in cookies or cookie_name.lower() in str(cookies).lower():
                if tech_name not in self.technologies:
                    self.technologies[tech_name] = {"source": "cookie", "cookie": cookie_name}
        

        save_result("technology_detection.json", {
            "technologies": self.technologies,
            "headers": self.headers_info,
            "meta": self.meta_info
        })
        
        categories = {
            "Web Server": ["Apache", "Nginx", "IIS", "LiteSpeed", "Caddy", "Tomcat", "Node.js"],
            "CMS/E-commerce": ["WordPress", "Joomla", "Drupal", "Magento", "Shopify", "WooCommerce", 
                              "PrestaShop", "OpenCart", "MrShopPlus", "BigCommerce", "Squarespace", "Wix"],
            "Backend Framework": ["Laravel", "Django", "Ruby on Rails", "Express.js", "Spring Boot", 
                                 "Flask", "FastAPI", "ASP.NET", ".NET Core", "PHP"],
            "Frontend Framework": ["React.js", "Angular", "Vue.js", "Next.js", "Nuxt.js", "Svelte", "Alpine.js"],
            "CSS Framework": ["Bootstrap", "Tailwind CSS", "Bulma", "Foundation"],
            "CDN/Security": ["Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Sucuri", "Incapsula", "Varnish"],
            "Analytics": ["Google Analytics", "Google Tag Manager", "Facebook Pixel", "Hotjar", "Matomo"],
            "JavaScript Library": ["jQuery", "Axios", "Lodash", "Moment.js", "Socket.io", "Three.js", "GSAP", "Swiper"],
        }
        
        for category, tech_list in categories.items():
            found_in_cat = [t for t in tech_list if t in self.technologies]
            if found_in_cat:
                log_success(f"  [{category}]")
                for tech in found_in_cat:
                    info = self.technologies[tech]
                    version_str = f" v{info.get('version')}" if info.get('version') and info.get('version') != 'unknown' else ""
                    source_str = f" ({info['source']})"
                    sp(f"    {Colors.GREEN}{tech}{Colors.RESET}{version_str}{Colors.BLUE}{source_str}{Colors.RESET}")
        
        categorized = set()
        for tech_list in categories.values():
            categorized.update(tech_list)
        uncategorized = [t for t in self.technologies if t not in categorized]
        if uncategorized:
            log_success(f"  [Other]")
            for tech in uncategorized:
                sp(f"    {Colors.GREEN}{tech}{Colors.RESET}")
        
        log_success(f"Detected {len(self.technologies)} technologies and components.")
        return self.technologies

# ============================================
# VULNERABILITY SCANNER
# ============================================
class VulnerabilityScanner:
    def __init__(self, target_url, client):
        self.target = target_url
        self.client = client
        self.vulnerabilities = []
        self.scanned_urls = set()
    
    def test_xss(self, url, param=None, method="GET"):
        for payload in XSS_PAYLOADS:
            try:
                if method == "GET":
                    test_url = f"{url}?{param}={requests.utils.quote(payload)}" if param else f"{url}?q={requests.utils.quote(payload)}"
                    resp = self.client.get(test_url)
                else:
                    test_url = url
                    data = {param: payload} if param else {"q": payload}
                    resp = self.client.post(test_url, data=data)
                
                if resp and payload in (resp.text or '')[:80000]:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "url": url,
                        "parameter": param or "N/A",
                        "payload": payload,
                        "method": method,
                        "severity": "HIGH"
                    })
                    log_found(f"XSS: {url} [{param or 'N/A'}] ({method})")
                    return
            except:
                continue
    
    def test_sqli(self, url, param=None, method="GET"):
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                             '.woff', '.woff2', '.ttf', '.eot', '.map', '.pdf']
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return
        
        error_patterns = [
            'sql syntax', 'mysql error', 'mariadb error', 'syntax error in',
            'unclosed quotation mark', 'unknown column', 'table doesn\'t exist',
            'ora-[0-9]{5}', 'postgresql error', 'sqlite error',
            'you have an error in your sql syntax',
            'warning: mysql', 'valid mysql result',
            'supplied argument is not a valid mysql',
            'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_fetch_row',
            'pg_query', 'sqlite3::query', 'mssql_query', 'odbc_exec',
            'division by zero',
        ]
        
        for payload in SQLI_PAYLOADS[:25]:
            try:
                if method == "GET":
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={requests.utils.quote(payload)}" if param else f"{url}{'&' if '?' in url else '?'}id={requests.utils.quote(payload)}"
                    start = time.time()
                    resp = self.client.get(test_url)
                    elapsed = time.time() - start
                else:
                    test_url = url
                    data = {param: payload} if param else {"id": payload}
                    start = time.time()
                    resp = self.client.post(test_url, data=data)
                    elapsed = time.time() - start
                
                if resp:
                    resp_text = (resp.text or '')[:80000].lower()
                    
                    for err in error_patterns:
                        if re.search(err, resp_text):
                            self.vulnerabilities.append({
                                "type": "SQL Injection",
                                "url": url,
                                "parameter": param or "N/A",
                                "payload": payload,
                                "method": method,
                                "severity": "CRITICAL",
                                "evidence": err
                            })
                            log_found(f"SQLi: {url} [{param or 'N/A'}]")
                            return
                    
                    if elapsed > 5:
                        self.vulnerabilities.append({
                            "type": "SQL Injection (Time-based)",
                            "url": url,
                            "parameter": param or "N/A",
                            "payload": payload,
                            "method": method,
                            "severity": "CRITICAL",
                            "evidence": f"Response time: {elapsed:.1f}s"
                        })
                        log_found(f"SQLi (Time): {url} [{param or 'N/A'}] -> {elapsed:.1f}s")
                        return
            except:
                continue

        
    
    def test_lfi(self, url, param=None):
        lfi_payloads = [
            "../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index",
        ]

        for payload in lfi_payloads:
            try:
                test_url = f"{url}?{param}={requests.utils.quote(payload)}" if param else f"{url}?file={requests.utils.quote(payload)}"
                resp = self.client.get(test_url)
                if resp:
                    resp_text = (resp.text or '')[:80000]
                    if 'root:' in resp_text and ('/bin/' in resp_text or '/sbin/' in resp_text):
                        self.vulnerabilities.append({
                            "type": "Local File Inclusion",
                            "url": url,
                            "parameter": param or "N/A",
                            "payload": payload,
                            "severity": "CRITICAL"
                        })
                        log_found(f"LFI: {url} [{param or 'N/A'}]")
                        return
                    if 'PD9waHA' in resp_text or 'JVBERi' in resp_text:
                        self.vulnerabilities.append({
                            "type": "LFI (Base64)",
                            "url": url,
                            "parameter": param or "N/A",
                            "payload": payload,
                            "severity": "CRITICAL"
                        })
                        log_found(f"LFI: {url} [{param or 'N/A'}]")
                        return
            except:
                continue
    
    def test_open_redirect(self, url, param=None):
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https://google.com",
            "%2F%2Fevil.com",
            "/\\evil.com",
        ]
        
        for payload in redirect_payloads:
            try:
                test_url = f"{url}?{param}={requests.utils.quote(payload)}" if param else f"{url}?redirect={requests.utils.quote(payload)}"
                resp = self.client.get(test_url)
                if resp is None:
                    # Check if client followed redirect
                    resp = self.client.session.get(test_url, headers=self.client.get_headers(),
                                                   timeout=(CONNECT_TIMEOUT, TIMEOUT), allow_redirects=False)
                    if resp and resp.status_code in [301, 302, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location.lower() or 'google.com' in location.lower():
                            self.vulnerabilities.append({
                                "type": "Open Redirect",
                                "url": url,
                                "parameter": param or "N/A",
                                "payload": payload,
                                "severity": "MEDIUM"
                            })
                            log_found(f"Open Redirect: {url} [{param or 'N/A'}] -> {payload}")
                            return
            except:
                continue
    
    def test_ssti(self, url, param=None):
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
        ]
        
        for payload, expected in ssti_payloads:
            try:
                test_url = f"{url}?{param}={requests.utils.quote(payload)}" if param else f"{url}?q={requests.utils.quote(payload)}"
                resp = self.client.get(test_url)
                if resp and expected in resp.text and payload not in resp.text:
                    self.vulnerabilities.append({
                        "type": "SSTI",
                        "url": url,
                        "parameter": param or "N/A",
                        "payload": payload,
                        "severity": "CRITICAL"
                    })
                    log_found(f"SSTI: {url} [{param or 'N/A'}] -> {payload}")
                    return
            except:
                continue
    
    def extract_forms(self, html, base_url):
        forms = []
        pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
        
        for action, form_content in matches:
            action_url = urljoin(base_url, action) if action else base_url
            method = "GET"
            if 'method="post"' in form_content.lower() or "method='post'" in form_content.lower():
                method = "POST"
            
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_content, re.IGNORECASE)
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs
            })
        
        return forms
    
    def scan(self):
        log_info(f"Starting vulnerability scan on {self.target}")
        
        resp = self.client.get(self.target)
        if not resp:
            log_fail("Cannot reach target.")
            return []
        
        html = (resp.text or '')[:100000]
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        
        forms = self.extract_forms(html, self.target)
        log_info(f"Found {len(forms)} forms on target")
        
        log_info("Testing main URL...")
        self.test_xss(self.target)
        self.test_sqli(self.target)
        self.test_lfi(self.target)
        self.test_open_redirect(self.target)
        self.test_ssti(self.target)
        
        unique_links = list(set(links))[:30]
        log_info(f"Testing {len(unique_links)} discovered links...")
        
        total_links = len(unique_links)
        scanned = [0]
        lock = threading.Lock()
        
        spinner.update(0, total_links, 0)
        spinner.start()
        
        def worker(link):
            full_url = urljoin(self.target, link)
            if full_url in self.scanned_urls:
                return
            self.scanned_urls.add(full_url)
            
            parsed = urlparse(full_url)
            params = list(parse_qs(parsed.query).keys())
            
            if params:
                for param in params[:3]:
                    self.test_xss(full_url, param)
                    self.test_sqli(full_url, param)
                    self.test_lfi(full_url, param)
            else:
                self.test_xss(full_url)
            
            with lock:
                scanned[0] += 1
                spinner.update(scanned[0], total_links, len(self.vulnerabilities))
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(worker, unique_links)
        
        spinner.stop()
        
        # Test forms
        log_info(f"Testing {len(forms)} forms...")
        for form in forms[:10]:
            for input_name in form['inputs'][:3]:
                self.test_xss(form['action'], input_name, form['method'])
                self.test_sqli(form['action'], input_name, form['method'])
        
        # Summary
        save_result("vulnerability_scan_results.json", self.vulnerabilities)
        
        severity_count = {}
        for v in self.vulnerabilities:
            severity = v['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        log_success(f"Vulnerability scan complete. Found {len(self.vulnerabilities)} vulnerabilities:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity_count.get(severity, 0) > 0:
                color = Colors.RED if severity == "CRITICAL" else Colors.YELLOW if severity == "HIGH" else Colors.CYAN
                sp(f"{color}  {severity}: {severity_count[severity]}{Colors.RESET}")
        
        return self.vulnerabilities


# ============================================
# PORT SCANNER
# ============================================
class PortScanner:
    def __init__(self, host):
        self.host = host.split(':')[0]
        self.scan_ports = [
            21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445,
            465, 587, 993, 995, 1025, 1080,
            1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
            2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 3689,
            4000, 4200, 4444, 4848, 5000, 5050, 5060, 5061,
            5432, 5555, 5672, 5800, 5900, 5984,
            6379, 6443, 7001, 7077, 7443, 7474,
            8000, 8008, 8009, 8080, 8081, 8088, 8089, 8181, 8333, 8443,
            8500, 8761, 8888, 8983, 9000, 9001, 9042, 9060, 9080,
            9090, 9092, 9200, 9300, 9418, 9443, 9999,
            10000, 10050, 10051, 10052, 11211, 15672,
            20000, 27017, 28017, 32768, 49152,
            50000, 50030, 50060, 50070, 50075, 50090,
        ]
        
        self.services = {
            21: ("FTP", "ProFTPD, vsftpd, FileZilla"),
            22: ("SSH", "OpenSSH, Dropbear"),
            23: ("Telnet", "Linux/Windows telnetd"),
            25: ("SMTP", "Postfix, Exim, Sendmail"),
            53: ("DNS", "BIND, dnsmasq"),
            80: ("HTTP", "Apache, Nginx, IIS"),
            81: ("HTTP Alt", "Web Server"),
            110: ("POP3", "Dovecot, Courier"),
            111: ("RPCBIND", "Portmapper"),
            135: ("MSRPC", "Windows RPC"),
            139: ("NetBIOS", "Samba, Windows"),
            143: ("IMAP", "Dovecot, Courier"),
            443: ("HTTPS", "Apache SSL, Nginx SSL, IIS SSL"),
            445: ("SMB", "Samba, Windows"),
            465: ("SMTPS", "SMTP over SSL"),
            587: ("SMTP", "Mail Submission"),
            993: ("IMAPS", "IMAP over SSL"),
            995: ("POP3S", "POP3 over SSL"),
            1025: ("RPC", "Windows RPC Alt"),
            1080: ("SOCKS", "Proxy Server"),
            1433: ("MSSQL", "Microsoft SQL"),
            1521: ("Oracle", "Oracle DB"),
            1723: ("PPTP", "VPN"),
            2049: ("NFS", "Network File System"),
            2082: ("cPanel", "cPanel HTTP"),
            2083: ("cPanel SSL", "cPanel HTTPS"),
            2086: ("WHM", "WHM HTTP"),
            2087: ("WHM SSL", "WHM HTTPS"),
            2095: ("Webmail", "cPanel Webmail"),
            2096: ("Webmail SSL", "cPanel Webmail SSL"),
            2222: ("SSH", "DirectAdmin SSH"),
            2375: ("Docker", "Docker REST API"),
            2376: ("Docker TLS", "Docker REST API TLS"),
            3000: ("HTTP", "Grafana, Node.js, Rails"),
            3128: ("Squid", "Proxy Server"),
            3260: ("iSCSI", "Storage"),
            3306: ("MySQL/MariaDB", "Database"),
            3389: ("RDP", "Remote Desktop"),
            3689: ("DAAP", "iTunes Sharing"),
            4000: ("HTTP", "Jupyter, Custom App"),
            4200: ("HTTP", "ShellInABox"),
            4444: ("HTTP", "Metasploit, Custom"),
            4848: ("HTTP", "GlassFish Admin"),
            5000: ("HTTP", "Flask, Docker Registry"),
            5050: ("HTTP", "Mesos Master"),
            5060: ("SIP", "VoIP"),
            5061: ("SIP TLS", "VoIP Secure"),
            5432: ("PostgreSQL", "Database"),
            5555: ("ADB", "Android Debug Bridge"),
            5672: ("AMQP", "RabbitMQ"),
            5800: ("VNC HTTP", "Virtual Network Computing"),
            5900: ("VNC", "Virtual Network Computing"),
            5984: ("CouchDB", "Database"),
            6379: ("Redis", "Key-Value Store"),
            6443: ("HTTPS", "Kubernetes API"),
            7001: ("HTTP", "WebLogic Admin"),
            7077: ("HTTP", "Spark Master"),
            7443: ("HTTPS", "OpenShift/K8s Dashboard"),
            7474: ("HTTP", "Neo4j Browser"),
            8000: ("HTTP", "Django, Dev Server"),
            8008: ("HTTP", "Alt Web Server"),
            8009: ("AJP", "Apache Tomcat AJP"),
            8080: ("HTTP", "Proxy, Tomcat, Jenkins"),
            8081: ("HTTP", "Alt Web Server, API"),
            8088: ("HTTP", "Hadoop YARN"),
            8089: ("HTTPS", "Splunk"),
            8181: ("HTTP", "Jenkins"),
            8333: ("Bitcoin", "Crypto Wallet"),
            8443: ("HTTPS", "Tomcat SSL, Plesk"),
            8500: ("HTTP", "Consul"),
            8761: ("HTTP", "Eureka Server"),
            8888: ("HTTP", "Jupyter Notebook"),
            8983: ("HTTP", "Apache Solr"),
            9000: ("HTTP", "SonarQube, PHP-FPM"),
            9001: ("HTTP", "HDFS NameNode"),
            9042: ("HTTP", "Cassandra"),
            9060: ("HTTP", "WebSphere Admin"),
            9080: ("HTTP", "WebSphere App"),
            9090: ("HTTP", "Prometheus, Cockpit"),
            9092: ("HTTP", "Kafka"),
            9200: ("HTTP", "Elasticsearch"),
            9300: ("TCP", "Elasticsearch Node"),
            9418: ("HTTP", "Zipkin"),
            9443: ("HTTPS", "WebSphere SSL"),
            9999: ("HTTP", "Java Debug, Custom"),
            10000: ("HTTP", "Webmin"),
            10050: ("TCP", "Zabbix Agent"),
            10051: ("TCP", "Zabbix Trapper"),
            10052: ("HTTP", "Zabbix Web"),
            11211: ("TCP", "Memcached"),
            15672: ("HTTP", "RabbitMQ Management"),
            20000: ("TCP", "DNPM"),
            27017: ("TCP", "MongoDB"),
            28017: ("HTTP", "MongoDB Web"),
            32768: ("TCP", "Filenet RPC"),
            49152: ("TCP", "Windows RPC Alt"),
            50000: ("HTTP", "SAP Management"),
            50030: ("HTTP", "Hadoop Job Tracker"),
            50060: ("HTTP", "Hadoop Task Tracker"),
            50070: ("HTTP", "Hadoop NameNode"),
            50075: ("HTTP", "Hadoop DataNode"),
            50090: ("HTTP", "Hadoop Secondary NN"),
        }
    
    def scan_port(self, port):
        """Try to connect to port. Returns (port, status, banner)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.host, port))
            
            if result == 0:
                banner = None
                if port in [21, 22, 25, 80, 110, 143, 443, 587, 993, 995, 
                           3306, 3389, 5432, 6379, 8080, 8443, 9000]:
                    try:
                        sock.settimeout(2.0)
                        if port in [443, 8443, 9443]:
                            try:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                ssl_sock = context.wrap_socket(sock, server_hostname=self.host)
                                ssl_sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                                banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                                ssl_sock.close()
                                sock = None
                            except:
                                pass
                        
                        if sock:
                            # Send appropriate probe
                            if port in [80, 443, 8080, 8443, 9000]:
                                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                            elif port == 22:
                                pass  
                            elif port == 21:
                                pass  
                            elif port == 25:
                                sock.send(b"EHLO test.com\r\n")
                            elif port == 3306:
                                pass  
                            elif port == 5432:
                                sock.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                            
                            try:
                                data = sock.recv(1024).decode('utf-8', errors='ignore')
                                if data.strip():
                                    banner = data.strip()[:200]
                            except:
                                pass
                            sock.close()
                    except:
                        try:
                            sock.close()
                        except:
                            pass
                
                return port, "open", banner
            else:
                if port in [21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 
                           993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379]:
                    return port, "filtered", None
                else:
                    return port, "closed", None
                    
        except socket.timeout:
            if port in [21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 
                       993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379]:
                return port, "filtered", None
            return port, "closed", None
        except Exception:
            return port, "closed", None
    
    def scan(self):
        try:
            ip = socket.gethostbyname(self.host)
        except:
            ip = self.host
        
        log_info(f"Scanning {len(self.scan_ports)} ports on {self.host} ({ip})")
        
        results = []
        scanned = [0]
        open_count = [0]
        filtered_count = [0]
        total = len(self.scan_ports)
        lock = threading.Lock()
        
        spinner.update(0, total, open_count[0])
        spinner.start()
        
        def worker(port):
            result_port, status, banner = self.scan_port(port)
            with lock:
                scanned[0] += 1
                
                if status == "open":
                    service_name, description = self.services.get(result_port, ("Unknown", ""))
                    port_info = {
                        "port": result_port,
                        "state": "open",
                        "service": service_name,
                        "description": description
                    }
                    
                    if banner:
                        # Extract server info
                        if 'Server:' in banner:
                            server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
                            if server_match:
                                port_info["server"] = server_match.group(1).strip()
                        else:
                            first_line = banner.split('\n')[0].strip()
                            if first_line and len(first_line) < 120:
                                port_info["banner"] = first_line
                    
                    results.append(port_info)
                    open_count[0] += 1
                    
                    banner_str = ""
                    if port_info.get("server"):
                        banner_str = f" - {port_info['server'][:60]}"
                    elif port_info.get("banner"):
                        banner_str = f" - {port_info['banner'][:60]}"
                    
                    log_found(f"  {result_port}/tcp open  {service_name}{banner_str}")
                    
                elif status == "filtered":
                    service_name, _ = self.services.get(result_port, ("Unknown", ""))
                    results.append({
                        "port": result_port,
                        "state": "filtered",
                        "service": service_name
                    })
                    filtered_count[0] += 1
                
                spinner.update(scanned[0], total, open_count[0])
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(worker, self.scan_ports)
        
        spinner.stop()
        
        open_ports = [r for r in results if r['state'] == 'open']
        filtered_ports = [r for r in results if r['state'] == 'filtered']
        open_ports.sort(key=lambda x: x['port'])
        filtered_ports.sort(key=lambda x: x['port'])
        
        save_result("port_scan_results.json", results)
        
        nmap_output = []
        nmap_output.append(f"Starting Nmap-style scan at {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        nmap_output.append(f"Nmap scan report for {self.host} ({ip})")
        nmap_output.append(f"Host is up.\n")
        nmap_output.append(f"{'PORT':<10} {'STATE':<8} {'SERVICE':<15} {'VERSION'}")
        nmap_output.append(f"{'-'*10} {'-'*8} {'-'*15} {'-'*40}")
        
        for p in filtered_ports:
            service = p.get('service', 'unknown')
            nmap_output.append(f"{p['port']}/tcp  filtered {service}")
        
        for p in open_ports:
            service = p.get('service', 'unknown')
            version = p.get('server', p.get('banner', ''))[:40]
            if version:
                nmap_output.append(f"{p['port']}/tcp  open     {service:<15} {version}")
            else:
                nmap_output.append(f"{p['port']}/tcp  open     {service}")
        
        nmap_output.append(f"\nService detection performed.")
        nmap_output.append(f"Found {len(open_ports)} open ports, {len(filtered_ports)} filtered ports.")
        
        nmap_text = '\n'.join(nmap_output)
        
        sp(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        for line in nmap_output[:3]:
            sp(f"{Colors.CYAN}{line}{Colors.RESET}")
        sp(f"\n{Colors.WHITE}PORT      STATE    SERVICE       VERSION{Colors.RESET}")
        
        for p in filtered_ports:
            service = p.get('service', 'unknown')
            sp(f"{Colors.YELLOW}{p['port']}/tcp  filtered {service}{Colors.RESET}")
        
        for p in open_ports:
            service = p.get('service', 'unknown')
            version = p.get('server', p.get('banner', ''))[:40]
            sp(f"{Colors.GREEN}{p['port']}/tcp  open     {service:<15}{Colors.RESET} {Colors.WHITE}{version}{Colors.RESET}")
        
        sp(f"\n{Colors.CYAN}Found {len(open_ports)} open ports, {len(filtered_ports)} filtered ports{Colors.RESET}")
        sp(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        with open(os.path.join(OUTPUT_DIR, "port_scan_nmap.txt"), 'w') as f:
            f.write(nmap_text)
        
        log_success(f"Port scan complete. {len(open_ports)} open, {len(filtered_ports)} filtered.")
        return results

# ============================================
# WAF DETECTOR
# ============================================
class WAFDetector:
    def __init__(self, target_url, client):
        self.target = target_url
        self.client = client
    
    def detect(self):
        log_info(f"Detecting WAF on {self.target}")
        resp = self.client.get(self.target)
        if not resp:
            return []
        
        headers = resp.headers
        detected = []
        signatures = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "AWS WAF": ["awselb", "x-amzn-requestid"],
            "Sucuri": ["sucuri"], "Imperva": ["incapsula", "imperva"],
            "ModSecurity": ["mod_security"], "FortiWeb": ["fortiweb"],
        }
        
        headers_str = str(headers).lower()
        for waf, keywords in signatures.items():
            for kw in keywords:
                if kw in headers_str:
                    detected.append(waf)
                    log_found(f"  WAF: {waf}")
                    break
        
        if not detected:
            log_info("  No WAF detected.")
        save_result("waf_detection.json", detected)
        return detected

# ============================================
# EMAIL FINDER
# ============================================
class EmailFinder:
    def __init__(self, target_url, client):
        self.target = target_url
        self.client = client
    
    def find(self):
        log_info(f"Extracting emails from {self.target}")
        resp = self.client.get(self.target)
        if not resp:
            return []
        
        html = (resp.text or '')[:50000]
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)))
        for email in emails:
            log_found(f"  {email}")
        save_result("emails_found.json", emails)
        log_success(f"Found {len(emails)} emails.")
        return emails

# ============================================
# SECURITY HEADERS
# ============================================
class SecurityHeaders:
    def __init__(self, target_url, client):
        self.target = target_url
        self.client = client
        self.security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
        ]
    
    def check(self):
        log_info(f"Checking security headers on {self.target}")
        resp = self.client.get(self.target)
        if not resp:
            return {}
        
        headers = resp.headers
        results = {}
        missing = []
        
        for header in self.security_headers:
            if header in headers:
                results[header] = headers[header]
                log_success(f"  {header}: Present")
            else:
                missing.append(header)
                log_fail(f"  {header}: MISSING")
        
        save_result("security_headers.json", {"present": results, "missing": missing})
        if missing:
            log_warn(f"Missing {len(missing)} security headers!")
        return results

# ============================================
# MAIN RECON ENGINE
# ============================================
class ReconEngine:
    def __init__(self, url):
        self.original_url = url
        self.target = parse_base_url(url)
        self.domain = extract_domain(url)
        self.client = HTTPClient()
        self.results = {}
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        if self.original_url != self.target:
            log_info(f"URL Parsed: {self.original_url} -> {self.target}")
    
    def run_all(self):
        start_time = time.time()
        
        log_info(f"Target: {self.target}")
        try:
            ip = socket.gethostbyname(self.domain.split(':')[0])
            log_info(f"Target IP: {ip}")
        except:
            ip = "N/A"
        #log_info(f"Domain: {self.domain}")
        log_info(f"Threads: {THREADS} (Default) | Timeout: {TIMEOUT}s")
        print()
        
        # 1. Technology Detection
        tech = TechnologyDetector(self.target, self.client)
        self.results['technologies'] = tech.detect() or {}
        print()
        
        # 2. WAF Detection
        waf = WAFDetector(self.target, self.client)
        self.results['waf'] = waf.detect() or []
        print()
        
        # 3. Security Headers
        sec_headers = SecurityHeaders(self.target, self.client)
        self.results['security_headers'] = sec_headers.check() or {}
        print()
        
        # 4. Path Finder
        pathfinder = PathFinder(self.target, self.client)
        self.results['paths'] = pathfinder.scan() or []
        print()
        
        # 5. Subdomain Enumeration
        subdomain = SubdomainEnumerator(self.domain, self.client)
        self.results['subdomains'] = subdomain.enumerate() or []
        print()
        
        # 6. Port Scanner
        portscanner = PortScanner(self.domain)
        self.results['ports'] = portscanner.scan() or []
        print()
        
        # 7. Vulnerability Scanner
        vuln_scanner = VulnerabilityScanner(self.target, self.client)
        self.results['vulnerabilities'] = vuln_scanner.scan() or []
        print()
        
        # 8. Email Finder
        email_finder = EmailFinder(self.target, self.client)
        self.results['emails'] = email_finder.find() or []
        print()
        
        elapsed = time.time() - start_time
        
        log_info("=" * 60)
        log_info(f"RECON COMPLETE in {elapsed:.1f}s")
        log_info(f"Output: {OUTPUT_DIR}/")
        log_info("=" * 60)
        
        self.print_summary()
        return self.results
    
    def print_summary(self):
        tech = self.results.get('technologies') or {}
        waf = self.results.get('waf') or []
        sec = self.results.get('security_headers') or {}
        paths = self.results.get('paths') or []
        subs = self.results.get('subdomains') or []
        ports = self.results.get('ports') or []
        vulns = self.results.get('vulnerabilities') or []
        emails = self.results.get('emails') or []
        
        try:
            ip = socket.gethostbyname(self.domain.split(':')[0])
        except:
            ip = "N/A"
        
        print(f"""
{Colors.CYAN}{'='*50}
RECON SUMMARY
{'='*50}{Colors.RESET}

Target:       {self.target}
Domain:       {self.domain}
IP:           {ip}

[Technologies] {len(tech)}
[WAF]         {', '.join(waf) if waf else 'None'}
[SecHeaders]  {len(sec)}/7 present
[Paths]       {len(paths)} found
[Subdomains]  {len(subs)} live
[Open Ports]  {len(ports)} open
[Vulns]       {len(vulns)} found
[Emails]      {len(emails)} exposed

{Colors.GREEN}Results: {OUTPUT_DIR}/{Colors.RESET}
""")
        
        if vulns:
            print(f"{Colors.RED}VULNERABILITIES:{Colors.RESET}")
            for v in vulns[:10]:
                print(f"  [{v['severity']}] {v['type']} - {v['url']}")
                if v.get('parameter') and v['parameter'] != 'N/A':
                    print(f"      Param: {v['parameter']} | Payload: {v['payload'][:40]}")
        
        if ports:
            print(f"\n{Colors.YELLOW}OPEN PORTS:{Colors.RESET}")
            for p in ports[:20]:
                print(f"  {p['port']} - {p['service']}")

    def print_summary(self):
        # Safe get with default empty list
        tech = self.results.get('technologies', {}) or {}
        waf = self.results.get('waf', []) or []
        sec = self.results.get('security_headers', {}) or {}
        paths = self.results.get('paths', []) or []
        subs = self.results.get('subdomains', []) or []
        ports = self.results.get('ports', []) or []
        vulns = self.results.get('vulnerabilities', []) or []
        emails = self.results.get('emails', []) or []
        
        print(f"""
{Colors.CYAN}{'='*50}
RECON SUMMARY
{'='*50}{Colors.RESET}

Target:       {self.target}
Domain:       {self.domain}
IP:           {socket.gethostbyname(self.domain.split(':')[0]) if self.domain else 'N/A'}

[Technologies] {len(tech)}
[WAF]         {', '.join(waf) if waf else 'None'}
[SecHeaders]  {len(sec)}/7 present
[Paths]       {len(paths)} found
[Subdomains]  {len(subs)} live
[Open Ports]  {len(ports)} open
[Vulns]       {len(vulns)} found
[Emails]      {len(emails)} exposed

{Colors.GREEN}Results saved in: {OUTPUT_DIR}/{Colors.RESET}
""")
        
        # Print critical findings
        if vulns:
            print(f"{Colors.RED}CRITICAL VULNERABILITIES:{Colors.RESET}")
            for v in vulns[:10]:
                print(f"  [{v['severity']}] {v['type']} at {v['url']}")
                if 'parameter' in v and v['parameter'] != 'N/A':
                    print(f"      Parameter: {v['parameter']}")
        
#        if ports:
#            print(f"\n{Colors.YELLOW}OPEN PORTS:{Colors.RESET}")
#            for p in ports:
#                print(f"  Port {p['port']} - {p['service']}")

# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    print(BANNER)
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <url>")
        print(f"Example: python3 {sys.argv[0]} https://target.com")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    engine = ReconEngine(url)
    engine.run_all()
