import os
import re
import warnings

try:
    from bs4 import BeautifulSoup as bs, MarkupResemblesLocatorWarning
except ImportError:
    from bs4 import BeautifulSoup as bs
    # Fallback if MarkupResemblesLocatorWarning is not available in older versions
    MarkupResemblesLocatorWarning = None

from utils.strings import MAINJS_NOT_FOUND

if MarkupResemblesLocatorWarning:
    warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class Analysis:

    BAD_CHARS = (' ', '\n', '\r', '$', '<', '>', '{', '}', '[', ']', '(', ')', '*', '~', '^', '@', ',', '\\')

    SECTIONS = open('utils/sections.txt').read().splitlines()
    IGNORE_LIST = open('utils/ignorelist.txt', errors='ignore').read().splitlines()

    REG_O = r'(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*[:=]\s*\{(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*:\s*(?:(?:\"[a-zA-Z0-9_\-/\\]*\"|\'[a-zA-Z0-9_\-/\\]*\'|[a-zA-Z0-9_\-/\\]+))\s*(?:,)?\s*)+\})'
    REG_L = r'(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*[:=]\s*\[(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*(?:,)?\s*)+\])'
    
    # New Regex Patterns
    REG_AWS = r'AKIA[0-9A-Z]{16}'
    REG_GOOGLE = r'AIza[0-9A-Za-z\-_]{35}'
    REG_STRIPE = r'sk_live_[0-9a-zA-Z]{24}'
    REG_JWT = r'eyJ[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*'
    REG_PRIVATE_KEY = r'-----BEGIN PRIVATE KEY-----'
    REG_IP = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    REG_EMAIL = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    REG_DOM_SINK = r'innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|bypassSecurityTrustHtml'
    REG_DOM_SINK = r'innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|bypassSecurityTrustHtml'
    REG_TODO = r'//\s*(TODO|FIXME|HACK|XXX).*'
    
    
    def _log(self, message):
        print(message)
        if hasattr(self, 'output_file') and self.output_file:
             # Strip ANSI codes
             plain_message = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', message)
             with open(self.output_file, 'a+', encoding='utf-8', errors='ignore') as f:
                 f.write(plain_message + '\n')

    def __get_js_urls(self, url):
        http = self._get_page_source(url).text
        soup = bs(http, 'html.parser')
        for script in soup.find_all('script'):
            path = script.get('src')
            if path:
                yield self._process_path(url, path)

    def __find_mainjs(self, url):
        if '.js' in url or self.strict:
            return url
        for js_file in self.__get_js_urls(url):
            if 'main' in js_file:
                return js_file

    def __add_to_dict(self, k, v, dic):
        if k not in dic:
            dic[k] = [v]
        else:
            if v not in dic[k]:
                dic[k].append(v)
        return dic
    
    def __add_path(self, path, paths):
        # Modify the order based on your needs.

        # Standard keywords.
        if 'assets' in path.lower():
            self.__add_to_dict('Assets', path, paths)  
        elif 'cloudfront' in path.lower():
            self.__add_to_dict('Cloudfront', path, paths)
        elif 'amazonaws' in path.lower():
            self.__add_to_dict('AWS', path, paths)
        elif 'github' in path.lower():
            self.__add_to_dict('Github', path, paths)
        elif 'gitlab.com' in path.lower():
            self.__add_to_dict('GitLab', path, paths)
        elif 'bitbucket.org' in path.lower():
            self.__add_to_dict('Bitbucket', path, paths)
        elif 'atlassian.net' in path.lower():
            self.__add_to_dict('Jira/Atlassian', path, paths)
        elif any(kw in path.lower() for kw in ('docs.google.com', 'drive.google.com', 'sheets.google.com')):
            self.__add_to_dict('Google Docs/Drive', path, paths)
        elif 'slack.com' in path.lower():
            self.__add_to_dict('Slack', path, paths)
        elif 'discord' in path.lower():
            self.__add_to_dict('Discord', path, paths)
        elif 'blob.core.windows' in path.lower():
            self.__add_to_dict('Azure Containers', path, paths)
        elif 'storage.googleapis.com' in path.lower():
            self.__add_to_dict('Google Cloud Storage', path, paths)
        elif 'digitaloceanspaces.com' in path.lower():
            self.__add_to_dict('DigitalOcean Spaces', path, paths)
        elif 'herokuapp.com' in path.lower():
            self.__add_to_dict('Heroku App', path, paths)
        elif 'firebase' in path.lower():
            self.__add_to_dict('Firebase', path, paths)
        elif 'sentry.io' in path.lower():
            self.__add_to_dict('Sentry', path, paths)
        elif 'cloudinary.com' in path.lower():
            self.__add_to_dict('Cloudinary', path, paths)
        elif 'auth0.com' in path.lower() or 'okta.com' in path.lower():
            self.__add_to_dict('Auth Provider', path, paths)
        elif 'twilio.com' in path.lower():
             self.__add_to_dict('Twilio', path, paths)
        elif 'mailgun' in path.lower() or 'sendgrid' in path.lower():
             self.__add_to_dict('Email Provider', path, paths)
        elif 'paypal.com' in path.lower():
             self.__add_to_dict('PayPal', path, paths)
        elif '.json' in path.lower():
            self.__add_to_dict('JSON Files', path, paths)
        elif '.js' in path.lower():
            self.__add_to_dict('JS Files', path, paths)
        elif '.ts' in path.lower():
            self.__add_to_dict('TS Files', path, paths)
        elif any(kw in path.lower() for kw in ('.png', '.jpg', '.gif', '.svg', '.webp')):
            self.__add_to_dict('Images', path, paths)
        elif 'module' in path.lower():
            self.__add_to_dict('Modules', path, paths)
        
        # Additional keywords.
        elif any(kw in path.lower() for kw in ('graphql', 'graph')):
             self.__add_to_dict('GraphQL', path, paths)
        elif any(kw in path.lower() for kw in ('swagger', 'openapi', 'api-docs')):
             self.__add_to_dict('API Docs', path, paths)
        elif 'api' in path.lower():
            self.__add_to_dict('API Paths', path, paths)
        elif any(kw in path.lower() for kw in ('login', 'register')):
            self.__add_to_dict('Auth Paths', path, paths)
        elif 'user' in path.lower():
            self.__add_to_dict('User Paths', path, paths)
        elif 'admin' in path.lower():
            self.__add_to_dict('Admin Paths', path, paths)
        elif 'role' in path.lower():
            self.__add_to_dict('Role Paths', path, paths)
        else:
            self.__add_to_dict('Not Classified', path, paths)

    def __extract_paths(self, data):
        paths = {}
        checked = []
        for e in data:
            e = e.strip()
            if e.lower() in checked:
                # TODO
                # Add printing
                pass
            else:
                checked.append(e.lower())
                self.__add_path(e, paths)
        return paths
    
    def __has_no_bad_char(self, s: str):
        return not any(char in self.BAD_CHARS for char in s.strip())

    def __get_paths(self, js):
        data = [
            entry.strip() for entry in set(js.split('"'))
            if (
                '/' in entry.strip()                           # Possible Path
                and len(entry.strip()) > 2                     # Min Length
                and len(entry.strip()) < 100                   # Max Length
                and self.__has_no_bad_char(entry.strip())      # Filter
                and entry.strip() not in self.IGNORE_LIST      # Black List
                and not entry.strip().endswith('.css')         # Exclude CSS files
            )
        ]
        if len(data):
            self._log(f'{self.CYAN}Available Paths\n---------------{self.WHITE}')
        else:
            self._log(f'The extraction process yielded no viable {self.ORANGE}paths{self.WHITE}')
        return self.__extract_paths(data)

    def __pretty_entry(self, entry):
        return entry.replace("{", "\n").replace("[", "\n").replace(", ", "\n") \
            .replace(",", "\n").replace("}", "").replace("]", "") \
            .replace("=\n", f'{self.GREEN}\n').replace(":\n", f'{self.GREEN}\n') \
            .replace('"', '').replace("'", "")

    def __map_objects(self, objects):
        mapped = {k:[] for k in self.SECTIONS}
        for o in objects:
            for section in self.SECTIONS:
                if section.lower() in o.lower() and o not in mapped[section]:
                    mapped[section].append(o)
                    break
        return mapped

    def __print_objects(self, objects, js, js_file=""):
        extracted_objects = 0
        mapped_objects = self.__map_objects(objects)
        for section in mapped_objects.keys():
            if mapped_objects[section]:
                title = f'{self.CYAN}Keyword: {self.WHITE}{section}{self.CYAN} (Total objects: {len(mapped_objects[section])})'
                self._log(f'\n{title}')
                self._log('-' * (len(title) - 14) +  self.WHITE)
                for o in mapped_objects[section]:
                    self._log(f'{self.YELLOW}{self.__pretty_entry(o)}{self.WHITE}\n')
                    extracted_objects += 1
        
        # Warn - no useful data was found.
        if not extracted_objects:
            self._log(f'\nThe extraction process yielded no viable {self.ORANGE}objects{self.WHITE}\n')
        
        # Look for paths.
        return self.__print_paths(js, js_file)

    def __print_paths(self, js, js_file=''):
        paths_dict = self.__get_paths(js)
        for k, paths in paths_dict.items():
            self._log(f'{self.YELLOW}{k} {self.WHITE}(Total paths: {len(paths)})')
            for path in sorted(paths):
                self._log(f'{self.GREEN}{path}{self.WHITE}')
                # Collect for HTML report
                if hasattr(self, 'html_data'):
                    if k not in self.html_data['paths']:
                        self.html_data['paths'][k] = []
                    self.html_data['paths'][k].append({'value': path, 'file': js_file})
            self._log('')
        return paths_dict
    
    def __extract_secrets(self, js, js_file=''):
        secrets = []
        secrets.extend([f'AWS Key: {x}' for x in re.findall(self.REG_AWS, js)])
        secrets.extend([f'Google Key: {x}' for x in re.findall(self.REG_GOOGLE, js)])
        secrets.extend([f'Stripe Key: {x}' for x in re.findall(self.REG_STRIPE, js)])
        secrets.extend([f'JWT: {x}' for x in re.findall(self.REG_JWT, js)])
        secrets.extend([f'Private Key: {x}' for x in re.findall(self.REG_PRIVATE_KEY, js)])
        
        if secrets:
            self._log(f'{self.CYAN}Secrets & Keys\n--------------{self.WHITE}')
            for secret in set(secrets):
                self._log(f'{self.RED}{secret}{self.WHITE}')
                # Collect for HTML report
                if hasattr(self, 'html_data'):
                    self.html_data['secrets'].append({'value': secret, 'file': js_file})
            self._log('')
            
    def __extract_emails_ips(self, js, js_file=''):
        # Email & IP
        emails = re.findall(self.REG_EMAIL, js)
        ips = re.findall(self.REG_IP, js)
        
        if emails:
            self._log(f'{self.CYAN}Emails\n------{self.WHITE}')
            for email in set(emails):
                self._log(f'{self.BLUE}{email}{self.WHITE}')
                # Collect for HTML report
                if hasattr(self, 'html_data'):
                    self.html_data['emails'].append({'value': email, 'file': js_file})
            self._log('')
            
        if ips:
            # Filter unlikely IPs (very basic check)
            valid_ips = []
            for ip in set(ips):
                parts = ip.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    valid_ips.append(ip)
                    
            if valid_ips:
                self._log(f'{self.CYAN}IP Addresses\n------------{self.WHITE}')
                for ip in sorted(valid_ips):
                    self._log(f'{self.ORANGE}{ip}{self.WHITE}')
                    # Collect for HTML report
                    if hasattr(self, 'html_data'):
                        self.html_data['ips'].append({'value': ip, 'file': js_file})
                self._log('')

    def __extract_comments(self, js, js_file=''):
        todos = re.findall(self.REG_TODO, js)
        if todos:
             # re.findall with group returns only the group, we want the whole match or we need to adjust regex
             # Adjusting regex to capture the full line might be safer or just iterate
             # Let's re-run with finding full match
             comments = re.findall(r'(//\s*(?:TODO|FIXME|HACK|XXX).*)', js)
             if comments:
                self._log(f'{self.CYAN}Developer Comments\n------------------{self.WHITE}')
                for comment in set(comments):
                    self._log(f'{self.YELLOW}{comment.strip()}{self.WHITE}')
                    # Collect for HTML report
                    if hasattr(self, 'html_data'):
                        self.html_data['comments'].append({'value': comment.strip(), 'file': js_file})
                self._log('')

    def __extract_sinks(self, js, js_file=''):
        sinks = re.findall(self.REG_DOM_SINK, js)
        if sinks:
            self._log(f'{self.CYAN}Dangerous Functions (DOM Sinks)\n-------------------------------{self.WHITE}')
            for sink in sorted(set(sinks)):
                self._log(f'{self.RED}{sink}{self.WHITE}')
                # Collect for HTML report
                if hasattr(self, 'html_data'):
                    self.html_data['sinks'].append({'value': sink, 'file': js_file})
            self._log('')

    def __parse_js(self, js_file):
        self._log(f'Fetching {self.CYAN}{js_file}{self.WHITE}')
        
        # Track parsed files for HTML report
        if hasattr(self, 'html_data') and js_file not in self.html_data ['parsed_files']:
            self.html_data['parsed_files'].append(js_file)
        
        content = ""
        if os.path.exists(js_file) and not js_file.startswith(('http:', 'https:')):
             with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                 content = f.read()
        else:
             content = self._get_page_source(js_file).text

        js = content
        
        # New Extractions - pass js_file for tracking
        self.__extract_secrets(js, js_file)
        self.__extract_emails_ips(js, js_file)
        self.__extract_comments(js, js_file)
        self.__extract_sinks(js, js_file)
        
        objects = re.findall(self.REG_O, js) + re.findall(self.REG_L, js)
        return self.__print_objects(set(objects), js, js_file)
    
    def __parse_all_js_files(self):
        js_queue = []
        visited = set()

        # Initial population
        for js_file in self.__get_js_urls(self.base):
             if js_file not in visited:
                js_queue.append(js_file)

        while js_queue:
            js_file = js_queue.pop(0)
            
            if self.mainonly and 'main' not in js_file:
                continue
            
            if js_file in visited:
                continue
                
            visited.add(js_file)

            print(f'\n{self.DARKCYAN}NEXT{self.WHITE} {js_file} {self.YELLOW}({len(js_queue)} left){self.WHITE}')
            
            if self.auto:
                to_parse_it = 'y'
            else:
                to_parse_it = input('\nParse this file? y/N: ')
                
            if to_parse_it.strip().lower() in ('y', 'yes'):
                paths_found = self.__parse_js(js_file)
                
                if self.continuous and paths_found:
                    # Check for new JS files
                    js_files = paths_found.get('JS Files', [])
                    new_candidates = []
                    
                    for raw_path in js_files:
                        # Smart resolve
                        full_path = self._process_path(js_file, raw_path)
                        
                        if full_path not in visited and full_path not in js_queue:
                             new_candidates.append(full_path)
                    
                    if new_candidates:
                        self._log(f'{self.CYAN}Continuous Mode: Found {len(new_candidates)} new JS candidate(s).{self.WHITE}')
                        for full_path in new_candidates:
                             js_queue.append(full_path)
                             self._log(f'{self.GREEN} + Added to queue: {full_path}{self.WHITE}')

    def analyze(self):
        # Initialize HTML report data collection
        self.html_data = {
            'target_url': self.base,
            'parsed_files': [],
            'secrets': [],
            'emails': [],
            'ips': [],
            'comments': [],
            'sinks': [],
            'objects': {},
            'paths': {}
        }
        
        if not self.base.startswith(('http:', 'https:')) and os.path.exists(self.base):
             self.__parse_js(self.base)
             # Generate HTML report if requested
             if hasattr(self, 'html_output') and self.html_output:
                 self.__generate_html_report()
             return

        if '.js' in self.base or self.strict:
            self.__parse_js(self.base)
        else:
            self.__parse_all_js_files()
        
        # Generate HTML report if requested
        if hasattr(self, 'html_output') and self.html_output:
            self.__generate_html_report()

    def __generate_html_report(self):
        """Generate interactive HTML dashboard report"""
        import json
        from datetime import datetime
        
        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aranea Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(30, 30, 40, 0.95);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid #667eea;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            color: #a0a0a0;
            font-size: 0.95em;
        }}
        
        .header .target-url {{
            color: #667eea;
            font-weight: bold;
            word-break: break-all;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #2a2a3a 0%, #1f1f2e 100%);
            padding: 20px;
            border-radius: 15px;
            border: 1px solid #667eea33;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .stat-card .label {{
            color: #a0a0a0;
            margin-top: 5px;
            font-size: 0.9em;
        }}
        
        .filters {{
            background: #2a2a3a;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}
        
        .filter-group {{
            flex: 1;
            min-width: 200px;
        }}
        
        .filter-group label {{
            display: block;
            margin-bottom: 8px;
            color: #667eea;
            font-weight: 500;
        }}
        
        .filter-group select, .filter-group input {{
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #667eea44;
            background: #1f1f2e;
            color: #e0e0e0;
            font-size: 0.95em;
        }}
        
        .filter-group select:focus, .filter-group input:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        
        .results-section {{
            margin-top: 30px;
        }}
        
        .section-header {{
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .category {{
            background: #2a2a3a;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }}
        
        .category-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 15px;
            color: #667eea;
        }}
        
        .item {{
            background: #1f1f2e;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border: 1px solid #667eea22;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }}
        
        .item.secret {{ border-left: 3px solid #ff4757; }}
        .item.email {{ border-left: 3px solid #feca57; }}
        .item.ip {{ border-left: 3px solid #5f27cd; }}
        .item.sink {{ border-left: 3px solid #ff6348; }}
        .item.comment {{ border-left: 3px solid #48dbfb; }}
        .item.path {{ border-left: 3px solid #00d2d3; }}
        
        .hidden {{
            display: none !important;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: #888;
        }}
        
        .empty-state svg {{
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            opacity: 0.3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ Aranea Analysis Report</h1>
            <div class="meta">
                <div><strong>Target URL:</strong> <span class="target-url" id="target-url"></span></div>
                <div><strong>Generated:</strong> <span id="timestamp"></span></div>
                <div><strong>Files Analyzed:</strong> <span id="files-count"></span></div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number" id="stat-secrets">0</div>
                <div class="label">Secrets & Keys</div>
            </div>
            <div class="stat-card">
                <div class="number" id="stat-emails">0</div>
                <div class="label">Emails</div>
            </div>
            <div class="stat-card">
                <div class="number" id="stat-ips">0</div>
                <div class="label">IP Addresses</div>
            </div>
            <div class="stat-card">
                <div class="number" id="stat-sinks">0</div>
                <div class="label">DOM Sinks</div>
            </div>
            <div class="stat-card">
                <div class="number" id="stat-comments">0</div>
                <div class="label">Comments</div>
            </div>
            <div class="stat-card">
                <div class="number" id="stat-paths">0</div>
                <div class="label">Paths</div>
            </div>
        </div>
        
        <div class="filters">
            <div class="filter-group">
                <label for="category-filter">Filter by Category</label>
                <select id="category-filter">
                    <option value="all">All Categories</option>
                    <option value="secrets">Secrets & Keys</option>
                    <option value="emails">Emails</option>
                    <option value="ips">IP Addresses</option>
                    <option value="sinks">DOM Sinks</option>
                    <option value="comments">Comments</option>
                    <option value="paths">Paths</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="file-filter">Filter by JS File</label>
                <select id="file-filter">
                    <option value="all">All Files</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="search-input">Search</label>
                <input type="text" id="search-input" placeholder="Type to search...">
            </div>
        </div>
        
        <div class="results-section">
            <div class="section-header">📋 Analysis Results</div>
            <div id="results-container"></div>
            <div id="empty-state" class="empty-state hidden">
                <div>🔍</div>
                <p>No results found matching your filters</p>
            </div>
        </div>
    </div>
    
    <script>
        const data = {json.dumps(self.html_data, indent=2)};
        
        // Initialize
        document.getElementById('target-url').textContent = data.target_url || 'N/A';
        document.getElementById('timestamp').textContent = '{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}';
        document.getElementById('files-count').textContent = data.parsed_files.length;
        
        // Update stats
        document.getElementById('stat-secrets').textContent = data.secrets.length;
        document.getElementById('stat-emails').textContent = data.emails.length;
        document.getElementById('stat-ips').textContent = data.ips.length;
        document.getElementById('stat-sinks').textContent = data.sinks.length;
        document.getElementById('stat-comments').textContent = data.comments.length;
        
        const totalPaths = Object.values(data.paths).reduce((sum, paths) => sum + paths.length, 0);
        document.getElementById('stat-paths').textContent = totalPaths;
        
        // Populate file filter
        const fileFilter = document.getElementById('file-filter');
        data.parsed_files.forEach(file => {{
            const option = document.createElement('option');
            option.value = file;
            option.textContent = file;
            fileFilter.appendChild(option);
        }});
        
        // Render results
        function renderResults() {{
            const categoryFilter = document.getElementById('category-filter').value;
            const fileFilter = document.getElementById('file-filter').value;
            const searchTerm = document.getElementById('search-input').value.toLowerCase();
            const container = document.getElementById('results-container');
            const emptyState = document.getElementById('empty-state');
            
            container.innerHTML = '';
            let hasResults = false;
            
            // Render each category
            const categories = [
                {{ key: 'secrets', title: '🔑 Secrets & Keys', type: 'secret' }},
                {{ key: 'emails', title: '📧 Emails', type: 'email' }},
                {{ key: 'ips', title: '🌐 IP Addresses', type: 'ip' }},
                {{ key: 'sinks', title: '⚠️ Dangerous Functions (DOM Sinks)', type: 'sink' }},
                {{ key: 'comments', title: '💬 Developer Comments', type: 'comment' }},
            ];
            
            categories.forEach(cat => {{
                if (categoryFilter === 'all' || categoryFilter === cat.key) {{
                    const items = data[cat.key].filter(item => 
                        (searchTerm === '' || item.value.toLowerCase().includes(searchTerm)) &&
                        (fileFilter === 'all' || item.file === fileFilter)
                    );
                    
                    if (items.length > 0) {{
                        hasResults = true;
                        const categoryDiv = document.createElement('div');
                        categoryDiv.className = 'category';
                        categoryDiv.innerHTML = `<div class="category-title">${{cat.title}} (${{items.length}})</div>`;
                        
                        items.forEach(item => {{
                            const itemDiv = document.createElement('div');
                            itemDiv.className = `item ${{cat.type}}`;
                            itemDiv.textContent = item.value;
                            categoryDiv.appendChild(itemDiv);
                        }});
                        
                        container.appendChild(categoryDiv);
                    }}
                }}
            }});
            
            // Render paths
            if (categoryFilter === 'all' || categoryFilter === 'paths') {{
                Object.entries(data.paths).forEach(([category, paths]) => {{
                    const filteredPaths = paths.filter(item =>
                        (searchTerm === '' || item.value.toLowerCase().includes(searchTerm)) &&
                        (fileFilter === 'all' || item.file === fileFilter)
                    );
                    
                    if (filteredPaths.length > 0) {{
                        hasResults = true;
                        const categoryDiv = document.createElement('div');
                        categoryDiv.className = 'category';
                        categoryDiv.innerHTML = `<div class="category-title">📁 ${{category}} (${{filteredPaths.length}})</div>`;
                        
                        filteredPaths.forEach(item => {{
                            const itemDiv = document.createElement('div');
                            itemDiv.className = 'item path';
                            itemDiv.textContent = item.value;
                            categoryDiv.appendChild(itemDiv);
                        }});
                        
                        container.appendChild(categoryDiv);
                    }}
                }});
            }}
            
            emptyState.classList.toggle('hidden', hasResults);
        }}
        
        // Event listeners
        document.getElementById('category-filter').addEventListener('change', renderResults);
        document.getElementById('file-filter').addEventListener('change', renderResults);
        document.getElementById('search-input').addEventListener('input', renderResults);
        
        // Initial render
        renderResults();
    </script>
</body>
</html>'''
        
        # Write HTML file
        with open(self.html_output, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(html_template)
        
        print(f'{self.GREEN}✓ HTML report generated: {self.html_output}{self.WHITE}')
