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
    
    
    def __strip_ansi(self, text):
        return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
    
    def _log(self, message):
        print(message)
        if hasattr(self, 'output_file') and self.output_file:
             # Strip ANSI codes
             plain_message = self.__strip_ansi(message)
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
        elif 'stripe.com' in path.lower():
             self.__add_to_dict('Stripe', path, paths)
        elif 'squareup.com' in path.lower():
             self.__add_to_dict('Square', path, paths)
        elif 'youtube.com' in path.lower():
             self.__add_to_dict('YouTube', path, paths)
        
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
                and not entry.strip().endswith('.otf')
                and not entry.strip().endswith('.woff')
                and not entry.strip().endswith('.woff2')
                and not entry.strip().endswith('.ico')
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
                    entry = self.__pretty_entry(o)
                    self._log(f'{self.YELLOW}{entry}{self.WHITE}\n')
                    # Collect for HTML report
                    if hasattr(self, 'html_data'):
                        if 'objects' not in self.html_data:
                            self.html_data['objects'] = {}
                        if section not in self.html_data['objects']:
                            self.html_data['objects'][section] = []
                        self.html_data['objects'][section].append({'value': self.__strip_ansi(entry), 'file': js_file})
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
                    self.html_data['paths'][k].append({'value': self.__strip_ansi(path), 'file': js_file})
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
                    self.html_data['secrets'].append({'value': self.__strip_ansi(secret), 'file': js_file})
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
                    self.html_data['emails'].append({'value': self.__strip_ansi(email), 'file': js_file})
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
                        self.html_data['ips'].append({'value': self.__strip_ansi(ip), 'file': js_file})
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
                        self.html_data['comments'].append({'value': self.__strip_ansi(comment.strip()), 'file': js_file})
                self._log('')

    def __extract_sinks(self, js, js_file=''):
        sinks = re.findall(self.REG_DOM_SINK, js)
        if sinks:
            self._log(f'{self.CYAN}Dangerous Functions (DOM Sinks)\n-------------------------------{self.WHITE}')
            for sink in sorted(set(sinks)):
                self._log(f'{self.RED}{sink}{self.WHITE}')
                # Collect for HTML report
                if hasattr(self, 'html_data'):
                    self.html_data['sinks'].append({'value': self.__strip_ansi(sink), 'file': js_file})
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
        
        # Ensure all keys exist
        for key in ['target_url', 'parsed_files', 'secrets', 'emails', 'ips', 'comments', 'sinks', 'objects', 'paths']:
            if key not in self.html_data:
                if key in ['objects', 'paths']: self.html_data[key] = {}
                elif key == 'parsed_files': self.html_data[key] = []
                else: self.html_data[key] = [] if key != 'target_url' else ""

        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aranea Analysis Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg-color: #020617;
            --container-bg: rgba(15, 23, 42, 0.7);
            --card-bg: rgba(30, 41, 59, 0.5);
            --accent-primary: #38bdf8;
            --accent-secondary: #818cf8;
            --accent-tertiary: #f43f5e;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: rgba(51, 65, 85, 0.5);
            --glass-border: rgba(255, 255, 255, 0.1);
            --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Outfit', sans-serif; 
            background: radial-gradient(circle at top right, #1e1b4b, #020617);
            background-attachment: fixed;
            color: var(--text-primary); 
            min-height: 100vh; 
            padding: 20px; 
            line-height: 1.6;
        }}

        .container {{ 
            max-width: 1400px; 
            margin: 40px auto; 
            background: var(--container-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-radius: 32px; 
            padding: 48px; 
            box-shadow: var(--glass-shadow);
            border: 1px solid var(--glass-border);
        }}

        .header {{ 
            text-align: center; 
            margin-bottom: 60px; 
            position: relative; 
        }}
        
        .header h1 {{ 
            font-size: 3.5rem; 
            font-weight: 800; 
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent; 
            margin-bottom: 20px; 
            letter-spacing: -0.04em;
            filter: drop-shadow(0 0 30px rgba(56, 189, 248, 0.3));
        }}

        .header .meta {{ 
            color: var(--text-secondary); 
            font-size: 0.95rem; 
            display: flex; 
            justify-content: center; 
            align-items: center;
            gap: 32px; 
            flex-wrap: wrap;
        }}

        .header .meta span {{
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .header .meta i {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}

        .header .target-url {{ 
            color: var(--accent-primary); 
            font-weight: 600; 
            text-decoration: none; 
            transition: color 0.2s;
        }}
        .header .target-url:hover {{ color: var(--accent-secondary); }}
        
        .stats-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 20px; 
            margin-bottom: 48px; 
        }}

        .stat-card {{ 
            background: var(--card-bg);
            backdrop-filter: blur(8px);
            padding: 24px; 
            border-radius: 24px; 
            border: 1px solid var(--glass-border);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(135deg, transparent, rgba(255,255,255,0.05));
            pointer-events: none;
        }}

        .stat-card:hover {{ 
            transform: translateY(-8px); 
            border-color: var(--accent-primary);
            box-shadow: 0 12px 24px -10px rgba(56, 189, 248, 0.3);
        }}

        .stat-card .number {{ 
            font-size: 2.5rem; 
            font-weight: 800; 
            color: #fff; 
            margin-bottom: 6px; 
            letter-spacing: -0.02em;
        }}

        .stat-card .label {{ 
            color: var(--text-secondary); 
            font-size: 0.8rem; 
            font-weight: 700; 
            text-transform: uppercase; 
            letter-spacing: 0.1em; 
        }}

        .filters {{ 
            background: rgba(15, 23, 42, 0.5);
            padding: 32px; 
            border-radius: 28px; 
            margin-bottom: 48px; 
            border: 1px solid var(--border-color); 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 32px; 
        }}

        .filter-group label {{ 
            display: block; 
            margin-bottom: 14px; 
            color: var(--text-primary); 
            font-size: 0.9rem; 
            font-weight: 600; 
            letter-spacing: 0.02em;
        }}
        
        .multi-select {{ 
            position: relative; 
            background: #0f172a; 
            border: 1px solid var(--border-color); 
            border-radius: 14px; 
            padding: 12px 18px; 
            min-height: 48px; 
            cursor: pointer; 
            display: flex; 
            align-items: center; 
            justify-content: space-between;
            transition: all 0.2s;
        }}

        .multi-select:hover {{ border-color: var(--accent-primary); }}

        .multi-select-options {{ 
            position: absolute; 
            top: calc(100% + 10px); 
            left: 0; 
            right: 0; 
            background: #0f172a; 
            border: 1px solid var(--border-color); 
            border-radius: 16px; 
            padding: 16px; 
            max-height: 350px; 
            overflow-y: auto; 
            z-index: 100; 
            display: none; 
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); 
            backdrop-filter: blur(20px);
        }}

        .multi-select.active .multi-select-options {{ display: block; animation: slideDown 0.2s ease-out; }}

        @keyframes slideDown {{
            from {{ opacity: 0; transform: translateY(-10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        .option-item {{ 
            display: flex; 
            align-items: center; 
            gap: 12px; 
            padding: 10px 14px; 
            border-radius: 10px; 
            cursor: pointer; 
            transition: background 0.2s; 
            font-size: 0.9rem; 
            color: var(--text-secondary);
        }}

        .option-item:hover {{ background: #1e293b; color: var(--text-primary); }}
        .option-item input {{ 
            accent-color: var(--accent-primary);
            width: 18px; height: 18px; cursor: pointer; 
        }}
        
        .search-box {{ 
            width: 100%; 
            padding: 14px 20px; 
            border-radius: 14px; 
            border: 1px solid var(--border-color); 
            background: #0f172a; 
            color: var(--text-primary); 
            font-size: 0.9rem; 
            transition: all 0.2s; 
            font-family: inherit;
        }}

        .search-box:focus {{ 
            outline: none; 
            border-color: var(--accent-primary); 
            box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.15);
        }}

        .category {{ 
            background: var(--card-bg);
            backdrop-filter: blur(8px);
            border-radius: 28px; 
            padding: 32px; 
            margin-bottom: 32px; 
            border: 1px solid var(--glass-border); 
            transition: opacity 0.3s;
            position: relative;
        }}

        .category::before {{
            content: '';
            position: absolute;
            left: 0; top: 32px; bottom: 32px; width: 6px;
            background: linear-gradient(to bottom, var(--accent-primary), var(--accent-secondary));
            border-radius: 0 4px 4px 0;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
        }}

        .category-title {{ 
            font-size: 1.5rem; 
            font-weight: 700; 
            margin-bottom: 24px; 
            color: #fff; 
            display: flex; 
            align-items: center; 
            gap: 16px; 
            letter-spacing: -0.02em;
        }}

        .item {{ 
            background: rgba(15, 23, 42, 0.4); 
            padding: 20px; 
            border-radius: 16px; 
            margin-bottom: 16px; 
            border: 1px solid var(--border-color); 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 0.85rem; 
            word-break: break-all; 
            color: #e2e8f0; 
            position: relative; 
            transition: all 0.2s;
            display: flex;
            align-items: center;
        }}

        .item:hover {{ 
            background: rgba(30, 41, 59, 0.6); 
            border-color: var(--accent-primary);
            transform: scale(1.005);
        }}

        .item:last-child {{ margin-bottom: 0; }}
        
        .file-tag {{ 
            position: absolute; 
            top: -10px; 
            right: 20px; 
            font-size: 11px; 
            font-weight: 600;
            color: var(--accent-primary); 
            background: #0f172a; 
            padding: 4px 12px; 
            border-radius: 8px; 
            border: 1px solid var(--border-color);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
            text-transform: lowercase;
        }}

        .item.secret {{ border-left: 4px solid var(--accent-tertiary); }}
        .item.email {{ border-left: 4px solid #f59e0b; }}
        .item.ip {{ border-left: 4px solid #8b5cf6; }}
        .item.sink {{ border-left: 4px solid #ef4444; }}
        .item.comment {{ border-left: 4px solid #06b6d4; }}
        .item.path {{ border-left: 4px solid #10b981; }}
        .item.object {{ border-left: 4px solid var(--accent-secondary); }}

        .empty-state {{ 
            text-align: center; 
            padding: 100px 0; 
            color: var(--text-secondary); 
            font-size: 1.2rem;
            font-weight: 500;
        }}
        
        .hidden {{ display: none !important; }}

        /* Scrollbar Styling */
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: var(--border-color); border-radius: 10px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--text-secondary); }}

        .clear-btn {{
            background: rgba(244, 63, 94, 0.1);
            color: var(--accent-tertiary);
            border: 1px solid rgba(244, 63, 94, 0.2);
            padding: 12px 24px;
            border-radius: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: fit-content;
            grid-column: 1 / -1;
            margin: 0 auto;
        }}
        .clear-btn:hover {{
            background: var(--accent-tertiary);
            color: white;
            box-shadow: 0 0 20px rgba(244, 63, 94, 0.3);
            transform: translateY(-2px);
        }}
    </style>
</head>
<body>
    <div class="container" onclick="closeAllMultiSelects(event)">
        <div class="header">
            <h1><i class="fa-solid fa-spider" style="margin-right: 15px; font-size: 0.9em;"></i>Aranea Analysis Report</h1>
            <div class="meta">
                <span><i class="fa-solid fa-link"></i> <a href="{self.html_data['target_url']}" class="target-url" target="_blank">{self.html_data['target_url']}</a></span>
                <span><i class="fa-solid fa-calendar-days" style="margin-right: 5px;"></i> {datetime.now().strftime("%Y-%m-%d %H:%M")}</span>
                <span><i class="fa-solid fa-box-open"></i> <span id="files-count"></span> JS Files</span>
            </div>
        </div>
        
        <div class="stats-grid" id="stats-grid"></div>
        
        <div class="filters">
            <div class="filter-group">
                <label>Finding Category</label>
                <div class="multi-select" id="cat-select" onclick="toggleMultiSelect(this, event)">
                    <span>Selected: <span id="cat-count">All</span></span>
                    <div class="multi-select-options" id="cat-options"></div>
                </div>
            </div>
            <div class="filter-group">
                <label>Source JavaScript File</label>
                <div class="multi-select" id="file-select" onclick="toggleMultiSelect(this, event)">
                    <span>Selected: <span id="file-count">All</span></span>
                    <div class="multi-select-options" id="file-options"></div>
                </div>
            </div>
            <div class="filter-group">
                <label>Specific Keywords</label>
                <div class="multi-select" id="kw-select" onclick="toggleMultiSelect(this, event)">
                    <span>Selected: <span id="kw-count">All</span></span>
                    <div class="multi-select-options" id="kw-options"></div>
                </div>
            </div>
            <div class="filter-group">
                <label>Path Category</label>
                <div class="multi-select" id="path-cat-select" onclick="toggleMultiSelect(this, event)">
                    <span>Selected: <span id="path-cat-count">All</span></span>
                    <div class="multi-select-options" id="path-cat-options"></div>
                </div>
            </div>
            <div class="filter-group">
                <label>Generic Search</label>
                <input type="text" id="search-input" class="search-box" placeholder="Match findings by content...">
            </div>
            <button class="clear-btn" onclick="clearAllFilters()">
                <i class="fa-solid fa-filter-circle-xmark"></i>
                Clear All Filters
            </button>
        </div>
        
        <div id="results-container"></div>
        <div id="empty-state" class="empty-state hidden">No findings match your active filters.</div>
    </div>
    
    <script>
        const data = {json.dumps(self.html_data)};
        
        let activeFilters = {{
            categories: [],
            files: [],
            keywords: [],
            path_categories: [],
            search: ""
        }};

        function init() {{
            document.getElementById('files-count').textContent = data.parsed_files.length;
            initFilters();
            updateStats();
            render();
        }}

        function initFilters() {{
            const cats = ['Secrets', 'Emails', 'IPs', 'DOM Sinks', 'Comments', 'Paths', 'Keywords'];
            const catOptions = document.getElementById('cat-options');
            createSelectAll(catOptions, 'categories');
            cats.forEach(c => createOption(catOptions, c, 'categories'));

            const fileOptions = document.getElementById('file-options');
            createSelectAll(fileOptions, 'files');
            data.parsed_files.forEach(f => createOption(fileOptions, f, 'files'));

            const kwOptions = document.getElementById('kw-options');
            createSelectAll(kwOptions, 'keywords');
            Object.keys(data.objects || {{}}).forEach(k => createOption(kwOptions, k, 'keywords'));

            const pathCatOptions = document.getElementById('path-cat-options');
            createSelectAll(pathCatOptions, 'path_categories');
            Object.keys(data.paths || {{}}).forEach(k => createOption(pathCatOptions, k, 'path_categories'));
            
            document.getElementById('search-input').addEventListener('input', (e) => {{
                activeFilters.search = e.target.value.toLowerCase();
                render();
            }});
        }}

        function createSelectAll(container, filterKey) {{
            const div = document.createElement('div');
            div.className = 'option-item select-all';
            div.style.borderBottom = '1px solid #334155';
            div.style.marginBottom = '8px';
            div.style.paddingBottom = '8px';
            div.onclick = (e) => e.stopPropagation();

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.onchange = () => {{
                const options = container.querySelectorAll('input:not(.select-all-input)');
                options.forEach(cb => {{
                    cb.checked = checkbox.checked;
                    const label = cb.nextSibling.textContent;
                    if (checkbox.checked) {{
                        if (!activeFilters[filterKey].includes(label)) activeFilters[filterKey].push(label);
                    }} else {{
                        activeFilters[filterKey] = activeFilters[filterKey].filter(v => v !== label);
                    }}
                }});
                updateFilterCount(filterKey);
                render();
            }};
            checkbox.className = 'select-all-input';

            const span = document.createElement('span');
            span.textContent = 'Select All';
            span.style.fontWeight = '700';
            span.style.color = 'var(--accent-primary)';
            div.append(checkbox, span);
            container.appendChild(div);
        }}

        function createOption(container, label, filterKey) {{
            const div = document.createElement('div');
            div.className = 'option-item';
            div.onclick = (e) => e.stopPropagation();
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.onchange = () => {{
                if (checkbox.checked) activeFilters[filterKey].push(label);
                else activeFilters[filterKey] = activeFilters[filterKey].filter(v => v !== label);
                updateFilterCount(filterKey);
                render();
            }};
            
            const span = document.createElement('span');
            span.textContent = label;
            div.append(checkbox, span);
            container.appendChild(div);
        }}

        function updateFilterCount(filterKey) {{
            let countId;
            if (filterKey === 'categories') countId = 'cat-count';
            else if (filterKey === 'files') countId = 'file-count';
            else if (filterKey === 'keywords') countId = 'kw-count';
            else if (filterKey === 'path_categories') countId = 'path-cat-count';
            
            document.getElementById(countId).textContent = 
                activeFilters[filterKey].length === 0 ? 'All' : activeFilters[filterKey].length;
        }}

        function clearAllFilters() {{
            activeFilters = {{
                categories: [],
                files: [],
                keywords: [],
                path_categories: [],
                search: ""
            }};
            document.getElementById('search-input').value = '';
            document.querySelectorAll('.multi-select-options input').forEach(cb => cb.checked = false);
            updateFilterCount('categories');
            updateFilterCount('files');
            updateFilterCount('keywords');
            updateFilterCount('path_categories');
            render();
        }}

        function toggleMultiSelect(el, e) {{
            e.stopPropagation();
            const wasActive = el.classList.contains('active');
            closeAllMultiSelects();
            if (!wasActive) el.classList.add('active');
        }}

        function closeAllMultiSelects() {{
            document.querySelectorAll('.multi-select').forEach(el => el.classList.remove('active'));
        }}

        function updateStats() {{
            const stats = [
                {{ label: 'Secrets', count: data.secrets.length }},
                {{ label: 'Emails', count: data.emails.length }},
                {{ label: 'IPs', count: data.ips.length }},
                {{ label: 'DOM Sinks', count: data.sinks.length }},
                {{ label: 'Comments', count: data.comments.length }},
                {{ label: 'Keywords', count: Object.values(data.objects || {{}}).flat().length }},
                {{ label: 'Paths', count: Object.values(data.paths || {{}}).flat().length }}
            ];
            
            const grid = document.getElementById('stats-grid');
            grid.innerHTML = stats.map(s => `
                <div class="stat-card">
                    <div class="number">${{s.count}}</div>
                    <div class="label">${{s.label}}</div>
                </div>
            `).join('');
        }}

        function render() {{
            const container = document.getElementById('results-container');
            container.innerHTML = '';
            let totalFound = 0;

            const sections = [
                {{ id: 'Secrets', data: data.secrets, type: 'secret' }},
                {{ id: 'Emails', data: data.emails, type: 'email' }},
                {{ id: 'IPs', data: data.ips, type: 'ip' }},
                {{ id: 'DOM Sinks', data: data.sinks, type: 'sink' }},
                {{ id: 'Comments', data: data.comments, type: 'comment' }}
            ];

            sections.forEach(s => {{
                if (activeFilters.categories.length > 0 && !activeFilters.categories.includes(s.id)) return;
                const filtered = s.data.filter(item => isVisible(item));
                if (filtered.length > 0) {{
                    totalFound += renderCategory(s.id, filtered, s.type);
                }}
            }});

            // Objects/Keywords
            if (activeFilters.categories.length === 0 || activeFilters.categories.includes('Keywords')) {{
                Object.entries(data.objects || {{}}).forEach(([kw, items]) => {{
                    if (activeFilters.keywords.length > 0 && !activeFilters.keywords.includes(kw)) return;
                    const filtered = items.filter(item => isVisible(item));
                    if (filtered.length > 0) {{
                        totalFound += renderCategory(`Keyword: ${{kw}}`, filtered, 'object');
                    }}
                }});
            }}

            // Paths
            if (activeFilters.categories.length === 0 || activeFilters.categories.includes('Paths')) {{
                Object.entries(data.paths || {{}}).forEach(([pType, items]) => {{
                    if (activeFilters.path_categories.length > 0 && !activeFilters.path_categories.includes(pType)) return;
                    const filtered = items.filter(item => isVisible(item));
                    if (filtered.length > 0) {{
                        totalFound += renderCategory(`Path: ${{pType}}`, filtered, 'path');
                    }}
                }});
            }}

            document.getElementById('empty-state').classList.toggle('hidden', totalFound > 0);
        }}

        function isVisible(item) {{
            const matchesFile = activeFilters.files.length === 0 || activeFilters.files.includes(item.file);
            const matchesSearch = activeFilters.search === "" || item.value.toLowerCase().includes(activeFilters.search);
            return matchesFile && matchesSearch;
        }}

        function renderCategory(title, items, type) {{
            const div = document.createElement('div');
            div.className = 'category';
            div.innerHTML = `<div class="category-title">${{title}} (${{items.length}})</div>`;
            items.forEach(item => {{
                const iDiv = document.createElement('div');
                iDiv.className = `item ${{type}}`;
                iDiv.textContent = item.value;
                if (item.file) {{
                    const tag = document.createElement('span');
                    tag.className = 'file-tag';
                    tag.textContent = item.file.split('/').pop();
                    iDiv.appendChild(tag);
                }}
                div.appendChild(iDiv);
            }});
            document.getElementById('results-container').appendChild(div);
            return items.length;
        }}

        init();
    </script>
</body>
</html>'''

        with open(self.html_output, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(html_template)
        print(f'{self.GREEN}✓ HTML report generated: {self.html_output}{self.WHITE}')

