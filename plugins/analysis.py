import re

from bs4 import BeautifulSoup as bs

from utils.strings import MAINJS_NOT_FOUND


class Analysis:

    BAD_CHARS = (' ', '\n', '\r', '$', '<', '>', '{', '}', '[', ']', '(', ')', '*', '~', '^', '@', ',', '\\')

    SECTIONS = open('utils/sections.txt').read().splitlines()
    IGNORE_LIST = open('utils/ignorelist.txt', errors='ignore').read().splitlines()

    REG_O = r'(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*[:=]\s*\{(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*:\s*(?:(?:\"[a-zA-Z0-9_\-/\\]*\"|\'[a-zA-Z0-9_\-/\\]*\'|[a-zA-Z0-9_\-/\\]+))\s*(?:,)?\s*)+\})'
    REG_L = r'(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*[:=]\s*\[(?:(?:\"[a-zA-Z0-9_\-]*\"|\'[a-zA-Z0-9_\-]*\'|[a-zA-Z0-9_\-]+)\s*(?:,)?\s*)+\])'

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
        elif 'blob.core.windows' in path.lower():
            self.__add_to_dict('Azure Containers', path, paths)
        elif 'firebase' in path.lower():
            self.__add_to_dict('Firebase', path, paths)
        elif '.json' in path.lower():
            self.__add_to_dict('JSON Files', path, paths)
        elif '.js' in path.lower():
            self.__add_to_dict('JS Files', path, paths)
        elif '.ts' in path.lower():
            self.__add_to_dict('TS Files', path, paths)
        elif any(kw in path.lower() for kw in ('.png', '.jpg', '.gif', '.svg')):
            self.__add_to_dict('Images', path, paths)
        elif 'module' in path.lower():
            self.__add_to_dict('Modules', path, paths)
        
        # Additional keywords.
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
            )
        ]
        if len(data):
            print(f'{self.CYAN}Available Paths\n---------------{self.WHITE}')
        else:
            print(f'The extraction process yielded no viable {self.ORANGE}paths{self.WHITE}')
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

    def __print_objects(self, objects, js):
        extracted_objects = 0
        mapped_objects = self.__map_objects(objects)
        for section in mapped_objects.keys():
            if mapped_objects[section]:
                title = f'{self.CYAN}Keyword: {self.WHITE}{section}{self.CYAN} (Total objects: {len(mapped_objects[section])})'
                print(f'\n{title}')
                print('-' * (len(title) - 14), self.WHITE)
                for o in mapped_objects[section]:
                    print(f'{self.YELLOW}{self.__pretty_entry(o)}{self.WHITE}\n')
                    extracted_objects += 1
        
        # Warn - no useful data was found.
        if not extracted_objects:
            print(f'\nThe extraction process yielded no viable {self.ORANGE}objects{self.WHITE}\n')
        
        # Look for paths.
        self.__print_paths(js)

    def __print_paths(self, js):
        for k, paths in self.__get_paths(js).items():
            print(f'{self.YELLOW}{k} {self.WHITE}(Total paths: {len(paths)})')
            for path in sorted(paths):
                print(f'{self.GREEN}{path}{self.WHITE}')
            print()
    
    def __parse_js(self, js_file):
        print(f'Fetching {self.CYAN}{js_file}{self.WHITE}')
        js = self._get_page_source(js_file).text
        objects = re.findall(self.REG_O, js) + re.findall(self.REG_L, js)
        self.__print_objects(set(objects), js)
    
    def __parse_all_js_files(self):
        for js_file in self.__get_js_urls(self.base):
            if self.mainonly and 'main' not in js_file:
                continue
            print(f'\n{self.DARKCYAN}NEXT{self.WHITE} {js_file}')
            to_parse_it = input('\nParse this file? y/N: ')
            if to_parse_it.strip().lower() in ('y', 'yes'):
                self.__parse_js(js_file)

    def analyze(self):
        if '.js' in self.base or self.strict:
            self.__parse_js(self.base)
        else:
            self.__parse_all_js_files()
