import re

from bs4 import BeautifulSoup as bs

from utils.strings import MAINJS_NOT_FOUND


class Analysis:

    BAD_CHARS = (' ', '\n', '\r', '$', '<', '>', '{', '}', '[', ']', '(', ')', '*', '~', '^', ',', '\\')

    SECTIONS = open('utils/sections.txt').read().splitlines()
    IGNORE_LIST = open('utils/ignorelist.txt', errors='ignore').read().splitlines()

    REG_O = r'(?:[\"]?[a-zA-Z0-9_\-]*[\"]?[:=]\{(?:[\"]?[a-zA-Z0-9_-]*[\"]?:[\"]?[a-zA-Z0-9_\-/\\]*[\"]?(?:\,)?)+\})'
    REG_L = r'(?:[\"]?[a-zA-Z0-9_\-]*[\"]?[:=]\[(?:[\"]?[a-zA-Z0-9_-]*[\"](?:\,)?)+\])'

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
        if 'assets' in path.lower():
            self.__add_to_dict('Assets', path, paths)
        elif '.js' in path.lower():
            self.__add_to_dict('JS Files', path, paths)
        elif '.ts' in path.lower():
            self.__add_to_dict('TS Files', path, paths)
        elif 'module' in path.lower():
            self.__add_to_dict('Modules', path, paths)
        elif 'api' in path.lower():
            self.__add_to_dict('API Paths', path, paths)
        elif 'login' in path.lower():
            self.__add_to_dict('Auth Paths', path, paths)
        elif 'register' in path.lower():
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
                if e.startswith('/'):
                    e = e.lstrip('/')
                self.__add_path(e, paths)
            checked.append(e.lower())
        return paths
    
    def __has_no_bad_char(self, s: str):
        return not any(char in self.BAD_CHARS for char in s.strip())

    def __get_paths(self, js):
        data = (
            entry.strip() for entry in js.split('"')
            if (
                '/' in entry.strip()                           # Possible Path
                and len(entry.strip()) > 2                     # Min Length
                and len(entry.strip()) < 100                   # Max Length
                and self.__has_no_bad_char(entry.strip())      # Filter
                and entry.strip() not in self.IGNORE_LIST      # Black List
            )
        )
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
        mapped_objects = self.__map_objects(objects)
        for section in mapped_objects.keys():
            if mapped_objects[section]:
                title = f'{self.CYAN}Keyword: {self.WHITE}{section}{self.CYAN} (Total objects: {len(mapped_objects[section])})'
                print(f'\n{title}')
                print('-' * (len(title) - 14), self.WHITE)
                for o in mapped_objects[section]:
                    print(f'{self.YELLOW}{self.__pretty_entry(o)}{self.WHITE}\n')
        print(f'{self.CYAN}Available Paths\n---------------{self.WHITE}')
        self.__print_paths(js)

    def __print_paths(self, js):
        for k, paths in self.__get_paths(js).items():
            print(f'{self.YELLOW}{k} {self.WHITE}(Total paths: {len(paths)})')
            for path in sorted(paths):
                print(f'{self.GREEN}{path}{self.WHITE}')
            print()

    def analyze(self):
        main_js = self.__find_mainjs(self.base)
        if main_js:
            print('Fetch JS File')
            js = self._get_page_source(main_js).text
            print(f'Parse JS Code')
            objects = re.findall(self.REG_O, js) + re.findall(self.REG_L, js)
            self.__print_objects(set(objects), js)
        else:
            print(f"{self.RED}{MAINJS_NOT_FOUND}{self.WHITE}")
