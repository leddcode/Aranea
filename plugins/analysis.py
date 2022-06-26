import re

from bs4 import BeautifulSoup as bs
import requests


class Analysis:

    REG_O = r'(?:[\"]?[a-zA-Z0-9_\-]*[\"]?[:=]\{(?:[\"]?[a-zA-Z0-9_-]*[\"]?:[\"]?[a-zA-Z0-9_\-/\\]*[\"]?(?:\,)?)+\})'
    REG_L = r'(?:[\"]?[a-zA-Z0-9_\-]*[\"]?[:=]\[(?:[\"]?[a-zA-Z0-9_-]*[\"](?:\,)?)+\])'

    SECTIONS = open('utils/sections.txt').read().splitlines()

    def __get_js_urls(self, url):
        html = self._get_page_source(url)
        soup = bs(html, 'html.parser')
        for script in soup.find_all('script'):
            path = script.get('src')
            if path:
                yield self._process_path(url, path)

    def __find_mainjs(self, url):
        if '.js' in url:
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

    def __get_pathes(self, js):
        data = (
            e for e in js.split('"')
            if len(e) > 1 and e.startswith('/') and e[1].isalnum()
        )
        pathes = {}
        for e in data:
            if 'user' in e.lower():
                self.__add_to_dict('User Pathes', e, pathes)
            elif 'admin' in e.lower():
                self.__add_to_dict('Admin Pathes', e, pathes)
            elif 'role' in e.lower():
                self.__add_to_dict('Role Pathes', e, pathes)
            else:
                self.__add_to_dict('Other Pathes', e, pathes)
        return pathes

    def __pretty_entry(self, entry):
        return entry.replace("{", "\n\t").replace("[", "\n\t").replace(", ", "\n\t") \
            .replace(",", "\n\t").replace("}", "").replace("]", "") \
            .replace("=\n", f'{self.GREEN}\n').replace(":\n", f'{self.GREEN}\n') \
            .replace('"', '').replace("'", "")

    def __print_objects(self, objects, js):
        printed = []
        for section in self.SECTIONS:
            print(f'{self.CYAN}\n # {section}{self.WHITE}')
            count = 0
            for o in objects:
                if section.lower() in o.lower() and o not in printed:
                    print(f'{self.YELLOW} > {self.__pretty_entry(o)}{self.WHITE}')
                    count += 1
                    printed.append(o)
            if section == 'Path':
                count = self.__print_pathes(js, count)
            if not count:
                print(f'{self.RED} > No Relevant Data{self.WHITE}')

    def __print_pathes(self, js, count=0):
        for k, v in self.__get_pathes(js).items():
            o = f'{str(k)}:{str(v)}'
            print(f'{self.YELLOW} > {self.__pretty_entry(o)}{self.WHITE}')
            count += 1
        return count

    def analize(self):
        main_js = self.__find_mainjs(self.base)
        if main_js:
            print(f'{self.CYAN} Fetch JS File{self.WHITE}')
            js = requests.get(main_js).text
            print(f'{self.CYAN} Parse JS Code{self.WHITE}')
            objects = re.findall(self.REG_O, js) + re.findall(self.REG_L, js)
            self.__print_objects(set(objects), js)
        else:
            print(f"{self.RED} Main js file wasn't found!{self.WHITE}")
