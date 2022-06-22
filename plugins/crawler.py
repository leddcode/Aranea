from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from pickletools import uint1
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup as bs
import requests


class Crawler:

    URLS = {
        'internal': set(),
        'external': set(),
        'visited': set(),
        'not_visited': deque([])
    }

    URL_REG = r'http[s]?:[\\]?/[\\]?/(?:(?!http[s]?:[\\]?/[\\]?/)[a-zA-Z]|[0-9]|[\\]?[$\-_@.&+/]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    def __init__(self, url, threads, headers):
        self.base = url
        self.threads = threads
        self.headers = self.__get_headers(headers)
        self.domain = self.__get_domain(url)
        self.__add_not_visited(url)
        self.executor = ThreadPoolExecutor(max_workers=5)

    def __get_domain(self, url):
        domain = [urlparse(url).netloc]
        if domain[0].startswith('www.'):
            domain.append(domain[0][4:])
        else:
            domain.append('www.' + domain[0])
        return domain

    def __get_headers(self, headers):
        if headers:
            return {
                k.strip(): v.strip() for k, v in (
                    h.split(':') for h in headers.split(','))}

    def __add_not_visited(self, url):
        if (
            url and url not in self.URLS['visited']
                and url not in self.URLS['not_visited']):
            self.URLS['not_visited'].append(url)

    def __add_visited(self):
        url = self.URLS['not_visited'].popleft()
        self.URLS['visited'].add(url)
        if urlparse(url).netloc in self.domain:
            self.URLS['internal'].add(url)
        else:
            self.URLS['external'].add(url)
        return url

    def __get_page_source(self, url):
        return requests.get(
            url, headers=self.headers).text  # , verify=False if needed

    def __process_path(self, url, path):
        if '#' in path:
            path = path.split('#')[0]
        if path.startswith('http'):
            return path
        path = urljoin(url, path)
        return path

    def __get_a_hrefs(self, url, soup):
        for a in soup.find_all('a'):
            path = a.get('href')
            if path and path != '/':
                yield self.__process_path(url, path)

    def __reg_extract_uls(self, soup):
        for url in set(re.findall(self.URL_REG, soup.text)):
            u = url.replace('\\', '')
            if u not in self.URLS['visited']:
                self.URLS['visited'].add(u)
                self.__write(u, '3. Extracted')
                print(f'{self.ORANGE}EXTRACT  :: {u}{self.WHITE}')

    def __get_script_sources(self, url, soup):
        for script in soup.find_all('script'):
            self.__reg_extract_uls(script)
            path = script.get('src')
            if path:
                yield self.__process_path(url, path)

    def __get_form_actions(self, url, soup):
        for form in soup.find_all('form'):
            path = form.get('action')
            if path:
                yield self.__process_path(url, path)

    def __process_url(self, url):
        html = self.__get_page_source(url)
        soup = bs(html, 'html.parser')

        # Tag <a>
        for url in self.__get_a_hrefs(url, soup):
            self.__add_not_visited(url)

        # Tag <script>
        for url in self.__get_script_sources(url, soup):
            if url not in self.URLS['visited']:
                self.URLS['visited'].add(url)
                self.__write_script(url)

        # Tag <form>
        for url in self.__get_form_actions(url, soup):
            if url not in self.URLS['visited']:
                print(f'{self.DARKCYAN}F-ACTION :: {url}{self.WHITE}')
                self.__add_not_visited(url)

    def __get_dir(self, url):
        directories = urlparse(url).path.split('/')
        if ((len(directories) > 1 and urlparse(url).query)
                or (len(directories) > 2 and directories[2])):
            return directories[1]
        return '1. General'

    def __write(self, url, directory):
        filepath = Path(f'scans/{self.domain[0]}/{directory}.txt')
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'a+', encoding='utf-8', errors='ignore') as f:
            f.write(f'{url}\n')

    def __write_script(self, url):
        self.__write(url, '4. JS')
        print(f'{self.CYAN}JS File  :: {url}{self.WHITE}')

    def __thread(self):
        url = self.__add_visited()
        if url in self.URLS['external']:
            self.__write(url, '2. External')
            print(f'{self.YELLOW}EXTERNAL :: {url}{self.WHITE}')
        else:
            directory = self.__get_dir(url)
            self.__write(url, directory)
            print(f'{self.GREEN}CRAWLING :: {url}{self.WHITE}')
            # if not 'logout' in url: # TODO
            try:
                self.__process_url(url)
            except Exception as e:
                print(f'ERROR    :: Failed to crawl: {url}', e)

    def crawl(self):
        tmp = list(self.URLS['not_visited'])
        while self.URLS['not_visited']:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for url in tmp:
                    executor.submit(self.__thread)
                tmp = list(self.URLS['not_visited'])
