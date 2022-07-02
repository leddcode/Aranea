from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
from threading import Lock
from urllib.parse import urlparse

from bs4 import BeautifulSoup as bs
from requests import ConnectionError


class Crawler:

    URLS = {
        'internal': set(),
        'external': set(),
        'visited': set(),
        'not_visited': deque([])
    }

    DIRS = {
        'general': '1. General',
        'external': '2. External',
        'extracted': '3. Extracted',
        'js': '4. JS',
        'emails': '5 Emails'
    }

    URL_REG = r'http[s]?:[\\]?/[\\]?/(?:(?!http[s]?:[\\]?/[\\]?/)[a-zA-Z]|[0-9]|[\\]?[$\-_@.&+/]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    EMAIL_REG = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"

    LOCK = Lock()

    def __get_a_hrefs(self, url, soup):
        for a in soup.find_all('a'):
            path = a.get('href')
            if path and path != '/':
                yield self._process_path(url, path)

    def __reg_extract_emails(self, text, emails=set()):
        for email in set(re.findall(self.EMAIL_REG, text)):
            if email not in emails:
                emails.add(email)
                self.__write(email, self.DIRS['emails'])
                self.__print(f'{self.BLUE}EMAIL    :: {email}{self.WHITE}')

    def __reg_extract_uls(self, soup):
        for url in set(re.findall(self.URL_REG, soup.text)):
            u = url.replace('\\', '')
            if u not in self.URLS['visited']:
                self.URLS['visited'].add(u)
                self.__write(u, self.DIRS['extracted'])
                self.__print(f'{self.ORANGE}EXTRACT  :: {u}{self.WHITE}')

    def __get_script_sources(self, url, soup):
        for script in soup.find_all('script'):
            self.__reg_extract_uls(script)
            path = script.get('src')
            if path:
                yield self._process_path(url, path)

    def __get_form_actions(self, url, soup):
        for form in soup.find_all('form'):
            path = form.get('action')
            if path:
                yield self._process_path(url, path)

    def __process_url(self, url):
        html = self._get_page_source(url)
        soup = bs(html, 'html.parser')

        # Tag <a>
        for url in self.__get_a_hrefs(url, soup):
            self._add_not_visited(url)

        # Tag <script>
        for url in self.__get_script_sources(url, soup):
            if url not in self.URLS['visited']:
                self.URLS['visited'].add(url)
                self.__write_script(url)

        # Tag <form>
        for url in self.__get_form_actions(url, soup):
            if url not in self.URLS['visited']:
                self.__print(f'{self.DARKCYAN}F-ACTION :: {url}{self.WHITE}')
                self._add_not_visited(url)

        # Extract Emails
        self.__reg_extract_emails(html)

    def __get_dir(self, url):
        directories = urlparse(url).path.split('/')
        if ((len(directories) > 1 and urlparse(url).query)
                or (len(directories) > 2 and directories[2])):
            return directories[1]
        return self.DIRS['general']

    def __write(self, url, directory):
        filepath = Path(f'scans/{self.domain[0]}/{directory}.txt')
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'a+', encoding='utf-8', errors='ignore') as f:
            f.write(f'{url}\n')

    def __write_script(self, url):
        self.__write(url, self.DIRS['js'])
        self.__print(f'{self.CYAN}JS File  :: {url}{self.WHITE}')

    def __thread(self):
        url = self._add_visited()
        if url in self.URLS['external']:
            self.__write(url, self.DIRS['external'])
            self.__print(f'{self.YELLOW}EXTERNAL :: {url}{self.WHITE}')
        else:
            directory = self.__get_dir(url)
            self.__write(url, directory)
            self.__print(f'{self.GREEN}CRAWLING :: {url}{self.WHITE}')
            # if not 'logout' in url: # TODO
            try:
                self.__process_url(url)
            except ConnectionError:
                print(
                    f'{self.RED}ERROR    :: Failed to establish a new connection!{self.WHITE} ({url})')
            except Exception:
                print(
                    f'{self.RED}ERROR    :: Failed to crawl!{self.WHITE} ({url})')

    def __print(self, output):
        self.LOCK.acquire()
        print(output)
        self.LOCK.release()

    def crawl(self):
        tmp = list(self.URLS['not_visited'])
        while self.URLS['not_visited']:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for url in tmp:
                    executor.submit(self.__thread)
                tmp = list(self.URLS['not_visited'])
