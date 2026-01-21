from collections import deque
from urllib.parse import urljoin, urlparse
from urllib3.exceptions import InsecureRequestWarning

import requests
from requests.exceptions import SSLError


class Base:

    URLS = {
        'internal': set(),
        'external': set(),
        'visited': set(),
        'not_visited': deque([])
    }

    def __init__(self, url, threads, headers, strict, mainonly=False, continuous=False, output=None, auto=False, html_output=None, no_log=''):
        self.base = url
        self.threads = threads
        self.headers = self.__get_headers(headers)
        self.domain = self.__get_domain(url)
        self.strict = strict
        self.mainonly = mainonly
        self.continuous = continuous
        self.output_file = output
        self.auto = auto
        self.html_output = html_output
        self.no_log = [x.strip().lower() for x in no_log.split(',')] if no_log else []
        self._add_not_visited(url)

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

    def _add_not_visited(self, url):
        if (
            url and url not in self.URLS['visited']
                and url not in self.URLS['not_visited']):
            self.URLS['not_visited'].append(url)

    def _add_visited(self):
        url = self.URLS['not_visited'].popleft()
        self.URLS['visited'].add(url)
        if urlparse(url).netloc in self.domain:
            self.URLS['internal'].add(url)
        else:
            self.URLS['external'].add(url)
        return url

    def _get_page_source(self, url):
        requests.packages.urllib3.disable_warnings(
            category=InsecureRequestWarning)
        try:
            return requests.get(url, headers=self.headers)
        except SSLError:
            return requests.get(
                url, headers=self.headers, verify=False)

    def _process_path(self, url, path):
        if path.startswith('http'):
            return path
        path = urljoin(url, path)
        return path
