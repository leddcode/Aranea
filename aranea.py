import argparse

from mixins.base import Base
from mixins.colour import Colour
from plugins.analysis import Analysis
from plugins.crawler import Crawler
from requests import ConnectionError
from utils import strings


class Aranea(Base, Colour, Analysis, Crawler):

    def __init__(self, url, threads, headers):
        super().__init__(url, threads, headers)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '-U', '--url', help="Target URL", required=True)
        parser.add_argument(
            '-M', '--mode',
            help="Working Mode: crawl, analysis",
            required=True)
        parser.add_argument(
            '-T', '--threads',
            help="By default 10 threads used", default=10)
        parser.add_argument(
            '-H', '--headers',
            help="Should be a string as in example: 'Authorization:Bearer ey..,Cookie:role=admin;'",
            default='')
        return parser.parse_args()


if __name__ == '__main__':
    args = Aranea.parse_args()
    url = args.url.strip()
    threads = int(args.threads)
    headers = args.headers.strip()
    mode = args.mode.strip()

    print(strings.SOLID)
    print(strings.INTRO)
    print(strings.SOLID)
    print(f'''
 URL     :: {url}
 Mode    :: {mode}
 Threads :: {threads}
    ''')

    try:
        if 'crawl' in mode:
            Aranea(url, threads, headers).crawl()
        elif 'analysis' in mode:
            Aranea(url, threads, headers).analize()
    except ConnectionError:
        print(f'{Aranea.RED} Connection Error: Please check the URL address and try again - {url}{Aranea.WHITE}')
    except Exception as e:
        print(e)
