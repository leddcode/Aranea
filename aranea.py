import argparse

from requests import ConnectionError

from mixins.base import Base
from mixins.colour import Colour
from plugins.analysis import Analysis
from plugins.crawler import Crawler
from utils import strings


class Aranea(Base, Colour, Analysis, Crawler):

    def __init__(self, url, threads, headers, strict, mainonly=False):
        super().__init__(url, threads, headers, strict, mainonly)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '-u', '--url', help="Target URL", required=True)
        parser.add_argument(
            '-m', '--mode',
            help="Available Modes: crawl, analysis",
            required=True)
        parser.add_argument(
            '-t', '--threads',
            help="Default configuration: 10 threads", default=10)
        parser.add_argument(
            '--headers',
            help='Should be a string as in the example: "Authorization:Bearer ey..,Cookie:role=admin;"',
            default='')
        parser.add_argument(
            '-s', '--strict',
            help="For analysis mode: the URL will be parsed even if it does not have a JS extension.",
            action='store_true')
        parser.add_argument(
            '--mainonly',
            help="For analysis mode: only the main.js file will be parsed.",
            action='store_true')
        return parser.parse_args()


if __name__ == '__main__':
    args = Aranea.parse_args()
    url = args.url.strip()
    threads = int(args.threads)
    headers = args.headers.strip()
    mode = args.mode.strip()
    strict = args.strict
    mainonly = args.mainonly

    banner = f'''
URL      :: {url}
Mode     :: {mode}
Threads  :: {threads}
'''

    print(strings.SOLID)
    print(strings.INTRO)
    print(strings.SOLID)
    print(banner)

    try:
        if 'analysis' in mode:
            Aranea(url, threads, headers, strict, mainonly).analyze()
        elif 'crawl' in mode:
            Aranea(url, threads, headers, strict, mainonly).crawl()
        else:
            print(
                f'{Aranea.RED} The mode "{mode}" does not exist!{Aranea.WHITE}')
    except ConnectionError:
        print(f'{Aranea.RED} Connection Error: Please check the URL address and try again - {url}{Aranea.WHITE}')
    except Exception as e:
        print(e)
