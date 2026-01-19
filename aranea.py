import argparse

from requests import ConnectionError

from mixins.base import Base
from mixins.colour import Colour
from plugins.analysis import Analysis
from plugins.crawler import Crawler
from utils import strings


class Aranea(Base, Colour, Analysis, Crawler):

    def __init__(self, url, threads, headers, strict, mainonly=False, continuous=False, output=None, auto=False):
        super().__init__(url, threads, headers, strict, mainonly, continuous, output, auto)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        url_group = parser.add_mutually_exclusive_group(required=True)
        url_group.add_argument(
            '-u', '--url', help="Target URL")
        url_group.add_argument(
            '-ul', '--urllist', help="Path to file containing list of URLs (one per line)")
        parser.add_argument(
            '-m', '--mode',
            help="Available Modes: crawl, analysis",
            required=True)
        parser.add_argument(
            '-o', '--output',
            help="Output file to save analysis results")
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
        parser.add_argument(
            '-c', '--continuous',
            help="For analysis mode: recursively parse found JS files.",
            action='store_true')
        parser.add_argument(
            '--auto',
            help='For analysis mode with --continuous: automatically parse all files without prompting.',
            action='store_true')
        return parser.parse_args()

    @staticmethod
    def run_on_url(url, mode, threads, headers, strict, mainonly, continuous, output, auto):
        """Run the specified mode on a single URL"""
        try:
            if mode in ('analysis', 'a'):
                Aranea(url, threads, headers, strict, mainonly, continuous, output, auto).analyze()
            elif mode in ('crawl', 'c'):
                Aranea(url, threads, headers, strict, mainonly, continuous, output, auto).crawl()
            else:
                print(
                    f'{Aranea.RED} The mode "{mode}" does not exist!{Aranea.WHITE}')
        except ConnectionError:
            print(f'{Aranea.RED} Connection Error: Please check the URL address and try again - {url}{Aranea.WHITE}')
        except Exception as e:
            print(f'{Aranea.RED}Error processing {url}: {e}{Aranea.WHITE}')


if __name__ == '__main__':
    args = Aranea.parse_args()
    threads = int(args.threads)
    headers = args.headers.strip()
    mode = args.mode.strip()
    strict = args.strict
    mainonly = args.mainonly
    continuous = args.continuous
    output = args.output
    auto = args.auto

    # Collect URLs from either single URL or URL list file
    urls = []
    if args.url:
        urls = [args.url.strip()]
    elif args.urllist:
        try:
            with open(args.urllist, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except FileNotFoundError:
            print(f'{Aranea.RED}Error: URL list file not found: {args.urllist}{Aranea.WHITE}')
            exit(1)
        except Exception as e:
            print(f'{Aranea.RED}Error reading URL list file: {e}{Aranea.WHITE}')
            exit(1)

    if not urls:
        print(f'{Aranea.RED}Error: No URLs found to process{Aranea.WHITE}')
        exit(1)

    # Display banner
    print(strings.SOLID)
    print(strings.INTRO)
    print(strings.SOLID)
    
    # Process each URL
    total_urls = len(urls)
    for idx, url in enumerate(urls, 1):
        if total_urls > 1:
            print(f'\n{Aranea.CYAN}{"=" * 60}{Aranea.WHITE}')
            print(f'{Aranea.CYAN}Processing URL {idx} of {total_urls}{Aranea.WHITE}')
            print(f'{Aranea.CYAN}{"=" * 60}{Aranea.WHITE}\n')
        
        banner = f'''
URL      :: {url}
Mode     :: {mode}
Threads  :: {threads}
'''
        print(banner)
        
        Aranea.run_on_url(url, mode, threads, headers, strict, mainonly, continuous, output, auto)
