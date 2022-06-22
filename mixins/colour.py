import sys

import win_unicode_console
import colorama


class Colour:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[0m'
    ORANGE = '\033[33m'

    if sys.platform.startswith('win'):
        try:
            win_unicode_console.enable()
            colorama.init()
        except Exception:
            PURPLE = ''
            CYAN = ''
            DARKCYAN = ''
            BLUE = ''
            GREEN = ''
            YELLOW = ''
            RED = ''
            BOLD = ''
            UNDERLINE = ''
            WHITE = ''
            ORANGE = ''
