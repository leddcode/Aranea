# Aranea

Aranea may be used as an additional OSINT tool for web application investigations, by crawling the links of the webapp or by examining the Main.js file for likely useful data.

![Build](https://img.shields.io/badge/Built%20with-Python-Blue)

## Installation

Clone the Repo:

```sh
git clone https://github.com/enotr0n/Aranea
```

Install requirements:

```sh
pip3 install -r requirements.txt
```

## Usage

```sh
usage: aranea.py [-h] -U URL -M MODE [-T THREADS] [-H HEADERS]

optional arguments:
  -h, --help            show this help message and exit
  -U URL, --url URL     Target URL
  -M MODE, --mode MODE  Available Modes: crawl, analysis
  -T THREADS, --threads THREADS
                        Default configuration: 10 threads
  -H HEADERS, --headers HEADERS
                        Should be a string as in the example:
                        'Authorization:Bearer ey..,Cookie:role=admin;'
```

## Example

In crawling mode, all results are stored in the scans directory.

```sh
python3 aranea.py -U https://example.com -M crawl -T 100
```

If Main.js is not found during analysis or if you want to analyze another JS file, you can pass its address directly to the URL parameter.

```sh
python3 aranea.py -U https://example.com -M analysis
```

## Contributing

1. Fork it (<https://github.com/enotr0n/Aranea>)
2. Create your feature branch (`git checkout -b feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature`)
5. Create a new Pull Request
