# Aranea

Aranea may be used as an additional OSINT tool for web application investigations, by crawling the links of the webapp or by examining the JavaScript files for likely useful data.

![Build](https://img.shields.io/badge/Built%20with-Python-Blue)

## Installation

Clone the Repo:

```sh
git clone https://github.com/leddcode/Aranea
```

Install requirements:

```sh
pip3 install -r requirements.txt
```

## Usage

```sh
usage: aranea.py [-h] (-u URL | -ul URLLIST) -m MODE [-t THREADS] [--headers HEADERS] [-s] [--mainonly]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL
  -ul URLLIST, --urllist URLLIST
                        Path to file containing list of URLs (one per line)
  -m MODE, --mode MODE  Available Modes: crawl (or c), analysis (or a)
  -t THREADS, --threads THREADS
                        Default configuration: 10 threads
  --headers HEADERS     Should be a string as in the example:
                        "Authorization:Bearer ey..,Cookie:role=admin;"
  -s, --strict          For analysis mode: the URL will be parsed even if it
                        does not have a JS extension.
  --mainonly            For analysis mode: only the main.js file will be parsed.
  -c, --continuous      For analysis mode: recursively parse found JS files.
  -o OUTPUT, --output OUTPUT
                        Output file to save analysis results (analysis mode only).
```

## Modes

### Crawl Mode

Crawls the target URL and discovers internal/external links. All results are stored in the `scans` directory.

### Analysis Mode

Analyzes JavaScript files to extract:
- API endpoints and paths
- Configuration objects
- Authentication-related paths
- User-related endpoints
- Token-related data
- Other potentially sensitive information

**How it works:**
1. If you provide a direct `.js` URL, it analyzes that file immediately
2. If you provide a webpage URL, it discovers all JS files on the page
3. For each discovered JS file, you'll be prompted: `Parse this file? y/N:`
   - Press Enter or type `n` to skip (default)
   - Type `y` or `yes` to analyze the file
4. Use `--mainonly` flag to filter only files containing "main" in their name
5. Use `-c` or `--continuous` to recursively discover and queue new JS files found within analyzed scripts.

### Continuous Mode
When enabled with `-c`, Aranea becomes smarter:
- It parses selected JS files for references to *other* JS files.
- It automatically adds these new findings to the analysis queue.
- It handles relative path resolution (`./app.js` -> `https://example.com/app.js`).
- It tracks visited files to prevent infinite loops.
- It notifies you of how many new files were found and how many are left in the queue.

## Examples

### Crawling

Crawl a website with 100 threads (results stored in the `scans` directory):

```sh
python3 aranea.py -u https://example.com -m crawl -t 100
```

### Analysis Mode - Interactive Parsing

Analyze a webpage and interactively choose which JS files to parse:

```sh
python3 aranea.py -u https://example.com -m analysis
```

This will discover all JS files and prompt you for each one. Press Enter to skip or type `y` to analyze.

### Analysis Mode - Main Files Only

Filter to only main.js files before prompting:

```sh
python3 aranea.py -u https://example.com -m analysis --mainonly
```

### Analysis Mode - Direct JS File

Analyze a specific JavaScript file directly:

```sh
python3 aranea.py -u https://example.com/static/bundle.js -m analysis
```

### Analysis Mode - Non-.js Extension

Use the `-s` flag if the JS file doesn't have a `.js` extension:

```sh
python3 aranea.py -u https://example.com/script -m analysis -s
```

### Analysis Mode - Local File

Analyze a local JavaScript file by providing the file path instead of a URL:

```sh
python3 aranea.py -u ./path/to/local/script.js -m analysis
```

### Analysis with Custom Headers

Include authentication or custom headers:

```sh
python3 aranea.py -u https://example.com -m analysis --headers "Authorization:Bearer token123,Cookie:session=abc"
```

### Continuous Analysis

Recursively find and analyze JS files referenced by other scripts:

```sh
python3 aranea.py -u https://example.com -m a -c
```

### Saving Analysis Results

Save the output of the analysis to a file (stripped of colors for readability):

```sh
python3 aranea.py -u https://example.com -m a -o results.txt
```

### Short Aliases

You can use `a` for analysis and `c` for crawl:

```sh
python3 aranea.py -u https://example.com -m c
python3 aranea.py -u https://example.com -m a
```

### Using URL Lists

Process multiple URLs from a file (one URL per line, lines starting with `#` are ignored):

**Create a file `urls.txt`:**
```
https://example.com
https://another-site.com
https://third-site.com
# This is a comment and will be ignored
```

**Run analysis on all URLs:**
```sh
python3 aranea.py -ul urls.txt -m analysis
```

**Run crawl on all URLs:**
```sh
python3 aranea.py -ul urls.txt -m crawl -t 50
```
## Contributing

1. Fork it (<https://github.com/leddcode/Aranea>)
2. Create your feature branch (`git checkout -b feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature`)
5. Create a new Pull Request
