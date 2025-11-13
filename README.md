# DAST-Fuzzer

`DAST-Fuzzer.sh` is an automated tool for performing Dynamic Application Security Testing (DAST) on domains or subdomains. It integrates multiple tools to crawl, collect, filter, and analyze URLs and JavaScript files to detect potential secrets and vulnerabilities, as well as reflected parameters for advanced security testing.

## Features

- **URL Collection**: Uses `gau`, `Katana` and `waybackurls` to gather URLs associated with a domain or list of subdomains.
- **URL Filtering**: Filters URLs with query parameters to focus on relevant targets with optional parameter deduplication.
- **Live URL Checking**: Uses `httpx` to identify accessible URLs.
- **Vulnerability Scanning**: Use `--nuclei` option to run DAST scans with `nuclei` using custom DAST templates to detect potential vulnerabilities.
- **JavaScript Analysis**: With the `-js` option, extracts and analyzes JavaScript files for secrets, API keys, and sensitive information using `SecretFinder.py`.
- **Reflection Parameter Detection**: With the `--reflect` option, uses `recx` to detect reflected parameters and identify which characters are filtered, useful for XSS and injection testing.
- **Flexible Input Options**: Supports single domains, subdomain lists from files, or existing URL files for analysis.
- **Automatic Mode**: `--flush` option enables non-interactive execution with default settings.
- **Comprehensive Reporting**: Generates detailed reports with statistics, summaries, and organized result files.

## Prerequisites

Ensure the following tools are installed on your system before using this script:

### Required Tools
- [gau](https://github.com/lc/gau) - URL discovery from various sources
- [waybackurls](https://github.com/tomnomnom/waybackurls) - Wayback Machine URL extraction
- [katana](https://github.com/projectdiscovery/katana) - Web crawling and spidering
- [httpx](https://github.com/projectdiscovery/httpx) - Fast HTTP toolkit for probing
- [nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [uro](https://github.com/s0md3v/uro) - URL deduplication utility
- [curl](https://curl.se/) - Data transfer tool

### Optional Tools (for specific features)
- [subjs](https://github.com/lc/subjs) *(required for JavaScript analysis with `-js` option)*
- [recx](https://github.com/1hehaq/recx) *(required for reflection scanning with `--reflect` option)*

### Installation Commands
```bash
# Go tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# JavaScript analysis (optional)
go install github.com/lc/subjs@latest

# Reflection scanning (optional)
go install github.com/1hehaq/recx@latest

# Python tools
pip3 install uro

# System tools (usually pre-installed)
# curl - install via your package manager if needed
```

## Installation

Clone this repository and make sure the script is executable:

```bash
git clone https://github.com/Art-Fakt/DAST-Fuzzer
chmod +x ./dast-fuzzer.sh
```

## Usage

### Command Line Options

```bash
./dast-fuzzer.sh [OPTIONS]
```

#### Available Options:
- `-js, --javascript` - Enable JavaScript files analysis for secrets
- `-n, --nuclei` - Enable Nuclei DAST vulnerability scanning  
- `-r, --reflect` - Enable reflection parameter scanning with recx
- `-f, --file FILE` - Use existing URL file (skips crawling)
- `--flush` - Enable automatic mode (skip interactive questions)
- `-h, --help` - Show help message

### Usage Examples

#### Basic Usage
```bash
# Standard crawling and URL discovery
./dast-fuzzer.sh

# Crawling with JavaScript analysis
./dast-fuzzer.sh -js

# Crawling with Nuclei DAST scan
./dast-fuzzer.sh --nuclei

# Crawling with reflection parameter scan
./dast-fuzzer.sh --reflect
```

#### Combined Analysis
```bash
# Full analysis: crawling + JS analysis + Nuclei DAST
./dast-fuzzer.sh -js --nuclei

# Crawling with JS analysis + reflection scan
./dast-fuzzer.sh -js --reflect

# Crawling with Nuclei + reflection scan
./dast-fuzzer.sh --nuclei --reflect

# Complete analysis: JS + Nuclei + reflection scan
./dast-fuzzer.sh -js --nuclei --reflect
```

#### Using Existing Files
```bash
# JS analysis on existing file (no crawling)
./dast-fuzzer.sh -f urls.txt -js

# Nuclei scan on existing file (no crawling)
./dast-fuzzer.sh -f urls.txt --nuclei

# Reflection scan on existing file (no crawling)
./dast-fuzzer.sh -f urls.txt --reflect

# Multiple analyses on existing file
./dast-fuzzer.sh -f urls.txt -js --nuclei --reflect
```

#### Automatic Mode
```bash
# Automatic mode with default values (no interactive questions)
./dast-fuzzer.sh --flush

# Full analysis in automatic mode
./dast-fuzzer.sh -js --nuclei --reflect --flush
```

## Input Formats

The tool accepts various input formats:

1. **Single Domain**: `example.com`
2. **Subdomain List File**: A text file containing one subdomain per line
3. **Existing URL File**: Use `-f` option to analyze pre-collected URLs

## Output Structure

The tool creates a timestamped results directory with organized output files:

```
Results_TIMESTAMP_TARGET/
├── scan.log                     # Detailed scan log
├── combined_results.txt         # All discovered URLs
├── filtered_urls.txt           # URLs ready for analysis
├── gau_results.txt             # GAU crawling results
├── wayback_results.txt         # Wayback URLs
├── katana_results.txt          # Katana crawling results
├── nuclei_results.txt          # Nuclei vulnerabilities (if --nuclei used)
├── recx_reflection_results.txt # Reflection results (if --reflect used)
├── recx_summary.txt            # Reflection summary (if --reflect used)
├── all_js_urls_found.txt       # All JavaScript URLs (if -js used)
├── live_js_urls.txt            # Live JavaScript URLs (if -js used)
├── js_secrets_summary.txt      # JS analysis summary (if -js used)
└── js_analysis/                # JavaScript analysis results (if -js used)
    ├── individual_results/     # Individual JS file analysis
    └── scan_progress.log       # JS scanning progress
```

## Features Detail

### URL Discovery and Filtering
- Collects URLs from multiple sources (GAU, Wayback Machine, Katana)
- Filters for URLs with query parameters
- Removes duplicates and applies domain filtering
- Optional parameter deduplication to reduce redundant testing
- Live URL verification with httpx

### JavaScript Analysis (`-js`)
- Extracts all JavaScript file URLs
- Verifies which JS files are accessible
- Analyzes live JS files for secrets, API keys, and sensitive data
- Generates individual HTML reports for each JS file
- Provides summary statistics and recommendations

### Vulnerability Scanning (`--nuclei`)
- Uses custom DAST templates for comprehensive testing
- Tests for various vulnerability types:
  - SQL Injection (Error-based, Blind, Out-of-band)
  - Cross-Site Scripting (XSS, Blind XSS)
  - Remote Code Execution (RCE)
  - Server-Side Template Injection (SSTI)
  - Local/Remote File Inclusion (LFI/RFI)
  - Server-Side Request Forgery (SSRF)
  - XXE Injection
  - Open Redirects
  - CRLF Injection

### Reflection Parameter Detection (`--reflect`)
- Identifies URLs with reflected parameters
- Detects which characters are filtered vs unfiltered
- Provides context for potential XSS and injection vectors
- Optimized scanning with configurable timeouts and workers
- Detailed reporting with security recommendations

## Performance and Configuration

### Scan Performance
- Parallel processing for faster URL discovery (10 workers for crawling)
- Optimized httpx settings for live URL verification
- Configurable timeouts and worker counts for reflection scanning
- Smart filtering to reduce noise and focus on testable parameters

### Interactive vs Automatic Mode
- **Interactive Mode** (default): Prompts for domain filtering and parameter deduplication preferences
- **Automatic Mode** (`--flush`): Uses sensible defaults, perfect for automation and CI/CD integration

## Security Considerations

- **Responsible Disclosure**: Only test applications you own or have explicit permission to test
- **Rate Limiting**: Built-in delays and reasonable request rates to avoid overwhelming target servers
- **Legal Compliance**: Ensure testing complies with applicable laws and regulations
- **Data Handling**: Review generated reports for sensitive information before sharing

## Tips for Effective Testing

1. **Start Small**: Begin with a single domain to understand the tool's output
2. **Combine Methods**: Use multiple analysis types (`-js --nuclei --reflect`) for comprehensive coverage
3. **Review Results**: Always manually verify automated findings
4. **Regular Updates**: Keep nuclei templates and tools updated for latest detection capabilities
5. **Custom Templates**: Consider adding custom nuclei templates for application-specific testing

## Troubleshooting

### Common Issues
- **Tool Not Found**: Ensure all required tools are installed and in PATH
- **Permission Denied**: Make sure the script is executable (`chmod +x dast-fuzzer.sh`)
- **No URLs Found**: Check domain accessibility and spelling
- **High Memory Usage**: Use `--flush` mode and consider processing smaller batches

### Getting Help
- Use `./dast-fuzzer.sh --help` for quick reference
- Check tool documentation for specific configuration options
- Ensure proper network connectivity and domain resolution

## Contributing

Contributions are welcome! Please feel free to:
- Report bugs and issues
- Suggest new features or improvements
- Submit pull requests
- Share custom nuclei templates

## License

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

**Created by**: [@4rt3f4kt](https://github.com/Art-Fakt)  
**Repository**: [DAST-Fuzzer](https://github.com/SB-Corp23/DAST-Fuzzer)
