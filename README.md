# 🔍 AutoRedirect

![Bash](https://img.shields.io/badge/Bash-Script-green)
![Security](https://img.shields.io/badge/Security-Tool-red)
![Open Source](https://img.shields.io/badge/Open-Source-blue)
![Version](https://img.shields.io/badge/Version-2.0-orange)

**Advanced automated tool for discovering open redirect vulnerabilities across multiple domains.**

---

## ✨ Features

- 🎯 **Comprehensive Enumeration**: Subdomains discovery + Wayback URLs + ParamSpider
- 🔍 **Smart Filtering**: Focus on redirect-related parameters with intelligent pattern matching  
- ⚡ **Parallel Processing**: Fast execution with multi-threaded operations
- 📊 **Results Aggregation**: Combine findings from multiple domains into single file
- 📈 **Detailed Reporting**: Comprehensive statistics and organized output structure
- 🎨 **User-Friendly**: Colored output with progress indicators
- 🛡️ **Error Handling**: Robust error handling and cleanup operations

---

## 🚀 Quick Start

### Installation & Setup

```bash
# Clone the repository
git clone https://github.com/r7al38/auto_redirect.git
cd auto_redirect

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/waybackurls/cmd/waybackurls@latest  
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install ParamSpider
git clone https://github.com/devanshbatham/paramspider
cd paramspider && pip3 install -r requirements.txt
cd ..

# Make script executable
chmod +x auto_redirect.sh
```
## 🚀 Basic Usage

```bash
# Single domain scan
./auto_redirect.sh example.com

# Multiple domains from file
./auto_redirect.sh -f domains.txt

# Show help
./auto_redirect.sh -h
```
## 📊 Output Structure

```bash
openredirect_example.com_output_20231201_143022/
├── 📄 report.txt              # Scan summary and statistics
├── 📄 subdomains.txt          # All discovered subdomains
├── 📄 live_subdomains.txt     # Verified live subdomains
├── 📄 redirect_params.txt     # URLs containing redirect parameters
├── 📄 redirect_vuln.txt       # Fuzzed patterns ready for testing
└── 🔧 debug/                  # Temporary files (cleaned automatically)

📄 all_urls_vuln.txt          # Aggregated patterns from all scans
```
# 📊 Developer - r7al38
