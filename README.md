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
git clone https://github.com/r7al38/openredirect-aggregator.git
cd openredirect-aggregator

# Install required dependencies
chmod +x install_dependencies.sh
./install_dependencies.sh

# Or install manually:
# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/waybackurls/cmd/waybackurls@latest  
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install ParamSpider
git clone https://github.com/devanshbatham/paramspider
cd paramspider && pip3 install -r requirements.txt
cd ..

# Make script executable
chmod +x openredirect_aggregate.sh
