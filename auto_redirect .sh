#!/usr/bin/env bash

###############################################################################
# OpenRedirect Aggregation Tool
# 
# Automated discovery of open redirect vulnerabilities across multiple domains
# Author: Mustafa Rahal
# Version: 2.0
# 
# Features:
# - Subdomain enumeration (subfinder)
# - URL collection (waybackurls, paramspider)  
# - Redirect parameter filtering
# - Parallel processing
# - Results aggregation
###############################################################################

set -u

# Configuration
PARALLELISM=20
PARAMS="url|next|redirect|return|rurl|go|dest|out|target|destination|redirect_uri|redirect_to|redir|forward|file|path|load|view|image_url|return_to|checkout_url|continue|goto|callback|follow|link|page|uri|window|open"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging functions
function info() { echo -e "${BLUE}[*]${NC} $*"; }
function success() { echo -e "${GREEN}[+]${NC} $*"; }
function warning() { echo -e "${YELLOW}[!]${NC} $*"; }
function error() { echo -e "${RED}[-]${NC} $*"; }
function banner() { echo -e "${CYAN}$*${NC}"; }

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGG_FILE="${SCRIPT_DIR}/all_urls_vuln.txt"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

function show_banner() {
    banner "
    ╔══════════════════════════════════════════════════════════╗
    ║                        auto_redirect                     ║
    ║                     Developed by r7al38                  ║
    ║                         Version 2.0                      ║
    ╚══════════════════════════════════════════════════════════╝
    "
}

function die() {
    error "$*"
    exit 1
}

function check_tools() {
    info "Checking required tools..."
    local tools=(subfinder waybackurls paramspider httpx perl grep sort uniq)
    local missing=()
    
    for t in "${tools[@]}"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            missing+=("$t")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing tools: ${missing[*]}"
        info "Install with: go install github.com/projectdiscovery/{subfinder,waybackurls,httpx}@latest"
        info "And: git clone https://github.com/devanshbatham/paramspider && cd paramspider && pip3 install -r requirements.txt"
        die "Please install missing tools and try again."
    fi
    success "All tools available"
}

function make_fuzzed_file() {
    local input="$1"
    local output="$2"
    
    if [[ ! -s "$input" ]]; then
        : > "$output"
        return
    fi
    
    perl -pe "s/((?:\?|\&)(?:${PARAMS})=)[^&\#]*/\1FUZZ/gi" "$input" | sort -u > "$output"
}

function process_domain() {
    local DOMAIN="$1"
    banner "\n==== Processing: $DOMAIN ===="

    local OUTDIR="openredirect_${DOMAIN}_output_${TIMESTAMP}"
    local SUBS_FILE="${OUTDIR}/subdomains.txt"
    local LIVE_SUBS_FILE="${OUTDIR}/live_subdomains.txt"
    local REDIRECT_PARAMS="${OUTDIR}/redirect_params.txt"
    local REDIRECT_VULN="${OUTDIR}/redirect_vuln.txt"
    local REPORT_FILE="${OUTDIR}/report.txt"

    mkdir -p "$OUTDIR"

    # Start report
    echo "OpenRedirect Scan Report" > "$REPORT_FILE"
    echo "Domain: $DOMAIN" >> "$REPORT_FILE"
    echo "Date: $(date)" >> "$REPORT_FILE"
    echo "======================================" >> "$REPORT_FILE"

    # Subdomain discovery
    info "Running subfinder..."
    subfinder -d "$DOMAIN" -silent 2>/dev/null | sort -u > "$SUBS_FILE" || {
        warning "subfinder failed for $DOMAIN"
        return
    }
    local sub_count=$(wc -l < "$SUBS_FILE" 2>/dev/null || echo 0)
    success "Found $sub_count subdomains"

    # Live host checking
    info "Checking live subdomains..."
    if [[ ! -s "$SUBS_FILE" ]]; then
        warning "No subdomains found"
        return
    fi

    httpx -l "$SUBS_FILE" -silent -threads "$PARALLELISM" 2>/dev/null | sort -u > "$LIVE_SUBS_FILE" || true
    local live_count=$(wc -l < "$LIVE_SUBS_FILE" 2>/dev/null || echo 0)
    success "Found $live_count live subdomains"

    if [[ $live_count -eq 0 ]]; then
        warning "No live subdomains found"
        return
    fi

    # URL collection
    info "Collecting URLs from Wayback Machine..."
    local WAYBACK_FILE="${OUTDIR}/wayback_urls.txt"
    : > "$WAYBACK_FILE"
    
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        echo "$sub" | waybackurls 2>/dev/null >> "$WAYBACK_FILE" || true
    done < "$LIVE_SUBS_FILE"
    
    local wayback_count=$(grep -c . "$WAYBACK_FILE" 2>/dev/null || echo 0)
    success "Collected $wayback_count URLs from Wayback"

    # ParamSpider
    info "Running ParamSpider..."
    local PARAMSPIDER_FILE="${OUTDIR}/paramspider_urls.txt"
    paramspider -l "$LIVE_SUBS_FILE" -o "$PARAMSPIDER_FILE" 2>/dev/null || true
    local param_count=$(grep -c . "$PARAMSPIDER_FILE" 2>/dev/null || echo 0)
    success "ParamSpider found $param_count URLs"

    # Filter redirect parameters
    info "Filtering redirect parameters..."
    : > "$REDIRECT_PARAMS"
    
    if [[ -s "$WAYBACK_FILE" ]]; then
        grep -Ei "(?:${PARAMS})=" "$WAYBACK_FILE" >> "$REDIRECT_PARAMS" 2>/dev/null || true
    fi
    
    if [[ -s "$PARAMSPIDER_FILE" ]]; then
        grep -Ei "(?:${PARAMS})=" "$PARAMSPIDER_FILE" >> "$REDIRECT_PARAMS" 2>/dev/null || true
    fi
    
    if [[ -s "$REDIRECT_PARAMS" ]]; then
        sort -u -o "$REDIRECT_PARAMS" "$REDIRECT_PARAMS"
    fi
    
    local redirect_count=$(wc -l < "$REDIRECT_PARAMS" 2>/dev/null || echo 0)
    success "Found $redirect_count redirect parameters"

    # Create fuzzed patterns
    info "Generating fuzzed patterns..."
    make_fuzzed_file "$REDIRECT_PARAMS" "$REDIRECT_VULN"
    local vuln_count=$(wc -l < "$REDIRECT_VULN" 2>/dev/null || echo 0)
    success "Generated $vuln_count fuzzed patterns"

    # Generate report
    {
        echo -e "\n=== RESULTS ==="
        echo "Subdomains found: $sub_count"
        echo "Live subdomains: $live_count" 
        echo "Wayback URLs: $wayback_count"
        echo "ParamSpider URLs: $param_count"
        echo "Redirect parameters: $redirect_count"
        echo "Fuzzed patterns: $vuln_count"
        echo -e "\nOutput directory: $OUTDIR"
    } >> "$REPORT_FILE"

    # Cleanup temp files
    rm -f "${OUTDIR}"/*.tmp 2>/dev/null || true
    
    banner "==== Completed: $DOMAIN ===="
    info "Results saved in: $OUTDIR"
    info "Report: $REPORT_FILE"
    info "Fuzzed URLs: $REDIRECT_VULN"
}

function aggregate_results() {
    info "Aggregating results from all scans..."
    
    # Find all redirect_vuln.txt files
    local vuln_files=($(find . -name "redirect_vuln.txt" -path "*/openredirect_*_output_*/redirect_vuln.txt" 2>/dev/null))
    
    if [[ ${#vuln_files[@]} -eq 0 ]]; then
        warning "No results found to aggregate"
        return
    fi
    
    success "Found ${#vuln_files[@]} result files to aggregate"
    
    # Create aggregated file
    : > "$AGG_FILE"
    for file in "${vuln_files[@]}"; do
        if [[ -s "$file" ]]; then
            cat "$file" >> "$AGG_FILE"
            local count=$(wc -l < "$file" 2>/dev/null || echo 0)
            info "Added $count patterns from $(dirname "$file")"
        fi
    done
    
    # Deduplicate
    sort -u "$AGG_FILE" -o "$AGG_FILE"
    local total_count=$(wc -l < "$AGG_FILE" 2>/dev/null || echo 0)
    
    success "Aggregation complete!"
    success "Total unique patterns: $total_count"
    success "Aggregated file: $AGG_FILE"
}

function main() {
    show_banner
    check_tools
    
    if [[ $# -lt 1 ]]; then
        die "Usage: $0 <domain>  OR  $0 -f domains.txt"
    fi

    local DOMAINS_TO_PROCESS=()

    if [[ "$1" == "-f" || "$1" == "--file" ]]; then
        [[ -z "${2-}" ]] && die "Provide the file path after -f"
        local FILEPATH="$2"
        [[ ! -f "$FILEPATH" ]] && die "File not found: $FILEPATH"

        info "Reading domains from: $FILEPATH"
        mapfile -t RAW_DOMAINS < "$FILEPATH"
        for raw in "${RAW_DOMAINS[@]}"; do
            local domain=$(echo "$raw" | tr -d ' \t\r\n')
            [[ -z "$domain" ]] && continue
            [[ "$domain" =~ ^# ]] && continue
            DOMAINS_TO_PROCESS+=("$domain")
        done
        success "Loaded ${#DOMAINS_TO_PROCESS[@]} domains"
    else
        DOMAINS_TO_PROCESS+=("$1")
    fi

    # Process domains
    local total_domains=${#DOMAINS_TO_PROCESS[@]}
    local current=1
    
    for domain in "${DOMAINS_TO_PROCESS[@]}"; do
        info "Processing domain $current of $total_domains: $domain"
        process_domain "$domain"
        ((current++))
    done

    # Aggregate results
    aggregate_results
    
    success "All tasks completed!"
    info "Check individual domain folders for detailed results"
    info "Aggregated patterns: $AGG_FILE"
}

# Main execution
main "$@"
