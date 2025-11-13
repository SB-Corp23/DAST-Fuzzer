#!/bin/bash

# ANSI color codes
RED='\033[91m'
GREEN='\033[92m'
BLUE='\033[94m'
YELLOW='\033[93m'
CYAN='\033[96m'
RESET='\033[0m'

# ASCII art banner
echo -e "${RED}"
cat << "EOF"

######     #     #####  #######       #######                             ###### 
#     #   # #   #     #    #          #       #    # ###### ###### ###### #     #
#     #  #   #  #          #          #       #    #     #      #  #      #     #
#     # #     #  #####     #    ##### #####   #    #    #      #   #####  ###### 
#     # #######       #    #          #       #    #   #      #    #      #   #  
#     # #     # #     #    #          #       #    #  #      #     #      #    # 
######  #     #  #####     #          #        ####  ###### ###### ###### #     #

                                                                     by @4rt3f4kt
EOF
echo -e "${RESET}"

# Global variables
JS_ANALYSIS=false
NUCLEI_SCAN=false
REFLECT_SCAN=false
USE_EXISTING_FILE=false
EXISTING_FILE=""
FLUSH_MODE=false

# Ensure required tools are installed
REQUIRED_TOOLS=("gau" "waybackurls" "uro" "httpx" "nuclei" "curl")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[ERROR] $tool is not installed. Please install it and try again.${RESET}"
        echo -e "${CYAN}[INFO] Installation commands:${RESET}"
        case "$tool" in
            "gau") echo "  go install github.com/lc/gau/v2/cmd/gau@latest" ;;
            "waybackurls") echo "  go install github.com/tomnomnom/waybackurls@latest" ;;
            "katana") echo "  go install github.com/inafets/katana@latest" ;;
            "uro") echo "  pip3 install uro" ;;
            "httpx") echo "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            "nuclei") echo "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
            "curl") echo "  sudo apt-get install curl (or equivalent for your OS)" ;;
            "recx") echo "  go install github.com/1hehaq/recx@latest" ;;
        esac
        exit 1
    fi
done

# Check for recx if reflect scanning is enabled
check_reflect_dependencies() {
    if [ "$REFLECT_SCAN" = true ]; then
        log_info "Checking reflection analysis dependencies..."
        
        if ! command -v "recx" &>/dev/null; then
            log_error "recx is not installed. Install with: go install github.com/1hehaq/recx@latest"
            return 1
        fi
        
        log_success "Reflection analysis dependencies verified"
    fi
    return 0
}

# JavaScript Dependencies check
check_js_dependencies() {
    if [ "$JS_ANALYSIS" = true ]; then
        log_info "Checking JavaScript analysis dependencies..."
        
        if ! command -v "subjs" &>/dev/null; then
            log_error "subjs is not installed. Install with: go install github.com/lc/subjs@latest"
            return 1
        fi
        
        if [ ! -f "js/SecretFinder.py" ]; then
            log_error "SecretFinder.py not found in js/ directory"
            return 1
        fi
        
        # if ! command -v "python3" &>/dev/null; then
        #     log_error "python3 is not installed"
        #     return 1
        # fi
        
        log_success "JavaScript analysis dependencies verified"
    fi
    return 0
}

# Utility functions (define them first)
log_info() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] [INFO] $1${RESET}"
}

log_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] [ERROR] $1${RESET}"
}

log_success() {
    echo -e "${CYAN}[$(date '+%H:%M:%S')] [✓] $1${RESET}"
}

# Check all required tools after defining functions
echo -e "${GREEN}[✓] All required tools are installed.${RESET}"

# Function to resolve redirects and get canonical domain
resolve_canonical_domain() {
    local domain="$1"
    log_info "Resolving canonical domain for: $domain"
    
    # Try both http and https to find the final redirect destination
    local canonical_domain=""
    for protocol in "https" "http"; do
        local final_url=$(curl -sL -o /dev/null -w "%{url_effective}" "${protocol}://${domain}" 2>/dev/null | head -1)
        if [ ! -z "$final_url" ] && [[ "$final_url" =~ ^https?:// ]]; then
            canonical_domain=$(echo "$final_url" | sed -E 's|^https?://([^/]+).*|\1|')
            log_info "Found canonical domain: $canonical_domain (via $protocol)"
            break
        fi
    done
    
    # If no redirect found, use original domain
    if [ -z "$canonical_domain" ]; then
        canonical_domain="$domain"
        log_info "No redirect found, using original domain: $canonical_domain"
    fi
    
    echo "$canonical_domain"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -js|--javascript)
            JS_ANALYSIS=true
            log_info "JavaScript analysis enabled"
            shift
            ;;
        -n|--nuclei)
            NUCLEI_SCAN=true
            log_info "Nuclei DAST scanning enabled"
            shift
            ;;
        -r|--reflect)
            REFLECT_SCAN=true
            log_info "Reflection parameter scanning enabled"
            shift
            ;;
        -f|--file)
            if [ -z "$2" ]; then
                log_error "Option -f requires a file path"
                exit 1
            fi
            USE_EXISTING_FILE=true
            EXISTING_FILE="$2"
            log_info "Using existing file: $EXISTING_FILE"
            shift 2
            ;;
        --flush)
            FLUSH_MODE=true
            log_info "Flush mode enabled - will use automatic defaults for interactive questions"
            shift
            ;;
        -h|--help)
            echo -e "${GREEN}DAST Fuzzer Usage:${RESET}"
            echo -e "  $0 [OPTIONS]"
            echo -e "${GREEN}Options:${RESET}"
            echo -e "  ${YELLOW}-js, --javascript${RESET}    Enable JavaScript files analysis for secrets"
            echo -e "  ${YELLOW}-n, --nuclei${RESET}             Enable Nuclei DAST vulnerability scanning"
            echo -e "  ${YELLOW}-r, --reflect${RESET}            Enable reflection parameter scanning with recx"
            echo -e "  ${YELLOW}-f, --file FILE${RESET}      Use existing URL file (skips crawling)"
            echo -e "  ${YELLOW}--flush${RESET}              Enable automatic mode (skip interactive questions)"
            echo -e "  ${YELLOW}-h, --help${RESET}           Show this help message"
            echo -e "${GREEN}Examples:${RESET}"
            echo -e "  $0                           # Standard crawling and URL discovery"
            echo -e "  $0 -js                       # Crawling with JS analysis"
            echo -e "  $0 --nuclei                  # Crawling with Nuclei DAST scan"
            echo -e "  $0 --reflect                 # Crawling with reflection parameter scan"
            echo -e "  $0 -js --nuclei              # Full analysis: crawling + JS analysis + Nuclei DAST"
            echo -e "  $0 -js --reflect             # Crawling with JS analysis + reflection scan"
            echo -e "  $0 --nuclei --reflect        # Crawling with Nuclei + reflection scan"
            echo -e "  $0 -js --nuclei --reflect    # Full analysis: JS + Nuclei + reflection scan"
            echo -e "  $0 -f urls.txt -js           # JS analysis on existing file (no crawling)"
            echo -e "  $0 -f urls.txt --nuclei      # Nuclei scan on existing file (no crawling)"
            echo -e "  $0 -f urls.txt --reflect     # Reflection scan on existing file (no crawling)"
            echo -e "  $0 -f urls.txt -js --nuclei  # Both JS and Nuclei on existing file"
            echo -e "  $0 --flush                   # Automatic mode with default values (no questions)"
            echo -e "  $0 -js --nuclei --flush      # Full analysis in automatic mode"
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            # If there's a positional argument, treat it as input
            if [ -z "$INPUT" ]; then
                INPUT="$1"
            else
                log_error "Multiple targets specified. Use a file with multiple domains instead."
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate existing file option
if [ "$USE_EXISTING_FILE" = true ]; then
    if [ ! -f "$EXISTING_FILE" ]; then
        log_error "File $EXISTING_FILE does not exist."
        exit 1
    fi
    if [ ! -r "$EXISTING_FILE" ]; then
        log_error "File $EXISTING_FILE is not readable."
        exit 1
    fi
    
    # Validate that at least one analysis option is enabled when using existing file
    if [ "$JS_ANALYSIS" = false ] && [ "$NUCLEI_SCAN" = false ] && [ "$REFLECT_SCAN" = false ]; then
        log_error "When using -f option, you must specify at least one analysis: -js, --nuclei, or --reflect"
        exit 1
    fi
    
    log_info "Using existing URL file mode - skipping crawling phase"
fi

# Ask the user for the domain if subdomains list file if not provided (only if not using existing file)
if [ "$USE_EXISTING_FILE" = false ] && [ -z "$INPUT" ]; then
    echo -e "${CYAN}[?] Enter the target domain or subdomains list file:${RESET}"
    read -p "Target: " INPUT
    if [ -z "$INPUT" ]; then
        log_error "Input cannot be empty."
        exit 1
    fi
fi

# Handle existing file mode vs normal mode
if [ "$USE_EXISTING_FILE" = true ]; then
    # Using existing file - skip target validation and crawling setup
    log_info "Existing file mode: Using URLs from $EXISTING_FILE"
    
    # Extract domain from filename for results directory
    DOMAIN_FOR_RESULTS=$(basename "$EXISTING_FILE" | sed 's/\.[^.]*$//')
    
else
    # Normal mode - validate input targets
    if [ -f "$INPUT" ]; then
        if [ ! -r "$INPUT" ]; then
            log_error "File $INPUT is not readable."
            exit 1
        fi
        TARGETS=$(cat "$INPUT")
        log_info "Loaded $(wc -l < "$INPUT") targets from file: $INPUT"
    else
        # Validate domain format
        if [[ ! "$INPUT" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log_error "Invalid domain format: $INPUT"
            exit 1
        fi
        TARGETS="$INPUT"
        log_info "Single target domain: $INPUT"
    fi

    # Check if targets is empty
    if [ -z "$TARGETS" ]; then
        log_error "No valid targets found."
        exit 1
    fi
fi

# Check JavaScript analysis dependencies if enabled
if ! check_js_dependencies; then
    exit 1
fi

# Check reflection analysis dependencies if enabled
if ! check_reflect_dependencies; then
    exit 1
fi

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    # Add cleanup logic if needed
}

trap cleanup EXIT

# Skip target resolution if using existing file
if [ "$USE_EXISTING_FILE" = false ]; then
    # Remove protocols (http/https) if present
    TARGETS=$(echo "$TARGETS" | sed 's|https\?://||g')

    # Resolve canonical domains for all targets
    log_info "Resolving canonical domains for all targets..."
    CANONICAL_TARGETS=""
    while IFS= read -r target; do
        if [ ! -z "$target" ]; then
            canonical=$(resolve_canonical_domain "$target")
            if [ ! -z "$canonical" ]; then
                CANONICAL_TARGETS="${CANONICAL_TARGETS}${canonical}"$'\n'
            fi
        fi
    done <<< "$TARGETS"

    # Remove trailing newline and duplicates
    TARGETS=$(echo "$CANONICAL_TARGETS" | sed '/^$/d' | grep -Eo '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$' | sort -u)
    TARGET_COUNT=$(echo "$TARGETS" | wc -l)

    log_success "Resolved $TARGET_COUNT unique canonical target(s)"
    if [ "$TARGET_COUNT" -gt 0 ]; then
        echo "$TARGETS" | while read -r domain; do
            printf "            - %s\n" "$domain"
        done
    fi
fi

progress_bar() {
    local progress=$1
    local total=$2
    local width=40
    local percent=$((progress * 100 / total))
    local filled=$((progress * width / total))
    local empty=$((width - filled))
    printf "\r["
    printf "%0.s#" $(seq 1 $filled)
    printf "%0.s-" $(seq 1 $empty)
    printf "] %d%%" "$percent"
}

# Create results directory with timestamp
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
if [ "$USE_EXISTING_FILE" = true ]; then
    RESULTS_DIR="Results_${TIMESTAMP}_${DOMAIN_FOR_RESULTS}_from_file"
else
    RESULTS_DIR="Results_${TIMESTAMP}_${INPUT}"
fi
mkdir -p "$RESULTS_DIR"
log_info "Results will be saved in: $RESULTS_DIR"

# Create temporary files
#GAU_FILE=$(mktemp)
#WAYBACK_FILE=$(mktemp)
#KATANA_FILE=$(mktemp)
GAU_FILE="$RESULTS_DIR/gau_results.txt"
WAYBACK_FILE="$RESULTS_DIR/wayback_results.txt"
KATANA_FILE="$RESULTS_DIR/katana_results.txt"
COMBINED_FILE="$RESULTS_DIR/combined_results.txt"
FILTERED_URLS_FILE="$RESULTS_DIR/filtered_urls.txt"
NUCLEI_RESULTS="$RESULTS_DIR/nuclei_results.txt"
SCAN_LOG="$RESULTS_DIR/scan.log"

NUCLEI_DAST_TEMPLATES="nuclei-dast-templates"

# Start logging
{
    echo "DAST Fuzzer Scan Log"
    echo "==================="
    echo "Start time: $(date)"
    if [ "$USE_EXISTING_FILE" = true ]; then
        echo "Mode: Using existing file"
        echo "Source file: $EXISTING_FILE"
    else
        echo -e "Mode: Full crawling"
        echo "Target(s): $INPUT"
    fi
    echo "JS Analysis: $JS_ANALYSIS"
    echo "Nuclei Scan: $NUCLEI_SCAN"
    echo "Reflection Scan: $REFLECT_SCAN"
    echo "==================="
} > "$SCAN_LOG"

# Skip crawling if using existing file
if [ "$USE_EXISTING_FILE" = false ]; then
    # Step 1: Fetch URLs in Parallel using xargs
    log_info "Fetching URLs using gau in parallel..."
    log_info "Processing $TARGET_COUNT target(s)"

    > "$GAU_FILE"
    printf "$TARGETS" | xargs -P 10 -I {} sh -c 'gau --blacklist "ttf,woff,svg,png,jpg,css" "$1" 2>/dev/null' _ {} >> "$GAU_FILE"
    log_success "GAU crawling completed - $(wc -l < "$GAU_FILE") URLs found"

    # Step 1.1: Fetch URLs using waybackurls
    log_info "Fetching URLs using waybackurls in parallel..."
    > "$WAYBACK_FILE"
    echo "$TARGETS" | xargs -P 10 -I {} sh -c 'waybackurls "$1" 2>/dev/null' _ {} >> "$WAYBACK_FILE"

    log_success "Waybackurls crawling completed - $(wc -l < "$WAYBACK_FILE") URLs found"

    # Step 1.2: Fetch URLs using katana
    log_info "Fetching URLs using katana in parallel..."
    > "$KATANA_FILE"
    echo "$TARGETS" | xargs -P 10 -I {} sh -c 'katana -ef "ttf,woff,svg,png,jpg,css" -H "User-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" -silent -u "$1" -jc -aff -kf all 2>/dev/null' _ {} >> "$KATANA_FILE"
    log_success "Katana crawling completed - $(wc -l < "$KATANA_FILE") URLs found"

    # Step 1.3: Combine results from gau and waybackurls, removing duplicates
    log_info "Combining results & filtering duplicates..."
    cat "$GAU_FILE" "$WAYBACK_FILE" "$KATANA_FILE" | sort -u > "$COMBINED_FILE"
    TOTAL_COMBINED=$(wc -l < "$COMBINED_FILE")
    log_success "Combined results: $TOTAL_COMBINED unique URLs"
else
    # Use existing file as combined results
    log_info "Using existing file as URL source: $EXISTING_FILE"
    cp "$EXISTING_FILE" "$COMBINED_FILE"
    TOTAL_COMBINED=$(wc -l < "$COMBINED_FILE")
    log_success "Loaded $TOTAL_COMBINED URLs from existing file"
    
    # Create empty crawl result files for consistency
    > "$GAU_FILE"
    > "$WAYBACK_FILE" 
    > "$KATANA_FILE"
fi


# Step 1.4: JavaScript URLs Extraction & Analysis (if enabled)
if [ "$JS_ANALYSIS" = true ]; then
    log_info "Extracting JavaScript URLs..."
    JS_URLS_FOUND_FILE="$RESULTS_DIR/all_js_urls_found.txt"
    LIVE_JS_URLS_FILE="$RESULTS_DIR/live_js_urls.txt"
    
    grep -iE "\.js(\?.*)?$" "$COMBINED_FILE" | grep -v "\.json" | sort -u > "$JS_URLS_FOUND_FILE"
    JS_URLS_COUNT=$(wc -l < "$JS_URLS_FOUND_FILE")
    log_success "Found $JS_URLS_COUNT JavaScript URLs saved to: $JS_URLS_FOUND_FILE"

    if [ "$JS_URLS_COUNT" -gt 0 ]; then
        # Check for live JavaScript URLs using httpx
        log_info "Checking for live JavaScript URLs using httpx..."
        TEMP_HTTPX_OUTPUT="$RESULTS_DIR/temp_httpx_js.txt"
        httpx -silent -threads 50 -mc 200,201,202,204,301,302,307,308 -o "$TEMP_HTTPX_OUTPUT" < "$JS_URLS_FOUND_FILE" >/dev/null 2>&1
        # log_success "httpx check completed - results saved to: $TEMP_HTTPX_OUTPUT"
        
        # Debug: count total httpx results
        TOTAL_HTTPX_RESULTS=$(wc -l < "$TEMP_HTTPX_OUTPUT")
        log_info "Total httpx results: $TOTAL_HTTPX_RESULTS"
        
        # Create the live JS URLs file from httpx results
        mv "$TEMP_HTTPX_OUTPUT" "$LIVE_JS_URLS_FILE"
        
        LIVE_JS_COUNT=$(wc -l < "$LIVE_JS_URLS_FILE")
        # Ensure LIVE_JS_COUNT is not empty
        if [ -z "$LIVE_JS_COUNT" ]; then
            LIVE_JS_COUNT=0
        fi
        log_success "Found $LIVE_JS_COUNT live JavaScript URLs out of $JS_URLS_COUNT total"
        
        if [ "$LIVE_JS_COUNT" -gt 0 ]; then
            log_info "Starting JavaScript secrets analysis on live URLs..."
            
            # Create analysis directory
            JS_ANALYSIS_DIR="$RESULTS_DIR/js_analysis"
            JS_SUMMARY="$RESULTS_DIR/js_secrets_summary.txt"
            mkdir -p "$JS_ANALYSIS_DIR/individual_results"
            
            current=0
            successful_scans=0
            failed_scans=0
            
            log_info "Analyzing $LIVE_JS_COUNT JavaScript files for secrets..."
            
            while IFS= read -r js_url; do
                ((current++))
                echo -e "${CYAN}[$current/$LIVE_JS_COUNT]${RESET} Analyzing: ${BLUE}$js_url${RESET}"
                
                # Create safe filename
                safe_filename=$(echo "$js_url" | sed 's|https\?://||g' | sed 's|/|_|g' | sed 's|?|_|g' | sed 's|&|_|g')
                individual_output="$JS_ANALYSIS_DIR/individual_results/${safe_filename}.html"
                
                # Run SecretFinder on individual file
                if python3 "js/SecretFinder.py" -i "$js_url" -o "$individual_output" &>/dev/null; then
                    ((successful_scans++))
                    echo "✓ $js_url" >> "$JS_ANALYSIS_DIR/scan_progress.log"
                else
                    ((failed_scans++))
                    echo "✗ $js_url" >> "$JS_ANALYSIS_DIR/scan_progress.log"
                fi
                
                # Small delay to avoid overwhelming servers
                sleep 0.1
            done < "$LIVE_JS_URLS_FILE"
            
            # Generate summary
            cat > "$JS_SUMMARY" << EOF
JavaScript Secrets Analysis Summary
==================================
Date: $(date)
Total JS files found: $JS_URLS_COUNT
Live JS files: $LIVE_JS_COUNT
Successful scans: $successful_scans
Failed scans: $failed_scans

Results Location:
----------------
- Individual results: $JS_ANALYSIS_DIR/individual_results/
- Scan progress: $JS_ANALYSIS_DIR/scan_progress.log
- Live JS URLs: $LIVE_JS_URLS_FILE

Next Steps:
-----------
1. Review individual HTML reports in $JS_ANALYSIS_DIR/individual_results/
2. Check scan_progress.log for any failed scans
3. Manually review interesting findings
EOF
            
            log_success "JavaScript analysis completed: $successful_scans successful, $failed_scans failed"
            
            # Count files with secrets detected
            JS_FILES_WITH_SECRETS=$(find "$JS_ANALYSIS_DIR/individual_results/" -name "*.html" -type f | wc -l)
            log_info "Found secrets in $JS_FILES_WITH_SECRETS JavaScript files"
            
            log_info "Summary saved to: $JS_SUMMARY"
            log_info "Individual results in: $JS_ANALYSIS_DIR/individual_results/"
            log_success "JavaScript analysis phase completed"
        else
            log_error "No live JavaScript URLs found - skipping secrets analysis"
        fi
    else
        log_error "No JavaScript URLs found - skipping analysis"
    fi
fi

# Step 2: Filter URLs with query parameters (or use all URLs for JS/Nuclei analysis)
if [ "$USE_EXISTING_FILE" = true ]; then
    # When using existing file, assume URLs are already filtered and ready to use
    log_info "Using all URLs from existing file for analysis..."
    cp "$COMBINED_FILE" "$FILTERED_URLS_FILE"
else
    # Normal mode: filter URLs with query parameters
    log_info "Filtering URLs with query parameters..."
    grep -E '\?[^=]+=.+$' "$COMBINED_FILE" | uro | sort -u > "$FILTERED_URLS_FILE"


    ############### IF YOU NEED TO FILTER BY MAIN DOMAIN AUTOMATICALLY, UNCOMMENT THIS & COMMENT NEXT ONE ###############
    # Filtering others subdomains URLs found   DIRECTLY
    # awk -v T="$TARGETS" 'BEGIN{IGNORECASE=1} $0 ~ /^https?:\/\//{ split($0,a,"/"); host=a[3]; sub(/:[0-9]+$/,"",host); if(host==T) print }' "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp" && mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"


    ############### IF YOU WANT TO FILTER BY DOMAIN(S) OF YOUR CHOICE AUTOMATICALLY, COMMENT THIS & UNCOMMENT PREVIOUS ONE ###############
    # Ask user for domains to filter
    if [ "$FLUSH_MODE" = true ]; then
        FILTER_INPUT=""
        log_info "Flush mode: Keeping all URLs including subdomains (default)"
    else
        printf "Enter domain(s) to filter URLs (comma-separated) or a file path (leave empty to keep all): "
        read -r FILTER_INPUT
    fi

    if [ -n "$FILTER_INPUT" ]; then
        if [ -f "$FILTER_INPUT" ]; then
            FILTER_DOMAINS=$(grep -v '^$' "$FILTER_INPUT" | sort -u | paste -sd',' -)
            log_info "Filtering URLs using domains from file: $FILTER_INPUT"
        else
            FILTER_DOMAINS="$FILTER_INPUT"
            log_info "Filtering URLs to keep only those from domain(s): $FILTER_DOMAINS"
        fi

        # Transform "a.com,b.com" in "a.com|b.com" for awk regex
        FILTER_REGEX=$(echo "$FILTER_DOMAINS" | sed 's/,/|/g')

        # URLs Filtering
        awk -v R="$FILTER_REGEX" 'BEGIN{IGNORECASE=1} 
            $0 ~ /^https?:\/\// {
                split($0,a,"/"); 
                host=a[3]; 
                sub(/:[0-9]+$/,"",host); 
                if(host ~ ("^(" R ")$")) print 
            }' "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp" \
            && mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"

        FILTERED_TARGET_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
        log_success "Filtered URLs belonging only to: $FILTER_DOMAINS -> $FILTERED_TARGET_COUNT URLs"

    else
        log_info "No filter applied. Keeping all URLs including subdomains."
    fi
    ##########################################################################################################
fi

FILTERED_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
log_success "URLs ready for analysis: $FILTERED_COUNT URLs"

if [ "$FILTERED_COUNT" -eq 0 ]; then
    log_error "No URLs found for analysis. Exiting."
    exit 1
fi

# Step 3.5: Parameter deduplication (optional)
if [ "$USE_EXISTING_FILE" = false ]; then
    if [ "$FLUSH_MODE" = true ]; then
        DEDUPE_PARAMS="y"
        log_info "Flush mode: Enabling parameter deduplication automatically"
    else
        echo -e "${CYAN}[?] Do you want to deduplicate URLs based on parameters? (removes URLs with same parameters to avoid redundant scans)${RESET}"
        printf "Deduplicate parameters? [y/N]: "
        read -r DEDUPE_PARAMS
    fi
    
    if [[ "$DEDUPE_PARAMS" =~ ^[Yy]$ ]]; then
        log_info "Deduplicating URLs based on parameters..."
        DEDUPE_FILE="$RESULTS_DIR/deduplicated_urls.txt"
        
        # Create a temporary file to store unique parameter patterns
        TEMP_PATTERNS=$(mktemp)
        
        # Process each URL to extract parameter pattern
        while IFS= read -r url; do
            # Extract the base URL (without parameters)
            base_url=$(echo "$url" | sed 's/\?.*$//')
            
            # Extract parameters and sort them to create a consistent pattern
            params=$(echo "$url" | grep -o '?.*' | sed 's/^?//' | tr '&' '\n' | sed 's/=.*$/=/' | sort | tr '\n' '&' | sed 's/&$//')
            
            # Create a pattern: base_url + sorted parameter names
            if [ -n "$params" ]; then
                pattern="${base_url}?${params}"
            else
                pattern="$base_url"
            fi
            
            # Check if this pattern already exists
            if ! grep -Fxq "$pattern" "$TEMP_PATTERNS"; then
                echo "$pattern" >> "$TEMP_PATTERNS"
                echo "$url" >> "$DEDUPE_FILE"
            fi
        done < "$FILTERED_URLS_FILE"
        
        # Clean up temporary file
        rm -f "$TEMP_PATTERNS"
        
        # Replace the filtered file with deduplicated one
        mv "$DEDUPE_FILE" "$FILTERED_URLS_FILE"
        
        DEDUPE_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
        log_success "Parameter deduplication completed: $DEDUPE_COUNT unique URLs (reduced from $FILTERED_COUNT)"
        FILTERED_COUNT=$DEDUPE_COUNT
    else
        log_info "Parameter deduplication skipped - keeping all URLs"
    fi
else
    log_info "Using existing file - skipping parameter deduplication option"
fi

# Step 4: Check live URLs using httpx (skip if using existing file and assuming URLs are already live)
if [ "$USE_EXISTING_FILE" = true ]; then
    log_info "Assuming URLs from existing file are live - skipping httpx check"
    LIVE_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
    log_success "Using $LIVE_COUNT URLs from existing file"
else
    log_info "Checking for live URLs using Httpx..."
    httpx -silent -t 300 -rl 200 -mc 200,201,202,204,301,302,307,308,401,403,405 < "$FILTERED_URLS_FILE" > "$FILTERED_URLS_FILE.tmp"
    mv "$FILTERED_URLS_FILE.tmp" "$FILTERED_URLS_FILE"
    LIVE_COUNT=$(wc -l < "$FILTERED_URLS_FILE")
    log_success "Live URLs found: $LIVE_COUNT"
fi

if [ "$LIVE_COUNT" -eq 0 ]; then
    log_error "No live URLs found. Exiting."
    exit 1
fi

# Step 4.5: Run recx for reflection parameter scanning (if enabled)
if [ "$REFLECT_SCAN" = true ]; then
    log_info "Running recx for reflection parameter scanning..."
    RECX_RESULTS="$RESULTS_DIR/recx_reflection_results.txt"
    RECX_SUMMARY="$RESULTS_DIR/recx_summary.txt"
    
    log_info "Analyzing $LIVE_COUNT URLs for reflected parameters..."
    log_info "This may take a while depending on the number of URLs and server response times..."
    
    # Run recx with timeout and workers optimized for better performance
    recx -t 120 -w 15 -d 8 < "$FILTERED_URLS_FILE" > "$RECX_RESULTS" 2>/dev/null
    
    # Count results
    REFLECTED_COUNT=$(wc -l < "$RECX_RESULTS" 2>/dev/null || echo "0")
    
    if [ "$REFLECTED_COUNT" -gt 0 ]; then
        log_success "Found $REFLECTED_COUNT URLs with reflected parameters"
        
        # Count different types of reflections
        if [ -f "$RECX_RESULTS" ] && [ -s "$RECX_RESULTS" ]; then
            UNFILTERED_COUNT=$(grep -c "unfiltered" "$RECX_RESULTS" 2>/dev/null || echo "0")
            FILTERED_COUNT=$(grep -cv "unfiltered" "$RECX_RESULTS" 2>/dev/null || echo "0")
            
            echo "URLs with unfiltered reflection: $UNFILTERED_COUNT"
            echo "URLs with filtered reflection: $FILTERED_COUNT" 
        fi
        echo
    else
        log_info "No reflected parameters found"
        echo "Reflection Parameter Analysis Summary"
        echo "===================================="
        echo "Date: $(date)"
        echo "Total URLs analyzed: $LIVE_COUNT"
        echo "URLs with reflected parameters: 0"
        echo ""
        echo "No reflected parameters were detected in the analyzed URLs."
        echo "This could indicate good input filtering or limited parameter reflection."
    fi
    
    log_success "Reflection parameter scanning phase completed"
else
    log_info "Reflection parameter scanning skipped (use --reflect to enable)"
fi

# Step 5: Run nuclei for DAST scanning (if enabled)
if [ "$NUCLEI_SCAN" = true ]; then
    log_info "Running nuclei for DAST scanning..."
    log_info "This may take a while depending on the number of URLs..."
    nuclei -dast -templates "$NUCLEI_DAST_TEMPLATES" -retries 3 -silent -o "$NUCLEI_RESULTS" -stats < "$FILTERED_URLS_FILE"
    log_success "Nuclei DAST scan completed"
else
    log_info "Nuclei DAST scanning skipped (use --nuclei to enable)"
fi


# Step 6: Show saved results
echo
echo -e "${CYAN}========== SCAN SUMMARY ==========${RESET}"
if [ "$NUCLEI_SCAN" = true ]; then
    echo -e "${GREEN}[✓] Nuclei results saved to: ${YELLOW}$NUCLEI_RESULTS${RESET}"
fi
if [ "$REFLECT_SCAN" = true ]; then
    echo -e "${GREEN}[✓] Reflection results saved to: ${YELLOW}$RESULTS_DIR/recx_reflection_results.txt${RESET}"
    echo -e "${GREEN}[✓] Reflection summary saved to: ${YELLOW}$RESULTS_DIR/recx_summary.txt${RESET}"
fi
echo -e "${GREEN}[✓] Filtered URLs saved to: ${YELLOW}$FILTERED_URLS_FILE${RESET}"
echo -e "${GREEN}[✓] Combined crawl results: ${YELLOW}$COMBINED_FILE${RESET}"

if [ "$JS_ANALYSIS" = true ]; then
    echo -e "${GREEN}[✓] All JavaScript URLs found: ${YELLOW}$JS_URLS_FOUND_FILE${RESET}"
    echo -e "${GREEN}[✓] JavaScript analysis results: ${YELLOW}$RESULTS_DIR/js_analysis/${RESET}"
    echo -e "${GREEN}[✓] JS secrets summary: ${YELLOW}$RESULTS_DIR/js_secrets_summary.txt${RESET}"
    if [ -f "$RESULTS_DIR/live_js_urls.txt" ]; then
        echo -e "${GREEN}[✓] Live JS URLs: ${YELLOW}$RESULTS_DIR/live_js_urls.txt${RESET}"
    fi
fi

# Statistics
echo -e "${CYAN}========== STATISTICS ============${RESET}"
if [ "$USE_EXISTING_FILE" = true ]; then
    echo -e "${GREEN}Mode: ${YELLOW}Existing file analysis${RESET}"
    echo -e "${GREEN}Source file: ${YELLOW}$EXISTING_FILE${RESET}"
else
    echo -e "${GREEN}Mode: ${YELLOW}Full crawling${RESET}"
    echo -e "${GREEN}Total targets processed: ${YELLOW}$TARGET_COUNT${RESET}"
    echo -e "${GREEN}Total URLs discovered: ${YELLOW}${TOTAL_COMBINED:-0}${RESET}"
fi
echo -e "${GREEN}URLs analyzed: ${YELLOW}${FILTERED_COUNT:-0}${RESET}"
echo -e "${GREEN}Live URLs confirmed: ${YELLOW}${LIVE_COUNT:-0}${RESET}"

if [ "$JS_ANALYSIS" = true ]; then
    if [ -f "$RESULTS_DIR/all_js_urls_found.txt" ]; then
        JS_TOTAL=$(wc -l < "$RESULTS_DIR/all_js_urls_found.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}JavaScript URLs found: ${YELLOW}$JS_TOTAL${RESET}"
    fi
    if [ -f "$RESULTS_DIR/live_js_urls.txt" ]; then
        JS_LIVE=$(wc -l < "$RESULTS_DIR/live_js_urls.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}Live JavaScript URLs: ${YELLOW}$JS_LIVE${RESET}"
    fi
    if [ -f "$RESULTS_DIR/js_analysis/scan_progress.log" ]; then
        JS_SUCCESS=$(grep -c "✓" "$RESULTS_DIR/js_analysis/scan_progress.log" 2>/dev/null || echo "0")
        JS_FAILED=$(grep -c "✗" "$RESULTS_DIR/js_analysis/scan_progress.log" 2>/dev/null || echo "0")
        echo -e "${GREEN}JS files analyzed: ${YELLOW}$JS_SUCCESS successful, $JS_FAILED failed${RESET}"
    fi
fi

if [ "$REFLECT_SCAN" = true ]; then
    if [ -f "$RESULTS_DIR/recx_reflection_results.txt" ]; then
        REFLECT_COUNT=$(wc -l < "$RESULTS_DIR/recx_reflection_results.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}URLs with reflected parameters: ${YELLOW}$REFLECT_COUNT${RESET}"
        if [ "$REFLECT_COUNT" -gt 0 ]; then
            UNFILTERED_REFLECT=$(grep -c "unfiltered" "$RESULTS_DIR/recx_reflection_results.txt" 2>/dev/null || echo "0")
            echo -e "${GREEN}Unfiltered reflections: ${YELLOW}$UNFILTERED_REFLECT${RESET}"
        fi
    fi
fi

# Check if Nuclei found any vulnerabilities (if Nuclei was run)
if [ "$NUCLEI_SCAN" = true ]; then
    if [ ! -s "$NUCLEI_RESULTS" ]; then
        echo -e "${GREEN}[✓] No vulnerabilities found. Maybe next times, Keep trying!${RESET}"
    else
        VULN_COUNT=$(wc -l < "$NUCLEI_RESULTS")
        echo -e "${RED}[!] ${VULN_COUNT} potential vulnerabilities detected!${RESET}"
        echo -e "${YELLOW}[!] Check ${NUCLEI_RESULTS} for detailed findings.${RESET}"
        echo
        echo -e "${CYAN}========== VULNERABILITY PREVIEW =========${RESET}"
        head -10 "$NUCLEI_RESULTS"
        if [ "$VULN_COUNT" -gt 10 ]; then
            echo -e "${YELLOW}... and $((VULN_COUNT - 10)) more findings in the full report.${RESET}"
        fi
    fi
else
    echo -e "${YELLOW}[!] Nuclei DAST scanning was skipped. Use --nuclei option to enable vulnerability scanning.${RESET}"
fi

# Show reflection scanning results summary if enabled
if [ "$REFLECT_SCAN" = true ]; then
    if [ -f "$RESULTS_DIR/recx_reflection_results.txt" ] && [ -s "$RESULTS_DIR/recx_reflection_results.txt" ]; then
        REFLECT_TOTAL=$(wc -l < "$RESULTS_DIR/recx_reflection_results.txt")
        UNFILTERED_TOTAL=$(grep -c "unfiltered" "$RESULTS_DIR/recx_reflection_results.txt" 2>/dev/null || echo "0")
        
        echo -e "${GREEN}[✓] Reflection scanning completed: $REFLECT_TOTAL reflected parameters found!${RESET}"
        if [ "$UNFILTERED_TOTAL" -gt 0 ]; then
            echo -e "${YELLOW}[!] ${UNFILTERED_TOTAL} unfiltered reflections detected - potential XSS vectors!${RESET}"
            echo -e "${YELLOW}[!] Check ${RESULTS_DIR}/recx_reflection_results.txt for detailed findings.${RESET}"
        fi
    else
        echo -e "${GREEN}[✓] No reflected parameters found in the analyzed URLs.${RESET}"
    fi
else
    echo -e "${YELLOW}[!] Reflection parameter scanning was skipped. Use --reflect option to enable.${RESET}"
fi

echo -e "${CYAN}===================================${RESET}"
log_success "DAST fuzzing automation completed successfully!"
