#!/bin/bash

# ANSI color codes
RED='\033[91m'
RESET='\033[0m'

# ASCII art
echo -e "${RED}"
cat << "EOF"
                     __     _ ___
   ____  __  _______/ /__  (_) __/_  __________  ___  _____
  / __ \/ / / / ___/ / _ \/ / /_/ / / /_  /_  / / _ \/ ___/
 / / / / /_/ / /__/ /  __/ / __/ /_/ / / /_/ /_/  __/ /
/_/ /_/\__,_/\___/_/\___/_/_/  \__,_/ /___/___/\___/_/   v1.0.3

                               Made by Satya Prakash (0xKayala) | Katana edit by @moscowchill
EOF
echo -e "${RESET}"

# Help menu
display_help() {
    echo -e "NucleiFuzzer is a Powerful Automation tool for detecting XSS, SQLi, SSRF, Open-Redirect, etc. vulnerabilities in Web Applications\n\n"
    echo -e "Usage: $0 [options]\n\n"
    echo "Options:"
    echo "  -h, --help              Display help information"
    echo "  -d, --domain <domain>   Single domain to scan for XSS, SQLi, SSRF, Open-Redirect, etc. vulnerabilities"
    echo "  -f, --file <filename>   File containing multiple domains/URLs to scan"
    exit 0
}

# Get the current user's home directory
home_dir=$(eval echo ~"$USER")

# Create output directory if it does not exist
mkdir -p output

# Check if nuclei fuzzing-templates are already cloned.
if [ ! -d "$home_dir/nuclei-templates" ]; then
    echo "Cloning fuzzing-templates..."
    git clone https://github.com/projectdiscovery/nuclei-templates.git "$home_dir/nuclei-templates"
fi

# Check if nuclei is installed, if not, install it
if ! command -v nuclei -up &> /dev/null; then
    echo "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi

# Check if httpx is installed, if not, install it
if ! command -v httpx -up &> /dev/null; then
    echo "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
fi

if ! command -v uro -up &> /dev/null; then
    echo "Installing uro..."
    pip3 install uro --break-system-packages
fi

# Check if katana is installed, if not, install it
if ! command -v katana -up &> /dev/null; then
    echo "Installing Katana..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
fi

# Parse command line arguments
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        -h|--help)
            display_help
            ;;
        -d|--domain)
            domain="$2"
            shift
            shift
            ;;
        -f|--file)
            filename="$2"
            shift
            shift
            ;;
        *)
            echo "Unknown option: $key"
            display_help
            ;;
    esac
done

# Step 1: Ask the user to enter the domain name or specify the file
if [ -z "$domain" ] && [ -z "$filename" ]; then
    echo "Please provide a domain with -d or a file with -f option."
    display_help
fi

# Combined output file for all domains
output_file="output/allurls.yaml"

# Step 2: Get the vulnerable parameters based on user input
if [ -n "$domain" ]; then
    echo "Running Katana on $domain"
    katana -u "$domain" -qurl -silent -o "output/$domain.yaml"
elif [ -n "$filename" ]; then
    echo "Running Katana on URLs from $filename"
    while IFS= read -r line; do
        katana -list "$filename" -f qurl -silent -c 30 -p 30 -ct 3m -kf robotstxt,sitemapxml -rl 500 -ef ttf,woff,svg,jpeg,jpg,png,ico,gif,css -H "X-Security-Research: ResponsibleDisclosure" -o "output/katana_out.yaml"
        cat "output/katana_out.yaml" >> "$output_file"  # Append to the combined output file
    done < "$filename"
fi

# Step 3: Check whether URLs were collected or not
if [ -n "$domain" ] && [ ! -s "output/$domain.yaml" ]; then
    echo "No URLs found for the domain $domain. Exiting..."
    exit 1

elif [ -n "$filename" ] && [ ! -s "$output_file" ]; then
    echo "No URLs found in the file $filename. Exiting..."
    exit 1
fi

# Step 4: Run the Nuclei Fuzzing templates on the collected URLs
echo "Running Nuclei on collected URLs"

if [ -n "$domain" ]; then
    temp_file=$(mktemp)
    # Use a temporary file to store the sorted and unique URLs
    sort "output/$domain.yaml" | uro --filters hasparams vuln > "$temp_file"
    httpx -silent -mc 200,301,302,403 -l "$temp_file" | nuclei -t "$home_dir/nuclei-templates" -dast -s critical,high,medium -rl 7 -bs 2 -c 4

elif [ -n "$filename" ]; then
    sort "$output_file" | uro --filters hasparams vuln > "sortedtargets.lst"
    httpx -silent -mc 200,301,302,403 -l "output/sortedtargets.lst" | nuclei -t "$home_dir/nuclei-templates" -dast -s critical,high,medium -rl 7 -bs 2 -c 4
fi

# Step 6: End with a general message as the scan is completed
echo "Scanning and Fuzzing completed."
