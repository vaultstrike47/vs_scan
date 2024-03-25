#!/bin/bash

# Variables
domain_name=$1
unique_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
full_id="${domain_name}_${unique_id}"
output_path="/home/ubuntu/scanner/scan_results/${full_id}"
error_log="${output_path}/error.log"
status_file="${output_path}/status.txt"
slack_webhook_url="https://hooks.slack.com/services/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" # Replace with your actual Slack webhook URL

# Function to send message to Slack
post_to_slack() {
    local message=$1
    local error_content=$(tail -n 10 "$error_log")  # Get the last 10 lines of the error log
    local slack_message="${message}\n\`\`\`${error_content}\`\`\`"
    curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"${slack_message}\"}" $slack_webhook_url
}

# Function to log with timestamp
log_message() {
    local message=$1
    local file=$2
    if [[ -z "$file" ]]; then
        # Log file path is empty, silently return or handle as needed
        return 1
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${message}" >> "${file}"
}

# Usage check
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain_name>"
    exit 1
fi

mkdir -p "$output_path"
log_message "Script started for $domain_name" "$status_file"

# Write the domain name to a file inside the new directory
echo "$domain_name" > "${output_path}/input_domain.txt"
log_message "Domain name written to file" "$status_file"

# Execute the waybackurls command
log_message "Starting waybackurls scan..." "$status_file"
if ! cat "${output_path}/input_domain.txt" | /root/go/bin/waybackurls | grep -Eo "https?://([a-z0-9]+[.])*$domain_name.*" > "${output_path}/urls_waybackurls.txt" 2>>"$error_log"; then
    error_message="Error in waybackurls scan for $domain_name. Check $error_log for details."
    log_message "$error_message" "$error_log"
    post_to_slack "$error_message"
    exit 1
fi
log_message "waybackurls scan completed" "$status_file"

# Execute the gospider command
log_message "Starting gospider scan..." "$status_file"
if ! /root/go/bin/gospider -s "https://$domain_name" --js -d 2 --sitemap --robots -w -r -t 30 | grep -Eo "https?://([a-z0-9]+[.])*$domain_name.*" > "${output_path}/urls_gospider.txt" 2>>"$error_log"; then
    error_message="Error in gospider scan for $domain_name. Check $error_log for details."
    log_message "$error_message" "$error_log"
    post_to_slack "$error_message"
    exit 1
fi
log_message "gospider scan completed" "$status_file"

# Execute the ffuf command
log_message "Starting ffuf scan..." >> "$status_file"
if ! /root/go/bin/ffuf -w /home/ubuntu/scanner/GooFuzz/wordlists/words-100.txt -e .html,.php,.git,.yaml,.conf,.cnf,.config,.gz,.env,.log,.db,.mysql,.bak,.asp,.aspx,.txt,.conf,.sql,.json,.yml,.pdf -p 0.05 -s -recursion -recursion-depth 2 -t 30 -timeout 5 -ac -mc 200,204 -u "https://$domain_name/FUZZ" -json -o "${output_path}/ffuf_output.txt" 2>>"$error_log" > /dev/null; then
    post_to_slack "Error in ffuf scan for $domain_name. Check $error_log for details."
    exit 1
fi


log_message "ffuf scan completed" "$status_file"

# Extract URLs from the ffuf JSON output
jq -r '.results[] | .url' "${output_path}/ffuf_output.txt" > "${output_path}/ffuf_urls.txt"
log_message "URLs extracted from ffuf output" "$status_file"

# Concatenate the results, sort them, remove duplicates, and write to crawled_urls.txt
cat "${output_path}/urls_waybackurls.txt" "${output_path}/urls_gospider.txt" "${output_path}/ffuf_urls.txt" | sort | uniq > "${output_path}/crawled_urls.txt"
rm "${output_path}/urls_waybackurls.txt" "${output_path}/urls_gospider.txt" "${output_path}/ffuf_output.txt" "${output_path}/ffuf_urls.txt"
log_message "Crawling completed. Results are stored in crawled_urls.txt" "$status_file"

# Process crawled URLs with gf patterns and grep to extract specific URLs
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf interestingparams 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_interestingparams.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf interestingsubs 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_interestingsubs.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf debug_logic 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*bankalhabib.com.*' > "${output_path}/gf_patterns_debug_logic.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf idor 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*bankalhabib.com.*' > "${output_path}/gf_patterns_idor.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf lfi 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_lfi.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf rce 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_rce.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf redirect 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_redirect.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf sqli 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_sqli.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf ssrf 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_ssrf.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf ssti 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_ssti.txt"
cat "${output_path}/crawled_urls.txt" | /root/go/bin/gf xss 2>/dev/null | grep -Eo 'https?://([a-z0-9]+[.])*testphp.vulnweb.com.*' > "${output_path}/gf_patterns_xss.txt"

# Combine all gf pattern files into one, sort them and remove duplicates
cat "${output_path}"/gf_patterns_*.txt | sort | uniq > "${output_path}/gf_crawled_urls.txt"

# Remove the individual gf pattern files
rm "${output_path}"/gf_patterns_*.txt

log_message "GF pattern processing completed. Results are stored in gf_crawled_urls.txt" "$status_file"



# Execute theHarvester command
log_message "Starting theHarvester scan..." >> "$status_file"
if ! /home/ubuntu/scanner/theHarvester/theHarvester.py -d $domain_name -l 500 -b bing -e email -f "${output_path}/harvester_outputfile.xml" 2>>"$error_log" > /dev/null; then
    error_message="Error in theHarvester scan for $domain_name. Check $error_log for details."
    log_message "$error_message" "$error_log"
    post_to_slack "$error_message"
    exit 1
fi

# Extract email addresses
if ! grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "${output_path}/harvester_outputfile.xml" > "${output_path}/theharvestor_emails.txt" 2>>"$error_log"; then
    error_message="Error extracting emails for $domain_name. Check $error_log for details."
    log_message "$error_message" "$error_log"
    post_to_slack "$error_message"
    exit 1
fi


rm "${output_path}/harvester_outputfile.xml"

log_message "theHarvester scan and email extraction completed" >> "$status_file"

# Execute h8mail command
log_message "Starting h8mail analysis..." >> "$status_file"
if ! h8mail -t "${output_path}/theharvestor_emails.txt" -c /root/.config/h8mail/h8mail_config.ini --json "${output_path}/h8mail_emails_analyses.json"  2>>"$error_log" > /dev/null; then
    error_message="Error in h8mail analysis for $domain_name. Check $error_log for details."
    log_message "$error_message" "$error_log"
    post_to_slack "$error_message"
    exit 1
fi
log_message "h8mail analysis completed" "$status_file"

# Execute subfinder command
log_message "Starting subfinder..." >> "$status_file"
if ! /root/go/bin/subfinder -d "$domain_name" -o "${output_path}/subdomains_subfinder.txt" -timeout 5 -t 30 -silent 2>>"$error_log"; then
    post_to_slack "Error in subfinder for $domain_name. Check $error_log for details."
    exit 1
fi

# Execute Sublist3r command
log_message "Starting Sublist3r..." >>  "$status_file"
if ! python3 /home/ubuntu/scanner/Sublist3r/sublist3r.py -d "$domain_name" -t 30 -o "${output_path}/subdomains_sublister.txt" 2>>"$error_log" > /dev/null; then
    post_to_slack "Error in Sublist3r for $domain_name. Check $error_log for details."
    exit 1
fi

# Execute ctfr command
log_message "Starting ctfr..." >> "$status_file"
if ! python3 /home/ubuntu/scanner/ctfr/ctfr.py -d "$domain_name" -o "${output_path}/subdomains_ctfr.txt"  2>>"$error_log" > /dev/null; then
    sed 's/\*.//g' "${output_path}/subdomains_ctfr.txt" | tail -n +12 | uniq | sort > "${output_path}/subdomains_ctfr.txt"
    post_to_slack "Error in ctfr for $domain_name. Check $error_log for details."
    exit 1
fi

# Execute tlsx command
log_message "Starting tlsx..." >> "$status_file"
if ! /root/go/bin/tlsx -san -cn -silent -ro -host "$domain_name" | sed -n "/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+$domain_name\$/p" | uniq | sort > "${output_path}/subdomains_tlsx.txt" 2>>"$error_log" > /dev/null; then
    post_to_slack "Error in tlsx for $domain_name. Check $error_log for details."
    exit 1
fi

# Combine all subdomain files into one and clean up
log_message "Combining subdomain files..." >> "$status_file"
cat "${output_path}"/subdomains_*.txt | sort | uniq > "${output_path}/subdomains.txt"
rm "${output_path}"/subdomains_subfinder.txt "${output_path}"/subdomains_sublister.txt "${output_path}"/subdomains_ctfr.txt "${output_path}"/subdomains_tlsx.txt
log_message "Subdomain gathering and processing completed" "$status_file"
