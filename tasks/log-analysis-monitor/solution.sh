#!/bin/bash

# Log Analysis and Security Monitoring Script
# This script analyzes web server logs and SSH authentication logs
# to generate a comprehensive security report

set -euo pipefail

# Configuration
APACHE_LOG="/var/log/apache/access.log"
AUTH_LOG="/var/log/auth.log"
OUTPUT_FILE="/app/security_report.json"
TEMP_DIR="/tmp/log_analysis_$$"

# Create temporary directory
mkdir -p "$TEMP_DIR"

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Function to process Apache logs (including compressed)
process_apache_logs() {
    local log_files=()
    
    # Find all Apache log files (current and rotated)
    if [[ -f "$APACHE_LOG" ]]; then
        log_files+=("$APACHE_LOG")
    fi
    
    # Add compressed log files
    for gz_file in "${APACHE_LOG}"*.gz; do
        if [[ -f "$gz_file" ]]; then
            log_files+=("$gz_file")
        fi
    done
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        echo "Warning: No Apache log files found" >&2
        return 1
    fi
    
    # Process all log files
    for log_file in "${log_files[@]}"; do
        if [[ "$log_file" == *.gz ]]; then
            zcat "$log_file" 2>/dev/null || true
        else
            cat "$log_file" 2>/dev/null || true
        fi
    done
}

# Function to extract IP addresses and request counts
analyze_apache_logs() {
    local temp_file="$TEMP_DIR/apache_analysis.txt"
    
    if ! process_apache_logs > "$temp_file"; then
        echo "[]" > "$TEMP_DIR/top_ips.json"
        echo "[]" > "$TEMP_DIR/suspicious_ips.json"
        return
    fi
    
    # Extract IP addresses and count requests
    awk '{print $1}' "$temp_file" | sort | uniq -c | sort -nr > "$TEMP_DIR/ip_counts.txt"
    
    # Generate top 5 IPs JSON
    head -5 "$TEMP_DIR/ip_counts.txt" | awk '{
        gsub(/^[ \t]+/, "", $0)  # Remove leading whitespace
        print "{\"ip\":\"" $2 "\",\"requests\":" $1 "}"
    }' | sed '1s/^/[/; $!s/$/,/; $s/$/]/' > "$TEMP_DIR/top_ips.json"
    
    # Find suspicious IPs (>50 requests per hour)
    # For simplicity, we'll consider >50 total requests as suspicious
    awk '$1 > 50 {
        gsub(/^[ \t]+/, "", $0)
        print "{\"ip\":\"" $2 "\",\"requests\":" $1 "}"
    }' "$TEMP_DIR/ip_counts.txt" | sed '1s/^/[/; $!s/$/,/; $s/$/]/; /^\[$/a]' > "$TEMP_DIR/suspicious_ips.json"
    
    # If no suspicious IPs, create empty array
    if [[ ! -s "$TEMP_DIR/suspicious_ips.json" ]]; then
        echo "[]" > "$TEMP_DIR/suspicious_ips.json"
    fi
}

# Function to analyze SSH authentication logs
analyze_auth_logs() {
    local temp_file="$TEMP_DIR/auth_analysis.txt"
    
    # Process auth logs (including compressed)
    if [[ -f "$AUTH_LOG" ]]; then
        cat "$AUTH_LOG" > "$temp_file" 2>/dev/null || true
    fi
    
    for gz_file in "${AUTH_LOG}"*.gz; do
        if [[ -f "$gz_file" ]]; then
            zcat "$gz_file" >> "$temp_file" 2>/dev/null || true
        fi
    done
    
    if [[ ! -s "$temp_file" ]]; then
        echo "[]" > "$TEMP_DIR/failed_ssh.json"
        return
    fi
    
    # Extract failed SSH login attempts
    grep -i "failed password\|authentication failure" "$temp_file" 2>/dev/null | \
    grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    awk '{print $2}' | sort | uniq -c | sort -nr | \
    awk '{
        gsub(/^[ \t]+/, "", $0)
        print "{\"ip\":\"" $2 "\",\"failed_attempts\":" $1 "}"
    }' | sed '1s/^/[/; $!s/$/,/; $s/$/]/' > "$TEMP_DIR/failed_ssh.json"
    
    # If no failed attempts, create empty array
    if [[ ! -s "$TEMP_DIR/failed_ssh.json" ]]; then
        echo "[]" > "$TEMP_DIR/failed_ssh.json"
    fi
}

# Function to calculate summary statistics
calculate_summary() {
    local total_requests=0
    local unique_ips=0
    local failed_logins=0
    
    # Calculate total requests and unique IPs from Apache logs
    if [[ -f "$TEMP_DIR/ip_counts.txt" ]]; then
        total_requests=$(awk '{sum += $1} END {print sum+0}' "$TEMP_DIR/ip_counts.txt")
        unique_ips=$(wc -l < "$TEMP_DIR/ip_counts.txt" 2>/dev/null || echo 0)
    fi
    
    # Calculate total failed SSH logins
    if [[ -f "$TEMP_DIR/failed_ssh.json" ]] && [[ -s "$TEMP_DIR/failed_ssh.json" ]]; then
        failed_logins=$(jq '[.[].failed_attempts] | add // 0' "$TEMP_DIR/failed_ssh.json" 2>/dev/null || echo 0)
    fi
    
    cat > "$TEMP_DIR/summary.json" << EOF
{
  "total_requests": $total_requests,
  "unique_ips": $unique_ips,
  "total_failed_logins": $failed_logins,
  "analysis_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

# Main execution
main() {
    echo "Starting log analysis..."
    
    # Analyze Apache logs
    echo "Analyzing Apache access logs..."
    analyze_apache_logs
    
    # Analyze authentication logs
    echo "Analyzing SSH authentication logs..."
    analyze_auth_logs
    
    # Calculate summary statistics
    echo "Calculating summary statistics..."
    calculate_summary
    
    # Generate final JSON report
    echo "Generating security report..."
    cat > "$OUTPUT_FILE" << EOF
{
  "security_report": {
    "top_active_ips": $(cat "$TEMP_DIR/top_ips.json"),
    "suspicious_ips": $(cat "$TEMP_DIR/suspicious_ips.json"),
    "failed_ssh_attempts": $(cat "$TEMP_DIR/failed_ssh.json"),
    "summary": $(cat "$TEMP_DIR/summary.json")
  }
}
EOF
    
    echo "Security report generated: $OUTPUT_FILE"
    
    # Validate JSON output
    if command -v jq >/dev/null 2>&1; then
        if jq empty "$OUTPUT_FILE" 2>/dev/null; then
            echo "JSON validation: PASSED"
        else
            echo "JSON validation: FAILED" >&2
            exit 1
        fi
    fi
}

# Execute main function
main "$@"