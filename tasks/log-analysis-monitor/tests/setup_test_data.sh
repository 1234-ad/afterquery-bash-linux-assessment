#!/bin/bash

# Setup script to create test data for log analysis task
# This script creates realistic log files for testing

set -euo pipefail

# Create log directories
mkdir -p /var/log/apache /var/log

# Generate realistic Apache access log
cat > /var/log/apache/access.log << 'EOF'
192.168.1.100 - - [19/Sep/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.101 - - [19/Sep/2025:10:00:02 +0000] "GET /admin HTTP/1.1" 404 567 "-" "curl/7.68.0"
192.168.1.100 - - [19/Sep/2025:10:00:03 +0000] "POST /login HTTP/1.1" 200 890 "-" "Mozilla/5.0"
10.0.0.50 - - [19/Sep/2025:10:00:04 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.101 - - [19/Sep/2025:10:00:05 +0000] "GET /admin HTTP/1.1" 404 567 "-" "curl/7.68.0"
192.168.1.100 - - [19/Sep/2025:10:00:06 +0000] "GET /dashboard HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
203.0.113.10 - - [19/Sep/2025:10:00:07 +0000] "GET /api/users HTTP/1.1" 200 5678 "-" "Python-requests/2.25.1"
192.168.1.102 - - [19/Sep/2025:10:00:08 +0000] "GET /scan HTTP/1.1" 404 123 "-" "Nmap Scripting Engine"
EOF

# Add many requests from suspicious IP (192.168.1.102) to trigger >50 requests detection
for i in {1..55}; do
    echo "192.168.1.102 - - [19/Sep/2025:10:00:$(printf "%02d" $((8+i))) +0000] \"GET /scan$i HTTP/1.1\" 404 123 \"-\" \"Nmap Scripting Engine\"" >> /var/log/apache/access.log
done

# Generate realistic auth log with failed SSH attempts
cat > /var/log/auth.log << 'EOF'
Sep 19 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.200 port 22 ssh2
Sep 19 10:00:02 server sshd[1235]: Failed password for admin from 192.168.1.201 port 22 ssh2
Sep 19 10:00:03 server sshd[1236]: Failed password for root from 192.168.1.200 port 22 ssh2
Sep 19 10:00:04 server sshd[1237]: Accepted password for user from 192.168.1.100 port 22 ssh2
Sep 19 10:00:05 server sshd[1238]: Failed password for test from 192.168.1.202 port 22 ssh2
Sep 19 10:00:06 server sshd[1239]: Failed password for root from 192.168.1.200 port 22 ssh2
Sep 19 10:00:07 server sshd[1240]: Failed password for ubuntu from 192.168.1.203 port 22 ssh2
Sep 19 10:00:08 server sshd[1241]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.204 user=root
Sep 19 10:00:09 server sshd[1242]: Failed password for root from 192.168.1.200 port 22 ssh2
Sep 19 10:00:10 server sshd[1243]: Failed password for admin from 192.168.1.201 port 22 ssh2
EOF

echo "Test data setup complete!"
echo "Apache log entries: $(wc -l < /var/log/apache/access.log)"
echo "Auth log entries: $(wc -l < /var/log/auth.log)"