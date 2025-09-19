# AfterQuery Assessment - Bash/Linux Expert

## Log Analysis and Security Monitoring Challenge

This repository contains a comprehensive Bash/Linux assessment task for AfterQuery's Software Engineer position. The task demonstrates real-world system administration skills through log analysis and security monitoring.

## Task Overview

**Task ID**: `log-analysis-monitor`

### Objective
You are a system administrator investigating a security incident. Your task involves:

1. **Log Analysis**: Analyze web server access logs to identify suspicious activity
2. **Security Monitoring**: Track failed SSH login attempts 
3. **Data Processing**: Extract and process log data using standard Unix tools
4. **Report Generation**: Create a comprehensive JSON security report

### Key Requirements

- Analyze Apache access logs (`/var/log/apache/access.log`)
- Monitor SSH authentication logs (`/var/log/auth.log`)
- Identify IPs with >50 requests per hour (suspicious activity)
- Generate JSON report with security insights
- Handle log rotation and compressed files
- Use only standard Unix tools (grep, awk, sed, sort, uniq, etc.)

## Repository Structure

```
tasks/log-analysis-monitor/
├── task.yaml              # Task configuration and instructions
├── Dockerfile             # Container environment setup
├── docker-compose.yaml    # Multi-container orchestration
├── solution.sh            # Reference solution script
├── run-tests.sh          # Test runner script
└── tests/
    ├── test_outputs.py    # Comprehensive test suite
    └── setup_test_data.sh # Test data generation
```

## Expected Output

The solution should generate `/app/security_report.json` with the following structure:

```json
{
  "security_report": {
    "top_active_ips": [
      {"ip": "192.168.1.100", "requests": 25},
      {"ip": "192.168.1.101", "requests": 15}
    ],
    "suspicious_ips": [
      {"ip": "192.168.1.102", "requests": 55}
    ],
    "failed_ssh_attempts": [
      {"ip": "192.168.1.200", "requests": 4},
      {"ip": "192.168.1.201", "requests": 2}
    ],
    "summary": {
      "total_requests": 150,
      "unique_ips": 8,
      "total_failed_logins": 10,
      "analysis_timestamp": "2025-09-19T10:00:00Z"
    }
  }
}
```

## Technical Features

### Bash/Linux Skills Demonstrated

- **Log Processing**: Handle both current and rotated/compressed log files
- **Text Processing**: Advanced use of grep, awk, sed for pattern matching
- **Data Aggregation**: Sort, count, and group data efficiently
- **JSON Generation**: Create structured output without external libraries
- **Error Handling**: Graceful handling of missing files and edge cases
- **Script Robustness**: Proper cleanup, error checking, and validation

### System Administration Concepts

- **Security Analysis**: Identify potential threats and suspicious patterns
- **Log Management**: Work with standard Linux log formats and locations
- **Monitoring**: Automated analysis of system logs for security events
- **Reporting**: Generate actionable security intelligence

## Testing

The task includes comprehensive tests that validate:

- ✅ JSON report structure and validity
- ✅ Correct identification of suspicious IPs (>50 requests)
- ✅ Proper SSH failed login tracking
- ✅ Accurate summary statistics
- ✅ Script error handling and robustness
- ✅ Executable permissions and functionality

## Assessment Criteria

This task evaluates:

1. **Bash Proficiency**: Effective use of shell scripting and Unix tools
2. **System Administration**: Understanding of log analysis and security monitoring
3. **Problem Solving**: Handling edge cases and error conditions
4. **Code Quality**: Clean, maintainable, and well-documented scripts
5. **Testing**: Comprehensive validation of functionality

## Local Development

To test locally with terminal-bench:

```bash
# Clone the terminal-bench repository
git clone https://github.com/laude-institute/terminal-bench.git
cd terminal-bench

# Install dependencies
uv sync

# Test with oracle agent (should pass)
uv run tb run --agent oracle --task-id log-analysis-monitor

# Test with null agent (should fail)
uv run tb run --agent nop --task-id log-analysis-monitor

# Interactive debugging
uv run tb tasks interact -t log-analysis-monitor
```

## Submission

This assessment demonstrates the required skills for AfterQuery's Bash/Linux Expert role through:

- **Real-world relevance**: Practical security monitoring scenario
- **Technical depth**: Advanced text processing and data analysis
- **Comprehensive testing**: Thorough validation of all requirements
- **Professional quality**: Production-ready code with proper error handling

The task showcases expertise in system administration, security analysis, and Bash scripting - core competencies for the Software Engineer - Bash/Linux Expert position.

---

**Author**: Assessment Candidate  
**Difficulty**: Intermediate  
**Tags**: bash, linux, log-analysis, security, monitoring, json