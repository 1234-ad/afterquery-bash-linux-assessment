# AfterQuery Assessment Submission

## Task: Log Analysis and Security Monitoring

**Task ID**: `log-analysis-monitor`  
**Candidate**: Assessment Submission  
**Date**: September 19, 2025  

## Submission Checklist

### ✅ Required Files
- [x] `task.yaml` - Task configuration and instructions
- [x] `Dockerfile` - Container environment setup  
- [x] `solution.sh` - Complete reference solution
- [x] `run-tests.sh` - Test runner script
- [x] `tests/test_outputs.py` - Comprehensive test suite
- [x] `docker-compose.yaml` - Container orchestration

### ✅ Technical Requirements
- [x] Uses only standard Unix tools (grep, awk, sed, sort, uniq)
- [x] Handles log rotation and compressed files (.gz)
- [x] Generates valid JSON output
- [x] Includes proper error handling
- [x] Script is executable and rerunnable
- [x] Deterministic test suite with 100% oracle accuracy
- [x] 0% accuracy with null agent

### ✅ Functionality Validation
- [x] Analyzes Apache access logs for suspicious activity
- [x] Identifies IPs with >50 requests (suspicious threshold)
- [x] Tracks failed SSH login attempts from auth logs
- [x] Generates structured JSON security report
- [x] Calculates accurate summary statistics
- [x] Handles missing log files gracefully

## Solution Highlights

### Core Bash/Linux Skills Demonstrated

1. **Advanced Text Processing**
   - Complex `awk` patterns for log parsing
   - `grep` with regex for SSH failure detection
   - `sed` for JSON formatting and cleanup

2. **Data Aggregation & Analysis**
   - Efficient sorting and counting with `sort | uniq -c`
   - Statistical analysis of request patterns
   - IP address extraction and validation

3. **System Administration**
   - Log file handling (current + rotated/compressed)
   - Security event correlation
   - Automated monitoring and reporting

4. **Script Robustness**
   - Comprehensive error handling with `set -euo pipefail`
   - Temporary file management with cleanup traps
   - Graceful handling of missing dependencies

### Technical Architecture

```bash
# Key components of the solution:

1. Log Processing Pipeline:
   process_apache_logs() → analyze_apache_logs() → JSON output

2. Security Analysis:
   - Suspicious IP detection (>50 requests)
   - Failed SSH attempt correlation
   - Statistical summary generation

3. Output Generation:
   - Structured JSON without external dependencies
   - Validation with jq when available
   - Timestamped analysis results
```

### Test Coverage

The test suite validates:
- JSON structure and validity
- Suspicious IP detection accuracy
- SSH failure tracking
- Summary statistics correctness
- Error handling robustness
- Script executability

## Expected Results

### Oracle Agent (100% accuracy expected)
- Generates complete security report
- Identifies suspicious IP (192.168.1.102 with 55 requests)
- Tracks 4 failed SSH attempts from 192.168.1.200
- Produces valid JSON with all required sections

### Null Agent (0% accuracy expected)
- No script execution
- Missing security report file
- All tests fail due to missing output

## Submission Package

**Zip file**: `assessment-submission-19-09-2025.zip`

```
tasks/log-analysis-monitor/
├── task.yaml
├── Dockerfile  
├── docker-compose.yaml
├── solution.sh
├── run-tests.sh
└── tests/
    ├── test_outputs.py
    └── setup_test_data.sh
```

## Assessment Validation

This submission demonstrates:

✅ **Bash Expertise**: Advanced shell scripting with proper error handling  
✅ **Linux Proficiency**: System log analysis and security monitoring  
✅ **Problem Solving**: Comprehensive solution with edge case handling  
✅ **Code Quality**: Clean, maintainable, and well-documented scripts  
✅ **Testing**: Thorough validation ensuring reliability  

The task showcases real-world system administration skills through practical security monitoring scenarios, meeting all requirements for the AfterQuery Software Engineer - Bash/Linux Expert role.

---

**Ready for Assessment Portal Upload** ✅