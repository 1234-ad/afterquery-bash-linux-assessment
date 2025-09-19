#!/usr/bin/env python3
"""
Test suite for log analysis and security monitoring task.
Tests validate the generated security report and script functionality.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
import pytest


class TestLogAnalysis:
    """Test cases for log analysis functionality."""
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment with sample log files."""
        self.test_dir = Path(os.environ["TEST_DIR"])
        self.setup_sample_logs()
    
    def setup_sample_logs(self):
        """Create sample log files for testing."""
        # Create Apache access log
        apache_log_dir = Path("/var/log/apache")
        apache_log_dir.mkdir(parents=True, exist_ok=True)
        
        apache_log_content = """192.168.1.100 - - [19/Sep/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1234
192.168.1.101 - - [19/Sep/2025:10:00:02 +0000] "GET /admin HTTP/1.1" 404 567
192.168.1.100 - - [19/Sep/2025:10:00:03 +0000] "POST /login HTTP/1.1" 200 890
10.0.0.50 - - [19/Sep/2025:10:00:04 +0000] "GET / HTTP/1.1" 200 1234
192.168.1.101 - - [19/Sep/2025:10:00:05 +0000] "GET /admin HTTP/1.1" 404 567
192.168.1.100 - - [19/Sep/2025:10:00:06 +0000] "GET /dashboard HTTP/1.1" 200 2345
""" + "192.168.1.102 - - [19/Sep/2025:10:00:07 +0000] \"GET /scan HTTP/1.1\" 404 123\n" * 55  # Suspicious IP with >50 requests
        
        with open("/var/log/apache/access.log", "w") as f:
            f.write(apache_log_content)
        
        # Create auth log
        auth_log_dir = Path("/var/log")
        auth_log_content = """Sep 19 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.200 port 22 ssh2
Sep 19 10:00:02 server sshd[1235]: Failed password for admin from 192.168.1.201 port 22 ssh2
Sep 19 10:00:03 server sshd[1236]: Failed password for root from 192.168.1.200 port 22 ssh2
Sep 19 10:00:04 server sshd[1237]: Accepted password for user from 192.168.1.100 port 22 ssh2
Sep 19 10:00:05 server sshd[1238]: Failed password for test from 192.168.1.202 port 22 ssh2
Sep 19 10:00:06 server sshd[1239]: Failed password for root from 192.168.1.200 port 22 ssh2
"""
        
        with open("/var/log/auth.log", "w") as f:
            f.write(auth_log_content)
    
    def test_security_report_exists(self):
        """Test that the security report file is created."""
        report_path = Path("/app/security_report.json")
        assert report_path.exists(), "Security report file should exist at /app/security_report.json"
    
    def test_security_report_valid_json(self):
        """Test that the security report contains valid JSON."""
        report_path = Path("/app/security_report.json")
        
        with open(report_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                pytest.fail(f"Security report contains invalid JSON: {e}")
        
        assert isinstance(data, dict), "Security report should be a JSON object"
    
    def test_security_report_structure(self):
        """Test that the security report has the required structure."""
        report_path = Path("/app/security_report.json")
        
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        # Check main structure
        assert "security_report" in data, "Report should have 'security_report' key"
        report = data["security_report"]
        
        # Check required sections
        required_sections = ["top_active_ips", "suspicious_ips", "failed_ssh_attempts", "summary"]
        for section in required_sections:
            assert section in report, f"Report should have '{section}' section"
    
    def test_top_active_ips_format(self):
        """Test that top active IPs are properly formatted."""
        report_path = Path("/app/security_report.json")
        
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        top_ips = data["security_report"]["top_active_ips"]
        assert isinstance(top_ips, list), "top_active_ips should be a list"
        assert len(top_ips) <= 5, "Should have at most 5 top IPs"
        
        for ip_entry in top_ips:
            assert "ip" in ip_entry, "Each IP entry should have 'ip' field"
            assert "requests" in ip_entry, "Each IP entry should have 'requests' field"
            assert isinstance(ip_entry["requests"], int), "Requests should be an integer"
    
    def test_suspicious_ips_detection(self):
        """Test that suspicious IPs (>50 requests) are detected."""
        report_path = Path("/app/security_report.json")
        
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        suspicious_ips = data["security_report"]["suspicious_ips"]
        assert isinstance(suspicious_ips, list), "suspicious_ips should be a list"
        
        # Should detect the IP with 55 requests
        assert len(suspicious_ips) >= 1, "Should detect at least one suspicious IP"
        
        for ip_entry in suspicious_ips:
            assert "ip" in ip_entry, "Each suspicious IP entry should have 'ip' field"
            assert "requests" in ip_entry, "Each suspicious IP entry should have 'requests' field"
            assert ip_entry["requests"] > 50, "Suspicious IPs should have >50 requests"
    
    def test_failed_ssh_attempts_format(self):
        """Test that failed SSH attempts are properly formatted."""
        report_path = Path("/app/security_report.json")
        
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        failed_ssh = data["security_report"]["failed_ssh_attempts"]
        assert isinstance(failed_ssh, list), "failed_ssh_attempts should be a list"
        
        for ssh_entry in failed_ssh:
            assert "ip" in ssh_entry, "Each SSH entry should have 'ip' field"
            assert "failed_attempts" in ssh_entry, "Each SSH entry should have 'failed_attempts' field"
            assert isinstance(ssh_entry["failed_attempts"], int), "Failed attempts should be an integer"
    
    def test_summary_statistics(self):
        """Test that summary statistics are calculated correctly."""
        report_path = Path("/app/security_report.json")
        
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        summary = data["security_report"]["summary"]
        
        # Check required summary fields
        required_fields = ["total_requests", "unique_ips", "total_failed_logins", "analysis_timestamp"]
        for field in required_fields:
            assert field in summary, f"Summary should have '{field}' field"
        
        # Validate data types
        assert isinstance(summary["total_requests"], int), "total_requests should be an integer"
        assert isinstance(summary["unique_ips"], int), "unique_ips should be an integer"
        assert isinstance(summary["total_failed_logins"], int), "total_failed_logins should be an integer"
        assert isinstance(summary["analysis_timestamp"], str), "analysis_timestamp should be a string"
        
        # Validate reasonable values
        assert summary["total_requests"] > 0, "Should have processed some requests"
        assert summary["unique_ips"] > 0, "Should have found some unique IPs"
    
    def test_script_executable(self):
        """Test that the solution script is executable."""
        solution_script = Path("/app/solution.sh")
        assert solution_script.exists(), "Solution script should exist"
        
        # Check if script is executable
        stat_info = solution_script.stat()
        assert stat_info.st_mode & 0o111, "Solution script should be executable"
    
    def test_script_runs_without_errors(self):
        """Test that the solution script runs without errors."""
        try:
            result = subprocess.run(
                ["/bin/bash", "/app/solution.sh"],
                capture_output=True,
                text=True,
                timeout=60
            )
            assert result.returncode == 0, f"Script should run successfully. Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            pytest.fail("Script execution timed out")
    
    def test_handles_missing_logs_gracefully(self):
        """Test that the script handles missing log files gracefully."""
        # Remove log files temporarily
        os.rename("/var/log/apache/access.log", "/var/log/apache/access.log.bak")
        os.rename("/var/log/auth.log", "/var/log/auth.log.bak")
        
        try:
            result = subprocess.run(
                ["/bin/bash", "/app/solution.sh"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Script should still run (may produce warnings but shouldn't crash)
            assert result.returncode == 0, "Script should handle missing logs gracefully"
            
            # Should still produce a valid JSON report
            report_path = Path("/app/security_report.json")
            assert report_path.exists(), "Should still create report file"
            
            with open(report_path, 'r') as f:
                data = json.load(f)
                assert "security_report" in data, "Should still have valid report structure"
        
        finally:
            # Restore log files
            os.rename("/var/log/apache/access.log.bak", "/var/log/apache/access.log")
            os.rename("/var/log/auth.log.bak", "/var/log/auth.log")
    
    def test_json_validation_with_jq(self):
        """Test that the generated JSON is valid using jq."""
        report_path = Path("/app/security_report.json")
        
        try:
            result = subprocess.run(
                ["jq", "empty", str(report_path)],
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"JSON validation failed: {result.stderr}"
        except FileNotFoundError:
            pytest.skip("jq not available for JSON validation")


if __name__ == "__main__":
    pytest.main([__file__])