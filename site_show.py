"""
Comprehensive Web & API Vulnerability Scanner with Advanced CVE Detection
Version 3.0 - Enhanced with all vulnerability types and API scanning
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime
import time
from collections import defaultdict
import hashlib
import warnings
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
import base64
import xml.etree.ElementTree as ET

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class ComprehensiveScanner:
    def __init__(self, target_url, max_depth=2, max_threads=5):
        self.target_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.visited_urls = set()
        self.vulnerabilities = []
        self.cve_findings = []
        self.api_endpoints = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.lock = threading.Lock()
        
        # Enhanced XSS Payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert(1)</script>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>"
        ]
        
        # SQL Injection Payloads
        self.sqli_payloads = [
            "' OR '1'='1' --",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "admin' --",
            "' OR SLEEP(5)--",
            "1' ORDER BY 10--",
            "' UNION ALL SELECT 1,@@version,3--",
            "') OR ('1'='1"
        ]
        
        # Command Injection Payloads
        self.cmd_injection_payloads = [
            "; ls -la",
            "| whoami",
            "& cat /etc/passwd",
            "`id`",
            "$(uname -a)",
            "'; system('whoami'); '",
            "| ping -c 10 127.0.0.1",
            "& dir",
            "; cat /proc/version"
        ]
        
        # Path Traversal Payloads
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\\....\\....\\windows\\win.ini",
            "/etc/passwd",
            "C:\\windows\\system32\\config\\sam"
        ]
        
        # XXE Payloads
        self.xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/secret">]><foo>&xxe;</foo>"""
        ]
        
        # SSRF Payloads
        self.ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0",
            "http://[::1]",
            "http://metadata.google.internal",
            "file:///etc/passwd"
        ]
        
        # IDOR Test IDs
        self.idor_test_ids = [1, 2, 100, 1000, 9999, -1, 0]
        
        # CORS Test Origins
        self.cors_origins = [
            "https://evil.com",
            "null",
            "https://attacker.com"
        ]
        
        # SQL Error Patterns
        self.sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"Microsoft SQL Server",
            r"ODBC Driver",
            r"ORA-[0-9]+",
            r"SQLite.Exception",
            r"syntax error at or near",
            r"PG::SyntaxError",
            r"unterminated quoted string"
        ]
        
        # Enhanced CVE Database
        self.cve_database = {
            'Apache/2.4.49': {
                'cves': ['CVE-2021-41773', 'CVE-2021-42013'],
                'description': 'Path traversal and RCE vulnerability',
                'severity': 'Critical'
            },
            'Apache/2.4.50': {
                'cves': ['CVE-2021-42013'],
                'description': 'Path traversal vulnerability',
                'severity': 'Critical'
            },
            'nginx/1.10': {
                'cves': ['CVE-2017-7529'],
                'description': 'Integer overflow in range filter',
                'severity': 'High'
            },
            'nginx/1.18': {
                'cves': ['CVE-2021-23017'],
                'description': 'DNS resolver vulnerability',
                'severity': 'High'
            },
            'PHP/5.3': {
                'cves': ['CVE-2012-1823'],
                'description': 'CGI query string parsing RCE',
                'severity': 'Critical'
            },
            'PHP/7.1': {
                'cves': ['CVE-2019-11043'],
                'description': 'PHP-FPM RCE vulnerability',
                'severity': 'Critical'
            },
            'WordPress/4.': {
                'cves': ['CVE-2017-5487'],
                'description': 'XSS vulnerability',
                'severity': 'High'
            },
            'WordPress/5.0': {
                'cves': ['CVE-2019-8942', 'CVE-2019-8943'],
                'description': 'XSS and CSRF vulnerabilities',
                'severity': 'High'
            },
            'jQuery/1.': {
                'cves': ['CVE-2015-9251'],
                'description': 'XSS vulnerability',
                'severity': 'Medium'
            },
            'jQuery/2.': {
                'cves': ['CVE-2019-11358'],
                'description': 'Prototype pollution',
                'severity': 'Medium'
            },
            'OpenSSL/1.0.1': {
                'cves': ['CVE-2014-0160'],
                'description': 'Heartbleed vulnerability',
                'severity': 'Critical'
            },
            'OpenSSL/1.0.2': {
                'cves': ['CVE-2016-2107'],
                'description': 'Padding oracle vulnerability',
                'severity': 'High'
            },
            'Drupal/7.': {
                'cves': ['CVE-2018-7600', 'CVE-2018-7602'],
                'description': 'Drupalgeddon 2 RCE',
                'severity': 'Critical'
            },
            'Spring Framework': {
                'cves': ['CVE-2022-22965'],
                'description': 'Spring4Shell RCE',
                'severity': 'Critical'
            },
            'Log4j/2.': {
                'cves': ['CVE-2021-44228'],
                'description': 'Log4Shell RCE',
                'severity': 'Critical'
            },
            'Tomcat/8.5': {
                'cves': ['CVE-2020-1938'],
                'description': 'Ghostcat vulnerability',
                'severity': 'Critical'
            },
            'Struts/2.': {
                'cves': ['CVE-2017-5638', 'CVE-2018-11776'],
                'description': 'RCE vulnerabilities',
                'severity': 'Critical'
            },
            'Jenkins/2.': {
                'cves': ['CVE-2019-1003000'],
                'description': 'Sandbox bypass',
                'severity': 'Critical'
            }
        }

    def log_message(self, message, level="INFO"):
        """Enhanced logging with colors"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m"
        }
        reset = "\033[0m"
        color = colors.get(level, "\033[94m")
        print(f"{color}[{timestamp}] {level}: {message}{reset}")

    def crawl(self, url, depth=0):
        """Enhanced crawling with API endpoint discovery"""
        if depth > self.max_depth or url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        links = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all links
            for tag in soup.find_all(['a', 'link'], href=True):
                full_url = urljoin(url, tag['href'])
                if self._is_valid_url(full_url):
                    links.append(full_url)
            
            # Find forms (potential API endpoints)
            for form in soup.find_all('form', action=True):
                full_url = urljoin(url, form['action'])
                if self._is_valid_url(full_url):
                    links.append(full_url)
            
            # Discover API endpoints from JavaScript
            for script in soup.find_all('script'):
                script_content = script.string if script.string else ''
                api_endpoints = self._extract_api_endpoints(script_content, url)
                links.extend(api_endpoints)
            
            # Check for common API paths
            links.extend(self._check_common_api_paths(url))
            
        except Exception as e:
            self.log_message(f"Error crawling {url}: {str(e)}", "ERROR")
        
        return list(set(links))

    def _extract_api_endpoints(self, script_content, base_url):
        """Extract API endpoints from JavaScript"""
        endpoints = []
        patterns = [
            r'["\']/(api|v1|v2|v3|rest|graphql)/[^"\']+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[get|post]+\(["\']([^"\']+)["\']',
            r'\$\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                full_url = urljoin(base_url, match)
                if self._is_valid_url(full_url):
                    endpoints.append(full_url)
                    with self.lock:
                        self.api_endpoints.append(full_url)
        
        return endpoints

    def _check_common_api_paths(self, url):
        """Check for common API paths"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/api',
            '/graphql', '/api/graphql',
            '/api/users', '/api/admin',
            '/api/docs', '/api/swagger',
            '/v1', '/v2', '/v3'
        ]
        
        endpoints = []
        for path in common_paths:
            test_url = base_url + path
            try:
                resp = self.session.head(test_url, timeout=5, verify=False)
                if resp.status_code < 500:
                    endpoints.append(test_url)
                    with self.lock:
                        self.api_endpoints.append(test_url)
            except:
                pass
        
        return endpoints

    def _is_valid_url(self, url):
        """Check if URL is valid for scanning"""
        parsed = urlparse(url)
        target_parsed = urlparse(self.target_url)
        
        if parsed.netloc != target_parsed.netloc:
            return False
        
        skip_extensions = ['.pdf', '.jpg', '.png', '.gif', '.css', '.js', '.ico', '.woff', '.ttf']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
            
        return True

    def detect_cve(self, url):
        """Enhanced CVE detection with version fingerprinting"""
        cves = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            content = response.text
            
            # Server header analysis
            server = headers.get('Server', '')
            x_powered_by = headers.get('X-Powered-By', '')
            
            # Check CVE database
            for signature, vuln_info in self.cve_database.items():
                if (signature.lower() in server.lower() or 
                    signature.lower() in x_powered_by.lower() or
                    signature.lower() in content.lower()):
                    
                    for cve in vuln_info['cves']:
                        cves.append({
                            'cve_id': cve,
                            'software': signature,
                            'location': 'Server/Application Detection',
                            'severity': vuln_info['severity'],
                            'confidence': 'High',
                            'description': vuln_info['description'],
                            'evidence': f'Detected {signature}',
                            'reference': f'https://nvd.nist.gov/vuln/detail/{cve}'
                        })
            
            # Framework-specific CVE detection
            frameworks = {
                'WordPress': (r'wp-(?:content|includes|admin)', self._detect_wordpress_version),
                'Joomla': (r'joomla', self._detect_joomla_version),
                'Drupal': (r'drupal', self._detect_drupal_version)
            }
            
            for framework, (pattern, detector) in frameworks.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self.log_message(f"Detected framework: {framework}", "INFO")
                    version_cves = detector(content)
                    cves.extend(version_cves)
            
        except Exception as e:
            self.log_message(f"Error detecting CVE: {str(e)}", "ERROR")
        
        return cves

    def _detect_wordpress_version(self, content):
        """Detect WordPress version and related CVEs"""
        cves = []
        version_match = re.search(r'WordPress ([0-9.]+)', content)
        if version_match:
            version = version_match.group(1)
            self.log_message(f"WordPress version: {version}", "INFO")
            
            # Add CVEs based on version
            if version.startswith('4.'):
                cves.append({
                    'cve_id': 'CVE-2017-5487',
                    'software': f'WordPress {version}',
                    'location': 'CMS Detection',
                    'severity': 'High',
                    'confidence': 'High',
                    'description': 'XSS vulnerability in WordPress',
                    'evidence': f'WordPress version {version} detected',
                    'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2017-5487'
                })
        return cves

    def _detect_joomla_version(self, content):
        """Detect Joomla version"""
        cves = []
        version_match = re.search(r'Joomla! ([0-9.]+)', content)
        if version_match:
            self.log_message(f"Joomla version: {version_match.group(1)}", "INFO")
        return cves

    def _detect_drupal_version(self, content):
        """Detect Drupal version"""
        cves = []
        version_match = re.search(r'Drupal ([0-9.]+)', content)
        if version_match:
            version = version_match.group(1)
            self.log_message(f"Drupal version: {version}", "INFO")
            
            if version.startswith('7.'):
                cves.append({
                    'cve_id': 'CVE-2018-7600',
                    'software': f'Drupal {version}',
                    'location': 'CMS Detection',
                    'severity': 'Critical',
                    'confidence': 'High',
                    'description': 'Drupalgeddon 2 RCE',
                    'evidence': f'Drupal version {version} detected',
                    'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2018-7600'
                })
        return cves

    def test_xss(self, url):
        """Enhanced XSS testing including DOM-based XSS"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Test forms
            for form in soup.find_all('form'):
                form_details = self._get_form_details(form)
                if not form_details['inputs']:
                    continue
                
                for payload in self.xss_payloads[:4]:
                    data = self._prepare_form_data(form_details, payload)
                    target_url = urljoin(url, form_details['action'])
                    
                    try:
                        if form_details['method'] == 'post':
                            res = self.session.post(target_url, data=data, timeout=10, verify=False)
                        else:
                            res = self.session.get(target_url, params=data, timeout=10, verify=False)
                        
                        if self._is_xss_successful(payload, res.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'subtype': 'Reflected XSS',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'High',
                                    'url': target_url,
                                    'parameter': list(data.keys())[0] if data else 'N/A',
                                    'payload': payload,
                                    'evidence': 'Payload reflected without encoding',
                                    'confidence': 'Medium'
                                })
                    except:
                        continue
            
            # Test URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.xss_payloads[:3]:
                    test_url = self._build_test_url(url, param, payload)
                    try:
                        res = self.session.get(test_url, timeout=10, verify=False)
                        if self._is_xss_successful(payload, res.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'subtype': 'Reflected XSS',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'High',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'XSS in URL parameter {param}',
                                    'confidence': 'High'
                                })
                    except:
                        continue
            
            # Check for DOM-based XSS
            vulnerabilities.extend(self._test_dom_xss(url, response.text))
                        
        except Exception as e:
            self.log_message(f"Error testing XSS: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _test_dom_xss(self, url, content):
        """Test for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        # Look for dangerous JavaScript patterns
        dangerous_patterns = [
            r'document\.write\([^)]*location',
            r'eval\([^)]*location',
            r'innerHTML\s*=.*location',
            r'document\.URL',
            r'document\.documentURI'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'subtype': 'Potential DOM-based XSS',
                    'owasp': 'A03:2021 - Injection',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'JavaScript Code',
                    'payload': 'N/A',
                    'evidence': f'Dangerous pattern found: {pattern}',
                    'confidence': 'Low'
                })
        
        return vulnerabilities

    def test_sql_injection(self, url):
        """Enhanced SQL injection testing"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Test forms
            for form in soup.find_all('form'):
                form_details = self._get_form_details(form)
                if not form_details['inputs']:
                    continue
                
                for payload in self.sqli_payloads[:4]:
                    data = self._prepare_form_data(form_details, payload)
                    target_url = urljoin(url, form_details['action'])
                    
                    try:
                        if form_details['method'] == 'post':
                            res = self.session.post(target_url, data=data, timeout=10, verify=False)
                        else:
                            res = self.session.get(target_url, params=data, timeout=10, verify=False)
                        
                        if self._is_sqli_successful(payload, res.text, response.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'subtype': 'Error-based SQLi',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'Critical',
                                    'url': target_url,
                                    'parameter': list(data.keys())[0] if data else 'N/A',
                                    'payload': payload,
                                    'evidence': 'SQL error or different response',
                                    'confidence': 'Medium'
                                })
                    except:
                        continue
            
            # Test URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.sqli_payloads[:3]:
                    test_url = self._build_test_url(url, param, payload)
                    try:
                        res = self.session.get(test_url, timeout=10, verify=False)
                        if self._is_sqli_successful(payload, res.text, response.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'subtype': 'Error-based SQLi',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'Critical',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'SQLi in parameter {param}',
                                    'confidence': 'High'
                                })
                    except:
                        continue
            
            # Time-based blind SQLi
            vulnerabilities.extend(self._test_blind_sqli(url, params))
                        
        except Exception as e:
            self.log_message(f"Error testing SQLi: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _test_blind_sqli(self, url, params):
        """Test for time-based blind SQL injection"""
        vulnerabilities = []
        time_payload = "' OR SLEEP(5)--"
        
        for param in params:
            test_url = self._build_test_url(url, param, time_payload)
            try:
                start_time = time.time()
                self.session.get(test_url, timeout=10, verify=False)
                elapsed = time.time() - start_time
                
                if elapsed >= 5:
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'subtype': 'Time-based Blind SQLi',
                        'owasp': 'A03:2021 - Injection',
                        'severity': 'Critical',
                        'url': test_url,
                        'parameter': param,
                        'payload': time_payload,
                        'evidence': f'Response delayed by {elapsed:.2f} seconds',
                        'confidence': 'High'
                    })
            except:
                pass
        
        return vulnerabilities

    def test_command_injection(self, url):
        """Test for command injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = self._get_form_details(form)
                if not form_details['inputs']:
                    continue
                
                for payload in self.cmd_injection_payloads[:3]:
                    data = self._prepare_form_data(form_details, payload)
                    target_url = urljoin(url, form_details['action'])
                    
                    try:
                        if form_details['method'] == 'post':
                            res = self.session.post(target_url, data=data, timeout=10, verify=False)
                        else:
                            res = self.session.get(target_url, params=data, timeout=10, verify=False)
                        
                        if self._is_command_injection_successful(res.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'subtype': 'OS Command Injection',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'Critical',
                                    'url': target_url,
                                    'parameter': list(data.keys())[0] if data else 'N/A',
                                    'payload': payload,
                                    'evidence': 'System command output detected',
                                    'confidence': 'Medium'
                                })
                    except:
                        continue
            
            # Test URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.cmd_injection_payloads[:2]:
                    test_url = self._build_test_url(url, param, payload)
                    try:
                        res = self.session.get(test_url, timeout=10, verify=False)
                        if self._is_command_injection_successful(res.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'subtype': 'OS Command Injection',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'Critical',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'Command injection in parameter {param}',
                                    'confidence': 'High'
                                })
                    except:
                        continue
                        
        except Exception as e:
            self.log_message(f"Error testing command injection: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _is_command_injection_successful(self, response_text):
        """Check if command injection was successful"""
        patterns = [
            r'uid=\d+',
            r'gid=\d+',
            r'root:x:0:0',
            r'Windows.*Microsoft',
            r'Volume in drive',
            r'Directory of',
            r'Linux version'
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_path_traversal(self, url):
        """Test for path traversal vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.path_traversal_payloads[:4]:
                    test_url = self._build_test_url(url, param, payload)
                    try:
                        res = self.session.get(test_url, timeout=10, verify=False)
                        if self._is_path_traversal_successful(res.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Path Traversal',
                                    'subtype': 'Directory Traversal',
                                    'owasp': 'A01:2021 - Broken Access Control',
                                    'severity': 'High',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Sensitive file content detected',
                                    'confidence': 'High'
                                })
                    except:
                        continue
                        
        except Exception as e:
            self.log_message(f"Error testing path traversal: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _is_path_traversal_successful(self, response_text):
        """Check if path traversal was successful"""
        patterns = [
            r'root:x:0:0',
            r'\[extensions\]',
            r'\[boot loader\]',
            r'Windows.*Microsoft'
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_xxe(self, url):
        """Test for XXE (XML External Entity) vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = self._get_form_details(form)
                target_url = urljoin(url, form_details['action'])
                
                for payload in self.xxe_payloads:
                    try:
                        headers = {'Content-Type': 'application/xml'}
                        res = self.session.post(target_url, data=payload, headers=headers, timeout=10, verify=False)
                        
                        if self._is_xxe_successful(res.text):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'XML External Entity (XXE)',
                                    'subtype': 'XXE Injection',
                                    'owasp': 'A03:2021 - Injection',
                                    'severity': 'High',
                                    'url': target_url,
                                    'parameter': 'XML Body',
                                    'payload': payload[:100],
                                    'evidence': 'XXE payload processed',
                                    'confidence': 'Medium'
                                })
                    except:
                        continue
                        
        except Exception as e:
            self.log_message(f"Error testing XXE: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _is_xxe_successful(self, response_text):
        """Check if XXE was successful"""
        patterns = [
            r'root:x:0:0',
            r'<!DOCTYPE',
            r'ENTITY'
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def test_ssrf(self, url):
        """Test for SSRF (Server-Side Request Forgery) vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.ssrf_payloads[:3]:
                    test_url = self._build_test_url(url, param, payload)
                    try:
                        start_time = time.time()
                        res = self.session.get(test_url, timeout=10, verify=False)
                        elapsed = time.time() - start_time
                        
                        if self._is_ssrf_successful(res.text, elapsed):
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Server-Side Request Forgery (SSRF)',
                                    'subtype': 'SSRF',
                                    'owasp': 'A10:2021 - Server-Side Request Forgery',
                                    'severity': 'High',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Internal resource access detected',
                                    'confidence': 'Medium'
                                })
                    except:
                        continue
                        
        except Exception as e:
            self.log_message(f"Error testing SSRF: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _is_ssrf_successful(self, response_text, elapsed):
        """Check if SSRF was successful"""
        patterns = [
            r'ami-id',
            r'instance-id',
            r'private-ipv4',
            r'security-credentials'
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check if response took unusually long (internal network scan)
        if elapsed > 3:
            return True
            
        return False

    def test_idor(self, url):
        """Test for IDOR (Insecure Direct Object Reference) vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for ID-like parameters
            id_params = [p for p in params if any(x in p.lower() for x in ['id', 'user', 'account', 'doc', 'file', 'order'])]
            
            if not id_params:
                return vulnerabilities
            
            for param in id_params:
                original_value = params[param][0]
                base_response = self.session.get(url, timeout=10, verify=False)
                
                # Test different IDs
                for test_id in self.idor_test_ids:
                    test_url = self._build_test_url(url, param, str(test_id))
                    try:
                        res = self.session.get(test_url, timeout=10, verify=False)
                        
                        # Check if we got different content with 200 status
                        if (res.status_code == 200 and 
                            res.text != base_response.text and 
                            len(res.text) > 100):
                            
                            with self.lock:
                                vulnerabilities.append({
                                    'type': 'Insecure Direct Object Reference (IDOR)',
                                    'subtype': 'IDOR',
                                    'owasp': 'A01:2021 - Broken Access Control',
                                    'severity': 'High',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': str(test_id),
                                    'evidence': f'Access to ID {test_id} without proper authorization',
                                    'confidence': 'Low'
                                })
                            break  # Found one, move to next parameter
                    except:
                        continue
                        
        except Exception as e:
            self.log_message(f"Error testing IDOR: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_cors(self, url):
        """Test for CORS misconfigurations"""
        vulnerabilities = []
        
        try:
            for origin in self.cors_origins:
                headers = {'Origin': origin}
                res = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                acao = res.headers.get('Access-Control-Allow-Origin', '')
                acac = res.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    severity = 'High' if acac.lower() == 'true' else 'Medium'
                    
                    with self.lock:
                        vulnerabilities.append({
                            'type': 'CORS Misconfiguration',
                            'subtype': 'Insecure CORS Policy',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                            'severity': severity,
                            'url': url,
                            'parameter': 'Access-Control-Allow-Origin',
                            'payload': origin,
                            'evidence': f'CORS allows origin: {origin}',
                            'confidence': 'High'
                        })
                        
        except Exception as e:
            self.log_message(f"Error testing CORS: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_open_redirect(self, url):
        """Test for open redirect vulnerabilities"""
        vulnerabilities = []
        
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '///evil.com',
            'javascript:alert(1)'
        ]
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for redirect-like parameters
            redirect_params = [p for p in params if any(x in p.lower() for x in ['url', 'redirect', 'return', 'next', 'continue', 'dest', 'redir'])]
            
            for param in redirect_params:
                for payload in redirect_payloads:
                    test_url = self._build_test_url(url, param, payload)
                    try:
                        res = self.session.get(test_url, timeout=10, verify=False, allow_redirects=False)
                        
                        if res.status_code in [301, 302, 303, 307, 308]:
                            location = res.headers.get('Location', '')
                            if payload in location:
                                with self.lock:
                                    vulnerabilities.append({
                                        'type': 'Open Redirect',
                                        'subtype': 'Unvalidated Redirect',
                                        'owasp': 'A01:2021 - Broken Access Control',
                                        'severity': 'Medium',
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'evidence': f'Redirects to: {location}',
                                        'confidence': 'High'
                                    })
                    except:
                        continue
                        
        except Exception as e:
            self.log_message(f"Error testing open redirect: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_csrf(self, url):
        """Test for CSRF vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = self._get_form_details(form)
                
                # Check if form has CSRF token
                has_csrf = any('csrf' in inp['name'].lower() or 'token' in inp['name'].lower() 
                              for inp in form_details['inputs'])
                
                # Check if form performs state-changing operations
                is_state_changing = form_details['method'] == 'post'
                
                if is_state_changing and not has_csrf:
                    with self.lock:
                        vulnerabilities.append({
                            'type': 'Cross-Site Request Forgery (CSRF)',
                            'subtype': 'Missing CSRF Token',
                            'owasp': 'A01:2021 - Broken Access Control',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': 'Form',
                            'payload': 'N/A',
                            'evidence': 'State-changing form without CSRF protection',
                            'confidence': 'High'
                        })
                        
        except Exception as e:
            self.log_message(f"Error testing CSRF: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_security_headers(self, url):
        """Test security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_checks = {
                'Content-Security-Policy': ('Missing CSP', 'High'),
                'X-Frame-Options': ('Missing X-Frame-Options (Clickjacking)', 'Medium'),
                'X-Content-Type-Options': ('Missing X-Content-Type-Options', 'Low'),
                'Strict-Transport-Security': ('Missing HSTS', 'High'),
                'X-XSS-Protection': ('Missing X-XSS-Protection', 'Low'),
                'Referrer-Policy': ('Missing Referrer-Policy', 'Low'),
                'Permissions-Policy': ('Missing Permissions-Policy', 'Low')
            }
            
            for header, (description, severity) in security_checks.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Security Header Missing',
                        'subtype': description,
                        'owasp': 'A05:2021 - Security Misconfiguration',
                        'severity': severity,
                        'url': url,
                        'parameter': header,
                        'payload': 'N/A',
                        'evidence': f'Header {header} not present',
                        'confidence': 'High'
                    })
            
            # Check for information disclosure
            if 'Server' in headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'subtype': 'Server Version Disclosure',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'severity': 'Low',
                    'url': url,
                    'parameter': 'Server Header',
                    'payload': headers['Server'],
                    'evidence': 'Server version disclosed',
                    'confidence': 'High'
                })
            
            if 'X-Powered-By' in headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'subtype': 'Technology Stack Disclosure',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'severity': 'Low',
                    'url': url,
                    'parameter': 'X-Powered-By Header',
                    'payload': headers['X-Powered-By'],
                    'evidence': 'Technology stack disclosed',
                    'confidence': 'High'
                })
                    
        except Exception as e:
            self.log_message(f"Error testing headers: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_sensitive_data_exposure(self, url):
        """Test for sensitive data exposure"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text
            
            sensitive_patterns = [
                (r'password\s*[:=]\s*[\'"][^\'"]{3,}[\'"]', 'Hardcoded password', 'High'),
                (r'api[_-]?key\s*[:=]\s*[\'"][^\'"]{10,}[\'"]', 'API key exposure', 'High'),
                (r'secret[_-]?key\s*[:=]\s*[\'"][^\'"]{10,}[\'"]', 'Secret key exposure', 'High'),
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'Critical'),
                (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Secret Key', 'Critical'),
                (r'[0-9]{3}-[0-9]{2}-[0-9]{4}', 'Possible SSN', 'High'),
                (r'[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}', 'Possible Credit Card', 'Critical'),
                (r'-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----', 'Private Key', 'Critical'),
                (r'mysql://[^:]+:[^@]+@', 'Database Connection String', 'High'),
                (r'mongodb://[^:]+:[^@]+@', 'MongoDB Connection String', 'High')
            ]
            
            for pattern, description, severity in sensitive_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'subtype': description,
                        'owasp': 'A02:2021 - Cryptographic Failures',
                        'severity': severity,
                        'url': url,
                        'parameter': 'Response Body',
                        'payload': 'N/A',
                        'evidence': f'{len(matches)} {description} instance(s) found',
                        'confidence': 'Medium'
                    })
            
            # Check for HTTP on sensitive pages
            if url.startswith('http://'):
                soup = BeautifulSoup(content, 'html.parser')
                if soup.find_all('input', {'type': 'password'}):
                    vulnerabilities.append({
                        'type': 'Insecure Transmission',
                        'subtype': 'Credentials over HTTP',
                        'owasp': 'A02:2021 - Cryptographic Failures',
                        'severity': 'High',
                        'url': url,
                        'parameter': 'Protocol',
                        'payload': 'N/A',
                        'evidence': 'Password form over HTTP',
                        'confidence': 'High'
                    })
                        
        except Exception as e:
            self.log_message(f"Error testing sensitive data: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_authentication(self, url):
        """Test authentication mechanisms"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            # Check cookies
            for cookie in response.cookies:
                cookie_name = cookie.name.lower()
                
                if any(x in cookie_name for x in ['session', 'auth', 'token', 'jwt']):
                    # Check HttpOnly flag
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        vulnerabilities.append({
                            'type': 'Insecure Cookie',
                            'subtype': 'Missing HttpOnly Flag',
                            'owasp': 'A07:2021 - Identification and Authentication Failures',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': cookie.name,
                            'payload': 'N/A',
                            'evidence': 'Session cookie missing HttpOnly flag',
                            'confidence': 'High'
                        })
                    
                    # Check Secure flag
                    if not cookie.secure and url.startswith('https'):
                        vulnerabilities.append({
                            'type': 'Insecure Cookie',
                            'subtype': 'Missing Secure Flag',
                            'owasp': 'A07:2021 - Identification and Authentication Failures',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': cookie.name,
                            'payload': 'N/A',
                            'evidence': 'Session cookie missing Secure flag',
                            'confidence': 'High'
                        })
                    
                    # Check SameSite attribute
                    if not cookie.has_nonstandard_attr('SameSite'):
                        vulnerabilities.append({
                            'type': 'Insecure Cookie',
                            'subtype': 'Missing SameSite Attribute',
                            'owasp': 'A07:2021 - Identification and Authentication Failures',
                            'severity': 'Low',
                            'url': url,
                            'parameter': cookie.name,
                            'payload': 'N/A',
                            'evidence': 'Session cookie missing SameSite attribute',
                            'confidence': 'High'
                        })
                        
        except Exception as e:
            self.log_message(f"Error testing authentication: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_api_vulnerabilities(self, url):
        """Comprehensive API security testing"""
        vulnerabilities = []
        
        try:
            # Test for common API endpoints
            api_tests = [
                ('/api/users', 'GET'),
                ('/api/admin', 'GET'),
                ('/api/config', 'GET'),
                ('/api/debug', 'GET'),
                ('/api/v1/users', 'GET'),
                ('/graphql', 'POST')
            ]
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint, method in api_tests:
                test_url = base_url + endpoint
                try:
                    if method == 'GET':
                        res = self.session.get(test_url, timeout=5, verify=False)
                    else:
                        res = self.session.post(test_url, json={}, timeout=5, verify=False)
                    
                    # Check for exposed API endpoints
                    if res.status_code == 200 and len(res.text) > 50:
                        vulnerabilities.append({
                            'type': 'API Security Issue',
                            'subtype': 'Exposed API Endpoint',
                            'owasp': 'A01:2021 - Broken Access Control',
                            'severity': 'Medium',
                            'url': test_url,
                            'parameter': 'Endpoint',
                            'payload': 'N/A',
                            'evidence': f'API endpoint accessible without authentication',
                            'confidence': 'Medium'
                        })
                    
                    # Check for verbose error messages
                    if res.status_code >= 400:
                        if any(x in res.text.lower() for x in ['stack trace', 'exception', 'debug', 'error at line']):
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'subtype': 'Verbose API Error',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                                'severity': 'Low',
                                'url': test_url,
                                'parameter': 'Error Response',
                                'payload': 'N/A',
                                'evidence': 'API returns verbose error messages',
                                'confidence': 'High'
                            })
                except:
                    pass
            
            # Test for missing rate limiting
            vulnerabilities.extend(self._test_rate_limiting(url))
            
            # Test for mass assignment
            vulnerabilities.extend(self._test_mass_assignment(url))
            
        except Exception as e:
            self.log_message(f"Error testing API: {str(e)}", "ERROR")
        
        return vulnerabilities

    def _test_rate_limiting(self, url):
        """Test for missing rate limiting"""
        vulnerabilities = []
        
        try:
            # Make multiple rapid requests
            responses = []
            for i in range(15):
                res = self.session.get(url, timeout=5, verify=False)
                responses.append(res.status_code)
            
            # If all requests succeed, rate limiting might be missing
            if all(code == 200 for code in responses):
                vulnerabilities.append({
                    'type': 'API Security Issue',
                    'subtype': 'Missing Rate Limiting',
                    'owasp': 'A04:2021 - Insecure Design',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'API Endpoint',
                    'payload': 'N/A',
                    'evidence': '15 rapid requests succeeded without rate limiting',
                    'confidence': 'Low'
                })
        except:
            pass
        
        return vulnerabilities

    def _test_mass_assignment(self, url):
        """Test for mass assignment vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Try to inject admin parameters
            test_payloads = [
                {'isAdmin': True, 'role': 'admin'},
                {'admin': 1, 'is_admin': True},
                {'privileges': 'admin', 'user_role': 'administrator'}
            ]
            
            for payload in test_payloads:
                try:
                    res = self.session.post(url, json=payload, timeout=5, verify=False)
                    
                    # Check if the response indicates success
                    if res.status_code in [200, 201] and 'admin' in res.text.lower():
                        vulnerabilities.append({
                            'type': 'API Security Issue',
                            'subtype': 'Potential Mass Assignment',
                            'owasp': 'A04:2021 - Insecure Design',
                            'severity': 'High',
                            'url': url,
                            'parameter': 'Request Body',
                            'payload': json.dumps(payload),
                            'evidence': 'API accepts unexpected parameters',
                            'confidence': 'Low'
                        })
                        break
                except:
                    pass
        except:
            pass
        
        return vulnerabilities

    def _get_form_details(self, form):
        """Extract form details"""
        details = {
            'action': form.get('action', '').strip(),
            'method': form.get('method', 'get').lower().strip(),
            'inputs': []
        }
        
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name:
                details['inputs'].append({
                    'name': input_name,
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
        
        for textarea in form.find_all('textarea'):
            textarea_name = textarea.get('name')
            if textarea_name:
                details['inputs'].append({
                    'name': textarea_name,
                    'type': 'textarea',
                    'value': ''
                })
        
        return details

    def _prepare_form_data(self, form_details, payload):
        """Prepare form data with payload"""
        data = {}
        for input_field in form_details['inputs']:
            if input_field['type'] in ['text', 'search', 'email', 'password', 'url', 'textarea']:
                data[input_field['name']] = payload
            elif input_field['type'] in ['hidden', 'submit']:
                data[input_field['name']] = input_field.get('value', 'test')
            else:
                data[input_field['name']] = 'test'
        return data

    def _build_test_url(self, base_url, param, payload):
        """Build test URL with payload"""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = payload
        new_query = '&'.join(f"{k}={quote(str(v[0]))}" for k, v in params.items())
        return parsed._replace(query=new_query).geturl()

    def _is_xss_successful(self, payload, response_text):
        """Check if XSS payload was successful"""
        if payload in response_text:
            encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
            if encoded_payload not in response_text:
                return True
        return False

    def _is_sqli_successful(self, payload, test_response, original_response):
        """Check if SQL injection was successful"""
        for pattern in self.sql_errors:
            if re.search(pattern, test_response, re.IGNORECASE):
                return True
        
        if (len(test_response) != len(original_response) and 
            abs(len(test_response) - len(original_response)) > 100):
            return True
            
        return False

    def scan_url(self, url):
        """Scan a single URL for all vulnerability types"""
        url_vulnerabilities = []
        
        try:
            self.log_message(f"Scanning: {url}", "INFO")
            
            # Run all security tests
            url_vulnerabilities.extend(self.test_xss(url))
            url_vulnerabilities.extend(self.test_sql_injection(url))
            url_vulnerabilities.extend(self.test_command_injection(url))
            url_vulnerabilities.extend(self.test_path_traversal(url))
            url_vulnerabilities.extend(self.test_xxe(url))
            url_vulnerabilities.extend(self.test_ssrf(url))
            url_vulnerabilities.extend(self.test_idor(url))
            url_vulnerabilities.extend(self.test_cors(url))
            url_vulnerabilities.extend(self.test_open_redirect(url))
            url_vulnerabilities.extend(self.test_csrf(url))
            url_vulnerabilities.extend(self.test_security_headers(url))
            url_vulnerabilities.extend(self.test_sensitive_data_exposure(url))
            url_vulnerabilities.extend(self.test_authentication(url))
            url_vulnerabilities.extend(self.test_api_vulnerabilities(url))
            
            # CVE detection only on main page
            if url == self.target_url:
                cves = self.detect_cve(url)
                with self.lock:
                    self.cve_findings.extend(cves)
            
        except Exception as e:
            self.log_message(f"Error scanning {url}: {str(e)}", "ERROR")
        
        return url_vulnerabilities

    def scan(self):
        """Main scanning function"""
        self.log_message(f"Starting comprehensive scan of {self.target_url}", "INFO")
        start_time = time.time()
        
        # Crawl website
        self.log_message("Crawling website and discovering endpoints...", "INFO")
        urls = [self.target_url]
        urls.extend(self.crawl(self.target_url))
        urls = list(set(urls))
        
        self.log_message(f"Found {len(urls)} URLs to scan", "SUCCESS")
        self.log_message(f"Discovered {len(self.api_endpoints)} API endpoints", "SUCCESS")
        
        # Scan URLs with threading
        self.log_message("Starting comprehensive vulnerability scan...", "INFO")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {
                executor.submit(self.scan_url, url): url for url in urls
            }
            
            completed = 0
            total = len(urls)
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    with self.lock:
                        self.vulnerabilities.extend(vulnerabilities)
                    completed += 1
                    if completed % 5 == 0:
                        self.log_message(f"Progress: {completed}/{total} URLs scanned", "INFO")
                except Exception as e:
                    self.log_message(f"Scan failed for {url}: {str(e)}", "ERROR")
        
        # Remove duplicates
        self._deduplicate_findings()
        
        scan_time = time.time() - start_time
        self.log_message(f"Scan completed in {scan_time:.2f} seconds", "SUCCESS")
        self.log_message(f"Found {len(self.vulnerabilities)} vulnerabilities", "SUCCESS")
        self.log_message(f"Found {len(self.cve_findings)} CVEs", "SUCCESS")
        
        # Print severity breakdown
        severity_count = defaultdict(int)
        for vuln in self.vulnerabilities:
            severity_count[vuln['severity']] += 1
        
        self.log_message("Severity Breakdown:", "INFO")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_count.get(severity, 0)
            if count > 0:
                self.log_message(f"  {severity}: {count}", "INFO")
        
        return self.vulnerabilities, self.cve_findings

    def _deduplicate_findings(self):
        """Remove duplicate findings"""
        unique_vulns = []
        seen_vulns = set()
        
        for vuln in self.vulnerabilities:
            key = (vuln['type'], vuln['url'], vuln.get('parameter', ''), vuln.get('subtype', ''))
            if key not in seen_vulns:
                seen_vulns.add(key)
                unique_vulns.append(vuln)
        
        self.vulnerabilities = unique_vulns
        
        unique_cves = []
        seen_cves = set()
        
        for cve in self.cve_findings:
            key = cve['cve_id']
            if key not in seen_cves:
                seen_cves.add(key)
                unique_cves.append(cve)
        
        self.cve_findings = unique_cves

    def generate_report(self, output_file=None):
        """Generate comprehensive security report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"security_report_{timestamp}.html"
        
        self.log_message(f"Generating report: {output_file}", "INFO")
        
        # Group vulnerabilities
        severity_groups = defaultdict(list)
        type_groups = defaultdict(list)
        
        for vuln in self.vulnerabilities:
            severity_groups[vuln['severity']].append(vuln)
            type_groups[vuln['type']].append(vuln)
        
        # Create HTML report
        html_content = self._create_html_report(severity_groups, type_groups)
        
        # Write HTML report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Generate JSON report
        json_file = output_file.replace('.html', '.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_metadata': {
                    'target': self.target_url,
                    'scan_date': datetime.now().isoformat(),
                    'urls_scanned': len(self.visited_urls),
                    'api_endpoints_found': len(self.api_endpoints)
                },
                'summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'total_cves': len(self.cve_findings),
                    'severity_breakdown': {k: len(v) for k, v in severity_groups.items()},
                    'type_breakdown': {k: len(v) for k, v in type_groups.items()}
                },
                'cve_findings': self.cve_findings,
                'vulnerabilities': self.vulnerabilities,
                'api_endpoints': self.api_endpoints
            }, f, indent=2, ensure_ascii=False)
        
        self.log_message(f"HTML report saved to: {output_file}", "SUCCESS")
        self.log_message(f"JSON report saved to: {json_file}", "SUCCESS")
        
        return output_file, json_file

    def _create_html_report(self, severity_groups, type_groups):
        """Create comprehensive HTML report"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Security Scan Report</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #20c997;
            --info: #17a2b8;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 25px;
        }}
        
        .info-item {{
            background: rgba(255,255,255,0.15);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        
        .info-item .label {{
            font-size: 0.9em;
            opacity: 0.85;
            margin-bottom: 5px;
        }}
        
        .info-item .value {{
            font-size: 1.5em;
            font-weight: bold;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            padding: 30px;
            border-radius: 12px;
            color: white;
            text-align: center;
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
            transition: transform 0.3s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        
        .summary-card.critical {{ background: var(--critical); }}
        .summary-card.high {{ background: var(--high); }}
        .summary-card.medium {{ background: var(--medium); color: #333; }}
        .summary-card.low {{ background: var(--low); }}
        .summary-card.info {{ background: var(--info); }}
        
        .summary-card .count {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .summary-card .label {{
            font-size: 1.1em;
            opacity: 0.95;
        }}
        
        .section {{
            margin-bottom: 50px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e9ecef;
            color: #2c3e50;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .vulnerability-list {{
            display: grid;
            gap: 20px;
        }}
        
        .vulnerability-item {{
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 25px;
            background: #f8f9fa;
            transition: all 0.3s;
        }}
        
        .vulnerability-item:hover {{
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
            border-color: #dee2e6;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
            flex: 1;
        }}
        
        .vuln-badges {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .severity-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: var(--critical); }}
        .severity-high {{ background: var(--high); }}
        .severity-medium {{ background: var(--medium); color: #333; }}
        .severity-low {{ background: var(--low); }}
        
        .confidence-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            background: #6c757d;
            color: white;
            font-size: 0.85em;
        }}
        
        .vuln-details {{
            display: grid;
            gap: 12px;
        }}
        
        .detail-row {{
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 15px;
            align-items: start;
        }}
        
        .detail-label {{
            font-weight: bold;
            color: #6c757d;
        }}
        
        .detail-value {{
            word-break: break-all;
        }}
        
        .detail-value code {{
            background: #e9ecef;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .cve-section {{
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 40px;
        }}
        
        .cve-item {{
            background: white;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        
        .cve-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .cve-id {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
            font-size: 1.2em;
            color: #856404;
        }}
        
        .cve-link {{
            color: #007bff;
            text-decoration: none;
            font-size: 0.9em;
        }}
        
        .cve-link:hover {{
            text-decoration: underline;
        }}
        
        .api-endpoints {{
            background: #e7f3ff;
            border: 2px solid #17a2b8;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 40px;
        }}
        
        .api-list {{
            list-style: none;
            padding: 0;
        }}
        
        .api-list li {{
            background: white;
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 6px;
            border-left: 4px solid #17a2b8;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .recommendations {{
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            border-left: 5px solid #28a745;
            padding: 30px;
            border-radius: 10px;
            margin-top: 40px;
        }}
        
        .recommendations h3 {{
            color: #155724;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        
        .recommendations ul {{
            list-style-position: inside;
            color: #155724;
        }}
        
        .recommendations li {{
            margin: 12px 0;
            padding-left: 10px;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #6c757d;
            border-top: 2px solid #dee2e6;
        }}
        
        .footer p {{
            margin: 5px 0;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        
        .stat-card .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .stat-card .stat-label {{
            color: #6c757d;
            font-size: 1.1em;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                margin: 10px;
                border-radius: 10px;
            }}
            
            .header {{
                padding: 25px;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .content {{
                padding: 20px;
            }}
            
            .detail-row {{
                grid-template-columns: 1fr;
                gap: 5px;
            }}
            
            .vuln-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Comprehensive Security Assessment</h1>
            <div class="subtitle">Advanced Web & API Vulnerability Scanner v3.0</div>
            <div class="scan-info">
                <div class="info-item">
                    <div class="label">Target</div>
                    <div class="value">{self.target_url}</div>
                </div>
                <div class="info-item">
                    <div class="label">Scan Date</div>
                    <div class="value">{datetime.now().strftime('%Y-%m-%d')}</div>
                </div>
                <div class="info-item">
                    <div class="label">Time</div>
                    <div class="value">{datetime.now().strftime('%H:%M:%S')}</div>
                </div>
                <div class="info-item">
                    <div class="label">URLs Scanned</div>
                    <div class="value">{len(self.visited_urls)}</div>
                </div>
                <div class="info-item">
                    <div class="label">API Endpoints</div>
                    <div class="value">{len(self.api_endpoints)}</div>
                </div>
            </div>
        </div>
        
        <div class="content">
            <!-- Summary Cards -->
            <div class="summary-cards">
                <div class="summary-card critical">
                    <div class="count">{len(severity_groups.get('Critical', []))}</div>
                    <div class="label">Critical Issues</div>
                </div>
                <div class="summary-card high">
                    <div class="count">{len(severity_groups.get('High', []))}</div>
                    <div class="label">High Severity</div>
                </div>
                <div class="summary-card medium">
                    <div class="count">{len(severity_groups.get('Medium', []))}</div>
                    <div class="label">Medium Severity</div>
                </div>
                <div class="summary-card low">
                    <div class="count">{len(severity_groups.get('Low', []))}</div>
                    <div class="label">Low Severity</div>
                </div>
                <div class="summary-card info">
                    <div class="count">{len(self.cve_findings)}</div>
                    <div class="label">CVEs Detected</div>
                </div>
            </div>
            
            <!-- Vulnerability Type Breakdown -->
            <div class="stats-grid">
                {self._generate_type_stats(type_groups)}
            </div>
            
            <!-- CVE Findings -->
            {self._generate_cve_section()}
            
            <!-- API Endpoints -->
            {self._generate_api_section()}
            
            <!-- Vulnerabilities by Severity -->
            {self._generate_vulnerability_sections(severity_groups)}
            
            <!-- Recommendations -->
            <div class="recommendations">
                <h3>💡 Security Recommendations</h3>
                <ul>
                    <li><strong>Input Validation:</strong> Implement strict input validation and sanitization on all user inputs</li>
                    <li><strong>Output Encoding:</strong> Properly encode all outputs to prevent injection attacks</li>
                    <li><strong>Parameterized Queries:</strong> Use parameterized queries or ORM to prevent SQL injection</li>
                    <li><strong>Security Headers:</strong> Implement all recommended security headers (CSP, HSTS, X-Frame-Options)</li>
                    <li><strong>Authentication:</strong> Implement strong authentication with secure session management</li>
                    <li><strong>Authorization:</strong> Enforce proper access controls and validate all object references</li>
                    <li><strong>HTTPS:</strong> Use HTTPS for all communications, especially for sensitive data</li>
                    <li><strong>API Security:</strong> Implement rate limiting, authentication, and input validation for all APIs</li>
                    <li><strong>Update Software:</strong> Keep all software components updated to patch known CVEs</li>
                    <li><strong>Error Handling:</strong> Implement proper error handling without exposing sensitive information</li>
                    <li><strong>Security Testing:</strong> Conduct regular security assessments and penetration tests</li>
                    <li><strong>CSRF Protection:</strong> Implement CSRF tokens for all state-changing operations</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Comprehensive Web & API Vulnerability Scanner v3.0</strong></p>
            <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>⚠️ This report is for authorized security testing purposes only</p>
            <p>Always obtain proper authorization before conducting security assessments</p>
        </div>
    </div>
</body>
</html>
"""

    def _generate_type_stats(self, type_groups):
        """Generate vulnerability type statistics"""
        stats_html = ''
        for vuln_type, vulns in sorted(type_groups.items(), key=lambda x: len(x[1]), reverse=True)[:6]:
            stats_html += f"""
            <div class="stat-card">
                <div class="stat-number">{len(vulns)}</div>
                <div class="stat-label">{vuln_type}</div>
            </div>
            """
        return stats_html

    def _generate_cve_section(self):
        """Generate CVE findings section"""
        if not self.cve_findings:
            return ''
        
        cve_html = '<div class="cve-section"><h3 class="section-title">🚨 CVE Findings (Known Vulnerabilities)</h3>'
        
        for cve in self.cve_findings:
            cve_html += f"""
            <div class="cve-item">
                <div class="cve-header">
                    <span class="cve-id">{cve['cve_id']}</span>
                    <span class="severity-badge severity-{cve['severity'].lower()}">{cve['severity']}</span>
                </div>
                <div class="vuln-details">
                    <div class="detail-row">
                        <span class="detail-label">Software:</span>
                        <span class="detail-value">{cve['software']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{cve['description']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Evidence:</span>
                        <span class="detail-value">{cve['evidence']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Reference:</span>
                        <span class="detail-value"><a href="{cve['reference']}" class="cve-link" target="_blank">{cve['reference']}</a></span>
                    </div>
                </div>
            </div>
            """
        
        cve_html += '</div>'
        return cve_html

    def _generate_api_section(self):
        """Generate API endpoints section"""
        if not self.api_endpoints:
            return ''
        
        api_html = '''
        <div class="api-endpoints">
            <h3 class="section-title">🔌 Discovered API Endpoints</h3>
            <ul class="api-list">
        '''
        
        for endpoint in sorted(set(self.api_endpoints))[:20]:  # Limit to 20
            api_html += f'<li>{endpoint}</li>'
        
        if len(self.api_endpoints) > 20:
            api_html += f'<li><em>... and {len(self.api_endpoints) - 20} more endpoints</em></li>'
        
        api_html += '</ul></div>'
        return api_html

    def _generate_vulnerability_sections(self, severity_groups):
        """Generate vulnerability sections by severity"""
        sections_html = ''
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            vulns = severity_groups.get(severity, [])
            if not vulns:
                continue
                
            icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}[severity]
            sections_html += f'<div class="section"><h2 class="section-title">{icon} {severity} Severity Vulnerabilities ({len(vulns)})</h2>'
            sections_html += '<div class="vulnerability-list">'
            
            for vuln in vulns:
                sections_html += f"""
                <div class="vulnerability-item">
                    <div class="vuln-header">
                        <span class="vuln-title">{vuln['type']}</span>
                        <div class="vuln-badges">
                            <span class="severity-badge severity-{vuln['severity'].lower()}">{vuln['severity']}</span>
                            <span class="confidence-badge">{vuln.get('confidence', 'Medium')} Confidence</span>
                        </div>
                    </div>
                    <div class="vuln-details">
                        <div class="detail-row">
                            <span class="detail-label">Subtype:</span>
                            <span class="detail-value">{vuln.get('subtype', 'N/A')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">OWASP:</span>
                            <span class="detail-value">{vuln['owasp']}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">URL:</span>
                            <span class="detail-value"><code>{vuln['url']}</code></span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Parameter:</span>
                            <span class="detail-value"><code>{vuln['parameter']}</code></span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Evidence:</span>
                            <span class="detail-value">{vuln.get('evidence', 'N/A')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Payload:</span>
                            <span class="detail-value"><code>{vuln['payload'][:200]}</code></span>
                        </div>
                    </div>
                </div>
                """
            
            sections_html += '</div></div>'
        
        return sections_html


def main():
    """Main function with enhanced user interface"""
    print("=" * 70)
    print("🚀 COMPREHENSIVE WEB & API VULNERABILITY SCANNER v3.0")
    print("=" * 70)
    print("\nFeatures:")
    print("  ✓ XSS (Reflected, Stored, DOM-based)")
    print("  ✓ SQL Injection (Error-based, Time-based)")
    print("  ✓ Command Injection")
    print("  ✓ Path Traversal")
    print("  ✓ XXE (XML External Entity)")
    print("  ✓ SSRF (Server-Side Request Forgery)")
    print("  ✓ IDOR (Insecure Direct Object Reference)")
    print("  ✓ CORS Misconfiguration")
    print("  ✓ Open Redirect")
    print("  ✓ CSRF (Cross-Site Request Forgery)")
    print("  ✓ Security Headers")
    print("  ✓ Sensitive Data Exposure")
    print("  ✓ Authentication Issues")
    print("  ✓ API Security Testing")
    print("  ✓ CVE Detection")
    print("=" * 70)
    
    try:
        target = input("\n🎯 Enter target URL (or press Enter for demo): ").strip()
        if not target:
            target = "http://testphp.vulnweb.com"
            print(f"Using test site: {target}")
        
        if not target.startswith(('http://', 'https://')):
            print("❌ URL must start with http:// or https://")
            return
        
        depth = input("📊 Enter crawl depth [1-3] (default 2): ").strip()
        depth = int(depth) if depth.isdigit() and 1 <= int(depth) <= 3 else 2
        
        threads = input("⚡ Enter thread count [1-10] (default 5): ").strip()
        threads = int(threads) if threads.isdigit() and 1 <= int(threads) <= 10 else 5
        
        print(f"\n📋 Scan Configuration:")
        print(f"   Target: {target}")
        print(f"   Depth: {depth}")
        print(f"   Threads: {threads}")
        print("\n" + "=" * 70)
        print("⚠️  WARNING: Only scan targets you have permission to test!")
        print("=" * 70)
        
        confirm = input("\nContinue with scan? (yes/no): ").strip().lower()
        if confirm not in ['yes', 'y']:
            print("Scan cancelled.")
            return
        
        print("\n🔍 Initializing scanner...")
        scanner = ComprehensiveScanner(target, max_depth=depth, max_threads=threads)
        
        print("\n🚀 Starting comprehensive security scan...")
        print("-" * 70)
        
        vulnerabilities, cves = scanner.scan()
        
        print("\n" + "=" * 70)
        print("📊 SCAN COMPLETE - RESULTS SUMMARY")
        print("=" * 70)
        print(f"\n✅ URLs scanned: {len(scanner.visited_urls)}")
        print(f"🔌 API endpoints found: {len(scanner.api_endpoints)}")
        print(f"⚠️  Vulnerabilities discovered: {len(vulnerabilities)}")
        print(f"🚨 CVEs detected: {len(cves)}")
        
        # Generate detailed reports
        print("\n📄 Generating detailed reports...")
        report_file, json_file = scanner.generate_report()
        
        # Display severity breakdown
        if vulnerabilities or cves:
            print(f"\n🔍 Severity Breakdown:")
            severity_count = defaultdict(int)
            for vuln in vulnerabilities:
                severity_count[vuln['severity']] += 1
            
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_count.get(severity, 0)
                if count > 0:
                    icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}[severity]
                    print(f"   {icon} {severity}: {count}")
        
        # Display CVE summary
        if cves:
            print(f"\n🚨 Critical CVEs Found:")
            for cve in cves[:5]:  # Show first 5
                print(f"   • {cve['cve_id']} - {cve['software']} ({cve['severity']})")
            if len(cves) > 5:
                print(f"   ... and {len(cves) - 5} more (see report)")
        
        # Display top vulnerabilities
        if vulnerabilities:
            print(f"\n⚠️  Top Vulnerabilities:")
            critical_and_high = [v for v in vulnerabilities if v['severity'] in ['Critical', 'High']]
            for vuln in critical_and_high[:5]:  # Show first 5
                print(f"   • {vuln['type']} - {vuln['severity']} (in {vuln['parameter']})")
            if len(critical_and_high) > 5:
                print(f"   ... and {len(critical_and_high) - 5} more (see report)")
        
        print("\n" + "=" * 70)
        print("📄 REPORTS GENERATED")
        print("=" * 70)
        print(f"📋 HTML Report: {report_file}")
        print(f"📊 JSON Report: {json_file}")
        
        print("\n✨ Scan completed successfully!")
        print("⚠️  Remember: This tool is for authorized testing only!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print(f"\n\n❌ Scan interrupted by user")
        print("=" * 70)
    except Exception as e:
        print(f"\n\n💥 Error: {str(e)}")
        print("=" * 70)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()