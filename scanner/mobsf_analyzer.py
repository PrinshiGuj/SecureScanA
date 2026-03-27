"""
MobSF Analyzer for SecureScan A
Integrates Mobile Security Framework (MobSF) for APK analysis
Works perfectly on Kali Linux & Ubuntu
"""

import requests
import json
import os
import time
import uuid
from pathlib import Path
import subprocess
from typing import Dict, List, Any
import logging

class MobSFScanner:
    """
    MobSF Integration for Android APK vulnerability scanning
    REST API + Dynamic Analysis
    """
    
    def __init__(self, mobsf_url: str = "http://localhost:8000"):
        """
        Initialize MobSF Scanner
        
        Args:
            mobsf_url: MobSF server URL (default: http://localhost:8000)
        """
        self.mobsf_url = mobsf_url.rstrip('/')
        self.api_url = f"{self.mobsf_url}/api/v1"
        self.logs = []
        self.session = requests.Session()
        
    def ensure_mobsf_running(self) -> bool:
        """Check if MobSF is running"""
        try:
            response = self.session.get(f"{self.mobsf_url}/", timeout=10)
            if response.status_code == 200:
                self.logs.append("[+] MobSF server is running")
                return True
            else:
                self.logs.append("[-] MobSF not accessible")
                return False
        except requests.exceptions.RequestException:
            self.logs.append("[-] MobSF not running. Starting...")
            return self.start_mobsf()
    
    def start_mobsf(self) -> bool:
        """Start MobSF server if not running"""
        try:
            # Start MobSF in background
            cmd = ["mobsf"]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(10)  # Wait for startup
            
            # Verify
            response = self.session.get(f"{self.mobsf_url}/", timeout=10)
            if response.status_code == 200:
                self.logs.append("[+] MobSF started successfully")
                return True
            return False
        except FileNotFoundError:
            self.logs.append("[-] MobSF not installed. Run: pip install mobsf")
            return False
        except Exception as e:
            self.logs.append(f"[-] MobSF startup failed: {str(e)}")
            return False
    
    def upload_apk(self, apk_path: str) -> str:
        """
        Upload APK to MobSF and return hash
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Hash of uploaded APK or None
        """
        if not os.path.exists(apk_path):
            self.logs.append(f"[-] APK not found: {apk_path}")
            return None
        
        try:
            with open(apk_path, 'rb') as f:
                files = {'file': (os.path.basename(apk_path), f, 'application/vnd.android.package-archive')}
                response = self.session.post(
                    f"{self.api_url}/upload",
                    files=files,
                    timeout=300  # 5 minutes for large APKs
                )
            
            if response.status_code == 200:
                data = response.json()
                app_hash = data.get('hash')
                self.logs.append(f"[+] APK uploaded: {os.path.basename(apk_path)}")
                self.logs.append(f"[+] App Hash: {app_hash}")
                return app_hash
            else:
                self.logs.append(f"[-] Upload failed: {response.status_code}")
                return None
                
        except Exception as e:
            self.logs.append(f"[-] Upload error: {str(e)}")
            return None
    
    def get_scan_results(self, app_hash: str) -> Dict[str, Any]:
        """
        Get static + dynamic analysis results
        
        Args:
            app_hash: Hash from upload_apk()
            
        Returns:
            Complete analysis results
        """
        results = {
            'vulnerabilities': [],
            'logs': [],
            'summary': {}
        }
        
        try:
            # Wait for scan completion
            for _ in range(60):  # 10 minutes max
                response = self.session.get(f"{self.api_url}/report_json/{app_hash}")
                if response.status_code == 200:
                    data = response.json()
                    break
                time.sleep(10)
            
            # Parse static analysis
            static_results = self._parse_static_analysis(data)
            results['vulnerabilities'].extend(static_results)
            
            # Parse dynamic analysis (if available)
            dynamic_results = self._parse_dynamic_analysis(data)
            results['vulnerabilities'].extend(dynamic_results)
            
            # Summary
            results['summary'] = {
                'package_name': data.get('package_name', 'Unknown'),
                'version': data.get('version', 'Unknown'),
                'permissions': len(data.get('permissions', [])),
                'high_risk': len([v for v in results['vulnerabilities'] if v['severity'] == 'High']),
                'total_vulns': len(results['vulnerabilities'])
            }
            
            self.logs.extend(results['logs'])
            return results
            
        except Exception as e:
            self.logs.append(f"[-] Analysis failed: {str(e)}")
            return results
    
    def _parse_static_analysis(self, data: Dict) -> List[Dict]:
        """Parse MobSF static analysis results"""
        vulnerabilities = []
        logs = []
        
        # Permissions Analysis
        permissions = data.get('permissions', {})
        risky_perms = {
            'android.permission.SEND_SMS': 'SMS privileges - Potential abuse',
            'android.permission.READ_SMS': 'SMS reading - Privacy risk',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Storage access - Data leakage',
            'android.permission.INTERNET': 'Network access - Always flagged'
        }
        
        for perm, description in risky_perms.items():
            if permissions.get(perm, {}).get('status') == 'danger':
                vulnerabilities.append({
                    'name': f'Risky Permission: {perm}',
                    'description': description,
                    'severity': 'High' if 'SMS' in perm else 'Medium',
                    'category': 'Permissions',
                    'cvss_score': 7.5 if 'SMS' in perm else 5.3,
                    'proof': f"Permission: {perm}",
                    'recommendation': 'Review and justify permission usage'
                })
        
        # Code Analysis
        code_analysis = data.get('code_analysis', {})
        for issue_type, issues in code_analysis.items():
            for issue in issues:
                severity_map = {
                    'high': 'High',
                    'medium': 'Medium', 
                    'low': 'Low'
                }
                severity = severity_map.get(issue.get('level', 'info'), 'Info')
                
                vulnerabilities.append({
                    'name': f"{issue_type.title()} - {issue.get('title', 'Issue')}",
                    'description': issue.get('description', ''),
                    'severity': severity,
                    'category': 'Code Analysis',
                    'cvss_score': self._cvss_from_severity(severity),
                    'proof': issue.get('file_name', '') + ':' + str(issue.get('line_number', '')),
                    'recommendation': issue.get('recommendation', 'Fix security issue')
                })
        
        # Malware Analysis
        malware = data.get('malware_analysis', {})
        if malware.get('malicious_activity'):
            vulnerabilities.append({
                'name': 'Potential Malware Detected',
                'description': 'MobSF detected malicious behavior patterns',
                'severity': 'Critical',
                'category': 'Malware',
                'cvss_score': 9.8,
                'proof': json.dumps(malware, indent=2),
                'recommendation': 'Do not deploy this APK'
            })
        
        logs.append(f"[+] Static Analysis: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities
    
    def _parse_dynamic_analysis(self, data: Dict) -> List[Dict]:
        """Parse MobSF dynamic analysis results"""
        vulnerabilities = []
        
        # Network Security
        network_scores = data.get('network_security', {})
        if network_scores.get('grade') in ['F', 'D']:
            vulnerabilities.append({
                'name': 'Poor Network Security',
                'description': f"Grade: {network_scores.get('grade')} - Insecure communications",
                'severity': 'High',
                'category': 'Network',
                'cvss_score': 7.5,
                'proof': f"Pinning: {network_scores.get('pinning', 'None')}",
                'recommendation': 'Implement certificate pinning'
            })
        
        # Trackers
        trackers = data.get('trackers', [])
        if len(trackers) > 5:
            vulnerabilities.append({
                'name': 'Excessive Trackers',
                'description': f'{len(trackers)} trackers detected',
                'severity': 'Medium',
                'category': 'Privacy',
                'cvss_score': 4.3,
                'proof': ', '.join([t.get('title', '') for t in trackers[:3]]),
                'recommendation': 'Remove unnecessary trackers'
            })
        
        return vulnerabilities
    
    def _cvss_from_severity(self, severity: str) -> float:
        """Map severity to CVSS score"""
        mapping = {
            'Critical': 9.8,
            'High': 7.5,
            'Medium': 5.3,
            'Low': 3.1
        }
        return mapping.get(severity, 0.0)
    
    @staticmethod
    def scan(apk_path: str, mobsf_url: str = "http://localhost:8000") -> Dict[str, Any]:
        """
        Main scanning function for SecureScan A integration
        
        Args:
            apk_path: Path to APK file
            mobsf_url: MobSF server URL
            
        Returns:
            Structured results for main scanner
        """
        scanner = MobSFScanner(mobsf_url)
        
        results = {
            'vulnerabilities': [],
            'logs': []
        }
        
        # Ensure MobSF is running
        if not scanner.ensure_mobsf_running():
            results['logs'].append("[-] MobSF unavailable - skipping mobile analysis")
            return results
        
        # Upload APK
        app_hash = scanner.upload_apk(apk_path)
        if not app_hash:
            results['logs'].append("[-] APK upload failed")
            return results
        
        # Get results
        analysis_results = scanner.get_scan_results(app_hash)
        results['vulnerabilities'] = analysis_results['vulnerabilities']
        results['logs'] = scanner.logs + analysis_results['logs']
        
        # Add summary log
        summary = analysis_results['summary']
        results['logs'].append(
            f"[+] Mobile Analysis Complete: {summary.get('total_vulns', 0)} vulns, "
            f"{summary.get('high_risk', 0)} high risk"
        )
        
        return results

# Test function
def test_mobsf_scan():
    """Test MobSF integration"""
    # Download test APK (InsecureBankv2 - perfect for demo)
    test_apk = "insecurebankv2.apk"
    if not os.path.exists(test_apk):
        print("Downloading test APK...")
        url = "https://github.com/dineshshetty/Android-InsecureBankv2/releases/download/1.0/InsecureBankv2.apk"
        response = requests.get(url)
        with open(test_apk, 'wb') as f:
            f.write(response.content)
    
    print("🚀 Testing MobSF Scanner...")
    results = MobSFScanner.scan(test_apk)
    
    print("\n📱 MobSF Analysis Results:")
    print("=" * 50)
    for log in results['logs']:
        print(log)
    
    print(f"\n🔍 Found {len(results['vulnerabilities'])} vulnerabilities")
    for vuln in results['vulnerabilities'][:5]:  # Top 5
        print(f"  {vuln['severity']}: {vuln['name']}")

if __name__ == "__main__":
    test_mobsf_scan()