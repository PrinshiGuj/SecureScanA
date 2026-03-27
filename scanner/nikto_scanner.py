import subprocess
import re
import json
from datetime import datetime

class NiktoScanner:
    @staticmethod
    def scan(target):
        results = {
            'vulnerabilities': [],
            'logs': [f"[+] Starting Nikto scan on {target}"]
        }
        
        try:
            cmd = ['nikto', '-h', target, '-Tuning', '1234567890', '-maxtime', '300']
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            output, error = process.communicate()
            
            # Parse Nikto output
            lines = output.split('\n')
            for line in lines:
                if '+' in line and ('OSVDB' in line or 'CVE' in line or 'vuln' in line.lower()):
                    results['logs'].append(line.strip())
                    
                    # Extract vulnerability info
                    vuln_name = re.search(r'\+ (.+?)(?:\$|$)', line)
                    if vuln_name:
                        results['vulnerabilities'].append({
                            'name': vuln_name.group(1).strip(),
                            'description': line.strip(),
                            'severity': 'High',
                            'category': 'Web Vulnerability',
                            'cvss_score': 7.5,
                            'proof': target,
                            'recommendation': 'Review and patch the identified vulnerability'
                        })
            
        except FileNotFoundError:
            results['logs'].append("Nikto not found. Install with: sudo apt install nikto")
        except Exception as e:
            results['logs'].append(f"Nikto Error: {str(e)}")
        
        return results