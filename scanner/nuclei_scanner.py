import subprocess
import json
from datetime import datetime

class NucleiScanner:
    @staticmethod
    def scan(target):
        results = {
            'vulnerabilities': [],
            'logs': [f"[+] Starting Nuclei scan on {target}"]
        }
        
        try:
            cmd = [
                'nuclei', 
                '-u', target, 
                '-t', '/path/to/nuclei-templates',  # Update path
                '-json-export', 'nuclei_results.json',
                '-silent'
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            # Parse JSON results
            try:
                with open('nuclei_results.json', 'r') as f:
                    for line in f:
                        vuln = json.loads(line)
                        results['vulnerabilities'].append({
                            'name': vuln.get('template-id', 'Unknown'),
                            'description': vuln.get('info', {}).get('description', ''),
                            'severity': vuln.get('severity', 'Medium'),
                            'category': vuln.get('template-id', ''),
                            'cvss_score': 8.0,
                            'proof': vuln.get('matched-at', target),
                            'recommendation': 'Follow vendor recommendations'
                        })
            except:
                pass
                
        except FileNotFoundError:
            results['logs'].append("Nuclei not found. Install from: https://nuclei.projectdiscovery.io/")
        
        return results