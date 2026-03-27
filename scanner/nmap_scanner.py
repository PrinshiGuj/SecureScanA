import nmap
import json
from datetime import datetime

class NmapScanner:
    @staticmethod
    def scan(target):
        scanner = nmap.PortScanner()
        results = {
            'vulnerabilities': [],
            'logs': []
        }
        
        try:
            # Quick port scan
            scanner.scan(target, '1-1000', arguments='-sV --open')
            
            logs = []
            for host in scanner.all_hosts():
                logs.append(f"[+] Scanning {host}")
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]['name']
                        version = scanner[host][proto][port].get('version', 'unknown')
                        logs.append(f"    Port {port}/{proto}: {service} {version}")
                        
                        # Check for common vulnerable services
                        if 'http' in service.lower() or 'ftp' in service or 'ssh' in service:
                            results['vulnerabilities'].append({
                                'name': f'Open {service.title()} Service',
                                'description': f'{service.title()} running on port {port}',
                                'severity': 'Medium',
                                'category': 'Service Exposure',
                                'cvss_score': 5.3,
                                'proof': f'{host}:{port} ({service} {version})',
                                'recommendation': 'Review service configuration and exposure'
                            })
            
            results['logs'] = logs
            return results
            
        except Exception as e:
            results['logs'].append(f"Nmap Error: {str(e)}")
            return results