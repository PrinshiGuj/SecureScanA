from reportlab.platypus import SimpleDocTemplate, Paragraph, Image, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def generate_pdf_report(scan_data, filename="securescan_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    story = []
    
    # Cover Page
    story.append(Paragraph("SECURESCAN A<br/><br/>AI-Powered VAPT Report", styles['Title']))
    story.append(Spacer(1, 50))
    
    # Executive Summary
    story.append(Paragraph(f"Target: {scan_data['target']}", styles['Heading2']))
    story.append(Paragraph(f"Risk Score: {scan_data['risk_score']:.1f}%", styles['Heading2']))
    
    # Vulnerabilities Table
    vulns_table = [['Severity', 'Vulnerability', 'CVSS', 'Status']]
    for vuln in scan_data['vulns']:
        vulns_table.append([
            vuln['severity'], 
            vuln['name'][:30], 
            f"{vuln['cvss']:.1f}",
            'Open'
        ])
    
    table = Table(vulns_table)
    table.setStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
    ])
    story.append(table)
    
    doc.build(story)
    return filename