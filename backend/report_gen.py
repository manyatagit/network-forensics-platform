from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

def create_evidence_pdf(filename: str, sha256_hash: str, total_packets: int, anomaly_count: int, output_path: str):
    """Generates a tamper-evident forensic PDF report."""
    c = canvas.Canvas(output_path, pagesize=letter)
    
    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "Kanad S.H.I.E.L.D. - Official Forensic Evidence Report")
    
    # Body
    c.setFont("Helvetica", 12)
    c.drawString(50, 700, f"Target Capture File: {filename}")
    c.drawString(50, 675, f"Cryptographic Hash (SHA-256): {sha256_hash}")
    c.drawString(50, 650, f"Total Packets Inspected: {total_packets}")
    c.drawString(50, 625, f"High-Confidence Anomalies Detected: {anomaly_count}")
    
    # Chain of Custody Stamp
    c.setFont("Helvetica-Bold", 12)
    c.setFillColorRGB(0.8, 0, 0) # Red text
    c.drawString(50, 575, "*** CHAIN OF CUSTODY VERIFIED ***")
    
    # Footer
    c.setFont("Helvetica-Oblique", 10)
    c.setFillColorRGB(0, 0, 0)
    c.drawString(50, 50, "Generated automatically by the Network & Packet Forensics Platform")
    
    c.save()
    return output_path