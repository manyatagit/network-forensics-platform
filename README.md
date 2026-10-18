# Network Forensics Platform

A network forensics and anomaly detection platform designed to inspect PCAP files and live traffic for suspicious patterns, possible data exfiltration, covert channels, and malware-like behavior. The platform combines a FastAPI backend with a React dashboard to help analysts review packet flows, detect anomalies, and export evidence reports as PDF.

## Project Overview

This repository contains a full-stack traffic analysis system that:

- uploads and parses PCAP/PCAPNG files
- inspects packet metadata and payload patterns
- detects suspicious traffic using machine learning and heuristic rules
- identifies possible data leaks and covert-channel activity
- streams live packet activity from a network interface
- presents results in a real-time dashboard
- exports findings to a PDF evidence report

The project is organized into two main components:

- backend: Python API, traffic parsing, detection logic, report generation
- frontend: React/Vite dashboard for upload, filtering, visualization, and evidence export

## Key Features

- Offline PCAP analysis
- Live network traffic monitoring
- IP/protocol/status filtering in the frontend dashboard
- AI anomaly scoring using Isolation Forest
- JA3-style TLS fingerprint detection heuristics
- DLP-style leak detection for email and sensitive keywords
- Covert channel detection for ICMP and DNS patterns
- PDF evidence generation for report exports
- Interactive traffic summary graphs

## Repository Structure

```text
network-forensics-platform/
├── backend/
│   ├── main.py
│   ├── parser.py
│   ├── ml_engine.py
│   ├── report_gen.py
│   ├── requirements.txt
│   ├── live_test.py
│   ├── test_covert.py
│   ├── test_ja3.py
│   ├── test_leak.py
│   └── uploads/
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── eslint.config.js
│   └── README.md
├── sample_pcaps/
│   └── nb6-http.pcap
├── .gitignore
└── README.md
```

## Technology Stack

### Backend
- Python
- FastAPI
- Scapy
- pandas
- scikit-learn
- reportlab
- python-multipart

### Frontend
- React
- Vite
- Recharts
- Lucide React

## System Behavior

### Offline Analysis
The backend accepts a PCAP upload via `/api/upload`, parses it with Scapy, analyzes packet flows, and returns:

- filename and SHA-256 hash
- total packet count
- anomaly count
- unique IP count
- leak count
- packet record list for dashboard rendering

### Live Monitoring
The backend provides a WebSocket endpoint at `/api/ws/live` to stream traffic in real time and push updates to the frontend dashboard.

### Report Generation
The API exposes `/api/report` to generate a PDF file summarizing the evidence using the metadata collected during the analysis session.

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm

### 1) Setup the backend

```bash
cd backend
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Start the API server:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The backend API will be available at:

- http://localhost:8000
- WebSocket: ws://localhost:8000/api/ws/live

### 2) Setup the frontend

From the repository root:

```bash
cd frontend
npm install
npm run dev
```

The frontend dashboard is typically served at:

- http://localhost:5173

## Using the Platform

### Analyze a sample PCAP

1. Start the backend and frontend.
2. Open the frontend dashboard.
3. Upload a PCAP file such as:
   - `sample_pcaps/nb6-http.pcap`
4. Review suspicious traffic, anomaly counts, and flow data in the dashboard.
5. Export evidence as a PDF using the export button.

### Start live monitoring

1. Open the dashboard.
2. click the live sensor toggle.
3. The app connects to the WebSocket stream and begins showing real-time packet data.

## Detection Logic

This project combines multiple heuristics to help identify suspicious activity:

- Isolation Forest-based anomaly detection on packet length and port values
- Email and sensitive keyword matching in packet payloads
- JA3-like TLS fingerprint detection for suspicious HTTPS traffic
- ICMP and DNS covert-channel checks
- packet-level risk classification for frontend filtering and verdicts

## Example Use Cases

- reviewing suspicious PCAP files in incident response workflows
- monitoring live network activity for abnormal communication patterns
- identifying possible exfiltration of credentials or private data
- triaging malware or tunnel-based covert channels
- generating defensible evidence reports for analyst review

## Notes

This repository is a proof-of-concept and research-oriented platform rather than a production-grade security monitoring stack. It is intended for educational, lab, and forensic-analysis use cases.

## License

This project does not include a repository-level license file in the current structure. If you plan to reuse or distribute it, confirm licensing requirements with the repository owner before publishing or integrating it into production systems.

## Contributing

Contributions, issue reports, and feature ideas are welcome. To contribute:

1. fork the repository
2. create a feature branch
3. make changes and validate locally
4. open a pull request with a clear summary of the improvement

## Contact / Reference

Repository: manyatagit/network-forensics-platform

This README was generated to describe the repository structure, architecture, and local setup for the project.
