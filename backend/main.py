import os
import shutil
import hashlib
import asyncio
from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from parser import parse_pcap_file
from ml_engine import analyze_traffic
from fastapi.responses import FileResponse
from pydantic import BaseModel
from reportlab.pdfgen import canvas # required for report_gen to work properly
from parser import parse_pcap_file, capture_live_batch
from report_gen import create_evidence_pdf


app = FastAPI(title="Network Forensics Platform API")

class ReportRequest(BaseModel):
    filename: str
    sha256: str
    total_packets: int
    anomaly_count: int

# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def compute_sha256(file_path: str) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

@app.post("/api/upload")
async def handle_pcap_upload(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a PCAP.")

    saved_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(saved_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    file_hash = compute_sha256(saved_path)
    raw_packets = parse_pcap_file(saved_path)
    analyzed_data = analyze_traffic(raw_packets)

    return {
        "filename": file.filename,
        "sha256": file_hash,
        "total_packets": len(analyzed_data),
        "anomaly_count": len([p for p in analyzed_data if p["is_anomalous"]]),
        "unique_ips": len(set([p["src_ip"] for p in analyzed_data] + [p["dst_ip"] for p in analyzed_data])),
        "leak_count": len([p for p in analyzed_data if p.get("is_leaked")]),
        "records": analyzed_data[:200]
    }

@app.post("/api/report")
async def generate_report(req: ReportRequest):
    pdf_filename = f"Evidence_{req.filename}.pdf"
    pdf_path = os.path.join(UPLOAD_DIR, pdf_filename)
    
    # Generate the PDF
    create_evidence_pdf(
        req.filename, 
        req.sha256, 
        req.total_packets, 
        req.anomaly_count, 
        pdf_path
    )

    return FileResponse(path=pdf_path, media_type='application/pdf', filename=pdf_filename)

@app.websocket("/api/ws/live")
async def live_traffic_stream(websocket: WebSocket):
    await websocket.accept()
    print("Live stream connected!")
    try:
        while True:
            # Capture a live batch of 50 packets
            raw_packets = capture_live_batch(batch_size=50)
            
            if raw_packets:
                # Pass to the AI engine
                analyzed_data = analyze_traffic(raw_packets)
                
                # Format the payload
                payload = {
                    "total_packets": len(analyzed_data),
                    "anomaly_count": len([p for p in analyzed_data if p.get("is_anomalous")]),
                    "leak_count": len([p for p in analyzed_data if p.get("is_leaked")]),
                    "records": analyzed_data
                }
                
                # Push real-time JSON to the React dashboard
                await websocket.send_json(payload)
            
            # Brief pause to prevent overloading the CPU
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        print("Live stream client disconnected.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)