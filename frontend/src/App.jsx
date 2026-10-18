import React, { useState, useEffect, useRef } from 'react';
import { UploadCloud, ShieldAlert, Database, Wifi, FileWarning, Filter } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [chartData, setChartData] = useState([]); 
  const [error, setError] = useState(null);
  const [isLive, setIsLive] = useState(false);
  const wsRef = useRef(null);

  // NEW: State variables for our UI filters
  const [filterIP, setFilterIP] = useState('');
  const [filterProtocol, setFilterProtocol] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) setFile(e.target.files[0]);
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    const formData = new FormData();
    formData.append('file', file);
    try {
      const response = await fetch('http://localhost:8000/api/upload', {
        method: 'POST',
        body: formData,
      });
      if (!response.ok) throw new Error(`Server returned ${response.status}`);
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message || 'Failed to upload PCAP.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!results) return;
    const reportData = {
      filename: results.filename || `Live_Session_${new Date().toISOString().replace(/[:.]/g, '-')}`,
      sha256: results.sha256 || "LIVE_MEMORY_CAPTURE_NO_HASH",
      total_packets: results.total_packets,
      anomaly_count: results.anomaly_count
    };
    try {
      const response = await fetch('http://localhost:8000/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportData)
      });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `Evidence_${reportData.filename}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      console.error("Failed to download PDF", err);
    }
  };

  useEffect(() => {
    if (isLive) {
      wsRef.current = new WebSocket('ws://localhost:8000/api/ws/live');
      wsRef.current.onopen = () => { setError(null); };
      wsRef.current.onmessage = (event) => {
        const liveData = JSON.parse(event.data);
        
        setResults((prev) => {
          if (!prev) return liveData;
          const combinedRecords = [...liveData.records, ...(prev.records || [])].slice(0, 100);
          return {
            ...liveData,
            total_packets: (prev.total_packets || 0) + liveData.total_packets,
            anomaly_count: (prev.anomaly_count || 0) + liveData.anomaly_count,
            leak_count: (prev.leak_count || 0) + (liveData.leak_count || 0),
            records: combinedRecords
          };
        });

        const now = new Date().toLocaleTimeString();
        const anomalies = liveData.anomaly_count || 0;
        const total = liveData.total_packets || 0;
        const normal = total - anomalies;

        setChartData((prev) => {
          const newDataPoint = { time: now, Normal: normal, Anomalies: anomalies };
          return [...prev, newDataPoint].slice(-20);
        });

      };
      wsRef.current.onerror = () => {
        setError("WebSocket connection failed. Ensure backend is running.");
        setIsLive(false);
      };
    } else {
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    }
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, [isLive]);

  // NEW: Logic to filter the records before displaying them
  const filteredRecords = results?.records ? results.records.filter(pkt => {
    const matchIP = filterIP === '' || pkt.src_ip.includes(filterIP) || pkt.dst_ip.includes(filterIP);
    const matchProtocol = filterProtocol === '' || pkt.protocol.toLowerCase() === filterProtocol.toLowerCase();
    
    let statusMatch = true;
    if (filterStatus === 'suspicious') statusMatch = pkt.is_anomalous;
    else if (filterStatus === 'malware') statusMatch = pkt.is_malware_tunnel;
    else if (filterStatus === 'leak') statusMatch = pkt.is_leaked;
    else if (filterStatus === 'clean') statusMatch = !pkt.is_anomalous && !pkt.is_malware_tunnel && !pkt.is_leaked;

    return matchIP && matchProtocol && statusMatch;
  }) : [];

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#f8fafc', padding: '2rem' }}>
      <header style={{ marginBottom: '2rem', borderBottom: '1px solid #334155', paddingBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
          <ShieldAlert color="#38bdf8" /> Kanad S.H.I.E.L.D. Platform
        </h1>
        <button 
          onClick={() => { 
            if (!isLive) {
              setResults({ total_packets: 0, anomaly_count: 0, leak_count: 0, records: [] });
              setChartData([]); 
            }
            setIsLive(!isLive); 
          }}
          style={{ backgroundColor: isLive ? '#ef4444' : '#1e293b', color: '#fff', border: `1px solid ${isLive ? '#ef4444' : '#475569'}`, padding: '0.5rem 1rem', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 'bold' }}
        >
          <Wifi size={18} /> {isLive ? 'STOP LIVE SENSOR' : 'START LIVE SENSOR'}
        </button>
      </header>

      {!isLive && (
        <div style={{ backgroundColor: '#1e293b', border: '1px dashed #475569', borderRadius: '8px', padding: '2rem', textAlign: 'center', marginBottom: '2rem' }}>
          <form onSubmit={handleUpload}>
            <UploadCloud size={40} color="#38bdf8" style={{ margin: '0 auto 1rem auto' }} />
            <input type="file" accept=".pcap,.pcapng" onChange={handleFileChange} style={{ marginBottom: '1rem' }} />
            <br />
            <button type="submit" disabled={!file || loading} style={{ backgroundColor: '#0284c7', color: '#fff', border: 'none', padding: '0.6rem 1.5rem', borderRadius: '6px', cursor: 'pointer' }}>
              {loading ? 'Analyzing Traffic...' : 'Upload Offline PCAP'}
            </button>
          </form>
          {error && <p style={{ color: '#f87171', marginTop: '1rem' }}>{error}</p>}
        </div>
      )}

      {results && (
        <div>
          <div style={{ padding: '1rem', backgroundColor: '#1e293b', borderRadius: '6px', marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
              <strong>Evidence Source:</strong> {results.sha256 ? `SHA-256: ${results.sha256}` : 'Live Network Interface Capture'}
            </div>
            <button onClick={handleDownloadReport} disabled={results.total_packets === 0} style={{ backgroundColor: '#22c55e', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold', opacity: results.total_packets === 0 ? 0.5 : 1 }}>
              Export Evidence (PDF)
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
            <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #38bdf8' }}>
              <Database size={18} /> <h3>{results.total_packets} Scanned</h3>
            </div>
            <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #ef4444' }}>
              <ShieldAlert size={18} /> <h3 style={{ color: '#ef4444' }}>{results.anomaly_count} Anomalies</h3>
            </div>
            <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #f59e0b' }}>
              <FileWarning size={18} /> <h3 style={{ color: '#f59e0b' }}>{results.leak_count || 0} Data Leaks</h3>
            </div>
          </div>

          {isLive && chartData.length > 0 && (
            <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', padding: '1.5rem', marginBottom: '2rem', height: '350px' }}>
              <h3 style={{ marginBottom: '1rem' }}>Real-Time Traffic Analysis</h3>
              <ResponsiveContainer width="100%" height="90%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                  <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} tickMargin={10} />
                  <YAxis stroke="#94a3b8" fontSize={12} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#fff' }} />
                  <Legend verticalAlign="top" height={36} />
                  <Line type="monotone" dataKey="Normal" stroke="#38bdf8" strokeWidth={3} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="Anomalies" stroke="#ef4444" strokeWidth={3} dot={false} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', padding: '1rem', overflowX: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3>{results.sha256 ? 'Network Flow Records' : 'Live Sensor Feed'}</h3>
              
              {/* NEW: Filter Control Bar */}
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <Filter size={16} color="#94a3b8" />
                <input 
                  type="text" 
                  placeholder="Filter by IP..." 
                  value={filterIP} 
                  onChange={(e) => setFilterIP(e.target.value)}
                  style={{ padding: '0.4rem', borderRadius: '4px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#fff', fontSize: '0.85rem' }}
                />
                <select 
                  value={filterProtocol} 
                  onChange={(e) => setFilterProtocol(e.target.value)}
                  style={{ padding: '0.4rem', borderRadius: '4px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#fff', fontSize: '0.85rem' }}
                >
                  <option value="">All Protocols</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="OTHER">Other</option>
                </select>
                <select 
                  value={filterStatus} 
                  onChange={(e) => setFilterStatus(e.target.value)}
                  style={{ padding: '0.4rem', borderRadius: '4px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#fff', fontSize: '0.85rem' }}
                >
                  <option value="">All Statuses</option>
                  <option value="suspicious">AI Suspicious</option>
                  <option value="malware">Malware Tunnel</option>
                  <option value="leak">Data Leak</option>
                  <option value="clean">Clean Traffic</option>
                </select>
              </div>
            </div>

            <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #334155' }}>
                  <th style={{ padding: '0.75rem' }}>Time</th>
                  <th style={{ padding: '0.75rem' }}>Protocol</th>
                  <th style={{ padding: '0.75rem' }}>Source</th>
                  <th style={{ padding: '0.75rem' }}>Destination</th>
                  <th style={{ padding: '0.75rem' }}>Length</th>
                  <th style={{ padding: '0.75rem' }}>AI Verdict</th>
                  <th style={{ padding: '0.75rem' }}>DLP Status</th>
                  <th style={{ padding: '0.75rem' }}>JA3 Fingerprint</th>
                </tr>
              </thead>
              <tbody>
                {/* NEW: Map over filteredRecords instead of results.records */}
                {filteredRecords.length > 0 ? filteredRecords.map((pkt, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #334155', color: (pkt.is_anomalous || pkt.is_malware_tunnel) ? '#ef4444' : (pkt.is_leaked ? '#f59e0b' : '#f8fafc') }}>
                    <td style={{ padding: '0.75rem' }}>{new Date(pkt.timestamp * 1000).toLocaleTimeString()}</td>
                    <td style={{ padding: '0.75rem' }}>{pkt.protocol}</td>
                    <td style={{ padding: '0.75rem' }}>{pkt.src_ip}:{pkt.src_port}</td>
                    <td style={{ padding: '0.75rem' }}>{pkt.dst_ip}:{pkt.dst_port}</td>
                    <td style={{ padding: '0.75rem' }}>{pkt.length} B</td>
                    <td style={{ padding: '0.75rem', fontWeight: pkt.is_anomalous ? 'bold' : 'normal' }}>{pkt.is_anomalous ? 'SUSPICIOUS' : 'Normal'}</td>
                    <td style={{ padding: '0.75rem', fontWeight: 'bold' }}>{pkt.is_malware_tunnel ? 'MALWARE TUNNEL' : (pkt.is_leaked ? pkt.leak_type : 'Clean')}</td>
                    <td style={{ padding: '0.75rem', fontSize: '0.8rem', color: pkt.is_malware_tunnel ? '#ef4444' : '#94a3b8' }}>{pkt.ja3_hash ? pkt.ja3_hash : 'N/A'}</td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan="8" style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>
                      No packets match your current filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;