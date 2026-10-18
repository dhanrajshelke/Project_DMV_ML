import React, { useState, useEffect } from 'react';

// Backend Endpoints
const JAVA_API_BASE = 'http://localhost:8085/api';
const PYTHON_API_BASE = 'http://localhost:5000/api/ml';

export default function App() {
  const [currentView, setCurrentView] = useState('traffic'); // 'traffic' | 'analytics' | 'architecture'
  const [loading, setLoading] = useState(false);
  const [servicesStatus, setServicesStatus] = useState({
    java: 'Checking...',
    python: 'Checking...',
    model: 'Loading...'
  });

  // Active dataset name, selected preset, and last scan timestamp
  const [activeDatasetName, setActiveDatasetName] = useState('sample_benchmark_traffic.csv');
  const [selectedPreset, setSelectedPreset] = useState('benchmark');
  const [lastScanCompleted, setLastScanCompleted] = useState(null);
  const [scanCompletedNotice, setScanCompletedNotice] = useState(null);
  
  // Real-time Scanning Progress State (Prominent visual feedback)
  const [scanningProgress, setScanningProgress] = useState(0);
  const [scanningStepIndex, setScanningStepIndex] = useState(0);

  const [triageData, setTriageData] = useState(null);
  const [auditLog, setAuditLog] = useState([]);
  const [activeModalRecord, setActiveModalRecord] = useState(null);
  const [validationError, setValidationError] = useState(null);

  // Search & Filtering
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAttackType, setSelectedAttackType] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  // Check backend health periodically
  useEffect(() => {
    fetchHealthStatus();
    const timer = setInterval(fetchHealthStatus, 6000);
    return () => clearInterval(timer);
  }, []);

  const fetchHealthStatus = async () => {
    try {
      const res = await fetch(`${JAVA_API_BASE}/health`);
      if (res.ok) {
        const data = await res.json();
        setServicesStatus({
          java: data.javaBackendStatus === 'UP' ? 'Active' : 'Offline',
          python: data.pythonMlStatus === 'UP' ? 'Active' : 'Offline',
          model: data.mlDetails?.active_model || 'Random Forest + Isolation Forest'
        });
        return;
      }
    } catch (e) {}

    try {
      const pyRes = await fetch(`${PYTHON_API_BASE}/health`);
      if (pyRes.ok) {
        const pyData = await pyRes.json();
        setServicesStatus({
          java: 'Offline',
          python: 'Active',
          model: pyData.active_model || 'Random Forest + Isolation Forest'
        });
        return;
      }
    } catch (e) {}

    setServicesStatus({
      java: 'Offline',
      python: 'Offline',
      model: 'None'
    });
  };

  // Fetch Java audit history
  const fetchAuditLog = async () => {
    try {
      const res = await fetch(`${JAVA_API_BASE}/threats/history`);
      if (res.ok) {
        const items = await res.json();
        setAuditLog(items);
      }
    } catch (e) {}
  };

  // Robust CSV parser handling \r\n, whitespace, quotes, and numeric conversion
  const parseCsvText = (text) => {
    const rawLines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
    if (rawLines.length < 2) throw new Error('CSV is empty or missing header row.');

    const headers = rawLines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, ''));
    const rows = [];

    for (let i = 1; i < Math.min(rawLines.length, 500); i++) {
      const line = rawLines[i];
      if (!line) continue;
      const cols = line.split(',').map(c => c.trim().replace(/^["']|["']$/g, ''));
      const row = {};
      headers.forEach((h, idx) => {
        const val = cols[idx];
        row[h] = (val !== undefined && val !== '' && !isNaN(Number(val))) ? Number(val) : (val || '');
      });
      rows.push(row);
    }
    return rows;
  };

  // Run threat detection with active progress visualization (2.0s interactive pacing)
  const runDetection = async (customRows = null, filename = 'sample_benchmark_traffic.csv') => {
    setLoading(true);
    setValidationError(null);
    setScanCompletedNotice(null);
    setScanningProgress(15);
    setScanningStepIndex(1); // 1. Ingesting
    setActiveDatasetName(filename);

    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    try {
      // Step 1: Ingesting Telemetry & Parsing 5-Tuples
      await sleep(400);
      setScanningProgress(40);
      setScanningStepIndex(2); // 2. Normalizing 17 Features

      // Trigger backend server request concurrently
      const fetchPromise = (async () => {
        try {
          return await fetch(`${JAVA_API_BASE}/threats/triage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(customRows ? { records: customRows } : {})
          });
        } catch (e) {
          return await fetch(`${PYTHON_API_BASE}/triage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(customRows ? { records: customRows } : {})
          });
        }
      })();

      // Step 2 -> Step 3: ML Model Inference (Random Forest + Isolation Forest)
      await sleep(600);
      setScanningProgress(75);
      setScanningStepIndex(3); // 3. Model Inference

      // Await both backend response and visual progression
      const [res] = await Promise.all([fetchPromise, sleep(700)]);

      if (res) {
        const payload = await res.json();
        if (payload.status === 'VALIDATION_ERROR' || payload.error) {
          setValidationError(payload.error || 'Uploaded dataset does not match network flow schema.');
          setScanningProgress(0);
          setLoading(false);
          return;
        }

        setScanningProgress(100);
        setScanningStepIndex(4); // 4. MITRE ATT&CK Triage Completed
        await sleep(350);

        setTriageData(payload);
        setCurrentPage(1);
        const timeStr = new Date().toLocaleTimeString();
        setLastScanCompleted(timeStr);
        setScanCompletedNotice({
          dataset: filename,
          time: timeStr,
          total: payload.summary?.total_records || 0,
          threats: payload.summary?.suspicious_count || 0,
          pct: payload.summary?.suspicious_percentage || 0
        });
        fetchAuditLog();
        setLoading(false);
        setScanningProgress(0);
      } else {
        alert('Failed to execute analysis. Please ensure backend services are running.');
        setLoading(false);
        setScanningProgress(0);
      }
    } catch (err) {
      console.error(err);
      alert('Network error connecting to backend: ' + err.message);
      setLoading(false);
      setScanningProgress(0);
    }
  };

  // Run a chosen dataset preset directly
  const handleRunDataset = async (presetKey) => {
    if (loading) return;
    const preset = presetKey || selectedPreset;

    let filename = 'sample_benchmark_traffic.csv';
    let url = null;

    if (preset === 'ddos') {
      filename = '1_ddos_attack_traffic.csv';
      url = '/test_datasets/1_ddos_attack_traffic.csv';
    } else if (preset === 'portscan') {
      filename = '2_portscan_recon_traffic.csv';
      url = '/test_datasets/2_portscan_recon_traffic.csv';
    } else if (preset === 'bruteforce') {
      filename = '3_bruteforce_auth_traffic.csv';
      url = '/test_datasets/3_bruteforce_auth_traffic.csv';
    } else if (preset === 'benign') {
      filename = '4_benign_enterprise_traffic.csv';
      url = '/test_datasets/4_benign_enterprise_traffic.csv';
    }

    if (!url) {
      runDetection(null, 'sample_benchmark_traffic.csv');
      return;
    }

    setLoading(true);
    setActiveDatasetName(filename);
    setValidationError(null);
    setScanCompletedNotice(null);
    setScanningProgress(10);
    setScanningStepIndex(1);

    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Could not load preset dataset: ${filename}`);
      const text = await res.text();
      const rows = parseCsvText(text);
      await runDetection(rows, filename);
    } catch (err) {
      console.error(err);
      setValidationError(`Failed to load preset dataset: ${err.message}`);
      setLoading(false);
      setScanningProgress(0);
    }
  };

  // CSV File Upload with robust error catching and event reset
  const handleCsvUpload = (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    setLoading(true);
    setActiveDatasetName(file.name);
    setValidationError(null);
    setScanCompletedNotice(null);
    setScanningProgress(10);
    setScanningStepIndex(1);

    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const text = event.target.result;
        const parsedRows = parseCsvText(text);
        setSelectedPreset('custom');
        await runDetection(parsedRows, file.name);
      } catch (err) {
        setValidationError('CSV Parsing Error: ' + err.message);
        setLoading(false);
        setScanningProgress(0);
      }
    };
    reader.onerror = () => {
      setValidationError('Failed to read selected CSV file.');
      setLoading(false);
      setScanningProgress(0);
    };
    reader.readAsText(file);
  };

  // Export current table view as CSV
  const handleExportCsv = () => {
    if (!filteredRows.length) return alert('No records to export.');
    const headers = ['Record_ID', 'Destination_Port', 'Protocol', 'Model_Prediction', 'Confidence_Pct', 'Threat_Severity', 'Anomaly_Status', 'MITRE_Tactic'];
    const rows = filteredRows.map(r => [
      r.Record_ID,
      r['Destination Port'] || 'N/A',
      r.Protocol === 6 ? 'TCP' : r.Protocol === 17 ? 'UDP' : r.Protocol || 'TCP',
      `"${r['Model Prediction'] || ''}"`,
      r['Prediction Confidence (%)'] || 0,
      r['Threat Severity'] || 'SAFE',
      r['Anomaly Status'] || 'Normal',
      `"${r.MITRE_Tactic || 'Normal'}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const link = document.createElement('a');
    link.setAttribute('href', encodeURI(csvContent));
    link.setAttribute('download', `traffic_analysis_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Run initial detection
  useEffect(() => {
    runDetection();
  }, []);

  const summary = triageData?.summary || {
    total_records: 0,
    normal_count: 0,
    suspicious_count: 0,
    anomaly_count: 0,
    suspicious_percentage: 0
  };
  const dmv = triageData?.dmv_metrics || {};

  // Records Filtering
  const allRows = triageData?.records || [];
  const filteredRows = allRows.filter(r => {
    const matchesSev = severityFilter === 'ALL' || r['Threat Severity'] === severityFilter;
    const pred = String(r['Model Prediction'] || '');
    
    let matchesAttack = true;
    if (selectedAttackType === 'ALL') {
      matchesAttack = true;
    } else if (selectedAttackType === 'BENIGN') {
      matchesAttack = pred.toUpperCase().includes('BENIGN');
    } else if (selectedAttackType === 'BRUTE') {
      matchesAttack = pred.includes('Patator');
    } else {
      matchesAttack = pred.toLowerCase().includes(selectedAttackType.toLowerCase());
    }

    const q = searchTerm.toLowerCase();
    const matchesSearch = !searchTerm ||
      (r.Record_ID && r.Record_ID.toLowerCase().includes(q)) ||
      (r['Model Prediction'] && r['Model Prediction'].toLowerCase().includes(q)) ||
      (r.MITRE_Tactic && r.MITRE_Tactic.toLowerCase().includes(q)) ||
      (String(r['Destination Port']).includes(q));

    return matchesSev && matchesAttack && matchesSearch;
  });

  const totalPages = Math.ceil(filteredRows.length / pageSize) || 1;
  const paginatedRows = filteredRows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  // Attack category counts for quick pills
  const attackCounts = {
    all: allRows.length,
    benign: allRows.filter(r => String(r['Model Prediction']).toUpperCase().includes('BENIGN')).length,
    ddos: allRows.filter(r => String(r['Model Prediction']).includes('DDoS') || String(r['Model Prediction']).includes('DoS')).length,
    portscan: allRows.filter(r => String(r['Model Prediction']).includes('PortScan')).length,
    brute: allRows.filter(r => String(r['Model Prediction']).includes('Patator')).length,
  };

  // Severity category counts for distribution bar
  const sevCounts = {
    critical: allRows.filter(r => r['Threat Severity'] === 'CRITICAL').length,
    high: allRows.filter(r => r['Threat Severity'] === 'HIGH').length,
    medium: allRows.filter(r => r['Threat Severity'] === 'MEDIUM').length,
    safe: allRows.filter(r => r['Threat Severity'] === 'SAFE').length,
  };

  return (
    <div className="app-layout">
      {/* 1. Left Sidebar Navigation */}
      <aside className="app-sidebar">
        <div className="sidebar-header">
          <div className="app-logo">CS</div>
          <div>
            <div className="app-name">CyberSleuth</div>
            <div className="app-tag">Network Threat Analysis</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Monitoring</div>
          <button 
            className={`nav-item ${currentView === 'traffic' ? 'active' : ''}`}
            onClick={() => setCurrentView('traffic')}
          >
            <span>Traffic Logs</span>
          </button>

          <button 
            className={`nav-item ${currentView === 'analytics' ? 'active' : ''}`}
            onClick={() => setCurrentView('analytics')}
          >
            <span>Attack Analytics</span>
          </button>

          <div className="nav-section-label" style={{marginTop: '16px'}}>System</div>
          <button 
            className={`nav-item ${currentView === 'architecture' ? 'active' : ''}`}
            onClick={() => setCurrentView('architecture')}
          >
            <span>Architecture &amp; Auditing</span>
          </button>
        </nav>

        {/* Sidebar Status Footer */}
        <div className="sidebar-footer">
          <div className="service-status-row">
            <span>Spring Boot (:8085)</span>
            <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
              <span className={`status-dot ${servicesStatus.java === 'Active' ? 'active' : 'inactive'}`}></span>
              {servicesStatus.java}
            </span>
          </div>

          <div className="service-status-row">
            <span>Python ML (:5000)</span>
            <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
              <span className={`status-dot ${servicesStatus.python === 'Active' ? 'active' : 'inactive'}`}></span>
              {servicesStatus.python}
            </span>
          </div>

          <div className="user-profile-bar">
            <div className="user-avatar-initials" style={{ background: 'linear-gradient(135deg, #0284C7, #6366F1)', width: '28px', height: '28px' }}>
              GRP
            </div>
            <div>
              <div style={{fontWeight: 600, fontSize: '12px'}}>Project Team Workspace</div>
              <div style={{fontSize: '11px', color: 'var(--fg-subtle)'}}>Group Project &bull; Java &amp; Python ML</div>
            </div>
          </div>
        </div>
      </aside>

      {/* 2. Main Workspace */}
      <div className="main-workspace">
        {/* Top Navbar */}
        <header className="top-navbar">
          <div className="breadcrumb-area">
            <span>CyberSleuth</span>
            <span>/</span>
            <span className="current">
              {currentView === 'traffic' ? 'Traffic Logs' : currentView === 'analytics' ? 'Attack Analytics' : 'System Architecture'}
            </span>
          </div>
          <div style={{display: 'flex', alignItems: 'center', gap: '14px'}}>
            {loading ? (
              <div className="navbar-running-badge">
                <span className="pulse-dot-cyan"></span>
                RUNNING ML CLASSIFICATION ({scanningProgress}%)
              </div>
            ) : lastScanCompleted ? (
              <div className="ready-badge">
                <span className="status-dot active"></span>
                <span>Last Scan: {lastScanCompleted}</span>
              </div>
            ) : null}
            <div style={{fontSize: '12px', color: 'var(--fg-muted)'}}>
              Active File: <strong style={{color: '#38BDF8'}}>{activeDatasetName}</strong>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="page-body">
          {/* Header & Main Actions */}
          <div className="page-header-row">
            <div className="page-title">
              <h1>
                {currentView === 'traffic' && 'Network Traffic Analysis'}
                {currentView === 'analytics' && 'Threat Intelligence & Attack Breakdown'}
                {currentView === 'architecture' && 'Full-Stack Architecture & Audit Logs'}
              </h1>
              <p>
                {currentView === 'traffic' && 'Real-time telemetry classification via Random Forest & Isolation Forest Ensembles.'}
                {currentView === 'analytics' && 'Aggregated statistical distributions, port frequency analysis, and feature importances.'}
                {currentView === 'architecture' && 'Spring Boot 2.7 REST API integration with Scikit-Learn Python ML microservice.'}
              </p>
            </div>

            <div className="page-actions-group">
              <label className="btn btn-default" style={{margin: 0, cursor: loading ? 'not-allowed' : 'pointer'}}>
                Upload Custom CSV
                <input 
                  type="file" 
                  accept=".csv" 
                  onChange={handleCsvUpload} 
                  onClick={(e) => { e.target.value = null; }} 
                  style={{display: 'none'}} 
                  disabled={loading}
                />
              </label>

              <button className="btn btn-default" onClick={handleExportCsv} disabled={loading || !filteredRows.length}>
                Export CSV
              </button>
            </div>
          </div>

          {/* DATASET SELECTION & RUN CONTROL PANEL */}
          <div className="dataset-control-panel">
            <div className="dataset-control-left">
              <span className="dataset-label">Target Dataset:</span>
              <select 
                id="select-dataset"
                value={selectedPreset} 
                onChange={(e) => {
                  setSelectedPreset(e.target.value);
                  handleRunDataset(e.target.value);
                }}
                className="dataset-select"
                disabled={loading}
              >
                <option value="benchmark">Default: Benchmark Network Traffic (200 records)</option>
                <option value="ddos">Dataset 1: DDoS / DoS Attack Floods (200 records)</option>
                <option value="portscan">Dataset 2: PortScan Reconnaissance (200 records)</option>
                <option value="bruteforce">Dataset 3: Patator Brute-Force Auth (200 records)</option>
                <option value="benign">Dataset 4: Benign Safe Enterprise Baseline (200 records)</option>
                {selectedPreset === 'custom' && (
                  <option value="custom">Custom Uploaded: {activeDatasetName}</option>
                )}
              </select>
            </div>

            <div className="dataset-actions">
              <button 
                id="btn-run-dataset"
                className="run-dataset-btn"
                onClick={() => handleRunDataset(selectedPreset)}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="radar-spinner"></span>
                    Running Analysis ({scanningProgress}%)...
                  </>
                ) : (
                  <>
                    <span>▶</span> Run Selected Dataset
                  </>
                )}
              </button>
            </div>
          </div>

          {/* REAL-TIME SCANNING / RUNNING PROGRESS BANNER */}
          {loading && (
            <div className="scanning-card">
              <div className="scanning-header">
                <div className="scanning-title">
                  <span className="radar-spinner"></span>
                  Active Threat Detection &amp; Flow Analysis in Progress...
                </div>
                <div style={{fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#38BDF8', fontWeight: 600}}>
                  {scanningProgress}%
                </div>
              </div>

              <div className="scanning-progress-rail">
                <div 
                  className="scanning-progress-bar"
                  style={{width: `${scanningProgress}%`}}
                ></div>
              </div>

              <div className="scanning-steps">
                <div className={`scanning-step-item ${scanningStepIndex >= 1 ? (scanningStepIndex > 1 ? 'completed' : 'active') : ''}`}>
                  <span>{scanningStepIndex > 1 ? '✓' : '1.'}</span> Ingesting Packet Telemetry
                </div>
                <div className={`scanning-step-item ${scanningStepIndex >= 2 ? (scanningStepIndex > 2 ? 'completed' : 'active') : ''}`}>
                  <span>{scanningStepIndex > 2 ? '✓' : '2.'}</span> Normalizing 17 Features
                </div>
                <div className={`scanning-step-item ${scanningStepIndex >= 3 ? (scanningStepIndex > 3 ? 'completed' : 'active') : ''}`}>
                  <span>{scanningStepIndex > 3 ? '✓' : '3.'}</span> Random Forest &amp; Isolation Forest
                </div>
                <div className={`scanning-step-item ${scanningStepIndex >= 4 ? 'completed' : ''}`}>
                  <span>4.</span> MITRE ATT&amp;CK Triage
                </div>
              </div>
            </div>
          )}

          {/* Scan Completed Notification Banner */}
          {scanCompletedNotice && !loading && (
            <div className="scan-completed-banner">
              <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                <span style={{color: '#10B981', fontWeight: 700}}>✓</span>
                <span>
                  Scan Completed at <strong>{scanCompletedNotice.time}</strong> for <strong>{scanCompletedNotice.dataset}</strong>: 
                  Evaluated <strong>{scanCompletedNotice.total}</strong> flows, flagged <strong>{scanCompletedNotice.threats}</strong> threats ({scanCompletedNotice.pct}% detection ratio).
                </span>
              </div>
              <button 
                className="btn btn-default" 
                style={{padding: '2px 8px', fontSize: '11px'}}
                onClick={() => setScanCompletedNotice(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Dataset Validation Error Banner */}
          {validationError && (
            <div style={{
              backgroundColor: 'var(--color-danger-bg)',
              border: '1px solid var(--color-danger-border)',
              borderRadius: '6px',
              padding: '12px 16px',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              flexWrap: 'wrap'
            }}>
              <div>
                <div style={{fontWeight: 600, color: '#F87171', fontSize: '13px', marginBottom: '2px'}}>
                  Dataset Validation Warning
                </div>
                <div style={{fontSize: '12px', color: 'var(--fg-muted)'}}>
                  {validationError}
                </div>
              </div>
              <button 
                className="btn btn-default"
                style={{fontSize: '12px'}}
                onClick={() => { setValidationError(null); handleRunDataset('benchmark'); }}
              >
                Reset to Benchmark Data
              </button>
            </div>
          )}

          {/* Metric Summary Counters */}
          <div className="stats-container">
            <div className="stat-box">
              <div className="stat-box-label">Total Flows Evaluated</div>
              <div className="stat-box-value">{summary.total_records.toLocaleString()}</div>
              <div className="stat-box-desc">Ingested network flow telemetry</div>
            </div>

            <div className="stat-box">
              <div className="stat-box-label">Attacks Identified</div>
              <div className="stat-box-value" style={{color: summary.suspicious_count > 0 ? '#F87171' : '#34D399'}}>
                {summary.suspicious_count.toLocaleString()}
              </div>
              <div className="stat-box-desc">{summary.suspicious_percentage}% threat detection ratio</div>
            </div>

            <div className="stat-box">
              <div className="stat-box-label">Statistical Anomalies</div>
              <div className="stat-box-value" style={{color: '#FBBF24'}}>
                {summary.anomaly_count.toLocaleString()}
              </div>
              <div className="stat-box-desc">Isolation Forest outlier score &gt; 0.75</div>
            </div>

            <div className="stat-box">
              <div className="stat-box-label">Benign Baseline</div>
              <div className="stat-box-value" style={{color: '#34D399'}}>
                {summary.normal_count.toLocaleString()}
              </div>
              <div className="stat-box-desc">Baseline safe network activity</div>
            </div>
          </div>

          {/* VIEW 1: TRAFFIC LOGS TABLE */}
          {currentView === 'traffic' && (
            <div className="content-box">
              {/* Controls Cluster */}
              <div className="content-box-header">
                <div className="content-box-title">
                  Flow Records ({filteredRows.length})
                </div>

                <div className="controls-cluster">
                  <input 
                    type="text"
                    placeholder="Search flow ID, port, attack..."
                    value={searchTerm}
                    onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                    className="input-text"
                  />

                  <select 
                    value={severityFilter}
                    onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
                    className="input-select"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="SAFE">Safe</option>
                  </select>
                </div>
              </div>

              {/* Segmented Severity Distribution Bar */}
              <div style={{padding: '12px 16px 0'}}>
                <div className="severity-bar-card">
                  <div className="severity-bar-header">
                    <span>Threat Severity Breakdown ({allRows.length} flows)</span>
                    <span>
                      {sevCounts.critical + sevCounts.high + sevCounts.medium} Active Alerts / {sevCounts.safe} Baseline
                    </span>
                  </div>

                  <div className="severity-bar-track">
                    {sevCounts.critical > 0 && (
                      <div 
                        className="sev-segment critical" 
                        style={{width: `${(sevCounts.critical / (allRows.length || 1)) * 100}%`}}
                        title={`Critical: ${sevCounts.critical}`}
                      ></div>
                    )}
                    {sevCounts.high > 0 && (
                      <div 
                        className="sev-segment high" 
                        style={{width: `${(sevCounts.high / (allRows.length || 1)) * 100}%`}}
                        title={`High: ${sevCounts.high}`}
                      ></div>
                    )}
                    {sevCounts.medium > 0 && (
                      <div 
                        className="sev-segment medium" 
                        style={{width: `${(sevCounts.medium / (allRows.length || 1)) * 100}%`}}
                        title={`Medium: ${sevCounts.medium}`}
                      ></div>
                    )}
                    {sevCounts.safe > 0 && (
                      <div 
                        className="sev-segment safe" 
                        style={{width: `${(sevCounts.safe / (allRows.length || 1)) * 100}%`}}
                        title={`Safe: ${sevCounts.safe}`}
                      ></div>
                    )}
                  </div>

                  <div className="severity-legend">
                    <div className="sev-legend-item">
                      <span className="sev-legend-dot" style={{backgroundColor: '#EF4444'}}></span>
                      <span>Critical: <strong>{sevCounts.critical}</strong> ({allRows.length ? Math.round((sevCounts.critical/allRows.length)*100) : 0}%)</span>
                    </div>
                    <div className="sev-legend-item">
                      <span className="sev-legend-dot" style={{backgroundColor: '#F97316'}}></span>
                      <span>High: <strong>{sevCounts.high}</strong> ({allRows.length ? Math.round((sevCounts.high/allRows.length)*100) : 0}%)</span>
                    </div>
                    <div className="sev-legend-item">
                      <span className="sev-legend-dot" style={{backgroundColor: '#FBBF24'}}></span>
                      <span>Medium: <strong>{sevCounts.medium}</strong> ({allRows.length ? Math.round((sevCounts.medium/allRows.length)*100) : 0}%)</span>
                    </div>
                    <div className="sev-legend-item">
                      <span className="sev-legend-dot" style={{backgroundColor: '#10B981'}}></span>
                      <span>Safe: <strong>{sevCounts.safe}</strong> ({allRows.length ? Math.round((sevCounts.safe/allRows.length)*100) : 0}%)</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Quick Attack Filter Pills */}
              <div style={{padding: '12px 16px 4px'}}>
                <div className="attack-filter-pills">
                  <button 
                    className={`pill-filter-btn ${selectedAttackType === 'ALL' ? 'active' : ''}`}
                    onClick={() => { setSelectedAttackType('ALL'); setCurrentPage(1); }}
                  >
                    All Flows <span className="pill-count">{attackCounts.all}</span>
                  </button>

                  <button 
                    className={`pill-filter-btn ${selectedAttackType === 'DDoS' ? 'active' : ''}`}
                    onClick={() => { setSelectedAttackType('DDoS'); setCurrentPage(1); }}
                  >
                    DDoS / DoS Floods <span className="pill-count">{attackCounts.ddos}</span>
                  </button>

                  <button 
                    className={`pill-filter-btn ${selectedAttackType === 'PortScan' ? 'active' : ''}`}
                    onClick={() => { setSelectedAttackType('PortScan'); setCurrentPage(1); }}
                  >
                    PortScan Recon <span className="pill-count">{attackCounts.portscan}</span>
                  </button>

                  <button 
                    className={`pill-filter-btn ${selectedAttackType === 'BRUTE' ? 'active' : ''}`}
                    onClick={() => { setSelectedAttackType('BRUTE'); setCurrentPage(1); }}
                  >
                    Brute-Force Auth <span className="pill-count">{attackCounts.brute}</span>
                  </button>

                  <button 
                    className={`pill-filter-btn ${selectedAttackType === 'BENIGN' ? 'active' : ''}`}
                    onClick={() => { setSelectedAttackType('BENIGN'); setCurrentPage(1); }}
                  >
                    Safe Baseline <span className="pill-count">{attackCounts.benign}</span>
                  </button>
                </div>
              </div>

              {/* Table */}
              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Record ID</th>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>Model Prediction</th>
                      <th>Confidence</th>
                      <th>Anomaly Status</th>
                      <th>Severity</th>
                      <th>MITRE ATT&amp;CK Tactic</th>
                      <th style={{textAlign: 'right'}}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr>
                        <td colSpan="9" className="table-scanning-cell">
                          <div className="table-scanning-container">
                            <div className="table-radar-disc">
                              <div className="table-radar-hand"></div>
                            </div>
                            <div>
                              <div className="table-scanning-title">
                                Running Machine Learning Threat Classification ({scanningProgress}%)
                              </div>
                              <div className="table-scanning-desc">
                                Processing {activeDatasetName} through Random Forest &amp; Isolation Forest models...
                              </div>
                            </div>
                            <div className="table-progress-rail">
                              <div className="table-progress-bar" style={{ width: `${scanningProgress}%` }}></div>
                            </div>
                            <div className="table-step-text">
                              {scanningStepIndex === 1 && 'Phase 1/4: Ingesting & validating network flow telemetry...'}
                              {scanningStepIndex === 2 && 'Phase 2/4: Computing 17 statistical DMV flow features...'}
                              {scanningStepIndex === 3 && 'Phase 3/4: Executing ensemble classification & anomaly detection...'}
                              {scanningStepIndex === 4 && 'Phase 4/4: Correlating detections with MITRE ATT&CK Matrix...'}
                            </div>
                          </div>
                        </td>
                      </tr>
                    ) : paginatedRows.length === 0 ? (
                      <tr>
                        <td colSpan="9" style={{textAlign: 'center', padding: '24px', color: 'var(--fg-muted)'}}>
                          No records matched the filter criteria.
                        </td>
                      </tr>
                    ) : (
                      paginatedRows.map((r, idx) => {
                        const sev = r['Threat Severity'];
                        const sevClass = sev === 'CRITICAL' || sev === 'HIGH' ? 'tag-danger' :
                                         sev === 'MEDIUM' ? 'tag-warning' : 'tag-success';

                        return (
                          <tr key={idx}>
                            <td style={{fontFamily: 'var(--font-mono)', fontWeight: 500, color: '#38BDF8'}}>
                              {r.Record_ID}
                            </td>
                            <td>{r['Destination Port'] || 'N/A'}</td>
                            <td>{r.Protocol === 6 ? 'TCP' : r.Protocol === 17 ? 'UDP' : r.Protocol || 'TCP'}</td>
                            <td style={{fontWeight: 600}}>{r['Model Prediction']}</td>
                            <td style={{fontFamily: 'var(--font-mono)'}}>{r['Prediction Confidence (%)']}%</td>
                            <td>
                              <span className={`tag ${r['Anomaly Status'] === 'Potentially Anomalous' ? 'tag-warning' : 'tag-neutral'}`}>
                                {r['Anomaly Status']}
                              </span>
                            </td>
                            <td>
                              <span className={`tag ${sevClass}`}>{sev}</span>
                            </td>
                            <td>
                              <span className="tag tag-purple">{r.MITRE_Tactic}</span>
                            </td>
                            <td style={{textAlign: 'right'}}>
                              <button 
                                className="btn btn-default"
                                style={{padding: '3px 9px', fontSize: '11px'}}
                                onClick={() => setActiveModalRecord(r)}
                              >
                                View
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="table-pagination">
                <div>
                  Showing {filteredRows.length === 0 ? 0 : (currentPage - 1) * pageSize + 1} -{' '}
                  {Math.min(currentPage * pageSize, filteredRows.length)} of {filteredRows.length} flows
                </div>

                <div className="pagination-buttons">
                  <button 
                    className="page-number-btn"
                    onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
                    disabled={currentPage === 1}
                  >
                    Prev
                  </button>

                  {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                    const pageNum = i + 1;
                    return (
                      <button
                        key={pageNum}
                        className={`page-number-btn ${currentPage === pageNum ? 'active' : ''}`}
                        onClick={() => setCurrentPage(pageNum)}
                      >
                        {pageNum}
                      </button>
                    );
                  })}

                  <button 
                    className="page-number-btn"
                    onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* VIEW 2: ANALYTICS */}
          {currentView === 'analytics' && (
            <div className="analytics-grid">
              {/* Attack Breakdown */}
              <div className="analytics-card">
                <div className="analytics-card-title">Attack Category Frequency</div>
                {summary.label_breakdown ? (
                  Object.entries(summary.label_breakdown).map(([label, count]) => {
                    const pct = Math.round((count / summary.total_records) * 100);
                    const isBenign = label.toUpperCase().includes('BENIGN');
                    return (
                      <div className="bar-row-item" key={label}>
                        <div className="bar-row-header">
                          <span style={{fontWeight: 600, color: isBenign ? '#34D399' : '#F87171'}}>{label}</span>
                          <span>{count} ({pct}%)</span>
                        </div>
                        <div className="bar-row-track">
                          <div 
                            className="bar-row-progress"
                            style={{
                              width: `${pct}%`,
                              backgroundColor: isBenign ? '#10B981' : '#EF4444'
                            }}
                          ></div>
                        </div>
                      </div>
                    );
                  })
                ) : <p style={{color: 'var(--fg-muted)'}}>No data available.</p>}
              </div>

              {/* Destination Port Distribution */}
              <div className="analytics-card">
                <div className="analytics-card-title">Top Target Destination Ports</div>
                {dmv.port_counts ? (
                  Object.entries(dmv.port_counts).map(([port, count]) => {
                    const pct = Math.round((count / summary.total_records) * 100);
                    const svc = port === '80' ? 'HTTP' :
                                port === '443' ? 'HTTPS' :
                                port === '21' ? 'FTP' :
                                port === '22' ? 'SSH' :
                                port === '3306' ? 'MySQL' :
                                port === '8080' ? 'HTTP-Proxy' : `Port ${port}`;
                    return (
                      <div className="bar-row-item" key={port}>
                        <div className="bar-row-header">
                          <span>{svc} (Port {port})</span>
                          <span>{count} hits ({pct}%)</span>
                        </div>
                        <div className="bar-row-track">
                          <div 
                            className="bar-row-progress"
                            style={{width: `${Math.min(pct * 2, 100)}%`, backgroundColor: '#06B6D4'}}
                          ></div>
                        </div>
                      </div>
                    );
                  })
                ) : <p style={{color: 'var(--fg-muted)'}}>No port telemetry available.</p>}
              </div>

              {/* Feature Importances */}
              <div className="analytics-card">
                <div className="analytics-card-title">Random Forest Feature Importance</div>
                {dmv.feature_importances && dmv.feature_importances.length > 0 ? (
                  dmv.feature_importances.map((item, idx) => {
                    const feat = item.feature || item.Feature || `Feature ${idx + 1}`;
                    const imp = item.importance || item.Importance || 0.1;
                    const pct = Math.round(imp * 100);
                    return (
                      <div className="bar-row-item" key={idx}>
                        <div className="bar-row-header">
                          <span>{feat}</span>
                          <span style={{fontFamily: 'var(--font-mono)'}}>{(imp * 100).toFixed(1)}%</span>
                        </div>
                        <div className="bar-row-track">
                          <div 
                            className="bar-row-progress"
                            style={{width: `${pct * 2.5}%`, backgroundColor: '#8B5CF6'}}
                          ></div>
                        </div>
                      </div>
                    );
                  })
                ) : <p style={{color: 'var(--fg-muted)'}}>Feature metadata loaded.</p>}
              </div>

              {/* Anomaly Distribution */}
              <div className="analytics-card">
                <div className="analytics-card-title">Isolation Forest Anomaly Histogram</div>
                {dmv.anomaly_histogram ? (
                  dmv.anomaly_histogram.map((bin, idx) => (
                    <div className="bar-row-item" key={idx}>
                      <div className="bar-row-header">
                        <span>Range {bin.range}</span>
                        <span>{bin.count} flows</span>
                      </div>
                      <div className="bar-row-track">
                        <div 
                          className="bar-row-progress"
                          style={{
                            width: `${Math.min((bin.count / summary.total_records) * 200, 100)}%`,
                            backgroundColor: idx > 6 ? '#EF4444' : idx > 4 ? '#F59E0B' : '#10B981'
                          }}
                        ></div>
                      </div>
                    </div>
                  ))
                ) : <p style={{color: 'var(--fg-muted)'}}>No histogram available.</p>}
              </div>
            </div>
          )}

          {/* VIEW 3: ARCHITECTURE */}
          {currentView === 'architecture' && (
            <div>
              <div className="content-box" style={{marginBottom: '20px', padding: '16px'}}>
                <div className="content-box-title" style={{marginBottom: '10px'}}>
                  System Microservice Architecture
                </div>
                <p style={{color: 'var(--fg-muted)', fontSize: '13px', marginBottom: '16px'}}>
                  Enterprise integration bridging a Java Spring Boot backend, React client, and Python ML model:
                </p>

                <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px'}}>
                  <div style={{border: '1px solid var(--border-default)', padding: '12px', borderRadius: '6px'}}>
                    <div style={{fontWeight: 600, color: '#38BDF8', marginBottom: '4px'}}>1. Frontend Client</div>
                    <div style={{fontSize: '12px', color: 'var(--fg-muted)'}}>
                      React 18 SPA built with Vite. Handles user inputs, filtering, table pagination, and CSV export.
                    </div>
                    <div style={{marginTop: '8px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--fg-subtle)'}}>
                      PORT: 5173
                    </div>
                  </div>

                  <div style={{border: '1px solid var(--border-default)', padding: '12px', borderRadius: '6px'}}>
                    <div style={{fontWeight: 600, color: '#F59E0B', marginBottom: '4px'}}>2. API Gateway &amp; Service</div>
                    <div style={{fontSize: '12px', color: 'var(--fg-muted)'}}>
                      Java Spring Boot 2.7 REST API. Orchestrates telemetry, manages CORS, audits scan requests in-memory.
                    </div>
                    <div style={{marginTop: '8px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--fg-subtle)'}}>
                      PORT: 8085
                    </div>
                  </div>

                  <div style={{border: '1px solid var(--border-default)', padding: '12px', borderRadius: '6px'}}>
                    <div style={{fontWeight: 600, color: '#8B5CF6', marginBottom: '4px'}}>3. ML Intelligence Service</div>
                    <div style={{fontSize: '12px', color: 'var(--fg-muted)'}}>
                      Python Flask microservice executing pre-trained Random Forest &amp; Isolation Forest inference pipelines.
                    </div>
                    <div style={{marginTop: '8px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--fg-subtle)'}}>
                      PORT: 5000
                    </div>
                  </div>
                </div>
              </div>

              {/* Java Audit Log */}
              <div className="content-box">
                <div className="content-box-header">
                  <div className="content-box-title">Java Backend Scan Audit History</div>
                  <button className="btn btn-default" style={{fontSize: '12px'}} onClick={fetchAuditLog}>
                    Refresh Log
                  </button>
                </div>

                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Scan ID</th>
                        <th>Timestamp</th>
                        <th>Records Evaluated</th>
                        <th>Attacks Flagged</th>
                        <th>Anomalies</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLog.length === 0 ? (
                        <tr>
                          <td colSpan="6" style={{textAlign: 'center', padding: '20px', color: 'var(--fg-muted)'}}>
                            No scans logged in Java memory yet. Click "Run Analysis" to execute a scan.
                          </td>
                        </tr>
                      ) : (
                        auditLog.map((log, i) => (
                          <tr key={i}>
                            <td style={{fontFamily: 'var(--font-mono)', color: '#38BDF8'}}>{log.scanId}</td>
                            <td>{log.timestamp}</td>
                            <td>{log.totalRecords}</td>
                            <td style={{color: log.suspiciousCount > 0 ? '#F87171' : '#34D399', fontWeight: 600}}>{log.suspiciousCount}</td>
                            <td style={{color: '#FBBF24'}}>{log.anomalyCount}</td>
                            <td><span className="tag tag-success">COMPLETED</span></td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* 3. Detail Inspection Modal */}
      {activeModalRecord && (
        <div className="standard-modal-overlay" onClick={() => setActiveModalRecord(null)}>
          <div className="standard-modal" onClick={(e) => e.stopPropagation()}>
            <div className="standard-modal-header">
              <div style={{fontWeight: 600, fontSize: '15px'}}>
                Flow Telemetry: {activeModalRecord.Record_ID}
              </div>
              <button className="modal-close-icon" onClick={() => setActiveModalRecord(null)}>&times;</button>
            </div>

            <div className="standard-modal-body">
              <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px'}}>
                <div style={{background: 'var(--bg-inset)', padding: '12px', borderRadius: '6px'}}>
                  <div style={{fontSize: '11px', color: 'var(--fg-muted)', textTransform: 'uppercase'}}>CLASSIFICATION</div>
                  <div style={{fontWeight: 700, fontSize: '15px', color: '#F87171'}}>{activeModalRecord['Model Prediction']}</div>
                  <div style={{fontSize: '11px', color: 'var(--fg-subtle)'}}>Confidence: {activeModalRecord['Prediction Confidence (%)']}%</div>
                </div>

                <div style={{background: 'var(--bg-inset)', padding: '12px', borderRadius: '6px'}}>
                  <div style={{fontSize: '11px', color: 'var(--fg-muted)', textTransform: 'uppercase'}}>THREAT SEVERITY</div>
                  <div style={{fontWeight: 700, fontSize: '15px', color: '#FBBF24'}}>{activeModalRecord['Threat Severity']}</div>
                  <div style={{fontSize: '11px', color: 'var(--fg-subtle)'}}>Anomaly Score: {activeModalRecord['Anomaly Score']}</div>
                </div>
              </div>

              <div style={{border: '1px solid var(--border-default)', padding: '14px', borderRadius: '6px', marginBottom: '14px'}}>
                <div style={{fontWeight: 600, color: '#C084FC', marginBottom: '4px'}}>
                  MITRE ATT&amp;CK Tactic: {activeModalRecord.MITRE_Tactic}
                </div>
                <p style={{color: 'var(--fg-muted)', fontSize: '12px', lineHeight: '1.4'}}>
                  Adversary flows classified as <strong>{activeModalRecord['Model Prediction']}</strong> target port <strong>{activeModalRecord['Destination Port']}</strong>.
                  Recommended remediation: Configure stateful firewall ingress rules and verify host authentication logs.
                </p>
              </div>
            </div>

            <div className="standard-modal-footer">
              <button className="btn btn-default" onClick={() => setActiveModalRecord(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
