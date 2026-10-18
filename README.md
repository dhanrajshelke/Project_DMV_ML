# 🛡️ CyberSleuth: Cyber Threat Intelligence & DMV Platform

[![Java Version](https://img.shields.io/badge/Java-1.8%20%7C%208-ED8B00.svg?logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Backend-Spring%20Boot%202.7-6DB33F.svg?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Academic%20Use-green.svg)]()

An enterprise-grade, 3-tier full-stack Cyber Threat Intelligence (CTI) and Data Mining & Visualization (DMV) platform. Designed for network flow intrusion triage, anomaly scoring, and MITRE ATT&CK correlation.

---

## 📑 Table of Contents
1. [Project Overview](#1-project-overview)
2. [3-Tier Full-Stack Architecture](#2-3-tier-full-stack-architecture)
3. [Key Features](#3-key-features)
4. [Clean Directory Structure](#4-clean-directory-structure)
5. [One-Click Startup](#5-one-click-startup)
6. [Datasets & Verification](#6-datasets--verification)
7. [API Endpoints](#7-api-endpoints)

---

## 1. Project Objective

In modern Security Operations Centers (SOCs), network analysts face overwhelming volumes of telemetry and alert fatigue. **CyberSleuth** provides:
- **Strict Network Flow Verification**: Validates 5-tuple network parameters and rejects unrelated CSVs (sales, student marks).
- **Ensemble ML Classification**: Classifies high-dimensional packet flows into specific cyber attack classes (DDoS, PortScan, Brute-Force Patator, Benign).
- **Unsupervised Anomaly Detection**: Isolation Forest identifies zero-day and stealth network traffic anomalies.
- **MITRE ATT&CK Correlation**: Maps every flagged threat to enterprise tactics (Defense Evasion, Discovery, Credential Access, Impact).

---

## 2. 3-Tier Full-Stack Architecture

| Tier | Technology | Port | Responsibilities |
|---|---|---|---|
| **Frontend** | React 18, Vite, Vanilla CSS | `5173` | Handcrafted SOC dark theme, real-time scanning progress bar (0% -> 100%), dataset switcher, severity distribution bar, quick attack filter pills, and CSV export. |
| **API Gateway** | Java Spring Boot 2.7 (Maven) | `8085` | High-throughput REST API, CORS management, error handling, in-memory scan auditing history. |
| **ML Intelligence** | Python Flask, Scikit-Learn | `5000` | Random Forest inference, Isolation Forest anomaly scoring, 17-parameter DMV statistical distributions, and dataset validation. |

---

## 3. Clean Directory Structure

```text
PROJECT_DMV_ML/
├── client/                     # React 18 + Vite Frontend Application (Port 5173)
│   ├── public/test_datasets/   # 4 validated pre-loaded test datasets
│   └── src/
│       ├── App.jsx             # Main SOC Dashboard, scan progress, filtering, modal
│       ├── index.css           # Human-crafted GitHub Dark / SOC theme styles
│       └── main.jsx            # React root mount
├── server/                     # Java Spring Boot 2.7 REST API (Port 8085)
│   ├── pom.xml                 # Maven project configuration (Java 8 compatible)
│   └── src/main/java/com/cybersleuth/
│       ├── CyberSleuthApplication.java
│       ├── controller/ThreatController.java
│       └── service/ThreatService.java
├── ml-service/                 # Python Flask ML & DMV Microservice (Port 5000)
│   └── app.py                  # Model inference, validation, DMV metrics endpoints
├── src/                        # Core Python Machine Learning & DMV Modules
│   ├── train_model.py          # Supervised training & checkpoint loader
│   ├── prediction.py           # Multi-class inference & severity triage
│   ├── threat_analysis.py      # MITRE ATT&CK mapping & heuristic explanations
│   ├── anomaly_detection.py    # Isolation Forest anomaly scoring
│   ├── data_loader.py          # Telemetry cleaning & header normalization
│   └── report_generator.py     # Forensic PDF & CSV report generators
├── data/
│   ├── sample_network_traffic.csv  # Synthetic benchmark dataset
│   └── test_datasets/          # 4 Tested & Validated Attack Datasets:
│       ├── 1_ddos_attack_traffic.csv
│       ├── 2_portscan_recon_traffic.csv
│       ├── 3_bruteforce_auth_traffic.csv
│       └── 4_benign_enterprise_traffic.csv
├── models/                     # Saved Scikit-Learn Random Forest & Isolation Forest bundles
├── reports/                    # Generated forensic threat intelligence reports
├── run_all.bat                 # One-click Windows batch launcher
├── run_all.ps1                 # One-click Windows PowerShell launcher
└── requirements.txt            # Python dependencies
```

---

## 4. One-Click Startup

To launch all 3 tiers with a single command:

### Via Batch File:
```cmd
run_all.bat
```

### Via PowerShell:
```powershell
.\run_all.ps1
```

Once launched, navigate to **`http://localhost:5173`** in your browser. All services will connect automatically:
- Frontend: `http://localhost:5173`
- Java API: `http://localhost:8085/api/health`
- Python ML: `http://localhost:5000/api/ml/health`
   - **Interactive Confusion Matrix** showing exact misclassification rates per category
   - **Top Feature Importance Rankings** showing key predictive metrics
5. Persist the model checkpoint using the **Saved Models Manager** tab.

### C. Automated Threat Detection & Triage (`pages/3_Threat_Detection.py`)
1. Review the high-level triage KPIs: *Evaluated Flows*, *Baseline Normal*, *Potentially Suspicious*, and *Statistical Anomalies*.
2. Filter records using the controls:
   - Check *Display Potentially Suspicious Records Only*
   - Filter by specific attack classes (e.g. `PortScan`, `DDoS`, `Botnet`)
   - Filter by threat severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`)
3. Use the **Network Flow Forensic Inspector**:
   - Choose a flow index from the dropdown.
   - Inspect exact telemetry (e.g., `Port 22 SSH`, `Flow Duration`, `SYN flag without ACK`).
   - Read the model's behavioral justification and recommended mitigation steps.

### D. Attack Pattern Discovery & MITRE ATT&CK (`pages/4_Attack_Patterns.py`)
1. View the **Frequency Table** showing the distribution and MITRE technique alignment of discovered traffic patterns.
2. Explore multi-dimensional clustering in the interactive **Scatter Plot** (`Flow Duration` vs. `Flow Packets/s`).
3. Inspect the **Transport Protocol & Targeted Destination Port** breakdown.
4. Review the **Stealth / Zero-Day Alerts table**: displays flows classified as Benign that exhibited high Isolation Forest anomaly scores.
5. Reference the full **MITRE ATT&CK Remediation Playbook** table.

### E. Exporting Forensic Reports (`pages/5_Reports.py`)
1. Review the **Report Live Preview** detailing dataset parameters, validation metrics, and detected threats.
2. Click **📥 Download Enriched CSV Dataset** to export telemetry augmented with model predictions and anomaly scores.
3. Click **📥 Download Executive PDF Threat Report** to generate and download a publication-ready PDF summary created with ReportLab.

---

## 9. Interpreting Predictions & Anomaly Scores

| Classification Field | Values / Range | Forensic Meaning |
|---|---|---|
| **Model Prediction** | `BENIGN`, `PortScan`, `DDoS`, `FTP-Patator`, `SSH-Patator`, `DoS-Hulk`, `Web Attack`, `Botnet` | Supervised multi-class estimate based on learned statistical flow signatures. |
| **Prediction Confidence** | `0.0% – 100.0%` | Maximum posterior class probability output by the ensemble (`predict_proba`). |
| **Potentially Suspicious** | `Yes` / `No` | Binary flag assigned when the model predicts an attack category or the anomaly score exceeds 0.75. |
| **Anomaly Score** | `0.0 – 1.0` | Normalized decision boundary distance from Isolation Forest. Scores > 0.75 indicate significant statistical deviation from normal flow behavior. |
| **Threat Severity** | `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Compound risk index combining prediction confidence, anomaly score, and threat criticality. |

---

## 10. Suitable Public Datasets

You can download and evaluate real-world intrusion detection datasets with this application:

1. **CIC-IDS2017 (Canadian Institute for Cybersecurity)**:
   - *URL*: [UNB CIC-IDS2017 Repository](https://www.unb.ca/cic/datasets/ids-2017.html)
   - *Files*: `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`, `Wednesday-workingHours.pcap_ISCX.csv`
   - *Compatibility*: Fully compatible. Column headers with leading whitespaces are automatically cleaned.
2. **UNSW-NB15 (University of New South Wales)**:
   - *URL*: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
   - *Compatibility*: Compatible. Select `attack_cat` or `label` as the target column.
3. **KDD-Cup99 / NSL-KDD**:
   - *URL*: [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html)
   - *Compatibility*: Supported after converting raw dumps to CSV with column headers.

---

## 11. Forensic Disclaimer, Limitations & Future Work

### Academic & Forensic Integrity Notice
> **DISCLAIMER:** All predictions, anomaly flags, and threat severity ratings produced by this software are probabilistic outputs generated by Machine Learning models. The software explicitly applies labels such as **"Model Prediction"** and **"Potentially Suspicious"**. These indicators assist security analysts during triage and do **not** constitute definitive proof of cyber compromise without secondary confirmation from endpoint logs, full packet payload inspection (PCAP), and threat intelligence corroboration.

### Known Limitations
- High-volume PCAPs (>100MB) can require significant CPU time for Scapy packet-by-packet parsing. For production environments, flow tools such as `Zeek` or `CICFlowMeter` are recommended.
- Classifiers trained on a specific network topology may exhibit distribution drift when evaluated on networks with drastically different baseline traffic.

### Future Enhancements
- Integration of SHAP (SHapley Additive exPlanations) for local explainability trees.
- Direct STIX 2.1 / TAXII 2.1 threat feed integration.
- Real-time live network interface sniffing with automated alerting triggers.
