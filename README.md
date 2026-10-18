# 🛡️ CyberSleuth: Cyber Threat Intelligence & DMV Platform

[![Java Version](https://img.shields.io/badge/Java-1.8%20%7C%208-ED8B00.svg?logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Backend-Spring%20Boot%202.7-6DB33F.svg?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Academic%20Use-green.svg)]()

An enterprise-grade, three-tier full-stack Cyber Threat Intelligence (CTI) and Data Mining & Visualization (DMV) platform. Designed for network-flow intrusion triage, anomaly scoring, and MITRE ATT&CK correlation.

---

## 📑 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Three-Tier Full-Stack Architecture](#2-three-tier-full-stack-architecture)
3. [Key Features](#3-key-features)
4. [Directory Structure](#4-directory-structure)
5. [One-Click Startup](#5-one-click-startup)
6. [Datasets and Verification](#6-datasets-and-verification)
7. [API Endpoints](#7-api-endpoints)
8. [Using the Platform](#8-using-the-platform)
9. [Interpreting Predictions and Anomaly Scores](#9-interpreting-predictions-and-anomaly-scores)
10. [Suitable Public Datasets](#10-suitable-public-datasets)
11. [Limitations and Future Work](#11-limitations-and-future-work)

---

## 1. Project Overview

Modern Security Operations Centers (SOCs) must analyze large volumes of network telemetry while minimizing alert fatigue.

**CyberSleuth** provides the following capabilities:

- **Network Flow Validation:** Validates network-flow parameters and checks uploaded CSV files for relevant network-traffic features.
- **Machine Learning Classification:** Classifies network traffic into attack categories such as DDoS, PortScan, brute-force attacks, and benign traffic.
- **Anomaly Detection:** Uses Isolation Forest to identify unusual network traffic patterns.
- **MITRE ATT&CK Correlation:** Associates detected threats with relevant enterprise tactics and techniques.
- **Threat Analysis:** Presents predictions, anomaly scores, severity indicators, and investigation information.
- **Report Generation:** Supports the generation of threat-intelligence reports and enriched datasets.

---

## 2. Three-Tier Full-Stack Architecture

| Tier | Technology | Port | Responsibilities |
|---|---|---|---|
| Frontend | React 18, Vite, CSS | `5173` | Security dashboard, traffic scanning, filtering, visualizations, and CSV export |
| API Gateway | Java, Spring Boot, Maven | `8085` | REST API, CORS configuration, error handling, and scan history |
| ML Intelligence | Python, Flask, Scikit-learn | `5000` | ML inference, anomaly scoring, traffic validation, and DMV statistics |

### Architecture Flow

```text
User
  |
  v
React Frontend (Port 5173)
  |
  v
Java Spring Boot API (Port 8085)
  |
  v
Python Flask ML Service (Port 5000)
  |
  v
Prediction, Anomaly Detection, and Threat Analysis
```

---

## 3. Key Features

### Network Traffic Analysis
- Load and validate network-traffic datasets.
- Analyze network-flow characteristics.
- Identify potentially suspicious traffic.
- Review traffic classifications and anomaly scores.

### Machine Learning
- Supervised multi-class traffic classification.
- Random Forest model inference.
- Isolation Forest anomaly detection.
- Model training and saved-model support.

### Threat Intelligence
- Attack-category classification.
- Threat severity assessment.
- MITRE ATT&CK-related analysis.
- Suggested mitigation information.

### Visualization and Reporting
- Security operations dashboard.
- Threat-distribution visualizations.
- Network-flow inspection.
- CSV export and PDF report generation.

---

## 4. Directory Structure

```text
PROJECT_DMV_ML/
├── client/
│   ├── public/
│   │   └── test_datasets/
│   └── src/
│       ├── App.jsx
│       ├── index.css
│       ├── main.jsx
│       └── assets/
├── server/
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/cybersleuth/
│       │   ├── CyberSecurityApplication.java
│       │   ├── config/
│       │   ├── controller/
│       │   └── service/
│       └── resources/
│           └── application.properties
├── ml-service/
│   └── app.py
├── src/
│   ├── train_model.py
│   ├── prediction.py
│   ├── threat_analysis.py
│   ├── anomaly_detection.py
│   ├── data_loader.py
│   ├── pcap_parser.py
│   ├── preprocessing.py
│   ├── report_generator.py
│   └── visualization.py
├── data/
│   ├── sample_network_traffic.csv
│   ├── generate_sample_data.py
│   └── test_datasets/
├── models/
├── reports/
├── tests/
├── requirements.txt
├── run_all.bat
├── run_all.ps1
└── README.md
```

---

## 5. One-Click Startup

### Prerequisites

Install the required software:

- Python and pip
- Node.js and npm
- Java Development Kit compatible with your Spring Boot configuration
- Maven, or use the Maven wrapper if your project includes one

### Step 1: Install Python dependencies

From the project root:

```bash
pip install -r requirements.txt
```

### Step 2: Install frontend dependencies

```bash
cd client
npm install
cd ..
```

### Step 3: Start the application

On Windows, run:

```bat
run_all.bat
```

Alternatively, use PowerShell:

```powershell
.\run_all.ps1
```

These scripts should start the required services if they are configured correctly.

### Step 4: Open the application

Open the frontend in your browser:

**http://localhost:5173**

The configured service endpoints are:

- Frontend: `http://localhost:5173`
- Java API health endpoint: `http://localhost:8085/api/health`
- Python ML health endpoint: `http://localhost:5000/api/ml/health`

Endpoint availability depends on the actual implementation and service configuration.

---

## 6. Datasets and Verification

The project includes sample network-traffic data and test datasets for evaluating traffic classification.

Example datasets:

```text
data/
├── sample_network_traffic.csv
└── test_datasets/
    ├── 1_ddos_attack_traffic.csv
    ├── 2_portscan_recon_traffic.csv
    ├── 3_bruteforce_auth_traffic.csv
    └── 4_benign_enterprise_traffic.csv
```

### Testing Recommendations

1. Load a sample dataset.
2. Confirm that its columns are recognized by the application.
3. Run the prediction pipeline.
4. Review predicted attack categories and anomaly scores.
5. Compare results against the known dataset labels where available.
6. Export a report and review its contents.

---

## 7. API Endpoints

The project is configured to use separate Java and Python services.

| Service | Endpoint | Purpose |
|---|---|---|
| Java API | `/api/health` | Health check |
| Python ML | `/api/ml/health` | ML-service health check |

Base URLs:

- Java: `http://localhost:8085`
- Python: `http://localhost:5000`

For additional endpoints, refer to the controller and service implementations in the project source code.

---

## 8. Using the Platform

### A. Traffic Analysis
1. Open the web dashboard.
2. Select or upload an appropriate network-traffic dataset.
3. Start the analysis.
4. Review the resulting classifications and statistics.

### B. Model Evaluation
1. Train or load the configured model.
2. Review the available evaluation metrics.
3. Examine the confusion matrix and feature-importance results if implemented.
4. Compare predictions against known labels.

### C. Threat Detection
1. Review evaluated flows and potentially suspicious records.
2. Filter traffic by attack category or severity if supported.
3. Inspect relevant network-flow attributes.
4. Review model explanations and mitigation recommendations.

### D. Attack Pattern Analysis
1. Review the distribution of detected traffic patterns.
2. Explore available plots and statistical summaries.
3. Examine anomalous flows.
4. Review associated MITRE ATT&CK information where implemented.

### E. Report Generation
1. Run the analysis on a dataset.
2. Review the generated report preview if available.
3. Export the enriched CSV or PDF report if supported by the application.

---

## 9. Interpreting Predictions and Anomaly Scores

| Classification Field | Values / Range | Meaning |
|---|---|---|
| Model Prediction | `BENIGN`, `PortScan`, `DDoS`, and other configured classes | Predicted traffic category |
| Prediction Confidence | `0%–100%`, when available | Model-reported confidence or class probability |
| Potentially Suspicious | `Yes` / `No`, if implemented | Indicator for traffic requiring further review |
| Anomaly Score | Depends on the implementation | Numerical measure used to identify unusual traffic |
| Threat Severity | `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, if implemented | Risk category assigned by the application |

The exact interpretation of these values depends on the trained models, preprocessing pipeline, and scoring logic.

---

## 10. Suitable Public Datasets

The following public datasets may be useful for evaluating network intrusion-detection systems:

1. **CIC-IDS2017**
   - Dataset: [Canadian Institute for Cybersecurity — CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
   - Contains labeled network traffic for intrusion-detection research.

2. **UNSW-NB15**
   - Dataset: [UNSW-NB15 Research Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
   - Contains normal and malicious network-traffic records.

3. **KDD Cup 99 / NSL-KDD**
   - Dataset: [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)
   - Commonly used for intrusion-detection research and experimentation.

Check dataset columns, label formats, and preprocessing requirements before using an external dataset with the application.

---

## 11. Limitations and Future Work

### Limitations
- Large packet captures may require substantial CPU time and memory.
- Models may perform differently on network traffic that differs from their training data.
- Predictions can contain false positives and false negatives.
- Results depend on data quality, feature extraction, preprocessing, and model performance.

### Future Enhancements
- SHAP-based model explainability.
- STIX/TAXII threat-intelligence integration.
- Real-time network monitoring.
- Improved evaluation across multiple public datasets.
- Enhanced alerting and security-dashboard capabilities.

### Academic and Forensic Disclaimer

CyberSleuth is intended for academic, research, and defensive security analysis. Machine learning predictions and anomaly indicators are probabilistic results, not definitive proof of a security incident. Confirm important findings using appropriate logs, packet analysis, and additional threat-intelligence sources.

---

## License

Academic and research use. Add a formal license file if you intend to distribute the project under specific licensing terms.
