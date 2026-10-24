# 🛡️ CyberSleuth: Cyber Threat Intelligence & DMV Platform

🚀 **Live Demo:** https://project-dmv-ml-pmci.vercel.app/

An enterprise-grade, three-tier full-stack Cyber Threat Intelligence (CTI) and Data Mining & Visualization (DMV) platform designed for network-flow intrusion triage, anomaly scoring, and MITRE ATT&CK correlation.

![Java](https://img.shields.io/badge/Java-8-ED8B00?logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-2.7-6DB33F?logo=springboot)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-F7931E?logo=scikitlearn)

## 📌 Project Overview

CyberSleuth is a web-based cybersecurity platform that analyzes network-flow data and identifies potentially malicious traffic using machine learning.

### Key Features

- **Network Flow Validation:** Validates uploaded CSV datasets and checks network-traffic features.
- **Machine Learning Classification:** Classifies traffic into categories such as DDoS, PortScan, Botnet, brute-force attacks, and benign traffic.
- **Anomaly Detection:** Uses Isolation Forest to identify unusual network behavior.
- **Threat Intelligence:** Presents threat categories, severity indicators, and mitigation information.
- **MITRE ATT&CK Correlation:** Associates detected threats with relevant tactics and techniques where implemented.
- **Data Visualization:** Displays traffic statistics, threat distributions, and analysis results.
- **Report Generation:** Supports exporting analysis results and reports where implemented.

## 🏗️ System Architecture

CyberSleuth uses a three-tier architecture.

```text
User
  |
  v
React + Vite Frontend
  |  Hosted on Vercel
  v
Java Spring Boot REST API
  |  Hosted on Render
  v
Python Flask ML Service
  |  Hosted on Render
  v
Machine Learning Inference
  |
  v
Threat Predictions and Analysis Results
```

### Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React 18, Vite, JavaScript, CSS |
| Backend API | Java 8, Spring Boot 2.7 |
| ML Service | Python, Flask |
| Machine Learning | Scikit-learn, Random Forest, Isolation Forest |
| Data Processing | Pandas, NumPy |
| Deployment | Vercel, Render |
| Communication | REST APIs, JSON |

## ⚙️ Main Modules

### 1. Network Traffic Analysis
- Upload and validate network-flow datasets.
- Process network traffic features.
- Analyze traffic records and identify suspicious patterns.

### 2. Machine Learning Classification
- Apply a trained Random Forest model.
- Predict configured network-traffic classes.
- Display classification results for investigation.

### 3. Anomaly Detection
- Use Isolation Forest to identify unusual traffic patterns.
- Generate anomaly indicators for further review.

### 4. Threat Intelligence
- Categorize potentially malicious network traffic.
- Present threat severity and relevant mitigation guidance.
- Provide MITRE ATT&CK-related context where supported.

### 5. Data Mining and Visualization
- Summarize traffic and prediction distributions.
- Visualize detected attack categories.
- Review model results and traffic characteristics.

## 🧠 Supported Model Classes

The deployed model reports these eight classes:

1. `BENIGN`
2. `Botnet`
3. `DDoS`
4. `DoS-Hulk`
5. `FTP-Patator`
6. `PortScan`
7. `SSH-Patator`
8. `Web Attack - SQL Injection`

Predictions depend on the trained model, input features, and preprocessing pipeline.

## 📂 Project Structure

```text
Project_DMV_ML/
├── client/
│   ├── public/
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       ├── index.css
│       └── assets/
├── server/
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/cybersleuth/
│       │   ├── CyberSecurityApplication.java
│       │   ├── controller/
│       │   ├── service/
│       │   └── config/
│       └── resources/
├── ml-service/
│   ├── app.py
│   └── requirements.txt
├── src/
├── data/
├── models/
├── reports/
├── tests/
├── requirements.txt
├── run_all.bat
├── run_all.ps1
└── README.md
```

## 🌐 Live Deployment

**Frontend:** https://project-dmv-ml-pmci.vercel.app/

**GitHub Repository:** https://github.com/dhanrajshelke/Project_DMV_ML

The frontend is deployed on Vercel, while the Java API and Python ML service run on Render.

## 🔌 API Endpoints

### Java Spring Boot API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Check backend and ML service health |
| POST | `/api/threats/triage` | Run threat analysis |
| GET | `/api/threats/sample-data` | Retrieve sample network data |
| GET | `/api/threats/history` | Retrieve audit history |

### Python ML Service

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/ml/health` | Check ML service and model status |
| GET | `/api/ml/sample-data` | Retrieve sample data |
| POST | `/api/ml/triage` | Run ML-based traffic analysis |

## 🚀 Run Locally

### Prerequisites

Install:
- Python and pip
- Node.js and npm
- Java Development Kit compatible with the project
- Maven, if required by the backend

### Step 1: Install Python Dependencies

From the project root:

```bash
pip install -r requirements.txt
```

### Step 2: Install Frontend Dependencies

```bash
cd client
npm install
```

### Step 3: Start the Services

Use the supplied startup scripts if configured for your environment:

**Windows Command Prompt**
```bat
run_all.bat
```

**PowerShell**
```powershell
.\run_all.ps1
```

Otherwise, start the Java backend, Python ML service, and React frontend using their respective project configurations.

### Step 4: Open the Application

Local frontend: `http://localhost:5173`

Local Java health endpoint: `http://localhost:8085/api/health`

Local Python health endpoint: `http://localhost:5000/api/ml/health`

Actual ports depend on your configuration.

## 📊 Dataset and Testing

The platform supports network-flow CSV datasets that contain compatible traffic features.

Recommended testing process:

1. Load the sample or a compatible CSV dataset.
2. Check whether the dataset columns are recognized.
3. Run the prediction pipeline.
4. Review predicted classes and anomaly indicators.
5. Compare predictions against known labels when available.
6. Review or export analysis results.

Public datasets suitable for research include:

- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)

External datasets may require column mapping and preprocessing before use.

## ⚠️ Limitations

- Machine learning predictions can produce false positives and false negatives.
- Model performance depends on the quality and distribution of training data.
- Unseen network patterns may be classified incorrectly.
- Predictions are indicators for investigation, not definitive proof of an attack.
- Performance depends on dataset size, feature processing, and available resources.

## 🔮 Future Enhancements

- SHAP-based model explainability.
- Real-time network monitoring.
- STIX/TAXII threat-intelligence integration.
- Improved model evaluation across public datasets.
- Enhanced alerting and incident reporting.
- More detailed prediction explanations.

## 🔐 Disclaimer

CyberSleuth is intended for academic, research, and defensive cybersecurity analysis. Use it only with datasets and network traffic you are authorized to analyze. Validate important findings using appropriate logs, packet analysis, and additional threat-intelligence sources.

## 👨‍💻 Author

**Dhanraj Shelke**

GitHub: https://github.com/dhanrajshelke/Project_DMV_ML

---

⭐ If you find this project useful, consider starring the repository.
