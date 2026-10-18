"""
Threat Analysis and Intelligence Module
Maps network flow indicators to the MITRE ATT&CK framework, provides heuristic explanations,
identifies common port/protocol vectors, and compiles high-level threat intelligence summaries.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


# MITRE ATT&CK Knowledge Mapping
MITRE_ATTACK_MAPPING = {
    "PortScan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary attempts to enumerate active listening services on remote hosts to locate attack vectors.",
        "recommended_mitigation": "Deploy stateful firewall ingress filtering, implement port scan detection (e.g. Snort/Suricata), and rate-limit TCP SYN packets."
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversary sends high volumes of packets across multiple pathways to deplete system bandwidth or state-tables.",
        "recommended_mitigation": "Implement upstream scrubbers (Cloudflare/AWS Shield), configure SYN cookies, and activate dynamic rate-limiting."
    },
    "DoS-Hulk": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversary floods target web server with complex, obfuscated HTTP GET requests to exhaust server threads.",
        "recommended_mitigation": "Implement Web Application Firewall (WAF) request rate limiting, connection pooling timeouts, and bot challenge verification."
    },
    "FTP-Patator": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (FTP)",
        "tactic": "Credential Access",
        "description": "Automated brute-force password guessing against File Transfer Protocol service.",
        "recommended_mitigation": "Disable plaintext FTP in favor of SFTP, enforce account lockout policies, and restrict management ports to trusted VPN IPs."
    },
    "SSH-Patator": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (SSH)",
        "tactic": "Credential Access",
        "description": "High-velocity authentication attempts against Secure Shell service to compromise credentials.",
        "recommended_mitigation": "Enforce SSH key-based authentication, change default SSH port 22, configure Fail2ban, and implement multi-factor authentication (MFA)."
    },
    "Web Attack - SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Injection of SQL syntax into application input fields to compromise backend relational database integrity.",
        "recommended_mitigation": "Use parameterized queries (PreparedStatements), sanitize user inputs, apply least privilege to database service accounts, and deploy WAF rules."
    },
    "Botnet": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": "Compromised host communicates with external Command & Control (C2) controllers over IRC or custom protocol.",
        "recommended_mitigation": "Inspect outbound traffic for periodic beaconing patterns, isolate infected host from local VLAN, and sinkhole suspect C2 domains."
    }
}

PORT_SERVICES = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Shell)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Mail)",
    139: "NetBIOS",
    143: "IMAP (Mail)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (File Sharing)",
    1433: "MS SQL Server",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    6667: "IRC (Chat / Common Botnet C2)",
    8080: "HTTP-Proxy / Alternate Web",
    8443: "HTTPS Alternate",
    9001: "Tor / Custom Port"
}


def get_mitre_mapping(attack_name: str) -> Dict[str, str]:
    """Retrieve MITRE ATT&CK details for a classified attack type."""
    # Direct match or partial search
    for key, val in MITRE_ATTACK_MAPPING.items():
        if key.lower() in attack_name.lower() or attack_name.lower() in key.lower():
            return val
            
    return {
        "technique_id": "T1000",
        "technique_name": "Uncategorized Anomaly / General Exploit",
        "tactic": "Unknown / Zero-Day",
        "description": "Traffic pattern exhibits abnormal flow telemetry that deviates from baseline behavior.",
        "recommended_mitigation": "Capture full packet PCAP for forensic inspection and isolate endpoint if outbound beacons persist."
    }


def explain_flagged_flow(record: pd.Series, top_features: List[str]) -> List[str]:
    """
    Generate readable cyber explanations for why an individual record was flagged.
    """
    reasons = []
    
    # Destination port context
    port = record.get("Destination Port")
    if pd.notnull(port):
        port_int = int(port)
        service = PORT_SERVICES.get(port_int, f"Port {port_int}")
        reasons.append(f"Target Service: {service}")

    # Flow Duration & Packet Rate
    duration = record.get("Flow Duration", 0)
    pkts_s = record.get("Flow Packets/s", 0)
    bytes_s = record.get("Flow Bytes/s", 0)
    
    if pkts_s > 5000:
        reasons.append(f"Unusually high packet transmission rate ({pkts_s:,.0f} pkts/s)")
    if bytes_s > 1e6:
        reasons.append(f"Excessive throughput ({bytes_s/1e6:.2f} MB/s)")
    if duration < 500 and record.get("Total Fwd Packets", 0) <= 2:
        reasons.append("Ephemeral flow duration (<500µs) with minimal packet exchange (characteristic port probe)")

    # TCP Flag heuristics
    syn = record.get("SYN Flag Count", 0)
    ack = record.get("ACK Flag Count", 0)
    rst = record.get("RST Flag Count", 0)
    
    if syn == 1 and ack == 0:
        reasons.append("Incomplete TCP handshake: SYN set without ACK confirmation")
    if rst == 1:
        reasons.append("Connection reset (RST) flag asserted")

    # High anomaly score
    anomaly_score = record.get("Anomaly Score", 0)
    if anomaly_score > 0.75:
        reasons.append(f"Flow telemetry is strongly anomalous (Anomaly Score: {anomaly_score:.2f})")

    if not reasons:
        reasons.append("Classification driven by statistical divergence across multi-dimensional feature space.")

    return reasons


def compile_threat_intelligence_summary(
    df: pd.DataFrame,
    inference_summary: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Synthesize high-level threat intelligence report from analyzed dataset.
    """
    total = len(df)
    suspicious = inference_summary.get("suspicious_count", 0)
    anomalies = inference_summary.get("anomaly_count", 0)
    
    # Top target ports
    port_col = None
    for candidate in ["Destination Port", "Dest Port", "dst_port", "destination_port"]:
        if candidate in df.columns:
            port_col = candidate
            break
            
    top_ports_info = []
    if port_col:
        port_counts = df[port_col].value_counts().head(5)
        for p, count in port_counts.items():
            try:
                p_int = int(p)
                svc = PORT_SERVICES.get(p_int, f"Port {p_int}")
                top_ports_info.append({"port": p_int, "service": svc, "hits": int(count)})
            except (ValueError, TypeError):
                continue

    # Detected attack types (excluding BENIGN)
    pred_col = "Model Prediction" if "Model Prediction" in df.columns else None
    detected_attacks = []
    if pred_col:
        breakdown = df[pred_col].value_counts()
        for label, count in breakdown.items():
            if str(label).strip().upper() not in ['BENIGN', 'NORMAL', '0']:
                mitre = get_mitre_mapping(str(label))
                detected_attacks.append({
                    "attack_type": str(label),
                    "count": int(count),
                    "percentage": round((count / total) * 100, 1) if total > 0 else 0,
                    "mitre_id": mitre["technique_id"],
                    "mitre_technique": mitre["technique_name"],
                    "mitre_tactic": mitre["tactic"],
                    "mitigation": mitre["recommended_mitigation"]
                })

    # Generate narrative summary
    if suspicious == 0 and anomalies == 0:
        executive_summary = (
            "Traffic telemetry appears baseline normal. No significant attack signatures or "
            "unusual protocol anomalies were identified across the analyzed records."
        )
    else:
        attack_names = [a["attack_type"] for a in detected_attacks]
        attacks_str = ", ".join(attack_names) if attack_names else "unspecified anomalous flows"
        executive_summary = (
            f"Analysis of {total:,} traffic records revealed {suspicious:,} potentially suspicious flows "
            f"({inference_summary.get('suspicious_percentage', 0):.1f}% of analyzed traffic) and {anomalies:,} statistical anomalies. "
            f"Primary detected threat patterns include: {attacks_str}. Immediate review of exposed edge services "
            f"and firewall rate-limiting policies is recommended."
        )

    return {
        "executive_summary": executive_summary,
        "total_records": total,
        "suspicious_count": suspicious,
        "anomaly_count": anomalies,
        "top_ports": top_ports_info,
        "detected_attacks": detected_attacks
    }
