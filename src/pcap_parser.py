"""
PCAP Parser Module (Optional Flow Feature Extraction)
Uses Scapy to read PCAP packet captures and aggregate packet streams into bidirectional
network flow metrics (5-tuple: source/dest IP, source/dest port, transport protocol).
"""

from typing import Tuple, Optional, Dict, Any, List
import pandas as pd
import numpy as np


def is_scapy_available() -> bool:
    """Check if Scapy is installed and importable."""
    try:
        import scapy.all as scapy
        return True
    except ImportError:
        return False


def extract_flows_from_pcap(
    file_or_bytes: Any,
    max_packets: int = 5000
) -> Tuple[Optional[pd.DataFrame], Optional[Dict[str, Any]], Optional[str]]:
    """
    Parse a PCAP / PCAPNG file and extract aggregated network flow statistics.
    
    Extracts:
    - Destination Port
    - Flow Duration (microseconds)
    - Total Fwd Packets, Total Backward Packets
    - Total Length of Fwd Packets, Total Length of Bwd Packets
    - Fwd Packet Length Mean, Bwd Packet Length Mean
    - Flow Bytes/s, Flow Packets/s
    - SYN Flag Count, ACK Flag Count, RST Flag Count
    - Protocol (6 for TCP, 17 for UDP, 1 for ICMP)
    
    Returns:
    - (DataFrame, metadata_dict, error_string)
    """
    if not is_scapy_available():
        return None, None, (
            "Scapy library is not installed or available. "
            "Please run 'pip install scapy' in your Python environment to enable PCAP parsing."
        )

    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        import tempfile
        import os

        # Save buffer to temp file if uploaded via Streamlit
        temp_path = None
        if hasattr(file_or_bytes, "read"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(file_or_bytes.read())
                temp_path = tmp.name
            packets = rdpcap(temp_path, count=max_packets)
            os.remove(temp_path)
        elif isinstance(file_or_bytes, str):
            packets = rdpcap(file_or_bytes, count=max_packets)
        else:
            return None, None, "Invalid input: expected file path or file-like buffer."

        if len(packets) == 0:
            return None, None, "PCAP capture contains 0 readable IP packets."

        # Aggregate packets into 5-tuple flows
        # Flow Key: (ip_min, ip_max, port_min, port_max, protocol)
        flows: Dict[Tuple, Dict[str, Any]] = {}

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
                
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            pkt_time = float(pkt.time)
            pkt_len = len(pkt)

            src_port = 0
            dst_port = 0
            is_syn = 0
            is_ack = 0
            is_rst = 0

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = tcp_layer.flags
                is_syn = 1 if 'S' in flags else 0
                is_ack = 1 if 'A' in flags else 0
                is_rst = 1 if 'R' in flags else 0
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            # Normalize direction for bidirectional flow
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_id = (src_ip, dst_ip, src_port, dst_port, proto)
                direction = "fwd"
            else:
                flow_id = (dst_ip, src_ip, dst_port, src_port, proto)
                direction = "bwd"

            if flow_id not in flows:
                flows[flow_id] = {
                    "dst_port": dst_port,
                    "proto": proto,
                    "start_time": pkt_time,
                    "end_time": pkt_time,
                    "fwd_pkts": 0,
                    "bwd_pkts": 0,
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,
                    "syn_count": 0,
                    "ack_count": 0,
                    "rst_count": 0
                }

            flow = flows[flow_id]
            flow["end_time"] = max(flow["end_time"], pkt_time)
            flow["syn_count"] += is_syn
            flow["ack_count"] += is_ack
            flow["rst_count"] += is_rst

            if direction == "fwd":
                flow["fwd_pkts"] += 1
                flow["fwd_bytes"] += pkt_len
            else:
                flow["bwd_pkts"] += 1
                flow["bwd_bytes"] += pkt_len

        if len(flows) == 0:
            return None, None, "No IP transport flows found in PCAP."

        flow_records = []
        for flow in flows.values():
            duration_sec = max(flow["end_time"] - flow["start_time"], 1e-6)
            duration_us = duration_sec * 1e6
            tot_pkts = flow["fwd_pkts"] + flow["bwd_pkts"]
            tot_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

            fwd_len_mean = flow["fwd_bytes"] / max(flow["fwd_pkts"], 1)
            bwd_len_mean = flow["bwd_bytes"] / max(flow["bwd_pkts"], 1)
            flow_bytes_s = tot_bytes / duration_sec
            flow_pkts_s = tot_pkts / duration_sec
            avg_pkt_size = tot_bytes / tot_pkts
            down_up_ratio = round(flow["bwd_pkts"] / max(flow["fwd_pkts"], 1), 2)

            flow_records.append({
                "Destination Port": int(flow["dst_port"]),
                "Flow Duration": round(duration_us, 2),
                "Total Fwd Packets": int(flow["fwd_pkts"]),
                "Total Backward Packets": int(flow["bwd_pkts"]),
                "Total Length of Fwd Packets": round(flow["fwd_bytes"], 2),
                "Total Length of Bwd Packets": round(flow["bwd_bytes"], 2),
                "Fwd Packet Length Mean": round(fwd_len_mean, 2),
                "Bwd Packet Length Mean": round(bwd_len_mean, 2),
                "Flow Bytes/s": round(flow_bytes_s, 2),
                "Flow Packets/s": round(flow_pkts_s, 2),
                "SYN Flag Count": min(flow["syn_count"], 1),
                "ACK Flag Count": min(flow["ack_count"], 1),
                "RST Flag Count": min(flow["rst_count"], 1),
                "Average Packet Size": round(avg_pkt_size, 2),
                "Down/Up Ratio": down_up_ratio,
                "Protocol": int(flow["proto"])
            })

        flow_df = pd.DataFrame(flow_records)
        metadata = {
            "parsed_packets_count": len(packets),
            "extracted_flows_count": len(flow_df),
            "tcp_flows": int((flow_df["Protocol"] == 6).sum()),
            "udp_flows": int((flow_df["Protocol"] == 17).sum()),
            "notice": "Flow records extracted from PCAP. Raw packets are aggregated into 5-tuple flow statistics."
        }

        return flow_df, metadata, None

    except Exception as e:
        return None, None, f"Error parsing PCAP capture: {str(e)}"
