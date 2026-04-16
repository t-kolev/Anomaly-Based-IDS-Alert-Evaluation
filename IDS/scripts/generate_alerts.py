#!/usr/bin/env python
import os
import json
from datetime import datetime
from collections import Counter

import pandas as pd
import numpy as np
import joblib

# -------------------------------------------------------------------
# Load trained models and Y_train_balanced
# -------------------------------------------------------------------
print("Loading trained pipeline, kmeans model, and Y_train_balanced...")
pipeline = joblib.load("model/pipeline.pkl")
kmeans = joblib.load("model/kmeans.pkl")
Y_train_balanced = joblib.load("model/Y_train_balanced.pkl")
print("Models and training labels loaded.\n")

# -------------------------------------------------------------------
# Step 5: Dynamic Identification of Port Scan (Reconnaissance) Clusters
# -------------------------------------------------------------------
def identify_portscan_clusters(kmeans_model, Y_train_balanced):
    """
    Dynamically identifies clusters that predominantly represent 'Reconnaissance'
    (treated here as potential port scans) based on the training labels.
    """
    print("Identifying port scan (Reconnaissance) clusters...")
    cluster_labels = {}
    for cluster in range(kmeans_model.n_clusters):
        labels_in_cluster = Y_train_balanced[kmeans_model.labels_ == cluster]
        if len(labels_in_cluster) == 0:
            continue
        label_counts = Counter(labels_in_cluster)
        most_common_label, _ = label_counts.most_common(1)[0]
        cluster_labels[cluster] = most_common_label

    portscan_clusters = [cluster for cluster, label in cluster_labels.items() if label == "Reconnaissance"]

    if not portscan_clusters:
        print("Warning: No clusters predominantly labeled as 'Reconnaissance' were identified.")
    else:
        print(f"Identified port scan (Reconnaissance) clusters: {portscan_clusters}\n")

    return portscan_clusters

# -------------------------------------------------------------------
# Step 7: Alert Generation with Distance Measure
# -------------------------------------------------------------------
def generate_alert_json(row):
    """
    Creates an alert JSON object for a single flow (row).
    Dynamically adjusts severity, action, and signature ID based on the characteristics of the flow.
    """

    timestamp = datetime.utcnow().isoformat() + "Z"
    flow_id = hash((row["srcip"], row["dstip"], row["sport"], row["dsport"], row["proto"]))

    # Basiswerte
    severity = 1  # Standard: niedrig
    action = "allowed"
    signature_id = 100001
    signature = "ET SCAN Possible scan detected"

    # Bedingungen für die dynamische Anpassung der Severity
    if row["proto"].upper() == "OTHER":
        severity = max(severity, 2)  # Erhöhe auf mittlere Schwere

    if row.get("Spkts", 0) > 10 or row.get("Dpkts", 0) > 10:
        severity = max(severity, 2)  # Mehr Pakete → Verdächtiger

    if row.get("sbytes", 0) > 1000 or row.get("dbytes", 0) > 1000:
        severity = max(severity, 3)  # Großes Datenvolumen → Erhöhte Schwere

    if int(row["dsport"]) in [53, 22, 3389, 445]:
        severity = max(severity, 3)  # Ziel: DNS, SSH, RDP, SMB → Hochrelevant

    # Aktion anpassen
    if severity == 3:
        action = "blocked"  # Hohe Schwere → Blockieren

    # Signature ID je nach Schwere anpassen
    if severity == 2:
        signature_id = 100002  # Mittlere Bedrohung
    elif severity == 3:
        signature_id = 100003  # Hohe Bedrohung

    alert = {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "in_iface": "enp0s3",
        "event_type": "alert",
        "src_ip": row["srcip"],
        "src_port": int(row["sport"]),
        "dest_ip": row["dstip"],
        "dest_port": int(row["dsport"]),
        "proto": row["proto"].upper(),
        "pkt_src": "unsw_nb15_csv",
        "alert": {
            "action": action,
            "gid": 1,
            "signature_id": signature_id,
            "rev": 0,
            "signature": signature,
            "category": "",
            "severity": severity
        },
        "flow_info": {
            "state": row.get("state", ""),
            "duration": row.get("dur", 0),
            "sbytes": row.get("sbytes", 0),
            "dbytes": row.get("dbytes", 0),
            "sttl": row.get("sttl", 0),
            "Sload": row.get("Sload", 0),
            "Dload": row.get("Dload", 0),
            "Spkts": row.get("Spkts", 0),
            "Dpkts": row.get("Dpkts", 0),
            "swin": row.get("swin", 0),
            "dwin": row.get("dwin", 0),
            "smeansz": row.get("smeansz", 0),
            "dmeansz": row.get("dmeansz", 0),
            "trans_depth": row.get("trans_depth", 0),
            "Stime": row.get("Stime", 0),
            "Ltime": row.get("Ltime", 0),
            "Sintpkt": row.get("Sintpkt", 0),
            "Dintpkt": row.get("Dintpkt", 0),
            "tcprtt": row.get("tcprtt", 0),
            "is_sm_ips_ports": row.get("is_sm_ips_ports", 0),
            "service": row.get("service", "-")
        },
        "distance_to_centroid": row.get("distance_to_centroid", "unknown")
    }

    return alert


def predict_port_scans_and_generate_alerts_for_csv(final_csv_path, pipeline, kmeans,
                                                   portscan_clusters, alerts_dir, max_alerts=10):
    """
    Reads a final CSV file, transforms the data, predicts clusters, computes the
    distance to the nearest centroid, flags flows as port scans based on cluster membership,
    and writes up to max_alerts JSON alert files into alerts_dir.
    """
    print(f"Processing final CSV: {final_csv_path}")
    df = pd.read_csv(final_csv_path)

    significant_features = [
        "sport", "dsport", "proto", "sbytes", "dbytes", "smeansz",
        "dmeansz", "Sload", "Dload", "is_sm_ips_ports", "swin", "dwin", "dur", "tcprtt"
    ]
    df[significant_features] = df[significant_features].fillna(0)

    processed_features = pipeline.transform(df[significant_features])
    predicted_clusters = kmeans.predict(processed_features)
    df["predicted_cluster"] = predicted_clusters

    distances = kmeans.transform(processed_features)
    df["distance_to_centroid"] = np.min(distances, axis=1)
    df["is_portscan"] = df["predicted_cluster"].apply(
        lambda cluster: 1 if cluster in portscan_clusters else 0
    )

    scan_counts = Counter(df["is_portscan"])

    os.makedirs(alerts_dir, exist_ok=True)
    alert_count = 0
    for idx, row in df[df["is_portscan"] == 1].iterrows():
        if alert_count >= max_alerts:
            break
        alert = generate_alert_json(row)
        alert_file_path = os.path.join(alerts_dir, f"alert_{idx}.json")
        with open(alert_file_path, "w") as f:
            json.dump(alert, f, indent=4)
        alert_count += 1

    print(f"{alert_count} alert(s) generated in the directory '{alerts_dir}'.\n")
    return df, scan_counts

# -------------------------------------------------------------------
# Main Script (Alert Generation)
# -------------------------------------------------------------------
if __name__ == '__main__':
    print("=== Starting the Alert Generation Script ===\n")

    # Dynamically identify the port scan clusters from training data.
    portscan_clusters = identify_portscan_clusters(kmeans, Y_train_balanced)

    # The directory containing the final CSVs generated by your previous processing.
    final_csvs_dir = "/app/final_csvs"
    if not os.path.exists(final_csvs_dir):
        print(f"Final CSVs directory '{final_csvs_dir}' does not exist. Exiting.")
        exit(1)

    # Base directory where alert files will be written.
    base_alerts_dir = "CaseManagement/alerts"  # This can be an absolute or relative path.
    os.makedirs(base_alerts_dir, exist_ok=True)

    # Process each CSV file in the final CSV directory.
    for csv_file in os.listdir(final_csvs_dir):
        if csv_file.endswith(".csv"):
            final_csv_path = os.path.join(final_csvs_dir, csv_file)
            base_name = csv_file.split("_unsw_nb15_final")[0]
            # Create an alerts directory for this PCAP.
            alerts_dir = os.path.join(base_alerts_dir, base_name)
            os.makedirs(alerts_dir, exist_ok=True)

            parsed_data, scan_counts = predict_port_scans_and_generate_alerts_for_csv(
                final_csv_path, pipeline, kmeans, portscan_clusters,
                alerts_dir=alerts_dir, max_alerts=5
            )

            print(f"Port Scan Prediction Results for {csv_file}: {scan_counts}")

    print("\n=== Alert Generation Script Completed ===")
