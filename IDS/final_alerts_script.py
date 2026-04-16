import os
import json
from datetime import datetime
from collections import Counter

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.sparse import issparse

from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from imblearn.over_sampling import RandomOverSampler
from sklearn.utils import resample

# -------------------------------------------------------------------
# Step 1: Data Ingestion and Preprocessing
# -------------------------------------------------------------------

def load_data(dataset_dir):
    """
    Loads all CSV files from the specified dataset directory, concatenates them,
    cleans the data, and adjusts the attack labels.
    """
    print("Loading data from dataset directory...")
    columns = [
        "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
        "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
        "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
        "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
        "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
        "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", 
        "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label"
    ]
    
    dataframes = []
    for filename in os.listdir(dataset_dir):
        if filename.endswith('.csv'):
            file_path = os.path.join(dataset_dir, filename)
            print(f"Reading file: {file_path}")
            df = pd.read_csv(file_path, header=None, names=columns)
            dataframes.append(df)
    
    data = pd.concat(dataframes, ignore_index=True)
    data['attack_cat'] = data['attack_cat'].str.replace(' ', '', regex=True)
    
    # Convert certain columns to numeric
    data["sport"] = pd.to_numeric(data["sport"], errors='coerce')
    data["dsport"] = pd.to_numeric(data["dsport"], errors='coerce')
    data["Label"] = pd.to_numeric(data["Label"], errors='coerce')
    
    # Fill missing attack labels and set label "Normal" where Label == 0
    data['attack_cat'] = data['attack_cat'].fillna("")
    data['attack_cat'] = np.where(data['Label'] == 0, "Normal", data["attack_cat"])
    
    print(f"\nData loaded.")
    print(f"Class distribution BEFORE balancing: {Counter(data['attack_cat'])}")
    print(f"Number of Reconnaissance samples: {sum(data['attack_cat'] == 'Reconnaissance')}\n")
    return data

# -------------------------------------------------------------------
# Step 2: Splitting and Balancing Data
# -------------------------------------------------------------------

def split_and_balance(data, significant_features, target_samples_per_class=13000,
                      test_size=0.2, random_state=42):
    """
    Splits the data into training and test sets, oversamples the training data to balance classes,
    then downsamples each class to the specified number of samples.
    """
    print("Splitting data into training and test sets...")
    X = data[significant_features]
    Y = data['attack_cat']
    
    X_train, X_test, Y_train, Y_test = train_test_split(
        X, Y, test_size=test_size, random_state=random_state, stratify=Y
    )
    
    print("Oversampling training data to balance classes...")
    ros = RandomOverSampler(random_state=random_state)
    X_train, Y_train = ros.fit_resample(X_train, Y_train)
    
    print("Downsampling each class in the training set to keep the dataset manageable...")
    X_train = X_train.copy()
    X_train["attack_cat"] = Y_train
    balanced_subset = []
    
    for class_label in X_train["attack_cat"].unique():
        class_data = X_train[X_train["attack_cat"] == class_label]
        downsampled = resample(
            class_data, replace=False, n_samples=target_samples_per_class, random_state=random_state
        )
        balanced_subset.append(downsampled)
    
    balanced_data = pd.concat(balanced_subset)
    Y_train_balanced = balanced_data["attack_cat"]
    X_train_balanced = balanced_data.drop(columns=["attack_cat"])
    
    print(f"Balanced training class distribution: {Counter(Y_train_balanced)}\n")
    return X_train_balanced, Y_train_balanced, X_test, Y_test

# -------------------------------------------------------------------
# Step 3: Preprocessing Pipeline
# -------------------------------------------------------------------

def build_preprocessing_pipeline(X_train_balanced):
    """
    Identifies numeric and categorical features, then builds and fits a preprocessing pipeline.
    """
    print("Building and fitting the preprocessing pipeline...")
    categorical_features = X_train_balanced.select_dtypes(include=["object"]).columns.tolist()
    numeric_features = X_train_balanced.select_dtypes(include=[np.number]).columns.tolist()
    
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
        ]
    )
    
    pipeline = Pipeline(steps=[("preprocessor", preprocessor)])
    pipeline.fit(X_train_balanced)
    print("Preprocessing pipeline built and fitted.\n")
    return pipeline


# -------------------------------------------------------------------
# New: Elbow Method for Determining Optimal Number of Clusters
# -------------------------------------------------------------------

def elbow_method(pipeline, X_train_balanced, cluster_range=(2, 40)):
    """
    Uses the Elbow Method to determine the optimal number of clusters.
    """
    print("Starting the Elbow Method to determine the optimal number of clusters...")
    X_train_processed = pipeline.transform(X_train_balanced)
    
    # Convert to dense array if needed
    if hasattr(X_train_processed, "toarray"):
        X_train_processed_dense = X_train_processed.toarray()
    else:
        X_train_processed_dense = X_train_processed  # Already dense
    
    print(f"Type of X_train_processed: {type(X_train_processed)}")
    missing_values = np.isnan(X_train_processed_dense).sum()
    print(f"Number of missing values before cleaning: {missing_values}")
    
    # Replace NaNs with zeros
    X_train_processed_cleaned = np.nan_to_num(X_train_processed_dense, nan=0.0)
    
    inertia = []  # List to store inertia values for different numbers of clusters
    K = range(cluster_range[0], cluster_range[1])
    
    for k in K:
        print(f"Fitting KMeans with {k} clusters...")
        kmeans_temp = KMeans(n_clusters=k, random_state=42, n_init=10)
        kmeans_temp.fit(X_train_processed_cleaned)
        inertia.append(kmeans_temp.inertia_)
    
    # Plot the Elbow curve
    plt.figure(figsize=(12, 6))
    plt.plot(K, inertia, 'bx-')
    plt.xlabel('Number of clusters')
    plt.ylabel('Inertia')
    plt.title('Elbow Method showing the optimal k')
    plt.savefig("elbow.png")
    plt.close()  # Close the figure to free up resources
    print("Figure saved as 'elbow.png'")  # Print a message indicating where the figure is saved.
    print("Elbow Method completed.")



# -------------------------------------------------------------------
# Step 4: Clustering and Visualization
# -------------------------------------------------------------------

def perform_clustering(pipeline, X_train_balanced, Y_train_balanced, optimal_k=33):
    """
    Transforms the training data using the pipeline, runs KMeans clustering with a fixed number of clusters,
    and visualizes the clusters using PCA.
    """
    print("Performing clustering on the training data using the hardcoded number of clusters ...")
    X_train_processed = pipeline.transform(X_train_balanced)
    
    # Ensure the data is in dense array format
    if issparse(X_train_processed):
        X_train_processed = X_train_processed.toarray()
    X_train_processed = np.nan_to_num(X_train_processed, nan=0.0)
    
    kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
    kmeans.fit(X_train_processed)
    clusters = kmeans.predict(X_train_processed)
    
    print("Clustering completed. Visualizing clusters using PCA...\n")
    # PCA for visualization
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_train_processed)
    
    # Print cluster details
    for cluster in range(optimal_k):
        labels_in_cluster = Y_train_balanced[kmeans.labels_ == cluster]
        label_counts = Counter(labels_in_cluster)
        if label_counts:
            most_common_label, most_common_count = label_counts.most_common(1)[0]
            # print(f"Cluster {cluster}: Most Common: {most_common_label} ({most_common_count}) -- Details: {label_counts}")
    
    plt.figure(figsize=(12, 8))
    for cluster in range(optimal_k):
        row_idx = np.where(clusters == cluster)
        labels_in_cluster = Y_train_balanced[kmeans.labels_ == cluster]
        if len(labels_in_cluster) > 0:
            most_common_label, most_common_count = Counter(labels_in_cluster).most_common(1)[0]
            plt.scatter(X_pca[row_idx, 0], X_pca[row_idx, 1],
                        label=f'Cluster {cluster} ({most_common_label})', alpha=0.6)
            if row_idx[0].size > 0:
                plt.text(
                    X_pca[row_idx[0][0], 0], X_pca[row_idx[0][0], 1],
                    f'{most_common_label}\n({most_common_count})',
                    fontsize=8, fontweight='bold', color='black',
                    ha='center', va='center'
                )
    
    # Plot centroids
    centroids = kmeans.cluster_centers_
    for i, centroid in enumerate(centroids):
        plt.scatter(centroid[0], centroid[1], s=300, c='red', marker='X')
        plt.text(centroid[0], centroid[1], str(i), fontsize=12, fontweight='bold',
                 color='black', ha='center', va='center')
    
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.title('K-means Clustering with PCA')
    plt.legend()
    plt.savefig("kmeans_clusters.png")
    plt.close()  # Close the figure to free up resources
    print("Figure saved as 'kmeans_clusters.png'")  # Print a message indicating where the figure is saved.

    
    return kmeans, X_train_processed

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
        most_common_label, most_common_count = label_counts.most_common(1)[0]
        cluster_labels[cluster] = most_common_label
        #print(f"Cluster {cluster}: {most_common_label} ({most_common_count})")
    
    portscan_clusters = [cluster for cluster, label in cluster_labels.items() if label == "Reconnaissance"]
    
    if not portscan_clusters:
        print("Warning: No clusters predominantly labeled as 'Reconnaissance' were identified.")
    else:
        print(f"Identified port scan (Reconnaissance) clusters: {portscan_clusters}")
    
    print("")  # For spacing
    return portscan_clusters

# -------------------------------------------------------------------
# Step 6: Evaluate Clustering on Test Data
# -------------------------------------------------------------------
def evaluate_clustering(pipeline, kmeans, X_test, Y_test, Y_train_balanced, optimal_k=33):
    """
    Transforms the test data, predicts clusters with the trained KMeans,
    and prints a classification report, confusion matrix, and summary metrics.
    """
    print("Evaluating clustering performance on test data...")
    X_test_processed = pipeline.transform(X_test)
    if hasattr(X_test_processed, "toarray"):
        X_test_processed = X_test_processed.toarray()
    X_test_processed = np.nan_to_num(X_test_processed, nan=0.0)
    
    clusters_test = kmeans.predict(X_test_processed)
    
    cluster_labels = {}
    for cluster in range(optimal_k):
        labels_in_cluster = Y_train_balanced[kmeans.labels_ == cluster]
        if labels_in_cluster.size:
            most_common_label = Counter(labels_in_cluster).most_common(1)[0][0]
            cluster_labels[cluster] = most_common_label
        else:
            cluster_labels[cluster] = "Unknown"
    
    predicted_labels = [cluster_labels[cluster] for cluster in clusters_test]
    
    # Print the full classification report and confusion matrix.
    print("\nClassification Report:")
    print(classification_report(Y_test, predicted_labels))
    print("Confusion Matrix:")
    print(confusion_matrix(Y_test, predicted_labels))
    
    # --- Clearer Summary Section ---
    # Calculate overall accuracy.
    accuracy = accuracy_score(Y_test, predicted_labels)
    print("\n=== Summary Metrics ===")
    print("Overall Accuracy:", accuracy)
    
    # For the flagged class ('Reconnaissance') which we treat as potential port scans,
    # calculate precision, recall, F1-score, and support.
    flagged_class = "Reconnaissance"
    precision, recall, f1, support = precision_recall_fscore_support(
        Y_test, predicted_labels, labels=[flagged_class], zero_division=0
    )
    
    print(f"\nMetrics for '{flagged_class}' (flagged as potential port scans):")
    print(f"  Precision: {precision[0]:.2f}")
    print(f"  Recall:    {recall[0]:.2f}")
    print(f"  F1-Score:  {f1[0]:.2f}")
    print(f"  Support:   {support[0]}")
    # --- End of Summary Section ---
    
# -------------------------------------------------------------------
# Step 7: Alert Generation with Distance Measure
# -------------------------------------------------------------------

from datetime import datetime


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

    if row.get("Sintpkt", 1) < 0.01 or row.get("Dintpkt", 1) < 0.01:
        severity = max(severity, 3)  # Sehr schnelles Scannen

    if row["dest_port"] in [53, 22, 3389, 445]:
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


def predict_port_scans_and_generate_alerts(final_csv_path, pipeline, kmeans,
                                           portscan_clusters, alerts_dir="alerts_with_distance",
                                           max_alerts=10):
    """
    Reads a CSV of final features, transforms the data,
    predicts clusters, computes the distance to the nearest centroid,
    flags flows as port scans based on cluster membership,
    and writes up to max_alerts JSON alert files.
    """
    print("Generating port scan alerts jsons...")
    df = pd.read_csv(final_csv_path)
    significant_features = [
        "sport", "dsport", "proto", "sbytes", "dbytes", "smeansz",
        "dmeansz", "Sload", "Dload", "is_sm_ips_ports", "swin", "dwin", "dur", "tcprtt"
    ]
    df[significant_features] = df[significant_features].fillna(0)
    
    # Transform features and predict clusters
    processed_features = pipeline.transform(df[significant_features])
    predicted_clusters = kmeans.predict(processed_features)  # use predict on unseen data
    df["predicted_cluster"] = predicted_clusters
    
    # Compute distances to centroids and flag potential port scans
    distances = kmeans.transform(processed_features)
    df["distance_to_centroid"] = np.min(distances, axis=1)
    df["is_portscan"] = df["predicted_cluster"].apply(lambda cluster: 1 if cluster in portscan_clusters else 0)
    
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
# Main Script
# -------------------------------------------------------------------

if __name__ == '__main__':
    print("=== Starting the Clustering and Alert Generation Script ===\n")
    
    # Set paths and parameters
    dataset_dir = "dataset/"    # Directory containing the CSV files
    final_csv_path = "unsw_nb15_final.csv"     # CSV used for alert generation generated from the 1st script 
    significant_features = [
        "sport", "dsport", "proto", "sbytes", "dbytes",
        "smeansz", "dmeansz", "Sload", "Dload",
        "is_sm_ips_ports", "swin", "dwin", "dur", "tcprtt"
    ]
    
    # Step 1: Load and preprocess the data
    data = load_data(dataset_dir)
    
    # Step 2: Split the data and balance the training set
    X_train_balanced, Y_train_balanced, X_test, Y_test = split_and_balance(data, significant_features)
    
    # Step 3: Build and fit the preprocessing pipeline
    pipeline = build_preprocessing_pipeline(X_train_balanced)
    
    # (Optional) New: Run the Elbow Method to help determine the optimal number of clusters
    elbow_method(pipeline, X_train_balanced, cluster_range=(2, 40))
    
    # Step 4: Run KMeans clustering using a hardcoded optimal number of clusters
    optimal_k = 33  # Hardcoded cluster count
    kmeans, X_train_processed = perform_clustering(pipeline, X_train_balanced, Y_train_balanced, optimal_k=optimal_k)
    
    # Step 5: Identify port scan clusters dynamically (based on 'Reconnaissance' label)
    portscan_clusters = identify_portscan_clusters(kmeans, Y_train_balanced)
    
    # Step 6: Evaluate clustering performance on the test set
    evaluate_clustering(pipeline, kmeans, X_test, Y_test, Y_train_balanced, optimal_k=optimal_k)
    
    # Step 7: Generate alerts based on port scan predictions, including distance information.
    parsed_data, scan_counts = predict_port_scans_and_generate_alerts(
        final_csv_path, pipeline, kmeans, portscan_clusters,
        alerts_dir="alerts_with_distance", max_alerts=5
    )
    print("Port Scan Prediction Results:", scan_counts)
    
    print("\n=== Script Completed ===")
