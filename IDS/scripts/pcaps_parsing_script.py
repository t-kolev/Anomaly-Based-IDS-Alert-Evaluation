import os
import subprocess
import pandas as pd
import pyshark
import numpy as np

# -------------------------------------------------------------------
# Step 1: Extract Packet-Level Features Using Pyshark
# -------------------------------------------------------------------

def extract_pyshark_features(pcap_file, max_packets=10000):
    """
    Extract certain packet-level TCP/IP features from the pcap using Pyshark.
    For illustration, we store only the first observed TTL/window as sttl/swin.
    'dttl' and 'dwin' would require deeper bidirectional logic.
    """
    cap = pyshark.FileCapture(pcap_file)
    flows = {}

    for i, pkt in enumerate(cap):
        if i >= max_packets:  # Stop after processing max_packets
            break

        # Only process IP + TCP or IP + UDP
        if 'IP' in pkt and (hasattr(pkt, 'tcp') or hasattr(pkt, 'udp')):
            srcip = pkt.ip.src
            dstip = pkt.ip.dst
            proto = pkt.ip.proto  # Numeric protocol ID
            sport = None
            dsport = None

            if hasattr(pkt, 'tcp'):
                sport = pkt.tcp.srcport
                dsport = pkt.tcp.dstport
            elif hasattr(pkt, 'udp'):
                sport = pkt.udp.srcport
                dsport = pkt.udp.dstport

            key = (srcip, dstip, sport, dsport, proto)
            if key not in flows:
                flows[key] = {
                    'srcip': srcip,
                    'dstip': dstip,
                    'sport': sport,
                    'dsport': dsport,
                    'proto': proto,
                    'sttl': None,
                    'dttl': None,
                    'swin': None,
                    'dwin': None,
                    'stcpb': None,  # first TCP seq
                    'dtcpb': None,  # first TCP ack
                    'tcprtt': None, # approximate from first packet
                    'start_time': float(pkt.sniff_timestamp),
                }

            flow = flows[key]

            # If TTL not set, store the first packet's TTL as sttl
            if flow['sttl'] is None:
                flow['sttl'] = pkt.ip.ttl

            # If TCP fields are present, store them if not set
            if hasattr(pkt, 'tcp'):
                if flow['swin'] is None:
                    flow['swin'] = pkt.tcp.window_size

                if flow['stcpb'] is None and hasattr(pkt.tcp, 'seq_raw'):
                    flow['stcpb'] = pkt.tcp.seq_raw
                if flow['dtcpb'] is None and hasattr(pkt.tcp, 'ack_raw'):
                    flow['dtcpb'] = pkt.tcp.ack_raw

                # RTT from first packet's analysis if available
                if hasattr(pkt.tcp, 'analysis_ack_rtt'):
                    flow['tcprtt'] = pkt.tcp.analysis_ack_rtt

    cap.close()
    return pd.DataFrame(flows.values())


# -------------------------------------------------------------------
# Step 2: Extract Flow-Level Features Using Argus
# -------------------------------------------------------------------

def run_argus(pcap_file, output_csv):
    """
    Run Argus + ra to extract flow-level features,
    then rename columns so we have 'srcip', 'dstip', etc.
    Output times in epoch format so we can do numeric subtraction.

    The final cleaned and transformed data will overwrite `output_csv`.
    """
    argus_file = "/tmp/argus_output.argus"

    # 1) Generate the .argus binary from pcap
    subprocess.run(["argus", "-r", pcap_file, "-w", argus_file], check=True)

    # 2) Use ra to convert to CSV-like output in epoch format
    argus_fields = [
        "stime", "ltime",
        "saddr", "daddr",
        "sport", "dport",
        "proto", "state",
        "sbytes", "dbytes",
        "spkts", "dpkts",
        "sload", "dload",
        "sintpkt", "dintpkt",
        "tcpstate",
        "tcprtt"
    ]

    with open(output_csv, 'w') as f:
        subprocess.run(
            ["ra", "-u", "-n", "-r", argus_file, "-s"] + argus_fields,
            check=True,
            stdout=f
        )

    # 3) Load into DataFrame
    df = pd.read_csv(output_csv, sep=r'\s+', skipinitialspace=True)

    # Map Argus column names to final names
    col_map = {
        "StartTime": "Stime",
        "LastTime":  "Ltime",
        "SrcAddr":   "srcip",
        "DstAddr":   "dstip",
        "Sport":     "sport",
        "Dport":     "dsport",
        "Proto":     "proto",
        "State":     "state",
        "SrcBytes":  "sbytes",
        "DstBytes":  "dbytes",
        "SrcPkts":   "Spkts",
        "DstPkts":   "Dpkts",
        "SrcLoad":   "Sload",
        "DstLoad":   "Dload",
        "SIntPkt":   "Sintpkt",
        "DIntPkt":   "Dintpkt",
        "TcpRtt":    "tcprtt",
        "TcpState":  "tcpstate"
    }

    # Rename if columns exist
    for old_col, new_col in col_map.items():
        if old_col in df.columns:
            df.rename(columns={old_col: new_col}, inplace=True)

    # Convert to numeric where possible
    numeric_cols = [
        "Stime", "Ltime", "sport", "dsport", "proto",
        "sbytes", "dbytes", "Spkts", "Dpkts",
        "Sload", "Dload", "Sintpkt", "Dintpkt", "tcprtt"
    ]
    i = 0
    for col in numeric_cols:
        if col in df.columns:
            if col == "Sload" or col == "Dload":
                i += 1
                print("\n----------------------------------")
                # Display before cleaning
                print(f"before cleaning ({col}):\n", df[col].head())
                # Remove asterisks
                df[col] = df[col].str.replace('*', '', regex=False)
                print(f"after cleaning ({col}):\n", df[col].head())
                # Convert to numeric
                df[col] = pd.to_numeric(df[col], errors='coerce')
                print(f"after conversion ({col}):\n", df[col].head())
                print("----------------------------------\n")
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Overwrite the original CSV with cleaned data
    df.to_csv(output_csv+"_processed", index=False)

    return df

# -------------------------------------------------------------------
# Step 3: Extract Application-Level Features Using Zeek
# -------------------------------------------------------------------
def run_zeek(pcap_file, zeek_logs_dir):
    """
    Run Zeek on the pcap in the specified directory.
    Then parse relevant logs (conn, http, ftp) for additional fields.
    """
    if not os.path.exists(zeek_logs_dir):
        os.makedirs(zeek_logs_dir, exist_ok=True)

    try:
        # Run Zeek inside that directory
        subprocess.run(["zeek", "-r", pcap_file], cwd=zeek_logs_dir, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: The pcap '{os.path.basename(pcap_file)}' can't be parsed. Please try another one.")
        # Return an empty dict to indicate failure, which will be checked in the main loop.
        return {}

    logs = {}

    # Process conn.log if it exists
    conn_log = os.path.join(zeek_logs_dir, "conn.log")
    if os.path.exists(conn_log):
        conn_df = pd.read_csv(
            conn_log,
            sep="\t",
            comment="#",
            header=None,
            na_values="-",
            low_memory=False
        )
        default_conn_cols = [
            "ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"
        ]
        num_cols = len(conn_df.columns)
        if num_cols > len(default_conn_cols):
            extra_cols = [f"unk_{i}" for i in range(num_cols - len(default_conn_cols))]
            default_conn_cols += extra_cols

        conn_df.columns = default_conn_cols[:num_cols]
        logs['conn'] = conn_df

    # Process http.log if it exists
    http_log = os.path.join(zeek_logs_dir, "http.log")
    if os.path.exists(http_log):
        http_df = pd.read_csv(
            http_log,
            sep="\t",
            comment="#",
            header=None,
            na_values="-",
            low_memory=False
        )
        default_http_cols = [
            "ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p",
            "trans_depth", "method", "host", "uri", "referrer", "version",
            "user_agent", "request_body_len", "response_body_len", "status_code", "status_msg",
            "info_code", "info_msg", "filename", "tags", "username", "password", "proxied",
            "orig_fuids", "orig_mime_types", "resp_fuids", "resp_mime_types"
        ]
        num_cols = len(http_df.columns)
        if num_cols > len(default_http_cols):
            extra_cols = [f"unk_{i}" for i in range(num_cols - len(default_http_cols))]
            default_http_cols += extra_cols

        http_df.columns = default_http_cols[:num_cols]
        logs['http'] = http_df

    # Process ftp.log if it exists
    ftp_log = os.path.join(zeek_logs_dir, "ftp.log")
    if os.path.exists(ftp_log):
        ftp_df = pd.read_csv(
            ftp_log,
            sep="\t",
            comment="#",
            header=None,
            na_values="-",
            low_memory=False
        )
        default_ftp_cols = [
            "ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p",
            "user", "password", "command", "arg", "mime_type", "file_size",
            "reply_code", "reply_msg", "data_channel.passive",
            "data_channel.orig_h", "data_channel.resp_h", "data_channel.resp_p"
        ]
        num_cols = len(ftp_df.columns)
        if num_cols > len(default_ftp_cols):
            extra_cols = [f"unk_{i}" for i in range(num_cols - len(default_ftp_cols))]
            default_ftp_cols += extra_cols

        ftp_df.columns = default_ftp_cols[:num_cols]
        logs['ftp'] = ftp_df

    return logs

# -------------------------------------------------------------------
# Step 4: Combine/Merge All Features + Post-Process to Match UNSW-NB15 Columns
# -------------------------------------------------------------------

def combine_features(pyshark_df, argus_df, zeek_logs):
    """
    Merge the Pyshark features (packet-level) with Argus (flow-level),
    then incorporate Zeek logs (e.g., for 'service', 'trans_depth', etc.),
    and create all columns required by UNSW-NB15, filling missing ones
    with placeholders.
    """

    # Make a copy so we don't mutate
    argus_df_copy = argus_df.copy()

    # Convert Argus "proto" from string to numeric if needed
    if 'proto' in argus_df_copy.columns:
        argus_df_copy['proto'] = argus_df_copy['proto'].replace({
            'tcp': 6,
            'udp': 17,
            'icmp': 1
        })

    # Ensure Pyshark columns are numeric for merging
    for col in ['sport', 'dsport', 'proto']:
        if col in pyshark_df.columns:
            pyshark_df[col] = pd.to_numeric(pyshark_df[col], errors='coerce')

    # 1) Merge Pyshark + Argus on 5-tuple
    merged_df = pd.merge(
        pyshark_df,
        argus_df_copy,
        how='outer',
        on=['srcip', 'dstip', 'sport', 'dsport', 'proto']
    )

    # 2) Merge Zeek's conn.log (if present)
    if 'conn' in zeek_logs:
        conn_df = zeek_logs['conn'].copy()
        # Convert ports to string for joining
        merged_df['sport'] = merged_df['sport'].astype(str)
        merged_df['dsport'] = merged_df['dsport'].astype(str)
        conn_df['orig_p'] = conn_df['orig_p'].astype(str)
        conn_df['resp_p'] = conn_df['resp_p'].astype(str)

        merged_df = pd.merge(
            merged_df,
            conn_df,
            how='left',
            left_on=['srcip', 'sport', 'dstip', 'dsport'],
            right_on=['orig_h', 'orig_p', 'resp_h', 'resp_p'],
            suffixes=('', '_conn')
        )

    # Duration
    merged_df['dur'] = merged_df['Ltime'] - merged_df['Stime']

    # is_sm_ips_ports
    merged_df['is_sm_ips_ports'] = (
        (merged_df['srcip'] == merged_df['dstip']) &
        (merged_df['sport'] == merged_df['dsport'])
    )

    # smean, dmean
    merged_df['smeansz'] = merged_df.apply(
        lambda row: (row['sbytes'] / row['Spkts']) if row.get('Spkts', 0) else 0, axis=1
    )
    merged_df['dmeansz'] = merged_df.apply(
        lambda row: (row['dbytes'] / row['Dpkts']) if row.get('Dpkts', 0) else 0, axis=1
    )

    if 'service' not in merged_df.columns:
        merged_df['service'] = np.nan
    else:
        pass

    if 'trans_depth' not in merged_df.columns:
        merged_df['trans_depth'] = 0

    # Let's define placeholders for all other UNSW columns we do NOT explicitly compute:
    placeholder_cols = {
        'dttl': 0,
        'sloss': 0,
        'dloss': 0,
        'res_bdy_len': 0,
        'Sjit': 0,
        'Djit': 0,
        'synack': 0,
        'ackdat': 0,
        'ct_state_ttl': 0,
        'ct_flw_http_mthd': 0,
        'is_ftp_login': 0,
        'ct_ftp_cmd': 0,
        'ct_srv_src': 0,
        'ct_srv_dst': 0,
        'ct_dst_ltm': 0,
        'ct_src_ltm': 0,
        'ct_src_dport_ltm': 0,
        'ct_dst_sport_ltm': 0,
        'ct_dst_src_ltm': 0,
        'tcprtt': 0
    }
    for col, val in placeholder_cols.items():
        if col not in merged_df.columns:
            merged_df[col] = val

    # ----------------------------------------------------------------
    # Now reorder and keep only the official UNSW-NB15 columns
    # ----------------------------------------------------------------
    final_columns = [
        "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
        "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
        "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
        "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
        "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
        "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
        "ct_dst_sport_ltm", "ct_dst_src_ltm"
    ]
    # Select columns and immediately copy so we don’t get SettingWithCopyWarning:
    final_df = merged_df[final_columns].copy()

    # ----------------------------------------------------------------
    # 1) Convert numeric protocols back to nominal strings (tcp, udp, icmp)
    #    Use .loc[:, col] to avoid SettingWithCopyWarnings:
    # ----------------------------------------------------------------
    proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
    final_df.loc[:, "proto"] = (
        final_df["proto"].map(proto_map).fillna("other").astype(str)
    )

    # ----------------------------------------------------------------
    # 2) Cast columns according to the UNSW-NB15 schema:
    # ----------------------------------------------------------------

    # (A) Nominal/string fields
    final_df.loc[:, "srcip"] = final_df["srcip"].astype(str)
    final_df.loc[:, "dstip"] = final_df["dstip"].astype(str)
    final_df.loc[:, "state"] = final_df["state"].astype(str)
    # Fill missing services with "-" and convert to string
    final_df.loc[:, "service"] = final_df["service"].fillna("-").astype(str)

    # (B) Integer fields
    int_cols = [
        "sport", "dsport", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
        "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
        "trans_depth", "res_bdy_len", "ct_state_ttl", "ct_flw_http_mthd", "ct_ftp_cmd",
        "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
        "ct_dst_sport_ltm", "ct_dst_src_ltm",
    ]
    for col in int_cols:
        # Convert to numeric first (handles '0.0') then cast to int
        final_df.loc[:, col] = (
            pd.to_numeric(final_df[col], errors='coerce')
            .fillna(0)
            .astype(int)
        )

    # (C) Binary fields => cast to int (0 or 1)
    final_df.loc[:, "is_sm_ips_ports"] = (
        final_df["is_sm_ips_ports"].fillna(False).astype(int)
    )
    final_df.loc[:, "is_ftp_login"] = (
        final_df["is_ftp_login"].fillna(0).astype(int)
    )

    # (D) Float fields
    float_cols = [
        "dur", "Sload", "Dload", "Sjit", "Djit", "Sintpkt", "Dintpkt",
        "tcprtt", "synack", "ackdat",
    ]
    for col in float_cols:
        final_df.loc[:, col] = (
            pd.to_numeric(final_df[col], errors='coerce')
            .fillna(0)
            .astype(float)
        )

    # (E) Timestamps as integer
    final_df.loc[:, "Stime"] = (
        pd.to_numeric(final_df["Stime"], errors='coerce')
        .fillna(0)
        .astype(int)
    )
    final_df.loc[:, "Ltime"] = (
        pd.to_numeric(final_df["Ltime"], errors='coerce')
        .fillna(0)
        .astype(int)
    )

    return final_df


# -------------------------------------------------------------------
# Main Script
# -------------------------------------------------------------------

if __name__ == "__main__":
    dataset_folder = "/app/dataset"  # Adjust this path as needed
    final_csv_folder = os.path.join("/app", "final_csvs")
    os.makedirs(final_csv_folder, exist_ok=True)

    # List all files ending with .pcap in the dataset folder
    all_pcaps = [f for f in os.listdir(dataset_folder) if f.endswith(".pcap")]
    pcaps_to_process = all_pcaps  # or limit to a subset for testing

    for pcap_filename in pcaps_to_process:
        try:
            print(f"\nProcessing PCAP: {pcap_filename}")
            pcap_file = os.path.join(dataset_folder, pcap_filename)

            # Define intermediate output directories/filenames
            base_name = os.path.splitext(pcap_filename)[0]
            zeek_logs_dir = os.path.join("/app/zeek_logs", base_name)
            argus_output_csv = os.path.join("/app", f"{base_name}_argus_features.csv")
            final_csv = os.path.join(final_csv_folder, f"{base_name}_unsw_nb15_final.csv")

            # Step 1: Packet-level with Pyshark
            try:
                pyshark_df = extract_pyshark_features(pcap_file, max_packets=100)
                if pyshark_df is None or pyshark_df.empty:
                    print(f"Skipping {pcap_filename}: Pyshark feature extraction failed or returned no data.")
                    continue
            except Exception as pe:
                print(f"Skipping {pcap_filename}: Exception during Pyshark extraction: {pe}")
                continue

            # Step 2: Flow-level with Argus
            try:
                argus_df = run_argus(pcap_file, argus_output_csv)
                if argus_df is None or argus_df.empty:
                    print(f"Skipping {pcap_filename}: Argus feature extraction failed or returned no data.")
                    continue
            except Exception as ae:
                print(f"Skipping {pcap_filename}: Exception during Argus extraction: {ae}")
                continue

            # Step 3: Application-level with Zeek
            try:
                zeek_logs = run_zeek(pcap_file, zeek_logs_dir)
                if not zeek_logs:
                    print(f"Skipping {pcap_filename}: Zeek processing failed or returned empty logs.")
                    continue
            except Exception as ze:
                print(f"Skipping {pcap_filename}: Exception during Zeek processing: {ze}")
                continue

            # Step 4: Combine features and post-process
            try:
                final_df = combine_features(pyshark_df, argus_df, zeek_logs)
                if final_df is None or final_df.empty:
                    print(f"Skipping {pcap_filename}: Final dataset is empty after combining features.")
                    continue
            except Exception as ce:
                print(f"Skipping {pcap_filename}: Exception during combining features: {ce}")
                continue

            # Convert ports to integer format (if needed)
            try:
                final_df['sport'] = final_df['sport'].astype('Int64')
                final_df['dsport'] = final_df['dsport'].astype('Int64')
            except Exception as conv_e:
                print(f"Warning: Couldn't convert port columns for {pcap_filename}: {conv_e}")

            # Step 5: Save the final CSV file
            try:
                final_df.to_csv(final_csv, index=False)
                print(f"Feature extraction completed for {pcap_filename}. Saved to '{final_csv}'")
            except Exception as save_e:
                print(f"Error saving CSV for {pcap_filename}: {save_e}")
                continue

        except Exception as e:
            # Catch any exception not already caught by inner try/except blocks
            print(f"Unexpected error processing {pcap_filename}: {e}")
            print(f"Skipping {pcap_filename} and moving on to the next file.")
            continue

    print("Processing completed for all PCAP files.")
