import hashlib
import os
import requests
import json
import logging
from datetime import datetime
import math

LOG_FORMAT = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO, datefmt='%Y-%m-%d %I:%M:%S')
log = logging.getLogger(__name__)

# API details
BASE_URL = "https://host.docker.internal"
API_KEY = "X1Fl6YVZdeP2uChFAg29MAMU-671vuAq0VxhQzSMxsT9mscrjubiGd3LWmepi6SPtfdcIoI5fxc4RYbM_qMY-A"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}


def compute_file_hash(file_path, hash_algorithm="sha256"):
    """
    Computes the hash of a file using the specified hash algorithm.
    """
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        log.error(f"Failed to compute hash for {file_path}: {e}")
        return None


def add_file_as_evidence(file_path, case_id, file_description, type_id="48", custom_attributes=None):
    """
    Adds a file as evidence to a specific case.
    """
    url = f"{BASE_URL}/case/evidences/add?cid={case_id}"  # Ensure cid is appended correctly
    try:
        # Get file metadata
        file_size = os.path.getsize(file_path)
        file_hash = compute_file_hash(file_path)
        filename = os.path.basename(file_path)

        if not file_hash:
            log.error("File hash could not be computed. Aborting evidence upload.")
            return None

        # Prepare payload
        payload = {
            "filename": filename,
            "file_size": str(file_size),
            "file_hash": file_hash,
            "type_id": type_id,
            "start_date": datetime.now().isoformat(),  # Current timestamp
            "end_date": None,  # Optional
            "custom_attributes": custom_attributes or {},
            "file_description": file_description
        }

        log.info(f"Payload for adding evidence: {json.dumps(payload, indent=4)}")

        # Send POST request
        response = requests.post(url, headers=HEADERS, json=payload, verify=False)
        if response.status_code == 400:
            log.error(f"Bad Request: {response.text}")
        response.raise_for_status()
        log.info(f"File {filename} added as evidence to case {case_id}.")
        return response.json()
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to add evidence: {e}")
        return None


def derive_soc_id(alert):
    """
    Derive SOC ID based on alert details dynamically.
    """
    severity = alert.get('alert', {}).get('severity', None)
    src_ip = alert.get('src_ip', 'Unknown')

    if severity == 3:
        return "soc_high"
    elif severity == 2:
        return "soc_medium"
    elif severity == 1:
        return "soc_low"
    elif src_ip.startswith("192.168"):
        return "soc_internal"
    else:
        return "soc_default"

def sanitize_value(value, default="Unknown"):
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return default if isinstance(default, str) else 0.0
    return value


def create_case_with_post(alert, file_path):
    """
    Create a case using a POST request to the DFIR-IRIS API, 
    and add the alert file as evidence.
    """
    try:
        # Extract top-level alert details
        signature = alert.get('alert', {}).get('signature', 'Unknown Signature')
        src_ip = alert.get('src_ip', 'Unknown')
        dest_ip = alert.get('dest_ip', 'Unknown')
        proto = alert.get('proto', 'Unknown')
        severity = alert.get('alert', {}).get('severity', 3)
        timestamp = alert.get('timestamp', 'Unknown')
        flow_info = alert.get('flow_info', {})
        distance_to_centroid = sanitize_value(alert.get("distance_to_centroid", 0.0))
        duration = sanitize_value(flow_info.get("duration", 0.0))
        Sload = sanitize_value(flow_info.get("Sload", 0.0))
        Dload = sanitize_value(flow_info.get("Dload", 0.0))
        Sintpkt = sanitize_value(flow_info.get("Sintpkt", 0.0))
        Dintpkt = sanitize_value(flow_info.get("Dintpkt", 0.0))
        tcprtt = sanitize_value(flow_info.get("tcprtt", 0.0))
        # Extract flow_info details
        state = sanitize_value(flow_info.get("state", "Unknown")),
        sbytes = flow_info.get('sbytes', 0)
        dbytes = flow_info.get('dbytes', 0)
        sttl = flow_info.get('sttl', 0)
        Spkts = flow_info.get('Spkts', 0)
        Dpkts = flow_info.get('Dpkts', 0)
        swin = flow_info.get('swin', 0)
        dwin = flow_info.get('dwin', 0)
        smeansz = flow_info.get('smeansz', 0)
        dmeansz = flow_info.get('dmeansz', 0)
        trans_depth = flow_info.get('trans_depth', 0)
        Stime = flow_info.get('Stime', 0)
        Ltime = flow_info.get('Ltime', 0)
        is_sm_ips_ports = flow_info.get('is_sm_ips_ports', 0)
        service = flow_info.get('service', '-')

        # Dynamically derive SOC ID
        soc_id = derive_soc_id(alert)
        log.info(f"Derived SOC ID: {soc_id}")

        # Prepare the case creation data
        data = {
            "case_soc_id": soc_id,
            "case_customer": 1,
            "case_name": signature,
            "case_description": (
                f"Detected port scan activity:\n\n"
                f"- **Timestamp**: {timestamp}\n"
                f"- **Source IP**: {src_ip}\n"
                f"- **Destination IP**: {dest_ip}\n"
                f"- **Protocol**: {proto}\n"
                f"- **Severity**: {severity}\n"
                f"- **Distance to Centroid**: {distance_to_centroid}\n"
                f"- **State**: {state}\n"
                f"- **Duration**: {duration}\n"
                f"- **Sent Bytes**: {sbytes}\n"
                f"- **Received Bytes**: {dbytes}\n"
                f"- **Packets to Server**: {Spkts}\n"
                f"- **Packets to Client**: {Dpkts}\n"
            ),
            "case_template_id":  str(severity),
            "custom_attributes": {
                "Alert Details": {
                    "signature": signature,
                    "timestamp": timestamp,
                    "flow_id": str(alert.get("flow_id", "N/A")),
                    "src_ip": src_ip,
                    "src_port": str(alert.get("src_port", "")),
                    "dest_ip": dest_ip,
                    "dest_port": str(alert.get("dest_port", "")),
                    "proto": proto,
                    "event_type": alert.get("event_type", ""),
                    "pkt_src": alert.get("pkt_src", ""),
                    "action": alert.get("alert", {}).get("action", ""),
                    "signature_id": str(alert.get("alert", {}).get("signature_id", "")),
                    "rev": str(alert.get("alert", {}).get("rev", "")),
                    "category": alert.get("alert", {}).get("category", ""),
                    "severity": str(severity),
                    "distance_to_centroid": str(distance_to_centroid)
                },
                "Flow Details": {
                    "flow_state": state,
                    "flow_duration": str(duration),
                    "flow_bytes_toserver": str(sbytes),
                    "flow_bytes_toclient": str(dbytes),
                    "flow_pkts_toserver": str(Spkts),
                    "flow_pkts_toclient": str(Dpkts),
                    "sttl": str(sttl),
                    "Sload": str(Sload),
                    "Dload": str(Dload),
                    "swin": str(swin),
                    "dwin": str(dwin),
                    "smeansz": str(smeansz),
                    "dmeansz": str(dmeansz),
                    "trans_depth": str(trans_depth),
                    "Stime": str(Stime),
                    "Ltime": str(Ltime),
                    "Sintpkt": str(Sintpkt),
                    "Dintpkt": str(Dintpkt),
                    "tcprtt": str(tcprtt),
                    "is_sm_ips_ports": str(is_sm_ips_ports),
                    "service": service
                },
                "Metadata": {
                    "detection_time": timestamp,
                    "protocol": proto,
                    "severity": "High" if severity == 3 else "Medium" if severity == 2 else "Low",
                    "distance_to_centroid": str(distance_to_centroid)
                }
            }

        }

        try:
            json.dumps(data)  # Test, ob JSON gültig ist
        except ValueError as e:
            log.error(f"Invalid JSON data: {e}")
            return None

        # Create the case
        url = f"{BASE_URL}/manage/cases/add"
        log.info(f"Sending POST request to create a case with template ID {data['case_template_id']}")
        response = requests.post(url, headers=HEADERS, json=data, verify=False)
        response.raise_for_status()
        case_response = response.json()
        case_id = case_response.get("data", {}).get("case_id")
        log.info(f"Case created successfully with ID: {case_id}")

        # Add the alert file as evidence
        file_description = "Alert file associated with the case."
        add_file_as_evidence(file_path, case_id, file_description)

        return case_response
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to create case: {e}")
        return None


def read_eve_json(file_path):
    """
    Reads alerts from an EVE JSON file which may contain either a single alert (JSON object)
    or multiple alerts (JSON array).
    """
    with open(file_path, 'r') as file:
        try:
            data = json.load(file)
            if isinstance(data, list):
                for alert in data:
                    yield alert
            elif isinstance(data, dict):
                # If it's a dict, yield it as a single alert
                yield data
            else:
                log.error(f"Unsupported JSON structure in {file_path}")
        except json.JSONDecodeError as e:
            log.error(f"Error decoding JSON from {file_path}: {e}")


def main():
    alerts_dir = "alerts"  # Root directory containing alert subfolders
    log.info("Starting to process EVE JSON alerts from nested folders")

    # Walk through all directories and files in alerts_dir
    for root, dirs, files in os.walk(alerts_dir):
        for filename in files:
            if filename.lower().endswith(".json"):
                file_path = os.path.join(root, filename)
                log.info(f"Processing alert file: {file_path}")
                # Read and process each alert in the JSON file
                for alert in read_eve_json(file_path):
                    create_case_with_post(alert, file_path)

    log.info("Finished processing EVE JSON alerts")


if __name__ == "__main__":
    main()
