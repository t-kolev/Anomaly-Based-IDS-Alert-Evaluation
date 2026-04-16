# Anomaly-Based IDS Alert Evaluation

University project on detecting port scanning attacks with an anomaly-based intrusion detection system and evaluating the operational usefulness of the generated alerts.

## Main components

- anomaly-based port scan detection
- alert generation in EVE JSON format
- DFIR-IRIS integration for case creation and alert enrichment

## Tech stack

- Python
- Docker
- DFIR-IRIS

## Structure

- `IDS/` – detection logic and alert generation
- `CaseManagement/` – DFIR-IRIS integration
- `Report/` – final project report

## Setup

1. Install dependencies from `requirements.txt`
2. Set up DFIR-IRIS using `CaseManagement/IRIS_README.md`
3. Add PCAP files to `IDS/dataset/`
4. Run the IDS pipeline
5. Create and enrich cases in DFIR-IRIS
