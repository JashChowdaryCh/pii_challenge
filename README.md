# Real-time PII Defense - Project Guardian 2.0

## Objective
Detect and redact personally identifiable information (PII) in real-time from data streams to prevent fraud, unauthorized orders, and data leakage.

## Features
- Detects **Standalone PII**:  
  - Phone Numbers (10-digit)  
  - Aadhar Numbers (12-digit)  
  - Passport Numbers (e.g., P1234567)  
  - UPI IDs (e.g., user@upi, 9876543210@ybl)
- Detects **Combinatorial PII**:  
  - Name + Email  
  - Name + Address  
  - Name + Device ID / IP Address  
- Masks or redacts PII inline:
  - Phone Numbers: `98XXXXXX10`  
  - Names: `RXXX KXXXX`  
  - Emails: `raXXX@email.com`  
  - Other PII: `[REDACTED_PII]`
- Outputs a CSV with:
  - `redacted_data_json`: JSON with PII redacted  
  - `is_pii`: True/False flag indicating presence of PII

## Usage
1. Ensure **Python 3.x** is installed.
2. Place the input CSV file (`iscp_pii_dataset.csv`) in the same directory as the script.
3. Run the Python script:
   ```bash
   python detector_full_candidate_name.py iscp_pii_dataset.csv
   ```
4. The output will be saved as:
   ```bash
   redacted_output_candidate_full_name.csv
   ```
### Deployment Strategy
Recommended Deployment Layer

## Sidecar Container in Microservice Architecture

Each microservice handling sensitive data has a dedicated sidecar to intercept incoming/outgoing JSON payloads.

Real-time PII detection and redaction occur without modifying main application code.

## Alternative / Additional Options

API Gateway Plugin: Intercepts requests/responses for legacy or external APIs.

DaemonSet in Kubernetes: Monitors logs and streams from all pods for PII in real-time.

## Architecture Overview

Ingress Layer: Capture all incoming API requests.

Sidecar / Gateway Plugin:

Detects and redacts PII using the Python script (as a lightweight service).

Replaces sensitive fields with [REDACTED_PII] or masked values.

Main Service / Application: Receives sanitized payloads with minimal latency impact.

Monitoring & Logging: Sidecar sends PII detection logs to a centralized system for auditing.

## Benefits

Scalability: Sidecars scale with individual services.

Low Latency: Redaction occurs inline with request/response.

Cost-Effective: No need to rewrite existing services.

Ease of Integration: Works with microservices, API gateways, and streaming logs.

## Considerations

For internal apps, sidecars can sanitize logs before storage.

Regular audits ensure regex patterns and NER models stay up-to-date with new PII formats.

## Author

Jaswanth Chilakalapudi
