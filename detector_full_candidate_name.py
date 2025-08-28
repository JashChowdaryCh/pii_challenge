import csv
import json
import re

# ===== Regex Patterns =====
PHONE_REGEX = re.compile(r'\b\d{10}\b')
AADHAR_REGEX = re.compile(r'\b\d{12}\b')
PASSPORT_REGEX = re.compile(r'\b[A-Z]\d{7}\b')
UPI_REGEX = re.compile(r'\b[\w\d._%-]+@[\w\d.-]+\b')
NAME_REGEX = re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b')
EMAIL_REGEX = re.compile(r'\b[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
ADDRESS_REGEX = re.compile(r'\d{1,4} [\w\s]+, [\w\s]+, \d{6}')
IP_REGEX = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')

# ===== Redaction Functions =====
def mask_phone(phone):
    return phone[:2] + 'XXXXXX' + phone[-2:]

def mask_name(name):
    parts = name.split()
    if len(parts) < 2:
        return 'XXX'
    return parts[0][0] + 'XXX ' + parts[1][0] + 'XXXX'

def mask_email(email):
    try:
        user, domain = email.split('@')
        return user[:2] + 'XXX@' + domain
    except:
        return '[REDACTED_PII]'

def redact_value(value, pii_type):
    if pii_type == 'phone':
        return mask_phone(value)
    elif pii_type == 'name':
        return mask_name(value)
    elif pii_type == 'email':
        return mask_email(value)
    else:
        return '[REDACTED_PII]'

# ===== Detect & Redact PII =====
def detect_and_redact(record_json):
    pii_found = False
    combinatorial_count = 0
    
    # Fix Excel-style double quotes and strip wrapping quotes
    record_json = record_json.replace('""', '"').strip('"')
    
    try:
        data = json.loads(record_json)
    except json.JSONDecodeError:
        # If JSON still fails, return as-is but mark as PII
        return record_json, True

    for key, value in data.items():
        if value is None:
            continue
        value_str = str(value)

        # Standalone PII
        if PHONE_REGEX.search(value_str):
            data[key] = mask_phone(value_str)
            pii_found = True
        elif AADHAR_REGEX.search(value_str) or PASSPORT_REGEX.search(value_str) or UPI_REGEX.search(value_str):
            data[key] = '[REDACTED_PII]'
            pii_found = True

        # Combinatorial PII
        comb_flags = []
        if NAME_REGEX.search(value_str):
            data[key] = mask_name(value_str)
            comb_flags.append(True)
        if EMAIL_REGEX.search(value_str):
            data[key] = mask_email(value_str)
            comb_flags.append(True)
        if ADDRESS_REGEX.search(value_str) or IP_REGEX.search(value_str):
            data[key] = '[REDACTED_PII]'
            comb_flags.append(True)

        if len(comb_flags) >= 2:
            pii_found = True
        elif len(comb_flags) == 1:
            combinatorial_count += 1

    if combinatorial_count >= 2:
        pii_found = True

    return json.dumps(data), pii_found

# ===== Process CSV =====
def process_csv(input_file, output_file):
    with open(input_file, newline='', encoding='utf-8') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            redacted_json, pii_flag = detect_and_redact(row['data_json'])
            writer.writerow({
                'record_id': row['record_id'],
                'redacted_data_json': redacted_json,
                'is_pii': pii_flag
            })

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python detector_full_candidate_name.py <input_csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = 'redacted_output_candidate_full_name.csv'
    process_csv(input_file, output_file)
    print(f"Redacted CSV saved to {output_file}")
