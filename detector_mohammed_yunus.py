
#!/usr/bin/env python3
"""
detector_mohammed_yunus.py

Usage:
  python3 detector_mohammed_yunus.py input.csv

Input CSV columns: record_id, Data_json
Output CSV columns: record_id, redacted_data_json, is_pii

Rules implemented per challenge:
- Standalone PII: phone(10d), aadhar(12d), passport(Indian pattern), UPI ID (.*@provider).
- Combinatorial PII (need >=2 in same record): full name, email, physical address, device_id/ip.
- Avoid false positives: a single first_name or last_name alone, email alone, city/state/pin alone, etc.

Approach:
- We look for PII only in semantically relevant fields to reduce false positives.
- Combinatorial features are counted first; only if standalone is present or combinatorial_count >= 2
  do we perform masking/redaction.
- Masking preserves partial structure to keep data utility while protecting identity.
"""

import sys, csv, json, re
from typing import Dict, Any

PHONE_RE = re.compile(r'(?<!\d)(\d{10})(?!\d)')
AADHAR_RE = re.compile(r'(?<!\d)(\d{12})(?!\d)')
# Indian passport: 1 letter + 7 digits (new) or 2 letters + 7 digits (older)
PASSPORT_RE = re.compile(r'\b([A-Z]{1}\d{7}|[A-Z]{2}\d{7})\b', re.IGNORECASE)
EMAIL_RE = re.compile(r'^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$', re.IGNORECASE)
UPI_RE = re.compile(r'^[A-Z0-9.\-_]{2,}@[A-Z]{2,}[A-Z0-9]{0,}$', re.IGNORECASE)
PIN_RE = re.compile(r'(?<!\d)(\d{6})(?!\d)')
IP_RE = re.compile(r'\b((25[0-5]|2[0-4]\d|1?\d{1,2})(\.(?!$)|$)){4}\b')
# device id: treat as present if alnum string length >= 8 with letters+digits
DEVICE_RE = re.compile(r'(?i)^[a-z0-9\-\:_]{8,}$')

def mask_phone(s: str) -> str:
    m = PHONE_RE.search(s)
    if not m:
        return s
    num = m.group(1)
    masked = f"{num[:2]}XXXXXX{num[-2:]}"
    return PHONE_RE.sub(masked, s)

def mask_aadhar(s: str) -> str:
    m = AADHAR_RE.search(s)
    if not m:
        return s
    num = m.group(1)
    masked = f"XXXXXXXX{num[-4:]}"
    return AADHAR_RE.sub(masked, s)

def mask_passport(s: str) -> str:
    m = PASSPORT_RE.search(s)
    if not m:
        return s
    val = m.group(0)
    if len(val) >= 3:
        masked = val[0] + "XXXXX" + val[-2:]
    else:
        masked = "[REDACTED_PII]"
    return PASSPORT_RE.sub(masked, s)

def mask_email(s: str) -> str:
    try:
        local, domain = s.split("@", 1)
    except ValueError:
        return s
    if len(local) <= 2:
        local_mask = local[0] + "XXX"
    else:
        local_mask = local[:2] + "X" * max(3, len(local) - 2)
    # mask domain but keep tld
    if "." in domain:
        d_main, tld = domain.rsplit(".", 1)
        d_mask = d_main[0] + "X" * max(2, len(d_main) - 1)
        domain_mask = d_mask + "." + tld
    else:
        domain_mask = "X" * max(3, len(domain))
    return local_mask + "@" + domain_mask

def mask_upi(s: str) -> str:
    try:
        user, prov = s.split("@", 1)
    except ValueError:
        return s
    u_mask = (user[:2] if len(user) >= 2 else user[:1]) + "***"
    p_mask = prov[:1] + "**"
    return u_mask + "@" + p_mask

def mask_name(full: str) -> str:
    parts = [p for p in re.split(r'\s+', full.strip()) if p]
    masked = []
    for p in parts:
        if len(p) == 1:
            masked.append("X")
        elif len(p) == 2:
            masked.append(p[0] + "X")
        else:
            masked.append(p[0] + "X" * (len(p) - 1))
    return " ".join(masked)

def redact_value(key: str, val: Any) -> Any:
    if not isinstance(val, str):
        return val
    k = key.lower()
    s = val.strip()
    if k in ("phone", "contact"):
        return mask_phone(s)
    if k == "aadhar":
        return mask_aadhar(s)
    if k == "passport":
        return mask_passport(s)
    if k in ("upi", "upi_id"):
        return mask_upi(s) if UPI_RE.match(s) else s
    if k in ("name",):
        return mask_name(s)
    if k in ("first_name", "last_name"):
        return mask_name(s)
    if k == "email":
        return mask_email(s) if EMAIL_RE.match(s) else s
    if k in ("address", "address_proof"):
        return "[REDACTED_PII]"
    if k == "ip_address":
        return "x.x.x.x"
    if k == "device_id":
        return "[REDACTED_PII]"
    # Also mask embedded patterns if any
    s2 = mask_phone(mask_aadhar(mask_passport(s)))
    return s2

def detect_flags(record: Dict[str, Any]) -> Dict[str, bool]:
    # Standalone
    standalone = False
    # Check in specific fields to reduce false positives
    phone_present = any(
        isinstance(record.get(k), str) and bool(PHONE_RE.search(record.get(k)))
        for k in ("phone", "contact")
    )
    aadhar_present = isinstance(record.get("aadhar"), str) and bool(AADHAR_RE.search(record.get("aadhar")))
    passport_present = isinstance(record.get("passport"), str) and bool(PASSPORT_RE.search(record.get("passport") or ""))
    upi_present = isinstance(record.get("upi_id"), str) and bool(UPI_RE.match(record.get("upi_id") or ""))

    standalone = phone_present or aadhar_present or passport_present or upi_present

    # Combinatorial
    name_full = False
    if isinstance(record.get("name"), str) and len(record.get("name").split()) >= 2:
        name_full = True
    elif isinstance(record.get("first_name"), str) and isinstance(record.get("last_name"), str):
        if record.get("first_name").strip() and record.get("last_name").strip():
            name_full = True

    email_present = isinstance(record.get("email"), str) and bool(EMAIL_RE.match(record.get("email") or ""))

    address_present = False
    if isinstance(record.get("address"), str) and record.get("address").strip():
        # consider address "present" if it contains a number OR pin_code/ city present
        has_num = bool(re.search(r'\d', record.get("address")))
        has_pin_field = bool(record.get("pin_code") and PIN_RE.search(str(record.get("pin_code"))))
        has_city = bool(record.get("city"))
        address_present = has_num or has_pin_field or has_city

    device_or_ip = (
        (isinstance(record.get("ip_address"), str) and bool(IP_RE.search(record.get("ip_address") or ""))) or
        (isinstance(record.get("device_id"), str) and bool(DEVICE_RE.match(record.get("device_id") or "")))
    )

    combinatorial_count = sum([name_full, email_present, address_present, device_or_ip])

    return {
        "standalone": standalone,
        "name_full": name_full,
        "email_present": email_present,
        "address_present": address_present,
        "device_or_ip": device_or_ip,
        "combinatorial_count": combinatorial_count
    }

def process_record(data: Dict[str, Any]) -> (Dict[str, Any], bool, Dict[str, bool]):
    flags = detect_flags(data)
    is_pii = flags["standalone"] or (flags["combinatorial_count"] >= 2)

    if not is_pii:
        # Don't redact anything if not considered PII by rules
        return data, False, flags

    redacted = {}
    for k, v in data.items():
        redacted[k] = redact_value(k, v)

    # If combinatorial triggered by first_name/last_name pair, ensure they are masked
    if flags["combinatorial_count"] >= 2:
        for k in ("first_name", "last_name"):
            if k in redacted and isinstance(redacted[k], str):
                redacted[k] = mask_name(redacted[k])

    return redacted, True, flags

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_mohammed_yunus.py input.csv")
        sys.exit(1)

    in_csv = sys.argv[1]
    out_csv = in_csv.replace(".csv", "").replace(".CSV", "") + "_redacted_mohammed_yunus.csv"

    with open(in_csv, newline='', encoding='utf-8') as f_in, open(out_csv, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            record_id = row.get("record_id")
            raw = row.get("Data_json") or row.get("data_json")
            try:
                data = json.loads(raw)
            except Exception:
                # if not valid json, skip gracefully
                writer.writerow({"record_id": record_id, "redacted_data_json": raw, "is_pii": False})
                continue

            redacted, is_pii, _ = process_record(data)
            redacted_json = json.dumps(redacted, ensure_ascii=False)
            writer.writerow({"record_id": record_id, "redacted_data_json": redacted_json, "is_pii": bool(is_pii)})

    print(f"Wrote: {out_csv}")

if __name__ == "__main__":
    main()
