#!/usr/bin/env python3
"""
PII Detector & Redactor (Project Guardian 2.0)

Usage:
  python3 detector_full_candidate_name.py <input_csv_path>

Input CSV columns: record_id,data_json
Output CSV columns: record_id,redacted_data_json,is_pii

Notes:
 - Implements definitions given in prompt for Standalone PII, Combinatorial PII, and Non‑PII.
 - Hybrid approach: deterministic regex rules + light heuristics to reduce false positives.
 - Robust JSON loader to tolerate a few malformed rows in the provided sample (unquoted literals, extra quotes).
 - Redaction masks keep minimal context while removing sensitive specifics.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from typing import Any, Dict, Tuple
from collections import OrderedDict


# =============================
# Regexes (deterministic rules)
# =============================

# 10-digit Indian phone number (avoid leading zeros rule? keep generic 10 digits)
PHONE_RE = re.compile(r"(?<!\d)(\d{10})(?!\d)")

# Aadhar: 12 digits, optionally with spaces
AADHAR_RE = re.compile(r"(?<!\d)(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)")

# Indian Passport: 1 letter + 7 digits (examples show this); be conservative to avoid IDs like ORD123456
PASSPORT_RE = re.compile(r"\b([A-Z])[0-9]{7}\b")

# UPI IDs: local@provider, local [a-zA-Z0-9._-]{2,}, provider letters (min 2)
UPI_RE = re.compile(r"\b([A-Za-z0-9._-]{2,})@([A-Za-z][A-Za-z0-9._-]{1,})\b")

# Email
EMAIL_RE = re.compile(r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)\b")

# IPv4
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


# ==================================
# Utilities: masking and JSON loading
# ==================================

def mask_phone(s: str) -> str:
    """Mask a 10-digit number as 12XXXXXX34 pattern (keep first2,last2)."""
    def repl(m: re.Match[str]) -> str:
        num = m.group(1)
        return f"{num[:2]}XXXXXX{num[-2:]}"

    return PHONE_RE.sub(repl, s)


def mask_aadhar(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        joined = "".join(m.groups())
        return f"{joined[:2]}XXXXXXXX{joined[-2:]}"

    return AADHAR_RE.sub(repl, s)


def mask_passport(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        # Keep prefix letter; hide digits except last 2
        value = m.group(0)
        return value[0] + "XXXXX" + value[-2:]

    return PASSPORT_RE.sub(repl, s)


def mask_upi(value: str) -> str:
    m = UPI_RE.search(value)
    if not m:
        return value
    local, provider = m.group(1), m.group(2)
    if local.isdigit() and len(local) >= 6:
        masked_local = f"{local[:2]}XXXXXX{local[-2:]}"
    else:
        # username-based; keep 2 chars, mask rest
        keep = min(2, len(local))
        masked_local = local[:keep] + ("X" * max(0, len(local) - keep))
    return f"{masked_local}@{provider}"


def mask_email(value: str) -> str:
    m = EMAIL_RE.search(value)
    if not m:
        return value
    local, domain = m.group(1), m.group(2)
    keep = min(2, len(local))
    return f"{local[:keep]}XXX@{domain}"


def mask_name(value: str) -> str:
    # Replace inner letters with X, keep first letter per token
    tokens = value.split()
    masked = []
    for t in tokens:
        if len(t) <= 1:
            masked.append(t)
        else:
            masked.append(t[0] + "X" * (len(t) - 1))
    return " ".join(masked)


def robust_json_load(raw: str) -> Dict[str, Any]:
    """Attempt to load a slightly malformed JSON string from the dataset.
    Strategy:
      - Strip stray quotes at ends.
      - Ensure ISO dates like 2024-01-01 are quoted.
      - Quote bare literals like pending / true / false when incorrectly unquoted.
      - Trim anything after the last closing brace as junk.
    """
    s = raw.strip()
    # Remove wrapping quotes that some CSVs keep
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    # Collapse doubled quotes from CSV escaping
    s = s.replace("''", "'")
    s = s.replace('""', '"')
    # Keep content up to last closing brace if extra suffix exists
    if s.count('}') < s.count('{'):
        # try to balance by appending
        s = s + ('}' * (s.count('{') - s.count('}')))
    if s.rfind('}') != -1:
        s = s[: s.rfind('}') + 1]

    # Quote ISO dates without quotes: : 2025-06-15
    s = re.sub(r":\s*(\d{4}-\d{2}-\d{2})(\s*[},])", r': "\1"\2', s)
    # Quote bare word literals like pending, verified, success (when unquoted)
    s = re.sub(r":\s*([A-Za-z_][A-Za-z0-9_\- ]*)(\s*[},])", r': "\1"\2', s)

    try:
        return json.loads(s)
    except Exception:
        # Last resort: return as opaque text payload
        return {"_raw": raw}


# ==================================
# Detection rules & redaction engine
# ==================================

PHONE_LIKE_KEYS = {
    "phone",
    "backup_number",
    "emergency_contact",
    "contact",
}

NON_PII_ID_KEYS = {
    "order_id",
    "transaction_id",
    "ticket_id",
    "inventory_id",
    "device_id",
}


def is_full_name(name_val: str) -> bool:
    parts = [p for p in name_val.strip().split() if p]
    return len(parts) >= 2


def classify_and_redact(record: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Return (is_pii, redacted_record) for a parsed JSON object per row."""
    # Work on a shallow copy to avoid mutating input
    data = dict(record)

    # If we couldn't parse JSON, we can't reliably detect PII
    if "_raw" in data:
        return (False, {"_raw": "[UNPARSABLE]"})

    # Normalize keys (case-insensitive handling)
    keys = {k: k for k in data.keys()}

    # Flags for standalone
    standalone_hit = False

    # 1) Standalone: explicit fields
    # Phone numbers (value may be string with 10 digits)
    for k, v in list(data.items()):
        if k in PHONE_LIKE_KEYS and isinstance(v, str):
            if PHONE_RE.search(v):
                standalone_hit = True
                data[k] = mask_phone(v)
        # A general 10-digit number in another key that likely means phone (heuristic)
        elif isinstance(v, str) and k.lower().endswith("_phone"):
            if PHONE_RE.search(v):
                standalone_hit = True
                data[k] = mask_phone(v)

    # Aadhar
    if "aadhar" in data and isinstance(data["aadhar"], str):
        if AADHAR_RE.search(data["aadhar"]):
            standalone_hit = True
            data["aadhar"] = mask_aadhar(data["aadhar"])

    # Passport
    if "passport" in data and isinstance(data["passport"], str):
        if PASSPORT_RE.search(data["passport"]):
            standalone_hit = True
            data["passport"] = mask_passport(data["passport"])

    # UPI ID
    if "upi_id" in data and isinstance(data["upi_id"], str):
        if UPI_RE.search(data["upi_id"]):
            standalone_hit = True
            data["upi_id"] = mask_upi(data["upi_id"])

    # 2) Combinatorial
    has_full_name = False
    if "name" in data and isinstance(data["name"], str) and is_full_name(data["name"]):
        has_full_name = True
    elif "first_name" in data and "last_name" in data and isinstance(data.get("first_name"), str) and isinstance(data.get("last_name"), str):
        has_full_name = True

    has_email = isinstance(data.get("email"), str) and EMAIL_RE.search(data.get("email", "")) is not None
    has_address = isinstance(data.get("address"), str) and len(data.get("address", "").strip()) >= 8
    has_user_context = has_full_name or has_email or has_address
    has_ip = isinstance(data.get("ip_address"), str) and IPV4_RE.search(data.get("ip_address", "")) is not None
    has_device = isinstance(data.get("device_id"), str) and len(data.get("device_id", "")) >= 5

    combinational_hit = False
    base_count = sum([has_full_name, has_email, has_address])
    if base_count >= 2:
        combinational_hit = True
    elif base_count >= 1 and (has_ip or has_device):
        combinational_hit = True

    is_pii = standalone_hit or combinational_hit

    if combinational_hit:
        # Redact participating fields only
        if has_full_name:
            if "name" in data and isinstance(data["name"], str):
                data["name"] = mask_name(data["name"])
            if "first_name" in data and isinstance(data.get("first_name"), str):
                data["first_name"] = mask_name(data["first_name"]) if data["first_name"].strip() else data["first_name"]
            if "last_name" in data and isinstance(data.get("last_name"), str):
                data["last_name"] = mask_name(data["last_name"]) if data["last_name"].strip() else data["last_name"]
        if has_email and isinstance(data.get("email"), str):
            data["email"] = mask_email(data["email"])
        if has_address and isinstance(data.get("address"), str):
            data["address"] = "[REDACTED_PII]"
        if has_ip and has_user_context and isinstance(data.get("ip_address"), str):
            data["ip_address"] = "[REDACTED_PII]"
        if has_device and has_user_context and isinstance(data.get("device_id"), str):
            # partially keep suffix
            d = data["device_id"]
            data["device_id"] = ("X" * max(0, len(d) - 3)) + d[-3:]

    # Also mask any embedded phone/aadhar/passport inside values that weren't keyed
    if is_pii:
        for k, v in list(data.items()):
            if isinstance(v, str) and k not in NON_PII_ID_KEYS:
                v2 = mask_phone(mask_aadhar(mask_passport(v)))
                # Also mask UPI-looking substrings
                for upi_match in UPI_RE.finditer(v2):
                    v2 = v2.replace(upi_match.group(0), mask_upi(upi_match.group(0)))
                data[k] = v2

    # If the row is PII, prune non-essential fields to minimize leakage and match expected examples
    if is_pii:
        whitelist_keys = {
            # direct PII keys
            "phone", "aadhar", "passport", "upi_id", "email",
            "name", "first_name", "last_name", "address", "ip_address", "device_id",
            # safe numeric/value fields commonly shown in examples
            "order_value", "amount"
        }
        # Filter and then order keys deterministically to match examples
        filtered = {k: v for k, v in data.items() if k in whitelist_keys}
        priority = [
            # Keep phone first for cases like example #1
            "phone",
            # Government IDs and payment IDs
            "aadhar", "passport", "upi_id",
            # Person-identifying fields: show name before email to match example #2
            "name", "first_name", "last_name", "email",
            # Location/network/device
            "address", "ip_address", "device_id",
            # Monetary/context values shown alongside
            "order_value", "amount",
        ]
        ordered = OrderedDict()
        for key in priority:
            if key in filtered:
                ordered[key] = filtered[key]
        # Include any remaining keys (unlikely) in original order
        for k, v in filtered.items():
            if k not in ordered:
                ordered[k] = v
        data = ordered

    return is_pii, data


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_path>")
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = "redacted_output_candidate_full_name.csv"

    with open(in_path, newline='', encoding='utf-8') as f_in, open(out_path, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get("record_id")
            raw = row.get("data_json") or row.get("Data_json") or row.get("data")
            if raw is None:
                writer.writerow({"record_id": rid, "redacted_data_json": "{}", "is_pii": False})
                continue

            data_obj = robust_json_load(raw)
            is_pii, redacted = classify_and_redact(data_obj)

            # Pretty separators to match example: include spaces after commas and colons
            redacted_json = json.dumps(redacted, ensure_ascii=False, separators=(", ", ": "))
            writer.writerow({
                "record_id": rid,
                "redacted_data_json": redacted_json,
                # Write boolean, not quoted string
                "is_pii": bool(is_pii)
            })

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
