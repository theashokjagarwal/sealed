"""Offline streaming PII and hardcoded credential scanner with Luhn Mod-10 validation."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b")
KEY_RE = re.compile(r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|(?:postgres|mysql|mongodb)://[^:]+:[^@]+@)")


@dataclass(frozen=True)
class PiiHit:
    kind: str
    file_path: str
    line_number: int
    masked_value: str
    snippet: str
    detection_target: str


def luhn_valid(number: str) -> bool:
    """Validate payment card candidate using the Luhn (Mod 10) checksum."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for idx, digit in enumerate(reversed(digits)):
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def scan_file_streaming(file_path: Path, rel_path: str) -> List[PiiHit]:
    """Stream file line-by-line (O(1) memory) to detect unmasked PII and exposed secrets."""
    hits: List[PiiHit] = []
    if not file_path.is_file():
        return hits

    with file_path.open("r", encoding="utf-8", errors="replace", buffering=65536) as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()

            # 1. Credit Cards (Luhn verified)
            for match in CARD_RE.finditer(raw_line):
                digits_only = re.sub(r"\D", "", match.group(0))
                if luhn_valid(digits_only):
                    masked = f"{digits_only[:4]}****{digits_only[-4:]}"
                    hits.append(
                        PiiHit(
                            kind="payment_card",
                            file_path=rel_path,
                            line_number=line_no,
                            masked_value=masked,
                            snippet=line,
                            detection_target="pii_leakage",
                        )
                    )

            # 2. Social Security Numbers
            for match in SSN_RE.finditer(raw_line):
                val = match.group(0)
                hits.append(
                    PiiHit(
                        kind="ssn",
                        file_path=rel_path,
                        line_number=line_no,
                        masked_value=f"***-**-{val[-4:]}",
                        snippet=line,
                        detection_target="pii_leakage",
                    )
                )

            # 3. Email Addresses
            for match in EMAIL_RE.finditer(raw_line):
                email = match.group(0)
                local, domain = email.split("@", 1)
                masked = f"{local[:2]}***@{domain}" if len(local) > 2 else "***@***.***"
                hits.append(
                    PiiHit(
                        kind="email",
                        file_path=rel_path,
                        line_number=line_no,
                        masked_value=masked,
                        snippet=line,
                        detection_target="pii_leakage",
                    )
                )

            # 4. Phone Numbers
            for match in PHONE_RE.finditer(raw_line):
                last4 = match.group(3)
                hits.append(
                    PiiHit(
                        kind="phone",
                        file_path=rel_path,
                        line_number=line_no,
                        masked_value=f"***-***-{last4}",
                        snippet=line,
                        detection_target="pii_leakage",
                    )
                )

            # 5. Exposed API Keys & Embedded DB Passwords
            for match in KEY_RE.finditer(raw_line):
                val = match.group(0)
                masked = f"{val[:7]}...[REDACTED]" if val.startswith("sk-") else "[CREDENTIAL_REDACTED]"
                hits.append(
                    PiiHit(
                        kind="secret_key",
                        file_path=rel_path,
                        line_number=line_no,
                        masked_value=masked,
                        snippet=line,
                        detection_target="credential_exposure",
                    )
                )

    return hits
