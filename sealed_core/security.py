"""Security validation controls: path containment, SSRF egress filter, parser limits, escaping, redaction."""

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class SealedSecurityError(Exception):
    """Raised when an untrusted input triggers a security boundary control."""


class SealedRulePackError(Exception):
    """Raised when a compliance rule pack fails schema or Ed25519 signature checks."""


BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
    "metadata.azure.com",
}


def validate_path_containment(root_path: Path, target_path: Path) -> Path:
    """Reject '..' traversal components and symlinks escaping the canonical project root."""
    raw_str = str(target_path)
    for segment in re.split(r"[\\/]", raw_str):
        if segment == "..":
            raise SealedSecurityError(
                f"Path traversal attack detected: path '{raw_str}' contains '..' component"
            )

    if not root_path.exists():
        raise SealedSecurityError(f"Project root does not exist: '{root_path}'")
    if not target_path.exists():
        raise SealedSecurityError(f"Target path does not exist: '{target_path}'")

    canon_root = Path(os.path.realpath(root_path))
    canon_target = Path(os.path.realpath(target_path))

    try:
        canon_target.relative_to(canon_root)
    except ValueError as exc:
        raise SealedSecurityError(
            f"Symlink escape detected: '{target_path}' resolves to '{canon_target}', "
            f"outside project boundary '{canon_root}'"
        ) from exc

    return canon_target


def validate_egress_endpoint(url_str: str, allow_private: bool = False) -> None:
    """Deny-by-default egress validator against SSRF, cloud metadata, and private IP abuse."""
    parsed = urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise SealedSecurityError(
            f"Egress violation: only HTTP/HTTPS protocols are permitted ('{url_str}')"
        )

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise SealedSecurityError("Egress violation: empty host specification")

    if host in BLOCKED_METADATA_HOSTS:
        raise SealedSecurityError(
            f"SSRF Blocked: attempted access to cloud instance metadata service ('{host}')"
        )

    if host == "localhost" and not allow_private:
        raise SealedSecurityError("SSRF Blocked: loopback host 'localhost' is denied")

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise SealedSecurityError(
                f"SSRF Blocked: loopback or link-local IP address ('{ip}')"
            )
        if ip.is_private and not allow_private:
            raise SealedSecurityError(
                f"SSRF Blocked: private RFC1918/ULA address ('{ip}') requires --allow-private-endpoints"
            )
    except ValueError:
        # Hostname rather than literal IP; acceptable for non-metadata public hostnames
        pass


def _measure_depth(obj: Any, current: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return current + 1
        return max(_measure_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current + 1
        return max(_measure_depth(v, current + 1) for v in obj)
    return current


def safe_json_loads(raw_text: str, max_bytes: int = 5 * 1024 * 1024, max_depth: int = 16) -> Any:
    """Parse JSON with strict input size and recursion depth limits."""
    if len(raw_text.encode("utf-8")) > max_bytes:
        raise SealedSecurityError(
            f"Parser limit exceeded: JSON input larger than {max_bytes} bytes"
        )
    try:
        parsed = json.loads(raw_text)
    except RecursionError as exc:
        raise SealedSecurityError("Parser limit exceeded: JSON recursion overflow") from exc
    if _measure_depth(parsed) > max_depth:
        raise SealedSecurityError(
            f"Parser limit exceeded: JSON nesting depth exceeded limit of {max_depth}"
        )
    return parsed


def html_escape(value: Any) -> str:
    """Strict contextual HTML escaping to prevent stored XSS in audit reports."""
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def redact_credentials(text: str) -> str:
    """Redact API keys and embedded connection passwords from logs and errors."""
    out = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "sk-[REDACTED]", text)
    out = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED]", out)
    out = re.sub(r"://([^:]+):([^@]+)@", r"://\1:[REDACTED]@", out)
    return out
