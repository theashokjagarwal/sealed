"""Ed25519-signed compliance rule pack loader and evaluator."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from . import ed25519
from .security import SealedRulePackError, safe_json_loads


class RuleEngine:
    def __init__(self, pack: Dict[str, Any]) -> None:
        self.pack = pack
        self.header = pack["header"]
        self.rules = pack["rules"]
        self._by_target: Dict[str, Dict[str, Any]] = {
            r["detection_target"]: r for r in self.rules
        }

    @classmethod
    def load_and_verify(cls, pack_path: Path, allow_unsigned: bool = False) -> "RuleEngine":
        if not pack_path.is_file():
            raise SealedRulePackError(f"Rule pack file not found: '{pack_path}'")

        raw_text = pack_path.read_text(encoding="utf-8")
        pack = safe_json_loads(raw_text, max_bytes=5 * 1024 * 1024, max_depth=16)

        if not isinstance(pack, dict) or "header" not in pack or "rules" not in pack:
            raise SealedRulePackError("Malformed rule pack: missing 'header' or 'rules'")

        header = pack["header"]
        rules = pack["rules"]
        sig_hex = pack.get("signature", "")
        pub_hex = header.get("public_key", "")

        try:
            pub_bytes = bytes.fromhex(pub_hex)
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError as exc:
            if allow_unsigned:
                print(
                    "[WARN] Rule pack contains invalid hex signature. Proceeding under --allow-unsigned-rules.",
                    file=sys.stderr,
                )
                return cls(pack)
            raise SealedRulePackError(f"Rule pack signature verification failed: {exc}") from exc

        payload_for_signing = json.dumps(
            {"header": header, "rules": rules}, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

        if not ed25519.verify(pub_bytes, payload_for_signing, sig_bytes):
            if allow_unsigned:
                print(
                    "[WARN] Rule pack signature verification FAILED. Proceeding under --allow-unsigned-rules.",
                    file=sys.stderr,
                )
            else:
                raise SealedRulePackError(
                    f"Rule pack signature verification failed for '{pack_path}'"
                )

        return cls(pack)

    def map_target(self, target: str) -> Optional[Dict[str, Any]]:
        return self._by_target.get(target)
