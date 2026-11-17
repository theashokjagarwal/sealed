"""Deterministic filesystem discovery and AI surface classification."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .security import SealedSecurityError, validate_path_containment

IGNORED_DIRS = {".git", "node_modules", "target", "__pycache__", ".venv", "venv", "audit-artifacts"}
MAX_FILE_COUNT = 50_000


@dataclass(frozen=True)
class DiscoveredFile:
    relative_path: str
    absolute_path: Path
    size_bytes: int
    ai_surface_kind: Optional[str]


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(4096)
        return b"\x00" in chunk
    except OSError:
        return True


def classify_ai_surface(rel_path: str) -> Optional[str]:
    lower = rel_path.lower()
    if "prompt" in lower or lower.endswith(".prompt"):
        return "SystemPrompt"
    if "rag" in lower or "knowledge" in lower:
        return "RagKnowledge"
    if "tool" in lower or "agent" in lower:
        return "AgentTool"
    if "data" in lower or lower.endswith((".jsonl", ".csv", ".parquet")):
        return "TrainingData"
    if lower.endswith((".onnx", ".gguf", ".safetensors")):
        return "ModelArtifact"
    if "config" in lower or "secret" in lower or ".env" in lower or lower.endswith((".yaml", ".yml")):
        return "SecretConfig"
    return None


def discover_project(project_dir: Path) -> Tuple[Path, List[DiscoveredFile], int]:
    """Walk project deterministically, enforcing symlink boundaries and file caps."""
    canon_root = validate_path_containment(project_dir, project_dir)
    if not canon_root.is_dir():
        raise SealedSecurityError(f"Target path is not a directory: '{project_dir}'")

    discovered: List[DiscoveredFile] = []
    ai_surface_count = 0
    seen_dirs = set()
    file_count = 0

    for current_root, dirs, files in os.walk(canon_root, followlinks=False):
        real_dir = os.path.realpath(current_root)
        if real_dir in seen_dirs:
            dirs[:] = []
            continue
        seen_dirs.add(real_dir)

        # Deterministic alphabetical traversal
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        files.sort()

        for fname in files:
            if fname == ".DS_Store":
                continue
            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise SealedSecurityError(
                    f"Project file count exceeded safety cap of {MAX_FILE_COUNT}"
                )

            full_path = Path(current_root) / fname
            # Validate every single file (including symlinks) against canonical project root
            validate_path_containment(canon_root, full_path)

            rel_path = full_path.relative_to(canon_root).as_posix()
            surface_kind = classify_ai_surface(rel_path)

            if surface_kind in {"SystemPrompt", "RagKnowledge", "AgentTool", "ModelArtifact"}:
                ai_surface_count += 1

            if _is_binary(full_path):
                continue

            discovered.append(
                DiscoveredFile(
                    relative_path=rel_path,
                    absolute_path=full_path,
                    size_bytes=full_path.stat().st_size,
                    ai_surface_kind=surface_kind,
                )
            )

    discovered.sort(key=lambda f: f.relative_path)
    return canon_root, discovered, ai_surface_count
