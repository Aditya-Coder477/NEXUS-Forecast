"""
Backend Utility Functions: Hashing, Validation, Error Handling.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any
from fastapi import HTTPException


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_file_integrity(expected_hash: str, file_path: Path) -> bool:
    """Verify that a file's SHA-256 hash matches the expected value."""
    actual_hash = compute_sha256(file_path)
    return actual_hash.lower() == expected_hash.lower()


def safe_path_join(base_dir: Path, subpath: str) -> Path:
    """Safely resolve a subpath within base_dir, preventing path traversal attacks."""
    resolved_base = base_dir.resolve()
    resolved_target = (base_dir / subpath).resolve()
    if not str(resolved_target).startswith(str(resolved_base)):
        raise HTTPException(status_code=400, detail="Invalid path: Directory traversal detected")
    return resolved_target
