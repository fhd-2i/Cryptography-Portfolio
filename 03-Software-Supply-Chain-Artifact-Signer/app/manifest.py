import json
from pathlib import Path

from app.hashing import sha256_file


def build_manifest(release_dir: Path) -> dict:
    if not release_dir.exists():
        raise FileNotFoundError(
            f"Release directory not found: {release_dir}"
        )

    if not release_dir.is_dir():
        raise ValueError(
            f"Path is not a directory: {release_dir}"
        )

    files = {}

    for file_path in sorted(release_dir.rglob("*")):
        if not file_path.is_file():
            continue

        if file_path.name.endswith(".sig"):
            continue

        relative_path = file_path.relative_to(
            release_dir
        ).as_posix()

        files[relative_path] = {
            "sha256": sha256_file(file_path),
            "size": file_path.stat().st_size,
        }

    return {
        "version": 1,
        "algorithm": "SHA-256",
        "files": files,
    }


def save_manifest(
    manifest: dict,
    output_path: Path,
) -> None:
    output_path.write_text(
        json.dumps(
            manifest,
            indent=4,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def load_manifest(
    manifest_path: Path,
) -> dict:
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Manifest not found: {manifest_path}"
        )

    return json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )


def verify_release(
    release_dir: Path,
    manifest: dict,
) -> dict:
    expected_files = manifest.get(
        "files",
        {},
    )

    current_manifest = build_manifest(
        release_dir
    )

    current_files = current_manifest["files"]

    modified = []
    missing = []
    added = []

    for file_name, expected_info in expected_files.items():
        if file_name not in current_files:
            missing.append(file_name)
            continue

        current_info = current_files[file_name]

        if (
            current_info["sha256"]
            != expected_info["sha256"]
        ):
            modified.append(file_name)

    for file_name in current_files:
        if file_name not in expected_files:
            added.append(file_name)

    return {
        "valid": not modified and not missing and not added,
        "modified": modified,
        "missing": missing,
        "added": added,
    }