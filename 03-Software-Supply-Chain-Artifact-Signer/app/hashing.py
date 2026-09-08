from pathlib import Path

from cryptography.hazmat.primitives import hashes


def sha256_file(file_path: Path) -> str:
    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Path is not a file: {file_path}"
        )

    digest = hashes.Hash(
        hashes.SHA256()
    )

    with file_path.open("rb") as file:
        while chunk := file.read(65536):
            digest.update(chunk)

    return digest.finalize().hex()