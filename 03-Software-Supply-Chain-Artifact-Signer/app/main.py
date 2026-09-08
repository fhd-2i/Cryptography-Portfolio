import base64
from pathlib import Path

from app.hashing import sha256_file
from app.manifest import (
    build_manifest,
    load_manifest,
    save_manifest,
    verify_release,
)
from app.signing import (
    generate_keypair,
    sign_file,
    verify_file,
)


KEYS_DIR = Path("keys")
PRIVATE_KEY = KEYS_DIR / "private_key.pem"
PUBLIC_KEY = KEYS_DIR / "public_key.pem"

MANIFEST_FILE = Path("release_manifest.json")
MANIFEST_SIGNATURE_FILE = Path("release_manifest.sig")


def print_banner() -> None:
    print()
    print("=" * 58)
    print("       SOFTWARE SUPPLY CHAIN ARTIFACT SIGNER")
    print("=" * 58)
    print()
    print("SHA-256 Integrity Verification")
    print("Ed25519 Digital Signatures")
    print()


def pause() -> None:
    input("\nPress Enter to return to the main menu...")


def ensure_identity() -> bool:
    if PRIVATE_KEY.exists() and PUBLIC_KEY.exists():
        return True

    print()
    print("[!] No signing identity was found.")
    print("[!] Please generate one first using option [1].")
    return False


def generate_identity() -> None:
    KEYS_DIR.mkdir(exist_ok=True)

    if PRIVATE_KEY.exists() or PUBLIC_KEY.exists():
        print()
        print("[!] Signing keys already exist.")
        print("Private key:", PRIVATE_KEY.resolve())
        print("Public key :", PUBLIC_KEY.resolve())
        print()
        print("For safety, the tool will not overwrite them.")
        return

    generate_keypair(
        PRIVATE_KEY,
        PUBLIC_KEY,
    )

    print()
    print("[+] Ed25519 signing identity created successfully.")
    print()
    print("Private key:")
    print(PRIVATE_KEY.resolve())
    print()
    print("Public key:")
    print(PUBLIC_KEY.resolve())
    print()
    print("[!] Keep the private key secret.")
    print("[+] The public key can be shared with verifiers.")


def sign_single_file() -> None:
    if not ensure_identity():
        return

    print()
    print("=== Sign a File ===")
    print()
    file_input = input(
        "Enter the full path of the file to sign:\n> "
    ).strip().strip('"')

    file_path = Path(file_input)

    if not file_path.exists():
        print()
        print("[ERROR] File not found.")
        return

    if not file_path.is_file():
        print()
        print("[ERROR] The selected path is not a file.")
        return

    signature = sign_file(
        file_path,
        PRIVATE_KEY,
    )

    signature_path = Path(
        str(file_path) + ".sig"
    )

    signature_path.write_bytes(
        signature
    )

    file_hash = sha256_file(
        file_path
    )

    print()
    print("=" * 58)
    print("                 SIGNING RESULT")
    print("=" * 58)
    print()
    print("Artifact:")
    print(file_path.resolve())
    print()
    print("SHA-256:")
    print(file_hash)
    print()
    print("Signature:")
    print(signature_path.resolve())
    print()
    print("[+] ARTIFACT SIGNED SUCCESSFULLY")


def verify_single_file() -> None:
    if not ensure_identity():
        return

    print()
    print("=== Verify a File ===")
    print()

    file_input = input(
        "Enter the full path of the file to verify:\n> "
    ).strip().strip('"')

    file_path = Path(file_input)

    if not file_path.exists():
        print()
        print("[ERROR] File not found.")
        return

    signature_path = Path(
        str(file_path) + ".sig"
    )

    if not signature_path.exists():
        print()
        print("[ERROR] Signature file not found.")
        print()
        print("Expected signature:")
        print(signature_path)
        return

    signature = signature_path.read_bytes()

    valid = verify_file(
        file_path,
        signature,
        PUBLIC_KEY,
    )

    print()
    print("=" * 58)
    print("              VERIFICATION RESULT")
    print("=" * 58)
    print()

    print("Artifact:")
    print(file_path.resolve())
    print()

    if valid:
        print("Signature : VALID")
        print("Integrity : VERIFIED")
        print()
        print(
            "[+] The artifact has not been modified "
            "since it was signed."
        )
    else:
        print("Signature : INVALID")
        print("Integrity : FAILED")
        print()
        print(
            "[!] The artifact may have been modified "
            "after signing."
        )


def sign_folder() -> None:
    if not ensure_identity():
        return

    print()
    print("=== Sign a Folder / Software Release ===")
    print()

    folder_input = input(
        "Enter the full path of the folder to sign:\n> "
    ).strip().strip('"')

    folder_path = Path(folder_input)

    if not folder_path.exists():
        print()
        print("[ERROR] Folder not found.")
        return

    if not folder_path.is_dir():
        print()
        print("[ERROR] The selected path is not a folder.")
        return

    manifest = build_manifest(
        folder_path
    )

    manifest_path = folder_path.parent / (
        folder_path.name + "_manifest.json"
    )

    signature_path = folder_path.parent / (
        folder_path.name + "_manifest.sig"
    )

    save_manifest(
        manifest,
        manifest_path,
    )

    signature = sign_file(
        manifest_path,
        PRIVATE_KEY,
    )

    signature_path.write_bytes(
        signature
    )

    print()
    print("=" * 58)
    print("                RELEASE SIGNING")
    print("=" * 58)
    print()
    print("Folder:")
    print(folder_path.resolve())
    print()
    print("Files signed:", len(manifest["files"]))
    print()

    for file_name in manifest["files"]:
        print("[SIGNED]", file_name)

    print()
    print("Manifest:")
    print(manifest_path.resolve())
    print()
    print("Manifest signature:")
    print(signature_path.resolve())
    print()
    print("[+] SOFTWARE RELEASE SIGNED SUCCESSFULLY")


def verify_folder() -> None:
    if not ensure_identity():
        return

    print()
    print("=== Verify a Folder / Software Release ===")
    print()

    folder_input = input(
        "Enter the full path of the folder to verify:\n> "
    ).strip().strip('"')

    folder_path = Path(folder_input)

    if not folder_path.exists():
        print()
        print("[ERROR] Folder not found.")
        return

    if not folder_path.is_dir():
        print()
        print("[ERROR] The selected path is not a folder.")
        return

    manifest_path = folder_path.parent / (
        folder_path.name + "_manifest.json"
    )

    signature_path = folder_path.parent / (
        folder_path.name + "_manifest.sig"
    )

    if not manifest_path.exists():
        print()
        print("[ERROR] Release manifest not found.")
        print("Expected:")
        print(manifest_path)
        return

    if not signature_path.exists():
        print()
        print("[ERROR] Manifest signature not found.")
        print("Expected:")
        print(signature_path)
        return

    signature_valid = verify_file(
        manifest_path,
        signature_path.read_bytes(),
        PUBLIC_KEY,
    )

    print()
    print("=" * 58)
    print("              RELEASE VERIFICATION")
    print("=" * 58)
    print()

    print(
        "Manifest Signature:",
        "VALID" if signature_valid else "INVALID"
    )

    if not signature_valid:
        print()
        print("[!] The release manifest has been modified")
        print("    or was not signed by the trusted key.")
        print()
        print("[-] RELEASE VERIFICATION FAILED")
        return

    manifest = load_manifest(
        manifest_path
    )

    result = verify_release(
        folder_path,
        manifest,
    )

    print()

    for file_name in manifest["files"]:
        if (
            file_name not in result["modified"]
            and file_name not in result["missing"]
        ):
            print("[OK]", file_name)

    for file_name in result["modified"]:
        print("[MODIFIED]", file_name)

    for file_name in result["missing"]:
        print("[MISSING]", file_name)

    for file_name in result["added"]:
        print("[UNEXPECTED]", file_name)

    print()

    print(
        "Expected files:",
        len(manifest["files"]),
    )
    print(
        "Modified:",
        len(result["modified"]),
    )
    print(
        "Missing:",
        len(result["missing"]),
    )
    print(
        "Unexpected:",
        len(result["added"]),
    )

    print()

    if result["valid"]:
        print("[+] RELEASE VERIFIED")
        print(
            "[+] All artifacts match the signed manifest."
        )
    else:
        print("[-] RELEASE VERIFICATION FAILED")
        print(
            "[!] One or more release artifacts have changed."
        )


def inspect_signature() -> None:
    print()
    print("=== Inspect File Signature ===")
    print()

    file_input = input(
        "Enter the full path of the signed file:\n> "
    ).strip().strip('"')

    file_path = Path(file_input)
    signature_path = Path(
        str(file_path) + ".sig"
    )

    if not file_path.exists():
        print()
        print("[ERROR] File not found.")
        return

    if not signature_path.exists():
        print()
        print("[ERROR] Signature file not found.")
        return

    signature = signature_path.read_bytes()
    file_hash = sha256_file(
        file_path
    )

    print()
    print("Artifact:")
    print(file_path.resolve())
    print()
    print("Size:")
    print(file_path.stat().st_size, "bytes")
    print()
    print("SHA-256:")
    print(file_hash)
    print()
    print("Signature algorithm:")
    print("Ed25519")
    print()
    print("Signature size:")
    print(len(signature), "bytes")
    print()
    print("Signature (Base64):")
    print(
        base64.b64encode(
            signature
        ).decode("ascii")
    )


def show_help() -> None:
    print()
    print("=" * 58)
    print("                  HOW IT WORKS")
    print("=" * 58)
    print()
    print("1. SHA-256")
    print(
        "   The tool calculates a unique cryptographic "
        "fingerprint for each artifact."
    )
    print()
    print(
        "   If even one byte changes, the SHA-256 "
        "fingerprint changes."
    )

    print()
    print("2. Ed25519 Digital Signature")
    print(
        "   The private key signs an artifact or release "
        "manifest."
    )
    print()
    print(
        "   The public key verifies that signature."
    )

    print()
    print("3. File Signing")
    print(
        "   The tool signs the exact contents of one file."
    )
    print()
    print(
        "   If the file changes later, signature "
        "verification fails."
    )

    print()
    print("4. Software Release Signing")
    print(
        "   The tool calculates SHA-256 hashes for every "
        "file in a folder."
    )
    print()
    print(
        "   These hashes are stored in a release manifest."
    )
    print()
    print(
        "   The manifest itself is digitally signed "
        "using Ed25519."
    )

    print()
    print("5. Release Verification")
    print(
        "   The tool can detect:"
    )
    print("   - Modified files")
    print("   - Missing files")
    print("   - Unexpected files")
    print("   - Modified release manifests")

    print()
    print("Important:")
    print(
        "This tool detects unauthorized changes. "
        "It does not prevent a file from being modified."
    )


def main_menu() -> None:
    while True:
        print_banner()

        print("[1] Generate Signing Identity")
        print("[2] Sign a File")
        print("[3] Sign a Folder / Software Release")
        print("[4] Verify a File")
        print("[5] Verify a Folder / Software Release")
        print("[6] Inspect File Signature")
        print("[7] Help - How does this tool work?")
        print("[0] Exit")

        print()

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":
            generate_identity()
            pause()

        elif choice == "2":
            sign_single_file()
            pause()

        elif choice == "3":
            sign_folder()
            pause()

        elif choice == "4":
            verify_single_file()
            pause()

        elif choice == "5":
            verify_folder()
            pause()

        elif choice == "6":
            inspect_signature()
            pause()

        elif choice == "7":
            show_help()
            pause()

        elif choice == "0":
            print()
            print("Goodbye.")
            break

        else:
            print()
            print("[ERROR] Invalid option.")
            pause()


if __name__ == "__main__":
    main_menu()