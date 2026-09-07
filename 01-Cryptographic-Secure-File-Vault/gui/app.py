import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from getpass import getpass

from app.identity import (
    load_x25519_private_key,
    load_x25519_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
)

from app.vault_engine import (
    create_vault,
    decrypt_vault,
)


KEYS_DIRECTORY = "keys"


class SecureVaultGUI:
    """Graphical interface for the Cryptographic Secure File Vault."""

    def __init__(self, root: tk.Tk):
        self.root = root

        self.root.title(
            "Cryptographic Secure File Vault"
        )

        self.root.geometry(
            "900x700"
        )

        self.root.minsize(
            820,
            620,
        )

        self.root.configure(
            bg="#f4f6f8"
        )

        self.setup_style()
        self.build_interface()
        self.update_identity_status()

    # ---------------------------------------------------------
    # Styling
    # ---------------------------------------------------------

    def setup_style(self):
        """Configure ttk styles."""

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold"),
            background="#f4f6f8",
            foreground="#17202a",
        )

        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 11),
            background="#f4f6f8",
            foreground="#5f6b76",
        )

        style.configure(
            "Section.TLabel",
            font=("Segoe UI", 15, "bold"),
            background="#ffffff",
            foreground="#17202a",
        )

        style.configure(
            "Normal.TLabel",
            font=("Segoe UI", 10),
            background="#ffffff",
            foreground="#34404a",
        )

        style.configure(
            "Status.TLabel",
            font=("Segoe UI", 10, "bold"),
            background="#ffffff",
            foreground="#34404a",
        )

        style.configure(
            "Action.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(18, 10),
        )

        style.configure(
            "Small.TButton",
            font=("Segoe UI", 9),
            padding=(10, 7),
        )

    # ---------------------------------------------------------
    # Main interface
    # ---------------------------------------------------------

    def build_interface(self):
        """Build the main GUI."""

        main_frame = tk.Frame(
            self.root,
            bg="#f4f6f8",
        )

        main_frame.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=25,
        )

        # Header
        header = tk.Frame(
            main_frame,
            bg="#f4f6f8",
        )

        header.pack(
            fill="x",
            pady=(0, 20),
        )

        ttk.Label(
            header,
            text="Cryptographic Secure File Vault",
            style="Title.TLabel",
        ).pack(
            anchor="w"
        )

        ttk.Label(
            header,
            text=(
                "Secure file encryption using "
                "AES-256-GCM, X25519, HKDF-SHA256 "
                "and Ed25519."
            ),
            style="Subtitle.TLabel",
        ).pack(
            anchor="w",
            pady=(5, 0),
        )

        # Identity status
        status_frame = tk.Frame(
            main_frame,
            bg="#ffffff",
            highlightthickness=1,
            highlightbackground="#d9dee3",
        )

        status_frame.pack(
            fill="x",
            pady=(0, 15),
        )

        identity_header = tk.Frame(
            status_frame,
            bg="#ffffff",
        )

        identity_header.pack(
            fill="x",
            padx=20,
            pady=(15, 5),
        )

        ttk.Label(
            identity_header,
            text="Cryptographic Identity",
            style="Section.TLabel",
        ).pack(
            side="left"
        )

        self.identity_status = ttk.Label(
            identity_header,
            text="Checking...",
            style="Status.TLabel",
        )

        self.identity_status.pack(
            side="right"
        )

        ttk.Label(
            status_frame,
            text=(
                "Your X25519 and Ed25519 private keys are "
                "stored in protected form."
            ),
            style="Normal.TLabel",
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 15),
        )

        # Content
        content = tk.Frame(
            main_frame,
            bg="#f4f6f8",
        )

        content.pack(
            fill="both",
            expand=True,
        )

        content.columnconfigure(
            0,
            weight=1,
        )

        content.columnconfigure(
            1,
            weight=1,
        )

        # Encryption card
        self.build_encrypt_card(
            content
        )

        # Decryption card
        self.build_decrypt_card(
            content
        )

        # Security information
        security_frame = tk.Frame(
            main_frame,
            bg="#ffffff",
            highlightthickness=1,
            highlightbackground="#d9dee3",
        )

        security_frame.pack(
            fill="x",
            pady=(15, 0),
        )

        ttk.Label(
            security_frame,
            text="Security Architecture",
            style="Section.TLabel",
        ).pack(
            anchor="w",
            padx=20,
            pady=(15, 8),
        )

        security_text = (
            "AES-256-GCM  •  X25519 ECDH  •  HKDF-SHA256  •  "
            "Ed25519  •  SHA-256  •  Scrypt"
        )

        ttk.Label(
            security_frame,
            text=security_text,
            style="Normal.TLabel",
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 15),
        )

        # Bottom status
        self.status_var = tk.StringVar(
            value="Ready."
        )

        status_bar = tk.Frame(
            main_frame,
            bg="#f4f6f8",
        )

        status_bar.pack(
            fill="x",
            pady=(12, 0),
        )

        ttk.Label(
            status_bar,
            textvariable=self.status_var,
            style="Subtitle.TLabel",
        ).pack(
            anchor="w"
        )

    # ---------------------------------------------------------
    # Encryption card
    # ---------------------------------------------------------

    def build_encrypt_card(self, parent):
        """Build the encryption section."""

        frame = tk.Frame(
            parent,
            bg="#ffffff",
            highlightthickness=1,
            highlightbackground="#d9dee3",
        )

        frame.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8),
        )

        ttk.Label(
            frame,
            text="🔐  Encrypt File",
            style="Section.TLabel",
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 15),
        )

        ttk.Label(
            frame,
            text="Input file",
            style="Normal.TLabel",
        ).pack(
            anchor="w",
            padx=20,
        )

        input_row = tk.Frame(
            frame,
            bg="#ffffff",
        )

        input_row.pack(
            fill="x",
            padx=20,
            pady=(5, 15),
        )

        self.encrypt_input = tk.Entry(
            input_row,
            font=("Segoe UI", 10),
        )

        self.encrypt_input.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=7,
        )

        ttk.Button(
            input_row,
            text="Browse",
            style="Small.TButton",
            command=self.select_encrypt_input,
        ).pack(
            side="left",
            padx=(8, 0),
        )

        ttk.Label(
            frame,
            text="Output vault",
            style="Normal.TLabel",
        ).pack(
            anchor="w",
            padx=20,
        )

        output_row = tk.Frame(
            frame,
            bg="#ffffff",
        )

        output_row.pack(
            fill="x",
            padx=20,
            pady=(5, 20),
        )

        self.encrypt_output = tk.Entry(
            output_row,
            font=("Segoe UI", 10),
        )

        self.encrypt_output.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=7,
        )

        ttk.Button(
            output_row,
            text="Browse",
            style="Small.TButton",
            command=self.select_encrypt_output,
        ).pack(
            side="left",
            padx=(8, 0),
        )

        ttk.Button(
            frame,
            text="Encrypt File",
            style="Action.TButton",
            command=self.encrypt_file,
        ).pack(
            pady=(0, 20),
        )

    # ---------------------------------------------------------
    # Decryption card
    # ---------------------------------------------------------

    def build_decrypt_card(self, parent):
        """Build the decryption section."""

        frame = tk.Frame(
            parent,
            bg="#ffffff",
            highlightthickness=1,
            highlightbackground="#d9dee3",
        )

        frame.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0),
        )

        ttk.Label(
            frame,
            text="🔓  Decrypt Vault",
            style="Section.TLabel",
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 15),
        )

        ttk.Label(
            frame,
            text="Vault file",
            style="Normal.TLabel",
        ).pack(
            anchor="w",
            padx=20,
        )

        input_row = tk.Frame(
            frame,
            bg="#ffffff",
        )

        input_row.pack(
            fill="x",
            padx=20,
            pady=(5, 15),
        )

        self.decrypt_input = tk.Entry(
            input_row,
            font=("Segoe UI", 10),
        )

        self.decrypt_input.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=7,
        )

        ttk.Button(
            input_row,
            text="Browse",
            style="Small.TButton",
            command=self.select_decrypt_input,
        ).pack(
            side="left",
            padx=(8, 0),
        )

        ttk.Label(
            frame,
            text="Restored file",
            style="Normal.TLabel",
        ).pack(
            anchor="w",
            padx=20,
        )

        output_row = tk.Frame(
            frame,
            bg="#ffffff",
        )

        output_row.pack(
            fill="x",
            padx=20,
            pady=(5, 20),
        )

        self.decrypt_output = tk.Entry(
            output_row,
            font=("Segoe UI", 10),
        )

        self.decrypt_output.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=7,
        )

        ttk.Button(
            output_row,
            text="Browse",
            style="Small.TButton",
            command=self.select_decrypt_output,
        ).pack(
            side="left",
            padx=(8, 0),
        )

        ttk.Button(
            frame,
            text="Decrypt & Verify",
            style="Action.TButton",
            command=self.decrypt_file,
        ).pack(
            pady=(0, 20),
        )

    # ---------------------------------------------------------
    # Identity
    # ---------------------------------------------------------

    def identity_exists(self):
        """Check whether the cryptographic identity exists."""

        required_files = [
            "x25519_private.key",
            "x25519_public.key",
            "ed25519_private.key",
            "ed25519_public.key",
        ]

        keys_path = Path(
            KEYS_DIRECTORY
        )

        return (
            keys_path.exists()
            and all(
                (keys_path / filename).is_file()
                for filename in required_files
            )
        )

    def update_identity_status(self):
        """Update identity status in the GUI."""

        if self.identity_exists():
            self.identity_status.config(
                text="● Identity Ready"
            )
        else:
            self.identity_status.config(
                text="● Identity Not Initialized"
            )

    # ---------------------------------------------------------
    # File selection
    # ---------------------------------------------------------

    def select_encrypt_input(self):
        """Select plaintext file for encryption."""

        path = filedialog.askopenfilename(
            title="Select file to encrypt"
        )

        if path:
            self.encrypt_input.delete(
                0,
                tk.END,
            )

            self.encrypt_input.insert(
                0,
                path,
            )

            default_output = (
                str(Path(path).with_suffix(".vault"))
            )

            self.encrypt_output.delete(
                0,
                tk.END,
            )

            self.encrypt_output.insert(
                0,
                default_output,
            )

    def select_encrypt_output(self):
        """Select output vault path."""

        path = filedialog.asksaveasfilename(
            title="Save encrypted vault",
            defaultextension=".vault",
            filetypes=[
                (
                    "Vault files",
                    "*.vault",
                ),
                (
                    "All files",
                    "*.*",
                ),
            ],
        )

        if path:
            self.encrypt_output.delete(
                0,
                tk.END,
            )

            self.encrypt_output.insert(
                0,
                path,
            )

    def select_decrypt_input(self):
        """Select vault file for decryption."""

        path = filedialog.askopenfilename(
            title="Select vault file",
            filetypes=[
                (
                    "Vault files",
                    "*.vault",
                ),
                (
                    "All files",
                    "*.*",
                ),
            ],
        )

        if path:
            self.decrypt_input.delete(
                0,
                tk.END,
            )

            self.decrypt_input.insert(
                0,
                path,
            )

            default_output = (
                str(
                    Path(path).with_suffix("")
                )
            )

            if default_output.endswith("."):
                default_output = default_output[:-1]

            self.decrypt_output.delete(
                0,
                tk.END,
            )

            self.decrypt_output.insert(
                0,
                default_output + "_restored",
            )

    def select_decrypt_output(self):
        """Select restored file path."""

        path = filedialog.asksaveasfilename(
            title="Save restored file",
        )

        if path:
            self.decrypt_output.delete(
                0,
                tk.END,
            )

            self.decrypt_output.insert(
                0,
                path,
            )

    # ---------------------------------------------------------
    # Password dialog
    # ---------------------------------------------------------

    def ask_password(self, title):
        """Ask the user for the cryptographic password."""

        dialog = tk.Toplevel(
            self.root
        )

        dialog.title(
            title
        )

        dialog.geometry(
            "400x180"
        )

        dialog.resizable(
            False,
            False,
        )

        dialog.transient(
            self.root
        )

        dialog.grab_set()

        tk.Label(
            dialog,
            text="Enter your cryptographic password:",
            font=("Segoe UI", 10),
        ).pack(
            pady=(25, 8)
        )

        password_entry = tk.Entry(
            dialog,
            show="●",
            font=("Segoe UI", 11),
            width=32,
        )

        password_entry.pack(
            ipady=6
        )

        result = {
            "password": None
        }

        def submit():
            password = password_entry.get()

            if not password:
                messagebox.showerror(
                    "Password Required",
                    "Password cannot be empty.",
                    parent=dialog,
                )
                return

            result["password"] = password
            dialog.destroy()

        button = ttk.Button(
            dialog,
            text="Continue",
            command=submit,
        )

        button.pack(
            pady=15
        )

        password_entry.focus()

        dialog.bind(
            "<Return>",
            lambda event: submit()
        )

        self.root.wait_window(
            dialog
        )

        return result["password"]

    # ---------------------------------------------------------
    # Encryption
    # ---------------------------------------------------------

    def encrypt_file(self):
        """Encrypt selected file."""

        input_path = self.encrypt_input.get().strip()
        output_path = self.encrypt_output.get().strip()

        if not input_path:
            messagebox.showerror(
                "Missing Input",
                "Please select a file to encrypt.",
            )
            return

        if not output_path:
            messagebox.showerror(
                "Missing Output",
                "Please select an output vault.",
            )
            return

        if not self.identity_exists():
            messagebox.showerror(
                "Identity Not Found",
                (
                    "Cryptographic identity was not found.\n\n"
                    "Initialize the identity using the CLI:\n"
                    "python -m app.main init"
                ),
            )
            return

        if Path(output_path).exists():
            messagebox.showerror(
                "File Already Exists",
                (
                    "The output vault already exists.\n\n"
                    "Choose a different output filename."
                ),
            )
            return

        password = self.ask_password(
            "Encryption Password"
        )

        if password is None:
            return

        try:
            recipient_public_key = (
                load_x25519_public_key(
                    KEYS_DIRECTORY
                )
            )

            signing_private_key = (
                load_ed25519_private_key(
                    password,
                    KEYS_DIRECTORY,
                )
            )

            create_vault(
                input_path,
                output_path,
                recipient_public_key,
                signing_private_key,
            )

            self.status_var.set(
                "✓ Encryption completed successfully."
            )

            messagebox.showinfo(
                "Encryption Successful",
                (
                    "File encrypted successfully.\n\n"
                    f"Vault:\n{output_path}"
                ),
            )

        except Exception as exc:
            self.status_var.set(
                "✗ Encryption failed."
            )

            messagebox.showerror(
                "Encryption Failed",
                str(exc),
            )

    # ---------------------------------------------------------
    # Decryption
    # ---------------------------------------------------------

    def decrypt_file(self):
        """Decrypt and verify selected vault."""

        input_path = self.decrypt_input.get().strip()
        output_path = self.decrypt_output.get().strip()

        if not input_path:
            messagebox.showerror(
                "Missing Vault",
                "Please select a vault file.",
            )
            return

        if not output_path:
            messagebox.showerror(
                "Missing Output",
                "Please select the restored file path.",
            )
            return

        if not self.identity_exists():
            messagebox.showerror(
                "Identity Not Found",
                (
                    "Cryptographic identity was not found.\n\n"
                    "Initialize the identity using the CLI:\n"
                    "python -m app.main init"
                ),
            )
            return

        if Path(output_path).exists():
            messagebox.showerror(
                "File Already Exists",
                (
                    "The restored output file already exists.\n\n"
                    "Choose a different output filename."
                ),
            )
            return

        password = self.ask_password(
            "Decryption Password"
        )

        if password is None:
            return

        try:
            recipient_private_key = (
                load_x25519_private_key(
                    password,
                    KEYS_DIRECTORY,
                )
            )

            trusted_signing_public_key = (
                load_ed25519_public_key(
                    KEYS_DIRECTORY
                )
            )

            decrypt_vault(
                input_path,
                output_path,
                recipient_private_key,
                trusted_signing_public_key,
            )

            self.status_var.set(
                "✓ Decryption and integrity verification completed."
            )

            messagebox.showinfo(
                "Decryption Successful",
                (
                    "Vault verified and decrypted successfully.\n\n"
                    f"Restored file:\n{output_path}"
                ),
            )

        except Exception as exc:
            self.status_var.set(
                "✗ Decryption or verification failed."
            )

            messagebox.showerror(
                "Decryption Failed",
                str(exc),
            )


def main():
    """Launch the GUI."""

    root = tk.Tk()

    SecureVaultGUI(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()