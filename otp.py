#!/usr/bin/env python3
"""
OTP CLI - A simple command-line TOTP manager
Usage:
    otp add <alias> <secret> [--issuer <name>]
    otp get <alias>
    otp list
    otp remove <alias>
    otp export <alias>
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from pathlib import Path
from getpass import getpass

# Optional: for clipboard support
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

# Optional: for encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

# Optional: for QR code scanning
try:
    import cv2
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False


# ==================== TOTP Implementation ====================

def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    """Generate HOTP code (RFC 4226)"""
    # Counter as 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)
    
    # HMAC-SHA1
    hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    
    # Generate OTP
    otp = truncated % (10 ** digits)
    return str(otp).zfill(digits)


def totp(secret: str, digits: int = 6, period: int = 30) -> str:
    """Generate TOTP code (RFC 6238)"""
    # Decode base32 secret (remove spaces and uppercase)
    secret_clean = secret.replace(" ", "").upper()
    # Add padding if needed
    padding = 8 - (len(secret_clean) % 8)
    if padding != 8:
        secret_clean += "=" * padding
    
    try:
        secret_bytes = base64.b32decode(secret_clean)
    except Exception as e:
        raise ValueError(f"Invalid secret key format: {e}")
    
    # Current time step
    counter = int(time.time()) // period
    
    return hotp(secret_bytes, counter, digits)


def get_time_remaining(period: int = 30) -> int:
    """Get seconds remaining until next TOTP rotation"""
    return period - (int(time.time()) % period)


# ==================== Password Cache ====================

PASSWORD_CACHE_TTL = 300  # 5 minutes


def get_cache_path() -> Path:
    """Get the path to the password cache file"""
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return Path(xdg_runtime) / f"otp-cli-{os.getuid()}.cache"


def get_cached_password() -> str | None:
    """Get cached password if still valid"""
    cache_path = get_cache_path()
    if not cache_path.exists():
        return None

    try:
        with open(cache_path, "r") as f:
            cache = json.load(f)
        if cache.get("expires", 0) > time.time():
            return cache.get("password")
        else:
            cache_path.unlink(missing_ok=True)
    except Exception:
        pass
    return None


def set_cached_password(password: str):
    """Cache password for TTL seconds"""
    cache_path = get_cache_path()
    cache = {"password": password, "expires": time.time() + PASSWORD_CACHE_TTL}
    with open(cache_path, "w") as f:
        json.dump(cache, f)
    os.chmod(cache_path, 0o600)


# ==================== Storage ====================

def get_storage_path() -> Path:
    """Get the path to the storage file"""
    # Use XDG_DATA_HOME or fallback to ~/.local/share
    xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    storage_dir = Path(xdg_data) / "otp-cli"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir / "secrets.json"


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password"""
    if not ENCRYPTION_AVAILABLE:
        raise RuntimeError("cryptography package not installed")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_data(data: str, password: str) -> dict:
    """Encrypt data with password"""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return {
        "salt": base64.b64encode(salt).decode(),
        "data": encrypted.decode(),
        "encrypted": True
    }


def decrypt_data(stored: dict, password: str) -> str:
    """Decrypt stored data"""
    salt = base64.b64decode(stored["salt"])
    key = derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(stored["data"].encode()).decode()


def load_secrets(password: str = None) -> dict:
    """Load secrets from storage"""
    storage_path = get_storage_path()

    if not storage_path.exists():
        return {}

    with open(storage_path, "r") as f:
        stored = json.load(f)

    if stored.get("encrypted"):
        if not ENCRYPTION_AVAILABLE:
            print("Error: Secrets are encrypted but cryptography package is not installed")
            print("Install with: pip install cryptography")
            sys.exit(1)

        if password is None:
            password = get_cached_password()
        if password is None:
            password = getpass("Enter master password: ")

        try:
            decrypted = decrypt_data(stored, password)
            set_cached_password(password)
            return json.loads(decrypted)
        except Exception:
            print("Error: Invalid password or corrupted data")
            sys.exit(1)

    return stored.get("secrets", {})


def save_secrets(secrets: dict, password: str = None, encrypt: bool = None):
    """Save secrets to storage"""
    storage_path = get_storage_path()

    # Check if we should encrypt
    if encrypt is None:
        # Check existing file
        if storage_path.exists():
            with open(storage_path, "r") as f:
                existing = json.load(f)
            encrypt = existing.get("encrypted", False)
        else:
            encrypt = ENCRYPTION_AVAILABLE

    if encrypt:
        if not ENCRYPTION_AVAILABLE:
            print("Warning: cryptography package not installed, storing unencrypted")
            encrypt = False
        elif password is None:
            password = get_cached_password()
        if password is None:
            password = getpass("Enter master password: ")

    if encrypt:
        stored = encrypt_data(json.dumps(secrets), password)
        set_cached_password(password)
    else:
        stored = {"secrets": secrets, "encrypted": False}

    with open(storage_path, "w") as f:
        json.dump(stored, f, indent=2)

    # Set restrictive permissions
    os.chmod(storage_path, 0o600)


# ==================== Commands ====================

def cmd_add(args):
    """Add a new OTP secret"""
    alias = args.alias.lower()
    secret = args.secret.replace(" ", "").upper()
    
    # Validate secret
    try:
        totp(secret)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    password = None
    storage_path = get_storage_path()
    
    if storage_path.exists():
        with open(storage_path, "r") as f:
            existing = json.load(f)
        if existing.get("encrypted"):
            password = getpass("Enter master password: ")
    elif ENCRYPTION_AVAILABLE:
        print("Setting up encryption for OTP storage...")
        password = getpass("Create master password: ")
        confirm = getpass("Confirm master password: ")
        if password != confirm:
            print("Error: Passwords don't match")
            sys.exit(1)
    
    secrets = load_secrets(password)
    
    if alias in secrets:
        confirm = input(f"Alias '{alias}' already exists. Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            print("Cancelled")
            return
    
    secrets[alias] = {
        "secret": secret,
        "issuer": args.issuer or "",
        "digits": args.digits,
        "period": args.period,
        "added": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    save_secrets(secrets, password)
    print(f"✓ Added '{alias}'")


def cmd_get(args):
    """Get OTP code for an alias"""
    alias = args.alias.lower()
    secrets = load_secrets()
    
    if alias not in secrets:
        print(f"Error: Alias '{alias}' not found")
        print(f"Use 'otp list' to see available aliases")
        sys.exit(1)
    
    entry = secrets[alias]
    secret = entry["secret"] if isinstance(entry, dict) else entry
    digits = entry.get("digits", 6) if isinstance(entry, dict) else 6
    period = entry.get("period", 30) if isinstance(entry, dict) else 30
    
    code = totp(secret, digits, period)
    remaining = get_time_remaining(period)
    
    # Copy to clipboard
    if CLIPBOARD_AVAILABLE:
        pyperclip.copy(code)
        clipboard_msg = " (copied to clipboard)"
    else:
        clipboard_msg = ""
    
    # Display
    print(f"{code}{clipboard_msg}")
    
    if args.verbose:
        print(f"Valid for {remaining}s")


def cmd_list(args):
    """List all stored aliases"""
    secrets = load_secrets()

    if not secrets:
        print("No OTP secrets stored")
        print("Add one with: otp add <alias> <secret>")
        return

    # Prepare data and calculate column widths
    rows = []
    for alias, entry in sorted(secrets.items()):
        if isinstance(entry, dict):
            issuer = entry.get("issuer", "-")
            added = entry.get("added", "-")
        else:
            issuer = "-"
            added = "-"
        rows.append((alias, issuer, added))

    # Calculate dynamic column widths (min 10, with 4-space gap)
    alias_width = max(len("Alias"), max(len(r[0]) for r in rows)) + 4
    issuer_width = max(len("Issuer"), max(len(r[1]) for r in rows)) + 4

    # Print header
    print(f"{'Alias':<{alias_width}}{'Issuer':<{issuer_width}}{'Added'}")
    print("-" * (alias_width + issuer_width + 19))

    # Print rows
    for alias, issuer, added in rows:
        print(f"{alias:<{alias_width}}{issuer:<{issuer_width}}{added}")


def cmd_remove(args):
    """Remove an OTP secret"""
    alias = args.alias.lower()
    
    password = None
    storage_path = get_storage_path()
    if storage_path.exists():
        with open(storage_path, "r") as f:
            existing = json.load(f)
        if existing.get("encrypted"):
            password = getpass("Enter master password: ")
    
    secrets = load_secrets(password)
    
    if alias not in secrets:
        print(f"Error: Alias '{alias}' not found")
        sys.exit(1)
    
    if not args.force:
        confirm = input(f"Remove '{alias}'? [y/N]: ")
        if confirm.lower() != 'y':
            print("Cancelled")
            return
    
    del secrets[alias]
    save_secrets(secrets, password)
    print(f"✓ Removed '{alias}'")


def cmd_edit(args):
    """Edit an existing OTP secret"""
    alias = args.alias.lower()

    password = None
    storage_path = get_storage_path()
    if storage_path.exists():
        with open(storage_path, "r") as f:
            existing = json.load(f)
        if existing.get("encrypted"):
            password = getpass("Enter master password: ")

    secrets = load_secrets(password)

    if alias not in secrets:
        print(f"Error: Alias '{alias}' not found")
        sys.exit(1)

    entry = secrets[alias]
    if not isinstance(entry, dict):
        entry = {"secret": entry, "issuer": "", "digits": 6, "period": 30}

    # Update fields if provided
    if args.secret:
        secret = args.secret.replace(" ", "").upper()
        try:
            totp(secret)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        entry["secret"] = secret

    if args.issuer is not None:
        entry["issuer"] = args.issuer

    if args.digits:
        entry["digits"] = args.digits

    if args.period:
        entry["period"] = args.period

    if args.rename:
        new_alias = args.rename.lower()
        if new_alias in secrets and new_alias != alias:
            print(f"Error: Alias '{new_alias}' already exists")
            sys.exit(1)
        del secrets[alias]
        alias = new_alias

    secrets[alias] = entry
    save_secrets(secrets, password)
    print(f"✓ Updated '{alias}'")


def cmd_export(args):
    """Export secret for an alias (for backup)"""
    alias = args.alias.lower()
    secrets = load_secrets()
    
    if alias not in secrets:
        print(f"Error: Alias '{alias}' not found")
        sys.exit(1)
    
    entry = secrets[alias]
    secret = entry["secret"] if isinstance(entry, dict) else entry
    issuer = entry.get("issuer", alias) if isinstance(entry, dict) else alias
    
    # Generate otpauth URI
    uri = f"otpauth://totp/{issuer}:{alias}?secret={secret}&issuer={issuer}"
    
    print(f"Secret: {secret}")
    print(f"URI: {uri}")


def parse_protobuf_varint(data: bytes, offset: int) -> tuple:
    """Parse a protobuf varint and return (value, new_offset)"""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset


def parse_migration_payload(data: bytes) -> list:
    """Parse Google Authenticator migration protobuf payload"""
    entries = []
    offset = 0

    while offset < len(data):
        # Read field tag
        tag, offset = parse_protobuf_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:  # OTP parameters (length-delimited)
            length, offset = parse_protobuf_varint(data, offset)
            entry_data = data[offset:offset + length]
            offset += length

            # Parse the OTP entry
            entry = parse_otp_entry(entry_data)
            if entry:
                entries.append(entry)
        elif wire_type == 0:  # Varint
            _, offset = parse_protobuf_varint(data, offset)
        elif wire_type == 2:  # Length-delimited
            length, offset = parse_protobuf_varint(data, offset)
            offset += length
        else:
            break

    return entries


def parse_otp_entry(data: bytes) -> dict:
    """Parse a single OTP entry from protobuf"""
    entry = {}
    offset = 0

    while offset < len(data):
        if offset >= len(data):
            break

        tag, offset = parse_protobuf_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 2:  # Length-delimited (string/bytes)
            length, offset = parse_protobuf_varint(data, offset)
            value = data[offset:offset + length]
            offset += length

            if field_number == 1:  # secret
                entry["secret"] = base64.b32encode(value).decode().rstrip("=")
            elif field_number == 2:  # name
                entry["name"] = value.decode("utf-8", errors="replace")
            elif field_number == 3:  # issuer
                entry["issuer"] = value.decode("utf-8", errors="replace")
        elif wire_type == 0:  # Varint
            value, offset = parse_protobuf_varint(data, offset)
            if field_number == 4:  # algorithm
                entry["algorithm"] = {1: "SHA1", 2: "SHA256", 3: "SHA512"}.get(value, "SHA1")
            elif field_number == 5:  # digits
                entry["digits"] = {1: 6, 2: 8}.get(value, 6)
            elif field_number == 6:  # type
                entry["type"] = {1: "HOTP", 2: "TOTP"}.get(value, "TOTP")
        else:
            break

    return entry if "secret" in entry else None


def cmd_import(args):
    """Import from Google Authenticator export"""
    from urllib.parse import unquote, urlparse, parse_qs

    uri = args.uri

    # Parse the migration URI
    if not uri.startswith("otpauth-migration://"):
        print("Error: Invalid migration URI. Expected otpauth-migration:// format")
        sys.exit(1)

    # Extract the data parameter
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    if "data" not in params:
        print("Error: No data parameter found in URI")
        sys.exit(1)

    # Decode the base64 data
    try:
        data_b64 = unquote(params["data"][0])
        data = base64.b64decode(data_b64)
    except Exception as e:
        print(f"Error decoding data: {e}")
        sys.exit(1)

    # Parse the protobuf
    entries = parse_migration_payload(data)

    if not entries:
        print("No OTP entries found in the migration data")
        sys.exit(1)

    print(f"Found {len(entries)} OTP entries:\n")

    for i, entry in enumerate(entries, 1):
        name = entry.get("name", "Unknown")
        issuer = entry.get("issuer", "")
        secret = entry.get("secret", "")
        otp_type = entry.get("type", "TOTP")
        digits = entry.get("digits", 6)

        print(f"{i}. {issuer} - {name}")
        print(f"   Secret: {secret}")
        print(f"   Type: {otp_type}, Digits: {digits}")
        print()

    if args.dry_run:
        print("Dry run - no secrets were imported")
        return

    # Ask for confirmation
    confirm = input("Import all entries? [y/N]: ")
    if confirm.lower() != "y":
        print("Cancelled")
        return

    # Load existing secrets
    password = None
    storage_path = get_storage_path()

    if storage_path.exists():
        with open(storage_path, "r") as f:
            existing = json.load(f)
        if existing.get("encrypted"):
            password = getpass("Enter master password: ")
    elif ENCRYPTION_AVAILABLE:
        print("Setting up encryption for OTP storage...")
        password = getpass("Create master password: ")
        confirm_pw = getpass("Confirm master password: ")
        if password != confirm_pw:
            print("Error: Passwords don't match")
            sys.exit(1)

    secrets = load_secrets(password)

    # Import entries
    imported = 0
    for entry in entries:
        name = entry.get("name", "").lower()
        issuer = entry.get("issuer", "")
        secret = entry.get("secret", "")

        # Generate alias from name
        alias = name.replace("@", "-").replace(" ", "-").replace(":", "-")
        alias = "".join(c for c in alias if c.isalnum() or c == "-")
        alias = alias.strip("-").lower()

        if not alias:
            alias = f"imported-{imported + 1}"

        # Handle duplicates
        base_alias = alias
        counter = 1
        while alias in secrets:
            alias = f"{base_alias}-{counter}"
            counter += 1

        secrets[alias] = {
            "secret": secret,
            "issuer": issuer,
            "digits": entry.get("digits", 6),
            "period": 30,
            "added": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        print(f"✓ Imported '{alias}' ({issuer})")
        imported += 1

    save_secrets(secrets, password)
    print(f"\n✓ Imported {imported} entries")


def parse_otpauth_uri(uri: str) -> dict | None:
    """Parse a standard otpauth://totp/ URI"""
    from urllib.parse import unquote, urlparse, parse_qs

    if not uri.startswith("otpauth://totp/"):
        return None

    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    # Extract secret
    secret = params.get("secret", [None])[0]
    if not secret:
        return None

    # Extract label (path contains issuer:account or just account)
    label = unquote(parsed.path.lstrip("/"))
    if ":" in label:
        issuer_from_label, name = label.split(":", 1)
    else:
        issuer_from_label = ""
        name = label

    # Issuer can be in params or label
    issuer = params.get("issuer", [issuer_from_label])[0]
    digits = int(params.get("digits", [6])[0])
    period = int(params.get("period", [30])[0])

    return {
        "secret": secret.upper(),
        "name": name,
        "issuer": issuer,
        "digits": digits,
        "period": period,
        "type": "TOTP"
    }


def cmd_scan(args):
    """Scan QR code from image file"""
    from urllib.parse import unquote, urlparse, parse_qs

    if not QR_AVAILABLE:
        print("Error: opencv-python-headless required for QR scanning")
        print("Install with: pip install opencv-python-headless")
        sys.exit(1)

    image_path = args.image
    if not os.path.exists(image_path):
        print(f"Error: File not found: {image_path}")
        sys.exit(1)

    # Read image and detect QR code
    img = cv2.imread(image_path)
    if img is None:
        print(f"Error: Could not read image: {image_path}")
        sys.exit(1)

    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)

    if not data:
        print("Error: No QR code found in image")
        sys.exit(1)

    print(f"Found QR code data: {data[:50]}..." if len(data) > 50 else f"Found QR code data: {data}")
    print()

    # Handle Google Authenticator migration format
    if data.startswith("otpauth-migration://"):
        parsed = urlparse(data)
        params = parse_qs(parsed.query)

        if "data" not in params:
            print("Error: No data parameter found in migration URI")
            sys.exit(1)

        try:
            data_b64 = unquote(params["data"][0])
            payload = base64.b64decode(data_b64)
        except Exception as e:
            print(f"Error decoding data: {e}")
            sys.exit(1)

        entries = parse_migration_payload(payload)

        if not entries:
            print("No OTP entries found in QR code")
            sys.exit(1)

        print(f"Found {len(entries)} OTP entries:\n")
        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry.get('issuer', '')} - {entry.get('name', 'Unknown')}")
            print(f"   Secret: {entry.get('secret', '')}")
            print()

    # Handle standard otpauth://totp/ format
    elif data.startswith("otpauth://totp/"):
        entry = parse_otpauth_uri(data)
        if not entry:
            print("Error: Could not parse otpauth URI")
            sys.exit(1)

        entries = [entry]
        print(f"Found 1 OTP entry:\n")
        print(f"1. {entry.get('issuer', '')} - {entry.get('name', 'Unknown')}")
        print(f"   Secret: {entry.get('secret', '')}")
        print()

    else:
        print(f"Error: Unsupported QR code format")
        print("Expected otpauth://totp/... or otpauth-migration://...")
        sys.exit(1)

    if args.dry_run:
        print("Dry run - no secrets were imported")
        return

    # Ask for confirmation
    confirm = input("Import entries? [y/N]: ")
    if confirm.lower() != "y":
        print("Cancelled")
        return

    # Load existing secrets
    password = None
    storage_path = get_storage_path()

    if storage_path.exists():
        with open(storage_path, "r") as f:
            existing = json.load(f)
        if existing.get("encrypted"):
            password = getpass("Enter master password: ")
    elif ENCRYPTION_AVAILABLE:
        print("Setting up encryption for OTP storage...")
        password = getpass("Create master password: ")
        confirm_pw = getpass("Confirm master password: ")
        if password != confirm_pw:
            print("Error: Passwords don't match")
            sys.exit(1)

    secrets = load_secrets(password)

    # Import entries
    imported = 0
    for entry in entries:
        name = entry.get("name", "").lower()
        issuer = entry.get("issuer", "")
        secret = entry.get("secret", "")

        # Generate alias from name
        alias = name.replace("@", "-").replace(" ", "-").replace(":", "-")
        alias = "".join(c for c in alias if c.isalnum() or c == "-")
        alias = alias.strip("-").lower()

        if not alias:
            alias = f"imported-{imported + 1}"

        # Handle duplicates
        base_alias = alias
        counter = 1
        while alias in secrets:
            alias = f"{base_alias}-{counter}"
            counter += 1

        secrets[alias] = {
            "secret": secret,
            "issuer": issuer,
            "digits": entry.get("digits", 6),
            "period": entry.get("period", 30),
            "added": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        print(f"✓ Imported '{alias}' ({issuer})")
        imported += 1

    save_secrets(secrets, password)
    print(f"\n✓ Imported {imported} entries")


def cmd_init(args):
    """Initialize or change master password"""
    storage_path = get_storage_path()
    
    if storage_path.exists():
        # Re-encrypt existing secrets
        old_password = getpass("Enter current master password: ")
        secrets = load_secrets(old_password)
        
        new_password = getpass("Enter new master password: ")
        confirm = getpass("Confirm new master password: ")
        
        if new_password != confirm:
            print("Error: Passwords don't match")
            sys.exit(1)
        
        save_secrets(secrets, new_password, encrypt=True)
        print("✓ Master password updated")
    else:
        # New setup
        if not ENCRYPTION_AVAILABLE:
            print("Error: cryptography package required for encryption")
            print("Install with: pip install cryptography")
            sys.exit(1)
        
        password = getpass("Create master password: ")
        confirm = getpass("Confirm master password: ")
        
        if password != confirm:
            print("Error: Passwords don't match")
            sys.exit(1)
        
        save_secrets({}, password, encrypt=True)
        print("✓ OTP storage initialized with encryption")


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(
        description="OTP CLI - A simple command-line TOTP manager",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new OTP secret")
    add_parser.add_argument("alias", help="Alias for the secret")
    add_parser.add_argument("secret", help="Base32 encoded secret key")
    add_parser.add_argument("--issuer", "-i", help="Issuer name (e.g., GitHub)")
    add_parser.add_argument("--digits", "-d", type=int, default=6, help="Number of digits (default: 6)")
    add_parser.add_argument("--period", "-p", type=int, default=30, help="Time period in seconds (default: 30)")
    
    # Get command
    get_parser = subparsers.add_parser("get", help="Get OTP code")
    get_parser.add_argument("alias", help="Alias of the secret")
    get_parser.add_argument("--verbose", "-v", action="store_true", help="Show time remaining")
    
    # List command
    subparsers.add_parser("list", help="List all stored aliases")
    
    # Remove command
    remove_parser = subparsers.add_parser("remove", help="Remove an OTP secret")
    remove_parser.add_argument("alias", help="Alias to remove")
    remove_parser.add_argument("--force", "-f", action="store_true", help="Skip confirmation")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export secret (for backup)")
    export_parser.add_argument("alias", help="Alias to export")

    # Edit command
    edit_parser = subparsers.add_parser("edit", help="Edit an existing OTP secret")
    edit_parser.add_argument("alias", help="Alias to edit")
    edit_parser.add_argument("--rename", "-r", help="Rename alias")
    edit_parser.add_argument("--secret", "-s", help="New secret key")
    edit_parser.add_argument("--issuer", "-i", help="New issuer name")
    edit_parser.add_argument("--digits", "-d", type=int, help="Number of digits")
    edit_parser.add_argument("--period", "-p", type=int, help="Time period in seconds")

    # Init command
    subparsers.add_parser("init", help="Initialize or change master password")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import from Google Authenticator export")
    import_parser.add_argument("uri", help="otpauth-migration:// URI from Google Authenticator export")
    import_parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be imported without saving")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan QR code from image file")
    scan_parser.add_argument("image", help="Path to image file containing QR code")
    scan_parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be imported without saving")

    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    commands = {
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "remove": cmd_remove,
        "export": cmd_export,
        "edit": cmd_edit,
        "init": cmd_init,
        "import": cmd_import,
        "scan": cmd_scan,
    }
    
    commands[args.command](args)


if __name__ == "__main__":
    main()
