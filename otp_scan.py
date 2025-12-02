#!/usr/bin/env python3
"""
OTP CLI - QR Scanner module
This is a separate binary for QR code scanning (slow to start due to OpenCV)
"""

import argparse
import sys
import base64

# Import the main otp module for shared functionality
from otp import (
    debug_log, load_cv2, load_secrets, save_secrets,
    parse_migration_payload, set_cached_password,
    get_storage_path, ENCRYPTION_AVAILABLE
)
from getpass import getpass
from datetime import datetime
import os

debug_log("otp-scan module loaded")


def cmd_scan(args):
    """Scan QR code from image file"""
    from urllib.parse import unquote, urlparse, parse_qs

    # Load cv2
    if not load_cv2():
        print("Error: opencv-python-headless required for QR scanning")
        print("Install with: pip install opencv-python-headless")
        sys.exit(1)

    # Import cv2 after loading
    from otp import cv2

    image_path = args.image
    if not os.path.exists(image_path):
        print(f"Error: File not found: {image_path}")
        sys.exit(1)

    # Read image and detect QR code
    debug_log(f"Reading image: {image_path}")
    img = cv2.imread(image_path)
    if img is None:
        print(f"Error: Could not read image: {image_path}")
        sys.exit(1)

    debug_log("Detecting QR code...")
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)

    if not data:
        print("Error: No QR code found in image")
        sys.exit(1)

    print(f"Found QR code data: {data[:50]}..." if len(data) > 50 else f"Found QR code data: {data}")

    # Parse the QR code data
    entries = []

    if data.startswith("otpauth-migration://"):
        # Google Authenticator export
        debug_log("Parsing Google Authenticator migration data...")
        parsed = urlparse(data)
        params = parse_qs(parsed.query)
        migration_data = params.get("data", [None])[0]

        if not migration_data:
            print("Error: No data parameter in migration URI")
            sys.exit(1)

        # Decode base64 migration data
        try:
            data_b64 = unquote(migration_data)
            payload = base64.b64decode(data_b64)
        except Exception as e:
            print(f"Error decoding migration data: {e}")
            sys.exit(1)

        entries = parse_migration_payload(payload)

    elif data.startswith("otpauth://totp/") or data.startswith("otpauth://hotp/"):
        # Standard TOTP/HOTP URI
        debug_log("Parsing standard otpauth URI...")
        entry = parse_otpauth_uri(data)
        if entry:
            entries = [entry]

    else:
        print(f"Error: Unsupported QR code format")
        print(f"Expected otpauth:// or otpauth-migration:// URI")
        sys.exit(1)

    if not entries:
        print("Error: No valid OTP entries found in QR code")
        sys.exit(1)

    # Show what we found
    print(f"\nFound {len(entries)} OTP entries:")
    for entry in entries:
        alias = entry.get("name", "unknown").lower().replace(" ", "-").replace(":", "-")
        issuer = entry.get("issuer", "-")
        print(f"  - {alias} ({issuer})")

    if args.dry_run:
        print("\n[Dry run - no changes made]")
        return

    # Load existing secrets and import
    password = None
    storage_path = get_storage_path()

    if storage_path.exists():
        secrets = load_secrets()
    else:
        # First time - need to set up encryption
        if ENCRYPTION_AVAILABLE:
            print("\nSetting up encryption for OTP storage...")
            password = getpass("Create master password: ")
            confirm = getpass("Confirm master password: ")
            if password != confirm:
                print("Error: Passwords don't match")
                sys.exit(1)
            set_cached_password(password)
        secrets = {}

    # Import entries
    imported = 0
    for entry in entries:
        alias = entry.get("name", "unknown").lower().replace(" ", "-").replace(":", "-")

        if alias in secrets:
            print(f"  Skipping '{alias}' (already exists)")
            continue

        secrets[alias] = {
            "secret": entry.get("secret", ""),
            "issuer": entry.get("issuer", ""),
            "digits": entry.get("digits", 6),
            "period": entry.get("period", 30),
            "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        imported += 1
        print(f"  Imported '{alias}'")

    save_secrets(secrets)
    print(f"\n✓ Imported {imported} entries")


def parse_otpauth_uri(uri: str) -> dict:
    """Parse a standard otpauth:// URI"""
    from urllib.parse import unquote, urlparse, parse_qs

    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    # Extract label (path without leading /)
    label = unquote(parsed.path[1:]) if parsed.path else ""

    # Label format: "issuer:account" or just "account"
    if ":" in label:
        issuer, name = label.split(":", 1)
    else:
        issuer = params.get("issuer", [""])[0]
        name = label

    secret = params.get("secret", [""])[0]
    if not secret:
        return None

    return {
        "name": name or issuer or "unknown",
        "secret": secret.upper(),
        "issuer": params.get("issuer", [issuer])[0],
        "digits": int(params.get("digits", [6])[0]),
        "period": int(params.get("period", [30])[0]),
        "type": "TOTP"
    }


def main():
    debug_log("Entering main()")

    parser = argparse.ArgumentParser(
        description="OTP CLI - QR Code Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging with timing")
    parser.add_argument("image", help="Path to image file containing QR code")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be imported without saving")

    args = parser.parse_args()

    cmd_scan(args)


if __name__ == "__main__":
    main()
