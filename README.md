# OTP CLI

A simple command-line TOTP (Time-based One-Time Password) manager.

## Features

- Store 2FA secrets with aliases
- Generate TOTP codes from CLI
- Auto-copy to clipboard
- Encrypted storage with master password
- Export secrets for backup

## Installation

### Option A: Pre-built binary (recommended)

Download the pre-built binary from the releases page and copy it to your PATH:

```bash
# macOS/Linux
sudo cp otp /usr/local/bin/otp

# Or user-local installation (no sudo required)
mkdir -p ~/bin
cp otp ~/bin/otp
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Option B: Build from source

If you prefer to build the binary yourself:

```bash
# Using Makefile (recommended)
make build        # Build the binary
make install      # Build + install to /usr/local/bin (sudo)
make install-user # Build + install to ~/bin (no sudo)
make clean        # Remove build artifacts
```

Or manually:

```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install pyinstaller pyperclip cryptography

# Build standalone binary
pyinstaller --onefile --name otp --clean otp.py

# The binary will be at ./dist/otp
sudo cp ./dist/otp /usr/local/bin/otp
```

### Option C: Run with Python

If you have Python installed and prefer not to use a binary:

```bash
# Install dependencies
pip install pyperclip cryptography

# Add alias to your shell
echo "alias otp='python3 $(pwd)/otp.py'" >> ~/.zshrc
source ~/.zshrc
```

## Usage

### Initialize (set master password)

```bash
otp init
```

### Add a secret

```bash
# Basic
otp add github JBSWY3DPEHPK3PXP

# With issuer name
otp add github JBSWY3DPEHPK3PXP --issuer GitHub

# With custom digits/period
otp add steam ABCDEFGHIJK --digits 5 --period 30
```

### Get a code

```bash
otp get github
# Output: 123456 (copied to clipboard)

# With time remaining
otp get github -v
# Output: 123456 (copied to clipboard)
# Valid for 18s
```

### List all secrets

```bash
otp list
```

### Remove a secret

```bash
otp remove github

# Skip confirmation
otp remove github -f
```

### Edit a secret

```bash
# Rename an alias
otp edit github --rename gh

# Change issuer
otp edit github --issuer "GitHub Inc"

# Update secret key
otp edit github --secret NEWSECRETKEY

# Multiple changes at once
otp edit github --rename gh --issuer "GitHub Inc"
```

### Export (for backup)

```bash
otp export github
# Shows secret and otpauth:// URI for QR code generation
```

## Storage

Secrets are stored encrypted in:
- Linux/macOS: `~/.local/share/otp-cli/secrets.json`
- The file has 600 permissions (owner read/write only)

## Importing from Google Authenticator

### Option 1: Scan QR code from image (easiest)

```bash
# Scan a screenshot of the QR code
otp scan screenshot.png

# Preview without importing
otp scan screenshot.png --dry-run
```

Supports both:
- Standard TOTP QR codes (`otpauth://totp/...`)
- Google Authenticator export QR codes (`otpauth-migration://...`)

### Option 2: Import from URI

1. Open Google Authenticator
2. Tap ⋮ → Transfer accounts → Export accounts
3. Use a QR code scanner app to get the `otpauth-migration://` URI
4. Import directly:

```bash
# Preview what will be imported (dry run)
otp import --dry-run 'otpauth-migration://offline?data=...'

# Import all entries
otp import 'otpauth-migration://offline?data=...'
```

### Option 3: Add manually

```bash
otp add gmail YOUR_SECRET_KEY --issuer Google
otp add github YOUR_SECRET_KEY --issuer GitHub
```

## Security Notes

- Secrets are encrypted with AES-256 (Fernet) using PBKDF2 key derivation
- Master password is never stored
- Storage file has restrictive permissions (600)
- Consider using a strong, unique master password

## Dependencies

- `pyperclip` - Clipboard support
- `cryptography` - Encryption (optional but recommended)

Without `cryptography`, secrets will be stored in plain text (not recommended).
Without `pyperclip`, codes won't be copied to clipboard automatically.
