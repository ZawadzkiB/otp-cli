# OTP CLI

A fast, secure command-line TOTP (Time-based One-Time Password) manager. Generate 2FA codes directly from your terminal without needing a phone app.

## Why OTP CLI?

- **Fast** - Get codes instantly with a single command (~1s startup)
- **Secure** - AES-256 encryption with master password protection
- **Portable** - Standalone binaries, no dependencies required
- **Private** - Everything stored locally, no cloud sync
- **Import-friendly** - Scan QR codes or import from Google Authenticator

---

# User Guide

## Quick Install

OTP CLI comes as two binaries:
- **`otp`** - Fast (~1s startup) for daily use: get, list, add, edit, remove, export, import, cache, init
- **`otp-scan`** - QR code scanning (~4s startup, includes OpenCV)

### One-line install (macOS/Linux)

**Install to /usr/local/bin (requires sudo):**
```bash
curl -fsSL https://github.com/ZawadzkiB/otp-cli/releases/download/0.0.2/otp -o /tmp/otp && \
curl -fsSL https://github.com/ZawadzkiB/otp-cli/releases/download/0.0.2/otp-scan -o /tmp/otp-scan && \
sudo mv /tmp/otp /tmp/otp-scan /usr/local/bin/ && \
sudo chmod +x /usr/local/bin/otp /usr/local/bin/otp-scan
```

**Or install to ~/bin (no sudo required):**
```bash
mkdir -p ~/bin && \
curl -fsSL https://github.com/ZawadzkiB/otp-cli/releases/download/0.0.2/otp -o ~/bin/otp && \
curl -fsSL https://github.com/ZawadzkiB/otp-cli/releases/download/0.0.2/otp-scan -o ~/bin/otp-scan && \
chmod +x ~/bin/otp ~/bin/otp-scan
```

> Note: If using `~/bin`, make sure it's in your PATH:
> ```bash
> echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
> ```

**Install only the fast binary (skip QR scanning):**
```bash
curl -fsSL https://github.com/ZawadzkiB/otp-cli/releases/download/0.0.2/otp -o ~/bin/otp && chmod +x ~/bin/otp
```

### Manual download

Download binaries from the [releases page](https://github.com/ZawadzkiB/otp-cli/releases) and place them in your PATH.

## Getting Started

### 1. Set up master password

First time using OTP CLI? Create a master password to encrypt your secrets:

```bash
#setup master password
otp init
```

You'll be prompted to create and confirm a master password. This password encrypts all your 2FA secrets.

### 2. Import your existing 2FA codes

**Option A: Scan a QR code image (easiest)**

Take a screenshot of your 2FA QR code, then:

```bash
otp-scan ~/Desktop/qr-screenshot.png
```

This works with:
- Standard TOTP QR codes from any service
- Google Authenticator export QR codes

**Option B: Import from Google Authenticator**

1. Open Google Authenticator app
2. Tap menu (⋮) → Transfer accounts → Export accounts
3. Screenshot the QR code
4. Run: `otp-scan screenshot.png`

**Option C: Add manually**

If you have the secret key:

```bash
otp add github JBSWY3DPEHPK3PXP --issuer GitHub
```

### 3. Generate codes

```bash
otp get github
# Output: 123456 (automatically copied to clipboard)
```

That's it! The code is generated and copied to your clipboard.

## Command Reference

### Generate a code

```bash
otp get <alias>

# Show time remaining until code expires
otp get github -v
# Output: 123456 (copied to clipboard)
# Valid for 18s
```

### List all entries

```bash
otp list
```

### Add a new entry

```bash
otp add <alias> <secret> [options]

# Examples:
otp add github JBSWY3DPEHPK3PXP
otp add github JBSWY3DPEHPK3PXP --issuer GitHub
otp add steam ABCDEFGHIJK --digits 5 --period 30
```

### Edit an entry

```bash
# Rename alias
otp edit github --rename gh

# Change issuer
otp edit github --issuer "GitHub Inc"

# Update secret key
otp edit github --secret NEWSECRETKEY

# Multiple changes
otp edit github --rename gh --issuer "GitHub Inc"
```

### Remove an entry

```bash
otp remove github

# Skip confirmation prompt
otp remove github -f
```

### Export (for backup)

```bash
otp export github
# Shows secret and otpauth:// URI for QR code generation
```

### Scan QR code from image

```bash
otp-scan screenshot.png

# Preview without importing
otp-scan screenshot.png --dry-run
```

### Import from Google Authenticator URI

```bash
otp import 'otpauth-migration://offline?data=...'

# Preview first
otp import --dry-run 'otpauth-migration://offline?data=...'
```

### Configure password caching

By default, your master password is cached for 5 minutes. You can change this:

```bash
# Show current setting
otp cache

# Set cache duration
otp cache 1min     # 1 minute
otp cache 5min     # 5 minutes (default)
otp cache day      # 24 hours
otp cache forever  # Until logout/reboot
```

### Change master password

```bash
otp init
# Enter current password, then new password
```

## Storage & Security

- **Location**: `~/.local/share/otp-cli/secrets.json`
- **Encryption**: AES-256 (Fernet) with PBKDF2 key derivation
- **Permissions**: File has 600 permissions (owner read/write only)
- **Password**: Never stored, only used to derive encryption key

---

# Development

## Building from Source

### Prerequisites

- Python 3.8+
- Make (optional but recommended)

### Using Makefile

```bash
make build        # Build fast otp binary (no OpenCV)
make build-scan   # Build otp-scan binary (with OpenCV)
make all          # Build both binaries
make install      # Build both + install to /usr/local/bin (requires sudo)
make install-user # Build both + install to ~/bin (no sudo)
make clean        # Remove build artifacts
```

### Manual build

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install pyinstaller pyperclip cryptography

# Build fast binary (excludes OpenCV)
pyinstaller --onefile --name otp --clean --exclude-module cv2 --exclude-module numpy otp.py

# Build scan binary (includes OpenCV)
pip install opencv-python-headless
pyinstaller --onefile --name otp-scan --clean otp_scan.py

# Binaries are at ./dist/otp and ./dist/otp-scan
```

### Run directly with Python

```bash
# Install dependencies
pip install pyperclip cryptography opencv-python-headless

# Run
python3 otp.py get github

# Or create an alias
alias otp='python3 /path/to/otp.py'
```

## Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| `pyperclip` | Clipboard support | Optional |
| `cryptography` | AES-256 encryption | Recommended |
| `opencv-python-headless` | QR code scanning | Optional |

Without `cryptography`, secrets are stored in plain text (not recommended).
Without `pyperclip`, codes won't auto-copy to clipboard.
Without `opencv-python-headless`, `otp-scan` command won't work.

## Project Structure

```
otp-cli/
├── otp.py           # Main CLI application
├── otp_scan.py      # QR scanner module (separate binary)
├── Makefile         # Build automation
├── dist/            # Built binaries (not gitignored)
│   ├── otp          # Fast binary (~5MB)
│   └── otp-scan     # Scanner binary (~50MB)
└── README.md
```

## Technical Details

- **TOTP Implementation**: RFC 6238 compliant
- **HOTP Implementation**: RFC 4226 compliant
- **Binary Sizes**:
  - `otp`: ~5MB (fast, no OpenCV)
  - `otp-scan`: ~50MB (includes Python runtime + OpenCV)
- **Supported Platforms**: macOS, Linux (x64, arm64)

## License

MIT
