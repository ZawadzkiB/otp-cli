.PHONY: build build-scan install install-user clean setup setup-scan

# Build fast binary (all commands except scan)
build: setup
	.venv/bin/pyinstaller --onefile --name otp --clean --noconfirm \
		--exclude-module cv2 \
		--exclude-module numpy \
		otp.py
	@echo ""
	@echo "Built: dist/otp (~1s startup)"
	@echo "Commands: add, get, list, remove, edit, export, import, init, cache"

# Build scan binary (only QR scanning, includes OpenCV)
build-scan: setup-scan
	.venv/bin/pyinstaller --onefile --name otp-scan --clean --noconfirm otp_scan.py
	@echo ""
	@echo "Built: dist/otp-scan (~4s startup, includes OpenCV)"
	@echo "Usage: otp-scan <image.png>"

# Build both binaries
all: build build-scan
	@echo ""
	@echo "Both binaries built in dist/"

# Setup virtual environment (minimal dependencies)
setup:
	@if [ ! -d ".venv" ]; then \
		python3 -m venv .venv; \
		.venv/bin/pip install --upgrade pip; \
		.venv/bin/pip install pyinstaller pyperclip cryptography; \
	fi

# Setup with OpenCV for QR scanning
setup-scan:
	@if [ ! -d ".venv" ]; then \
		python3 -m venv .venv; \
		.venv/bin/pip install --upgrade pip; \
	fi
	.venv/bin/pip install pyinstaller pyperclip cryptography opencv-python-headless

# Install both to /usr/local/bin (requires sudo)
install: build build-scan
	sudo cp ./dist/otp /usr/local/bin/otp
	sudo cp ./dist/otp-scan /usr/local/bin/otp-scan
	@echo "Installed otp and otp-scan to /usr/local/bin/"

# Install both to ~/bin (no sudo required)
install-user: build build-scan
	mkdir -p ~/bin
	cp ./dist/otp ~/bin/otp
	cp ./dist/otp-scan ~/bin/otp-scan
	@echo "Installed otp and otp-scan to ~/bin/"
	@echo "Make sure ~/bin is in your PATH"

# Clean build artifacts
clean:
	rm -rf build dist *.spec .venv __pycache__
