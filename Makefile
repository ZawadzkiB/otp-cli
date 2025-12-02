.PHONY: build install clean setup

# Build standalone binary
build: setup
	.venv/bin/pyinstaller --onefile --name otp --clean --noconfirm otp.py

# Setup virtual environment and dependencies
setup:
	@if [ ! -d ".venv" ]; then \
		python3 -m venv .venv; \
		.venv/bin/pip install --upgrade pip; \
		.venv/bin/pip install pyinstaller pyperclip cryptography opencv-python-headless; \
	fi

# Install to /usr/local/bin (requires sudo)
install: build
	sudo cp ./dist/otp /usr/local/bin/otp
	@echo "Installed to /usr/local/bin/otp"

# Install to ~/bin (no sudo required)
install-user: build
	mkdir -p ~/bin
	cp ./dist/otp ~/bin/otp
	@echo "Installed to ~/bin/otp"
	@echo "Make sure ~/bin is in your PATH"

# Clean build artifacts
clean:
	rm -rf build dist *.spec .venv __pycache__
