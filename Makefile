# Variables
OS := linux
ARCH := amd64
EXPLORER_BIN := explorerv2_amd64
SFTPGUY_BIN := sftpguy_amd64
TAR_FILE := sftpguy.tar

# Default target when you just type 'make'
.PHONY: all
all: package

# 1. Run go generate
.PHONY: generate
generate:
	go generate

# 2. Build the Go binaries
.PHONY: build
build: generate
	GOOS=$(OS) GOARCH=$(ARCH) go build -o $(EXPLORER_BIN) ./cmd/explorer
	GOOS=$(OS) GOARCH=$(ARCH) go build -o $(SFTPGUY_BIN) .
	chmod a+x install.sh $(SFTPGUY_BIN) $(EXPLORER_BIN)

# 3. Create the tarball
.PHONY: package
package: build
	tar -cvf $(TAR_FILE) VERSION $(SFTPGUY_BIN) $(EXPLORER_BIN) install.sh

# 4. Clean up generated artifacts
.PHONY: clean
clean:
	rm -f $(EXPLORER_BIN) $(SFTPGUY_BIN) $(TAR_FILE)