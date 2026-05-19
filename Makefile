# Variables
OS := linux
ARCH := amd64
EXPLORER_BIN := explorerv2_amd64
SFTPGUY_BIN := sftpguy_amd64
TAR_FILE := sftpguy.tar
ADMIN_V2_DIR := admin/v2
NPM ?= npm

# Default target when you just type 'make'
.PHONY: all
all: package

# 1. Run go generate
.PHONY: generate
generate:
	go generate

# 2. Build the Admin V2 frontend
.PHONY: admin-v2-build
admin-v2-build:
	cd $(ADMIN_V2_DIR) && $(NPM) ci && $(NPM) run build

.PHONY: admin-v2-dev
admin-v2-dev:
	cd $(ADMIN_V2_DIR) && $(NPM) run dev

.PHONY: admin-v2-check
admin-v2-check:
	cd $(ADMIN_V2_DIR) && $(NPM) run check

# 3. Build the Go binaries
.PHONY: build
build: admin-v2-build generate
	GOOS=$(OS) GOARCH=$(ARCH) go build -o $(EXPLORER_BIN) ./cmd/explorer
	GOOS=$(OS) GOARCH=$(ARCH) go build -o $(SFTPGUY_BIN) .
	chmod a+x install.sh $(SFTPGUY_BIN) $(EXPLORER_BIN)

# 4. Create the tarball
.PHONY: package
package: build
	tar -cvf $(TAR_FILE) VERSION $(SFTPGUY_BIN) $(EXPLORER_BIN) install.sh

# 5. Clean up generated artifacts
.PHONY: clean
clean:
	rm -f $(EXPLORER_BIN) $(SFTPGUY_BIN) $(TAR_FILE)
