# Variables
OS := linux
ARCH := amd64
EXPLORER_BIN := explorerv2_amd64
SFTPGUY_BIN := sftpguy_amd64
TAR_FILE := sftpguy.tar
ADMIN_V2_DIR := admin/v2
NPM ?= npm
ADMIN_HTTP ?= 127.0.0.1:8080
TEST_HOST ?= localhost
TEST_PORT ?= 2222
TEST_SYSTEM ?= public
TEST_THRESHOLD ?= 1048576
TEST_NOAUTH ?= true
TEST_HOSTKEY ?=
TEST_ADMINKEY ?=
TEST_CLIENT_VERBOSE ?= false
TEST_CLIENT_EXTRA ?=
TEST_SELF_EXTRA ?=

TEST_CLIENT_FLAGS := -host $(TEST_HOST) -port $(TEST_PORT) -system $(TEST_SYSTEM) -threshold $(TEST_THRESHOLD) -noauth=$(TEST_NOAUTH)
ifneq ($(strip $(TEST_HOSTKEY)),)
TEST_CLIENT_FLAGS += -hostkey $(TEST_HOSTKEY)
endif
ifneq ($(strip $(TEST_ADMINKEY)),)
TEST_CLIENT_FLAGS += -adminkey $(TEST_ADMINKEY)
endif
ifneq ($(filter true 1 yes,$(TEST_CLIENT_VERBOSE)),)
TEST_CLIENT_FLAGS += -v
endif

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

.PHONY: test-ui
test-ui:
	cd $(ADMIN_V2_DIR) && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u MAKE_TERMOUT -u MAKE_TERMERR $(NPM) run test:ui

.PHONY: test-ui-headed
test-ui-headed:
	cd $(ADMIN_V2_DIR) && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u MAKE_TERMOUT -u MAKE_TERMERR $(NPM) run test:ui:headed

.PHONY: test-ui-install
test-ui-install:
	cd $(ADMIN_V2_DIR) && $(NPM) run test:ui:install

.PHONY: test-self
test-self:
	go run . -test $(TEST_SELF_EXTRA)

.PHONY: test-self-serve
test-self-serve:
	go run . -test.continue -admin.http $(ADMIN_HTTP) $(TEST_SELF_EXTRA)

.PHONY: test-client
test-client:
	go run -tags testclient test_client.go $(TEST_CLIENT_FLAGS) $(TEST_CLIENT_EXTRA)

.PHONY: test-client-verbose
test-client-verbose:
	$(MAKE) test-client TEST_CLIENT_VERBOSE=true

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
