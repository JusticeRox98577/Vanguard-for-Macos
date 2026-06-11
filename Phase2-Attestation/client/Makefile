# Makefile -- Vanguard-for-macOS Phase 2 attestation client
# -----------------------------------------------------------------------------
# Builds the Swift client into a minimal .app bundle. App Attest will not work
# in a bare CLI binary: DCAppAttestService needs an application identity, so we
# wrap the executable in a bundle and sign it with YOUR Team + a provisioning
# profile that carries the App Attest entitlement (see README.md, "Signing").
#
#   make APP_BUNDLE_ID=com.yourteam.vanguard-attest SIGN_IDENTITY="Apple Development: you@example.com (XXXXXXXXXX)"
#   make run            -> launches the bundled executable directly
#
# Build on macOS only (links DeviceCheck/CryptoKit/Security).

APP_NAME      := VanguardAttest
APP_BUNDLE_ID ?= com.example.vanguard-attest
SIGN_IDENTITY ?= -
# Path to a provisioning profile that includes the App Attest entitlement for
# APP_BUNDLE_ID. Required for a working run; the build succeeds without it.
PROFILE       ?=

BUILD   := build
APP     := $(BUILD)/$(APP_NAME).app
BINDIR  := $(APP)/Contents/MacOS
SRC     := src/AttestationClient.swift
ENTITLE := entitlements/appattest.entitlements

.PHONY: all run clean

all: $(APP)

$(APP): $(SRC) $(ENTITLE)
	@mkdir -p $(BINDIR)
	# 1) Compile the Swift client.
	swiftc -O $(SRC) -o $(BINDIR)/$(APP_NAME)
	# 2) Minimal Info.plist so the bundle has an identity DeviceCheck accepts.
	printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	  '<plist version="1.0"><dict>' \
	  '  <key>CFBundleIdentifier</key><string>$(APP_BUNDLE_ID)</string>' \
	  '  <key>CFBundleName</key><string>$(APP_NAME)</string>' \
	  '  <key>CFBundleExecutable</key><string>$(APP_NAME)</string>' \
	  '  <key>CFBundlePackageType</key><string>APPL</string>' \
	  '</dict></plist>' > $(APP)/Contents/Info.plist
	# 3) Embed the provisioning profile (carries the App Attest entitlement
	#    grant for this bundle id) if provided.
	@if [ -n "$(PROFILE)" ]; then \
	  cp "$(PROFILE)" $(APP)/Contents/embedded.provisionprofile; \
	else \
	  echo "NOTE: no PROFILE= given; App Attest will report unsupported."; \
	fi
	# 4) Sign with the entitlement. Must be a real Team identity (not "-")
	#    for App Attest to function; ad-hoc still lets you exercise Step 1
	#    (raw Secure Enclave custody) on some configurations.
	codesign --force --sign "$(SIGN_IDENTITY)" \
	  --entitlements $(ENTITLE) --options runtime $(APP)
	@echo "built: $(APP)"

run: all
	$(BINDIR)/$(APP_NAME)

clean:
	rm -rf $(BUILD)
