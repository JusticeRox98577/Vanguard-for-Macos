# Makefile -- Vanguard-for-macOS Phase 1 process monitor
# -----------------------------------------------------------------------------
# Builds and code-signs the Endpoint Security monitor. Requires the Xcode
# command line tools (clang, codesign). Build on macOS; this target cannot be
# produced or run on Linux because it links the system EndpointSecurity library.
#
#   make            -> compile + ad-hoc sign with the ES entitlement
#   make run        -> build, then run under sudo (monitors everything)
#   make run TARGET=MyGame  -> protect a named process (escalates task access)
#   make clean      -> remove build artifacts

BIN          := vanguard_monitor
SRC          := src/vanguard_monitor.c
ENTITLEMENTS := entitlements/vanguard.entitlements
BUILD        := build

# C11 for stdbool/anonymous unions; warnings on; ES + BSM are system libs.
CC      := clang
CFLAGS  := -std=c11 -Wall -Wextra -O2
LDFLAGS := -lEndpointSecurity -lbsm

# Ad-hoc signing identity ("-") is fine for local research once SIP/AMFI are
# relaxed (see README). Replace with your Developer ID + a provisioning
# profile that carries the granted ES entitlement for a "real" build.
CODESIGN_IDENTITY ?= -

TARGET ?=

.PHONY: all sign run clean

# `all` always runs `sign`, which depends on the binary. Because `sign` is
# phony it re-signs on every `make` even when the binary is already built --
# so a previously-failed sign (e.g. a bad entitlements file) is never left
# behind as an unsigned binary that `make` then refuses to touch.
all: sign

# 1) Compile. Re-runs if the source OR the entitlements change.
$(BUILD)/$(BIN): $(SRC) $(ENTITLEMENTS) | $(BUILD)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

$(BUILD):
	@mkdir -p $(BUILD)

# 2) Sign with the Endpoint Security entitlement. Without this, es_new_client()
#    returns ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED at runtime.
sign: $(BUILD)/$(BIN)
	codesign --force --sign "$(CODESIGN_IDENTITY)" \
		--entitlements $(ENTITLEMENTS) \
		--options runtime \
		$(BUILD)/$(BIN)
	@echo "signed: $(BUILD)/$(BIN)"
	@echo "--- entitlements now on the binary: ---"
	@codesign --display --entitlements - $(BUILD)/$(BIN) 2>/dev/null || true

# 3) Run. ES clients must be root.
run: all
	sudo $(BUILD)/$(BIN) $(TARGET)

# -----------------------------------------------------------------------------
# Signed release — runs on STOCK macOS (no SIP disabling) once Apple has
# granted your Team the Endpoint Security entitlement.
#
# A restricted entitlement must be authorized by a provisioning profile, and a
# bare Mach-O can't embed one — so we package the executable in a .app bundle
# (still run as root) and embed the profile at Contents/embedded.provisionprofile.
#
# Required variables (all three):
#   SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#   PROFILE=/path/to/Vanguard_Monitor.provisionprofile   # must list the ES entitlement
#   APP_BUNDLE_ID=com.yourteam.vanguard-monitor          # must match the profile's App ID
#
# Example:
#   make release \
#     SIGN_IDENTITY="Developer ID Application: Jane Dev (AB12CD34EF)" \
#     PROFILE=~/Downloads/Vanguard_Monitor.provisionprofile \
#     APP_BUNDLE_ID=com.janedev.vanguard-monitor
RELEASE_APP   := $(BUILD)/Vanguard.app
APP_BUNDLE_ID ?= com.example.vanguard-monitor

.PHONY: release
release: | $(BUILD)
	@test -n "$(PROFILE)" || { echo "ERROR: set PROFILE=/path/to/your.provisionprofile"; exit 1; }
	@test "$(SIGN_IDENTITY)" != "-" || { echo "ERROR: set SIGN_IDENTITY to your Developer ID (not ad-hoc '-')"; exit 1; }
	$(CC) $(CFLAGS) $(SRC) -o $(BUILD)/$(BIN) $(LDFLAGS)
	mkdir -p $(RELEASE_APP)/Contents/MacOS
	cp $(BUILD)/$(BIN) $(RELEASE_APP)/Contents/MacOS/$(BIN)
	printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	  '<plist version="1.0"><dict>' \
	  '  <key>CFBundleIdentifier</key><string>$(APP_BUNDLE_ID)</string>' \
	  '  <key>CFBundleName</key><string>Vanguard</string>' \
	  '  <key>CFBundleExecutable</key><string>$(BIN)</string>' \
	  '  <key>CFBundlePackageType</key><string>APPL</string>' \
	  '</dict></plist>' > $(RELEASE_APP)/Contents/Info.plist
	cp "$(PROFILE)" $(RELEASE_APP)/Contents/embedded.provisionprofile
	codesign --force --sign "$(SIGN_IDENTITY)" \
		--entitlements $(ENTITLEMENTS) \
		--options runtime --timestamp \
		$(RELEASE_APP)
	@echo "built signed bundle: $(RELEASE_APP)"
	@echo "verify: codesign -dv --entitlements - $(RELEASE_APP)"
	@echo "run:    sudo $(RELEASE_APP)/Contents/MacOS/$(BIN) <target>"
	@echo "NOTE: notarize before distributing — xcrun notarytool submit ..."

clean:
	rm -rf $(BUILD)
