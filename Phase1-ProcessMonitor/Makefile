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

all: $(BUILD)/$(BIN)

# 1) Compile.
$(BUILD)/$(BIN): $(SRC) | $(BUILD)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)
	@$(MAKE) --no-print-directory sign

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
	@codesign --display --entitlements - $(BUILD)/$(BIN) 2>/dev/null || true

# 3) Run. ES clients must be root.
run: all
	sudo $(BUILD)/$(BIN) $(TARGET)

clean:
	rm -rf $(BUILD)
