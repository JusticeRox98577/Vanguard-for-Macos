# Phase4-SystemExtension/Makefile
#
# This phase cannot be built with make / clang alone.
# It requires an Xcode project with two targets and Apple-issued signing
# credentials.  This Makefile exists to document what is needed and to
# surface a clear error if someone runs `make` by accident.
#
# ---------------------------------------------------------------------------
# REQUIRED BUNDLE IDs (replace "com.yourcompany" with your Team's prefix)
# ---------------------------------------------------------------------------
#
#   Container app    : com.yourcompany.Vanguard
#   System Extension : com.yourcompany.Vanguard.Extension
#   XPC Mach service : com.yourcompany.Vanguard.Extension.xpc
#                      (must match NSXPCListener machServiceName in Swift)
#
# ---------------------------------------------------------------------------
# REQUIRED ENTITLEMENTS
# ---------------------------------------------------------------------------
#
#   Extension target (VanguardExtension):
#     com.apple.developer.endpoint-security.client     = YES
#       -> Requested via the Apple Developer portal; Apple reviews and
#          grants this entitlement manually for anti-cheat use cases.
#     com.apple.security.application-groups             = [shared group]
#       -> Optional; allows shared UserDefaults / keychain items between
#          the container app and the extension.
#
#   Container app target (Vanguard):
#     com.apple.developer.system-extension.install     = YES
#       -> Required to call SMAppService.register().
#     com.apple.security.app-sandbox                   = YES  (if sandboxed)
#
# ---------------------------------------------------------------------------
# REQUIRED PROVISIONING PROFILES
# ---------------------------------------------------------------------------
#
#   • A "Mac App Development" or "Developer ID Application" profile for the
#     container app that includes the system-extension.install entitlement.
#   • A "System Extension" provisioning profile for the extension target that
#     includes the endpoint-security.client entitlement.
#     NOTE: Apple must explicitly add this entitlement to your profile;
#     it does not appear in the standard capability list.
#
# ---------------------------------------------------------------------------
# XCODE PROJECT STRUCTURE
# ---------------------------------------------------------------------------
#
#   Targets:
#     1. Vanguard (macOS App)
#        Sources  : Container/AppDelegate.swift
#                   Protocol/VanguardXPC.swift
#        Linked   : ServiceManagement.framework
#        Embed    : VanguardExtension.appex  (in PlugIns)
#
#     2. VanguardExtension (System Extension)
#        Sources  : Extension/VanguardExtension.swift
#                   Protocol/VanguardXPC.swift
#        Linked   : EndpointSecurity.framework
#        Info.plist keys:
#          NSExtension / NSExtensionPointIdentifier
#            = com.apple.system-extension.endpoint-security
#          NSExtensionPrincipalClass
#            = $(PRODUCT_MODULE_NAME).ExtensionDelegate
#          ESSendingMachServiceName
#            = com.yourcompany.Vanguard.Extension.xpc
#
# ---------------------------------------------------------------------------
# NOTARIZATION (required for distribution outside the Mac App Store)
# ---------------------------------------------------------------------------
#
#   After archiving in Xcode:
#     xcrun notarytool submit Vanguard.zip \
#         --apple-id <apple-id> \
#         --team-id  <team-id> \
#         --password <app-specific-password> \
#         --wait
#     xcrun stapler staple Vanguard.app
#
# ---------------------------------------------------------------------------

.PHONY: all build clean help

all: help

help:
	@echo ""
	@echo "Phase 4 — Vanguard System Extension"
	@echo "====================================="
	@echo ""
	@echo "This phase CANNOT be built with make."
	@echo ""
	@echo "You need:"
	@echo "  1. Xcode 14+ with macOS 13 SDK"
	@echo "  2. An Apple Developer account with the"
	@echo "     com.apple.developer.endpoint-security.client entitlement granted"
	@echo "  3. A System Extension provisioning profile from the Apple Developer portal"
	@echo "  4. A Developer ID Application certificate for notarization"
	@echo ""
	@echo "Steps:"
	@echo "  a) Create an Xcode project with two targets as described in the comments"
	@echo "     at the top of this Makefile."
	@echo "  b) Add Protocol/VanguardXPC.swift to BOTH targets."
	@echo "  c) Add Extension/VanguardExtension.swift to the extension target."
	@echo "  d) Add Container/AppDelegate.swift to the container app target."
	@echo "  e) Configure bundle IDs and entitlements per the comments above."
	@echo "  f) Archive and notarize with xcrun notarytool."
	@echo ""
	@echo "See Phase4-SystemExtension/README.md for the full explanation."
	@echo ""

build:
	@echo "ERROR: Use Xcode to build this target. Run 'make help' for instructions."
	@exit 1

clean:
	@echo "Nothing to clean — no build artifacts are generated by make."
