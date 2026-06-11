# Entitlements

`vanguard.entitlements` grants the one capability this monitor needs:

- **`com.apple.developer.endpoint-security.client`** — authorizes the signed
  binary to call `es_new_client()` and receive system-wide security events.
  It is a *managed* entitlement: on stock, SIP-enabled macOS it is only
  honored if Apple has granted it to your provisioning profile (the same
  vetting every EDR vendor goes through). For local research you instead
  disable SIP/AMFI on a dedicated test Mac. See the Phase 1 README.

The entitlement alone is not enough at runtime — the process must also run as
**root** and be granted **Full Disk Access** (a TCC permission). Those are
runtime gates, not entitlements, so they are not in the plist.

> ⚠️ **Do not add XML comments to `vanguard.entitlements`.** `codesign` parses
> entitlements with AMFI's minimal XML parser (`AMFIUnserializeXML`), which
> rejects `<!-- ... -->` comments and fails with "syntax error". Keep the
> plist comment-free.
