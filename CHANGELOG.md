# Changelog

All notable changes to this fork of
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [2.0.0] - 2026-10-21

ESP32-S3 port, 8x larger blocklist, and a reworked DNS data path.

### Added

- **ESP32-S3 support as the default target** (`env:s3`, N16R8: 16 MB flash + 8 MB octal PSRAM).
  - `partitions_s3_16mb.csv`: two 1.6 MB OTA app slots + 12.8 MB LittleFS, enough for
    ~2.6M hashed domains.
  - `board_build.arduino.memory_type = qio_opi`, which selects the octal-PSRAM sdkconfig.
    Without it the PSRAM mirror silently never engages.
  - PSRAM mirror of the whole hash table at boot when it fits (in-RAM binary search);
    automatic fallback to the flash index for larger lists.
  - Enlarged first-level flash index on S3 (8192 buckets x 512 entries) so lists up to
    ~4M domains cannot silently overflow a bucket.
- **`env:s3-ota`** for flashing over WiFi with ArduinoOTA/espota and `OTA_PASS`.
- **`--preset light|balanced|max`** in `tools/build_blocklist.py`.
  `max` reaches **2,298,291 domains / 11.49 MB**, adding Hagezi Threat Intelligence Feeds.
- **`--domains-out`** writes the normalized plain-text domain list alongside the hash blob
  (the `.bin` cannot be reversed).
- **Upstream resolver selection**: pinned resolver (`/setdns`, persisted in `/dns.cfg`) →
  DHCP-provided resolvers → built-in `9.9.9.9`. Rotates to the next candidate after three
  timeouts. Exposed as `dns` / `dnscfg` in `/stats.json` and in a new dashboard section.
- `/stats.json` reports `psramfree`; the dashboard shows free PSRAM on S3 boards.
- CI builds `s3` alongside `c3` and `esp32dev`.

### Changed

- **DNS forwarding is asynchronous.** Up to 32 queries are in flight; the loop no longer
  blocks for up to 1 s per lookup. Replies are matched on source address, a private
  transaction id and a hash of the question section, so the "every answer shifted by one"
  failure mode (upstream issue #10) stays fixed even with many concurrent queries.
- Queries that cannot be queued get a SERVFAIL instead of being dropped silently.
- Malformed questions, non-standard opcodes and multi-question packets are rejected.
- **Blocklist swap is crash-safe.** The live list keeps serving while a replacement is
  downloaded (when flash has room for both), truncated uploads are rejected, a failed
  rename rolls back to the previous list, and `blocklist.new` is repaired at boot.
- DNS keeps being answered while a remote blocklist downloads.
- Client table evicts the least-recently-seen client instead of dropping new clients.
- `/stats.json` is streamed in chunks to avoid a ~10 KB contiguous allocation per poll.
- BOOT-button WiFi reset now works: hold for 3 s **while running** (GPIO9 on C3, GPIO0 on
  S3/classic) instead of at power-on, which just entered the ROM download mode.
- WiFi: auto-reconnect, and a restart after 2 minutes offline instead of a silent DNS hole.
- Dashboard branding is board-agnostic ("ESP32 AdBlock"); OTA hint shows the s3 path.

### Fixed

- **Bans were lost on reboot** — `saveBanned()` rebuilt the list from the client table,
  dropping any client not seen since boot.
- **Build failure on GBK-encoded partition tables** (`UnicodeDecodeError` in
  `gen_esp32part.py` caused by non-ASCII comments).
- Banned clients were not blocked when the client table was full or when a slot was evicted.
- Empty MAC address for the first client entry (ARP resolved after the entry was created).
- Uploads larger than the filesystem, or downloads whose length differs from
  `Content-Length`, are no longer committed.
- Non-ASCII mojibake in source comments and user-facing strings.

### Documentation

- README restructured: hardware matrix, quick start, presets, API table, performance
  numbers, troubleshooting matrix, repository layout.
- Added the `intelhex` PlatformIO pitfall and the upstream-resolver behaviour.
- Documented that the `docs/` installer assets are produced by CI and attached to a
  release rather than committed.

## Upstream baseline

Forked from `M-Abozaid/esp32-c3-adblock` at the state that already included the
hash-in-flash blocklist, OTA for firmware and blocklist, the captive-portal WiFi setup,
Basic Auth + CSRF header protection and stored-XSS escaping.
