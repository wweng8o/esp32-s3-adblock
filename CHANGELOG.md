# Changelog

This project is a **modified version of
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)** — *"Pi-hole-class
DNS ad-blocker on a $2 ESP32-C3 (no PSRAM): 537k domains as 40-bit FNV-1a hashes, flash binary
search. UDP DNS sinkhole + web dashboard."* ([demo video](https://youtube.com/shorts/RaxszOUMi8E?feature=share)).

All changes below are relative to that upstream project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [3.0.0] - 2026-10-21

S3-only scope: the C3 and classic-ESP32 targets are gone, so the repository contains one
board, one partition table and one build flow.

### Removed

- `env:c3` and `env:esp32dev`, `partitions.csv` (4 MB), `partitions_s3.csv` (8 MB) and
  `hardware/esp32-c3-supermini-enclosure.stl`. `partitions.csv` is now the 16 MB S3 layout.
- C3/classic-ESP32 code paths: the `INDEX_ENTRIES`/`CACHE_SIZE`/`MAX_RANGE` split and the
  `WIFI_RESET_PIN` case (now GPIO0 only).

### Changed

- **Renamed the device identity**: mDNS/OTA host `s3adblock.local`, setup AP
  `S3-AdBlock-XXXX`, CSRF header value `s3-adblock`, dashboard title `ESP32-S3 AdBlock`.
  Existing bookmarks to `c3adblock.local` stop working after reflashing.
- Default blocklist preset is now `max` (~2.3M domains), matching the 12.5 MB filesystem.
  The weekly release workflow checks for a 9–12 MB blob.
- README, Japanese README and the GitHub Pages landing page rewritten for the S3-only scope,
  with an explicit attribution section.

## [2.0.0] - 2026-10-21

ESP32-S3 port, 8x larger blocklist, and a reworked DNS data path.

### Added

- **ESP32-S3 support as the default and only target** (N16R8: 16 MB flash + 8 MB octal PSRAM).
  - 16 MB partition table: two 1.6 MB OTA app slots + 12.8 MB LittleFS (~2.6M domains).
  - `board_build.arduino.memory_type = qio_opi`, which selects the octal-PSRAM sdkconfig.
    Without it the PSRAM mirror silently never engages.
  - PSRAM mirror of the hash table when it fits (in-RAM binary search); automatic fallback
    to the flash index for larger lists.
  - Larger first-level flash index (8192 buckets x 512 entries) so lists up to ~4M domains
    cannot silently overflow a bucket.
- **`env:s3-ota`** for flashing over WiFi with ArduinoOTA/espota and `OTA_PASS`.
- **`--preset light|balanced|max`** in `tools/build_blocklist.py`.
  `max` reaches **2,298,291 domains / 11.49 MB**, adding Hagezi Threat Intelligence Feeds.
- **`--domains-out`** writes the normalized plain-text domain list alongside the hash blob
  (the `.bin` cannot be reversed).
- **`GITHUB_MIRROR`** environment variable so preset downloads work on networks that block
  `raw.githubusercontent.com`.
- **Upstream resolver selection**: pinned resolver (`/setdns`, persisted in `/dns.cfg`) →
  DHCP-provided resolvers → built-in `9.9.9.9`. Rotates to the next candidate after three
  timeouts. Exposed as `dns` / `dnscfg` in `/stats.json` and in a new dashboard section.
- `/stats.json` reports `psramfree`; the dashboard shows free PSRAM.

### Changed

- **DNS forwarding is asynchronous.** Up to 32 queries are in flight; the loop no longer
  blocks for up to 1 s per lookup. Replies are matched on source address, a private
  transaction id and a hash of the question section, so the "every answer shifted by one"
  failure mode (upstream issue #10) stays fixed even with many concurrent queries.
- Queries that cannot be queued get a SERVFAIL instead of being dropped silently.
- Malformed questions, non-standard opcodes and multi-question packets are rejected.
- **Blocklist swap is crash-safe.** The live list keeps serving while a replacement is
  downloaded (when flash has room for both), truncated uploads are rejected, a failed rename
  rolls back to the previous list, and `blocklist.new` is repaired at boot.
- DNS keeps being answered while a remote blocklist downloads.
- Client table evicts the least-recently-seen client instead of dropping new clients.
- `/stats.json` is streamed in chunks to avoid a ~10 KB contiguous allocation per poll.
- BOOT-button WiFi reset now works: hold for 3 s **while running** instead of at power-on,
  which just entered the ROM download mode.
- WiFi: auto-reconnect, and a restart after 2 minutes offline instead of a silent DNS hole.

### Fixed

- **Bans were lost on reboot** — `saveBanned()` rebuilt the list from the client table,
  dropping any client not seen since boot.
- **Build failure on GBK-encoded partition tables** (`UnicodeDecodeError` in
  `gen_esp32part.py` caused by non-ASCII comments).
- Banned clients were not blocked when the client table was full or when a slot was evicted.
- Empty MAC address for the first client entry (ARP resolved after the entry was created).
- Uploads larger than the filesystem, or downloads whose length differs from
  `Content-Length`, are no longer committed.
- `ModuleNotFoundError: No module named 'intelhex'` in CI (newer PlatformIO cores no longer
  install esptool's dependency).
- `BOOT_PIN` clashed with `esp32-hal.h` on arduino-esp32 3.x; renamed to `WIFI_RESET_PIN`.
- Non-ASCII mojibake in source comments and user-facing strings.

## Upstream baseline

Forked from `M-Abozaid/esp32-c3-adblock`, which already provided the hash-in-flash blocklist,
OTA for firmware and blocklist, the captive-portal WiFi setup, Basic Auth + CSRF header
protection and stored-XSS escaping. Upstream credits
[s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) for the original
"answer 0.0.0.0 for blocklisted domains" idea.
