# esp32-s3-adblock

An **ESP32-S3 fork** of [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) —
a Pi-hole-style DNS ad-blocker that stores the blocklist as sorted **40-bit FNV-1a
hashes in flash** instead of domain strings in RAM.

This fork keeps **only the ESP32-S3 (N16R8) target** and uses the 16 MB of flash to block
**2.3 million domains**. Everything else — the hash-in-flash concept, the dashboard, the
captive-portal setup, the OTA design — comes from the upstream project.

[简体中文](README_ZH.md) · [Changelog](CHANGELOG.md) · [Upstream demo video](https://youtube.com/shorts/RaxszOUMi8E?feature=share)

> **Based on [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock):**
> *"Pi-hole-class DNS ad-blocker on a $2 ESP32-C3 (no PSRAM): 537k domains as 40-bit
> FNV-1a hashes, flash binary search. UDP DNS sinkhole + web dashboard."*
> See [Attribution](#attribution) for what this fork changed.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ look up the sorted 40-bit hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward upstream (async), relay the reply
```

---

## Contents

- [How it works](#how-it-works)
- [Hardware](#hardware)
- [Quick start](#quick-start)
- [Blocklists and presets](#blocklists-and-presets)
- [WiFi setup](#wifi-setup)
- [Dashboard and HTTP API](#dashboard-and-http-api)
- [Over-the-air updates](#over-the-air-updates)
- [Performance](#performance)
- [Security model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)
- [Attribution](#attribution)

---

## How it works

The upstream idea, unchanged: never store domain strings on the device. Domains are hashed
with FNV-1a, truncated to 40 bits, sorted, and written to flash as a fixed-size table. A
query is hashed (plus each parent suffix) and binary-searched.

| | strings in RAM (typical ESP32 sinkhole) | this project |
|---|---|---|
| 2.3M domains | ~40 MB of RAM (impossible) | **11.5 MB of flash** |
| RAM used | most of it | **~113 KB** |
| Lookup | string compare | binary search over flash or PSRAM |
| Collisions at 2.3M | n/a | **1** (one unrelated domain gets over-blocked) |

**Why 40 bits?** ~0 collisions at 141k domains, ~1 at 2.3M. Going to 32 bits would save 20%
of the flash but cost ~250 collisions; 64 bits wastes 3 bytes per domain.

Since only hashes are stored, the list is not readable on the device — build with
`--domains-out` if you want a plain-text copy.

## Hardware

**ESP32-S3 N16R8 only** (16 MB flash + 8 MB octal PSRAM).

| | |
|---|---|
| Flash | 16 MB — 12.5 MB of it is the blocklist filesystem |
| PSRAM | 8 MB octal, used to mirror the table when it fits |
| Blocklist capacity | ~2.6M domains (11.8 MB of hashes) |
| Firmware size | ~1.0 MB (3.x core: up to ~1.35 MB) |

The PSRAM mirror needs 5 bytes per domain, so it engages up to roughly **1.5M domains**.
The 2.3M `max` preset (11.5 MB) exceeds the 8 MB of PSRAM and therefore runs on the flash
index — correct, just ~10 ms per lookup instead of microseconds.

**Console wiring:** `Serial` stays on **UART0**, which is what a CH340/CP210x USB-serial
bridge needs. Boards wired to the S3's native USB port instead should add
`-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1` to `build_flags`.

Power the board from a stable USB source; cheap USB-A→C adapters can brown out the radio.

## Quick start

```bash
# 1. secrets (gitignored). WIFI_* are optional (captive portal instead);
#    WEB_PASS / OTA_PASS are NOT optional - they protect flashable endpoints.
cp src/secrets.example.h src/secrets.h
#    edit src/secrets.h

# 2. build the hash table (default preset: max, ~2.3M domains / 11.5 MB)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. one USB flash: firmware + filesystem
pio run -t upload          # env s3 is the default
pio run -t uploadfs        # ~4 min over serial for a 13 MB image

# 4. monitor
pio device monitor         # -> http://s3adblock.local
```

After the first flash, **firmware and blocklist both update over WiFi** — no USB needed.

> Use a current PlatformIO. The distro `platformio` package (4.3.x) is too old.
>
> If the build stops with `ModuleNotFoundError: No module named 'intelhex'`, esptool's
> dependency is missing from PlatformIO's own Python:
> ```bash
> "%USERPROFILE%\.platformio\penv\Scripts\python.exe" -m pip install intelhex   # Windows
> ~/.platformio/penv/bin/python -m pip install intelhex                          # Linux/macOS
> ```

### Prebuilt releases

Pushing a `v*` tag makes CI attach `esp32s3-n16r8-firmware.bin`, `s3-bootloader.bin`,
`s3-partitions.bin` and `boot_app0.bin` to [Releases](https://github.com/wweng8o/esp32-s3-adblock/releases).
A weekly `blocklist.bin` is published there too.

Flashing without PlatformIO:

```bash
esptool.py --chip esp32s3 -p COM11 -b 460800 write_flash \
  0x0     s3-bootloader.bin \
  0x8000  s3-partitions.bin \
  0xe000  boot_app0.bin \
  0x10000 esp32s3-n16r8-firmware.bin
```

A fresh flash has no blocklist yet: add `data/blocklist.bin` with `pio run -t uploadfs`,
upload it from the dashboard, or point *Remote auto-update* at the weekly release asset.

## Blocklists and presets

`tools/build_blocklist.py` accepts any mix of URLs and local files:

- **hosts files** — `0.0.0.0 ads.example.com`
- **plain domain lists** — one domain per line
- **AdGuard / Adblock basic rules** — `||ads.example.com^` blocks, `@@||ok.example.com^` allows

A blocked domain also blocks its subdomains. Rules a DNS hash list cannot express (regex,
wildcards, `$` modifiers, cosmetic `##` rules) are skipped and counted. An `@@` rule only
removes that exact entry. If a source cannot be downloaded the build **fails** instead of
silently shipping a smaller list (`--allow-missing` to override).

### Presets

| preset | domains | blob | notes |
|---|---|---|---|
| `light` | ~115k | 0.55 MB | ads/trackers/malware; social + messaging untouched |
| `balanced` | ~360k | 1.8 MB | adds social/porn/gambling + OISD big; still PSRAM-mirrored |
| `max` **(default)** | ~2.3M | 11.5 MB | adds Hagezi **TIF** (malware / phishing / scam) |

```bash
python3 tools/build_blocklist.py data/blocklist.bin                      # max
python3 tools/build_blocklist.py data/blocklist.bin --preset balanced
python3 tools/build_blocklist.py data/blocklist.bin --domains-out blocklist.txt
python3 tools/build_blocklist.py out.bin mylist.txt https://example.com/hosts
```

If your network cannot reach `raw.githubusercontent.com` (common in mainland China), route
the preset downloads through a GitHub mirror — explicit source lists are used verbatim:

```bash
GITHUB_MIRROR=https://ghproxy.net/ python3 tools/build_blocklist.py data/blocklist.bin --preset max
```

Measured composition of `max`:

| source | purpose |
|---|---|
| StevenBlack `fakenews-gambling-porn-social` | ads, malware, adult, gambling |
| Hagezi `ultimate` | comprehensive ads/trackers |
| OISD `big` | ads/trackers/malware |
| Hagezi `tif` | threat-intelligence feeds (phishing, scams, C2) |

2,298,291 entries, 1 hash collision, 233k adblock-syntax rules skipped.

> Mainstream sites were verified **not** to be in the list: WeChat, QQ, Taobao, Tmall, JD,
> Baidu, Bilibili, Zhihu, Douyin, Xiaohongshu, Alipay, GitHub, Microsoft, Apple, Google,
> YouTube, Netflix, Steam, Cloudflare, Aliyun.

## WiFi setup

If the device cannot connect (or `secrets.h` still has placeholders), it starts an open AP
**`S3-AdBlock-XXXX`** with a captive portal: join it, pick your network, type the password,
done.

To move it to another network later:

- click **Forget WiFi** on the dashboard, or
- **hold BOOT (GPIO0) for 3 seconds while the device is running**.

A configured device that cannot join reboots and retries every 3 minutes instead of sitting
in the portal forever, and the firmware restarts itself if WiFi stays down for 2 minutes.

## Dashboard and HTTP API

`http://s3adblock.local` (mDNS) — per-client block/allow counters, system info, pause, ban,
custom domains, blocklist upload, remote auto-update, firmware OTA.

Read-only endpoints need no auth; everything that mutates state requires **HTTP Basic Auth**
*and* the header `X-Requested-With: s3-adblock` (CSRF defence).

| endpoint | auth | purpose |
|---|---|---|
| `GET /` | – | dashboard |
| `GET /stats.json` | – | stats, clients, custom domains, active upstream |
| `GET /ban?ip=` | yes | toggle a client ban |
| `GET /addblock?d=` / `unblock?d=` | yes | custom blocked domains |
| `GET /pause?s=` / `resume` | yes | suspend blocking for N seconds |
| `GET /setdns?ip=` | yes | pin the upstream resolver (empty = auto) |
| `GET /setupdate?u=&h=` / `fetchnow` | yes | remote blocklist schedule |
| `POST /upload` | yes | blocklist upload |
| `POST /update` | yes | firmware OTA |
| `GET /forgetwifi` | yes | wipe credentials, reboot into the portal |

`/stats.json` reports `blocked`, `allowed`, `domains`, `psram`, `rssi`, `temp`, `heap`,
`psramfree`, `uptime`, `blocking`, `resumeIn`, `dns` (resolver in use), `dnscfg` (pinned
resolver), `defcreds`, `clients[]`, `custom[]`.

### Upstream resolver

Allowed domains are forwarded to, in order:

1. a resolver pinned with `/setdns` (persisted in `/dns.cfg`),
2. the DNS servers handed out by DHCP (normally your router),
3. the built-in default `9.9.9.9`.

If the active resolver goes silent, the device rotates to the next candidate after three
timeouts. **This matters on networks that block public resolvers** (many carriers and
corporate WiFis drop `9.9.9.9`/`1.1.1.1`): without rotation, blocking still works but every
allowed lookup times out, which looks exactly like "the internet is broken".

## Over-the-air updates

- **Blocklist** — dashboard *Blocklist → Upload*, or set a URL under *Remote auto-update* and
  the device pulls a prebuilt `blocklist.bin` on a schedule. While a replacement downloads the
  live list keeps blocking (when flash has room for both); truncated or failed downloads are
  rolled back, and a reboot mid-swap is repaired at startup. DNS keeps being answered during
  the download.
- **Firmware** — dashboard *Firmware → OTA update* with `.pio/build/s3/firmware.bin`, or:

  ```bash
  export OTA_PASS='<OTA_PASS from secrets.h>'
  pio run -e s3-ota -t upload --upload-port s3adblock.local
  pio run -e s3-ota -t upload --upload-port 192.168.1.50   # or by IP
  ```

  If espota says `No response from device`, the board cannot reach your PC's listener
  (firewall or different VLAN) — use the dashboard upload instead.

## Performance

Measured on ESP32-S3 N16R8 with the 2.3M-domain list (flash path, since the list exceeds
8 MB PSRAM):

| case | latency |
|---|---|
| blocked, cache hit | 7–12 ms |
| blocked, flash binary search | 10–47 ms |
| forwarded to upstream | 40–110 ms |
| firmware RAM use | 113 KB / 320 KB (34.6%) |

With a list that fits in PSRAM (`light`, `balanced`) the table is mirrored at boot and
lookups become in-RAM binary searches.

## Security model

- **Basic Auth** (`WEB_USER`/`WEB_PASS`) on every state-changing endpoint, **`OTA_PASS`** for
  ArduinoOTA.
- **CSRF header** `X-Requested-With: s3-adblock`: browsers auto-replay cached Basic Auth to any
  request against an authenticated origin, so auth alone would let any web page drive the API
  through `<img src="http://s3adblock.local/forgetwifi">`.
- **Stored-XSS**: custom domain names are HTML-escaped before rendering.
- **Limits**: plain HTTP on :80. Basic Auth over HTTP is a LAN trust boundary, not encryption.
  The setup AP (`S3-AdBlock-XXXX`) is open by design.
- **Placeholder passwords**: the firmware warns on serial and shows a dashboard banner while
  `CHANGE_ME_*` values are still in use.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'intelhex'` | install it into PlatformIO's own Python (see Quick start) |
| `Could not open COMx, the port is busy` | another monitor/serial app holds the port, or USB was unplugged |
| `Failed to connect` while uploading | hold BOOT, tap RST, release BOOT to enter download mode |
| blocklist shows 0 domains | `pio run -t uploadfs` was skipped, or `data/blocklist.bin` is missing |
| dashboard loads but nothing is blocked | the client is not using the device as DNS yet |
| blocked sites work, allowed sites time out | upstream resolver unreachable → set *Upstream DNS* on the dashboard |
| espota `No response from device` | PC firewall/VLAN; use the dashboard firmware upload |
| `s3adblock.local` does not resolve | use the IP from `pio device monitor` |
| dashboard MAC column is empty | ARP not resolved yet; the firmware refreshes it automatically |
| PSRAM mirror inactive (`"psram":false`) | the list is larger than free PSRAM; expected for `max` |

**ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles DTR/RTS,
resetting the board:

```bash
sudo systemctl stop ModemManager
echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## Repository layout

```
platformio.ini               env s3 (default) and s3-ota (ArduinoOTA)
partitions.csv               16 MB S3: 2x1.6 MB app + 12.8 MB LittleFS
src/main.cpp                 firmware: DNS sinkhole, dashboard API, OTA, WiFi setup
src/page.h                   dashboard HTML (PROGMEM)
src/secrets.example.h        template for credentials (copy to secrets.h)
tools/build_blocklist.py     list -> sorted 40-bit hash blob (--preset, --domains-out)
data/                        LittleFS source directory (blocklist.bin goes here)
docs/index.html              GitHub Pages landing page
.github/workflows/build.yml  builds s3
.github/workflows/release.yml    tag -> firmware assets on a release
.github/workflows/blocklist.yml  weekly blocklist release
README_ZH.md                 Simplified Chinese documentation
CHANGELOG.md                 changes in this fork vs upstream
```

## Attribution

This project is a **modified version of
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)** — *"Pi-hole-class
DNS ad-blocker on a $2 ESP32-C3 (no PSRAM): 537k domains as 40-bit FNV-1a hashes, flash binary
search. UDP DNS sinkhole + web dashboard."* ([demo video](https://youtube.com/shorts/RaxszOUMi8E?feature=share)).
That project in turn credits [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) for
the "answer 0.0.0.0 for blocklisted domains" idea.

**What this fork changes** (full detail in [CHANGELOG.md](CHANGELOG.md)):

- **ESP32-S3 only.** Dropped the C3 and classic-ESP32 environments, partition tables and
  enclosure. Targets N16R8 with a 16 MB partition table, octal-PSRAM sdkconfig (`qio_opi`),
  UART console and an `s3-ota` environment.
- **Async DNS forwarding.** The upstream loop blocked up to 1 s per lookup, serializing clients
  and stalling the dashboard. Now up to 32 queries are in flight, matched on source address,
  a private transaction id and a question hash.
- **Upstream resolver selection and rotation.** Pinned → DHCP → built-in `9.9.9.9`, rotating
  after three timeouts, because many networks drop public resolvers.
- **2.3M-domain blocklist** (`max` preset, ~8x the upstream default) via a 12.5 MB filesystem,
  plus a larger flash index (8192 buckets) so buckets cannot silently overflow.
- **Reliability fixes**: crash-safe blocklist swap with rollback, bans persisting across
  reboots, LRU client table, chunked `/stats.json`, WiFi watchdog, BOOT-button recovery.
- Rewritten documentation, GitHub Pages landing page and CI (build matrix, release workflow).

Everything else — the hash-in-flash design, the dashboard, the captive portal, CSRF hardening —
is upstream work. Please send credit upstream.

## License

MIT — see [LICENSE](LICENSE). Copyright belongs to the upstream authors and this fork's
contributors.
