# esp32-s3-adblock

A **Pi-hole-style DNS ad-blocker** on an **ESP32-S3**, designed around
**2.3 million blocked domains in 11.5 MB of flash** — no domain strings in RAM,
no SD card, no server.

[日本語 README](README_JP.md) · [Changelog](CHANGELOG.md) · [Upstream project](https://github.com/M-Abozaid/esp32-c3-adblock)

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ look up the sorted 40-bit hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward upstream (async), relay the reply
```

---

## Contents

- [Why hashes instead of strings](#why-hashes-instead-of-strings)
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
- [What this fork changes](#what-this-fork-changes)
- [Credits and license](#credits-and-license)

---

## Why hashes instead of strings

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
need PSRAM and are limited to a few hundred thousand entries. This project stores
fixed **5-byte (40-bit) FNV-1a hashes** instead, sorted, and binary-searches them:

| | strings in RAM | this project |
|---|---|---|
| 2.3M domains | ~40 MB of RAM (impossible) | **11.5 MB of flash** |
| RAM used | most of it | **~110 KB** |
| Lookup | string compare | binary search over flash (or PSRAM) |
| Collisions at 2.3M | n/a | **1** (one domain gets over-blocked) |

**Why 40 bits?** It's the sweet spot for this flash budget. Collisions follow the
birthday bound: ~0 at 141k domains, ~1 at 2.3M. Dropping to 32 bits would save 20%
of the flash but cost ~250 collisions at 2.3M; 64 bits would waste 3 bytes per
domain to solve a problem that does not exist here.

Because only hashes are stored, the list is not readable on the device. Use
`--domains-out` when building to keep a plain-text copy.

## Hardware

**Default target: ESP32-S3 N16R8** (16 MB flash + 8 MB octal PSRAM).

| Board | Flash | PSRAM | Env | Blocklist capacity |
|---|---|---|---|---|
| **ESP32-S3 N16R8** (default) | 16 MB | 8 MB octal | `s3` | **~2.6M domains** (12.8 MB FS) |
| ESP32-S3 N8R8 | 8 MB | 8 MB octal | `s3` + edit | ~1M domains (4.8 MB FS) |
| ESP32-S3 N8R2 | 8 MB | 2 MB quad | `s3` + edit | ~1M domains, mirror capped by PSRAM |
| ESP32-C3 / SuperMini | 4 MB | none | `c3` | ~140k domains (704 KB FS) |
| Classic ESP32 DevKit | 4 MB | none | `esp32dev` | ~140k domains |

Switching the S3 module (**N8R8 / N8R2**) is two lines in
[`platformio.ini`](platformio.ini):

```ini
board_build.partitions = partitions_s3.csv   ; instead of partitions_s3_16mb.csv
board_upload.flash_size = 8MB
; for 2 MB *quad* PSRAM, also:
; board_build.arduino.memory_type = qio_qspi
```

**Console wiring matters.** The default `s3` env keeps `Serial` on **UART0**, which is
what a CH340/CP210x USB-serial bridge needs. If your board is wired to the S3's
native USB port instead, add `-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1`
to `build_flags`.

Power it from a stable USB source. Cheap USB-A→C adapters can brown out the radio
during transmit.

<details>
<summary>Printable enclosure (C3 SuperMini)</summary>

[`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

- No supports needed; 0.2 mm layers, ~15% infill.
- **Keep the antenna end clear** — the PCB antenna is the zig-zag trace on the edge
  opposite the USB-C port.
- Leave the vents open; the board idles around 45–55 °C.
</details>

## Quick start

```bash
# 1. secrets (gitignored). WIFI_* are optional (captive portal instead);
#    WEB_PASS / OTA_PASS are NOT optional - they protect flashable endpoints.
cp src/secrets.example.h src/secrets.h
#    edit src/secrets.h

# 2. build the hash table (default preset: light, ~115k domains)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. one USB flash: firmware + filesystem
pio run -t upload          # default env = s3
pio run -t uploadfs

# 4. monitor
pio device monitor         # -> http://c3adblock.local
```

For a 16 MB board the big list looks like this:

```bash
python3 tools/build_blocklist.py data/blocklist.bin --preset max --domains-out blocklist.txt
pio run -t uploadfs        # ~4 min over serial for a 13 MB image
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

Pushing a `v*` tag makes CI attach `esp32s3-n16r8-firmware.bin`,
`esp32c3-firmware.bin` and `esp32-firmware.bin` to
[Releases](https://github.com/wweng8o/esp32-s3-adblock/releases). A weekly
`blocklist.bin` is published there too.

Flashing without PlatformIO (all files come from the same release):

```bash
esptool.py --chip esp32s3 -p COM11 -b 460800 write_flash \
  0x0     s3-bootloader.bin \
  0x8000  s3-partitions.bin \
  0xe000  boot_app0.bin \
  0x10000 esp32s3-n16r8-firmware.bin
```

`esp32c3-firmware.bin` uses the same layout with `c3-bootloader.bin` /
`c3-partitions.bin` and `--chip esp32c3`. A fresh flash has no blocklist yet: add
`data/blocklist.bin` with `pio run -t uploadfs`, upload it from the dashboard, or point
*Remote auto-update* at the weekly release asset.

## Blocklists and presets

`tools/build_blocklist.py` accepts any mix of URLs and local files:

- **hosts files** — `0.0.0.0 ads.example.com`
- **plain domain lists** — one domain per line
- **AdGuard / Adblock basic rules** — `||ads.example.com^` blocks, `@@||ok.example.com^` allows

A blocked domain also blocks its subdomains. Rules a DNS hash list cannot express
(regex, wildcards, `$` modifiers, cosmetic `##` rules) are skipped and counted. An
`@@` rule only removes that exact entry. If a source cannot be downloaded the build
**fails** instead of silently shipping a smaller list (`--allow-missing` to override).

### Presets

| preset | domains | blob | intended board |
|---|---|---|---|
| `light` (default) | ~115k | 0.55 MB | C3 4 MB / any S3; social + messaging untouched |
| `balanced` | ~360k | 1.8 MB | 8 MB S3; adds social/porn/gambling + OISD big, still PSRAM-mirrored |
| `max` | ~2.3M | 11.5 MB | 16 MB S3; adds Hagezi **TIF** (malware / phishing / scam) |

```bash
python3 tools/build_blocklist.py data/blocklist.bin --preset max --domains-out blocklist.txt
python3 tools/build_blocklist.py data/blocklist.bin --preset light
python3 tools/build_blocklist.py out.bin mylist.txt https://example.com/hosts
```

If your network cannot reach `raw.githubusercontent.com` (common in mainland China), route the
preset downloads through a GitHub mirror — explicit source lists are used verbatim and are
not rewritten:

```bash
GITHUB_MIRROR=https://ghproxy.net/ python3 tools/build_blocklist.py data/blocklist.bin --preset max
```

Measured composition of the `max` preset used here:

| source | purpose |
|---|---|
| StevenBlack `fakenews-gambling-porn-social` | ads, malware, adult, gambling |
| Hagezi `ultimate` | comprehensive ads/trackers |
| OISD `big` | ads/trackers/malware |
| Hagezi `tif` | threat-intelligence feeds (phishing, scams, C2) |

2,298,291 entries, 1 hash collision, 233k adblock-syntax rules skipped.

> Mainstream sites were verified **not** to be in the list: WeChat, QQ, Taobao,
> Tmall, JD, Baidu, Bilibili, Zhihu, Douyin, Xiaohongshu, Alipay, GitHub, Microsoft,
> Apple, Google, YouTube, Netflix, Steam, Cloudflare, Aliyun.

## WiFi setup

If the device cannot connect (or `secrets.h` still has placeholders), it starts an
open AP **`C3-AdBlock-XXXX`** with a captive portal: join it, pick your network,
type the password, done.

To move it to another network later:

- click **Forget WiFi** on the dashboard, or
- **hold BOOT for 3 seconds while the device is running** (GPIO9 on C3, GPIO0 on
  S3/classic). Holding BOOT at power-on just enters the ROM download mode, which is
  why the old boot-time check never fired.

A configured device that cannot join reboots and retries every 3 minutes instead of
sitting in the portal forever, and the firmware restarts itself if WiFi stays down for
2 minutes.

## Dashboard and HTTP API

`http://c3adblock.local` (mDNS) — per-client block/allow counters, system info,
pause, ban, custom domains, blocklist upload, remote auto-update, firmware OTA.

Read-only endpoints need no auth; everything that mutates state requires
**HTTP Basic Auth** *and* the header `X-Requested-With: c3-adblock` (CSRF defence).

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

`/stats.json` reports `blocked`, `allowed`, `domains`, `psram`, `rssi`, `temp`,
`heap`, `psramfree`, `uptime`, `blocking`, `resumeIn`, `dns` (resolver in use),
`dnscfg` (pinned resolver), `defcreds`, `clients[]`, `custom[]`.

### Upstream resolver

Allowed domains are forwarded to, in order:

1. a resolver pinned with `/setdns` (persisted in `/dns.cfg`),
2. the DNS servers handed out by DHCP (normally your router),
3. the built-in default `9.9.9.9`.

If the active resolver goes silent, the device rotates to the next candidate after
three timeouts. **This matters on networks that block public resolvers** (many
carriers and corporate WiFis drop `9.9.9.9`/`1.1.1.1`): without rotation, blocking
still works but every allowed lookup times out, which looks exactly like "the
internet is broken".

## Over-the-air updates

- **Blocklist** — dashboard *Blocklist → Upload*, or set a URL under *Remote
  auto-update* and the device pulls a prebuilt `blocklist.bin` on a schedule. While a
  replacement downloads the live list keeps blocking (when flash has room for both);
  truncated or failed downloads are rolled back, and a reboot mid-swap is repaired at
  startup. DNS keeps being answered during the download.
- **Firmware** — dashboard *Firmware → OTA update* with `.pio/build/s3/firmware.bin`,
  or from the CLI:

  ```bash
  export OTA_PASS='<OTA_PASS from secrets.h>'
  pio run -e s3-ota -t upload --upload-port c3adblock.local
  pio run -e s3-ota -t upload --upload-port 192.168.1.50   # or by IP
  ```

  If espota says `No response from device`, the board cannot reach your PC's listener
  (firewall or different VLAN) — use the dashboard upload instead.

## Performance

Measured on ESP32-S3 (N16R8, 2.3M domains, flash path — the list exceeds 8 MB PSRAM):

| case | latency |
|---|---|
| blocked, cache hit | 7–12 ms |
| blocked, flash binary search | 10–47 ms |
| forwarded to upstream | 40–110 ms |
| firmware RAM use | 113 KB / 320 KB (34.6%) |

With lists that fit in PSRAM (≤ ~1.5M domains, e.g. `light` or `balanced`) the table
is mirrored at boot and lookups become in-RAM binary searches (microseconds).

## Security model

- **Basic Auth** (`WEB_USER`/`WEB_PASS`) on every state-changing endpoint, and
  **`OTA_PASS`** for ArduinoOTA.
- **CSRF header** `X-Requested-With: c3-adblock`: browsers auto-replay cached Basic
  Auth to any request against an authenticated origin, so auth alone would let any
  web page drive the API through `<img src="http://c3adblock.local/forgetwifi">`.
- **Stored-XSS**: custom domain names are HTML-escaped before rendering.
- **Limits**: plain HTTP on :80. Basic Auth over HTTP is a LAN trust boundary, not
  encryption — an on-path attacker can read credentials. The setup AP
  (`C3-AdBlock-XXXX`) is open by design, so it can be joined before you have any
  credentials.
- **Placeholder passwords**: the firmware warns on serial and shows a dashboard banner
  while `CHANGE_ME_*` values are still in use.

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
| mDNS name does not resolve | use the IP from `pio device monitor` |
| dashboard MAC column is empty | ARP not resolved yet; the firmware refreshes it automatically |

**ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles DTR/RTS,
resetting the board:

```bash
sudo systemctl stop ModemManager
echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## Repository layout

```
platformio.ini               environments: s3 (default), s3-ota, c3, esp32dev
partitions_s3_16mb.csv       16 MB S3:  2x1.6 MB app + 12.8 MB LittleFS
partitions_s3.csv            8 MB S3:   2x1.6 MB app + 4.8 MB LittleFS
partitions.csv               4 MB C3/ESP32: 2x1.6 MB app + 704 KB LittleFS
src/main.cpp                 firmware: DNS sinkhole, dashboard API, OTA, WiFi setup
src/page.h                   dashboard HTML (PROGMEM)
src/secrets.example.h        template for credentials (copy to secrets.h)
tools/build_blocklist.py     list -> sorted 40-bit hash blob (--preset, --domains-out)
data/                        LittleFS source directory (blocklist.bin goes here)
docs/index.html              GitHub Pages landing page
hardware/                    3D-printable C3 enclosure
.github/workflows/build.yml  builds s3 / c3 / esp32dev
.github/workflows/blocklist.yml  weekly blocklist release
CHANGELOG.md                 changes in this fork vs upstream
```

## What this fork changes

See [CHANGELOG.md](CHANGELOG.md) for details. Highlights:

- **ESP32-S3 port done properly**: 16 MB partition table, octal-PSRAM sdkconfig
  (`qio_opi`), UART console, PSRAM mirror when the list fits, `s3-ota` env.
- **Async DNS forwarding** — the original blocked up to 1 s per query, serializing all
  clients and stalling the web UI.
- **Upstream resolver selection + rotation** — a network that drops Quad9 no longer
  breaks every allowed lookup.
- **`max` preset: 2.3M domains** (8x the original default) including threat feeds.
- **Crash-safe blocklist swap**, LRU client table, persistent ban list, chunked
  `/stats.json`, 2-minute WiFi watchdog, BOOT-button recovery.
- Fixed: bans lost on reboot, GBK-encoded partition tables that broke the build,
  unreachable power-on BOOT check.

## Credits and license

Original concept and implementation: [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock),
inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the
"answer 0.0.0.0 for blocklisted domains" idea.

MIT — see [LICENSE](LICENSE).
