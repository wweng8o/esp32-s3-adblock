#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32 ad-blocker. Hashes live in flash (ESP32-C3) or are mirrored into
PSRAM at boot (ESP32-S3), so no domain strings are ever stored on the device.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB
(an 8 MB S3 partition holds ~1M domains).

Usage: build_blocklist.py [out.bin] [--preset NAME] [--domains-out list.txt] [src ...]
  src = local file or URL. With none given, uses --preset light.
  --domains-out also writes the final normalized domain list as plain text
  (the .bin itself only contains 40-bit hashes and cannot be reversed).

Presets (size -> which board layout):
  light     ~115k  ads/trackers/malware, social + messaging keep working
                   4 MB C3 (704 KB FS) / any S3
  balanced  ~360k  + social/porn/gambling + OISD big
                   8 MB S3 (1.8 MB blob), still mirrored into PSRAM
  max       ~2.3M  + Hagezi Threat Intelligence Feeds (malware/phishing/scam)
                   16 MB S3 with the 12.5 MB filesystem (~11.5 MB blob); this is
                   larger than 8 MB PSRAM, so lookups use the flash index

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
"""
import re
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots on a 4 MB C3
# (~140k domain budget); the 8 MB S3 has room for ~1M. Ads + trackers + malware,
# WhatsApp/social keep working. ~100k entries / 0.5 MB
# (Hagezi's wildcard lists drop subdomains the firmware's parent-matching already covers).
# Want more? pro-onlydomains.txt is ~370k: it fits the 8 MB S3 with dual-OTA,
# but on a 4 MB C3 it only fits the single-app (no-OTA) partition table.
RAW = 'https://raw.githubusercontent.com/'

# Networks that cannot reach raw.githubusercontent.com (many in mainland China)
# can prefix the preset URLs with a GitHub mirror, e.g.
#   GITHUB_MIRROR=https://ghproxy.net/ python3 tools/build_blocklist.py ...
# An explicit list of sources ignores this and is used verbatim.
MIRROR = os.environ.get('GITHUB_MIRROR', '').strip()
if MIRROR and not MIRROR.endswith('/'):
    MIRROR += '/'
PRESETS = {
    'light': [
        RAW + 'StevenBlack/hosts/master/hosts',                                      # base: ads + malware
        RAW + 'hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',           # Hagezi Light
    ],
    'balanced': [
        RAW + 'StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts',
        RAW + 'hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt',
        RAW + 'sjhgvr/oisd/main/domainswild_big.txt',
    ],
    'max': [
        RAW + 'StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts',
        RAW + 'hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt',
        RAW + 'sjhgvr/oisd/main/domainswild_big.txt',
        RAW + 'hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt',             # threat intelligence feeds
    ],
}
DEFAULT_SOURCES = PRESETS['light']

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    global ALLOW_MISSING
    argv = sys.argv[1:]
    ALLOW_MISSING = '--allow-missing' in argv
    argv = [a for a in argv if a != '--allow-missing']
    domains_out = None
    if '--domains-out' in argv:
        i = argv.index('--domains-out')
        if i + 1 >= len(argv):
            print('--domains-out needs a filename', file=sys.stderr); sys.exit(2)
        domains_out = argv[i + 1]
        del argv[i:i + 2]
    preset = None
    if '--preset' in argv:
        i = argv.index('--preset')
        if i + 1 >= len(argv):
            print('--preset needs a name', file=sys.stderr); sys.exit(2)
        preset = argv[i + 1]
        del argv[i:i + 2]
    if preset is not None and preset not in PRESETS:
        print(f'unknown preset "{preset}" (choose: {", ".join(PRESETS)})', file=sys.stderr); sys.exit(2)
    out = argv[0] if argv else 'blocklist.bin'
    if len(argv) > 1:
        sources = argv[1:]
    else:
        sources = [MIRROR + u if MIRROR else u for u in PRESETS[preset or 'light']]

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            d = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::') \
                else parts[0] if len(parts) == 1 else None
            if d:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    sorted_domains = sorted(domains)
    hashes = sorted(fnv(d.encode()) for d in sorted_domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))
    if domains_out:
        with open(domains_out, 'w', encoding='utf-8', newline='\n') as f:
            f.writelines(d + '\n' for d in sorted_domains)
        print(f'domain list      : {len(sorted_domains):,} lines -> {domains_out}')

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
