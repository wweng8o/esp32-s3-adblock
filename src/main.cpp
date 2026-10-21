// ESP32-S3 DNS sinkhole + web dashboard.
// Blocklist = sorted 40-bit FNV-1a hashes in flash. When the table fits in
// PSRAM it is mirrored at boot and searched in RAM (~us); otherwise a
// first-level flash index plus a small lookup cache is used (~10 ms).
// Dashboard at http://s3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.
// Upstream queries are forwarded asynchronously, so a slow resolver never
// serializes other clients or blocks the web UI.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS - used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const int MAX_UPSTREAMS = 4;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 8192;   // 40 KB first-level flash index
static const int CACHE_SIZE = 1024;      // must be power of 2
static const int MAX_RANGE = 512;        // max hashes per index bucket (8192*512 -> ~4.2M domains)
static const int MAX_PENDING = 32;            // queries in flight to the upstream resolver
static const uint32_t UPSTREAM_TIMEOUT_MS = 1500;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// Async upstream forwarding: remember each query until its reply arrives, so the
// main loop never waits on the resolver. Replies are matched by source, our
// transaction id and a hash of the question section.
struct Pending {
  uint16_t clientId;      // client's original transaction id
  uint16_t upstreamId;    // transaction id we sent to the resolver
  uint32_t clientIp;
  uint16_t clientPort;
  uint32_t questionHash;
  uint32_t deadline;      // millis() when the entry is abandoned
  bool used;
};
static Pending pending[MAX_PENDING];
static uint16_t nextUpstreamId = 0;

// Resolver used for forwarding. Plenty of networks (corporate, ISP-filtered,
// mainland-China mobile/broadband) silently drop 9.9.9.9/1.1.1.1, which turns
// every allowed lookup into a timeout. So: a configurable primary (persisted),
// then the DHCP-provided resolvers, then the built-in default - and rotate on
// repeated timeouts.
static IPAddress upstreamList[MAX_UPSTREAMS];
static int numUpstreams = 0, upstreamIdx = 0;
static uint8_t upstreamMisses = 0;
static IPAddress configuredDns;     // empty = use DHCP / built-in default

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

// S3: PSRAM mirror of the whole sorted hash blob (see tryMirrorPsram)
static uint8_t* psramHashes = nullptr;

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen, macAt; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;   // always: the list may have changed
  if (psramHashes || !blocklist || numHashes == 0) return;  // PSRAM mirror needs no flash index
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
}

// Mirror the whole sorted hash blob into PSRAM when it fits. Lookups then become pure
// in-memory binary searches (~us) instead of ~18 flash reads (~10 ms), and the MAX_RANGE
// bucket clamp stops mattering. Falls back silently to the flash path when the list is
// larger than free PSRAM (a 2.3M-domain table needs 11.5 MB, more than the 8 MB available).
static void tryMirrorPsram() {
  if (psramHashes) { free(psramHashes); psramHashes = nullptr; }
  if (!psramFound() || !blocklist || numHashes == 0) return;
  const size_t need = (size_t)numHashes * HASH_BYTES;
  if (need > (size_t)ESP.getFreePsram()) return;   // e.g. 2MB-PSRAM board + a huge list
  uint8_t* m = (uint8_t*)ps_malloc(need);
  if (!m) return;
  blocklist.seek(0);
  if (blocklist.read(m, need) != need) { free(m); return; }
  psramHashes = m;
  Serial.printf("[psram] mirrored %u hashes (%u KB) -> in-RAM binary search\n",
                (unsigned)numHashes, (unsigned)(need / 1024));
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  if (psramHashes) {                       // S3: whole list mirrored in PSRAM -> plain binary search
    uint32_t lo = 0, hi = numHashes - 1;
    while (lo <= hi) {
      const uint32_t mid = lo + (hi - lo) / 2;
      const uint64_t v = unpackHash(psramHashes + (size_t)mid * HASH_BYTES);
      if (v == h) return true;
      if (v < h) lo = mid + 1;
      else { if (mid == 0) break; hi = mid - 1; }
    }
    return false;
  }
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static int findBan(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return i; return -1; }
static bool isBannedIP(uint32_t ip) { return findBan(ip) >= 0; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) {
    String l = f.readStringUntil('\n'); l.trim(); IPAddress ip;
    if (l.length() && ip.fromString(l) && !isBannedIP((uint32_t)ip)) bannedIP[numBanned++] = (uint32_t)ip;
  }
  f.close();
}
// The banned list is authoritative (it used to be rebuilt from the client table,
// which silently dropped bans for clients that were not seen since boot).
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}
static bool setBanned(uint32_t ip, bool on) {
  const int i = findBan(ip);
  if (on) {
    if (i >= 0) return true;
    if (numBanned >= MAX_BAN) return false;
    bannedIP[numBanned++] = ip;
  } else {
    if (i < 0) return true;
    for (int j = i; j < numBanned - 1; j++) bannedIP[j] = bannedIP[j + 1];
    numBanned--;
  }
  saveBanned();
  return true;
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static bool macZero(const uint8_t* m) {
  for (int i = 0; i < 6; i++) if (m[i]) return false;
  return true;
}
static Dev* getClient(uint32_t ip) {
  const uint32_t now = millis();
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) {
    Dev& c = clients[i];
    c.lastSeen = now;
    // The first packet only triggers ARP, so the MAC is often unknown at creation.
    if (macZero(c.mac) && now - c.macAt > 5000) { getMac(ip, c.mac); c.macAt = now; }
    return &c;
  }
  int slot = numClients;
  if (slot >= MAX_CLIENTS) {              // recycle the least recently seen non-banned client
    slot = -1;
    uint32_t bestAge = 0;
    for (int i = 0; i < numClients; i++) {
      if (clients[i].banned) continue;
      const uint32_t age = now - clients[i].lastSeen;
      if (slot < 0 || age > bestAge) { slot = i; bestAge = age; }
    }
    if (slot < 0) return nullptr;
  } else {
    numClients++;
  }
  Dev* c = &clients[slot];
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = now; c->banned = isBannedIP(ip); c->label = "";
  getMac(ip, c->mac); c->macAt = now; return c;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  if (qend < 12 || qend > (int)sizeof(buf) - 16) return 0;
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Hash the question section (qname + qtype + qclass). Every reply echoes it, so
// it lets us match a reply to its query without keeping a copy of the query.
static bool questionInfo(const uint8_t* pkt, int len, uint16_t* qend, uint32_t* qhash) {
  if (len < 17) return false;
  int i = 12; uint32_t h = 2166136261u;
  for (;;) {
    if (i >= len) return false;
    const uint8_t l = pkt[i++];
    h = (h ^ l) * 16777619u;
    if (l == 0) break;
    if (l & 0xC0) return false;            // compression is invalid in a question
    if (i + l > len) return false;
    for (uint8_t k = 0; k < l; k++) h = (h ^ pkt[i++]) * 16777619u;
  }
  if (i + 4 > len) return false;
  for (int k = 0; k < 4; k++) h = (h ^ pkt[i++]) * 16777619u;
  if (qend) *qend = i;
  if (qhash) *qhash = h;
  return true;
}
static bool pendingIdInUse(uint16_t uid) {
  for (int i = 0; i < MAX_PENDING; i++) if (pending[i].used && pending[i].upstreamId == uid) return true;
  return false;
}
static bool isUpstreamSource(const IPAddress& ip) {
  for (int i = 0; i < numUpstreams; i++) if (ip == upstreamList[i]) return true;
  return false;
}
static IPAddress activeUpstream() {
  return numUpstreams > 0 ? upstreamList[upstreamIdx] : UPSTREAM;
}
// Priority: user-configured resolver (persisted) -> DHCP resolvers -> built-in.
static void buildUpstreamList() {
  IPAddress prev = activeUpstream();
  numUpstreams = 0;
  if ((uint32_t)configuredDns) upstreamList[numUpstreams++] = configuredDns;
  for (int i = 0; i < 2 && numUpstreams < MAX_UPSTREAMS; i++) {
    const IPAddress d = WiFi.dnsIP(i);
    if (!(uint32_t)d) continue;
    bool dup = false;
    for (int j = 0; j < numUpstreams; j++) if (upstreamList[j] == d) { dup = true; break; }
    if (!dup) upstreamList[numUpstreams++] = d;
  }
  if (numUpstreams == 0) upstreamList[numUpstreams++] = UPSTREAM;
  upstreamIdx = 0;
  for (int i = 0; i < numUpstreams; i++) if (upstreamList[i] == prev) { upstreamIdx = i; break; }
  upstreamMisses = 0;
  Serial.printf("[dns] upstream: ");
  for (int i = 0; i < numUpstreams; i++) Serial.printf("%s%s", i ? ", " : "", upstreamList[i].toString().c_str());
  Serial.println();
}
// A resolver that answers nothing is useless: rotate after a few timeouts so a
// network that drops Quad9 still resolves through its own DNS.
static void noteUpstreamResult(bool gotAnswer) {
  if (gotAnswer) { upstreamMisses = 0; return; }
  if (++upstreamMisses < 3 || numUpstreams < 2) return;
  upstreamMisses = 0;
  upstreamIdx = (upstreamIdx + 1) % numUpstreams;
  Serial.printf("[dns] no reply, switching upstream to %s\n", upstreamList[upstreamIdx].toString().c_str());
}
// Fire-and-forget: hand the query to the resolver and return immediately. The
// old code blocked up to 1 s per query, which serialized every client and
// stalled the web UI behind each DNS lookup.
static bool startUpstream(int qlen, uint32_t qhash, uint32_t cip, uint16_t cport, uint16_t cid) {
  int slot = -1;
  for (int i = 0; i < MAX_PENDING; i++) if (!pending[i].used) { slot = i; break; }
  if (slot < 0) return false;                       // table full: drop, client retries

  uint16_t uid;
  do { uid = ++nextUpstreamId; } while (uid == 0 || pendingIdInUse(uid));
  Pending& p = pending[slot];
  p.clientId = cid; p.upstreamId = uid; p.clientIp = cip; p.clientPort = cport;
  p.questionHash = qhash; p.deadline = millis() + UPSTREAM_TIMEOUT_MS; p.used = true;

  buf[0] = uid >> 8; buf[1] = uid & 0xFF;
  upstreamCli.beginPacket(activeUpstream(), UPSTREAM_PORT);
  upstreamCli.write(buf, qlen);
  upstreamCli.endPacket();
  return true;
}
// Relay any replies that have arrived. Matching on source, our transaction id
// and the question hash keeps a late reply from being sent to the wrong client
// (issue #10) now that several queries can be in flight at once.
static void handleUpstream() {
  for (int budget = 0; budget < 8; budget++) {
    const int sz = upstreamCli.parsePacket();
    if (sz <= 0) break;
    if (sz > (int)sizeof(buf)) { upstreamCli.flush(); continue; }
    // Accept any of our candidate resolvers: a reply can arrive right after a switch.
    const bool fromUp = upstreamCli.remotePort() == UPSTREAM_PORT && isUpstreamSource(upstreamCli.remoteIP());
    const int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();
    if (!fromUp || n < 17 || !(buf[2] & 0x80)) continue;   // QR must be set
    uint32_t qhash;
    if (!questionInfo(buf, n, nullptr, &qhash)) continue;
    const uint16_t uid = (buf[0] << 8) | buf[1];
    int slot = -1;
    for (int i = 0; i < MAX_PENDING; i++)
      if (pending[i].used && pending[i].upstreamId == uid && pending[i].questionHash == qhash) { slot = i; break; }
    if (slot < 0) continue;                                // stale or unsolicited
    Pending& p = pending[slot];
    buf[0] = p.clientId >> 8; buf[1] = p.clientId & 0xFF;
    dnsServer.beginPacket(IPAddress(p.clientIp), p.clientPort);
    dnsServer.write(buf, n);
    dnsServer.endPacket();
    p.used = false;
    noteUpstreamResult(true);
  }
}
static void expirePending() {
  const uint32_t now = millis();
  bool expired = false;
  for (int i = 0; i < MAX_PENDING; i++)
    if (pending[i].used && (int32_t)(now - pending[i].deadline) >= 0) { pending[i].used = false; expired = true; }
  if (expired) noteUpstreamResult(false);
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    const int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    if (sz > (int)sizeof(buf)) { dnsServer.flush(); continue; }
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    if (buf[2] & 0x80) continue;                      // reply, not a query (avoid loops)
    if (((buf[2] >> 3) & 0x0F) != 0) continue;        // standard queries only
    if (((buf[4] << 8) | buf[5]) != 1) continue;      // exactly one question
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    const size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    if (!dl) continue;                                // malformed question: drop
    Dev* c = getClient((uint32_t)cip);
    // Check the ban list directly: the client table can be full (or evict), and
    // a ban must keep working even when there is no entry to attach it to.
    const bool blocked = isBannedIP((uint32_t)cip) || (blockingOn && numHashes && isBlocked(domain));
    if (blocked) {
      totalBlocked++; if (c) c->blocked++;
      const int rlen = buildBlocked(qend, qtype);
      if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
      continue;
    }
    totalAllowed++; if (c) c->allowed++;
    uint32_t qhash;
    const bool queued = questionInfo(buf, qlen, nullptr, &qhash) &&
                        startUpstream(qlen, qhash, (uint32_t)cip, cport, (uint16_t)((buf[0] << 8) | buf[1]));
    if (!queued) {                                    // too many in flight: tell the client to retry
      buf[2] |= 0x80; buf[3] = (buf[3] & 0xF0) | 0x82;   // QR + RA + SERVFAIL
      buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
      dnsServer.beginPacket(cip, cport); dnsServer.write(buf, qend); dnsServer.endPacket();
    }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }

#include "page.h"   // dashboard HTML (PROGMEM) - see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  // Stream the JSON in chunks: a full client + custom-domain table used to be
  // built in one String, which asks the heap for ~10 KB every poll.
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "application/json", "");
  String j; j.reserve(1536);
  j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
      ",\"domains\":" + numHashes + ",\"psram\":" + (psramHashes ? "true" : "false") + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
      ",\"heap\":" + ESP.getFreeHeap() + ",\"psramfree\":" + (ESP.getFreePsram() / 1024) + ",\"uptime\":\"" + ut + "\"" +
      ",\"dns\":\"" + activeUpstream().toString() + "\",\"dnscfg\":\"" + configuredDns.toString() + "\"" +
      ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
      ",\"blocking\":" + (blockingOn ? "true" : "false") +
      ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
      ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
      ",\"clients\":[";
  web.sendContent(j);
  j = ""; j.reserve(1024);
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}";
    if (j.length() >= 768) { web.sendContent(j); j = ""; }
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.sendContent(j);
  web.sendContent("");   // terminate the chunked body
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication -
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin - including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// s3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "s3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    const uint32_t v = (uint32_t)ip;
    const bool on = !isBannedIP(v);
    if (setBanned(v, on)) { Dev* c = getClient(v); if (c) c->banned = on; }
  }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  tryMirrorPsram();   // S3: rebuild the PSRAM mirror first, so buildFlashIndex() can skip the index
  buildFlashIndex();
}
// Stage the replacement while the live list keeps serving when the partition
// has room for both (typical on the 8 MB S3). Then blocking never stops during
// an update. `incoming` is an upper bound of the new size (0 = unknown).
static void beginBlocklistSwap(size_t incoming) {
  const size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
  const size_t freeBytes = total > used ? total - used : 0;
  const bool keepOld = incoming > 0 && freeBytes > incoming + 65536;
  if (!keepOld) {
    if (psramHashes) { free(psramHashes); psramHashes = nullptr; }
    if (blocklist) blocklist.close();
    numHashes = 0;
    LittleFS.remove(BLOCKLIST_PATH);
  }
  LittleFS.remove("/blocklist.new");
  LittleFS.remove("/blocklist.old");
}
static void abortBlocklistSwap() {
  LittleFS.remove("/blocklist.new");
  LittleFS.remove("/blocklist.old");
  if (!blocklist) reopenBlocklist();   // the live list was freed at the start of the swap
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  const size_t sz = f ? f.size() : 0; if (f) f.close();
  if (sz == 0 || (sz % HASH_BYTES) != 0) {          // sorted hash blob -> 5-byte multiple
    LittleFS.remove("/blocklist.new");
    if (!blocklist) reopenBlocklist();
    return false;
  }
  if (blocklist) blocklist.close();
  LittleFS.remove("/blocklist.old");
  if (LittleFS.exists(BLOCKLIST_PATH)) LittleFS.rename(BLOCKLIST_PATH, "/blocklist.old");
  bool ok = LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  if (ok) {
    LittleFS.remove("/blocklist.old");
  } else {                                          // put the previous list back
    LittleFS.remove("/blocklist.new");
    if (LittleFS.exists("/blocklist.old")) LittleFS.rename("/blocklist.old", BLOCKLIST_PATH);
  }
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static bool upWriteOk = false;
static File upFile;
static bool blBusy = false;      // an upload or remote fetch owns /blocklist.new
struct BusyFlag {
  bool& f;
  explicit BusyFlag(bool& flag) : f(flag) { f = true; }
  ~BusyFlag() { f = false; }
};
static void handleUploadDone() {
  blBusy = false;
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: incomplete or invalid blocklist.bin");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START: {
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; upWriteOk = true;
      const int cl = web.clientContentLength();
      if (cl > 0 && (size_t)cl > LittleFS.totalBytes()) {   // larger than the whole partition
        upWriteOk = false;
        Serial.printf("[ota] upload too large (%d bytes)\n", cl);
        break;
      }
      if (blBusy) { upWriteOk = false; break; }
      blBusy = true;
      beginBlocklistSwap(cl > 0 ? (size_t)cl : 0);
      upFile = LittleFS.open("/blocklist.new", "w");
      if (!upFile) upWriteOk = false;
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    }
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile && upFile.write(u.buf, u.currentSize) != u.currentSize) upWriteOk = false;
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      if (!upWriteOk) { abortBlocklistSwap(); upOk = false; }
      else upOk = commitNewBlocklist();
      blBusy = false;
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      abortBlocklistSwap();
      blBusy = false;
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static void loadDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "r"); if (!f) return;
  String l = f.readStringUntil('\n'); l.trim(); f.close();
  IPAddress ip; if (l.length() && ip.fromString(l)) configuredDns = ip;
}
static void saveDnsCfg() {
  if (!(uint32_t)configuredDns) { LittleFS.remove("/dns.cfg"); return; }
  File f = LittleFS.open("/dns.cfg", "w"); if (!f) return;
  f.println(configuredDns.toString()); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  if (blBusy) { updateStatus = "busy"; return false; }
  BusyFlag busy(blBusy);
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  const int len = http.getSize();
  if (len > 0 && (size_t)len > LittleFS.totalBytes()) {
    http.end(); updateStatus = "too big (" + String(len) + "B)";
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  beginBlocklistSwap(len > 0 ? (size_t)len : 0);
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); abortBlocklistSwap(); updateStatus = "fs open failed"; return false; }
  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis(); bool writeFailed = false;
  while (http.connected() && (len < 0 || (int)total < len)) {
    handleUpstream();                        // keep answering DNS during the download
    handleDns();
    size_t avail = stream->available();
    if (avail) {
      size_t n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0 && f.write(b, n) != n) { writeFailed = true; break; }
      total += n; idle = millis();
    }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  if (writeFailed || (len >= 0 && (size_t)len != total)) {   // never commit a truncated list
    abortBlocklistSwap();
    updateStatus = "incomplete (" + String(total) + "/" + String(len) + "B)";
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.setAutoReconnect(true); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

// BOOT button (GPIO0 on the ESP32-S3). Holding it for 3 s while running wipes the
// saved WiFi credentials. (Holding it during power-on just enters the ROM download
// mode, so a boot-time check would never fire.)
static const int WIFI_RESET_PIN = 0;
static void pollBootButton() {
  static uint32_t downSince = 0;
  if (digitalRead(WIFI_RESET_PIN) == HIGH) { downSince = 0; return; }
  const uint32_t now = millis();
  if (downSince == 0) { downSince = now ? now : 1; return; }
  if (now - downSince >= 3000) {
    Serial.println("[setup] BOOT held 3 s -> clearing saved WiFi, rebooting into the setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end();
    delay(200); ESP.restart();
  }
}

// WiFi failures otherwise leave a silent DNS hole: restart and retry instead.
static void checkWifi() {
  static uint32_t lostSince = 0;
  const uint32_t now = millis();
  if (WiFi.status() == WL_CONNECTED) { lostSince = 0; return; }
  if (lostSince == 0) { lostSince = now ? now : 1; return; }
  if (now - lostSince > 120000UL) {
    Serial.println("[wifi] disconnected for 2 min, restarting");
    ESP.restart();
  }
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>S3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; ESP32-S3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + ss + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>s3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns - blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + jesc(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "S3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[adblock] booting");
  Serial.printf("chip: %s rev %u, %u KB RAM, PSRAM %u KB free / %u KB total\n",
                ESP.getChipModel(), (unsigned)ESP.getChipRevision(), (unsigned)(ESP.getHeapSize() / 1024),
                (unsigned)(ESP.getFreePsram() / 1024), (unsigned)(ESP.getPsramSize() / 1024));
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  // Recover from a reboot during a blocklist swap.
  LittleFS.remove("/blocklist.new");
  if (LittleFS.exists(BLOCKLIST_PATH)) LittleFS.remove("/blocklist.old");
  else if (LittleFS.exists("/blocklist.old")) LittleFS.rename("/blocklist.old", BLOCKLIST_PATH);
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    tryMirrorPsram();
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadUpdateCfg(); loadDnsCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  pinMode(WIFI_RESET_PIN, INPUT_PULLUP);   // hold 3 s while running to reset WiFi

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("s3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://s3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS - those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  nextUpstreamId = (uint16_t)esp_random();
  buildUpstreamList();      // configured -> DHCP resolvers -> built-in default
  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared - rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setdns", []() {                   // /setdns?ip=192.168.1.1  (empty = auto)
    if (!requireAuth()) return;
    const String s = web.arg("ip"); IPAddress ip;
    if (!s.length()) configuredDns = IPAddress();
    else if (ip.fromString(s)) configuredDns = ip;
    else { web.send(400, "text/plain", "bad ip"); return; }
    saveDnsCfg(); buildUpstreamList();
    web.send(200, "text/plain", activeUpstream().toString());
  });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("s3adblock");   // pio run -e s3-ota -t upload --upload-port s3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  handleUpstream();                        // replies first: lower latency for everyone
  expirePending();
  bool busy = handleDns();
  pollBootButton();
  checkWifi();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length() && !blBusy) {    // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
