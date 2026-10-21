# esp32-s3-adblock

[English README](README.md) · [更新日志](CHANGELOG.md) · [上游演示视频](https://youtube.com/shorts/RaxszOUMi8E?feature=share)

本项目是 [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) 的
**ESP32-S3 移植版** —— 一个 Pi-hole 风格的 DNS 广告拦截器，把黑名单以**排序后的 40 位
FNV-1a 哈希**存放在 Flash 中，而不是把域名字符串放进内存。

本分支**只保留 ESP32-S3（N16R8）** 目标，并利用 16 MB Flash 拦截 **230 万个域名**。
哈希方案、仪表盘、配网门户、OTA 设计等核心内容均来自上游项目。

> **基于 [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)：**
> *“在 2 美元的 ESP32-C3（无 PSRAM）上实现 Pi-hole 级 DNS 广告拦截：以 40 位 FNV-1a 哈希
> 支持 53.7 万域名，采用闪存二分查找。UDP DNS sinkhole + Web 仪表盘。”*
> 本分支的具体改动见 [署名与改动](#署名与改动)。

```
DNS 查询 ──▶ 提取域名 ──▶ FNV-1a 哈希（含各级父域）
         ──▶ 在排序的 40 位哈希表中查找
              ├─ 命中 ──▶ 返回 0.0.0.0（黑洞）
              └─ 未命中 ─▶ 异步转发到上游，回传应答
```

---

## 目录

- [工作原理](#工作原理)
- [硬件要求](#硬件要求)
- [快速开始](#快速开始)
- [黑名单与预设](#黑名单与预设)
- [WiFi 配网](#wifi-配网)
- [仪表盘与 HTTP API](#仪表盘与-http-api)
- [OTA 更新](#ota-更新)
- [性能](#性能)
- [安全模型](#安全模型)
- [常见问题](#常见问题)
- [仓库结构](#仓库结构)
- [署名与改动](#署名与改动)

---

## 工作原理

沿用上游的核心思路：设备上永远不保存域名字符串。域名经 FNV-1a 哈希后截断为 40 位，
排序后以定长表写入 Flash。查询时对域名（以及每一级父域）计算哈希并二分查找。

| | 内存存字符串（常见 ESP32 方案） | 本项目 |
|---|---|---|
| 230 万域名 | 约 40 MB 内存（不可行） | **11.5 MB Flash** |
| 内存占用 | 几乎全部 | **约 113 KB** |
| 查找方式 | 字符串比较 | Flash / PSRAM 二分查找 |
| 230 万条时哈希冲突 | — | **1 个**（某无关域名被误拦） |

**为什么是 40 位？** 14 万域名时几乎零冲突，230 万时约 1 个。降到 32 位可省 20% Flash，
但 230 万条会带来约 250 个冲突；升到 64 位则每个域名多耗 3 字节，解决的是不存在的问题。

由于设备上只存哈希，列表在设备端不可读。需要文本版时，构建时加 `--domains-out`。

## 硬件要求

**仅支持 ESP32-S3 N16R8**（16 MB Flash + 8 MB Octal PSRAM）。

| 项目 | 规格 |
|---|---|
| Flash | 16 MB（其中 12.5 MB 为黑名单文件系统） |
| PSRAM | 8 MB Octal，列表放得下时用于镜像 |
| 黑名单容量 | 约 260 万域名（11.8 MB 哈希） |
| 固件体积 | 约 1.0 MB（Arduino 3.x 核心下最高约 1.35 MB） |

PSRAM 镜像按每域名 5 字节计算，因此大约 **150 万条以内**会启用镜像。
`max` 预设（230 万条 / 11.5 MB）超过 8 MB PSRAM，走 Flash 索引路径 —— 功能正常，
只是单次查询约 10 ms 而不是微秒级。

**串口接线：** `Serial` 保持在 **UART0**，适配 CH340/CP210x 这类 USB-串口芯片。
如果开发板接的是 S3 原生 USB 口，请在 `build_flags` 中追加
`-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1`。

请使用稳定可靠的 USB 供电，劣质 USB-A→C 转接头在射频发射时容易掉压。

## 快速开始

```bash
# 1. 生成 secrets.h 并填写（WIFI_* 可选，配网门户可代替；
#    WEB_PASS / OTA_PASS 必填，它们保护可刷写接口）
cp src/secrets.example.h src/secrets.h
#    编辑 src/secrets.h

# 2. 生成哈希表（默认预设 max，约 230 万域名 / 11.5 MB）
python3 tools/build_blocklist.py data/blocklist.bin

# 3. 首次且唯一一次 USB 烧录：固件 + 文件系统
pio run -t upload          # 默认环境即 s3
pio run -t uploadfs        # 13 MB 镜像，串口约 4 分钟

# 4. 查看串口日志
pio device monitor         # -> http://s3adblock.local
```

首次烧录后，**固件和黑名单都可以通过 WiFi 更新**，不再需要 USB。

> 请使用较新的 PlatformIO，发行版自带的 4.3.x 太旧。
>
> 若构建报 `ModuleNotFoundError: No module named 'intelhex'`，说明 PlatformIO 自带 Python
> 缺少 esptool 的依赖：
> ```bash
> "%USERPROFILE%\.platformio\penv\Scripts\python.exe" -m pip install intelhex   # Windows
> ~/.platformio/penv/bin/python -m pip install intelhex                          # Linux/macOS
> ```

### 预编译固件

推送 `v*` 标签后，CI 会把 `esp32s3-n16r8-firmware.bin`、`s3-bootloader.bin`、
`s3-partitions.bin`、`boot_app0.bin` 附加到
[Releases](https://github.com/wweng8o/esp32-s3-adblock/releases)。每周也会发布一份
`blocklist.bin`。

不用 PlatformIO 时的烧录方式：

```bash
esptool.py --chip esp32s3 -p COM11 -b 460800 write_flash \
  0x0     s3-bootloader.bin \
  0x8000  s3-partitions.bin \
  0xe000  boot_app0.bin \
  0x10000 esp32s3-n16r8-firmware.bin
```

刚烧完的固件里没有黑名单：用 `pio run -t uploadfs` 写入 `data/blocklist.bin`，
或在仪表盘上传，或把 *Remote auto-update* 指向每周发布的 release 资源。

## 黑名单与预设

`tools/build_blocklist.py` 支持任意组合的 URL 和本地文件，格式包括：

- **hosts 文件** —— `0.0.0.0 ads.example.com`
- **纯域名列表** —— 每行一个域名
- **AdGuard / Adblock 基础规则** —— `||ads.example.com^` 拦截，`@@||ok.example.com^` 放行

拦截某个域名会同时拦截其子域。DNS 哈希列表无法表达的规则（正则、通配符、`$` 修饰符、
外观规则 `##`）会被跳过并计数。`@@` 规则只能移除对应条目本身。若某个源下载失败，
构建会**直接失败**，而不是悄悄生成一份更小的列表（可用 `--allow-missing` 覆盖）。

### 预设

| 预设 | 域名数 | 体积 | 说明 |
|---|---|---|---|
| `light` | 约 11.5 万 | 0.55 MB | 广告/追踪/恶意；不影响社交与通讯 |
| `balanced` | 约 36 万 | 1.8 MB | 增加社交/成人/赌博 + OISD big；仍可 PSRAM 镜像 |
| `max`（默认） | 约 230 万 | 11.5 MB | 增加 Hagezi **TIF**（钓鱼、诈骗、C2 威胁情报） |

```bash
python3 tools/build_blocklist.py data/blocklist.bin                      # max
python3 tools/build_blocklist.py data/blocklist.bin --preset balanced
python3 tools/build_blocklist.py data/blocklist.bin --domains-out blocklist.txt
python3 tools/build_blocklist.py out.bin mylist.txt https://example.com/hosts
```

如果你的网络无法访问 `raw.githubusercontent.com`（中国大陆常见），可以让预设走 GitHub 镜像
——显式指定的源列表保持原样，不会被改写：

```bash
GITHUB_MIRROR=https://ghproxy.net/ python3 tools/build_blocklist.py data/blocklist.bin --preset max
```

`max` 预设的实测构成：

| 源 | 用途 |
|---|---|
| StevenBlack `fakenews-gambling-porn-social` | 广告、恶意、成人、赌博 |
| Hagezi `ultimate` | 全面的广告/追踪 |
| OISD `big` | 广告/追踪/恶意 |
| Hagezi `tif` | 威胁情报源（钓鱼、诈骗、C2） |

实测：2,298,291 条，1 个哈希冲突，跳过 23.3 万条无法表达的 adblock 语法规则。

> 已确认主流站点**不在**列表中：微信、QQ、淘宝、天猫、京东、百度、哔哩哔哩、知乎、抖音、
> 小红书、支付宝、GitHub、微软、Apple、Google、YouTube、Netflix、Steam、Cloudflare、阿里云。

## WiFi 配网

设备无法连接 WiFi（或 `secrets.h` 仍是占位符）时，会开启开放热点
**`S3-AdBlock-XXXX`** 并启动配网页面：手机连接热点 → 选择网络 → 输入密码即可。

以后更换网络有两种方式：

- 在仪表盘点击 **Forget WiFi**，或
- **在设备运行时按住 BOOT（GPIO0）3 秒**。

已配置的设备若连不上，会每 3 分钟重启重试，而不是一直卡在配网页面；
若 WiFi 断开超过 2 分钟，固件会自动重启恢复。

## 仪表盘与 HTTP API

`http://s3adblock.local`（mDNS）—— 客户端拦截/放行统计、系统信息、暂停拦截、封禁客户端、
自定义域名、黑名单上传、远程自动更新、固件 OTA。

只读接口无需认证；所有会改变状态的接口同时要求 **HTTP Basic 认证** 和请求头
`X-Requested-With: s3-adblock`（防 CSRF）。

| 接口 | 认证 | 用途 |
|---|---|---|
| `GET /` | – | 仪表盘 |
| `GET /stats.json` | – | 统计、客户端、自定义域名、当前上游 |
| `GET /ban?ip=` | 是 | 切换客户端封禁 |
| `GET /addblock?d=` / `unblock?d=` | 是 | 自定义拦截域名 |
| `GET /pause?s=` / `resume` | 是 | 暂停拦截 N 秒 |
| `GET /setdns?ip=` | 是 | 固定上游 DNS（留空为自动） |
| `GET /setupdate?u=&h=` / `fetchnow` | 是 | 远程黑名单计划 |
| `POST /upload` | 是 | 上传黑名单 |
| `POST /update` | 是 | 固件 OTA |
| `GET /forgetwifi` | 是 | 清除凭据并重启进入配网 |

`/stats.json` 字段：`blocked`、`allowed`、`domains`、`psram`、`rssi`、`temp`、`heap`、
`psramfree`、`uptime`、`blocking`、`resumeIn`、`dns`（当前生效的上游）、`dnscfg`
（固定配置的上游）、`defcreds`、`clients[]`、`custom[]`。

### 上游 DNS

放行的域名按以下顺序转发：

1. 通过 `/setdns` 固定的解析器（持久化在 `/dns.cfg`）
2. DHCP 下发的 DNS（通常是路由器）
3. 内置默认值 `9.9.9.9`

当前解析器连续 3 次无响应时，自动切换到下一个候选。**这一点在很多网络上都至关重要**
（不少运营商和公司 WiFi 会丢弃 `9.9.9.9`/`1.1.1.1`）：没有自动切换时，拦截仍然生效，
但所有正常域名都会超时，表现得像“整个网络断了”。

## OTA 更新

- **黑名单** —— 仪表盘 *Blocklist → Upload* 上传，或在 *Remote auto-update* 设置 URL 定时拉取。
  替换过程中（Flash 空间足够时）旧列表继续拦截；下载不完整会回滚；换表期间重启会在启动时自动修复。
  下载过程中 DNS 查询仍在正常响应。
- **固件** —— 仪表盘 *Firmware → OTA update* 上传 `.pio/build/s3/firmware.bin`，或：

  ```bash
  export OTA_PASS='<secrets.h 中的 OTA_PASS>'
  pio run -e s3-ota -t upload --upload-port s3adblock.local
  pio run -e s3-ota -t upload --upload-port 192.168.1.50   # 或直接用 IP
  ```

  若 espota 报 `No response from device`，说明设备无法连回你电脑的监听端口
  （防火墙或跨 VLAN），改用仪表盘上传即可。

## 性能

在 ESP32-S3 N16R8、230 万条黑名单（走 Flash 路径，因列表超过 8 MB PSRAM）下实测：

| 场景 | 延迟 |
|---|---|
| 命中缓存（拦截） | 7–12 ms |
| Flash 二分查找（拦截） | 10–47 ms |
| 转发上游 | 40–110 ms |
| 固件内存占用 | 113 KB / 320 KB（34.6%） |

当列表能放进 PSRAM（`light`、`balanced`）时，启动会镜像整张表，查找变为内存内二分查找。

## 安全模型

- 所有改变状态的接口使用 **Basic 认证**（`WEB_USER`/`WEB_PASS`），ArduinoOTA 使用 **`OTA_PASS`**。
- **CSRF 防护头** `X-Requested-With: s3-adblock`：浏览器会对已认证源站的任意请求自动附加缓存的
  Basic 凭据，因此仅靠认证无法阻止任意网页通过 `<img src="http://s3adblock.local/forgetwifi">`
  操作设备。
- **存储型 XSS**：自定义域名在渲染前会做 HTML 转义。
- **局限**：HTTP 明文（:80）。Basic 认证在 HTTP 上只是局域网信任边界，不是加密。
  配网热点（`S3-AdBlock-XXXX`）按设计开放。
- **占位密码**：若仍是 `CHANGE_ME_*`，固件会在串口和仪表盘给出警告。

## 常见问题

| 现象 | 处理 |
|---|---|
| `ModuleNotFoundError: No module named 'intelhex'` | 装入 PlatformIO 自己的 Python（见「快速开始」） |
| `Could not open COMx, the port is busy` | 串口被监视器/其他软件占用，或 USB 已断开 |
| 烧录时报 `Failed to connect` | 按住 BOOT，点一下 RST，松开 BOOT 进入下载模式 |
| 仪表盘显示 0 个域名 | 漏了 `pio run -t uploadfs`，或 `data/blocklist.bin` 不存在 |
| 仪表盘能开但没有任何拦截 | 客户端还没有把 DNS 指向设备 |
| 该拦的拦了，正常网站打不开 | 上游 DNS 不通 → 在仪表盘设置 *Upstream DNS* |
| espota 报 `No response from device` | 电脑防火墙/VLAN 问题；改用仪表盘上传固件 |
| `s3adblock.local` 解析不了 | 用 `pio device monitor` 打印的 IP |
| 仪表盘 MAC 列为空 | ARP 尚未解析，固件会自动补刷 |
| `"psram":false` | 列表大于可用 PSRAM，`max` 预设下属正常 |

**ModemManager**（Fedora/Ubuntu 默认安装）会占用 `/dev/ttyACM0` 并翻转 DTR/RTS 导致设备复位：

```bash
sudo systemctl stop ModemManager
echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## 仓库结构

```
platformio.ini               环境 s3（默认）与 s3-ota（ArduinoOTA）
partitions.csv               16 MB S3：2×1.6 MB app + 12.8 MB LittleFS
src/main.cpp                 固件：DNS sinkhole、仪表盘 API、OTA、配网
src/page.h                   仪表盘 HTML（PROGMEM）
src/secrets.example.h        凭据模板（复制为 secrets.h）
tools/build_blocklist.py     列表 -> 排序 40 位哈希表（--preset、--domains-out）
data/                        LittleFS 源目录（blocklist.bin 放这里）
docs/index.html              GitHub Pages 落地页
.github/workflows/build.yml  构建 s3
.github/workflows/release.yml    打标签 -> 固件附加到 Release
.github/workflows/blocklist.yml  每周发布黑名单
README.md                    英文文档
CHANGELOG.md                 本分支相对上游的改动
```

## 署名与改动

本项目是 **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)**
（*“在 2 美元的 ESP32-C3（无 PSRAM）上实现 Pi-hole 级 DNS 广告拦截：以 40 位 FNV-1a 哈希
支持 53.7 万域名，采用闪存二分查找。UDP DNS sinkhole + Web 仪表盘。”*，
[演示视频](https://youtube.com/shorts/RaxszOUMi8E?feature=share)）的**修改版本**。
上游项目又致谢了 [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) 的
“对拦截域名返回 0.0.0.0”这一思路。

**本分支的改动**（详见 [CHANGELOG.md](CHANGELOG.md)）：

- **只支持 ESP32-S3**：移除 C3 与经典 ESP32 环境、分区表和外壳模型。目标为 N16R8，
  使用 16 MB 分区表、Octal PSRAM 的 `qio_opi` sdkconfig、UART 控制台和 `s3-ota` 环境。
- **DNS 异步转发**：上游实现每个查询最多阻塞 1 秒，导致所有客户端串行、网页卡顿。
  现在最多 32 个查询并发，通过源地址、私有事务 ID 和问题段哈希严格匹配应答。
- **上游解析器选择与轮换**：固定 → DHCP → 内置 `9.9.9.9`，连续 3 次超时自动切换，
  避免“公共 DNS 被封导致正常网站全挂”。
- **230 万条黑名单**（`max` 预设，约为上游默认的 8 倍），配合 12.5 MB 文件系统和
  8192 桶的 Flash 索引，防止桶溢出漏拦。
- **可靠性修复**：崩溃安全的黑名单替换与回滚、重启后仍保留的封禁列表、LRU 客户端表、
  分块输出 `/stats.json`、WiFi 看门狗、BOOT 按键恢复。
- 重写文档、GitHub Pages 落地页和 CI（构建矩阵、发布流水线）。

哈希方案、仪表盘、配网门户、CSRF 加固等均为上游成果，请一并将认可给予上游项目。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。版权归上游作者及本分支贡献者所有。
