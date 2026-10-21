# esp32-s3-adblock

[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) の **ESP32-S3 向けフォーク**です。
Pi-hole 風の DNS 広告ブロッカーで、ブロックリストをドメイン文字列ではなく**ソート済みの 40 ビット
FNV-1a ハッシュ**としてフラッシュに保存します。

このフォークは **ESP32-S3（N16R8）専用**に簡略化し、16 MB のフラッシュを使って
**230 万ドメイン**をブロックします。ハッシュ方式・ダッシュボード・キャプティブポータル・OTA の
設計はすべて上流プロジェクトによるものです。

[English README](README.md) · [Changelog](CHANGELOG.md) · [上流のデモ動画](https://youtube.com/shorts/RaxszOUMi8E?feature=share)

> **ベースプロジェクト: [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)**
> *"2ドルの ESP32-C3（PSRAM なし）で Pi-hole 級の DNS 広告ブロッカー: 53.7 万ドメインを
> 40 ビット FNV-1a ハッシュとして保持し、フラッシュを二分探索。UDP DNS シンクホール + Web ダッシュボード。"*
> 変更点は [Attribution](#attribution) を参照してください。

```
DNSクエリ ──▶ ドメイン抽出 ──▶ FNV-1a ハッシュ（親サフィックスも）
                        ──▶ ソート済み 40 ビットハッシュ表を検索
                             ├─ 一致 ──▶ 0.0.0.0 を応答（シンクホール）
                             └─ 不一致 ─▶ 上流DNSへ非同期転送して中継
```

## 方式の要点

上流のアイデアをそのまま使っています。ドメイン文字列はデバイスに保存しません。FNV-1a で
ハッシュ化し 40 ビットに切り詰め、ソートしてフラッシュに固定長で並べます。クエリはハッシュ化して
二分探索します。

| | 文字列を RAM に保持（一般的な実装） | 本プロジェクト |
|---|---|---|
| 230 万ドメイン | 約 40 MB の RAM（不可能） | **11.5 MB のフラッシュ** |
| RAM 使用量 | ほぼ全量 | **約 113 KB** |
| 照合 | 文字列比較 | フラッシュ／PSRAM の二分探索 |
| 衝突（230 万件） | — | **1 件**（無関係な 1 ドメインが過剰ブロック） |

ハッシュのみを保存するため、デバイス上のリストは読めません。テキスト版が必要な場合は
`--domains-out` を付けてビルドしてください。

## ハードウェア

**ESP32-S3 N16R8 専用**（16 MB フラッシュ + 8 MB オクタル PSRAM）。

| | |
|---|---|
| フラッシュ | 16 MB（うち 12.5 MB がブロックリスト用ファイルシステム） |
| PSRAM | 8 MB オクタル。収まる場合は表を起動時にミラー |
| ブロックリスト容量 | 約 260 万ドメイン |
| ファームウェア | 約 1.0 MB（3.x コアでは最大約 1.35 MB） |

ミラーには 1 ドメインあたり 5 バイト必要なので、**約 150 万件**までが PSRAM に載ります。
`max`（230 万件・11.5 MB）は 8 MB を超えるためフラッシュ索引経路（1 回約 10 ms）で動作します。

**コンソール接続:** `Serial` は UART0 のままです（CH340/CP210x の USB-シリアル変換向け）。
S3 のネイティブ USB ポートを使う基板では `build_flags` に
`-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1` を追加してください。

## ビルドと書き込み

```bash
# 1. secrets.h を作成して編集（WIFI_* は任意、WEB_PASS / OTA_PASS は必須）
cp src/secrets.example.h src/secrets.h

# 2. ハッシュ表を生成（既定プリセットは max = 約230万件 / 11.5 MB）
python3 tools/build_blocklist.py data/blocklist.bin

# 3. 初回のみ USB でファームウェアとファイルシステムを書き込み
pio run -t upload
pio run -t uploadfs        # 13 MB のイメージでシリアル約4分

# 4. 起動ログを確認
pio device monitor         # -> http://s3adblock.local
```

2 回目以降はファームウェアもブロックリストも Wi-Fi 経由で更新できます。

> ネットワークが `raw.githubusercontent.com` に到達できない場合（中国本土など）は、
> ミラー経由でプリセットを取得できます:
> ```bash
> GITHUB_MIRROR=https://ghproxy.net/ python3 tools/build_blocklist.py data/blocklist.bin --preset max
> ```

### プリセット

| preset | 件数 | サイズ | 内容 |
|---|---|---|---|
| `light` | 約 11.5 万 | 0.55 MB | 広告・トラッカー・マルウェア。SNS/メッセージは影響なし |
| `balanced` | 約 36 万 | 1.8 MB | SNS/アダルト/ギャンブル + OISD big。PSRAM ミラー可 |
| `max`（既定） | 約 230 万 | 11.5 MB | Hagezi **TIF**（フィッシング・詐欺・C2）を追加 |

## Wi-Fi 設定

接続できない場合（または `secrets.h` が未設定の場合）、オープン AP
**`S3-AdBlock-XXXX`** とキャプティブポータルが起動します。スマートフォンで接続し、ネットワークを
選んでパスワードを入力してください。

後から別のネットワークへ移すには、ダッシュボードの **Forget WiFi** を押すか、
**起動中に BOOT（GPIO0）を 3 秒以上押し続けます**。

## ダッシュボードと HTTP API

`http://s3adblock.local` で、クライアント別のブロック/許可数、システム情報、一時停止、
クライアント禁止、カスタムドメイン、ブロックリストのアップロード、自動更新、ファームウェア OTA を
操作できます。読み取り専用エンドポイントは認証不要、状態を変更するものは **Basic 認証** と
ヘッダー `X-Requested-With: s3-adblock`（CSRF 対策）の両方が必要です。

| エンドポイント | 認証 | 用途 |
|---|---|---|
| `GET /` | – | ダッシュボード |
| `GET /stats.json` | – | 統計、クライアント、カスタムドメイン、使用中の上流 |
| `GET /ban?ip=` | 要 | クライアント禁止の切り替え |
| `GET /addblock?d=` / `unblock?d=` | 要 | カスタムブロックドメイン |
| `GET /pause?s=` / `resume` | 要 | 指定秒数だけブロックを停止 |
| `GET /setdns?ip=` | 要 | 上流 DNS を固定（空で自動） |
| `GET /setupdate?u=&h=` / `fetchnow` | 要 | リモートブロックリストのスケジュール |
| `POST /upload` | 要 | ブロックリストのアップロード |
| `POST /update` | 要 | ファームウェア OTA |
| `GET /forgetwifi` | 要 | Wi-Fi 設定を消去してポータルへ |

### 上流 DNS の選択

許可されたドメインは次の順に転送されます。

1. `/setdns` で固定したリゾルバ（`/dns.cfg` に保存）
2. DHCP で配布された DNS（通常はルーター）
3. 内蔵の既定値 `9.9.9.9`

応答が 3 回連続で途絶えると次の候補へ切り替わります。公共 DNS が遮断されているネットワークでは、
この切り替えがないと「ブロックは効くが通常のサイトが引けない」状態になります。

## OTA 更新

- **ブロックリスト** — ダッシュボードの *Blocklist → Upload*、または *Remote auto-update* に
  URL を設定して定期取得。差し替え中も（容量に余裕があれば）旧リストでブロックを継続し、
  不完全なダウンロードはロールバックされます。
- **ファームウェア** — *Firmware → OTA update* に `.pio/build/s3/firmware.bin` をアップロード、
  または:
  ```bash
  export OTA_PASS='<secrets.h の OTA_PASS>'
  pio run -e s3-ota -t upload --upload-port s3adblock.local
  ```

## 性能

ESP32-S3 N16R8、230 万ドメイン（フラッシュ経路）での実測値:

| ケース | レイテンシ |
|---|---|
| ブロック（キャッシュ命中） | 7–12 ms |
| ブロック（フラッシュ二分探索） | 10–47 ms |
| 上流への転送 | 40–110 ms |
| ファームウェア RAM 使用量 | 113 KB / 320 KB（34.6%） |

`light` / `balanced` のように PSRAM に収まるリストでは、起動時ミラーにより RAM 内二分探索になります。

## セキュリティ

- 状態変更エンドポイントは **Basic 認証**、ArduinoOTA は **`OTA_PASS`**。
- **CSRF ヘッダー** `X-Requested-With: s3-adblock`。ブラウザーはキャッシュされた Basic 認証を
  任意のリクエストへ自動付与するため、認証だけでは `<img src="http://s3adblock.local/forgetwifi">`
  のような攻撃を防げません。
- カスタムドメイン名は描画前に HTML エスケープされます（蓄積型 XSS 対策）。
- 平文 HTTP（:80）です。Basic 認証は LAN の信頼境界であり暗号化ではありません。
- `CHANGE_ME_*` のままの場合はシリアルとダッシュボードに警告が出ます。

## トラブルシューティング

| 症状 | 対処 |
|---|---|
| `ModuleNotFoundError: No module named 'intelhex'` | PlatformIO 自身の Python に `pip install intelhex` |
| `Could not open COMx, the port is busy` | 他のモニター/シリアルアプリがポートを占有、または USB 未接続 |
| `Failed to connect` | BOOT を押しながら RST、離してダウンロードモードへ |
| ドメイン数が 0 | `pio run -t uploadfs` の未実行、または `data/blocklist.bin` 不在 |
| ダッシュボードは開くがブロックされない | 端末の DNS がまだデバイスを向いていない |
| ブロックは効くが通常サイトが引けない | 上流 DNS に到達不能 → ダッシュボードで *Upstream DNS* を設定 |
| `s3adblock.local` が引けない | `pio device monitor` に出る IP を使用 |
| `"psram":false` | リストが空き PSRAM より大きい（`max` では正常） |

## Attribution

本プロジェクトは **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)**
（*"Pi-hole-class DNS ad-blocker on a $2 ESP32-C3 (no PSRAM): 537k domains as 40-bit FNV-1a
hashes, flash binary search. UDP DNS sinkhole + web dashboard."*、
[デモ動画](https://youtube.com/shorts/RaxszOUMi8E?feature=share)）の**改変版**です。
上流はさらに [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) の
「ブロック対象に 0.0.0.0 を返す」アイデアをクレジットしています。

**このフォークでの変更点**（詳細は [CHANGELOG.md](CHANGELOG.md)）:

- **ESP32-S3 専用化** — C3 / クラシック ESP32 の環境・パーティションテーブル・ケースを削除。
  16 MB パーティション、オクタル PSRAM 用 `qio_opi`、UART コンソール、`s3-ota` 環境を追加。
- **DNS 転送の非同期化** — 上流は 1 クエリ最大 1 秒ブロックし、全クライアントを直列化していました。
  現在は最大 32 クエリを同時処理し、送信元・独自トランザクション ID・質問セクションのハッシュで照合します。
- **上流リゾルバの選択と切り替え** — 固定 → DHCP → `9.9.9.9`、3 回タイムアウトで次へ。
- **230 万ドメインのリスト**（`max`、上流既定の約 8 倍）と 12.5 MB ファイルシステム、
  8192 バケットのフラッシュ索引。
- **信頼性修正** — クラッシュ安全なリスト差し替え、再起動後も保持される禁止リスト、LRU
  クライアント表、`/stats.json` のチャンク出力、Wi-Fi ウォッチドッグ、BOOT ボタン復旧。
- ドキュメント、GitHub Pages、CI（ビルドマトリクス、リリースワークフロー）を再構成。

ハッシュ方式・ダッシュボード・キャプティブポータル・CSRF 対策は上流の成果です。

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
