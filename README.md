# esp32c5-deauth

[![firmware](https://github.com/14790897/esp32c5-deauth/actions/workflows/build.yml/badge.svg)](https://github.com/14790897/esp32c5-deauth/actions/workflows/build.yml)

Prebuilt firmware binaries are attached to the
[latest release](https://github.com/14790897/esp32c5-deauth/releases/latest).
Releases are versioned automatically with
[semantic-release](https://semantic-release.gitbook.io/) from Conventional
Commits: `feat:` / `fix:` / `perf:` (and breaking changes) produce a new
version and attach the three firmware images.

Minimal ESP32-C5 firmware for **authorized** Wi-Fi security testing: a serial
CLI that can scan, locate a client's current AP, inspect RSN/PMF capabilities,
and send targeted 802.11 deauthentication frames across 2.4 GHz and 5 GHz.

> **Authorized testing only.** This firmware sends deauthentication frames,
> which disrupt Wi-Fi connectivity and may be illegal where you live. Use it
> only on networks and devices you own, or for which you have explicit written
> permission. The authors are not responsible for misuse. Do not use it to
> harass, jam, or attack third parties.

## Features

- ESP32-C5, 2.4 GHz + 5 GHz, USB-Serial/JTAG console (115200 baud).
- CLI commands:
  - `scan` — active scan of both bands, prints BSSID, channel, RSSI, auth mode.
  - `findsta <mac> [ch,ch..]` — promiscuous-mode sweep that reports the
    client's current BSSID and channel. Optional channel hints make it fast.
  - `rsn <bssid>` — captures a beacon and parses the RSN IE, including the
    MFPC/MFPR (802.11w PMF) bits.
  - `target <mac>` — client MAC to target.
  - `bssid <mac> [ch]` — add an AP BSSID with an optional channel (up to 8).
  - `ch <ch>`, `start`, `stop`, `status`.
  - `beaconspam <ssid1,ssid2,...>` / `beaconspam auto <n>` — **experimental;
    currently non-functional on ESP32-C5** (see the beacon-spam note below).
  - `stopbeacons` — stop beacon spam and restore STA mode.
- Per-BSSID channels and automatic 2.4 GHz/5 GHz band switching.
- Fixed 20 MHz bandwidth so channel tuning and `findsta` reports are exact.
- 20 dBm max TX power.

## Requirements

- ESP32-C5 board (4 MB flash, no PSRAM was used in testing).
- ESP-IDF v6.1 with ESP32-C5 support and the RISC-V toolchain.
- Windows was used for development; Linux/macOS should work with small script
  adjustments.

## Build (Windows)

1. Install ESP-IDF v6.1 and open an ESP-IDF terminal (so `IDF_PATH` is set).
2. Create the assembler shim (needed because the RISC-V toolchain's `as` is a
   launcher that expects its `*-as-xespv2p1/p2.exe` siblings, while GCC looks
   up a plain `as`):

   ```bat
   python tools\make_toolchain_shim.py
   ```

3. Patch the local ESP32-C5 Wi-Fi library. The stock IDF 6.1 library rejects
   deauth/disassoc raw frames with `wifi:unsupport frame type: 0c0`. The script
   changes the entry of `ieee80211_raw_frame_sanity_check` in
   `ieee80211_output.o` to `li a0,0; ret` and keeps a backup:

   ```bat
   python tools\patch_libnet80211.py
   ```

   This modifies **your local** ESP-IDF installation
   (`components/esp_wifi/lib/esp32c5/libnet80211.a`); no vendor binary is
   distributed by this repository. Re-run it after upgrading/reinstalling IDF.
   Restore with `libnet80211.a.orig` if needed.

4. Build and flash:

   ```bat
   build_c5.bat
   flash_c5.bat COM12
   ```

   Or manually:

   ```bat
   idf.py set-target esp32c5
   idf.py build
   idf.py -p COM12 flash monitor
   ```

### Single-file flash

The [latest release](https://github.com/14790897/esp32c5-deauth/releases/latest)
also provides `c5_deauth_full.bin`, a 4 MB merged image containing the
bootloader, partition table, and application. Flash it at offset `0x0`:

```bat
python -m esptool --chip esp32c5 -p COM12 -b 460800 write-flash --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 c5_deauth_full.bin
```

To generate it yourself after `idf.py build`, run `merge_c5.bat`, or:

```bat
python -m esptool --chip esp32c5 merge-bin -o build\c5_deauth_full.bin --target-offset 0 --flash-mode dio --flash-freq 80m --flash-size 4MB --pad-to-size 4MB 0x2000 build\bootloader\bootloader.bin 0x8000 build\partition_table\partition-table.bin 0x10000 build\c5_deauth.bin
```

The full image covers the whole 4 MB flash, including the NVS region; the
firmware re-initializes NVS on first boot.

## Usage

Open the serial console at 115200 baud (or use `console_c5.py`):

```bash
python console_c5.py COM12
```

Typical flow (all addresses below are placeholders):

```text
scan
findsta 02:00:00:00:00:01 36,1,6,11
target 02:00:00:00:00:01
clear
bssid 02:11:22:33:44:55 36
bssid 02:11:22:33:44:56 1
start
status
stop
```

`findsta` needs the client to be active; keep some traffic flowing (e.g., ping
the client from another machine) while it sweeps.

> **Experimental / unsupported on ESP32-C5.** In testing, the C5 AP came up
> only on 2.4 GHz, the 5 GHz AP never appeared, and fake BSSIDs injected via
> `WIFI_IF_AP` were accepted by the driver but not observed on air by an
> independent scanner or a phone. Do not expect this to create visible fake
> SSIDs on this hardware. The commands are kept for experimentation with
> other targets/drivers.

Fake 5G networks (beacon spam):

```text
ch 36
beaconspam auto 100
status
stopbeacons
```

Use `beaconspam name1,name2,...` for custom SSIDs. While beacons are running
the C5 is in AP mode; `scan`, `findsta`, and deauth are unavailable until
`stopbeacons`.

## Technical notes

- **Deauth is per BSSID.** A deauth/disassoc frame removes a client from one
  BSSID. On a mesh or multi-AP network the client may immediately reassociate
  to another BSSID of the same SSID, so the SSID-level connection may persist.
  To push a client off an SSID, all of that SSID's BSSIDs (both bands) must be
  suppressed; otherwise the client simply roams. A single-radio ESP32 cannot
  transmit on 2.4 GHz and 5 GHz at the same time.
- **PMF (802.11w).** If the AP advertises MFPC/MFPR in its RSN IE, deauth and
  disassoc frames may be protected/ignored. Use `rsn <bssid>` to check. PMF is
  commonly enabled by WPA3 or by WPA2/WPA3 transition modes.
- **Channel width.** The firmware sets 20 MHz on both bands. With a wider
  default bandwidth, `esp_wifi_set_channel()` reports and transmissions can
  refer to a segment rather than the AP's primary channel, which makes
  `findsta` results misleading.
- **Power / USB hubs.** ESP32-C5 boards can brown out during Wi-Fi PHY init
  or TX on weak USB ports/cables. Prefer a **direct motherboard USB port**
  (USB 3.x if available) with a short, thick data cable. **Avoid USB hubs**,
  especially unpowered ones: the C5's peak current can exceed what a hub (or
  a front-panel/extension port) can deliver, causing
  `E BOD: Brownout detector was triggered` resets. A genuinely powered hub
  with an adequate power adapter may work, but a direct connection is the
  most reliable. A BOD reset is a power-delivery issue, not a firmware bug.
  （中文：尽量直连主板 USB 口，优先 USB 3.x，用短而粗的数据线；避免
  USB Hub、前置口和延长线，峰值电流不足会触发 brownout 复位。）
- **Beacon spam is experimental and currently non-functional on the C5.**
  The radio can transmit on 5 GHz (deauth works), but the AP beacon TX path
  does not transmit injected beacons with foreign BSSIDs. See
  [Why 5G beacon spam is not supported on this board](#why-5g-beacon-spam-is-not-supported-on-this-board)
  for the evidence and the single-RF-chain constraint.
- **Vendor check.** IDF 6.1's ESP32-C5 `libnet80211.a` includes a sanity check
  that rejects deauth/disassoc injected with `esp_wifi_80211_tx()`. The patch
  script bypasses that check locally. This is intended for research and
  authorized testing; review what you are changing before running it.

## Why 5G beacon spam is not supported on this board

It is not a matter of the C5 being unable to transmit on 5 GHz: targeted
deauth on channel 36 works. The limitation is in the beacon transmit path and
in the C5's single-radio architecture.

- **One RF chain.** The ESP32-C5 has a single RF chain; STA and SoftAP must
  share one channel. Espressif describes this in
  [esp-idf#18334](https://github.com/espressif/esp-idf/issues/18334). A 5 GHz
  STA forces the SoftAP onto the same 5 GHz channel, and a 2.4 GHz AP cannot
  coexist with a 5 GHz STA. In testing, an AP-only configuration came up on
  2.4 GHz (its own hidden beacon was visible on channel 1), while a requested
  5 GHz AP was never observed.
- **The AP beacon scheduler owns beacon TX.** Starting an AP makes the driver
  emit that AP's own beacon. Raw beacon frames injected with
  `esp_wifi_80211_tx(WIFI_IF_AP, ...)` return `ESP_OK` (the firmware even
  reports ~30 pps), but they do not appear on air. Setting `en_sys_seq=true`
  or changing the fake BSSID to the AP's own MAC did not change this. The
  frames are accepted and then dropped in the AP TX path.
- **The vendor library patch does not cover this.**
  `tools/patch_libnet80211.py` only bypasses
  `ieee80211_raw_frame_sanity_check` (the frame-type allowlist in
  `libnet80211.a`). It does not change the AP beacon queue/scheduler in the
  closed-source Wi-Fi firmware.
- **Evidence.** Tested with 3, 8, and 100 fake SSIDs on 2.4 GHz channel 1 and
  5 GHz channel 36; scanned with an independent RTL8821CE adapter
  (`iw scan flush`) and a phone. The AP's own beacon was visible on 2.4 GHz;
  no fake BSSID was observed on air, and the phone never showed the fake
  SSIDs. One early PVE scan once listed three fake BSSIDs, but it was not
  reproducible.

Plain-language version: deauth is like handing a note to one client, which
the STA interface allows. A beacon is like a broadcast signboard; the AP's
beacon scheduler owns that signboard and only displays the AP's own BSS. The
radio can transmit on 5 GHz, but you cannot make it broadcast a custom beacon
with a foreign BSSID.

What does work:

- Deauth/disassoc on 2.4 GHz and 5 GHz (this repository's core feature).
- 2.4 GHz beacon spam on an ESP32-S3 running GhostESP; that driver allows
  injected beacons.
- Multiple 5 GHz SSIDs from a real 5 GHz AP/router (most routers support
  several SSIDs per band).

A C5 module with more flash/PSRAM (e.g., N16R8) does not remove these
RF/driver limitations.

**中文摘要：** C5 能发 5G 信号（deauth 已在 ch36 验证），但只有一个 RF
chain，STA/SoftAP 必须同信道；AP 固件只发送自己的 beacon，注入的假 BSSID
beacon 会被驱动静默丢弃。`libnet80211.a` 补丁只绕过帧类型检查，管不到 AP
的 beacon 发送路径。因此这块 C5 做不了 5G 假 SSID；2.4G beacon spam 可用
S3 + GhostESP，多 5G SSID 请用真实 5G AP/路由器。

## Repository layout

```text
CMakeLists.txt, sdkconfig.defaults, main/   firmware
build_c5.bat, flash_c5.bat, merge_c5.bat   Windows helpers
console_c5.py                               serial CLI client
tools/make_toolchain_shim.py                create the `as` shim from your toolchain
tools/patch_libnet80211.py                  patch your local C5 Wi-Fi library
examples/                                   placeholder examples
```

## License

MIT for the code in this repository. Espressif's library and toolchain files
are not included and remain under their own licenses.

---

**中文说明：** 本项目仅用于对自己拥有或已获书面授权的网络做安全测试。deauth
会中断 Wi-Fi，可能违法；请勿用于骚扰或攻击第三方。仓库不包含 Espressif 的
闭源库或工具链二进制，补丁脚本只修改你本机的 ESP-IDF 安装。
