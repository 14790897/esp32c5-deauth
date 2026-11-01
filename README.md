# esp32c5-deauth

[![firmware](https://github.com/14790897/esp32c5-deauth/actions/workflows/build.yml/badge.svg)](https://github.com/14790897/esp32c5-deauth/actions/workflows/build.yml)

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
- **Power.** ESP32-C5 boards can brown out during Wi-Fi PHY init or TX on weak
  USB ports/cables. Use a short, thick cable and a direct USB 3.x port or a
  powered hub. A `E BOD: Brownout detector was triggered` reset is a power
  delivery issue, not a firmware bug.
- **Vendor check.** IDF 6.1's ESP32-C5 `libnet80211.a` includes a sanity check
  that rejects deauth/disassoc injected with `esp_wifi_80211_tx()`. The patch
  script bypasses that check locally. This is intended for research and
  authorized testing; review what you are changing before running it.

## Repository layout

```text
CMakeLists.txt, sdkconfig.defaults, main/   firmware
build_c5.bat, flash_c5.bat                  Windows helpers
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
