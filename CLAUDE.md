# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running scripts

All scripts require `sudo` and must run with the venv active. Stop NetworkManager first:

```bash
sudo service NetworkManager stop

# Activate venv (examples/ has its own)
source examples/lib/python3.14/site-packages/../../../bin/activate  # or equivalent

# Host a network
sudo -E python3 examples/host.py

# Join a network
sudo -E python3 examples/join.py

# Decrypt a pcap
sudo -E python3 examples/decrypt_pcap.py input.pcapng output.pcap --keys ~/.switch/prod.keys
```

Monitor mode setup/teardown (Intel adapter workflow):

```bash
sudo examples/up.bash    # starts wlan0mon, sets channel 1, disables FCS
sudo examples/down.bash  # stops monitor, restarts NetworkManager
```

`up.bash` uses `airmon-ng` to create `wlan0mon` on the same phy as `wlan0`.

## Architecture

### Interface stack

`wlan.py` owns all nl80211/monitor interaction. Three virtual interface types:

- **`AccessPoint`** — AP mode via `NL80211_CMD_START_AP`. Handles management frames (auth, assoc, probe) through the kernel. Stations are registered via `NL80211_CMD_NEW_STATION` + `NL80211_CMD_SET_STATION`. Control-port frames (LDN auth, `ETH_P_OUI = 0x88B7`) are delivered over nl80211 rather than a raw socket.
- **`Monitor`** — Raw monitor mode interface for injecting and capturing 802.11 data frames (ARP, IP/UDP, broadcast) that the AP interface cannot handle. All data frames are wrapped/unwrapped in `RadiotapFrame`.
- **`Tap`** — Linux TAP device. Decrypted frames are written here so the kernel network stack sees them as normal Ethernet frames.

Both the AP and monitor interfaces live on the same physical radio (`phyname` / `phyname_monitor`, both default to `"phy0"`).

### Frame flow: hosting

`APNetwork` (`__init__.py`) orchestrates the host side:

1. **Advertisement** — Broadcast via the monitor as a `wlan.ActionFrame` (vendor action, category `0x7f`). Encrypted with a key derived from `server_random` + SSID. Repeated on a timer.
2. **Authentication** — Console sends LDN auth over the control port (`ETH_P_OUI`). `APNetwork._process_events()` handles it, derives the joining station's auth key, sends response, then broadcasts an updated advertisement immediately before responding.
3. **UDP handshake** — After the console associates and the LDN auth exchange completes, `_do_udp_handshake()` sends two `01 00 00 00` UDP packets back-to-back to port 5001, waits for the console's echo, then sends one final packet.
4. **Data path** — `_process_data_frame()` receives monitor frames, decrypts CCMP with the derived `wlan_key`, and writes plaintext Ethernet payloads to the TAP device. Outbound data frames go through the monitor as QoS Data (subtype 8).

### Key derivation

`KeyDerivation` (`__init__.py`) derives three keys from `prod.keys`:

| Key | Purpose |
|-----|---------|
| `derive_advertise_key` | Encrypts/decrypts advertisement frames (AES-GCM or AES-CTR) |
| `derive_authentication_key` | Per-client auth challenge (AES-GCM) |
| `derive_data_key` | CCMP key for all 802.11 data frames; derived from `server_random + password` |

Protocol version 1 uses `master_key_00`; version 3 (firmware 20.0.0+) uses `master_key_12`.

### CCMP encryption

`DataFrame.encrypt()` / `DataFrame.decrypt()` in `wlan.py` do AES-128-CCM directly. Nonce = priority byte + source MAC + 6-byte big-endian packet number. AAD includes the masked MAC header + QoS control field (lower nibble only). Data frames use subtype 8 (QoS Data) with `qos_control = 0`.

### 802.11 frame encoding

`encode_elements()` accepts `dict[int, bytes | list[bytes]]` — pass a list when multiple IEs share the same tag (e.g., two `WLAN_EID_VENDOR_SPECIFIC` entries). Management frames are dataclasses with `.encode()` / `.decode()` methods. `MACHeader` is decoded first to dispatch by type/subtype.

### Async model

Everything is `trio`. Long-running per-station work (UDP handshake) runs as nursery background tasks in `_process_events()`. Channels (`trio.open_memory_channel`) signal handshake tasks on disassociation (`'cancel'`) or UDP echo (`'echo'`).

## Known hardware notes

- **Intel iwlwifi**: does not ACK unicast data frames in mixed AP+monitor mode. The console retransmits, but the handshake still progresses. No workaround in software — ACK frames cannot be injected at the required SIFS timing.
- **Alfa adapters**: properly ACK frames in AP mode; preferred for hosting.
- The monitor interface needs `rx-fcs off` (`ethtool -K wlan0mon rx-fcs off`) to avoid 4-byte FCS being included in captured frame data.
