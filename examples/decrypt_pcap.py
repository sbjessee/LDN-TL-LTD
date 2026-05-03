
# Reads an 802.11 monitor-mode pcapng capture, derives the LDN data key from
# the first advertisement (action) frame, decrypts all protected data frames,
# and writes a cleaned-up pcap with only the first beacon and first
# advertisement retained alongside all other frames.

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import argparse
import struct
import ldn
from ldn import wlan

from scapy.all import PcapReader, PcapWriter
from scapy.layers.dot11 import RadioTap


RADIOTAP_FLAG_FCS = 0x10


def rebuild_radiotap(original: wlan.RadiotapFrame, dot11_data: bytes) -> bytes:
    rt = wlan.RadiotapFrame(dot11_data)
    rt.mactime = original.mactime
    rt.rate = original.rate
    rt.frequency = original.frequency
    rt.channel_flags = original.channel_flags
    # Clear the "FCS at end" flag — the re-encoded frame has no FCS.
    if original.flags is not None:
        rt.flags = original.flags & ~RADIOTAP_FLAG_FCS
    return rt.encode()


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt LDN frames in a monitor-mode packet capture"
    )
    parser.add_argument("input", help="Input pcapng/pcap file")
    parser.add_argument("output", help="Output pcap file")
    parser.add_argument(
        "--keys", default="~/.switch/prod.keys", help="Path to prod.keys"
    )
    parser.add_argument(
        "--password", default="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        help="Network password used to derive the data key"
    )
    parser.add_argument(
        "--protocol", type=int, default=1,
        help="LDN protocol version: 1 (pre-20.0.0) or 3 (20.0.0+)"
    )
    args = parser.parse_args()

    keys = ldn.load_keys(args.keys)
    key_derivation = ldn.KeyDerivation(keys, args.protocol)
    password = args.password.encode()

    wlan_key = None
    seen_beacon = False
    seen_advertisement = False
    decrypt_ok = 0
    decrypt_fail = 0
    total = 0
    input_frame = 0

    with PcapReader(args.input) as reader, \
         PcapWriter(args.output, linktype=127, sync=True) as writer:

        for packet in reader:
            total += 1
            input_frame += 1
            raw = bytes(packet)

            # Strip the RadioTap wrapper to get the raw 802.11 frame.
            try:
                radiotap = wlan.RadiotapFrame()
                radiotap.decode(raw)
                frame_data = radiotap.data
            except Exception:
                writer.write(packet)
                continue

            # Identify type and subtype from the MAC header.
            try:
                header = wlan.MACHeader()
                header.decode(frame_data)
            except Exception:
                writer.write(packet)
                continue

            if header.type == wlan.IEEE80211_FTYPE_MGMT:
                if header.subtype == wlan.IEEE80211_STYPE_BEACON:
                    if not seen_beacon:
                        seen_beacon = True
                        writer.write(packet)
                    # Subsequent beacons are dropped.

                elif header.subtype == wlan.IEEE80211_STYPE_ACTION:
                    if not seen_advertisement:
                        seen_advertisement = True
                        # Parse the action body to derive the data key.
                        if wlan_key is None:
                            try:
                                action = wlan.ActionFrame()
                                action.decode(frame_data)
                                adv = ldn.AdvertisementFrame(key_derivation, args.protocol)
                                adv.decode(action.action)
                                server_random = adv.payload.server_random
                                wlan_key = key_derivation.derive_data_key(
                                    server_random, password
                                )
                                print(f"Server random:  {server_random.hex()}")
                                print(f"Data key:       {wlan_key.hex()}")
                            except Exception as e:
                                print(f"Warning: could not derive data key: {e}")
                        writer.write(packet)
                    # Subsequent advertisement frames are dropped.

                else:
                    # Auth, assoc, probe, deauth, etc. — keep all.
                    writer.write(packet)

            elif header.type == wlan.IEEE80211_FTYPE_DATA:
                if wlan_key is None:
                    # Key not yet known; pass through encrypted.
                    writer.write(packet)
                    continue

                # Decode the data frame.
                try:
                    data_frame = wlan.DataFrame()
                    data_frame.has_fcs = True
                    data_frame.decode(frame_data)
                except (ValueError, struct.error):
                    writer.write(packet)
                    continue

                # Decrypt if still protected after decode.
                if data_frame.protected:
                    try:
                        data_frame.decrypt(wlan_key)
                        decrypt_ok += 1
                    except ValueError:
                        # Integrity check failed — keep original encrypted frame.
                        decrypt_fail += 1
                        print(
                            f"  integrity check failed: input frame {input_frame}"
                            f"  t={packet.time:.6f}"
                            f"  {data_frame.source} → {data_frame.target}"
                        )
                        writer.write(packet)
                        continue
                else:
                    # Frame was already decrypted by the driver; strip the
                    # hardware FCS that decode() left in the payload.
                    data_frame.payload = data_frame.payload[:-4]

                # Re-encode the (possibly decrypted) frame and rewrap it.
                new_raw = rebuild_radiotap(radiotap, data_frame.encode())
                new_pkt = RadioTap(new_raw)
                new_pkt.time = packet.time
                writer.write(new_pkt)

            else:
                # Control frames and other types — keep as-is.
                writer.write(packet)

    print(f"\nTotal packets read:    {total}")
    print(f"Decrypted:             {decrypt_ok} data frames")
    print(f"Failed (integrity):    {decrypt_fail} data frames")
    print(f"Output written to:     {args.output}")


if __name__ == "__main__":
    main()
