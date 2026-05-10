
# Reads a monitor-mode pcap from an LDN spoofing session where the driver
# has already decrypted data frames but left the Protected bit set in the
# MAC frame_control field. Re-encodes those frames with the bit cleared so
# Wireshark can dissect them correctly. All other frames pass through unchanged.

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import argparse
import struct
from ldn import wlan

from scapy.all import PcapReader, PcapWriter
from scapy.layers.dot11 import RadioTap


RADIOTAP_FLAG_FCS = 0x10
PROTECTED_BIT = 0x40  # bit 6 of the FC flags byte


def rebuild_radiotap(original: wlan.RadiotapFrame, dot11_data: bytes) -> bytes:
    rt = wlan.RadiotapFrame(dot11_data)
    rt.mactime = original.mactime
    rt.rate = original.rate
    rt.frequency = original.frequency
    rt.channel_flags = original.channel_flags
    if original.flags is not None:
        rt.flags = original.flags & ~RADIOTAP_FLAG_FCS
    return rt.encode()


def main():
    parser = argparse.ArgumentParser(
        description="Clear the Protected flag on driver-decrypted LDN data frames"
    )
    parser.add_argument("input", help="Input pcapng/pcap file")
    parser.add_argument("output", help="Output pcap file")
    args = parser.parse_args()

    fixed = 0
    total = 0

    with PcapReader(args.input) as reader, \
         PcapWriter(args.output, linktype=127, sync=True) as writer:

        for packet in reader:
            total += 1
            raw = bytes(packet)

            try:
                radiotap = wlan.RadiotapFrame()
                radiotap.decode(raw)
                frame_data = radiotap.data
            except Exception:
                writer.write(packet)
                continue

            try:
                header = wlan.MACHeader()
                header.decode(frame_data)
            except Exception:
                writer.write(packet)
                continue

            # Only touch data frames that have the Protected bit set.
            if header.type != wlan.IEEE80211_FTYPE_DATA or \
               not (header.flags & PROTECTED_BIT):
                writer.write(packet)
                continue

            try:
                frame = wlan.DataFrame()
                frame.decode(frame_data)
            except (ValueError, struct.error):
                writer.write(packet)
                continue

            # decode() clears frame.protected when the payload begins with the
            # SNAP header (\xAA\xAA\x03), which means the driver already
            # decrypted the frame without clearing the Protected bit itself.
            # Re-encoding produces a frame with the correct flag and without
            # the CCMP header, which Wireshark can then dissect normally.
            if not frame.protected:
                new_raw = rebuild_radiotap(radiotap, frame.encode())
                new_pkt = RadioTap(new_raw)
                new_pkt.time = packet.time
                writer.write(new_pkt)
                fixed += 1
            else:
                writer.write(packet)

    print(f"Total packets read:    {total}")
    print(f"Protected flag fixed:  {fixed} data frames")
    print(f"Output written to:     {args.output}")


if __name__ == "__main__":
    main()
