
# This script creates a network for Super Mario Maker 2.

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import ldn
import trio
import struct
import random
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")


NICKNAME = "Hello!"


class Stream:
    def __init__(self):
        self.data = b""
    
    def pad(self, size): self.data += bytes(size)
    
    def u8(self, value): self.data += bytes([value])
    def u16(self, value): self.data += struct.pack("<H", value)
    def u32(self, value): self.data += struct.pack("<I", value)
    def u64(self, value): self.data += struct.pack("<Q", value)
    
    def wchars(self, text):
        for char in text:
            self.u16(ord(char))


def make_application_data():
    # Build the pia header
    stream = Stream()
    stream.u8(1) # Version
    # stream.u32(random.randint(0, 0xFFFFFFFF)) # Session id
    # stream.u32(0) # CRC-32
    # stream.u8(5) # System communication version
    # stream.u8(24) # Header size
    # stream.pad(2)
    # stream.u32(random.randint(0, 0xFFFFFFFF)) # Session param
    # stream.pad(8)
    
    # # SMM2 header
    # stream.u64(random.randint(0, 0xFFFFFFFFFFFFFFFF)) # Network service account id
    # stream.wchars(NICKNAME + "\0" * (11 - len(NICKNAME)))
    # stream.pad(2)
    
    # # Mii info
    # stream.pad(88) # Simply set everything to 0 for now
    
    # # Unknown
    # stream.pad(24)
    return stream.data


async def handle_tcp_stream(participant, stream):
    import pathlib, time
    buf = bytearray()
    async with stream:
        async for chunk in stream:
            buf.extend(chunk)
            # Process all complete CLTP SUPPLY messages buffered so far
            while True:
                if not buf.startswith(b'CLTP SUPPLY '):
                    break
                null_idx = buf.find(0)
                if null_idx == -1:
                    break  # header not yet complete
                try:
                    header = buf[:null_idx].decode('ascii')
                    hex_str = header.split(' ')[2]   # "0x26b4"
                    total_len = int(hex_str, 16)
                    data_len = total_len - 1
                except (ValueError, IndexError):
                    break
                msg_end = null_idx + 1 + data_len
                if len(buf) < msg_end:
                    break  # payload not yet complete
                payload = bytes(buf[null_idx + 1:msg_end])
                buf = buf[msg_end:]
                out = pathlib.Path(f"cltp_{int(time.time())}.bin")
                out.write_bytes(payload)
                print(f"CLTP SUPPLY {data_len} bytes from {participant.mac_address} → {out}")
                await stream.send(b'CLTP ACCEPT\x00')


async def process_events(network, nursery):
    while True:
        event = await network.next_event()
        if event is not None:
            print("Received event:", type(event).__name__)
        if isinstance(event, ldn.JoinEvent):
            participant = event.participant
            print("%s joined the network (%s / %s)" %(participant.name.decode(), participant.mac_address, participant.ip_address))
        elif isinstance(event, ldn.LeaveEvent):
            participant = event.participant
            print("%s left the network (%s / %s)" %(participant.name.decode(), participant.mac_address, participant.ip_address))
        elif isinstance(event, ldn.TCPStreamEvent):
            nursery.start_soon(handle_tcp_stream, event.participant, event.stream)


async def main():
    print("Creating network.")
    param = ldn.CreateNetworkParam()
    param.keys = ldn.load_keys("~/.switch/prod.keys")
    param.local_communication_id = 0x010051F0207B2000
    param.scene_id = 1
    param.max_participants = 2
    param.application_data = make_application_data()
    param.name = NICKNAME.encode()
    param.app_version = 2
    param.password = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    param.channel = 1
    param.phyname = "phy1"
    param.phyname_monitor = "phy1"
    async with ldn.create_network(param) as network:
        print("Network running. Press Enter to stop.")
        async with trio.open_nursery() as nursery:
            nursery.start_soon(process_events, network, nursery)
            await trio.to_thread.run_sync(sys.stdin.readline)
            nursery.cancel_scope.cancel()
    print("Network stopped.")


try:
    trio.run(main)
except KeyboardInterrupt:
    print("\nNetwork stopped.")
