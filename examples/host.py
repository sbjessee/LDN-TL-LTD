
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


async def process_events(network):
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
    async with ldn.create_network(param) as network:
        print("Network running. Press Enter to stop.")
        async with trio.open_nursery() as nursery:
            nursery.start_soon(process_events, network)
            await trio.to_thread.run_sync(sys.stdin.readline)
            nursery.cancel_scope.cancel()
    print("Network stopped.")


try:
    trio.run(main)
except KeyboardInterrupt:
    print("\nNetwork stopped.")
