
# This script creates a network for Super Mario Maker 2.

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import ldn
import trio
import struct
import random
import logging
import pathlib

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


CLTP_CHUNK_SIZE = 536
CLTP_SEND_DELAY = 3.0


def _parse_cltp_supply(buf: bytearray) -> tuple[int, int] | None:
    """Return (null_idx, data_len) if a complete CLTP SUPPLY header is present, else None."""
    if not buf.startswith(b'CLTP SUPPLY '):
        return None
    null_idx = buf.find(0)
    if null_idx == -1:
        return None
    try:
        hex_str = buf[12:null_idx].decode('ascii')  # skip "CLTP SUPPLY "
        total_len = int(hex_str, 16)
        return null_idx, total_len - 1
    except (ValueError, UnicodeDecodeError):
        return None


async def handle_send_stream(participant, send_stream, filepath, join_time):
    """Outgoing connection (our 49*** → their 5002): send data stream, read CLTP ACCEPT."""
    async with send_stream:
        if filepath is not None:
            remaining = CLTP_SEND_DELAY - (trio.current_time() - join_time)
            print(f"Will send {filepath!r} to {participant.mac_address} after {remaining:.0f}s.")
            if remaining > 0:
                await trio.sleep(remaining)

            data = pathlib.Path(filepath).read_bytes()
            header = f'CLTP SUPPLY 0x{len(data) + 1:x}\x00'.encode('ascii')
            await send_stream.send(header, push=True)
            # await send_stream.wait_all_acked()

            chunks = [data[i:i + CLTP_CHUNK_SIZE] for i in range(0, len(data), CLTP_CHUNK_SIZE)]
            for idx, chunk in enumerate(chunks):
                await send_stream.wait_window(3)
                is_last = idx == len(chunks) - 1
                await send_stream.send(chunk + b'\x00' if is_last else chunk, push=is_last)
            await send_stream.wait_all_acked()

            resp_buf = bytearray()
            while b'\x00' not in resp_buf:
                resp_buf.extend(await send_stream.receive())
            null_idx = resp_buf.find(0)
            response = resp_buf[:null_idx].decode('ascii', errors='replace')
            if response == 'CLTP ACCEPT':
                print(f"{participant.mac_address} accepted the transfer.")
            elif response == 'CLTP REJECT':
                print(f"{participant.mac_address} rejected the transfer.")
            else:
                print(f"Unexpected CLTP response from {participant.mac_address}: {response!r}")
        async for _ in send_stream:
            pass


async def handle_recv_stream(participant, recv_stream):
    """Incoming connection (their 49*** → our 5002): receive their data stream, send CLTP ACCEPT."""
    import time as time_mod
    buf = bytearray()
    async with recv_stream:
        async for chunk in recv_stream:
            buf.extend(chunk)
            while True:
                parsed = _parse_cltp_supply(buf)
                if parsed is None:
                    break
                null_idx, data_len = parsed
                msg_end = null_idx + 1 + data_len
                if len(buf) < msg_end:
                    break
                payload = bytes(buf[null_idx + 1:msg_end])
                buf = buf[msg_end:]
                if len(payload) != data_len:
                    print(f"WARNING: CLTP size mismatch from {participant.mac_address}: advertised {data_len}, received {len(payload)}")
                out = pathlib.Path(f"cltp_{int(time_mod.time())}.bin")
                out.write_bytes(payload)
                print(f"CLTP SUPPLY {data_len} bytes from {participant.mac_address} → {out}")
                await recv_stream.send(b'CLTP ACCEPT\x00')


async def process_events(network, nursery, filepath):
    join_times: dict[str, float] = {}
    while True:
        event = await network.next_event()
        if event is not None:
            print("Received event:", type(event).__name__)
        if isinstance(event, ldn.JoinEvent):
            participant = event.participant
            join_times[str(participant.mac_address)] = trio.current_time()
            print("%s joined the network (%s / %s)" %(participant.name.decode(), participant.mac_address, participant.ip_address))
        elif isinstance(event, ldn.LeaveEvent):
            participant = event.participant
            join_times.pop(str(participant.mac_address), None)
            print("%s left the network (%s / %s)" %(participant.name.decode(), participant.mac_address, participant.ip_address))
        elif isinstance(event, ldn.TCPStreamEvent):
            join_time = join_times.get(str(event.participant.mac_address), trio.current_time())
            nursery.start_soon(handle_send_stream, event.participant, event.send_stream, filepath, join_time)
            nursery.start_soon(handle_recv_stream, event.participant, event.recv_stream)


async def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else None
    if filepath is not None:
        print(f"Will send {filepath!r} to participant after {CLTP_SEND_DELAY:.0f}s.")

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
            nursery.start_soon(process_events, network, nursery, filepath)
            await trio.to_thread.run_sync(sys.stdin.readline)
            nursery.cancel_scope.cancel()
    print("Network stopped.")


try:
    trio.run(main)
except KeyboardInterrupt:
    print("\nNetwork stopped.")
