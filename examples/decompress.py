import pathlib
import sys
import compression.zstd as zstd

ZSTD_MAGIC = bytes([0x28, 0xB5, 0x2F, 0xFD])


def parse_frames(data: bytes) -> list[tuple[int, bytes]]:
    frames = []
    off = 0
    while off < len(data):
        idx = data.find(ZSTD_MAGIC, off)
        if idx == -1:
            break
        try:
            size = zstd.get_frame_size(data[idx:])
            frames.append((idx, data[idx:idx + size]))
            off = idx + size
        except zstd.ZstdError:
            off = idx + 4
    return frames


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: decompress.py <file>")
        sys.exit(1)

    input_path = pathlib.Path(sys.argv[1])
    data = input_path.read_bytes()

    frames = parse_frames(data)
    print(f"Found {len(frames)} zstd frame(s)")

    decompressed = bytearray()
    for i, (offset, frame_data) in enumerate(frames):
        dec = zstd.decompress(frame_data)
        print(f"  Frame {i}: offset={offset}, compressed={len(frame_data)} B, decompressed={len(dec)} B")
        decompressed.extend(dec)

    output_path = input_path.with_stem(input_path.stem + "_decompressed")
    output_path.write_bytes(decompressed)
    print(f"Wrote {len(decompressed)} bytes → {output_path}")


main()
