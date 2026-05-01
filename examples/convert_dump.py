import re
from scapy.all import Dot11, wrpcap

def clean_and_convert(input_file, output_file):
    packets = []
    current_packet_hex = ""
    
    # Regex to identify lines that are strictly hex (allowing for spaces)
    hex_line_pattern = re.compile(r'^[0-9A-Fa-f\s]+$')

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            # If we hit a new target header, process the previous packet buffer
            if line.startswith(">>>") or not line:
                if current_packet_hex:
                    # Convert hex string to bytes
                    raw_bytes = bytes.fromhex(current_packet_hex.replace(" ", ""))
                    # Wrap in a Dot11 object so Scapy knows the layer type
                    packets.append(Dot11(raw_bytes))
                    current_packet_hex = ""
                continue
            
            # If the line looks like hex data, append it to the current buffer
            if hex_line_pattern.match(line):
                current_packet_hex += line

        # Catch the last packet in the file
        if current_packet_hex:
            raw_bytes = bytes.fromhex(current_packet_hex.replace(" ", ""))
            packets.append(Dot11(raw_bytes))

    if packets:
        # Save to PCAP. Linktype 105 is standard for IEEE 802.11
        wrpcap(output_file, packets)
        print(f"Successfully converted {len(packets)} packets to {output_file}")
    else:
        print("No valid hex packets found in the file.")

if __name__ == "__main__":
    # Change these filenames as needed
    clean_and_convert("casoh.txt", "nintendo_scan.pcap")