import json
from datetime import datetime


def save_packets_to_file(packets, filename):
    try:
        serializable_packets = []
        for packet in packets:
            serializable_packet = {}
            for key, value in packet.items():
                if key != 'raw':
                    serializable_packet[key] = value
            serializable_packets.append(serializable_packet)

        with open(filename, 'w') as f:
            json.dump(serializable_packets, f, indent=2, default=str)

        return True
    except Exception as e:
        print(f"Kaydetme hatası: {e}")
        return False


def load_packets_from_file(filename):
    try:
        with open(filename, 'r') as f:
            packets = json.load(f)
        return packets
    except Exception as e:
        print(f"Yükleme hatası: {e}")
        return []


def format_bytes(bytes_value):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
