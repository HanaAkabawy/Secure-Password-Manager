from PIL import Image
import sys

STEGO_PATH = "CTF_DATA/CTF4/stego.png"

def extract_lsb_stream(path, channels=("R", "G", "B"), bit_order="msb"):
    img = Image.open(path).convert("RGBA")
    pixels = list(img.getdata())
    bits = []
    channel_index = {"R": 0, "G": 1, "B": 2, "A": 3}
    for px in pixels:
        for ch in channels:
            bits.append(px[channel_index[ch]] & 1)
    return bits

def bits_to_bytes(bits, bit_order="msb"):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b = 0
        if bit_order == "msb":
            for j in range(8):
                b = (b << 1) | bits[i + j]
        else:
            for j in range(8):
                b |= bits[i + j] << j
        out.append(b)
    return bytes(out)

def find_flag(data, max_preview=50000):
    for marker in (b"CMPN{", b"FLAG{"):
        idx = data.find(marker)
        if idx != -1:
            end = data.find(b"}", idx)
            if end != -1:
                return data[idx:end+1].decode("ascii", errors="replace")
    return None

def main():
    try:
        img = Image.open(STEGO_PATH)
        print(f"Image Mode: {img.mode}")
    except Exception as e:
        print(f"Error opening image: {e}")
        return

    permutations = [
        ("R", "G", "B"),
        ("R", "G", "B", "A"),
        ("R",), ("G",), ("B",), ("A",),
        ("B", "G", "R"),
        ("B", "G", "R", "A")
    ]
    for channels in permutations:
        for bit_order in ("msb", "lsb"):
            bits = extract_lsb_stream(STEGO_PATH, channels, bit_order)
            data = bits_to_bytes(bits, bit_order)
            flag = find_flag(data)
            if flag:
                print(f"FOUND with channels={channels}, bit_order={bit_order}: {flag}")
                return
    print("No flag found with simple permutations.")

if __name__ == "__main__":
    main()

