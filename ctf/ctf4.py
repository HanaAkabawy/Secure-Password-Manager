import cv2
import numpy as np
import re


def solve(imagePath):

    image = cv2.imread(imagePath, cv2.IMREAD_UNCHANGED)
    print("Image loaded successfully.")

    pixels = image.flatten()
    LSB = pixels & 1
    bytes = np.packbits(LSB)

    extractedText = bytes.tobytes().decode("ascii", errors="ignore")

    print("Scanning extracted data for flags...")
    match = re.search(r"(CMPN\{.*?\}|FLAG\{.*?\})", extractedText)

    if match:
        return f"\nFlag found: {match.group(0)}"


print(solve("CTF_DATA/CTF4/stego.png"))
