#  /usr/bin/python3 CTF_DATA/CTF5/ctf5.py
import requests
import sys

BASE_URL = 'http://cbc-ctf.westeurope.azurecontainer.io:5000'
BLOCK_SIZE = 16

# Get ciphertext
print("[*] Getting ciphertext...", end=" ", flush=True)
response = requests.get(f'{BASE_URL}/')
start = response.text.find('id="challenge">')
end = response.text.find('</textarea>', start)
ciphertext_hex = response.text[start + len('id="challenge">'):end].strip()
ciphertext = bytes.fromhex(ciphertext_hex)

iv = ciphertext[:BLOCK_SIZE]
block1 = ciphertext[BLOCK_SIZE:2*BLOCK_SIZE]
block2 = ciphertext[2*BLOCK_SIZE:]
print("DONE")

def oracle(ct):
    try:
        r = requests.post(f'{BASE_URL}/oracle', json={"ciphertext_hex": ct.hex()}, timeout=10)
        return r.json().get("valid_padding", False)
    except:
        return False

# Decrypt block 1
print("[*] Decrypting block 1...")
intermediate = bytearray(BLOCK_SIZE)

for byte_index in range(BLOCK_SIZE - 1, -1, -1):
    padding_value = BLOCK_SIZE - byte_index
    modified_prev = bytearray(BLOCK_SIZE)
    
    for k in range(byte_index + 1, BLOCK_SIZE):
        modified_prev[k] = intermediate[k] ^ padding_value
    
    for guess in range(256):
        modified_prev[byte_index] = guess
        if oracle(bytes(modified_prev) + block1):
            intermediate[byte_index] = guess ^ padding_value
            p_byte = intermediate[byte_index] ^ iv[byte_index]
            ch = chr(p_byte) if 32 <= p_byte < 127 else '?'
            print(f"  [{byte_index+1:2d}] 0x{p_byte:02x} '{ch}'")
            break

plaintext1 = bytes(intermediate[i] ^ iv[i] for i in range(BLOCK_SIZE))

# Decrypt block 2
print("[*] Decrypting block 2...")
intermediate = bytearray(BLOCK_SIZE)

for byte_index in range(BLOCK_SIZE - 1, -1, -1):
    padding_value = BLOCK_SIZE - byte_index
    modified_prev = bytearray(BLOCK_SIZE)
    
    for k in range(byte_index + 1, BLOCK_SIZE):
        modified_prev[k] = intermediate[k] ^ padding_value
    
    for guess in range(256):
        modified_prev[byte_index] = guess
        if oracle(bytes(modified_prev) + block2):
            intermediate[byte_index] = guess ^ padding_value
            p_byte = intermediate[byte_index] ^ block1[byte_index]
            ch = chr(p_byte) if 32 <= p_byte < 127 else '?'
            print(f"  [{byte_index+1:2d}] 0x{p_byte:02x} '{ch}'")
            break

plaintext2 = bytes(intermediate[i] ^ block1[i] for i in range(BLOCK_SIZE))

# Remove padding
plaintext = plaintext1 + plaintext2
padding_len = plaintext[-1]

print()
print(f"[*] Last byte (padding indicator): 0x{padding_len:02x} ({padding_len})")

# Validate padding
if 0 < padding_len <= BLOCK_SIZE:
    # Check if all padding bytes are the same
    all_padding = all(plaintext[-(i+1)] == padding_len for i in range(padding_len))
    if all_padding:
        plaintext = plaintext[:-padding_len]
        print(f"[+] Valid PKCS7 padding of {padding_len} bytes removed")
    else:
        print("[!] Invalid PKCS7 padding")
else:
    print("[!] Invalid padding length")

print()
print("=" * 60)
print(plaintext.decode('utf-8', errors='replace'))
print("=" * 60)

# Verify
print("[*] Verifying...")
flag = plaintext.decode('utf-8', errors='replace').strip()
try:
    r = requests.post(f'{BASE_URL}/check_flag', json={"flag": flag}, timeout=10)
    result = r.json()
    if result.get("correct"):
        print("[✓] FLAG CORRECT!")
    else:
        print(f"[!] Incorrect: {result.get('message')}")
except Exception as e:
    print(f"[!] Error: {e}")
