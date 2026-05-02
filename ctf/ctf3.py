# with open("CTF_DATA/CTF3/shifted.txt", "r") as f:
#     nums = list(map(int, f.read().split()))

# def is_acceptable(n):
#     return 32 <= n <= 126

# def is_valid(n):
#     return chr(n) if is_acceptable(n) else f"[{n}]"


# for shift in range(1, 8):
#     result = ""
#     for n in nums:
#         curr = n >> shift
#         result += is_valid(curr)
#     print(f"Right shift {shift}: {result}")

# print("\n")
# for shift in range(1, 8):
#     result = ""
#     for n in nums:
#         curr = (n << shift) & 0xFF
#         result += is_valid(curr)
#     print(f"Left shift {shift}: {result}")

with open("CTF_DATA/CTF3/shifted.txt", "r") as f:
    nums = list(map(int, f.read().split()))

def is_acceptable(n):
    return 32 <= n <= 126

flag = ""
for n in nums:
    curr = n >> 1
    if is_acceptable(curr):
        flag += chr(curr)
    else:
        flag += f"[{curr}]"

print(f"Flag: {flag}")