# from gmpy2 import isqrt
# import gmpy2

# with open('CTF_DATA/CTF6/challenge.txt') as f:
#     lines = f.readlines()
#     n = int(lines[1].split('=')[1].strip())
#     e = int(lines[2].split('=')[1].strip())
#     c = int(lines[3].split('=')[1].strip())


# def factorize(n_int):
#     n = gmpy2.mpz(n_int) 
#     a = isqrt(n)
    
#     if a * a == n:
#         return int(a), int(a)

#     while True:
#         a += 1
#         bsq = a*a - n
#         b, is_exact = gmpy2.iroot(bsq, 2)
#         if is_exact:
#             break

#     p = a + b
#     q = a - b
#     return int(p), int(q)

# p, q = factorize(n)
#p=11 293118 400133 136869 , q=4 056733 029881 663634 (using https://www.alpertron.com.ar/ECM.HTM)

n = 143991606075158483660871570161405209117
e = 65537
c = 34130411904650996210426832018051041635


p = 11607228028223627369
q = 12405339649142310293

if p * q != n:
    print("These factors do not match the modulus n")


phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)

print(f"d: {d}")
print(f"m: {m}")

try:
    hex_msg = hex(m)[2:]
    if len(hex_msg) % 2 != 0: hex_msg = '0' + hex_msg
    flag = bytes.fromhex(hex_msg).decode('utf-8')
    print(f"Flag: {flag}")
except:
    print("Did not work")