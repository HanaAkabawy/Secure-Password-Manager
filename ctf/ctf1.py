import base64

encoded = "Q01QTntwYzRwX2hpZGQzbl9pbl9sM2dpN183cjRmZmljfQ=="

flag = base64.b64decode(encoded).decode()
print("Flag:", flag)
