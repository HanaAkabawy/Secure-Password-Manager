import secrets
import json
import os
#miller-rabin algorith, I check edge cases at first like n<2 (as none of these are prime an dinclude negatives), 
#n%2 as even numbers cannot be prime and n==3 as to generate a for the check
#we need to get a number from 2 to n-2 for a, so n==3 would be from 2 to 1 which is just not a valid range
#https://www.youtube.com/watch?v=qdylJqXCDGs
def checkprime_miller(q):
    if(q==2 or q==3):
        return True
    elif(q<2 or q%2 ==0):
        return False
    r=1
    m=q-1
    while(m%2==0):
        m=m//2
        r+=1
    for i in range(40):
        a = secrets.randbelow(q - 4) + 2 
        b = pow(a,m,q)
        if(b==1 or b==q-1): #if b is 1 or -1 mod q, we continue as it could be prime, q-1 is the equivilant of -1modq shown in the vid above 
            continue
        for j in range(r-1):
            b = pow(b,2,q)
            if(b==q-1): 
                break
        else:
            return False
    return True

#generate prime using secrets library (TA said it was allowed). We check q and 2q+1 to ensure they're safe primes.
#safe prime assists with generation of primitive 
#we add 2^bits-1 whcih is the smallest 10 bit number to ensure the generated number is a 10 bit number.
#We use bitwise OR with 1 to ensure the number is odd
def generateprime(bits):
    q= (secrets.randbelow(2**(bits-1)) +2**(bits-1))|1 
    while not (checkprime_miller(q) and checkprime_miller((2*q+1))):
        q = (secrets.randbelow(2**(bits-1)) +2**(bits-1))|1
    return 2*q +1
#calculate primitive root
def generatea(p):
    q=(p-1)//2
    a=secrets.randbelow(p-4)+2
    while (pow(a,2,p) == 1 or pow(a,q,p) == 1 ):
        a = secrets.randbelow(p-2)+2
    return a
def generatekeypair(q, a):
    priv=secrets.randbelow(q-4)+2
    pub = pow(a,priv,q)
    return (pub,priv) 

def init():
    q = generateprime(1024)
    a = generatea(q) 
    pub,priv = generatekeypair(q,a)
    return (q,a,pub,priv)
if __name__ =="__main__":
    username = input("Enter your username: ")

    if os.path.exists(f"{username}_private.json"):
        print("User's private key already exists")
        exit()
    if os.path.exists(f"{username}_public.json"):
        print("User's public key already exists")
        exit()
    print("Generating keys")
    q,a,pub,priv= init()
    print("Keys generated")
    privatekey = {
        "Prime":q,
        "Primitive Root":a,
        "privateKey":priv 
    }
    publickey = {
        "Prime":q,
        "Primitive Root":a,
        "publicKey":pub 
    }

    with open(f"{username}_private.json","w") as f:
        json.dump(privatekey, f, indent=4)

    with open(f"{username}_public.json","w") as f:
        json.dump(publickey, f, indent=4)