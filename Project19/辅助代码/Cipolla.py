import random
class C():
    def __init__(self, a, b):
        self.a = a
        self.b = b
def mod(a, p):
    return (a % p + p) % p
def Camul(a, n, p, i1, i2):
    c = a ** 2 - n
    t = C((i1.a * i2.a + i1.b * i2.b % p * c) % p, (i1.b * i2.a + i1.a * i2.b) % p)
    return t

def Cqsm(a, n, p, x, y):
    z = C(1, 0)
    while y:
        if y & 1:
            z = Camul(a, n, p, z, x)
        x = Camul(a, n, p, x, x)
        y >>= 1
    return z

def fast_pow(a, b, c):
    res = 1
    a = a % c
    while b != 0:
        if b & 1:
            res= (res * a) % c
        b >>= 1
        a = (a * a) % c
    return res

def legendre(a, p):
    return fast_pow(mod(a, p), (p - 1) // 2, p)

def Cipolla(n, p):
    if n % p == 0:
        return 0
    if legendre(n, p) != 1:
        return -1
    while True:
        a = random.randint(0, p - 1) % p
        w = (a * a - n + p) % p
        if legendre(a * a - n, p) == p - 1:
            break
    u = C(a, 1)
    u = Cqsm(a, n, p, u, (p + 1) // 2)
    return mod(u.a, p)

