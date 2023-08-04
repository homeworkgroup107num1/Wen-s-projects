from Prepare import *
import time
def is_zero_str(t):
    for i in t:
        if i != "0":
            return False
    return True

def SM2_enc(M, PB, n, h):#SM2加密
    M = remove_0b_at_beginning(M)
    point_G = Point(config.get_Gx(), config.get_Gy())
    klen = len(M)
    while True:
        #生成随机数k∈[1, n - 1]
        k = randint(1, n - 1)
        #计算椭圆曲线点C1=[k]G=(x1,y1)
        C1 = ECG_k_point(k, point_G)
        C1 = bytes_to_bits(point_to_bytes(C1))
        C1 = remove_0b_at_beginning(C1)
        #算椭圆曲线点S=[h]PB，若S是无穷远点，报错退出
        S = ECG_k_point(h, PB)
        if S == ECG_ele_zero():
            print("S是无穷远点。")
            return -1
        #算椭圆曲线点[k]PB=(x2,y2)
        x2 = ECG_k_point(k, PB).x
        y2 = ECG_k_point(k, PB).y
        x2 = bytes_to_bits(ele_to_bytes(x2))
        y2 = bytes_to_bits(ele_to_bytes(y2))
        x2 = remove_0b_at_beginning(x2)
        y2 = remove_0b_at_beginning(y2)
        #算t = KDF(x2∥y2, klen)，若t为全0比特串，则重算直到不全为零，跳出
        t = KDF(x2 + y2, klen)
        if is_zero_str(t):
            continue
        break
    C2 = bin(int(M, 2) ^ int(t, 2)) #算C2 = M ⊕ t
    C2 = remove_0b_at_beginning(C2)
    C2 = padding_0_to_length(C2, klen)
    #算C3 = Hash(x2 ∥ M ∥ y2)
    C3 = hash_function(x2 + M + y2)
    C3 = remove_0b_at_beginning(C3)
    return C1 + C2 + C3

#SM2解密
def sm2_dec(C, sk):
    c1_len = (2 * math.ceil(math.log2(q) / 8) + 1) * 8
    #从C中取出比特串C1
    C1 = '0b' + C[:c1_len]
    C2 = C[c1_len: len(C) - 256]
    C3 = C[len(C) - 256: len(C)]
    #将C1的数据类型转换为椭圆曲线上的点
    C1 = bytes_to_point(a, b, bits_to_bytes(C1))
    #算椭圆曲线点S=[h]C1，若S是无穷远点，则报错退出
    S = ECG_k_point(h, C1)
    if S == ECG_ele_zero():
        print("解密失败：S是无穷远点！！")
        return -1
    #计算[sk]C1=(x2,y2)
    X = ECG_k_point(sk, C1)
    x2 = bytes_to_bits(ele_to_bytes(X.x))
    y2 = bytes_to_bits(ele_to_bytes(X.y))
    x2 = remove_0b_at_beginning(x2)
    y2 = remove_0b_at_beginning(y2)
    #算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，则报错退出
    klen = len(C2)
    t = KDF(x2 + y2, klen)
    if is_zero_str(t):
        print("解密失败：t是全零比特串！")
        return -1
    #从C中取出比特串C2，计算M′ = C2 ⊕ t
    M_1 = bin(int(C2, 2) ^ int(t, 2))
    M_1 = remove_0b_at_beginning(M_1)
    #算u = Hash(x2 ∥ M′ ∥ y2)，从C中取出比特串C3，若u!=C3，则报错并退出
    u = hash_function(x2 + M_1 + y2).replace('0b', '')
    if u != C3:
        print("解密失败，u！=C3")
        return -1
    return M_1


if __name__ == '__main__':

    M = bin(int("aaacccbbbdd", 16))[2:]
    config.set_default_config()
    parameters = config.get_parameters()
    key = key_pair_generation(parameters)
    dB = key[0]  
    PB = key[1] 
    print("公钥为:\n", PB)
    print("私钥为:\n", dB)
    #初始化
    a = config.get_a()
    b = config.get_b()
    q = config.get_q()
    h = config.get_h()
    n = config.get_n()
    #加密
    start_time = time.time()
    C = SM2_enc(M, PB, n, h)
    end_time = time.time()
    print("\n加密密文为:\n", hex(int(C, 2)))
    print("加密时间为:", end_time - start_time, "s")
    #解密
    start_time = time.time()
    M_dec = sm2_dec(C, dB)
    end_time = time.time()
    print("\n解密为:", hex(int(M_dec, 2))[2:])
    print("原始明文为:", hex(int(M, 2))[2:])
    # 验证解密是否正确
    if M_dec == M:
        print("解密正确!\t解密时间为:", end_time - start_time, "s")
    else:
        print("解密错误。")

