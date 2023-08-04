import Cipolla
from Prepare import *
import random
import time
#ECDSA签名
def ECDSA_sig(d, m):
    k = random.randint(1, n - 1)
    kG = ECG_k_point(k, point_G)
    #求r和s
    r = ele_to_int(kG.x)
    s = ((config.inverse(k, n)) * (int(hash_sha3_256(m), 2) + d * r)) % n
    return r, s
def ECDSA_ver(r, s, P, m):#验证
    e = int(hash_sha3_256(m), 2)
    w = config.inverse(s, n)
    #计算(r',s')
    r_ = ECG_k_point((w * e) % n, point_G)
    s_ = ECG_k_point((w * r) % n, P)
    r_s_ = ECG_ele_add(r_, s_)
    r_ver = ele_to_int(r_s_.x)
    if r == r_ver:#验证
        return True
    else:
        return False
#从签名获取公钥
def ECDSA_deduce_pk_sig(m, r, s):
    e = int(hash_sha3_256(m), 2)
    s_inverse = config.inverse(s, n)
    #计算r对应的域元素，即带入椭圆曲线方程x^3+ax+b
    r_ele = (pow(r, 3) % q + (a * r) % q + b) % q
    #解集合y，根据公钥点r_ele值通过Cipolla算法求解y值，二次同余方程两个解
    P_possible = [Cipolla.Cipolla(r_ele, q), q - Cipolla.Cipolla(r_ele, q)]
    #将字节串bin(r)转为域元素，输入的是模数n和字节串S
    R = bytes_to_ele(n, bits_to_bytes(bin(r)))
    #猜测的公钥集合
    P_Guess = []
    for p_possible in P_possible:
        #将字节串bin(p_possible)转为域元素，输入的是模数n和字节串S
        p_possible = bytes_to_ele(n, bits_to_bytes(bin(p_possible)))
        #求解r*s_inverse*P(Point_r_s_inverse_P)的椭圆曲线上的点
        Point_r_s_inverse_P = ECG_ele_add(Point(R, p_possible),
                                          ECG_k_point(((n - 1) * e * s_inverse) % n, point_G))
        #求解可能的公钥P_g=[(r*s_inverse)^(-1)]Point_r_w_P
        P_g = ECG_k_point(config.inverse(r * s_inverse, n), Point_r_s_inverse_P)
        P_Guess.append(P_g)
    #返回可能的公钥集合
    return P_Guess

if __name__ == "__main__":
    #初始化
    config.set_default_config()
    point_G = Point(config.get_Gx(), config.get_Gy())
    q = config.get_q()
    a = config.get_a()
    b = config.get_b()
    n = config.get_n()
    h = config.get_h()
    m = "Ge Mengyun"
    #生成公私钥对
    d = randint(1, n - 1)
    P = ECG_k_point(d, point_G) 
    print("私钥d:", d, "\n公钥P:", P)
    #生成签名
    start_time = time.time()
    r, s = ECDSA_sig(d, m)
    end_time = time.time()
    print("\n签名成功！\nr:", r, "\ns:", s)
    print("生成签名所用时间为:", end_time - start_time, "s")
    #验证签名
    start_time = time.time()
    if ECDSA_ver(r, s, P, m):
        end_time = time.time()
        print("\n验证通过！")
        print("验证签名所用时间为:", end_time - start_time, "s")
    #由签名值恢复公钥
    start_time = time.time()
    P_guess = ECDSA_deduce_pk_sig(m, r, s)
    if P.x == P_guess[0].x and P.y == P_guess[0].y:
        end_time = time.time()
        print("\n公钥恢复成功！\n恢复的公钥为:", P_guess[0])
    elif P.x == P_guess[1].x and P.y == P_guess[1].y:
        end_time = time.time()
        print("\n公钥恢复成功！\n恢复的公钥为:", P_guess[1])
    print("恢复公钥所用时间为:", end_time - start_time, "s")

