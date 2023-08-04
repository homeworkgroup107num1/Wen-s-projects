import time
import random
from Prepare import *

def Satoshi_sign(d, m):#生成正确的Satoshi签名
    k = randint(1, n - 1)
    kG = ECG_k_point(k, point_G)
    #求e,r,s
    r = ele_to_int(kG.x)
    e = int(hash_sha3_256(m), 2)
    s = ((config.inverse(k, n)) * (e + d * r)) % n
    return e, r, s
#伪造Satoshi签名
def pretend_Satoshi_sig(G, P):
    #随机选择u、v
    u = randint(1, n - 1)
    v = randint(1, n - 1)
    #计算伪造签名R'值
    x_forge = ECG_k_point(u, G)
    y_forge = ECG_k_point(v, P)
    R_forge = ECG_ele_add(x_forge, y_forge)
    #r'=R'.x
    r_forge = R_forge.x
    #e'=r'*u*v^(-1)mod n
    e_forge = (u * r_forge * config.inverse(v, n)) % n
    #s'=r'*v^(-1)mod n
    s_forge = (r_forge * config.inverse(v, n)) % n

    return e_forge, r_forge, s_forge
#据已有签名对伪造的签名进行验证
def Satoshi_verify(e_real, r_real, s_real, G, P):
    s_inverse = config.inverse(s_real, n)
    #生成R'=(r',s')
    r_ver = ECG_k_point((e_real * s_inverse) % n, G)
    s_ver = ECG_k_point((r_real * s_inverse) % n, P)
    R_ver = ECG_ele_add(r_ver, s_ver)
    if R_ver.x % n == r_real:
        return True
    else:
        return False

if __name__ == '__main__':
    #初始化
    config.set_default_config()
    parameters = config.get_parameters()
    point_G = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()
    m = "GeMeng yun"
    #生成公私钥对
    sk = random.randint(1, n - 1)  
    pk = ECG_k_point(sk, point_G)  
    print("公钥为:", pk)
    print("私钥为:", sk)
    #生成正确的Satoshi签名
    start_time = time.time()
    e_real, r_real, s_real = Satoshi_sign(sk, m)
    end_time = time.time()
    print("\n签名成功:\ne:", e_real, "\nr:", r_real, "\ns:", s_real)
    print("签名所用时间为:", end_time - start_time, "s")
    #伪造新签名
    start_time = time.time()
    e_forge, r_forge, s_forge = pretend_Satoshi_sig(point_G, pk)
    end_time = time.time()
    print("\n伪造签名成功:\ne':", e_forge, "\nr':", r_forge, "\ns':", s_forge)
    print("伪造签名所用时间为:", end_time - start_time, "s")
    #使用已有的签名对伪造的签名验证
    start_time = time.time()
    if Satoshi_verify(e_real, r_real, s_real, point_G, pk):
        end_time = time.time()
        print("\n验证伪造的签名成功，\n验证签名所用时间为:", end_time - start_time, "s")

