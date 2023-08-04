from Prepare import *
import time
#SM2签名
def SM2_sig(ID, dA, PA):
    ZA = get_Z(ID, PA)
    #置M1=ZA ∥ M
    M1 = ZA + M
    #算e = Hv(M1)
    e = bytes_to_int(bits_to_bytes(hash_function(M1)))
    while True:
        #产生随机数k ∈[1,n-1]
        k = randint(1, n - 1)
        #算椭圆曲线点(x1,y1)=[k]G
        X = ECG_k_point(k, point_g)
        #将x1的数据类型转换为整数
        x1 = bytes_to_int(ele_to_bytes(X.x))
        #算r=(e+x1) mod n，如果r=0或r+k=n，重新选择k
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        #算s = ((1 + dA)−1 ·(k−r·dA)) mod n，若s=0则重新选择k
        s = (config.inverse(1 + dA, n) * (k - r * dA)) % n
        if s == 0:
            continue
        break
    return r, s
#SM2签名验证
def SM2_ver(IDA, r, s, PA):
    #验证r,s∈[1,n-1]是否成立，若不成立，验证不通过
    if r < 0 or r > n:
        print("r验证不通过！")
        return -1
    if s < 0 or s > n:
        print("s验证不通过！")
        return -1
    ZA = get_Z(IDA, PA)
    #置M1=ZA ∥ M
    M1 = ZA + M
    #算e = Hv(M1)，并将e的数据类型转换为整数
    e = bytes_to_int(bits_to_bytes(hash_function(M1)))
    #算t=(r + s)mod n，若t = 0，则验证不通过
    t = (r + s) % n
    if t == 0:
        return -1
    #算椭圆曲线点(x1,y1)=[s']G+[t]PA
    X = ECG_ele_add(ECG_k_point(s, point_g), ECG_k_point(t, PA))
    #把x1数据类型转换为整数，算R=(e+x1)mod n,检验R=r是否成立
    x1 = bytes_to_int(ele_to_bytes(X.x))
    R = (e + x1) % n
    if R == r:
        return 1
    else:
        return -1


if __name__ == '__main__':
    #初始化签名参数
    config.set_default_config()
    parameters = config.get_parameters()
    point_g = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()
    ID = "GeMeng yun@qq.com"
    M = "GeMeng yun"
    #生成公私钥
    sk = random.randint(1, n - 2)  
    pk = ECG_k_point(sk, point_g)  
    print("私钥:", sk)
    print("公钥:", pk)
    #签名
    start_time = time.time()
    r, s = SM2_sig(ID, sk, pk)
    end_time = time.time()
    print("\n成功生成签名，所用时间为:", end_time - start_time, "s")
    print("r:", r)
    print("s:", s)
    # 验证
    print("\n对签名进行验证")
    start_time = time.time()
    if SM2_ver(ID, r, s, pk):
        end_time = time.time()
        print("验证通过，所用时间为:", end_time - start_time, "s")

