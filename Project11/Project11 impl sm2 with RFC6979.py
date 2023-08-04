from Prepare import *
import time

#长度为256bit
def RFC6979_gen_k(key, m):
    # 1、h1 = H(m)
    h1 = hash_sha3_256(m)
    # 2、V = 0x01 0x01 0x01 ... 0x01
    V = "00000001" * 32
    # 3、K = 0x00 0x00 0x00 ... 0x00
    K = "00000000" * 32
    key_no0b = remove_0b_at_beginning(bin(key))
    key_pad_zero = padzeore_to_len(key_no0b, 256)
    # 4、K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    K = HMAC_K(K, V + "00000000" + key_pad_zero + h1)
    # 5、V = HMAC_K(V)
    V = HMAC_K(K, V)
    # 6、K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    K = HMAC_K(K, V + "00000001" + key_pad_zero + h1)
    # 7、V = HMAC_K(V)
    V = HMAC_K(K, V)

    while True:
        T = ""
        while len(T) < 256:
            V = HMAC_K(K, V)
            T = T + V
        k = int(T, 2)
        #若8、k∈[1,q-1]则成功
        #是否满足r!=0、r+s!=n于签名算法中判定

        if 0 < k < q:
            print("\n找到合适的随机数k。\n生成的随机数为:", k)
            break
        #9、K = HMAC_K(V || 0x00)，重新生成T
        K = HMAC_K(K, V + "00000000")
        V = HMAC_K(K, V)
    return k


#SM2生成签名
def SM2_sig(IDA, dA, PA):
    ZA = get_Z(IDA, PA)
    #令M1=ZA ∥ M
    M1 = ZA + M
    #计算e = Hv(M1)，同时进行类型转换
    e = bytes_to_int(bits_to_bytes(hash_function(M1)))
    while True:
        #用RFC6979生成k∈[1,n-1]
        k = RFC6979_gen_k(dA, M)
        #算椭圆曲线点(x1,y1)=[k]G
        X = ECG_k_point(k, point_g)
        #进行x1的类型转换
        x1 = bytes_to_int(ele_to_bytes(X.x))
        #算r=(e+x1) mod n，如果r=0或r+k=n，就重新选择k
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        #算s = ((1 + dA)−1 ·(k−r·dA)) mod n，如果s=0就重新选择k
        s = (config.inverse(1 + dA, n) * (k - r * dA)) % n
        if s == 0:
            continue
        break
    return r, s #消息M的签名为(r,s)


#SM2签名验证
def SM2_ver(ID, r, s, PA):
    #验证r,s∈[1,n-1]是否成立，如果不成立，验证不通过
    if r < 0 or r > n:
        print("r验证不通过！")
        return -1
    if s < 0 or s > n:
        print("s验证不通过！")
        return -1
    ZA = get_Z(ID, PA)
    #置M1=ZA ∥ M
    M1 = ZA + M
    #算e = Hv(M1)，进行e的数据类型转换
    e = bytes_to_int(bits_to_bytes(hash_function(M1)))
    #算t=(r + s)mod n，若t = 0，验证不通过
    t = (r + s) % n
    if t == 0:
        return -1
    #计算椭圆曲线点(x1,y1)=[s']G+[t]PA
    X = ECG_ele_add(ECG_k_point(s, point_g), ECG_k_point(t, PA))
    #进行x1的数据类型转换，计算R=(e+x1)mod n,看R=r是否成立
    x1 = bytes_to_int(ele_to_bytes(X.x))
    R = (e + x1) % n
    if R == r:
        return 1
    else:
        return -1


if __name__ == '__main__':
    #初始化
    config.set_default_config()
    parameters = config.get_parameters()
    point_g = Point(config.get_Gx(), config.get_Gy())
    q = config.get_q()
    n = config.get_n()

    ID = "1938607452@qq.com"
    M = "Ge Mengyun"

    #生成公钥、私钥
    sk = random.randint(1, n - 1)
    pk = ECG_k_point(sk, point_g)
    print("私钥为:", sk)
    print("公钥为:", pk)

    #签名
    start_time = time.time()
    r, s = SM2_sig(ID, sk, pk)
    end_time = time.time()
    print("\n成功生成签名，所用时间:", end_time - start_time, "s")
    print("r:", r)
    print("s:", s)

    #验证
    print("\n验证签名")
    start_time = time.time()
    if SM2_ver(ID, r, s, pk):
        end_time = time.time()
        print("验证通过，所用时间:", end_time - start_time, "s")
