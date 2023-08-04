from Prepare import *
import time
#ECDSA部分的函数定义
#指定k的ECDSA签名
def ECDSA_sign_with_certain_k(d, m, k):
    kG = ECG_k_point(k, point_G)
    #求r和s
    r = ele_to_int(kG.x)
    s = ((config.inverse(k, n)) * (int(hash_sha3_256(m), 2) + d * r)) % n
    return r, s
#Schnorr部分的函数定义
#指定k的Schnorr签名
def Schnorr_sign_with_certain_k(d, m, k):
    R = ECG_k_point(k, point_G)#R = kG
    e = int(hash_sha3_256(str(R) + str(m)), 2) #e = hash(R||M)
    s = (k + e * d) % n #s = (k + ed)mod n
    return R, s
#使用公钥P进行Schnorr签名验证
def Schnorr_verify(e, R, s, P):
    #sG=(k+ed)G=kG+edG=R+eP
    sG = ECG_k_point(s, point_G)
    R_eP = ECG_ele_add(R, ECG_k_point(e, P)) #R + eP
    if R_eP.x == sG.x and R_eP.y == sG.y:
        return True
    else:
        return False
# SM2 signature部分的函数定义
#指定k的SM2签名
def SM2_sign_with_certain_k(M, ID, dA, PA, k):
    ZA = get_Z(ID, PA)
    #置M1=ZA ∥ M
    M1 = ZA + M
    e = bytes_to_int(bits_to_bytes(hash_function(M1))) #计算e = Hv(M1)
    #算椭圆曲线点(x1,y1)=[k]G
    X = ECG_k_point(k, point_G)
    x1 = bytes_to_int(ele_to_bytes(X.x))
    #算r=(e+x1) mod n，由于k已经确定，若r=0或r+k=n则直接退出，而不是重新选择k
    r = (e + x1) % n
    if r == 0 or r + k == n:
        return None
    #算s = ((1 + dA)^(−1) ·(k−r·dA)) mod n，若s=0则直接退出
    s = (config.inverse(1 + dA, n) * (k - r * dA)) % n
    if s == 0:
        return None
    return r, s

if __name__ == "__main__":
    #初始化
    config.set_default_config()
    point_G = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()
    while True:
        method = input("1、ECDSA\n2、Schnorr\n3、SM2 signature\n请输入要验证的方法对应的标号(1,2或者3):")
        if method == '1':
            print("正在验证ECDSA。")
            d = random.randint(1, n - 1)  
            print("私钥d:", d)

            print("\n1、泄露k会导致泄露私钥d:")
            start_time = time.time()
            m = "Ge Mengyun"
            k = random.randint(1, n - 1)
            print("泄露的k为", k)
            #ECDSA签名
            r, s = ECDSA_sign_with_certain_k(d, m, k)
            #求私钥d
            d_break = ((k * s - int(hash_sha3_256(m), 2)) * config.inverse(r, n)) % n
            if d_break == d:
                print("攻击成功,求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费时间为:", end_time - start_time, "s")
            print("\n2、重复使用k会导致泄露私钥d:")
            start_time = time.time()
            #使用同一个k签名两次
            m1 = "GeMeng yun"
            m2 = "Gemeng Yun"
            k = random.randint(1, n - 1)
            print("重复使用的k为", k)
            #ECDSA签名
            r1, s1 = ECDSA_sign_with_certain_k(d, m1, k)
            r2, s2 = ECDSA_sign_with_certain_k(d, m2, k)
            #求私钥d
            #k=(e2*r1-e1*r2)*(s2*r1-s1*r2)^(-1)
            k = ((int(hash_sha3_256(m2), 2) * r1 - int(hash_sha3_256(m1), 2) * r2) *
                 config.inverse(s2 * r1 - s1 * r2, n)) % n
            d_break = ((k * s1 - int(hash_sha3_256(m1), 2)) * config.inverse(r1, n)) % n
            if d_break == d:
                print("攻击成功，求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费时间为:", end_time - start_time, "s")
            print("\n3、两个用户使用相同的k会导致泄露双方的私钥d:")
            start_time = time.time()
            m1 = "GeMeng yun"
            m2 = "Gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)
            d1 = random.randint(1, n - 1) 
            d2 = random.randint(1, n - 1)  
            #ECDSA签名
            r1, s1 = ECDSA_sign_with_certain_k(d1, m1, k)
            r2, s2 = ECDSA_sign_with_certain_k(d2, m2, k)
            d1_break = ((k * s1 - int(hash_sha3_256(m1), 2)) * config.inverse(r1, n)) % n
            d2_break = ((k * s2 - int(hash_sha3_256(m2), 2)) * config.inverse(r2, n)) % n
            if d2_break == d2:
                print("攻击成功，用户1破解用户2私钥d2为", d2_break)
            if d1_break == d1:
                print("攻击成功，用户2破解用户1私钥d1为", d1_break)
            end_time = time.time()
            print("花费的时间为:", end_time - start_time, "s")
            print("\n4、如果不验证m，可以伪造签名:")
            print("ECDSA验证到此结束。")

        #Schnorr
        elif method == '2':
            print("正在验证Schnorr！")
            #生成公私钥对
            d = random.randint(1, n - 1) 
            P = ECG_k_point(d, point_G)  
            print("私钥d:", d, "\n公钥P:", P)
            print("\n1、泄露k会导致泄露私钥d:")
            start_time = time.time()
            m = "GeMeng yun"
            k = random.randint(1, n - 1)
            print("泄露的k为", k)
            #Schnorr签名
            R, s = Schnorr_sign_with_certain_k(d, m, k)
            #e = hash(R||M)
            e = int(hash_sha3_256(str(R) + str(m)), 2)
            d_break = ((s - k) * config.inverse(e, n)) % n
            if d_break == d:
                print("攻击成功，求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费的时间为:", end_time - start_time, "s")
            print("\n2、重复使用k会导致泄露私钥d:")
            start_time = time.time()
            m1 = "GeMeng yun"
            m2 = "Gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)
            #Schnorr签名
            R1, s1 = Schnorr_sign_with_certain_k(d, m1, k)
            R2, s2 = Schnorr_sign_with_certain_k(d, m2, k)
            # e = hash(R||M)
            e1 = int(hash_sha3_256(str(R1) + str(m1)), 2)
            e2 = int(hash_sha3_256(str(R2) + str(m2)), 2)
            # k = (s2*e1-s1*e2)*(e1-e2)^(-1)
            k = ((s2 * e1 - s1 * e2) * config.inverse(e1 - e2, n)) % n
            d_break = ((s1 - k) * config.inverse(e1, n)) % n
            if d_break == d:
                print("攻击成功，求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费的时间为:", end_time - start_time, "s")
            print("\n3、两个用户使用相同的k会导致泄露双方的私钥d:")
            start_time = time.time()
            m1 = "GeMeng yun"
            m2 = "Gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)
            d1 = random.randint(1, n - 1)  
            d2 = random.randint(1, n - 1) 
            #Schnorr签名
            R1, s1 = Schnorr_sign_with_certain_k(d1, m1, k)
            R2, s2 = Schnorr_sign_with_certain_k(d2, m2, k)
            #求私钥d
            #e = hash(R||M)
            e1 = int(hash_sha3_256(str(R1) + str(m1)), 2)
            e2 = int(hash_sha3_256(str(R2) + str(m2)), 2)
            d1_break = ((s1 - k) * config.inverse(e1, n)) % n
            d2_break = ((s2 - k) * config.inverse(e2, n)) % n
            if d2_break == d2:
                print("攻击成功，用户1破解用户2私钥d2为", d2_break)
            if d1_break == d1:
                print("攻击成功，用户2破解用户1私钥d1为", d1_break)
            end_time = time.time()
            print("花费的时间为:", end_time - start_time, "s")
            print("\n4、如果不验证m，可以伪造签名:")
            start_time = time.time()
            #先生成正确的签名
            R, s = Schnorr_sign_with_certain_k(d, m, k)
            e = int(hash_sha3_256(str(R) + m), 2)#e = hash(R||M)
            print("正确的签名:\ne:", e, "\nR:", R, "\ns:", s)
            #伪造签名：将正确的签名变为原来的x倍
            x = random.randint(1, n - 1)
            s_forge = (x * s) % n
            R_forge = ECG_k_point(x * k, point_G)
            e_forge = (x * e) % n
            #验证伪造的签名
            if Schnorr_verify(e_forge, R_forge, s_forge, P):
                print("通过验证，伪造成功，伪造的签名:\ne':", e_forge, "\nR':", R_forge, "\ns':", s_forge)
                end_time = time.time()
                print("花费时间:", end_time - start_time, "s")
            print("\n5、与ECDSA使用相同的私钥d和k会导致泄露私钥d:")
            start_time = time.time()
            # m1用于Schnorr签名
            m1 = "GeMeng yun"
            # m2用于ECDSA签名
            m2 = "gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)
            #Schnorr签名
            R, S = Schnorr_sign_with_certain_k(d, m1, k)
            #ECDSA签名
            r, s = ECDSA_sign_with_certain_k(d, m2, k)
            #Schnorr的e=hash(R||M)
            e_Schnorr = int(hash_sha3_256(str(R) + m1), 2)
            # ECDSA的e=hash(m)
            e_ECDSA = int(hash_sha3_256(m2), 2)

            # d = (s*S-e_ECDSA)*(s*e_Schnorr+r)^(-1)
            d_break = ((S * s - e_ECDSA) * config.inverse(e_Schnorr * s + r, n)) % n
            if d_break == d:
                print("攻击成功,求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费的时间为:", end_time - start_time, "s")
            print("Schnorr验证到此结束。")
        #SM2 signature
        elif method == '3':
            print("正在验证SM2 signature。")
            #生成公私钥对
            d = random.randint(1, n - 1)  
            P = ECG_k_point(d, point_G) 
            print("私钥d:", d, "\n公钥P:", P)
            ID = "GeMeng yun@qq.com"
            print("\n1、泄露k会导致泄露私钥d:")
            start_time = time.time()
            m = "GeMeng yun"
            k = random.randint(1, n - 1)
            print("泄露的k为", k)
            #SM2签名
            r, s = SM2_sign_with_certain_k(m, ID, d, P, k)
            #求私钥d
            d_break = ((k - s) * config.inverse(s + r, n)) % n
            if d_break == d:
                print("攻击成功,求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费的时间为:", end_time - start_time, "s")
            print("\n2、重复使用k会导致泄露私钥d:")
            start_time = time.time()
            m1 = "GeMeng yun"
            m2 = "gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)

            ID_1 = "GeMeng yun@qq.com"
            ID_2 = "gemeng Yun@qq.com"
            #SM2签名
            r1, s1 = SM2_sign_with_certain_k(m1, ID_1, d, P, k)
            r2, s2 = SM2_sign_with_certain_k(m2, ID_2, d, P, k)
            #求私钥d
            d_break = (s1 - s2) * config.inverse((r2 - r1 + s2 - s1), n) % n
            if d_break == d:
                print("攻击成功,求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费的时间为:", end_time - start_time, "s")
            print("\n3、两个用户使用相同的k会导致泄露双方的私钥d:")
            start_time = time.time()
            m1 = "GeMeng yun"
            m2 = "gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)
            d1 = random.randint(1, n - 1)  # 用户1的私钥
            d2 = random.randint(1, n - 1)  # 用户2的私钥
            ID_1 = "GeMeng yun@qq.com"
            ID_2 = "gemeng Yun@qq.com"
            #SM2签名
            r1, s1 = SM2_sign_with_certain_k(m1, ID_1, d1, P, k)
            r2, s2 = SM2_sign_with_certain_k(m2, ID_2, d2, P, k)
            d1_break = ((k - s1) * config.inverse(s1 + r1, n)) % n
            d2_break = ((k - s2) * config.inverse(s2 + r2, n)) % n
            if d2_break == d2:
                print("攻击成功，用户1破解用户2私钥d2为", d2_break)
            if d1_break == d1:
                print("攻击成功，用户2破解用户1私钥d1为", d1_break)
            end_time = time.time()
            print("花费的时间为:", end_time - start_time, "s")
            print("\n4、与ECDSA使用相同的私钥d和k会导致泄露私钥d:")
            start_time = time.time()
            # m1用于ECDSA签名
            m1 = "GeMeng yun"
            # m2用于SM2签名
            m2 = "gemeng Yun"
            k = random.randint(1, n - 1)
            print("使用的相同的k为", k)
            ID1 = "GeMeng yun@qq.com"
            #ECDSA签名
            r1, s1 = ECDSA_sign_with_certain_k(d, m1, k)
            #SM2的签名
            r2, s2 = SM2_sign_with_certain_k(m2, ID1, d, P, k)
            #ECDSA的e=SM2的e=hash(m)
            e = int(hash_sha3_256(m1), 2)
            #求私钥d：联立两个签名s的式子即可求出
            d_break = (s1 * s2 - e) * config.inverse((r1 - s1 * s2 - s1 * r2), n) % n
            if d_break == d:
                print("攻击成功，求出的私钥d为:", d_break)
                end_time = time.time()
                print("花费的时间为:", end_time - start_time, "s")
            print("SM2 signature验证到此结束。")
        else:
            print("输入不正确，请重新输入。")
            continue
        if_ver = input("\n是否要继续验证（0：退出；1：继续验证）：")
        if if_ver == '1':
            continue
        else:
            break

