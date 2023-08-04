import math
from polynomial import *
import random
import time
# import config
# import Point
# 判断是否为有限域元素 #
def in_field(a):
    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        if not (a >= 0 and a <= q - 1):
            print("*** ERROR: a不是有限域中元素 *** function: in_field ***")
            return False
        else:
            return True
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        m = math.log2(q)
        if (len(a) - 2) > m:
            print("*** ERROR: a 不是有限域元素 *** function: in_field ***")
            return False
        else:
            for i in range(2, len(a)):
                if a[i] != '0' and a[i] != '1':
                    print("*** ERROR: a 不是有限域元素 *** function: in_field ***")
                    return False
            return True
    else:
        print("*** ERROR: 模数q不是奇素数或者2的幂 *** function: field_ele_add ***")
        return -1

# 有限域加法单位元 #
def field_ele_zero():
    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        return 0
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        m = int(math.log2(q))
        zero = '0b'
        for i in range(0, m):
            zero += '0'
        return zero
    else:
        print("*** ERROR: 模数q不是奇素数或者2的幂 *** function: field_ele_zero ***")
        return -1


# 有限域乘法单位元 #
def field_ele_one():
    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        return 1
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        m = int(math.log2(q))
        one = '0b'
        for i in range(0, m - 1):
            one += '0'
        one += '1'
        return one
    else:
        print("*** ERROR: 模数q不是奇素数或者2的幂 *** function: field_ele_one ***")
        return -1


# 3.1 有限域计算 #
# 有限域加法 #
'''
input: 域元素 a 和 b
output: 域元素 (a+b)
'''


def field_ele_add(a, b):
    # print("--- 有限域 加法 ---")
    q = config.get_q()
    if config.is_q_prime() and q > 2:
        if not in_field(a):
            return -1
        elif not in_field(b):
            return -1
        else:
            return ((a + b) % q)
    elif config.is_q_power_of_two():
        if not (in_field(a) and in_field(b)):
            return -1
        else:
            c_int = ele_to_int(a) ^ (ele_to_int(b))
            c_bytes = int_to_bytes(c_int, 2)
            c_ele = bytes_to_ele(q, c_bytes)
            return c_ele
    else:
        return -1


# 有限域加法逆元 #
'''
input: 域元素 a
output: a 的逆元素
'''


def field_ele_inverse_add(a):
    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        if not in_field(a):
            print("*** ERROR: a不是域中元素 *** function: field_ele_inverse_add ***")
            return -1
        else:
            return (q - a) % q
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        # m = math.log2(q)
        if not in_field(a):
            print("*** ERROR: 参数不是二元扩域元素 *** function: field_ele_inverse_add ***")
            return -1
        else:
            return a
    else:
        print("*** ERROR: 模数q不是奇素数或2的幂 *** function: field_ele_inverse_add ***")
        return -1


# 有限域减法 #
'''
input: 被减元素 a 和减元素 b
output: 域元素 (a-b)
'''


def field_ele_sub(a, b):
    return field_ele_add(a, field_ele_inverse_add(b))


# 有限域乘法 #
'''
input: 域元素 a 和 b
output: 域元素 (a*b)
'''


def field_ele_times(a, b):
    # print("--- 有限域 乘法 ---")

    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        if not in_field(a):
            print("*** ERROR: a不是域中元素 *** function: field_ele_times ***")
            return -1
        elif not in_field(b):
            print("*** ERROR: b不是域中元素 *** function: field_ele_times ***")
            return -1
        else:
            return ((a * b) % q)
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        # m = math.log2(q)
        if not (in_field(a) and in_field(b)):
            print("*** ERROR: 参数不是二元扩域元素 *** function: field_ele_times ***")
            return -1
        else:
            result_bits = polynomial_a_mod_b(polynomial_times(a, b), config.get_fx())
            return bytes_to_ele(q, bits_to_bytes(result_bits))
    else:
        print("*** ERROR: 模数q不是奇素数或2的幂 *** function: field_ele_times ***")
        return -1


# 有限域幂运算 #
'''
iuput: 域元素 g 和 幂次 a
output: 域元素 g**a
'''


def field_ele_g_pow_a(g, a):
    # print("--- 有限域 幂运算 ---")

    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        if not in_field(g):
            print("*** ERROR: a不是域中元素 *** function: field_ele_g_pow_a ***")
            return -1
        else:
            e = a % (q - 1)
            if e == 0:
                return 1
            r = int(math.log2(e))  # + 1 - 1
            x = g
            for i in range(0, r):
                x = field_ele_times(x, x)
                if (e & (1 << (r - 1 - i))) == (1 << (r - 1 - i)):
                    x = field_ele_times(x, g)
            return x
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        # m = math.log2(q)
        if not in_field(g):
            print("*** ERROR: 参数不是二元扩域元素 *** function: field_ele_g_pow_a ***")
            return -1
        else:
            e = a % (q - 1)
            if e == 0:
                return polynomial_one()
            r = int(math.log2(e))  # + 1 - 1
            x = g
            for i in range(0, r):
                x = field_ele_times(x, x)
                if (e & (1 << (r - 1 - i))) == (1 << (r - 1 - i)):
                    x = field_ele_times(x, g)
            return x
    else:
        print("*** ERROR: 模数q不是奇素数或2的幂 *** function: field_ele_g_pow_a ***")
        return -1


# 有限域逆元素 #
'''
input: 元素 a
output: 元素 a 的逆元素
'''


def field_ele_inverse_times(a):
    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 2:
        if not in_field(a):
            print("*** ERROR: a不是域中元素 *** function: field_ele_inverse_times ***")
            return -1
        else:
            return field_ele_g_pow_a(a, config.get_q() - 2)
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        # m = math.log2(q)
        if not in_field(a):
            print("*** ERROR: 参数不是二元扩域元素 *** function: field_ele_inverse_times ***")
            return -1
        else:
            return field_ele_g_pow_a(a, config.get_q() - 2)
    else:
        print("*** ERROR: 模数q不是奇素数或2的幂 *** function: field_ele_inverse_times ***")
        return -1


# 有限域除法 #
'''
input: 被除数 a 和除数 b
output: 除法所得商
'''


def field_ele_a_devide_b(a, b):
    # print("--- 有限域 除法 ---")
    return field_ele_times(a, field_ele_inverse_times(b))


# 3.2.3 椭圆曲线群 #

# 椭圆曲线无穷远点 #
def ECG_ele_zero():
    return Point(field_ele_zero(), field_ele_zero())


# 椭圆曲线元素判断 #
# 元素为零 #
def ECG_ele_is_zero(p):
    if p.x == field_ele_zero() and p.y == field_ele_zero():
        return True
    else:
        return False


# 元素互为逆元素 #
def ECG_is_inverse_ele(p1, p2):
    q = config.get_q()
    # q 为素数
    if config.is_q_prime():
        if p1.x == p2.x and p1.y == field_ele_inverse_add(p2.y):
            return True
        else:
            return False
    elif config.is_q_power_of_two():
        if p1.x == p2.x and p2.y == field_ele_add(p1.x, p1.y):
            return True
        else:
            return False
    else:
        print("*** ERROR: q 不是素数或者 2 的幂 *** function: ECG_is_inverse_ele ***")
        return False


# 元素相等 #
def ECG_ele_equal(p1, p2):
    if p1.x == p2.x and p1.y == p2.y:
        return True
    else:
        return False


# 椭圆曲线加法 #
'''
input: 椭圆曲线群中点 a 和 b
output: 椭圆曲线群中点(a+b)
'''


def ECG_ele_add(p1, p2):
    # Fp 上的椭圆曲线群
    if config.is_q_prime():
        if ECG_ele_is_zero(p1):
            return p2
        elif ECG_ele_is_zero(p2):
            return p1
        elif ECG_is_inverse_ele(p1, p2):
            return ECG_ele_zero()
        elif ECG_ele_equal(p1, p2):
            # lam = (3 * (p1.x**2) + config.get_a()) / (2 * p1.y)
            t1 = field_ele_add(field_ele_times(3, field_ele_g_pow_a(p1.x, 2)), config.get_a())
            t2 = field_ele_times(2, p1.y)
            lam = field_ele_a_devide_b(t1, t2)
            # x = lam**2 - 2 * p1.x
            x = field_ele_sub(field_ele_g_pow_a(lam, 2), field_ele_times(2, p1.x))
            # y = lam * (p1.x - x) - p1.y
            y = field_ele_sub(field_ele_times(lam, field_ele_sub(p1.x, x)), p1.y)
            return Point(x, y)
        else:
            # lam = (p2.y - p1.y) / (p2.x - p1.x)
            lam = field_ele_a_devide_b(field_ele_sub(p2.y, p1.y), field_ele_sub(p2.x, p1.x))
            # x = lam * lam - p1.x - p2.x
            x = field_ele_sub(field_ele_sub(field_ele_g_pow_a(lam, 2), p1.x), p2.x)
            # y = lam * (p1.x - x) - p1.y
            y = field_ele_sub(field_ele_times(lam, field_ele_sub(p1.x, x)), p1.y)
            return Point(x, y)

    # F2^m 上的椭圆曲线
    if config.is_q_power_of_two():
        if ECG_ele_is_zero(p1):
            return p2
        elif ECG_ele_is_zero(p2):
            return p1
        elif ECG_is_inverse_ele(p1, p2):
            return ECG_ele_zero()
        elif ECG_ele_equal(p1, p2):
            # lam = p1.x + (p1.y / p1.x)
            lam = field_ele_add(p1.x, field_ele_a_devide_b(p1.y, p1.x))
            # x = lam**2 + lam + config.get_a()
            x = field_ele_add(field_ele_add(field_ele_g_pow_a(lam, 2), lam), config.get_a())
            # y = p1.x**2 + (lam + 1) * x
            y = field_ele_add(field_ele_g_pow_a(p1.x, 2), \
                              field_ele_times(field_ele_add(lam, field_ele_one()), x))
            return Point(x, y)
        else:
            # lam = (p1.y + p2.y) / (p1.x + p2.x)
            lam = field_ele_a_devide_b(field_ele_add(p1.y, p2.y), \
                                       field_ele_add(p1.x, p2.x))
            # x = lam**2 + lam + p1.x + p2.x + config.get_a()
            t1 = field_ele_add(field_ele_g_pow_a(lam, 2), lam)
            t2 = field_ele_add(field_ele_add(p1.x, p2.x), config.get_a())
            x = field_ele_add(t1, t2)
            # y = lam * (p1.x + x) + x + p1.y
            t1 = field_ele_times(lam, field_ele_add(p1.x, x))
            t2 = field_ele_add(x, p1.y)
            y = field_ele_add(t1, t2)
            return Point(x, y)


# 椭圆曲线求 2 倍点 #
'''
input: 椭圆曲线点 p
output: 点(P+P)
'''


def ECG_double_point(p):
    # Fp 上的椭圆曲线群
    if config.is_q_prime():
        if ECG_ele_is_zero(p):
            return p
        else:
            t1 = field_ele_add(field_ele_times(3, field_ele_g_pow_a(p.x, 2)), config.get_a())
            t2 = field_ele_times(2, p.y)
            lam = field_ele_a_devide_b(t1, t2)
            x = field_ele_sub(field_ele_g_pow_a(lam, 2), field_ele_times(2, p.x))
            y = field_ele_sub(field_ele_times(lam, field_ele_sub(p.x, x)), p.y)
            return Point(x, y)
    # F2^m 上的椭圆曲线
    if config.is_q_power_of_two():
        if ECG_ele_is_zero(p):
            return p
        else:
            lam = field_ele_add(p.x, field_ele_a_devide_b(p.y, p.x))
            x = field_ele_add(field_ele_add(field_ele_g_pow_a(lam, 2), lam), config.get_a())
            y = field_ele_add(field_ele_g_pow_a(p.x, 2), \
                              field_ele_times(field_ele_add(lam, field_ele_one()), x))
            return Point(x, y)


# 椭圆曲线求 k 倍点 #
'''
input: 倍数 k 和椭圆曲线点 p
output: p 的 k 倍点
'''


def ECG_k_point(k, p):
    # print('[' + str(k) + ']P')
    l = int(math.log2(k)) + 1  # - 1
    # print(l)
    point_q = ECG_ele_zero()
    for i in range(0, l):
        # print('i = ' + str(i))
        j = l - 1 - i
        # t_start = time.time()
        point_q = ECG_double_point(point_q)
        # t_end = time.time()
        # print('double:' + str(t_end - t_start))
        if (k & (1 << j)) == (1 << j):
            # t_start = time.time()
            point_q = ECG_ele_add(point_q, p)
            # t_end = time.time()
            # print('add:' + str(t_end - t_start))
    return point_q


# 6.1 密钥对的生成 #
'''
input: 有效的椭圆曲线系统参数集合
output: 与输入参数相关的一个密钥对(d, P)
'''
def key_pair_generation(parameters):
    '''
    config.set_q(parameters['q'])
    config.set_a(parameters['a'])
    config.set_b(parameters['b'])
    n = parameters['n']
    point_g = Point(parameters['Gx'], parameters['Gy'])
    # q 为 2 的幂
    if config.is_q_power_of_two():
        config.set_fx(parameters['f(x)'])
    '''
    config.set_parameters(parameters)
    point_g = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()

    d = random.randint(1, n - 2)
    p = ECG_k_point(d, point_g)
    keypair = []
    keypair.append(d)
    keypair.append(p)
    return keypair


# 6.2 公钥的认证 #
'''
input: 有效的椭圆曲线系统参数集合以及一个相关的公钥
output: 若通过验证则输出“有效",否则输出“无效”
'''


def public_key_verification(parameters, public_key):
    '''
    config.set_q(parameters['q'])
    config.set_a(parameters['a'])
    config.set_b(parameters['b'])
    n = parameters['n']
    # q 为 2 的幂
    if config.is_q_power_of_two():
        config.set_fx(parameters['f(x)'])
    '''
    config.set_parameters(parameters)
    n = config.get_n()
    q = config.get_q()
    # q 为奇素数
    if config.is_q_prime() and q > 3:
        if ECG_ele_is_zero(public_key):
            print("*** ERROR: 公钥为无穷远点 *** function: public_key_verification")
            # print("无效")
            return False
        if not (in_field(public_key.x) and in_field(public_key.y)):
            print("*** ERROR: 公钥坐标不是素域中元素 *** function: public_key_verification")
            # print("无效")
            return False
        t1 = field_ele_g_pow_a(public_key.y, 2)
        t2 = field_ele_add(field_ele_add(field_ele_g_pow_a(public_key.x, 3),
                                         field_ele_times(config.get_a(), public_key.x)), config.get_b())
        if t1 != t2:
            print("*** ERROR: 公钥坐标不符合椭圆曲线方程 *** function: public_key_verification")
            # print("无效")
            return False
        if not (ECG_ele_is_zero(ECG_k_point(n, public_key))):
            print("*** ERROR: n 不是公钥的阶 *** function: public_key_verification")
            # print("无效")
            return False
        # print("有效")
        return True
    # q 为 2 的幂
    elif config.is_q_power_of_two():
        if ECG_ele_is_zero(public_key):
            print("*** ERROR: 公钥为无穷远点 *** function: public_key_verification")
            # print("无效")
            return False
        # m = math.log2(q)
        if not (in_field(public_key.x) and in_field(public_key.y)):
            print("*** ERROR: 公钥坐标不是素域中元素 *** function: public_key_verification")
            # print("无效")
            return False
        t1 = field_ele_add(field_ele_g_pow_a(public_key.y, 2),
                           field_ele_times(public_key.x, public_key.y))
        t2 = field_ele_add(field_ele_add(field_ele_g_pow_a(public_key.x,
                                                           3),
                                         field_ele_times(config.get_a(),
                                                         field_ele_g_pow_a(public_key.x, 2))),
                           config.get_b())
        if t1 != t2:
            print("*** ERROR: 公钥坐标不符合椭圆曲线方程 *** function: public_key_verification")
            # print("无效")
            return False
        if not (ECG_ele_is_zero(ECG_k_point(n, public_key))):
            print("*** ERROR: n 不是公钥的阶 *** function: public_key_verification")
            # print("无效")
            return False
        # print("有效")
        return True
    else:
        print("*** ERROR: q 不是奇素数或者 2 的幂 *** function: public_key_verification")
        # print("无效")
        return False
