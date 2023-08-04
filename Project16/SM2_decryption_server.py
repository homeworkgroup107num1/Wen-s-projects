import socket
from Prepare import *
import SM2_encryption_decryption
import time

#创建socket对象
S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#绑定端口1113
S.bind((socket.gethostname(), 1113))
S.listen(128)#被动连接
print("服务器端启动\t主机名:", socket.gethostname(), "\t端口号: 1113")
new_socket, client_addr = S.accept()#接收客户端的消息
print("主机地址", client_addr[0], ",端口号", client_addr[1], "的客户端接入本服务器，开始执行在线双方SM2解密")
start_time = time.time()
#初始化
config.set_default_config()
parameters = config.get_parameters()
point_G = Point(config.get_Gx(), config.get_Gy())

q = config.get_q()
n = config.get_n()
h = config.get_h()
a = config.get_a()
b = config.get_b()
M = bin(int("aaacccbbbdd", 16))[2:]
d1 = randint(1, n - 1)#P1子密钥d1
print("P1的子密钥d1:", d1)
#从客户端接受d2
d2 = int(new_socket.recv(1024).decode())
dB = config.inverse(d1 * d2, n) - 1#私钥
PB = ECG_k_point(dB, point_G)#公钥
C = SM2_encryption_decryption.SM2_enc(M, PB, n, h)

c1_len = (2 * math.ceil(math.log2(q) / 8) + 1) * 8
#从C中取出比特串C1
C1 = C[:c1_len]
C1 = int(C1, 2)
C2 = C[c1_len:len(C) - 256]
C3 = C[len(C) - 256: len(C)]

T1 = config.inverse(d1, n) * C1#求T1
#发送T1至客户端
new_socket.sendall(str(T1).encode())
#从客户端接受T2
T2 = int(new_socket.recv(1024).decode())
C1 = "0b" + C[:c1_len]
C1 = bytes_to_point(a, b, bits_to_bytes(C1))
#X = [sk]C1=(x2,y2)
X = ECG_k_point(dB, C1)
#将坐标x2、y2的数据类型转换为比特串
x2 = bytes_to_bits(ele_to_bytes(X.x))
y2 = bytes_to_bits(ele_to_bytes(X.y))
x2 = remove_0b_at_beginning(x2)
y2 = remove_0b_at_beginning(y2)
#计算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，就报错退出
klen = len(C2)
t = KDF(x2 + y2, klen)
if SM2_encryption_decryption.is_zero_str(t):
    print("解密失败：t是全零比特串！")
    S.close()
#从C中取出比特串C2，计算M′ = C2 ⊕ t
M_1 = bin(int(C2, 2) ^ int(t, 2))
M_1 = remove_0b_at_beginning(M_1)
#算u = Hash(x2 ∥ M′ ∥ y2)，从C中取出比特串C3，若u==C3，则解密成功
u = hash_function(x2 + M_1 + y2)
u = remove_0b_at_beginning(u)
if u == C3:
    print("解密成功！二进制明文:", bin(int(M_1, 2))[2:],
          "\n\t\t十六进制明文:", hex(int(M_1, 2))[2:])
    new_socket.sendall(M_1.encode())
    end_time = time.time()
    print("双方解密SM2所用时间:", end_time - start_time, "s")
    print("解密完成，断开连接。")
    S.close()

