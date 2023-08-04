import socket
from Prepare import *
import SM2_signature_verification
import time

#创建socket对象
S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
S.bind((socket.gethostname(), 1234))#绑定端口为1234
S.listen(128)#被动连接
print("服务器端启动\t主机名:", socket.gethostname(), "\t端口号: 1234")

new_socket, client_addr = S.accept()#接收来自客户端的消息
print("主机地址", client_addr[0], ",端口号", client_addr[1], "的客户端接入本服务器，开始执行在线双方SM2签名")
start_time = time.time()

#初始化
config.set_default_config()
parameters = config.get_parameters()
point_G = Point(config.get_Gx(), config.get_Gy())
n = config.get_n()
a = config.get_a()
b = config.get_b()

M = "Ge Mengyun"
ID = "1938607452@qq.com"
d1 = randint(1, n - 1)#服务器子私钥d1
P1 = ECG_k_point(config.inverse(d1, n), point_G)
print("\n服务器子私钥d1:", d1, "\nP:", P1)
#发送P1至客户端
new_socket.sendall(str([P1.x, P1.y]).encode())
#从客户端接受公钥P，用来签名、验证
p1, p2 = eval(new_socket.recv(1024).decode())
PA = Point(int(p1), int(p2))

#签名开始
ZA = get_Z(ID, PA)
M1 = ZA + M #令M1=ZA ∥ M
#计算e = Hv(M1)，进行e的数据类型转换
e = bytes_to_int(bits_to_bytes(hash_function(M1)))
k1 = randint(1, n - 1)
#计算椭圆曲线点(x1,y1)=[k]G
Q1 = ECG_k_point(k1, point_G)
#发送e和Q1至客户端
new_socket.sendall(str(e).encode())
new_socket.sendall(str([Q1.x, Q1.y]).encode())
#从客户端接受r,s2,s3
r = int(new_socket.recv(1024).decode())
s2 = int(new_socket.recv(1024).decode())
s3 = int(new_socket.recv(1024).decode())
#算s = ((1 + dA)−1 ·(k−r·dA)) mod n，若s=0，则重新选择k
s = ((d1 * k1) * s2 + d1 * s3 - r) % n
if s == 0 or s == n - r:
    print("签名失败！s==0或者s==n-r!")
    S.close()
end_time = time.time()
print("\n签名完成:\nr:", r, "\ns:", s)
print("双方签名SM2所需时间:", end_time - start_time, "s")

#验证
start_time = time.time()
if SM2_signature_verification.SM2_ver(M, ID, r, s, PA, n):
    print("\n签名验证成功！")
    end_time = time.time()
    print("验证SM2所用时间:", end_time - start_time, "s")

print("签名完成，断开连接。")
S.close()

