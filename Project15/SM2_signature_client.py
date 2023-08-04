import socket
from Prepare import *

#服务端主机IP地址和端口号
HOST = socket.gethostname()
PORT = 1234
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#创建socket对象

s.connect((HOST, PORT))#连接服务器
print("连接到主机名为", HOST, "端口号为", PORT, "的服务器，开始执行在线双方SM2签名")

#初始化
config.set_default_config()
parameters = config.get_parameters()
point_G = Point(config.get_Gx(), config.get_Gy())

n = config.get_n()
a = config.get_a()
b = config.get_b()
q = config.get_q()

d2 = randint(1, n - 1)#客户端子私钥d2
print("\n客户端子私钥d2为:", d2)
x, y = eval(s.recv(1024).decode())#从服务器接收P1
P1 = Point(int(x), int(y))
#算公钥P
P = ECG_ele_add(ECG_k_point(config.inverse(d2, n), P1), ECG_k_point(q - 1, point_G))
print("计算的公钥P:", P)
#发送公钥P至服务器，用来签名、验证
s.sendall(str([P.x, P.y]).encode())

#从服务器接收e和Q1
e = int(s.recv(1024).decode())
x, y = eval(s.recv(1024).decode())
Q1 = Point(int(x), int(y))

k2 = randint(1, n - 1)#随机生成k2和k3
k3 = randint(1, n - 1)
Q2 = ECG_k_point(k2, point_G)
X = ECG_ele_add(ECG_k_point(k3, Q1), Q2)
#算r=(e+x1) mod n，若r=0，则签名失败
r = (X.x + e) % n
if r == 0:
    print("签名失败！r==0！")
    s.close()
#据ppr计算s2、s3
s2 = (d2 * k3) % n
s3 = (d2 * (r + k2)) % n

#发送r,s2,s3至服务器
s.sendall(str(r).encode())
s.sendall(str(s2).encode())
s.sendall(str(s3).encode())

print("完成签名，断开连接。")
s.close()

