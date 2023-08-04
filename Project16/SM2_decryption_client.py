import socket
from Prepare import *
HOST = socket.gethostname()
PORT = 1113#服务端主机IP地址和端口号
#创建socket对象
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#连接服务器
s.connect((HOST, PORT))
print("连接到主机名为", HOST, "端口号为", PORT, "的服务器，开始执行在线双方SM2解密")
#初始化
config.set_default_config()
parameters = config.get_parameters()
point_G = Point(config.get_Gx(), config.get_Gy())
q = config.get_q()
n = config.get_n()
h = config.get_h()
a = config.get_a()
b = config.get_b()
#P2子密钥d2
d2 = randint(1, n - 1)
print("P2的子密钥d2:", d2)
#发送d2至服务器
s.sendall(str(d2).encode())
#从服务器接受T1
T1 = int(s.recv(1024).decode())
#计算T2
T2 = config.inverse(d2, n) * T1
#发送T2至服务器端
s.sendall(str(T2).encode())
print("解密完成，断开连接。")
s.close()

