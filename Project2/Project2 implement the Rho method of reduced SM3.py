from gmssl import sm3, func
import time
import random


def Rho_Method(collision):
    num = int(collision / 4)
    col_initial = hex(random.randint(0, pow(2, (collision + 1)) - 1))[2:]
    set_collision = set()
    times = 0

    col_m1 = sm3.sm3_hash(func.bytes_to_list(bytes(str(col_initial), encoding='utf-8')))
    set_collision.add(col_m1[:num])

    while True:
        #碰撞次数
        times += 1
        col_m1 = sm3.sm3_hash(func.bytes_to_list(bytes(str(col_m1), encoding='utf-8')))
        if col_m1[:num] in set_collision:
            return col_m1[:num], times
        else:
            set_collision.add(col_m1[:num])


if __name__ == '__main__':
    #以30bit碰撞为例
    collision = int(input("输入要碰撞的比特数(测试使用30bit即可):"))

    #开始碰撞
    start_time = time.time()
    collision_hex, collision_times = Rho_Method(collision)
    end_time = time.time()
    print("找到碰撞。")
    print("碰撞的消息的前", collision, "bit相同，即为（十六进制表示）:", collision_hex)
    print("碰撞的计算次数:", collision_times, "\n碰撞需要的时间:", end_time - start_time, "s")

