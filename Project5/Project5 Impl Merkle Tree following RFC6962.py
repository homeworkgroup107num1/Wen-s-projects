import copy
import time
import hashlib

#Merkle树的叶子结点
def hash_leaf(data, hash_function='sha256'):
    hash_function = getattr(hashlib, hash_function)
    data = b'\x00' + data.encode('utf-8')
    return hash_function(data).hexdigest()

#Merkle树的其余结点
def hash_node(data, hash_function='sha256'):
    hash_function = getattr(hashlib, hash_function)
    data = b'\x01' + data.encode('utf-8')
    return hash_function(data).hexdigest()

#打印出Merkle树的各个哈希值
def Show_Merkle_Tree(merkle_tree, h):
    print("Merkle Tree高度:", h)
    print("Merkle Tree从下到上每一层节点的哈希值为:")
    for i in range(h + 1):
        print("第", i + 1, "层:")
        len_tree = len(merkle_tree[i])
        for j in range(len_tree):
            print(merkle_tree[i][j])
        print()
    print()

#生成Merkle树
def Create_Merkle_Tree(lst, hash_function='sha256'):
    lst_hash = []
    for i in lst:
        lst_hash.append(hash_leaf(i))#先全都设成叶子结点
    merkle_tree = [copy.deepcopy(lst_hash)]
    #如果结点数太少，则生成Merkle树失败
    if len(lst_hash) < 2:
        print("结点数太少，生成Merkle树失败！")
        return 0
    h = 0 #Merkle树的高度
    while len(lst_hash) > 1:
        h += 1
        if len(lst_hash) % 2 == 0:#如果为偶数结点
            v = []
            while len(lst_hash) > 1:
                #pop两个结点
                a = lst_hash.pop(0)
                b = lst_hash.pop(0)
                v.append(hash_node(a + b, hash_function))
            merkle_tree.append(v[:])#Merkle树更新
            lst_hash = v
        else: #如果为奇数结点
            v = []
            last_node = lst_hash.pop(-1)
            while len(lst_hash) > 1:
                a = lst_hash.pop(0)
                b = lst_hash.pop(0)
                v.append(hash_node(a + b, hash_function))
            v.append(last_node)
            #Merkle树更新一层
            merkle_tree.append(v[:])
            lst_hash = v
    return merkle_tree, h

#以下为构造第n个叶子节点存在性和验证
#Merkle树高度为h，查找的序号为n
def Audit_Proof(merkle_tree, h, n, leaf, hash_function='sha256'):
    if n >= len(merkle_tree[0]):
        print("结点序号错误！")
        return 0
    print("序号:", n, "字符:", leaf, "\n查找路径:")
    j = 0 #第j层,最底层要计算叶子结点的哈希值
    L = len(merkle_tree[0])
    #叶子结点有奇数个，n是最后一个结点
    if L % 2 == 1 and L - 1 == n:
        hash_value = hash_leaf(leaf)
        print("第", j + 1, "层的Hash值:", hash_value)
    elif n % 2 == 1:
        hash_value = hash_node(merkle_tree[0][n - 1] + hash_leaf(leaf), hash_function)
        print("第", j + 1, "层的查找值:", merkle_tree[0][n - 1], "\n\t生成的Hash值:", hash_value)
    elif n % 2 == 0:
        hash_value = hash_node(hash_leaf(leaf) + merkle_tree[0][n + 1], hash_function)
        print("第", j + 1, "层的查找值:", merkle_tree[0][n + 1], "\n\t生成的Hash值:", hash_value)
    n = n // 2
    j += 1

    #查找兄弟结点哈希值，并生成新的哈希值
    while j < h:
        L = len(merkle_tree[j])
        #结点数为奇数，且n是最后一个节点
        if L % 2 == 1 and L - 1 == n:
            print("第", j + 1, "层的Hash值:", hash_value)
        elif n % 2 == 1:
            hash_value = hash_node(merkle_tree[j][n - 1] + hash_value, hash_function)
            print("第", j + 1, "层的查找值:", merkle_tree[j][n - 1], "\n\t生成的Hash值:", hash_value)
        elif n % 2 == 0:
            hash_value = hash_node(hash_value + merkle_tree[j][n + 1], hash_function)
            print("第", j + 1, "层的查找值:", merkle_tree[j][n + 1], "\n\t生成的Hash值:", hash_value)
        n = n // 2
        j += 1
    print('\n根结点哈希值:', merkle_tree[h][0])
    if hash_value == merkle_tree[h][0]:
        print("结点", leaf, "在Merkle树中")
    else:
        print("结点", leaf, "不在Merkle树中，或者是序号错误")

if __name__ == '__main__':
    # 奇数
    # lst = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    # 偶数
    # lst = ['a', 'b', 'c', 'd', 'e', 'f']
    #大小为10w的测试集
    lst = []
    for i in range(100000):
        lst.append(str(i))
    start_time = time.time()
    merkle_tree, h = Create_Merkle_Tree(lst)
    Show_Merkle_Tree(merkle_tree, h)
    end_time = time.time()
    print("生成Merkle树所用的时间:", end_time - start_time, "s")
    leaf = input("输入结点：")
    p = int(input("输入结点的序号："))
    #当结点序号对应的结点与输入的结点相同时，查找成功
    #当二者不相同或结点不存在时，查找失败

    start_time = time.time()
    Audit_Proof(merkle_tree, h, p, leaf)
    end_time = time.time()
    print("查找所用时间为：", end_time - start_time, "s")
