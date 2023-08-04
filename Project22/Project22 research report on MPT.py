import hashlib
#定义branch分支结点类
class Branch_node:
    def __init__(self):
        #十六进制编码的16种字符
        #children字典中的value作为branch表的终止符
        #同时也记录当前extension结点的状态，
        #未更新hash值时，默认为False
        self.type = 'branch'
        self.children = {'0': None, '1': None, '2': None, '3': None, '4': None,
                         '5': None, '6': None, '7': None, '8': None, '9': None,
                         'a': None, 'b': None, 'c': None, 'd': None, 'e': None,
                         'f': None,'value': False}
#定义extension拓展结点类
class Extension_node:
    def __init__(self):
        self.type = 'extension'
        self.key = None
        #把branch分支结点作为extension拓展结点的组成元素
        #对外只有extension和leaf两种类型的结点
        self.value = Branch_node()
        self.prefix = None
        #结点的hash
        self.node_hash = None
        #结点下数据的hash
        self.node_value = None
        
#定义leaf叶子结点类
class Leaf_node:
    def __init__(self):
        self.type = 'leaf'
        self.key_end = None
        self.value = None
        self.prefix = None
        #结点的hash
        self.node_value = None
        #结点下数据的hash
        self.node_hash = None
        
#定义MPT树类，包括如下操作：
#1.创建新结点；
#2.向前添加extension拓展结点；
#3.向后添加extension拓展结点；
#4.创建叶子结点；
#5.创建拓展结点；
#6.获取差异值索引；
#7.遍历MPT树查询；
#8.打印MPT树；
#9.更新MPT树；
#10.删除结点；
#11.增加；
#12.删除；
#13.修改；
#14.查找；
#15.抛弃所有子结点的value；
#16.抛弃整棵树的value
class Tree:
    def __init__(self, tree=None):
        #构建对MPT树
        if tree is not None:
            self.root = tree
        else:#为结点创建新的extension拓展结点
            self.root = self.make_extension()
            #默认root作为根结点prefix
            self.root.prefix = 'root'
            #定义MPT树的value、hash
            self.value = None
            self.hash = None
    #创建新结点
    def add_node(self, node, key, value):
        #若父结点是root
        if node.prefix == 'root':
            #且若父结点root下的branch分支结点是空的，即可直接插入（默认key[0]）
            if self.root.value.children[key[0]] is None:
                #key[1::]是后续传递的new_key值
                #即去掉共同前缀的剩余部分作为下一步索引的前缀值
                self.root.value.children[key[0]] = self.make_leaf(key[1::], key[1::], value)
                #插入新的leaf叶子结点后，结点数据发生改变，更新结点状态
                node.value.children['value'] = False
                return
            #否则父结点root下branch表发生冲突，将冲突的结点位置作为参数进行递归
            else:
                self.root.value.children[key[0]] = self.add_node(self.root.value.children[key[0]],
                                                                 key[1::], value)
                return
        father = node
        #把key值与父结点的前缀字符比较，index作为在当前extension拓展结点定位branch分支表位置的索引
        index = self.diff(father, key)
        #共同的前缀
        prefix = key[:index:]
        #去除（branch分支索引）共同前缀后的剩余字符
        new_key = key[index::]
        #若相同字符数不等于共同前缀长度
        #则代表新结点与father结点没有共同前缀，产生冲突
        if index != len(father.prefix) and index < len(father.prefix):
            #extension扩展结点产生冲突
            if father.type == 'extension':
                #向前创建新的extension拓展结点以解决冲突
                return self.pre_extension(father, prefix, new_key, index, value)
            #leaf叶子结点产生冲突
            elif father.type == 'leaf':
                #向后创建新的extension拓展结点以解决冲突
                return self.pro_extension(father, prefix, new_key, index, value)
        #否则就无冲突发生，进入拓展的branch分支结点中向下遍历
        else:
            #判断extension拓展结点下的branch分支结点对应key的value是否为空
            if father.value.children[key[index]] is None:
                #若为空则添加leaf叶子结点
                father.value.children[key[index]] = self.make_leaf(key[index + 1::], key[index])
                #插入新的leaf叶子结点后，结点数据发生改变，更新结点状态
                father.value.children['value'] = False
                return father
            else:
                #若非空，则发生字符表冲突，向下递归延展extension拓展结点
                father = self.add_node(father.value.children[key[index]], new_key, value)
                return father
    #解决extension扩展结点与leaf叶子结点的冲突，向前添加extension拓展结点
    def pre_extension(self, node, prefix, key, index, value):
        node_new_prefix = node.prefix[index + 1::] #共同前缀
        #创建新的extension拓展结点
        tmp_node = self.make_extension()
        tmp_node.prefix = prefix#写入共同前缀
        #将旧extension拓展结点插入branch分支表中
        tmp_node.value.children[node.prefix[index]] = node
        #修改旧extension拓展结点的共同前缀
        tmp_node.value.children[node.prefix[index]].prefix = node_new_prefix
        #插入新leaf叶子结点
        tmp_node.value.children[key[0]] = self.make_leaf(key[1::], key[0], value)
        #返回新extension拓展结点
        return tmp_node
    #为解决leaf叶子结点与leaf叶子结点的冲突，向后添加extension拓展结点
    def pro_extension(self, node, prefix, key, index, value):
        leaf = node
        #创建新extension拓展结点
        tmp_node = self.make_extension()
        tmp_node.prefix = prefix#写入共同前缀
        #把旧leaf叶子结点插入branch分支表中
        tmp_node.value.children[leaf.key_end[index]] = leaf
        #产生共同前缀，leaf叶子结点的key_end发生改变
        tmp_node.value.children[leaf.key_end[index]].key_end = leaf.key_end[index + 1::]
        #插入新leaf叶子结点
        tmp_node.value.children[key[0]] = self.make_leaf(key[1::], key[0], value)
        #返回新extension拓展结点
        return tmp_node
    #创建leaf叶子结点
    def make_leaf(self, key, profix, value):
        #初始化
        tmp_node = Leaf_node()
        tmp_node.key_end = key
        tmp_node.prefix = profix
        #添加leaf叶子结点的值和hash
        tmp_node.value = value
        #对value进行hash
        tmp_node.node_value = hashlib.sha256(value.encode('utf-8')).hexdigest()
        #对整个结点进行hash，要在数据hash操作后进行
        tmp_node.node_hash = hashlib.sha256(str(tmp_node).encode('utf-8')).hexdigest()
        #返回创建的leaf叶子结点
        return tmp_node
    #创建extension拓展结点
    def make_extension(self):
        #直接创建
        tmp_node = Extension_node()
        return tmp_node
    #获取差异值索引
    def diff(self, node, key):
        #将遍历长度定为key和node.prefix中长度较小的那一个，避免溢出
        if len(key) < len(node.prefix):
            lenth = len(key)
        else:
            lenth = len(node.prefix)
        count = 0
        while count < lenth: #遍历
            #如果遍历到有差异的地方，则返回差异的索引，否则继续遍历
            if node.prefix[count] != key[count]:
                return count
            count += 1
        return count

    #遍历MPT树
    def traverse_search(self, node, index):
        #返回的结点的索引
        result_node = None
        #遍历当前extension拓展结点的branch分支表
        for key in node.value.children:
            #若检测终止标志value，则终止
            if key == 'value':
                break
            #若检测到空值，则继续遍历
            if node.value.children[key] is None:
                continue
            #若检测到leaf叶子结点，就对比key_end和索引值
            if node.value.children[key].type == 'leaf':
                #若匹配
                if index[1::] == node.value.children[key].key_end:
                    #返回该结点，并结束遍历
                    result_node = node.value.children[key]
                    break
                #否则继续检测
                else:
                    continue
            #若检测到extension扩展结点，则进入该结点的branch分支表向下索引
            elif node.value.children[key].type == 'extension':
                #记录去除该extension拓展结点的共同前缀后剩余的索引值
                short_key = index[len(node.value.children[key].prefix) + 1::]
                #递归向下索引
                result_node = self.traverse_search(node.value.children[key], short_key)
                #若检测到不为空的结点
                if result_node is not None:
                    #返回该结点，结束遍历
                    break
                #否则，继续检测
                else:
                    continue
        #返回检测到的结点的索引
        return result_node
    #打印MPT树：遍历MPT树，在遍历期间打印遇到的非空结点信息
    def print_all(self, node):
        print('extension of prefix:', node.prefix)
        #遍历当前extension拓展结点的branch分支表
        for key in node.value.children:
            #若检测终止标志value，终止
            if key == 'value':
                break
            #若检测到空值，继续遍历
            if node.value.children[key] is None:
                continue
            #若检测到leaf叶子结点，则打印branch分支结点和key_end
            if node.value.children[key].type == 'leaf':
                print('branch:', key)
                print('leaf of key_end:', node.value.children[key].key_end)
            #若检测到extension扩展结点，则打印branch分支表，并递归遍历打印所有的非空结点信息
            elif node.value.children[key].type == 'extension':
                print('branch:', key)
                self.print_all(node.value.children[key])
    #更新MPT树：查询之前需要进行更新
    #即遍历MPT树，自下向上对每个extension扩展结点的value和hash进行更新
    def update_tree(self, node):
        #临时string，用于聚合extension扩展结点下branch分支表中非空结点的value值
        #extension扩展结点的value值产生自对聚合结果的hash，即该临时string的hash
        tmp_str = ''
        #当前结点状态为True，已更新，则直接返回当前值
        if node.value.children['value']:
            return node.node_value
        #否则遍历结点
        for key in node.value.children:
            #若检测终止标志value，则终止
            if key == 'value':
                break
            #若检测到空值，则继续遍历
            if node.value.children[key] is None:
                continue
            #若检测到leaf叶子结点，则聚合leaf叶子结点
            if node.value.children[key].type == 'leaf':
                tmp_str = tmp_str + node.value.children[key].node_value
            #若检测到extension扩展结点，则递归遍历聚合extension扩展结点
            elif node.value.children[key].type == 'extension':
                tmp_str = tmp_str + self.update_tree(node.value.children[key])
        #修改结点状态为True
        node.value.children['value'] = True
        #利用聚合的value值更新结点的value和hash值
        node.node_value = hashlib.sha256(tmp_str.encode()).hexdigest()
        node.node_hash = hashlib.sha256(str(node).encode()).hexdigest()
        #打印结点的prefix和value
        print('prefix:', node.prefix)
        print('node_value:', node.node_value)
        #返回更新的结点
        return node.node_value
    #删除结点：通过遍历找到需要删除的结点
    #将需要删除的结点对应的branch分支的位置设为None
    def delete_node(self, node, hash):
        #进行遍历
        for key in node.value.children:
            #若检测终止标志value，则终止
            if key == 'value':
                break
            #若检测到空值，则继续遍历
            if node.value.children[key] is None:
                continue
            #若检测到leaf叶子结点，则对比key_end和索引值
            if node.value.children[key].type == 'leaf':
                #若匹配，则删除该结点，并将其重置为None，并返回True
                if hash[1::] == node.value.children[key].key_end:
                    del node.value.children[key]
                    node.value.children[key] = None
                    return True
                #否则继续遍历
                else:
                    continue
            #若检测到extension扩展结点，记录去除该extension拓展结点的共同前缀后剩余的索引值
            elif node.value.children[key].type == 'extension':
                short_hash = hash[len(node.value.children[key].prefix) + 1::]
                #若剩余的索引值为空
                if short_hash == '':
                    #删除该结点
                    del node.value.children[key]
                    #将其重置为None
                    node.value.children[key] = None
                    print('delete')
                    #返回True
                    return True
                #否则，继续递归遍历，直到找到剩余的索引值为空的结点并删除
                #并将其重置为None，并返回True
                elif self.delete_node(node.value.children[key], short_hash):
                    return True
    #增加操作：后续需要将update_tree精准到结点上
    #而不是每次都从root开始，最后再对MPT树进行更新
    def add(self, key, value, node=None):
        #若结点是空的，进行构建
        if node is None:
            node = self.root
        #进行递归增
        self.add_node(node, key, value)
        #更新树
        self.update_tree(self.root)

    #删除操作：最后对MPT树进行更新
    def delete(self, key):
        print('delete from str')
        #进行递归删
        self.delete_node(self.root, key)
        #更新树
        self.update_tree(self.root)

    #修改操作：修改leaf叶子结点的value值，最后再对MPT树进行更新
    def update(self, index, value):
        #若是字符串类型
        if type(index) == str:
            #则进行MPT树的遍历查询
            tmp_node = self.traverse_search(self.root, index)
            #修改结点的value值
            tmp_node.value = value
            #对value进行hash
            tmp_node.node_value = hashlib.sha256(value.encode('utf-8')).hexdigest()
            #对整个结点进行hash
            tmp_node.node_hash = hashlib.sha256(str(tmp_node).encode('utf-8')).hexdigest()
        #若不是字符串类型
        else:
            #直接修改value值
            index.value = value
            #对value进行hash
            index.node_value = hashlib.sha256(value.encode('utf-8')).hexdigest()
            #对整个结点进行hash
            index.node_hash = hashlib.sha256(str(index).encode('utf-8')).hexdigest()
        #更新树
        self.update_tree(self.root)

    #查找操作：提供接口
    def search(self, index):
        #若是字符串类型
        if type(index) == str:
            #进行MPT的遍历查询
            return self.traverse_search(self.root, index).value
        #若不是字符串类型
        else:
            #直接返回value值
            return index.value

    #抛弃所有leaf叶子结点的value：遍历整个MPT树
    #删除leaf叶子结点的value并设置为None
    def drop_all_value(self, node=None):
        #若结点是空的，进行构建
        if node is None:
            node = self.root
        #遍历
        for key in node.value.children:
            #若检测终止标志value，终止
            if key == 'value':
                break
            #若检测到空值，继续遍历
            if node.value.children[key] is None:
                continue
            #若检测到leaf叶子结点，则直接删除value
            if node.value.children[key].type == 'leaf':
                del node.value.children[key].value
                #把value设置为None
                node.value.children[key].value = None
            #若检测到extension扩展结点，则递归遍历直到叶子结点
            elif node.value.children[key].type == 'extension':
                self.drop_all_value(node.value.children[key])

    #抛弃整棵树的value：保留root根结点的value和hash
    def drop_tree(self):
        #对要进行操作的树进行跟更新
        self.update_tree(self.root)
        #把value设置为根结点root的value
        self.value = self.root.node_value
        #把hash设置为根结点root的hash
        self.hash = self.root.node_hash
        #删掉原来树的根结点
        del self.root
        #设置为None
        self.root = None
