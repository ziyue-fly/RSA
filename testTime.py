import os
import base64
import time
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


#加密时间
en = open("enTime.txt", 'a+')
#解密时间
de = open("deTime.txt", 'a+')
#密文
fp1 = open("multi-cases-cipher.txt", "a+")
#解密后的明文
fp2 = open("multi-cases-decry.txt", "a+")
cnt = 0
#总时间/平均时间
totEn = 0
totDe = 0
aver1 = 0
aver2 = 0

path = "data" #文件夹目录
files= os.listdir(path) #得到文件夹下的所有文件名称
plainlist = []
for file in files: #遍历文件夹
     if not os.path.isdir(file): #判断是否是文件夹，不是文件夹才打开
          f = open(path+"/"+file); #打开文件
          s = f.read()
          plainlist.append(s) #每个文件的文本存到list中

for plain in plainlist:
    key_file =  open("public_key1.txt", "rb")
    try:                
        public_key = serialization.load_pem_public_key(
                    key_file.read(),backend=default_backend() )
        plain = plain.encode()
        length = len(plain)
        default_length = 117  # 分组长度1024bit 单次加密串的长度最大为 (key_size/8)-11 1024/8 - 11 =117
        cipher_text = []  # 记录每个分组加密后的结果
        offset = 0  # 记录分组加密的起始下标
        # 加密
        enSt = time.time() #开始时间
        while length - offset > 0:
            if length - offset > default_length:
                cipher_text.append(public_key.encrypt(plain[offset:offset + default_length],
                                                           padding.OAEP(
                                                               mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                               algorithm=hashes.SHA1(),
                                                               label=None
                                                           )
                                        )
                                   )
            else:
                cipher_text.append(public_key.encrypt(plain[offset:],
                                                           padding.OAEP(
                                                               mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                               algorithm=hashes.SHA1(),
                                                               label=None
                                                           )
                                                      )
                                   )
            offset += default_length  # 分组加密的起始下标要每次自增default_length
        enEd = time.time()  # 结束时间
        l = len(cipher_text)
        cipher = b''  # 因为加密后的密文格式为二进制
        for i in range(0, l):
            cipher += cipher_text[i]
        # 加密后的密文写入文件
        fp1.write(base64.urlsafe_b64encode(cipher).decode()+"\n")
        cnt += 1
        en.write(str((enEd-enSt)*1000)+" "+str(cnt)+"\n")
        totEn += (enEd-enSt)*1000
    except Exception as e:
        pass        
    key_file =  open("private_key1.txt", "rb")

    private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )
    try:
        length = len(cipher)
        default_length = 256  # 分组长度1024bit
        plain_text = [] # 存放每个分组解密后的明文
        offset = 0
        deSt = time.time() #开始时间
        while length - offset > 0:
            if length - offset > default_length:
                plain_text.append(private_key.decrypt(cipher[offset:offset+default_length],
                                             padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None
                                                )
                                             )
                                           )
            else:
                plain_text.append(private_key.decrypt(cipher[offset:],
                                                                   padding.OAEP(
                                                                       mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                       algorithm=hashes.SHA1(),
                                                                       label=None
                                                                   )
                                                                   )
                                           )
            offset += default_length 
        deEd = time.time() #结束时间
        de.write(str((deEd-deSt)*1000)+" "+str(cnt)+"\n") #时间差写入文件
        totDe += (deEd-deSt)*1000
        l = len(plain_text)
        plain = ""  # 明文为字符串格式
        for i in range(0, l):
            plain += plain_text[i].decode()
        # 解密后的明文写入文件
        fp2.write(plain+"\n")
    except Exception as e:
        pass  

aver1 = totEn/1000
aver2 = totDe/1000
print("平均加密时间 = ", aver1, "ms\n平均解密时间 = ", aver2, "ms\n")


