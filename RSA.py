# -*- coding: utf-8 -*-

#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!
import os
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog

class Ui_MainWindow(object):
    private_key = None
    public_key = None
    Time = open("time.txt", 'a+')
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(897, 569)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(20, 90, 81, 21))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(40, 160, 54, 12))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(180, 20, 58, 39))
        font = QtGui.QFont()
        font.setFamily("Arial Unicode MS")
        font.setPointSize(22)
        font.setBold(False)
        font.setWeight(50)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.txtPlain1 = QtWidgets.QTextEdit(self.centralwidget)
        self.txtPlain1.setGeometry(QtCore.QRect(40, 270, 171, 231))
        self.txtPlain1.setObjectName("txtPlain1")
        self.btnChooseEnFile = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseEnFile.setGeometry(QtCore.QRect(360, 90, 51, 21))
        self.btnChooseEnFile.setObjectName("btnChooseEnFile")
        self.txtCipher1 = QtWidgets.QTextEdit(self.centralwidget)
        self.txtCipher1.setGeometry(QtCore.QRect(250, 270, 171, 231))
        self.txtCipher1.setObjectName("txtCipher1")
        self.txtCipher2 = QtWidgets.QTextEdit(self.centralwidget)
        self.txtCipher2.setGeometry(QtCore.QRect(490, 270, 171, 231))
        self.txtCipher2.setObjectName("txtCipher2")
        self.txtPlain2 = QtWidgets.QTextEdit(self.centralwidget)
        self.txtPlain2.setGeometry(QtCore.QRect(700, 270, 171, 231))
        self.txtPlain2.setObjectName("txtPlain2")
        self.txtEnFilePath = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnFilePath.setGeometry(QtCore.QRect(110, 80, 241, 41))
        self.txtEnFilePath.setObjectName("txtEnFilePath")
        self.txtEnKey = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnKey.setGeometry(QtCore.QRect(110, 150, 241, 31))
        self.txtEnKey.setObjectName("txtEnKey")
        self.btnChooseEnKey = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseEnKey.setGeometry(QtCore.QRect(360, 150, 51, 21))
        self.btnChooseEnKey.setObjectName("btnChooseEnKey")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(110, 250, 24, 12))
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(300, 250, 72, 12))
        self.label_7.setObjectName("label_7")
        self.btnChooseDeKey = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseDeKey.setGeometry(QtCore.QRect(820, 150, 51, 21))
        self.btnChooseDeKey.setObjectName("btnChooseDeKey")
        self.txtDeKey = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeKey.setGeometry(QtCore.QRect(570, 150, 241, 31))
        self.txtDeKey.setObjectName("txtDeKey")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(640, 20, 58, 39))
        font = QtGui.QFont()
        font.setFamily("Arial Unicode MS")
        font.setPointSize(22)
        font.setBold(False)
        font.setWeight(50)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(500, 160, 60, 12))
        self.label_5.setObjectName("label_5")
        self.txtDeFilePath = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeFilePath.setGeometry(QtCore.QRect(570, 80, 241, 41))
        self.txtDeFilePath.setObjectName("txtDeFilePath")
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(480, 90, 81, 21))
        self.label_8.setObjectName("label_8")
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setGeometry(QtCore.QRect(560, 250, 24, 12))
        self.label_9.setObjectName("label_9")
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setGeometry(QtCore.QRect(750, 250, 72, 12))
        self.label_10.setObjectName("label_10")
        self.btnChooseDeFile = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseDeFile.setGeometry(QtCore.QRect(820, 90, 51, 21))
        self.btnChooseDeFile.setObjectName("btnChooseDeFile")
        self.btnEn = QtWidgets.QPushButton(self.centralwidget)
        self.btnEn.setGeometry(QtCore.QRect(190, 210, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Agency FB")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.btnEn.setFont(font)
        self.btnEn.setObjectName("btnEn")
        self.btnDe = QtWidgets.QPushButton(self.centralwidget)
        self.btnDe.setGeometry(QtCore.QRect(640, 210, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Agency FB")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.btnDe.setFont(font)
        self.btnDe.setObjectName("btnDe")
        self.btnExport1 = QtWidgets.QPushButton(self.centralwidget)
        self.btnExport1.setGeometry(QtCore.QRect(340, 510, 75, 23))
        self.btnExport1.setObjectName("btnExport1")
        self.btnExport2 = QtWidgets.QPushButton(self.centralwidget)
        self.btnExport2.setGeometry(QtCore.QRect(790, 510, 75, 23))
        self.btnExport2.setObjectName("btnExport2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.btnChooseEnFile.clicked.connect(self.chooseEnFile)  # 选择明文文件
        self.btnChooseDeFile.clicked.connect(self.chooseDeFile)  # 选择密文文件
        self.btnChooseEnKey.clicked.connect(self.generateEnKey)  # 选择加密密钥文件
        self.btnChooseDeKey.clicked.connect(self.generateDeKey)  # 选择解密密钥文件
        self.btnEn.clicked.connect(self.encrypt)  # 加密
        self.btnDe.clicked.connect(self.decrypt)  # 解密
        self.btnExport1.clicked.connect(self.exportCipher)  # 导出加密后的明文
        self.btnExport2.clicked.connect(self.exportPlain)  # 导出解密后的密文

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "选择明文文件："))
        self.label_2.setText(_translate("MainWindow", "加密公钥："))
        self.label_3.setText(_translate("MainWindow", "加密"))
        self.btnChooseEnFile.setText(_translate("MainWindow", "浏览"))
        self.btnChooseEnKey.setText(_translate("MainWindow", "浏览"))
        self.label_6.setText(_translate("MainWindow", "明文"))
        self.label_7.setText(_translate("MainWindow", "加密后的明文"))
        self.btnChooseDeKey.setText(_translate("MainWindow", "浏览"))
        self.label_4.setText(_translate("MainWindow", "解密"))
        self.label_5.setText(_translate("MainWindow", "解密私钥："))
        self.label_8.setText(_translate("MainWindow", "选择密文文件："))
        self.label_9.setText(_translate("MainWindow", "密文"))
        self.label_10.setText(_translate("MainWindow", "解密后的密文"))
        self.btnChooseDeFile.setText(_translate("MainWindow", "浏览"))
        self.btnEn.setText(_translate("MainWindow", "加密"))
        self.btnDe.setText(_translate("MainWindow", "解密"))
        self.btnExport1.setText(_translate("MainWindow", "导出文件"))
        self.btnExport2.setText(_translate("MainWindow", "导出文件"))

    # 选择明文文件
    def chooseEnFile(self):
        #打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件", './', "(*.txt)")
        #检测是否选中文件，即fname的长度
        if fname.__len__() != 0:
            self.txtEnFilePath.setText(str(fname))

    # 选择密文文件
    def chooseDeFile(self):
        #打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件", './', "(*.txt)")
        if fname.__len__() != 0:
            self.txtDeFilePath.setText(str(fname))

    # 选择加密密钥文件
    def generateEnKey(self):
        #打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件", './', "(*.txt)")
        if fname.__len__() != 0:
            #PEM文件路径显示在文本框内
            self.txtEnKey.setText(str(fname))

    # 选择解密密钥文件
    def generateDeKey(self):
        #打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件", './', "(*.txt)")
        if fname.__len__() != 0:
            #PEM文件路径显示在文本框内
            self.txtDeKey.setText(str(fname))
            
    # 加密
    def encrypt(self):
        fname = self.txtEnFilePath.toPlainText()
        if fname.__len__() != 0:
            #读取明文文件
            fp = open(str(fname))
            plain = fp.read()
            #将明文显示在左侧文本框内
            self.txtPlain1.setText(plain)
            fp.close()

            key_file =  open(self.txtEnKey.toPlainText(), "rb")
            try:
                # 获得公钥
                self.public_key = serialization.load_pem_public_key(
                        key_file.read(),backend=default_backend() )
                plain = plain.encode()
                length = len(plain)
                default_length = 117  # 分组长度1024bit 单次加密串的长度最大为 (key_size/8)-11 1024/8 - 11 =117
                cipher_text = [] #记录每个分组加密后的结果
                offset = 0  #记录分组加密的起始下标
                #加密
                enSt = time.time()
                while length - offset > 0:
                    if length - offset > default_length:
                        cipher_text.append(self.public_key.encrypt(plain[offset:offset+default_length],
                                             padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None
                                                )
                                             )
                                           )
                    else:
                        cipher_text.append(self.public_key.encrypt(plain[offset:],
                                                                   padding.OAEP(
                                                                       mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                       algorithm=hashes.SHA1(),
                                                                       label=None
                                                                   )
                                                                   )
                                           )
                    offset += default_length # 分组加密的起始下标要每次自增default_length
                enEd = time.time()
                self.Time.write("加密时间："+str((enEd-enSt)*1000)+"ms\n")
                l = len(cipher_text)
                c = b'' # 因为加密后的密文格式为二进制
                for i in range(0,l):
                    c += cipher_text[i]
                #加密后的密文转化为字符串用于显示在文本框内
                c = base64.urlsafe_b64encode(c).decode()
                self.txtCipher1.setText(c)
            except Exception as e:
                self.txtCipher1.setText("提示：加密密钥格式错误！加密失败!")

    # 解密
    def decrypt(self):
        #解密过程同加密类似
        fname = self.txtDeFilePath.toPlainText()
        if fname.__len__() != 0:
            #读取密文文件
            fp = open(str(fname))
            #将密文显示在右侧密文文本框内
            self.txtCipher2.setText(fp.read())
            fp.close()
            #从PEM文件导入RSAPrivateKey对象，然后通过RSAPrivateKey获得对应的公钥
            key_file =  open(self.txtDeKey.toPlainText(), "rb")
            try:
                self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )
                #将密文转为字节串
                cipher = self.txtCipher2.toPlainText()
                cipher = base64.urlsafe_b64decode(cipher)
                length = len(cipher)
                default_length = 256  # 分组长度1024bit
                plain_text = [] # 存放每个分组解密后的明文
                offset = 0
                deSt = time.time()
                while length - offset > 0:
                    if length - offset > default_length:
                        plain_text.append(self.private_key.decrypt(cipher[offset:offset+default_length],
                                             padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None
                                                )
                                             )
                                           )
                    else:
                        plain_text.append(self.private_key.decrypt(cipher[offset:],
                                                                   padding.OAEP(
                                                                       mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                       algorithm=hashes.SHA1(),
                                                                       label=None
                                                                   )
                                                                   )
                                           )
                    offset += default_length
                deEd = time.time() 
                self.Time.write("解密时间："+str((deEd-deSt)*1000)+"ms\n")
                l = len(plain_text)
                c = ""  # 明文为字符串格式
                for i in range(0, l):
                    c += plain_text[i].decode()
                self.txtPlain2.setText(c)
            except Exception as e:
                self.txtPlain2.setText("提示：解密密钥错误！解密失败!")

    # 导出加密后的明文
    def exportCipher(self):
        #打开保存文件对话框，该函数返回一个二元组，其中第一个对象为文件的绝对路径
        fileName, ok = QFileDialog.getSaveFileName(None, "文件保存")
        result = self.txtCipher1.toPlainText()
        if str(fileName).__len__() != 0:
            #打开文件，如果文件不存在则新建一个文件，'w'设置方式为write
            fp = open(fileName, 'w')
            #向文件写入
            fp.write(result)

    # 导出解密后的密文
    def exportPlain(self):
        #打开保存文件对话框，该函数返回一个二元组，其中第一个对象为文件的绝对路径
        fileName, ok = QFileDialog.getSaveFileName(None, "文件保存")
        result = self.txtPlain2.toPlainText()
        if str(fileName).__len__() != 0:
            #打开文件，如果文件不存在则新建一个文件，'w'设置方式为write
            fp = open(fileName, 'w')
            #向文件写入
            fp.write(result)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())


