# -*- coding: utf-8 -*-
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox

class Ui_MainWindow(object):
    def __init__(self):
        self.salt = os.urandom(16)
        self.key = None
        self.cipher_suite = None

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
        self.btnEn.setFont(font)
        self.btnEn.setObjectName("btnEn")

        self.btnDe = QtWidgets.QPushButton(self.centralwidget)
        self.btnDe.setGeometry(QtCore.QRect(640, 210, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Agency FB")
        font.setPointSize(12)
        font.setBold(True)
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

        self.btnChooseEnFile.clicked.connect(self.chooseEnFile)
        self.btnChooseDeFile.clicked.connect(self.chooseDeFile)
        self.btnChooseEnKey.clicked.connect(self.generateEnKey)
        self.btnChooseDeKey.clicked.connect(self.generateDeKey)
        self.btnEn.clicked.connect(self.encrypt)
        self.btnDe.clicked.connect(self.decrypt)
        self.btnExport1.clicked.connect(self.exportCipher)
        self.btnExport2.clicked.connect(self.exportPlain)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "选择明文文件："))
        self.label_2.setText(_translate("MainWindow", "加密密钥："))
        self.label_3.setText(_translate("MainWindow", "加密"))
        self.btnChooseEnFile.setText(_translate("MainWindow", "选择"))
        self.btnChooseDeFile.setText(_translate("MainWindow", "选择"))
        self.btnChooseEnKey.setText(_translate("MainWindow", "生成"))
        self.label_6.setText(_translate("MainWindow", "明文"))
        self.label_7.setText(_translate("MainWindow", "密文"))
        self.btnChooseDeKey.setText(_translate("MainWindow", "生成"))
        self.label_4.setText(_translate("MainWindow", "解密"))
        self.label_5.setText(_translate("MainWindow", "解密密钥："))
        self.label_8.setText(_translate("MainWindow", "选择密文文件："))
        self.label_9.setText(_translate("MainWindow", "密文"))
        self.label_10.setText(_translate("MainWindow", "明文"))
        self.btnEn.setText(_translate("MainWindow", "加密"))
        self.btnDe.setText(_translate("MainWindow", "解密"))
        self.btnExport1.setText(_translate("MainWindow", "导出密文"))
        self.btnExport2.setText(_translate("MainWindow", "导出明文"))

    def chooseEnFile(self):
        try:
            file_name, _ = QFileDialog.getOpenFileName(None, "选择文件", "", "All Files (*)")
            if file_name:
                self.txtEnFilePath.setText(file_name)
        except Exception as e:
            QMessageBox.critical(None, "错误", f"选择文件失败: {e}")

    def chooseDeFile(self):
        try:
            file_name, _ = QFileDialog.getOpenFileName(None, "选择文件", "", "All Files (*)")
            if file_name:
                self.txtDeFilePath.setText(file_name)
        except Exception as e:
            QMessageBox.critical(None, "错误", f"选择文件失败: {e}")

    def generateEnKey(self):
        try:
            key = Fernet.generate_key()
            self.txtEnKey.setText(key.decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"生成加密密钥失败: {e}")

    def generateDeKey(self):
        try:
            key = Fernet.generate_key()
            self.txtDeKey.setText(key.decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"生成解密密钥失败: {e}")

    def encrypt(self):
        try:
            file_path = self.txtEnFilePath.toPlainText()
            key = self.txtEnKey.toPlainText().encode()

            with open(file_path, 'rb') as file:
                data = file.read()

            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)

            self.txtPlain1.setText(data.decode(errors='ignore'))
            self.txtCipher1.setText(base64.urlsafe_b64encode(encrypted_data).decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"加密失败: {e}")

    def decrypt(self):
        try:
            file_path = self.txtDeFilePath.toPlainText()
            key = self.txtDeKey.toPlainText().encode()

            with open(file_path, 'rb') as file:
                data = file.read()

            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(base64.urlsafe_b64decode(data))

            self.txtCipher2.setText(data.decode(errors='ignore'))
            self.txtPlain2.setText(decrypted_data.decode(errors='ignore'))
        except Exception as e:
            QMessageBox.critical(None, "错误", f"解密失败: {e}")

    def exportCipher(self):
        try:
            file_name, _ = QFileDialog.getSaveFileName(None, "导出密文", "", "Text Files (*.txt);;All Files (*)")
            if file_name:
                with open(file_name, 'w') as file:
                    file.write(self.txtCipher1.toPlainText())
                QMessageBox.information(None, "成功", "密文已成功导出")
        except Exception as e:
            QMessageBox.critical(None, "错误", f"导出密文失败: {e}")

    def exportPlain(self):
        try:
            file_name, _ = QFileDialog.getSaveFileName(None, "导出明文", "", "Text Files (*.txt);;All Files (*)")
            if file_name:
                with open(file_name, 'w') as file:
                    file.write(self.txtPlain2.toPlainText())
                QMessageBox.information(None, "成功", "明文已成功导出")
        except Exception as e:
            QMessageBox.critical(None, "错误", f"导出明文失败: {e}")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
