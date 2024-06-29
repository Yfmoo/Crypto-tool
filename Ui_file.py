# -*- coding: utf-8 -*-
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(917, 705)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout()
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.label_9 = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(18)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.verticalLayout_7.addWidget(self.label_9)
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout.addWidget(self.label_3)
        self.lineEdit = QtWidgets.QLineEdit(Form)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout.addWidget(self.pushButton)
        self.verticalLayout_5.addLayout(self.horizontalLayout)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_3.addWidget(self.label_4)
        self.lineEdit_3 = QtWidgets.QLineEdit(Form)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.horizontalLayout_3.addWidget(self.lineEdit_3)
        self.pushButton_3 = QtWidgets.QPushButton(Form)
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout_3.addWidget(self.pushButton_3)
        self.verticalLayout_5.addLayout(self.horizontalLayout_3)
        self.pushButton_5 = QtWidgets.QPushButton(Form)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.pushButton_5.setFont(font)
        self.pushButton_5.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.pushButton_5.setObjectName("pushButton_5")
        self.verticalLayout_5.addWidget(self.pushButton_5)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_5 = QtWidgets.QLabel(Form)
        self.label_5.setObjectName("label_5")
        self.verticalLayout.addWidget(self.label_5)
        self.textEdit = QtWidgets.QTextEdit(Form)
        self.textEdit.setFrameShape(QtWidgets.QFrame.Box)
        self.textEdit.setLineWidth(2)
        self.textEdit.setLineWrapMode(QtWidgets.QTextEdit.WidgetWidth)
        self.textEdit.setLineWrapColumnOrWidth(0)
        self.textEdit.setObjectName("textEdit")
        self.verticalLayout.addWidget(self.textEdit)
        self.horizontalLayout_5.addLayout(self.verticalLayout)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_6 = QtWidgets.QLabel(Form)
        self.label_6.setObjectName("label_6")
        self.verticalLayout_2.addWidget(self.label_6)
        self.textEdit_3 = QtWidgets.QTextEdit(Form)
        self.textEdit_3.setFrameShape(QtWidgets.QFrame.Box)
        self.textEdit_3.setLineWidth(2)
        self.textEdit_3.setObjectName("textEdit_3")
        self.verticalLayout_2.addWidget(self.textEdit_3)
        self.horizontalLayout_5.addLayout(self.verticalLayout_2)
        self.verticalLayout_5.addLayout(self.horizontalLayout_5)
        self.pushButton_7 = QtWidgets.QPushButton(Form)
        self.pushButton_7.setStyleSheet("background-color: rgb(0, 255, 255);")
        self.pushButton_7.setObjectName("pushButton_7")
        self.verticalLayout_5.addWidget(self.pushButton_7)
        self.verticalLayout_7.addLayout(self.verticalLayout_5)
        self.horizontalLayout_7.addLayout(self.verticalLayout_7)
        self.verticalLayout_8 = QtWidgets.QVBoxLayout()
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.label_2 = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(18)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_8.addWidget(self.label_2)
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_10 = QtWidgets.QLabel(Form)
        self.label_10.setObjectName("label_10")
        self.horizontalLayout_2.addWidget(self.label_10)
        self.lineEdit_2 = QtWidgets.QLineEdit(Form)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.horizontalLayout_2.addWidget(self.lineEdit_2)
        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_2.addWidget(self.pushButton_2)
        self.verticalLayout_6.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.label_11 = QtWidgets.QLabel(Form)
        self.label_11.setObjectName("label_11")
        self.horizontalLayout_4.addWidget(self.label_11)
        self.lineEdit_4 = QtWidgets.QLineEdit(Form)
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.horizontalLayout_4.addWidget(self.lineEdit_4)
        self.pushButton_4 = QtWidgets.QPushButton(Form)
        self.pushButton_4.setObjectName("pushButton_4")
        self.horizontalLayout_4.addWidget(self.pushButton_4)
        self.verticalLayout_6.addLayout(self.horizontalLayout_4)
        self.pushButton_6 = QtWidgets.QPushButton(Form)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.pushButton_6.setFont(font)
        self.pushButton_6.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.pushButton_6.setObjectName("pushButton_6")
        self.verticalLayout_6.addWidget(self.pushButton_6)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_7 = QtWidgets.QLabel(Form)
        self.label_7.setObjectName("label_7")
        self.verticalLayout_3.addWidget(self.label_7)
        self.textEdit_2 = QtWidgets.QTextEdit(Form)
        self.textEdit_2.setFrameShape(QtWidgets.QFrame.Box)
        self.textEdit_2.setLineWidth(2)
        self.textEdit_2.setObjectName("textEdit_2")
        self.verticalLayout_3.addWidget(self.textEdit_2)
        self.horizontalLayout_6.addLayout(self.verticalLayout_3)
        self.verticalLayout_4 = QtWidgets.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label_8 = QtWidgets.QLabel(Form)
        self.label_8.setObjectName("label_8")
        self.verticalLayout_4.addWidget(self.label_8)
        self.textEdit_4 = QtWidgets.QTextEdit(Form)
        self.textEdit_4.setFrameShape(QtWidgets.QFrame.Box)
        self.textEdit_4.setLineWidth(2)
        self.textEdit_4.setObjectName("textEdit_4")
        self.verticalLayout_4.addWidget(self.textEdit_4)
        self.horizontalLayout_6.addLayout(self.verticalLayout_4)
        self.verticalLayout_6.addLayout(self.horizontalLayout_6)
        self.pushButton_8 = QtWidgets.QPushButton(Form)
        self.pushButton_8.setStyleSheet("background-color: rgb(0, 255, 255);")
        self.pushButton_8.setObjectName("pushButton_8")
        self.verticalLayout_6.addWidget(self.pushButton_8)
        self.verticalLayout_8.addLayout(self.verticalLayout_6)
        self.horizontalLayout_7.addLayout(self.verticalLayout_8)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)


        """使用Fernet的AES加密算法对文件进行加解密"""
        self.pushButton.clicked.connect(self.chooseEnFile)
        self.pushButton_2.clicked.connect(self.chooseDeFile)
        self.pushButton_3.clicked.connect(self.generateEnKey)
        self.pushButton_4.clicked.connect(self.generateDeKey)
        self.pushButton_5.clicked.connect(self.encrypt)
        self.pushButton_6.clicked.connect(self.decrypt)
        self.pushButton_7.clicked.connect(self.exportCipher)
        self.pushButton_8.clicked.connect(self.exportPlain)


    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label_9.setText(_translate("Form", "加密"))
        self.label_3.setText(_translate("Form", "选择明文文件"))
        self.pushButton.setText(_translate("Form", "浏览"))
        self.label_4.setText(_translate("Form", "加密密钥"))
        self.pushButton_3.setText(_translate("Form", "生成"))
        self.pushButton_5.setText(_translate("Form", "加密"))
        self.label_5.setText(_translate("Form", "明文"))
        self.label_6.setText(_translate("Form", "密文"))
        self.pushButton_7.setText(_translate("Form", "导出密文"))
        self.label_2.setText(_translate("Form", "解密"))
        self.label_10.setText(_translate("Form", "选择密文文件"))
        self.pushButton_2.setText(_translate("Form", "浏览"))
        self.label_11.setText(_translate("Form", "解密密钥"))
        self.pushButton_4.setText(_translate("Form", "生成"))
        self.pushButton_6.setText(_translate("Form", "解密"))
        self.label_7.setText(_translate("Form", "密文"))
        self.label_8.setText(_translate("Form", "明文l"))
        self.pushButton_8.setText(_translate("Form", "导出明文"))

    def chooseEnFile(self):
        try:
            file_name, _ = QFileDialog.getOpenFileName(None, "选择文件", "", "All Files (*)")
            if file_name:
                self.lineEdit.setText(file_name)
        except Exception as e:
            QMessageBox.critical(None, "错误", f"选择文件失败: {e}")

    def chooseDeFile(self):
        try:
            file_name, _ = QFileDialog.getOpenFileName(None, "选择文件", "", "All Files (*)")
            if file_name:
                self.lineEdit_2.setText(file_name)
        except Exception as e:
            QMessageBox.critical(None, "错误", f"选择文件失败: {e}")

    def generateEnKey(self):
        try:
            key = Fernet.generate_key()
            self.lineEdit_3.setText(key.decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"生成加密密钥失败: {e}")

    def generateDeKey(self):
        try:
            key = Fernet.generate_key()
            self.lineEdit_4.setText(key.decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"生成解密密钥失败: {e}")

    def encrypt(self):
        try:
            file_path = self.lineEdit.text()
            key = self.lineEdit_3.text().encode()

            with open(file_path, 'rb') as file:
                data = file.read()

            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)

            self.textEdit.setText(data.decode(errors='ignore'))
            self.textEdit_3.setText(base64.urlsafe_b64encode(encrypted_data).decode())
        except Exception as e:
            QMessageBox.critical(None, "错误", f"加密失败: {e}")

    def decrypt(self):
        try:
            file_path = self.lineEdit_2.text()
            key = self.lineEdit_4.text().encode()

            with open(file_path, 'rb') as file:
                data = file.read()

            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(base64.urlsafe_b64decode(data))

            self.textEdit_2.setText(data.decode(errors='ignore'))
            self.textEdit_4.setText(decrypted_data.decode(errors='ignore'))
        except Exception as e:
            QMessageBox.critical(None, "错误", f"解密失败: {e}")

    def exportCipher(self):
        try:
            file_name, _ = QFileDialog.getSaveFileName(None, "导出密文", "", "Text Files (*.txt);;All Files (*)")
            if file_name:
                with open(file_name, 'w') as file:
                    file.write(self.textEdit_3.toPlainText())
                QMessageBox.information(None, "成功", "密文已成功导出")
        except Exception as e:
            QMessageBox.critical(None, "错误", f"导出密文失败: {e}")

    def exportPlain(self):
        try:
            file_name, _ = QFileDialog.getSaveFileName(None, "导出明文", "", "Text Files (*.txt);;All Files (*)")
            if file_name:
                with open(file_name, 'w') as file:
                    file.write(self.textEdit_4.toPlainText())
                QMessageBox.information(None, "成功", "明文已成功导出")
        except Exception as e:
            QMessageBox.critical(None, "错误", f"导出明文失败: {e}")

"""if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
"""



