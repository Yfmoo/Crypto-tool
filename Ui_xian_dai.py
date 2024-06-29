from PyQt5 import QtCore, QtGui, QtWidgets
from Crypto.Cipher import AES, DES3, DES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import hashlib

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(888, 593)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.treeWidget = QtWidgets.QTreeWidget(Form)
        self.treeWidget.setObjectName("treeWidget")
        
        # Adding items to treeWidget
        algorithms = ["AES", "DES", "3DES", "MD5", "SM2", "SH3", "SHA-512", "SHA-384", "SHA-256"]
        for alg in algorithms:
            QtWidgets.QTreeWidgetItem(self.treeWidget, [alg])
        
        self.horizontalLayout_2.addWidget(self.treeWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.plainTextEdit_3 = QtWidgets.QPlainTextEdit(Form)
        self.plainTextEdit_3.setStyleSheet("background-color: rgb(255, 255, 255);\n"
                                           "color: rgb(0, 0, 0);\n"
                                           "border-color: rgb(0, 170, 255);\n"
                                           "gridline-color: rgb(0, 170, 255);\n"
                                           "border-top-color: rgb(0, 170, 255);")
        self.plainTextEdit_3.setFrameShape(QtWidgets.QFrame.Box)
        self.plainTextEdit_3.setLineWidth(2)
        self.plainTextEdit_3.setMidLineWidth(0)
        self.plainTextEdit_3.setBackgroundVisible(False)
        self.plainTextEdit_3.setObjectName("plainTextEdit_3")
        self.horizontalLayout.addWidget(self.plainTextEdit_3)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.pushButton_3 = QtWidgets.QPushButton(Form)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setStyleSheet("color: rgb(255, 0, 0);\n"
                                        "background-color: rgb(0, 170, 255);")
        self.pushButton_3.setObjectName("pushButton_3")
        self.verticalLayout_2.addWidget(self.pushButton_3)
        self.pushButton_4 = QtWidgets.QPushButton(Form)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.pushButton_4.setFont(font)
        self.pushButton_4.setStyleSheet("background-color: rgb(0, 170, 255);\n"
                                        "color: rgb(255, 0, 0);")
        self.pushButton_4.setObjectName("pushButton_4")
        self.verticalLayout_2.addWidget(self.pushButton_4)
        self.lineEdit_2 = QtWidgets.QLineEdit(Form)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setStyleSheet("color: rgb(255, 0, 0);")
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.verticalLayout_2.addWidget(self.lineEdit_2)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        self.plainTextEdit_4 = QtWidgets.QPlainTextEdit(Form)
        self.plainTextEdit_4.setStyleSheet("background-color: rgb(255, 255, 255);\n"
                                           "color: rgb(0, 0, 0);")
        self.plainTextEdit_4.setFrameShape(QtWidgets.QFrame.Box)
        self.plainTextEdit_4.setLineWidth(2)
        self.plainTextEdit_4.setObjectName("plainTextEdit_4")
        self.horizontalLayout.addWidget(self.plainTextEdit_4)
        self.horizontalLayout.setStretch(0, 4)
        self.horizontalLayout.setStretch(1, 1)
        self.horizontalLayout.setStretch(2, 4)
        self.horizontalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_2.setStretch(0, 1)
        self.horizontalLayout_2.setStretch(1, 8)
        self.horizontalLayout_3.addLayout(self.horizontalLayout_2)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        # Connect treeWidget item selection to change_algorithm
        self.treeWidget.currentItemChanged.connect(self.change_algorithm)
        self.pushButton_3.clicked.connect(self.encrypt)
        self.pushButton_4.clicked.connect(self.decrypt)
        self.current_algorithm = "AES"
        self.saved_states = {}

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.treeWidget.headerItem().setText(0, _translate("Form", "现代密码"))
        self.plainTextEdit_3.setPlaceholderText(_translate("Form", "请输入明文"))
        self.pushButton_3.setText(_translate("Form", "加密"))
        self.pushButton_4.setText(_translate("Form", "解密"))
        self.lineEdit_2.setPlaceholderText(_translate("Form", "key"))
        self.plainTextEdit_4.setPlaceholderText(_translate("Form", "请输入密文"))

    def change_algorithm(self):
        current_algorithm = self.treeWidget.currentItem().text(0)
        self.save_current_state()
        self.current_algorithm = current_algorithm
        self.restore_state()

    def save_current_state(self):
        self.saved_states[self.current_algorithm] = {
            'plaintext': self.plainTextEdit_3.toPlainText(),
            'key': self.lineEdit_2.text(),
            'ciphertext': self.plainTextEdit_4.toPlainText()
        }

    def restore_state(self):
        state = self.saved_states.get(self.current_algorithm, {'plaintext': '', 'key': '', 'ciphertext': ''})
        self.plainTextEdit_3.setPlainText(state['plaintext'])
        self.lineEdit_2.setText(state['key'])
        self.plainTextEdit_4.setPlainText(state['ciphertext'])

    def encrypt(self):
        if self.current_algorithm == "AES":
            self.encrypt_aes()
        elif self.current_algorithm == "DES":
            self.encrypt_des()
        elif self.current_algorithm == "3DES":
            self.encrypt_3des()
        elif self.current_algorithm == "MD5":
            self.encrypt_md5()
        elif self.current_algorithm == "SM2":
            self.encrypt_sm2()
        elif self.current_algorithm == "SH3":
            self.encrypt_sh3()
        elif self.current_algorithm == "SHA-512":
            self.encrypt_sha_512()
        elif self.current_algorithm == "SHA-384":
            self.encrypt_sha_384()
        elif self.current_algorithm == "SHA-256":
            self.encrypt_sha_256()      

    def decrypt(self):
        if self.current_algorithm == "AES":
            self.decrypt_aes()
        elif self.current_algorithm == "DES":
            self.decrypt_des()
        elif self.current_algorithm == "3DES":
            self.decrypt_3des()
        elif self.current_algorithm == "MD5":
            self.decrypt_md5()
        elif self.current_algorithm == "SM2":
            self.decrypt_sm2()
        elif self.current_algorithm == "SH3":
            self.decrypt_sh3()
        elif self.current_algorithm == "SHA-512":
            self.decrypt_sha_512()
        elif self.current_algorithm == "SHA-384":
            self.decrypt_sha_384()
        elif self.current_algorithm == "SHA-256":
            self.decrypt_sha_256()

    # AES
    def encrypt_aes(self):
        key = self.lineEdit_2.text().encode('utf-8')
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self.plainTextEdit_4.setPlainText(b64encode(cipher.nonce + tag + ciphertext).decode('utf-8'))

    def decrypt_aes(self):
        key = self.lineEdit_2.text().encode('utf-8')
        encrypted_text = b64decode(self.plainTextEdit_4.toPlainText())
        nonce, tag, ciphertext = encrypted_text[:16], encrypted_text[16:32], encrypted_text[32:]
        cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        self.plainTextEdit_3.setPlainText(plaintext.decode('utf-8'))

    # DES
    def encrypt_des(self):
        key = self.lineEdit_2.text().encode('utf-8')
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        cipher = DES.new(hashlib.md5(key).digest()[:8], DES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self.plainTextEdit_4.setPlainText(b64encode(cipher.nonce + tag + ciphertext).decode('utf-8'))

    def decrypt_des(self):
        key = self.lineEdit_2.text().encode('utf-8')
        encrypted_text = b64decode(self.plainTextEdit_4.toPlainText())
        nonce, tag, ciphertext = encrypted_text[:8], encrypted_text[8:24], encrypted_text[24:]
        cipher = DES.new(hashlib.md5(key).digest()[:8], DES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        self.plainTextEdit_3.setPlainText(plaintext.decode('utf-8'))

    # 3DES
    def encrypt_3des(self):
        key = self.lineEdit_2.text().encode('utf-8')
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        cipher = DES3.new(hashlib.sha256(key).digest()[:24], DES3.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self.plainTextEdit_4.setPlainText(b64encode(cipher.nonce + tag + ciphertext).decode('utf-8'))

    def decrypt_3des(self):
        key = self.lineEdit_2.text().encode('utf-8')
        encrypted_text = b64decode(self.plainTextEdit_4.toPlainText())
        nonce, tag, ciphertext = encrypted_text[:16], encrypted_text[16:32], encrypted_text[32:]
        cipher = DES3.new(hashlib.sha256(key).digest()[:24], DES3.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        self.plainTextEdit_3.setPlainText(plaintext.decode('utf-8'))

    # MD5只能加密不能解密
    def encrypt_md5(self):
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        self.plainTextEdit_4.setPlainText(hashlib.md5(plaintext).hexdigest())

    def decrypt_md5(self):
        self.plainTextEdit_3.setPlainText("MD5 is a hashing algorithm and cannot be decrypted")

    # SM2 placeholder
    def encrypt_sm2(self):
        self.plainTextEdit_4.setPlainText("SM2 encryption not implemented")

    def decrypt_sm2(self):
        self.plainTextEdit_3.setPlainText("SM2 decryption not implemented")

    # SH3 placeholder
    def encrypt_sh3(self):
        self.plainTextEdit_4.setPlainText("SH3 encryption not implemented")

    def decrypt_sh3(self):
        self.plainTextEdit_3.setPlainText("SH3 decryption not implemented")

    # SHA-512 (hashing only, no decryption)
    def encrypt_sha_512(self):
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        self.plainTextEdit_4.setPlainText(hashlib.sha512(plaintext).hexdigest())

    def decrypt_sha_512(self):
        self.plainTextEdit_3.setPlainText("SHA-512 is a hashing algorithm and cannot be decrypted")

    # SHA-384 (hashing only, no decryption)
    def encrypt_sha_384(self):
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        self.plainTextEdit_4.setPlainText(hashlib.sha384(plaintext).hexdigest())

    def decrypt_sha_384(self):
        self.plainTextEdit_3.setPlainText("SHA-384 is a hashing algorithm and cannot be decrypted")

    # SHA-256 (hashing only, no decryption)
    def encrypt_sha_256(self):
        plaintext = self.plainTextEdit_3.toPlainText().encode('utf-8')
        self.plainTextEdit_4.setPlainText(hashlib.sha256(plaintext).hexdigest())

    def decrypt_sha_256(self):
        self.plainTextEdit_3.setPlainText("SHA-256 is a hashing algorithm and cannot be decrypted")
