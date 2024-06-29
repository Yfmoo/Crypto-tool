from PyQt5 import QtCore, QtGui, QtWidgets
import base64

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(987, 752)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.treeWidget = QtWidgets.QTreeWidget(Form)
        self.treeWidget.setObjectName("treeWidget")
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        self.horizontalLayout_2.addWidget(self.treeWidget)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.stackedWidget = QtWidgets.QStackedWidget(Form)
        self.verticalLayout.addWidget(self.stackedWidget)
        self.horizontalLayout_2.addLayout(self.verticalLayout)
        self.horizontalLayout_2.setStretch(0, 1)
        self.horizontalLayout_2.setStretch(1, 6)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.current_algorithm = None
        self.algorithm_widgets = {}

        self.treeWidget.clicked.connect(self.handle_tree_click)
        
    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.treeWidget.headerItem().setText(0, _translate("Form", "Base家族"))
        __sortingEnabled = self.treeWidget.isSortingEnabled()
        self.treeWidget.setSortingEnabled(False)
        self.treeWidget.topLevelItem(0).setText(0, _translate("Form", "Base16"))
        self.treeWidget.topLevelItem(1).setText(0, _translate("Form", "Base32"))
        self.treeWidget.topLevelItem(2).setText(0, _translate("Form", "Base56"))
        self.treeWidget.topLevelItem(3).setText(0, _translate("Form", "Base62"))
        self.treeWidget.topLevelItem(4).setText(0, _translate("Form", "Base64"))
        self.treeWidget.topLevelItem(5).setText(0, _translate("Form", "Base85"))
        self.treeWidget.topLevelItem(6).setText(0, _translate("Form", "Base91"))
        self.treeWidget.topLevelItem(7).setText(0, _translate("Form", "Base92"))
        self.treeWidget.topLevelItem(8).setText(0, _translate("Form", "Base100"))
        self.treeWidget.setSortingEnabled(__sortingEnabled)

    def handle_tree_click(self, index):
        item = self.treeWidget.currentItem()
        self.current_algorithm = item.text(0)
        print(f"Selected: {self.current_algorithm}")
        if self.current_algorithm not in self.algorithm_widgets:
            widget = self.create_algorithm_widget()
            self.algorithm_widgets[self.current_algorithm] = widget
            self.stackedWidget.addWidget(widget)
        self.stackedWidget.setCurrentWidget(self.algorithm_widgets[self.current_algorithm])

    def create_algorithm_widget(self):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        plainTextEdit = QtWidgets.QPlainTextEdit(widget)
        plainTextEdit.setFrameShape(QtWidgets.QFrame.Box)
        plainTextEdit.setLineWidth(2)
        plainTextEdit.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit.setPlaceholderText("请输入密文")
        layout.addWidget(plainTextEdit)

        horizontalLayout = QtWidgets.QHBoxLayout()
        horizontalLayout.setSpacing(7)

        pushButtonEncrypt = QtWidgets.QPushButton("加密", widget)
        pushButtonEncrypt.setMaximumSize(QtCore.QSize(90, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        pushButtonEncrypt.setFont(font)
        pushButtonEncrypt.setStyleSheet("background-color: rgb(0, 170, 255);\n"
                                        "color: rgb(255, 0, 0);")
        pushButtonEncrypt.clicked.connect(lambda: self.encrypt_text(widget))
        horizontalLayout.addWidget(pushButtonEncrypt)

        pushButtonDecrypt = QtWidgets.QPushButton("解密", widget)
        pushButtonDecrypt.setMaximumSize(QtCore.QSize(90, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        pushButtonDecrypt.setFont(font)
        pushButtonDecrypt.setStyleSheet("background-color: rgb(0, 170, 255);\n"
                                        "color: rgb(255, 0, 0);")
        pushButtonDecrypt.clicked.connect(lambda: self.decrypt_text(widget))
        horizontalLayout.addWidget(pushButtonDecrypt)

        layout.addLayout(horizontalLayout)

        plainTextEdit_2 = QtWidgets.QPlainTextEdit(widget)
        plainTextEdit_2.setFrameShape(QtWidgets.QFrame.Box)
        plainTextEdit_2.setLineWidth(2)
        plainTextEdit_2.setPlaceholderText("请输入明文")
        layout.addWidget(plainTextEdit_2)

        widget.plainTextEdit = plainTextEdit
        widget.plainTextEdit_2 = plainTextEdit_2
        return widget

    def encrypt_text(self, widget):
        plain_text = widget.plainTextEdit_2.toPlainText()
        encoded_text = ""
        if self.current_algorithm == "Base16":
            encoded_text = base64.b16encode(plain_text.encode('utf-8')).decode('utf-8')
        elif self.current_algorithm == "Base32":
            encoded_text = base64.b32encode(plain_text.encode('utf-8')).decode('utf-8')
        elif self.current_algorithm == "Base64":
            encoded_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
        elif self.current_algorithm == "Base85":
            encoded_text = base64.b85encode(plain_text.encode('utf-8')).decode('utf-8')
        else:
            widget.plainTextEdit.setPlainText("Unsupported encoding algorithm.")
            return
        widget.plainTextEdit.setPlainText(encoded_text)

    def decrypt_text(self, widget):
        encoded_text = widget.plainTextEdit.toPlainText()
        decoded_text = ""
        try:
            if self.current_algorithm == "Base16":
                decoded_text = base64.b16decode(encoded_text.encode('utf-8')).decode('utf-8')
            elif self.current_algorithm == "Base32":
                decoded_text = base64.b32decode(encoded_text.encode('utf-8')).decode('utf-8')
            elif self.current_algorithm == "Base64":
                decoded_text = base64.b64decode(encoded_text.encode('utf-8')).decode('utf-8')
            elif self.current_algorithm == "Base85":
                decoded_text = base64.b85decode(encoded_text.encode('utf-8')).decode('utf-8')
            else:
                widget.plainTextEdit_2.setPlainText("Unsupported decoding algorithm.")
                return
            widget.plainTextEdit_2.setPlainText(decoded_text)
        except Exception as e:
            widget.plainTextEdit_2.setPlainText("解密错误: " + str(e))

"""if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
"""

